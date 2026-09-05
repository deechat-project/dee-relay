// Package prekey is the relay's one-time-prekey (OPK) authority for
// recipient-side forward secrecy (X3DH-lite, the `v3` envelope).
//
// Recipients publish a pool of signed one-time prekeys to their home node.
// Each sender claims a *distinct* unused prekey; the node guarantees one-time
// issuance by popping under a lock.
//
// A pool is named by its owner's queue tag, never by a routing id. A routing id
// is a name — it is minted from a handle slug, so it is guessable, and nothing
// about presenting one proves it is yours. A queue tag is the hash of a secret
// only the owner holds, which makes the pool's own key the ownership proof:
// publishing to a pool and asking after one both require the secret behind the
// tag, and a sender claiming from one holds the tag because its contact gave it
// the tag. See internal/queue/capability.go for the derivation. Because claim-once is the whole security
// guarantee, this store is deliberately NOT mesh-replicated — it is pinned to
// the recipient's home node so a single authority can never hand the same
// prekey to two senders (see internal/mesh/syncer.go which skips it).
package prekey

import (
	"strings"
	"sync"
	"time"

	"deechat/chat-node/internal/model"
)

const (
	defaultMaxPerRecipient = 100
	// defaultMaxBuckets caps how many device pools this store will hold at once.
	// Every other cap in the node bounds a per-identity quantity; without this
	// one the bucket map itself is unbounded, so a caller that publishes under a
	// fresh queue tag each time grows the store until the host runs out — the
	// one term deploy/memory-ceiling.sh used to admit it could not count. Owning
	// a tag is proved, but minting one is free, so this ceiling is still what
	// bounds the map.
	defaultMaxBuckets   = 5000
	defaultPublishedTTL = 30 * 24 * time.Hour
	// defaultClaimBurst/defaultClaimRefill size the per-bucket token bucket that
	// gates how fast the genuine one-time pool can be drained. A legitimate
	// trickle of senders stays well under the burst; a flood exhausts the tokens
	// and is throttled onto the reusable last-resort prekey instead of burning
	// one-time entries.
	defaultClaimBurst  = 32
	defaultClaimRefill = time.Second
)

type Store struct {
	mu              sync.Mutex
	maxPerRecipient int
	maxBuckets      int
	publishedTTL    time.Duration
	claimBurst      float64
	claimRefill     time.Duration
	now             func() time.Time
	queues          map[string][]entry
	// lastResort holds the single reusable last-resort prekey per bucket. Unlike
	// queues it is never popped — it is replaced by the owner on rotation and
	// served whenever the one-time pool can't (drained, or rate-limited).
	lastResort map[string]entry
	// tokens is the per-bucket claim rate-limiter state.
	tokens map[string]bucketState
}

type entry struct {
	value       model.PrekeyEntry
	publishedAt time.Time
}

// bucketState is a token bucket: tokens accrue at one per claimRefill up to
// claimBurst, and each one-time claim spends one.
type bucketState struct {
	tokens     float64
	lastRefill time.Time
}

// bucketKey scopes a pool to a single device of its owner. The owner is named by
// its queue tag; a device by its encoded DevicePublicKeyBundle string, with
// deviceKey=="" the owner-wide pool a group or primary-only sender claims from.
func bucketKey(ownerTag, deviceKey string) string {
	return ownerTag + "\x00" + deviceKey
}

// Limits sizes a Store. A zero field takes the package default.
type Limits struct {
	// MaxPerRecipient is the one-time pool ceiling for a single device bucket.
	MaxPerRecipient int
	// MaxBuckets is the ceiling on the number of device buckets held at once.
	// A publish that would create bucket MaxBuckets+1 is refused rather than
	// evicting an existing bucket: eviction would let a flood of fresh queue
	// tags delete real recipients' pools, and existing buckets are TTL-pruned
	// already. Refusing also matches how the queue store handles a full purge
	// table.
	MaxBuckets int
	// PublishedTTL is how long an unclaimed entry survives.
	PublishedTTL time.Duration
	// ClaimBurst is the per-bucket token-bucket capacity (claims allowed
	// back-to-back); ClaimRefill is the time to accrue one token.
	ClaimBurst  int
	ClaimRefill time.Duration
}

func NewStore(maxPerRecipient int, publishedTTL time.Duration, now func() time.Time) *Store {
	return NewStoreWithLimits(Limits{MaxPerRecipient: maxPerRecipient, PublishedTTL: publishedTTL}, now)
}

// NewStoreWithLimits builds a Store from an operator's configured caps.
func NewStoreWithLimits(limits Limits, now func() time.Time) *Store {
	if limits.MaxPerRecipient <= 0 {
		limits.MaxPerRecipient = defaultMaxPerRecipient
	}
	if limits.MaxBuckets <= 0 {
		limits.MaxBuckets = defaultMaxBuckets
	}
	if limits.PublishedTTL <= 0 {
		limits.PublishedTTL = defaultPublishedTTL
	}
	if limits.ClaimBurst <= 0 {
		limits.ClaimBurst = defaultClaimBurst
	}
	if limits.ClaimRefill <= 0 {
		limits.ClaimRefill = defaultClaimRefill
	}
	if now == nil {
		now = time.Now
	}
	return &Store{
		maxPerRecipient: limits.MaxPerRecipient,
		maxBuckets:      limits.MaxBuckets,
		publishedTTL:    limits.PublishedTTL,
		claimBurst:      float64(limits.ClaimBurst),
		claimRefill:     limits.ClaimRefill,
		now:             now,
		queues:          make(map[string][]entry),
		lastResort:      make(map[string]entry),
		tokens:          make(map[string]bucketState),
	}
}

// Publish appends unused, valid entries to the pool ownerTag names, skipping any
// whose OpkID already exists (idempotent replenish) and enforcing the cap.
//
// ownerTag is the caller's own queue tag, derived by the httpapi layer from the
// capability the publish proved — never a value off the wire. That is the whole
// ownership story: a caller can only fill the pool it can prove is its own, so
// filling a victim's pool to lock them out of publishing is not a request this
// store can be asked to serve.
//
// It returns the number of one-time entries admitted, and false when the store
// is at its bucket ceiling and this publish would have created a new bucket —
// nothing is stored in that case, including the last-resort prekey. A caller
// that already has a bucket is never refused, so a relay at capacity keeps
// serving the recipients it already carries.
func (s *Store) Publish(ownerTag string, value model.PrekeyPublish) (int, bool) {
	ownerTag = strings.TrimSpace(ownerTag)
	if ownerTag == "" {
		return 0, false
	}
	key := bucketKey(ownerTag, strings.TrimSpace(value.DeviceKey))
	now := s.now().UTC()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneLocked(now)
	if !s.bucketExistsLocked(key) && s.bucketCountLocked() >= s.maxBuckets {
		return 0, false
	}
	existing := make(map[string]struct{})
	for _, item := range s.queues[key] {
		existing[item.value.OpkID] = struct{}{}
	}
	added := 0
	for _, candidate := range value.Entries {
		candidate.OpkID = strings.TrimSpace(candidate.OpkID)
		if candidate.OpkID == "" || candidate.PublicKey == "" || candidate.Signature == "" {
			continue
		}
		if _, dup := existing[candidate.OpkID]; dup {
			continue
		}
		if len(s.queues[key]) >= s.maxPerRecipient {
			break
		}
		s.queues[key] = append(s.queues[key], entry{value: candidate, publishedAt: now})
		existing[candidate.OpkID] = struct{}{}
		added++
	}
	// Record/replace the reusable last-resort prekey, validated like a one-time
	// entry. It is kept separately from the queue and never popped on claim.
	if lr := value.LastResort; lr != nil {
		lr.OpkID = strings.TrimSpace(lr.OpkID)
		if lr.OpkID != "" && lr.PublicKey != "" && lr.Signature != "" {
			lr.LastResort = true
			s.lastResort[key] = entry{value: *lr, publishedAt: now}
		}
	}
	return added, true
}

// bucketExistsLocked reports whether key already names a live bucket. A bucket
// is live while it holds one-time entries or a last-resort prekey — the two
// maps are keyed alike and either one alone is a pool this store is carrying.
func (s *Store) bucketExistsLocked(key string) bool {
	if _, ok := s.queues[key]; ok {
		return true
	}
	_, ok := s.lastResort[key]
	return ok
}

// bucketCountLocked counts live buckets across both maps without double-counting
// the (usual) case where one key is in both. Call pruneLocked first: an expired
// bucket must not hold a slot against a new recipient.
func (s *Store) bucketCountLocked() int {
	count := len(s.queues)
	for key := range s.lastResort {
		if _, ok := s.queues[key]; !ok {
			count++
		}
	}
	return count
}

// BucketCount returns the number of live device pools, for /health and for the
// ceiling deploy/memory-ceiling.sh derives.
func (s *Store) BucketCount() int {
	now := s.now().UTC()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneLocked(now)
	return s.bucketCountLocked()
}

// Claim issues a prekey from the pool ownerTag names, deciding per call whether
// to dip into the genuine one-time pool or serve the reusable last-resort
// prekey (LRPK), driven by the per-bucket token bucket:
//
//   - token available AND one-time queue non-empty → pop a distinct one-time
//     entry (best: per-sender forward secrecy) — the legitimate low-rate path.
//     The pop-under-lock is the claim-once guarantee.
//   - no token (rate exceeded) OR queue empty → serve the LRPK (recipient-side
//     FS at rotation granularity), flagged LastResort, never popped.
//   - no LRPK published either → (zero, false) → the sender's graceful `v2`
//     fallback.
//
// A claim flood is thus throttled onto the reusable LRPK, preserving the
// one-time entries for the genuine trickle.
func (s *Store) Claim(ownerTag, deviceKey string) (model.PrekeyEntry, bool) {
	key := bucketKey(strings.TrimSpace(ownerTag), strings.TrimSpace(deviceKey))
	now := s.now().UTC()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneLocked(now)
	queue := s.queues[key]
	// takeTokenLocked is only consulted when a one-time entry is actually
	// available to pop, so an empty queue never spends a token.
	if len(queue) > 0 && s.takeTokenLocked(key, now) {
		claimed := queue[0]
		s.queues[key] = queue[1:]
		if len(s.queues[key]) == 0 {
			delete(s.queues, key)
		}
		return claimed.value, true
	}
	if lr, ok := s.lastResort[key]; ok {
		served := lr.value
		served.LastResort = true
		return served, true
	}
	return model.PrekeyEntry{}, false
}

// takeTokenLocked refills the bucket for key by elapsed time and spends one
// token, returning whether a token was available. A bucket seen for the first
// time starts full (burst).
func (s *Store) takeTokenLocked(key string, now time.Time) bool {
	st, ok := s.tokens[key]
	if !ok {
		st = bucketState{tokens: s.claimBurst, lastRefill: now}
	} else if elapsed := now.Sub(st.lastRefill); elapsed > 0 {
		st.tokens += float64(elapsed) / float64(s.claimRefill)
		if st.tokens > s.claimBurst {
			st.tokens = s.claimBurst
		}
		st.lastRefill = now
	}
	available := st.tokens >= 1
	if available {
		st.tokens--
	}
	s.tokens[key] = st
	return available
}

// Status reports the number of unused prekeys currently available in the pool
// ownerTag names (deviceKey=="" is the owner-wide bucket).
func (s *Store) Status(ownerTag, deviceKey string) int {
	key := bucketKey(strings.TrimSpace(ownerTag), strings.TrimSpace(deviceKey))
	now := s.now().UTC()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneLocked(now)
	return len(s.queues[key])
}

func (s *Store) Prune() { s.mu.Lock(); defer s.mu.Unlock(); s.pruneLocked(s.now().UTC()) }

// Count returns the total number of unused prekeys across all recipients.
func (s *Store) Count() int {
	now := s.now().UTC()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneLocked(now)
	total := 0
	for _, queue := range s.queues {
		total += len(queue)
	}
	return total
}

// LastResortCount returns the number of buckets holding a last-resort prekey
// (one per publishing device), surfaced in /health.
func (s *Store) LastResortCount() int {
	now := s.now().UTC()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneLocked(now)
	return len(s.lastResort)
}

func (s *Store) pruneLocked(now time.Time) {
	for key, queue := range s.queues {
		kept := queue[:0]
		for _, item := range queue {
			if item.publishedAt.Add(s.publishedTTL).After(now) {
				kept = append(kept, item)
			}
		}
		if len(kept) == 0 {
			delete(s.queues, key)
		} else {
			s.queues[key] = kept
		}
	}
	// Last-resort prekeys honor the same TTL, but since the owner rotates them
	// weekly (well within publishedTTL) they are effectively kept until replaced.
	for key, item := range s.lastResort {
		if !item.publishedAt.Add(s.publishedTTL).After(now) {
			delete(s.lastResort, key)
		}
	}
	// Drop limiter state for buckets with nothing left to protect, so the token
	// map can't grow without bound after pools drain.
	for key := range s.tokens {
		if len(s.queues[key]) == 0 {
			if _, ok := s.lastResort[key]; !ok {
				delete(s.tokens, key)
			}
		}
	}
}
