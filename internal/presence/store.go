package presence

import (
	"strings"
	"sync"
	"time"

	"deechat/chat-node/internal/model"
)

// maxRecordsPerCaller is one caller's share of the heartbeat table: how many
// records it may hold once the table is full and a slot has to be taken from
// somebody. Below capacity it is not consulted at all — a share is a claim on a
// scarce table, not a quota on an idle one — so a relay that never fills its
// table behaves exactly as it did before.
//
// A caller here is what the heartbeat proved about itself: the queue tag of the
// capability it presented, or the admitted credential it came in under. A
// caller that proved neither shares one bucket with every other such caller,
// which is the whole of what proof buys — a share of its own.
//
// Deliberately a constant and not a knob, for the same reason as
// attachment.maxChunksPerTransfer: an identity publishes one grant hash per
// profile and rotates it, so 32 is an order of magnitude of headroom over what
// an honest caller needs, and no operator has a reason to tune it. Moving it
// costs deploy/memory-ceiling.sh nothing — it changes who holds the table's
// 5000 records, never how many there are.
const maxRecordsPerCaller = 32

type record struct {
	ownerHash string
	grantHash string
	// caller is the identity this record is charged to, "" for a heartbeat that
	// proved nothing (an open box, an older client, or a replicated record from
	// a peer — a peer's copy has no claim on this box ahead of its own users).
	caller    string
	lastSeen  time.Time
	updatedAt time.Time
	expiresAt time.Time
}

// Grant is what one heartbeat proved about its caller, resolved by the httpapi
// layer and handed down as plain strings — the same shape attachment.Grant has,
// and for the same reason: this package stays the authority on its own caps and
// learns nothing about a caller beyond a key to count under.
//
// The zero value is an unattributed heartbeat and is what the mesh import path
// and an older client both get.
type Grant struct {
	// Caller keys the share. The httpapi layer prefixes it so a queue tag and a
	// credential index can never collide.
	Caller string
}

type Store struct {
	mu          sync.Mutex
	maxRecords  int
	lastSeenTTL time.Duration
	now         func() time.Time
	records     map[string]record
	// callers counts records per caller key, kept in lock-step with records by
	// putLocked and dropLocked alone. At most one entry per record, so it is
	// bounded by maxRecords and costs nothing the table is not already sized for.
	callers     map[string]int
	revocations map[string]model.PresenceRevocation
}

func NewStore(maxRecords int, lastSeenTTL time.Duration, now func() time.Time) *Store {
	if maxRecords <= 0 {
		maxRecords = 5000
	}
	if lastSeenTTL <= 0 {
		lastSeenTTL = 24 * time.Hour
	}
	if now == nil {
		now = time.Now
	}
	return &Store{maxRecords: maxRecords, lastSeenTTL: lastSeenTTL, now: now, records: make(map[string]record), callers: make(map[string]int), revocations: make(map[string]model.PresenceRevocation)}
}

// Heartbeat records a lease for a caller that proved nothing about itself: the
// mesh import path, and an older client that sends no capability. See
// HeartbeatWithGrant for what proof buys.
func (s *Store) Heartbeat(value model.PresenceHeartbeat) bool {
	return s.HeartbeatWithGrant(value, Grant{})
}

// HeartbeatWithGrant records a lease and charges it to grant.Caller.
//
// A full table used to refuse any grant hash it was not already carrying, and a
// record is held for lastSeenTTL (24 hours) while a heartbeat only reports
// *online* for five minutes — so one burst of junk grant hashes locked every new
// identity out of presence for a day. Two rules replace that refusal, and both
// only apply once the table is full:
//
//   - A caller past its share does not get a slot at anybody's expense.
//   - A slot is taken from the record with the weakest claim to it: an offline
//     one first (its useful life is already over), and failing that one held by
//     a caller past its own share. If every record is online and inside its
//     share, the table is genuinely full and the heartbeat is refused.
//
// So the worst a burst can now do is hold the table for as long as it keeps
// re-sending every record it holds — and even then only against callers that
// proved no more than it did.
func (s *Store) HeartbeatWithGrant(value model.PresenceHeartbeat, grant Grant) bool {
	value.OwnerHash = strings.TrimSpace(value.OwnerHash)
	value.GrantHash = strings.TrimSpace(value.GrantHash)
	now := s.now().UTC()
	if value.UpdatedAt.IsZero() {
		value.UpdatedAt = now
	}
	if value.OwnerHash == "" || value.GrantHash == "" || !value.ExpiresAt.After(now) || value.ExpiresAt.After(now.Add(5*time.Minute)) {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneLocked(now)
	if revoked, exists := s.revocations[value.OwnerHash]; exists {
		if !value.UpdatedAt.After(revoked.UpdatedAt) {
			return false
		}
		delete(s.revocations, value.OwnerHash)
	}
	caller := strings.TrimSpace(grant.Caller)
	if _, exists := s.records[value.GrantHash]; !exists && !s.makeRoomLocked(now, caller) {
		return false
	}
	s.putLocked(record{ownerHash: value.OwnerHash, grantHash: value.GrantHash, caller: caller, lastSeen: now, updatedAt: value.UpdatedAt.UTC(), expiresAt: value.ExpiresAt.UTC()})
	return true
}

// makeRoomLocked reports whether caller may take a slot for a record the table
// does not already hold, evicting one weaker claim if it has to.
func (s *Store) makeRoomLocked(now time.Time, caller string) bool {
	if len(s.records) < s.maxRecords {
		return true
	}
	if s.callers[caller] >= maxRecordsPerCaller {
		return false
	}
	victim, found := "", false
	// Rank 0 is an offline record, rank 1 one whose caller is past its share.
	// Anything else is a live lease inside its share and is not a candidate.
	bestRank, bestSeen := 2, time.Time{}
	for key, item := range s.records {
		rank := 2
		switch {
		case !item.expiresAt.After(now):
			rank = 0
		case item.caller != caller && s.callers[item.caller] > maxRecordsPerCaller:
			rank = 1
		}
		if rank == 2 {
			continue
		}
		if !found || rank < bestRank || (rank == bestRank && item.lastSeen.Before(bestSeen)) {
			victim, found, bestRank, bestSeen = key, true, rank, item.lastSeen
		}
	}
	if !found {
		return false
	}
	s.dropLocked(victim)
	return true
}

// putLocked and dropLocked are the only writers of records, so that callers
// cannot drift out of lock-step with it — the same rule the queue store's
// bookkeeping maps live by, and there is a test for the leak.
func (s *Store) putLocked(value record) {
	if previous, exists := s.records[value.grantHash]; exists {
		s.releaseLocked(previous.caller)
	}
	s.records[value.grantHash] = value
	s.callers[value.caller]++
}

func (s *Store) dropLocked(grantHash string) {
	item, exists := s.records[grantHash]
	if !exists {
		return
	}
	delete(s.records, grantHash)
	s.releaseLocked(item.caller)
}

func (s *Store) releaseLocked(caller string) {
	if s.callers[caller] <= 1 {
		delete(s.callers, caller)
		return
	}
	s.callers[caller]--
}

func (s *Store) Query(grants []string) []model.PresenceStatus {
	now := s.now().UTC()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneLocked(now)
	result := make([]model.PresenceStatus, 0, len(grants))
	for _, grant := range grants {
		if item, ok := s.records[strings.TrimSpace(grant)]; ok {
			result = append(result, model.PresenceStatus{GrantHash: item.grantHash, Online: item.expiresAt.After(now), LastSeen: item.lastSeen})
		}
	}
	return result
}

func (s *Store) Revoke(ownerHash string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	count := 0
	now := s.now().UTC()
	for key, item := range s.records {
		if item.ownerHash == strings.TrimSpace(ownerHash) {
			s.dropLocked(key)
			count++
		}
	}
	owner := strings.TrimSpace(ownerHash)
	// The revocation deletions above always run; the tombstone is only stored if
	// the map has room, so a flood of distinct owner hashes on the public
	// /presence/revoke (and /profile/purge) endpoint can't grow it without bound.
	s.storeRevocationLocked(model.PresenceRevocation{OwnerHash: owner, UpdatedAt: now, ExpiresAt: now.Add(s.lastSeenTTL)})
	return count
}

func (s *Store) Prune() { s.mu.Lock(); defer s.mu.Unlock(); s.pruneLocked(s.now().UTC()) }
func (s *Store) Count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneLocked(s.now().UTC())
	return len(s.records)
}
func (s *Store) Snapshot() []model.PresenceHeartbeat {
	now := s.now().UTC()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneLocked(now)
	result := make([]model.PresenceHeartbeat, 0, len(s.records))
	for _, item := range s.records {
		result = append(result, model.PresenceHeartbeat{
			OwnerHash: item.ownerHash, GrantHash: item.grantHash, UpdatedAt: item.updatedAt, ExpiresAt: item.expiresAt,
		})
	}
	return result
}
func (s *Store) Import(values []model.PresenceHeartbeat) {
	for _, value := range values {
		s.Heartbeat(value)
	}
}
func (s *Store) Revocations() []model.PresenceRevocation {
	now := s.now().UTC()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneLocked(now)
	result := make([]model.PresenceRevocation, 0, len(s.revocations))
	for _, value := range s.revocations {
		result = append(result, value)
	}
	return result
}
func (s *Store) ImportRevocations(values []model.PresenceRevocation) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now().UTC()
	for _, value := range values {
		if value.OwnerHash == "" || !value.ExpiresAt.After(now) {
			continue
		}
		current, exists := s.revocations[value.OwnerHash]
		if exists && !value.UpdatedAt.After(current.UpdatedAt) {
			continue
		}
		if !exists && len(s.revocations) >= s.maxRecords {
			continue
		}
		s.revocations[value.OwnerHash] = value
		for key, item := range s.records {
			if item.ownerHash == value.OwnerHash && !item.updatedAt.After(value.UpdatedAt) {
				s.dropLocked(key)
			}
		}
	}
}

// storeRevocationLocked records a revocation tombstone, refreshing one that
// already exists but declining to insert a brand-new owner hash once the map is
// at capacity (TTL-pruned, never written to disk).
func (s *Store) storeRevocationLocked(value model.PresenceRevocation) {
	if _, exists := s.revocations[value.OwnerHash]; !exists && len(s.revocations) >= s.maxRecords {
		return
	}
	s.revocations[value.OwnerHash] = value
}

func (s *Store) pruneLocked(now time.Time) {
	for key, item := range s.records {
		if item.lastSeen.Add(s.lastSeenTTL).Before(now) {
			s.dropLocked(key)
		}
	}
	for key, item := range s.revocations {
		if !item.ExpiresAt.After(now) {
			delete(s.revocations, key)
		}
	}
}
