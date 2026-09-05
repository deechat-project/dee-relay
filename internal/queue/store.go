package queue

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"deechat/chat-node/internal/model"
)

var (
	ErrDuplicate       = errors.New("duplicate record")
	ErrExpired         = errors.New("record is expired")
	ErrQueueFull       = errors.New("queue is full")
	ErrPairQuotaFull   = errors.New("per-pair backlog quota is full")
	ErrSlotsFull       = errors.New("this circle's queue slots are all occupied")
	ErrPayloadTooLarge = errors.New("encrypted payload exceeds the size cap")
	ErrInvalid         = errors.New("record is invalid")
	ErrNotOwned        = errors.New("caller did not prove ownership of the queue this record belongs to")
)

// Grant is the admitted credential's authority over one write, resolved by the
// httpapi layer from internal/admission and handed down as plain numbers.
//
// The zero value is an unattributed write — an open box, or a relay that is
// loaded with credentials but not yet enforcing. It gets the box's own caps,
// which is exactly what the free self-hosted path must keep getting.
//
// Credential is a per-boot integer and never the credential itself, so the
// strongest thing this package can build out of what it is given is a count per
// circle. A map from queue tags to a circle would be a membership roster, which
// is more than the admission token itself discloses and is exactly what this
// relay must not be able to build.
type Grant struct {
	Credential uint32
	// Slots caps undelivered envelopes charged to this credential. Zero means the
	// box's own cap, which for this dimension is the global message cap.
	Slots int
	// MaxPerPair lowers the per-pair backlog quota. It may only lower it.
	MaxPerPair int
	// Retention lowers the ceiling on a sender's requested expiry. It may only
	// lower it — a credential cannot buy a longer window than the box allows.
	Retention time.Duration
}

// lowerOf resolves a box cap against a credential's, and is the single place
// both of the rules that make this schema safe to change are implemented: zero
// means the box's own cap, and a credential may only ever lower one.
func lowerOf(box, credential int) int {
	if credential <= 0 || credential > box {
		return box
	}
	return credential
}

func lowerOfDuration(box, credential time.Duration) time.Duration {
	if credential <= 0 || credential > box {
		return box
	}
	return credential
}

type StoreConfig struct {
	MaxMessages     int
	MaxAcks         int
	MaxPurges       int
	MaxPerPair      int
	MaxPayloadBytes int
	MaxTTL          time.Duration
	DefaultTTL      time.Duration
	Now             func() time.Time
}

type Stats struct {
	Messages int `json:"messages"`
	Acks     int `json:"acks"`
	Purges   int `json:"purges"`
}

type ImportResult struct {
	AcceptedMessages  int
	DuplicateMessages int
	AcceptedAcks      int
	DuplicateAcks     int
	Rejected          int
}

type Store struct {
	mu sync.RWMutex

	maxMessages     int
	maxAcks         int
	maxPurges       int
	maxPerPair      int
	maxPayloadBytes int
	maxTTL          time.Duration
	defaultTTL      time.Duration
	now             func() time.Time

	messages map[string]model.MessageEnvelope
	acks     map[string]model.AckRecord
	purges   map[string]model.PurgeRecord
	// pairCounts tracks undelivered messages per (sender→recipient) lane so the
	// per-pair backlog quota is an O(1) check instead of a full scan. It is kept
	// in lock-step with `messages` through addMessageLocked/deleteMessageLocked.
	pairCounts map[string]int

	// credentialCounts is how many undelivered envelopes each admitted circle is
	// holding: one integer per credential, incremented on accept and decremented
	// on delivery or expiry. Occupancy is charged to the credential that POSTED
	// the envelope, not to the one that will collect it — the sender's circle is
	// the one paying for the relay, and the alternative needs the relay to work
	// out which circle a recipient belongs to, which is the roster it must not
	// build.
	//
	// A count, never a set. `map[uint32]int` rather than anything keyed by a
	// queue tag is the whole rule: a number says how much a circle is holding, a
	// tag set says who is in it. The difference is one line of code either way,
	// which is why it is written down here as well as in the design.
	credentialCounts map[uint32]int
	// messageCredential remembers which credential a queued envelope was charged
	// to so the count can be decremented when it leaves. It is keyed by message
	// id — not by tag, and not by anything about the circle — and it is never
	// serialized, so a replicating peer never learns this relay's attribution.
	messageCredential map[string]uint32

	// seq numbers records in local arrival order so a replicating peer can page
	// through them with a cursor instead of re-reading the same prefix forever.
	//
	// It has to be arrival order, not CreatedAt: CreatedAt comes from the client,
	// so it is neither monotone (a device with a skewed clock, or one that queues
	// offline and posts later) nor unique. A cursor on a value the sender controls
	// silently skips records; a cursor on arrival order cannot.
	//
	// Both maps are kept in lock-step with the record maps through the four
	// add/delete helpers — a leaked entry here would be an unbounded map on a
	// relay whose memory ceiling is derived from the record caps.
	seq        uint64
	messageSeq map[string]uint64
	ackSeq     map[string]uint64

	// messageTags is the write-authorization index: for each message id this
	// relay holds any record about, the recipient tag a caller-posted ack for it
	// has to prove, and how many records are keeping that binding alive.
	//
	// It is an index and not a scan because the alternative is walking the whole
	// ack map on every POST /acks while holding s.mu — at the default caps a
	// 20k-entry walk on an ungated route, which is the one performance shape
	// this store already has a standing complaint about.
	//
	// Refcounted, and kept in lock-step by the same four add/delete helpers as
	// messageSeq and ackSeq: the binding has to outlive the envelope, because
	// the first terminal ack deletes it and the second still has to be proved.
	messageTags map[string]tagBinding
	// messagesByPurge and acksByMessage are the deletion indexes /profile/purge
	// runs on: message ids under the owner tombstone hash a sender stamped on
	// them, and ack ids under the message each ack names.
	//
	// They exist for the same reason messageTags does — the alternative is a
	// scan under s.mu, and here it was two of them: every envelope to find the
	// owner's, then every ack to find those envelopes'. At the default caps
	// that is a 10k+10k walk with the whole store locked, which any caller can
	// trigger in a loop on a route that is deliberately ungated (it only ever
	// removes data, and it is the last thing a circle does on a relay it is
	// leaving, so gating it would strand the mail it is trying to clear).
	//
	// Neither is a new store a caller can grow independently: there is at most
	// one entry per record, added and removed by the same four add/delete
	// helpers that keep messageSeq and ackSeq in lock-step, and an envelope
	// carrying no purge hash is not indexed at all. A purge hash is also what
	// acksByMessage lets hasTerminalAckLocked stop scanning for.
	messagesByPurge map[string]map[string]struct{}
	acksByMessage   map[string]map[string]struct{}
	// epoch changes on every start. The queues are RAM-only, so a restart empties
	// them; a peer that kept a cursor across our restart would page from a
	// high-water mark that no longer exists and never see the records it lost.
	// Publishing the epoch lets it notice and start over.
	epoch string
}

func NewStore(cfg StoreConfig) *Store {
	if cfg.MaxMessages <= 0 {
		cfg.MaxMessages = 1000
	}
	// The ack lane is deliberately larger than the message lane, and the
	// difference is load-bearing: everything above maxMessages is the budget
	// caller-posted acks may occupy, and the maxMessages entries below it are
	// reserved for the node's own coupled node_received acks — which is what
	// makes it impossible for ack pressure to refuse a POST /messages. A
	// deployment configured with no external budget is refused at boot by
	// config.Validate; a Store built directly (tests, embedders) is corrected
	// here rather than serving an ack lane no caller is allowed to write to.
	if cfg.MaxAcks <= cfg.MaxMessages {
		cfg.MaxAcks = 2 * cfg.MaxMessages
	}
	if cfg.MaxPurges <= 0 {
		cfg.MaxPurges = 1000
	}
	if cfg.MaxPerPair <= 0 {
		cfg.MaxPerPair = 10
	}
	if cfg.MaxPayloadBytes <= 0 {
		cfg.MaxPayloadBytes = 8192
	}
	if cfg.MaxTTL <= 0 {
		cfg.MaxTTL = 72 * time.Hour
	}
	if cfg.DefaultTTL <= 0 {
		cfg.DefaultTTL = 24 * time.Hour
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &Store{
		maxMessages:       cfg.MaxMessages,
		maxAcks:           cfg.MaxAcks,
		maxPurges:         cfg.MaxPurges,
		maxPerPair:        cfg.MaxPerPair,
		maxPayloadBytes:   cfg.MaxPayloadBytes,
		maxTTL:            cfg.MaxTTL,
		defaultTTL:        cfg.DefaultTTL,
		now:               cfg.Now,
		messages:          make(map[string]model.MessageEnvelope),
		acks:              make(map[string]model.AckRecord),
		purges:            make(map[string]model.PurgeRecord),
		pairCounts:        make(map[string]int),
		credentialCounts:  make(map[uint32]int),
		messageCredential: make(map[string]uint32),
		messageSeq:        make(map[string]uint64),
		ackSeq:            make(map[string]uint64),
		messageTags:       make(map[string]tagBinding),
		messagesByPurge:   make(map[string]map[string]struct{}),
		acksByMessage:     make(map[string]map[string]struct{}),
		epoch:             newEpoch(),
	}
}

// newEpoch is random rather than a timestamp: two relays started in the same
// second must not share an epoch, and a clock that steps backwards must not
// make a fresh store look like the one a peer already has a cursor into.
func newEpoch() string {
	var raw [8]byte
	if _, err := rand.Read(raw[:]); err != nil {
		// crypto/rand does not fail in practice; if it ever does, an epoch that
		// changes on every read is the safe direction — peers reset their cursors
		// and re-read, which costs bandwidth rather than records.
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(raw[:])
}

// Epoch identifies this store's lifetime. See the field comment.
func (s *Store) Epoch() string { return s.epoch }

// AddMessage queues an envelope with no credential attached: the box's caps
// apply and nothing is charged to a circle. This is the free self-hosted path
// and the mesh/test path; the public write path uses AddMessageWithGrant.
func (s *Store) AddMessage(envelope model.MessageEnvelope, nodeID string) (model.AckRecord, error) {
	return s.AddMessageWithGrant(envelope, nodeID, Grant{})
}

// AddMessageWithGrant queues an envelope against an admitted credential's terms.
func (s *Store) AddMessageWithGrant(envelope model.MessageEnvelope, nodeID string, grant Grant) (model.AckRecord, error) {
	envelope.ID = strings.TrimSpace(envelope.ID)
	envelope.Sender = strings.TrimSpace(envelope.Sender)
	envelope.Recipient = strings.TrimSpace(envelope.Recipient)
	envelope.EncryptedPayload = strings.TrimSpace(envelope.EncryptedPayload)
	envelope.RecipientTag = strings.TrimSpace(envelope.RecipientTag)
	envelope.SenderTag = strings.TrimSpace(envelope.SenderTag)
	now := s.now().UTC()

	if envelope.ID == "" || envelope.Sender == "" || envelope.Recipient == "" || envelope.EncryptedPayload == "" {
		return model.AckRecord{}, ErrInvalid
	}
	if len(envelope.EncryptedPayload) > s.maxPayloadBytes {
		return model.AckRecord{}, ErrPayloadTooLarge
	}
	if envelope.CreatedAt.IsZero() {
		envelope.CreatedAt = now
	}
	if envelope.ExpiresAt.IsZero() {
		envelope.ExpiresAt = now.Add(s.defaultTTL)
	}
	// Clamp a client-set window to the node ceiling so a sender can't pin RAM
	// for longer than the node is willing to relay, and to the circle's own
	// retention window when its credential names a shorter one. The coupled
	// node_received ack inherits this clamped ExpiresAt.
	//
	// Retention is the tier ladder's headline lever (24h → 48h → 72h across the
	// shared pool), and it is a clamp rather than a rejection on purpose: a
	// sender asking for longer than its circle bought gets its message relayed
	// for as long as the circle bought, not an error it cannot act on.
	if maxExpiry := now.Add(lowerOfDuration(s.maxTTL, grant.Retention)); envelope.ExpiresAt.After(maxExpiry) {
		envelope.ExpiresAt = maxExpiry
	}
	if !envelope.ExpiresAt.After(now) {
		return model.AckRecord{}, ErrExpired
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.messages[envelope.ID]; exists {
		return s.nodeReceivedAck(envelope, nodeID, now), ErrDuplicate
	}
	if purgeHash := envelope.Metadata["purgeHash"]; purgeHash != "" {
		if purge, exists := s.purges[purgeHash]; exists && purge.ExpiresAt.After(now) {
			return model.AckRecord{}, ErrDuplicate
		}
	}
	// Per-pair backlog quota: a single (sender→recipient) lane can't hold more
	// than maxPerPair undelivered messages, so one chatty pair or one flooder
	// can't starve every other conversation the way the global cap alone allows.
	if s.pairCounts[pairKey(envelope.Sender, envelope.Recipient)] >= lowerOf(s.maxPerPair, grant.MaxPerPair) {
		return model.AckRecord{}, ErrPairQuotaFull
	}
	// The circle's own ceiling, checked before the box's: at the sizing each tier
	// ships with it never rejects anything the per-pair quota would have allowed
	// a circle of that size, and it binds only when a circle is larger than the
	// tier it bought. What it prevents is one circle taking the shared box —
	// the global cap protects the host, this protects the neighbours, and
	// neither substitutes for the other.
	if grant.Credential != 0 {
		if slots := lowerOf(s.maxMessages, grant.Slots); s.credentialCounts[grant.Credential] >= slots {
			return model.AckRecord{}, ErrSlotsFull
		}
	}
	if len(s.messages) >= s.maxMessages {
		return model.AckRecord{}, ErrQueueFull
	}

	ack := s.nodeReceivedAck(envelope, nodeID, now)
	if err := s.addAckLocked(ack, now); err != nil {
		return model.AckRecord{}, err
	}
	s.addMessageLocked(envelope, grant.Credential)
	return ack, nil
}

// MessagesForRecipient returns the queued envelopes for recipient that auth is
// allowed to read. Expiry is swept for every candidate regardless of
// authorization, so an unauthorized fetch still cannot be used to keep dead
// records alive — but it never sees a tagged one.
func (s *Store) MessagesForRecipient(recipient string, limit int, auth Auth) []model.MessageEnvelope {
	recipient = strings.TrimSpace(recipient)
	if recipient == "" {
		return nil
	}
	if limit <= 0 {
		limit = 100
	}
	now := s.now().UTC()

	s.mu.Lock()
	defer s.mu.Unlock()

	messages := make([]model.MessageEnvelope, 0)
	for id, envelope := range s.messages {
		if !envelope.ExpiresAt.After(now) {
			s.deleteMessageLocked(id)
			continue
		}
		if envelope.Recipient == recipient && auth.permits(envelope.RecipientTag) {
			messages = append(messages, envelope)
		}
	}
	sort.Slice(messages, func(i, j int) bool {
		return messages[i].CreatedAt.Before(messages[j].CreatedAt)
	})
	if len(messages) > limit {
		return messages[:limit]
	}
	return messages
}

// AddAck records an ack with no credential attached and no ownership check: the
// box's own ceilings apply and the caller is trusted. Nothing reachable from a
// listener may use it — POST /acks goes through AddAckWithGrant with the
// authorization that request presented.
func (s *Store) AddAck(ack model.AckRecord, nodeID string) error {
	return s.AddAckWithGrant(ack, nodeID, Grant{}, TrustedAuth())
}

// AddAckWithGrant records a caller-posted ack against an admitted credential's
// terms. Unlike an envelope it is charged to no circle's slots, but it is held
// to the same retention ceiling and to the external ack budget.
//
// auth is what the caller proved about itself, and it is checked against the
// acked message's recipient tag: five of the six ack types delete the message
// they name, so an unproved ack is a way to destroy a third party's queued mail
// with nothing but its id. ErrNotOwned when the node holds a tag for the message
// and the caller cannot match it.
func (s *Store) AddAckWithGrant(ack model.AckRecord, nodeID string, grant Grant, auth Auth) error {
	ack.ID = strings.TrimSpace(ack.ID)
	ack.MessageID = strings.TrimSpace(ack.MessageID)
	ack.Sender = strings.TrimSpace(ack.Sender)
	ack.Recipient = strings.TrimSpace(ack.Recipient)
	ack.SenderTag = strings.TrimSpace(ack.SenderTag)
	ack.Reason = boundedAckReason(ack.Reason)
	now := s.now().UTC()

	if ack.ID == "" || ack.MessageID == "" || ack.Sender == "" || ack.Recipient == "" || !validAckType(ack.Type) {
		return ErrInvalid
	}
	if ack.CreatedAt.IsZero() {
		ack.CreatedAt = now
	}
	if ack.ExpiresAt.IsZero() {
		ack.ExpiresAt = now.Add(s.defaultTTL)
	}
	// Clamp a client-set window the same way an envelope's is clamped: to the
	// node ceiling, and to the circle's own retention window when its credential
	// names a shorter one. Without this a caller could park an ack in RAM until
	// long after the message it refers to has expired — PruneExpired would never
	// reach it, and the entry would hold its slot in the ack lane for years.
	if maxExpiry := now.Add(lowerOfDuration(s.maxTTL, grant.Retention)); ack.ExpiresAt.After(maxExpiry) {
		ack.ExpiresAt = maxExpiry
	}
	if ack.NodeID == "" {
		ack.NodeID = nodeID
	}
	if !ack.ExpiresAt.After(now) {
		return ErrExpired
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// Authorization before anything else, including the duplicate check: what
	// the node already holds for a message id is not a caller's business until
	// it has proved the queue is its own.
	//
	// The tag the caller sent is discarded either way. When the node holds no
	// binding — a message it never carried, or one whose every record has
	// expired — the ack is stored unproved, because there is nothing behind it
	// left to destroy and refusing would only break a late ack for a message
	// that already timed out. What that leaves an unproved caller is a slot in
	// the caller-posted ack budget, which is bounded and self-healing — parity
	// with what posting to a fabricated recipient already buys a caller.
	ack.RecipientTag = ""
	if tag, bound := s.recipientTagForMessageLocked(ack.MessageID); bound {
		if !auth.permits(tag) {
			return ErrNotOwned
		}
		ack.RecipientTag = tag
	}

	if _, exists := s.acks[ack.ID]; exists {
		return ErrDuplicate
	}
	if err := s.addExternalAckLocked(ack, now); err != nil {
		return err
	}
	if deletesQueuedMessage(ack.Type) {
		s.deleteMessageLocked(ack.MessageID)
	}
	return nil
}

// recipientTagForMessageLocked resolves the queue a message was addressed to,
// and reports whether this node knows it at all.
//
// The binding is held by every record naming the message, not by the envelope
// alone, which is what makes it survive delivery: the first terminal ack deletes
// the envelope, and the coupled node_received ack carries the tag for the rest
// of the message's life so the second terminal ack still has something to be
// proved against.
func (s *Store) recipientTagForMessageLocked(messageID string) (string, bool) {
	binding, bound := s.messageTags[messageID]
	return binding.tag, bound
}

// AcksForSender returns the ack records for sender that auth is allowed to read.
// Same authorization shape as MessagesForRecipient, against the ack's SenderTag.
func (s *Store) AcksForSender(sender string, limit int, auth Auth) []model.AckRecord {
	sender = strings.TrimSpace(sender)
	if sender == "" {
		return nil
	}
	if limit <= 0 {
		limit = 100
	}
	now := s.now().UTC()

	s.mu.Lock()
	defer s.mu.Unlock()

	acks := make([]model.AckRecord, 0)
	for id, ack := range s.acks {
		if !ack.ExpiresAt.After(now) {
			s.deleteAckLocked(id)
			continue
		}
		if ack.Sender == sender && auth.permits(ack.SenderTag) {
			acks = append(acks, ack)
		}
	}
	sort.Slice(acks, func(i, j int) bool {
		return acks[i].CreatedAt.Before(acks[j].CreatedAt)
	})
	if len(acks) > limit {
		return acks[:limit]
	}
	return acks
}

// Snapshot returns the first page of the queue. Kept for callers that want a
// look at the head of it; replication uses SnapshotSince.
func (s *Store) Snapshot(limit int) model.SyncPayload {
	return s.SnapshotSince(0, limit)
}

// SnapshotSince returns the records that arrived after cursor `since`, oldest
// arrival first, at most `limit` of them, together with the cursor to ask for
// next and whether more are already waiting.
//
// Paging is why this exists. The original snapshot was "the oldest 500 records,
// every time", which does not converge: a relay holding more than 500
// undelivered records replicated the same 500 on every tick and the newest mail
// — the whole point of a pool — never crossed. Measured on a three-relay
// loopback pool: 621 records held, 501 replicated, unchanged over nine ticks.
//
// The limit stays per-page rather than per-kind because it is also what bounds
// the response body, and it counts messages and acks together for the same
// reason.
func (s *Store) SnapshotSince(since uint64, limit int) model.SyncPayload {
	if limit <= 0 {
		limit = 500
	}
	now := s.now().UTC()

	s.mu.Lock()
	defer s.mu.Unlock()

	// Expiry is applied first so an expired record is never handed to a peer that
	// would import it and then have to expire it again.
	for id, envelope := range s.messages {
		if !envelope.ExpiresAt.After(now) {
			s.deleteMessageLocked(id)
		}
	}
	for id, ack := range s.acks {
		if !ack.ExpiresAt.After(now) {
			s.deleteAckLocked(id)
		}
	}
	for hash, purge := range s.purges {
		if !purge.ExpiresAt.After(now) {
			delete(s.purges, hash)
		}
	}

	type ref struct {
		seq   uint64
		id    string
		isAck bool
	}
	pending := make([]ref, 0, len(s.messageSeq)+len(s.ackSeq))
	for id, seq := range s.messageSeq {
		if seq > since {
			pending = append(pending, ref{seq: seq, id: id})
		}
	}
	for id, seq := range s.ackSeq {
		if seq > since {
			pending = append(pending, ref{seq: seq, id: id, isAck: true})
		}
	}
	sort.Slice(pending, func(i, j int) bool { return pending[i].seq < pending[j].seq })

	more := len(pending) > limit
	if more {
		pending = pending[:limit]
	}

	payload := model.SyncPayload{
		Epoch:    s.epoch,
		NextSeq:  since,
		More:     more,
		Messages: make([]model.MessageEnvelope, 0, len(pending)),
		Acks:     make([]model.AckRecord, 0, len(pending)),
	}
	for _, item := range pending {
		if item.isAck {
			payload.Acks = append(payload.Acks, s.acks[item.id])
		} else {
			payload.Messages = append(payload.Messages, s.messages[item.id])
		}
		payload.NextSeq = item.seq
	}

	// Purge tombstones ride along on every page, not just the first. They are
	// capped (DEE_NODE_MAX_PURGES) and tiny, and a page that carries records but
	// not the tombstone that deletes them would let a purged message come back on
	// the next exchange.
	payload.Purges = make([]model.PurgeRecord, 0, len(s.purges))
	for _, purge := range s.purges {
		payload.Purges = append(payload.Purges, purge)
	}
	return payload
}

func (s *Store) ImportSnapshot(payload model.SyncPayload) ImportResult {
	now := s.now().UTC()
	result := ImportResult{}

	s.mu.Lock()
	defer s.mu.Unlock()
	for _, purge := range payload.Purges {
		if purge.PurgeHash == "" || !purge.ExpiresAt.After(now) {
			result.Rejected++
			continue
		}
		// The owner-purge deletion always runs (it only removes data); the
		// tombstone is only stored if the map has room, so a flood of distinct
		// purge hashes from a trusted peer can't grow it without bound.
		s.storePurgeLocked(purge)
		s.purgeOwnerLocked(purge.PurgeHash)
	}

	for _, envelope := range payload.Messages {
		err := s.importMessageLocked(envelope, now)
		switch {
		case err == nil:
			result.AcceptedMessages++
		case errors.Is(err, ErrDuplicate):
			result.DuplicateMessages++
		default:
			result.Rejected++
		}
	}

	for _, ack := range payload.Acks {
		err := s.importAckLocked(ack, now)
		switch {
		case err == nil:
			result.AcceptedAcks++
		case errors.Is(err, ErrDuplicate):
			result.DuplicateAcks++
		default:
			result.Rejected++
		}
	}

	return result
}

func (s *Store) PruneExpired(now time.Time) Stats {
	s.mu.Lock()
	defer s.mu.Unlock()

	now = now.UTC()
	for id, envelope := range s.messages {
		if !envelope.ExpiresAt.After(now) {
			s.deleteMessageLocked(id)
		}
	}
	for id, ack := range s.acks {
		if !ack.ExpiresAt.After(now) {
			s.deleteAckLocked(id)
		}
	}
	for hash, purge := range s.purges {
		if !purge.ExpiresAt.After(now) {
			delete(s.purges, hash)
		}
	}
	return s.statsLocked()
}

func (s *Store) Stats() Stats {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.statsLocked()
}

func (s *Store) PurgeOwner(purgeHash string) (int, int) {
	purgeHash = strings.TrimSpace(purgeHash)
	s.mu.Lock()
	defer s.mu.Unlock()
	// Always purge the owner's data; only the tombstone insertion is capped so a
	// flood of distinct purge hashes on the public /profile/purge endpoint can't
	// grow the map without bound (it is TTL-pruned, never written to disk).
	s.storePurgeLocked(model.PurgeRecord{PurgeHash: purgeHash, ExpiresAt: s.now().UTC().Add(s.defaultTTL)})
	return s.purgeOwnerLocked(purgeHash)
}

// storePurgeLocked records a purge tombstone, refreshing one that already
// exists but declining to insert a brand-new hash once the map is at capacity.
func (s *Store) storePurgeLocked(purge model.PurgeRecord) {
	if _, exists := s.purges[purge.PurgeHash]; !exists && len(s.purges) >= s.maxPurges {
		return
	}
	s.purges[purge.PurgeHash] = purge
}

// purgeOwnerLocked deletes an owner's queued mail and every ack naming it, by
// index lookup rather than by walking the two record maps. See messagesByPurge.
//
// An empty hash matches nothing. Envelopes carrying no purgeHash are not
// indexed, so a purge for "" is a no-op instead of deleting the mail of every
// sender that stamped no hash at all — which is what the scan it replaces did.
// No caller reaches it with one (the route requires a non-empty hash and the
// import path skips an empty tombstone), so this only closes the shape.
func (s *Store) purgeOwnerLocked(purgeHash string) (int, int) {
	owned := s.messagesByPurge[purgeHash]
	if len(owned) == 0 {
		return 0, 0
	}
	// Snapshot the ids: deleteMessageLocked mutates the set being ranged over.
	purgedMessageIDs := make([]string, 0, len(owned))
	for id := range owned {
		purgedMessageIDs = append(purgedMessageIDs, id)
	}
	messages, acks := 0, 0
	for _, id := range purgedMessageIDs {
		s.deleteMessageLocked(id)
		messages++
		for _, ackID := range s.ackIDsForMessageLocked(id) {
			s.deleteAckLocked(ackID)
			acks++
		}
	}
	return messages, acks
}

// ackIDsForMessageLocked copies out the ack ids naming a message, so a caller
// may delete them while walking.
func (s *Store) ackIDsForMessageLocked(messageID string) []string {
	naming := s.acksByMessage[messageID]
	if len(naming) == 0 {
		return nil
	}
	ids := make([]string, 0, len(naming))
	for id := range naming {
		ids = append(ids, id)
	}
	return ids
}

// indexAddLocked and indexRemoveLocked maintain a key → set-of-ids index. An
// empty key is never indexed, and a set is deleted with its last member so the
// index holds no key the record maps no longer justify.
func indexAddLocked(index map[string]map[string]struct{}, key, id string) {
	if key == "" || id == "" {
		return
	}
	ids, exists := index[key]
	if !exists {
		ids = make(map[string]struct{})
		index[key] = ids
	}
	ids[id] = struct{}{}
}

func indexRemoveLocked(index map[string]map[string]struct{}, key, id string) {
	ids, exists := index[key]
	if !exists {
		return
	}
	delete(ids, id)
	if len(ids) == 0 {
		delete(index, key)
	}
}

// externalAckCapacity is the occupancy ceiling for an ack a caller posted —
// POST /acks and the mesh import path. It leaves maxMessages entries of the
// lane free at all times, and a coupled ack is at most one per queued message,
// so the node's own acks always have room. See NewStore.
func (s *Store) externalAckCapacity() int { return s.maxAcks - s.maxMessages }

// addAckLocked inserts an ack against the whole lane. Only the coupled
// node_received ack minted inside AddMessageWithGrant may use it; every
// caller-posted ack goes through addExternalAckLocked.
func (s *Store) addAckLocked(ack model.AckRecord, now time.Time) error {
	return s.addAckWithinLocked(ack, now, s.maxAcks)
}

func (s *Store) addExternalAckLocked(ack model.AckRecord, now time.Time) error {
	return s.addAckWithinLocked(ack, now, s.externalAckCapacity())
}

func (s *Store) addAckWithinLocked(ack model.AckRecord, now time.Time, capacity int) error {
	if _, exists := s.acks[ack.ID]; exists {
		return ErrDuplicate
	}
	if len(s.acks) >= capacity {
		return ErrQueueFull
	}
	if ack.ExpiresAt.IsZero() {
		ack.ExpiresAt = now.Add(s.defaultTTL)
	}
	if !ack.ExpiresAt.After(now) {
		return ErrExpired
	}
	s.acks[ack.ID] = ack
	s.seq++
	s.ackSeq[ack.ID] = s.seq
	s.bindMessageTagLocked(ack.MessageID, ack.RecipientTag)
	indexAddLocked(s.acksByMessage, ack.MessageID, ack.ID)
	return nil
}

func (s *Store) importMessageLocked(envelope model.MessageEnvelope, now time.Time) error {
	envelope.ID = strings.TrimSpace(envelope.ID)
	envelope.Sender = strings.TrimSpace(envelope.Sender)
	envelope.Recipient = strings.TrimSpace(envelope.Recipient)
	envelope.EncryptedPayload = strings.TrimSpace(envelope.EncryptedPayload)

	if envelope.ID == "" || envelope.Sender == "" || envelope.Recipient == "" || envelope.EncryptedPayload == "" {
		return ErrInvalid
	}
	if len(envelope.EncryptedPayload) > s.maxPayloadBytes {
		return ErrPayloadTooLarge
	}
	if envelope.CreatedAt.IsZero() {
		envelope.CreatedAt = now
	}
	if envelope.ExpiresAt.IsZero() {
		envelope.ExpiresAt = now.Add(s.defaultTTL)
	}
	if maxExpiry := now.Add(s.maxTTL); envelope.ExpiresAt.After(maxExpiry) {
		envelope.ExpiresAt = maxExpiry
	}
	if !envelope.ExpiresAt.After(now) {
		return ErrExpired
	}
	if _, exists := s.messages[envelope.ID]; exists {
		return ErrDuplicate
	}
	if purgeHash := envelope.Metadata["purgeHash"]; purgeHash != "" {
		if purge, exists := s.purges[purgeHash]; exists && purge.ExpiresAt.After(now) {
			return ErrDuplicate
		}
	}
	if s.hasTerminalAckLocked(envelope.ID) {
		return ErrDuplicate
	}
	if len(s.messages) >= s.maxMessages {
		return ErrQueueFull
	}
	// A replicated envelope is charged to nobody. The relay that accepted it from
	// its sender already charged that circle's slots, and a pool member cannot
	// know which credential that was — attribution is a per-boot index, which is
	// meaningless on another box and is deliberately never put on the wire.
	// Occupancy is therefore counted once, where the sale is.
	s.addMessageLocked(envelope, 0)
	return nil
}

func (s *Store) importAckLocked(ack model.AckRecord, now time.Time) error {
	ack.ID = strings.TrimSpace(ack.ID)
	ack.MessageID = strings.TrimSpace(ack.MessageID)
	ack.Sender = strings.TrimSpace(ack.Sender)
	ack.Recipient = strings.TrimSpace(ack.Recipient)
	ack.Reason = boundedAckReason(ack.Reason)

	if ack.ID == "" || ack.MessageID == "" || ack.Sender == "" || ack.Recipient == "" || !validAckType(ack.Type) {
		return ErrInvalid
	}
	if ack.CreatedAt.IsZero() {
		ack.CreatedAt = now
	}
	if ack.ExpiresAt.IsZero() {
		ack.ExpiresAt = now.Add(s.defaultTTL)
	}
	// No grant travels with a replicated record — the credential index is a
	// per-boot number that means nothing on another box — so the box ceiling is
	// the only clamp available here, and it is the one that matters: a peer's
	// accepted ack must not outlive what this node is willing to hold.
	if maxExpiry := now.Add(s.maxTTL); ack.ExpiresAt.After(maxExpiry) {
		ack.ExpiresAt = maxExpiry
	}
	if !ack.ExpiresAt.After(now) {
		return ErrExpired
	}
	if _, exists := s.acks[ack.ID]; exists {
		return ErrDuplicate
	}
	if err := s.addExternalAckLocked(ack, now); err != nil {
		return err
	}
	if deletesQueuedMessage(ack.Type) {
		s.deleteMessageLocked(ack.MessageID)
	}
	return nil
}

func (s *Store) hasTerminalAckLocked(messageID string) bool {
	for id := range s.acksByMessage[messageID] {
		if deletesQueuedMessage(s.acks[id].Type) {
			return true
		}
	}
	return false
}

func (s *Store) nodeReceivedAck(envelope model.MessageEnvelope, nodeID string, now time.Time) model.AckRecord {
	return model.AckRecord{
		ID:        envelope.ID + ":node_received",
		MessageID: envelope.ID,
		Sender:    envelope.Sender,
		Recipient: envelope.Recipient,
		Type:      model.AckNodeReceived,
		CreatedAt: now,
		ExpiresAt: envelope.ExpiresAt,
		NodeID:    nodeID,
		// Carry the sender's read-authorization tag onto the ack it will come
		// back for. Without this the node would mint an ack its own sender
		// could not fetch once enforcement is on.
		SenderTag: envelope.SenderTag,
		// And the recipient's, which is not read authorization but write
		// authorization: this ack outlives the envelope, so it is what a later
		// caller-posted ack for the same message is proved against once a
		// terminal ack has deleted the envelope itself.
		RecipientTag: envelope.RecipientTag,
	}
}

// pairKey identifies a (sender→recipient) lane for the per-pair backlog quota.
// The NUL separator can't appear in a trimmed routing id, so distinct pairs
// never collide.
func pairKey(sender, recipient string) string {
	return sender + "\x00" + recipient
}

// tagBinding is one message id's write authorization: the recipient tag records
// naming it are proved against, and how many live records still name it.
//
// An empty tag is a real binding — the message came from a client that predates
// fetch auth — and Auth.permits already decides what that is worth in each mode.
// It is the only value that may be replaced: an ack for a message this relay had
// not yet seen binds "" first, and the envelope's own tag supersedes it when the
// message arrives. A non-empty tag is never overwritten, so nothing a caller
// posts can loosen the proof another record already established.
type tagBinding struct {
	tag     string
	records int
}

// bindMessageTagLocked adds one record to a message id's binding.
func (s *Store) bindMessageTagLocked(messageID, tag string) {
	if messageID == "" {
		return
	}
	binding := s.messageTags[messageID]
	binding.records++
	if binding.tag == "" {
		binding.tag = tag
	}
	s.messageTags[messageID] = binding
}

// releaseMessageTagLocked drops one record from a message id's binding, and the
// binding itself once nothing names it any more.
func (s *Store) releaseMessageTagLocked(messageID string) {
	binding, exists := s.messageTags[messageID]
	if !exists {
		return
	}
	if binding.records <= 1 {
		delete(s.messageTags, messageID)
		return
	}
	binding.records--
	s.messageTags[messageID] = binding
}

// addMessageLocked is the single insertion point for the message map; it keeps
// the per-pair and per-credential counters in lock-step. Callers must already
// hold the lock and have rejected duplicates.
func (s *Store) addMessageLocked(envelope model.MessageEnvelope, credential uint32) {
	s.messages[envelope.ID] = envelope
	s.pairCounts[pairKey(envelope.Sender, envelope.Recipient)]++
	if credential != 0 {
		s.credentialCounts[credential]++
		s.messageCredential[envelope.ID] = credential
	}
	s.seq++
	s.messageSeq[envelope.ID] = s.seq
	s.bindMessageTagLocked(envelope.ID, envelope.RecipientTag)
	indexAddLocked(s.messagesByPurge, envelope.Metadata["purgeHash"], envelope.ID)
}

// deleteMessageLocked is the single deletion point for the message map; it keeps
// the per-pair and per-credential counters in lock-step. Safe to call with an id
// that isn't present (acks routinely target messages this node never queued).
//
// Every way an envelope can leave the queue funnels through here — delivered,
// read, expired, purged, retracted — which is what makes "decremented on
// delivery or expiry" a property of the code rather than of a list of call
// sites someone has to keep complete.
func (s *Store) deleteMessageLocked(id string) {
	envelope, exists := s.messages[id]
	if !exists {
		return
	}
	delete(s.messages, id)
	delete(s.messageSeq, id)
	s.releaseMessageTagLocked(id)
	indexRemoveLocked(s.messagesByPurge, envelope.Metadata["purgeHash"], id)
	key := pairKey(envelope.Sender, envelope.Recipient)
	if s.pairCounts[key] <= 1 {
		delete(s.pairCounts, key)
	} else {
		s.pairCounts[key]--
	}
	if credential, charged := s.messageCredential[id]; charged {
		delete(s.messageCredential, id)
		if s.credentialCounts[credential] <= 1 {
			delete(s.credentialCounts, credential)
		} else {
			s.credentialCounts[credential]--
		}
	}
}

// Occupancy is how many undelivered envelopes a credential is holding. For
// tests and for the load harness; nothing publishes it, and /health in
// particular does not — a circle's usage figure is answerable to that circle,
// not to an unauthenticated endpoint.
func (s *Store) Occupancy(credential uint32) int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.credentialCounts[credential]
}

// deleteAckLocked is the single deletion point for the ack map, for the same
// reason deleteMessageLocked is one for messages: the replication cursor map has
// to be kept in lock-step or it grows without bound.
func (s *Store) deleteAckLocked(id string) {
	ack, exists := s.acks[id]
	if !exists {
		return
	}
	delete(s.acks, id)
	delete(s.ackSeq, id)
	s.releaseMessageTagLocked(ack.MessageID)
	indexRemoveLocked(s.acksByMessage, ack.MessageID, id)
}

func (s *Store) statsLocked() Stats {
	return Stats{Messages: len(s.messages), Acks: len(s.acks), Purges: len(s.purges)}
}

// MaxAckReasonBytes bounds the opaque rejection marker an ack may carry. The
// markers the client mints are short constants; anything longer is a client
// trying to use the ack lane for storage, and is dropped rather than refused —
// losing the reason costs the sender a sentence, losing the ack would leave the
// message it rejects sitting in the queue.
const MaxAckReasonBytes = 64

func boundedAckReason(reason string) string {
	reason = strings.TrimSpace(reason)
	if len(reason) > MaxAckReasonBytes {
		return ""
	}
	return reason
}

func validAckType(ackType model.AckType) bool {
	switch ackType {
	case model.AckNodeReceived, model.AckRecipientDeviceReceived, model.AckRecipientRead, model.AckExpired, model.AckRejected, model.AckRetractionApplied:
		return true
	default:
		return false
	}
}

func deletesQueuedMessage(ackType model.AckType) bool {
	switch ackType {
	case model.AckRecipientDeviceReceived, model.AckRecipientRead, model.AckExpired, model.AckRejected, model.AckRetractionApplied:
		return true
	default:
		return false
	}
}
