package attachment

import (
	"errors"
	"strings"
	"sync"
	"time"
)

var (
	ErrDuplicate        = errors.New("duplicate attachment chunk")
	ErrWindowFull       = errors.New("attachment relay window is full")
	ErrTooManySessions  = errors.New("attachment relay session limit reached")
	ErrInvalid          = errors.New("attachment chunk is invalid")
	ErrTooLarge         = errors.New("attachment exceeds this relay's size ceiling")
	ErrTransitExhausted = errors.New("this circle's daily transit ceiling is spent")
	ErrTooManyChunks    = errors.New("attachment is split into more chunks than this relay carries")
)

// maxChunksPerTransfer is how many chunk indices one transfer may span. It
// exists so that what a live session remembers in order to refuse a replay is
// bounded by a number this relay picked, rather than by how finely a sender
// chose to slice its file — the whole-transfer byte ceiling cannot do that job,
// because it is spent by one 50 MB chunk and by five million ten-byte ones
// alike.
//
// Deliberately a constant and not a knob. On any configuration this relay will
// actually accept, the byte ceiling binds long first: the client sends 512 KB
// plaintext chunks that encrypt and base64 to roughly 700 KB, so a 50 MB
// attachment spans about 73 indices and a sender would have to slice a
// full-size attachment into 6 KB pieces to reach this. A sender that does is
// refused (ErrTooManyChunks) rather than the box paying for it.
//
// deploy/memory-ceiling.sh counts maxSessions x this / 8 bytes and names the
// constant: the same standing obligation as the presence store's 5000 — if this
// number moves, that line moves with it.
const maxChunksPerTransfer = 8192

// Grant is the admitted credential's authority over one push, resolved by the
// httpapi layer from internal/admission and handed down as plain numbers. The
// zero value is an unattributed push — an open box, or a relay loaded with
// credentials but not enforcing — and gets the box's own caps.
//
// Credential is a per-boot integer, never the credential itself: the strongest
// thing this package can build out of it is a count and a byte total per
// circle, never a set of what was seen under it. That is the whole rule.
type Grant struct {
	Credential uint32
	// AttachmentBytes lowers the whole-transfer ceiling for this circle.
	AttachmentBytes int
	// ConcurrentTransfers caps this circle's live sessions.
	ConcurrentTransfers int
	// TransitBytesPerDay is a rolling 24-hour ceiling on bytes this circle pushes
	// through the relay.
	TransitBytesPerDay int64
}

// lowerOf resolves a box cap against a credential's: zero means the box's own
// cap, and a credential may only ever lower one. Deliberately duplicated from
// internal/queue rather than shared, so that each package's own caps stay the
// authority on what that package will accept.
func lowerOf(box, credential int) int {
	if credential <= 0 || credential > box {
		return box
	}
	return credential
}

// Chunk is one encrypted slice of an attachment in flight between two
// simultaneously connected peers. The node never reads the payload (it is
// AES/XChaCha ciphertext) and never persists it: a chunk lives only between the
// sender's POST and the recipient's next drain. CreatedAt/ExpiresAt are accepted
// for wire-compatibility with older clients but carry no retention meaning — the
// relay has no TTL.
type Chunk struct {
	ID               string    `json:"id"`
	TransferID       string    `json:"transferId"`
	Capability       string    `json:"capability"`
	Recipient        string    `json:"recipient"`
	Index            int       `json:"index"`
	TotalChunks      int       `json:"totalChunks"`
	EncryptedPayload string    `json:"encryptedPayload"`
	SizeBytes        int       `json:"sizeBytes"`
	CreatedAt        time.Time `json:"createdAt"`
	ExpiresAt        time.Time `json:"expiresAt"`
}

// Stats reports what the relay is currently holding in flight. With a
// store-and-forward queue this used to grow to the whole backlog; here it is
// bounded by maxWindow per active session and drops to zero as transfers drain.
type Stats struct {
	Sessions int `json:"sessions"`
	Chunks   int `json:"chunks"`
	Bytes    int `json:"bytes"`
}

// session is one live transfer. It is keyed by its per-transfer capability (an
// opaque secret unique to the transfer), which both peers learn from the offer
// envelope. It holds at most maxWindow chunks; a sender that races ahead of the
// recipient is back-pressured (ErrWindowFull) rather than allowed to buffer the
// whole file on the node.
type session struct {
	transferID string
	capability string
	recipient  string
	window     []Chunk
	bytes      int
	// totalChunks is the index space this transfer declared on its first chunk,
	// pinned for the life of the session. A sender that re-declares it mid-stream
	// is malformed, and honouring the second figure would mean resizing seen from
	// an untrusted number.
	totalChunks int
	// seen is a bitmap over [0, totalChunks) of the indices this transfer has
	// accepted, so a replay of a chunk already drained out of the window is
	// refused rather than delivered twice. Keyed by index and not by the sender's
	// chunk id: a set of ids is bounded only by how long the sender makes them,
	// while an index is a bit, and the recipient reassembles by index anyway.
	seen         []uint64
	lastActivity time.Time

	// credential is the per-boot index of the circle this transfer is charged
	// to, or zero for an unattributed push. It is set from the first chunk and
	// never changes: a transfer belongs to one circle, and re-charging it
	// mid-stream would be a way to spend two circles' allowances on one file.
	credential uint32

	// pushedBytes is every distinct chunk this transfer has ever pushed, not just
	// what is in the window right now. `bytes` drops back to zero on each drain,
	// so it can never express a whole-attachment ceiling: a sender streaming a
	// 4 GB file eight chunks at a time never exceeds the window even once.
	pushedBytes int
}

// Relay is a presence-gated live pass-through for attachment bytes. It replaces
// the old store-and-forward map: nothing is retained at rest, there is no TTL,
// and the chunk bytes in flight are bounded by maxWindow * maxSessions.
//
// Beside those bytes a session keeps one bit per chunk index it has accepted,
// so that a replay of a chunk already drained is refused rather than delivered
// twice. That set is bounded too — by maxChunksPerTransfer, which is why a
// transfer declaring more indices than that is refused — so the footprint
// deploy/memory-ceiling.sh derives is the whole footprint.
type Relay struct {
	mu sync.Mutex

	maxWindow          int
	maxChunkBytes      int
	maxAttachmentBytes int
	maxSessions        int
	idleTimeout        time.Duration
	now                func() time.Time
	sessions           map[string]*session

	// transit is the rolling 24-hour byte total per circle. A number per
	// credential and nothing else — no record of which transfers, which
	// recipients, or when beyond the hour bucket the bytes landed in.
	transit map[uint32]*transitWindow
}

// transitWindow is 24 hourly buckets, so the ceiling rolls rather than resetting
// on a fixed boundary that a sender could simply wait for. Hour granularity is
// the honest resolution: it is a circuit breaker sized at 50 GB/day,
// roughly five hundred 100 MB files, not a meter anyone is billed from.
type transitWindow struct {
	bytes [24]int64
	hour  [24]int64
}

func (w *transitWindow) add(now time.Time, n int64) {
	hour := now.Unix() / 3600
	slot := hour % 24
	if w.hour[slot] != hour {
		w.hour[slot] = hour
		w.bytes[slot] = 0
	}
	w.bytes[slot] += n
}

func (w *transitWindow) total(now time.Time) int64 {
	oldest := now.Unix()/3600 - 23
	var sum int64
	for slot := range w.bytes {
		if w.hour[slot] >= oldest {
			sum += w.bytes[slot]
		}
	}
	return sum
}

// NewRelay builds a relay. maxWindow caps in-flight chunks per transfer,
// maxAttachmentBytes caps a whole transfer (the figure published on /health),
// maxSessions caps concurrent transfers, idleTimeout drops a session whose peers
// have gone quiet (e.g. one disconnected) so no window lingers.
func NewRelay(maxWindow, maxChunkBytes, maxAttachmentBytes, maxSessions int, idleTimeout time.Duration, now func() time.Time) *Relay {
	if maxWindow <= 0 {
		maxWindow = 8
	}
	if maxChunkBytes <= 0 {
		maxChunkBytes = 1024 * 1024
	}
	if maxAttachmentBytes <= 0 {
		maxAttachmentBytes = 50 * 1024 * 1024
	}
	if maxSessions <= 0 {
		maxSessions = 256
	}
	if idleTimeout <= 0 {
		idleTimeout = 30 * time.Second
	}
	if now == nil {
		now = time.Now
	}
	return &Relay{
		maxWindow:          maxWindow,
		maxChunkBytes:      maxChunkBytes,
		maxAttachmentBytes: maxAttachmentBytes,
		maxSessions:        maxSessions,
		idleTimeout:        idleTimeout,
		now:                now,
		sessions:           make(map[string]*session),
		transit:            make(map[uint32]*transitWindow),
	}
}

// MaxAttachmentBytes is the whole-transfer ceiling this relay enforces. It is
// published on /health so a client can size its own send guard to the relay it
// is actually pointed at instead of to a constant compiled into the app.
func (r *Relay) MaxAttachmentBytes() int { return r.maxAttachmentBytes }

// Push adds one chunk with no credential attached: the box's caps apply and
// nothing is charged to a circle. The public push path uses PushWithGrant.
func (r *Relay) Push(chunk Chunk) error {
	return r.PushWithGrant(chunk, Grant{})
}

// PushWithGrant adds one chunk to its transfer's in-flight window, against an
// admitted credential's terms. It returns ErrWindowFull when the window is
// already full (the sender must wait for the recipient to drain), ErrDuplicate
// for a chunk already in flight or drained, ErrTooManySessions when the
// concurrent-transfer cap is reached — the box's or the circle's —
// ErrTooManyChunks when the transfer declares more chunk indices than
// maxChunksPerTransfer, and ErrTransitExhausted when the circle has spent its
// rolling daily ceiling.
func (r *Relay) PushWithGrant(chunk Chunk, grant Grant) error {
	now := r.now().UTC()
	chunk.ID = strings.TrimSpace(chunk.ID)
	chunk.TransferID = strings.TrimSpace(chunk.TransferID)
	chunk.Capability = strings.TrimSpace(chunk.Capability)
	chunk.Recipient = strings.TrimSpace(chunk.Recipient)
	chunk.EncryptedPayload = strings.TrimSpace(chunk.EncryptedPayload)
	if chunk.ID == "" || chunk.TransferID == "" || chunk.Capability == "" ||
		chunk.Recipient == "" || chunk.EncryptedPayload == "" ||
		chunk.Index < 0 || chunk.TotalChunks <= 0 || chunk.Index >= chunk.TotalChunks ||
		chunk.SizeBytes <= 0 || chunk.SizeBytes > r.maxChunkBytes {
		return ErrInvalid
	}
	// The chunk cap has to be measured on the bytes the relay is about to hold,
	// not on the sender's word for how many there are. SizeBytes is a field in
	// an untrusted request; checking it alone let a sender declare 8 KiB and
	// attach 50 MB, which is how the memory ceiling
	// (sessions x window x maxChunkBytes) stopped being a ceiling.
	payloadBytes := len(chunk.EncryptedPayload)
	if payloadBytes > r.maxChunkBytes {
		return ErrInvalid
	}
	// Checked before the session map is touched, so an over-sliced transfer never
	// occupies a session slot and never sizes a bitmap from its own declaration.
	if chunk.TotalChunks > maxChunksPerTransfer {
		return ErrTooManyChunks
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	r.sweepLocked(now)

	sess := r.sessions[chunk.Capability]
	if sess == nil {
		if len(r.sessions) >= r.maxSessions {
			return ErrTooManySessions
		}
		// The circle's own live-transfer allowance, checked at the same point as
		// the box's and answered the same way. A fairness cap: it exists so one
		// circle cannot take the box, and the sender's remedy — wait and retry —
		// is identical, which is why it is not a distinct error.
		if grant.Credential != 0 && grant.ConcurrentTransfers > 0 &&
			r.sessionsForLocked(grant.Credential) >= lowerOf(r.maxSessions, grant.ConcurrentTransfers) {
			return ErrTooManySessions
		}
		sess = &session{
			transferID:   chunk.TransferID,
			capability:   chunk.Capability,
			recipient:    chunk.Recipient,
			totalChunks:  chunk.TotalChunks,
			seen:         make([]uint64, (chunk.TotalChunks+63)/64),
			lastActivity: now,
			credential:   grant.Credential,
		}
		r.sessions[chunk.Capability] = sess
	}
	// A capability is per-transfer; a mismatched transfer/recipient/chunk count on
	// the same capability is a malformed or hostile request.
	if sess.transferID != chunk.TransferID || sess.recipient != chunk.Recipient ||
		sess.totalChunks != chunk.TotalChunks {
		return ErrInvalid
	}
	word, bit := chunk.Index/64, uint(chunk.Index%64)
	if sess.seen[word]&(1<<bit) != 0 {
		return ErrDuplicate
	}
	if len(sess.window) >= r.maxWindow {
		return ErrWindowFull
	}
	// The rolling daily ceiling, charged to the circle that opened the transfer
	// rather than to the one presenting this chunk — the two are the same in
	// practice, and pinning it to the session is what stops a second credential
	// being used to top up a transfer already at its limit.
	if sess.credential != 0 && grant.TransitBytesPerDay > 0 {
		window := r.transit[sess.credential]
		if window != nil && window.total(now)+int64(payloadBytes) > grant.TransitBytesPerDay {
			return ErrTransitExhausted
		}
	}
	// Measured on the real payload and on every chunk the transfer has ever
	// pushed, for the same reason the per-chunk cap is: TotalChunks is the
	// sender's word, and a sender willing to lie about it is exactly the one this
	// ceiling is for. Refusing here rather than at chunk 0 costs the honest
	// sender nothing — the client's own guard stops it before the first push.
	if sess.pushedBytes+payloadBytes > lowerOf(r.maxAttachmentBytes, grant.AttachmentBytes) {
		return ErrTooLarge
	}
	sess.window = append(sess.window, chunk)
	// Account the real length too: Stats.Bytes is what monitoring watches for
	// memory pressure, and a self-declared size would let a hostile sender
	// occupy the window while reporting almost nothing.
	sess.bytes += payloadBytes
	sess.pushedBytes += payloadBytes
	sess.seen[word] |= 1 << bit
	sess.lastActivity = now
	if sess.credential != 0 {
		window := r.transit[sess.credential]
		if window == nil {
			window = &transitWindow{}
			r.transit[sess.credential] = window
		}
		window.add(now, int64(payloadBytes))
	}
	return nil
}

// sessionsForLocked counts a circle's live transfers. A scan rather than a
// counter: the session map is bounded by maxSessions (16 on the sized VPS, 256
// at the defaults) and this runs only when a transfer opens.
func (r *Relay) sessionsForLocked(credential uint32) int {
	count := 0
	for _, sess := range r.sessions {
		if sess.credential == credential {
			count++
		}
	}
	return count
}

// TransitToday is a circle's rolling 24-hour byte total. For tests and the load
// harness; nothing publishes it.
func (r *Relay) TransitToday(credential uint32) int64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	window := r.transit[credential]
	if window == nil {
		return 0
	}
	return window.total(r.now().UTC())
}

// Drain hands the recipient every chunk currently buffered for its transfer and
// clears the window so the sender can push more. It returns nil if no live
// transfer matches recipient+capability. The chunks' IDs stay remembered so a
// sender re-POSTing an already-delivered chunk is rejected as a duplicate rather
// than re-buffered.
func (r *Relay) Drain(recipient, capability string) []Chunk {
	recipient = strings.TrimSpace(recipient)
	capability = strings.TrimSpace(capability)
	if recipient == "" || capability == "" {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.sweepLocked(r.now().UTC())

	sess := r.sessions[capability]
	if sess == nil || sess.recipient != recipient || len(sess.window) == 0 {
		return nil
	}
	out := sess.window
	sess.window = nil
	sess.bytes = 0
	sess.lastActivity = r.now().UTC()
	return out
}

// Complete tears down a transfer's session once the recipient has the whole
// file. It returns the number of chunks that were still in flight (normally 0).
func (r *Relay) Complete(transferID, capability string) int {
	transferID = strings.TrimSpace(transferID)
	capability = strings.TrimSpace(capability)
	r.mu.Lock()
	defer r.mu.Unlock()
	sess := r.sessions[capability]
	if sess == nil || sess.transferID != transferID {
		return 0
	}
	inFlight := len(sess.window)
	delete(r.sessions, capability)
	return inFlight
}

// Prune drops idle sessions and spent transit windows, and reports the live
// footprint.
func (r *Relay) Prune() Stats {
	now := r.now().UTC()
	r.mu.Lock()
	defer r.mu.Unlock()
	r.sweepLocked(now)
	// Transit windows are pruned here rather than in sweepLocked because
	// sweepLocked runs on every chunk push and this is a per-credential walk.
	// A circle that has sent nothing for a day holds no bytes worth remembering.
	for credential, window := range r.transit {
		if window.total(now) == 0 {
			delete(r.transit, credential)
		}
	}
	return r.statsLocked()
}

// Stats reports the current in-flight footprint after pruning idle sessions.
func (r *Relay) Stats() Stats {
	return r.Prune()
}

func (r *Relay) statsLocked() Stats {
	stats := Stats{Sessions: len(r.sessions)}
	for _, sess := range r.sessions {
		stats.Chunks += len(sess.window)
		stats.Bytes += sess.bytes
	}
	return stats
}

func (r *Relay) sweepLocked(now time.Time) {
	for key, sess := range r.sessions {
		if now.Sub(sess.lastActivity) > r.idleTimeout {
			delete(r.sessions, key)
		}
	}
}
