package attachment

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func sampleChunk(id string, index, total int) Chunk {
	return Chunk{
		ID:               id,
		TransferID:       "transfer-1",
		Capability:       "opaque-secret",
		Recipient:        "bob",
		Index:            index,
		TotalChunks:      total,
		EncryptedPayload: "cipher12",
		SizeBytes:        8,
	}
}

func TestRelayPassesChunksThroughAndRetainsNothing(t *testing.T) {
	now := time.Date(2026, 6, 7, 12, 0, 0, 0, time.UTC)
	relay := NewRelay(4, 8, 0, 16, time.Minute, func() time.Time { return now })

	if err := relay.Push(sampleChunk("chunk-0", 0, 2)); err != nil {
		t.Fatalf("Push(0) returned error: %v", err)
	}
	if err := relay.Push(sampleChunk("chunk-1", 1, 2)); err != nil {
		t.Fatalf("Push(1) returned error: %v", err)
	}
	// Wrong recipient sees nothing; wrong capability sees nothing.
	if got := relay.Drain("mallory", "opaque-secret"); got != nil {
		t.Fatalf("wrong recipient drained chunks: %#v", got)
	}
	if got := relay.Drain("bob", "wrong"); got != nil {
		t.Fatalf("wrong capability drained chunks: %#v", got)
	}

	got := relay.Drain("bob", "opaque-secret")
	if len(got) != 2 {
		t.Fatalf("drained %d chunks, want 2", len(got))
	}
	// After a drain the window is empty: the relay holds nothing at rest.
	if stats := relay.Stats(); stats.Chunks != 0 || stats.Bytes != 0 {
		t.Fatalf("stats after drain = %#v, want zero chunks/bytes", stats)
	}
	// A second drain returns nothing — the window was handed off in one shot.
	if got := relay.Drain("bob", "opaque-secret"); got != nil {
		t.Fatalf("second drain returned chunks: %#v", got)
	}
}

func TestRelayWindowBackPressuresUntilDrained(t *testing.T) {
	now := time.Date(2026, 6, 7, 12, 0, 0, 0, time.UTC)
	relay := NewRelay(2, 8, 0, 16, time.Minute, func() time.Time { return now })

	if err := relay.Push(sampleChunk("chunk-0", 0, 4)); err != nil {
		t.Fatalf("Push(0): %v", err)
	}
	if err := relay.Push(sampleChunk("chunk-1", 1, 4)); err != nil {
		t.Fatalf("Push(1): %v", err)
	}
	// Window of 2 is full — the sender is back-pressured, not allowed to buffer
	// the whole file on the node.
	if err := relay.Push(sampleChunk("chunk-2", 2, 4)); !errors.Is(err, ErrWindowFull) {
		t.Fatalf("Push(2) error = %v, want ErrWindowFull", err)
	}
	// Recipient drains, freeing the window; the sender can now continue.
	if got := relay.Drain("bob", "opaque-secret"); len(got) != 2 {
		t.Fatalf("drained %d, want 2", len(got))
	}
	if err := relay.Push(sampleChunk("chunk-2", 2, 4)); err != nil {
		t.Fatalf("Push(2) after drain: %v", err)
	}
}

func TestRelayDedupesAndRejectsRepostOfDrainedChunk(t *testing.T) {
	now := time.Date(2026, 6, 7, 12, 0, 0, 0, time.UTC)
	relay := NewRelay(4, 8, 0, 16, time.Minute, func() time.Time { return now })

	if err := relay.Push(sampleChunk("chunk-0", 0, 2)); err != nil {
		t.Fatalf("Push(0): %v", err)
	}
	if err := relay.Push(sampleChunk("chunk-0", 0, 2)); !errors.Is(err, ErrDuplicate) {
		t.Fatalf("duplicate in-window error = %v, want ErrDuplicate", err)
	}
	relay.Drain("bob", "opaque-secret")
	// Even after delivery, re-posting the same chunk id is a duplicate, not a
	// re-buffer.
	if err := relay.Push(sampleChunk("chunk-0", 0, 2)); !errors.Is(err, ErrDuplicate) {
		t.Fatalf("duplicate post-drain error = %v, want ErrDuplicate", err)
	}
}

func TestRelayCompleteTearsDownSession(t *testing.T) {
	now := time.Date(2026, 6, 7, 12, 0, 0, 0, time.UTC)
	relay := NewRelay(4, 8, 0, 16, time.Minute, func() time.Time { return now })

	_ = relay.Push(sampleChunk("chunk-0", 0, 2))
	if removed := relay.Complete("transfer-1", "opaque-secret"); removed != 1 {
		t.Fatalf("Complete removed = %d, want 1 in-flight", removed)
	}
	if stats := relay.Stats(); stats.Sessions != 0 || stats.Chunks != 0 {
		t.Fatalf("stats after complete = %#v, want zero", stats)
	}
	// Completing an unknown transfer is a no-op.
	if removed := relay.Complete("transfer-1", "opaque-secret"); removed != 0 {
		t.Fatalf("Complete on torn-down session = %d, want 0", removed)
	}
}

func TestRelayDropsIdleSessionWindow(t *testing.T) {
	now := time.Date(2026, 6, 7, 12, 0, 0, 0, time.UTC)
	relay := NewRelay(4, 8, 0, 16, time.Minute, func() time.Time { return now })

	if err := relay.Push(sampleChunk("chunk-0", 0, 2)); err != nil {
		t.Fatalf("Push(0): %v", err)
	}
	// One peer disconnects: no drain, no push. After the idle timeout the whole
	// in-flight window is dropped — nothing lingers on the node.
	now = now.Add(2 * time.Minute)
	if stats := relay.Prune(); stats.Sessions != 0 || stats.Chunks != 0 || stats.Bytes != 0 {
		t.Fatalf("stats after idle = %#v, want zero", stats)
	}
}

func TestRelayConcurrentTransfersAreIsolated(t *testing.T) {
	now := time.Date(2026, 6, 7, 12, 0, 0, 0, time.UTC)
	relay := NewRelay(4, 8, 0, 16, time.Minute, func() time.Time { return now })

	a := sampleChunk("a-0", 0, 1)
	b := Chunk{ID: "b-0", TransferID: "transfer-2", Capability: "other-secret", Recipient: "carol", Index: 0, TotalChunks: 1, EncryptedPayload: "cipher12", SizeBytes: 8}
	if err := relay.Push(a); err != nil {
		t.Fatalf("Push(a): %v", err)
	}
	if err := relay.Push(b); err != nil {
		t.Fatalf("Push(b): %v", err)
	}
	if got := relay.Drain("bob", "opaque-secret"); len(got) != 1 || got[0].ID != "a-0" {
		t.Fatalf("transfer A drain = %#v, want a-0 only", got)
	}
	if got := relay.Drain("carol", "other-secret"); len(got) != 1 || got[0].ID != "b-0" {
		t.Fatalf("transfer B drain = %#v, want b-0 only", got)
	}
}

func TestRelayRejectsCapabilityReuseAcrossTransfers(t *testing.T) {
	now := time.Date(2026, 6, 7, 12, 0, 0, 0, time.UTC)
	relay := NewRelay(4, 8, 0, 16, time.Minute, func() time.Time { return now })

	if err := relay.Push(sampleChunk("chunk-0", 0, 2)); err != nil {
		t.Fatalf("Push(0): %v", err)
	}
	hijack := sampleChunk("chunk-x", 0, 2)
	hijack.TransferID = "transfer-evil"
	if err := relay.Push(hijack); !errors.Is(err, ErrInvalid) {
		t.Fatalf("capability reuse error = %v, want ErrInvalid", err)
	}
}

func TestRelayEnforcesSessionCap(t *testing.T) {
	now := time.Date(2026, 6, 7, 12, 0, 0, 0, time.UTC)
	relay := NewRelay(4, 8, 0, 1, time.Minute, func() time.Time { return now })

	if err := relay.Push(sampleChunk("chunk-0", 0, 1)); err != nil {
		t.Fatalf("Push(0): %v", err)
	}
	second := Chunk{ID: "s-0", TransferID: "transfer-2", Capability: "cap-2", Recipient: "carol", Index: 0, TotalChunks: 1, EncryptedPayload: "cipher12", SizeBytes: 8}
	if err := relay.Push(second); !errors.Is(err, ErrTooManySessions) {
		t.Fatalf("session cap error = %v, want ErrTooManySessions", err)
	}
}

func TestRelayRejectsOversizeChunk(t *testing.T) {
	now := time.Date(2026, 6, 7, 12, 0, 0, 0, time.UTC)
	relay := NewRelay(4, 8, 0, 16, time.Minute, func() time.Time { return now })

	big := sampleChunk("chunk-0", 0, 1)
	big.SizeBytes = 9 // exceeds maxChunkBytes of 8
	if err := relay.Push(big); !errors.Is(err, ErrInvalid) {
		t.Fatalf("oversize error = %v, want ErrInvalid", err)
	}
}

// A sender that lies about SizeBytes used to walk straight past the chunk cap,
// because the cap was checked against the claim and never against the payload.
// The memory ceiling in deploy/memory-ceiling.sh is sessions x window x
// maxChunkBytes, so this was the difference between a derived ceiling and a
// decorative one: 16 x 4 x "whatever the sender sends".
func TestRelayRejectsUnderDeclaredOversizePayload(t *testing.T) {
	now := time.Date(2026, 6, 7, 12, 0, 0, 0, time.UTC)
	relay := NewRelay(4, 8, 0, 16, time.Minute, func() time.Time { return now })

	liar := sampleChunk("chunk-0", 0, 1)
	liar.EncryptedPayload = strings.Repeat("x", 4096) // 512x the cap
	liar.SizeBytes = 1                                // ...declared as one byte
	if err := relay.Push(liar); !errors.Is(err, ErrInvalid) {
		t.Fatalf("under-declared oversize error = %v, want ErrInvalid", err)
	}
	if stats := relay.Stats(); stats.Bytes != 0 || stats.Chunks != 0 {
		t.Fatalf("rejected chunk still occupies the relay: %#v", stats)
	}
}

// Stats.Bytes is the monitoring signal for relay memory pressure, so it has to
// count bytes held rather than bytes claimed.
func TestRelayStatsCountActualPayloadBytes(t *testing.T) {
	now := time.Date(2026, 6, 7, 12, 0, 0, 0, time.UTC)
	relay := NewRelay(4, 8, 0, 16, time.Minute, func() time.Time { return now })

	chunk := sampleChunk("chunk-0", 0, 1)
	chunk.EncryptedPayload = "12345678" // 8 bytes, at the cap
	chunk.SizeBytes = 1                 // under-declared
	if err := relay.Push(chunk); err != nil {
		t.Fatalf("Push: %v", err)
	}
	if stats := relay.Stats(); stats.Bytes != 8 {
		t.Fatalf("Stats().Bytes = %d, want 8 (the payload, not the claim)", stats.Bytes)
	}
}

// The whole-transfer ceiling is the figure /health publishes and the app sizes
// its send guard from, so it has to survive the one thing the window cap cannot
// see: a sender that stays inside the window forever and simply keeps going.
func TestRelayRejectsTransferOverTheAttachmentCeiling(t *testing.T) {
	now := time.Date(2026, 6, 7, 12, 0, 0, 0, time.UTC)
	// 8-byte chunks, a 20-byte attachment ceiling: two chunks fit, the third does
	// not — and each one is drained before the next, so the window is empty every
	// time and only the cumulative count can refuse it.
	relay := NewRelay(4, 8, 20, 16, time.Minute, func() time.Time { return now })

	for index, id := range []string{"chunk-0", "chunk-1"} {
		if err := relay.Push(sampleChunk(id, index, 3)); err != nil {
			t.Fatalf("Push(%s): %v", id, err)
		}
		relay.Drain("bob", "opaque-secret")
	}
	if err := relay.Push(sampleChunk("chunk-2", 2, 3)); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("push past the ceiling = %v, want ErrTooLarge", err)
	}
	// Refused, not buffered: the relay is holding nothing for the transfer it
	// just declined.
	if stats := relay.Stats(); stats.Chunks != 0 {
		t.Fatalf("refused chunk still occupies the relay: %#v", stats)
	}
}

// A relay whose ceiling is left unset must behave exactly as the app's old
// hardcoded guard did, so an existing deployment that sets no new variable sees
// no change at all.
func TestRelayDefaultsToTheCeilingTheAppUsedToHardcode(t *testing.T) {
	relay := NewRelay(4, 8, 0, 16, time.Minute, nil)
	if got := relay.MaxAttachmentBytes(); got != 50*1024*1024 {
		t.Fatalf("MaxAttachmentBytes() = %d, want 50 MB", got)
	}
}

func TestRelayRefusesATransferSlicedPastTheIndexCeiling(t *testing.T) {
	now := time.Date(2026, 6, 7, 12, 0, 0, 0, time.UTC)
	relay := NewRelay(4, 8, 0, 16, time.Minute, func() time.Time { return now })

	if err := relay.Push(sampleChunk("chunk-0", 0, maxChunksPerTransfer)); err != nil {
		t.Fatalf("Push at the ceiling: %v", err)
	}
	over := sampleChunk("chunk-0", 0, maxChunksPerTransfer+1)
	over.Capability = "other-secret"
	over.TransferID = "transfer-2"
	if err := relay.Push(over); !errors.Is(err, ErrTooManyChunks) {
		t.Fatalf("Push one index past the ceiling = %v, want ErrTooManyChunks", err)
	}
	// Refused before the session map is touched: an over-sliced transfer must not
	// cost a session slot, which is the cheaper thing to take than the memory.
	if got := relay.Stats().Sessions; got != 1 {
		t.Fatalf("Sessions = %d, want 1 (the refused transfer opened none)", got)
	}
}

func TestRelayReplaySetIsBoundedByTheIndexCeiling(t *testing.T) {
	now := time.Date(2026, 6, 7, 12, 0, 0, 0, time.UTC)
	relay := NewRelay(4, 8, 0, 16, time.Minute, func() time.Time { return now })

	if err := relay.Push(sampleChunk("chunk-0", 0, maxChunksPerTransfer)); err != nil {
		t.Fatalf("Push: %v", err)
	}
	// The term deploy/memory-ceiling.sh counts: one bit per index a transfer may
	// span, and nothing that grows with the sender's chunk ids. If this stops
	// holding, the script's footprint stops being the whole footprint.
	sess := relay.sessions["opaque-secret"]
	if sess == nil {
		t.Fatal("no session for the pushed chunk")
	}
	if got, want := len(sess.seen)*8, maxChunksPerTransfer/8; got != want {
		t.Fatalf("replay set = %d bytes, want %d (maxChunksPerTransfer bits)", got, want)
	}
}

func TestRelayRemembersDrainedChunksByIndexNotByID(t *testing.T) {
	now := time.Date(2026, 6, 7, 12, 0, 0, 0, time.UTC)
	relay := NewRelay(4, 8, 0, 16, time.Minute, func() time.Time { return now })

	if err := relay.Push(sampleChunk("chunk-0", 0, 2)); err != nil {
		t.Fatalf("Push(0): %v", err)
	}
	relay.Drain("bob", "opaque-secret")
	// The same slice of the file under a fresh id is the same replay, and renaming
	// it must not buy a second delivery. The recipient reassembles by index, so
	// the index is what a session remembers.
	if err := relay.Push(sampleChunk("renamed", 0, 2)); !errors.Is(err, ErrDuplicate) {
		t.Fatalf("renamed replay of index 0 = %v, want ErrDuplicate", err)
	}
	if err := relay.Push(sampleChunk("chunk-1", 1, 2)); err != nil {
		t.Fatalf("Push(1) after the refused replay: %v", err)
	}
}

func TestRelayPinsTheDeclaredChunkCount(t *testing.T) {
	now := time.Date(2026, 6, 7, 12, 0, 0, 0, time.UTC)
	relay := NewRelay(4, 8, 0, 16, time.Minute, func() time.Time { return now })

	if err := relay.Push(sampleChunk("chunk-0", 0, 2)); err != nil {
		t.Fatalf("Push(0): %v", err)
	}
	// Re-declaring the index space mid-transfer would mean resizing the replay
	// set from an untrusted number, so it is malformed rather than honoured.
	if err := relay.Push(sampleChunk("chunk-1", 1, 4096)); !errors.Is(err, ErrInvalid) {
		t.Fatalf("re-declared totalChunks = %v, want ErrInvalid", err)
	}
}
