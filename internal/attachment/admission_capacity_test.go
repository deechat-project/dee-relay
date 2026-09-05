package attachment

import (
	"strings"
	"testing"
	"time"
)

// The three attachment dimensions a credential carries.
// The whole-transfer ceiling is the one that is sold; concurrent transfers and
// the daily transit ceiling are fairness caps — published in the terms so
// nothing is secret, never a headline.

func grantedChunk(id string, index int, payload string) Chunk {
	return Chunk{
		ID:               id,
		TransferID:       "transfer-1",
		Capability:       "capability-1",
		Recipient:        "bob-route",
		Index:            index,
		TotalChunks:      64,
		EncryptedPayload: payload,
		SizeBytes:        len(payload),
	}
}

func TestACircleCeilingLowersTheBoxCeilingButNeverRaisesIt(t *testing.T) {
	relay := NewRelay(8, 1024, 4096, 4, time.Minute, time.Now)
	payload := strings.Repeat("x", 1024)

	// Lowered to 2 KiB on a box that carries 4 KiB.
	low := Grant{Credential: 7, AttachmentBytes: 2048}
	for i := 0; i < 2; i++ {
		if err := relay.PushWithGrant(grantedChunk("low-"+string(rune('a'+i)), i, payload), low); err != nil {
			t.Fatalf("chunk %d: %v", i, err)
		}
	}
	if err := relay.PushWithGrant(grantedChunk("low-c", 2, payload), low); err != ErrTooLarge {
		t.Fatalf("the chunk past the circle's ceiling returned %v, want ErrTooLarge", err)
	}

	// Claiming 1 GB on a 4 KiB box gets 4 KiB.
	relay = NewRelay(8, 1024, 4096, 4, time.Minute, time.Now)
	high := Grant{Credential: 7, AttachmentBytes: 1 << 30}
	for i := 0; i < 4; i++ {
		if err := relay.PushWithGrant(grantedChunk("high-"+string(rune('a'+i)), i, payload), high); err != nil {
			t.Fatalf("chunk %d: %v", i, err)
		}
		relay.Drain("bob-route", "capability-1")
	}
	if err := relay.PushWithGrant(grantedChunk("high-e", 4, payload), high); err != ErrTooLarge {
		t.Fatalf("a credential raised the box's attachment ceiling: %v", err)
	}
}

func TestACircleCannotOpenMoreTransfersThanItsTermsAllow(t *testing.T) {
	relay := NewRelay(8, 1024, 1<<20, 16, time.Minute, time.Now)
	payload := strings.Repeat("x", 512)
	grant := Grant{Credential: 7, ConcurrentTransfers: 2}

	open := func(n int, g Grant) error {
		chunk := grantedChunk("chunk-"+string(rune('a'+n)), 0, payload)
		chunk.TransferID = "transfer-" + string(rune('a'+n))
		chunk.Capability = "capability-" + string(rune('a'+n))
		return relay.PushWithGrant(chunk, g)
	}

	for i := 0; i < 2; i++ {
		if err := open(i, grant); err != nil {
			t.Fatalf("transfer %d: %v", i, err)
		}
	}
	if err := open(2, grant); err != ErrTooManySessions {
		t.Fatalf("the third concurrent transfer returned %v, want ErrTooManySessions", err)
	}
	// The box still has 14 sessions free, and the neighbours can use them.
	if err := open(3, Grant{Credential: 8, ConcurrentTransfers: 2}); err != nil {
		t.Fatalf("the neighbouring circle was refused: %v", err)
	}
}

func TestTheDailyTransitCeilingIsSpentAndRecovers(t *testing.T) {
	clock := time.Date(2026, 8, 11, 12, 0, 0, 0, time.UTC)
	relay := NewRelay(8, 2048, 1<<30, 16, time.Hour, func() time.Time { return clock })
	payload := strings.Repeat("x", 1024)
	grant := Grant{Credential: 7, TransitBytesPerDay: 3 * 1024}

	for i := 0; i < 3; i++ {
		if err := relay.PushWithGrant(grantedChunk("chunk-"+string(rune('a'+i)), i, payload), grant); err != nil {
			t.Fatalf("chunk %d: %v", i, err)
		}
		relay.Drain("bob-route", "capability-1")
	}
	if got := relay.TransitToday(7); got != 3*1024 {
		t.Fatalf("transit today = %d, want 3072", got)
	}
	if err := relay.PushWithGrant(grantedChunk("chunk-d", 3, payload), grant); err != ErrTransitExhausted {
		t.Fatalf("the chunk past the daily ceiling returned %v, want ErrTransitExhausted", err)
	}

	// Rolling, not tumbling: it frees up as the oldest hours fall out of the
	// window rather than all at once on a boundary a sender could wait for.
	clock = clock.Add(25 * time.Hour)
	if got := relay.TransitToday(7); got != 0 {
		t.Fatalf("transit after a day = %d, want 0", got)
	}
	if err := relay.PushWithGrant(grantedChunk("chunk-e", 4, payload), grant); err != nil {
		t.Fatalf("the circle did not recover after 24 hours: %v", err)
	}
}

func TestTransitIsCountedPerCircleAndPrunedWhenSpent(t *testing.T) {
	clock := time.Date(2026, 8, 11, 12, 0, 0, 0, time.UTC)
	relay := NewRelay(8, 2048, 1<<30, 16, time.Hour, func() time.Time { return clock })
	payload := strings.Repeat("x", 1024)

	if err := relay.PushWithGrant(grantedChunk("chunk-a", 0, payload), Grant{Credential: 7, TransitBytesPerDay: 1 << 20}); err != nil {
		t.Fatalf("push: %v", err)
	}
	if got := relay.TransitToday(8); got != 0 {
		t.Fatalf("a second circle was charged %d bytes it did not send", got)
	}

	clock = clock.Add(25 * time.Hour)
	relay.Prune()
	if got := relay.TransitToday(7); got != 0 {
		t.Fatalf("a spent window was not pruned: %d", got)
	}
}

// The free self-hosted path, again: no credential, no charge, box caps.
func TestAnUnattributedPushIsChargedToNobody(t *testing.T) {
	relay := NewRelay(8, 2048, 1<<20, 16, time.Minute, time.Now)
	if err := relay.Push(grantedChunk("chunk-a", 0, strings.Repeat("x", 1024))); err != nil {
		t.Fatalf("push: %v", err)
	}
	if got := relay.TransitToday(0); got != 0 {
		t.Fatalf("transit under the zero credential = %d, want 0", got)
	}
}
