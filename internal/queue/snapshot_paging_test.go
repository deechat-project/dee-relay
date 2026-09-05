package queue

import (
	"fmt"
	"testing"
	"time"

	"deechat/chat-node/internal/model"
)

var pagingNow = time.Date(2026, 7, 26, 12, 0, 0, 0, time.UTC)

func pagingStore(t *testing.T, capacity int) *Store {
	t.Helper()
	return NewStore(StoreConfig{
		MaxMessages: capacity,
		MaxAcks:     2 * capacity,
		MaxPurges:   10,
		DefaultTTL:  time.Hour,
		Now:         func() time.Time { return pagingNow },
	})
}

func addPagingMessage(t *testing.T, store *Store, id string) {
	t.Helper()
	if _, err := store.AddMessage(model.MessageEnvelope{
		ID:               id,
		Sender:           "alice",
		Recipient:        "queue-" + id,
		EncryptedPayload: "ciphertext",
		ExpiresAt:        pagingNow.Add(time.Hour),
	}, "node-a"); err != nil {
		t.Fatalf("AddMessage %s: %v", id, err)
	}
}

// The cursor is in *arrival* order, not CreatedAt: CreatedAt comes from the
// client, so it is neither unique nor monotone (a skewed clock, or a device that
// composed offline and posted later). A cursor on a value the sender controls
// skips records silently.
func TestSnapshotSinceWalksTheWholeQueueInPages(t *testing.T) {
	store := pagingStore(t, 100)
	// Deliberately descending CreatedAt: arrival order and creation order disagree.
	for i := 0; i < 30; i++ {
		if _, err := store.AddMessage(model.MessageEnvelope{
			ID:               fmt.Sprintf("msg-%02d", i),
			Sender:           "alice",
			Recipient:        fmt.Sprintf("queue-%02d", i),
			CreatedAt:        pagingNow.Add(-time.Duration(i) * time.Minute),
			EncryptedPayload: "ciphertext",
			ExpiresAt:        pagingNow.Add(time.Hour),
		}, "node-a"); err != nil {
			t.Fatalf("AddMessage %d: %v", i, err)
		}
	}

	seen := map[string]bool{}
	var cursor uint64
	pages := 0
	for {
		page := store.SnapshotSince(cursor, 7)
		pages++
		if pages > 20 {
			t.Fatal("paging did not terminate")
		}
		for _, message := range page.Messages {
			if seen[message.ID] {
				t.Fatalf("%s appeared on two pages; the cursor is not advancing correctly", message.ID)
			}
			seen[message.ID] = true
		}
		if page.NextSeq <= cursor && page.More {
			t.Fatalf("page %d claims more records but the cursor stayed at %d", pages, cursor)
		}
		cursor = page.NextSeq
		if !page.More {
			break
		}
	}

	if len(seen) != 30 {
		t.Fatalf("paged over %d of 30 messages", len(seen))
	}
	// Messages and acks share one cursor, so 30 messages plus their 30 acks at 7
	// records a page is 9 pages.
	if pages < 8 {
		t.Fatalf("walked the queue in %d pages of 7; that cannot cover 60 records", pages)
	}
	if final := store.SnapshotSince(cursor, 7); len(final.Messages) != 0 || len(final.Acks) != 0 || final.More {
		t.Fatalf("a page past the end returned %d messages, %d acks, more=%v",
			len(final.Messages), len(final.Acks), final.More)
	}
}

func TestSnapshotSinceReportsAStableEpoch(t *testing.T) {
	store := pagingStore(t, 10)
	first := store.SnapshotSince(0, 10).Epoch
	if first == "" {
		t.Fatal("snapshot carries no epoch")
	}
	if second := store.SnapshotSince(0, 10).Epoch; second != first {
		t.Fatalf("epoch changed between reads: %q then %q", first, second)
	}
	// A restart is a new store, and it must not look like the same one: a peer's
	// cursor into the old sequence would silently skip everything the restart lost.
	if fresh := pagingStore(t, 10).SnapshotSince(0, 10).Epoch; fresh == first {
		t.Fatal("a fresh store reports the same epoch as another; a peer cannot detect a restart")
	}
}

// Purge tombstones ride on every page, not just the first: a page carrying records
// but not the tombstone that deletes them would let purged mail come back on the
// next exchange.
func TestEveryPageCarriesThePurgeTombstones(t *testing.T) {
	store := pagingStore(t, 100)
	for i := 0; i < 10; i++ {
		addPagingMessage(t, store, fmt.Sprintf("msg-%02d", i))
	}
	store.PurgeOwner("owner-hash-1")

	first := store.SnapshotSince(0, 4)
	if len(first.Purges) != 1 {
		t.Fatalf("first page purges = %d, want 1", len(first.Purges))
	}
	second := store.SnapshotSince(first.NextSeq, 4)
	if len(second.Purges) != 1 {
		t.Fatalf("second page purges = %d, want 1", len(second.Purges))
	}
}

// The cursor maps are extra per-record state, and this relay's memory ceiling is
// derived from the record caps. A leaked entry per deleted record would be an
// unbounded map that MemoryMax is not sized for.
func TestTheCursorMapsDoNotOutliveTheirRecords(t *testing.T) {
	store := pagingStore(t, 100)
	for i := 0; i < 20; i++ {
		addPagingMessage(t, store, fmt.Sprintf("msg-%02d", i))
	}

	// Terminal acks delete their messages; expiry sweeps the rest.
	for i := 0; i < 10; i++ {
		id := fmt.Sprintf("msg-%02d", i)
		if err := store.AddAck(model.AckRecord{
			ID:        id + ":read",
			MessageID: id,
			Sender:    "alice",
			Recipient: "queue-" + id,
			Type:      model.AckRecipientRead,
			ExpiresAt: pagingNow.Add(time.Hour),
		}, "node-a"); err != nil {
			t.Fatalf("AddAck for %s: %v", id, err)
		}
	}
	store.PruneExpired(pagingNow.Add(2 * time.Hour))

	stats := store.Stats()
	if stats.Messages != 0 || stats.Acks != 0 {
		t.Fatalf("expected an empty store after expiry, got %+v", stats)
	}
	store.mu.RLock()
	messageSeqs, ackSeqs := len(store.messageSeq), len(store.ackSeq)
	store.mu.RUnlock()
	if messageSeqs != 0 || ackSeqs != 0 {
		t.Fatalf("cursor maps still hold %d message and %d ack entries after every record went away",
			messageSeqs, ackSeqs)
	}
}
