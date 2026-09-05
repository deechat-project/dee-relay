package queue

import (
	"fmt"
	"testing"
	"time"

	"deechat/chat-node/internal/model"
)

// /profile/purge used to walk every message and then every ack while holding
// the store lock, on a route that is deliberately ungated. It is two index
// lookups now, and these are the tests that hold that up: the deletion is the
// same one it was, and the indexes hold nothing the record maps do not.

func purgeIndexStore(now time.Time) *Store {
	return NewStore(StoreConfig{
		MaxMessages: 100,
		MaxAcks:     200,
		MaxPerPair:  100,
		DefaultTTL:  time.Hour,
		MaxTTL:      time.Hour,
		Now:         func() time.Time { return now },
	})
}

func queueEnvelope(id, owner string) model.MessageEnvelope {
	envelope := model.MessageEnvelope{
		ID: id, Sender: "alice", Recipient: "bob", EncryptedPayload: "cipher",
	}
	if owner != "" {
		envelope.Metadata = map[string]string{"purgeHash": owner}
	}
	return envelope
}

func TestPurgeOwnerDeletesOnlyTheOwnersMailAndItsAcks(t *testing.T) {
	now := time.Date(2026, 9, 5, 10, 0, 0, 0, time.UTC)
	store := purgeIndexStore(now)

	for _, seed := range []struct{ id, owner string }{
		{"m-1", "owner-a"},
		{"m-2", "owner-a"},
		{"m-3", "owner-b"},
		{"m-4", ""}, // stamped with no purge hash at all
	} {
		if _, err := store.AddMessage(queueEnvelope(seed.id, seed.owner), "node"); err != nil {
			t.Fatalf("AddMessage %s: %v", seed.id, err)
		}
	}

	// One index key per distinct hash, and the unstamped envelope is in none of
	// them — the whole point of the index over the scan.
	if got := len(store.messagesByPurge); got != 2 {
		t.Fatalf("purge index keys = %d, want 2 (owner-a, owner-b)", got)
	}

	messages, acks := store.PurgeOwner("owner-a")
	// Two envelopes, and the coupled node_received ack each one minted.
	if messages != 2 || acks != 2 {
		t.Fatalf("PurgeOwner(owner-a) = (%d, %d), want (2, 2)", messages, acks)
	}
	if stats := store.Stats(); stats.Messages != 2 || stats.Acks != 2 {
		t.Fatalf("after purge stats = %#v, want 2 messages and 2 acks left", stats)
	}
	for _, id := range []string{"m-3", "m-4"} {
		if _, held := store.messages[id]; !held {
			t.Fatalf("purge for owner-a took %s with it", id)
		}
	}
	if _, indexed := store.messagesByPurge["owner-a"]; indexed {
		t.Fatalf("purge index kept an empty set for a fully purged owner")
	}
}

func TestPurgeOwnerWithoutAHashDeletesNothing(t *testing.T) {
	now := time.Date(2026, 9, 5, 10, 0, 0, 0, time.UTC)
	store := purgeIndexStore(now)
	if _, err := store.AddMessage(queueEnvelope("m-1", ""), "node"); err != nil {
		t.Fatalf("AddMessage: %v", err)
	}

	// The scan this replaced matched every envelope carrying no purgeHash,
	// because "" == "". No route reaches PurgeOwner with an empty hash, but the
	// index makes it a lookup that finds nothing rather than a mass deletion.
	if messages, acks := store.PurgeOwner("  "); messages != 0 || acks != 0 {
		t.Fatalf("PurgeOwner(\"\") = (%d, %d), want (0, 0)", messages, acks)
	}
	if got := store.Stats().Messages; got != 1 {
		t.Fatalf("empty-hash purge left %d messages, want 1", got)
	}
}

// The indexes are one entry per record and are kept in lock-step by the same
// add/delete helpers as messageSeq/ackSeq, so a leak here would be unbounded
// state deploy/memory-ceiling.sh is not sized for. Every way a record leaves
// the store is exercised: purged, deleted by a terminal ack, and expired.
func TestPurgeIndexesHoldNothingOnceEveryRecordHasLeft(t *testing.T) {
	now := time.Date(2026, 9, 5, 10, 0, 0, 0, time.UTC)
	store := purgeIndexStore(now)

	for i := 0; i < 6; i++ {
		id := fmt.Sprintf("m-%d", i)
		if _, err := store.AddMessage(queueEnvelope(id, fmt.Sprintf("owner-%d", i%3)), "node"); err != nil {
			t.Fatalf("AddMessage %s: %v", id, err)
		}
	}

	// 1. Purged.
	store.PurgeOwner("owner-0")

	// 2. Deleted by a terminal ack, which leaves the ack itself behind.
	for _, id := range []string{"m-1", "m-4"} {
		ack := model.AckRecord{
			ID: id + ":received", MessageID: id, Sender: "alice", Recipient: "bob",
			Type: model.AckRecipientDeviceReceived, CreatedAt: now, ExpiresAt: now.Add(time.Minute),
		}
		if err := store.AddAck(ack, "node"); err != nil {
			t.Fatalf("AddAck for %s: %v", id, err)
		}
	}

	// 3. Expired, which is the sweep that has to clear the rest.
	if stats := store.PruneExpired(now.Add(2 * time.Hour)); stats.Messages != 0 || stats.Acks != 0 {
		t.Fatalf("PruneExpired left %#v", stats)
	}

	if len(store.messagesByPurge) != 0 {
		t.Fatalf("messagesByPurge leaked %d keys: %#v", len(store.messagesByPurge), store.messagesByPurge)
	}
	if len(store.acksByMessage) != 0 {
		t.Fatalf("acksByMessage leaked %d keys: %#v", len(store.acksByMessage), store.acksByMessage)
	}
	if len(store.messageTags) != 0 {
		t.Fatalf("messageTags leaked %d keys", len(store.messageTags))
	}
}
