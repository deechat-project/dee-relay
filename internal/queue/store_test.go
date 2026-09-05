package queue

import (
	"errors"
	"strings"
	"testing"
	"time"

	"deechat/chat-node/internal/model"
)

func TestStoreAddsMessageAndNodeAckWithoutInspectingPayload(t *testing.T) {
	now := time.Date(2026, 6, 5, 10, 0, 0, 0, time.UTC)
	store := NewStore(StoreConfig{
		MaxMessages: 10,
		MaxAcks:     10,
		DefaultTTL:  time.Hour,
		Now:         func() time.Time { return now },
	})

	ack, err := store.AddMessage(model.MessageEnvelope{
		ID:               "msg-1",
		Sender:           "alice-device-route",
		Recipient:        "bob-device-route",
		EncryptedPayload: "opaque-ciphertext-that-the-node-never-parses",
	}, "node-a")
	if err != nil {
		t.Fatalf("AddMessage returned error: %v", err)
	}
	if ack.Type != model.AckNodeReceived {
		t.Fatalf("ack type = %q, want %q", ack.Type, model.AckNodeReceived)
	}

	messages := store.MessagesForRecipient("bob-device-route", 10, NewAuth(nil, true))
	if len(messages) != 1 {
		t.Fatalf("message count = %d, want 1", len(messages))
	}
	if messages[0].EncryptedPayload != "opaque-ciphertext-that-the-node-never-parses" {
		t.Fatalf("payload changed during relay")
	}

	acks := store.AcksForSender("alice-device-route", 10, NewAuth(nil, true))
	if len(acks) != 1 || acks[0].Type != model.AckNodeReceived {
		t.Fatalf("node ack was not queued for sender: %#v", acks)
	}
}

func TestStoreRejectsDuplicateExpiredAndFullMessageQueues(t *testing.T) {
	now := time.Date(2026, 6, 5, 10, 0, 0, 0, time.UTC)
	store := NewStore(StoreConfig{
		MaxMessages: 1,
		MaxAcks:     10,
		DefaultTTL:  time.Hour,
		Now:         func() time.Time { return now },
	})

	envelope := model.MessageEnvelope{
		ID:               "msg-1",
		Sender:           "alice",
		Recipient:        "bob",
		EncryptedPayload: "ciphertext",
		ExpiresAt:        now.Add(time.Hour),
	}
	if _, err := store.AddMessage(envelope, "node-a"); err != nil {
		t.Fatalf("AddMessage returned error: %v", err)
	}
	if _, err := store.AddMessage(envelope, "node-a"); !errors.Is(err, ErrDuplicate) {
		t.Fatalf("duplicate err = %v, want ErrDuplicate", err)
	}

	_, err := store.AddMessage(model.MessageEnvelope{
		ID:               "expired",
		Sender:           "alice",
		Recipient:        "bob",
		EncryptedPayload: "ciphertext",
		ExpiresAt:        now.Add(-time.Second),
	}, "node-a")
	if !errors.Is(err, ErrExpired) {
		t.Fatalf("expired err = %v, want ErrExpired", err)
	}

	_, err = store.AddMessage(model.MessageEnvelope{
		ID:               "msg-2",
		Sender:           "alice",
		Recipient:        "bob",
		EncryptedPayload: "ciphertext",
		ExpiresAt:        now.Add(time.Hour),
	}, "node-a")
	if !errors.Is(err, ErrQueueFull) {
		t.Fatalf("full err = %v, want ErrQueueFull", err)
	}
}

func TestRecipientAckDeletesQueuedMessage(t *testing.T) {
	now := time.Date(2026, 6, 5, 10, 0, 0, 0, time.UTC)
	store := NewStore(StoreConfig{
		MaxMessages: 10,
		MaxAcks:     10,
		DefaultTTL:  time.Hour,
		Now:         func() time.Time { return now },
	})

	_, err := store.AddMessage(model.MessageEnvelope{
		ID:               "msg-1",
		Sender:           "alice",
		Recipient:        "bob",
		EncryptedPayload: "ciphertext",
	}, "node-a")
	if err != nil {
		t.Fatalf("AddMessage returned error: %v", err)
	}

	err = store.AddAck(model.AckRecord{
		ID:        "ack-1",
		MessageID: "msg-1",
		Sender:    "alice",
		Recipient: "bob",
		Type:      model.AckRecipientDeviceReceived,
	}, "node-a")
	if err != nil {
		t.Fatalf("AddAck returned error: %v", err)
	}
	if got := store.MessagesForRecipient("bob", 10, NewAuth(nil, true)); len(got) != 0 {
		t.Fatalf("message remained queued after recipient ack: %#v", got)
	}
}

func TestRetractionAppliedAckIsAcceptedAndDeletesQueuedMessage(t *testing.T) {
	// Regression: the recipient confirms a delete-for-everyone with a
	// retraction_applied_ack. The node once rejected this type with 400
	// "ack record is invalid", which left the retraction undeliverable and
	// (because the app aborted its envelope batch on the throw) blocked every
	// later message behind it in the queue.
	now := time.Date(2026, 6, 26, 10, 0, 0, 0, time.UTC)
	store := NewStore(StoreConfig{
		MaxMessages: 10,
		MaxAcks:     10,
		DefaultTTL:  time.Hour,
		Now:         func() time.Time { return now },
	})

	if _, err := store.AddMessage(model.MessageEnvelope{
		ID:               "retract-1",
		Sender:           "alice",
		Recipient:        "bob",
		EncryptedPayload: "ciphertext",
	}, "node-a"); err != nil {
		t.Fatalf("AddMessage returned error: %v", err)
	}

	if err := store.AddAck(model.AckRecord{
		ID:        "ack-retract-1",
		MessageID: "retract-1",
		Sender:    "alice",
		Recipient: "bob",
		Type:      model.AckRetractionApplied,
	}, "node-a"); err != nil {
		t.Fatalf("AddAck rejected retraction_applied_ack: %v", err)
	}
	if got := store.MessagesForRecipient("bob", 10, NewAuth(nil, true)); len(got) != 0 {
		t.Fatalf("retraction remained queued after applied ack: %#v", got)
	}
}

func TestPruneExpiredRemovesMessagesAndAcks(t *testing.T) {
	now := time.Date(2026, 6, 5, 10, 0, 0, 0, time.UTC)
	store := NewStore(StoreConfig{
		MaxMessages: 10,
		MaxAcks:     10,
		DefaultTTL:  time.Hour,
		Now:         func() time.Time { return now },
	})

	_, err := store.AddMessage(model.MessageEnvelope{
		ID:               "msg-1",
		Sender:           "alice",
		Recipient:        "bob",
		EncryptedPayload: "ciphertext",
		ExpiresAt:        now.Add(time.Minute),
	}, "node-a")
	if err != nil {
		t.Fatalf("AddMessage returned error: %v", err)
	}

	stats := store.PruneExpired(now.Add(2 * time.Minute))
	if stats.Messages != 0 || stats.Acks != 0 {
		t.Fatalf("stats after prune = %#v, want empty", stats)
	}
}

func TestImportSnapshotDedupesAndAppliesTerminalAcks(t *testing.T) {
	now := time.Date(2026, 6, 5, 10, 0, 0, 0, time.UTC)
	store := NewStore(StoreConfig{
		MaxMessages: 10,
		MaxAcks:     10,
		DefaultTTL:  time.Hour,
		Now:         func() time.Time { return now },
	})

	payload := model.SyncPayload{
		NodeID: "node-b",
		Messages: []model.MessageEnvelope{
			{
				ID:               "msg-1",
				Sender:           "alice",
				Recipient:        "bob",
				CreatedAt:        now,
				ExpiresAt:        now.Add(time.Hour),
				EncryptedPayload: "opaque-ciphertext",
			},
			{
				ID:               "expired",
				Sender:           "alice",
				Recipient:        "bob",
				CreatedAt:        now.Add(-2 * time.Hour),
				ExpiresAt:        now.Add(-time.Hour),
				EncryptedPayload: "opaque-ciphertext",
			},
		},
		Acks: []model.AckRecord{
			{
				ID:        "ack-delivered-msg-1",
				MessageID: "msg-1",
				Sender:    "alice",
				Recipient: "bob",
				Type:      model.AckRecipientDeviceReceived,
				CreatedAt: now,
				ExpiresAt: now.Add(time.Hour),
				NodeID:    "node-b",
			},
		},
	}

	result := store.ImportSnapshot(payload)
	if result.AcceptedMessages != 1 || result.AcceptedAcks != 1 || result.Rejected != 1 {
		t.Fatalf("import result = %#v", result)
	}
	if got := store.MessagesForRecipient("bob", 10, NewAuth(nil, true)); len(got) != 0 {
		t.Fatalf("terminal ack did not remove imported message: %#v", got)
	}
	if got := store.AcksForSender("alice", 10, NewAuth(nil, true)); len(got) != 1 {
		t.Fatalf("imported ack count = %d, want 1", len(got))
	}

	duplicate := store.ImportSnapshot(payload)
	if duplicate.DuplicateMessages != 1 || duplicate.DuplicateAcks != 1 {
		t.Fatalf("duplicate import result = %#v", duplicate)
	}
}

func TestSnapshotPrunesExpiredRecordsAndReturnsOpaqueQueues(t *testing.T) {
	now := time.Date(2026, 6, 5, 10, 0, 0, 0, time.UTC)
	store := NewStore(StoreConfig{
		MaxMessages: 10,
		MaxAcks:     10,
		DefaultTTL:  time.Hour,
		Now:         func() time.Time { return now },
	})

	if _, err := store.AddMessage(model.MessageEnvelope{
		ID:               "msg-1",
		Sender:           "alice",
		Recipient:        "bob",
		EncryptedPayload: "ciphertext",
		ExpiresAt:        now.Add(time.Hour),
	}, "node-a"); err != nil {
		t.Fatalf("AddMessage returned error: %v", err)
	}

	snapshot := store.Snapshot(10)
	if len(snapshot.Messages) != 1 {
		t.Fatalf("snapshot message count = %d, want 1", len(snapshot.Messages))
	}
	if snapshot.Messages[0].EncryptedPayload != "ciphertext" {
		t.Fatalf("snapshot changed ciphertext payload")
	}
	if len(snapshot.Acks) != 1 || snapshot.Acks[0].Type != model.AckNodeReceived {
		t.Fatalf("snapshot acks = %#v, want node received ack", snapshot.Acks)
	}
}

func TestPurgeOwnerRemovesOwnedQueues(t *testing.T) {
	now := time.Date(2026, 6, 5, 10, 0, 0, 0, time.UTC)
	store := NewStore(StoreConfig{MaxMessages: 10, MaxAcks: 10, DefaultTTL: time.Hour, Now: func() time.Time { return now }})
	_, _ = store.AddMessage(model.MessageEnvelope{ID: "msg-1", Sender: "alice", Recipient: "bob", EncryptedPayload: "cipher", Metadata: map[string]string{"purgeHash": "secret"}}, "node")
	messages, acks := store.PurgeOwner("secret")
	if messages != 1 || acks != 1 || store.Stats().Messages != 0 || store.Stats().Acks != 0 {
		t.Fatalf("purge result messages=%d acks=%d stats=%#v", messages, acks, store.Stats())
	}
}

func TestPurgeTombstonesAreCappedButStillPurge(t *testing.T) {
	now := time.Date(2026, 6, 17, 10, 0, 0, 0, time.UTC)
	store := NewStore(StoreConfig{
		MaxMessages: 100,
		MaxAcks:     100,
		MaxPurges:   2,
		DefaultTTL:  time.Hour,
		Now:         func() time.Time { return now },
	})

	// Queue a message under a third (over-cap) purge hash so we can prove the
	// owner-purge deletion still runs even when the tombstone can't be stored.
	if _, err := store.AddMessage(model.MessageEnvelope{
		ID: "m-3", Sender: "s", Recipient: "r", EncryptedPayload: "x",
		Metadata: map[string]string{"purgeHash": "owner-3"},
	}, "node-a"); err != nil {
		t.Fatalf("AddMessage: %v", err)
	}

	for _, owner := range []string{"owner-1", "owner-2", "owner-3"} {
		store.PurgeOwner(owner)
	}

	if got := store.Stats().Purges; got != 2 {
		t.Fatalf("purge tombstone map = %d, want capped at 2", got)
	}
	if got := store.Stats().Messages; got != 0 {
		t.Fatalf("over-cap PurgeOwner did not delete the owner's message: %d remain", got)
	}
}

func TestStoreEnforcesPerPairQuotaWithoutStarvingOtherPairs(t *testing.T) {
	now := time.Date(2026, 6, 5, 10, 0, 0, 0, time.UTC)
	store := NewStore(StoreConfig{
		MaxMessages: 1000,
		MaxPerPair:  2,
		DefaultTTL:  time.Hour,
		Now:         func() time.Time { return now },
	})

	add := func(id, sender, recipient string) error {
		_, err := store.AddMessage(model.MessageEnvelope{
			ID: id, Sender: sender, Recipient: recipient, EncryptedPayload: "x",
		}, "node-a")
		return err
	}

	// Alice fills her 2-slot lane to Bob, then is rejected on the third.
	if err := add("a1", "alice", "bob"); err != nil {
		t.Fatalf("a1: %v", err)
	}
	if err := add("a2", "alice", "bob"); err != nil {
		t.Fatalf("a2: %v", err)
	}
	if err := add("a3", "alice", "bob"); !errors.Is(err, ErrPairQuotaFull) {
		t.Fatalf("a3 error = %v, want ErrPairQuotaFull", err)
	}

	// A different sender to the same recipient gets its own lane (fan-in is safe).
	if err := add("c1", "carol", "bob"); err != nil {
		t.Fatalf("carol must not be starved by alice's full lane: %v", err)
	}
	// And alice to a different recipient gets its own lane too.
	if err := add("a4", "alice", "dave"); err != nil {
		t.Fatalf("alice→dave is a distinct lane: %v", err)
	}

	// Draining alice→bob (delivered ack) frees a slot so she can send again.
	if err := store.AddAck(model.AckRecord{
		ID: "ack-a1", MessageID: "a1", Sender: "alice", Recipient: "bob",
		Type: model.AckRecipientDeviceReceived,
	}, "node-a"); err != nil {
		t.Fatalf("delivered ack: %v", err)
	}
	if err := add("a5", "alice", "bob"); err != nil {
		t.Fatalf("a5 should fit after a slot drained: %v", err)
	}
}

func TestStoreRejectsOversizePayload(t *testing.T) {
	now := time.Date(2026, 6, 5, 10, 0, 0, 0, time.UTC)
	store := NewStore(StoreConfig{
		MaxMessages:     10,
		MaxPayloadBytes: 16,
		DefaultTTL:      time.Hour,
		Now:             func() time.Time { return now },
	})

	if _, err := store.AddMessage(model.MessageEnvelope{
		ID: "big", Sender: "s", Recipient: "r",
		EncryptedPayload: "this-payload-is-well-over-sixteen-bytes",
	}, "node-a"); !errors.Is(err, ErrPayloadTooLarge) {
		t.Fatalf("oversize error = %v, want ErrPayloadTooLarge", err)
	}
	if got := store.Stats().Messages; got != 0 {
		t.Fatalf("oversize payload was queued: %d messages", got)
	}

	if _, err := store.AddMessage(model.MessageEnvelope{
		ID: "ok", Sender: "s", Recipient: "r", EncryptedPayload: "small",
	}, "node-a"); err != nil {
		t.Fatalf("within-cap payload rejected: %v", err)
	}
}

func TestStoreClampsExpiresAtToMaxTTL(t *testing.T) {
	now := time.Date(2026, 6, 5, 10, 0, 0, 0, time.UTC)
	store := NewStore(StoreConfig{
		MaxMessages: 10,
		MaxTTL:      time.Hour,
		DefaultTTL:  time.Hour,
		Now:         func() time.Time { return now },
	})

	if _, err := store.AddMessage(model.MessageEnvelope{
		ID: "m", Sender: "s", Recipient: "r", EncryptedPayload: "x",
		ExpiresAt: now.Add(72 * time.Hour),
	}, "node-a"); err != nil {
		t.Fatalf("AddMessage: %v", err)
	}

	messages := store.MessagesForRecipient("r", 10, NewAuth(nil, true))
	if len(messages) != 1 {
		t.Fatalf("message count = %d, want 1", len(messages))
	}
	if want := now.Add(time.Hour); !messages[0].ExpiresAt.Equal(want) {
		t.Fatalf("ExpiresAt = %v, want clamped to %v", messages[0].ExpiresAt, want)
	}
}

func TestStorePairQuotaRecoversAfterExpiry(t *testing.T) {
	now := time.Date(2026, 6, 5, 10, 0, 0, 0, time.UTC)
	clock := now
	store := NewStore(StoreConfig{
		MaxMessages: 1000,
		MaxPerPair:  1,
		MaxTTL:      time.Hour,
		DefaultTTL:  time.Hour,
		Now:         func() time.Time { return clock },
	})

	if _, err := store.AddMessage(model.MessageEnvelope{
		ID: "m1", Sender: "s", Recipient: "r", EncryptedPayload: "x",
		ExpiresAt: now.Add(30 * time.Minute),
	}, "node-a"); err != nil {
		t.Fatalf("m1: %v", err)
	}

	// Let the lane's only message expire and get pruned, then the counter must
	// have been released so the same pair can send again.
	clock = now.Add(time.Hour)
	store.PruneExpired(clock)
	if _, err := store.AddMessage(model.MessageEnvelope{
		ID: "m2", Sender: "s", Recipient: "r", EncryptedPayload: "x",
	}, "node-a"); err != nil {
		t.Fatalf("pair quota did not recover after expiry: %v", err)
	}
}

func TestRejectionReasonIsRelayedVerbatimAndBounded(t *testing.T) {
	// A recipient that took a message off the queue and could not open it says
	// so on the rejection, so the original sender can tell that apart from a
	// message refused as garbage. The node relays the marker without reading
	// it — but bounds it, because an ack lane is not storage.
	now := time.Date(2026, 8, 27, 10, 0, 0, 0, time.UTC)
	store := NewStore(StoreConfig{
		MaxMessages: 10,
		MaxAcks:     10,
		DefaultTTL:  time.Hour,
		Now:         func() time.Time { return now },
	})

	err := store.AddAck(model.AckRecord{
		ID:        "ack-1",
		MessageID: "msg-1",
		Sender:    "alice",
		Recipient: "bob",
		Type:      model.AckRejected,
		Reason:    "recipient_cannot_open",
	}, "node-a")
	if err != nil {
		t.Fatalf("AddAck returned error: %v", err)
	}

	err = store.AddAck(model.AckRecord{
		ID:        "ack-2",
		MessageID: "msg-2",
		Sender:    "alice",
		Recipient: "bob",
		Type:      model.AckRejected,
		Reason:    strings.Repeat("x", MaxAckReasonBytes+1),
	}, "node-a")
	if err != nil {
		t.Fatalf("AddAck with an oversize reason returned error: %v", err)
	}

	acks := store.AcksForSender("alice", 10, NewAuth(nil, true))
	if len(acks) != 2 {
		t.Fatalf("AcksForSender returned %d acks, want 2", len(acks))
	}
	byID := map[string]model.AckRecord{}
	for _, ack := range acks {
		byID[ack.ID] = ack
	}
	if got := byID["ack-1"].Reason; got != "recipient_cannot_open" {
		t.Fatalf("relayed reason = %q, want %q", got, "recipient_cannot_open")
	}
	// Dropped, not refused: losing the sentence costs the sender an explanation,
	// losing the ack would leave the message it rejects sitting in the queue.
	if got := byID["ack-2"].Reason; got != "" {
		t.Fatalf("oversize reason = %q, want it dropped", got)
	}
}
