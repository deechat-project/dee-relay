package queue

import (
	"testing"
	"time"

	"deechat/chat-node/internal/model"
)

// The ack lane had the two defects this file guards: a client-set expiry was
// stored verbatim on both write paths, so PruneExpired never reached it; and a
// full ack map failed the POST /messages that would have coupled its own ack,
// so a few dozen junk acks refused all new mail on the box until a restart.

func TestAddAckClampsAClientSetExpiryToTheNodeCeiling(t *testing.T) {
	now := time.Date(2026, 6, 5, 10, 0, 0, 0, time.UTC)
	store := NewStore(StoreConfig{
		MaxMessages: 10,
		MaxAcks:     30,
		MaxTTL:      48 * time.Hour,
		DefaultTTL:  time.Hour,
		Now:         func() time.Time { return now },
	})

	ack := model.AckRecord{
		ID:        "ack-forever",
		MessageID: "msg-1",
		Sender:    "alice",
		Recipient: "bob",
		Type:      model.AckRecipientRead,
		CreatedAt: now,
		ExpiresAt: time.Date(2076, 1, 1, 0, 0, 0, 0, time.UTC),
	}
	if err := store.AddAck(ack, "node-a"); err != nil {
		t.Fatalf("AddAck returned error: %v", err)
	}

	stored := store.AcksForSender("alice", 10, NewAuth(nil, true))
	if len(stored) != 1 {
		t.Fatalf("ack count = %d, want 1", len(stored))
	}
	if want := now.Add(48 * time.Hour); !stored[0].ExpiresAt.Equal(want) {
		t.Fatalf("stored expiry = %s, want the ceiling %s", stored[0].ExpiresAt, want)
	}
}

func TestAddAckClampsToTheCredentialsShorterRetention(t *testing.T) {
	now := time.Date(2026, 6, 5, 10, 0, 0, 0, time.UTC)
	store := NewStore(StoreConfig{
		MaxMessages: 10,
		MaxAcks:     30,
		MaxTTL:      72 * time.Hour,
		DefaultTTL:  time.Hour,
		Now:         func() time.Time { return now },
	})

	err := store.AddAckWithGrant(model.AckRecord{
		ID:        "ack-forever",
		MessageID: "msg-1",
		Sender:    "alice",
		Recipient: "bob",
		Type:      model.AckRecipientRead,
		CreatedAt: now,
		ExpiresAt: time.Date(2076, 1, 1, 0, 0, 0, 0, time.UTC),
	}, "node-a", Grant{Credential: 7, Retention: 24 * time.Hour}, TrustedAuth())
	if err != nil {
		t.Fatalf("AddAckWithGrant returned error: %v", err)
	}

	stored := store.AcksForSender("alice", 10, NewAuth(nil, true))
	if want := now.Add(24 * time.Hour); len(stored) != 1 || !stored[0].ExpiresAt.Equal(want) {
		t.Fatalf("stored expiry = %#v, want the credential's window %s", stored, want)
	}
}

func TestImportSnapshotClampsAPeersAckExpiry(t *testing.T) {
	now := time.Date(2026, 6, 5, 10, 0, 0, 0, time.UTC)
	store := NewStore(StoreConfig{
		MaxMessages: 10,
		MaxAcks:     30,
		MaxTTL:      48 * time.Hour,
		DefaultTTL:  time.Hour,
		Now:         func() time.Time { return now },
	})

	result := store.ImportSnapshot(model.SyncPayload{
		NodeID: "node-b",
		Acks: []model.AckRecord{{
			ID:        "ack-forever",
			MessageID: "msg-1",
			Sender:    "alice",
			Recipient: "bob",
			Type:      model.AckRecipientRead,
			CreatedAt: now,
			ExpiresAt: time.Date(2076, 1, 1, 0, 0, 0, 0, time.UTC),
			NodeID:    "node-b",
		}},
	})
	if result.AcceptedAcks != 1 {
		t.Fatalf("accepted acks = %d, want 1: %#v", result.AcceptedAcks, result)
	}

	stored := store.AcksForSender("alice", 10, NewAuth(nil, true))
	if want := now.Add(48 * time.Hour); len(stored) != 1 || !stored[0].ExpiresAt.Equal(want) {
		t.Fatalf("stored expiry = %#v, want the ceiling %s", stored, want)
	}
}

// A caller-posted ack may occupy at most maxAcks-maxMessages entries. The
// reserve below that is what keeps the message path working: a coupled ack is
// at most one per queued message, and messages are capped at maxMessages.
func TestAFullExternalAckBudgetLeavesTheMessagePathWorking(t *testing.T) {
	now := time.Date(2026, 6, 5, 10, 0, 0, 0, time.UTC)
	store := NewStore(StoreConfig{
		MaxMessages: 4,
		MaxAcks:     10,
		MaxTTL:      48 * time.Hour,
		DefaultTTL:  time.Hour,
		Now:         func() time.Time { return now },
	})

	// Six is maxAcks-maxMessages: the whole external budget, filled with junk
	// naming pairs that do not exist, which is all POST /acks asks of a caller.
	accepted := 0
	for i := 0; i < 20; i++ {
		err := store.AddAck(model.AckRecord{
			ID:        "junk-" + string(rune('a'+i)),
			MessageID: "no-such-message",
			Sender:    "attacker",
			Recipient: "nobody",
			Type:      model.AckRecipientRead,
			CreatedAt: now,
			ExpiresAt: now.Add(time.Hour),
		}, "node-a")
		if err == nil {
			accepted++
			continue
		}
		if err != ErrQueueFull {
			t.Fatalf("junk ack %d returned %v, want ErrQueueFull", i, err)
		}
		break
	}
	if accepted != 6 {
		t.Fatalf("external budget accepted %d acks, want 6 (maxAcks-maxMessages)", accepted)
	}

	// Every message slot still fills, and every one of them still gets the
	// coupled node_received ack the sender needs to see.
	for i := 0; i < 4; i++ {
		ack, err := store.AddMessage(model.MessageEnvelope{
			ID:               "msg-" + string(rune('a'+i)),
			Sender:           "alice",
			Recipient:        "bob",
			EncryptedPayload: "opaque-ciphertext",
		}, "node-a")
		if err != nil {
			t.Fatalf("AddMessage %d under a full external ack budget: %v", i, err)
		}
		if ack.Type != model.AckNodeReceived {
			t.Fatalf("message %d got no coupled ack: %#v", i, ack)
		}
	}

	acks := store.AcksForSender("alice", 10, NewAuth(nil, true))
	if len(acks) != 4 {
		t.Fatalf("coupled ack count = %d, want 4", len(acks))
	}
}
