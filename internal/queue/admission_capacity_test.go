package queue

import (
	"testing"
	"time"

	"deechat/chat-node/internal/model"
)

// Personal, Crew and Team all live in one shared pool on one box, and every cap
// this package had was per-box — so before these terms existed the three tiers
// were the same product under three names. These tests are what makes them
// different.

func capacityStore(now func() time.Time) *Store {
	return NewStore(StoreConfig{
		MaxMessages:     100,
		MaxAcks:         200,
		MaxPerPair:      10,
		MaxPayloadBytes: 8192,
		MaxTTL:          72 * time.Hour,
		DefaultTTL:      24 * time.Hour,
		Now:             now,
	})
}

func envelopeTo(id, recipient string) model.MessageEnvelope {
	return model.MessageEnvelope{
		ID:               id,
		Sender:           "alice-route",
		Recipient:        recipient,
		EncryptedPayload: "ciphertext",
	}
}

func TestACircleCannotExceedItsQueueSlots(t *testing.T) {
	store := capacityStore(time.Now)
	grant := Grant{Credential: 7, Slots: 3}

	for i := 0; i < 3; i++ {
		if _, err := store.AddMessageWithGrant(envelopeTo(string(rune('a'+i)), "bob-route"), "node-a", grant); err != nil {
			t.Fatalf("message %d: %v", i, err)
		}
	}
	if _, err := store.AddMessageWithGrant(envelopeTo("d", "bob-route"), "node-a", grant); err != ErrSlotsFull {
		t.Fatalf("the fourth message returned %v, want ErrSlotsFull", err)
	}
	if got := store.Occupancy(7); got != 3 {
		t.Fatalf("occupancy = %d, want 3", got)
	}

	// The box is nowhere near full, and the circle next door is unaffected: that
	// is the point of a per-credential cap sitting beside the global one.
	if _, err := store.AddMessageWithGrant(envelopeTo("e", "bob-route"), "node-a", Grant{Credential: 8, Slots: 3}); err != nil {
		t.Fatalf("the neighbouring circle was refused: %v", err)
	}
}

// "Incremented on accept and decremented on delivery or expiry" — both halves,
// because a counter that only goes up is a circle that fills up once and never
// sends again.
func TestSlotsAreReleasedOnDeliveryAndOnExpiry(t *testing.T) {
	clock := time.Date(2026, 8, 11, 12, 0, 0, 0, time.UTC)
	store := capacityStore(func() time.Time { return clock })
	grant := Grant{Credential: 7, Slots: 4}

	for _, id := range []string{"m1", "m2"} {
		if _, err := store.AddMessageWithGrant(envelopeTo(id, "bob-route"), "node-a", grant); err != nil {
			t.Fatalf("%s: %v", id, err)
		}
	}
	if got := store.Occupancy(7); got != 2 {
		t.Fatalf("occupancy after two sends = %d, want 2", got)
	}

	// Delivered.
	if err := store.AddAck(model.AckRecord{
		ID: "m1-delivered", MessageID: "m1", Sender: "alice-route", Recipient: "bob-route",
		Type: model.AckRecipientDeviceReceived,
	}, "node-a"); err != nil {
		t.Fatalf("delivery ack: %v", err)
	}
	if got := store.Occupancy(7); got != 1 {
		t.Fatalf("occupancy after delivery = %d, want 1", got)
	}

	// Expired.
	clock = clock.Add(48 * time.Hour)
	store.PruneExpired(clock)
	if got := store.Occupancy(7); got != 0 {
		t.Fatalf("occupancy after expiry = %d, want 0", got)
	}

	// And the slots are usable again, which is the property the counter exists
	// for: a Crew circle that filled up during an outage is not billed for it
	// afterwards.
	if _, err := store.AddMessageWithGrant(envelopeTo("m3", "bob-route"), "node-a", grant); err != nil {
		t.Fatalf("after draining: %v", err)
	}
}

func TestSlotsAreReleasedWhenAnOwnerPurges(t *testing.T) {
	store := capacityStore(time.Now)
	envelope := envelopeTo("m1", "bob-route")
	envelope.Metadata = map[string]string{"purgeHash": "owner-hash"}
	if _, err := store.AddMessageWithGrant(envelope, "node-a", Grant{Credential: 7, Slots: 4}); err != nil {
		t.Fatalf("add: %v", err)
	}
	store.PurgeOwner("owner-hash")
	if got := store.Occupancy(7); got != 0 {
		t.Fatalf("occupancy after a purge = %d, want 0", got)
	}
}

// A credential may only ever LOWER a box cap. The Apache-2.0 binary must not be
// able to sell more than the operator configured — otherwise a self-hoster's own
// ceilings are advisory, and so are ours.
func TestACredentialCanOnlyLowerTheBoxCaps(t *testing.T) {
	clock := time.Date(2026, 8, 11, 12, 0, 0, 0, time.UTC)
	store := capacityStore(func() time.Time { return clock })

	// Retention: the box says 72h, the credential asks for a week.
	envelope := envelopeTo("greedy", "bob-route")
	envelope.ExpiresAt = clock.Add(7 * 24 * time.Hour)
	if _, err := store.AddMessageWithGrant(envelope, "node-a", Grant{
		Credential: 7, Slots: 10, Retention: 7 * 24 * time.Hour,
	}); err != nil {
		t.Fatalf("add: %v", err)
	}
	held := store.MessagesForRecipient("bob-route", 10, NewAuth(nil, true))
	if len(held) != 1 {
		t.Fatalf("held %d messages, want 1", len(held))
	}
	if want := clock.Add(72 * time.Hour); held[0].ExpiresAt.After(want) {
		t.Fatalf("expiry = %v, want no later than the box's %v", held[0].ExpiresAt, want)
	}

	// Slots: the box holds 100 messages, the credential claims 1000.
	for i := 0; i < 99; i++ {
		if _, err := store.AddMessageWithGrant(envelopeTo(string(rune('A'+i%26))+string(rune('a'+i/26)), "bob-route-"+string(rune('a'+i%26))),
			"node-a", Grant{Credential: 7, Slots: 1000}); err != nil {
			t.Fatalf("message %d: %v", i, err)
		}
	}
	_, err := store.AddMessageWithGrant(envelopeTo("one-too-many", "zoe-route"), "node-a", Grant{Credential: 7, Slots: 1000})
	if err != ErrSlotsFull && err != ErrQueueFull {
		t.Fatalf("a credential claiming 1000 slots on a 100-message box got %v", err)
	}
}

// Retention as a clamp, not a rejection: a sender asking for longer than its
// circle bought gets the message relayed for as long as the circle bought.
func TestTheGrantedRetentionWindowClampsRatherThanRejects(t *testing.T) {
	clock := time.Date(2026, 8, 11, 12, 0, 0, 0, time.UTC)
	store := capacityStore(func() time.Time { return clock })

	envelope := envelopeTo("m1", "bob-route")
	envelope.ExpiresAt = clock.Add(60 * time.Hour) // inside the box's 72h
	ack, err := store.AddMessageWithGrant(envelope, "node-a", Grant{Credential: 7, Retention: 24 * time.Hour})
	if err != nil {
		t.Fatalf("add: %v", err)
	}
	if want := clock.Add(24 * time.Hour); !ack.ExpiresAt.Equal(want) {
		t.Fatalf("ack expiry = %v, want the circle's window %v", ack.ExpiresAt, want)
	}
}

func TestTheGrantedPerPairQuotaOnlyLowers(t *testing.T) {
	store := capacityStore(time.Now)

	// Lowered to 2, on a box configured for 10.
	grant := Grant{Credential: 7, MaxPerPair: 2}
	for i := 0; i < 2; i++ {
		if _, err := store.AddMessageWithGrant(envelopeTo("low-"+string(rune('a'+i)), "bob-route"), "node-a", grant); err != nil {
			t.Fatalf("message %d: %v", i, err)
		}
	}
	if _, err := store.AddMessageWithGrant(envelopeTo("low-c", "bob-route"), "node-a", grant); err != ErrPairQuotaFull {
		t.Fatalf("the third on one lane returned %v, want ErrPairQuotaFull", err)
	}

	// Raised to 50: tiering an anti-flood rule upward would sell the right to
	// flood harder, so it does not happen.
	raised := Grant{Credential: 8, MaxPerPair: 50}
	for i := 0; i < 10; i++ {
		if _, err := store.AddMessageWithGrant(envelopeTo("high-"+string(rune('a'+i)), "carol-route"), "node-a", raised); err != nil {
			t.Fatalf("message %d: %v", i, err)
		}
	}
	if _, err := store.AddMessageWithGrant(envelopeTo("high-k", "carol-route"), "node-a", raised); err != ErrPairQuotaFull {
		t.Fatalf("a credential raised the per-pair quota above the box's: %v", err)
	}
}

// The free self-hosted path: no credential, no charge, box caps. Stated as a
// test because it is the behaviour that must survive every future change here.
func TestAnUnattributedWriteIsChargedToNobody(t *testing.T) {
	store := capacityStore(time.Now)
	if _, err := store.AddMessage(envelopeTo("m1", "bob-route"), "node-a"); err != nil {
		t.Fatalf("add: %v", err)
	}
	if got := store.Occupancy(0); got != 0 {
		t.Fatalf("occupancy under the zero credential = %d, want 0", got)
	}
}

// Replicated records are charged to nobody: the relay that accepted the envelope
// already charged its sender's circle, and a per-boot index means nothing on
// another box. Counting it twice would bill a circle for the pool's own copies.
func TestAReplicatedRecordIsChargedToNobody(t *testing.T) {
	store := capacityStore(time.Now)
	store.ImportSnapshot(model.SyncPayload{
		Messages: []model.MessageEnvelope{envelopeTo("m1", "bob-route")},
	})
	for credential := uint32(0); credential < 4; credential++ {
		if got := store.Occupancy(credential); got != 0 {
			t.Fatalf("occupancy for credential %d = %d, want 0", credential, got)
		}
	}
}
