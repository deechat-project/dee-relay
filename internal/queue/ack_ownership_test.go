package queue

import (
	"errors"
	"testing"
	"time"

	"deechat/chat-node/internal/model"
)

const (
	ownerSecret    = "bob-queue-secret-32-bytes-of-random"
	strangerSecret = "stranger-guessed-this-secret"
)

// TestAnAckIsProvedAgainstTheMessageItDeletes. The wire carries no authorization
// for an ack — the tag it is proved against is the one the *node* holds for the
// message, so an attacker who learned a message id has nothing to present.
func TestAnAckIsProvedAgainstTheMessageItDeletes(t *testing.T) {
	store, now := ownedMessageStore(t)

	err := store.AddAckWithGrant(readAck("ack-1", "msg-1", now), "node-a", Grant{}, NewAuth([]string{strangerSecret}, true))
	if !errors.Is(err, ErrNotOwned) {
		t.Fatalf("ack from a stranger = %v, want ErrNotOwned", err)
	}
	if got := store.Stats().Messages; got != 1 {
		t.Fatalf("queued messages after the refused ack = %d, want 1", got)
	}

	if err := store.AddAckWithGrant(readAck("ack-2", "msg-1", now), "node-a", Grant{}, NewAuth([]string{ownerSecret}, true)); err != nil {
		t.Fatalf("ack from the owner returned %v", err)
	}
	if got := store.Stats().Messages; got != 0 {
		t.Fatalf("queued messages after the owner's ack = %d, want 0", got)
	}
}

// TestAnAckCannotCarryItsOwnAuthorization. A tag arriving on the wire is
// discarded: an ack that authorized itself would authorize nothing.
func TestAnAckCannotCarryItsOwnAuthorization(t *testing.T) {
	store, now := ownedMessageStore(t)

	forged := readAck("ack-1", "msg-1", now)
	forged.RecipientTag = TagForSecret(strangerSecret)
	err := store.AddAckWithGrant(forged, "node-a", Grant{}, NewAuth([]string{strangerSecret}, true))
	if !errors.Is(err, ErrNotOwned) {
		t.Fatalf("ack naming its own tag = %v, want ErrNotOwned", err)
	}
}

// TestTheBindingSurvivesTheEnvelopeAndCannotBeLoosened. The first terminal ack
// deletes the envelope; the coupled node_received ack keeps the tag for the rest
// of the message's life, and a later ack — including one that arrives with a tag
// of its own — is still held to it.
func TestTheBindingSurvivesTheEnvelopeAndCannotBeLoosened(t *testing.T) {
	store, now := ownedMessageStore(t)

	delivered := readAck("ack-delivered", "msg-1", now)
	delivered.Type = model.AckRecipientDeviceReceived
	if err := store.AddAckWithGrant(delivered, "node-a", Grant{}, NewAuth([]string{ownerSecret}, true)); err != nil {
		t.Fatalf("delivered ack returned %v", err)
	}
	if got := store.Stats().Messages; got != 0 {
		t.Fatalf("messages after the delivered ack = %d, want 0", got)
	}

	err := store.AddAckWithGrant(readAck("ack-read", "msg-1", now), "node-a", Grant{}, NewAuth([]string{strangerSecret}, true))
	if !errors.Is(err, ErrNotOwned) {
		t.Fatalf("read ack from a stranger, envelope already gone = %v, want ErrNotOwned", err)
	}
}

// TestAnAckForAnUnknownMessageIsStoredUnproved keeps the refusal as narrow as
// the harm — see the httpapi test of the same shape for why that is also what
// keeps the refusal from being an oracle.
func TestAnAckForAnUnknownMessageIsStoredUnproved(t *testing.T) {
	store, now := ownedMessageStore(t)

	if err := store.AddAckWithGrant(readAck("ack-1", "msg-never-seen", now), "node-a", Grant{}, NewAuth(nil, false)); err != nil {
		t.Fatalf("ack for a message this node never held returned %v", err)
	}
}

// TestAnUnprovedAckDoesNotBindATagAnEnvelopeThenInherits. An ack can arrive
// before the message it names — a replicating peer, or a retry that overtook the
// envelope. The empty binding it leaves must be superseded when the real
// envelope lands, or an attacker could pre-bind a message id to "" and ack it
// away afterwards.
func TestAnUnprovedAckDoesNotBindATagAnEnvelopeThenInherits(t *testing.T) {
	now := time.Date(2026, 9, 5, 10, 0, 0, 0, time.UTC)
	store := NewStore(StoreConfig{MaxMessages: 10, MaxAcks: 30, DefaultTTL: time.Hour, Now: func() time.Time { return now }})

	early := readAck("ack-early", "msg-1", now)
	early.Type = model.AckRejected
	if err := store.AddAckWithGrant(early, "node-a", Grant{}, NewAuth([]string{strangerSecret}, true)); err != nil {
		t.Fatalf("ack ahead of its message returned %v", err)
	}

	// hasTerminalAckLocked refuses the envelope outright once a terminal ack for
	// it exists, so use a second id for the envelope half of the check.
	if _, err := store.AddMessage(taggedEnvelope("msg-2", now), "node-a"); err != nil {
		t.Fatalf("AddMessage returned %v", err)
	}
	err := store.AddAckWithGrant(readAck("ack-late", "msg-2", now), "node-a", Grant{}, NewAuth([]string{strangerSecret}, true))
	if !errors.Is(err, ErrNotOwned) {
		t.Fatalf("ack after the envelope landed = %v, want ErrNotOwned", err)
	}
}

// TestTheBindingIndexEmptiesWithTheRecordsThatHoldIt. messageTags is refcounted
// and is not sized by any cap of its own, so a leaked entry would be exactly the
// unbounded map deploy/memory-ceiling.sh exists to rule out. It has to be empty
// once every record naming a message is gone.
func TestTheBindingIndexEmptiesWithTheRecordsThatHoldIt(t *testing.T) {
	now := time.Date(2026, 9, 5, 10, 0, 0, 0, time.UTC)
	store := NewStore(StoreConfig{MaxMessages: 10, MaxAcks: 30, DefaultTTL: time.Hour, Now: func() time.Time { return now }})

	for _, id := range []string{"msg-1", "msg-2", "msg-3"} {
		if _, err := store.AddMessage(taggedEnvelope(id, now), "node-a"); err != nil {
			t.Fatalf("AddMessage %s returned %v", id, err)
		}
	}
	// One delivered by an ack, one purged, one left to expire — every way an
	// envelope can leave, since the refcount is what the four helpers maintain.
	if err := store.AddAckWithGrant(readAck("ack-1", "msg-1", now), "node-a", Grant{}, NewAuth([]string{ownerSecret}, true)); err != nil {
		t.Fatalf("ack returned %v", err)
	}
	store.PurgeOwner("purge-hash")
	store.PruneExpired(now.Add(48 * time.Hour))

	if got := store.Stats(); got.Messages != 0 || got.Acks != 0 {
		t.Fatalf("records left = %+v, want none", got)
	}
	store.mu.Lock()
	remaining := len(store.messageTags)
	store.mu.Unlock()
	if remaining != 0 {
		t.Fatalf("messageTags holds %d bindings after every record left, want 0", remaining)
	}
}

func ownedMessageStore(t *testing.T) (*Store, time.Time) {
	t.Helper()
	now := time.Date(2026, 9, 5, 10, 0, 0, 0, time.UTC)
	store := NewStore(StoreConfig{MaxMessages: 10, MaxAcks: 30, DefaultTTL: time.Hour, Now: func() time.Time { return now }})
	if _, err := store.AddMessage(taggedEnvelope("msg-1", now), "node-a"); err != nil {
		t.Fatalf("AddMessage returned %v", err)
	}
	return store, now
}

func taggedEnvelope(id string, now time.Time) model.MessageEnvelope {
	return model.MessageEnvelope{
		ID:               id,
		Sender:           "alice",
		Recipient:        "bob",
		CreatedAt:        now,
		ExpiresAt:        now.Add(time.Hour),
		EncryptedPayload: "ciphertext",
		RecipientTag:     TagForSecret(ownerSecret),
		Metadata:         map[string]string{"purgeHash": "purge-hash"},
	}
}

func readAck(id, messageID string, now time.Time) model.AckRecord {
	return model.AckRecord{
		ID:        id,
		MessageID: messageID,
		Sender:    "alice",
		Recipient: "bob",
		Type:      model.AckRecipientRead,
		CreatedAt: now,
		ExpiresAt: now.Add(time.Hour),
	}
}
