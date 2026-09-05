package queue

import (
	"testing"
	"time"

	"deechat/chat-node/internal/model"
)

func TestTagForSecretIsStableAndDomainSeparated(t *testing.T) {
	const secret = "queue-secret"
	if TagForSecret(secret) != TagForSecret(secret) {
		t.Fatal("TagForSecret is not deterministic")
	}
	if TagForSecret(secret) == TagForSecret(secret+"x") {
		t.Fatal("distinct secrets produced the same tag")
	}
	if TagForSecret("") != "" {
		t.Fatal("an empty secret must not derive a tag — it would match untagged records")
	}
	// The domain prefix is what stops a tag from colliding with any other
	// SHA-256 the protocol publishes over the same secret.
	if TagForSecret(secret) == TagForSecret(tagDomain+secret) {
		t.Fatal("the tag hash is not domain-separated from a bare hash of the secret")
	}
}

func TestAuthIgnoresCapabilitiesPastTheCap(t *testing.T) {
	secrets := []string{"s1", "s2", "s3", "s4", "s5"}
	auth := NewAuth(secrets, false)

	if !auth.permits(TagForSecret("s4")) {
		t.Fatal("the fourth capability should still be honoured")
	}
	if auth.permits(TagForSecret("s5")) {
		t.Fatalf("a fifth capability was honoured — the cap of %d is not enforced", maxCapabilities)
	}
}

func TestAuthTreatsBlankCapabilitiesAsAbsent(t *testing.T) {
	auth := NewAuth([]string{"", "   "}, false)
	if auth.permits(TagForSecret("")) {
		t.Fatal("blank capabilities must not authorize anything")
	}
	if auth.permits("") {
		t.Fatal("untagged records must stay withheld when allowUntagged is false")
	}
}

// TestMeshSyncPreservesTags is the property that makes this design work across a
// federated mesh: the tag travels with the record, so any node that ends up
// holding the queue can verify a fetch without knowing anything about the owner.
func TestMeshSyncPreservesTags(t *testing.T) {
	const bobSecret = "bob-queue-secret"
	now := time.Now().UTC()
	origin := NewStore(StoreConfig{MaxMessages: 10, MaxAcks: 10, DefaultTTL: time.Hour, Now: func() time.Time { return now }})
	peer := NewStore(StoreConfig{MaxMessages: 10, MaxAcks: 10, DefaultTTL: time.Hour, Now: func() time.Time { return now }})

	if _, err := origin.AddMessage(model.MessageEnvelope{
		ID:               "msg-1",
		Sender:           "alice",
		Recipient:        "bob",
		ExpiresAt:        now.Add(time.Hour),
		EncryptedPayload: "ciphertext",
		RecipientTag:     TagForSecret(bobSecret),
	}, "node-a"); err != nil {
		t.Fatalf("add message: %v", err)
	}

	peer.ImportSnapshot(origin.Snapshot(10))

	if got := len(peer.MessagesForRecipient("bob", 10, NewAuth(nil, true))); got != 0 {
		t.Fatalf("the synced record was served without proof = %d, want 0", got)
	}
	if got := len(peer.MessagesForRecipient("bob", 10, NewAuth([]string{bobSecret}, false))); got != 1 {
		t.Fatalf("the owner could not read the synced record = %d, want 1", got)
	}
}
