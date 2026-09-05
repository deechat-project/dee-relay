package httpapi

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"deechat/chat-node/internal/config"
	"deechat/chat-node/internal/model"
	"deechat/chat-node/internal/peer"
	"deechat/chat-node/internal/queue"
)

// The threat this file pins down: anyone who knows a routing id could pull that
// identity's queued envelopes and acks. Routing ids are handle slugs, so
// "knows or guesses" is a dictionary attack. See the README,
// § "Queue-read authorization".

const (
	bobSecret     = "bob-queue-secret-32-bytes-of-random"
	aliceSecret   = "alice-queue-secret-32-bytes-random"
	strangerGuess = "stranger-guessed-this-secret"
)

// TestTaggedQueueIsWithheldWithoutCapability is the core guarantee, and it holds
// in *compatibility* mode: protection starts when a sender stamps a tag, not
// when the operator flips the enforcement flag.
func TestTaggedQueueIsWithheldWithoutCapability(t *testing.T) {
	server := newTestServer()
	postTaggedMessage(t, server, "msg-tagged", "alice-route", "bob-route")

	if got := len(fetchMessages(t, server, "bob-route", "")); got != 0 {
		t.Fatalf("messages served with no capability = %d, want 0", got)
	}
	if got := len(fetchMessages(t, server, "bob-route", bobSecret)); got != 1 {
		t.Fatalf("messages served to the owner = %d, want 1", got)
	}
}

// TestWrongCapabilityIsNotAnOracle: a wrong secret must be indistinguishable
// from an empty queue. A 403 here would hand back the "does this routing id have
// mail waiting" signal the design exists to remove.
func TestWrongCapabilityIsNotAnOracle(t *testing.T) {
	server := newTestServer()
	postTaggedMessage(t, server, "msg-tagged", "alice-route", "bob-route")

	withMail := getWithCapability(t, server, "/messages?recipient=bob-route", strangerGuess)
	noMail := getWithCapability(t, server, "/messages?recipient=nobody-route", strangerGuess)

	if withMail.Code != http.StatusOK || noMail.Code != http.StatusOK {
		t.Fatalf("statuses = %d and %d, want both 200", withMail.Code, noMail.Code)
	}
	if withMail.Body.String() != noMail.Body.String() {
		t.Fatalf("a wrong capability is distinguishable from an empty queue:\n queue with mail: %s\n queue with none: %s",
			withMail.Body.String(), noMail.Body.String())
	}
}

// TestUntaggedQueueStillFlowsInCompatMode: a client that predates fetch auth
// keeps working until the operator enforces. Without this the rollout would be a
// flag day.
func TestUntaggedQueueStillFlowsInCompatMode(t *testing.T) {
	server := newTestServer()
	postMessageEnvelope(t, server, model.MessageEnvelope{
		ID:               "msg-legacy",
		Sender:           "alice-route",
		Recipient:        "bob-route",
		ExpiresAt:        time.Now().Add(time.Hour).UTC(),
		EncryptedPayload: "ciphertext",
	}, http.StatusAccepted)

	if got := len(fetchMessages(t, server, "bob-route", "")); got != 1 {
		t.Fatalf("legacy messages served in compat mode = %d, want 1", got)
	}
}

func TestEnforcingNodeRequiresACapability(t *testing.T) {
	server := newEnforcingTestServer()
	postTaggedMessage(t, server, "msg-tagged", "alice-route", "bob-route")

	recorder := getWithCapability(t, server, "/messages?recipient=bob-route", "")
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("status with no capability = %d, want 401", recorder.Code)
	}
	var body struct {
		Error string `json:"error"`
	}
	decodeResponse(t, recorder, &body)
	if body.Error != "capability_required" {
		t.Fatalf("error = %q, want capability_required", body.Error)
	}
}

// TestEnforcingNodeWithholdsUntaggedRecords is the other half of enforcement:
// flipping the flag must actually stop serving the legacy records, otherwise a
// stranger keeps everything it had before.
func TestEnforcingNodeWithholdsUntaggedRecords(t *testing.T) {
	server := newEnforcingTestServer()
	// Reach past the handler: an enforcing node rejects an untagged POST, so the
	// only way this record exists is a mesh import from a node that isn't
	// enforcing yet — exactly the case worth testing.
	if _, err := server.store.AddMessage(model.MessageEnvelope{
		ID:               "msg-legacy",
		Sender:           "alice-route",
		Recipient:        "bob-route",
		ExpiresAt:        time.Now().Add(time.Hour).UTC(),
		EncryptedPayload: "ciphertext",
	}, "node-a"); err != nil {
		t.Fatalf("seed untagged message: %v", err)
	}

	if got := len(fetchMessages(t, server, "bob-route", bobSecret)); got != 0 {
		t.Fatalf("untagged messages served by an enforcing node = %d, want 0", got)
	}
}

// TestEnforcingNodeRejectsUntaggedPost: accepting it would queue mail nobody can
// fetch. A loud rejection beats a silent black hole.
func TestEnforcingNodeRejectsUntaggedPost(t *testing.T) {
	server := newEnforcingTestServer()
	recorder := postMessageEnvelope(t, server, model.MessageEnvelope{
		ID:               "msg-untagged",
		Sender:           "alice-route",
		Recipient:        "bob-route",
		ExpiresAt:        time.Now().Add(time.Hour).UTC(),
		EncryptedPayload: "ciphertext",
	}, http.StatusBadRequest)

	var body struct {
		Error string `json:"error"`
	}
	decodeResponse(t, recorder, &body)
	if body.Error != "fetch_tag_required" {
		t.Fatalf("error = %q, want fetch_tag_required", body.Error)
	}
}

// TestNodeMintedAckCarriesTheSenderTag: the node mints node_received itself, so
// if it dropped the sender's tag the sender could never fetch the ack for its
// own message once enforcement is on.
func TestNodeMintedAckCarriesTheSenderTag(t *testing.T) {
	server := newTestServer()
	postTaggedMessage(t, server, "msg-tagged", "alice-route", "bob-route")

	if got := len(fetchAcks(t, server, "alice-route", aliceSecret)); got != 1 {
		t.Fatalf("acks served to the sender = %d, want 1", got)
	}
	// The recipient's own secret must not open the sender's ack lane.
	if got := len(fetchAcks(t, server, "alice-route", bobSecret)); got != 0 {
		t.Fatalf("acks served to the wrong holder = %d, want 0", got)
	}
}

// TestRotationServesBothTags: after rotating, the queue still holds envelopes
// stamped with the previous tag, and contacts may not have seen the new one. One
// fetch presenting both secrets must drain both.
func TestRotationServesBothTags(t *testing.T) {
	const rotated = "bob-rotated-queue-secret"
	server := newTestServer()
	postTaggedMessage(t, server, "msg-old-tag", "alice-route", "bob-route")
	postMessageEnvelope(t, server, model.MessageEnvelope{
		ID:               "msg-new-tag",
		Sender:           "alice-route",
		Recipient:        "bob-route",
		ExpiresAt:        time.Now().Add(time.Hour).UTC(),
		EncryptedPayload: "ciphertext",
		RecipientTag:     queue.TagForSecret(rotated),
		SenderTag:        queue.TagForSecret(aliceSecret),
	}, http.StatusAccepted)

	both := bobSecret + " " + rotated
	if got := len(fetchMessages(t, server, "bob-route", both)); got != 2 {
		t.Fatalf("messages served across a rotation = %d, want 2", got)
	}
}

func newEnforcingTestServer() *Server {
	cfg := config.Config{
		NodeID:           "node-a",
		Addr:             ":0",
		PublicURL:        "http://node-a.local",
		MaxMessages:      10,
		MaxAcks:          10,
		DefaultTTL:       time.Hour,
		CleanupInterval:  time.Minute,
		RequireFetchAuth: true,
	}
	store := queue.NewStore(queue.StoreConfig{
		MaxMessages: cfg.MaxMessages,
		MaxAcks:     cfg.MaxAcks,
		DefaultTTL:  cfg.DefaultTTL,
	})
	pool := peer.NewPool(cfg.NodeID, cfg.PublicURL, cfg.MeshPeers)
	return NewServer(cfg, store, pool)
}

func postTaggedMessage(t *testing.T, server *Server, id, sender, recipient string) {
	t.Helper()
	postMessageEnvelope(t, server, model.MessageEnvelope{
		ID:               id,
		Sender:           sender,
		Recipient:        recipient,
		CreatedAt:        time.Now().UTC(),
		ExpiresAt:        time.Now().Add(time.Hour).UTC(),
		EncryptedPayload: "ciphertext",
		RecipientTag:     queue.TagForSecret(bobSecret),
		SenderTag:        queue.TagForSecret(aliceSecret),
	}, http.StatusAccepted)
}

func postMessageEnvelope(t *testing.T, server *Server, envelope model.MessageEnvelope, wantStatus int) *httptest.ResponseRecorder {
	t.Helper()
	recorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, requestJSON(t, http.MethodPost, "/messages", envelope))
	if recorder.Code != wantStatus {
		t.Fatalf("POST /messages status = %d, want %d, body = %s", recorder.Code, wantStatus, recorder.Body.String())
	}
	return recorder
}

func fetchMessages(t *testing.T, server *Server, recipient, capability string) []model.MessageEnvelope {
	t.Helper()
	recorder := getWithCapability(t, server, "/messages?recipient="+recipient, capability)
	if recorder.Code != http.StatusOK {
		t.Fatalf("GET /messages status = %d, body = %s", recorder.Code, recorder.Body.String())
	}
	var body struct {
		Messages []model.MessageEnvelope `json:"messages"`
	}
	decodeResponse(t, recorder, &body)
	return body.Messages
}

func fetchAcks(t *testing.T, server *Server, sender, capability string) []model.AckRecord {
	t.Helper()
	recorder := getWithCapability(t, server, "/acks?sender="+sender, capability)
	if recorder.Code != http.StatusOK {
		t.Fatalf("GET /acks status = %d, body = %s", recorder.Code, recorder.Body.String())
	}
	var body struct {
		Acks []model.AckRecord `json:"acks"`
	}
	decodeResponse(t, recorder, &body)
	return body.Acks
}

func getWithCapability(t *testing.T, server *Server, target, capability string) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(http.MethodGet, target, nil)
	if capability != "" {
		request.Header.Set(queueCapabilityHeader, capability)
	}
	recorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, request)
	return recorder
}
