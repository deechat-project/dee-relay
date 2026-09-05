package httpapi

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"deechat/chat-node/internal/model"
	"deechat/chat-node/internal/queue"
)

// The threat this file pins down is the other half of fetch_auth_test.go's. That
// file is about reading a queue you do not own; this one is about *writing* into
// one — the three routes that took no ownership proof at all:
//
//   - POST /acks. Five of the six ack types delete the message they name, so a
//     caller who learned a message id could destroy a third party's queued mail
//     with one unauthenticated request.
//   - POST /prekeys. A pool used to be keyed by routing id, so anyone could open
//     a victim's pool and fill its 100 entries with prekeys nobody holds the
//     private half of — locking the real owner out of publishing until the TTL
//     ran out.
//   - GET /prekeys/status. Same key, so it answered "does this identity hold
//     prekeys" for any routing id anyone cared to try.
//
// All three are the same missing thing, a proof of ownership over a routing id,
// and all three are answered the same way: a routing id is a name — it is minted
// from a handle slug, so it is guessable and proves nothing — and a queue tag is
// the hash of a secret only its owner holds. Nothing here is keyed on the id any
// more.

// TestAnAckCannotDeleteAMessageWithoutTheRecipientsCapability is the mail-loss
// case, and it is the reason POST /acks is a write and not a note.
func TestAnAckCannotDeleteAMessageWithoutTheRecipientsCapability(t *testing.T) {
	server := newTestServer()
	postTaggedMessage(t, server, "msg-tagged", "alice-route", "bob-route")

	refused := postAckAs(t, server, terminalAck("ack-1", "msg-tagged"), strangerGuess)
	if refused.Code != http.StatusForbidden {
		t.Fatalf("ack posted with a stranger's secret = %d, want 403; body = %s", refused.Code, refused.Body.String())
	}
	if got := len(fetchMessages(t, server, "bob-route", bobSecret)); got != 1 {
		t.Fatalf("queued messages after the refused ack = %d, want 1 — the mail was deleted", got)
	}

	// And the owner can still do it, which is the whole point: this is an
	// authorization, not a new obstacle to delivery.
	accepted := postAckAs(t, server, terminalAck("ack-2", "msg-tagged"), bobSecret)
	if accepted.Code != http.StatusAccepted {
		t.Fatalf("ack posted by the recipient = %d, want 202; body = %s", accepted.Code, accepted.Body.String())
	}
	if got := len(fetchMessages(t, server, "bob-route", bobSecret)); got != 0 {
		t.Fatalf("queued messages after the owner's ack = %d, want 0", got)
	}
}

// TestTheAckBindingOutlivesTheMessage: the first terminal ack deletes the
// envelope, and the proof has to survive it. A recipient posts a delivered ack
// and then a read ack for the same message — by the second one there is no
// envelope left to read a tag off, and it must still be the recipient's alone.
func TestTheAckBindingOutlivesTheMessage(t *testing.T) {
	server := newTestServer()
	postTaggedMessage(t, server, "msg-tagged", "alice-route", "bob-route")

	delivered := terminalAck("ack-delivered", "msg-tagged")
	delivered.Type = model.AckRecipientDeviceReceived
	if got := postAckAs(t, server, delivered, bobSecret).Code; got != http.StatusAccepted {
		t.Fatalf("delivered ack = %d, want 202", got)
	}

	read := terminalAck("ack-read", "msg-tagged")
	if got := postAckAs(t, server, read, strangerGuess).Code; got != http.StatusForbidden {
		t.Fatalf("read ack from a stranger, after the envelope was deleted = %d, want 403", got)
	}
	if got := postAckAs(t, server, read, bobSecret).Code; got != http.StatusAccepted {
		t.Fatalf("read ack from the recipient = %d, want 202", got)
	}
}

// TestAnAckForAMessageThisRelayNeverHeldIsAccepted keeps the refusal exactly as
// narrow as the harm. There is nothing behind such an ack to destroy, and
// refusing would break a late ack for a message that has already timed out — so
// what an unproved caller gets is a slot in the caller-posted ack budget, which
// is bounded and expires — parity with what posting to a fabricated recipient
// already buys a caller.
//
// It is also what keeps the 403 from being an oracle: the node refuses only
// where it holds a tag the caller could not match, never because a message is
// absent, so the answer never distinguishes an absent message from someone
// else's.
func TestAnAckForAMessageThisRelayNeverHeldIsAccepted(t *testing.T) {
	server := newTestServer()

	stray := terminalAck("ack-stray", "msg-this-node-never-saw")
	if got := postAckAs(t, server, stray, "").Code; got != http.StatusAccepted {
		t.Fatalf("ack for an unknown message = %d, want 202", got)
	}
}

// TestAnUntaggedMessageStaysAckableInCompatMode: a client predating fetch auth
// stamps no tag, and the node is not enforcing, so its own acks still land.
// Enforcement is what closes this path, exactly as it does for a read.
func TestAnUntaggedMessageStaysAckableInCompatMode(t *testing.T) {
	server := newTestServer()
	postMessageEnvelope(t, server, model.MessageEnvelope{
		ID:               "msg-untagged",
		Sender:           "alice-route",
		Recipient:        "bob-route",
		CreatedAt:        time.Now().UTC(),
		ExpiresAt:        time.Now().Add(time.Hour).UTC(),
		EncryptedPayload: "ciphertext",
	}, http.StatusAccepted)

	if got := postAckAs(t, server, terminalAck("ack-1", "msg-untagged"), "").Code; got != http.StatusAccepted {
		t.Fatalf("ack for an untagged message on a compat node = %d, want 202", got)
	}
}

// TestEnforcingNodeRefusesAnAckWithNoCapabilityAtAll pins the other status: an
// enforcing node answers 401 before it looks at anything, the same as it does
// for a read, rather than 403 after resolving the message.
func TestEnforcingNodeRefusesAnAckWithNoCapabilityAtAll(t *testing.T) {
	server := newEnforcingTestServer()
	postTaggedMessage(t, server, "msg-tagged", "alice-route", "bob-route")

	if got := postAckAs(t, server, terminalAck("ack-1", "msg-tagged"), "").Code; got != http.StatusUnauthorized {
		t.Fatalf("ack with no capability on an enforcing node = %d, want 401", got)
	}
}

// TestAPrekeyPoolIsOnlyFillableByItsOwner is the lockout case. Mallory publishes
// as hard as she likes; what she fills is her own pool, because the pool she
// names is the one her capability derives.
func TestAPrekeyPoolIsOnlyFillableByItsOwner(t *testing.T) {
	server := newTestServer()

	if got := publishPrekeyAs(t, server, "mallory-secret", "opk-mallory").Code; got != http.StatusAccepted {
		t.Fatalf("mallory's publish = %d, want 202", got)
	}
	if got := publishPrekeyAs(t, server, bobSecret, "opk-bob").Code; got != http.StatusAccepted {
		t.Fatalf("bob's publish = %d, want 202", got)
	}

	if got := prekeyStatusAs(t, server, bobSecret); got != 1 {
		t.Fatalf("bob's pool = %d entries, want 1 — mallory's publish landed in it", got)
	}
	if got := prekeyStatusAs(t, server, "mallory-secret"); got != 1 {
		t.Fatalf("mallory's pool = %d entries, want 1", got)
	}

	// And a sender claims from bob's pool with bob's *tag*, which is the public
	// half his contacts already hold — not with a routing id anyone can guess.
	claimed := httptest.NewRecorder()
	server.Handler().ServeHTTP(claimed, httptest.NewRequest(http.MethodGet, "/prekeys/claim?tag="+queue.TagForSecret(bobSecret), nil))
	var body struct {
		Prekey model.PrekeyEntry `json:"prekey"`
	}
	decodeResponse(t, claimed, &body)
	if body.Prekey.OpkID != "opk-bob" {
		t.Fatalf("claim against bob's tag = %q, want opk-bob", body.Prekey.OpkID)
	}
}

// TestPrekeyWritesAndStatusRequireACapability: both routes act on the caller's
// own pool, so a request that proves nothing names no pool and there is nothing
// for the node to do with it. Refused in *both* modes — unlike a read, there is
// no pre-fetch-auth record here whose compatibility has to be kept.
func TestPrekeyWritesAndStatusRequireACapability(t *testing.T) {
	for _, server := range map[string]*Server{"compat": newTestServer(), "enforcing": newEnforcingTestServer()} {
		publish := httptest.NewRecorder()
		server.Handler().ServeHTTP(publish, requestJSON(t, http.MethodPost, "/prekeys", model.PrekeyPublish{
			Entries: []model.PrekeyEntry{{OpkID: "opk-1", PublicKey: "pub", Signature: "sig"}},
		}))
		if publish.Code != http.StatusUnauthorized {
			t.Fatalf("POST /prekeys with no capability = %d, want 401", publish.Code)
		}

		status := httptest.NewRecorder()
		server.Handler().ServeHTTP(status, httptest.NewRequest(http.MethodGet, "/prekeys/status", nil))
		if status.Code != http.StatusUnauthorized {
			t.Fatalf("GET /prekeys/status with no capability = %d, want 401", status.Code)
		}
	}
}

// TestPrekeyStatusCannotBeAskedAboutSomebodyElse is the oracle, and the fix is
// that the question is no longer expressible: the route takes no subject, so the
// only pool a caller can ask after is the one it proved. A stranger presenting a
// secret of their own gets an answer about their own empty pool and learns
// nothing about bob's.
func TestPrekeyStatusCannotBeAskedAboutSomebodyElse(t *testing.T) {
	server := newTestServer()
	if got := publishPrekeyAs(t, server, bobSecret, "opk-bob").Code; got != http.StatusAccepted {
		t.Fatalf("bob's publish = %d, want 202", got)
	}

	if got := prekeyStatusAs(t, server, bobSecret); got != 1 {
		t.Fatalf("bob asking about bob = %d, want 1", got)
	}
	if got := prekeyStatusAs(t, server, strangerGuess); got != 0 {
		t.Fatalf("a stranger's status = %d, want 0 — the answer is about the asker, not about bob", got)
	}

	// The old shape, spelled out so a regression is loud: there is no parameter
	// that names another identity. A routing id in the query is ignored, so it
	// cannot come back as an answer about somebody else.
	guessing := getWithCapability(t, server, "/prekeys/status?recipient=bob-route", strangerGuess)
	var status struct {
		Available int `json:"available"`
	}
	decodeResponse(t, guessing, &status)
	if status.Available != 0 {
		t.Fatalf("status for ?recipient=bob-route = %d, want 0 — the route answered about a routing id", status.Available)
	}
}

func terminalAck(id, messageID string) model.AckRecord {
	return model.AckRecord{
		ID:        id,
		MessageID: messageID,
		Sender:    "alice-route",
		Recipient: "bob-route",
		Type:      model.AckRecipientRead,
		CreatedAt: time.Now().UTC(),
		ExpiresAt: time.Now().Add(time.Hour).UTC(),
		SenderTag: queue.TagForSecret(aliceSecret),
	}
}

func postAckAs(t *testing.T, server *Server, ack model.AckRecord, capability string) *httptest.ResponseRecorder {
	t.Helper()
	request := requestJSON(t, http.MethodPost, "/acks", ack)
	if capability != "" {
		request.Header.Set(queueCapabilityHeader, capability)
	}
	recorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, request)
	return recorder
}

func publishPrekeyAs(t *testing.T, server *Server, secret, opkID string) *httptest.ResponseRecorder {
	t.Helper()
	recorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, asOwner(requestJSON(t, http.MethodPost, "/prekeys", model.PrekeyPublish{
		Entries: []model.PrekeyEntry{{OpkID: opkID, PublicKey: "pub-" + opkID, Signature: "sig-" + opkID}},
	}), secret))
	return recorder
}

func prekeyStatusAs(t *testing.T, server *Server, secret string) int {
	t.Helper()
	recorder := getWithCapability(t, server, "/prekeys/status", secret)
	if recorder.Code != http.StatusOK {
		t.Fatalf("GET /prekeys/status status = %d, body = %s", recorder.Code, recorder.Body.String())
	}
	var body struct {
		Available int `json:"available"`
	}
	decodeResponse(t, recorder, &body)
	return body.Available
}
