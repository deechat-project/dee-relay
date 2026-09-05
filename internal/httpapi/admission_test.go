package httpapi

import (
	"crypto/ed25519"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"deechat/chat-node/internal/admission"
	"deechat/chat-node/internal/config"
	"deechat/chat-node/internal/model"
	"deechat/chat-node/internal/peer"
	"deechat/chat-node/internal/queue"
)

// What this file pins down: before it, a relay's URL *was* its entitlement.
// Anyone who learned the address could point a correctly-tagged client at it and
// use it for free and forever, which meant the first public relay URL would have
// become a permanent free hosted tier by accident.
//
// The address is still not a secret and must never be load-bearing: it leaks
// through DNS, TLS SNI, the device's own config and a screenshot, and a trial
// user is *told* it. Everything here rests on the credential instead.

const stewardCode = "K7M2QRVX8N4PJ0TWZC3HYB6D9F"

// TestAnUngatedRelayServesEveryone is the free self-hosted path, and it is first
// because it is the one that must not change. A relay with no credential file
// applies its box caps to everyone, exactly as generously as it did before this
// gate existed.
func TestAnUngatedRelayServesEveryone(t *testing.T) {
	server := newTestServer()

	postMessageEnvelope(t, server, testEnvelope("msg-open"), http.StatusAccepted)
	if got := getWithAdmission(t, server, "/messages?recipient=bob-route", "").Code; got != http.StatusOK {
		t.Fatalf("GET /messages on an open relay = %d, want 200", got)
	}
	if requireAdmissionOnHealth(t, server) {
		t.Fatal("an open relay publishes requireAdmission=true")
	}
}

// TestAnEnforcingRelayRefusesAnUnprovisionedClient: the whole point. Reads and
// writes both — a gate on writes alone leaves an expired trial using us as free
// store-and-forward, and a gate on reads alone leaves it using us as a drop box.
func TestAnEnforcingRelayRefusesAnUnprovisionedClient(t *testing.T) {
	server, _ := newGatedServer(t, true)

	for _, route := range []struct {
		method string
		target string
		body   any
	}{
		{http.MethodPost, "/messages", testEnvelope("msg-refused")},
		{http.MethodGet, "/messages?recipient=bob-route", nil},
		{http.MethodPost, "/acks", model.AckRecord{}},
		{http.MethodGet, "/acks?sender=alice-route", nil},
		{http.MethodPost, "/presence/heartbeat", model.PresenceHeartbeat{}},
		{http.MethodPost, "/presence/query", model.PresenceQuery{}},
		{http.MethodPost, "/prekeys", model.PrekeyPublish{}},
		{http.MethodGet, "/prekeys/claim?tag=bob-tag", nil},
		{http.MethodGet, "/prekeys/status", nil},
		{http.MethodPost, "/attachments/chunks", map[string]any{}},
		{http.MethodGet, "/attachments/chunks?recipient=bob-route&capability=x", nil},
		{http.MethodPost, "/attachments/complete", map[string]any{"transferId": "t", "capability": "c"}},
	} {
		recorder := httptest.NewRecorder()
		var request *http.Request
		if route.body == nil {
			request = httptest.NewRequest(route.method, route.target, nil)
		} else {
			request = requestJSON(t, route.method, route.target, route.body)
		}
		server.Handler().ServeHTTP(recorder, request)
		if recorder.Code != http.StatusUnauthorized {
			t.Errorf("%s %s = %d, want 401: an ungated route on an enforcing relay is free service",
				route.method, route.target, recorder.Code)
		}
	}
}

// /health stays reachable, because monitoring has to be able to assert the
// switch without holding a credential — and because the node refuses to boot
// enforcing with nothing loaded, a live relay publishing true is admitting
// somebody.
func TestHealthIsReachableAndPublishesTheSwitch(t *testing.T) {
	server, _ := newGatedServer(t, true)
	if !requireAdmissionOnHealth(t, server) {
		t.Fatal("an enforcing relay does not publish requireAdmission=true")
	}
}

func TestAdmissionAdmitsAndTheTermsComeBackWithIt(t *testing.T) {
	server, _ := newGatedServer(t, true)
	token, terms := admitTestCircle(t, server, stewardCode)

	if terms["tier"] != "crew" {
		t.Fatalf("tier = %v, want crew", terms["tier"])
	}
	if terms["queueSlots"] != float64(4) {
		t.Fatalf("queueSlots = %v, want the granted 4", terms["queueSlots"])
	}
	if terms["retentionWindowSec"] != float64((30 * time.Minute).Seconds()) {
		t.Fatalf("retentionWindowSec = %v, want 1800", terms["retentionWindowSec"])
	}
	if _, present := terms["concurrentTransfers"]; present {
		t.Fatal("a zero field reached the client: zero means the box's own cap, which is not a per-credential value")
	}

	postMessageWithAdmission(t, server, testEnvelope("msg-admitted"), token, http.StatusAccepted)
	if got := getWithAdmission(t, server, "/messages?recipient=bob-route", token).Code; got != http.StatusOK {
		t.Fatalf("an admitted read = %d, want 200", got)
	}
}

// The terms are answered to the circle they belong to and to nobody else. A
// relay's *own* ceiling is on /health because it is a property of the box; a
// circle's retention window is not, and an unauthenticated endpoint must not
// answer questions about a specific credential.
func TestHealthPublishesNoPerCredentialValue(t *testing.T) {
	server, _ := newGatedServer(t, true)
	admitTestCircle(t, server, stewardCode)

	recorder := getWithAdmission(t, server, "/health", "")
	var health map[string]any
	decodeResponse(t, recorder, &health)
	for _, leaked := range []string{"tier", "queueSlots", "retentionWindow", "retentionWindowSec",
		"credentials", "admissionCredentials", "notAfter", "transitBytesPerDay"} {
		if _, present := health[leaked]; present {
			t.Errorf("/health publishes %q", leaked)
		}
	}
}

// A wrong or unknown credential answers the same way whether or not this relay
// has ever heard of it. Otherwise the endpoint is an oracle for which circles
// buy from us — the same reasoning the queue-capability path uses.
func TestAdmissionIsNotAnOracle(t *testing.T) {
	server, _ := newGatedServer(t, true)

	_, unknownID := admission.KeyFromCode("K7M2QRVX8N4PJ0TWZC3HYB6D9E")
	unknown := redeem(t, server, unknownID, challenge(t, server), []byte("not a signature at all"))

	key, knownID := admission.KeyFromCode(stewardCode)
	nonce := challenge(t, server)
	wrongSignature := ed25519.Sign(key, admission.Transcript("a different nonce", knownID))
	known := redeem(t, server, knownID, nonce, wrongSignature)

	if unknown.Code != known.Code {
		t.Fatalf("an unknown credential answers %d and a known one with a bad proof answers %d",
			unknown.Code, known.Code)
	}
	if unknown.Body.String() != known.Body.String() {
		t.Fatalf("the two are distinguishable by body:\n unknown: %s\n known:   %s",
			unknown.Body.String(), known.Body.String())
	}
}

// "Expired" and "unknown" have to be different answers — a steward whose window
// ended needs to be told that — so the proof is checked BEFORE the store is
// consulted. Without that ordering, anyone holding a credential id and no proof
// at all could ask this endpoint which circles have ever bought from us.
func TestOnlyACodeHolderCanTellExpiredFromUnknown(t *testing.T) {
	server, credentials := newGatedServer(t, true)
	key, id := admission.KeyFromCode(stewardCode)
	credentials.Replace([]admission.Credential{{
		ID:    id,
		Terms: admission.Terms{Tier: "crew", NotAfter: time.Now().Add(-time.Minute).UTC()},
	}})

	_, unknownID := admission.KeyFromCode("K7M2QRVX8N4PJ0TWZC3HYB6D9J")
	withoutProof := redeem(t, server, id, challenge(t, server), []byte("no proof"))
	unknown := redeem(t, server, unknownID, challenge(t, server), []byte("no proof"))
	if withoutProof.Body.String() != unknown.Body.String() || withoutProof.Code != unknown.Code {
		t.Fatalf("an expired credential is distinguishable from an unknown one without a proof:\n expired: %d %s\n unknown: %d %s",
			withoutProof.Code, withoutProof.Body.String(), unknown.Code, unknown.Body.String())
	}

	nonce := challenge(t, server)
	withProof := redeem(t, server, id, nonce, ed25519.Sign(key, admission.Transcript(nonce, id)))
	if errorCode(t, withProof) != "admission_expired" {
		t.Fatal("the code holder was not told their window had ended")
	}
}

// A session is a handle into the live credential set, not a cached decision. The
// credential is re-resolved per request rather than at provisioning: a session
// opened on day 14 must not survive into day 15, and a revoked credential must
// stop working now rather than in fifteen minutes.
func TestRevokingACredentialTakesEffectMidSession(t *testing.T) {
	server, credentials := newGatedServer(t, true)
	token, _ := admitTestCircle(t, server, stewardCode)
	postMessageWithAdmission(t, server, testEnvelope("msg-before"), token, http.StatusAccepted)

	credentials.Replace(nil)

	recorder := postMessageWithAdmission(t, server, testEnvelope("msg-after"), token, http.StatusForbidden)
	if got := errorCode(t, recorder); got != "admission_refused" {
		t.Fatalf("error = %q, want admission_refused", got)
	}
}

func TestAnExpiredCredentialStopsBeingServed(t *testing.T) {
	server, credentials := newGatedServer(t, true)
	token, _ := admitTestCircle(t, server, stewardCode)

	_, id := admission.KeyFromCode(stewardCode)
	credentials.Replace([]admission.Credential{{
		ID:    id,
		Terms: admission.Terms{Tier: "crew", NotAfter: time.Now().Add(-time.Minute).UTC()},
	}})

	recorder := postMessageWithAdmission(t, server, testEnvelope("msg-expired"), token, http.StatusForbidden)
	if got := errorCode(t, recorder); got != "admission_expired" {
		// The split matters to the client: "re-sign" and "your circle's window
		// ended" are different things to put in front of a person.
		t.Fatalf("error = %q, want admission_expired", got)
	}
}

func TestAnUnknownSessionTokenIsRefusedEvenWhenNotEnforcing(t *testing.T) {
	server, _ := newGatedServer(t, false)

	recorder := postMessageWithAdmission(t, server, testEnvelope("msg-stale"), "not-a-real-session", http.StatusUnauthorized)
	if got := errorCode(t, recorder); got != "admission_stale" {
		t.Fatalf("error = %q, want admission_stale: a client that believes it is admitted and is not must find out", got)
	}
}

// The rollout position, and the reason admission has its own switch: credentials
// loaded, enforcement off. An admitted circle gets its terms; everyone else
// still gets box caps, so the operator can watch before flipping.
func TestCredentialsWithoutEnforcementStillGrantTerms(t *testing.T) {
	server, _ := newGatedServer(t, false)

	postMessageEnvelope(t, server, testEnvelope("msg-unadmitted"), http.StatusAccepted)

	token, _ := admitTestCircle(t, server, stewardCode)
	envelope := testEnvelope("msg-admitted")
	envelope.ExpiresAt = time.Now().Add(48 * time.Hour).UTC()
	recorder := postMessageWithAdmission(t, server, envelope, token, http.StatusAccepted)

	var body struct {
		Ack model.AckRecord `json:"ack"`
	}
	decodeResponse(t, recorder, &body)
	// The circle's 30-minute retention window, applied even though the relay is
	// not refusing anyone yet.
	if window := time.Until(body.Ack.ExpiresAt); window > 31*time.Minute {
		t.Fatalf("the granted retention window was not applied: expiry is %v away", window)
	}
}

// Capacity, end to end through the HTTP surface: a capacity sentence, never a
// permission sentence — nothing has happened to a member, the circle is
// simply holding as much as its tier is sized for.
func TestACircleFillsItsOwnSlotsAndNobodyElsesFirst(t *testing.T) {
	server, _ := newGatedServer(t, true)
	token, _ := admitTestCircle(t, server, stewardCode)

	for i := 0; i < 4; i++ {
		envelope := testEnvelope("msg-slot-" + string(rune('a'+i)))
		envelope.Recipient = "bob-route-" + string(rune('a'+i))
		postMessageWithAdmission(t, server, envelope, token, http.StatusAccepted)
	}
	overflow := testEnvelope("msg-slot-overflow")
	overflow.Recipient = "carol-route"
	recorder := postMessageWithAdmission(t, server, overflow, token, http.StatusTooManyRequests)
	if got := errorCode(t, recorder); got != "circle_slots_full" {
		t.Fatalf("error = %q, want circle_slots_full", got)
	}

	// The box itself still has room, and another circle is unaffected.
	other, _ := admitTestCircle(t, server, "K7M2QRVX8N4PJ0TWZC3HYB6D9G")
	neighbour := testEnvelope("msg-neighbour")
	neighbour.Recipient = "dave-route"
	postMessageWithAdmission(t, server, neighbour, other, http.StatusAccepted)
}

// --- helpers ------------------------------------------------------------------

// newGatedServer builds a relay that admits two circles: the steward's, on a
// deliberately tiny Crew-shaped grant, and a neighbour's, so "one circle cannot
// take the box" is testable.
func newGatedServer(t *testing.T, enforcing bool) (*Server, *admission.Store) {
	t.Helper()
	cfg := config.Config{
		NodeID:           "node-a",
		Addr:             ":0",
		PublicURL:        "http://node-a.local",
		MaxMessages:      50,
		MaxAcks:          100,
		DefaultTTL:       time.Hour,
		MaxTTL:           72 * time.Hour,
		CleanupInterval:  time.Minute,
		RequireAdmission: enforcing,
	}
	store := queue.NewStore(queue.StoreConfig{
		MaxMessages: cfg.MaxMessages,
		MaxAcks:     cfg.MaxAcks,
		MaxTTL:      cfg.MaxTTL,
		DefaultTTL:  cfg.DefaultTTL,
	})

	credentials := admission.NewStore()
	credentials.Replace([]admission.Credential{
		newTestCredential(stewardCode, 4),
		newTestCredential("K7M2QRVX8N4PJ0TWZC3HYB6D9G", 4),
	})
	server := NewServer(cfg, store, peer.NewPool(cfg.NodeID, cfg.PublicURL, nil)).WithAdmissions(credentials)
	return server, credentials
}

func newTestCredential(code string, slots int) admission.Credential {
	_, id := admission.KeyFromCode(code)
	return admission.Credential{
		ID: id,
		Terms: admission.Terms{
			Tier:            "crew",
			NotAfter:        time.Now().Add(14 * 24 * time.Hour).UTC(),
			QueueSlots:      slots,
			RetentionWindow: admission.Duration(30 * time.Minute),
		},
	}
}

func testEnvelope(id string) model.MessageEnvelope {
	return model.MessageEnvelope{
		ID:               id,
		Sender:           "alice-route",
		Recipient:        "bob-route",
		CreatedAt:        time.Now().UTC(),
		ExpiresAt:        time.Now().Add(time.Hour).UTC(),
		EncryptedPayload: "ciphertext",
	}
}

func challenge(t *testing.T, server *Server) string {
	t.Helper()
	recorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/admission/challenge", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("POST /admission/challenge = %d, body = %s", recorder.Code, recorder.Body.String())
	}
	var body struct {
		Nonce string `json:"nonce"`
	}
	decodeResponse(t, recorder, &body)
	if body.Nonce == "" {
		t.Fatal("the challenge carried no nonce")
	}
	return body.Nonce
}

func redeem(t *testing.T, server *Server, credentialID, nonce string, signature []byte) *httptest.ResponseRecorder {
	t.Helper()
	recorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, requestJSON(t, http.MethodPost, "/admission/redeem", map[string]any{
		"credential": credentialID,
		"nonce":      nonce,
		"signature":  base64.RawURLEncoding.EncodeToString(signature),
	}))
	return recorder
}

func admitTestCircle(t *testing.T, server *Server, code string) (string, map[string]any) {
	t.Helper()
	key, id := admission.KeyFromCode(code)
	nonce := challenge(t, server)
	recorder := redeem(t, server, id, nonce, ed25519.Sign(key, admission.Transcript(nonce, id)))
	if recorder.Code != http.StatusOK {
		t.Fatalf("POST /admission/redeem = %d, body = %s", recorder.Code, recorder.Body.String())
	}
	var body struct {
		Session string         `json:"session"`
		Terms   map[string]any `json:"terms"`
	}
	decodeResponse(t, recorder, &body)
	if body.Session == "" {
		t.Fatal("redemption returned no session")
	}
	return body.Session, body.Terms
}

func getWithAdmission(t *testing.T, server *Server, target, token string) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(http.MethodGet, target, nil)
	if token != "" {
		request.Header.Set(admissionHeader, token)
	}
	recorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, request)
	return recorder
}

func postMessageWithAdmission(t *testing.T, server *Server, envelope model.MessageEnvelope, token string, wantStatus int) *httptest.ResponseRecorder {
	t.Helper()
	request := requestJSON(t, http.MethodPost, "/messages", envelope)
	request.Header.Set(admissionHeader, token)
	recorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, request)
	if recorder.Code != wantStatus {
		t.Fatalf("POST /messages status = %d, want %d, body = %s", recorder.Code, wantStatus, recorder.Body.String())
	}
	return recorder
}

func errorCode(t *testing.T, recorder *httptest.ResponseRecorder) string {
	t.Helper()
	var body struct {
		Error string `json:"error"`
	}
	decodeResponse(t, recorder, &body)
	return body.Error
}

func requireAdmissionOnHealth(t *testing.T, server *Server) bool {
	t.Helper()
	recorder := getWithAdmission(t, server, "/health", "")
	var health struct {
		RequireAdmission bool `json:"requireAdmission"`
	}
	decodeResponse(t, recorder, &health)
	return health.RequireAdmission
}
