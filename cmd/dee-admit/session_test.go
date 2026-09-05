package main

// These tests run against the *real* relay handler, not a stub of it, and that
// is the point of them. The thing this command exists to prevent is a second
// implementation of the code → keypair → signature derivation drifting from the
// one the relay verifies with; a fake server that accepts whatever this file
// sends would prove nothing about that. So internal/httpapi serves the two
// routes, internal/admission holds the credentials, and a signature that stops
// verifying fails here.

import (
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"deechat/chat-node/internal/admission"
	"deechat/chat-node/internal/config"
	"deechat/chat-node/internal/httpapi"
	"deechat/chat-node/internal/peer"
	"deechat/chat-node/internal/queue"
)

const testCode = "DAAYH9DHD0570JN56MNR638HP8"

func TestSessionOpensAgainstTheRealRelay(t *testing.T) {
	relay, _ := gatedRelay(t, credentialFor(testCode, time.Now().Add(14*24*time.Hour)))

	token, expiresIn, terms, err := redeemFor(t, relay, testCode)
	if err != nil {
		t.Fatalf("a code the relay admits was refused: %v", err)
	}
	if token == "" {
		t.Fatal("the exchange returned an empty session token")
	}
	if expiresIn <= 0 {
		t.Fatalf("expiresInSec = %d, want a positive window", expiresIn)
	}
	// The terms come back from the exchange rather than from the local file,
	// because what the operator needs to see is what the RELAY thinks the code
	// grants — the two differ exactly when the file was edited and not reloaded.
	if got := describeGrantedTerms(terms); !strings.Contains(got, "crew") {
		t.Fatalf("terms = %q, want the tier the relay granted", got)
	}
}

// The token has to work. An exchange that returns a plausible string which the
// gate then refuses would leave setup-verify.sh reporting a working relay as one
// that loses mail, so the round trip is asserted rather than assumed.
func TestSessionTokenIsAcceptedByTheGate(t *testing.T) {
	relay, _ := gatedRelay(t, credentialFor(testCode, time.Now().Add(14*24*time.Hour)))

	token, _, _, err := redeemFor(t, relay, testCode)
	if err != nil {
		t.Fatalf("redeem: %v", err)
	}

	request := httptest.NewRequest("GET", "/messages?recipient=nobody", nil)
	request.Header.Set("X-Dee-Admission", token)
	recorder := httptest.NewRecorder()
	relay.Config.Handler.ServeHTTP(recorder, request)
	if recorder.Code == 401 || recorder.Code == 403 {
		t.Fatalf("the gate refused the session this exchange opened: %d %s", recorder.Code, recorder.Body.String())
	}
}

// The three refusals are one status code on the wire and three different jobs
// for whoever is reading the report. Telling them apart is most of the value of
// running this by hand during a support thread.
func TestSessionTellsTheRefusalsApart(t *testing.T) {
	expired, _ := gatedRelay(t, credentialFor(testCode, time.Now().Add(-time.Hour)))
	if _, _, _, err := redeemFor(t, expired, testCode); err == nil {
		t.Fatal("an expired credential opened a session")
	} else if !strings.Contains(err.Error(), "window has ended") {
		t.Fatalf("expired credential said %q, want the renewal instruction", err)
	}

	unknown, _ := gatedRelay(t, credentialFor("K7M2QRVX8N4PJ0TWZC3HYB6D9G", time.Now().Add(time.Hour)))
	if _, _, _, err := redeemFor(t, unknown, testCode); err == nil {
		t.Fatal("a code this relay never admitted opened a session")
	} else if !strings.Contains(err.Error(), "does not admit") {
		t.Fatalf("unknown credential said %q", err)
	}
}

// A code arrives lowercased from a text message, or hyphenated because someone
// grouped it to read it out. All three forms have to derive the same credential
// the relay stored, or a customer's perfectly correct code simply does not work.
func TestSessionNormalizesTheCodeTheWayTheRelayDoes(t *testing.T) {
	relay, _ := gatedRelay(t, credentialFor(testCode, time.Now().Add(time.Hour)))

	for _, written := range []string{
		testCode,
		strings.ToLower(testCode),
		"DAAY-H9DH-D057-0JN5-6MNR-638H-P8",
		"  " + testCode + "  ",
	} {
		if _, _, _, err := redeemFor(t, relay, written); err != nil {
			t.Fatalf("the code written as %q was refused: %v", written, err)
		}
	}
}

// --- helpers ------------------------------------------------------------------

// redeemFor runs the whole exchange the command runs, over a live loopback
// listener, so the HTTP client in session.go is the code under test rather than
// something reimplemented here.
func redeemFor(t *testing.T, relay *httptest.Server, code string) (string, int, map[string]any, error) {
	t.Helper()
	key, credentialID := admission.KeyFromCode(code)
	client := relay.Client()

	nonce, err := challenge(client, relay.URL)
	if err != nil {
		return "", 0, nil, err
	}
	return redeem(client, relay.URL, credentialID, nonce, signChallenge(key, nonce, credentialID))
}

func gatedRelay(t *testing.T, credentials ...admission.Credential) (*httptest.Server, *admission.Store) {
	t.Helper()
	cfg := config.Config{
		NodeID:           "session-test",
		Addr:             ":0",
		PublicURL:        "http://session-test.local",
		MaxMessages:      50,
		MaxAcks:          100,
		DefaultTTL:       time.Hour,
		MaxTTL:           72 * time.Hour,
		CleanupInterval:  time.Minute,
		RequireAdmission: true,
	}
	store := queue.NewStore(queue.StoreConfig{
		MaxMessages: cfg.MaxMessages,
		MaxAcks:     cfg.MaxAcks,
		MaxTTL:      cfg.MaxTTL,
		DefaultTTL:  cfg.DefaultTTL,
	})
	admissions := admission.NewStore()
	admissions.Replace(credentials)
	server := httpapi.NewServer(cfg, store, peer.NewPool(cfg.NodeID, cfg.PublicURL, nil)).
		WithAdmissions(admissions)

	relay := httptest.NewServer(server.Handler())
	t.Cleanup(relay.Close)
	return relay, admissions
}

func credentialFor(code string, notAfter time.Time) admission.Credential {
	_, id := admission.KeyFromCode(code)
	return admission.Credential{
		ID: id,
		Terms: admission.Terms{
			Tier:     "crew",
			NotAfter: notAfter.UTC(),
		},
	}
}
