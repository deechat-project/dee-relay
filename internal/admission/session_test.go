package admission

import (
	"crypto/ed25519"
	"testing"
	"time"
)

func proofFor(t *testing.T, sessions *Sessions, code string) (string, string) {
	t.Helper()
	key, id := KeyFromCode(code)
	nonce, _, err := sessions.Challenge()
	if err != nil {
		t.Fatalf("Challenge: %v", err)
	}
	if err := sessions.VerifyProof(id, nonce, ed25519.Sign(key, Transcript(nonce, id))); err != nil {
		t.Fatalf("VerifyProof: %v", err)
	}
	token, _, err := sessions.Open(id)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	return id, token
}

func TestASignedChallengeOpensASession(t *testing.T) {
	sessions := NewSessions(time.Now)
	id, token := proofFor(t, sessions, "K7M2QRVX8N4PJ0TWZC3HYB6D9F")

	resolved, err := sessions.Resolve(token)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if resolved != id {
		t.Fatalf("session resolved to %s, want %s", resolved, id)
	}
}

// A nonce is spent whether or not the proof was good. Otherwise one challenge
// buys an unbounded number of attempts, which is the only thing standing between
// an attacker and offline-quality guessing against a live relay.
func TestANonceIsSpentOnFirstUseEvenByABadProof(t *testing.T) {
	sessions := NewSessions(time.Now)
	key, id := KeyFromCode("K7M2QRVX8N4PJ0TWZC3HYB6D9F")

	nonce, _, err := sessions.Challenge()
	if err != nil {
		t.Fatalf("Challenge: %v", err)
	}
	good := ed25519.Sign(key, Transcript(nonce, id))
	if err := sessions.VerifyProof(id, nonce, good[:len(good)-1]); err != ErrBadProof {
		t.Fatalf("a truncated signature returned %v, want ErrBadProof", err)
	}
	if err := sessions.VerifyProof(id, nonce, good); err != ErrBadProof {
		t.Fatal("the nonce survived a failed attempt; one challenge is now unlimited guesses")
	}

	// And a fresh challenge still works, so spending it is not a lockout.
	proofFor(t, sessions, "K7M2QRVX8N4PJ0TWZC3HYB6D9F")
}

func TestAReplayedProofIsRefused(t *testing.T) {
	sessions := NewSessions(time.Now)
	key, id := KeyFromCode("K7M2QRVX8N4PJ0TWZC3HYB6D9F")

	nonce, _, _ := sessions.Challenge()
	signature := ed25519.Sign(key, Transcript(nonce, id))
	if err := sessions.VerifyProof(id, nonce, signature); err != nil {
		t.Fatalf("the first redemption failed: %v", err)
	}
	if err := sessions.VerifyProof(id, nonce, signature); err != ErrBadProof {
		t.Fatal("the same proof was accepted twice; a captured exchange is reusable")
	}
}

func TestAStaleChallengeIsRefused(t *testing.T) {
	clock := time.Date(2026, 8, 11, 12, 0, 0, 0, time.UTC)
	sessions := NewSessions(func() time.Time { return clock })
	key, id := KeyFromCode("K7M2QRVX8N4PJ0TWZC3HYB6D9F")

	nonce, ttl, _ := sessions.Challenge()
	clock = clock.Add(ttl + time.Second)
	if err := sessions.VerifyProof(id, nonce, ed25519.Sign(key, Transcript(nonce, id))); err != ErrBadProof {
		t.Fatalf("an expired nonce was accepted: %v", err)
	}
}

func TestASessionExpiresAndIsSweptAway(t *testing.T) {
	clock := time.Date(2026, 8, 11, 12, 0, 0, 0, time.UTC)
	sessions := NewSessions(func() time.Time { return clock })
	_, token := proofFor(t, sessions, "K7M2QRVX8N4PJ0TWZC3HYB6D9F")

	clock = clock.Add(sessionTTL + time.Second)
	if _, err := sessions.Resolve(token); err != ErrNoSession {
		t.Fatalf("an expired session resolved with %v, want ErrNoSession", err)
	}
	if _, live := sessions.Counts(); live != 0 {
		t.Fatalf("%d expired sessions are still held", live)
	}
}

// Revocation drops the circle's live sessions rather than waiting for them to
// age out. The per-request lookup already refuses them; this keeps the table
// from holding a revoked circle's tokens for another quarter of an hour.
func TestForgettingACredentialClosesItsSessions(t *testing.T) {
	sessions := NewSessions(time.Now)
	id, token := proofFor(t, sessions, "K7M2QRVX8N4PJ0TWZC3HYB6D9F")
	_, otherToken := proofFor(t, sessions, "K7M2QRVX8N4PJ0TWZC3HYB6D9E")

	sessions.Forget(id)
	if _, err := sessions.Resolve(token); err != ErrNoSession {
		t.Fatal("a forgotten credential's session still resolves")
	}
	if _, err := sessions.Resolve(otherToken); err != nil {
		t.Fatalf("another circle's session was dropped too: %v", err)
	}
}

// One circle fills its own allowance rather than the table. Every member's
// device opens its own session under the same credential, so the eviction has to
// be per credential and it has to drop the oldest rather than refusing the
// newest — a member who just re-signed is the one still using the relay.
func TestOneCircleCannotFillTheSessionTable(t *testing.T) {
	sessions := NewSessions(time.Now)
	key, id := KeyFromCode("K7M2QRVX8N4PJ0TWZC3HYB6D9F")

	var tokens []string
	for i := 0; i < maxSessionsPerCredential+5; i++ {
		nonce, _, err := sessions.Challenge()
		if err != nil {
			t.Fatalf("Challenge %d: %v", i, err)
		}
		if err := sessions.VerifyProof(id, nonce, ed25519.Sign(key, Transcript(nonce, id))); err != nil {
			t.Fatalf("VerifyProof %d: %v", i, err)
		}
		token, _, err := sessions.Open(id)
		if err != nil {
			t.Fatalf("Open %d: %v", i, err)
		}
		tokens = append(tokens, token)
	}

	if _, live := sessions.Counts(); live != maxSessionsPerCredential {
		t.Fatalf("live sessions = %d, want the per-credential cap of %d", live, maxSessionsPerCredential)
	}
	if _, err := sessions.Resolve(tokens[0]); err != ErrNoSession {
		t.Fatal("the oldest session survived; eviction is dropping the wrong end")
	}
	if _, err := sessions.Resolve(tokens[len(tokens)-1]); err != nil {
		t.Fatalf("the newest session was evicted: %v", err)
	}
}

// The challenge route is the one thing on this gate anyone can reach, so the
// table behind it is bounded and answers with back-pressure rather than growing.
func TestTheChallengeTableIsBounded(t *testing.T) {
	sessions := NewSessions(time.Now)
	for i := 0; i < maxNonces; i++ {
		if _, _, err := sessions.Challenge(); err != nil {
			t.Fatalf("Challenge %d: %v", i, err)
		}
	}
	if _, _, err := sessions.Challenge(); err != ErrGateBusy {
		t.Fatalf("challenge %d returned %v, want ErrGateBusy", maxNonces+1, err)
	}
	if outstanding, _ := sessions.Counts(); outstanding != maxNonces {
		t.Fatalf("outstanding challenges = %d, want %d", outstanding, maxNonces)
	}
}

// And it recovers on its own: the cap is back-pressure for the duration of a
// flood, not a state a relay has to be restarted out of.
func TestTheChallengeTableDrainsWithTime(t *testing.T) {
	clock := time.Date(2026, 8, 11, 12, 0, 0, 0, time.UTC)
	sessions := NewSessions(func() time.Time { return clock })
	for i := 0; i < maxNonces; i++ {
		if _, _, err := sessions.Challenge(); err != nil {
			t.Fatalf("Challenge %d: %v", i, err)
		}
	}
	clock = clock.Add(nonceTTL + time.Second)
	if _, _, err := sessions.Challenge(); err != nil {
		t.Fatalf("the gate did not recover after the challenges expired: %v", err)
	}
}
