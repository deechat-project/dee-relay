package admission

import (
	"crypto/rand"
	"encoding/base64"
	"sync"
	"time"
)

// The gate is a challenge-response, not a bearer string, and that is the one
// piece of this design that could not be added later without re-issuing every
// code.
//
// A bearer token is reusable by anyone who captures it. TLS covers the wire
// today, but "the credential never travels" is a property worth having outright:
// what crosses the network is a signature over a nonce this relay issued
// seconds ago and will never accept again, so a captured exchange yields nothing
// replayable. The relay holds only public keys, so a copy of its credential file
// yields nothing either.
//
// What it does NOT defend against, stated so it is never designed around: a
// client that presents its credential to a relay of an attacker's choosing hands
// that relay a live proof, which the relay can forward to the real one. Only
// channel binding fixes that, and the defence here is the ordinary one — a
// client presents a credential only to the relay it was provisioned with, over
// TLS that authenticates it. The damage if it fails is the same as a leaked
// invite: relay capacity, never conversation, because messages are sealed to
// contacts verified in person.
const (
	// nonceTTL is how long a challenge stays answerable. Long enough for a phone
	// on a slow link to sign and come back; short enough that the outstanding set
	// stays small under a flood.
	nonceTTL = 30 * time.Second

	// sessionTTL is how long a proof buys before the client must sign again.
	//
	// It is NOT how long admission is cached. Every request re-resolves the
	// credential from the live store, so a revocation or an expiry takes effect
	// on the next call — a session opened on day 14 does not survive into day 15.
	// This value only decides how often a client re-signs.
	sessionTTL = 15 * time.Minute

	// maxNonces bounds the challenge table. POST /admission/challenge is
	// unauthenticated by necessity — the nonce is what the client signs — so it
	// is the one route on this gate that anyone can reach, and an unbounded table
	// behind it is a memory exhaustion on a relay whose MemoryMax is derived from
	// its record caps.
	maxNonces = 8192

	// maxSessionsPerCredential bounds one circle's footprint. Every member's
	// device holds the same credential and opens its own session, so this is
	// sized well above a Team circle's device count; the point is that a circle
	// that misbehaves fills its own allowance rather than the table.
	maxSessionsPerCredential = 128

	// maxSessions bounds the table overall.
	maxSessions = 16384
)

type sessionEntry struct {
	credentialID string
	expiresAt    time.Time
}

// Sessions holds the two ephemeral tables the gate needs: outstanding challenges
// and live sessions. Both are RAM-only and both are bounded.
type Sessions struct {
	mu sync.Mutex

	nonces   map[string]time.Time
	sessions map[string]sessionEntry
	// byCredential keeps each circle's tokens in issue order so the oldest can be
	// dropped when that circle reaches its allowance. It maps a credential to its
	// own session tokens and to nothing else — it is not, and must never become,
	// a record of what was seen under a credential.
	byCredential map[string][]string

	now func() time.Time
}

func NewSessions(now func() time.Time) *Sessions {
	if now == nil {
		now = time.Now
	}
	return &Sessions{
		nonces:       make(map[string]time.Time),
		sessions:     make(map[string]sessionEntry),
		byCredential: make(map[string][]string),
		now:          now,
	}
}

// Challenge issues a single-use nonce for a client to sign.
func (s *Sessions) Challenge() (string, time.Duration, error) {
	now := s.now().UTC()

	s.mu.Lock()
	defer s.mu.Unlock()
	s.sweepLocked(now)
	if len(s.nonces) >= maxNonces {
		return "", 0, ErrGateBusy
	}
	nonce, err := randomToken()
	if err != nil {
		return "", 0, err
	}
	s.nonces[nonce] = now.Add(nonceTTL)
	return nonce, nonceTTL, nil
}

// VerifyProof spends the nonce and checks the signature, and is deliberately
// separate from Open so a caller can interpose the credential lookup *between*
// the two.
//
// That ordering is the point. Checking the store first would let anyone holding
// a credential id — with no proof at all — learn whether this relay has ever
// admitted it, because "expired" and "unknown" have to be different answers to
// the circle that owns the credential. Verifying first means only a code holder
// can tell those two apart.
//
// The nonce is spent whether or not the signature verifies: a caller that can
// retry the same nonce until a guess lands is a caller with an unbounded number
// of attempts against one challenge, and nothing about a failed proof makes it
// worth a second look.
func (s *Sessions) VerifyProof(credentialID, nonce string, signature []byte) error {
	now := s.now().UTC()

	s.mu.Lock()
	spent := s.spendNonceLocked(nonce, now)
	s.mu.Unlock()

	if !spent || !Verify(credentialID, nonce, signature) {
		return ErrBadProof
	}
	return nil
}

// Open starts a session for a credential whose proof has already been verified
// and whose terms have already been resolved.
func (s *Sessions) Open(credentialID string) (string, time.Duration, error) {
	now := s.now().UTC()

	s.mu.Lock()
	defer s.mu.Unlock()
	s.sweepLocked(now)
	if len(s.sessions) >= maxSessions {
		return "", 0, ErrGateBusy
	}
	token, err := randomToken()
	if err != nil {
		return "", 0, err
	}
	s.sessions[token] = sessionEntry{credentialID: credentialID, expiresAt: now.Add(sessionTTL)}
	tokens := append(s.byCredential[credentialID], token)
	for len(tokens) > maxSessionsPerCredential {
		delete(s.sessions, tokens[0])
		tokens = tokens[1:]
	}
	s.byCredential[credentialID] = tokens
	return token, sessionTTL, nil
}

// Resolve returns the credential a session token stands for. It deliberately
// does not extend the session: a client re-signs on a fixed cadence rather than
// holding one token open indefinitely by staying busy.
func (s *Sessions) Resolve(token string) (string, error) {
	if token == "" {
		return "", ErrNoSession
	}
	now := s.now().UTC()

	s.mu.Lock()
	defer s.mu.Unlock()
	entry, ok := s.sessions[token]
	if !ok {
		return "", ErrNoSession
	}
	if !entry.expiresAt.After(now) {
		s.dropLocked(token, entry.credentialID)
		return "", ErrNoSession
	}
	return entry.credentialID, nil
}

// Forget drops every session held under a credential. Called when a credential
// stops resolving, so a revoked circle's tokens do not sit in the table until
// they age out.
func (s *Sessions) Forget(credentialID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, token := range s.byCredential[credentialID] {
		delete(s.sessions, token)
	}
	delete(s.byCredential, credentialID)
}

// Counts reports the two table sizes, for tests and for the load harness.
func (s *Sessions) Counts() (nonces int, sessions int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.nonces), len(s.sessions)
}

func (s *Sessions) spendNonceLocked(nonce string, now time.Time) bool {
	expiry, ok := s.nonces[nonce]
	if !ok {
		return false
	}
	delete(s.nonces, nonce)
	return expiry.After(now)
}

func (s *Sessions) dropLocked(token, credentialID string) {
	delete(s.sessions, token)
	remaining := s.byCredential[credentialID][:0]
	for _, candidate := range s.byCredential[credentialID] {
		if candidate != token {
			remaining = append(remaining, candidate)
		}
	}
	if len(remaining) == 0 {
		delete(s.byCredential, credentialID)
		return
	}
	s.byCredential[credentialID] = remaining
}

func (s *Sessions) sweepLocked(now time.Time) {
	for nonce, expiry := range s.nonces {
		if !expiry.After(now) {
			delete(s.nonces, nonce)
		}
	}
	for token, entry := range s.sessions {
		if !entry.expiresAt.After(now) {
			s.dropLocked(token, entry.credentialID)
		}
	}
}

// randomToken is 256 bits. A nonce and a session token are both unguessable by
// construction rather than by rate limit.
//
// A failure is returned rather than absorbed. crypto/rand does not fail in
// practice, but the one unrecoverable outcome here is a predictable token, and
// the empty string is the most predictable of all — it would be stored as a
// live nonce that any caller could present.
func randomToken() (string, error) {
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", ErrGateBusy
	}
	return base64.RawURLEncoding.EncodeToString(raw[:]), nil
}
