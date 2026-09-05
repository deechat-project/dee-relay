// Package admission is the relay's gate: which circles this box carries mail
// for, and how much of it each one may hold.
//
// Before it existed, a relay's URL *was* its entitlement — anyone who learned
// the address could point a correctly-tagged client at it and use it for free,
// forever. Queue-read authorization (internal/queue.Auth) never addressed that;
// it keeps one circle from reading another's mail, which is confidentiality
// between circles, not admission. See the README, § "Relay admission".
//
// Four properties are the expensive ones — retrofitting any of them means
// re-issuing every code in circulation, so they are decided here rather than
// discovered later:
//
//  1. **The relay holds no secret.** A redemption code derives an Ed25519
//     keypair; the relay stores the public half. A copy of the credential file
//     admits nobody. This is strictly stronger than storing a hash of the code,
//     and it is what lets the proof be a signature rather than a replayable
//     bearer string.
//  2. **A credential carries terms, never a yes/no.** Personal, Crew and Team
//     share one box, so a boolean would make them the same product under three
//     names.
//  3. **Zero means "use the box's own cap", everywhere.** A credential written
//     before a field existed reads as unrestricted *by the credential*, so
//     adding a dimension later is not a retrofit.
//  4. **A credential may only ever lower a box cap, never raise one.** The
//     Apache-2.0 binary must not be able to sell more than the operator
//     configured, and an anti-flood rule must never be tiered upward.
//
// Nothing here branches on the tier label. It is data for support replies; the
// relay enforces the numbers beside it, which is what keeps a price list out of
// an Apache-2.0 binary.
package admission

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// keyDomain domain-separates the code → keypair derivation. The website mints
// the code and derives the public half to store; the app derives the private
// half to sign with. Changing this string invalidates every
// code in circulation, so it is versioned rather than edited — the same rule the
// queue-tag domain follows.
const keyDomain = "deechat.admission-key.v1|"

// proofDomain domain-separates the challenge signature, so a signature produced
// for admission can never be mistaken for one produced by any other part of the
// system that signs with a key derived the same way.
const proofDomain = "deechat.admission-proof.v1|"

// codeAlphabet is Crockford base32: no I, L, O or U, so a code read off a
// success page and typed on a phone cannot be misheard as another valid code.
// Manual entry is the fallback path for a broken camera or a screen reader, and
// that path is only usable if the alphabet is.
const codeAlphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

// CodeBytes is the entropy in a redemption code. 128 bits — 26 characters once
// encoded.
const CodeBytes = 16

// NewCode mints a redemption code: 128 random bits in Crockford base32.
//
// The plaintext is returned once and never stored. Nothing in this
// package writes it anywhere; the caller shows it and forgets it, and the only
// thing that survives is the credential id derived from it.
func NewCode() (string, error) {
	raw := make([]byte, CodeBytes)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("mint redemption code: %w", err)
	}
	var out strings.Builder
	var acc, bits uint32
	for _, b := range raw {
		acc = acc<<8 | uint32(b)
		bits += 8
		for bits >= 5 {
			bits -= 5
			out.WriteByte(codeAlphabet[(acc>>bits)&31])
		}
	}
	if bits > 0 {
		out.WriteByte(codeAlphabet[(acc<<(5-bits))&31])
	}
	return out.String(), nil
}

// NormalizeCode is what every side must apply before deriving anything from a
// code, and it exists because the alternative is a support thread. A code
// arrives lowercased from a text message, hyphenated because someone grouped it
// for legibility, or with an O where a zero was printed. All three must derive
// the same credential as the code on the success page, or the customer's
// perfectly correct code simply does not work.
func NormalizeCode(code string) string {
	var out strings.Builder
	out.Grow(len(code))
	for _, r := range strings.ToUpper(strings.TrimSpace(code)) {
		switch r {
		case 'O':
			out.WriteByte('0')
		case 'I', 'L':
			out.WriteByte('1')
		case 'U':
			// Crockford excludes U; it is only ever a mis-transcription, and
			// dropping it silently would derive a different credential than the
			// one the customer holds. Keep it, so the code fails loudly instead.
			out.WriteByte('U')
		default:
			if strings.ContainsRune(codeAlphabet, r) {
				out.WriteRune(r)
			}
			// Everything else — spaces, hyphens, the punctuation a mail client
			// inserts — is grouping, not content.
		}
	}
	return out.String()
}

// KeyFromCode derives the credential keypair a redemption code stands for.
//
// The relay only ever needs the second return value. The private key exists here
// for two callers: the issuance path that mints a code, and tests, which have to
// be able to produce a real proof.
// It is derived, never stored — there is no key file anywhere in this design.
func KeyFromCode(code string) (ed25519.PrivateKey, string) {
	seed := sha256.Sum256([]byte(keyDomain + NormalizeCode(code)))
	key := ed25519.NewKeyFromSeed(seed[:])
	return key, CredentialID(key.Public().(ed25519.PublicKey))
}

// CredentialID is how a credential is named everywhere outside the client: the
// base64url of its Ed25519 public key. It is derived one-way from the code, so
// publishing it (in a config file, in a log line) discloses nothing that would
// let anyone use the credential.
func CredentialID(pub ed25519.PublicKey) string {
	return base64.RawURLEncoding.EncodeToString(pub)
}

// Transcript is the exact byte string a client signs to prove it holds the code
// behind a credential id.
//
// The credential id is inside the signed bytes as well as beside them: a
// signature is then self-describing, and cannot be presented as a proof for some
// other credential. The nonce is what makes it unreplayable — it was issued by
// this relay, is single-use, and expires in seconds.
func Transcript(nonce, credentialID string) []byte {
	return []byte(proofDomain + nonce + "|" + credentialID)
}

// Verify reports whether signature is a valid proof of credentialID over nonce.
func Verify(credentialID, nonce string, signature []byte) bool {
	pub, err := base64.RawURLEncoding.DecodeString(credentialID)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return false
	}
	if len(signature) != ed25519.SignatureSize {
		return false
	}
	return ed25519.Verify(ed25519.PublicKey(pub), Transcript(nonce, credentialID), signature)
}

// Terms are what a credential grants. Six capacity fields, an expiry, and a
// label. The schema is the part that had to be right before the first code was
// issued; the integers are editable in place afterwards, so re-pricing edits the
// terms stored beside a credential, and the customer's code does not change.
//
// Every capacity field is zero-valued as "the box's own cap", and every one of
// them may only ever lower it. So a credential minted before a field existed
// keeps working, and a credential that asks for more than the operator
// configured gets what the operator configured.
type Terms struct {
	// Tier is a support label — personal, crew, team. Nothing branches on it.
	Tier string `json:"tier,omitempty"`

	// NotAfter is the only date, and expiry *is* the enforcement model: nothing
	// is ever revoked in the normal course, entitlements simply end. Required —
	// a credential with no expiry is a permanent free hosted tier.
	NotAfter time.Time `json:"notAfter"`

	// QueueSlots is how many undelivered envelopes this circle may hold at once,
	// derived rather than chosen: members × (members−1) × the per-pair quota, at
	// the count the tier is sized for. Set exactly there it never rejects
	// anything the per-pair quota would have allowed a circle of that size; it
	// binds only when a circle is larger than the tier it bought.
	QueueSlots int `json:"queueSlots,omitempty"`

	// RetentionWindow clamps a sender's requested expiry. The headline lever:
	// 24h → 48h → 72h across the shared pool.
	RetentionWindow Duration `json:"retentionWindow,omitempty"`

	// AttachmentBytes is the whole-transfer ceiling for this circle.
	AttachmentBytes int `json:"attachmentBytes,omitempty"`

	// ConcurrentTransfers is how many live attachment sessions this circle may
	// hold at once. A fairness cap: published, never sold.
	ConcurrentTransfers int `json:"concurrentTransfers,omitempty"`

	// TransitBytesPerDay is a rolling 24-hour ceiling on bytes through the
	// attachment relay. A circuit breaker, deliberately one number across all
	// shared tiers — a breaker that scales with price says "pay more to abuse
	// more".
	TransitBytesPerDay int64 `json:"transitBytesPerDay,omitempty"`

	// MaxPerPair overrides the box's per-pair backlog quota downward. It exists
	// so the concept is present from v1, while every shared tier stays at the box
	// value, because tiering an anti-flood rule upward would sell the right to
	// flood harder — which the lower-only rule makes impossible anyway.
	MaxPerPair int `json:"maxPerPair,omitempty"`
}

// Credential is one admitted circle: a public key and what it may do.
//
// There is deliberately nothing else in this struct, and the loader refuses a
// file that carries anything else: billing identity and relay slot must not be
// joinable in one place, and an issuance service that
// writes an email address next to a credential turns a stated concession into a
// stored fact.
type Credential struct {
	ID    string `json:"credential"`
	Terms Terms  `json:"terms"`
}

// Duration is a time.Duration that reads as "48h" in JSON rather than as a
// count of nanoseconds. Operator config is edited by hand, and the units in an
// env file next to it are already written this way.
type Duration time.Duration

func (d Duration) Duration() time.Duration { return time.Duration(d) }

// String is the shape a window is written and read in — "48h", not "48h0m0s".
// The relay never writes the credential file; issuance does (cmd/dee-admit), and
// what it produces sits in the same document as hand-written entries, so the two
// should not be distinguishable. Both parse either way.
func (d Duration) String() string {
	switch value := time.Duration(d); {
	case value == 0:
		return "0s"
	case value%time.Hour == 0:
		return fmt.Sprintf("%dh", value/time.Hour)
	case value%time.Minute == 0:
		return fmt.Sprintf("%dm", value/time.Minute)
	default:
		return value.String()
	}
}

func (d Duration) MarshalJSON() ([]byte, error) {
	return json.Marshal(d.String())
}

func (d *Duration) UnmarshalJSON(raw []byte) error {
	var text string
	if err := json.Unmarshal(raw, &text); err != nil {
		return fmt.Errorf("a duration must be a string such as \"48h\": %w", err)
	}
	parsed, err := time.ParseDuration(text)
	if err != nil {
		return fmt.Errorf("%q is not a duration: %w", text, err)
	}
	if parsed < 0 {
		return fmt.Errorf("%q is negative", text)
	}
	*d = Duration(parsed)
	return nil
}
