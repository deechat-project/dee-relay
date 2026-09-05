package admission

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// The code is minted by the website and typed or scanned into the app; the relay
// only ever sees the public key derived from it. Every test here is really the
// same question: can three separate implementations, in three languages, agree
// on what a given code means?

func TestACodeAlwaysDerivesTheSameCredential(t *testing.T) {
	_, first := KeyFromCode("K7M2QRVX8N4PJ0TWZC3HYB6D9F")
	_, second := KeyFromCode("K7M2QRVX8N4PJ0TWZC3HYB6D9F")
	if first != second {
		t.Fatalf("the same code derived two credentials: %s and %s", first, second)
	}
	if _, other := KeyFromCode("K7M2QRVX8N4PJ0TWZC3HYB6D9E"); other == first {
		t.Fatal("two different codes derived the same credential")
	}
}

// The customer's code arrives lowercased by a mail client, hyphenated because
// someone grouped it to read it out, and with the letters Crockford base32
// leaves out because whoever transcribed it did not know that. All of those are
// the same code, and a support thread is the cost of getting this wrong.
func TestATranscribedCodeDerivesTheSameCredential(t *testing.T) {
	_, canonical := KeyFromCode("K7M2QRVX8N4PJ0TWZC3HYB6D9F")
	for _, transcription := range []string{
		"k7m2qrvx8n4pj0twzc3hyb6d9f",
		"K7M2-QRVX-8N4P-J0TW-ZC3H-YB6D-9F",
		" K7M2 QRVX 8N4P J0TW ZC3H YB6D 9F ",
		"K7M2QRVX8N4PJOTWZC3HYB6D9F", // a letter O typed for a zero
		"K7M2QRVX8N4PJ0TWZC3HYB6D9F.",
	} {
		if _, got := KeyFromCode(transcription); got != canonical {
			t.Errorf("%q derived %s, want the canonical %s", transcription, got, canonical)
		}
	}
}

// A mis-transcribed U is not silently repaired. Crockford excludes it, so it can
// only be a typo — and guessing which character was meant would derive a
// credential the customer does not hold, which fails in exactly the same way but
// looks like the relay's fault.
func TestAnExcludedLetterIsNotGuessedAt(t *testing.T) {
	_, canonical := KeyFromCode("K7M2QRVX8N4PJ0TWZC3HYB6D9F")
	if _, got := KeyFromCode("K7M2QRVXUN4PJ0TWZC3HYB6D9F"); got == canonical {
		t.Fatal("a U was silently repaired into another character")
	}
}

func TestANewCodeIs128BitsInTheCrockfordAlphabet(t *testing.T) {
	code, err := NewCode()
	if err != nil {
		t.Fatalf("NewCode: %v", err)
	}
	if len(code) != 26 {
		t.Fatalf("code length = %d, want the 26 characters 128 bits encodes to: %q", len(code), code)
	}
	for _, r := range code {
		if !strings.ContainsRune(codeAlphabet, r) {
			t.Fatalf("code %q contains %q, which is not in the Crockford alphabet", code, r)
		}
	}
	other, _ := NewCode()
	if other == code {
		t.Fatal("two mints produced the same code")
	}
}

// The proof is a signature over a nonce the relay issued, and it verifies
// against nothing but the credential it names.
func TestAProofVerifiesOnlyForItsOwnNonceAndCredential(t *testing.T) {
	key, id := KeyFromCode("K7M2QRVX8N4PJ0TWZC3HYB6D9F")
	nonce := "nonce-the-relay-issued"
	signature := ed25519.Sign(key, Transcript(nonce, id))

	if !Verify(id, nonce, signature) {
		t.Fatal("a valid proof did not verify")
	}
	if Verify(id, "some-other-nonce", signature) {
		t.Fatal("a proof verified against a nonce it was not made for — it is replayable")
	}

	_, otherID := KeyFromCode("K7M2QRVX8N4PJ0TWZC3HYB6D9E")
	if Verify(otherID, nonce, signature) {
		t.Fatal("a proof verified as another credential")
	}
	if Verify(id, nonce, append([]byte{}, make([]byte, ed25519.SignatureSize)...)) {
		t.Fatal("a zero signature verified")
	}
	if Verify("not-base64url!!", nonce, signature) {
		t.Fatal("a malformed credential id verified")
	}
}

// The relay holds only public keys. Stated as a test because it is the property
// that makes a leaked credential file worthless, and it would be quietly lost by
// anyone "simplifying" the derivation into a stored shared secret.
func TestTheCredentialIdIsAPublicKey(t *testing.T) {
	key, id := KeyFromCode("K7M2QRVX8N4PJ0TWZC3HYB6D9F")
	raw, err := base64.RawURLEncoding.DecodeString(id)
	if err != nil {
		t.Fatalf("credential id is not base64url: %v", err)
	}
	if len(raw) != ed25519.PublicKeySize {
		t.Fatalf("credential id is %d bytes, want an Ed25519 public key", len(raw))
	}
	if !ed25519.PublicKey(raw).Equal(key.Public()) {
		t.Fatal("the credential id is not the public half of the derived key")
	}
}

func TestCredentialFileRefusesAnythingButTerms(t *testing.T) {
	_, id := KeyFromCode("K7M2QRVX8N4PJ0TWZC3HYB6D9F")

	good := `{"credentials":[{"credential":"` + id + `","terms":{"tier":"crew","notAfter":"2030-01-01T00:00:00Z","queueSlots":1320,"retentionWindow":"48h"}}]}`
	credentials, err := ParseCredentials([]byte(good))
	if err != nil {
		t.Fatalf("a well-formed file did not parse: %v", err)
	}
	if len(credentials) != 1 || credentials[0].ID != id {
		t.Fatalf("parsed %d credentials, want the one for %s", len(credentials), id)
	}
	if credentials[0].Terms.RetentionWindow.Duration() != 48*time.Hour {
		t.Fatalf("retentionWindow = %v, want 48h", credentials[0].Terms.RetentionWindow.Duration())
	}

	// The privacy control, not a hygiene one: an issuance service that starts
	// writing the buyer's email beside the credential — so a lost code can be
	// re-sent — turns a stated privacy property into a stored fact on the relay.
	// Here the file does not load and the operator finds out at boot.
	withIdentity := `{"credentials":[{"credential":"` + id + `","email":"buyer@example.org","terms":{"notAfter":"2030-01-01T00:00:00Z"}}]}`
	if _, err := ParseCredentials([]byte(withIdentity)); err == nil {
		t.Fatal("a credential file carrying billing identity was accepted")
	}
	withIdentityInTerms := `{"credentials":[{"credential":"` + id + `","terms":{"notAfter":"2030-01-01T00:00:00Z","customer":"acme"}}]}`
	if _, err := ParseCredentials([]byte(withIdentityInTerms)); err == nil {
		t.Fatal("a credential file carrying billing identity inside terms was accepted")
	}
}

func TestCredentialFileRefusesTheThingsThatWouldFailSilently(t *testing.T) {
	_, id := KeyFromCode("K7M2QRVX8N4PJ0TWZC3HYB6D9F")
	_, otherID := KeyFromCode("K7M2QRVX8N4PJ0TWZC3HYB6D9E")

	for name, body := range map[string]string{
		"no notAfter": `{"credentials":[{"credential":"` + id + `","terms":{"tier":"crew"}}]}`,
		"not a key":   `{"credentials":[{"credential":"nope","terms":{"notAfter":"2030-01-01T00:00:00Z"}}]}`,
		"short key":   `{"credentials":[{"credential":"` + base64.RawURLEncoding.EncodeToString([]byte("too short")) + `","terms":{"notAfter":"2030-01-01T00:00:00Z"}}]}`,
		"negative":    `{"credentials":[{"credential":"` + id + `","terms":{"notAfter":"2030-01-01T00:00:00Z","queueSlots":-1}}]}`,
		"twice":       `{"credentials":[{"credential":"` + id + `","terms":{"notAfter":"2030-01-01T00:00:00Z"}},{"credential":"` + id + `","terms":{"notAfter":"2031-01-01T00:00:00Z"}}]}`,
		"trailing":    `{"credentials":[{"credential":"` + otherID + `","terms":{"notAfter":"2030-01-01T00:00:00Z"}}]} {"credentials":[]}`,
		"bad window":  `{"credentials":[{"credential":"` + id + `","terms":{"notAfter":"2030-01-01T00:00:00Z","retentionWindow":"48 hours"}}]}`,
	} {
		if _, err := ParseCredentials([]byte(body)); err == nil {
			t.Errorf("%s: the file parsed, and a credential that loads wrong is one nobody notices", name)
		}
	}
}

func TestAnExpiredCredentialIsKnownAndRefused(t *testing.T) {
	_, id := KeyFromCode("K7M2QRVX8N4PJ0TWZC3HYB6D9F")
	now := time.Date(2026, 8, 11, 12, 0, 0, 0, time.UTC)

	store := NewStore()
	store.Replace([]Credential{{ID: id, Terms: Terms{NotAfter: now.Add(time.Hour)}}})

	if _, err := store.Lookup(id, now); err != nil {
		t.Fatalf("a live credential did not resolve: %v", err)
	}
	if _, err := store.Lookup(id, now.Add(2*time.Hour)); err != ErrExpiredCredential {
		t.Fatalf("an expired credential resolved with %v, want ErrExpiredCredential", err)
	}
	if _, err := store.Lookup("someone-else", now); err != ErrUnknownCredential {
		t.Fatalf("an unknown credential resolved with %v, want ErrUnknownCredential", err)
	}
}

// A reload must not renumber a circle that is still there. The per-boot index is
// what queued mail is charged against, so a credential that changed index would
// hand its occupancy to whoever inherited the number.
func TestAReloadKeepsEveryIndexItAlreadyIssued(t *testing.T) {
	_, first := KeyFromCode("K7M2QRVX8N4PJ0TWZC3HYB6D9F")
	_, second := KeyFromCode("K7M2QRVX8N4PJ0TWZC3HYB6D9E")
	_, third := KeyFromCode("K7M2QRVX8N4PJ0TWZC3HYB6D9G")
	now := time.Date(2026, 8, 11, 12, 0, 0, 0, time.UTC)
	live := Terms{NotAfter: now.Add(time.Hour)}

	store := NewStore()
	store.Replace([]Credential{{ID: first, Terms: live}, {ID: second, Terms: live}})
	firstGrant, _ := store.Lookup(first, now)
	secondGrant, _ := store.Lookup(second, now)
	if firstGrant.Index == 0 || firstGrant.Index == secondGrant.Index {
		t.Fatalf("indexes are not distinct and non-zero: %d and %d", firstGrant.Index, secondGrant.Index)
	}

	// second is revoked and third is added in the same edit.
	store.Replace([]Credential{{ID: first, Terms: live}, {ID: third, Terms: live}})

	reloaded, err := store.Lookup(first, now)
	if err != nil {
		t.Fatalf("a credential that survived the reload no longer resolves: %v", err)
	}
	if reloaded.Index != firstGrant.Index {
		t.Fatalf("index moved from %d to %d across a reload", firstGrant.Index, reloaded.Index)
	}
	if _, err := store.Lookup(second, now); err != ErrUnknownCredential {
		t.Fatalf("a revoked credential still resolves: %v", err)
	}
	thirdGrant, _ := store.Lookup(third, now)
	if thirdGrant.Index == secondGrant.Index {
		t.Fatal("a new credential inherited the index of the one it replaced, and with it that circle's occupancy")
	}
	if store.Count() != 2 {
		t.Fatalf("Count = %d, want 2", store.Count())
	}
}

// A window is written the way it is read: the credential file is edited by hand
// beside what issuance writes, and "10m0s" trimmed carelessly to "1" is a
// ten-fold change nobody would see in a diff.
func TestAWindowRoundTripsThroughTheShapeItIsWrittenIn(t *testing.T) {
	for _, window := range []time.Duration{
		0, time.Second, 30 * time.Second, time.Minute, 10 * time.Minute,
		90 * time.Minute, time.Hour, 24 * time.Hour, 48 * time.Hour, 7 * 24 * time.Hour,
	} {
		body, err := json.Marshal(Duration(window))
		if err != nil {
			t.Fatalf("marshal %s: %v", window, err)
		}
		var read Duration
		if err := json.Unmarshal(body, &read); err != nil {
			t.Fatalf("%s marshalled to %s, which does not parse: %v", window, body, err)
		}
		if read.Duration() != window {
			t.Errorf("%s marshalled to %s and read back as %s", window, body, read.Duration())
		}
	}
}
