package issue

import (
	"crypto"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"deechat/chat-node/internal/admission"
)

func tempFile(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "credentials.json")
}

func mintOne(t *testing.T, path string, terms admission.Terms) (string, admission.Credential) {
	t.Helper()
	file, err := Open(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	code, credential, err := file.Mint(terms)
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	if err := file.Save(); err != nil {
		t.Fatalf("save: %v", err)
	}
	return code, credential
}

func terms(days int) admission.Terms {
	return admission.Terms{Tier: "crew", NotAfter: time.Now().Add(time.Duration(days) * 24 * time.Hour).UTC().Truncate(time.Second)}
}

// The property the whole item exists for: a code minted here admits a client at
// the relay, and the relay never sees the code. Tested end to end through the
// relay's own store and verifier rather than against this package's idea of
// them, because the only failure that matters is the two disagreeing.
func TestAMintedCodeAdmitsAtTheRelay(t *testing.T) {
	path := tempFile(t)
	code, credential := mintOne(t, path, terms(14))

	store := admission.NewStore()
	loaded, err := store.LoadFile(path)
	if err != nil {
		t.Fatalf("the relay could not load the file this tool wrote: %v", err)
	}
	if loaded != 1 {
		t.Fatalf("relay loaded %d credentials, want 1", loaded)
	}
	grant, err := store.Lookup(credential.ID, time.Now())
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if grant.Terms.Tier != "crew" {
		t.Errorf("granted tier %q, want crew", grant.Terms.Tier)
	}

	key, id := admission.KeyFromCode(code)
	if id != credential.ID {
		t.Fatalf("the code derives %s, the file carries %s", id, credential.ID)
	}
	signature, err := key.Sign(nil, admission.Transcript("a-nonce", id), crypto.Hash(0))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if !admission.Verify(id, "a-nonce", signature) {
		t.Error("a proof made from the minted code does not verify against the credential in the file")
	}
}

// The package's first property, asserted against the bytes rather than against
// intent.
// The whole privacy claim rests on the code existing nowhere after the moment it
// is shown, and the way it comes back is somebody adding a field "so a lost code
// can be re-sent".
func TestTheCodeIsNeverWrittenToTheFile(t *testing.T) {
	path := tempFile(t)
	code, credential := mintOne(t, path, terms(14))

	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	written := string(body)
	if strings.Contains(written, code) {
		t.Fatal("the credential file contains the plaintext redemption code")
	}
	// Half of it is as bad as all of it: 128 bits with the first characters
	// known is not 128 bits any more.
	if strings.Contains(written, code[:8]) {
		t.Fatal("the credential file contains a prefix of the redemption code")
	}
	if !strings.Contains(written, credential.ID) {
		t.Fatal("the credential file does not contain the credential id it minted")
	}
}

func TestMintKeepsWhatIsAlreadyThere(t *testing.T) {
	path := tempFile(t)
	_, first := mintOne(t, path, terms(14))
	_, second := mintOne(t, path, terms(30))

	file, err := Open(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if file.Count() != 2 {
		t.Fatalf("file holds %d credentials, want 2", file.Count())
	}
	found := map[string]bool{}
	for _, credential := range file.Credentials() {
		found[credential.ID] = true
	}
	if !found[first.ID] || !found[second.ID] {
		t.Error("a mint dropped a credential that was already admitted")
	}
	// Credentials() is expiry order, and the operator reads it as the renewal
	// queue. Soonest first or it is just a list.
	ordered := file.Credentials()
	if ordered[0].ID != first.ID {
		t.Error("credentials are not listed soonest-expiry first")
	}
}

// A tool that repairs a file it did not understand un-admits every circle it
// could not read. Refusing is the whole behaviour.
func TestAFileThatDoesNotParseIsNeverTouched(t *testing.T) {
	path := tempFile(t)
	original := []byte(`{"credentials": [{"credential": "x", "email": "someone@example.com"}]}`)
	if err := os.WriteFile(path, original, 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if _, err := Open(path); err == nil {
		t.Fatal("opened a credential file the relay would refuse to load")
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(after) != string(original) {
		t.Error("the file changed despite the open failing")
	}
}

func TestRenewMovesTheWindowAndKeepsTheCode(t *testing.T) {
	path := tempFile(t)
	code, credential := mintOne(t, path, terms(14))

	file, err := Open(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	now := time.Now()
	was, is, err := file.Renew(credential.ID, now, 30*24*time.Hour)
	if err != nil {
		t.Fatalf("renew: %v", err)
	}
	if !is.After(was) {
		t.Fatalf("renewal did not extend the window: %s → %s", was, is)
	}
	// Extended from the existing expiry, not from today: renewing early must
	// not cost the customer days they have already paid for.
	if want := was.Add(30 * 24 * time.Hour).Truncate(time.Second); !is.Equal(want) {
		t.Errorf("renewed to %s, want %s (from the existing expiry)", is, want)
	}
	if err := file.Save(); err != nil {
		t.Fatalf("save: %v", err)
	}

	// The code is unchanged, so no member re-provisions.
	derived, err := CredentialFromCode(code)
	if err != nil {
		t.Fatalf("derive: %v", err)
	}
	if derived != credential.ID {
		t.Error("renewal changed which credential the customer's code derives")
	}
	store := admission.NewStore()
	if _, err := store.LoadFile(path); err != nil {
		t.Fatalf("relay load: %v", err)
	}
	if _, err := store.Lookup(credential.ID, is.Add(-time.Hour)); err != nil {
		t.Errorf("the renewed credential is not admitted inside its new window: %v", err)
	}
}

func TestRenewingALapsedCredentialRunsFromNow(t *testing.T) {
	path := tempFile(t)
	_, credential := mintOne(t, path, admission.Terms{
		Tier:     "crew",
		NotAfter: time.Now().Add(-72 * time.Hour).UTC().Truncate(time.Second),
	})
	file, err := Open(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	now := time.Now()
	_, is, err := file.Renew(credential.ID, now, 30*24*time.Hour)
	if err != nil {
		t.Fatalf("renew: %v", err)
	}
	if want := now.Add(30 * 24 * time.Hour); is.Before(want.Add(-time.Minute)) {
		t.Errorf("a lapsed credential renewed to %s, which backdates the window into days already spent", is)
	}
}

func TestRenewAndRevokeRefuseAnUnknownCredential(t *testing.T) {
	path := tempFile(t)
	mintOne(t, path, terms(14))
	file, err := Open(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	unknown, err := CredentialFromCode("ZZZZ ZZZZ ZZZZ ZZZZ ZZZZ ZZ")
	if err != nil {
		t.Fatalf("derive: %v", err)
	}
	if _, _, err := file.Renew(unknown, time.Now(), time.Hour); err == nil {
		t.Error("renewed a credential this file does not carry")
	}
	if _, err := file.Revoke(unknown); err == nil {
		t.Error("revoked a credential this file does not carry")
	}
}

func TestRevokeRemovesOnlyTheOneNamed(t *testing.T) {
	path := tempFile(t)
	_, first := mintOne(t, path, terms(14))
	_, second := mintOne(t, path, terms(30))

	file, err := Open(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if _, err := file.Revoke(first.ID); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if err := file.Save(); err != nil {
		t.Fatalf("save: %v", err)
	}

	store := admission.NewStore()
	if _, err := store.LoadFile(path); err != nil {
		t.Fatalf("relay load: %v", err)
	}
	if _, err := store.Lookup(first.ID, time.Now()); err == nil {
		t.Error("the revoked credential is still admitted")
	}
	if _, err := store.Lookup(second.ID, time.Now()); err != nil {
		t.Errorf("revoking one credential un-admitted another: %v", err)
	}
}

// The relay reloads on a signal that can arrive between any two writes, so the
// replacement is a rename and there is never a second file in that directory
// that looks like a credential file.
func TestSaveLeavesNoTemporaryFileBehind(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "credentials.json")
	mintOne(t, path, terms(14))

	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	if len(entries) != 1 || entries[0].Name() != "credentials.json" {
		names := make([]string, 0, len(entries))
		for _, entry := range entries {
			names = append(names, entry.Name())
		}
		t.Errorf("credential directory holds %v, want only credentials.json", names)
	}
}

// The relay usually runs as a different user than the operator issuing codes. A
// replacement it cannot read is a credential file that stops applying at the
// next restart, hours after the mint that caused it.
func TestSavePreservesTheFileMode(t *testing.T) {
	path := tempFile(t)
	mintOne(t, path, terms(14))
	if err := os.Chmod(path, 0o640); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	mintOne(t, path, terms(30))

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if info.Mode().Perm() != 0o640 {
		t.Errorf("file mode is %v after a mint, want 0640", info.Mode().Perm())
	}
}

func TestANewFileIsWrittenTight(t *testing.T) {
	path := tempFile(t)
	mintOne(t, path, terms(14))
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("a new credential file is %v, want 0600", info.Mode().Perm())
	}
}

func TestMintRefusesToReissueTheSameCredential(t *testing.T) {
	path := tempFile(t)
	_, credential := mintOne(t, path, terms(14))
	file, err := Open(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	file.credentials = append(file.credentials, admission.Credential{ID: credential.ID, Terms: terms(1)})
	if err := file.Save(); err == nil {
		t.Error("wrote a file carrying one credential twice; the relay refuses to load it")
	}
}

// Marshal is the last thing between this tool and a file the relay will not
// load. It has to fail on anything the strict parser refuses, not just on what
// this package happens to produce.
func TestMarshalRefusesWhatTheRelayWouldRefuse(t *testing.T) {
	file := &File{path: "credentials.json", mode: 0o600}
	file.credentials = []admission.Credential{{ID: "not-a-key", Terms: terms(1)}}
	if _, err := file.Marshal(); err == nil {
		t.Error("rendered a credential whose id is not an Ed25519 public key")
	}

	file.credentials = []admission.Credential{{ID: mustID(t), Terms: admission.Terms{Tier: "crew"}}}
	if _, err := file.Marshal(); err == nil {
		t.Error("rendered a credential with no notAfter: that is a permanent free hosted tier")
	}
}

func mustID(t *testing.T) string {
	t.Helper()
	code, err := admission.NewCode()
	if err != nil {
		t.Fatalf("code: %v", err)
	}
	_, id := admission.KeyFromCode(code)
	return id
}

func TestCredentialFromCodeAcceptsTheCodeAsATypedString(t *testing.T) {
	code, err := admission.NewCode()
	if err != nil {
		t.Fatalf("code: %v", err)
	}
	_, id := admission.KeyFromCode(code)

	// How the code arrives from a mail client and from a support thread. Each
	// must resolve to the same credential or a correct code does not work.
	for _, typed := range []string{
		strings.ToLower(code),
		code[:4] + "-" + code[4:8] + " " + code[8:],
		"  " + code + "\n",
	} {
		derived, err := CredentialFromCode(typed)
		if err != nil {
			t.Fatalf("derive %q: %v", typed, err)
		}
		if derived != id {
			t.Errorf("%q derives %s, want %s", typed, derived, id)
		}
	}
	if _, err := CredentialFromCode("   "); err == nil {
		t.Error("accepted an empty code")
	}
}

func TestOpenRefusesAPathThatNamesNothing(t *testing.T) {
	if _, err := Open(""); err == nil {
		t.Error("opened an unnamed credential file; --file unset would write somewhere surprising")
	}
}

func TestOpenTreatsAMissingFileAsAnEmptySet(t *testing.T) {
	file, err := Open(tempFile(t))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if file.Existed() || file.Count() != 0 {
		t.Error("a missing credential file did not open as an empty set")
	}
}

// --- presets ---------------------------------------------------------------

func writePresets(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "tiers.json")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write presets: %v", err)
	}
	return path
}

func TestPresetsCarryEveryCapacityFieldOntoTheTerms(t *testing.T) {
	path := writePresets(t, `{"tiers": [{"tier": "crew", "queueSlots": 1320,
		"retentionWindow": "48h", "attachmentBytes": 104857600,
		"concurrentTransfers": 4, "transitBytesPerDay": 53687091200}]}`)
	presets, err := LoadPresets(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	preset, err := presets.Lookup("CREW") // typed by a human on a support shift
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	notAfter := time.Now().Add(14 * 24 * time.Hour)
	granted := preset.Terms(notAfter)
	if granted.Tier != "crew" || granted.QueueSlots != 1320 ||
		granted.RetentionWindow.Duration() != 48*time.Hour ||
		granted.AttachmentBytes != 104857600 || granted.ConcurrentTransfers != 4 ||
		granted.TransitBytesPerDay != 53687091200 {
		t.Errorf("preset did not carry through: %+v", granted)
	}
	if !granted.NotAfter.Equal(notAfter.UTC().Truncate(time.Second)) {
		t.Errorf("notAfter is %s, want %s", granted.NotAfter, notAfter)
	}
	if _, err := presets.Lookup("enterprise"); err == nil {
		t.Error("looked up a tier the file does not carry")
	}
}

// A typo in a field name that decoded to "unset" would grant the box's own caps
// to a circle that paid for a share of them, and nobody would notice until the
// box filled.
func TestPresetsRefuseWhatTheyDoNotUnderstand(t *testing.T) {
	for name, body := range map[string]string{
		"a misspelled field":      `{"tiers": [{"tier": "crew", "queueSlot": 1320}]}`,
		"an expiry on a tier":     `{"tiers": [{"tier": "crew", "notAfter": "2030-01-01T00:00:00Z"}]}`,
		"an identity on a tier":   `{"tiers": [{"tier": "crew", "email": "someone@example.com"}]}`,
		"a tier with no name":     `{"tiers": [{"queueSlots": 10}]}`,
		"the same tier twice":     `{"tiers": [{"tier": "crew"}, {"tier": "crew"}]}`,
		"no tiers at all":         `{"tiers": []}`,
		"a second JSON document":  `{"tiers": [{"tier": "crew"}]}{"tiers": []}`,
		"a duration that is not":  `{"tiers": [{"tier": "crew", "retentionWindow": "two days"}]}`,
		"a duration as a number":  `{"tiers": [{"tier": "crew", "retentionWindow": 172800}]}`,
		"a negative retention":    `{"tiers": [{"tier": "crew", "retentionWindow": "-48h"}]}`,
		"a comment where it goes": `{"_comment": "fine", "tiers": [{"tier": "crew"}]}`,
	} {
		_, err := LoadPresets(writePresets(t, body))
		if name == "a comment where it goes" {
			if err != nil {
				t.Errorf("%s: %v — a file an operator edits needs somewhere to say why", name, err)
			}
			continue
		}
		if err == nil {
			t.Errorf("%s: loaded without complaint", name)
		}
	}
}

// The shipped presets are the price list. Pinned here because the file is edited
// by hand when prices move, and a mistyped queueSlots is a capacity promise
// nobody re-derives.
func TestTheShippedPresetsMatchThePublishedTerms(t *testing.T) {
	presets, err := LoadPresets(filepath.Join("..", "..", "deploy", "tiers.example.json"))
	if err != nil {
		t.Fatalf("load deploy/tiers.example.json: %v", err)
	}
	want := map[string]struct {
		slots     int
		retention time.Duration
		transfers int
	}{
		"personal": {300, 24 * time.Hour, 2},
		"crew":     {1320, 48 * time.Hour, 4},
		"team":     {6000, 72 * time.Hour, 8},
	}
	for tier, expected := range want {
		preset, err := presets.Lookup(tier)
		if err != nil {
			t.Errorf("%s: %v", tier, err)
			continue
		}
		if preset.QueueSlots != expected.slots {
			t.Errorf("%s grants %d queue slots, the published terms say %d", tier, preset.QueueSlots, expected.slots)
		}
		if preset.RetentionWindow.Duration() != expected.retention {
			t.Errorf("%s retains for %s, the published terms say %s", tier, preset.RetentionWindow.Duration(), expected.retention)
		}
		if preset.ConcurrentTransfers != expected.transfers {
			t.Errorf("%s allows %d concurrent transfers, the published terms say %d", tier, preset.ConcurrentTransfers, expected.transfers)
		}
		// One number across all three shared tiers, deliberately: a circuit
		// breaker that scales with price says "pay more to abuse more".
		if preset.TransitBytesPerDay != 50*(1<<30) {
			t.Errorf("%s has a transit ceiling of %d, every shared tier gets 50 GB", tier, preset.TransitBytesPerDay)
		}
		// A credential may only ever lower a box cap, so the shared pool has to
		// run DEE_NODE_MAX_ATTACHMENT_BYTES at 100 MB for this to mean anything.
		if preset.AttachmentBytes != 100*(1<<20) {
			t.Errorf("%s has an attachment ceiling of %d, the published terms say 100 MB", tier, preset.AttachmentBytes)
		}
	}

	// Dedicated and Sovereign are a label and a date: the box is theirs, and its
	// env file is the only ceiling that means anything.
	for _, tier := range []string{"dedicated", "sovereign"} {
		preset, err := presets.Lookup(tier)
		if err != nil {
			t.Errorf("%s: %v", tier, err)
			continue
		}
		if preset.QueueSlots != 0 || preset.RetentionWindow != 0 || preset.AttachmentBytes != 0 ||
			preset.ConcurrentTransfers != 0 || preset.TransitBytesPerDay != 0 || preset.MaxPerPair != 0 {
			t.Errorf("%s carries capacity terms; it gets a label and a date and nothing else: %+v", tier, preset)
		}
	}
}

func TestReadCodeTakesOneLine(t *testing.T) {
	code, err := ReadCode(strings.NewReader("  a1b2-c3d4 \nignored\n"))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if code != "a1b2-c3d4" {
		t.Errorf("read %q", code)
	}
	if _, err := ReadCode(strings.NewReader("")); err == nil {
		t.Error("read a code from nothing")
	}
}

// A mint that fails after generating a code leaves the operator asking whether
// the code was issued, and there is no way to answer it: the code is gone and
// the file never changed. The check belongs before anything is generated.
func TestOpenFailsBeforeACodeExistsWhenTheDirectoryIsMissing(t *testing.T) {
	path := filepath.Join(t.TempDir(), "not-a-directory", "credentials.json")
	if _, err := Open(path); err == nil {
		t.Error("opened a credential file in a directory that does not exist; the failure would land after the mint")
	}
}
