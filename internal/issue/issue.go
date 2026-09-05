// Package issue is admission's other half: the tool that *writes* the credential
// file the relay only ever reads.
//
// The relay can gate a circle but nothing can create one. Hand-issuance is
// allowed for the trial lane and not for anything paid, and this package is the
// one mechanism behind both: the CLI in cmd/dee-admit for the trial and
// hand-approved lanes, and the payment webhook that follows it, so the two
// cannot drift on what a tier means or on what a credential file may contain.
//
// Four properties, and each of them is here rather than in the caller because a
// second caller would otherwise have to remember it:
//
//  1. **The plaintext code is returned once and never stored.** Mint hands it
//     back and keeps the derived public key; the private half is dropped on the
//     line that derives it. A lost code has no self-service recovery, which is
//     accepted deliberately: an issuance service that kept a copy so it could
//     re-send one would give away the privacy claim that buys.
//  2. **Nothing here can write an identity.** There is no field for an email or
//     a customer id anywhere in this package, and the relay's parser refuses a
//     file that carries one: billing identity and relay slot must not be
//     joinable in one place, and the failure mode is a well-meaning "so support
//     can find them" commit, not a malicious one.
//  3. **Tier presets are a file, never a table in the binary.** A price list
//     belongs nowhere in the published relay, and the same reasoning applies to
//     anything published beside it. It also means re-pricing is an edit to
//     deploy/tiers.example.json rather than a release.
//  4. **The file is replaced atomically, and never with bytes the relay would
//     refuse.** The relay re-reads on SIGHUP, so a half-written file is a
//     reload that either fails or — worse, before the strict parser — applies a
//     truncated credential set to a live box.
//
// Why this package may write to disk at all when internal/audit forbids it
// everywhere else: the ban is on *the relay* keeping durable state, and this is
// not the relay. It is not linked into cmd/dee-relay, it writes an operator
// config file rather than user state, and TestNothingTheRelayImportsIsExempt
// fails the build if the relay ever reaches it.
package issue

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"deechat/chat-node/internal/admission"
)

var (
	// ErrNoSuchCredential: renew or revoke named a credential this file does not
	// carry. An error rather than a no-op, because the caller is usually a
	// support reply and "nothing happened" must not read as "done".
	ErrNoSuchCredential = errors.New("this file admits no such credential")
	// ErrAlreadyAdmitted: the derived credential is already in the file. At 128
	// bits this is not a collision; it is the same code being minted twice, and
	// silently replacing the terms beside it would re-issue a live circle.
	ErrAlreadyAdmitted = errors.New("that credential is already in this file")
	// ErrNoSuchTier: the presets file has no such tier.
	ErrNoSuchTier = errors.New("no such tier in the presets file")
)

// File is a credential file, read into memory and written back whole.
//
// Whole is the only safe granularity: the relay parses the file as one document
// and applies it as one set, so an incremental edit that leaves the rest of the
// file unparsed would let this tool write a file it never validated.
type File struct {
	path        string
	credentials []admission.Credential
	mode        fs.FileMode
	existed     bool
}

// Open reads a credential file. A missing file is an empty set rather than an
// error — minting the first credential is how a relay is provisioned, and
// requiring the operator to hand-write `{"credentials": []}` first is a step
// that exists only to be forgotten.
//
// A file that does not parse is an error and nothing is written, ever. The
// alternative is a tool that "repairs" a file it did not understand, which on
// this design silently un-admits every circle it could not read.
func Open(path string) (*File, error) {
	if strings.TrimSpace(path) == "" {
		return nil, errors.New("no credential file given: pass --file, or set DEE_NODE_ADMISSION_FILE to the one the relay reads")
	}
	info, err := os.Stat(path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		// The directory is checked here rather than at the save, because a mint
		// that fails *after* generating a code leaves the operator asking the one
		// question this tool must never make them ask: was that code issued or
		// not? Failing before anything is generated has no such state.
		if _, err := os.Stat(filepath.Dir(path)); err != nil {
			return nil, fmt.Errorf("credential file: %w", err)
		}
		// 0600 for a file this tool creates. It names no secret — the codes are
		// gone and only public keys remain — but it is the operator's record of
		// who is admitted, and the default should be the tight one.
		return &File{path: path, mode: 0o600}, nil
	case err != nil:
		return nil, fmt.Errorf("credential file: %w", err)
	case !info.Mode().IsRegular():
		return nil, fmt.Errorf("%s is not a regular file", path)
	}
	credentials, err := admission.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return &File{path: path, credentials: credentials, mode: info.Mode().Perm(), existed: true}, nil
}

// Path is the file this set came from and will be written back to.
func (f *File) Path() string { return f.path }

// Existed reports whether the file was already there when it was opened.
func (f *File) Existed() bool { return f.existed }

// Credentials returns the current set, sorted by expiry — soonest first, which
// is the order the renewals are in.
func (f *File) Credentials() []admission.Credential {
	out := append([]admission.Credential(nil), f.credentials...)
	sort.Slice(out, func(i, j int) bool {
		if !out[i].Terms.NotAfter.Equal(out[j].Terms.NotAfter) {
			return out[i].Terms.NotAfter.Before(out[j].Terms.NotAfter)
		}
		return out[i].ID < out[j].ID
	})
	return out
}

// Count is how many circles this file admits.
func (f *File) Count() int { return len(f.credentials) }

// Mint creates a credential and returns the redemption code that derives it.
//
// The code is the only artifact the customer ever needs and the only one this
// process will ever see: it is returned to the caller and nothing here writes it
// anywhere. The private key derived from it is discarded on the line below —
// there is no key file in this design and no way to reconstruct the code from
// what is stored.
func (f *File) Mint(terms admission.Terms) (code string, credential admission.Credential, err error) {
	code, err = admission.NewCode()
	if err != nil {
		return "", admission.Credential{}, err
	}
	_, id := admission.KeyFromCode(code)
	if _, found := f.find(id); found {
		return "", admission.Credential{}, ErrAlreadyAdmitted
	}
	credential = admission.Credential{ID: id, Terms: terms}
	f.credentials = append(f.credentials, credential)
	return code, credential, nil
}

// Renew extends a credential's window without touching the credential itself.
//
// Renewal does not mint a new code, so a circle never re-provisions on payment:
// the steward pays, the window moves, and no member does anything at all. The extension runs from whichever is later, now or the
// current expiry — renewing early must not cost the customer the days they
// already paid for, and renewing a lapsed circle must not backdate the window
// into a past that has already been spent.
func (f *File) Renew(id string, now time.Time, extend time.Duration) (was, is time.Time, err error) {
	index, found := f.find(id)
	if !found {
		return time.Time{}, time.Time{}, ErrNoSuchCredential
	}
	if extend <= 0 {
		return time.Time{}, time.Time{}, errors.New("a renewal must extend the window; there is no negative renewal")
	}
	was = f.credentials[index].Terms.NotAfter
	from := was
	if from.Before(now) {
		from = now
	}
	is = from.Add(extend).UTC().Truncate(time.Second)
	f.credentials[index].Terms.NotAfter = is
	return was, is, nil
}

// Revoke removes a credential.
//
// It is the exception rather than the mechanism: expiry is how entitlements
// end, and revocation exists for a refund, a chargeback, or a code the
// customer says has been shared. The relay tells nobody which of the two
// happened — an unknown credential and a revoked one get the same answer, so the
// endpoint cannot be used to ask whether a given circle buys from us.
func (f *File) Revoke(id string) (admission.Credential, error) {
	index, found := f.find(id)
	if !found {
		return admission.Credential{}, ErrNoSuchCredential
	}
	revoked := f.credentials[index]
	f.credentials = append(f.credentials[:index:index], f.credentials[index+1:]...)
	return revoked, nil
}

func (f *File) find(id string) (int, bool) {
	for i := range f.credentials {
		if f.credentials[i].ID == id {
			return i, true
		}
	}
	return 0, false
}

// fileShape is the on-disk document. It mirrors the unexported shape the relay
// parses, and Marshal proves the two agree by parsing what it produced with the
// relay's own reader before any of it reaches the disk.
type fileShape struct {
	Credentials []admission.Credential `json:"credentials"`
}

// Marshal renders the file and verifies the relay would load it.
//
// The verification is the point. This tool and the relay are two pieces of code
// with one file between them, and the failure they can produce together is
// silent: a field written in a shape the strict parser rejects does not break
// here, it breaks at the relay's next SIGHUP — which keeps the previous set and
// logs into a volatile journal, so the operator sees a successful mint and a
// circle that is not admitted.
func (f *File) Marshal() ([]byte, error) {
	ordered := append([]admission.Credential(nil), f.credentials...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].ID < ordered[j].ID })

	body, err := json.MarshalIndent(fileShape{Credentials: ordered}, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("render credential file: %w", err)
	}
	body = append(body, '\n')

	parsed, err := admission.ParseCredentials(body)
	if err != nil {
		return nil, fmt.Errorf("refusing to write a file this relay would not load: %w", err)
	}
	if len(parsed) != len(ordered) {
		return nil, fmt.Errorf("refusing to write: rendered %d credentials and read back %d", len(ordered), len(parsed))
	}
	return body, nil
}

// Save replaces the file atomically.
//
// Temp file in the same directory, then rename, because the relay re-reads this
// file on a signal that can arrive between any two writes. A rename is the only
// way the reader sees either the old set or the new one and never half of
// either. The mode and owner of the file being replaced are carried across: the
// relay usually runs as a different user than the operator issuing codes, and a
// replacement it cannot read is a credential file that stops applying at the
// next restart, discovered long after the mint that caused it.
func (f *File) Save() error {
	body, err := f.Marshal()
	if err != nil {
		return err
	}

	directory := filepath.Dir(f.path)
	temp, err := os.CreateTemp(directory, ".credentials-*.json")
	if err != nil {
		return fmt.Errorf("write credential file: %w", err)
	}
	name := temp.Name()
	defer func() {
		// A leftover temp in the credential directory is not harmless: it is a
		// second file that looks like a credential file and is not the one being
		// read. Removed on every path but the successful rename.
		if name != "" {
			_ = os.Remove(name)
		}
	}()

	if err := temp.Chmod(f.mode); err != nil {
		temp.Close()
		return fmt.Errorf("write credential file: %w", err)
	}
	if f.existed {
		adoptOwner(f.path, temp)
	}
	if _, err := temp.Write(body); err != nil {
		temp.Close()
		return fmt.Errorf("write credential file: %w", err)
	}
	// Sync before the rename: the rename is atomic with respect to a reader, not
	// with respect to a power cut, and a credential file that survives a crash
	// as zero bytes is an enforcing relay that admits nobody.
	if err := temp.Sync(); err != nil {
		temp.Close()
		return fmt.Errorf("write credential file: %w", err)
	}
	if err := temp.Close(); err != nil {
		return fmt.Errorf("write credential file: %w", err)
	}
	if err := os.Rename(name, f.path); err != nil {
		return fmt.Errorf("write credential file: %w", err)
	}
	name = ""
	f.existed = true
	return nil
}

// Preset is a tier's capacity terms, without a date.
//
// There is deliberately no notAfter field: expiry belongs to an issue, never to
// a tier, and a presets file that could carry one would let a trial preset
// quietly become a permanent entitlement. The parser refuses unknown fields, so
// writing one there fails to load rather than being ignored.
type Preset struct {
	Tier                string             `json:"tier"`
	QueueSlots          int                `json:"queueSlots,omitempty"`
	RetentionWindow     admission.Duration `json:"retentionWindow,omitempty"`
	AttachmentBytes     int                `json:"attachmentBytes,omitempty"`
	ConcurrentTransfers int                `json:"concurrentTransfers,omitempty"`
	TransitBytesPerDay  int64              `json:"transitBytesPerDay,omitempty"`
	MaxPerPair          int                `json:"maxPerPair,omitempty"`
}

// Terms are what this preset grants until notAfter. Every capacity field carries
// through unchanged, including the zeros: zero means "the box's own cap", so a
// tier that sets nothing — Dedicated and Sovereign, whose box is their own — is
// a label and a date and nothing else.
func (p Preset) Terms(notAfter time.Time) admission.Terms {
	return admission.Terms{
		Tier:                p.Tier,
		NotAfter:            notAfter.UTC().Truncate(time.Second),
		QueueSlots:          p.QueueSlots,
		RetentionWindow:     p.RetentionWindow,
		AttachmentBytes:     p.AttachmentBytes,
		ConcurrentTransfers: p.ConcurrentTransfers,
		TransitBytesPerDay:  p.TransitBytesPerDay,
		MaxPerPair:          p.MaxPerPair,
	}
}

// Presets is a loaded tier file.
type Presets struct {
	path  string
	tiers []Preset
}

type presetFile struct {
	// Comment is read and thrown away. JSON has no comments and this is a file
	// an operator edits to change a price, so it needs somewhere to say why a
	// number is what it is. Note the asymmetry with the credential file, which
	// has no such escape hatch and must not gain one: this file is ours and
	// carries no identity, that one sits on the relay and must never be able to
	// hold a customer's name.
	Comment json.RawMessage `json:"_comment,omitempty"`
	Tiers   []Preset        `json:"tiers"`
}

// LoadPresets reads a tier file, strictly.
//
// Strictly for the same reason the credential parser is: this is the file a
// price change edits, and a typo in a field name that decoded to "unset" would
// mint a credential granting the box's own caps to a circle that paid for a
// share of them. A tier that grants everything is indistinguishable from an
// unmetered relay, and nobody would notice until the box filled.
func LoadPresets(path string) (*Presets, error) {
	body, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read tier presets: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()

	var file presetFile
	if err := decoder.Decode(&file); err != nil {
		return nil, fmt.Errorf("parse tier presets: %w", err)
	}
	if err := decoder.Decode(new(struct{})); err != io.EOF {
		return nil, errors.New("parse tier presets: trailing content after the first JSON document")
	}
	if len(file.Tiers) == 0 {
		return nil, fmt.Errorf("%s names no tiers", path)
	}
	seen := make(map[string]bool, len(file.Tiers))
	for _, tier := range file.Tiers {
		if strings.TrimSpace(tier.Tier) == "" {
			return nil, fmt.Errorf("%s has a tier with no name", path)
		}
		if seen[tier.Tier] {
			return nil, fmt.Errorf("%s names %q twice; one tier cannot have two sets of terms", path, tier.Tier)
		}
		seen[tier.Tier] = true
	}
	return &Presets{path: path, tiers: file.Tiers}, nil
}

// Lookup finds a tier by name, case-insensitively — the name is typed by a human
// on a support shift, and `Crew` is not a different product from `crew`.
func (p *Presets) Lookup(name string) (Preset, error) {
	for _, tier := range p.tiers {
		if strings.EqualFold(tier.Tier, name) {
			return tier, nil
		}
	}
	return Preset{}, fmt.Errorf("%w: %s knows %s", ErrNoSuchTier, p.path, strings.Join(p.Names(), ", "))
}

// Names lists the tiers this file carries, in file order.
func (p *Presets) Names() []string {
	names := make([]string, 0, len(p.tiers))
	for _, tier := range p.tiers {
		names = append(names, tier.Tier)
	}
	return names
}

// CredentialFromCode derives the credential id a redemption code names.
//
// It is how revoke and renew take a code instead of an id: the customer quoting
// a support thread has the 26 characters, never the base64url key. Deriving is
// one-way, so this reads the customer's code without ever being able to store
// something that reproduces it.
func CredentialFromCode(code string) (string, error) {
	normalized := admission.NormalizeCode(code)
	if normalized == "" {
		return "", errors.New("that is not a redemption code")
	}
	_, id := admission.KeyFromCode(normalized)
	return id, nil
}

// ReadCode takes a code from a reader, for callers that would rather not put one
// in a shell history or a process listing.
func ReadCode(source io.Reader) (string, error) {
	scanner := bufio.NewScanner(source)
	if !scanner.Scan() {
		if err := scanner.Err(); err != nil {
			return "", err
		}
		return "", errors.New("no code on the input")
	}
	return strings.TrimSpace(scanner.Text()), nil
}
