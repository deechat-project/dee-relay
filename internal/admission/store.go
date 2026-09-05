package admission

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

var (
	// ErrUnknownCredential: this relay has never admitted that credential, or no
	// longer does. Indistinguishable on purpose — a caller must not be able to
	// tell "revoked" from "never valid here", which would make the endpoint an
	// oracle for whether a given circle buys from us.
	ErrUnknownCredential = errors.New("credential is not admitted by this relay")
	// ErrExpiredCredential: known, and its window has ended.
	ErrExpiredCredential = errors.New("credential has expired")
	// ErrBadProof: the signature does not verify, or the nonce was never issued,
	// was already spent, or has expired.
	ErrBadProof = errors.New("admission proof is not valid")
	// ErrGateBusy: the unauthenticated challenge table is full. Back-pressure,
	// not refusal — see Sessions.
	ErrGateBusy = errors.New("admission gate is busy")
	// ErrNoSession: the presented session token is unknown or has expired.
	ErrNoSession = errors.New("admission session is unknown or expired")
)

// Store is the set of credentials this relay admits, plus the per-boot index
// each one is counted under.
//
// It holds no user state and nothing durable: the credential file is *read*,
// never written (the no-durable-state audit forbids the write, and issuance owns
// the file). Reload swaps the set in place, which is what makes revoking a
// credential a signal rather than a restart — and a restart on this design
// empties every other circle's queue.
type Store struct {
	mu          sync.RWMutex
	credentials map[string]Credential

	// index gives each credential a small integer for the lifetime of this
	// process, and it is the ONLY identifier that leaves this package.
	//
	// The rule it enforces: count under a credential, never accumulate a set of
	// what was seen under it. The queue store and the attachment relay are handed
	// an integer, so the strongest thing either of them could build out of what
	// it holds is a number per circle — never a map from queue tags to a circle,
	// which would be a membership roster and is exactly what this relay must not
	// be able to build.
	//
	// Entries are never removed and never reused within a boot: a credential
	// that is revoked and re-added must not inherit another circle's occupancy
	// counter, and one that survives a reload must keep its own.
	index     map[string]uint32
	nextIndex uint32

	// loaded is the credential count, read on the hot path by callers deciding
	// whether this box gates anything at all.
	loaded atomic.Int64
}

// NewStore returns an empty store. Empty means *open*: a relay with no
// credentials configured applies its box caps to everyone, because that is the
// free self-hosted path and it must stay exactly that generous. The
// enforcing case is a separate switch for that reason — "unconfigured" cannot
// mean "closed" here the way it does for the mesh secret.
func NewStore() *Store {
	return &Store{
		credentials: make(map[string]Credential),
		index:       make(map[string]uint32),
	}
}

// Count is how many credentials are loaded. Used at boot to refuse an enforcing
// relay with nothing to admit, and by tests. Deliberately *not* published on
// /health: the switch is what monitoring has to assert, and the number of
// circles a box carries is nobody else's business.
func (s *Store) Count() int { return int(s.loaded.Load()) }

// Grant is one admitted request's authority: which circle it is charged to, and
// what that circle's terms are. Built per request from the live store, so a
// credential that expires or is revoked mid-session stops working on the next
// call rather than when the session ends.
type Grant struct {
	// Index is the per-boot integer the counters key on. Zero means
	// unattributed — an open box, or a relay in rollout mode serving a client
	// that has not presented a credential yet.
	Index uint32
	ID    string
	Terms Terms
}

// Admitted reports whether this grant names a credential at all.
func (g Grant) Admitted() bool { return g.Index != 0 }

// Lookup resolves a credential id to a grant, or reports why not.
//
// The two failure modes are kept apart because the client's remedy differs: an
// unknown credential is a code that was never valid here or has been revoked,
// and an expired one is a circle whose window ended and whose steward can renew
// it. Both leave local transports untouched: the relay simply stops answering,
// and nothing on the device changes.
func (s *Store) Lookup(id string, now time.Time) (Grant, error) {
	s.mu.RLock()
	credential, known := s.credentials[id]
	index := s.index[id]
	s.mu.RUnlock()

	if !known {
		return Grant{}, ErrUnknownCredential
	}
	if !credential.Terms.NotAfter.After(now) {
		return Grant{}, ErrExpiredCredential
	}
	return Grant{Index: index, ID: id, Terms: credential.Terms}, nil
}

// Replace swaps in a new credential set, preserving the per-boot index of every
// credential that was already known.
func (s *Store) Replace(credentials []Credential) {
	next := make(map[string]Credential, len(credentials))
	s.mu.Lock()
	for _, credential := range credentials {
		next[credential.ID] = credential
		if _, seen := s.index[credential.ID]; !seen {
			s.nextIndex++
			s.index[credential.ID] = s.nextIndex
		}
	}
	s.credentials = next
	s.mu.Unlock()
	s.loaded.Store(int64(len(next)))
}

// ReadFile parses a credential file without applying it.
//
// Separate from Replace on purpose: a caller reloading a live relay has to be
// able to inspect what a file would do *before* it does it — an enforcing relay
// that applies an empty file stops serving every circle at once. A malformed
// file returns an error and changes nothing, whole or not at all, because a
// reload that half-applies is a relay that has stopped admitting circles the
// operator believes it admits.
func ReadFile(path string) ([]Credential, error) {
	body, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read admission credentials: %w", err)
	}
	return ParseCredentials(body)
}

// LoadFile reads a credential file and replaces the store's contents with it.
func (s *Store) LoadFile(path string) (int, error) {
	credentials, err := ReadFile(path)
	if err != nil {
		return 0, err
	}
	s.Replace(credentials)
	return len(credentials), nil
}

// credentialFile is the on-disk shape. One key, so the file can gain a version
// or a comment field later without every existing file becoming invalid.
type credentialFile struct {
	Credentials []Credential `json:"credentials"`
}

// ParseCredentials reads the credential file format, strictly.
//
// Unknown fields are refused rather than ignored, and that is a privacy control
// rather than a hygiene one: billing identity and relay slot must not be
// joinable in one place. An issuance service that starts writing "email" or
// "customer" beside a credential — for the best of reasons, so a lost code can
// be re-sent — turns a stated privacy property into a stored fact on the relay.
// Here that file does not load, and the operator finds out at boot.
func ParseCredentials(body []byte) ([]Credential, error) {
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()

	var file credentialFile
	if err := decoder.Decode(&file); err != nil {
		return nil, fmt.Errorf("parse admission credentials: %w", err)
	}
	if err := decoder.Decode(new(struct{})); err != io.EOF {
		return nil, fmt.Errorf("parse admission credentials: trailing content after the first JSON document")
	}

	seen := make(map[string]bool, len(file.Credentials))
	for i := range file.Credentials {
		credential := &file.Credentials[i]
		if err := validateCredential(*credential); err != nil {
			return nil, fmt.Errorf("credential %d: %w", i+1, err)
		}
		if seen[credential.ID] {
			return nil, fmt.Errorf("credential %d: %s appears twice; one circle cannot have two sets of terms", i+1, credential.ID)
		}
		seen[credential.ID] = true
	}
	sort.Slice(file.Credentials, func(i, j int) bool {
		return file.Credentials[i].ID < file.Credentials[j].ID
	})
	return file.Credentials, nil
}

func validateCredential(credential Credential) error {
	pub, err := base64.RawURLEncoding.DecodeString(credential.ID)
	if err != nil {
		return fmt.Errorf("%q is not base64url: %w", credential.ID, err)
	}
	if len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("%q decodes to %d bytes, not the %d of an Ed25519 public key",
			credential.ID, len(pub), ed25519.PublicKeySize)
	}
	if credential.Terms.NotAfter.IsZero() {
		return fmt.Errorf("%s has no notAfter: expiry is the enforcement model, and a credential without one is a permanent free hosted tier", credential.ID)
	}
	for name, value := range map[string]int64{
		"queueSlots":          int64(credential.Terms.QueueSlots),
		"attachmentBytes":     int64(credential.Terms.AttachmentBytes),
		"concurrentTransfers": int64(credential.Terms.ConcurrentTransfers),
		"transitBytesPerDay":  credential.Terms.TransitBytesPerDay,
		"maxPerPair":          int64(credential.Terms.MaxPerPair),
	} {
		if value < 0 {
			return fmt.Errorf("%s has a negative %s: zero means the box's own cap, and there is no value below it", credential.ID, name)
		}
	}
	return nil
}
