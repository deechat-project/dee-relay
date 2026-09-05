package queue

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"strings"
)

// tagDomain domain-separates the queue-tag hash. The Dart client derives the
// same tag over the same bytes;
// changing this string breaks every client, so it is versioned rather than edited.
const tagDomain = "deechat.queue-tag.v1|"

// maxCapabilities caps how many secrets one fetch may present. More than one is
// needed only across a rotation — the queue may still hold envelopes stamped
// with the previous tag, and contacts may not have seen the new one yet. Four
// 256-bit guesses is the same zero chance as one; the cap exists to bound work
// per request, not to resist brute force.
const maxCapabilities = 4

// TagForSecret derives the public queue tag from a queue secret. The tag is what
// senders stamp on records and what the node stores; the secret never reaches
// the node except as proof inside a fetch it authorizes.
func TagForSecret(secret string) string {
	if secret == "" {
		return ""
	}
	sum := sha256.Sum256(append([]byte(tagDomain), []byte(secret)...))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// Auth is the read authorization one fetch presented: the tags derived from its
// capability header, plus whether records carrying no tag at all may still be
// served (the pre-fetch-auth compatibility path).
//
// It holds no node state and is built per request — the queue-ownership proof
// lives entirely in the record's tag and the caller's secret, which is what
// keeps the node stateless and lets any node in the mesh verify a fetch.
type Auth struct {
	tags          []string
	allowUntagged bool
	// trusted short-circuits every check. It is set by TrustedAuth alone, never
	// by NewAuth, so the zero Auth — the one a forgotten parameter produces —
	// authorizes nothing rather than everything.
	trusted bool
}

// TrustedAuth is the authorization of a caller this package does not check: the
// in-process paths that never crossed the wire, and the tests. Nothing served on
// a listener may use it — a request's authorization comes from NewAuth over what
// that request actually presented.
func TrustedAuth() Auth { return Auth{allowUntagged: true, trusted: true} }

// NewAuth derives the authorization for the given presented secrets. Secrets
// beyond maxCapabilities are ignored. Passing no secrets yields an Auth that can
// only read untagged records — and only if allowUntagged is set.
func NewAuth(secrets []string, allowUntagged bool) Auth {
	tags := make([]string, 0, len(secrets))
	for _, secret := range secrets {
		secret = strings.TrimSpace(secret)
		if secret == "" {
			continue
		}
		tags = append(tags, TagForSecret(secret))
		if len(tags) == maxCapabilities {
			break
		}
	}
	return Auth{tags: tags, allowUntagged: allowUntagged}
}

// AuthorizesUntagged reports whether this Auth can read records with no tag.
func (a Auth) AuthorizesUntagged() bool { return a.allowUntagged }

// Subject is the queue this caller is acting *as*: the tag of the first secret
// it presented, or "" when it presented none.
//
// permits answers the other question — may this caller touch a record somebody
// else stamped — and it is the one a queue read asks. Subject is for the routes
// keyed by the owner's own queue rather than by a record's tag: a prekey pool is
// named by its owner's tag, so publishing to one and asking after one both name
// the caller, and a caller can only ever name itself.
func (a Auth) Subject() string {
	if len(a.tags) == 0 {
		return ""
	}
	return a.tags[0]
}

// permits reports whether a record carrying tag may be served.
//
// An empty tag is a record from a client that predates fetch auth; serving it is
// a compatibility decision, not an authorization one. A non-empty tag is served
// only against proof, in every mode — so a record is protected from the moment a
// sender stamps it, whether or not the node is enforcing yet.
func (a Auth) permits(tag string) bool {
	if a.trusted {
		return true
	}
	if tag == "" {
		return a.allowUntagged
	}
	for _, candidate := range a.tags {
		if subtle.ConstantTimeCompare([]byte(candidate), []byte(tag)) == 1 {
			return true
		}
	}
	return false
}
