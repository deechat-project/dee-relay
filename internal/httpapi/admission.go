package httpapi

import (
	"encoding/base64"
	"errors"
	"net/http"
	"time"

	"deechat/chat-node/internal/admission"
	"deechat/chat-node/internal/attachment"
	"deechat/chat-node/internal/queue"
)

// admissionHeader carries the session token a request was admitted under. A
// header rather than a query parameter, for the reason the queue capability is
// one: a query string lands in every proxy access log.
//
// The name is duplicated on the client side the same way
// queueCapabilityHeader is. Changing it here changes it there.
const admissionHeader = "X-Dee-Admission"

// The exchange, in two calls:
//
//	POST /admission/challenge  → { nonce, expiresInSec }
//	POST /admission/redeem     { credential, nonce, signature }
//	                           → { session, expiresInSec, terms }
//
// and then X-Dee-Admission: <session> on every gated request.
//
// Three things about this shape are the expensive ones to change later, so they
// are stated here as well as in the design:
//
//   - **The credential never travels.** The client signs a nonce this relay
//     issued; the relay holds only the public half. A captured exchange is not
//     replayable and a captured credential file admits nobody.
//   - **The session is a handle, not a cached decision.** Every gated request
//     re-resolves the credential from the live store, so revocation and expiry
//     both take effect on the next call — a session opened on day 14 does not
//     survive into day 15.
//   - **Terms come back from the exchange and never from /health.** The
//     box-wide maxAttachmentBytes is published there because it is a property of
//     the box; a circle's retention window is not, and an unauthenticated
//     endpoint must not answer questions about a specific credential.

func (s *Server) handleAdmissionChallenge(w http.ResponseWriter, r *http.Request) {
	nonce, ttl, err := s.sessions.Challenge()
	if err != nil {
		// The one unauthenticated route on this gate, so the one that can be
		// flooded by anyone. Back-pressure rather than a bigger table.
		writeError(w, http.StatusTooManyRequests, "admission_busy",
			"too many outstanding admission challenges; retry shortly")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"nonce":        nonce,
		"expiresInSec": int(ttl.Seconds()),
	})
}

func (s *Server) handleAdmissionRedeem(w http.ResponseWriter, r *http.Request) {
	var value struct {
		Credential string `json:"credential"`
		Nonce      string `json:"nonce"`
		Signature  string `json:"signature"`
	}
	if err := decodeJSON(r, &value); err != nil || value.Credential == "" || value.Nonce == "" || value.Signature == "" {
		writeError(w, http.StatusBadRequest, "invalid_admission_proof",
			"credential, nonce and signature are required")
		return
	}
	signature, err := base64.RawURLEncoding.DecodeString(value.Signature)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_admission_proof", "signature is not base64url")
		return
	}

	// Proof first, store second. "Expired" and "unknown" have to be different
	// answers — a steward whose window ended needs to be told that, not told to
	// try again — and checking the store first would hand that distinction to
	// anyone holding a credential id with no proof at all, turning the endpoint
	// into an oracle for which circles buy from us. Verified first, only a code
	// holder can tell the two apart, and everyone else gets one answer.
	if err := s.sessions.VerifyProof(value.Credential, value.Nonce, signature); err != nil {
		writeError(w, http.StatusForbidden, "admission_refused", "this relay does not admit that credential")
		return
	}

	grant, err := s.admissions.Lookup(value.Credential, time.Now().UTC())
	switch {
	case errors.Is(err, admission.ErrExpiredCredential):
		s.sessions.Forget(value.Credential)
		writeError(w, http.StatusForbidden, "admission_expired",
			"this circle's relay window has ended; local and nearby transports are unaffected")
		return
	case err != nil:
		writeError(w, http.StatusForbidden, "admission_refused",
			"this relay does not admit that credential")
		return
	}

	token, ttl, err := s.sessions.Open(value.Credential)
	switch {
	case errors.Is(err, admission.ErrGateBusy):
		writeError(w, http.StatusTooManyRequests, "admission_busy", "too many live admission sessions; retry shortly")
		return
	case err != nil:
		writeError(w, http.StatusForbidden, "admission_refused", "this relay does not admit that credential")
		return
	}

	terms := grant.Terms
	writeJSON(w, http.StatusOK, map[string]any{
		"session":      token,
		"expiresInSec": int(ttl.Seconds()),
		// The granted terms, so the client can size its own guards to what it
		// actually holds and take the smaller of the two — the pattern
		// resolveAttachmentCeilingBytes already uses for the box-wide ceiling.
		// Zero fields are omitted: a zero means "the box's own cap", and the box
		// caps a client is allowed to know are on /health.
		"terms": termsJSON(terms),
	})
}

func termsJSON(terms admission.Terms) map[string]any {
	out := map[string]any{
		"notAfter": terms.NotAfter.UTC().Format(time.RFC3339),
	}
	if terms.Tier != "" {
		out["tier"] = terms.Tier
	}
	if terms.QueueSlots > 0 {
		out["queueSlots"] = terms.QueueSlots
	}
	if terms.RetentionWindow > 0 {
		out["retentionWindowSec"] = int(terms.RetentionWindow.Duration().Seconds())
	}
	if terms.AttachmentBytes > 0 {
		out["attachmentBytes"] = terms.AttachmentBytes
	}
	if terms.ConcurrentTransfers > 0 {
		out["concurrentTransfers"] = terms.ConcurrentTransfers
	}
	if terms.TransitBytesPerDay > 0 {
		out["transitBytesPerDay"] = terms.TransitBytesPerDay
	}
	if terms.MaxPerPair > 0 {
		out["maxPerPair"] = terms.MaxPerPair
	}
	return out
}

// admit resolves the credential a request is charged to. It writes the response
// and returns false when the request may not proceed.
//
// Three modes, and the difference between the first two is the whole reason
// admission needs its own switch:
//
//   - **No credentials loaded.** The box serves everyone at its own caps. This
//     is the free self-hosted path and it stays exactly that generous.
//   - **Credentials loaded, not enforcing.** An admitted circle gets its terms;
//     everyone else still gets box caps. The rollout position.
//   - **Enforcing.** A request without a live session is refused.
//
// Presenting a *bad* token is an error in all three, because a client that
// believes it is admitted and is silently not would otherwise run on box caps
// and never find out.
func (s *Server) admit(w http.ResponseWriter, r *http.Request) (admission.Grant, bool) {
	token := r.Header.Get(admissionHeader)
	if token == "" {
		if s.cfg.RequireAdmission {
			writeError(w, http.StatusUnauthorized, "admission_required",
				"this relay serves provisioned circles; redeem a relay invite at POST /admission/challenge")
			return admission.Grant{}, false
		}
		return admission.Grant{}, true
	}

	credentialID, err := s.sessions.Resolve(token)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "admission_stale",
			"this admission session has expired; run the challenge exchange again")
		return admission.Grant{}, false
	}

	// Re-resolved per request, never cached at connect: this is what makes
	// revocation immediate and what stops a session opened on day 14 from
	// surviving into day 15.
	grant, err := s.admissions.Lookup(credentialID, time.Now().UTC())
	if err != nil {
		s.sessions.Forget(credentialID)
		if errors.Is(err, admission.ErrExpiredCredential) {
			writeError(w, http.StatusForbidden, "admission_expired",
				"this circle's relay window has ended; local and nearby transports are unaffected")
			return admission.Grant{}, false
		}
		writeError(w, http.StatusForbidden, "admission_refused",
			"this relay does not admit that credential")
		return admission.Grant{}, false
	}
	return grant, true
}

// queueGrant projects an admitted credential onto the queue store's dimensions,
// and attachmentGrant onto the attachment relay's. Each store applies the
// zero-means-box and lower-only rules against its own caps rather than having
// them resolved here, so the package that owns a cap stays the authority on it.
func queueGrant(grant admission.Grant) queue.Grant {
	return queue.Grant{
		Credential: grant.Index,
		Slots:      grant.Terms.QueueSlots,
		MaxPerPair: grant.Terms.MaxPerPair,
		Retention:  grant.Terms.RetentionWindow.Duration(),
	}
}

func attachmentGrant(grant admission.Grant) attachment.Grant {
	return attachment.Grant{
		Credential:          grant.Index,
		AttachmentBytes:     grant.Terms.AttachmentBytes,
		ConcurrentTransfers: grant.Terms.ConcurrentTransfers,
		TransitBytesPerDay:  grant.Terms.TransitBytesPerDay,
	}
}
