package httpapi

import (
	"fmt"
	"net/http"
	"time"
)

// Request bodies are decoded into memory before any cap is consulted:
// DEE_NODE_MAX_PAYLOAD_BYTES is checked by queue.Store *after* the envelope has
// been unmarshalled, and DEE_NODE_MAX_CHUNK_BYTES by attachment.Relay after the
// chunk has been. On a relay whose queues are RAM-only and whose MemoryMax is
// derived from those caps, that ordering means one unauthenticated POST with a
// large body can take the process out — and an OOM kill on this design does not
// degrade the relay, it empties every queue on it.
//
// So the body is bounded before it is read. This is the in-binary half of the
// reverse proxy's body limits (deploy/Caddyfile.example, deploy/nginx.conf.example):
// same reasoning as the mesh auth layers, where the ops rule and the code rule
// are both present because neither should be load-bearing alone. A relay run
// without the proxy — or behind a proxy someone reconfigured — still has this.
//
// The limits are derived from the configured caps rather than exposed as another
// knob, so they cannot drift away from what the binary will actually accept.
const (
	// Slack above the payload cap for the surrounding JSON: ids, tags,
	// timestamps, and batched requests such as POST /prekeys (bounded at 100
	// entries per recipient, roughly 20 KB). Deliberately generous — this is a
	// memory bound, not a validation rule, and the real limits are enforced by
	// the stores underneath.
	bodyEnvelopeSlack = 256 << 10
)

// bodyLimitFor returns the largest request body a route can legitimately carry.
//
// The zero-value fallbacks mirror the ones queue.NewStore and
// attachment.NewRelay apply to the same fields. Without them a Config built by
// hand rather than by config.Load would get a limit tighter than what the store
// underneath accepts, which would reject valid requests instead of hostile ones.
func (s *Server) bodyLimitFor(path string) int64 {
	payloadBytes := s.cfg.MaxPayloadBytes
	if payloadBytes <= 0 {
		payloadBytes = 8192
	}
	chunkBytes := s.cfg.MaxChunkBytes
	if chunkBytes <= 0 {
		chunkBytes = 1 << 20
	}

	switch path {
	case "/attachments/chunks":
		return int64(chunkBytes) + bodyEnvelopeSlack
	default:
		return int64(payloadBytes) + bodyEnvelopeSlack
	}
}

// defaultBodyReadTimeout is what a Config built by hand rather than by
// config.FromEnv gets, mirroring the zero-value fallbacks elsewhere in this
// file. A body read with no deadline at all is the failure this middleware
// exists to prevent, so the fallback may not be "no deadline".
const defaultBodyReadTimeout = 20 * time.Second

// limitBodies rejects an over-large body on Content-Length before reading it,
// caps what a body that understates or omits its length can actually deliver,
// and bounds how long the read may wait. The size case surfaces to the handler
// as a decode error (400) rather than 413, which is imprecise but not the
// point: the point is that the read stops.
//
// The deadline is the same rule in the time dimension, and it is the one that
// was missing. ReadHeaderTimeout on the server bounds the headers; nothing
// bounded the body, so a client that sent headers and then stopped — a crash, a
// dropped link, or an HTTP client whose own timeout fired and abandoned the
// request without closing the socket — parked a goroutine and a connection in
// the body reader permanently. Three of those, plus 28 connections leaked the
// same way, is what a wedged relay looked like from the inside in the incident
// that produced this deadline, while
// GETs on fresh connections kept answering 200.
//
// Bodies only. A request with none — every GET, including the long-poll on
// /attachments/chunks that is meant to park for RelayPollTimeout — returns
// above without a deadline being set.
func (s *Server) limitBodies(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Body == nil || r.Body == http.NoBody {
			next.ServeHTTP(w, r)
			return
		}
		limit := s.bodyLimitFor(r.URL.Path)
		if r.ContentLength > limit {
			writeError(w, http.StatusRequestEntityTooLarge, "payload_too_large",
				fmt.Sprintf("request body exceeds this route's limit of %d bytes", limit))
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, limit)
		// Per request, not per connection: net/http clears the read deadline
		// after each request's headers when Server.ReadTimeout is unset, so this
		// cannot leak onto the next request on a kept-alive connection. An error
		// here means the ResponseWriter does not support deadlines (it does on
		// every real server; some test doubles do not), in which case the size
		// cap above still applies and the read is simply unbounded in time, as
		// it was before.
		_ = http.NewResponseController(w).SetReadDeadline(time.Now().Add(s.bodyReadTimeout()))
		next.ServeHTTP(w, r)
	})
}

func (s *Server) bodyReadTimeout() time.Duration {
	if s.cfg.BodyReadTimeout > 0 {
		return s.cfg.BodyReadTimeout
	}
	return defaultBodyReadTimeout
}
