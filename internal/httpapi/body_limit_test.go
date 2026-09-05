package httpapi

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The caps are enforced by the stores, which see a request only after it has
// been decoded — so before this limit existed, "DEE_NODE_MAX_PAYLOAD_BYTES=8192"
// still meant an unauthenticated caller could hand the relay a 200 MB body and
// have it allocated in full before being told it was too big. On a RAM-only
// relay with a derived MemoryMax, that is not a rejected request, it is an OOM
// kill that empties every queue on the host.
func TestOversizeBodyIsRejectedBeforeItIsRead(t *testing.T) {
	server := newTestServer()

	limit := server.bodyLimitFor("/messages")
	body := strings.Repeat("x", int(limit)+1)
	request := httptest.NewRequest(http.MethodPost, "/messages", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, request)

	if recorder.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413", recorder.Code)
	}
	if !strings.Contains(recorder.Body.String(), "payload_too_large") {
		t.Fatalf("body = %q, want payload_too_large", recorder.Body.String())
	}
}

// The Content-Length check alone would be worth little: it is a number the
// sender chooses. What has to hold is that the *read* stops at the limit, so
// this counts the bytes the handler was actually able to pull off a body whose
// declared length is a lie. The request is otherwise valid JSON, so without the
// bound the decoder would consume all of it before any cap was consulted.
func TestUnderstatedBodyLengthStopsBeingRead(t *testing.T) {
	server := newTestServer()
	limit := server.bodyLimitFor("/messages")

	envelope := `{"id":"msg-big","sender":"alice","recipient":"bob","encryptedPayload":"` +
		strings.Repeat("x", int(limit)+(4<<20)) + `"}`
	counter := &countingReader{inner: strings.NewReader(envelope)}
	request := httptest.NewRequest(http.MethodPost, "/messages", counter)
	request.Header.Set("Content-Type", "application/json")
	request.ContentLength = 64 // the lie
	recorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, request)

	if recorder.Code == http.StatusOK || recorder.Code == http.StatusAccepted {
		t.Fatalf("status = %d, want a rejection", recorder.Code)
	}
	// One buffered read may straddle the limit; nothing beyond that.
	if counter.read > limit+(64<<10) {
		t.Fatalf("read %d bytes from a body limited to %d — the read did not stop", counter.read, limit)
	}
}

// Whichever way a body turns out to be too big, the refusal is the same
// refusal. A declared length over the limit was already answered 413; a body
// that understated its length tripped MaxBytesReader *during* the decode, and
// the handler reported what it saw — a decode failure, 400 invalid_json. A
// client that special-cases 413 (ours marks such a message permanently failed
// rather than retrying it for a week) was told it had sent malformed JSON.
func TestBodyThatOverrunsDuringDecodeIsAlso413(t *testing.T) {
	server := newTestServer()
	limit := server.bodyLimitFor("/messages")

	envelope := `{"id":"msg-big","sender":"alice","recipient":"bob","encryptedPayload":"` +
		strings.Repeat("x", int(limit)+(1<<20)) + `"}`
	request := httptest.NewRequest(http.MethodPost, "/messages", strings.NewReader(envelope))
	request.Header.Set("Content-Type", "application/json")
	request.ContentLength = 64 // the lie
	recorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, request)

	if recorder.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d (%s), want 413", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), "payload_too_large") {
		t.Fatalf("body = %q, want payload_too_large", recorder.Body.String())
	}
}

// And a body that is simply not JSON still gets the answer that describes it.
func TestMalformedBodyIsStill400(t *testing.T) {
	server := newTestServer()

	request := httptest.NewRequest(http.MethodPost, "/messages", strings.NewReader("{not json"))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, request)

	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status = %d (%s), want 400", recorder.Code, recorder.Body.String())
	}
}

type countingReader struct {
	inner *strings.Reader
	read  int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.inner.Read(p)
	c.read += int64(n)
	return n, err
}

// The limits are per route because the routes carry different things. Sizing
// them all to the message payload would reject every attachment chunk; sizing
// them all to a chunk would leave /messages unbounded in practice.
func TestBodyLimitsAreSizedPerRoute(t *testing.T) {
	server := newTestServer()
	server.cfg.MaxPayloadBytes = 8192
	server.cfg.MaxChunkBytes = 1 << 20

	messages := server.bodyLimitFor("/messages")
	chunks := server.bodyLimitFor("/attachments/chunks")

	if messages >= chunks {
		t.Fatalf("limits are not ordered: messages=%d chunks=%d", messages, chunks)
	}
	// Each limit must clear what the route legitimately carries.
	if chunks <= int64(server.cfg.MaxChunkBytes) {
		t.Fatalf("chunk limit %d does not clear one max-size chunk (%d)", chunks, server.cfg.MaxChunkBytes)
	}
	if messages <= int64(server.cfg.MaxPayloadBytes) {
		t.Fatalf("message limit %d does not clear one max-size payload (%d)", messages, server.cfg.MaxPayloadBytes)
	}
}

// A hand-built Config (tests, embedders) leaves the caps at zero, where the
// stores apply their own defaults. The limit has to apply the same ones or it
// becomes tighter than what the store accepts.
func TestBodyLimitsFallBackToStoreDefaults(t *testing.T) {
	server := newTestServer()
	server.cfg.MaxPayloadBytes = 0
	server.cfg.MaxChunkBytes = 0

	if got := server.bodyLimitFor("/messages"); got <= 8192 {
		t.Fatalf("message limit with zero config = %d, want above the store default", got)
	}
	if got := server.bodyLimitFor("/attachments/chunks"); got <= 1<<20 {
		t.Fatalf("chunk limit with zero config = %d, want above the relay default", got)
	}
}

// A max-size chunk must still get through. This is the regression that would
// turn a memory bound into a broken attachment path: the client sends 512 KiB
// plaintext chunks that base64 to roughly 700 KiB.
func TestMaxSizeChunkFitsWithinTheLimit(t *testing.T) {
	server := newTestServer()
	server.cfg.MaxChunkBytes = 1 << 20

	chunk := map[string]any{
		"id": "chunk-limit", "transferId": "transfer-limit", "capability": "cap-limit",
		"recipient": "bob", "index": 0, "totalChunks": 1,
		"encryptedPayload": strings.Repeat("x", 700*1024),
		"sizeBytes":        700 * 1024,
	}
	recorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, requestJSON(t, http.MethodPost, "/attachments/chunks", chunk))

	if recorder.Code != http.StatusAccepted {
		t.Fatalf("status = %d (%s), want 202 — a real chunk must clear the body limit",
			recorder.Code, recorder.Body.String())
	}
}
