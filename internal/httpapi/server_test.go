package httpapi

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"deechat/chat-node/internal/config"
	"deechat/chat-node/internal/model"
	"deechat/chat-node/internal/peer"
	"deechat/chat-node/internal/queue"
)

func TestServerMessageAndAckFlow(t *testing.T) {
	server := newTestServer()

	message := model.MessageEnvelope{
		ID:               "msg-1",
		Sender:           "alice-route",
		Recipient:        "bob-route",
		CreatedAt:        time.Now().UTC(),
		ExpiresAt:        time.Now().Add(time.Hour).UTC(),
		EncryptedPayload: "ciphertext",
	}
	postMessage := requestJSON(t, http.MethodPost, "/messages", message)
	postMessageRecorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(postMessageRecorder, postMessage)
	if postMessageRecorder.Code != http.StatusAccepted {
		t.Fatalf("POST /messages status = %d, body = %s", postMessageRecorder.Code, postMessageRecorder.Body.String())
	}

	getMessages := httptest.NewRequest(http.MethodGet, "/messages?recipient=bob-route", nil)
	getMessagesRecorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(getMessagesRecorder, getMessages)
	if getMessagesRecorder.Code != http.StatusOK {
		t.Fatalf("GET /messages status = %d", getMessagesRecorder.Code)
	}
	var messagesResponse struct {
		Messages []model.MessageEnvelope `json:"messages"`
	}
	decodeResponse(t, getMessagesRecorder, &messagesResponse)
	if len(messagesResponse.Messages) != 1 {
		t.Fatalf("message count = %d, want 1", len(messagesResponse.Messages))
	}

	ack := model.AckRecord{
		ID:        "ack-1",
		MessageID: "msg-1",
		Sender:    "alice-route",
		Recipient: "bob-route",
		Type:      model.AckRecipientDeviceReceived,
		CreatedAt: time.Now().UTC(),
		ExpiresAt: time.Now().Add(time.Hour).UTC(),
		Signature: "recipient-e2e-signature",
	}
	postAck := requestJSON(t, http.MethodPost, "/acks", ack)
	postAckRecorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(postAckRecorder, postAck)
	if postAckRecorder.Code != http.StatusAccepted {
		t.Fatalf("POST /acks status = %d, body = %s", postAckRecorder.Code, postAckRecorder.Body.String())
	}

	getAcks := httptest.NewRequest(http.MethodGet, "/acks?sender=alice-route", nil)
	getAcksRecorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(getAcksRecorder, getAcks)
	if getAcksRecorder.Code != http.StatusOK {
		t.Fatalf("GET /acks status = %d", getAcksRecorder.Code)
	}
	var acksResponse struct {
		Acks []model.AckRecord `json:"acks"`
	}
	decodeResponse(t, getAcksRecorder, &acksResponse)
	if len(acksResponse.Acks) != 2 {
		t.Fatalf("ack count = %d, want node ack and recipient ack", len(acksResponse.Acks))
	}
	if acksResponse.Acks[1].Signature != ack.Signature {
		t.Fatalf("ack signature = %q, want %q", acksResponse.Acks[1].Signature, ack.Signature)
	}
}

func TestServerRejectsPlaintextShapedMessageFields(t *testing.T) {
	server := newTestServer()
	request := httptest.NewRequest(
		http.MethodPost,
		"/messages",
		bytes.NewBufferString(`{"id":"msg-1","sender":"alice","recipient":"bob","encryptedPayload":"ciphertext","plaintext":"hello"}`),
	)
	request.Header.Set("Content-Type", "application/json")

	recorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 for unknown plaintext field", recorder.Code)
	}
}

func attachmentChunk(id string, index int) map[string]any {
	now := time.Now().UTC()
	return map[string]any{
		"id": id, "transferId": "transfer-1", "capability": "secret",
		"recipient": "bob", "index": index, "totalChunks": 32,
		"encryptedPayload": "opaque-ciphertext-" + id, "sizeBytes": 32,
		"createdAt": now, "expiresAt": now.Add(time.Minute),
	}
}

func TestServerLiveRelaysAttachmentChunksAndRetainsNothing(t *testing.T) {
	server := newTestServer()
	postRecorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(postRecorder, requestJSON(t, http.MethodPost, "/attachments/chunks", attachmentChunk("chunk-1", 0)))
	if postRecorder.Code != http.StatusAccepted {
		t.Fatalf("POST attachment status = %d body = %s", postRecorder.Code, postRecorder.Body.String())
	}
	getRecorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(getRecorder, httptest.NewRequest(http.MethodGet, "/attachments/chunks?recipient=bob&capability=secret", nil))
	if getRecorder.Code != http.StatusOK || !bytes.Contains(getRecorder.Body.Bytes(), []byte("opaque-ciphertext-chunk-1")) {
		t.Fatalf("GET attachment status = %d body = %s", getRecorder.Code, getRecorder.Body.String())
	}
	// After the recipient drained, a second poll finds an empty window — the node
	// kept nothing.
	emptyRecorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(emptyRecorder, httptest.NewRequest(http.MethodGet, "/attachments/chunks?recipient=bob&capability=secret&wait=0", nil))
	if emptyRecorder.Code != http.StatusOK || bytes.Contains(emptyRecorder.Body.Bytes(), []byte("opaque-ciphertext")) {
		t.Fatalf("second GET should be empty: status = %d body = %s", emptyRecorder.Code, emptyRecorder.Body.String())
	}
	completeRecorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(completeRecorder, requestJSON(t, http.MethodPost, "/attachments/complete", map[string]string{"transferId": "transfer-1", "capability": "secret"}))
	if completeRecorder.Code != http.StatusOK {
		t.Fatalf("complete status = %d body = %s", completeRecorder.Code, completeRecorder.Body.String())
	}
}

func TestServerBackPressuresWhenRelayWindowFull(t *testing.T) {
	server := newTestServer() // default relay window = 8
	for i := 0; i < 8; i++ {
		rec := httptest.NewRecorder()
		server.Handler().ServeHTTP(rec, requestJSON(t, http.MethodPost, "/attachments/chunks", attachmentChunk("chunk-"+strconv.Itoa(i), i)))
		if rec.Code != http.StatusAccepted {
			t.Fatalf("POST %d status = %d body = %s", i, rec.Code, rec.Body.String())
		}
	}
	// The 9th push with the recipient not draining must be back-pressured.
	full := httptest.NewRecorder()
	server.Handler().ServeHTTP(full, requestJSON(t, http.MethodPost, "/attachments/chunks", attachmentChunk("chunk-8", 8)))
	if full.Code != http.StatusTooManyRequests || !bytes.Contains(full.Body.Bytes(), []byte("window_full")) {
		t.Fatalf("expected 429 window_full, got status = %d body = %s", full.Code, full.Body.String())
	}
}

func TestServerNodesAndHealth(t *testing.T) {
	server := newTestServer()

	healthRecorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(healthRecorder, httptest.NewRequest(http.MethodGet, "/health", nil))
	if healthRecorder.Code != http.StatusOK {
		t.Fatalf("GET /health status = %d", healthRecorder.Code)
	}

	nodesRecorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(nodesRecorder, httptest.NewRequest(http.MethodGet, "/nodes", nil))
	if nodesRecorder.Code != http.StatusOK {
		t.Fatalf("GET /nodes status = %d", nodesRecorder.Code)
	}
	var nodesResponse struct {
		Nodes []model.NodeInfo `json:"nodes"`
	}
	decodeResponse(t, nodesRecorder, &nodesResponse)
	// Only this relay. /nodes used to publish everything the node had heard about
	// from its peers, which made it the pool's gossip channel and a compromised
	// member's way to advertise a host of its choosing to everyone else.
	if len(nodesResponse.Nodes) != 1 || nodesResponse.Nodes[0].ID != "node-a" {
		t.Fatalf("GET /nodes = %#v, want this relay and nothing else", nodesResponse.Nodes)
	}
}

func TestServerMeshSnapshotRequiresThePoolSecret(t *testing.T) {
	server := newTestServer()

	recorder := httptest.NewRecorder()
	server.MeshHandler().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/mesh/snapshot", nil))
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("snapshot without the pool secret status = %d, want 403", recorder.Code)
	}

	request := httptest.NewRequest(http.MethodGet, "/mesh/snapshot", nil)
	request.Header.Set(meshSecretHeader, testMeshSecret)
	trustedRecorder := httptest.NewRecorder()
	server.MeshHandler().ServeHTTP(trustedRecorder, request)
	if trustedRecorder.Code != http.StatusOK {
		t.Fatalf("trusted snapshot status = %d, body = %s", trustedRecorder.Code, trustedRecorder.Body.String())
	}
	var payload model.SyncPayload
	decodeResponse(t, trustedRecorder, &payload)
	if payload.NodeID != "node-a" {
		t.Fatalf("snapshot node id = %q, want node-a", payload.NodeID)
	}
	if payload.Epoch == "" {
		t.Fatal("snapshot carries no epoch, so a peer cannot tell a restart from a gap")
	}
}

// The write endpoint is gone. Replication is pull-only, so no pool member — with
// or without the secret — can push a record at this relay. That is all this test
// checks; a peer this relay pulls from can still put records into these queues,
// which is what replication is. Importing is covered where it now happens, in
// internal/mesh.
func TestServerHasNoMeshWriteEndpoint(t *testing.T) {
	server := newTestServer()
	now := time.Now().UTC()
	payload := model.SyncPayload{
		NodeID: "node-b",
		Messages: []model.MessageEnvelope{{
			ID:               "msg-from-peer",
			Sender:           "alice-route",
			Recipient:        "bob-route",
			CreatedAt:        now,
			ExpiresAt:        now.Add(time.Hour),
			EncryptedPayload: "peer-ciphertext",
		}},
	}

	for name, handler := range map[string]http.Handler{
		"public": server.Handler(),
		"mesh":   server.MeshHandler(),
	} {
		request := requestJSON(t, http.MethodPost, "/mesh/sync", payload)
		request.Header.Set(meshSecretHeader, testMeshSecret)
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, request)
		if recorder.Code == http.StatusAccepted || recorder.Code == http.StatusOK {
			t.Fatalf("POST /mesh/sync on the %s listener = %d; the route must not exist", name, recorder.Code)
		}
	}
	if got := len(server.store.MessagesForRecipient("bob-route", 10, queue.NewAuth(nil, true))); got != 0 {
		t.Fatalf("records reached the queue through a removed endpoint = %d, want 0", got)
	}
}

func TestServerPrekeyPublishClaimAndDrain(t *testing.T) {
	server := newTestServer()

	publish := model.PrekeyPublish{
		Entries: []model.PrekeyEntry{
			{OpkID: "opk-1", PublicKey: "pub-1", Signature: "sig-1"},
			{OpkID: "opk-2", PublicKey: "pub-2", Signature: "sig-2"},
		},
	}
	publishRecorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(publishRecorder, asOwner(requestJSON(t, http.MethodPost, "/prekeys", publish), "bob-secret"))
	if publishRecorder.Code != http.StatusAccepted {
		t.Fatalf("POST /prekeys status = %d body = %s", publishRecorder.Code, publishRecorder.Body.String())
	}

	statusRecorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(statusRecorder, asOwner(httptest.NewRequest(http.MethodGet, "/prekeys/status", nil), "bob-secret"))
	var status struct {
		Available int `json:"available"`
	}
	decodeResponse(t, statusRecorder, &status)
	if status.Available != 2 {
		t.Fatalf("available = %d, want 2", status.Available)
	}

	claimed := make(map[string]bool)
	for i := 0; i < 2; i++ {
		claimRecorder := httptest.NewRecorder()
		server.Handler().ServeHTTP(claimRecorder, httptest.NewRequest(http.MethodGet, "/prekeys/claim?tag="+poolTag("bob-secret"), nil))
		if claimRecorder.Code != http.StatusOK {
			t.Fatalf("claim %d status = %d body = %s", i, claimRecorder.Code, claimRecorder.Body.String())
		}
		var response struct {
			Prekey model.PrekeyEntry `json:"prekey"`
		}
		decodeResponse(t, claimRecorder, &response)
		if claimed[response.Prekey.OpkID] {
			t.Fatalf("claim-once violated: %q claimed twice", response.Prekey.OpkID)
		}
		claimed[response.Prekey.OpkID] = true
	}

	drainedRecorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(drainedRecorder, httptest.NewRequest(http.MethodGet, "/prekeys/claim?tag="+poolTag("bob-secret"), nil))
	if drainedRecorder.Code != http.StatusNotFound {
		t.Fatalf("drained claim status = %d, want 404", drainedRecorder.Code)
	}
}

// TestServerPrekeyClaimServesLastResort verifies that once the one-time pool is
// drained a published last-resort prekey is served over HTTP with the
// lastResort flag set (instead of a 404 → v2 downgrade).
func TestServerPrekeyClaimServesLastResort(t *testing.T) {
	server := newTestServer()

	publish := model.PrekeyPublish{
		Entries:    []model.PrekeyEntry{{OpkID: "opk-1", PublicKey: "pub-1", Signature: "sig-1"}},
		LastResort: &model.PrekeyEntry{OpkID: "lrpk-1", PublicKey: "lr-pub", Signature: "lr-sig"},
	}
	rec := httptest.NewRecorder()
	server.Handler().ServeHTTP(rec, asOwner(requestJSON(t, http.MethodPost, "/prekeys", publish), "bob-secret"))
	if rec.Code != http.StatusAccepted {
		t.Fatalf("POST /prekeys status = %d body = %s", rec.Code, rec.Body.String())
	}

	claim := func() model.PrekeyEntry {
		r := httptest.NewRecorder()
		server.Handler().ServeHTTP(r, httptest.NewRequest(http.MethodGet, "/prekeys/claim?tag="+poolTag("bob-secret"), nil))
		if r.Code != http.StatusOK {
			t.Fatalf("claim status = %d body = %s", r.Code, r.Body.String())
		}
		var response struct {
			Prekey model.PrekeyEntry `json:"prekey"`
		}
		decodeResponse(t, r, &response)
		return response.Prekey
	}

	// First claim pops the genuine one-time entry (no flag).
	if first := claim(); first.LastResort || first.OpkID != "opk-1" {
		t.Fatalf("first claim = %q lastResort=%v, want opk-1 one-time", first.OpkID, first.LastResort)
	}
	// Pool now drained → the reusable last-resort is served, flagged.
	second := claim()
	if !second.LastResort || second.OpkID != "lrpk-1" {
		t.Fatalf("drained claim = %q lastResort=%v, want flagged lrpk-1", second.OpkID, second.LastResort)
	}
}

// TestServerPrekeyDeviceScoped verifies that two devices of one recipient hold
// independent pools over HTTP: publish carries deviceKey, claim/status take a
// ?device= param, and a device's claim never yields another device's prekey.
func TestServerPrekeyDeviceScoped(t *testing.T) {
	server := newTestServer()

	publishDevice := func(device string, ids ...string) {
		entries := make([]model.PrekeyEntry, 0, len(ids))
		for _, id := range ids {
			entries = append(entries, model.PrekeyEntry{OpkID: id, PublicKey: "pub-" + id, Signature: "sig-" + id})
		}
		rec := httptest.NewRecorder()
		server.Handler().ServeHTTP(rec, asOwner(requestJSON(t, http.MethodPost, "/prekeys", model.PrekeyPublish{
			DeviceKey: device, Entries: entries,
		}), "bob-secret"))
		if rec.Code != http.StatusAccepted {
			t.Fatalf("publish device %q status = %d body = %s", device, rec.Code, rec.Body.String())
		}
	}
	publishDevice("devA", "a-1", "a-2")
	publishDevice("devB", "b-1")

	statusFor := func(query string) int {
		rec := httptest.NewRecorder()
		server.Handler().ServeHTTP(rec, asOwner(httptest.NewRequest(http.MethodGet, "/prekeys/status?"+query, nil), "bob-secret"))
		var status struct {
			Available int `json:"available"`
		}
		decodeResponse(t, rec, &status)
		return status.Available
	}
	if got := statusFor("device=devA"); got != 2 {
		t.Fatalf("devA available = %d, want 2", got)
	}
	if got := statusFor("device=devB"); got != 1 {
		t.Fatalf("devB available = %d, want 1", got)
	}
	// Absent ?device= → the owner-wide bucket, empty here.
	if got := statusFor(""); got != 0 {
		t.Fatalf("legacy available = %d, want 0", got)
	}

	// Claim devB twice: the second is a drained 404 and devA stays untouched.
	rec := httptest.NewRecorder()
	server.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/prekeys/claim?tag="+poolTag("bob-secret")+"&device=devB", nil))
	var claim struct {
		Prekey model.PrekeyEntry `json:"prekey"`
	}
	decodeResponse(t, rec, &claim)
	if claim.Prekey.OpkID != "b-1" {
		t.Fatalf("devB claim = %q, want b-1", claim.Prekey.OpkID)
	}
	drained := httptest.NewRecorder()
	server.Handler().ServeHTTP(drained, httptest.NewRequest(http.MethodGet, "/prekeys/claim?tag="+poolTag("bob-secret")+"&device=devB", nil))
	if drained.Code != http.StatusNotFound {
		t.Fatalf("drained devB claim status = %d, want 404", drained.Code)
	}
	if got := statusFor("device=devA"); got != 2 {
		t.Fatalf("devA available after devB drain = %d, want 2", got)
	}
}

func newTestServer() *Server {
	cfg := config.Config{
		NodeID:          "node-a",
		Addr:            ":0",
		PublicURL:       "http://node-a.local",
		MeshAddr:        "127.0.0.1:0",
		MeshPeers:       []string{"http://10.0.0.2:8081"},
		MeshSecret:      testMeshSecret,
		MaxMessages:     10,
		MaxAcks:         10,
		DefaultTTL:      time.Hour,
		CleanupInterval: time.Minute,
	}
	store := queue.NewStore(queue.StoreConfig{
		MaxMessages: cfg.MaxMessages,
		MaxAcks:     cfg.MaxAcks,
		DefaultTTL:  cfg.DefaultTTL,
	})
	return NewServer(cfg, store, peer.NewPool(cfg.NodeID, cfg.PublicURL, cfg.MeshPeers))
}

func requestJSON(t *testing.T, method string, target string, value any) *http.Request {
	t.Helper()
	var body bytes.Buffer
	if err := json.NewEncoder(&body).Encode(value); err != nil {
		t.Fatalf("encode request: %v", err)
	}
	request := httptest.NewRequest(method, target, &body)
	request.Header.Set("Content-Type", "application/json")
	return request
}

// asOwner presents a queue secret on a request. A prekey pool is keyed by its
// owner's queue tag, so these tests name a pool by the secret behind it rather
// than by a routing id — which is the whole point: there is no longer a routing
// id anywhere on the prekey routes.
func asOwner(request *http.Request, secret string) *http.Request {
	request.Header.Set(queueCapabilityHeader, secret)
	return request
}

// poolTag is the public half a sender claims against, exactly as a contact holds
// it from the contact code.
func poolTag(secret string) string { return queue.TagForSecret(secret) }

func decodeResponse(t *testing.T, recorder *httptest.ResponseRecorder, target any) {
	t.Helper()
	if err := json.NewDecoder(recorder.Body).Decode(target); err != nil {
		t.Fatalf("decode response: %v", err)
	}
}

// TestPrekeyBucketCeilingIsServedAsBackPressure walks the configured cap out to
// the wire: a new recipient past DEE_NODE_MAX_PREKEY_BUCKETS is refused with a
// status the client already backs off on, and a recipient the box already
// carries keeps publishing. It also pins the wiring — the store the server ends
// up using has to be the one sized from cfg.
func TestPrekeyBucketCeilingIsServedAsBackPressure(t *testing.T) {
	cfg := config.Config{
		NodeID:           "node-a",
		PublicURL:        "http://node-a.local",
		MaxMessages:      10,
		MaxAcks:          10,
		DefaultTTL:       time.Hour,
		MaxPrekeyBuckets: 1,
	}
	store := queue.NewStore(queue.StoreConfig{MaxMessages: cfg.MaxMessages, MaxAcks: cfg.MaxAcks, DefaultTTL: cfg.DefaultTTL})
	server := NewServer(cfg, store, peer.NewPool(cfg.NodeID, cfg.PublicURL, nil))

	publish := func(secret, opk string) *httptest.ResponseRecorder {
		recorder := httptest.NewRecorder()
		server.Handler().ServeHTTP(recorder, asOwner(requestJSON(t, http.MethodPost, "/prekeys", model.PrekeyPublish{
			Entries: []model.PrekeyEntry{{OpkID: opk, PublicKey: "pub", Signature: "sig"}},
		}), secret))
		return recorder
	}

	if got := publish("bob-secret", "opk-1").Code; got != http.StatusAccepted {
		t.Fatalf("first publish = %d, want 202", got)
	}
	refused := publish("mallory-secret", "opk-2")
	if refused.Code != http.StatusTooManyRequests {
		t.Fatalf("publish past the ceiling = %d, want 429; body = %s", refused.Code, refused.Body.String())
	}
	if got := publish("bob-secret", "opk-1b").Code; got != http.StatusAccepted {
		t.Fatalf("replenish at the ceiling = %d, want 202", got)
	}

	healthRecorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(healthRecorder, httptest.NewRequest(http.MethodGet, "/health", nil))
	var health struct {
		PrekeyBuckets int `json:"prekeyBuckets"`
	}
	if err := json.Unmarshal(healthRecorder.Body.Bytes(), &health); err != nil {
		t.Fatalf("decode health: %v", err)
	}
	if health.PrekeyBuckets != 1 {
		t.Fatalf("health prekeyBuckets = %d, want 1", health.PrekeyBuckets)
	}
}
