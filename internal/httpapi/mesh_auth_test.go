package httpapi

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"deechat/chat-node/internal/config"
	"deechat/chat-node/internal/model"
	"deechat/chat-node/internal/peer"
	"deechat/chat-node/internal/queue"
)

// Two threats are pinned down here.
//
// The credential: mesh peers used to authenticate on self-asserted X-Dee-Node-ID /
// X-Dee-Node-URL headers, compared against this node's own id, its public URL,
// and the trusted-peer registry. All of those values are published
// unauthenticated on /health and /nodes, so any caller could set one header and
// pull every identity's queued records out of /mesh/snapshot — an end-run around
// fetch auth — or inject records through /mesh/sync.
//
// The exposure: /mesh/* is no longer served on the public listener in any configuration,
// and there is no write endpoint at all. The proxy's 404 for /mesh/* is still
// deployed, but it is now backed by there being nothing behind it to forward to.
// See deploy/README.md.

const testMeshSecret = "shared-pool-mesh-secret-32-bytes-x"

// TestMeshIsNotOnThePublicListener is the structural claim. Not behind a flag,
// not behind the secret: the public mux has no mesh route, so a proxy
// misconfiguration cannot expose one.
func TestMeshIsNotOnThePublicListener(t *testing.T) {
	server := newTestServer()
	seedMeshRecord(t, server)

	for _, target := range []string{"/mesh/snapshot", "/mesh/sync"} {
		request := httptest.NewRequest(http.MethodGet, target, nil)
		// The correct credential, which must not matter on this listener.
		request.Header.Set(meshSecretHeader, testMeshSecret)
		recorder := httptest.NewRecorder()
		server.Handler().ServeHTTP(recorder, request)

		if recorder.Code != http.StatusNotFound {
			t.Fatalf("%s on the PUBLIC listener = %d, want 404", target, recorder.Code)
		}
		if strings.Contains(recorder.Body.String(), "ciphertext") {
			t.Fatalf("the public listener served queued records at %s: %s", target, recorder.Body.String())
		}
	}
}

// TestSpoofedPeerHeadersCannotReachMesh walks the credentials the old check
// accepted. Every one of them is public, and none of them is evidence now. Run
// against the mesh listener, which is the only place the route exists.
func TestSpoofedPeerHeadersCannotReachMesh(t *testing.T) {
	server := newTestServer()
	seedMeshRecord(t, server)

	spoofs := []struct {
		name   string
		header string
		value  string
	}{
		// Both published by GET /health and GET /nodes.
		{"the node's own id", "X-Dee-Node-ID", "node-a"},
		{"the node's own public URL", "X-Dee-Node-URL", "http://node-a.local"},
		// What a configured peer's entry used to look like on /nodes.
		{"a peer's URL", "X-Dee-Node-ID", "http://node-b.local"},
		{"a peer's URL as a URL", "X-Dee-Node-URL", "http://node-b.local"},
	}

	for _, spoof := range spoofs {
		t.Run(spoof.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, "/mesh/snapshot", nil)
			request.Header.Set(spoof.header, spoof.value)
			recorder := httptest.NewRecorder()
			server.MeshHandler().ServeHTTP(recorder, request)

			if recorder.Code != http.StatusForbidden {
				t.Fatalf("snapshot with %s = %d, want 403; body = %s",
					spoof.name, recorder.Code, recorder.Body.String())
			}
			if strings.Contains(recorder.Body.String(), "ciphertext") {
				t.Fatalf("snapshot leaked queued records to a spoofed peer: %s", recorder.Body.String())
			}
		})
	}
}

// TestWrongMeshSecretIsRejected — the credential is compared, not merely present.
func TestWrongMeshSecretIsRejected(t *testing.T) {
	server := newTestServer()

	request := httptest.NewRequest(http.MethodGet, "/mesh/snapshot", nil)
	request.Header.Set(meshSecretHeader, testMeshSecret+"x")
	recorder := httptest.NewRecorder()
	server.MeshHandler().ServeHTTP(recorder, request)

	if recorder.Code != http.StatusForbidden {
		t.Fatalf("snapshot with a wrong secret = %d, want 403", recorder.Code)
	}
}

// TestMeshHandlerIsAbsentWithoutASecret: the failure mode of a security switch
// must be closed. With no credential configured there is no mesh listener to
// stand up at all.
func TestMeshHandlerIsAbsentWithoutASecret(t *testing.T) {
	server := newMeshlessTestServer()
	seedMeshRecord(t, server)

	if handler := server.MeshHandler(); handler != nil {
		t.Fatal("a node with no mesh secret returned a mesh handler")
	}
	for _, target := range []string{"/mesh/snapshot", "/mesh/sync"} {
		request := httptest.NewRequest(http.MethodGet, target, nil)
		// The strongest credential the old code accepted, plus the new one.
		request.Header.Set("X-Dee-Node-ID", "node-a")
		request.Header.Set(meshSecretHeader, testMeshSecret)
		recorder := httptest.NewRecorder()
		server.Handler().ServeHTTP(recorder, request)

		if recorder.Code != http.StatusNotFound {
			t.Fatalf("%s on a node with no mesh secret = %d, want 404; body = %s",
				target, recorder.Code, recorder.Body.String())
		}
	}
}

// TestMeshSnapshotIsNotAnEndRunAroundFetchAuth states the whole point in one
// place: on an enforcing node, the two doors into a queue agree. Before the
// pool secret, /messages returned 401 while /mesh/snapshot handed back every
// queue.
func TestMeshSnapshotIsNotAnEndRunAroundFetchAuth(t *testing.T) {
	server := newEnforcingMeshTestServer()
	postTaggedMessage(t, server, "msg-tagged", "alice-route", "bob-route")

	front := getWithCapability(t, server, "/messages?recipient=bob-route", "")
	if front.Code != http.StatusUnauthorized {
		t.Fatalf("GET /messages with no capability = %d, want 401", front.Code)
	}

	side := httptest.NewRequest(http.MethodGet, "/mesh/snapshot", nil)
	side.Header.Set("X-Dee-Node-ID", "node-a")
	sideRecorder := httptest.NewRecorder()
	server.MeshHandler().ServeHTTP(sideRecorder, side)
	if sideRecorder.Code != http.StatusForbidden {
		t.Fatalf("GET /mesh/snapshot with a spoofed peer header = %d, want 403; body = %s",
			sideRecorder.Code, sideRecorder.Body.String())
	}

	// And the same request through the front door, where the route does not exist.
	public := httptest.NewRequest(http.MethodGet, "/mesh/snapshot", nil)
	public.Header.Set(meshSecretHeader, testMeshSecret)
	publicRecorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(publicRecorder, public)
	if publicRecorder.Code != http.StatusNotFound {
		t.Fatalf("GET /mesh/snapshot on the public listener = %d, want 404", publicRecorder.Code)
	}
}

// TestPoolMemberWithTheSecretStillReplicates — the fixes close the holes without
// closing the feature.
func TestPoolMemberWithTheSecretStillReplicates(t *testing.T) {
	server := newTestServer()
	seedMeshRecord(t, server)

	snapshot := httptest.NewRequest(http.MethodGet, "/mesh/snapshot", nil)
	snapshot.Header.Set(meshSecretHeader, testMeshSecret)
	recorder := httptest.NewRecorder()
	server.MeshHandler().ServeHTTP(recorder, snapshot)
	if recorder.Code != http.StatusOK {
		t.Fatalf("snapshot with the pool secret = %d", recorder.Code)
	}
	var payload model.SyncPayload
	decodeResponse(t, recorder, &payload)
	if len(payload.Messages) != 1 {
		t.Fatalf("replicated messages = %d, want 1", len(payload.Messages))
	}
	if payload.NextSeq == 0 {
		t.Fatal("snapshot returned records but no cursor to continue from")
	}
}

// A page must not hand back records the caller already has. The cursor is the
// only thing standing between a pool and re-reading every queue on every tick.
func TestMeshSnapshotHonoursTheCursor(t *testing.T) {
	server := newTestServer()
	seedMeshRecord(t, server)

	first := meshSnapshot(t, server, "")
	if len(first.Messages) != 1 {
		t.Fatalf("first page messages = %d, want 1", len(first.Messages))
	}
	second := meshSnapshot(t, server, "?since="+strconv.FormatUint(first.NextSeq, 10))
	if len(second.Messages) != 0 || len(second.Acks) != 0 {
		t.Fatalf("a page past the cursor returned %d messages and %d acks, want none",
			len(second.Messages), len(second.Acks))
	}
	if second.More {
		t.Fatal("a page past the cursor claims more records are waiting")
	}
}

func TestMeshSnapshotRejectsAnUnparseableCursor(t *testing.T) {
	server := newTestServer()
	request := httptest.NewRequest(http.MethodGet, "/mesh/snapshot?since=yesterday", nil)
	request.Header.Set(meshSecretHeader, testMeshSecret)
	recorder := httptest.NewRecorder()
	server.MeshHandler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("snapshot with a junk cursor = %d, want 400", recorder.Code)
	}
}

// TestHealthPublishesMeshStateNotTheSecret: /health is the endpoint that used to
// hand out the mesh credential, so what it says about mesh matters. It now also
// carries replication health — counts and staleness, never peering urls, because
// this endpoint is internet-facing.
func TestHealthPublishesMeshStateNotTheSecret(t *testing.T) {
	recorder := httptest.NewRecorder()
	newTestServer().Handler().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/health", nil))

	body := recorder.Body.String()
	if strings.Contains(body, testMeshSecret) {
		t.Fatalf("/health published the mesh secret: %s", body)
	}
	if strings.Contains(body, "10.0.0.2") {
		t.Fatalf("/health published a peering url: %s", body)
	}
	var health struct {
		MeshEnabled bool `json:"meshEnabled"`
		Mesh        struct {
			Peers            int `json:"peers"`
			Reachable        int `json:"reachable"`
			OldestSyncAgeSec int `json:"oldestSyncAgeSec"`
		} `json:"mesh"`
	}
	decodeResponse(t, recorder, &health)
	if !health.MeshEnabled {
		t.Fatal("meshEnabled = false on a node configured with a mesh secret")
	}
	if health.Mesh.Peers != 1 {
		t.Fatalf("mesh.peers = %d, want the one configured peer", health.Mesh.Peers)
	}
	// Nothing has synced yet, and that has to be visible rather than look healthy:
	// a pool whose every sync returns 404 published the same /health as a working
	// one before this existed.
	if health.Mesh.Reachable != 0 || health.Mesh.OldestSyncAgeSec != -1 {
		t.Fatalf("mesh health before any sync = %+v, want 0 reachable and age -1", health.Mesh)
	}
}

func meshSnapshot(t *testing.T, server *Server, query string) model.SyncPayload {
	t.Helper()
	request := httptest.NewRequest(http.MethodGet, "/mesh/snapshot"+query, nil)
	request.Header.Set(meshSecretHeader, testMeshSecret)
	recorder := httptest.NewRecorder()
	server.MeshHandler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("snapshot%s = %d, body = %s", query, recorder.Code, recorder.Body.String())
	}
	var payload model.SyncPayload
	decodeResponse(t, recorder, &payload)
	return payload
}

func newMeshlessTestServer() *Server {
	cfg := config.Config{
		NodeID:          "node-a",
		Addr:            ":0",
		PublicURL:       "http://node-a.local",
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

func newEnforcingMeshTestServer() *Server {
	cfg := config.Config{
		NodeID:           "node-a",
		Addr:             ":0",
		PublicURL:        "http://node-a.local",
		MeshAddr:         "127.0.0.1:0",
		MeshSecret:       testMeshSecret,
		MaxMessages:      10,
		MaxAcks:          10,
		DefaultTTL:       time.Hour,
		CleanupInterval:  time.Minute,
		RequireFetchAuth: true,
	}
	store := queue.NewStore(queue.StoreConfig{
		MaxMessages: cfg.MaxMessages,
		MaxAcks:     cfg.MaxAcks,
		DefaultTTL:  cfg.DefaultTTL,
	})
	return NewServer(cfg, store, peer.NewPool(cfg.NodeID, cfg.PublicURL, cfg.MeshPeers))
}

func meshTestEnvelope() model.MessageEnvelope {
	now := time.Now().UTC()
	return model.MessageEnvelope{
		ID:               "msg-injected",
		Sender:           "alice-route",
		Recipient:        "bob-route",
		CreatedAt:        now,
		ExpiresAt:        now.Add(time.Hour),
		EncryptedPayload: "ciphertext",
	}
}

func seedMeshRecord(t *testing.T, server *Server) {
	t.Helper()
	if _, err := server.store.AddMessage(meshTestEnvelope(), server.cfg.NodeID); err != nil {
		t.Fatalf("seed queued record: %v", err)
	}
}
