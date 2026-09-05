package mesh

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"deechat/chat-node/internal/config"
	"deechat/chat-node/internal/httpapi"
	"deechat/chat-node/internal/model"
	"deechat/chat-node/internal/peer"
	"deechat/chat-node/internal/queue"
)

// poolSecret stands in for DEE_NODE_MESH_SECRET, shared across the pool.
const poolSecret = "shared-pool-mesh-secret-32-bytes-x"

var syncTime = time.Date(2026, 6, 5, 10, 0, 0, 0, time.UTC)

func newStore(t *testing.T, capacity int) *queue.Store {
	t.Helper()
	return queue.NewStore(queue.StoreConfig{
		MaxMessages: capacity,
		MaxAcks:     2 * capacity,
		DefaultTTL:  time.Hour,
		Now:         func() time.Time { return syncTime },
	})
}

func seed(t *testing.T, store *queue.Store, id, sender, recipient, payload, nodeID string) {
	t.Helper()
	if _, err := store.AddMessage(model.MessageEnvelope{
		ID:               id,
		Sender:           sender,
		Recipient:        recipient,
		CreatedAt:        syncTime,
		ExpiresAt:        syncTime.Add(time.Hour),
		EncryptedPayload: payload,
	}, nodeID); err != nil {
		t.Fatalf("seed %s: %v", id, err)
	}
}

// servePeer stands a relay up on its MESH handler, which is the only listener
// /mesh/* is served on. Handler() — the public one — has no mesh route at all.
func servePeer(t *testing.T, nodeID string, store *queue.Store) *httptest.Server {
	t.Helper()
	httpServer := httptest.NewServer(meshHandlerFor(t, nodeID, store))
	t.Cleanup(httpServer.Close)
	return httpServer
}

func meshHandlerFor(t *testing.T, nodeID string, store *queue.Store) http.Handler {
	t.Helper()
	cfg := config.Config{
		NodeID:     nodeID,
		PublicURL:  "http://" + nodeID + ".local",
		MeshAddr:   "127.0.0.1:0",
		MeshSecret: poolSecret,
		DefaultTTL: time.Hour,
	}
	handler := httpapi.NewServer(cfg, store, peer.NewPool(cfg.NodeID, cfg.PublicURL, nil)).MeshHandler()
	if handler == nil {
		t.Fatal("MeshHandler is nil for a node with a mesh secret")
	}
	return handler
}

func syncerFor(t *testing.T, nodeID, secret string, store *queue.Store, peerURLs ...string) (*Syncer, *peer.Pool) {
	t.Helper()
	cfg := config.Config{
		NodeID:             nodeID,
		PublicURL:          "http://" + nodeID + ".local",
		MeshAddr:           "127.0.0.1:0",
		MeshPeers:          peerURLs,
		MeshSecret:         secret,
		MeshRequestTimeout: 2 * time.Second,
		DefaultTTL:         time.Hour,
	}
	pool := peer.NewPool(cfg.NodeID, cfg.PublicURL, cfg.MeshPeers)
	return NewSyncer(cfg, store, pool), pool
}

func TestSyncerPullsOpaqueQueuesFromAPoolMember(t *testing.T) {
	storeB := newStore(t, 20)
	seed(t, storeB, "msg-from-b", "alice", "bob", "ciphertext-from-b", "node-b")
	peerB := servePeer(t, "node-b", storeB)

	storeA := newStore(t, 20)
	syncer, pool := syncerFor(t, "node-a", poolSecret, storeA, peerB.URL)

	if errs := syncer.SyncAll(context.Background()); len(errs) != 0 {
		t.Fatalf("SyncAll errors = %v", errs)
	}

	pulled := storeA.MessagesForRecipient("bob", 10, queue.NewAuth(nil, true))
	if len(pulled) != 1 || pulled[0].EncryptedPayload != "ciphertext-from-b" {
		t.Fatalf("node-a pulled messages = %#v", pulled)
	}
	if len(storeA.AcksForSender("alice", 10, queue.NewAuth(nil, true))) == 0 {
		t.Fatal("node-a did not import node-b's acks")
	}
	if health := pool.Health(time.Now()); health.Reachable != 1 || health.OldestSyncAgeSec < 0 {
		t.Fatalf("pool health after a good sync = %+v", health)
	}
}

// Replication is pull-only, so a sync leaves the peer's queue untouched: this
// syncer reads the peer's snapshot and posts nothing back.
func TestSyncerNeverWritesIntoThePeersQueue(t *testing.T) {
	storeB := newStore(t, 20)
	peerB := servePeer(t, "node-b", storeB)

	storeA := newStore(t, 20)
	seed(t, storeA, "msg-from-a", "carol", "dana", "ciphertext-from-a", "node-a")
	syncer, _ := syncerFor(t, "node-a", poolSecret, storeA, peerB.URL)

	if errs := syncer.SyncAll(context.Background()); len(errs) != 0 {
		t.Fatalf("SyncAll errors = %v", errs)
	}
	if stats := storeB.Stats(); stats.Messages != 0 || stats.Acks != 0 {
		t.Fatalf("the peer's queue changed during a pull: %+v", stats)
	}
}

// TestSyncerCannotReplicateWithTheWrongSecret is the outbound half of the
// pool-secret credential: before it, node-a only had to assert its own id in a
// header to pull node-b's entire queue.
func TestSyncerCannotReplicateWithTheWrongSecret(t *testing.T) {
	storeB := newStore(t, 20)
	seed(t, storeB, "msg-from-b", "alice", "bob", "ciphertext-from-b", "node-b")
	peerB := servePeer(t, "node-b", storeB)

	storeA := newStore(t, 20)
	syncer, _ := syncerFor(t, "node-a", "not-the-pool-secret", storeA, peerB.URL)

	if errs := syncer.SyncAll(context.Background()); len(errs) == 0 {
		t.Fatal("SyncAll succeeded against a peer outside the pool")
	}
	if pulled := storeA.MessagesForRecipient("bob", 10, queue.NewAuth(nil, true)); len(pulled) != 0 {
		t.Fatalf("node-a pulled %d messages with the wrong secret, want 0", len(pulled))
	}
}

// TestSyncerRefusesToReplicateWithNoSecret: an operator who configures peers but
// forgets the secret gets no replication, not unauthenticated replication.
func TestSyncerRefusesToReplicateWithNoSecret(t *testing.T) {
	syncer, _ := syncerFor(t, "node-a", "", newStore(t, 5), "http://node-b.local")
	if errs := syncer.SyncAll(context.Background()); len(errs) != 1 {
		t.Fatalf("SyncAll errors with no mesh secret = %v, want exactly one refusal", errs)
	}
}

// TestSyncerPagesPastTheFirstPage is the replication finding that produced
// paging, as a test.
//
// The original exchange asked for the oldest 500 records every tick and pushed the
// same 500 back, so a relay holding more than a page never replicated past it:
// measured on a three-relay loopback pool, 621 records held and 501 replicated,
// unchanged over nine ticks. The newest mail — the whole point of a pool — was
// exactly what never crossed.
func TestSyncerPagesPastTheFirstPage(t *testing.T) {
	const held = 1200

	storeB := newStore(t, 4000)
	for i := 0; i < held; i++ {
		seed(t, storeB, fmt.Sprintf("msg-%04d", i), "alice", fmt.Sprintf("queue-%04d", i), "ciphertext", "node-b")
	}
	peerB := servePeer(t, "node-b", storeB)

	storeA := newStore(t, 4000)
	syncer, _ := syncerFor(t, "node-a", poolSecret, storeA, peerB.URL)
	if errs := syncer.SyncAll(context.Background()); len(errs) != 0 {
		t.Fatalf("SyncAll errors = %v", errs)
	}

	// Every message, including the newest, in one tick.
	if stats := storeA.Stats(); stats.Messages != held {
		t.Fatalf("node-a holds %d of %d messages after one sync; the tail did not cross", stats.Messages, held)
	}
	newest := storeA.MessagesForRecipient(fmt.Sprintf("queue-%04d", held-1), 5, queue.NewAuth(nil, true))
	if len(newest) != 1 {
		t.Fatalf("the newest message did not replicate: %#v", newest)
	}
}

// The cursor is what makes paging affordable: a tick with nothing new must cost
// one request, not a re-read of the peer's whole queue.
func TestSyncerCursorStopsItRereadingTheSameRecords(t *testing.T) {
	storeB := newStore(t, 2000)
	for i := 0; i < 700; i++ {
		seed(t, storeB, fmt.Sprintf("msg-%04d", i), "alice", fmt.Sprintf("queue-%04d", i), "ciphertext", "node-b")
	}

	var mu sync.Mutex
	requests := 0
	peerB := servePeer(t, "node-b", storeB)
	counted := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		requests++
		mu.Unlock()
		proxied, err := http.NewRequest(r.Method, peerB.URL+r.URL.RequestURI(), nil)
		if err != nil {
			t.Errorf("build proxied request: %v", err)
			return
		}
		proxied.Header = r.Header.Clone()
		response, err := http.DefaultClient.Do(proxied)
		if err != nil {
			t.Errorf("proxy to peer: %v", err)
			return
		}
		defer response.Body.Close()
		w.WriteHeader(response.StatusCode)
		if _, err := io.Copy(w, response.Body); err != nil {
			t.Errorf("copy body: %v", err)
		}
	}))
	defer counted.Close()

	storeA := newStore(t, 2000)
	syncer, _ := syncerFor(t, "node-a", poolSecret, storeA, counted.URL)

	if errs := syncer.SyncAll(context.Background()); len(errs) != 0 {
		t.Fatalf("first SyncAll errors = %v", errs)
	}
	mu.Lock()
	first := requests
	requests = 0
	mu.Unlock()
	if first < 2 {
		t.Fatalf("first sync made %d requests; 700 messages plus their acks needs more than one page", first)
	}

	if errs := syncer.SyncAll(context.Background()); len(errs) != 0 {
		t.Fatalf("second SyncAll errors = %v", errs)
	}
	mu.Lock()
	second := requests
	mu.Unlock()
	if second != 1 {
		t.Fatalf("a sync with nothing new made %d requests, want 1", second)
	}
}

// A peer restart empties its queues and restarts its sequence numbers. A cursor
// held across that would page from a mark the peer no longer has, so the epoch
// tells the puller to start over.
func TestSyncerResetsItsCursorWhenThePeerRestarts(t *testing.T) {
	storeB := newStore(t, 20)
	seed(t, storeB, "msg-before", "alice", "bob", "ciphertext", "node-b")

	var live atomic.Value
	live.Store(meshHandlerFor(t, "node-b", storeB))
	peerB := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		live.Load().(http.Handler).ServeHTTP(w, r)
	}))
	defer peerB.Close()

	storeA := newStore(t, 20)
	syncer, _ := syncerFor(t, "node-a", poolSecret, storeA, peerB.URL)
	if errs := syncer.SyncAll(context.Background()); len(errs) != 0 {
		t.Fatalf("first SyncAll errors = %v", errs)
	}

	// The restart: a brand-new store, so a new epoch and sequence numbers from 1,
	// served at the same peering url.
	restarted := newStore(t, 20)
	seed(t, restarted, "msg-after", "alice", "bob", "ciphertext", "node-b")
	live.Store(meshHandlerFor(t, "node-b", restarted))

	if errs := syncer.SyncAll(context.Background()); len(errs) != 0 {
		t.Fatalf("SyncAll after the peer restart = %v", errs)
	}
	pulled := storeA.MessagesForRecipient("bob", 10, queue.NewAuth(nil, true))
	if len(pulled) != 2 {
		t.Fatalf("node-a holds %d of bob's messages after the peer restarted, want both", len(pulled))
	}
}

// A peer answering with a redirect must not be followed. Go copies custom headers
// onto the redirected request, and the pool secret is a custom header — verified
// against a stand-in peer, which received it in full before this was closed.
func TestSyncerRefusesARedirectRatherThanForwardingTheSecret(t *testing.T) {
	var mu sync.Mutex
	var leaked string
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		leaked = r.Header.Get(model.MeshSecretHeader)
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"nodeId":"attacker","messages":[],"acks":[]}`))
	}))
	defer target.Close()

	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+r.URL.RequestURI(), http.StatusFound)
	}))
	defer redirector.Close()

	syncer, _ := syncerFor(t, "node-a", poolSecret, newStore(t, 20), redirector.URL)
	if errs := syncer.SyncAll(context.Background()); len(errs) == 0 {
		t.Fatal("SyncAll followed a redirect instead of refusing it")
	}
	mu.Lock()
	defer mu.Unlock()
	if leaked != "" {
		t.Fatalf("the pool secret reached the redirect target: %q", leaked)
	}
}

// A peer that claims more records but does not advance the cursor gets one page
// and an error, not an unbounded request storm.
func TestSyncerStopsWhenAPeersCursorDoesNotAdvance(t *testing.T) {
	var mu sync.Mutex
	requests := 0
	stuck := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		requests++
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"nodeId":"stuck","epoch":"e1","nextSeq":0,"more":true,"messages":[],"acks":[]}`))
	}))
	defer stuck.Close()

	syncer, _ := syncerFor(t, "node-a", poolSecret, newStore(t, 20), stuck.URL)
	if errs := syncer.SyncAll(context.Background()); len(errs) != 1 {
		t.Fatalf("SyncAll errors against a stuck cursor = %v, want one", errs)
	}
	mu.Lock()
	defer mu.Unlock()
	if requests != 1 {
		t.Fatalf("made %d requests against a peer whose cursor never advances, want 1", requests)
	}
}

// The sync list comes from configuration and from nowhere else. A peer used to be
// able to name new trusted nodes in its /nodes response; the syncer no longer asks
// any peer anything about the pool, and this asserts the only path it requests.
func TestSyncerOnlyEverAsksForTheSnapshotPath(t *testing.T) {
	var mu sync.Mutex
	var paths []string
	watcher := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		paths = append(paths, r.URL.Path)
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		// A poisoned roster, which nothing reads any more.
		_, _ = w.Write([]byte(`{"nodeId":"poison","epoch":"e1","nextSeq":0,"messages":[],"acks":[],` +
			`"nodes":[{"id":"attacker","url":"http://attacker.example","trusted":true}]}`))
	}))
	defer watcher.Close()

	syncer, pool := syncerFor(t, "node-a", poolSecret, newStore(t, 20), watcher.URL)
	_ = syncer.SyncAll(context.Background())

	mu.Lock()
	defer mu.Unlock()
	for _, path := range paths {
		if path != "/mesh/snapshot" {
			t.Fatalf("syncer requested %q; the only path it may request is /mesh/snapshot", path)
		}
	}
	targets := pool.Targets()
	if len(targets) != 1 || targets[0] != watcher.URL {
		t.Fatalf("sync targets after a poisoned response = %v, want only the configured peer", targets)
	}
}

// TestSyncerRefusesAnEndlessSnapshotPage stands up a peer that answers
// GET /mesh/snapshot with a body that never ends. Before the pull side was
// bounded, this decoded straight into the puller's heap: pagesPerSync and
// pageSize cap the records asked for, and nothing capped the bytes accepted.
func TestSyncerRefusesAnEndlessSnapshotPage(t *testing.T) {
	filler := `{"id":"x","sender":"s","recipient":"r","encryptedPayload":"` + strings.Repeat("A", 4096) + `"},`
	flood := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if _, err := io.WriteString(w, `{"nodeId":"flood","messages":[`); err != nil {
			return
		}
		for {
			select {
			case <-r.Context().Done():
				return
			default:
			}
			// Stops when the puller hangs up, which is the behaviour under test.
			if _, err := io.WriteString(w, filler); err != nil {
				return
			}
		}
	}))
	defer flood.Close()

	store := newStore(t, 100)
	syncer, _ := syncerFor(t, "local", poolSecret, store, flood.URL)

	_, err := syncer.SyncPeer(context.Background(), flood.URL)
	if err == nil {
		t.Fatal("an endless snapshot page was accepted; the pull side is unbounded again")
	}
	if !strings.Contains(err.Error(), "refusing to buffer") {
		t.Fatalf("the page was refused for the wrong reason: %v", err)
	}
	if got := store.Stats().Messages; got != 0 {
		t.Fatalf("a refused page still imported %d messages", got)
	}
}

// TestTheSnapshotCeilingIsDerivedFromThisNodesCaps pins the ceiling to the
// configured caps rather than to a knob of its own, and pins the zero-value
// fallbacks: a Config built by hand must not get a ceiling tighter than the
// records a peer may legitimately serve.
func TestTheSnapshotCeilingIsDerivedFromThisNodesCaps(t *testing.T) {
	sized, _ := syncerFor(t, "local", poolSecret, newStore(t, 10))
	sized.cfg.MaxPayloadBytes = 8192
	sized.cfg.MaxPurges = 1000

	want := int64(pageSize)*int64(8192+snapshotRecordSlack) +
		1000*snapshotPurgeSlack +
		snapshotPresenceRecords*snapshotPresenceSlack
	if got := sized.maxSnapshotBytes(); got != want {
		t.Fatalf("ceiling is %d bytes, derived figure is %d", got, want)
	}

	// A page of full-size records, its tombstones and both presence tables has
	// to fit under the ceiling, or replication refuses pages a peer is entitled
	// to serve.
	legitimate := int64(pageSize) * int64(8192)
	if want <= legitimate {
		t.Fatalf("ceiling %d is below a legal page's payload bytes alone (%d)", want, legitimate)
	}

	bare, _ := syncerFor(t, "local", poolSecret, newStore(t, 10))
	bare.cfg.MaxPayloadBytes = 0
	bare.cfg.MaxPurges = 0
	if got := bare.maxSnapshotBytes(); got != want {
		t.Fatalf("a zero-value config got %d bytes rather than the default-derived %d", got, want)
	}
}
