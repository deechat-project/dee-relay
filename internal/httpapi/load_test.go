package httpapi

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"deechat/chat-node/internal/config"
	"deechat/chat-node/internal/model"
	"deechat/chat-node/internal/peer"
	"deechat/chat-node/internal/queue"
)

// This file is a synthetic load / integration harness for the capacity & quota
// work. The node only ever sees opaque ciphertext blobs and routing ids, so a
// realistic many-user simulation needs no crypto and no real accounts: it just
// drives the real HTTP handlers (POST /messages, GET /messages, POST /acks,
// GET /acks, GET /health) concurrently and asserts the system-level invariants
// that "100 real users hammering the relay" would actually exercise:
//
//   - nothing is lost: every accepted message is delivered exactly once;
//   - resends reuse the same envelope id and dedupe (app resend model);
//   - the per-pair quota isolates one flooder from every other conversation;
//   - oversize payloads are refused (413) and over-long TTLs are clamped;
//   - delivered acks drain the queue back to empty;
//   - none of it races (run with `go test -race`).

// loadServer builds a server with explicit capacity knobs so each scenario can
// pick caps that make the invariant under test observable.
func loadServer(cfg config.Config) *Server {
	store := queue.NewStore(queue.StoreConfig{
		MaxMessages:     cfg.MaxMessages,
		MaxAcks:         cfg.MaxAcks,
		MaxPerPair:      cfg.MaxPerPair,
		MaxPayloadBytes: cfg.MaxPayloadBytes,
		MaxTTL:          cfg.MaxTTL,
		DefaultTTL:      cfg.DefaultTTL,
	})
	pool := peer.NewPool(cfg.NodeID, cfg.PublicURL, cfg.MeshPeers)
	return NewServer(cfg, store, pool)
}

func roomyConfig() config.Config {
	return config.Config{
		NodeID:          "load-node",
		PublicURL:       "http://load-node.local",
		MaxMessages:     1_000_000,
		MaxAcks:         1_000_000,
		MaxPerPair:      10,
		MaxPayloadBytes: 8192,
		MaxTTL:          72 * time.Hour,
		DefaultTTL:      24 * time.Hour,
	}
}

type postResult struct {
	Accepted  bool   `json:"accepted"`
	Duplicate bool   `json:"duplicate"`
	Error     string `json:"error"`
}

// call drives one request through the real router exactly as net/http would.
// httptest.NewRecorder is per-call, so this is safe to invoke from many
// goroutines against the same server (the store is mutex-guarded).
func call(server *Server, method, target string, body any) (int, []byte) {
	var req *http.Request
	if body != nil {
		var buf bytes.Buffer
		if err := json.NewEncoder(&buf).Encode(body); err != nil {
			panic(err)
		}
		req = httptest.NewRequest(method, target, &buf)
		req.Header.Set("Content-Type", "application/json")
	} else {
		req = httptest.NewRequest(method, target, nil)
	}
	rec := httptest.NewRecorder()
	server.Handler().ServeHTTP(rec, req)
	return rec.Code, rec.Body.Bytes()
}

func postMessage(server *Server, env model.MessageEnvelope) (int, postResult) {
	code, body := call(server, http.MethodPost, "/messages", env)
	var r postResult
	_ = json.Unmarshal(body, &r)
	return code, r
}

func getMessages(t *testing.T, server *Server, recipient string) []model.MessageEnvelope {
	t.Helper()
	code, body := call(server, http.MethodGet, "/messages?recipient="+recipient+"&limit=500", nil)
	if code != http.StatusOK {
		t.Fatalf("GET /messages(%s) = %d: %s", recipient, code, body)
	}
	var resp struct {
		Messages []model.MessageEnvelope `json:"messages"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatalf("decode messages: %v", err)
	}
	return resp.Messages
}

func getAcks(t *testing.T, server *Server, sender string) []model.AckRecord {
	t.Helper()
	code, body := call(server, http.MethodGet, "/acks?sender="+sender+"&limit=500", nil)
	if code != http.StatusOK {
		t.Fatalf("GET /acks(%s) = %d: %s", sender, code, body)
	}
	var resp struct {
		Acks []model.AckRecord `json:"acks"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatalf("decode acks: %v", err)
	}
	return resp.Acks
}

func storedMessages(t *testing.T, server *Server) int {
	t.Helper()
	code, body := call(server, http.MethodGet, "/health", nil)
	if code != http.StatusOK {
		t.Fatalf("GET /health = %d", code)
	}
	var resp struct {
		Queues queue.Stats `json:"queues"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatalf("decode health: %v", err)
	}
	return resp.Queues.Messages
}

func envelope(id, sender, recipient, payload string) model.MessageEnvelope {
	return model.MessageEnvelope{
		ID:               id,
		Sender:           sender,
		Recipient:        recipient,
		CreatedAt:        time.Now().UTC(),
		ExpiresAt:        time.Now().Add(time.Hour).UTC(),
		EncryptedPayload: payload,
	}
}

// TestLoad100UsersFullLifecycle simulates a 100-user mesh where every user
// concurrently sends a message to several peers, every recipient drains its
// inbox and acks delivery, and every sender collects its acks. It asserts the
// end-to-end "nothing lost, nothing duplicated, queue drains to empty"
// guarantee under concurrent load.
func TestLoad100UsersFullLifecycle(t *testing.T) {
	const users = 100
	const fanout = 3 // each user messages this many distinct peers
	server := loadServer(roomyConfig())

	user := func(i int) string { return fmt.Sprintf("user-%03d", i) }
	// Deterministic, collision-free message id per (sender,recipient) lane.
	msgID := func(s, r int) string { return fmt.Sprintf("m-%03d-%03d", s, r) }

	type sent struct{ sender, recipient int }
	var plan []sent
	for s := 0; s < users; s++ {
		for k := 1; k <= fanout; k++ {
			plan = append(plan, sent{sender: s, recipient: (s + k) % users})
		}
	}
	totalMessages := len(plan) // 300

	// Phase 1 — concurrent sends. Every lane is distinct so all must be accepted.
	var accepted int64
	var wg sync.WaitGroup
	for _, p := range plan {
		wg.Add(1)
		go func(p sent) {
			defer wg.Done()
			env := envelope(msgID(p.sender, p.recipient), user(p.sender), user(p.recipient),
				fmt.Sprintf("ciphertext-%s-%s", user(p.sender), user(p.recipient)))
			code, res := postMessage(server, env)
			if code == http.StatusAccepted && res.Accepted && !res.Duplicate {
				atomic.AddInt64(&accepted, 1)
			} else {
				t.Errorf("send %s->%s = %d (%+v)", user(p.sender), user(p.recipient), code, res)
			}
		}(p)
	}
	wg.Wait()
	if accepted != int64(totalMessages) {
		t.Fatalf("accepted = %d, want %d", accepted, totalMessages)
	}

	// Phase 2 — every recipient drains its inbox; assert exactly-once delivery.
	delivered := make(map[string]int)
	for r := 0; r < users; r++ {
		for _, m := range getMessages(t, server, user(r)) {
			if m.Recipient != user(r) {
				t.Fatalf("message %s routed to wrong recipient %s", m.ID, user(r))
			}
			delivered[m.ID]++
		}
	}
	if len(delivered) != totalMessages {
		t.Fatalf("distinct delivered = %d, want %d", len(delivered), totalMessages)
	}
	for id, n := range delivered {
		if n != 1 {
			t.Fatalf("message %s delivered %d times, want exactly 1", id, n)
		}
	}

	// Phase 3 — concurrent delivered-acks from every recipient.
	for _, p := range plan {
		wg.Add(1)
		go func(p sent) {
			defer wg.Done()
			ack := model.AckRecord{
				ID:        msgID(p.sender, p.recipient) + ":delivered",
				MessageID: msgID(p.sender, p.recipient),
				Sender:    user(p.sender),
				Recipient: user(p.recipient),
				Type:      model.AckRecipientDeviceReceived,
				CreatedAt: time.Now().UTC(),
				ExpiresAt: time.Now().Add(time.Hour).UTC(),
			}
			if code, body := call(server, http.MethodPost, "/acks", ack); code != http.StatusAccepted {
				t.Errorf("ack %s = %d: %s", ack.ID, code, body)
			}
		}(p)
	}
	wg.Wait()

	// Phase 4 — every sender sees a terminal (delivered) ack for each message.
	for s := 0; s < users; s++ {
		seen := make(map[string]bool)
		for _, a := range getAcks(t, server, user(s)) {
			if a.Type == model.AckRecipientDeviceReceived {
				seen[a.MessageID] = true
			}
		}
		for k := 1; k <= fanout; k++ {
			id := msgID(s, (s+k)%users)
			if !seen[id] {
				t.Fatalf("sender %s missing delivered ack for %s", user(s), id)
			}
		}
	}

	// Phase 5 — delivered acks drain the queue back to empty.
	if got := storedMessages(t, server); got != 0 {
		t.Fatalf("stored messages after full delivery = %d, want 0", got)
	}
}

// TestLoadPairQuotaIsolatesFlooder is the core capacity guarantee: one pair
// flooding past the per-pair backlog quota gets 429s for the overflow, while a
// totally separate conversation is unaffected. This is what a global cap alone
// could not promise.
func TestLoadPairQuotaIsolatesFlooder(t *testing.T) {
	cfg := roomyConfig()
	cfg.MaxPerPair = 10
	server := loadServer(cfg)

	const flood = 25
	var ok, quota int64
	var wg sync.WaitGroup
	for i := 0; i < flood; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			env := envelope(fmt.Sprintf("flood-%02d", i), "flooder", "victim", "spam")
			code, res := postMessage(server, env)
			switch code {
			case http.StatusAccepted:
				atomic.AddInt64(&ok, 1)
			case http.StatusTooManyRequests:
				if res.Error != "pair_quota_full" {
					t.Errorf("429 with error=%q, want pair_quota_full", res.Error)
				}
				atomic.AddInt64(&quota, 1)
			default:
				t.Errorf("flood %d unexpected status %d", i, code)
			}
		}(i)
	}
	wg.Wait()

	if ok != int64(cfg.MaxPerPair) {
		t.Fatalf("accepted from flooder = %d, want %d", ok, cfg.MaxPerPair)
	}
	if quota != int64(flood-cfg.MaxPerPair) {
		t.Fatalf("quota-rejected = %d, want %d", quota, flood-cfg.MaxPerPair)
	}

	// A bystander conversation still goes through — the flooder did not starve it.
	if code, res := postMessage(server, envelope("bystander-1", "alice", "bob", "hi")); code != http.StatusAccepted {
		t.Fatalf("bystander send = %d (%+v), want 202 — flooder starved an unrelated pair", code, res)
	}
	if got := storedMessages(t, server); got != cfg.MaxPerPair+1 {
		t.Fatalf("stored = %d, want %d (flooder quota + 1 bystander)", got, cfg.MaxPerPair+1)
	}
}

// TestLoadPayloadCapRejected confirms an oversize ciphertext is refused with a
// structured 413 the app maps to a terminal failure (resending can't help).
func TestLoadPayloadCapRejected(t *testing.T) {
	cfg := roomyConfig()
	cfg.MaxPayloadBytes = 1024
	server := loadServer(cfg)

	under := envelope("ok-size", "alice", "bob", strings.Repeat("x", cfg.MaxPayloadBytes))
	if code, _ := postMessage(server, under); code != http.StatusAccepted {
		t.Fatalf("at-limit payload = %d, want 202", code)
	}
	over := envelope("too-big", "alice", "carol", strings.Repeat("x", cfg.MaxPayloadBytes+1))
	code, res := postMessage(server, over)
	if code != http.StatusRequestEntityTooLarge || res.Error != "payload_too_large" {
		t.Fatalf("oversize payload = %d (%q), want 413 payload_too_large", code, res.Error)
	}
}

// TestLoadTTLClampedToCeiling confirms a sender can't pin node RAM beyond the
// node's ceiling: a far-future client window is clamped to now+MaxTTL.
func TestLoadTTLClampedToCeiling(t *testing.T) {
	cfg := roomyConfig()
	cfg.MaxTTL = 72 * time.Hour
	server := loadServer(cfg)

	env := envelope("greedy-ttl", "alice", "bob", "ciphertext")
	env.ExpiresAt = time.Now().Add(1000 * time.Hour).UTC() // way past the ceiling
	if code, _ := postMessage(server, env); code != http.StatusAccepted {
		t.Fatalf("send = %d, want 202", code)
	}
	msgs := getMessages(t, server, "bob")
	if len(msgs) != 1 {
		t.Fatalf("delivered = %d, want 1", len(msgs))
	}
	ceiling := time.Now().Add(cfg.MaxTTL).Add(time.Minute) // small slack for test runtime
	if msgs[0].ExpiresAt.After(ceiling) {
		t.Fatalf("expiresAt = %s not clamped to ~now+%s", msgs[0].ExpiresAt, cfg.MaxTTL)
	}
	if !msgs[0].ExpiresAt.After(time.Now()) {
		t.Fatalf("expiresAt = %s already in the past", msgs[0].ExpiresAt)
	}
}

// TestLoadResendReusesEnvelopeAndDedupes mirrors the app resend model: a sender
// that hasn't seen a delivered-ack re-posts the SAME envelope id repeatedly.
// The node must accept the first and dedupe the rest (200 duplicate), and the
// recipient must still see exactly one copy.
func TestLoadResendReusesEnvelopeAndDedupes(t *testing.T) {
	server := loadServer(roomyConfig())
	env := envelope("resend-1", "alice", "bob", "ciphertext")

	// First send is the real one; the next four are resends of the same envelope.
	if code, res := postMessage(server, env); code != http.StatusAccepted || res.Duplicate {
		t.Fatalf("first send = %d duplicate=%v, want 202 fresh", code, res.Duplicate)
	}
	var dupes int64
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			code, res := postMessage(server, env)
			if code == http.StatusOK && res.Duplicate {
				atomic.AddInt64(&dupes, 1)
			} else {
				t.Errorf("resend = %d duplicate=%v, want 200 duplicate=true", code, res.Duplicate)
			}
		}()
	}
	wg.Wait()
	if dupes != 4 {
		t.Fatalf("deduped resends = %d, want 4", dupes)
	}
	if msgs := getMessages(t, server, "bob"); len(msgs) != 1 {
		t.Fatalf("recipient sees %d copies of a resent envelope, want 1", len(msgs))
	}
}

// TestLoadConcurrentSamePairCounterConsistency hammers a single (sender→
// recipient) lane from many goroutines while interleaving deliveries, then
// asserts the per-pair counter (the newest, most race-prone code) and the
// global store agree on exactly how many messages remain. Most valuable under
// `go test -race`.
func TestLoadConcurrentSamePairCounterConsistency(t *testing.T) {
	cfg := roomyConfig()
	cfg.MaxPerPair = 1_000_000 // isolate the race, not the quota, in this test
	server := loadServer(cfg)

	const n = 200
	// Concurrently post n distinct messages on one lane and, for the even ids,
	// concurrently post a delivered-ack that removes the message again.
	var posted, removed int64
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			id := fmt.Sprintf("pair-%04d", i)
			if code, _ := postMessage(server, envelope(id, "chatty", "listener", "blob")); code == http.StatusAccepted {
				atomic.AddInt64(&posted, 1)
			}
			if i%2 == 0 {
				ack := model.AckRecord{
					ID:        id + ":delivered",
					MessageID: id,
					Sender:    "chatty",
					Recipient: "listener",
					Type:      model.AckRecipientDeviceReceived,
					CreatedAt: time.Now().UTC(),
					ExpiresAt: time.Now().Add(time.Hour).UTC(),
				}
				if code, _ := call(server, http.MethodPost, "/acks", ack); code == http.StatusAccepted {
					atomic.AddInt64(&removed, 1)
				}
			}
		}(i)
	}
	wg.Wait()

	// Whatever the interleaving, the store must hold exactly posted-removed
	// messages, and the recipient's visible inbox must agree with the counter.
	want := int(posted - removed)
	if got := storedMessages(t, server); got != want {
		t.Fatalf("stored = %d, want posted(%d)-removed(%d)=%d", got, posted, removed, want)
	}
	if got := len(getMessages(t, server, "listener")); got != want {
		t.Fatalf("inbox = %d, want %d — per-pair counter and message map diverged", got, want)
	}
}
