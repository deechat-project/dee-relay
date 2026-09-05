package httpapi

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"deechat/chat-node/internal/admission"
	"deechat/chat-node/internal/config"
	"deechat/chat-node/internal/peer"
	"deechat/chat-node/internal/presence"
	"deechat/chat-node/internal/queue"
)

// A presence heartbeat is not a write into anybody's queue, so the capability is
// optional here — but it is what buys the caller a share of the table nobody
// else can spend. This file pins the wiring: that the header actually reaches
// presence.Store as a caller key, and that a credential is the fallback when
// there is no header. The store's own tests own the policy.

func TestACapableHeartbeatIsNotLockedOutByAFloodOfAnonymousOnes(t *testing.T) {
	store := presence.NewStore(34, 24*time.Hour, time.Now)
	server := newPresenceServer(store)
	expires := time.Now().UTC().Add(4 * time.Minute)

	for index := 0; index < 34; index++ {
		if code := heartbeat(t, server, "flood-owner-"+strconv.Itoa(index), "flood-grant-"+strconv.Itoa(index), expires, ""); code != http.StatusAccepted {
			t.Fatalf("anonymous heartbeat %d refused below capacity: %d", index, code)
		}
	}
	if code := heartbeat(t, server, "another-owner", "another-grant", expires, ""); code == http.StatusAccepted {
		t.Fatal("the anonymous bucket took a slot from a live lease")
	}
	if code := heartbeat(t, server, "alice", "alice-grant", expires, "alice-queue-secret"); code != http.StatusAccepted {
		t.Fatalf("a caller with a capability was locked out by unattributed leases: %d", code)
	}
}

func TestPresenceAttributionPrefersTheTagAndFallsBackToTheCredential(t *testing.T) {
	tagged := httptest.NewRequest(http.MethodPost, "/presence/heartbeat", nil)
	tagged.Header.Set(queueCapabilityHeader, "alice-queue-secret")
	subject := queue.TagForSecret("alice-queue-secret")

	if got := presenceGrant(admission.Grant{Index: 7}, tagged); got.Caller != "tag:"+subject {
		t.Fatalf("a presented capability did not name the caller: %q", got.Caller)
	}
	bare := httptest.NewRequest(http.MethodPost, "/presence/heartbeat", nil)
	if got := presenceGrant(admission.Grant{Index: 7}, bare); got.Caller != "credential:7" {
		t.Fatalf("an admitted caller with no capability was not charged to its credential: %q", got.Caller)
	}
	if got := presenceGrant(admission.Grant{}, bare); got.Caller != "" {
		t.Fatalf("a caller that proved nothing got a key of its own: %q", got.Caller)
	}
}

func newPresenceServer(store *presence.Store) *Server {
	cfg := config.Config{NodeID: "node-a", PublicURL: "http://node-a.local", MaxMessages: 10, MaxAcks: 20, DefaultTTL: time.Hour}
	queues := queue.NewStore(queue.StoreConfig{MaxMessages: cfg.MaxMessages, MaxAcks: cfg.MaxAcks, DefaultTTL: cfg.DefaultTTL})
	return NewServer(cfg, queues, peer.NewPool(cfg.NodeID, cfg.PublicURL, nil), store)
}

func heartbeat(t *testing.T, server *Server, owner, grant string, expires time.Time, secret string) int {
	t.Helper()
	body, err := json.Marshal(map[string]any{"ownerHash": owner, "grantHash": grant, "expiresAt": expires})
	if err != nil {
		t.Fatalf("encode heartbeat: %v", err)
	}
	request := httptest.NewRequest(http.MethodPost, "/presence/heartbeat", bytes.NewReader(body))
	if secret != "" {
		request.Header.Set(queueCapabilityHeader, secret)
	}
	recorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, request)
	return recorder.Code
}
