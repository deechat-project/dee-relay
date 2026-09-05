package httpapi

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"deechat/chat-node/internal/config"
	"deechat/chat-node/internal/model"
	"deechat/chat-node/internal/peer"
	"deechat/chat-node/internal/queue"
)

// A full ack map used to fail POST /messages with queue_full, because the
// coupled node_received ack is added before the envelope. Junk acks cost an
// attacker nothing and name any pair they like, so this was a remote way to
// refuse all new mail on the box until a restart that drops every queue.
func TestAFullExternalAckBudgetDoesNotRefusePostMessages(t *testing.T) {
	cfg := config.Config{
		NodeID:      "node-a",
		Addr:        ":0",
		PublicURL:   "http://node-a.local",
		MaxMessages: 4,
		MaxAcks:     10,
		DefaultTTL:  time.Hour,
	}
	store := queue.NewStore(queue.StoreConfig{
		MaxMessages: cfg.MaxMessages,
		MaxAcks:     cfg.MaxAcks,
		DefaultTTL:  cfg.DefaultTTL,
	})
	server := NewServer(cfg, store, peer.NewPool(cfg.NodeID, cfg.PublicURL, cfg.MeshPeers))

	full := false
	for i := 0; i < 20; i++ {
		recorder := httptest.NewRecorder()
		server.Handler().ServeHTTP(recorder, requestJSON(t, http.MethodPost, "/acks", model.AckRecord{
			ID:        fmt.Sprintf("junk-%d", i),
			MessageID: "no-such-message",
			Sender:    "attacker",
			Recipient: "nobody",
			Type:      model.AckRecipientRead,
		}))
		if recorder.Code == http.StatusTooManyRequests {
			full = true
			break
		}
		if recorder.Code != http.StatusAccepted {
			t.Fatalf("junk ack %d status = %d, want 202 or 429", i, recorder.Code)
		}
	}
	if !full {
		t.Fatal("the external ack budget never filled; it is meant to be bounded")
	}

	recorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, requestJSON(t, http.MethodPost, "/messages", model.MessageEnvelope{
		ID:               "msg-1",
		Sender:           "alice",
		Recipient:        "bob",
		EncryptedPayload: "opaque-ciphertext",
	}))
	if recorder.Code != http.StatusAccepted {
		t.Fatalf("POST /messages status = %d, want 202 with the ack budget full", recorder.Code)
	}
	var accepted struct {
		Ack model.AckRecord `json:"ack"`
	}
	decodeResponse(t, recorder, &accepted)
	if accepted.Ack.Type != model.AckNodeReceived {
		t.Fatalf("accepted message got no coupled ack: %#v", accepted.Ack)
	}
}
