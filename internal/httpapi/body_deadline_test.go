package httpapi

import (
	"bufio"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"deechat/chat-node/internal/config"
	"deechat/chat-node/internal/peer"
	"deechat/chat-node/internal/queue"
)

// A relay wedged in production: every app->relay POST stopped completing,
// permanently,
// while GETs on fresh connections kept answering 200. A SIGQUIT dump of the live
// process had three goroutines parked in handlePostAck -> decodeJSON ->
// chunkedReader.beginChunk, in IO wait, waiting for a body that never came.
//
// The client's own timeout had fired minutes earlier; it had simply abandoned
// the request without closing the socket. dart:io flushes the request header
// block on its own as soon as anything is written and holds the body in an
// outgoing buffer until close() drains, so an abandoned request reaches the node
// as a complete, well-formed request whose body is still on the other machine.
//
// ReadHeaderTimeout bounded the headers. Nothing bounded the body, so the
// goroutine and its connection were held for the life of the process. These
// tests send exactly that — headers, then silence — over a real socket.
func TestABodyThatNeverArrivesIsGivenUpOn(t *testing.T) {
	server, addr := newDeadlineServer(t, 300*time.Millisecond)
	defer server.Close()

	conn := dial(t, addr)
	defer conn.Close()

	// A chunked body whose terminating chunk never comes: the shape the wedged
	// relay was actually holding.
	fmt.Fprint(conn, "POST /acks HTTP/1.1\r\nHost: relay\r\n"+
		"Content-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n")

	response := readResponse(t, conn, 5*time.Second)
	if !strings.HasPrefix(response, "HTTP/1.1 408") {
		t.Fatalf("status line = %q, want 408 — the reader is still parked on the body", response)
	}
	if !strings.Contains(response, "body_incomplete") {
		t.Fatalf("body = %q, want body_incomplete: a body that stopped arriving is not malformed input", response)
	}
}

// The same for a body that declares its length and then stops short, which is
// what the same abandonment looks like once the client sets Content-Length.
// Framing the body differently moves where the reader parks; it does not stop it
// parking, which is why the deadline is the fix and Content-Length is not.
func TestATruncatedContentLengthBodyIsGivenUpOn(t *testing.T) {
	server, addr := newDeadlineServer(t, 300*time.Millisecond)
	defer server.Close()

	conn := dial(t, addr)
	defer conn.Close()

	fmt.Fprint(conn, "POST /acks HTTP/1.1\r\nHost: relay\r\n"+
		"Content-Type: application/json\r\nContent-Length: 120\r\n\r\n{\"messageId\":")

	response := readResponse(t, conn, 5*time.Second)
	if !strings.HasPrefix(response, "HTTP/1.1 408") {
		t.Fatalf("status line = %q, want 408", response)
	}
}

// The deadline is on bodies, not on connections. A long-poll fetch is a GET with
// no body and is meant to park for RelayPollTimeout, so it must not be cut by a
// deadline shorter than that.
func TestABodylessRequestIsNotDeadlined(t *testing.T) {
	server, addr := newDeadlineServer(t, 100*time.Millisecond)
	defer server.Close()

	conn := dial(t, addr)
	defer conn.Close()

	// wait=1 parks the handler for a second, ten times the body deadline.
	fmt.Fprint(conn, "GET /attachments/chunks?recipient=bob&capability=cap&wait=1 HTTP/1.1\r\n"+
		"Host: relay\r\n\r\n")

	started := time.Now()
	response := readResponse(t, conn, 10*time.Second)
	if strings.HasPrefix(response, "HTTP/1.1 408") {
		t.Fatalf("the long poll was cut by the body deadline: %q", response)
	}
	if elapsed := time.Since(started); elapsed < 900*time.Millisecond {
		t.Fatalf("the poll returned after %v, want it to have parked for its full budget", elapsed)
	}
}

// A body that does arrive is still read to the end and acted on, deadline or
// not. Guards the obvious way to "fix" a parked reader: a deadline short or
// blunt enough to cut real traffic with it.
func TestACompleteBodyIsAcceptedWithinTheDeadline(t *testing.T) {
	server, addr := newDeadlineServer(t, 2*time.Second)
	defer server.Close()

	conn := dial(t, addr)
	defer conn.Close()

	body := `{"id":"ack-1","messageId":"m1","sender":"alice","recipient":"bob","type":"node_received_ack"}`
	fmt.Fprintf(conn, "POST /acks HTTP/1.1\r\nHost: relay\r\n"+
		"Content-Type: application/json\r\nContent-Length: %d\r\n\r\n%s", len(body), body)

	response := readResponse(t, conn, 5*time.Second)
	if strings.HasPrefix(response, "HTTP/1.1 408") {
		t.Fatalf("a body that did arrive was given up on: %q", response)
	}
	if !strings.Contains(response, `"accepted":true`) {
		t.Fatalf("a complete ack was not accepted: %q", response)
	}
}

func newDeadlineServer(t *testing.T, deadline time.Duration) (*httptest.Server, string) {
	t.Helper()
	cfg := config.Config{
		NodeID:           "node-a",
		PublicURL:        "http://node-a.local",
		MaxMessages:      10,
		MaxAcks:          10,
		DefaultTTL:       time.Hour,
		CleanupInterval:  time.Minute,
		RelayPollTimeout: 25 * time.Second,
		BodyReadTimeout:  deadline,
	}
	store := queue.NewStore(queue.StoreConfig{
		MaxMessages: cfg.MaxMessages,
		MaxAcks:     cfg.MaxAcks,
		DefaultTTL:  cfg.DefaultTTL,
	})
	api := NewServer(cfg, store, peer.NewPool(cfg.NodeID, cfg.PublicURL, nil))
	server := httptest.NewServer(api.Handler())
	return server, strings.TrimPrefix(server.URL, "http://")
}

func dial(t *testing.T, addr string) net.Conn {
	t.Helper()
	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial %s: %v", addr, err)
	}
	return conn
}

// readResponse returns the status line and headers, or fails if the peer says
// nothing at all before within — which is the wedge this file is about.
func readResponse(t *testing.T, conn net.Conn, within time.Duration) string {
	t.Helper()
	if err := conn.SetReadDeadline(time.Now().Add(within)); err != nil {
		t.Fatalf("set read deadline: %v", err)
	}
	reader := bufio.NewReader(conn)
	var out strings.Builder
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			if out.Len() == 0 {
				t.Fatalf("no response within %v: the handler is still parked on the request", within)
			}
			return out.String()
		}
		out.WriteString(line)
		if line == "\r\n" {
			// Headers done; take whatever body is already buffered.
			if n := reader.Buffered(); n > 0 {
				buf := make([]byte, n)
				_, _ = reader.Read(buf)
				out.Write(buf)
			}
			return out.String()
		}
	}
}

var _ = http.StatusRequestTimeout
