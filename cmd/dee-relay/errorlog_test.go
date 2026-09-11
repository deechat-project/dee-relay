package main

import (
	"bytes"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func redactedLine(t *testing.T, line string) string {
	t.Helper()
	var sink bytes.Buffer
	serverErrorLog(slog.New(slog.NewTextHandler(&sink, nil))).Print(line)
	return sink.String()
}

func TestServerErrorLogDropsTheClientAddress(t *testing.T) {
	for _, testCase := range []struct {
		name string
		line string
		gone string
	}{
		{"panic", "http: panic serving 203.0.113.4:53422: boom", "203.0.113.4"},
		{"tls handshake", "http: TLS handshake error from 198.51.100.7:1025: EOF", "198.51.100.7"},
		{"ipv6", "http: panic serving [2001:db8::1]:44311: boom", "2001:db8::1"},
		{"ipv6 zone", "http: panic serving [fe80::1%eth0]:44311: boom", "fe80::1"},
		{"bare address", "http: Accept error from 203.0.113.9; retrying", "203.0.113.9"},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			logged := redactedLine(t, testCase.line)
			if strings.Contains(logged, testCase.gone) {
				t.Errorf("client address survived redaction: %s", logged)
			}
			if !strings.Contains(logged, "redacted") {
				t.Errorf("nothing was redacted, so the pattern missed the address: %s", logged)
			}
		})
	}
}

// The line itself has to survive. Redaction that swallowed the reason would make
// a panic invisible, which is the failure this logger exists to keep visible.
func TestServerErrorLogKeepsTheReasonAndTheStack(t *testing.T) {
	logged := redactedLine(t,
		"http: panic serving 203.0.113.4:53422: runtime error: index out of range\n"+
			"goroutine 42 [running]:\nmain.handler(...)")
	for _, want := range []string{"panic serving", "index out of range", "goroutine 42", "main.handler"} {
		if !strings.Contains(logged, want) {
			t.Errorf("redaction lost %q from the line: %s", want, logged)
		}
	}
}

// End to end against a real http.Server: a handler that panics is the exact
// event that used to print the caller's address to stderr.
func TestPanicReachesTheLoggerWithoutTheAddress(t *testing.T) {
	var sink bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&sink, nil))

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		panic("boom")
	}))
	server.Listener.Close()
	server.Listener = listener
	server.Config.ErrorLog = serverErrorLog(logger)
	server.Start()
	defer server.Close()

	response, err := http.Get(server.URL) //nolint:bodyclose // the panic closes it
	if err == nil {
		response.Body.Close()
	}
	server.Close()

	logged := sink.String()
	if !strings.Contains(logged, "boom") {
		t.Fatalf("the panic never reached the logger: %q", logged)
	}
	host, _, _ := net.SplitHostPort(listener.Addr().String())
	if strings.Contains(logged, host+":") {
		t.Errorf("the client address reached the log: %s", logged)
	}
}
