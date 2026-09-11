package main

import (
	"log"
	"log/slog"
	"regexp"
	"strings"
)

// net/http writes the server's own failures — a panic while serving a request, a
// TLS handshake that fell over, an accept error — through Server.ErrorLog, and
// those lines name the client: `http: panic serving 203.0.113.4:53422: …`. Left
// unset, ErrorLog is log.Default() on stderr, which would make it the one path by
// which a caller's address reaches the log of a relay that otherwise records
// nothing per request. Dropping the lines is the wrong fix — a panic nobody can
// see is worse than a logged address — so they are kept and the address is not.
var remoteAddress = regexp.MustCompile(
	`\[[0-9a-fA-F:.]+(?:%[0-9a-zA-Z._-]+)?\]:\d{1,5}|\b(?:\d{1,3}\.){3}\d{1,3}(?::\d{1,5})?\b`)

// redactingWriter is the io.Writer side of that: one stdlib log line in, one
// slog record out. A panic arrives here as a single multi-line Write carrying its
// stack trace, which is the part worth having.
type redactingWriter struct{ logger *slog.Logger }

func (w redactingWriter) Write(line []byte) (int, error) {
	message := strings.TrimRight(string(line), "\n")
	w.logger.Warn("http server error", "detail", remoteAddress.ReplaceAllString(message, "redacted"))
	return len(line), nil
}

// serverErrorLog is what every http.Server in this binary must be given.
// internal/audit enforces that, because an unset ErrorLog fails open and looks
// like nothing at all until the day something panics.
func serverErrorLog(logger *slog.Logger) *log.Logger {
	return log.New(redactingWriter{logger: logger}, "", 0)
}
