package audit

import (
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// A relay logs a handful of lines per boot and nothing per request: no access
// log, no middleware, no handler that names a sender, a recipient, or a caller.
// net/http is the exception that does not go through any of that — an unset
// Server.ErrorLog falls back to log.Default() on stderr, and its lines carry the
// client's address (`http: panic serving 203.0.113.4:53422`). It fails open and
// silently: the gap is invisible until the first panic, by which time the address
// is already in the journal. So every server this binary builds is required to
// set it, here, rather than in a review someone has to remember to do.

var serverLiteral = regexp.MustCompile(`&http\.Server\{`)

func TestEveryHTTPServerSetsAnErrorLog(t *testing.T) {
	source := readSource(t, filepath.Join("cmd", "dee-relay", "main.go"))

	literals := serverLiteral.FindAllStringIndex(source, -1)
	if len(literals) == 0 {
		t.Fatal("found no &http.Server{ literals at all; this guard is scanning the wrong file")
	}
	for _, literal := range literals {
		body := composite(t, source[literal[1]:])
		if !strings.Contains(body, "ErrorLog:") {
			t.Errorf("an &http.Server{…} literal sets no ErrorLog, so net/http logs "+
				"client addresses to stderr:\n%s", body)
			continue
		}
		if !strings.Contains(body, "ErrorLog:          serverErrorLog(") &&
			!strings.Contains(body, "ErrorLog: serverErrorLog(") {
			t.Errorf("an &http.Server{…} literal sets ErrorLog to something other than "+
				"serverErrorLog, which is the only writer that strips the address:\n%s", body)
		}
	}
}

// The redacting writer must stay wired to a regexp that actually matches an
// address. A guard on the field alone would pass against an empty pattern.
func TestTheRedactionPatternIsNotEmpty(t *testing.T) {
	source := readSource(t, filepath.Join("cmd", "dee-relay", "errorlog.go"))
	if !strings.Contains(source, "regexp.MustCompile") {
		t.Error("errorlog.go compiles no pattern; the writer would pass addresses through")
	}
	if !strings.Contains(source, "ReplaceAllString") {
		t.Error("errorlog.go never substitutes; the pattern is compiled and unused")
	}
}

// composite returns the text of the brace-balanced literal beginning at the
// start of source (the opening brace is already consumed).
func composite(t *testing.T, source string) string {
	t.Helper()
	depth := 1
	for index, char := range source {
		switch char {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return source[:index]
			}
		}
	}
	t.Fatal("unbalanced &http.Server{ literal")
	return ""
}
