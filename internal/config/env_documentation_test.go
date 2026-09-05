package config

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// A deployment is configured entirely through DEE_NODE_* variables, read once
// at boot, with no validation pass and no error on an unknown name — envInt
// and envBool fall back silently by design. That makes a documented variable
// the node does not read indistinguishable, from the operator's side, from one
// it does: the value is set, the boot is clean, and nothing happens.
//
// This test found exactly that. README documented DEE_NODE_MAX_ATTACHMENT_BYTES
// (default 512 MB) and DEE_NODE_ATTACHMENT_TTL, neither of which has existed
// since the attachment store became a live relay bounded by
// RELAY_MAX_SESSIONS x RELAY_MAX_WINDOW x MAX_CHUNK_BYTES. The production-pool
// design derived its MemoryMax from the phantom 512 MB figure; the real ceiling
// at the defaults is 2 GiB.
//
// So: every DEE_NODE_* name in the docs must be read by this file, and every
// name this file reads must be documented.

var envKeyPattern = regexp.MustCompile(`DEE_NODE_[A-Z0-9_]+`)

// docsDescribingEnv are the files an operator configures a host from — and, past
// the first two, the files that *consume* the same names. monitor.sh reads caps
// out of the env file to decide when a queue is saturated, and the proxy configs
// are sized against the payload and chunk caps. A stale name in any of them
// repeats the original failure one layer up: monitoring that watches a variable
// the node does not have is monitoring that never fires.
var docsDescribingEnv = []string{
	"README.md",
	filepath.Join("deploy", "node.env.example"),
	filepath.Join("deploy", "monitor.sh"),
	filepath.Join("deploy", "memory-ceiling.sh"),
	filepath.Join("deploy", "Caddyfile.example"),
	filepath.Join("deploy", "nginx.conf.example"),
}

func TestEveryDocumentedEnvVarIsRead(t *testing.T) {
	read := envKeysReadByConfig(t)

	for _, doc := range docsDescribingEnv {
		body := readRepoFile(t, doc)
		var phantom []string
		for _, key := range envKeyPattern.FindAllString(body, -1) {
			if !read[key] {
				phantom = append(phantom, key)
			}
		}
		if len(phantom) > 0 {
			t.Errorf("%s documents %s, which config.go never reads: setting it does nothing and the boot is clean",
				doc, strings.Join(unique(phantom), ", "))
		}
	}
}

func TestEveryEnvVarIsDocumented(t *testing.T) {
	documented := map[string]bool{}
	for _, doc := range docsDescribingEnv {
		for _, key := range envKeyPattern.FindAllString(readRepoFile(t, doc), -1) {
			documented[key] = true
		}
	}

	var undocumented []string
	for key := range envKeysReadByConfig(t) {
		if !documented[key] {
			undocumented = append(undocumented, key)
		}
	}
	if len(undocumented) > 0 {
		sort.Strings(undocumented)
		t.Errorf("config.go reads %s, which no deployment doc mentions: a cap nobody knows about is a cap nobody sizes for",
			strings.Join(undocumented, ", "))
	}
}

// envKeysReadByConfig scans this package's own source for the literal keys
// passed to the env* helpers. Source text rather than reflection, because the
// keys are string literals and there is no registry to enumerate.
//
// Every non-test file in the package, not just config.go: validate.go reads
// DEE_NODE_TRUSTED_NODES in order to *refuse* it, and a rename an operator can
// still set has to stay documented until the refusal goes away.
func envKeysReadByConfig(t *testing.T) map[string]bool {
	t.Helper()
	keys := map[string]bool{}
	sources, err := filepath.Glob(filepath.Join(repoRoot(t), "internal", "config", "*.go"))
	if err != nil {
		t.Fatalf("glob config sources: %v", err)
	}
	for _, source := range sources {
		if strings.HasSuffix(source, "_test.go") {
			continue
		}
		body, err := os.ReadFile(source)
		if err != nil {
			t.Fatalf("read %s: %v", source, err)
		}
		for _, key := range envKeyPattern.FindAllString(string(body), -1) {
			keys[key] = true
		}
	}
	if len(keys) == 0 {
		t.Fatal("found no DEE_NODE_* keys in the config package; the scan is broken, not the config")
	}
	return keys
}

func readRepoFile(t *testing.T, relative string) string {
	t.Helper()
	body, err := os.ReadFile(filepath.Join(repoRoot(t), relative))
	if err != nil {
		t.Fatalf("read %s: %v", relative, err)
	}
	return string(body)
}

func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("go.mod not found above the test working directory")
		}
		dir = parent
	}
}

func unique(values []string) []string {
	seen := map[string]bool{}
	var result []string
	for _, value := range values {
		if !seen[value] {
			seen[value] = true
			result = append(result, value)
		}
	}
	sort.Strings(result)
	return result
}
