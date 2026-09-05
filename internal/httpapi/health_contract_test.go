package httpapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// /health is the one surface outside this repo's control that other things are
// written against by field name: README documents five of these keys, and the
// deploy scripts branch on them — acceptance.sh and setup-verify.sh read
// requireFetchAuth and meshEnabled, monitor.sh reads those plus requireAdmission
// and the mesh block, and setup-verify.sh sizes its canary from
// maxAttachmentBytes.
//
// A rename here is silent in every one of those places. A shell script that
// greps for a key that no longer exists does not fail — it reads empty, and a
// monitor that asserts "requireAdmission is true" against an absent field
// reports a gated box as open, or an open one as gated. That is the same failure
// as a documented cap the binary does not carry, one layer further out, so the
// names are pinned here rather than left to the documents that cite them.
func TestHealthPublishesEveryFieldTheDocsAndScriptsRead(t *testing.T) {
	server := newTestServer()

	recorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/health", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("GET /health status = %d", recorder.Code)
	}

	var health map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &health); err != nil {
		t.Fatalf("decode health: %v", err)
	}

	// Every key, with what reads it. A field removed on purpose has to be
	// removed from its reader in the same change, which is the point.
	required := []struct {
		key    string
		reader string
	}{
		{"status", "acceptance.sh, probe-public.sh"},
		{"nodeId", "pool-verify.sh"},
		{"requireFetchAuth", "README, monitor.sh, acceptance.sh, setup-verify.sh"},
		{"requireAdmission", "README, monitor.sh, setup-verify.sh"},
		{"meshEnabled", "README, monitor.sh, acceptance.sh, pool-verify.sh, setup-verify.sh"},
		{"maxAttachmentBytes", "README, setup-verify.sh, and the client's send guard"},
		{"prekeyBuckets", "README — a box refusing new prekey pools is otherwise invisible"},
		{"mesh", "monitor.sh: peers, reachable, oldestSyncAgeSec"},
		{"queues", "monitor.sh: queue saturation against the configured caps"},
		{"attachments", "monitor.sh: live transfers and bytes in flight"},
	}
	for _, want := range required {
		if _, ok := health[want.key]; !ok {
			t.Errorf("/health does not publish %q, which is read by %s", want.key, want.reader)
		}
	}

	// The mesh block is read a level down, and monitor.sh distinguishes "never
	// synced" (-1) from "stale", so the three names have to survive too.
	mesh, ok := health["mesh"].(map[string]any)
	if !ok {
		t.Fatalf("/health mesh = %#v, want an object", health["mesh"])
	}
	for _, key := range []string{"peers", "reachable", "oldestSyncAgeSec"} {
		if _, ok := mesh[key]; !ok {
			t.Errorf("/health mesh does not publish %q, which monitor.sh asserts on", key)
		}
	}

	// maxAttachmentBytes is the only cap published as a number, because the app
	// sizes its own send guard from it. A boolean or a string here would parse
	// and then silently refuse every file the operator raised the cap for.
	if _, ok := health["maxAttachmentBytes"].(float64); !ok {
		t.Errorf("/health maxAttachmentBytes = %#v, want a number the client can size a guard from", health["maxAttachmentBytes"])
	}

	// And the secret has never been publishable here. This is the endpoint that
	// leaked it once.
	if strings.Contains(recorder.Body.String(), testMeshSecret) {
		t.Error("/health response contains the mesh secret")
	}
}
