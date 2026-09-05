package audit

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// The mesh endpoint serves every identity's queued records to any caller holding
// the shared pool secret. It is the one route in this binary that fetch auth does
// not filter, so where it is mounted is a security property, not a layout detail.
//
// The pool secret fixed the credential (it used to be a self-asserted header).
// A later change fixed the exposure: /mesh/* is no longer on the public listener in any configuration, and
// there is no route that accepts a snapshot. Both are guarded here, next to the
// no-durable-state audit, because both are claims the deploy docs make on the
// code's behalf — and a claim nothing checks is a claim that rots.

// mount matches a route registration: s.mux.HandleFunc("GET /path", …) or
// s.meshMux.HandleFunc(…).
var mount = regexp.MustCompile(`s\.(\w+)\.HandleFunc\("(\w+) ([^"]+)"`)

func readSource(t *testing.T, relative string) string {
	t.Helper()
	body, err := os.ReadFile(filepath.Join(moduleRoot(t), relative))
	if err != nil {
		t.Fatalf("read %s: %v", relative, err)
	}
	return string(body)
}

// TestMeshRoutesAreOnlyOnTheMeshMux is the structural claim. The reverse proxy
// returns 404 for /mesh/* (deploy/Caddyfile.example, deploy/nginx.conf.example),
// and that rule is only worth having if there is nothing behind it: the same
// routes were once mounted on the public port and the proxy was the only thing
// in front of them.
func TestMeshRoutesAreOnlyOnTheMeshMux(t *testing.T) {
	source := readSource(t, filepath.Join("internal", "httpapi", "server.go"))

	found := 0
	for _, match := range mount.FindAllStringSubmatch(source, -1) {
		mux, method, path := match[1], match[2], match[3]
		if !strings.HasPrefix(path, "/mesh") {
			if mux == "meshMux" {
				t.Errorf("%s %s is mounted on the mesh listener; it is a public route", method, path)
			}
			continue
		}
		found++
		if mux != "meshMux" {
			t.Errorf("%s %s is mounted on s.%s: /mesh routes belong on the private mesh listener only", method, path, mux)
		}
	}
	if found == 0 {
		t.Fatal("found no /mesh route registrations at all; this guard is scanning the wrong thing")
	}
}

// TestNoMeshRouteAcceptsABody checks exactly two things, and claims nothing
// beyond them: no /mesh route is mounted with a method other than GET, and
// handleMeshSync — the push-side handler that was removed — has not come back.
//
// In particular it is not a claim that a pulled snapshot is validated. It is not:
// a peer this node pulls from is trusted with these queues. See deploy/README.md,
// "What a pool member is trusted with".
//
// Nor is it the whole of "nothing else imports a snapshot": a route is one way
// into ImportSnapshot and a second caller is another. That half is
// mesh_import_path_test.go.
func TestNoMeshRouteAcceptsABody(t *testing.T) {
	source := readSource(t, filepath.Join("internal", "httpapi", "server.go"))
	for _, match := range mount.FindAllStringSubmatch(source, -1) {
		method, path := match[2], match[3]
		if strings.HasPrefix(path, "/mesh") && method != "GET" {
			t.Errorf("%s %s exists: replication is pull-only, so no mesh route may accept a body", method, path)
		}
	}
	if strings.Contains(source, "handleMeshSync") {
		t.Error("handleMeshSync is back; POST /mesh/sync was removed on purpose")
	}
}

// TestTheProxyExamplesStillBlockMesh keeps the second layer honest. The
// code-level fix makes the proxy rule look unnecessary *today*, which is exactly
// when someone deletes it — and then one future refactor that mounts a mesh route
// on the public mux is enough to publish the replication endpoint to the internet.
func TestTheProxyExamplesStillBlockMesh(t *testing.T) {
	for _, example := range []string{"Caddyfile.example", "nginx.conf.example"} {
		body := readSource(t, filepath.Join("deploy", example))
		if !strings.Contains(body, "/mesh") {
			t.Errorf("%s no longer mentions /mesh; the proxy layer of the mesh exposure fix is gone", example)
		}
		if !strings.Contains(body, "404") {
			t.Errorf("%s no longer returns 404 for anything; check the /mesh rule", example)
		}
	}
}

// TestTheMeshListenerIsRefusedOnAPublicBind ties the deploy docs to the check that
// enforces them: the node validates DEE_NODE_MESH_ADDR at boot, and the env
// example has to describe an address the node will actually accept.
func TestTheMeshListenerIsRefusedOnAPublicBind(t *testing.T) {
	validate := readSource(t, filepath.Join("internal", "config", "validate.go"))
	for _, needed := range []string{"IsUnspecified", "isPrivateIP", "DEE_NODE_MESH_ADDR"} {
		if !strings.Contains(validate, needed) {
			t.Errorf("config validation no longer references %s: a public mesh bind would boot", needed)
		}
	}

	example := readSource(t, filepath.Join("deploy", "node.env.example"))
	if !strings.Contains(example, "DEE_NODE_MESH_ADDR") {
		t.Error("node.env.example does not mention DEE_NODE_MESH_ADDR, which every pool member needs")
	}
	if !strings.Contains(example, "DEE_NODE_MESH_PEERS") {
		t.Error("node.env.example does not mention DEE_NODE_MESH_PEERS")
	}
}
