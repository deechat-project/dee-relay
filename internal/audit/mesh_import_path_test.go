package audit

import (
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"io/fs"
	"path/filepath"
	"strings"
	"testing"
)

// queue.Store.ImportSnapshot is the widest write surface in this binary. It
// injects a peer's envelopes, applies its acks — five of the six ack types delete
// the queued message they name — and runs its purge tombstones, which delete a
// third party's queued mail. None of that is validated, and deliberately so:
// pulling a peer is trusting it with these queues, which is what replication is
// (deploy/README.md, "What a pool member is trusted with").
//
// That statement is only survivable because of who can reach the function. The
// trust is extended by *this* node choosing to pull from a peer it was configured
// with; a snapshot nobody asked for must have nowhere to arrive. The route half of
// that is guarded next door in mesh_exposure_test.go: no /mesh route accepts a
// body. This is the other half, and it is the one that was missing — a route is
// not the only way into a function, and until this file existed nothing stopped a
// second caller from handing ImportSnapshot a payload that came off the wire from
// somewhere else.
//
// The three guards below are one claim in three parts: only SyncPeer calls it,
// SyncPeer's payload is one this node fetched itself, and nothing in the mesh
// package can be mounted as a handler in the first place.

// theOnlyImporter is the one call site the pull path needs. Both halves matter:
// the file, so the call cannot move into a package that serves requests, and the
// function, so it cannot move into an exported entry point that takes a payload.
var theOnlyImporter = struct {
	file     string
	function string
}{
	file:     filepath.Join("internal", "mesh", "syncer.go"),
	function: "SyncPeer",
}

// TestImportSnapshotIsCalledOnlyFromTheMeshPull walks every non-test source the
// relay compiles and asserts the call site is where the docs say it is. A test
// caller is not in scope — internal/queue's own tests import snapshots directly,
// which is how the function is tested at all.
func TestImportSnapshotIsCalledOnlyFromTheMeshPull(t *testing.T) {
	root := moduleRoot(t)
	found := 0

	for _, dir := range []string{"internal", "cmd"} {
		err := filepath.WalkDir(filepath.Join(root, dir), func(path string, entry fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if entry.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			relative, relErr := filepath.Rel(root, path)
			if relErr != nil {
				return relErr
			}

			fileSet := token.NewFileSet()
			file, parseErr := parser.ParseFile(fileSet, path, nil, parser.SkipObjectResolution)
			if parseErr != nil {
				t.Fatalf("parse %s: %v", relative, parseErr)
			}

			for _, declaration := range file.Decls {
				function, ok := declaration.(*ast.FuncDecl)
				if !ok {
					continue
				}
				ast.Inspect(function, func(node ast.Node) bool {
					call, ok := node.(*ast.CallExpr)
					if !ok {
						return true
					}
					if name, ok := methodName(call.Fun); !ok || name != "ImportSnapshot" {
						return true
					}
					found++
					if relative != theOnlyImporter.file || function.Name.Name != theOnlyImporter.function {
						t.Errorf("%s:%d: %s calls ImportSnapshot; replication is pull-only, so the only caller is %s in %s",
							relative, fileSet.Position(call.Pos()).Line, function.Name.Name,
							theOnlyImporter.function, theOnlyImporter.file)
					}
					return true
				})
			}
			return nil
		})
		if err != nil {
			t.Fatalf("walk %s: %v", dir, err)
		}
	}

	if found == 0 {
		t.Fatal("found no ImportSnapshot call at all; this guard is scanning the wrong thing")
	}
}

// TestTheImportedSnapshotIsOneThisNodeFetched closes the gap the call site alone
// leaves open. SyncPeer being the only caller means nothing if SyncPeer can be
// handed a payload: an exported method taking a model.SyncPayload is a push
// endpoint with no route attached, and a route is an ordinary refactor away from
// one. So the payload has to come from this node's own request — the return of
// fetchSnapshot, which builds a GET against a peer the operator configured.
func TestTheImportedSnapshotIsOneThisNodeFetched(t *testing.T) {
	fileSet := token.NewFileSet()
	path := filepath.Join(moduleRoot(t), theOnlyImporter.file)
	file, err := parser.ParseFile(fileSet, path, nil, parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("parse %s: %v", theOnlyImporter.file, err)
	}

	syncPeer := findFunction(file, theOnlyImporter.function)
	if syncPeer == nil {
		t.Fatalf("%s no longer declares %s; this guard is scanning the wrong thing", theOnlyImporter.file, theOnlyImporter.function)
	}

	for _, parameter := range syncPeer.Type.Params.List {
		if rendered := renderExpr(t, fileSet, parameter.Type); strings.Contains(rendered, "SyncPayload") {
			t.Errorf("%s takes a %s: a caller that can supply a snapshot is a push path, whatever it is named",
				theOnlyImporter.function, rendered)
		}
	}

	imported := ""
	ast.Inspect(syncPeer, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		if name, ok := methodName(call.Fun); !ok || name != "ImportSnapshot" {
			return true
		}
		if len(call.Args) != 1 {
			t.Fatalf("ImportSnapshot is called with %d arguments; this guard expects one payload", len(call.Args))
		}
		argument, ok := call.Args[0].(*ast.Ident)
		if !ok {
			t.Fatalf("ImportSnapshot's argument is %s, not a local variable; trace it by hand and re-teach this guard",
				renderExpr(t, fileSet, call.Args[0]))
		}
		imported = argument.Name
		return true
	})
	if imported == "" {
		t.Fatalf("%s no longer calls ImportSnapshot; this guard is scanning the wrong thing", theOnlyImporter.function)
	}

	if !assignedFrom(syncPeer, imported, "fetchSnapshot") {
		t.Errorf("%s is passed to ImportSnapshot but is not the result of fetchSnapshot: a snapshot this node did not "+
			"request itself has no business being imported", imported)
	}
}

// TestTheMeshPullerServesNothing keeps the pull path unmountable. A handler in
// this package would put ImportSnapshot one HandleFunc away from the listener,
// and the route guard next door only scans internal/httpapi/server.go — it would
// see the registration, but not until someone wrote it.
func TestTheMeshPullerServesNothing(t *testing.T) {
	fileSet := token.NewFileSet()
	for _, path := range nonTestSources(t, filepath.Join("internal", "mesh")) {
		file, err := parser.ParseFile(fileSet, path, nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		name := filepath.Base(path)
		for _, declaration := range file.Decls {
			function, ok := declaration.(*ast.FuncDecl)
			if !ok {
				continue
			}
			for _, parameter := range function.Type.Params.List {
				rendered := renderExpr(t, fileSet, parameter.Type)
				if strings.Contains(rendered, "http.ResponseWriter") {
					t.Errorf("%s: %s takes an %s; the package that imports peer snapshots must not also serve them",
						name, function.Name.Name, rendered)
				}
				if function.Name.IsExported() && strings.Contains(rendered, "SyncPayload") {
					t.Errorf("%s: exported %s takes a %s; that is a push entry point without a route",
						name, function.Name.Name, rendered)
				}
			}
		}
	}
}

func findFunction(file *ast.File, name string) *ast.FuncDecl {
	for _, declaration := range file.Decls {
		if function, ok := declaration.(*ast.FuncDecl); ok && function.Name.Name == name {
			return function
		}
	}
	return nil
}

// assignedFrom reports whether name is assigned the result of a call to method
// anywhere in the function — `payload, err := s.fetchSnapshot(...)`.
func assignedFrom(function *ast.FuncDecl, name, method string) bool {
	matched := false
	ast.Inspect(function, func(node ast.Node) bool {
		assignment, ok := node.(*ast.AssignStmt)
		if !ok || len(assignment.Rhs) != 1 {
			return true
		}
		call, ok := assignment.Rhs[0].(*ast.CallExpr)
		if !ok {
			return true
		}
		if called, ok := methodName(call.Fun); !ok || called != method {
			return true
		}
		for _, target := range assignment.Lhs {
			if identifier, ok := target.(*ast.Ident); ok && identifier.Name == name {
				matched = true
			}
		}
		return true
	})
	return matched
}

func renderExpr(t *testing.T, fileSet *token.FileSet, expr ast.Expr) string {
	t.Helper()
	var rendered strings.Builder
	if err := printer.Fprint(&rendered, fileSet, expr); err != nil {
		t.Fatalf("render expression: %v", err)
	}
	return rendered.String()
}
