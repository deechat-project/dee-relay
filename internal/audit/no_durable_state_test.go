// Package audit holds the executable guards for the relay's defining invariant:
// it is a dumb relay that retains nothing across a restart. SECURITY.md points
// reporters at these tests by name, so what they do and do not enforce is
// written out here rather than summarised — a guard that is cited as evidence
// has to describe its own reach.
//
// What the tests in this file enforce:
//
//   - The binary depends only on the Go standard library
//     (TestNodeDependsOnlyOnStdlib). A third-party module is the usual way a DB
//     driver, a cache client or an object-store SDK arrives.
//   - No non-test source the relay can reach imports a durable-storage package
//     or calls a filesystem write, mutate or delete function in os/io/ioutil
//     (TestNodeWritesNoDurableState), under whatever local name the file
//     imports those packages by.
//   - The one exemption — the issuance CLI, which writes the operator's own
//     credential file — stays a separate binary the relay cannot link
//     (TestNothingTheRelayImportsIsExemptFromTheWriteBan).
//
// What they do not enforce, stated because the claim they used to carry was
// wider than the code:
//
//   - That every store is an in-RAM map. That is true, and it is visible in the
//     store constructors, but nothing here asserts it: a durable store reached
//     over the network would need no filesystem call at all. The stdlib-only
//     ban above is what makes that hard rather than what makes it impossible.
//   - A write through syscall directly, or through an *os.File a package
//     received rather than opened. syscall is imported for signal handling in
//     cmd/dee-relay, so it cannot be banned outright. This is a tripwire
//     against durable state being reintroduced by ordinary means, not a sandbox
//     against someone determined to smuggle it in.
package audit

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// forbiddenImports name standard-library packages that exist to persist or
// query durable on-disk/remote state. None belong in a RAM-only relay.
var forbiddenImports = map[string]string{
	"database/sql": "SQL database access implies a durable store",
	"encoding/gob": "gob is used to serialize state to disk",
	"plugin":       "loading plugins implies on-disk artifacts",
	// A subprocess writes what this process is banned from writing, and the ban
	// below would not see it. The relay has never needed to shell out.
	"os/exec": "a subprocess can write to disk on the relay's behalf",
}

// forbiddenCalls name the functions that create, write to, mutate or remove
// something on disk. Reading is allowed (config files, /proc, etc. — none of
// which retain user state); the node must never *write* state to disk.
//
// Delete and rename are here as well as create, because the claim is that the
// relay does not touch the filesystem's contents, and because a guard that
// banned only creation would pass a change that wrote through a handle and
// tidied up after itself. The keys are package-relative: the walk resolves each
// file's own local name for os and io/ioutil before matching, so an aliased
// import does not step around this list.
var forbiddenCalls = map[string]string{
	"os.Create":        "creates a file on disk",
	"os.CreateTemp":    "creates a file on disk",
	"os.OpenFile":      "opens a file for writing on disk",
	"os.WriteFile":     "writes a file to disk",
	"os.Mkdir":         "creates a directory on disk",
	"os.MkdirAll":      "creates directories on disk",
	"os.MkdirTemp":     "creates a directory on disk",
	"os.NewFile":       "wraps a file descriptor for disk I/O",
	"os.Symlink":       "creates an on-disk symlink",
	"os.Link":          "creates an on-disk hard link",
	"os.Rename":        "moves something on disk",
	"os.Remove":        "deletes something on disk",
	"os.RemoveAll":     "deletes something on disk",
	"os.Truncate":      "rewrites a file on disk",
	"os.Chmod":         "mutates a file on disk",
	"os.Chown":         "mutates a file on disk",
	"os.Chtimes":       "mutates a file on disk",
	"ioutil.WriteFile": "writes a file to disk",
	"ioutil.TempFile":  "creates a file on disk",
	"ioutil.TempDir":   "creates a directory on disk",
}

// writePackages maps an import path to the key prefix forbiddenCalls uses for
// it. A file may import either under any local name, so the walk reads each
// file's own import block rather than assuming the conventional one.
var writePackages = map[string]string{
	"os":        "os",
	"io/ioutil": "ioutil",
}

// localWriteNames returns the identifiers this file refers to the banned
// packages by, keyed by local name. A dot-import of either is refused outright:
// it would put Create and WriteFile in the file's own scope, where a selector
// match cannot see them.
func localWriteNames(t *testing.T, rel string, file *ast.File) map[string]string {
	t.Helper()
	names := map[string]string{}
	for _, imp := range file.Imports {
		prefix, banned := writePackages[strings.Trim(imp.Path.Value, `"`)]
		if !banned {
			continue
		}
		local := prefix
		if imp.Name != nil {
			local = imp.Name.Name
		}
		if local == "." {
			t.Errorf("%s dot-imports %s, which puts its write calls in file scope where this guard cannot see them",
				rel, imp.Path.Value)
			continue
		}
		if local == "_" {
			continue
		}
		names[local] = prefix
	}
	return names
}

// notTheRelay names the packages this ban does not cover, and the exemption is
// as narrow as it looks. The claim being guarded is that *the relay* retains
// nothing — every store an in-RAM map, a restart clearing all of it. Issuance is
// not the relay: it is a separate binary an operator runs by hand on the box, it
// writes the operator's own credential file rather than any user state, and the
// relay only ever reads that file.
//
// The exemption holds exactly as long as the relay cannot reach these packages,
// which is what TestNothingTheRelayImportsIsExemptFromTheWriteBan asserts. Adding
// an entry here without that test passing would silently move a file write into
// the published relay binary.
var notTheRelay = map[string]string{
	filepath.Join("cmd", "dee-admit"):  "the issuance CLI writes the credential file the relay reads",
	filepath.Join("internal", "issue"): "the issuance library behind it",
}

func moduleRoot(t *testing.T) string {
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

// TestNodeDependsOnlyOnStdlib asserts the node carries no third-party module
// dependencies. A new dependency is the most common way durable state (a DB
// driver, a cache client, an object-store SDK) sneaks in, so the zero-dep design
// is itself a load-bearing part of the no-server guarantee.
func TestNodeDependsOnlyOnStdlib(t *testing.T) {
	root := moduleRoot(t)
	data, err := os.ReadFile(filepath.Join(root, "go.mod"))
	if err != nil {
		t.Fatalf("read go.mod: %v", err)
	}
	if strings.Contains(string(data), "require") {
		t.Errorf("go.mod gained a `require` directive — the node must stay stdlib-only:\n%s", data)
	}
	if _, err := os.Stat(filepath.Join(root, "go.sum")); err == nil {
		t.Error("go.sum exists — the node must have no third-party dependencies")
	}
}

// TestNodeWritesNoDurableState parses every non-test source file and fails if
// any reintroduces a durable-storage import or a filesystem-write call.
func TestNodeWritesNoDurableState(t *testing.T) {
	root := moduleRoot(t)
	fset := token.NewFileSet()

	walkErr := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		if _, exempt := notTheRelay[relativePackage(root, path)]; exempt {
			return nil
		}
		file, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, path)

		for _, imp := range file.Imports {
			pkg := strings.Trim(imp.Path.Value, `"`)
			if reason, bad := forbiddenImports[pkg]; bad {
				t.Errorf("%s imports %q — %s; the node must keep no durable state", rel, pkg, reason)
			}
		}

		writeNames := localWriteNames(t, rel, file)
		ast.Inspect(file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			ident, ok := sel.X.(*ast.Ident)
			if !ok {
				return true
			}
			prefix, imported := writeNames[ident.Name]
			if !imported {
				return true
			}
			name := prefix + "." + sel.Sel.Name
			if reason, bad := forbiddenCalls[name]; bad {
				t.Errorf("%s calls %s.%s — %s; the node must never write state to disk",
					rel, ident.Name, sel.Sel.Name, reason)
			}
			return true
		})
		return nil
	})
	if walkErr != nil {
		t.Fatalf("walk source tree: %v", walkErr)
	}
}

// relativePackage is the module-relative directory a source file lives in, which
// is how notTheRelay names a package.
func relativePackage(root, path string) string {
	relative, err := filepath.Rel(root, filepath.Dir(path))
	if err != nil {
		return ""
	}
	return relative
}

// TestNothingTheRelayImportsIsExemptFromTheWriteBan walks the relay's import
// graph from its main package and fails if it reaches anything on the exemption
// list.
//
// This is what makes the exemption above a boundary rather than a hole. A tool
// that writes to disk is fine while it is a separate binary; the moment the
// relay links it — a shared helper moved into internal/issue, an import added
// for one convenient function — the audited claim stops being true, and it would
// stop being true silently, because the write is in a file the walk no longer
// looks at.
func TestNothingTheRelayImportsIsExemptFromTheWriteBan(t *testing.T) {
	const modulePrefix = "deechat/chat-node/"

	seen := map[string]bool{}
	pending := []string{filepath.Join("cmd", "dee-relay")}
	for len(pending) > 0 {
		pkg := pending[0]
		pending = pending[1:]
		if seen[pkg] {
			continue
		}
		seen[pkg] = true
		if reason, exempt := notTheRelay[pkg]; exempt {
			t.Errorf("the relay reaches %s, which is exempt from the durable-write ban (%s): the exemption only holds while the relay cannot link it",
				pkg, reason)
			continue
		}
		for _, path := range nonTestSources(t, pkg) {
			for _, imported := range parseSource(t, path).Imports {
				name := strings.Trim(imported.Path.Value, `"`)
				if strings.HasPrefix(name, modulePrefix) {
					pending = append(pending, filepath.FromSlash(strings.TrimPrefix(name, modulePrefix)))
				}
			}
		}
	}

	// The relay is a main package over ten-odd internal ones. A graph that
	// suddenly has two entries means the walk stopped finding imports and this
	// test is passing by not looking.
	if len(seen) < 8 {
		t.Fatalf("the relay's import graph came back with %d packages; this guard is scanning the wrong thing", len(seen))
	}
	if _, walked := seen[filepath.Join("internal", "admission")]; !walked {
		t.Error("the relay's import graph does not include internal/admission; this guard is scanning the wrong thing")
	}
}
