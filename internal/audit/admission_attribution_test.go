package audit

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// Admission gives the relay something it did not previously have: a stable
// per-circle identifier, and a usage figure beside it. What is published about
// that — here and in SECURITY.md — describes a *counter*, and the rule it rests
// on is:
//
//	count under the credential; never accumulate a set of what was seen under it.
//
// A counter is a number. A map from queue tags to a credential is a circle's
// membership roster — strictly more than the admission token itself discloses,
// and the one thing this relay must not be able to build. The difference is one
// line of code either way, which is why it is guarded here rather than written
// down somewhere and trusted.

// admissionAttributionPackages are the two packages that count. Both are handed
// a per-boot integer and neither may learn anything else about a circle.
var admissionAttributionPackages = []string{
	filepath.Join("internal", "queue"),
	filepath.Join("internal", "attachment"),
}

// TestTheCountingPackagesCannotNameACircle. The queue store and the attachment
// relay are given a uint32 that means nothing off this box and nothing after a
// restart. Importing the admission package would hand them the credential id
// itself, and from there a roster is an ordinary refactor away.
func TestTheCountingPackagesCannotNameACircle(t *testing.T) {
	for _, pkg := range admissionAttributionPackages {
		for _, path := range nonTestSources(t, pkg) {
			file := parseSource(t, path)
			for _, imported := range file.Imports {
				if strings.Contains(imported.Path.Value, "internal/admission") {
					rel, _ := filepath.Rel(moduleRoot(t), path)
					t.Errorf("%s imports internal/admission: attribution in this package is a per-boot integer, and a package that can name a circle can build a roster of one", rel)
				}
			}
		}
	}
}

// mapType matches a map declaration's key and value: map[K]V.
var mapType = regexp.MustCompile(`map\[([^\[\]]+)\]([A-Za-z0-9_.*\[\]]+)`)

// TestNothingPairsAQueueTagWithACredential is the rule stated directly. A tag is
// the handle a member's queue is addressed by; a credential is the circle paying
// for it. Either one alone is already disclosed. A map between them is the thing
// that is not.
func TestNothingPairsAQueueTagWithACredential(t *testing.T) {
	root := moduleRoot(t)
	walkErr := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		body, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, path)
		for _, match := range mapType.FindAllStringSubmatch(string(body), -1) {
			key, value := strings.ToLower(match[1]), strings.ToLower(match[2])
			tagged := strings.Contains(key, "tag") || strings.Contains(value, "tag")
			circled := strings.Contains(key, "credential") || strings.Contains(value, "credential") ||
				strings.Contains(key, "circle") || strings.Contains(value, "circle")
			if tagged && circled {
				t.Errorf("%s declares %s: a map from queue tags to a circle is a membership roster, which this relay must not be able to build", rel, match[0])
			}
		}
		return nil
	})
	if walkErr != nil {
		t.Fatalf("walk source tree: %v", walkErr)
	}
}

// TestTheAttributionIsAnIntegerCount. Stated positively, so that removing the
// counter and replacing it with something richer fails here rather than passing
// by absence.
func TestTheAttributionIsAnIntegerCount(t *testing.T) {
	store := readSource(t, filepath.Join("internal", "queue", "store.go"))
	if !strings.Contains(store, "credentialCounts map[uint32]int") {
		t.Error("queue.Store no longer counts occupancy as map[uint32]int; a counter is the only per-credential record permitted")
	}
	if !strings.Contains(store, "messageCredential map[string]uint32") {
		t.Error("queue.Store no longer remembers attribution by message id; the count cannot be decremented on delivery without it")
	}
	relay := readSource(t, filepath.Join("internal", "attachment", "relay.go"))
	if !strings.Contains(relay, "transit map[uint32]*transitWindow") {
		t.Error("attachment.Relay no longer counts transit per credential as a byte total")
	}
}

// TestAdmissionAttributionIsNeverSerialized. The per-boot index is meaningless
// on another box, and putting it on the wire would tell a pool member — or
// anyone who reads a replicated record — which of this relay's circles a queued
// envelope belongs to. The model package is where that would happen.
func TestAdmissionAttributionIsNeverSerialized(t *testing.T) {
	model := readSource(t, filepath.Join("internal", "model", "model.go"))
	for _, forbidden := range []string{"credential", "Credential", "admission", "Admission"} {
		if strings.Contains(model, forbidden) {
			t.Errorf("internal/model mentions %q: a wire record must carry no admission attribution", forbidden)
		}
	}
}

// TestThePublicWritePathsCarryAGrant. Both stores keep an ungated entry point —
// the free self-hosted path uses it, and so do replication and the tests — so a
// future handler that calls the wrong one would gate the request and then charge
// it to nobody, which is capacity that is sold and never metered. The check is
// structural because the failure is silent.
func TestThePublicWritePathsCarryAGrant(t *testing.T) {
	server := readSource(t, filepath.Join("internal", "httpapi", "server.go"))
	for _, required := range []string{"AddMessageWithGrant(", "PushWithGrant("} {
		if !strings.Contains(server, required) {
			t.Errorf("the public write path no longer calls %s: an admitted request would be charged to nobody", required)
		}
	}
	for _, forbidden := range []string{"s.store.AddMessage(", "s.attachments.Push("} {
		if strings.Contains(server, forbidden) {
			t.Errorf("the public write path calls %s, the ungated variant: it bypasses every per-circle cap", forbidden)
		}
	}
}

// TestEveryMeteredRouteIsGated walks the public mux and asserts that each route
// either checks admission or is on the short list of routes that must not.
//
// The list is the interesting part, and each entry is a decision rather than an
// omission:
//
//   - /health and /nodes are what monitoring reads, and /health is where the
//     enforcement switch is published — gating it would make an unmonitorable
//     relay.
//   - /admission/* is the exchange itself; the nonce is what a client signs to
//     become admitted, so it cannot require admission.
//   - /presence/revoke and /profile/purge only ever REMOVE data, and both are
//     the last thing a circle does on a relay it is leaving — often on the day
//     its window ended. Admission meters what a relay carries; it must never be
//     the reason a relay holds on to something.
var ungatedByDesign = map[string]bool{
	"/health":              true,
	"/nodes":               true,
	"/admission/challenge": true,
	"/admission/redeem":    true,
	"/presence/revoke":     true,
	"/profile/purge":       true,
}

func TestEveryMeteredRouteIsGated(t *testing.T) {
	handlers := map[string]*ast.FuncDecl{}
	var registrations []*ast.CallExpr
	for _, path := range nonTestSources(t, filepath.Join("internal", "httpapi")) {
		ast.Inspect(parseSource(t, path), func(n ast.Node) bool {
			switch node := n.(type) {
			case *ast.FuncDecl:
				if node.Recv != nil {
					handlers[node.Name.Name] = node
				}
			case *ast.CallExpr:
				if publicRouteRegistration(node) {
					registrations = append(registrations, node)
				}
			}
			return true
		})
	}
	if len(registrations) == 0 {
		t.Fatal("found no public route registrations at all; this guard is scanning the wrong thing")
	}

	for _, registration := range registrations {
		pattern, ok := stringLiteral(registration.Args[0])
		if !ok {
			t.Errorf("a route is registered with a non-literal pattern; this guard cannot see it")
			continue
		}
		route := pattern[strings.Index(pattern, " ")+1:]
		handlerName, ok := methodName(registration.Args[1])
		if !ok {
			t.Errorf("%s is registered with something other than a method value; this guard cannot see it", route)
			continue
		}
		decl, ok := handlers[handlerName]
		if !ok {
			t.Errorf("could not find the handler for %s (%q); this guard is scanning the wrong thing", route, handlerName)
			continue
		}

		gated := false
		ast.Inspect(decl, func(n ast.Node) bool {
			if call, ok := n.(*ast.CallExpr); ok {
				if sel, ok := call.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "admit" {
					gated = true
				}
			}
			return true
		})
		switch {
		case gated && ungatedByDesign[route]:
			t.Errorf("%s calls admit() but is on the ungated-by-design list; one of the two is wrong", route)
		case !gated && !ungatedByDesign[route]:
			t.Errorf("%s does not check admission and is not on the ungated-by-design list: on an enforcing relay it is free service", route)
		}
	}
}

// publicRouteRegistration matches s.mux.HandleFunc(pattern, handler) — the
// public listener only. The mesh listener is authenticated by the pool secret on
// a private address and has nothing to do with admission.
func publicRouteRegistration(call *ast.CallExpr) bool {
	selector, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || selector.Sel.Name != "HandleFunc" || len(call.Args) != 2 {
		return false
	}
	mux, ok := selector.X.(*ast.SelectorExpr)
	if !ok || mux.Sel.Name != "mux" {
		return false
	}
	receiver, ok := mux.X.(*ast.Ident)
	return ok && receiver.Name == "s"
}

func stringLiteral(expr ast.Expr) (string, bool) {
	literal, ok := expr.(*ast.BasicLit)
	if !ok || literal.Kind != token.STRING {
		return "", false
	}
	return strings.Trim(literal.Value, `"`), true
}

func methodName(expr ast.Expr) (string, bool) {
	selector, ok := expr.(*ast.SelectorExpr)
	if !ok {
		return "", false
	}
	return selector.Sel.Name, true
}

func nonTestSources(t *testing.T, pkg string) []string {
	t.Helper()
	matches, err := filepath.Glob(filepath.Join(moduleRoot(t), pkg, "*.go"))
	if err != nil {
		t.Fatalf("glob %s: %v", pkg, err)
	}
	var sources []string
	for _, path := range matches {
		if !strings.HasSuffix(path, "_test.go") {
			sources = append(sources, path)
		}
	}
	if len(sources) == 0 {
		t.Fatalf("found no sources in %s; this guard is scanning the wrong thing", pkg)
	}
	return sources
}

func parseSource(t *testing.T, path string) *ast.File {
	t.Helper()
	file, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	return file
}
