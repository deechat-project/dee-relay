package audit

import (
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"path/filepath"
	"strings"
	"testing"
)

// A cap the operator sets, the config package reads, the README documents — and
// the binary then drops on the floor — is indistinguishable from a working one
// from outside the process: the value is in the env file, the boot is clean, and
// nothing happens. internal/config/env_documentation_test.go closes half of that
// gap by pinning every documented name to a name config.go reads. This is the
// other half: the value config.go read has to reach the store it sizes.
//
// It is not hypothetical. cmd/dee-relay built the prekey store with the package
// defaults and handed it to NewServerWithStores, which used it in place of the
// one NewServer had sized from config — so DEE_NODE_PREKEY_CLAIM_BURST and
// DEE_NODE_PREKEY_CLAIM_REFILL were read, validated, documented, and then thrown
// away by every deployed relay. Nothing failed, and nothing could have.
//
// So: every store the binary constructs by hand is built from cfg, and a store
// that is deliberately not configurable is listed below with the reason, where a
// reader can see the whole set at once.
var storePackages = map[string]bool{
	"queue":      true,
	"prekey":     true,
	"attachment": true,
	"presence":   true,
	"admission":  true,
	"peer":       true,
	"mesh":       true,
}

// notSizedFromConfig are the constructions that legitimately take no cap from
// the operator's file. Each needs a reason a reader can check, not just an
// entry: an allowlist nobody has to justify to is how the defect above comes
// back wearing a different constructor.
var notSizedFromConfig = map[string]string{
	"presence.NewStore": "the presence table's 5000 records and 24h last-seen TTL are " +
		"hardcoded identically here and in NewServer, and deploy/memory-ceiling.sh " +
		"counts them as not configurable; changing that means changing all three",
	"admission.NewStore": "sized by the credential file it is asked to load, which is " +
		"the configured part; the constructor takes nothing",
}

func TestEveryStoreTheBinaryBuildsIsSizedFromConfig(t *testing.T) {
	path := filepath.Join(moduleRoot(t), "cmd", "dee-relay", "main.go")
	fileSet := token.NewFileSet()
	file, err := parser.ParseFile(fileSet, path, nil, parser.ParseComments)
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}

	checked := 0
	ast.Inspect(file, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		selector, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		pkg, ok := selector.X.(*ast.Ident)
		if !ok || !storePackages[pkg.Name] || !strings.HasPrefix(selector.Sel.Name, "New") {
			return true
		}

		name := pkg.Name + "." + selector.Sel.Name
		checked++
		if _, exempt := notSizedFromConfig[name]; exempt {
			return true
		}

		var rendered strings.Builder
		for _, arg := range call.Args {
			if err := printer.Fprint(&rendered, fileSet, arg); err != nil {
				t.Fatalf("render %s argument: %v", name, err)
			}
			rendered.WriteByte(' ')
		}
		if !strings.Contains(rendered.String(), "cfg") {
			t.Errorf("%s at %s is built without cfg: %s(%s). Either size it from the "+
				"operator's configuration, or add it to notSizedFromConfig with the reason",
				name, fileSet.Position(call.Pos()), name, strings.TrimSpace(rendered.String()))
		}
		return true
	})

	// The scan is worth more than the assertions if it silently matches nothing —
	// a rename of the store packages, or a main.go that stops constructing them,
	// would leave this test green over an empty set.
	if checked < len(notSizedFromConfig)+3 {
		t.Fatalf("found only %d store constructions in cmd/dee-relay/main.go; this guard is scanning the wrong thing", checked)
	}
}

// The prekey store is the one with two constructors, and the defaults one is
// what the deployed relay was using. Named on its own because the check above
// passes the moment cfg appears anywhere in the arguments, and prekey.NewStore
// has no argument it could appear in.
func TestTheBinaryNeverBuildsThePrekeyStoreWithPackageDefaults(t *testing.T) {
	source := readSource(t, filepath.Join("cmd", "dee-relay", "main.go"))
	if strings.Contains(source, "prekey.NewStore(") {
		t.Error("cmd/dee-relay builds the prekey store with prekey.NewStore, which ignores " +
			"DEE_NODE_PREKEY_CLAIM_BURST and DEE_NODE_PREKEY_CLAIM_REFILL; use " +
			"prekey.NewStoreWithLimits(httpapi.PrekeyLimits(cfg), …)")
	}
	if !strings.Contains(source, "prekey.NewStoreWithLimits(httpapi.PrekeyLimits(cfg)") {
		t.Error("cmd/dee-relay no longer sizes the prekey store from httpapi.PrekeyLimits(cfg); " +
			"the store NewServerWithStores is handed replaces the one NewServer sized")
	}
}
