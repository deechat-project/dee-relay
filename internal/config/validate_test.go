package config

import (
	"strings"
	"testing"
)

// Each case is a configuration an earlier build accepted. The node ran, /health
// said meshEnabled=true, and replication did nothing — or, for the peering-url
// cases, did something worse.

func TestValidateAcceptsAWorkingPoolMember(t *testing.T) {
	cfg := Config{
		NodeID:     "relay-1",
		Addr:       "127.0.0.1:8080",
		PublicURL:  "https://relay-1.example.org",
		MeshAddr:   "10.0.0.1:8081",
		MeshPeers:  []string{"http://10.0.0.2:8081", "http://10.0.0.3:8081"},
		MeshSecret: "pool-secret",
	}
	if errs := cfg.Validate(); len(errs) != 0 {
		t.Fatalf("Validate on a good config = %v", errs)
	}
}

func TestValidateAcceptsARelayWithNoMeshAtAll(t *testing.T) {
	cfg := Config{NodeID: "relay-1", Addr: ":8080", PublicURL: "https://relay-1.example.org"}
	if errs := cfg.Validate(); len(errs) != 0 {
		t.Fatalf("Validate on a mesh-less config = %v", errs)
	}
}

func TestValidateRefusesTheOldPeerVariable(t *testing.T) {
	t.Setenv("DEE_NODE_TRUSTED_NODES", "https://relay-2.example.org")
	cfg := Config{NodeID: "relay-1", PublicURL: "https://relay-1.example.org"}
	assertRefused(t, cfg, "DEE_NODE_MESH_PEERS")
}

func TestValidateRefusesMeshWithNoListener(t *testing.T) {
	cfg := Config{NodeID: "relay-1", PublicURL: "https://relay-1.example.org", MeshSecret: "pool-secret"}
	assertRefused(t, cfg, "DEE_NODE_MESH_ADDR")
}

func TestValidateRefusesAListenerWithNoSecret(t *testing.T) {
	cfg := Config{NodeID: "relay-1", PublicURL: "https://relay-1.example.org", MeshAddr: "10.0.0.1:8081"}
	assertRefused(t, cfg, "DEE_NODE_MESH_SECRET")
}

func TestValidateRefusesPeersWithNoSecret(t *testing.T) {
	cfg := Config{
		NodeID:    "relay-1",
		PublicURL: "https://relay-1.example.org",
		MeshPeers: []string{"http://10.0.0.2:8081"},
	}
	assertRefused(t, cfg, "DEE_NODE_MESH_SECRET")
}

// A wildcard bind is the default shape of every other address in the config, and
// on the mesh listener it would put a route that serves every identity's queued
// records on every interface, behind one shared secret.
func TestValidateRefusesAWildcardOrPublicMeshBind(t *testing.T) {
	for _, addr := range []string{":8081", "0.0.0.0:8081", "[::]:8081", "203.0.113.7:8081", "relay-1.example.org:8081"} {
		cfg := Config{
			NodeID:     "relay-1",
			PublicURL:  "https://relay-1.example.org",
			MeshAddr:   addr,
			MeshSecret: "pool-secret",
		}
		if errs := cfg.Validate(); len(errs) == 0 {
			t.Fatalf("Validate accepted DEE_NODE_MESH_ADDR=%q", addr)
		}
	}
}

func TestValidateAcceptsPrivateMeshBinds(t *testing.T) {
	// 10/8 and 192.168/16 for a provider private network or WireGuard, 100.64/10
	// for Tailscale, loopback for a single-host test pool.
	for _, addr := range []string{"10.0.0.1:8081", "192.168.10.4:8081", "100.101.102.103:8081", "127.0.0.1:8081"} {
		cfg := Config{
			NodeID:     "relay-1",
			PublicURL:  "https://relay-1.example.org",
			MeshAddr:   addr,
			MeshSecret: "pool-secret",
		}
		if errs := cfg.Validate(); len(errs) != 0 {
			t.Fatalf("Validate rejected the private bind %q: %v", addr, errs)
		}
	}
}

// The pool secret travels as a request header on every sync, so a plain-http peer
// url against a public host puts it on the wire in the clear.
func TestValidateRefusesCleartextPeeringToAPublicHost(t *testing.T) {
	cfg := Config{
		NodeID:     "relay-1",
		PublicURL:  "https://relay-1.example.org",
		MeshAddr:   "10.0.0.1:8081",
		MeshPeers:  []string{"http://relay-2.example.org"},
		MeshSecret: "pool-secret",
	}
	assertRefused(t, cfg, "clear")
}

func TestValidateRefusesADuplicatePeer(t *testing.T) {
	cfg := Config{
		NodeID:     "relay-1",
		PublicURL:  "https://relay-1.example.org",
		MeshAddr:   "10.0.0.1:8081",
		MeshPeers:  []string{"http://10.0.0.2:8081", "http://10.0.0.2:8081"},
		MeshSecret: "pool-secret",
	}
	// The original roster produced exactly this by accident — bootstrap entries keyed
	// by url, merged entries keyed by node id — and synced every peer twice a tick.
	assertRefused(t, cfg, "twice")
}

func TestValidateRefusesANodeThatPeersWithItself(t *testing.T) {
	cfg := Config{
		NodeID:     "relay-1",
		PublicURL:  "https://relay-1.example.org",
		MeshAddr:   "10.0.0.1:8081",
		MeshPeers:  []string{"https://relay-1.example.org"},
		MeshSecret: "pool-secret",
	}
	assertRefused(t, cfg, "own")
}

func TestValidateRefusesANonHTTPPeer(t *testing.T) {
	cfg := Config{
		NodeID:     "relay-1",
		PublicURL:  "https://relay-1.example.org",
		MeshAddr:   "10.0.0.1:8081",
		MeshPeers:  []string{"wg://10.0.0.2:8081"},
		MeshSecret: "pool-secret",
	}
	assertRefused(t, cfg, "http")
}

func assertRefused(t *testing.T, cfg Config, wantSubstring string) {
	t.Helper()
	errs := cfg.Validate()
	if len(errs) == 0 {
		t.Fatal("Validate accepted the configuration")
	}
	for _, err := range errs {
		if strings.Contains(err.Error(), wantSubstring) {
			return
		}
	}
	t.Fatalf("no error mentioned %q; got %v", wantSubstring, errs)
}

// A relay with no credentials configured is OPEN, not closed — that is the free
// self-hosted path and it must stay exactly that generous. Which is precisely
// why the enforcing case needs a switch that cannot fail silently: an operator
// who means to gate a box and mistypes the file path would otherwise run it open
// and it would look identical from the outside.
func TestValidateAcceptsARelayWithNoAdmissionAtAll(t *testing.T) {
	cfg := Config{NodeID: "relay-1", Addr: ":8080", PublicURL: "https://relay-1.example.org"}
	if errs := cfg.Validate(); len(errs) != 0 {
		t.Fatalf("Validate on an ungated config = %v", errs)
	}
}

func TestValidateRefusesEnforcementWithNothingToEnforce(t *testing.T) {
	cfg := Config{
		NodeID:           "relay-1",
		Addr:             ":8080",
		PublicURL:        "https://relay-1.example.org",
		RequireAdmission: true,
	}
	assertRefused(t, cfg, "DEE_NODE_ADMISSION_FILE")
}

func TestValidateAcceptsEnforcementWithACredentialFile(t *testing.T) {
	cfg := Config{
		NodeID:           "relay-1",
		Addr:             ":8080",
		PublicURL:        "https://relay-1.example.org",
		AdmissionFile:    "/etc/deechat/credentials.json",
		RequireAdmission: true,
	}
	if errs := cfg.Validate(); len(errs) != 0 {
		t.Fatalf("Validate on a gated config = %v", errs)
	}
}

// The ack lane above DEE_NODE_MAX_MESSAGES is the budget client-posted acks may
// occupy; below it is the reserve that keeps POST /messages working. A setting
// that leaves no budget would refuse every delivery and read ack on the box,
// which reads as a broken client rather than a misconfigured relay — so it is
// refused at boot, like every other safety switch here.
func TestValidateRefusesAnAckLaneWithNoExternalBudget(t *testing.T) {
	cfg := Config{
		NodeID:      "relay-1",
		Addr:        ":8080",
		PublicURL:   "https://relay-1.example.org",
		MaxMessages: 1000,
		MaxAcks:     1000,
	}
	assertRefused(t, cfg, "DEE_NODE_MAX_ACKS")
}

func TestValidateAcceptsTheDefaultAckRatio(t *testing.T) {
	cfg := Config{
		NodeID:      "relay-1",
		Addr:        ":8080",
		PublicURL:   "https://relay-1.example.org",
		MaxMessages: 1000,
		MaxAcks:     2000,
	}
	if errs := cfg.Validate(); len(errs) != 0 {
		t.Fatalf("Validate on the default cap ratio = %v", errs)
	}
}
