package peer

import (
	"errors"
	"net"
	"net/url"
	"testing"
	"time"
)

var poolNow = time.Date(2026, 7, 26, 12, 0, 0, 0, time.UTC)

func TestPoolTargetsAreExactlyWhatWasConfigured(t *testing.T) {
	pool := NewPool("relay-1", "https://relay-1.example.org",
		[]string{"http://10.0.0.2:8081", "", "http://10.0.0.2:8081", "http://10.0.0.3:8081"})

	targets := pool.Targets()
	if len(targets) != 2 || targets[0] != "http://10.0.0.2:8081" || targets[1] != "http://10.0.0.3:8081" {
		t.Fatalf("Targets = %v, want the two distinct configured peers in order", targets)
	}
}

// The roster used to grow from what peers said about each other, which is how one
// member's /nodes response could hand a stranger the pool secret. There is no way
// to add a target now, so this asserts the absence: recording an outcome for a url
// nobody configured must not create one.
func TestRecordingAnUnknownPeerAddsNothing(t *testing.T) {
	pool := NewPool("relay-1", "https://relay-1.example.org", []string{"http://10.0.0.2:8081"})

	pool.RecordSuccess("http://attacker.example", "attacker-owned", poolNow)
	pool.RecordFailure("http://attacker.example", errors.New("nope"), poolNow)

	if targets := pool.Targets(); len(targets) != 1 {
		t.Fatalf("Targets = %v after recording an unconfigured peer, want only the configured one", targets)
	}
	if health := pool.Health(poolNow); health.Peers != 1 {
		t.Fatalf("Health.Peers = %d, want 1", health.Peers)
	}
}

func TestSelfIsTheOnlyThingARelayPublishes(t *testing.T) {
	pool := NewPool("relay-1", "https://relay-1.example.org", []string{"http://10.0.0.2:8081"})
	self := pool.Self()
	if self.ID != "relay-1" || self.URL != "https://relay-1.example.org" {
		t.Fatalf("Self = %+v", self)
	}
}

// Health is what monitoring asserts, so each state has to be distinguishable:
// never synced, synced, and failing after having synced.
func TestHealthDistinguishesNeverSyncedFromStale(t *testing.T) {
	pool := NewPool("relay-1", "https://relay-1.example.org",
		[]string{"http://10.0.0.2:8081", "http://10.0.0.3:8081"})

	// Nothing has synced. -1 rather than a large age, because "never" is a
	// different fault from "late" and a deployment should be able to alert on it.
	if health := pool.Health(poolNow); health.Reachable != 0 || health.OldestSyncAgeSec != -1 {
		t.Fatalf("fresh pool health = %+v, want 0 reachable and -1", health)
	}

	// One of two synced: still -1, because a healthy peer must not average away a
	// peer that has never worked.
	pool.RecordSuccess("http://10.0.0.2:8081", "relay-2", poolNow)
	if health := pool.Health(poolNow.Add(10 * time.Second)); health.Reachable != 1 || health.OldestSyncAgeSec != -1 {
		t.Fatalf("half-synced pool health = %+v, want 1 reachable and -1", health)
	}

	// Both synced, at different times: the age reported is the older one.
	pool.RecordSuccess("http://10.0.0.3:8081", "relay-3", poolNow.Add(5*time.Second))
	health := pool.Health(poolNow.Add(30 * time.Second))
	if health.Reachable != 2 || health.OldestSyncAgeSec != 30 {
		t.Fatalf("synced pool health = %+v, want 2 reachable and age 30", health)
	}

	// A peer that starts failing stops counting as reachable, while its last
	// success keeps ageing — which is the signal that queues are diverging.
	pool.RecordFailure("http://10.0.0.2:8081", errors.New("404"), poolNow.Add(35*time.Second))
	health = pool.Health(poolNow.Add(60 * time.Second))
	if health.Reachable != 1 || health.OldestSyncAgeSec != 60 {
		t.Fatalf("failing pool health = %+v, want 1 reachable and age 60", health)
	}
}

func TestHealthClampsAClockThatStepsBackwards(t *testing.T) {
	pool := NewPool("relay-1", "https://relay-1.example.org", []string{"http://10.0.0.2:8081"})
	pool.RecordSuccess("http://10.0.0.2:8081", "relay-2", poolNow)

	// -1 has to keep meaning "never", so a negative age is reported as "just now"
	// rather than as a peer that has never worked.
	if health := pool.Health(poolNow.Add(-time.Minute)); health.OldestSyncAgeSec != 0 {
		t.Fatalf("OldestSyncAgeSec with a backwards clock = %d, want 0", health.OldestSyncAgeSec)
	}
}

// Self() is the only place the advertised url reaches a response body, so the
// re-derivation has to be visible through it rather than only through the
// resolver. Reaches into the pool's own address to script the host, since the
// machine running the test is not going to change networks on cue.
func TestSelfPublishesTheReDerivedAddress(t *testing.T) {
	pool := NewPool("relay-1", "http://192.168.1.37:8080", nil)
	host := []net.IP{net.ParseIP("192.168.1.37")}
	clock := poolNow
	pool.selfURL.localIPs = func() []net.IP { return host }
	pool.selfURL.now = func() time.Time { return clock }
	pool.selfURL.tracking = true
	pool.selfURL.currentIP = host[0]
	pool.selfURL.template, _ = url.Parse("http://192.168.1.37:8080")
	pool.selfURL.port = "8080"

	if self := pool.Self(); self.URL != "http://192.168.1.37:8080" {
		t.Fatalf("Self.URL = %q at launch", self.URL)
	}

	host = []net.IP{net.ParseIP("192.168.1.41")}
	clock = clock.Add(selfAddressRecheckInterval)
	if self := pool.Self(); self.URL != "http://192.168.1.41:8080" {
		t.Fatalf("Self.URL = %q after the host moved, want the current address", self.URL)
	}
}
