package peer

import (
	"net"
	"testing"
	"time"
)

func ips(values ...string) []net.IP {
	out := make([]net.IP, 0, len(values))
	for _, value := range values {
		out = append(out, net.ParseIP(value))
	}
	return out
}

// trackedAddress builds a selfAddress the way NewPool does, but over a scripted
// host rather than the machine running the test.
func trackedAddress(t *testing.T, configured string, host *[]net.IP, clock *time.Time) *selfAddress {
	t.Helper()
	address := &selfAddress{
		configured: configured,
		current:    configured,
		localIPs:   func() []net.IP { return *host },
		now:        func() time.Time { return *clock },
	}
	address.latch()
	return address
}

// The foot-gun as filed: a node that outlives the IP it baked at launch keeps
// advertising the dead address, so peers route sends and acks to a host that is
// not there while /health still says the node is fine.
func TestAdvertisedURLFollowsTheHostToANewAddress(t *testing.T) {
	host := ips("192.168.1.37")
	clock := time.Date(2026, 8, 28, 9, 0, 0, 0, time.UTC)
	address := trackedAddress(t, "http://192.168.1.37:8080", &host, &clock)

	if published, changed := address.resolve(); published != "http://192.168.1.37:8080" || changed {
		t.Fatalf("resolve at launch = %q changed=%v, want the configured url unchanged", published, changed)
	}

	host = ips("192.168.1.41")
	clock = clock.Add(selfAddressRecheckInterval)
	published, changed := address.resolve()
	if published != "http://192.168.1.41:8080" || !changed {
		t.Fatalf("resolve after the host moved = %q changed=%v, want the new address", published, changed)
	}
	if address.configured != "http://192.168.1.37:8080" {
		t.Fatalf("configured = %q, want the operator's string left alone", address.configured)
	}
}

// The re-derivation must not become its own foot-gun. A configured host that is
// not a literal this box holds is somebody else's decision — a domain, or a
// proxy's address — and stays exactly as configured no matter what the
// interfaces do.
func TestOnlyAnAddressThisHostHoldsIsEverReDerived(t *testing.T) {
	cases := []struct {
		name       string
		configured string
		host       []net.IP
	}{
		{"a domain", "https://relay-1.example.org", ips("192.168.1.37")},
		{"localhost", "http://localhost:8080", ips("192.168.1.37")},
		{"a loopback literal", "http://127.0.0.1:8080", ips("192.168.1.37")},
		{"an address on some other host", "http://203.0.113.9:8080", ips("192.168.1.37")},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			host := testCase.host
			clock := time.Date(2026, 8, 28, 9, 0, 0, 0, time.UTC)
			address := trackedAddress(t, testCase.configured, &host, &clock)
			if address.tracking {
				t.Fatalf("%s latched as re-derivable", testCase.configured)
			}

			host = ips("10.0.0.5")
			clock = clock.Add(time.Hour)
			if published, changed := address.resolve(); published != testCase.configured || changed {
				t.Fatalf("resolve = %q changed=%v, want %q untouched", published, changed, testCase.configured)
			}
		})
	}
}

// Between networks — asleep, or on the hop itself — there is no address to move
// to. The last known one is a better answer than an empty or truncated url, and
// the next check is seconds away.
func TestAnUnreachableHostKeepsTheLastKnownAddress(t *testing.T) {
	host := ips("192.168.1.37")
	clock := time.Date(2026, 8, 28, 9, 0, 0, 0, time.UTC)
	address := trackedAddress(t, "http://192.168.1.37:8080", &host, &clock)
	address.resolve()

	host = nil
	clock = clock.Add(selfAddressRecheckInterval)
	if published, changed := address.resolve(); published != "http://192.168.1.37:8080" || changed {
		t.Fatalf("resolve with every interface down = %q changed=%v, want the last known url", published, changed)
	}

	host = ips("192.168.1.41")
	clock = clock.Add(selfAddressRecheckInterval)
	if published, _ := address.resolve(); published != "http://192.168.1.41:8080" {
		t.Fatalf("resolve once the host is back = %q, want the new address", published)
	}
}

// /nodes is unauthenticated, so the interface lookup it triggers has to be
// bounded no matter how often it is polled.
func TestInterfacesAreNotReReadOnEveryPoll(t *testing.T) {
	host := ips("192.168.1.37")
	clock := time.Date(2026, 8, 28, 9, 0, 0, 0, time.UTC)
	lookups := 0
	address := &selfAddress{
		configured: "http://192.168.1.37:8080",
		current:    "http://192.168.1.37:8080",
		localIPs:   func() []net.IP { lookups++; return host },
		now:        func() time.Time { return clock },
	}
	address.latch()
	atLatch := lookups

	for i := 0; i < 50; i++ {
		address.resolve()
		clock = clock.Add(time.Second)
	}
	// 50 polls over 50 seconds: three checks at most, not fifty.
	if lookups-atLatch > 4 {
		t.Fatalf("interface lookups = %d over 50 s of polling, want the 15 s cache to bound them", lookups-atLatch)
	}
}

// A url rebuilt on an IPv6 literal has to stay parseable, and a rewrite must not
// silently change the family a peer was given.
func TestRewrittenURLKeepsSchemeFamilyAndPort(t *testing.T) {
	host := ips("2001:db8::1", "192.168.1.37")
	clock := time.Date(2026, 8, 28, 9, 0, 0, 0, time.UTC)
	address := trackedAddress(t, "https://[2001:db8::1]:9443/relay", &host, &clock)
	if !address.tracking {
		t.Fatal("an IPv6 literal this host holds should be re-derivable")
	}

	host = ips("192.168.1.41", "2001:db8::2")
	clock = clock.Add(selfAddressRecheckInterval)
	published, changed := address.resolve()
	if published != "https://[2001:db8::2]:9443/relay" || !changed {
		t.Fatalf("resolve = %q changed=%v, want the v6 replacement with scheme, port and path intact", published, changed)
	}
}

// Link-local and loopback addresses are on every machine and route for nobody:
// they must never be picked as a replacement.
func TestUnroutableAddressesAreNeverPublished(t *testing.T) {
	host := ips("192.168.1.37")
	clock := time.Date(2026, 8, 28, 9, 0, 0, 0, time.UTC)
	address := trackedAddress(t, "http://192.168.1.37:8080", &host, &clock)
	address.resolve()

	host = ips("169.254.7.7", "127.0.0.1", "10.0.0.9")
	// hostAddresses filters these out for real; the pick must not depend on that.
	filtered := make([]net.IP, 0, len(host))
	for _, candidate := range host {
		if usableHostIP(candidate) {
			filtered = append(filtered, candidate)
		}
	}
	host = filtered
	clock = clock.Add(selfAddressRecheckInterval)
	if published, _ := address.resolve(); published != "http://10.0.0.9:8080" {
		t.Fatalf("resolve = %q, want the only routable address", published)
	}
}

// The change hook is what puts a moved node in the operator's log; it must fire
// once per move and not on a re-check that found nothing.
func TestChangeHookFiresOnceForAMove(t *testing.T) {
	host := ips("192.168.1.37")
	clock := time.Date(2026, 8, 28, 9, 0, 0, 0, time.UTC)
	address := trackedAddress(t, "http://192.168.1.37:8080", &host, &clock)
	var moves [][2]string
	address.onChange = func(previous, current string) {
		moves = append(moves, [2]string{previous, current})
	}

	address.resolve()
	host = ips("192.168.1.41")
	clock = clock.Add(selfAddressRecheckInterval)
	address.resolve()
	clock = clock.Add(selfAddressRecheckInterval)
	address.resolve()

	if len(moves) != 1 || moves[0] != [2]string{"http://192.168.1.37:8080", "http://192.168.1.41:8080"} {
		t.Fatalf("moves = %v, want exactly one", moves)
	}
}
