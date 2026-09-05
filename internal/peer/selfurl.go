package peer

import (
	"net"
	"net/url"
	"strings"
	"sync"
	"time"
)

// selfAddressRecheckInterval bounds how often a lookup of this host's own
// interface addresses runs. /nodes is unauthenticated and can be polled, and the
// address of a laptop does not change more than once per network hop, so the
// answer is cached between checks.
const selfAddressRecheckInterval = 15 * time.Second

// selfAddress is the url this relay advertises for itself, and the reason it is
// not simply the configured string.
//
// DEE_NODE_PUBLIC_URL is baked at launch — scripts/start-relay.sh fills it from
// `ipconfig getifaddr`, which is a snapshot of one interface at one moment. A
// laptop node that keeps running across a network change then advertises an
// address it no longer holds: it still answers on 0.0.0.0, so /health and
// presence look reachable, while every peer routes sends and acks to a dead host
// and messages fail with no error. Diagnosed live 2026-06-26 on a node with
// ~7 days of uptime advertising 192.168.1.37 from a host that had moved to .41;
// a restart "fixed" it, which is why it kept coming back.
//
// So the address is re-derived rather than baked. Narrowly, though: rewriting a
// configured url is exactly the kind of helpfulness that breaks a real
// deployment, where the public address is a domain, or an address that belongs
// to a proxy rather than to this box. Re-derivation is therefore latched at
// construction and only when the configured host is a literal IP that this
// machine itself holds — which is true of the LAN-node case and of nothing else.
// A hostname, a loopback url, or an address on some other host is published
// exactly as configured, forever.
type selfAddress struct {
	mu sync.Mutex

	// configured is the string as the operator set it, and is what a non-tracking
	// address always publishes.
	configured string
	// template is the parsed configured url, host stripped, used to rebuild the
	// published string around a new IP. Nil when not tracking.
	template *url.URL
	port     string

	tracking bool
	current  string
	// currentIP is the literal this url is built on, so a refresh can ask the
	// cheap question ("do we still hold it?") before picking a replacement.
	currentIP net.IP

	lastCheck time.Time
	// localIPs and now are injected in tests. Nothing else may replace them.
	localIPs func() []net.IP
	now      func() time.Time
	onChange func(previous, current string)
}

func newSelfAddress(configured string) *selfAddress {
	address := &selfAddress{
		configured: configured,
		current:    configured,
		localIPs:   hostAddresses,
		now:        time.Now,
	}
	address.latch()
	return address
}

// latch decides once, at construction, whether this url is one we may re-derive.
func (a *selfAddress) latch() {
	parsed, err := url.Parse(a.configured)
	if err != nil || parsed.Host == "" {
		return
	}
	host := parsed.Hostname()
	ip := net.ParseIP(host)
	if ip == nil || !usableHostIP(ip) {
		// A name (including localhost) resolves at use, so it cannot go stale the
		// way a baked literal does.
		return
	}
	if !containsIP(a.localIPs(), ip) {
		// The literal is not ours: a NAT address, a proxy, or a plain
		// misconfiguration. Either way this node is not the authority on what it
		// should become.
		return
	}
	a.template = parsed
	a.port = parsed.Port()
	a.tracking = true
	a.currentIP = ip
}

// resolve returns the url to publish, re-deriving it at most once per
// selfAddressRecheckInterval.
func (a *selfAddress) resolve() (published string, changed bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if !a.tracking {
		return a.configured, false
	}
	now := a.now()
	if !a.lastCheck.IsZero() && now.Sub(a.lastCheck) < selfAddressRecheckInterval {
		return a.current, false
	}
	a.lastCheck = now

	addresses := a.localIPs()
	if len(addresses) == 0 {
		// Every interface is down (asleep, or between networks). Republishing
		// nothing helps nobody; the last known address is the better guess, and
		// the next check is 15 s away.
		return a.current, false
	}
	if containsIP(addresses, a.currentIP) {
		return a.current, false
	}
	replacement := pickHostIP(addresses, a.currentIP)
	if replacement == nil {
		return a.current, false
	}

	previous := a.current
	rebuilt := *a.template
	rebuilt.Host = hostPort(replacement, a.port)
	a.current = rebuilt.String()
	a.currentIP = replacement
	if a.onChange != nil {
		a.onChange(previous, a.current)
	}
	return a.current, true
}

// pickHostIP chooses the address that replaces one this host has lost. Same
// family first, because a url built on an IPv4 literal that turns into an IPv6
// one is a different reachability question for every peer holding it.
func pickHostIP(addresses []net.IP, previous net.IP) net.IP {
	wantV4 := previous.To4() != nil
	for _, candidate := range addresses {
		if (candidate.To4() != nil) == wantV4 {
			return candidate
		}
	}
	return addresses[0]
}

// hostAddresses is this machine's own usable unicast addresses, in interface
// order — which is the order `ipconfig getifaddr en0` reads, so the first entry
// is normally the same address the launch script would have baked.
func hostAddresses() []net.IP {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	var addresses []net.IP
	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		candidates, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, candidate := range candidates {
			network, ok := candidate.(*net.IPNet)
			if !ok || !usableHostIP(network.IP) {
				continue
			}
			addresses = append(addresses, network.IP)
		}
	}
	return addresses
}

// usableHostIP excludes the addresses no peer can route to: loopback (a url only
// this box can use), link-local (v4 169.254/16 and v6 fe80::/10, which need a
// zone), multicast, and the unspecified address.
func usableHostIP(ip net.IP) bool {
	if ip == nil || ip.IsUnspecified() || ip.IsLoopback() || ip.IsMulticast() {
		return false
	}
	return !ip.IsLinkLocalUnicast()
}

func containsIP(addresses []net.IP, want net.IP) bool {
	for _, candidate := range addresses {
		if candidate.Equal(want) {
			return true
		}
	}
	return false
}

func hostPort(ip net.IP, port string) string {
	host := ip.String()
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	if port == "" {
		return host
	}
	return host + ":" + port
}
