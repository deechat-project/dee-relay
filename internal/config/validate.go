package config

import (
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"
)

// This package had no validation pass at all until replication shipped: every value fell back
// silently, and a mesh that was configured wrongly ran, logged a warning into a
// volatile journal, and replicated nothing while /health still said
// meshEnabled=true. Every rule below exists because a specific misconfiguration
// was accepted by an earlier build.
//
// Validate returns every problem it finds rather than the first, because an
// operator editing one env file should not have to reboot once per mistake.
func (c Config) Validate() []error {
	var errs []error

	// DEE_NODE_TRUSTED_NODES was the original peer list. It named PUBLIC relay URLs
	// and doubled as the gossip seed. Both meanings are gone, and a silently
	// ignored value here would produce the exact failure this pass is about:
	// a pool that believes it replicates and does not.
	if legacy := strings.TrimSpace(os.Getenv("DEE_NODE_TRUSTED_NODES")); legacy != "" {
		errs = append(errs, fmt.Errorf(
			"DEE_NODE_TRUSTED_NODES is no longer read: rename it to DEE_NODE_MESH_PEERS and give it PEERING urls (the private address the other relays serve /mesh/* on), not public ones"))
	}

	if c.MeshSecret != "" && c.MeshAddr == "" {
		errs = append(errs, fmt.Errorf(
			"DEE_NODE_MESH_SECRET is set but DEE_NODE_MESH_ADDR is not: /mesh/* is never served on the public listener, so replication has nowhere to listen"))
	}
	if c.MeshAddr != "" && c.MeshSecret == "" {
		errs = append(errs, fmt.Errorf(
			"DEE_NODE_MESH_ADDR is set but DEE_NODE_MESH_SECRET is not: the mesh listener would serve no routes"))
	}
	if len(c.MeshPeers) > 0 && c.MeshSecret == "" {
		errs = append(errs, fmt.Errorf(
			"DEE_NODE_MESH_PEERS is set but DEE_NODE_MESH_SECRET is not: replication is off, so the peers would never be contacted"))
	}

	if c.MeshAddr != "" {
		errs = append(errs, validateMeshAddr(c.MeshAddr)...)
	}

	seen := map[string]bool{}
	for _, peer := range c.MeshPeers {
		if seen[peer] {
			errs = append(errs, fmt.Errorf("DEE_NODE_MESH_PEERS lists %s twice: it would be synced twice per tick", peer))
			continue
		}
		seen[peer] = true
		errs = append(errs, validatePeerURL(peer)...)
	}
	if c.PublicURL != "" && seen[strings.TrimRight(c.PublicURL, "/")] {
		errs = append(errs, fmt.Errorf(
			"DEE_NODE_MESH_PEERS contains this node's own DEE_NODE_PUBLIC_URL (%s): a peering url is the private address a peer serves /mesh/* on, and a node does not replicate with itself", c.PublicURL))
	}

	// The ack lane is split: everything above MaxMessages is the budget
	// caller-posted acks may occupy, and the rest is reserved for the node's own
	// coupled node_received acks, so a flood of junk acks cannot refuse a
	// POST /messages. MaxAcks <= MaxMessages makes that external budget zero or
	// negative, which would refuse every legitimate delivery and read ack on the
	// box. Refusing the boot is the closed failure mode a safety switch has to
	// have: the alternative is a relay that accepts mail and never acknowledges
	// it, which looks like a broken client for as long as nobody looks.
	//
	// Guarded on both being set because a Config assembled in code may leave a
	// cap at zero and mean "the store's default", and NewStore resolves that
	// pair safely; FromEnv never produces a non-positive cap, so every real
	// deployment reaches the check.
	if c.MaxAcks > 0 && c.MaxMessages > 0 && c.MaxAcks <= c.MaxMessages {
		errs = append(errs, fmt.Errorf(
			"DEE_NODE_MAX_ACKS (%d) must be greater than DEE_NODE_MAX_MESSAGES (%d): the ack lane above the message cap is the budget for client-posted acks, and at this setting there is none, so the relay would refuse every delivery and read ack", c.MaxAcks, c.MaxMessages))
	}

	// An enforcing relay with no credential file admits nobody, which is a
	// deployment that looks configured and serves no one. The counterpart check —
	// a file that loads zero credentials — is in main, where the file has been
	// read. Both refuse the boot rather than warn, for the same reason every
	// other rule here does.
	if c.RequireAdmission && c.AdmissionFile == "" {
		errs = append(errs, fmt.Errorf(
			"DEE_NODE_REQUIRE_ADMISSION is on but DEE_NODE_ADMISSION_FILE is unset: the relay would refuse every circle, including the operator's own"))
	}

	return errs
}

// validateMeshAddr refuses a mesh listener that is not demonstrably private.
//
// The public listener's protection for /mesh/* is that the routes are not
// mounted on it. The mesh listener's protection is that nothing on the internet
// can reach the address it binds — so a wildcard bind, which is the default
// shape of every other address in this file, would quietly undo the whole
// arrangement and leave a replication port open to the world with only the
// shared secret in front of it.
func validateMeshAddr(addr string) []error {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return []error{fmt.Errorf("DEE_NODE_MESH_ADDR %q is not host:port: %w", addr, err)}
	}
	if port == "" {
		return []error{fmt.Errorf("DEE_NODE_MESH_ADDR %q has no port", addr)}
	}
	if host == "" {
		return []error{fmt.Errorf(
			"DEE_NODE_MESH_ADDR %q binds every interface: give it the private address the other relays reach this node on (WireGuard, Tailscale, or a provider private network)", addr)}
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return []error{fmt.Errorf(
			"DEE_NODE_MESH_ADDR %q must be an IP address, not a name: the check that this listener is not internet-facing cannot be made on a name that resolves at boot and changes later", addr)}
	}
	if ip.IsUnspecified() {
		return []error{fmt.Errorf(
			"DEE_NODE_MESH_ADDR %q binds every interface: give it the private address the other relays reach this node on", addr)}
	}
	if !isPrivateIP(ip) {
		return []error{fmt.Errorf(
			"DEE_NODE_MESH_ADDR %q is a public address: the mesh listener serves every identity's queued records to anyone holding the pool secret, so it belongs on a private interface", addr)}
	}
	return nil
}

// validatePeerURL refuses a peering url that would put the pool secret on the
// wire in the clear. The secret travels as a request header on every sync, so
// `http://relay-2.example.org` leaks it to the first hop — and a plain `http`
// scheme against a public host is exactly what a reverse proxy's own
// http-to-https redirect looks like on the way in.
func validatePeerURL(raw string) []error {
	parsed, err := url.Parse(raw)
	if err != nil {
		return []error{fmt.Errorf("DEE_NODE_MESH_PEERS entry %q is not a url: %w", raw, err)}
	}
	if parsed.Host == "" {
		return []error{fmt.Errorf("DEE_NODE_MESH_PEERS entry %q has no host; it must be an absolute url", raw)}
	}
	switch parsed.Scheme {
	case "https":
		return nil
	case "http":
		host := parsed.Hostname()
		ip := net.ParseIP(host)
		if ip != nil && isPrivateIP(ip) {
			return nil
		}
		if host == "localhost" {
			return nil
		}
		return []error{fmt.Errorf(
			"DEE_NODE_MESH_PEERS entry %q is plain http to a host that is not demonstrably private: the pool secret is a request header, so this would put it on the wire in the clear. Use https, or a private peering address", raw)}
	default:
		return []error{fmt.Errorf("DEE_NODE_MESH_PEERS entry %q must be http or https, not %q", raw, parsed.Scheme)}
	}
}

// isPrivateIP covers loopback, RFC1918/ULA (net.IP.IsPrivate), link-local, and
// the 100.64.0.0/10 shared address space — the last because Tailscale hands out
// addresses from it, and a Tailscale interface is one of the two peering paths
// the deploy docs describe.
func isPrivateIP(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() {
		return true
	}
	return cgnat.Contains(ip)
}

var _, cgnat, _ = net.ParseCIDR("100.64.0.0/10")
