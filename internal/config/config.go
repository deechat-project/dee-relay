package config

import (
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	NodeID    string
	Addr      string
	PublicURL string

	// MeshAddr is the listener that serves /mesh/*, and it is a *second* listener
	// on purpose. Replication has to be reachable by the other relays while
	// staying unreachable from the internet, and those two requirements cannot
	// both be met on the public port: a peer reaching us at PublicURL arrives
	// through the reverse proxy, which returns 404 for /mesh/*. So
	// the mesh gets its own address on the private interface — WireGuard,
	// Tailscale, or a provider private network — and the public mux never mounts
	// a mesh route at all. Validate refuses a wildcard or public bind here.
	MeshAddr string
	// MeshPeers are the peering URLs of the other pool members: the ONLY hosts
	// this node will send its snapshot request, and the pool secret, to. They come
	// from local configuration and never from the wire. A peer used to be able to
	// name new trusted peers in its /nodes response, which handed the pool secret
	// and every queue to a host the operator never configured.
	MeshPeers       []string
	MeshSecret      string
	MaxMessages     int
	MaxAcks         int
	MaxPurges       int
	MaxPerPair      int
	MaxPayloadBytes int
	MaxTTL          time.Duration
	MaxChunkBytes   int

	// MaxAttachmentBytes is the largest whole attachment this relay will carry,
	// summed over a transfer's chunks. Unlike every other cap here it is also
	// *published* on /health, because the client cannot otherwise know it: the
	// send guard used to be a literal 50 MB compiled into the app, so a relay
	// configured to carry more could not be sold and a relay configured to carry
	// less rejected the file only after the user had waited for the push.
	//
	// The name was documented once before, as a phantom (see
	// env_documentation_test.go). It is real now, and enforced in
	// attachment.Relay rather than only advertised — an advertised ceiling
	// nothing checks is the same phantom wearing the opposite hat.
	//
	// The default matches the ceiling the app used to hardcode, so an existing
	// deployment that sets nothing behaves exactly as it did.
	MaxAttachmentBytes int
	RelayMaxWindow     int
	RelayMaxSessions   int
	RelayIdleTimeout   time.Duration
	RelayPollTimeout   time.Duration

	// BodyReadTimeout bounds how long a handler will wait for a request body
	// after the headers have arrived. Without it a client that sends headers and
	// then stops — a crash, a dropped link, or an HTTP client whose own timeout
	// fired and abandoned the request without closing the socket — parks a
	// goroutine and its connection in the body reader for the life of the
	// process. That is not hypothetical: it wedged a relay for four hours while
	// GET traffic on fresh connections kept answering 200, so nothing outside
	// the box looked wrong. Only bodies are bounded, so the long-poll on
	// GET /attachments/chunks (RelayPollTimeout) is untouched.
	BodyReadTimeout time.Duration

	// IdleTimeout closes a kept-alive connection that is not being used between
	// requests. Go's default is no limit, which means a client that leaks a
	// connection per abandoned request — as dart:io's HttpClient does on a
	// timeout — accumulates them on the relay until the process restarts.
	IdleTimeout        time.Duration
	DefaultTTL         time.Duration
	CleanupInterval    time.Duration
	MeshSyncInterval   time.Duration
	MeshRequestTimeout time.Duration
	PrekeyClaimBurst   int
	PrekeyClaimRefill  time.Duration

	// MaxPrekeyBuckets is the ceiling on the number of one-time-prekey pools
	// this relay holds — one pool per publishing device. It exists because it
	// was the one store with no cap of its own: prekey.Store bounded the keys
	// per pool and nothing bounded the pools, so a caller publishing under a
	// fresh recipient id each time grew the map until the host died, and
	// deploy/memory-ceiling.sh had to say in as many words that it could not
	// count that term. A pool at the ceiling refuses a *new* pool rather than
	// evicting one, so a relay at capacity keeps serving the recipients it
	// already carries.
	MaxPrekeyBuckets int

	// RequireFetchAuth makes a queue-read capability mandatory on GET /messages
	// and GET /acks, and rejects posts that carry no read-authorization tag.
	// Default false during client rollout: a tagged record is withheld without
	// proof either way, so this only decides whether *untagged* records — those
	// from clients predating fetch auth — are still served. See the README,
	// § "Queue-read authorization".
	RequireFetchAuth bool

	// AdmissionFile is the operator's credential file: which circles this relay
	// carries mail for, and on what terms. Unset means none, which means the box
	// serves everyone at its own caps — the free self-hosted path, and it must
	// stay exactly that generous.
	//
	// It is read, never written. The issuance tool owns the file; the relay only
	// loads it, at boot and on SIGHUP.
	AdmissionFile string

	// RequireAdmission refuses every gated route to a caller that has not proved
	// a credential. Default false, and the two off-states are different: with no
	// credential file the box is simply open, and with one loaded but this off,
	// an admitted circle gets its terms while everyone else still gets box caps —
	// the rollout shape RequireFetchAuth uses.
	//
	// Because "no credentials configured" has to mean *open* here, the enforcing
	// case needs a switch that cannot fail silently: it is published on /health,
	// and the node refuses to boot when it is on with nothing loaded. A box meant
	// to be gated that runs open looks identical from the outside, which is how a
	// relay ends up serving everyone for free without anyone noticing.
	RequireAdmission bool
}

// MeshEnabled reports whether this node will speak mesh replication at all.
// Without a shared secret the /mesh/* routes are not mounted and the syncer
// does not run: the endpoints hand out every identity's queued records, so
// "no credential configured" has to mean "closed", never "open to anyone".
func (c Config) MeshEnabled() bool { return c.MeshSecret != "" }

func FromEnv() Config {
	maxMessages := envInt("DEE_NODE_MAX_MESSAGES", 1000)
	// Each accepted message couples a node_received ack, and terminal
	// (delivered/read) acks must outlive the resend window so they keep
	// suppressing re-imports — so the ack store is sized to 2× the message
	// store by default. An explicit DEE_NODE_MAX_ACKS still overrides this.
	return Config{
		NodeID:             envString("DEE_NODE_ID", "local-node"),
		Addr:               envString("DEE_NODE_ADDR", ":8080"),
		PublicURL:          envString("DEE_NODE_PUBLIC_URL", "http://localhost:8080"),
		MeshAddr:           envString("DEE_NODE_MESH_ADDR", ""),
		MeshPeers:          envCSV("DEE_NODE_MESH_PEERS"),
		MeshSecret:         envString("DEE_NODE_MESH_SECRET", ""),
		MaxMessages:        maxMessages,
		MaxAcks:            envInt("DEE_NODE_MAX_ACKS", 2*maxMessages),
		MaxPurges:          envInt("DEE_NODE_MAX_PURGES", 1000),
		MaxPerPair:         envInt("DEE_NODE_MAX_PER_PAIR", 10),
		MaxPayloadBytes:    envInt("DEE_NODE_MAX_PAYLOAD_BYTES", 8192),
		MaxTTL:             envDuration("DEE_NODE_MAX_TTL", 72*time.Hour),
		MaxChunkBytes:      envInt("DEE_NODE_MAX_CHUNK_BYTES", 1024*1024),
		MaxAttachmentBytes: envInt("DEE_NODE_MAX_ATTACHMENT_BYTES", 50*1024*1024),
		RelayMaxWindow:     envInt("DEE_NODE_RELAY_MAX_WINDOW", 8),
		RelayMaxSessions:   envInt("DEE_NODE_RELAY_MAX_SESSIONS", 256),
		RelayIdleTimeout:   envDuration("DEE_NODE_RELAY_IDLE_TIMEOUT", 30*time.Second),
		RelayPollTimeout:   envDuration("DEE_NODE_RELAY_POLL_TIMEOUT", 25*time.Second),
		// Well above the slowest legitimate body (a 1 MB chunk push over a poor
		// link) and well below the hours a parked reader used to hold.
		BodyReadTimeout:    envDuration("DEE_NODE_BODY_READ_TIMEOUT", 20*time.Second),
		IdleTimeout:        envDuration("DEE_NODE_IDLE_TIMEOUT", 120*time.Second),
		DefaultTTL:         envDuration("DEE_NODE_DEFAULT_TTL", 24*time.Hour),
		CleanupInterval:    envDuration("DEE_NODE_CLEANUP_INTERVAL", 30*time.Second),
		MeshSyncInterval:   envDuration("DEE_NODE_MESH_SYNC_INTERVAL", 30*time.Second),
		MeshRequestTimeout: envDuration("DEE_NODE_MESH_REQUEST_TIMEOUT", 5*time.Second),
		PrekeyClaimBurst:   envInt("DEE_NODE_PREKEY_CLAIM_BURST", 32),
		PrekeyClaimRefill:  envDuration("DEE_NODE_PREKEY_CLAIM_REFILL", time.Second),
		// 5000 device pools, the same order as the presence store's fixed 5000
		// identities: both are sized off "how many identities does one box
		// serve", not off how much mail they send.
		MaxPrekeyBuckets: envInt("DEE_NODE_MAX_PREKEY_BUCKETS", 5000),
		RequireFetchAuth: envBool("DEE_NODE_REQUIRE_FETCH_AUTH", false),
		AdmissionFile:    envString("DEE_NODE_ADMISSION_FILE", ""),
		RequireAdmission: envBool("DEE_NODE_REQUIRE_ADMISSION", false),
	}
}

func envString(key, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(key)); value != "" {
		return value
	}
	return fallback
}

func envInt(key string, fallback int) int {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed <= 0 {
		return fallback
	}
	return parsed
}

// envBool reads a flag. Anything unparseable falls back rather than failing the
// boot — but note the asymmetry: for a security switch, falling back to the
// permissive default on a typo is the wrong failure. Deployments that mean to
// enforce should assert the setting from /health, not from the absence of a boot
// error.
func envBool(key string, fallback bool) bool {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	parsed, err := strconv.ParseBool(value)
	if err != nil {
		return fallback
	}
	return parsed
}

func envDuration(key string, fallback time.Duration) time.Duration {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	parsed, err := time.ParseDuration(value)
	if err != nil || parsed <= 0 {
		return fallback
	}
	return parsed
}

func envCSV(key string) []string {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return nil
	}
	parts := strings.Split(value, ",")
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		trimmed := strings.TrimSpace(part)
		if trimmed != "" {
			result = append(result, trimmed)
		}
	}
	return result
}
