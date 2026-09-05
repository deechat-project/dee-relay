// Package peer holds the pool roster: who this relay replicates with, and how
// that has been going.
//
// It used to be a *registry* — a map of nodes that grew from what peers said
// about each other in their /nodes responses. That design had two failures, both
// reproduced on a three-relay loopback pool before this rewrite:
//
//   - A peer could name a new trusted node, and the next tick sent that host the
//     pool secret and a full queue snapshot. The victim then republished the
//     attacker's url on its own unauthenticated /nodes, so one member's response
//     spread through the whole pool.
//   - Bootstrap entries were keyed by url and merged entries by node id, so three
//     relays produced six roster entries and every peer was synced twice per
//     tick.
//
// So the roster is now exactly what the operator configured, gossip is gone, and
// nothing a peer says can add a sync target. Dynamic membership is a federation
// question — who may join, Sybil resistance — and that design does not exist
// yet; until it does, a peer's own opinion about the pool is not evidence.
package peer

import (
	"sync"
	"time"

	"deechat/chat-node/internal/model"
)

// Pool is the configured set of peering urls plus the outcome of the last sync
// with each. The urls are private peering addresses, so they are deliberately
// not reachable through any public handler — see Health for what is published.
type Pool struct {
	mu sync.RWMutex

	selfID  string
	selfURL *selfAddress
	peers   []string
	status  map[string]*Status
}

// Status is per-peer replication state. ClaimedID is what the peer said its node
// id was in the snapshot it served: useful in a log line, never used to decide
// anything. The pool secret is what authorizes a peer, and it is shared, so a
// claimed id proves only that some pool member answered.
type Status struct {
	URL                 string
	ClaimedID           string
	LastSuccessAt       time.Time
	LastAttemptAt       time.Time
	LastError           string
	ConsecutiveFailures int
}

// Health is the publishable summary: counts and staleness, never urls. It goes
// on /health, which is internet-facing, because monitoring has to be able to
// assert that replication is *working* — the failure mode that made this
// necessary was a pool that
// reported meshEnabled=true while every sync had returned 404 for an hour, and
// nothing an operator could poll would have said so.
type Health struct {
	Peers int `json:"peers"`
	// Reachable counts peers whose last attempt succeeded.
	Reachable int `json:"reachable"`
	// OldestSyncAgeSec is how long ago the *least recently* synced peer last
	// succeeded, so one dead peer out of two cannot hide behind a healthy one.
	// -1 means at least one peer has never synced successfully since boot.
	OldestSyncAgeSec int `json:"oldestSyncAgeSec"`
}

func NewPool(selfID, selfURL string, peerURLs []string) *Pool {
	pool := &Pool{
		selfID:  selfID,
		selfURL: newSelfAddress(selfURL),
		status:  make(map[string]*Status, len(peerURLs)),
	}
	for _, url := range peerURLs {
		if url == "" || pool.status[url] != nil {
			continue
		}
		pool.peers = append(pool.peers, url)
		pool.status[url] = &Status{URL: url}
	}
	return pool
}

// Self is what this node publishes about itself. A relay knows its own public
// url and no other member's — the peering urls are private, and the public urls
// of the rest of the pool are the client's configuration, not the relay's.
//
// The url is re-derived here rather than read from a field: see selfAddress for
// why a LAN node that outlives its own IP is a silent delivery failure.
func (p *Pool) Self() model.NodeInfo {
	advertised, _ := p.selfURL.resolve()
	return model.NodeInfo{
		ID:        p.selfID,
		URL:       advertised,
		LastSeen:  time.Now().UTC(),
		Trusted:   true,
		Reachable: true,
	}
}

// RefreshSelfURL re-derives the advertised url on a schedule rather than waiting
// for a caller. /nodes is what publishes it, and a node nobody polls would
// otherwise not notice it had moved until the first request after the move —
// which is exactly the request that has to already be answerable. Reports
// whether the address changed, so the move gets a log line.
func (p *Pool) RefreshSelfURL() (string, bool) {
	return p.selfURL.resolve()
}

// OnSelfURLChange registers the log hook for a re-derived address. Set once,
// before the pool is serving.
func (p *Pool) OnSelfURLChange(fn func(previous, current string)) {
	p.selfURL.mu.Lock()
	defer p.selfURL.mu.Unlock()
	p.selfURL.onChange = fn
}

// Targets is the sync list, in configured order.
func (p *Pool) Targets() []string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	targets := make([]string, len(p.peers))
	copy(targets, p.peers)
	return targets
}

func (p *Pool) RecordSuccess(url, claimedID string, now time.Time) {
	p.mu.Lock()
	defer p.mu.Unlock()
	status := p.status[url]
	if status == nil {
		return
	}
	status.ClaimedID = claimedID
	status.LastAttemptAt = now.UTC()
	status.LastSuccessAt = now.UTC()
	status.LastError = ""
	status.ConsecutiveFailures = 0
}

func (p *Pool) RecordFailure(url string, err error, now time.Time) {
	p.mu.Lock()
	defer p.mu.Unlock()
	status := p.status[url]
	if status == nil {
		return
	}
	status.LastAttemptAt = now.UTC()
	if err != nil {
		status.LastError = err.Error()
	}
	status.ConsecutiveFailures++
}

func (p *Pool) Health(now time.Time) Health {
	p.mu.RLock()
	defer p.mu.RUnlock()

	health := Health{Peers: len(p.peers), OldestSyncAgeSec: -1}
	oldest := -1
	for _, url := range p.peers {
		status := p.status[url]
		if status.ConsecutiveFailures == 0 && !status.LastSuccessAt.IsZero() {
			health.Reachable++
		}
		if status.LastSuccessAt.IsZero() {
			oldest = -1
			break
		}
		// Clamped at zero: if the clock stepped backwards since the sync, "just
		// now" is the honest answer, and -1 has to keep meaning "never".
		age := int(now.UTC().Sub(status.LastSuccessAt).Seconds())
		if age < 0 {
			age = 0
		}
		if age > oldest {
			oldest = age
		}
	}
	health.OldestSyncAgeSec = oldest
	return health
}

// Statuses is for logs and tests. It carries peering urls, so it must not reach
// a response body.
func (p *Pool) Statuses() []Status {
	p.mu.RLock()
	defer p.mu.RUnlock()
	out := make([]Status, 0, len(p.peers))
	for _, url := range p.peers {
		out = append(out, *p.status[url])
	}
	return out
}
