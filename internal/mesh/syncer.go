package mesh

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"deechat/chat-node/internal/config"
	"deechat/chat-node/internal/model"
	"deechat/chat-node/internal/peer"
	"deechat/chat-node/internal/presence"
	"deechat/chat-node/internal/queue"
)

// Replication is pull-only, and that is a decision rather than an omission.
//
// The original syncer both pulled a peer's snapshot and pushed its own to
// POST /mesh/sync. Push cannot be paged: the pusher does not know which records
// the peer is missing, so it either sends the same bounded prefix forever (which
// is what happened — a relay holding more than one page never replicated past it)
// or walks its whole queue on every tick. The puller does know, because it knows
// what it has already imported, so paging belongs on the pull side and the push
// side has nothing left to do that a peer's own pull does not do better.
//
// Removing it also removes the pool's only write endpoint: a member serves its
// own snapshot to a peer that chose to pull it, and there is nothing to post to.
//
// What that does not mean is that a pulled snapshot is checked. It is not, and it
// cannot usefully be: queue.Store.ImportSnapshot injects a peer's envelopes, applies
// its acks — five of the six ack types delete the queued message they name — and
// runs its purge tombstones, which delete a third party's queued mail. Pulling a
// peer is trusting it with these queues, which is what replication is. See
// deploy/README.md, "What a pool member is trusted with", for the full statement.
const (
	// pagesPerSync bounds one tick. At the 500-record page size that is 10k
	// records, the default DEE_NODE_MAX_MESSAGES — enough to drain a full peer in
	// one tick, and a hard stop if a peer ever serves a cursor that does not
	// advance.
	pagesPerSync = 20
	pageSize     = 500
)

// A snapshot page is bounded before it is read, for the same reason a request
// body is (internal/httpapi/body_limit.go): the peer's answer is decoded into
// memory before anything about it is checked, and this relay's MemoryMax is
// derived from its record caps. The server-side half of that middleware covers
// what arrives on the listener; the pull is the one direction it never saw,
// because the client here is ours and the body is a peer's. pagesPerSync and
// pageSize bound the records we *ask* for, never the bytes we are handed — a
// hostile or simply broken peer answering GET /mesh/snapshot with an endless
// body drove the puller's memory with nothing to stop it.
//
// The ceiling is derived from this node's own caps rather than exposed as a
// knob, again mirroring body_limit.go, and the slack figures are the deliberate
// over-estimates deploy/memory-ceiling.sh uses for the same records. What that
// costs is stated rather than hidden: a peer configured with caps far larger
// than this node's serves pages this node will refuse. That is the honest
// failure — the alternative is accepting an unbounded body from it — and it is
// visible as a sync error rather than as a dead host.
const (
	// snapshotRecordSlack is the JSON around one record's payload: ids, tags,
	// timestamps, a signature and the field names.
	snapshotRecordSlack = 2 << 10

	// snapshotPresenceRecords is the presence table's fixed capacity, counted
	// twice because a page carries the peer's whole heartbeat table *and* its
	// whole revocation table. The 5000 is the constant cmd/dee-relay/main.go
	// passes to presence.NewStore, not an env var; if it moves, this moves with
	// it — the same standing obligation deploy/memory-ceiling.sh carries.
	snapshotPresenceRecords = 2 * 5000
	snapshotPresenceSlack   = 1 << 10

	// snapshotPurgeSlack is one tombstone: a hash and an expiry. Tombstones ride
	// on every page, capped at the peer's DEE_NODE_MAX_PURGES.
	snapshotPurgeSlack = 1 << 10
)

// maxSnapshotBytes is the largest page body this node will read from a peer.
// Zero-value fallbacks mirror the ones queue.NewStore applies to the same
// fields, so a Config built by hand rather than by config.Load does not get a
// ceiling tighter than the records a peer may legitimately serve.
func (s *Syncer) maxSnapshotBytes() int64 {
	payloadBytes := s.cfg.MaxPayloadBytes
	if payloadBytes <= 0 {
		payloadBytes = 8192
	}
	purges := s.cfg.MaxPurges
	if purges <= 0 {
		purges = 1000
	}
	return int64(pageSize)*int64(payloadBytes+snapshotRecordSlack) +
		int64(purges)*snapshotPurgeSlack +
		snapshotPresenceRecords*snapshotPresenceSlack
}

type Syncer struct {
	cfg      config.Config
	store    *queue.Store
	pool     *peer.Pool
	presence *presence.Store
	client   *http.Client

	// cursors is the per-peer high-water mark, keyed by peering url, with the
	// epoch it belongs to. A peer restart clears its queues, so a cursor kept
	// across one would page from a mark that no longer exists.
	//
	// Guarded because SyncPeer is exported: the node's own ticker calls SyncAll
	// from one goroutine, but a caller (a test, an admin trigger) may not.
	cursorsMu sync.Mutex
	cursors   map[string]cursor
}

func (s *Syncer) cursorFor(peerURL string) cursor {
	s.cursorsMu.Lock()
	defer s.cursorsMu.Unlock()
	return s.cursors[peerURL]
}

func (s *Syncer) setCursor(peerURL string, value cursor) {
	s.cursorsMu.Lock()
	defer s.cursorsMu.Unlock()
	s.cursors[peerURL] = value
}

type cursor struct {
	epoch string
	seq   uint64
}

type PeerSyncResult struct {
	PeerURL          string
	Pages            int
	PulledMessages   int
	PulledAcks       int
	AcceptedMessages int
	AcceptedAcks     int
}

func NewSyncer(cfg config.Config, store *queue.Store, pool *peer.Pool, presenceStores ...*presence.Store) *Syncer {
	timeout := cfg.MeshRequestTimeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	p := presence.NewStore(5000, 24*time.Hour, time.Now)
	if len(presenceStores) > 0 && presenceStores[0] != nil {
		p = presenceStores[0]
	}
	return &Syncer{
		cfg:      cfg,
		store:    store,
		pool:     pool,
		presence: p,
		cursors:  make(map[string]cursor),
		client: &http.Client{
			Timeout: timeout,
			// A redirect is refused rather than followed. Go copies custom headers
			// onto the redirected request, and the pool secret is a custom header:
			// a peer answering 302 — a compromised member, or a proxy someone
			// pointed at the wrong host — would otherwise hand the credential to
			// whatever host it named. Verified against a stand-in peer before this
			// was added; the secret arrived at the redirect target in full.
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return errors.New("peer answered with a redirect; refusing to forward the pool secret")
			},
		},
	}
}

func (s *Syncer) SyncAll(ctx context.Context) []error {
	if !s.cfg.MeshEnabled() {
		return []error{errors.New("mesh sync needs DEE_NODE_MESH_SECRET; refusing to replicate unauthenticated")}
	}
	var errs []error
	for _, peerURL := range s.pool.Targets() {
		if _, err := s.SyncPeer(ctx, peerURL); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", peerURL, err))
			s.pool.RecordFailure(peerURL, err, time.Now())
		}
	}
	return errs
}

// SyncPeer pulls pages from one peer until it reports no more, importing each
// page as it arrives. A page that fails mid-run keeps what was already imported
// and leaves the cursor where the last good page put it, so the next tick resumes
// instead of starting over.
func (s *Syncer) SyncPeer(ctx context.Context, peerURL string) (PeerSyncResult, error) {
	result := PeerSyncResult{PeerURL: peerURL}
	claimedID := ""

	for page := 0; page < pagesPerSync; page++ {
		current := s.cursorFor(peerURL)
		payload, err := s.fetchSnapshot(ctx, peerURL, current.seq)
		if err != nil {
			return result, err
		}
		result.Pages++
		claimedID = payload.NodeID

		if payload.Epoch != current.epoch && current.epoch != "" && current.seq != 0 {
			// The peer restarted: its queues are empty and its sequence numbers
			// start again, so anything we still hold from it is ours to keep and
			// its cursor has to go back to zero. Re-reading from the start is the
			// correct response, not an error.
			s.setCursor(peerURL, cursor{epoch: payload.Epoch})
			continue
		}

		result.PulledMessages += len(payload.Messages)
		result.PulledAcks += len(payload.Acks)
		imported := s.store.ImportSnapshot(payload)
		s.presence.Import(payload.Presence)
		s.presence.ImportRevocations(payload.PresenceRevocations)
		result.AcceptedMessages += imported.AcceptedMessages
		result.AcceptedAcks += imported.AcceptedAcks

		// The cursor advances on the peer's reported mark, including when the page
		// was empty of records: an empty page still means "nothing new up to here".
		if payload.NextSeq >= current.seq {
			s.setCursor(peerURL, cursor{epoch: payload.Epoch, seq: payload.NextSeq})
		}
		if !payload.More {
			break
		}
		if payload.NextSeq <= current.seq {
			// More records claimed, but the cursor did not move. Stopping is the
			// only safe response; looping here would be an unbounded request storm
			// against a peer serving a broken or hostile page.
			return result, fmt.Errorf("peer reported more records but its cursor did not advance past %d", current.seq)
		}
	}

	s.pool.RecordSuccess(peerURL, claimedID, time.Now())
	return result, nil
}

func (s *Syncer) fetchSnapshot(ctx context.Context, baseURL string, since uint64) (model.SyncPayload, error) {
	target, err := snapshotURL(baseURL, since)
	if err != nil {
		return model.SyncPayload{}, err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return model.SyncPayload{}, err
	}
	request.Header.Set(model.MeshSecretHeader, s.cfg.MeshSecret)
	// The node id is sent so a peer can put a name in a log line. It authorizes
	// nothing — it used to be the entire credential, which the pool secret replaced.
	request.Header.Set("X-Dee-Node-ID", s.cfg.NodeID)

	response, err := s.client.Do(request)
	if err != nil {
		return model.SyncPayload{}, err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return model.SyncPayload{}, fmt.Errorf("GET /mesh/snapshot returned %d", response.StatusCode)
	}
	var payload model.SyncPayload
	limited := http.MaxBytesReader(nil, response.Body, s.maxSnapshotBytes())
	if err := json.NewDecoder(limited).Decode(&payload); err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			return model.SyncPayload{}, fmt.Errorf("peer's snapshot page ran past %d bytes; refusing to buffer it", tooLarge.Limit)
		}
		return model.SyncPayload{}, err
	}
	return payload, nil
}

func snapshotURL(baseURL string, since uint64) (string, error) {
	parsed, err := url.Parse(strings.TrimRight(baseURL, "/"))
	if err != nil {
		return "", err
	}
	if parsed.Host == "" {
		return "", fmt.Errorf("peer url %q has no host", baseURL)
	}
	parsed.Path = strings.TrimRight(parsed.Path, "/") + "/mesh/snapshot"
	query := parsed.Query()
	query.Set("limit", strconv.Itoa(pageSize))
	if since > 0 {
		query.Set("since", strconv.FormatUint(since, 10))
	}
	parsed.RawQuery = query.Encode()
	return parsed.String(), nil
}
