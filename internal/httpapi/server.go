package httpapi

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"deechat/chat-node/internal/admission"
	"deechat/chat-node/internal/attachment"
	"deechat/chat-node/internal/config"
	"deechat/chat-node/internal/model"
	"deechat/chat-node/internal/peer"
	"deechat/chat-node/internal/prekey"
	"deechat/chat-node/internal/presence"
	"deechat/chat-node/internal/queue"
)

type Server struct {
	cfg         config.Config
	store       *queue.Store
	pool        *peer.Pool
	presence    *presence.Store
	attachments *attachment.Relay
	prekeys     *prekey.Store
	admissions  *admission.Store
	sessions    *admission.Sessions
	startedAt   time.Time
	mux         *http.ServeMux
	meshMux     *http.ServeMux
}

func NewServer(cfg config.Config, store *queue.Store, pool *peer.Pool, presenceStore ...*presence.Store) *Server {
	p := presence.NewStore(5000, 24*time.Hour, time.Now)
	if len(presenceStore) > 0 && presenceStore[0] != nil {
		p = presenceStore[0]
	}
	a := attachment.NewRelay(cfg.RelayMaxWindow, cfg.MaxChunkBytes, cfg.MaxAttachmentBytes, cfg.RelayMaxSessions, cfg.RelayIdleTimeout, time.Now)
	server := &Server{
		cfg:         cfg,
		store:       store,
		pool:        pool,
		presence:    p,
		attachments: a,
		prekeys:     prekey.NewStoreWithLimits(PrekeyLimits(cfg), time.Now),
		// An empty admission store is an open box, which is what a relay with no
		// credential file has to be: the free self-hosted path.
		admissions: admission.NewStore(),
		sessions:   admission.NewSessions(time.Now),
		startedAt:  time.Now().UTC(),
		mux:        http.NewServeMux(),
		meshMux:    http.NewServeMux(),
	}
	server.routes()
	return server
}

// PrekeyLimits sizes the prekey store from the operator's configuration.
//
// Exported because main.go builds the store for the running binary and hands it
// to NewServerWithStores, which uses it in place of the one NewServer built —
// so the two constructions have to agree. They did not: main's store was
// created with the package defaults, which is why DEE_NODE_PREKEY_CLAIM_BURST
// and DEE_NODE_PREKEY_CLAIM_REFILL were read from the environment, validated,
// and then dropped on the floor by every relay actually deployed.
func PrekeyLimits(cfg config.Config) prekey.Limits {
	return prekey.Limits{
		MaxBuckets:  cfg.MaxPrekeyBuckets,
		ClaimBurst:  cfg.PrekeyClaimBurst,
		ClaimRefill: cfg.PrekeyClaimRefill,
	}
}

func NewServerWithAttachments(cfg config.Config, store *queue.Store, pool *peer.Pool, presenceStore *presence.Store, attachmentRelay *attachment.Relay) *Server {
	return NewServerWithStores(cfg, store, pool, presenceStore, attachmentRelay, nil)
}

func NewServerWithStores(cfg config.Config, store *queue.Store, pool *peer.Pool, presenceStore *presence.Store, attachmentRelay *attachment.Relay, prekeyStore *prekey.Store) *Server {
	server := NewServer(cfg, store, pool, presenceStore)
	if attachmentRelay != nil {
		server.attachments = attachmentRelay
	}
	if prekeyStore != nil {
		server.prekeys = prekeyStore
	}
	return server
}

// WithAdmissions points the server at the operator's credential set. The store
// is shared rather than copied, so a SIGHUP reload in main takes effect on the
// next request without restarting a relay whose queues are RAM-only.
func (s *Server) WithAdmissions(credentials *admission.Store) *Server {
	if credentials != nil {
		s.admissions = credentials
	}
	return s
}

// Handler serves the public listener. It has no mesh route on it, at all, in any
// configuration — see routes.
func (s *Server) Handler() http.Handler {
	return s.limitBodies(s.mux)
}

// MeshHandler serves the private mesh listener (DEE_NODE_MESH_ADDR). It is
// separate from Handler because a peer has to be able to reach replication while
// the internet cannot, and the public listener sits behind a proxy that returns
// 404 for /mesh/* — the two requirements do not fit on one port.
//
// nil when no mesh secret is configured: with no credential there is nothing to
// listen for, and "unconfigured" has to mean closed.
func (s *Server) MeshHandler() http.Handler {
	if !s.cfg.MeshEnabled() {
		return nil
	}
	return s.limitBodies(s.meshMux)
}

func (s *Server) routes() {
	s.mux.HandleFunc("GET /health", s.handleHealth)
	s.mux.HandleFunc("GET /nodes", s.handleNodes)
	// The gate's own two routes are ungated, necessarily: the nonce is what a
	// client signs to get admitted, so it cannot itself require admission.
	s.mux.HandleFunc("POST /admission/challenge", s.handleAdmissionChallenge)
	s.mux.HandleFunc("POST /admission/redeem", s.handleAdmissionRedeem)
	s.mux.HandleFunc("POST /messages", s.handlePostMessage)
	s.mux.HandleFunc("GET /messages", s.handleGetMessages)
	s.mux.HandleFunc("POST /acks", s.handlePostAck)
	s.mux.HandleFunc("GET /acks", s.handleGetAcks)
	s.mux.HandleFunc("POST /presence/heartbeat", s.handlePresenceHeartbeat)
	s.mux.HandleFunc("POST /presence/query", s.handlePresenceQuery)
	s.mux.HandleFunc("POST /presence/revoke", s.handlePresenceRevoke)
	s.mux.HandleFunc("POST /profile/purge", s.handleProfilePurge)
	s.mux.HandleFunc("POST /prekeys", s.handlePublishPrekeys)
	s.mux.HandleFunc("GET /prekeys/claim", s.handleClaimPrekey)
	s.mux.HandleFunc("GET /prekeys/status", s.handlePrekeyStatus)
	s.mux.HandleFunc("POST /attachments/chunks", s.handlePostAttachmentChunk)
	s.mux.HandleFunc("GET /attachments/chunks", s.handleGetAttachmentChunks)
	s.mux.HandleFunc("POST /attachments/complete", s.handleCompleteAttachment)
	// Mesh replication is NOT mounted here. Not behind a flag, not behind the
	// secret — the public mux has no /mesh route in any configuration, so the
	// reverse proxy's 404 for /mesh/* is now backed by there being
	// nothing behind it to forward to.
	//
	// It lives on meshMux instead, served on the private DEE_NODE_MESH_ADDR, and
	// only when a shared secret is configured: with no credential there is nothing
	// to serve, because the failure mode of a security switch has to be closed.
	if s.cfg.MeshEnabled() {
		s.meshMux.HandleFunc("GET /mesh/snapshot", s.handleMeshSnapshot)
	}
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"status":      "ok",
		"nodeId":      s.cfg.NodeID,
		"uptimeSec":   int(time.Since(s.startedAt).Seconds()),
		"queues":      s.store.Stats(),
		"presence":    s.presence.Count(),
		"attachments": s.attachments.Stats(),
		// The one cap published as a *number* rather than as a boolean, because
		// the client sizes its own send guard from it: without this the app can
		// only fall back to a compiled-in constant, which is how a relay
		// configured to carry more than 50 MB stayed unsellable. Advertised and
		// enforced by the same field — see attachment.Relay.Push.
		"maxAttachmentBytes": s.attachments.MaxAttachmentBytes(),
		"prekeys":            s.prekeys.Count(),
		"prekeysLastResort":  s.prekeys.LastResortCount(),
		// Live pools against DEE_NODE_MAX_PREKEY_BUCKETS. Published because the
		// ceiling refuses new pools rather than evicting old ones: a box sitting
		// at its bucket cap is turning away new recipients, and nothing else
		// outside the process says so.
		"prekeyBuckets": s.prekeys.BucketCount(),
		// Published so a deployment can *assert* it is enforcing rather than
		// infer it from a clean boot — a typo in DEE_NODE_REQUIRE_FETCH_AUTH
		// otherwise fails open and silently.
		"requireFetchAuth": s.cfg.RequireFetchAuth,
		// Same reasoning, and here it is load-bearing: "no credentials
		// configured" MEANS open on this switch (it is the free self-hosted
		// path), so a box meant to be gated that runs open is invisible from the
		// outside without this. The node also refuses to boot when it is on with
		// nothing loaded, so a live relay publishing true is admitting somebody.
		//
		// The switch and nothing else. Not the credential count — how many
		// circles a box carries is not an unauthenticated endpoint's business —
		// and no per-credential value: terms come back from the admission
		// exchange, to the circle they belong to.
		"requireAdmission": s.cfg.RequireAdmission,
		// Whether replication is configured at all. Never the secret itself — this
		// is the endpoint that used to leak the mesh credential.
		"meshEnabled": s.cfg.MeshEnabled(),
		// Counts and staleness, never peering urls: enough for monitoring to assert
		// that replication is *working*, not just switched on. An earlier build let a pool
		// whose every sync had returned 404 for an hour published exactly the same
		// /health as a healthy one, and monitor.sh reported it green.
		"mesh": s.pool.Health(time.Now()),
	})
}

func (s *Server) handlePostAttachmentChunk(w http.ResponseWriter, r *http.Request) {
	grant, admitted := s.admit(w, r)
	if !admitted {
		return
	}
	var chunk attachment.Chunk
	if err := decodeJSON(r, &chunk); err != nil {
		writeDecodeError(w, err, "invalid_json", err.Error())
		return
	}
	switch err := s.attachments.PushWithGrant(chunk, attachmentGrant(grant)); {
	case err == nil:
		writeJSON(w, http.StatusAccepted, map[string]any{"accepted": true, "duplicate": false})
	case errors.Is(err, attachment.ErrDuplicate):
		writeJSON(w, http.StatusOK, map[string]any{"accepted": true, "duplicate": true})
	case errors.Is(err, attachment.ErrWindowFull):
		// Back-pressure: the recipient has not drained the in-flight window yet.
		// The sender must wait and retry — the node never buffers the whole file.
		writeError(w, http.StatusTooManyRequests, "window_full", "relay window is full; recipient has not drained, back off and retry")
	case errors.Is(err, attachment.ErrTooManySessions):
		writeError(w, http.StatusTooManyRequests, "relay_busy", "too many concurrent live transfers; retry shortly")
	case errors.Is(err, attachment.ErrTooLarge):
		// 413, not 429: retrying will not help, and the sender must fail the
		// transfer rather than back off. The ceiling is on /health, so a client
		// that reads it never reaches this branch — unless its circle's terms
		// name a lower one, which come back from the admission exchange.
		writeError(w, http.StatusRequestEntityTooLarge, "attachment_too_large", "attachment exceeds this relay's size ceiling; see maxAttachmentBytes on /health and the terms granted at admission")
	case errors.Is(err, attachment.ErrTooManyChunks):
		// 413 for the same reason as the branch above — retrying will not help —
		// but its own code, because the remedy is different: the sender is not
		// over the byte ceiling, it has sliced the file more finely than this
		// relay will track, and the fix is larger chunks rather than a smaller
		// file. No client that uses the app's chunk size can reach it.
		writeError(w, http.StatusRequestEntityTooLarge, "chunk_count_too_high", "attachment is split into more chunks than this relay carries; send larger chunks")
	case errors.Is(err, attachment.ErrTransitExhausted):
		// 429, but not the same 429 as the two above: this one does not clear in
		// seconds. The window is rolling, so the sender is told to stop rather
		// than to back off — a client that treats it as ordinary back-pressure
		// would retry uselessly for hours.
		writeError(w, http.StatusTooManyRequests, "transit_exhausted", "this circle has spent its daily transit ceiling; it recovers over the next 24 hours")
	default:
		writeError(w, http.StatusBadRequest, "invalid_attachment_chunk", "attachment chunk is invalid")
	}
}

// handleGetAttachmentChunks long-polls for the next slice of the recipient's
// live transfer. With no stored backlog, the recipient parks here until the
// sender pushes (up to the configured poll timeout) or the request is cancelled,
// then drains the bounded window in one shot — freeing it for the next push.
func (s *Server) handleGetAttachmentChunks(w http.ResponseWriter, r *http.Request) {
	// Admission is checked before the long poll parks, not while it is parked. A
	// drain that is already waiting when its circle's window ends finishes and
	// returns what it has; the next poll is refused, which is the same
	// granularity every other route has.
	if _, admitted := s.admit(w, r); !admitted {
		return
	}
	recipient := r.URL.Query().Get("recipient")
	capability := r.URL.Query().Get("capability")
	if recipient == "" || capability == "" {
		writeError(w, http.StatusBadRequest, "missing_attachment_route", "recipient and capability are required")
		return
	}

	wait := s.cfg.RelayPollTimeout
	if requested := r.URL.Query().Get("wait"); requested != "" {
		if secs, err := strconv.Atoi(requested); err == nil && secs >= 0 {
			wait = time.Duration(secs) * time.Second
			if wait > s.cfg.RelayPollTimeout {
				wait = s.cfg.RelayPollTimeout
			}
		}
	}

	deadline := time.Now().Add(wait)
	const tick = 200 * time.Millisecond
	for {
		if chunks := s.attachments.Drain(recipient, capability); len(chunks) > 0 {
			writeJSON(w, http.StatusOK, map[string]any{"chunks": chunks})
			return
		}
		if !time.Now().Before(deadline) {
			writeJSON(w, http.StatusOK, map[string]any{"chunks": []attachment.Chunk{}})
			return
		}
		select {
		case <-r.Context().Done():
			return
		case <-time.After(tick):
		}
	}
}

func (s *Server) handleCompleteAttachment(w http.ResponseWriter, r *http.Request) {
	if _, admitted := s.admit(w, r); !admitted {
		return
	}
	var value struct {
		TransferID string `json:"transferId"`
		Capability string `json:"capability"`
	}
	if err := decodeJSON(r, &value); err != nil || value.TransferID == "" || value.Capability == "" {
		writeDecodeError(w, err, "invalid_attachment_completion", "transferId and capability are required")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"removed": s.attachments.Complete(value.TransferID, value.Capability)})
}

// handlePresenceHeartbeat charges the lease to whatever the caller proved about
// itself, so that one caller cannot take the presence table from the rest.
//
// The capability is optional here, unlike on the prekey routes: a heartbeat is
// not a write into anybody's queue, and a profile that has minted no queue
// secret yet still deserves presence. What presenting one buys is a share of the
// table under a caller key nobody else can claim — see presence.Store's
// maxRecordsPerCaller for what that share is worth and when it is consulted.
func (s *Server) handlePresenceHeartbeat(w http.ResponseWriter, r *http.Request) {
	grant, admitted := s.admit(w, r)
	if !admitted {
		return
	}
	var value model.PresenceHeartbeat
	if err := decodeJSON(r, &value); err != nil || !s.presence.HeartbeatWithGrant(value, presenceGrant(grant, r)) {
		writeDecodeError(w, err, "invalid_presence", "presence heartbeat is invalid")
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]any{"accepted": true})
}

func (s *Server) handlePresenceQuery(w http.ResponseWriter, r *http.Request) {
	if _, admitted := s.admit(w, r); !admitted {
		return
	}
	var value model.PresenceQuery
	if err := decodeJSON(r, &value); err != nil {
		writeDecodeError(w, err, "invalid_query", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"presence": s.presence.Query(value.GrantHashes)})
}

// handlePresenceRevoke and handleProfilePurge are deliberately NOT gated.
//
// Both only ever *remove* data, and both are the last thing a circle does on a
// relay it is leaving — often on the day its window ends. Refusing them would
// mean an expired credential could no longer clear what it left behind, which is
// the wrong direction for this product: admission exists to meter what a relay
// carries, never to hold on to it. Neither is free service, and both already
// require a secret (the owner or purge hash) that only the owner holds.
//
// Because they are ungated, neither may be expensive. The queue half of a purge
// is two index lookups — the owner's message ids under its tombstone hash, then
// each message's ack ids — rather than the walk of both record maps under s.mu
// that it used to be. The presence half is a walk of a table capped at 5000
// records, which pruneLocked already performs on every presence call.
func (s *Server) handlePresenceRevoke(w http.ResponseWriter, r *http.Request) {
	var value model.PresenceRevoke
	if err := decodeJSON(r, &value); err != nil || value.OwnerHash == "" {
		writeDecodeError(w, err, "invalid_revoke", "owner hash is required")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"removed": s.presence.Revoke(value.OwnerHash)})
}

func (s *Server) handleProfilePurge(w http.ResponseWriter, r *http.Request) {
	var value model.ProfilePurge
	if err := decodeJSON(r, &value); err != nil || value.PurgeHash == "" {
		writeDecodeError(w, err, "invalid_purge", "purge hash is required")
		return
	}
	messages, acks := s.store.PurgeOwner(value.PurgeHash)
	presenceRemoved := s.presence.Revoke(value.PurgeHash)
	writeJSON(w, http.StatusOK, map[string]any{"messages": messages, "acks": acks, "presence": presenceRemoved})
}

// handlePublishPrekeys fills the caller's own prekey pool, and only ever its own:
// the pool is keyed by the queue tag derived from the capability presented, so
// the request carries no recipient at all. Before that, a caller could open a
// pool under any routing id it could guess and fill a real owner's 100 entries
// with prekeys nobody holds the private half of, locking the owner out of
// publishing until the TTL ran.
func (s *Server) handlePublishPrekeys(w http.ResponseWriter, r *http.Request) {
	if _, admitted := s.admit(w, r); !admitted {
		return
	}
	owner, ok := s.queueSubject(w, r)
	if !ok {
		return
	}
	var value model.PrekeyPublish
	if err := decodeJSON(r, &value); err != nil || (len(value.Entries) == 0 && value.LastResort == nil) {
		writeDecodeError(w, err, "invalid_prekey_publish", "at least one of entries or lastResort is required")
		return
	}
	added, ok := s.prekeys.Publish(owner, value)
	if !ok {
		// The box is carrying as many prekey pools as it is configured for and
		// this publish would open a new one. Refusing rather than evicting keeps
		// an existing recipient's pool from being pushed out by a newcomer; the
		// client's fallback is the `v2` envelope, which is exactly what it does
		// when a pool is drained.
		writeError(w, http.StatusTooManyRequests, "prekey_store_full",
			"this relay is at its one-time-prekey pool ceiling")
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]any{"accepted": true, "added": added, "available": s.prekeys.Status(owner, value.DeviceKey)})
}

// handleClaimPrekey is the one prekey route a caller other than the owner uses,
// so it takes no capability: a sender claims from its recipient's pool and does
// not hold the recipient's secret. What it names the pool by is the recipient's
// queue tag, which is what a contact was given in the contact code and what it
// already stamps on every envelope it sends — so the pool is reachable by
// exactly the parties the owner handed its tag to, and by nobody who merely
// guessed a routing id.
func (s *Server) handleClaimPrekey(w http.ResponseWriter, r *http.Request) {
	if _, admitted := s.admit(w, r); !admitted {
		return
	}
	tag := r.URL.Query().Get("tag")
	if tag == "" {
		writeError(w, http.StatusBadRequest, "missing_tag", "tag query parameter is required")
		return
	}
	device := r.URL.Query().Get("device")
	entry, ok := s.prekeys.Claim(tag, device)
	if !ok {
		writeError(w, http.StatusNotFound, "prekey_pool_drained", "no unused prekey is available for this recipient")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"prekey": entry})
}

// handlePrekeyStatus answers for the caller's own pool and takes no subject at
// all — the pool it reports on is the one the presented capability names, so
// there is no id to ask about somebody else with. That is the whole fix for what
// used to be an existence oracle: the question "does this identity hold prekeys"
// is no longer expressible, rather than answered to the wrong people.
func (s *Server) handlePrekeyStatus(w http.ResponseWriter, r *http.Request) {
	if _, admitted := s.admit(w, r); !admitted {
		return
	}
	owner, ok := s.queueSubject(w, r)
	if !ok {
		return
	}
	device := r.URL.Query().Get("device")
	writeJSON(w, http.StatusOK, map[string]any{"available": s.prekeys.Status(owner, device)})
}

// handleNodes publishes this relay and nothing else.
//
// It used to publish everything the node had heard about from its peers, which
// made it the pool's gossip channel — and a compromised member's way to advertise
// a host of its choosing to every other member and to clients. A relay knows its
// own public url; the rest of the pool is the client's configuration and the
// operator's, not something to be learned from a relay.
func (s *Server) handleNodes(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"nodes": []model.NodeInfo{s.pool.Self()}})
}

func (s *Server) handlePostMessage(w http.ResponseWriter, r *http.Request) {
	grant, admitted := s.admit(w, r)
	if !admitted {
		return
	}
	var envelope model.MessageEnvelope
	if err := decodeJSON(r, &envelope); err != nil {
		writeDecodeError(w, err, "invalid_json", err.Error())
		return
	}
	// An enforcing node must not accept an envelope nobody will be able to
	// fetch. Without recipientTag the message is a black hole; without senderTag
	// the acks it produces are, so the sender would never see delivery. Both are
	// worse than a loud rejection the client can act on.
	if s.cfg.RequireFetchAuth && (envelope.RecipientTag == "" || envelope.SenderTag == "") {
		writeError(w, http.StatusBadRequest, "fetch_tag_required",
			"this node requires recipientTag and senderTag on every envelope")
		return
	}

	ack, err := s.store.AddMessageWithGrant(envelope, s.cfg.NodeID, queueGrant(grant))
	switch {
	case err == nil:
		writeJSON(w, http.StatusAccepted, map[string]any{
			"accepted":  true,
			"duplicate": false,
			"ack":       ack,
		})
	case errors.Is(err, queue.ErrDuplicate):
		writeJSON(w, http.StatusOK, map[string]any{
			"accepted":  true,
			"duplicate": true,
			"ack":       ack,
		})
	case errors.Is(err, queue.ErrExpired):
		writeError(w, http.StatusGone, "expired", "message envelope is already expired")
	case errors.Is(err, queue.ErrPayloadTooLarge):
		writeError(w, http.StatusRequestEntityTooLarge, "payload_too_large", "encrypted payload exceeds the node size cap")
	case errors.Is(err, queue.ErrPairQuotaFull):
		writeError(w, http.StatusTooManyRequests, "pair_quota_full", "per-pair backlog quota is full; back off and retry")
	case errors.Is(err, queue.ErrSlotsFull):
		// A capacity sentence, never a permission sentence. Nothing has
		// happened to a member; the circle is holding as much undelivered mail as
		// its tier is sized for, and it drains as recipients come online.
		writeError(w, http.StatusTooManyRequests, "circle_slots_full",
			"this circle's relay capacity is full; it frees as queued messages are delivered")
	case errors.Is(err, queue.ErrQueueFull):
		writeError(w, http.StatusTooManyRequests, "queue_full", "message queue is full")
	default:
		writeError(w, http.StatusBadRequest, "invalid_message", "message envelope is invalid")
	}
}

func (s *Server) handleGetMessages(w http.ResponseWriter, r *http.Request) {
	if _, admitted := s.admit(w, r); !admitted {
		return
	}
	recipient := r.URL.Query().Get("recipient")
	if recipient == "" {
		writeError(w, http.StatusBadRequest, "missing_recipient", "recipient query parameter is required")
		return
	}
	auth, ok := s.queueAuth(w, r)
	if !ok {
		return
	}
	limit := parseLimit(r, 100)
	writeJSON(w, http.StatusOK, map[string]any{
		"messages": s.store.MessagesForRecipient(recipient, limit, auth),
	})
}

// handlePostAck is gated but charges no queue slots. Acks need no capacity
// field of their own: node_received couples 1:1 with an accepted envelope and
// the terminal ones delete theirs, so bounding a circle's queue slots bounds
// its ack store at the same 2x ratio the box already uses. What a caller-posted
// ack is held to is the external ack budget and the retention ceiling, both in
// queue.Store — the credential's shorter retention window applies here exactly
// as it does to an envelope, which is why the grant is passed through.
//
// It also takes the queue-read capability, because posting an ack is a write
// into the acked message's queue and not merely a note about it: five of the six
// ack types delete the message they name. The proof is against that message's
// recipientTag — the same tag GET /messages is proved against — so the party
// entitled to receive a message is the party entitled to ack it, and nobody who
// merely learned a message id can delete it.
func (s *Server) handlePostAck(w http.ResponseWriter, r *http.Request) {
	grant, admitted := s.admit(w, r)
	if !admitted {
		return
	}
	auth, ok := s.queueAuth(w, r)
	if !ok {
		return
	}
	var ack model.AckRecord
	if err := decodeJSON(r, &ack); err != nil {
		writeDecodeError(w, err, "invalid_json", err.Error())
		return
	}

	err := s.store.AddAckWithGrant(ack, s.cfg.NodeID, queueGrant(grant), auth)
	switch {
	case err == nil:
		writeJSON(w, http.StatusAccepted, map[string]any{"accepted": true, "duplicate": false})
	case errors.Is(err, queue.ErrDuplicate):
		writeJSON(w, http.StatusOK, map[string]any{"accepted": true, "duplicate": true})
	case errors.Is(err, queue.ErrExpired):
		writeError(w, http.StatusGone, "expired", "ack is already expired")
	case errors.Is(err, queue.ErrNotOwned):
		// 403 and not 404: this answers nothing about whether the message
		// exists. The node refuses only where it holds a tag the caller could
		// not match, and an ack for a message it holds nothing about is
		// accepted, so the refusal never distinguishes an absent message from
		// somebody else's.
		writeError(w, http.StatusForbidden, "ack_not_authorized",
			"acking a message requires the "+queueCapabilityHeader+" header for the queue it was addressed to")
	case errors.Is(err, queue.ErrQueueFull):
		writeError(w, http.StatusTooManyRequests, "queue_full", "ack queue is full")
	default:
		writeError(w, http.StatusBadRequest, "invalid_ack", "ack record is invalid")
	}
}

func (s *Server) handleGetAcks(w http.ResponseWriter, r *http.Request) {
	if _, admitted := s.admit(w, r); !admitted {
		return
	}
	sender := r.URL.Query().Get("sender")
	if sender == "" {
		writeError(w, http.StatusBadRequest, "missing_sender", "sender query parameter is required")
		return
	}
	auth, ok := s.queueAuth(w, r)
	if !ok {
		return
	}
	limit := parseLimit(r, 100)
	writeJSON(w, http.StatusOK, map[string]any{
		"acks": s.store.AcksForSender(sender, limit, auth),
	})
}

// queueCapabilityHeader carries the queue secrets a fetch is proving ownership
// with, space-separated (more than one only across a rotation). A header, not a
// query parameter: a query string lands in every proxy access log, and unlike an
// attachment capability this secret is long-lived.
const queueCapabilityHeader = "X-Dee-Queue-Capability"

// meshSecretHeader carries the shared pool secret (DEE_NODE_MESH_SECRET) that
// authorizes replication. Same reasoning as above for it being a header. The name
// lives in model so the server and the syncer cannot drift apart on it.
const meshSecretHeader = model.MeshSecretHeader

// queueAuth derives the read authorization for a queue fetch. It writes the
// response and returns false when the node is enforcing and the request proved
// nothing at all.
//
// A *wrong* capability is deliberately not an error: it yields an Auth that
// matches no record, so the fetch returns an empty list — indistinguishable from
// a queue with no mail. Answering "wrong capability" would restore the very
// existence oracle this endpoint is being hardened to remove.
func (s *Server) queueAuth(w http.ResponseWriter, r *http.Request) (queue.Auth, bool) {
	secrets := strings.Fields(r.Header.Get(queueCapabilityHeader))
	if s.cfg.RequireFetchAuth && len(secrets) == 0 {
		writeError(w, http.StatusUnauthorized, "capability_required",
			"queue reads require the "+queueCapabilityHeader+" header")
		return queue.Auth{}, false
	}
	// Untagged records stay readable only while the node is not enforcing. A
	// tagged record is withheld without proof in both modes.
	return queue.NewAuth(secrets, !s.cfg.RequireFetchAuth), true
}

// queueSubject is the queue tag a caller is acting *as*, for the two routes that
// operate on the caller's own pool rather than on a record somebody stamped. It
// writes the response and returns false when nothing was presented.
//
// Unlike queueAuth this refuses in *both* modes, enforcing or not. There is no
// compatibility case to keep open: a request with no capability names no pool,
// so there is nothing for the node to do with it either way, and the untagged
// path queueAuth preserves exists for records a sender stamped before fetch auth
// — never for a caller naming itself.
func (s *Server) queueSubject(w http.ResponseWriter, r *http.Request) (string, bool) {
	auth := queue.NewAuth(strings.Fields(r.Header.Get(queueCapabilityHeader)), false)
	subject := auth.Subject()
	if subject == "" {
		writeError(w, http.StatusUnauthorized, "capability_required",
			"this route acts on the caller's own queue and requires the "+queueCapabilityHeader+" header")
		return "", false
	}
	return subject, true
}

// presenceGrant resolves the identity a presence heartbeat is charged to, in the
// order of what each proof is worth. A queue tag is the hash of a 32-byte secret
// and names one identity, so it is preferred; an admitted credential names a
// whole circle and is the fallback for a client that presents no capability on a
// gated box. A caller that proved neither gets the empty key, which every other
// such caller shares.
//
// The prefixes exist so that a tag and a credential index can never collide in
// the store's counter map. Only one key is ever produced, which is what keeps
// this on the right side of the attribution rule: presenting a capability does
// not record the credential it came in under, so no credential is ever
// associated with the tags that heartbeat beneath it — the store holds a count
// per caller, never a roster (internal/audit/admission_attribution_test.go).
func presenceGrant(grant admission.Grant, r *http.Request) presence.Grant {
	if subject := queue.NewAuth(strings.Fields(r.Header.Get(queueCapabilityHeader)), false).Subject(); subject != "" {
		return presence.Grant{Caller: "tag:" + subject}
	}
	if grant.Index != 0 {
		return presence.Grant{Caller: "credential:" + strconv.FormatUint(uint64(grant.Index), 10)}
	}
	return presence.Grant{}
}

// handleMeshSnapshot serves one page of this relay's queue to a pool member.
//
// `since` is the cursor from the caller's last page; `limit` bounds the page. The
// response carries the epoch of this store, the cursor to ask for next, and
// whether more records are already waiting — see queue.Store.SnapshotSince for
// why paging is not optional.
//
// There is deliberately no counterpart that *accepts* a snapshot. Replication is
// pull-only (internal/mesh), so a peer cannot push records at this relay; what a
// peer this relay *pulls* from can put into these queues is unbounded, and that is
// what replication is. See deploy/README.md, "What a pool member is trusted with".
func (s *Server) handleMeshSnapshot(w http.ResponseWriter, r *http.Request) {
	if !s.isTrustedPeer(r) {
		writeError(w, http.StatusForbidden, "untrusted_peer", "mesh replication requires the pool secret")
		return
	}
	since, err := parseSince(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_since", err.Error())
		return
	}
	payload := s.store.SnapshotSince(since, parseLimit(r, 500))
	payload.NodeID = s.cfg.NodeID
	payload.Presence = s.presence.Snapshot()
	payload.PresenceRevocations = s.presence.Revocations()
	writeJSON(w, http.StatusOK, payload)
}

func parseSince(r *http.Request) (uint64, error) {
	value := r.URL.Query().Get("since")
	if value == "" {
		return 0, nil
	}
	parsed, err := strconv.ParseUint(value, 10, 64)
	if err != nil {
		return 0, errors.New("since must be a cursor from a previous page")
	}
	return parsed, nil
}

// isTrustedPeer authenticates a mesh peer on the shared pool secret, and on
// nothing else.
//
// It used to compare the self-asserted X-Dee-Node-ID and X-Dee-Node-URL headers
// against this node's own identity and the trusted-peer registry. Both of those
// values are published, unauthenticated, on /health and /nodes — so the
// credential was handed out by the endpoint it protected, and any caller could
// pull the whole queue out of /mesh/snapshot. The id header is still sent, so a
// peer can put a name in a log line, but it is not evidence of anything.
//
// The secret is shared across the pool, so this is pool membership, not peer
// identity: any member can act as any other. That is an honest fit for a handful
// of single-operator relays; per-node keypairs are the upgrade. deploy/README.md,
// "What a pool member is trusted with", states what that costs.
func (s *Server) isTrustedPeer(r *http.Request) bool {
	if !s.cfg.MeshEnabled() {
		return false
	}
	presented := r.Header.Get(meshSecretHeader)
	return subtle.ConstantTimeCompare([]byte(presented), []byte(s.cfg.MeshSecret)) == 1
}

// writeDecodeError answers a request whose body could not be read as JSON.
//
// A body that outran the route's limit is answered 413, not 400. limitBodies
// caps the read with http.MaxBytesReader, which trips *during* the decode and
// so surfaces here as an ordinary decode failure — and a client that special-
// cases 413 (as ours does, to mark a message permanently failed rather than
// retry it for a week) was told instead that it had sent malformed JSON. It is
// the same refusal either way; only one of them is true.
//
// [err] may be nil at call sites that combine the decode with validation of
// what it produced. errors.As is false for nil, so those keep their 400.
func writeDecodeError(w http.ResponseWriter, err error, code, message string) {
	var tooLarge *http.MaxBytesError
	if errors.As(err, &tooLarge) {
		writeError(w, http.StatusRequestEntityTooLarge, "payload_too_large",
			fmt.Sprintf("request body exceeds this route's limit of %d bytes", tooLarge.Limit))
		return
	}
	// A body that stopped arriving is not malformed input, and calling it
	// invalid_json sends whoever reads the logs looking for a client that
	// encodes badly instead of one that hung up mid-request. See limitBodies for
	// the deadline this reports.
	if errors.Is(err, os.ErrDeadlineExceeded) {
		writeError(w, http.StatusRequestTimeout, "body_incomplete",
			"request body was not delivered within the read deadline")
		return
	}
	writeError(w, http.StatusBadRequest, code, message)
}

func decodeJSON(r *http.Request, target any) error {
	defer r.Body.Close()
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	return decoder.Decode(target)
}

func parseLimit(r *http.Request, fallback int) int {
	value := r.URL.Query().Get("limit")
	if value == "" {
		return fallback
	}
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed <= 0 {
		return fallback
	}
	if parsed > 500 {
		return 500
	}
	return parsed
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func writeError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, map[string]any{
		"error":   code,
		"message": message,
	})
}
