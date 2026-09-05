package model

import "time"

// MessageEnvelope is one queued ciphertext. RecipientTag and SenderTag are the
// read-authorization handles described in the README, § "Queue-read
// authorization": each is the SHA-256
// of a queue secret only its owner holds, so a sender can *address* a queue
// without being able to read it. They are optional on the wire — an envelope
// from a client that predates fetch auth carries neither, and the node's
// RequireFetchAuth setting decides whether such an envelope is still accepted.
type MessageEnvelope struct {
	ID               string            `json:"id"`
	Sender           string            `json:"sender"`
	Recipient        string            `json:"recipient"`
	CreatedAt        time.Time         `json:"createdAt"`
	ExpiresAt        time.Time         `json:"expiresAt"`
	EncryptedPayload string            `json:"encryptedPayload"`
	ContentType      string            `json:"contentType,omitempty"`
	KeyID            string            `json:"keyId,omitempty"`
	Signature        string            `json:"signature,omitempty"`
	Metadata         map[string]string `json:"metadata,omitempty"`

	// RecipientTag gates GET /messages for Recipient.
	RecipientTag string `json:"recipientTag,omitempty"`
	// SenderTag gates GET /acks for Sender. It is stamped on the envelope
	// rather than derived, because the acks this message will produce are
	// minted by parties (this node, the recipient's device) that never learn
	// the sender's tag any other way.
	SenderTag string `json:"senderTag,omitempty"`
}

type AckType string

const (
	AckNodeReceived            AckType = "node_received_ack"
	AckRecipientDeviceReceived AckType = "recipient_device_received_ack"
	AckRecipientRead           AckType = "recipient_read_ack"
	AckExpired                 AckType = "expired_ack"
	AckRejected                AckType = "rejected_ack"
	AckRetractionApplied       AckType = "retraction_applied_ack"
)

type AckRecord struct {
	ID        string    `json:"id"`
	MessageID string    `json:"messageId"`
	Sender    string    `json:"sender"`
	Recipient string    `json:"recipient"`
	Type      AckType   `json:"type"`
	CreatedAt time.Time `json:"createdAt"`
	ExpiresAt time.Time `json:"expiresAt"`
	NodeID    string    `json:"nodeId,omitempty"`
	Signature string    `json:"signature,omitempty"`

	// SenderTag gates GET /acks for Sender — the party that fetches its own
	// ack lane. Copied from the message envelope by whoever mints the ack (the
	// node for node_received, the recipient's device for delivered/read).
	SenderTag string `json:"senderTag,omitempty"`

	// RecipientTag is the acked message's read-authorization tag, and it is what
	// POST /acks is authorized against: five of the six ack types delete the
	// message they name, so posting one is a write into the recipient's queue
	// and has to be proved like a read of it.
	//
	// The node sets this field itself, from the message the ack names — a value
	// arriving on the wire is discarded, because an ack that carried its own
	// authorization would authorize nothing. It is written down rather than
	// re-derived so the binding outlives the message: the first terminal ack
	// deletes the envelope, and the second one still has to be proved against
	// the same tag.
	RecipientTag string `json:"recipientTag,omitempty"`

	// Reason is a short opaque marker the recipient's device attaches to a
	// rejection, relayed verbatim so the original sender can tell a message its
	// recipient could not open from one it refused as garbage. The node never
	// interprets it and it is covered by Signature, so a node that rewrote it
	// would only invalidate the ack it tampered with. Bounded on the way in
	// (see queue.MaxAckReasonBytes) — this is an ack lane, not a mailbox.
	Reason string `json:"reason,omitempty"`
}

type NodeInfo struct {
	ID        string    `json:"id"`
	URL       string    `json:"url"`
	LastSeen  time.Time `json:"lastSeen"`
	Trusted   bool      `json:"trusted"`
	Reachable bool      `json:"reachable"`
}

// SyncPayload is one page of a peer's queue, as served by GET /mesh/snapshot.
//
// Epoch, NextSeq and More are the paging cursor. A page is bounded, so a puller
// asks repeatedly with NextSeq until More is false; Epoch changes when the
// serving relay restarts, which tells the puller its cursor is meaningless and
// it has to start from zero. Without this the exchange re-read the same oldest
// records on every tick and a queue longer than one page never replicated past
// it.
type SyncPayload struct {
	NodeID              string               `json:"nodeId"`
	Epoch               string               `json:"epoch,omitempty"`
	NextSeq             uint64               `json:"nextSeq,omitempty"`
	More                bool                 `json:"more,omitempty"`
	Messages            []MessageEnvelope    `json:"messages"`
	Acks                []AckRecord          `json:"acks"`
	Presence            []PresenceHeartbeat  `json:"presence,omitempty"`
	PresenceRevocations []PresenceRevocation `json:"presenceRevocations,omitempty"`
	Purges              []PurgeRecord        `json:"purges,omitempty"`
}

type PurgeRecord struct {
	PurgeHash string    `json:"purgeHash"`
	ExpiresAt time.Time `json:"expiresAt"`
}

// MeshSecretHeader carries the shared pool secret that authorizes replication.
// Defined here because both ends read it: httpapi checks it, internal/mesh sends
// it, and a drift between two copies of the name would fail open on one side.
//
// There is no SyncResult type any more. It was the response to POST /mesh/sync,
// and that route is gone: replication is pull-only, so there is nothing for a peer
// to post to. A peer that this node pulls from is a different matter — see
// internal/mesh, and deploy/README.md, "What a pool member is trusted with".
const MeshSecretHeader = "X-Dee-Mesh-Secret"

type PresenceHeartbeat struct {
	OwnerHash string    `json:"ownerHash"`
	GrantHash string    `json:"grantHash"`
	UpdatedAt time.Time `json:"updatedAt,omitempty"`
	ExpiresAt time.Time `json:"expiresAt"`
}

type PresenceQuery struct {
	GrantHashes []string `json:"grantHashes"`
}

type PresenceStatus struct {
	GrantHash string    `json:"grantHash"`
	Online    bool      `json:"online"`
	LastSeen  time.Time `json:"lastSeen"`
}

type PresenceRevoke struct {
	OwnerHash string `json:"ownerHash"`
}

type PresenceRevocation struct {
	OwnerHash string    `json:"ownerHash"`
	UpdatedAt time.Time `json:"updatedAt"`
	ExpiresAt time.Time `json:"expiresAt"`
}

type ProfilePurge struct {
	PurgeHash string `json:"purgeHash"`
}

// PrekeyEntry is a single signed one-time prekey (OPK) published by a recipient
// for recipient-side forward secrecy (the `v3` envelope). PublicKey is the
// base64 X25519 public half; Signature is the recipient identity Ed25519
// signature over it, verified by senders against the pinned contact key.
//
// LastResort marks an entry the node served from the reusable last-resort
// prekey (LRPK) rather than popping a one-time entry — set on claim responses
// when the one-time pool is drained or the per-bucket claim rate is exceeded.
// Senders verify an LRPK under a distinct signature transcript, so the flag
// also tells the claimer which transcript to expect.
type PrekeyEntry struct {
	OpkID      string `json:"opkId"`
	PublicKey  string `json:"publicKey"`
	Signature  string `json:"signature"`
	LastResort bool   `json:"lastResort,omitempty"`
}

// PrekeyPublish is a recipient publishing/replenishing its pool of one-time
// prekeys to its home node. LastResort, when present, is the recipient's signed
// reusable last-resort prekey (separate from the one-time Entries): the node
// serves it when the one-time pool is drained or a claim flood is being
// throttled, so a drained pool still yields recipient-side forward secrecy (at
// rotation granularity) instead of forcing the `v2` fallback.
//
// It names no recipient. The pool is keyed by the publisher's queue tag, which
// the node derives from the capability header the publish is proved with — so
// the routing id whose pool this is never reaches the relay at all, and a
// publisher can only ever fill its own pool.
type PrekeyPublish struct {
	DeviceKey  string        `json:"deviceKey,omitempty"`
	Entries    []PrekeyEntry `json:"entries"`
	LastResort *PrekeyEntry  `json:"lastResort,omitempty"`
}
