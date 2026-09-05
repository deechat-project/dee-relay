# DeeChat Relay

Small Go relay for DeeChat. The binary and unit are `dee-relay`.

This service is an optional, untrusted helper. It stores only opaque encrypted
message envelopes and ACK records in memory. It does not own identity, private
keys, contact trust, plaintext messages, or permanent history. It may temporarily
relay encrypted attachment chunks in bounded RAM queues; chunks are never
persisted or mesh-synchronized.

## Run

```bash
go run ./cmd/dee-relay
```

For a real host — container, systemd unit, memory ceiling, acceptance test —
see [deploy/README.md](deploy/README.md). Do not size a production relay from
the `go run` defaults; they assume a workstation.

Environment variables:

- `DEE_NODE_ID` stable local node identifier
- `DEE_NODE_ADDR` listen address, default `:8080`
- `DEE_NODE_PUBLIC_URL` URL announced by `/nodes`. If this is a literal IP that
  the host itself holds at launch — the LAN-node case, where a script fills it
  from `ipconfig getifaddr` — the node re-derives it when that address stops
  being one of its own, so a box that keeps running across a network change does
  not go on advertising an address it lost. A hostname, a loopback URL, or an
  address belonging to a proxy is published exactly as configured and is never
  rewritten. A re-derivation is logged at `warn`.
- `DEE_NODE_MESH_PEERS` comma-separated *peering* URLs of the other pool members
  — the complete list of hosts this node will send the pool secret to, and it
  comes from configuration only. A peer cannot introduce another peer. (This
  replaces `DEE_NODE_TRUSTED_NODES`, which the node now refuses to boot with.)
- `DEE_NODE_MESH_ADDR` the private address the mesh listener binds. `/mesh/*` is
  not served on `DEE_NODE_ADDR` in any configuration, so replication has its own
  listener; the node refuses a wildcard or public bind here
- `DEE_NODE_MESH_SECRET` shared pool secret authorizing `GET /mesh/snapshot`.
  **Unset (the default) means mesh is off and there is no mesh listener**, not
  that it is open. `GET /health` reports `meshEnabled`, and `mesh.peers` /
  `mesh.reachable` / `mesh.oldestSyncAgeSec`, so a deployment can assert that
  replication is *working* rather than merely switched on
- `DEE_NODE_MAX_MESSAGES` max RAM message envelopes (global safety cap), default 1000
- `DEE_NODE_MAX_ACKS` max RAM ACK records, default `2 × DEE_NODE_MAX_MESSAGES`
  (every accepted message couples a `node_received` ack, and terminal acks must
  outlive the resend window). The lane is split: everything above
  `DEE_NODE_MAX_MESSAGES` is the budget client-posted acks may occupy, and the
  rest is reserved for the node's own coupled acks — so a full ack store can
  never refuse a `POST /messages`. It must be greater than
  `DEE_NODE_MAX_MESSAGES` or the node refuses to boot, because at that setting
  there would be no budget for client acks at all. An ack that names a message
  this relay holds anything about is proved against that message's queue (below),
  so it cannot delete somebody else's mail; one naming a message the relay has
  never carried has no tag to be proved against and still occupies a slot, so a
  caller can fill that budget with junk. What the split buys is that the damage
  stops at the ack lane and expires within `DEE_NODE_MAX_TTL`
- `DEE_NODE_MAX_PURGES` max RAM purge tombstones, default 1000
- `DEE_NODE_MAX_PER_PAIR` max undelivered messages per `(sender→recipient)` lane,
  default 10 — fair-share anti-abuse cap so one chatty pair or one flooder can't
  starve other conversations (rejects with `pair_quota_full`, HTTP 429)
- `DEE_NODE_MAX_PAYLOAD_BYTES` max base64 `EncryptedPayload` per message, default
  8192 — text-only anti-abuse guard; attachments do not pass through this store
  (rejects with `payload_too_large`, HTTP 413). NB the `v4` envelope adds ~3.2 KB
  fixed overhead + ~1.8 encoded bytes per plaintext byte (measured), so 8192 fits
  only ~2820 ASCII chars — the client composer cap is 2500 to leave headroom for
  multi-byte text
- `DEE_NODE_MAX_TTL` ceiling on a client-set `expiresAt`, default `72h` — a longer
  client window is silently clamped to this, on messages and on acks alike, and
  on replicated records pulled from a pool peer
- `DEE_NODE_MAX_CHUNK_BYTES` max encrypted chunk size, default 1 MB. Do not
  lower it: the client sends 512 KB plaintext chunks, which encrypt and base64
  to roughly 700 KB, so a smaller cap rejects every chunk
- `DEE_NODE_MAX_ATTACHMENT_BYTES` largest whole attachment this relay will
  carry, default 50 MB. Unlike the caps around it this one is **published on
  `/health`**, and the app sizes its own send guard from it — so raising it here
  is what lets clients offer larger files, and lowering it makes them refuse the
  file up front instead of after the upload. Enforced on the summed chunks of a
  transfer, so a sender that lies about `totalChunks` gains nothing. It does not
  change the chunk footprint: the relay never holds more than one window of a
  transfer at a time, so that stays `sessions × window × chunk bytes`. Beside
  those bytes a live session keeps one bit per chunk index it has accepted, in
  order to refuse a replay of something already drained — bounded, because a
  transfer may span at most 8192 indices (a compiled-in constant, not a knob:
  the client's chunks encode to roughly 700 KB, so a 50 MB attachment spans
  about 73). A sender that slices more finely than that is refused with `413
  chunk_count_too_high` rather than paid for, which is what lets
  `deploy/memory-ceiling.sh` count the term
- `DEE_NODE_RELAY_MAX_SESSIONS` concurrent attachment transfers, default 256
- `DEE_NODE_RELAY_MAX_WINDOW` in-flight chunks per transfer, default 8 — with
  the two above it fixes the chunk footprint (`sessions × window × chunk bytes`),
  which is **the dominant memory term**: 2 GB at the defaults. Size it
  deliberately per host; a transfer opened past `DEE_NODE_RELAY_MAX_SESSIONS`
  gets `429 relay_busy` and retries, which is back-pressure, not loss
- `DEE_NODE_RELAY_IDLE_TIMEOUT` drop a transfer whose peers have gone quiet,
  default `30s`
- `DEE_NODE_RELAY_POLL_TIMEOUT` long-poll parking time on chunk fetch, default `25s`
- `DEE_NODE_BODY_READ_TIMEOUT` how long a request body may take to arrive once
  its headers have, default `20s`. Bodies only, so the long poll above is
  unaffected. A client that sends headers and then stops used to park a
  goroutine and its connection for the life of the process
- `DEE_NODE_IDLE_TIMEOUT` close a kept-alive connection idle between requests,
  default `120s`. Go's own default is no limit, so a client that leaks a
  connection per abandoned request accumulates them until the relay restarts
- `DEE_NODE_PREKEY_CLAIM_BURST` prekey claims allowed back to back, default 32
- `DEE_NODE_PREKEY_CLAIM_REFILL` time to accrue one claim token, default `1s`
- `DEE_NODE_MAX_PREKEY_BUCKETS` how many one-time-prekey pools this relay holds
  at once — one pool per publishing device — default 5000. At the ceiling a
  publish for a device the relay is not already carrying is refused with
  `429 prekey_store_full` rather than evicting somebody else's pool; the sender
  falls back to the `v2` envelope, exactly as it does against a drained pool.
  `GET /health` reports `prekeyBuckets`, so a box turning newcomers away says so
- `DEE_NODE_DEFAULT_TTL` default TTL duration, for example `24h`
- `DEE_NODE_CLEANUP_INTERVAL` expiry worker interval, for example `30s`
- `DEE_NODE_MESH_SYNC_INTERVAL` peer pull interval, for example `30s` — the sync
  loop runs only when `DEE_NODE_MESH_SECRET` is also set
- `DEE_NODE_MESH_REQUEST_TIMEOUT` outbound mesh request timeout, for example `5s`
- `DEE_NODE_REQUIRE_FETCH_AUTH` require a queue-read capability on `GET /messages`
  and `GET /acks`, default `false` while clients roll out. Note what the default
  does **not** mean: a record that carries a read-authorization tag is withheld
  without proof either way. The flag only decides whether records carrying *no*
  tag — from clients predating fetch auth — are still served, and whether an
  untagged `POST /messages` is rejected. `GET /health` reports the live value so
  a deployment can assert it is enforcing.
- `DEE_NODE_ADMISSION_FILE` path to the credential file naming the circles this
  relay carries mail for, and on what terms. Unset means none, and **none means
  open** — the caps above apply to everyone, which is the free self-hosted path.
  The file holds public keys, never codes, so a copy of it admits nobody. It is
  read and never written; `kill -HUP` re-reads it
- `DEE_NODE_REQUIRE_ADMISSION` refuse every metered route to a caller that has
  not proved a credential, default `false`. With credentials loaded and this
  off, an admitted circle gets its terms and everyone else still gets box caps —
  the rollout position. Published on `/health`, and the node **refuses to boot**
  when it is on with nothing loaded

## API

- `GET /health`
- `GET /nodes`
- `POST /admission/challenge` (relay admission, below)
- `POST /admission/redeem`
- `POST /messages`
- `GET /messages?recipient=<opaque-routing-id>` (queue-read capability, below)
- `POST /acks` (queue-read capability, below — an ack is a write into the acked
  message's queue)
- `GET /acks?sender=<opaque-sender-id>` (queue-read capability, below)
- `POST /attachments/chunks`
- `GET /attachments/chunks?recipient=<opaque-routing-id>&capability=<opaque-secret>`
- `POST /attachments/complete`
- `POST /presence/heartbeat` (queue-read capability optional, below — it is not
  required to publish a lease, but it earns the caller its own share of the
  presence table)
- `POST /presence/query`
- `POST /presence/revoke`
- `POST /profile/purge`
- `POST /prekeys` (queue-read capability, below — it fills the caller's own pool)
- `GET /prekeys/claim?tag=<opaque-queue-tag>&device=<opaque-device-key>`
- `GET /prekeys/status?device=<opaque-device-key>` (queue-read capability, below;
  it takes no subject — see *What `/prekeys/status` answers*)

On the private mesh listener (`DEE_NODE_MESH_ADDR`) only, and only when a pool
secret is configured:

- `GET /mesh/snapshot?since=<cursor>&limit=<n>`

There is no endpoint that *accepts* a snapshot. Replication is pull-only: a pool
member serves its own queue to a peer that chose to pull it, and there is nothing
for an outsider to post to.

Pulling is a trust decision, and it is the only one a pool has. A snapshot you
pull is injected into your queues — its envelopes, its acks (five of the six ack
types delete the queued message they name), and its purge tombstones, which delete
queued mail. The pool secret proves membership, not identity, so any member can
act as any other. Joining a pool means trusting every member with your queues;
`deploy/README.md`, *What a pool member is trusted with*, is the full statement.

All message payloads are opaque ciphertext from the node's perspective.

### Request body limits

Each route caps its request body at what its configured limit can legitimately
carry: `DEE_NODE_MAX_PAYLOAD_BYTES` plus JSON slack for most routes,
and `DEE_NODE_MAX_CHUNK_BYTES` plus slack for `POST /attachments/chunks`.
Over-large bodies get `413 payload_too_large`. (The mesh listener serves one GET
and takes no body at all.)

This bound exists separately from the caps because the caps are checked *after* a
request is decoded — so without it, `DEE_NODE_MAX_PAYLOAD_BYTES=8192` still
allowed an unauthenticated caller to have a 200 MB body allocated in full before
being told it was too big. On a RAM-only relay that is not a rejected request, it
is an OOM kill that empties every queue on the host. The reverse proxy bounds
bodies from outside as well (`deploy/Caddyfile.example`), but at one coarse
number per route family rather than at this one: the binary's limit is derived
from the caps it will actually enforce and is the tighter of the two. Neither
layer is meant to be load-bearing alone.

`sizeBytes` on an attachment chunk is likewise not trusted: the cap is measured
on the payload the relay is about to hold, not on the sender's claim about it.

### Queue-read authorization

`GET /messages` and `GET /acks` are queue reads, and a routing id is not a
credential — it is a name. Both accept:

- `X-Dee-Queue-Capability: <secret> [<secret> …]` — up to four space-separated
  queue secrets (more than one only across a rotation).

The node serves a record when `SHA-256("deechat.queue-tag.v1|" || secret)` equals
the `recipientTag` (messages) or `senderTag` (acks) the record carries. Senders
stamp the tag; only the queue owner holds the secret, so a sender can address a
queue it cannot read, and **a node cannot read another node's queue** even after
mesh sync hands it the tag.

Nothing about this is stored: the tag rides the record, so verification is
stateless and works on whichever node holds the queue. A wrong capability returns
`200` with an empty list — identical to a queue with no mail, so the endpoint is
not an existence oracle. Only a missing capability on an enforcing node returns
`401 capability_required`.

**The same header authorizes three writes.** A queue is not only something to
read out of:

- `POST /acks`. Five of the six ack types delete the message they name, so an
  ack is a write into the recipient's queue and not a note about it. The node
  proves it against that message's own `recipientTag` — the tag it already holds,
  never one the ack carries, since a record that authorized itself would
  authorize nothing. Without the proof, anyone who learned a message id could
  destroy a third party's queued mail. `403 ack_not_authorized`, and only where
  the node holds a tag the caller could not match: an ack for a message this
  relay never carried is accepted, because there is nothing behind it to destroy
  and a refusal there would be the existence oracle again. What such a caller
  gets is a slot in the caller-posted ack budget, which is capped and expires.
- `POST /prekeys` and `GET /prekeys/status`. Both act on the caller's *own* pool,
  which is named by the tag its capability derives — so the request carries no
  recipient at all, and the routing id the pool belongs to never reaches the
  relay. Refused with `401 capability_required` in both modes: unlike a read,
  there is no pre-fetch-auth record here whose compatibility has to be kept.

`GET /prekeys/claim` is the exception and takes no capability, because a sender
claiming from its recipient's pool does not hold the recipient's secret. It names
the pool by the recipient's **tag** — the public half a contact was given in the
contact code and already stamps on every envelope it sends — so a pool is
reachable by the parties its owner handed the tag to, and by nobody who guessed a
routing id. That distinction is the whole of it: a routing id is minted from a
handle slug, so it is guessable; a tag is the hash of a 32-byte secret.

`POST /presence/heartbeat` takes the header too, but does not require it: a
presence lease is not a write into anybody's queue, and a profile that has minted
no queue secret still deserves to be seen as online. What presenting it buys is a
**share of the presence table** — a caller key nobody else can claim. The table
holds 5000 leases, and a lease is kept for a day after it was last seen while it
only reports *online* for five minutes, so a full table that simply refused
newcomers could be held for that day by one burst of junk grant hashes. Instead a
full table takes the slot from the lease with the weakest claim on it: one whose
online window has passed, and failing that one held by a caller past its share.
A live lease from a caller inside its share is never the one taken — and if every
lease in the table is one of those, the table is genuinely full and the newcomer
is refused.

**A client that does not send the header cannot clear its own queue.** This is a
wire change, not a flag: a relay from before it and a client from after it (or
the reverse) will fail acks and prekey publishes rather than degrade. Prekeys
degrade gracefully — a failed claim is the `v2` fallback the sender already has —
but acks do not: a message whose terminal ack is refused stays queued and is
redelivered until it expires.

### What `/prekeys/status` answers

Only ever the caller's own pool, and there is no parameter with which to ask
about anyone else's. It answers for the pool the presented capability names, so
the question *does this identity hold prekeys* is not expressible rather than
answered to the wrong caller — which is what it used to be, keyed by routing id
and gated by nothing.

The same re-keying is what makes `POST /prekeys` safe. A pool used to be opened
by whoever published to a routing id first, so an attacker could fill a real
owner's hundred entries with prekeys nobody held the private half of and lock
them out of publishing until the TTL ran. Now the pool is the publisher's own tag,
and a caller can only fill what it can prove.

The damage bounds stay, because owning a tag is proved but *minting* one is free:
pools are capped (`DEE_NODE_MAX_PREKEY_BUCKETS`), entries per pool are capped,
and claims are rate-limited per pool.

### Relay admission

Queue-read authorization above answers *whose mail is this*. Admission answers a
different question — *does this relay carry mail for you at all* — and without it
a relay's URL is its entitlement: anyone who learns the address can point a
correctly-tagged client at it and use it for free, forever.

A relay with no `DEE_NODE_ADMISSION_FILE` admits everyone at the caps in its env
file, and that is the intended self-hosted behaviour. With a credential file:

```
POST /admission/challenge  → { "nonce": "…", "expiresInSec": 30 }
POST /admission/redeem     { "credential": "…", "nonce": "…", "signature": "…" }
                           → { "session": "…", "expiresInSec": 900, "terms": {…} }
```

then `X-Dee-Admission: <session>` on every metered request.

**The credential never travels.** A redemption code derives an Ed25519 keypair —
`seed = SHA-256("deechat.admission-key.v1|" || code)`, the code normalised to
Crockford base32 — and the relay stores only the public half, named by its
base64url encoding. What crosses the wire is a signature over
`"deechat.admission-proof.v1|" || nonce || "|" || credential`, against a nonce
this relay issued seconds ago and will never accept twice. So a captured exchange
is not replayable, and a copy of the credential file admits nobody.

**The session is a handle, not a cached decision.** Every metered request
re-resolves the credential from the live set, so revocation and expiry both take
effect on the next call rather than when the session ends. `notAfter` is the only
date; nothing is revoked in the normal course, entitlements expire.

**Terms come back from the exchange and never from `/health`.** `/health`
publishes `requireAdmission` and nothing else about admission — not the
credential count, and no per-credential value. The box-wide
`maxAttachmentBytes` is there because it is a property of the box; a circle's
retention window is not, and an unauthenticated endpoint must not answer
questions about a specific credential. The client takes the smaller of its own
constant and what it was granted.

Every capacity field in a credential's terms is optional, **zero means "use this
box's own cap"**, and a credential **may only ever lower one**. So a credential
written before a field existed keeps working, re-pricing edits stored terms
rather than re-issuing codes, and an Apache-2.0 binary cannot be made to serve
more than its operator configured. The `tier` label is data for support replies;
nothing branches on it, which is what keeps a price list out of this binary.

The relay keeps **one integer per credential** — undelivered envelopes held, and
bytes through the attachment relay in a rolling 24 hours. A count, never a set of
what was seen under it: a count says how much a circle is holding, a set of queue
tags would be its membership roster. That is enforced by
`internal/audit/admission_attribution_test.go`, not just by intent.

Two routes are ungated on purpose even when enforcing: `POST /presence/revoke`
and `POST /profile/purge` only ever *remove* data, and both are the last thing a
circle does on a relay it is leaving.
Being ungated is also why neither may be expensive: a purge finds an owner's
mail and its acks through an index keyed by the tombstone hash, so no caller can
make the relay walk its queues.

Refusals, and what each one means to a client:

| Code | Status | Meaning |
|------|--------|---------|
| `admission_required` | 401 | no session presented, and this relay is enforcing |
| `admission_stale` | 401 | the session expired; run the exchange again |
| `admission_expired` | 403 | the circle's window ended; local transports unaffected |
| `admission_refused` | 403 | not admitted here, or the proof did not verify |
| `admission_busy` | 429 | challenge or session table full; retry shortly |
| `circle_slots_full` | 429 | the circle's queue slots are occupied; frees as mail is delivered |
| `transit_exhausted` | 429 | the circle's daily transit ceiling is spent; recovers over 24h |

**Credentials are issued by a separate binary**, `cmd/dee-admit`, which is the
only thing in this module that writes to disk. It is separate for two reasons:
the relay must never branch on a tier label — that is what keeps a price list out
of this binary — and the relay's durable-state audit forbids it writing anything.
Nothing in `cmd/dee-relay` links it, and
`internal/audit/no_durable_state_test.go` fails the build if that ever changes.

```
go build -o dee-admit ./cmd/dee-admit
export DEE_NODE_ADMISSION_FILE=/etc/deechat/credentials.json

dee-admit mint --tier crew --days 14   # prints the code ONCE; nothing stores it
dee-admit renew  --code <the customer's code> --days 30
dee-admit revoke --credential <id>
dee-admit list
systemctl kill -s HUP dee-relay    # the relay re-reads the file

# and one command that writes nothing and talks to a running relay:
printf '%s\n' "$CODE" | dee-admit session --code - --relay https://relay.example.org
```

`session` runs the challenge/redeem exchange and prints the session token on
stdout, with the diagnosis on stderr. It is there for two callers.
`deploy/setup-verify.sh --admission-code -` spends a session on its canary, so
the delivery half of a verification run can happen on a relay whose gate is
closed — otherwise the canary is refused 401 and the box carrying paid mail is
the one box the script cannot prove delivers. And an operator holding "the
customer says their code does not work" gets the three refusals told apart:
window ended, never admitted here, or mistyped. It lives in this binary because
the code → keypair derivation does; a second implementation of it in a shell
script is the one that drifts.

`--tier` needs a presets file (`--tiers`, or `$DEE_ADMIT_TIERS`);
`deploy/tiers.example.json` is the one we ship. Without a tier the credential
grants this box's own caps and is a gate rather than a product — which is the
useful shape for an operator's own box. A self-hosted relay needs none of this:
no credential file means everyone gets the caps in the env file.

Renewal extends the window on the credential the customer already holds and never
mints a new code, so no member re-provisions when a circle pays. Revocation is
for a refund or a shared code; in the normal course entitlements simply expire.

### Mesh replication

`GET /mesh/snapshot` requires the shared pool secret in `X-Dee-Mesh-Secret`,
compared in constant time against `DEE_NODE_MESH_SECRET`. A request also carries
`X-Dee-Node-ID`, but that is self-asserted — it names the caller in a log line and
authorizes nothing. Without a configured secret there is no mesh listener at all.

Note what a shared secret is and is not. It proves *pool membership*, not peer
identity: any member can impersonate any other. That is an honest fit for a
handful of relays under one operator; per-node keypairs are the upgrade.

`/mesh/snapshot` returns every identity's queued records, unfiltered by queue tag
— it is the replication path, so it has to. Which is why it is not on the public
listener in any configuration: it binds `DEE_NODE_MESH_ADDR` on a private
interface, and the reverse proxy still returns `404` for `/mesh/*` so that the
public port has both no route and no forwarder.

Replication is pull-only and paged. A relay asks each configured peer for the
records that arrived after the cursor it last saw, until the peer reports no more;
nothing writes into a peer. What crosses is RAM-only encrypted envelopes, ACK
records, presence leases, and short-lived purge tombstones. Delivered, read,
expired, rejected and retraction-applied ACKs — five of the six types — delete
matching queued messages during import.

Pulling a peer is therefore the trust decision described above: see
`deploy/README.md`, *What a pool member is trusted with*.

Presence, last-seen records, purge capabilities, queues, and tombstones are
never written to disk. A node restart clears all of them.

## Capacity sizing

The per-pair quota gives the node a *deterministic* RAM ceiling: at ~10 KB per
queued text message (8 KB payload cap + envelope + coupled ack), the absolute
worst case is `Users × LanesPerUser × DEE_NODE_MAX_PER_PAIR × 10 KB`. Size
`DEE_NODE_MAX_MESSAGES` to the tier and let `DEE_NODE_MAX_ACKS` default to twice
it. Attachments do **not** enter this store, so the figures are text-only.

| Users | `MAX_MESSAGES` | `MAX_ACKS` | Box |
|-------|----------------|------------|-----|
| 1k    | 10,000         | 20,000     | 1 GB VPS  |
| 10k   | 100,000        | 200,000    | 2 GB VPS  |
| 50k   | 500,000        | 1,000,000  | 8 GB VPS  |
| 100k  | 1,000,000      | 2,000,000  | 16 GB VPS |

These are the `LanesPerUser = 1`, 100%-of-users-full ceilings — what you
provision for safety. Realistic steady-state occupancy is a fraction of this
(only a minority of users have mail waiting at any instant).

**The boxes above are the text-queue figures only, and they are not the whole
ceiling.** The attachment relay dominates: at its defaults it reserves 2 GB, so
a stock-config node needs ~3.5 GB, not the 1 GB the first row suggests. Derive
the real number for a host from that host's env file rather than reading it off
this table:

```bash
deploy/memory-ceiling.sh /etc/deechat/node.env
```

That script is the model: it reads the caps the host is actually configured
with, applies the fan-in multiplier, and prints the ceiling each subsystem
contributes rather than a single number to trust. It counts every store a caller
can grow, the per-session replay sets included, and it says which of its lines
come from a constant in the binary rather than from the env file.

## Verifying a release

Releases are built reproducibly — digest-pinned builder image, `-trimpath`,
`-buildvcs=false`, `-ldflags="-s -w -buildid="`, stdlib only — so anyone can
rebuild from this source and get the published SHA-256:

```bash
deploy/verify-artifact.sh     # rebuild, compare against deploy/FINGERPRINTS.md
go test ./internal/audit      # and the reason that digest is worth having
```

[deploy/FINGERPRINTS.md](deploy/FINGERPRINTS.md) is the published record and is
exact about what the two fingerprints prove. The one thing to carry away: a digest
attests to an *artifact*, never to a running process. Nothing here lets you verify
that a relay you are polling is running this code, and no wording in this repo
should suggest otherwise.

## License

Apache License 2.0 — see [LICENSE](LICENSE) and [NOTICE](NOTICE). The node is
licensed permissively on purpose: the claim "this relay cannot keep your data"
is only worth something if anyone can read the code and run the audit that
enforces it (`go test ./internal/audit`).

The DeeChat client applications are a separate, proprietary repository.

Security reports go through the repository's Security tab, not a public issue —
[SECURITY.md](SECURITY.md) says how, what is in scope, and what is designed-in
rather than broken.
