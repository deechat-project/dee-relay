# Deploying a relay

What a production relay needs beyond `go run`, and the reasoning behind each
piece: a reproducible image, a hardened unit, a memory ceiling derived from the caps
rather than guessed, a reverse proxy that keeps the replication endpoint off the
internet, health monitoring that asserts the security switches instead of
trusting a clean boot, fingerprints a stranger can check without asking us
anything, replication between two or three relays that actually converges, and
acceptance tests for each.

| File | What it is |
|---|---|
| `Dockerfile` | Two-stage build, digest-pinned bases, distroless runtime, nonroot |
| `dee-relay.service` | Bare-binary systemd unit — the simpler option |
| `dee-relay-container.service` | Podman variant of the same |
| `journald@deechat.conf` | Volatile log namespace, so logs do not land on disk |
| `node.env.example` | Every knob, with the values a small VPS should use |
| `memory-ceiling.sh` | Derives `MemoryMax` / `GOMEMLIMIT` from an env file |
| `build.sh` | Release build with the reproducibility flags, prints SHA-256 |
| `Caddyfile.example` | Reverse proxy: TLS, the `/mesh/*` 404, body limits, no logs |
| `nginx.conf.example` | Same rules for hosts that already run nginx |
| `monitor.sh` | Polls `/health` and alerts on the six signals that matter |
| `dee-node-monitor.service` / `.timer` | Runs the poll every minute |
| `setup-verify.sh` | One run, one report: binary, unit, exposure, running config, and a canary through the live delivery path |
| `acceptance.sh` | Single-relay assertions — reboot survival, the unit, the caps |
| `probe-public.sh` | Mesh-exposure assertions — the proxy, the public listener, and the mesh listener, independently |
| `pool-verify.sh` | Pool assertions — every member, then a canary that has to cross the pool and then be purged from it |
| `FINGERPRINTS.md` | The published record: what each fingerprint proves, and what it does not |
| `verify-artifact.sh` | The reproducible-build check a third party runs: rebuild, compare digests |
| `base-pins.sh` | Whether the pinned base digests still match their tags |
| `spki-hash.sh` | A relay's endpoint fingerprint, with the expiry it is good until |

## Install (bare binary)

```bash
./deploy/build.sh --verify                       # or docker build -f deploy/Dockerfile .
scp bin/dee-relay-linux-amd64 relay-1:/tmp/

# on the host
useradd --system --no-create-home --shell /usr/sbin/nologin deechat
install -m 0755 /tmp/dee-relay-linux-amd64 /usr/local/bin/dee-relay
install -d -m 0750 /etc/deechat
install -m 0640 -o root -g deechat node.env.example /etc/deechat/node.env
$EDITOR /etc/deechat/node.env                    # id, public URL, caps

./memory-ceiling.sh /etc/deechat/node.env        # → MemoryMax and GOMEMLIMIT
$EDITOR dee-relay.service                    # replace MemoryMax=REPLACE_ME
$EDITOR /etc/deechat/node.env                    # replace GOMEMLIMIT=REPLACE_ME

install -m 0644 journald@deechat.conf /etc/systemd/journald@deechat.conf
install -m 0644 dee-relay.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now dee-relay
```

## Install (proxy and monitoring)

```bash
# on the host
cp Caddyfile.example /etc/caddy/Caddyfile
$EDITOR /etc/caddy/Caddyfile                     # the hostname, and the body
                                                 # limits if you changed the caps
caddy validate --config /etc/caddy/Caddyfile     # nginx -t for the nginx variant
systemctl reload caddy

install -m 0755 monitor.sh /usr/local/bin/dee-node-monitor.sh
install -m 0644 dee-node-monitor.service dee-node-monitor.timer /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now dee-node-monitor.timer
```

The monitor exits 1 on a warning and 2 on something critical, and
`dee-node-monitor.service` has a commented `OnFailure=` for wiring that to
whatever alerts you. Wire it to something. A monitor that notifies nobody is
worse than no monitor, because it produces a green dashboard.

## Acceptance

Two runs with a reboot between them. The first proves the relay is configured
the way it claims; the second proves nobody had to be there.

```bash
./acceptance.sh http://127.0.0.1:8080 \
    --unit dee-relay.service --expect-fetch-auth false --expect-mesh false

reboot

./acceptance.sh http://127.0.0.1:8080 \
    --unit dee-relay.service --expect-fetch-auth false --expect-mesh false \
    --after-reboot

./memory-ceiling.sh /etc/deechat/node.env --check-unit /etc/systemd/system/dee-relay.service
```

`--after-reboot` asserts both the node's `uptimeSec` and the host's own uptime
are small. Without the second of those, a passing run only shows a process
running — not that it started itself.

Then the proxy, from anywhere and from the host:

```bash
./probe-public.sh https://relay-1.example.org                       # Layer 1 only
./probe-public.sh https://relay-1.example.org \
    --loopback-url http://127.0.0.1:8080 \
    --mesh-secret "$(grep MESH_SECRET /etc/deechat/node.env | cut -d= -f2)"
```

## Checking a whole relay in one run

The scripts above are per-milestone: each proves one thing well and assumes you
know which one to reach for. `setup-verify.sh` is the other shape — it checks the
whole relay at once and prints a report meant to be read by someone who was not
there when it ran.

```bash
sudo ./setup-verify.sh                                  # a standard install
sudo ./setup-verify.sh --report /tmp/relay-verify.txt
```

With no arguments it reads `/etc/deechat/node.env`, finds the unit, and derives
both URLs from it. It never prints a secret, it says "needs a human" rather than
guessing, and the test record it puts through the delivery path is minted with a
short life — so an interrupted run leaves an empty relay a minute later, with no
purge tombstone and nothing to clean up by hand.

Two of its checks exist nowhere else here. It compares the **running process
against the file on disk** — a cap edited and never restarted is the likeliest
single defect in a hand-built relay, and `/health` looks perfectly healthy
through it. And it puts a canary through the **full delivery cycle**: posted,
read back by the holder of its secret, refused to everyone else, deleted the
moment it is acked, and its remains expired and swept with nobody asking.

It deliberately does not duplicate what needs something it cannot have: reboot
survival stays in `acceptance.sh` (two runs, one reboot), the deeper mesh layers
stay in `probe-public.sh` (they need the pool secret), and replication stays in
`pool-verify.sh` (it needs more than one relay). It calls `memory-ceiling.sh`
directly when it is alongside.

## Publishing and checking fingerprints

```bash
./base-pins.sh                       # are the pinned base digests still current?
docker build -f deploy/Dockerfile -t dee-relay:$TAG .   # the release build
./verify-artifact.sh                 # rebuild, compare against FINGERPRINTS.md
./spki-hash.sh relay-1.example.org   # the endpoint fingerprint + its expiry
```

Record the binary digest and the SPKI hash in [`FINGERPRINTS.md`](FINGERPRINTS.md)
— it is both the human-readable record and the file `verify-artifact.sh` reads, so
the two cannot disagree. Read that file before publishing anything: the two
fingerprints prove different things, and neither proves the relay you are polling
is running that binary.

Two practical notes. The endpoint fingerprint **rotates** — Caddy makes a new
certificate key on every renewal by default, so it is published as a dated
observation and refreshed, not pinned. And a digest pin freezes the base image's
CA bundle, which the mesh syncer needs current roots from, so `base-pins.sh` is a
periodic decision, not a one-off.

## Four things worth understanding before you run one

**Memory is the loss mode.** Every store is a RAM map. An OOM kill does not
degrade the relay, it empties it: every undelivered message on that host is
gone. So `MemoryMax` comes from `memory-ceiling.sh` against the host's own env
file, `GOMEMLIMIT` sits below it so the collector fights back before the kernel
does, and `MemorySwapMax=0` because swap would write queued ciphertext to disk —
durable state by the back door on a relay whose whole claim is that it holds
none.

The attachment relay is the term that surprises people: `RELAY_MAX_SESSIONS ×
RELAY_MAX_WINDOW × MAX_CHUNK_BYTES` is 2 GB at the defaults, dwarfing the text
queues. `node.env.example` ships 16 × 4 × 1 MiB instead. Lower the session and
window counts, never the chunk size — the client's chunks are ~700 KB encrypted
and a smaller cap rejects all of them.

**Request bodies are bounded twice, and both halves matter.** The caps are
checked *after* a request has been decoded, so an unbounded body is an unbounded
allocation. The binary now limits each route to what its cap can legitimately
carry (`internal/httpapi/body_limit.go`), and the proxy configs bound bodies from
the outside as well — at one coarser number per route family, not at the
binary's. Keep the proxy's numbers in step with `node.env` when you change a
cap: too low rejects real traffic, too high just defers the rejection to the
binary.

**The audit guards the binary, not the host.**
`internal/audit/no_durable_state_test.go` fails the build if the node grows a
way to write to disk. It has nothing to say about journald persisting captured
stdout to `/var/log/journal`, about a volume mount, about swap — or about the
proxy. nginx buffers request bodies to a temp file once they pass
`client_body_buffer_size`, which on this relay means attachment chunks landing
in `/var/lib/nginx/body`; `nginx.conf.example` turns that off explicitly, and
Caddy streams by default. Access logs are off in both: every line would carry a
queue id in the URL and a client IP. Turning one on to debug something is a
change to the privacy posture, not an ops convenience.

**`/mesh/*` must not be reachable from the internet.** It demands
`X-Dee-Mesh-Secret`, but the snapshot endpoint returns
every identity's queued records by design — it is the replication path. Two
independent layers, because the point of two is that neither is load-bearing
alone: the secret, and a proxy that returns `404` for `/mesh/*`.

`probe-public.sh` checks them separately, and it will not accept a 404 whose
body is Go's `404 page not found` — that one came from the node, which means the
proxy forwarded the request and Layer 1 is missing. With `DEE_NODE_MESH_SECRET`
unset the routes are unmounted and everything 404s anyway, so without that
distinction the probe would pass a relay that is one `DEE_NODE_MESH_SECRET=`
away from an open door.

## Running more than one relay

A second relay is not a copy of the first with a different hostname. Four things
have to be true, and each of them was false in a build that looked healthy:

**1. Replication has its own listener, on a private address.** `/mesh/*` is not
served on `DEE_NODE_ADDR` in any configuration. Set `DEE_NODE_MESH_ADDR` to this
host's address on a private network — WireGuard, Tailscale, or a provider private
network — and the node will refuse to boot on a wildcard (`:8081`) or public bind.
This is why the proxy's `/mesh/*` 404 is now belt-and-braces rather than the only
thing between the internet and every identity's queued records: the peer reaches
replication at an address the proxy never sees, and the public port has no such
route to forward.

**2. The peer list is `DEE_NODE_MESH_PEERS`, it holds peering urls, and every
member lists every other member.** Replication is pull-only, so a record crosses
when the *receiving* relay pulls it; a one-way list replicates one way.
`DEE_NODE_TRUSTED_NODES` is refused at boot rather than ignored.

**3. Monitoring asserts that replication is happening**, not that it is switched
on:

```bash
deploy/monitor.sh http://127.0.0.1:8080 --env-file /etc/deechat/node.env \
    --expect-mesh true --expect-peers 2 --max-sync-age 120
```

On a relay that serves provisioned circles, add `--expect-admission true`. It is
the same class of check as the fetch-auth one and it fails the same way:
`DEE_NODE_REQUIRE_ADMISSION=ture` boots cleanly, `/health` reports
`requireAdmission: false`, and every circle on a gated box is carried for free
with nothing anywhere saying so. Passing `--env-file` asserts it automatically
from `DEE_NODE_REQUIRE_ADMISSION`. On a self-hosted box leave it alone — unset
means open, and open is the product there.

`meshEnabled=true` says the feature is configured and nothing more. A pool whose
every sync returned `404` for an hour published exactly the same `/health` as a
working one, with the failures in a volatile journal nobody reads. `mesh.peers`,
`mesh.reachable` and `mesh.oldestSyncAgeSec` are what make that visible; the last
is `-1` when a peer has never synced at all.

**4. The pool is checked as a pool.** Per-relay probes cannot see divergence:

```bash
deploy/probe-public.sh https://relay-1.example.org \
    --loopback-url http://127.0.0.1:8080 \
    --mesh-url http://10.0.0.1:8081 --mesh-secret "$DEE_NODE_MESH_SECRET"

deploy/pool-verify.sh https://relay-1.example.org https://relay-2.example.org \
    https://relay-3.example.org --sync-interval 30
```

`pool-verify.sh` posts a canary with its own capability to one member, requires it
to become readable from every other member, then purges it and requires it to
disappear from all of them. Also run `verify-artifact.sh` on each host: whether a
relay runs the published artifact is not something the relay can be asked over
HTTP.

### What a pool member is trusted with

This is the whole trust model of a pool, and everything else in the repo that
touches replication points here rather than paraphrasing it: **joining a pool
means trusting every other member with your queues.**

Replication is pull-only. Nothing on any listener accepts a snapshot, so a member
cannot write into a peer that has not chosen to pull from it, and there is no
endpoint an outsider can post one to.

Choosing to pull is the whole of the trust decision, and it is not a narrow one.
An imported snapshot's envelopes are injected into the local queues; its acks are
applied, and five of the six ack types delete the queued message they name; its
purge tombstones run an owner purge, which deletes queued mail belonging to a
third party. That is what replication is rather than a gap in validation — a pool
that does not trust its members has no mesh.

A shared pool secret proves *pool membership*, not peer identity. Any member can
act as any other, and a compromised member can serve a poisoned snapshot to every
peer that pulls from it. What it cannot do is introduce a host of its own choosing
to the rest of the pool: a peer is reached only because the pulling side lists it
in `DEE_NODE_MESH_PEERS`.

Per-node keypairs remain the upgrade that would change the last two paragraphs.
Until then, run a pool only across hosts you control, or across hosts whose
operators you would trust with the queued records themselves.

## What has not been run

The proxy files have not been run through `caddy validate` or `nginx -t` — do
that on the host before reloading. `probe-public.sh` has been checked against a
stand-in proxy implementing the same rules, which validates the probe, not the
configs.

**No release has been built from the pinned image, so `FINGERPRINTS.md` records no
digests yet** and `verify-artifact.sh` exits 4 saying there is nothing to compare
against. The container build path is the one thing here that needs a machine
with Docker or podman; everything else has been run. Note also what `build.sh
--verify` does and does not show: determinism for one toolchain on one machine,
which is the necessary half of a reproducible build, not the sufficient one. It
now prints the pinned version alongside the local one and says plainly when they
differ, because a digest from the wrong toolchain is not the release digest.

The endpoint fingerprint table is empty for the same reason as the single-relay
acceptance runs: there is no host.

**Replication has been verified on a three-relay loopback pool, not on three
hosts.** Everything above ran against three binaries on one machine talking over
loopback with 2-second sync intervals: convergence, the paging fix (620 records
crossing all three, where the earlier unpaged exchange stalled at 500), purge
propagation, a peer restart, `monitor.sh` going critical when a member dies, and
every
`pool-verify.sh` assertion failing when the condition it names is broken. What
loopback cannot show is the peering network — a real WireGuard or private-network
path, a relay whose peer is down for minutes rather than seconds, and TLS between
the client and each member. Turning queue-read authorization on across a pool is
a separate step again — see the main README, § "Queue-read authorization".
