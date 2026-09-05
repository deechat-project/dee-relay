# Published fingerprints

Two different claims, routinely conflated. Both are published; each says only
what it says.

## Artifact fingerprint

**SHA-256 of the released binary.** It proves the published artifact was built
from the source in this repository — checkable by anyone, without asking us
anything:

```bash
git checkout <release-tag>
deploy/verify-artifact.sh            # rebuild, compare against the record below
go test ./internal/audit             # the reason the digest is worth having
```

The audit test is the point of the exercise. A digest that matches source nobody
reads proves only that we shipped what we compiled. The digest plus
`internal/audit` — which fails the build if the relay gains a durable store —
is what makes *"this relay cannot keep your data"* checkable rather than
promised.

### The record

These lines are read by `deploy/verify-artifact.sh`; keep the format
(`binary-sha256 linux/<arch> <64 hex chars>`).

```
release: v0.1.0 (candidate — no tag cut, nothing published)
source-commit: none published yet
binary-sha256 linux/amd64 pending
binary-sha256 linux/arm64 pending
binary-sha256-candidate linux/amd64 6d59949502ab55588e5fc30fd6d591df7421ccd8153cdce6d4d8703f95fd80af
binary-sha256-candidate linux/arm64 ac9b886e1238ea1243995d96846b41b82e473bf11366be961c7d5f14aeccbc84
image-digest pending
```

**No release has been built from the pinned image yet**, so the published lines
stay `pending` and `verify-artifact.sh` still exits 4 for anyone asking it to
check a published claim. That is the honest answer and it does not change until
a container build produces one.

### Candidate is not published, and the difference is the whole point

The two `binary-sha256-candidate` lines were produced on 2026-08-12, before
this repository existed, from a private history no commit here corresponds to —
so nothing you can check out reproduces them, and that is one more reason they
are candidates. They were built by the **pinned toolchain** (go1.26.5, fetched with
`go install golang.org/dl/go1.26.5`) cross-compiling on macOS with the flags in
`deploy/build.sh` — twice per architecture, identical bytes both times. What that
establishes is real but narrow: the source is deterministic under the pinned
compiler.

What it does **not** establish is that the digest reproduces by the route this
document tells a third party to use, which is `deploy/Dockerfile` with its
digest-pinned builder. Nobody has run that route yet. Promoting these numbers to
the published lines before someone does would publish a value whose documented
reproduction path has never been executed — the same mistake as publishing a
digest from an unpinned toolchain, arrived at from the other direction.

So they sit here instead, where they do the one job they are good for: the
container build, when it happens, has something to disagree with. Two independent
paths landing on the same 64 hex characters is the evidence the reproducible-build
claim actually rests on; `internal/audit` asserts the two paths *ask* for the same
flags, and only this comparison shows they *produce* the same bytes.

They replace an earlier pair recorded 2026-08-10, which the `dee-tiny-node` →
`dee-relay` rename invalidated: the Go package import path is compiled into the
binary whatever `-trimpath` does, so moving `cmd/` moves the digest. The module
path `deechat/chat-node` is frozen for exactly this reason, and nothing else
scheduled before release touches a digest input.

Both base pins were confirmed current on 2026-08-10 (`deploy/base-pins.sh`), so a
container build run soon uses exactly the bases these candidates were meant to
match. If a pin moves first, rebuild the candidates too — the comparison is
meaningless across different bases.

### Promoting a candidate to published

```bash
deploy/base-pins.sh                      # pins still current? if not, stop
deploy/verify-artifact.sh --arch amd64   # container build; exit 5 == matches candidate
deploy/verify-artifact.sh --arch arm64
```

On exit 5 for both architectures: move each digest from its
`binary-sha256-candidate` line to the matching `binary-sha256` line, drop the
candidate lines, record the commit in this repository the release was built
from, cut the `v0.1.0` tag there, and record the
`image-digest` from the push. On exit 1, the two build paths disagree — that is a
finding about the build, not a formatting problem, and nothing gets published
until it is explained.

The tag is deliberately **not** cut yet. A tag that has to move because the
container build disagreed is worse than a commit id in a record, so `v0.1.0`
lands on the source only once the digest it names is confirmed.

### What makes the rebuild reproducible

- `CGO_ENABLED=0 GOOS=linux GOARCH=<arch>`, `-trimpath`, `-buildvcs=false`,
  `-ldflags="-s -w -buildid="`. `-trimpath` removes the builder's absolute paths;
  `-buildid=` drops the last nondeterministic field.
- `-buildvcs=false`, which is the flag this milestone would have shipped without
  and been wrong. Go's default (`auto`) stamps `vcs.revision`, `vcs.time` and
  `vcs.modified` into the binary, so the same source produced **three** different
  digests: built in a git clone, built from an export of that clone, and built in
  a clone with one file edited. The container build never sees `.git` — it copies
  `go.mod`, `cmd` and `internal` — so the two supported build paths could not have
  matched each other. The cost is that the binary no longer records its own
  commit; the digest-to-release mapping lives in the record above instead.
  `internal/audit/reproducible_build_test.go` asserts the flags in
  `deploy/Dockerfile` and `deploy/build.sh` stay identical, because two build
  paths that drift apart quietly stop being one reproducible build.
- Both `FROM` lines in `deploy/Dockerfile` are **digest-pinned**. A tag is
  mutable — `golang:1.26.5-alpine` is rebuilt whenever Alpine moves — so a tag
  pin gives a repeatable build, not a reproducible one.
- `GOTOOLCHAIN=local` in the build stage. With the default (`auto`), a `go.mod`
  requiring a newer Go than the builder ships makes the toolchain download
  another one mid-build: a different compiler behind an unchanged digest pin, and
  a network fetch during a build documented as fetching nothing.
- The module has **no third-party dependencies** (stdlib only, enforced by
  `internal/audit`), so there is no dependency tree to pin and nothing is
  fetched.
- The toolchain pin is **go1.26.5**. `go.mod` says `go 1.22`, which is a language
  floor, not the build version. The pin is also a security decision: the node is
  almost entirely `net/http`, so a builder on an end-of-life Go freezes the
  relay's TLS and HTTP stack at that release's patch level.

### The image digest is not the reproducible one

`image-digest` above identifies the exact image we pushed, for pinning a pull
(`podman pull …@sha256:…` in `dee-relay-container.service`). The registry
verifies it on download, so it is a real integrity check.

It is **not** something a third party should expect to reproduce. Layer tarballs
and the image config carry timestamps and ordering that the binary does not;
matching an image digest needs `SOURCE_DATE_EPOCH` plus timestamp rewriting and
still depends on the builder implementation. Reproduce the **binary** digest —
`verify-artifact.sh` extracts it from the image and hashes that, so it works on
whichever image you built.

## Endpoint fingerprint

**Base64 SHA-256 of the TLS certificate's SubjectPublicKeyInfo**, published
beside each relay's URL. It answers *"am I talking to the relay I think I am?"*
— useful for the Circle Relay Pack, where a steward hands out a relay address
and members want to check it out of band.

```bash
deploy/spki-hash.sh relay-1.example.org
deploy/spki-hash.sh relay-1.example.org --expect <base64>   # exit 3 on change
```

| Relay | URL | SPKI (base64 SHA-256) | Cert valid to | Recorded |
|-------|-----|-----------------------|---------------|----------|
| _none yet_ | | | | |

### This value rotates, and publishing it as a constant would be wrong

With Caddy's defaults **a new private key is generated for every new
certificate** — Caddy's own field documentation for `reuse_private_keys` says the
alternative exists so that "private keys already existing in storage will be
reused. Otherwise, a new key will be created for every new certificate to
mitigate pinning." With a 90-day ACME certificate renewed at 60 days, a published
SPKI hash therefore goes stale roughly every two months, and the alarm fires on
routine renewal — the worst possible failure mode for a value people are asked to
check.

So the fingerprint is published as a **dated observation with the certificate's
expiry attached**, not as a pin: the `Cert valid to` column is the date by which
the row must be refreshed, and a mismatch before that date is worth
investigating. `spki-hash.sh --expect` is the check; it prints the expiry so the
row can be refreshed from the same output.

Making the value stable is possible — `reuse_private_keys` in the site's `tls`
block, shipped commented in `Caddyfile.example` — but Caddy marks that option
**TEMPORARY** and says it "will likely be removed in the future," and it keeps
one key alive across years of renewals. Enabling it is a deliberate trade for a
relay whose fingerprint is handed out on paper, not the default.

Also worth being plain about the ceiling here: for a public hostname with a
browser-trusted certificate, TLS already answers most of the question. The SPKI
hash adds a check against mis-issuance and an out-of-band way to confirm an
address a steward gave you. That is genuinely useful and it is not dramatic.

## What neither fingerprint proves

**That the relay you are polling is running that binary.** A digest attests to an
artifact; it says nothing about a running process. Closing that gap needs remote
attestation, which is out of scope and out of proportion for this design.

The publishable claim is: *here is the source, here is the reproducible digest,
here is the audit test you can run yourself.* Never *"the running relay is
verified."*

## Keeping the pins honest

```bash
deploy/base-pins.sh        # do the pinned digests still match their tags?
```

A digest pin freezes everything the base image carries, including distroless' CA
bundle. That matters for a pool peered over `https` — the syncer needs current
roots to reach an HTTPS peer, and a frozen bundle is a relay that eventually
cannot. A pool peered over a private network (the arrangement `deploy/README.md`
describes, and the only one where `http` peering urls are accepted) makes no
outbound TLS connection at all, so the bundle is inert. Either way the pins are a
standing decision to review, not a one-time edit. When a base
moves and the new one is taken, the artifact digest changes too and the record
above has to be republished.
