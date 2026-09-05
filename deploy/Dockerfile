# syntax=docker/dockerfile:1
#
# Build context is the chat-node module root:
#   docker build -f deploy/Dockerfile -t dee-relay:dev .
#
# The runtime layer holds the binary and nothing else. There is no shell, no
# package manager, and no writable layer — which is the container half of the
# claim the no-durable-state audit makes about the binary.

# Both stages are pinned by digest. A tag is mutable — golang:1.26.5-alpine is
# rebuilt whenever Alpine moves — so a tag pin makes the build repeatable but not
# reproducible, and the SHA-256 published in FINGERPRINTS.md would drift out from
# under it. The tag is kept beside the digest for legibility; the digest is what
# Docker resolves, and there is deliberately no ARG to override the version with,
# because a version that no longer matches the digest is a silent contradiction.
#
# Both pins are multi-arch image indexes, so --platform and TARGETARCH still
# work. `deploy/base-pins.sh` reports when a tag has moved past its pin: a digest
# pin freezes the base's CA bundle too, and the mesh syncer needs current roots
# to reach an HTTPS peer, so these are reviewed deliberately, not set and left.
FROM golang:1.26.5-alpine@sha256:0178a641fbb4858c5f1b48e34bdaabe0350a330a1b1149aabd498d0699ff5fb2 AS build
WORKDIR /src

# GOTOOLCHAIN=local, because the default (auto) would defeat both claims this
# file makes. Verified: with auto, a go.mod requiring a newer Go than the builder
# ships makes the toolchain *download* another one mid-build ("go: downloading
# go1.99.0") — fetching over the network during a build documented as fetching
# nothing, and changing the compiler behind a pinned digest. local turns the same
# situation into a build failure that names the mismatch.
ENV GOTOOLCHAIN=local

# The module has no third-party dependencies (and so no go.sum) — the audit
# test enforces stdlib-only. Nothing is fetched during the build; if that ever
# changes, this COPY is the line that has to grow a verified download step.
COPY go.mod ./
COPY cmd ./cmd
COPY internal ./internal

ARG TARGETARCH=amd64
# CGO off gives a static binary with no libc to carry forward. -trimpath strips
# the builder's absolute paths and -buildid= drops the last nondeterministic
# field, so two builds of identical source produce identical bytes.
#
# -buildvcs=false because the default (auto) stamps vcs.revision, vcs.time and
# vcs.modified into the binary. Verified: the same source built inside a git
# clone and from an export of it produced two different digests, and a dirty tree
# a third — so a digest published from one path could never be reproduced from
# another. This build stage never sees .git anyway (only go.mod, cmd, internal are
# copied), which is exactly why the two build paths disagreed. The cost is that
# the binary no longer self-identifies its commit; the digest-to-release mapping
# is published in deploy/FINGERPRINTS.md instead.
#
# These flags are asserted to match deploy/build.sh by
# internal/audit/reproducible_build_test.go: two build paths that drift apart
# quietly stop being one reproducible build.
RUN CGO_ENABLED=0 GOOS=linux GOARCH=${TARGETARCH} \
    go build -trimpath -buildvcs=false -ldflags="-s -w -buildid=" -o /out/dee-relay ./cmd/dee-relay

# distroless/static rather than scratch: it carries CA certificates, which the
# mesh syncer needs to reach an HTTPS peer, and a nonroot passwd entry.
FROM gcr.io/distroless/static-debian12:nonroot@sha256:f5b485ea962d9bd1186b2f6b3a061191539b905b82ec395de78cbfae51f20e35 AS runtime
COPY --from=build /out/dee-relay /usr/local/bin/dee-relay

# 65532 is distroless' nonroot uid. Numeric on purpose: the runtime must not
# depend on name resolution that a read-only rootfs might not provide.
USER 65532:65532

# The public listener only. The mesh listener is not published: /mesh/* must not
# be reachable from the internet even though it demands a secret.
EXPOSE 8080

# No HEALTHCHECK: there is no shell or curl in the image to run one, and that is
# the right trade. Health checking is external — deploy/acceptance.sh and the
# monitoring poller both hit GET /health from outside.
ENTRYPOINT ["/usr/local/bin/dee-relay"]
