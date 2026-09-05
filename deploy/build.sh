#!/usr/bin/env bash
#
# Build the release binary with the flags the container uses, and print its
# SHA-256.
#
#   deploy/build.sh                    # linux/amd64 into ./bin
#   deploy/build.sh --arch arm64
#   deploy/build.sh --verify           # build twice, assert identical bytes
#   deploy/build.sh --expect <sha256>  # fail unless the digest matches
#
# --verify checks determinism *for this toolchain on this machine*, which is the
# necessary half of a reproducible build, not the sufficient one. Matching a
# published digest also needs the same Go version, so this script reads the
# pinned version out of deploy/Dockerfile and says plainly whether the local
# toolchain is it. If it is not, the digest below is a digest of something — just
# not of the release. The published artifact is built from deploy/Dockerfile with
# its digest-pinned builder; see deploy/FINGERPRINTS.md.

set -euo pipefail

arch="amd64"
verify=0
expect=""
while [ $# -gt 0 ]; do
    case "$1" in
        --arch) arch="$2"; shift 2 ;;
        --verify) verify=1; shift ;;
        --expect) expect="$2"; shift 2 ;;
        *) echo "usage: build.sh [--arch amd64|arm64] [--verify] [--expect <sha256>]" >&2; exit 2 ;;
    esac
done

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"
mkdir -p bin

# Same flags as deploy/Dockerfile, asserted equal by
# internal/audit/reproducible_build_test.go. -buildvcs=false matters more than it
# looks: with the default, a build inside a git clone embeds the revision and a
# dirty-tree flag, so this script and the container build produced different bytes
# from identical source.
build() {
    CGO_ENABLED=0 GOOS=linux GOARCH="$arch" GOTOOLCHAIN=local \
        go build -trimpath -buildvcs=false -ldflags="-s -w -buildid=" -o "$1" ./cmd/dee-relay
}

digest() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | cut -d' ' -f1
    else
        shasum -a 256 "$1" | cut -d' ' -f1
    fi
}

# The pinned builder version, taken from the Dockerfile rather than duplicated
# here: two copies of a version number is how a "reproducible" build stops being
# one without anybody editing the build.
pinned_go="$(sed -n 's/^FROM golang:\([0-9.]*\)-alpine@sha256:.*/\1/p' deploy/Dockerfile | head -1)"
local_go="$(go env GOVERSION)"   # e.g. go1.26.5
local_go="${local_go#go}"

out="bin/dee-relay-linux-$arch"
build "$out"
first="$(digest "$out")"

echo "toolchain  go$local_go (pinned for the release: go$pinned_go)"
if [ -n "$pinned_go" ] && [ "$pinned_go" != "$local_go" ]; then
    echo "           NOTE local toolchain differs from the pin, so this digest is"
    echo "           not the release digest. Build from deploy/Dockerfile to match."
fi
echo "target     linux/$arch"
echo "binary     $out ($(wc -c <"$out" | tr -d ' ') bytes)"
echo "sha256     $first"

if [ "$verify" = "1" ]; then
    second_out="$(mktemp -t dee-relay.XXXXXX)"
    trap 'rm -f "$second_out"' EXIT
    build "$second_out"
    second="$(digest "$second_out")"
    if [ "$first" = "$second" ]; then
        echo "verify     deterministic (two builds, identical bytes)"
    else
        echo "verify     NOT deterministic: $first != $second" >&2
        exit 1
    fi
fi

if [ -n "$expect" ]; then
    if [ "$first" = "$expect" ]; then
        echo "expect     MATCH"
    else
        echo "expect     MISMATCH" >&2
        echo "           expected $expect" >&2
        echo "           got      $first" >&2
        exit 1
    fi
fi
