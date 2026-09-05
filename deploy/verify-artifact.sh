#!/usr/bin/env bash
#
# Rebuild the relay binary from this source tree and compare its SHA-256 against
# the published digest. This is the script a third party runs; nothing in it
# needs credentials, a host, or trust in us.
#
#   deploy/verify-artifact.sh                      # container build, digest from FINGERPRINTS.md
#   deploy/verify-artifact.sh --expect <sha256>
#   deploy/verify-artifact.sh --arch arm64
#   deploy/verify-artifact.sh --runtime local      # no container runtime available
#
# Exit 0 match, 1 MISMATCH, 2 usage, 3 no usable build runtime, 4 no published
# digest to compare against, 5 matched a *candidate* digest (see below).
#
# Exit 5 is not a pass. FINGERPRINTS.md can carry a candidate digest — one built
# with the pinned toolchain but not yet through the pinned image — so that the
# first container build has something to disagree with. Matching it is evidence
# the two build paths agree; it says nothing about a published release, because
# there isn't one. Only a `binary-sha256` line is a published claim, and only
# matching that exits 0.
#
# Read what a match does and does not establish before relying on it:
#
#   It establishes that the published binary was built from source you can read.
#   It does NOT establish that the relay you are talking to is running it — a
#   digest attests to an artifact, never to a running process. See
#   deploy/FINGERPRINTS.md, which says the same thing at more length, because the
#   two claims are routinely conflated and only one of them is true here.

set -euo pipefail

arch="amd64"
expect=""
runtime=""
keep=0
while [ $# -gt 0 ]; do
    case "$1" in
        --arch) arch="$2"; shift 2 ;;
        --expect) expect="$2"; shift 2 ;;
        --runtime) runtime="$2"; shift 2 ;;
        --keep) keep=1; shift ;;
        *) echo "usage: verify-artifact.sh [--arch amd64|arm64] [--expect <sha256>] [--runtime docker|podman|local] [--keep]" >&2; exit 2 ;;
    esac
done

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

digest() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | cut -d' ' -f1
    else
        shasum -a 256 "$1" | cut -d' ' -f1
    fi
}

# The published digest lives in FINGERPRINTS.md in a line the script can read, so
# the document a human checks and the value a script compares cannot disagree.
published_digest() {
    sed -n "s/^binary-sha256 linux\/$arch \([0-9a-f]\{64\}\)$/\1/p" deploy/FINGERPRINTS.md | tail -1
}

# Read separately and never merged into the above: the whole value of a candidate
# is that it cannot be mistaken for a published digest by a script any more than
# by a reader.
candidate_digest() {
    sed -n "s/^binary-sha256-candidate linux\/$arch \([0-9a-f]\{64\}\)$/\1/p" deploy/FINGERPRINTS.md | tail -1
}

if [ -z "$runtime" ]; then
    if command -v docker >/dev/null 2>&1; then runtime="docker"
    elif command -v podman >/dev/null 2>&1; then runtime="podman"
    else runtime="none"
    fi
fi

pinned_go="$(sed -n 's/^FROM golang:\([0-9.]*\)-alpine@sha256:.*/\1/p' deploy/Dockerfile | head -1)"

case "$runtime" in
docker|podman)
    command -v "$runtime" >/dev/null 2>&1 || { echo "$runtime not found" >&2; exit 3; }
    tag="dee-relay-verify:$arch"
    echo "runtime    $runtime ($($runtime --version 2>/dev/null | head -1))"
    echo "builder    pinned in deploy/Dockerfile (go$pinned_go, digest-pinned base)"
    # --pull=never would be wrong here: the digest pin IS the integrity check, and
    # a verifier who has never pulled these bases has to be allowed to.
    "$runtime" build --platform "linux/$arch" -f deploy/Dockerfile -t "$tag" . >&2
    # distroless has no shell, so the binary comes out through the container
    # filesystem rather than by running anything inside the image.
    container="$("$runtime" create --platform "linux/$arch" "$tag")"
    out="$(mktemp -t dee-relay-verify.XXXXXX)"
    "$runtime" cp "$container:/usr/local/bin/dee-relay" "$out" >/dev/null
    "$runtime" rm -f "$container" >/dev/null
    if [ "$keep" = "0" ]; then trap 'rm -f "$out"' EXIT; else echo "binary     $out"; fi
    built="$(digest "$out")"
    ;;
local)
    command -v go >/dev/null 2>&1 || { echo "go not found and no container runtime" >&2; exit 3; }
    local_go="$(go env GOVERSION)"; local_go="${local_go#go}"
    echo "runtime    local go$local_go"
    if [ "$local_go" != "$pinned_go" ]; then
        # Not a warning. A different compiler produces different bytes, so a
        # comparison here would fail for a reason that says nothing about whether
        # the published artifact is honest — which is worse than not comparing.
        echo "           go$local_go is not the pinned go$pinned_go: a local build" >&2
        echo "           cannot match the published digest. Install go$pinned_go, or use" >&2
        echo "           a container runtime, or run deploy/build.sh to just see a digest." >&2
        exit 3
    fi
    out="$(mktemp -t dee-relay-verify.XXXXXX)"
    [ "$keep" = "0" ] && trap 'rm -f "$out"' EXIT
    CGO_ENABLED=0 GOOS=linux GOARCH="$arch" GOTOOLCHAIN=local \
        go build -trimpath -buildvcs=false -ldflags="-s -w -buildid=" -o "$out" ./cmd/dee-relay
    built="$(digest "$out")"
    ;;
none)
    echo "no container runtime (docker/podman) and --runtime local not requested" >&2
    exit 3
    ;;
*)
    echo "unknown runtime: $runtime" >&2
    exit 2
    ;;
esac

echo "target     linux/$arch"
echo "rebuilt    $built"

if [ -z "$expect" ]; then
    expect="$(published_digest)"
fi

if [ -z "$expect" ]; then
    echo "published  none recorded for linux/$arch in deploy/FINGERPRINTS.md"

    # A candidate is checked only when nothing is published. If both exist the
    # published line wins outright: a release that ships must never be verified
    # against a number that was explicitly not the release.
    candidate="$(candidate_digest)"
    if [ -n "$candidate" ]; then
        echo "candidate  $candidate"
        if [ "$built" = "$candidate" ]; then
            echo "result     CANDIDATE MATCH — this build path agrees with the recorded candidate"
            echo
            echo "Not a pass against a published release, because none is published. What"
            echo "it does show is that two independent build paths produce identical bytes"
            echo "from this source. See 'Promoting a candidate to published' in"
            echo "deploy/FINGERPRINTS.md for what to do with that."
            exit 5
        fi
        echo "result     MISMATCH against candidate" >&2
        echo >&2
        echo "Two build paths disagree on identical source. That is a finding about the" >&2
        echo "build, not a formatting problem: do not publish either digest until it is" >&2
        echo "explained. Check deploy/base-pins.sh first — a moved base pin invalidates" >&2
        echo "the comparison rather than failing it." >&2
        exit 1
    fi

    echo
    echo "Nothing to compare against, so this is not a pass. Either no release has"
    echo "been published for this architecture yet, or you are on a tree whose"
    echo "record has not been filled in. Pass --expect <sha256> to check a digest"
    echo "you got from elsewhere."
    exit 4
fi

echo "published  $expect"
if [ "$built" = "$expect" ]; then
    echo "result     MATCH — this source tree produces the published binary"
    exit 0
fi
echo "result     MISMATCH" >&2
exit 1
