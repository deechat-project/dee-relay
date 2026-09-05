#!/usr/bin/env bash
#
# Report whether the base-image digests pinned in deploy/Dockerfile are still
# what their tags resolve to.
#
#   deploy/base-pins.sh            # compare pins against the registries
#   deploy/base-pins.sh --print    # just print what the tags resolve to now
#
# Exit 0 pins current, 1 a tag has moved, 2 usage/lookup failure.
#
# Why this exists: pinning by digest is what makes the published SHA-256
# reproducible, and it also freezes everything the base carries — including
# distroless' CA bundle, which the mesh syncer needs current roots from to reach
# an HTTPS peer. So the pins are a standing decision to review, not a one-time
# edit, and a review needs the current values. A moved tag is *not* a failure to
# fix immediately: it means upstream rebuilt, and someone has to decide whether
# to take it and republish the digest. Both are legitimate; drifting without
# knowing is not.
#
# Needs curl only — no container runtime, which is the point: the operator who
# has to make this call may not be the one who can build.

set -euo pipefail

print_only=0
case "${1:-}" in
    "") ;;
    --print) print_only=1 ;;
    *) echo "usage: base-pins.sh [--print]" >&2; exit 2 ;;
esac

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
dockerfile="$root/deploy/Dockerfile"

accept="application/vnd.oci.image.index.v1+json, application/vnd.docker.distribution.manifest.list.v2+json, application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json"

# resolve <registry-host> <repository> <tag> [bearer-token]
# Prints the digest the tag currently resolves to. The digest comes from the
# Docker-Content-Digest response header rather than from hashing the body:
# re-hashing locally has to reproduce the exact bytes the registry canonicalized,
# and getting that subtly wrong would report drift that is not there.
resolve() {
    local host="$1" repo="$2" tag="$3" token="${4:-}"
    local headers auth=()
    headers="$(mktemp -t dee-base-pins.XXXXXX)"
    # Expanded as ${auth[@]+...} because gcr.io needs no token and bash 3.2 —
    # what macOS still ships — treats an empty array under `set -u` as unbound.
    [ -n "$token" ] && auth=(-H "Authorization: Bearer $token")
    if ! curl -sS -m 30 -o /dev/null -D "$headers" \
        "https://$host/v2/$repo/manifests/$tag" \
        -H "Accept: $accept" ${auth[@]+"${auth[@]}"}; then
        rm -f "$headers"
        return 1
    fi
    local digest
    digest="$(tr -d '\r' <"$headers" | sed -n 's/^[Dd]ocker-[Cc]ontent-[Dd]igest: //p' | tail -1)"
    rm -f "$headers"
    [ -n "$digest" ] || return 1
    printf '%s\n' "$digest"
}

# Docker Hub requires a token even for public pulls; gcr.io does not.
hub_token() {
    curl -sS -m 30 "https://auth.docker.io/token?service=registry.docker.io&scope=repository:library/$1:pull" \
        | sed -n 's/.*"token":"\([^"]*\)".*/\1/p'
}

status=0

check() {
    local label="$1" host="$2" repo="$3" tag="$4" pinned="$5" token="${6:-}"
    local current
    if ! current="$(resolve "$host" "$repo" "$tag" "$token")"; then
        echo "$label: LOOKUP FAILED for $tag" >&2
        status=2
        return
    fi
    if [ "$print_only" = "1" ]; then
        echo "$label"
        echo "  tag     $tag"
        echo "  current $current"
        return
    fi
    if [ "$current" = "$pinned" ]; then
        echo "$label: pin current"
        echo "  $tag -> $pinned"
    else
        echo "$label: TAG HAS MOVED"
        echo "  pinned  $pinned"
        echo "  current $current"
        echo "  decide: take the new base and republish the artifact digest, or keep the pin"
        [ "$status" = "2" ] || status=1
    fi
}

# Parse both pins out of the Dockerfile. One source of truth: a copy of these
# strings in this script is a second thing to forget to update.
builder_line="$(sed -n 's/^FROM \(golang:[^ ]*\) AS build/\1/p' "$dockerfile" | head -1)"
runtime_line="$(sed -n 's/^FROM \(gcr\.io\/[^ ]*\) AS runtime/\1/p' "$dockerfile" | head -1)"

if [ -z "$builder_line" ] || [ -z "$runtime_line" ]; then
    echo "could not find both FROM lines in $dockerfile" >&2
    exit 2
fi

builder_tag="${builder_line#golang:}"; builder_tag="${builder_tag%@*}"
builder_pin="${builder_line#*@}"
runtime_ref="${runtime_line%@*}"
runtime_tag="${runtime_ref##*:}"
runtime_repo="${runtime_ref#gcr.io/}"; runtime_repo="${runtime_repo%:*}"
runtime_pin="${runtime_line#*@}"

case "$builder_line" in *@sha256:*) ;; *) echo "builder FROM is not digest-pinned: $builder_line" >&2; exit 2 ;; esac
case "$runtime_line" in *@sha256:*) ;; *) echo "runtime FROM is not digest-pinned: $runtime_line" >&2; exit 2 ;; esac

check "builder (docker.io/library/golang)" \
    "registry-1.docker.io" "library/golang" "$builder_tag" "$builder_pin" "$(hub_token golang)"
check "runtime (gcr.io/$runtime_repo)" \
    "gcr.io" "$runtime_repo" "$runtime_tag" "$runtime_pin"

exit "$status"
