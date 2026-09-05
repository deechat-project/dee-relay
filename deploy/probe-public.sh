#!/usr/bin/env bash
#
# Mesh-exposure acceptance: the mesh route is not reachable from the internet,
# not reachable on the relay's own public port, and not reachable with a spoofed
# credential on the private listener where it does live. Three layers, checked
# independently — the point of having three is that none is load-bearing alone,
# and a run that cannot tell them apart proves nothing.
#
#   deploy/probe-public.sh https://relay-1.example.org
#   deploy/probe-public.sh https://relay-1.example.org --loopback-url http://127.0.0.1:8080
#   deploy/probe-public.sh https://relay-1.example.org --loopback-url http://127.0.0.1:8080 \
#       --mesh-url http://10.0.0.1:8081 --mesh-secret "$DEE_NODE_MESH_SECRET"
#
# Layer 1 is the reverse proxy: /mesh/* returns 404 from the public hostname,
# whatever headers the caller presents — including the correct pool secret.
# Layer 2 is the binary's public listener, which has no mesh route at all: 404
# with the correct secret, mesh on or off.
# Layer 3 is the private mesh listener (--mesh-url): a spoofed peer header or a
# wrong secret gets 403, the correct secret gets a snapshot, and there is no
# endpoint that accepts one.
#
# Run Layers 2 and 3 from the relay host. Without --loopback-url / --mesh-url the
# script says so rather than reporting a pass on part of the work.
#
# Exit codes: 0 all assertions passed, 1 an assertion failed, 2 usage error.

set -uo pipefail

public_url=""
loopback_url=""
mesh_url=""
mesh_secret=""

usage() {
    cat >&2 <<'EOF'
usage: probe-public.sh <public-url> [options]

  --loopback-url <url>   the node's own public listener, for Layer 2
                         (run from the relay host)
  --mesh-url <url>       the node's DEE_NODE_MESH_ADDR listener, for Layer 3
  --mesh-secret <value>  the configured DEE_NODE_MESH_SECRET; lets the probe
                         confirm the proxy blocks even a VALID credential, and
                         that replication itself still works
EOF
    exit 2
}

while [ $# -gt 0 ]; do
    case "$1" in
        --loopback-url) [ $# -ge 2 ] || usage; loopback_url="$2"; shift 2 ;;
        --mesh-url) [ $# -ge 2 ] || usage; mesh_url="$2"; shift 2 ;;
        --mesh-secret) [ $# -ge 2 ] || usage; mesh_secret="$2"; shift 2 ;;
        -h|--help) usage ;;
        -*) usage ;;
        *) [ -z "$public_url" ] || usage; public_url="$1"; shift ;;
    esac
done
[ -n "$public_url" ] || usage
public_url="${public_url%/}"
loopback_url="${loopback_url%/}"
mesh_url="${mesh_url%/}"

failures=0
pass() { printf '  ok    %s\n' "$1"; }
fail() { printf '  FAIL  %s\n' "$1" >&2; failures=$((failures + 1)); }
skip() { printf '  skip  %s\n' "$1"; }

json_field() {
    printf '%s' "$1" | sed -n "s/.*\"$2\"[[:space:]]*:[[:space:]]*\([^,}]*\).*/\1/p" | tr -d '" '
}

code_for() {
    # code_for <method> <url> [curl args...]
    local method="$1" url="$2"; shift 2
    curl -so /dev/null -w '%{http_code}' --max-time 15 -X "$method" "$@" "$url" 2>/dev/null
}

body_for() {
    local method="$1" url="$2"; shift 2
    curl -s --max-time 15 -X "$method" "$@" "$url" 2>/dev/null
}

# Go's http.ServeMux writes exactly this for an unmounted route. It is the only
# way to tell the two 404s apart: when mesh is off the node also 404s /mesh/*,
# so a bare status code cannot distinguish "the proxy blocked this" from "the
# route was never mounted" — and only the first is Layer 1.
readonly go_mux_404="404 page not found"

echo "== the relay is up (so a blanket 404 cannot pass as Layer 1) =="
health="$(curl -fsS --max-time 15 "$public_url/health" 2>/dev/null)"
if [ -z "$health" ]; then
    fail "GET $public_url/health did not return 200 — fix this before reading anything below"
    echo
    echo "$failures assertion(s) failed"
    exit 1
fi
node_id="$(json_field "$health" nodeId)"
mesh_enabled="$(json_field "$health" meshEnabled)"
fetch_auth="$(json_field "$health" requireFetchAuth)"
pass "GET /health returns 200 through the proxy"
printf '        nodeId=%s meshEnabled=%s requireFetchAuth=%s\n' "$node_id" "$mesh_enabled" "$fetch_auth"

echo
echo "== TLS =="
case "$public_url" in
    https://*)
        pass "probing over https"
        plain_host="${public_url#https://}"
        plain_code="$(code_for GET "http://$plain_host/health")"
        case "$plain_code" in
            301|302|307|308) pass "plain http redirects ($plain_code) rather than serving" ;;
            000) pass "plain http refuses connections" ;;
            *) fail "plain http /health returned $plain_code — a public relay must not serve cleartext" ;;
        esac ;;
    *)
        fail "$public_url is not https — the client refuses http:// for non-local hosts, so this relay is unusable" ;;
esac

echo
echo "== layer 1: /mesh/* is not internet-reachable =="
# Every credential the old mesh check accepted, plus the one the new check
# accepts. All of them must get 404 here: the proxy does not care whether the
# caller is a legitimate pool member, because a pool member does not replicate
# over the public interface.
#
# Each probe checks two things: the status is 404, and the 404 did not come from
# the node. A request that reached the node and found no route carries Go's
# ServeMux body, which means the proxy forwarded /mesh/* — Layer 1 is absent, and
# what is hiding it is Layer 2 (the node does not mount mesh on its public port at
# all). Two layers exist so that one missing is a warning rather than a breach;
# a run that cannot tell which one answered has checked one thing twice.
probe_layer1() {
    local label="$1" method="$2" path="$3"; shift 3
    local code body
    code="$(code_for "$method" "$public_url$path" "$@")"
    body="$(body_for "$method" "$public_url$path" "$@")"
    if [ "$code" != "404" ]; then
        fail "$method $path $label -> $code, expected 404 — /mesh/* is internet-reachable"
        return
    fi
    case "$body" in
        *"$go_mux_404"*)
            fail "$method $path $label -> 404 from the NODE, not the proxy — the request was forwarded; Layer 1 is missing and mesh being off is the only thing hiding it" ;;
        *)
            pass "$method $path $label -> 404 from the proxy" ;;
    esac
}

probe_layer1 "(no headers)" GET /mesh/snapshot
probe_layer1 "with the node's own id" GET /mesh/snapshot -H "X-Dee-Node-ID: $node_id"
probe_layer1 "with a trusted-looking peer url" GET /mesh/snapshot -H "X-Dee-Node-URL: $public_url"
probe_layer1 "(no headers)" POST /mesh/sync -H 'Content-Type: application/json' -d '{}'
probe_layer1 "with the node's own id" POST /mesh/sync -H "X-Dee-Node-ID: $node_id" \
    -H 'Content-Type: application/json' -d '{}'

if [ -n "$mesh_secret" ]; then
    # The sharpest form of the assertion: a caller holding the real pool secret
    # still gets nothing from the public interface.
    probe_layer1 "with the CORRECT pool secret" GET /mesh/snapshot -H "X-Dee-Mesh-Secret: $mesh_secret"
else
    skip "no --mesh-secret: cannot confirm the proxy blocks a valid credential too"
fi

echo
echo "== body limits (the proxy's half) =="
# A body the caps could never accept should die at the proxy, before the node
# allocates it. 413 from the proxy; the node applies the same bound itself, so
# see the Layer 2 section for the other half.
big_body="$(head -c 2000000 /dev/zero | tr '\0' 'x')"
big_code="$(printf '%s' "$big_body" | curl -so /dev/null -w '%{http_code}' --max-time 20 \
    -X POST -H 'Content-Type: application/json' --data-binary @- "$public_url/messages" 2>/dev/null)"
if [ "$big_code" = "413" ]; then
    pass "a 2 MB POST /messages is rejected with 413"
else
    fail "a 2 MB POST /messages returned $big_code, expected 413 — check the proxy body limit"
fi

if [ -z "$loopback_url" ]; then
    echo
    echo "== layer 2: not checked =="
    skip "no --loopback-url — this run covered the proxy only, so it proves Layer 1 and nothing about the binary"
    skip "re-run from the relay host with --loopback-url http://127.0.0.1:8080"
else
    echo
    echo "== layer 2: the node's public listener has no mesh route =="
    local_health="$(curl -fsS --max-time 10 "$loopback_url/health" 2>/dev/null)"
    if [ -z "$local_health" ]; then
        fail "GET $loopback_url/health did not answer — is this the relay host?"
    else
        local_mesh="$(json_field "$local_health" meshEnabled)"
        local_id="$(json_field "$local_health" nodeId)"

        # This assertion does not depend on whether mesh is configured: /mesh/*
        # is not mounted on the public listener in any configuration, so the
        # node's own 404 is the expected answer even with the correct pool secret.
        # An earlier build answered the same request with 403 (mesh on) or 404
        # (mesh off), and the proxy was the only thing keeping it off the
        # internet.
        for header in "X-Dee-Node-ID: $local_id" "X-Dee-Node-URL: $public_url" "X-Dee-Mesh-Secret: ${mesh_secret:-wrong-secret}"; do
            code="$(code_for GET "$loopback_url/mesh/snapshot" -H "$header")"
            body="$(body_for GET "$loopback_url/mesh/snapshot" -H "$header")"
            if [ "$code" = "404" ] && [ "${body#*$go_mux_404}" != "$body" ]; then
                pass "public listener GET /mesh/snapshot with '${header%%:*}' -> 404, route not mounted"
            else
                fail "public listener GET /mesh/snapshot with '${header%%:*}' -> $code, expected the node's own 404; body=$(printf '%.60s' "$body")"
            fi
        done
        code="$(code_for POST "$loopback_url/mesh/sync" -H 'Content-Type: application/json' -d '{}')"
        if [ "$code" = "404" ] || [ "$code" = "405" ]; then
            pass "public listener POST /mesh/sync -> $code, the write endpoint does not exist"
        else
            fail "public listener POST /mesh/sync -> $code — replication is pull-only, this route was removed"
        fi
        if [ "$local_mesh" = "true" ] && [ -z "$mesh_url" ]; then
            skip "meshEnabled=true but no --mesh-url: Layer 3 unchecked, so nothing here proves the mesh listener is guarded"
        fi

        big_local="$(printf '%s' "$big_body" | curl -so /dev/null -w '%{http_code}' --max-time 20 \
            -X POST -H 'Content-Type: application/json' --data-binary @- "$loopback_url/messages" 2>/dev/null)"
        if [ "$big_local" = "413" ]; then
            pass "the binary rejects the 2 MB body itself (413), independent of the proxy"
        else
            fail "loopback 2 MB POST /messages returned $big_local, expected 413"
        fi
    fi
fi

echo
if [ -z "$mesh_url" ]; then
    echo "== layer 3: not checked =="
    skip "no --mesh-url — the private replication listener was not probed"
else
    echo "== layer 3: the private mesh listener =="
    mesh_host="${mesh_url#*://}"; mesh_host="${mesh_host%%:*}"
    case "$mesh_host" in
        10.*|127.*|192.168.*|172.1[6-9].*|172.2[0-9].*|172.3[01].*|100.6[4-9].*|100.[7-9][0-9].*|100.1[01][0-9].*|100.12[0-7].*|localhost|\[::1\])
            pass "the mesh listener is on a private address ($mesh_host)" ;;
        *)
            fail "the mesh listener is on $mesh_host, which is not a private address — it serves every identity's queued records to any holder of the pool secret" ;;
    esac

    for header in "X-Dee-Node-ID: $node_id" "X-Dee-Node-URL: $public_url" "X-Dee-Mesh-Secret: wrong-secret"; do
        code="$(code_for GET "$mesh_url/mesh/snapshot" -H "$header")"
        if [ "$code" = "403" ]; then
            pass "mesh listener GET /mesh/snapshot with '${header%%:*}' -> 403"
        else
            fail "mesh listener GET /mesh/snapshot with '${header%%:*}' -> $code, expected 403"
        fi
    done

    code="$(code_for POST "$mesh_url/mesh/sync" -H "X-Dee-Mesh-Secret: ${mesh_secret:-wrong-secret}" \
        -H 'Content-Type: application/json' -d '{}')"
    if [ "$code" = "404" ] || [ "$code" = "405" ]; then
        pass "mesh listener POST /mesh/sync -> $code, the write endpoint does not exist"
    else
        fail "mesh listener POST /mesh/sync -> $code — replication is pull-only, this route was removed"
    fi

    if [ -n "$mesh_secret" ]; then
        # The positive control. Without it the 403s above could equally mean the
        # listener is simply broken, which would pass a probe and fail a pool.
        code="$(code_for GET "$mesh_url/mesh/snapshot" -H "X-Dee-Mesh-Secret: $mesh_secret")"
        body="$(body_for GET "$mesh_url/mesh/snapshot" -H "X-Dee-Mesh-Secret: $mesh_secret")"
        if [ "$code" != "200" ]; then
            fail "mesh listener GET /mesh/snapshot with the correct secret -> $code — replication is broken, so the 403s above prove nothing"
        elif [ "${body#*epoch}" = "$body" ]; then
            fail "the snapshot carries no epoch — a peer cannot tell a restart from a gap, so paging is not safe"
        else
            pass "mesh listener GET /mesh/snapshot with the correct secret -> 200 with a paging cursor"
        fi
    else
        skip "no --mesh-secret: the 403s above could also mean the mesh listener is broken"
    fi
fi

echo
if [ "$failures" -eq 0 ]; then
    echo "all assertions passed"
    exit 0
fi
echo "$failures assertion(s) failed"
exit 1
