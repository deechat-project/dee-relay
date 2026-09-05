#!/usr/bin/env bash
#
# Pool acceptance: the pool is a pool. Run it against every member at once, from
# anywhere that can reach their public urls.
#
#   deploy/pool-verify.sh https://relay-1.example.org https://relay-2.example.org \
#       https://relay-3.example.org --sync-interval 30
#
# What a single relay cannot demonstrate, and this does:
#
#   1. Each member is a distinct relay, and each one's mesh block agrees about how
#      many peers it has. A relay configured with the wrong peer list looks
#      perfectly healthy on its own.
#   2. Replication is actually running — mesh.reachable equals mesh.peers, and no
#      member's oldest successful sync is stale. An earlier build's pool whose
#      every sync returned 404 published exactly the same /health as a working
#      one.
#   3. A message posted to one member becomes readable from every other, within
#      the time the sync interval allows. This is the pool's entire purpose and it
#      was the thing that silently did not work: replication capped at one page,
#      so a relay holding more than 500 undelivered records never replicated the
#      newest ones.
#   4. A purge on one member removes the record from all of them, rather than the
#      record coming back on the next exchange.
#
# The canary is a real envelope on a random queue id with its own capability, so
# the probe can post it, read it back, and purge it without touching anyone
# else's mail. Nothing is left behind: step 4 is the cleanup.
#
# Not in scope: that every member runs the published artifact. A relay can lie
# about that over HTTP, so it is checked on each host with
# deploy/verify-artifact.sh — see deploy/FINGERPRINTS.md.
#
# Exit codes: 0 all assertions passed, 1 an assertion failed, 2 usage error.

set -uo pipefail

sync_interval=30
urls=()

usage() {
    cat >&2 <<'EOF'
usage: pool-verify.sh <public-url> <public-url> [<public-url> …] [options]

  --sync-interval <seconds>  DEE_NODE_MESH_SYNC_INTERVAL of the pool (default 30).
                             Convergence is allowed 3x this; staleness is
                             critical past 4x.
EOF
    exit 2
}

while [ $# -gt 0 ]; do
    case "$1" in
        --sync-interval) [ $# -ge 2 ] || usage; sync_interval="$2"; shift 2 ;;
        -h|--help) usage ;;
        -*) usage ;;
        *) urls+=("${1%/}"); shift ;;
    esac
done
[ "${#urls[@]}" -ge 2 ] || usage

failures=0
pass() { printf '  ok    %s\n' "$1"; }
fail() { printf '  FAIL  %s\n' "$1" >&2; failures=$((failures + 1)); }
info() { printf '  ..    %s\n' "$1"; }

json_field() {
    printf '%s' "$1" | sed -n "s/.*\"$2\"[[:space:]]*:[[:space:]]*\([^,}]*\).*/\1/p" | tr -d '" ' | head -n 1
}

expected_peers=$(( ${#urls[@]} - 1 ))
max_age=$(( sync_interval * 4 ))
deadline_seconds=$(( sync_interval * 3 ))

echo "== members =="
node_ids=""
for url in "${urls[@]}"; do
    health="$(curl -fsS --max-time 10 "$url/health" 2>/dev/null)"
    if [ -z "$health" ]; then
        fail "GET $url/health did not answer"
        continue
    fi
    node_id="$(json_field "$health" nodeId)"
    mesh_enabled="$(json_field "$health" meshEnabled)"
    peers="$(json_field "$health" peers)"
    reachable="$(json_field "$health" reachable)"
    age="$(json_field "$health" oldestSyncAgeSec)"

    case " $node_ids " in
        *" $node_id "*)
            fail "$url reports nodeId=$node_id, which another member already claimed — two relays sharing an id make monitoring meaningless" ;;
        *)
            node_ids="$node_ids $node_id" ;;
    esac

    if [ "$mesh_enabled" != "true" ]; then
        fail "$url has meshEnabled=$mesh_enabled — it is not in the pool"
        continue
    fi
    if [ -z "$peers" ]; then
        fail "$url publishes no mesh block; this build predates pool replication"
        continue
    fi
    if [ "$peers" != "$expected_peers" ]; then
        fail "$url ($node_id) has mesh.peers=$peers, expected $expected_peers — check DEE_NODE_MESH_PEERS on that host"
    elif [ "$reachable" != "$peers" ]; then
        fail "$url ($node_id) is replicating with $reachable of $peers peers"
    elif [ "$age" -lt 0 ]; then
        fail "$url ($node_id) has never completed a sync with at least one peer"
    elif [ "$age" -gt "$max_age" ]; then
        fail "$url ($node_id) last synced its slowest peer ${age}s ago (limit ${max_age}s)"
    else
        pass "$url ($node_id): $reachable/$peers peers, oldest sync ${age}s ago"
    fi
done

# --- convergence -------------------------------------------------------------
# The capability and its tag: the tag is what the relay matches a fetch against,
# and only the holder of the secret can produce it. Generated here so the canary
# is readable by this probe and nobody else.
# The tag is base64url of SHA-256 over the domain-separated secret, exactly as
# internal/queue.TagForSecret and the Dart client derive it. openssl rather than
# sha256sum/shasum because those disagree between Linux and macOS, and this script
# runs from wherever the operator is.
random_hex() { head -c "$1" /dev/urandom | od -An -tx1 | tr -d ' \n'; }
canary_secret="$(random_hex 32)"
canary_tag="$(printf 'deechat.queue-tag.v1|%s' "$canary_secret" \
    | openssl dgst -sha256 -binary | openssl base64 | tr -d '\n' | tr '+/' '-_' | tr -d '=')"
canary_queue="pool-verify-$(random_hex 8)"
canary_id="pool-verify-$(date +%s)-$$"
# The purge hash is an opaque handle its owner holds. Random here: the probe is
# the owner of this canary and nothing else must match it.
purge_hash="pool-verify-purge-$(random_hex 16)"

echo
echo "== convergence =="
post_body=$(cat <<EOF
{"id":"$canary_id","sender":"$canary_queue","recipient":"$canary_queue",
 "encryptedPayload":"cG9vbC12ZXJpZnk=","recipientTag":"$canary_tag","senderTag":"$canary_tag",
 "metadata":{"purgeHash":"$purge_hash"}}
EOF
)
origin="${urls[0]}"
post_code="$(printf '%s' "$post_body" | curl -so /dev/null -w '%{http_code}' --max-time 15 \
    -X POST -H 'Content-Type: application/json' --data-binary @- "$origin/messages" 2>/dev/null)"
case "$post_code" in
    200|201|202) pass "posted the canary to $origin" ;;
    *) fail "posting the canary to $origin returned $post_code; convergence cannot be checked"; post_code="" ;;
esac

if [ -n "$post_code" ]; then
    for url in "${urls[@]:1}"; do
        waited=0
        found=""
        while [ "$waited" -le "$deadline_seconds" ]; do
            body="$(curl -fsS --max-time 10 -H "X-Dee-Queue-Capability: $canary_secret" \
                "$url/messages?recipient=$canary_queue" 2>/dev/null)"
            case "$body" in
                *"$canary_id"*) found="yes"; break ;;
            esac
            sleep 2
            waited=$(( waited + 2 ))
        done
        if [ -n "$found" ]; then
            pass "the canary reached $url after ${waited}s"
        else
            fail "the canary never reached $url within ${deadline_seconds}s — this pool does not replicate"
        fi
    done
fi

# --- purge propagation and cleanup -------------------------------------------
echo
echo "== purge propagation =="
if [ -n "$post_code" ]; then
    purge_code="$(curl -so /dev/null -w '%{http_code}' --max-time 15 -X POST \
        -H 'Content-Type: application/json' -d "{\"purgeHash\":\"$purge_hash\"}" \
        "$origin/profile/purge" 2>/dev/null)"
    case "$purge_code" in
        200|202) info "purged the canary at $origin" ;;
        *) fail "POST /profile/purge at $origin returned $purge_code — the canary is still queued pool-wide" ;;
    esac

    for url in "${urls[@]}"; do
        waited=0
        gone=""
        while [ "$waited" -le "$deadline_seconds" ]; do
            body="$(curl -fsS --max-time 10 -H "X-Dee-Queue-Capability: $canary_secret" \
                "$url/messages?recipient=$canary_queue" 2>/dev/null)"
            case "$body" in
                *"$canary_id"*) ;;
                *) gone="yes"; break ;;
            esac
            sleep 2
            waited=$(( waited + 2 ))
        done
        if [ -n "$gone" ]; then
            pass "the canary is gone from $url after ${waited}s"
        else
            fail "the canary is still on $url ${deadline_seconds}s after the purge — a purged record that survives on one member comes back to the others"
        fi
    done
fi

echo
if [ "$failures" -eq 0 ]; then
    echo "all assertions passed for ${#urls[@]} members"
    exit 0
fi
echo "$failures assertion(s) failed"
exit 1
