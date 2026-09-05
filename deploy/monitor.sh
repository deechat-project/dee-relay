#!/usr/bin/env bash
#
# Poll GET /health and alert on the six things that matter. Nothing else is
# sampled: the queue endpoints are never touched, so monitoring this relay
# cannot become a durable record of who talked to whom.
#
#   deploy/monitor.sh http://127.0.0.1:8080 --env-file /etc/deechat/node.env
#   deploy/monitor.sh https://relay-1.example.org --expect-fetch-auth false
#
# The signal to build first is the fetch-auth assertion. envBool falls back to
# the default on an unparseable value, so DEE_NODE_REQUIRE_FETCH_AUTH=ture boots
# cleanly and enforces nothing. That behaviour is deliberate and commented in
# config.go — which is exactly why the deployment has to read the value back out
# of /health instead of trusting a clean boot.
#
# Exit codes: 0 healthy, 1 warning, 2 critical, 3 usage error. Run it from
# dee-node-monitor.timer, or from any checker that understands exit codes.

set -uo pipefail

base_url=""
env_file=""
expect_fetch_auth=""
expect_admission=""
expect_mesh=""
expect_peers=""
max_sync_age=""
state_dir="/run/dee-node-monitor"
warn_pct=80

usage() {
    cat >&2 <<'EOF'
usage: monitor.sh <base-url> [options]

  --env-file <path>           read the caps from the node's env file, so
                              saturation is measured against the real limits
  --expect-fetch-auth <bool>  assert requireFetchAuth (overrides --env-file)
  --expect-admission <bool>   assert requireAdmission (overrides --env-file).
                              On the shared pool this is the one that turns a
                              paid box into a free one when it fails open
  --expect-mesh <bool>        assert meshEnabled
  --expect-peers <n>          assert mesh.peers, and that every one of them is
                              reachable — a pool that replicates nothing looks
                              identical to a healthy one without this
  --max-sync-age <seconds>    critical when the least recently synced peer last
                              succeeded longer ago than this (suggest 4x
                              DEE_NODE_MESH_SYNC_INTERVAL)
  --state-dir <dir>           where to remember the last uptime, for
                              crash-loop detection (default /run/dee-node-monitor,
                              which is tmpfs — monitoring adds no durable state
                              either)
  --warn-pct <n>              warn at this percentage of a cap (default 80)
EOF
    exit 3
}

while [ $# -gt 0 ]; do
    case "$1" in
        --env-file) [ $# -ge 2 ] || usage; env_file="$2"; shift 2 ;;
        --expect-fetch-auth) [ $# -ge 2 ] || usage; expect_fetch_auth="$2"; shift 2 ;;
        --expect-admission) [ $# -ge 2 ] || usage; expect_admission="$2"; shift 2 ;;
        --expect-mesh) [ $# -ge 2 ] || usage; expect_mesh="$2"; shift 2 ;;
        --expect-peers) [ $# -ge 2 ] || usage; expect_peers="$2"; shift 2 ;;
        --max-sync-age) [ $# -ge 2 ] || usage; max_sync_age="$2"; shift 2 ;;
        --state-dir) [ $# -ge 2 ] || usage; state_dir="$2"; shift 2 ;;
        --warn-pct) [ $# -ge 2 ] || usage; warn_pct="$2"; shift 2 ;;
        -h|--help) usage ;;
        -*) usage ;;
        *) [ -z "$base_url" ] || usage; base_url="$1"; shift ;;
    esac
done
[ -n "$base_url" ] || usage
base_url="${base_url%/}"

status=0
crit() { printf 'CRIT  %s\n' "$1" >&2; status=2; }
warn() { printf 'WARN  %s\n' "$1" >&2; [ "$status" -lt 1 ] && status=1; return 0; }
ok()   { printf 'ok    %s\n' "$1"; }

json_field() {
    printf '%s' "$1" | sed -n "s/.*\"$2\"[[:space:]]*:[[:space:]]*\([^,}]*\).*/\1/p" | tr -d '" ' | head -n 1
}

# Read a value out of the env file without sourcing it — the same approach
# memory-ceiling.sh takes, for the same reason: this file is fed to systemd, not
# to a shell.
env_value() {
    [ -n "$env_file" ] && [ -r "$env_file" ] || return 1
    local found
    found="$(sed -n "s/^[[:space:]]*$1=//p" "$env_file" | tail -n 1 | tr -d "\"'")"
    [ -n "$found" ] || return 1
    printf '%s' "$found"
}

# --- reachability ------------------------------------------------------------
health="$(curl -fsS --max-time 10 "$base_url/health" 2>/dev/null)"
if [ -z "$health" ]; then
    crit "GET $base_url/health did not return 200 — relay down"
    exit 2
fi
ok "GET /health returns 200"

node_id="$(json_field "$health" nodeId)"
uptime_sec="$(json_field "$health" uptimeSec)"
fetch_auth="$(json_field "$health" requireFetchAuth)"
mesh_enabled="$(json_field "$health" meshEnabled)"
mesh_peers="$(json_field "$health" peers)"
mesh_reachable="$(json_field "$health" reachable)"
mesh_sync_age="$(json_field "$health" oldestSyncAgeSec)"
messages="$(json_field "$health" messages)"
acks="$(json_field "$health" acks)"
attachment_bytes="$(json_field "$health" bytes)"
sessions="$(json_field "$health" sessions)"

# --- the enforcement flip ----------------------------------------------------
if [ -z "$expect_fetch_auth" ] && [ -n "$env_file" ]; then
    expect_fetch_auth="$(env_value DEE_NODE_REQUIRE_FETCH_AUTH)"
fi
if [ -n "$expect_fetch_auth" ]; then
    if [ "$fetch_auth" = "$expect_fetch_auth" ]; then
        ok "requireFetchAuth=$fetch_auth as intended"
    else
        crit "requireFetchAuth=$fetch_auth, intended $expect_fetch_auth — the flip failed open silently${env_file:+ (check for a typo in $env_file)}"
    fi
else
    warn "requireFetchAuth is $fetch_auth but nothing asserted it — pass --expect-fetch-auth or --env-file"
fi

# Admission, and unlike fetch-auth an unasserted value is not worth a warning:
# the overwhelming majority of relays are self-hosted, where unset means open and
# open is the product. It is asserted where it was configured — and a box the env
# file says is gated, running ungated, is critical rather than a warning, because
# every circle on it is being carried for free and nothing about that is visible.
admission="$(json_field "$health" requireAdmission)"
if [ -z "$expect_admission" ] && [ -n "$env_file" ]; then
    expect_admission="$(env_value DEE_NODE_REQUIRE_ADMISSION)"
fi
if [ -n "$expect_admission" ]; then
    if [ -z "$admission" ]; then
        crit "no requireAdmission in /health — this build predates the admission gate"
    elif [ "$admission" = "$expect_admission" ]; then
        ok "requireAdmission=$admission as intended"
    else
        crit "requireAdmission=$admission, intended $expect_admission — the gate failed open silently${env_file:+ (check for a typo in $env_file)}"
    fi
fi

if [ -n "$expect_mesh" ]; then
    if [ "$mesh_enabled" = "$expect_mesh" ]; then
        ok "meshEnabled=$mesh_enabled as intended"
    else
        crit "meshEnabled=$mesh_enabled, intended $expect_mesh"
    fi
fi

# --- replication actually happening ------------------------------------------
# meshEnabled=true says the feature is configured, and nothing more. A pool whose
# every sync returned 404 for an hour published exactly this: the switch on, the
# queues diverging, the failures in a volatile journal nobody reads. So the pool
# counts and the staleness are asserted separately.
if [ -n "$expect_peers" ]; then
    if [ -z "$mesh_peers" ]; then
        crit "expected $expect_peers mesh peers but /health has no mesh block — is this build older than pool replication?"
    elif [ "$mesh_peers" != "$expect_peers" ]; then
        crit "mesh.peers=$mesh_peers, intended $expect_peers — DEE_NODE_MESH_PEERS does not list the pool this relay is in"
    elif [ "$mesh_reachable" != "$expect_peers" ]; then
        crit "mesh.reachable=$mesh_reachable of $mesh_peers peers — this relay is replicating with fewer members than it is configured for"
    else
        ok "mesh.peers=$mesh_peers, all reachable"
    fi
fi

if [ -n "$max_sync_age" ]; then
    if [ -z "$mesh_sync_age" ]; then
        crit "no mesh.oldestSyncAgeSec in /health — is this build older than pool replication?"
    elif [ "$mesh_sync_age" -lt 0 ]; then
        crit "at least one peer has never synced successfully since boot — replication is configured and not working"
    elif [ "$mesh_sync_age" -gt "$max_sync_age" ]; then
        crit "the least recently synced peer last succeeded ${mesh_sync_age}s ago (limit ${max_sync_age}s) — queues are diverging"
    else
        ok "mesh.oldestSyncAgeSec=$mesh_sync_age (within ${max_sync_age}s)"
    fi
fi

# --- crash-loop detection ----------------------------------------------------
# A relay that restarts keeps answering /health, so "up" is not the signal —
# uptime going backwards is. Every restart drops that host's queues, so a loop
# is silent, continuous message loss for senders who have gone offline.
if mkdir -p "$state_dir" 2>/dev/null; then
    state_file="$state_dir/$node_id.uptime"
    if [ -r "$state_file" ]; then
        previous="$(cat "$state_file" 2>/dev/null)"
        if [ -n "$previous" ] && [ "$uptime_sec" -lt "$previous" ]; then
            crit "uptimeSec went $previous -> $uptime_sec — the relay restarted, and its queues went with it"
        else
            ok "uptimeSec=$uptime_sec (no restart since the last poll)"
        fi
    else
        ok "uptimeSec=$uptime_sec (first poll, nothing to compare)"
    fi
    printf '%s' "$uptime_sec" > "$state_file"
else
    warn "cannot write $state_dir — crash-loop detection is off"
fi

# --- saturation --------------------------------------------------------------
# Full queues mean mail is being rejected outright. Warn early; a cap that is
# regularly touched is a sizing decision, not an incident.
check_cap() {
    local label="$1" value="$2" cap="$3"
    case "$value$cap" in
        ''|*[!0-9]*) return 0 ;; # missing or non-numeric: nothing to compare
    esac
    if [ "$cap" -le 0 ]; then
        return 0
    fi
    if [ "$value" -ge "$cap" ]; then
        crit "$label at $value/$cap — the cap is reached and records are being rejected"
    elif [ $((value * 100 / cap)) -ge "$warn_pct" ]; then
        warn "$label at $value/$cap (>= ${warn_pct}%)"
    else
        ok "$label at $value/$cap"
    fi
}

max_messages="$(env_value DEE_NODE_MAX_MESSAGES)" || max_messages=""
max_acks="$(env_value DEE_NODE_MAX_ACKS)" || max_acks=""
if [ -n "$max_messages" ] && [ -z "$max_acks" ]; then
    max_acks=$((max_messages * 2)) # the node's own default
fi
if [ -n "$max_messages" ]; then
    check_cap "queues.messages" "$messages" "$max_messages"
    check_cap "queues.acks" "$acks" "$max_acks"
else
    ok "queues.messages=$messages acks=$acks (no --env-file, so no cap to compare against)"
fi

# --- attachment relay memory ------------------------------------------------
# sessions x window x chunk is the dominant term in MemoryMax. Bytes near that
# product is the shape of an OOM kill, which on a RAM-only relay is not a
# degraded service — it is every queue on the host, gone.
relay_sessions="$(env_value DEE_NODE_RELAY_MAX_SESSIONS)" || relay_sessions=""
relay_window="$(env_value DEE_NODE_RELAY_MAX_WINDOW)" || relay_window=""
chunk_bytes="$(env_value DEE_NODE_MAX_CHUNK_BYTES)" || chunk_bytes=""
if [ -n "$relay_sessions" ] && [ -n "$relay_window" ] && [ -n "$chunk_bytes" ]; then
    attachment_cap=$((relay_sessions * relay_window * chunk_bytes))
    check_cap "attachments.bytes" "$attachment_bytes" "$attachment_cap"
    check_cap "attachments.sessions" "$sessions" "$relay_sessions"
else
    ok "attachments.bytes=$attachment_bytes sessions=$sessions (no --env-file, so no cap to compare against)"
fi

exit "$status"
