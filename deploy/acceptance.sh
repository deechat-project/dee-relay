#!/usr/bin/env bash
#
# Single-relay acceptance: the relay answers, holds nothing on disk, and comes
# back by itself after the host reboots.
#
#   deploy/acceptance.sh http://127.0.0.1:8080
#   deploy/acceptance.sh http://127.0.0.1:8080 --unit dee-relay.service
#   deploy/acceptance.sh http://127.0.0.1:8080 --unit dee-relay.service --after-reboot
#
# The reboot half cannot be automated from here without rebooting the host, so
# it is two runs with a `reboot` between them. --after-reboot adds the one
# assertion that distinguishes "came back unattended" from "someone started
# it": uptimeSec must be small, and the host's own uptime must be smaller than
# the last run.
#
# Exit codes: 0 all assertions passed, 1 an assertion failed, 2 usage error.

set -uo pipefail

base_url=""
unit=""
after_reboot=0
expect_fetch_auth=""
expect_mesh=""
max_uptime=300

usage() {
    cat >&2 <<'EOF'
usage: acceptance.sh <base-url> [options]

  --unit <name>            also check the systemd unit (needs systemctl)
  --after-reboot           assert the relay came back on its own
  --expect-fetch-auth <bool>  assert /health requireFetchAuth equals this
  --expect-mesh <bool>     assert /health meshEnabled equals this
  --max-uptime <seconds>   uptimeSec ceiling for --after-reboot (default 300)
EOF
    exit 2
}

while [ $# -gt 0 ]; do
    case "$1" in
        --unit) [ $# -ge 2 ] || usage; unit="$2"; shift 2 ;;
        --after-reboot) after_reboot=1; shift ;;
        --expect-fetch-auth) [ $# -ge 2 ] || usage; expect_fetch_auth="$2"; shift 2 ;;
        --expect-mesh) [ $# -ge 2 ] || usage; expect_mesh="$2"; shift 2 ;;
        --max-uptime) [ $# -ge 2 ] || usage; max_uptime="$2"; shift 2 ;;
        -h|--help) usage ;;
        -*) usage ;;
        *) [ -z "$base_url" ] || usage; base_url="$1"; shift ;;
    esac
done
[ -n "$base_url" ] || usage
base_url="${base_url%/}"

failures=0
pass() { printf '  ok    %s\n' "$1"; }
fail() { printf '  FAIL  %s\n' "$1" >&2; failures=$((failures + 1)); }
skip() { printf '  skip  %s\n' "$1"; }

# Pull one JSON field without depending on jq being installed on the relay
# host. The node's /health is a flat object, so this is sufficient and keeps
# the dependency list at curl.
json_field() {
    printf '%s' "$1" | sed -n "s/.*\"$2\"[[:space:]]*:[[:space:]]*\([^,}]*\).*/\1/p" | tr -d '" '
}

echo "== health =="
health="$(curl -fsS --max-time 10 "$base_url/health" 2>/dev/null)"
if [ -z "$health" ]; then
    fail "GET /health did not return 200"
    echo
    echo "$failures assertion(s) failed"
    exit 1
fi
pass "GET /health returns 200"

node_id="$(json_field "$health" nodeId)"
uptime_sec="$(json_field "$health" uptimeSec)"
fetch_auth="$(json_field "$health" requireFetchAuth)"
mesh_enabled="$(json_field "$health" meshEnabled)"
printf '        nodeId=%s uptimeSec=%s requireFetchAuth=%s meshEnabled=%s\n' \
    "$node_id" "$uptime_sec" "$fetch_auth" "$mesh_enabled"

# Assert the security switches rather than infer them from a clean boot: an
# unparseable DEE_NODE_REQUIRE_FETCH_AUTH falls back to the default silently,
# which is the failure mode this whole check exists for.
if [ -n "$expect_fetch_auth" ]; then
    if [ "$fetch_auth" = "$expect_fetch_auth" ]; then
        pass "requireFetchAuth is $expect_fetch_auth"
    else
        fail "requireFetchAuth is '$fetch_auth', expected '$expect_fetch_auth' — a typo in the env file fails open silently"
    fi
else
    skip "requireFetchAuth not asserted (pass --expect-fetch-auth)"
fi

if [ -n "$expect_mesh" ]; then
    if [ "$mesh_enabled" = "$expect_mesh" ]; then
        pass "meshEnabled is $expect_mesh"
    else
        fail "meshEnabled is '$mesh_enabled', expected '$expect_mesh'"
    fi
else
    skip "meshEnabled not asserted (pass --expect-mesh)"
fi

if printf '%s' "$health" | grep -qi 'secret\|capability'; then
    fail "/health mentions a credential — it is a public endpoint"
else
    pass "/health publishes no credential"
fi

echo
echo "== layer 1: the mesh routes are not reachable here =="
# Only meaningful against a public hostname. Against loopback the node itself
# answers, and a 403 is the correct answer there — the proxy is what must 404.
case "$base_url" in
    http://127.0.0.1*|http://localhost*|http://[::1]*)
        skip "loopback URL — Layer 1 is a proxy rule, re-run against the public hostname" ;;
    *)
        mesh_code="$(curl -so /dev/null -w '%{http_code}' --max-time 10 \
            -H 'X-Dee-Node-ID: '"$node_id" "$base_url/mesh/snapshot" 2>/dev/null)"
        if [ "$mesh_code" = "404" ]; then
            pass "GET /mesh/snapshot with a spoofed peer header returns 404 from the proxy"
        else
            fail "GET /mesh/snapshot returned $mesh_code, expected 404 — /mesh/* is internet-reachable"
        fi ;;
esac

if [ -n "$unit" ]; then
    echo
    echo "== unit =="
    if ! command -v systemctl >/dev/null 2>&1; then
        skip "no systemctl on this host"
    else
        if systemctl is-enabled --quiet "$unit"; then
            pass "$unit is enabled (starts at boot)"
        else
            fail "$unit is not enabled — it will not come back after a reboot"
        fi

        restart="$(systemctl show -p Restart --value "$unit")"
        if [ "$restart" = "always" ]; then
            pass "Restart=always"
        else
            fail "Restart=$restart, expected always"
        fi

        mem_max="$(systemctl show -p MemoryMax --value "$unit")"
        if [ -n "$mem_max" ] && [ "$mem_max" != "infinity" ]; then
            pass "MemoryMax=$mem_max (cross-check with memory-ceiling.sh --check-unit)"
        else
            fail "MemoryMax is unset — a flood becomes an OOM kill, and every queued message on this relay is lost"
        fi

        swap_max="$(systemctl show -p MemorySwapMax --value "$unit")"
        if [ "$swap_max" = "0" ]; then
            pass "MemorySwapMax=0 (queued ciphertext cannot be paged to disk)"
        else
            fail "MemorySwapMax=$swap_max — swap would write queue contents to disk"
        fi

        namespace="$(systemctl show -p LogNamespace --value "$unit")"
        if [ -n "$namespace" ]; then
            storage="$(sed -n 's/^[[:space:]]*Storage=//p' "/etc/systemd/journald@${namespace}.conf" 2>/dev/null | tail -n 1)"
            if [ "$storage" = "volatile" ]; then
                pass "log namespace '$namespace' is Storage=volatile"
            else
                fail "journald@${namespace}.conf Storage='$storage', expected volatile — logs would persist to /var/log/journal"
            fi
        else
            fail "no LogNamespace — the unit logs to the persistent system journal"
        fi

        # The binary is audited for this; the host is not. A relay that mounts a
        # volume has already lost the argument the project is built on.
        if systemctl show -p ExecStart --value "$unit" | grep -qE -- '--volume|-v /|--mount'; then
            fail "the unit mounts a volume"
        else
            pass "no volume mounts"
        fi
    fi
fi

if [ "$after_reboot" = "1" ]; then
    echo
    echo "== reboot survival =="
    if [ -z "$uptime_sec" ]; then
        fail "no uptimeSec in /health"
    elif [ "$uptime_sec" -lt "$max_uptime" ]; then
        pass "uptimeSec=$uptime_sec — this is a fresh process, not the pre-reboot one"
    else
        fail "uptimeSec=$uptime_sec exceeds $max_uptime — did the host actually reboot?"
    fi
    if [ -r /proc/uptime ]; then
        host_uptime="$(cut -d. -f1 /proc/uptime)"
        if [ "$host_uptime" -lt "$max_uptime" ]; then
            pass "host uptime ${host_uptime}s — the relay came up with the host, unattended"
        else
            fail "host uptime ${host_uptime}s — this host did not just reboot, so nothing was proven"
        fi
    else
        skip "no /proc/uptime — cannot confirm the host itself rebooted"
    fi
fi

echo
if [ "$failures" -eq 0 ]; then
    echo "all assertions passed"
    exit 0
fi
echo "$failures assertion(s) failed"
exit 1
