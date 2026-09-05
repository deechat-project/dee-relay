#!/usr/bin/env bash
#
# Relay Setup verification: one run on the host, one report to send back.
#
#   sudo deploy/setup-verify.sh                              # a standard install
#   sudo deploy/setup-verify.sh --public-url https://relay.example.org
#   sudo deploy/setup-verify.sh --report /tmp/relay-verify.txt
#
# This is the script the *customer's admin* runs, on a host we have no access
# to, and whose output is the whole of what we see. That shapes everything about
# it:
#
#   - It asks for nothing. With no arguments it reads /etc/deechat/node.env and
#     works out the unit, the loopback address and the public URL from there.
#   - It never prints a secret. Every value that could be one is redacted on the
#     way out (redact_value), because this output is going into an email.
#   - It says "needs a human" where it cannot decide, instead of guessing. A
#     report that fails honestly is diagnosable; one that passes vaguely is not.
#
# What it does that the other scripts here do not: it checks the *whole*
# delivery at once — binary, unit, exposure, running config, live relay path —
# and it checks the two things a per-milestone script has no reason to. The
# running process is compared against the file on disk (a cap edited and never
# restarted is the most likely single defect in a hand-built relay), and a
# canary is put through the full delivery cycle to prove the queue empties
# again afterwards.
#
# Overlap is deliberate where it is cheap and delegated where it is not:
#   acceptance.sh   reboot survival — needs a reboot, so it stays two runs
#   probe-public.sh mesh Layers 2 and 3 — needs the pool secret
#   pool-verify.sh  replication — needs more than one relay
#   memory-ceiling.sh  called directly when it is alongside
#
# The canary is its own cleanup. It is minted with a short life (--canary-ttl),
# so a run that is interrupted half-way leaves a relay that is empty again a
# minute later, with no purge tombstone and nothing for anyone to remove by
# hand.
#
# Exit codes: 0 every check passed, 1 a check failed, 2 usage error.
# Warnings ("needs a human") do not fail the run — they are what the email is
# for.

set -uo pipefail

readonly capability_header="X-Dee-Queue-Capability"

public_url=""
loopback_url=""
env_file=""
unit=""
canary_ttl=45
cleanup_interval=""
skip_canary=0
quick=0
report_file=""
admission_code=""
admission_session=""
dee_admit=""

usage() {
    cat >&2 <<'EOF'
usage: setup-verify.sh [options]

  --public-url <url>     the relay's public URL (default: DEE_NODE_PUBLIC_URL
                         from the env file)
  --loopback-url <url>   the node's own listener (default: derived from
                         DEE_NODE_ADDR)
  --env-file <path>      default /etc/deechat/node.env
  --unit <name>          default dee-relay.service, or the container unit
                         if that is the one installed
  --canary-ttl <seconds> how long the test record is minted for (default 45)
  --quick                skip the wait for the canary's records to expire; the
                         delivery half still runs
  --no-canary            skip the live relay path entirely. Use only on a relay
                         already carrying real traffic where the operator will
                         not accept a test record.
  --admission-code <c>   a redemption code this relay admits, or "-" to read it
                         from stdin. Required to exercise delivery on a relay
                         with DEE_NODE_REQUIRE_ADMISSION=true — without it the
                         gate refuses the canary and the delivery half of this
                         report cannot run.
  --dee-admit <path>     the dee-admit binary that opens the session
                         (default: dee-admit on PATH, or beside this script)
  --report <path>        also write the report here
EOF
    exit 2
}

while [ $# -gt 0 ]; do
    case "$1" in
        --public-url) [ $# -ge 2 ] || usage; public_url="${2%/}"; shift 2 ;;
        --loopback-url) [ $# -ge 2 ] || usage; loopback_url="${2%/}"; shift 2 ;;
        --env-file) [ $# -ge 2 ] || usage; env_file="$2"; shift 2 ;;
        --unit) [ $# -ge 2 ] || usage; unit="$2"; shift 2 ;;
        --canary-ttl) [ $# -ge 2 ] || usage; canary_ttl="$2"; shift 2 ;;
        --quick) quick=1; shift ;;
        --no-canary) skip_canary=1; shift ;;
        --admission-code) [ $# -ge 2 ] || usage; admission_code="$2"; shift 2 ;;
        --dee-admit) [ $# -ge 2 ] || usage; dee_admit="$2"; shift 2 ;;
        --report) [ $# -ge 2 ] || usage; report_file="$2"; shift 2 ;;
        -h|--help) usage ;;
        *) usage ;;
    esac
done

case "$canary_ttl" in
    ''|*[!0-9]*) usage ;;
esac
[ "$canary_ttl" -ge 10 ] || usage

# Read before anything is printed, and never printed afterwards. A code on the
# command line is in the shell history and in the process list of every other
# user on the box; "-" is the form the checklist tells the operator to use, and
# it has to be read here rather than deep inside the canary block, where the
# terminal has already been redirected.
if [ "$admission_code" = "-" ]; then
    IFS= read -r admission_code || admission_code=""
    [ -n "$admission_code" ] || { echo "--admission-code - was given but nothing arrived on stdin" >&2; exit 2; }
fi

# Everything below writes to stdout; --report tees the whole run rather than
# re-deriving it, so the file and the terminal cannot disagree.
if [ -n "$report_file" ]; then
    if ! : >"$report_file" 2>/dev/null; then
        echo "cannot write the report to $report_file" >&2
        exit 2
    fi
    exec > >(tee "$report_file") 2>&1
fi

failures=0
warnings=0
skips=0
pass() { printf '  ok    %s\n' "$1"; }
fail() { printf '  FAIL  %s\n' "$1"; failures=$((failures + 1)); }
warn() { printf '  ?     %s\n' "$1"; warnings=$((warnings + 1)); }
# Skips are counted, not just printed. A run on a host with no systemd skips the
# whole service section — boot, restart policy, non-root, MemoryMax,
# MemorySwapMax, the sandbox, the log namespace — and without a count the summary
# reads "0 failures" and looks like a pass. Noticing that by eye is exactly the
# job this script exists to take off a human.
skip() { printf '  skip  %s\n' "$1"; skips=$((skips + 1)); }
info() { printf '  ..    %s\n' "$1"; }

# A skip that took a whole section with it is named again in the summary, so the
# reply is written against what the run actually established rather than against
# the absence of the word FAIL.
unproven=""
unproven_section() { unproven="${unproven}${unproven:+
}  - $1"; }

# --- reading the env file ----------------------------------------------------
# An env file is data, not script: it is read line by line and never sourced,
# because this one may have been edited by hand minutes ago.
env_value() {
    [ -n "$env_file" ] && [ -r "$env_file" ] || return 0
    sed -n "s/^[[:space:]]*$1=//p" "$env_file" | tail -n 1 | sed 's/[[:space:]]*$//' | tr -d "\"'"
}

# Anything whose name says it is a credential is replaced by its length. The
# length is worth keeping: "set, 44 characters" and "set, 3 characters" are
# different bugs, and neither reveals the value.
redact_value() {
    case "$1" in
        *SECRET*|*TOKEN*|*PASSWORD*|*PASSPHRASE*|*_KEY|*APIKEY*)
            if [ -n "$2" ]; then printf '<redacted, %s characters>' "${#2}"; else printf '<unset>'; fi ;;
        *) printf '%s' "${2:-<unset>}" ;;
    esac
}

json_field() {
    printf '%s' "$1" | sed -n "s/.*\"$2\"[[:space:]]*:[[:space:]]*\([^,}]*\).*/\1/p" | tr -d '" ' | head -n 1
}

random_hex() { head -c "$1" /dev/urandom | od -An -tx1 | tr -d ' \n'; }

# RFC3339, n seconds from now. GNU and BSD date disagree about relative times,
# so the offset is done in seconds and formatted from the epoch.
iso_in() {
    local at=$(( $(date -u +%s) + $1 ))
    date -u -d "@$at" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -r "$at" +%Y-%m-%dT%H:%M:%SZ
}

have() { command -v "$1" >/dev/null 2>&1; }

# Every request in the delivery half goes through this rather than calling curl
# directly. A session header attached to the POST and forgotten on the read-back
# would report a working gated relay as one that loses mail, which is the most
# expensive wrong answer this script can give. One wrapper, so there is nowhere
# to forget it.
relay_curl() {
    if [ -n "$admission_session" ]; then
        curl -H "X-Dee-Admission: $admission_session" "$@"
    else
        curl "$@"
    fi
}

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# --- defaults the operator should not have to supply --------------------------
if [ -z "$env_file" ]; then
    for candidate in /etc/deechat/node.env "$script_dir/node.env"; do
        [ -r "$candidate" ] && { env_file="$candidate"; break; }
    done
fi

if [ -z "$unit" ] && have systemctl; then
    for candidate in dee-relay.service dee-relay-container.service; do
        if systemctl cat "$candidate" >/dev/null 2>&1; then unit="$candidate"; break; fi
    done
fi

node_addr="$(env_value DEE_NODE_ADDR)"
# "A path was given" and "that path is this relay's env file" are different
# claims, and a wrong --env-file must not be reported as a relay configured with
# nothing set.
env_ok=0
if [ -n "$node_addr" ] || [ -n "$(env_value DEE_NODE_ID)" ]; then env_ok=1; fi
if [ -z "$loopback_url" ] && [ -n "$node_addr" ]; then
    case "$node_addr" in
        # A wildcard or container-side bind is not an address to poll; the
        # loopback port is, and that is what --publish maps it to.
        :*) loopback_url="http://127.0.0.1${node_addr}" ;;
        0.0.0.0:*) loopback_url="http://127.0.0.1:${node_addr##*:}" ;;
        *) loopback_url="http://${node_addr}" ;;
    esac
fi
[ -n "$public_url" ] || public_url="$(env_value DEE_NODE_PUBLIC_URL)"
public_url="${public_url%/}"

# The live checks need somewhere to talk to. Loopback is preferred for the
# canary (it is the relay itself, not the proxy in front of it); the public URL
# is used when the script is run from a machine that is not the host.
probe_url="${loopback_url:-$public_url}"

echo "== this host =="
info "report generated $(date -u +'%Y-%m-%dT%H:%M:%SZ') (UTC)"
if [ -r /etc/os-release ]; then
    info "os: $(sed -n 's/^PRETTY_NAME=//p' /etc/os-release | tr -d '"')"
else
    info "os: $(uname -sr)"
fi
info "kernel: $(uname -sr)"
info "env file: ${env_file:-<none found>}"
info "unit: ${unit:-<none found>}"
info "public url: ${public_url:-<not configured>}"
info "polling: ${probe_url:-<nothing to poll>}"

if [ -z "$probe_url" ]; then
    echo
    echo "Nothing to poll: no --public-url, and no DEE_NODE_ADDR in ${env_file:-an env file}."
    echo "Re-run with --public-url <url>."
    exit 2
fi

health="$(curl -fsS --max-time 10 "$probe_url/health" 2>/dev/null)"
if [ -z "$health" ]; then
    fail "GET $probe_url/health did not answer — the relay is not running, or not on this address"
    echo
    echo "Everything below this line needs a running relay. Fix that first:"
    echo "  systemctl status ${unit:-dee-relay} ; journalctl --namespace deechat -n 50"
    exit 1
fi
node_id="$(json_field "$health" nodeId)"
uptime_sec="$(json_field "$health" uptimeSec)"
pass "the relay answers: nodeId=${node_id:-?}, up ${uptime_sec:-?}s"

# --- the binary ---------------------------------------------------------------
echo
echo "== the binary =="
binary=""
if [ -n "$unit" ] && have systemctl; then
    exec_start="$(systemctl show -p ExecStart --value "$unit" 2>/dev/null)"
    case "$exec_start" in
        *dee-relay*) binary="$(printf '%s' "$exec_start" | sed -n 's/.*path=\([^ ;]*\).*/\1/p' | head -n 1)" ;;
    esac
fi
[ -n "$binary" ] || { [ -x /usr/local/bin/dee-relay ] && binary=/usr/local/bin/dee-relay; }

if [ -z "$binary" ] || [ ! -r "$binary" ]; then
    skip "no binary on this host to digest (a container install digests the image instead)"
    unproven_section "the binary — nothing on this host was digested at all"
else
    if have sha256sum; then
        local_digest="$(sha256sum "$binary" | cut -d' ' -f1)"
    else
        local_digest="$(shasum -a 256 "$binary" | cut -d' ' -f1)"
    fi
    info "running binary: $binary"
    info "sha256: $local_digest"

    arch="amd64"
    case "$(uname -m)" in
        aarch64|arm64) arch="arm64" ;;
    esac
    fingerprints="$script_dir/FINGERPRINTS.md"
    published=""
    [ -r "$fingerprints" ] && published="$(sed -n "s/^binary-sha256 linux\/$arch \([0-9a-f]\{64\}\)$/\1/p" "$fingerprints" | tail -1)"
    if [ -z "$published" ]; then
        # Honest failure mode, and a known one: verify-artifact.sh exits 4 for
        # the same reason. Until a digest is published there is nothing on this
        # host that can be checked against anything, and saying "ok" here would
        # be the single most misleading line in the report.
        warn "no digest is published for linux/$arch, so this binary matches nothing — the report cannot show it is the released build"
    elif [ "$published" = "$local_digest" ]; then
        pass "matches the published digest for linux/$arch"
    else
        fail "does NOT match the published digest for linux/$arch ($published) — this host is running a binary we did not release"
    fi
fi
info "a digest attests to a file, never to the process serving /health — see FINGERPRINTS.md"

# --- the service --------------------------------------------------------------
echo
echo "== the service =="
if [ -z "$unit" ] || ! have systemctl; then
    skip "no systemd unit found; the service checks need one (a container install still needs its restart policy checked by hand)"
    unproven_section "the service — boot survival, restart policy, non-root, MemoryMax, MemorySwapMax=0, the sandbox and the log namespace were all unchecked"
else
    prop() { systemctl show -p "$1" --value "$unit" 2>/dev/null; }

    [ "$(systemctl is-enabled "$unit" 2>/dev/null)" = "enabled" ] \
        && pass "$unit is enabled — it starts at boot" \
        || fail "$unit is not enabled; it will not come back after a reboot (systemctl enable $unit)"
    [ "$(systemctl is-active "$unit" 2>/dev/null)" = "active" ] \
        && pass "$unit is active" \
        || fail "$unit is not active"

    restart="$(prop Restart)"
    [ "$restart" = "always" ] \
        && pass "Restart=always" \
        || fail "Restart=$restart — the relay will not restart itself after a crash"

    user="$(prop User)"
    case "$user" in
        ""|root) fail "the relay runs as ${user:-root}; it needs no privileges and must not have them" ;;
        *) pass "runs as $user, not root" ;;
    esac

    n_restarts="$(prop NRestarts)"
    case "$n_restarts" in
        ''|*[!0-9]*) ;;
        *) [ "$n_restarts" -gt 3 ] && warn "the unit has restarted $n_restarts times — check journalctl --namespace deechat for a crash loop" ;;
    esac

    # Memory. Every store is RAM-only, so an OOM kill is lost mail, and the
    # ceiling is derivable rather than a matter of taste.
    mem_max="$(prop MemoryMax)"
    if [ -z "$mem_max" ] || [ "$mem_max" = "infinity" ]; then
        fail "MemoryMax is unset — a flood becomes an OOM kill, and on a RAM-only relay that is every queued message on this host"
    else
        pass "MemoryMax=$mem_max"
        if [ -x "$script_dir/memory-ceiling.sh" ] && [ -n "$env_file" ] && [ -r "$env_file" ]; then
            unit_path="$(systemctl show -p FragmentPath --value "$unit" 2>/dev/null)"
            if [ -n "$unit_path" ] && [ -r "$unit_path" ]; then
                if "$script_dir/memory-ceiling.sh" "$env_file" --check-unit "$unit_path" >/dev/null 2>&1; then
                    pass "MemoryMax is at or above the ceiling derived from $env_file"
                else
                    fail "MemoryMax is BELOW the ceiling these caps need — run memory-ceiling.sh $env_file"
                fi
            fi
        fi
    fi
    swap_max="$(prop MemorySwapMax)"
    [ "$swap_max" = "0" ] \
        && pass "MemorySwapMax=0 — queued ciphertext cannot reach the disk through swap" \
        || fail "MemorySwapMax=$swap_max; swap would write queued records to disk on a relay whose claim is that it holds none"

    # The sandbox. Each of these is one line in the shipped unit, so a miss here
    # means the unit was edited or is not the one we ship.
    sandbox_missing=""
    check_prop() {
        local actual
        actual="$(prop "$1")"
        [ "$actual" = "$2" ] || sandbox_missing="$sandbox_missing $1=${actual:-unset}"
    }
    check_prop NoNewPrivileges yes
    check_prop ProtectSystem strict
    check_prop ProtectHome yes
    check_prop PrivateTmp yes
    check_prop MemoryDenyWriteExecute yes
    check_prop RestrictSUIDSGID yes
    check_prop LockPersonality yes
    rw_paths="$(prop ReadWritePaths)"
    [ -z "$rw_paths" ] || sandbox_missing="$sandbox_missing ReadWritePaths=$rw_paths"
    caps="$(prop CapabilityBoundingSet)"
    [ -z "$caps" ] || sandbox_missing="$sandbox_missing CapabilityBoundingSet=$caps"

    if [ -z "$sandbox_missing" ]; then
        pass "the filesystem and privilege sandbox is intact (read-only root, no capabilities, no writable paths)"
    else
        fail "the sandbox has been weakened:$sandbox_missing"
    fi

    log_ns="$(prop LogNamespace)"
    if [ "$log_ns" = "deechat" ]; then
        storage=""
        [ -r /etc/systemd/journald@deechat.conf ] && storage="$(sed -n 's/^[[:space:]]*Storage=//p' /etc/systemd/journald@deechat.conf | tail -n 1)"
        if [ "$storage" = "volatile" ]; then
            pass "logs go to the deechat namespace with Storage=volatile — they stay in RAM"
        else
            fail "the deechat log namespace has Storage=${storage:-unset}; boot and mesh lines will persist to /var/log/journal"
        fi
        for d in /var/log/journal/*deechat*; do
            [ -e "$d" ] && fail "$d exists — this namespace has written to disk at some point; remove it once Storage=volatile is in place"
        done
    else
        warn "LogNamespace=${log_ns:-unset}; without the deechat namespace the relay's log lines land in the host journal on disk"
    fi
fi

# --- what is exposed ----------------------------------------------------------
echo
echo "== what is exposed =="
if [ "$env_ok" = "0" ]; then
    skip "${env_file:-no env file} does not read as this relay's env file, so the bind addresses cannot be checked (re-run with sudo, or pass --env-file)"
elif [ -z "$node_addr" ]; then
    skip "DEE_NODE_ADDR is not set in $env_file; the node is on its default bind"
else
    case "$node_addr" in
        127.0.0.1:*|localhost:*|\[::1\]:*)
            pass "DEE_NODE_ADDR=$node_addr — the node listens on loopback and the proxy reaches it there" ;;
        :*|0.0.0.0:*|\[::\]:*)
            case "$unit" in
                *container*) warn "DEE_NODE_ADDR=$node_addr is correct for the container unit only if --publish binds it to 127.0.0.1; confirm the ExecStart line" ;;
                *) fail "DEE_NODE_ADDR=$node_addr is a wildcard bind — the node faces the internet directly, with no proxy and no TLS in front of it" ;;
            esac ;;
        *) warn "DEE_NODE_ADDR=$node_addr is neither loopback nor a wildcard; confirm this address is not routable from the internet" ;;
    esac
fi

mesh_addr="$(env_value DEE_NODE_MESH_ADDR)"
if [ "$env_ok" = "0" ]; then
    :
elif [ -z "$mesh_addr" ]; then
    info "mesh replication is not configured on this relay (one host, no pool)"
else
    case "$mesh_addr" in
        :*|0.0.0.0:*|\[::\]:*) fail "DEE_NODE_MESH_ADDR=$mesh_addr is a wildcard bind; the mesh endpoint serves every identity's queued records to anyone holding the pool secret" ;;
        *) info "DEE_NODE_MESH_ADDR=$mesh_addr — confirm this is a private interface (WireGuard, Tailscale, provider private network)" ;;
    esac
fi

# ss only, and listening sockets only. netstat's output differs enough between
# platforms that parsing both produces confident nonsense on one of them, and a
# report that invents open ports is worse than one that says it did not look.
listening=""
have ss && listening="$(ss -lntH 2>/dev/null | awk '{print $4}' | sort -u)"
if [ -z "$listening" ]; then
    skip "no ss on this host; the listening sockets could not be listed"
    unproven_section "what listens — no socket list, so nothing rules out another service on a public interface"
else
    unexpected=""
    while IFS= read -r sock; do
        [ -n "$sock" ] || continue
        port="${sock##*:}"
        addr="${sock%:*}"
        case "$addr" in
            127.0.0.1|::1|\[::1\]|localhost) continue ;;
        esac
        case "$port" in
            22|80|443) continue ;;
        esac
        unexpected="$unexpected $sock"
    done <<EOF
$listening
EOF
    if [ -z "$unexpected" ]; then
        pass "nothing but ssh and the proxy listens on a public interface"
    else
        warn "these sockets are open beyond loopback and beyond 22/80/443:$unexpected — each one is a service the relay's host exposes"
    fi
fi

if [ -z "$public_url" ]; then
    skip "no public URL configured, so the proxy in front of the relay cannot be checked"
    unproven_section "the proxy — TLS, HSTS, the http redirect and /mesh/* being 404 from the internet were not checked"
else
    is_https=0
    case "$public_url" in
        https://*) is_https=1 ;;
        *) fail "DEE_NODE_PUBLIC_URL is $public_url — a relay published over plain http exposes every request to the network in front of it" ;;
    esac

    public_code="$(curl -sS --max-time 10 -o /dev/null -w '%{http_code}' "$public_url/health" 2>/dev/null)"
    if [ "$public_code" = "000" ]; then
        # One finding, not five. Everything else out here needs an answer, and
        # repeating "did not answer" per check hides which thing is broken.
        fail "$public_url/health did not answer at all — DNS, the firewall, the certificate or the proxy. Nothing public could be checked; fix this and re-run"
    elif [ "$public_code" != "200" ]; then
        fail "$public_url/health returned $public_code — the proxy is answering but not from the relay"
    else
        if [ "$is_https" = "1" ]; then
            pass "$public_url/health answers over TLS with a certificate this host trusts"
        else
            pass "$public_url/health answers"
        fi

        headers="$(curl -sS --max-time 10 -D - -o /dev/null "$public_url/health" 2>/dev/null)"
        case "$headers" in
            *[Ss]trict-[Tt]ransport-[Ss]ecurity*) pass "HSTS is set" ;;
            *) warn "no Strict-Transport-Security header; the proxy is not the one we ship" ;;
        esac

        if [ "$is_https" = "1" ]; then
            plain="${public_url#https://}"
            redirect="$(curl -sS --max-time 10 -o /dev/null -w '%{http_code}' "http://$plain/health" 2>/dev/null)"
            case "$redirect" in
                30*) pass "plain http redirects ($redirect)" ;;
                000) info "plain http is not answered at all — also fine" ;;
                200) fail "http://$plain/health answered 200; the relay is reachable without TLS" ;;
                *) warn "http://$plain/health returned $redirect rather than a redirect" ;;
            esac
        fi

        # Layer 1 of the mesh rule, checkable without the pool secret: the public
        # hostname has no /mesh route, with or without a credential. Layers 2 and
        # 3 need the real secret and stay in probe-public.sh.
        mesh_code="$(curl -sS --max-time 10 -o /dev/null -w '%{http_code}' "$public_url/mesh/snapshot" 2>/dev/null)"
        bogus_code="$(curl -sS --max-time 10 -o /dev/null -w '%{http_code}' -H 'X-Dee-Mesh-Secret: not-the-secret' "$public_url/mesh/snapshot" 2>/dev/null)"
        if [ "$mesh_code" = "404" ] && [ "$bogus_code" = "404" ]; then
            pass "/mesh/* is 404 from the internet, with and without a credential"
        else
            fail "$public_url/mesh/snapshot returned $mesh_code (and $bogus_code with a bogus secret); it must be 404 from the public hostname"
        fi
        info "the deeper mesh layers need the pool secret: probe-public.sh $public_url --loopback-url ${loopback_url:-http://127.0.0.1:8080} --mesh-secret ..."
    fi
fi

# --- the configuration this relay is actually running -------------------------
echo
echo "== the configuration this relay is running =="
health_fetch_auth="$(json_field "$health" requireFetchAuth)"
health_mesh="$(json_field "$health" meshEnabled)"
health_max_attachment="$(json_field "$health" maxAttachmentBytes)"
health_admission="$(json_field "$health" requireAdmission)"
info "requireFetchAuth=$health_fetch_auth  meshEnabled=$health_mesh  requireAdmission=${health_admission:-<not published by this build>}  maxAttachmentBytes=$health_max_attachment"

if [ "$env_ok" = "0" ]; then
    skip "no env file to compare the running relay against, so the checks that catch an edit nobody restarted did not run"
    unproven_section "the running configuration — the process was never compared against a file, so a cap edited and never restarted would not have been caught"
else
    for key in DEE_NODE_ID DEE_NODE_MAX_MESSAGES DEE_NODE_MAX_ACKS DEE_NODE_MAX_PURGES \
               DEE_NODE_MAX_PER_PAIR \
               DEE_NODE_MAX_PAYLOAD_BYTES DEE_NODE_MAX_TTL DEE_NODE_DEFAULT_TTL \
               DEE_NODE_CLEANUP_INTERVAL DEE_NODE_RELAY_MAX_SESSIONS DEE_NODE_RELAY_MAX_WINDOW \
               DEE_NODE_MAX_CHUNK_BYTES DEE_NODE_MAX_ATTACHMENT_BYTES \
               DEE_NODE_ADMISSION_FILE DEE_NODE_REQUIRE_ADMISSION DEE_NODE_MESH_SECRET; do
        info "$key=$(redact_value "$key" "$(env_value "$key")")"
    done

    # The check no per-milestone script makes: is the process running the file?
    # An edited env file that nobody restarted is the likeliest single defect in
    # a hand-built relay, and /health looks perfectly healthy through it.
    env_attachment="$(env_value DEE_NODE_MAX_ATTACHMENT_BYTES)"
    if [ -n "$env_attachment" ] && [ -n "$health_max_attachment" ]; then
        [ "$env_attachment" = "$health_max_attachment" ] \
            && pass "the attachment ceiling on /health matches the env file ($health_max_attachment bytes)" \
            || fail "the env file says DEE_NODE_MAX_ATTACHMENT_BYTES=$env_attachment but the running relay advertises $health_max_attachment — it has not been restarted since that edit"
    fi

    env_fetch_auth="$(env_value DEE_NODE_REQUIRE_FETCH_AUTH)"
    if [ -n "$env_fetch_auth" ] && [ -n "$health_fetch_auth" ]; then
        # An unparseable value falls back to the default and boots cleanly, so
        # this has to be read back rather than inferred: the typo
        # DEE_NODE_REQUIRE_FETCH_AUTH=ture enforces nothing, silently.
        [ "$env_fetch_auth" = "$health_fetch_auth" ] \
            && pass "requireFetchAuth is enforcing the value in the env file ($health_fetch_auth)" \
            || fail "the env file says DEE_NODE_REQUIRE_FETCH_AUTH=$env_fetch_auth but the relay is running with $health_fetch_auth — a typo here fails open"
    fi

    # Admission, read back for the same reason and with one asymmetry worth
    # keeping straight: unset means OPEN, which is correct and deliberate on a
    # self-hosted box, and wrong on the shared pool. The relay refuses to boot
    # with the switch on and no credential file, so the survivable mistake is the
    # typo — DEE_NODE_REQUIRE_ADMISSION=ture boots clean, gates nothing, and
    # every circle on a paid box becomes a free one silently.
    env_admission="$(env_value DEE_NODE_REQUIRE_ADMISSION)"
    env_admission_file="$(env_value DEE_NODE_ADMISSION_FILE)"
    if [ -z "$health_admission" ]; then
        warn "this build does not publish requireAdmission on /health, so the admission switch cannot be read back — it predates the gate"
    elif [ -n "$env_admission" ] && [ "$env_admission" != "true" ] && [ "$env_admission" != "false" ]; then
        fail "DEE_NODE_REQUIRE_ADMISSION=$env_admission is neither true nor false, so it parsed as false and this relay is gating nothing — the typo that fails open"
    elif [ "$env_admission" = "true" ] && [ "$health_admission" = "true" ]; then
        pass "requireAdmission is enforcing — this relay serves only the circles in $env_admission_file"
    elif [ "$env_admission" = "true" ]; then
        fail "the env file says DEE_NODE_REQUIRE_ADMISSION=$env_admission but the relay is running with requireAdmission=$health_admission — it has not been restarted since that edit"
    elif [ "$health_admission" = "true" ]; then
        fail "the relay is enforcing admission but the env file says DEE_NODE_REQUIRE_ADMISSION=${env_admission:-<unset>}; the running process is not this configuration"
    elif [ -n "$env_admission_file" ]; then
        info "a credential file is configured with enforcement off — the rollout position: codes are loaded and watched, and nothing is refused yet"
    else
        info "no admission gate configured: this relay carries mail for anyone who knows its URL, bounded by the caps above. That is the free self-hosted path and is correct for a single-customer box"
    fi
    if [ -n "$env_admission_file" ] && [ ! -r "$env_admission_file" ]; then
        warn "DEE_NODE_ADMISSION_FILE=$env_admission_file is not readable from here; confirm the relay's own user can read it (re-run with sudo if this run could not)"
    fi

    # Same defect, seen from the other side: the file is newer than the process.
    if [ -n "$uptime_sec" ] && have stat; then
        mtime="$(stat -c %Y "$env_file" 2>/dev/null || stat -f %m "$env_file" 2>/dev/null)"
        if [ -n "$mtime" ]; then
            started_at=$(( $(date -u +%s) - uptime_sec ))
            if [ "$mtime" -gt "$started_at" ]; then
                fail "$env_file was edited after the relay started; the running process is not this configuration (systemctl restart ${unit:-dee-relay})"
            else
                pass "$env_file has not been touched since the relay started"
            fi
        fi
    fi

    cleanup_interval="$(env_value DEE_NODE_CLEANUP_INTERVAL)"
fi
info "the per-tier capacity figures this circle should be sized to are set at the sale, not by this script — see the Relay Setup checklist"

# --- the relay path -----------------------------------------------------------
echo
echo "== the relay path =="
baseline_messages="$(json_field "$health" messages)"
baseline_acks="$(json_field "$health" acks)"
info "queues before the canary: messages=$baseline_messages acks=$baseline_acks"

# --- the session the canary needs on a gated relay ----------------------------
# The code is not signed here. dee-admit derives the keypair the same way the
# relay and the app do — SHA-256 over a versioned domain string, then Ed25519 —
# and reimplementing that in openssl beside the Go that already does it is how
# the two drift apart without either being wrong on its own. So this asks the
# binary and carries the token it gets back.
if [ -n "$admission_code" ] && [ "$skip_canary" = "1" ]; then
    warn "--admission-code was given with --no-canary, so no session was opened and nothing was put through the relay"
elif [ -n "$admission_code" ]; then
    if [ -z "$dee_admit" ]; then
        for candidate in "$script_dir/dee-admit" /usr/local/bin/dee-admit; do
            [ -x "$candidate" ] && { dee_admit="$candidate"; break; }
        done
    fi
    [ -n "$dee_admit" ] || { have dee-admit && dee_admit="dee-admit"; }
    if [ -z "$dee_admit" ]; then
        fail "--admission-code was given but dee-admit is not on this box (looked on PATH, beside this script, and in /usr/local/bin). It is built from chat-node with: go build -o dee-admit ./cmd/dee-admit — pass it with --dee-admit <path>"
    else
        # stderr is kept: its refusal messages tell expired, revoked and mistyped
        # apart, and that is the whole diagnosis when a customer's code stops
        # working. Only the token comes back on stdout.
        session_err="$(mktemp)"
        admission_session="$(printf '%s' "$admission_code" \
            | "$dee_admit" session --code - --relay "$probe_url" 2>"$session_err")" || admission_session=""
        if [ -n "$admission_session" ]; then
            pass "the relay admitted this code and issued a session — the canary below runs as a provisioned circle, not as a stranger"
        else
            fail "the relay would not open a session for this code: $(tr '\n' ' ' <"$session_err" | sed 's/[[:space:]]*$//')"
            unproven_section "the relay path — the code did not open a session, so the delivery cycle ran (or was refused) without one"
        fi
        rm -f "$session_err"
    fi
elif [ "$health_admission" = "true" ] && [ "$skip_canary" != "1" ]; then
    info "this relay is gating, and no --admission-code was given: the canary below will be refused, and the delivery half of this report will not run"
fi

if [ "$skip_canary" = "1" ]; then
    skip "--no-canary: the delivery cycle was not exercised, so this report does not show that the relay delivers"
    unproven_section "the relay path — no record was put through, so this report does not show that mail crosses this box at all"
else
    # The capability and its tag, derived exactly as internal/queue.TagForSecret
    # and the Dart client derive them. openssl rather than sha256sum/shasum,
    # which disagree between Linux and macOS.
    canary_secret="$(random_hex 32)"
    canary_tag="$(printf 'deechat.queue-tag.v1|%s' "$canary_secret" \
        | openssl dgst -sha256 -binary | openssl base64 | tr -d '\n' | tr '+/' '-_' | tr -d '=')"
    canary_queue="setup-verify-$(random_hex 8)"
    canary_id="setup-verify-$(date +%s)-$$"
    canary_expiry="$(iso_in "$canary_ttl")"

    post_body=$(cat <<EOF
{"id":"$canary_id","sender":"$canary_queue","recipient":"$canary_queue",
 "expiresAt":"$canary_expiry",
 "encryptedPayload":"c2V0dXAtdmVyaWZ5","recipientTag":"$canary_tag","senderTag":"$canary_tag"}
EOF
)
    post_code="$(printf '%s' "$post_body" | relay_curl -sS -o /dev/null -w '%{http_code}' --max-time 15 \
        -X POST -H 'Content-Type: application/json' --data-binary @- "$probe_url/messages" 2>/dev/null)"
    case "$post_code" in
        200|201|202)
            if [ -n "$admission_session" ]; then
                pass "a test record was accepted through the closed gate, on a session this code opened (it expires by itself in ${canary_ttl}s, whatever happens below)"
            else
                pass "a test record was accepted (it expires by itself in ${canary_ttl}s, whatever happens below)"
            fi ;;
        401|403)
            # An enforcing relay refusing a canary that carries no credential is
            # the gate working, and calling it "does not accept mail" would be
            # the most misleading line this script can print — it says the box is
            # broken when what it has done is exactly its job. With a session in
            # hand it is the opposite: the caller IS admitted, so a refusal is
            # the gate refusing a circle that paid.
            if [ -n "$admission_session" ]; then
                fail "the relay refused the canary ($post_code) even though it admitted this code and issued a session — a provisioned circle cannot post mail to this box"
            elif [ "$health_admission" = "true" ]; then
                pass "the relay refused a canary carrying no credential ($post_code) — the admission gate is closed to callers it has not admitted"
                if [ -n "$admission_code" ]; then
                    skip "the delivery cycle needs an admitted caller, and no session was opened above, so it was not exercised"
                else
                    skip "the delivery cycle needs an admitted caller and no --admission-code was given, so it was not exercised"
                fi
                unproven_section "the relay path — the gate refused the canary, so nothing here shows that mail crosses this box for a circle that IS admitted. Re-run with --admission-code - and a code this relay admits, or walk device row D2"
            else
                fail "POST $probe_url/messages returned $post_code but this relay is not enforcing admission — something in front of it is rejecting mail"
            fi
            post_code="" ;;
        *) fail "POST $probe_url/messages returned $post_code — this relay does not accept mail"; post_code="" ;;
    esac

    if [ -n "$post_code" ]; then
        fetched="$(relay_curl -fsS --max-time 15 -H "$capability_header: $canary_secret" \
            "$probe_url/messages?recipient=$canary_queue" 2>/dev/null)"
        case "$fetched" in
            *"$canary_id"*) pass "the holder of the queue secret can read it back — the delivery path works end to end" ;;
            *) fail "the test record could not be read back with its own capability; mail posted to this relay does not come out again" ;;
        esac

        # The same read without the secret. A tagged record is withheld in both
        # modes, so this is an assertion and not a mode-dependent observation.
        unauth="$(relay_curl -sS --max-time 15 "$probe_url/messages?recipient=$canary_queue" 2>/dev/null)"
        case "$unauth" in
            *"$canary_id"*) fail "the test record was served to a caller with NO capability — anyone who learns a queue id can read that queue" ;;
            *) pass "the same read without the secret returns nothing" ;;
        esac

        # Delivery: the recipient's device ack is what deletes the queued
        # message. This is the drain the whole design rests on.
        ack_body=$(cat <<EOF
{"id":"$canary_id-ack","messageId":"$canary_id","sender":"$canary_queue","recipient":"$canary_queue",
 "type":"recipient_device_received_ack","expiresAt":"$canary_expiry","senderTag":"$canary_tag"}
EOF
)
        ack_code="$(printf '%s' "$ack_body" | relay_curl -sS -o /dev/null -w '%{http_code}' --max-time 15 \
            -X POST -H 'Content-Type: application/json' --data-binary @- "$probe_url/acks" 2>/dev/null)"
        case "$ack_code" in
            200|202) pass "the delivery ack was accepted" ;;
            *) fail "POST $probe_url/acks returned $ack_code — a delivered message would never leave the queue" ;;
        esac

        after="$(relay_curl -fsS --max-time 15 -H "$capability_header: $canary_secret" \
            "$probe_url/messages?recipient=$canary_queue" 2>/dev/null)"
        case "$after" in
            *"$canary_id"*) fail "the test record is STILL queued after delivery — this relay keeps delivered mail" ;;
            *) pass "the record is gone from the queue the moment it was delivered" ;;
        esac

        # And the ack lane empties too, on its own, without anyone asking. That
        # is the sweeper doing what the amnesia claim says it does.
        if [ "$quick" = "1" ]; then
            skip "--quick: did not wait for the ack records to expire (they go at ${canary_ttl}s + one cleanup interval)"
            unproven_section "the sweep — --quick did not wait, so nothing here shows the relay forgets what it carried without being asked"
        else
            sweep_seconds=30
            case "$cleanup_interval" in
                *s) sweep_seconds="${cleanup_interval%s}" ;;
                *m) sweep_seconds=$(( ${cleanup_interval%m} * 60 )) ;;
            esac
            case "$sweep_seconds" in ''|*[!0-9]*) sweep_seconds=30 ;; esac
            deadline=$(( canary_ttl + sweep_seconds + 15 ))
            info "waiting up to ${deadline}s for the relay to forget the test record by itself"
            waited=0
            gone=""
            while [ "$waited" -le "$deadline" ]; do
                acks="$(relay_curl -fsS --max-time 10 -H "$capability_header: $canary_secret" \
                    "$probe_url/acks?sender=$canary_queue" 2>/dev/null)"
                case "$acks" in
                    *"$canary_id"*) ;;
                    *) gone="yes"; break ;;
                esac
                sleep 5
                waited=$(( waited + 5 ))
            done
            if [ -n "$gone" ]; then
                pass "every trace of the canary expired and was swept, ${waited}s in — nobody had to delete anything"
            else
                fail "the canary's ack records were still there ${deadline}s later; the cleanup sweep is not running (DEE_NODE_CLEANUP_INTERVAL)"
            fi
        fi
    fi
fi

# --- what is left on the box --------------------------------------------------
echo
echo "== what is left on the box =="
final_health="$(curl -fsS --max-time 10 "$probe_url/health" 2>/dev/null)"
final_messages="$(json_field "$final_health" messages)"
final_acks="$(json_field "$final_health" acks)"
final_sessions="$(json_field "$final_health" sessions)"
final_bytes="$(json_field "$final_health" bytes)"
info "queues after: messages=$final_messages acks=$final_acks; attachment relay: sessions=$final_sessions bytes=$final_bytes"

if [ "$baseline_messages" = "0" ] && [ "$baseline_acks" = "0" ] \
   && [ "$final_messages" = "0" ] && [ "$final_acks" = "0" ]; then
    if [ "$skip_canary" = "1" ]; then
        info "the relay is holding nothing right now — but nothing was sent through it, so this is an observation and not a result"
    else
        pass "the relay held nothing before the test and holds nothing after it"
    fi
elif [ -n "$final_messages" ]; then
    # A relay carrying real traffic will never read zero, and demanding that it
    # does would make this check fail on exactly the relays that work.
    info "this relay is carrying live traffic, so the counts are not expected to be zero; what the canary showed is that a delivered record leaves"
fi
info "nothing observed over HTTP can prove the binary writes no state — that is internal/audit's test, plus the sandbox above"

echo
echo "== summary =="
echo "  checks failed:  $failures"
echo "  need a human:   $warnings"
echo "  not checked:    $skips"
if [ -n "$public_url" ]; then
    echo "  relay:          $public_url (nodeId ${node_id:-?})"
fi
if [ -n "$unproven" ]; then
    echo
    echo "This run proved less than a clean summary suggests. Unchecked here:"
    echo "$unproven"
    echo "None of these is a pass. Each is either checked another way or written"
    echo "into the delivery mail as something this box has not been shown to do."
fi
echo
echo "Send this whole output back to whoever set this box up for you, failures"
echo "included — that is what the verification round is for. Nothing here contains"
echo "a key, a message, or anyone's queue id."
echo
# Printed whatever the exit code: a run with a failure in it is a mid-delivery
# run, and it is exactly then that the rest of what is still owed matters.
echo "Not covered by this run, and not optional:"
echo "  reboot survival — acceptance.sh <url> --unit ${unit:-dee-relay.service} --after-reboot"
echo "  the devices     — the per-device rows in the Relay Setup checklist"
if [ "$failures" -eq 0 ]; then
    exit 0
fi
exit 1
