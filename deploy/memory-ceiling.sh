#!/usr/bin/env bash
#
# Derive MemoryMax and GOMEMLIMIT for a host from that host's node.env.
#
#   deploy/memory-ceiling.sh /etc/deechat/node.env
#   deploy/memory-ceiling.sh /etc/deechat/node.env --check-unit /etc/systemd/system/dee-relay.service
#
# Every store in the node is an in-RAM map, so the ceiling is a function of the
# configured caps and nothing else. Guessing it is the failure the design doc
# names: too low and a flood becomes an OOM kill, which on a RAM-only relay
# means every queued message on this host is gone.
#
# --check-unit exits non-zero when the unit's MemoryMax is below the derived
# figure, so a cap raised in node.env without a matching unit edit is caught
# before the host is.
#
# Per-record sizes below are deliberate over-estimates: the cost of being
# generous is unused headroom, the cost of being tight is lost mail.

set -euo pipefail

readonly MIB=1048576

# Go runtime, HTTP server, and connection buffers before a single record is
# stored. Measured baseline is well under this; round up.
readonly BASELINE_MIB=64

# Live-set to ceiling factor. The Go collector needs room to work above the
# live set even with GOMEMLIMIT set; below ~1.3 it thrashes.
readonly HEADROOM_NUM=15
readonly HEADROOM_DEN=10

# GOMEMLIMIT as a percentage of MemoryMax. It is a soft limit — the collector
# works harder as it approaches, rather than the kernel killing the process —
# so it must sit below the hard cap, not on it.
readonly SOFT_LIMIT_PCT=90

usage() {
    echo "usage: $(basename "$0") <env-file> [--check-unit <unit-file>]" >&2
    exit 2
}

env_file=""
unit_file=""
while [ $# -gt 0 ]; do
    case "$1" in
        --check-unit) [ $# -ge 2 ] || usage; unit_file="$2"; shift 2 ;;
        -h|--help) usage ;;
        -*) usage ;;
        *) [ -z "$env_file" ] || usage; env_file="$1"; shift ;;
    esac
done
[ -n "$env_file" ] || usage
[ -f "$env_file" ] || { echo "no such env file: $env_file" >&2; exit 2; }

# Read KEY=VALUE without sourcing the file: an env file is data, and this
# script may run against one an operator just edited.
raw_value() {
    sed -n "s/^[[:space:]]*$1=//p" "$env_file" | tail -n 1 | sed 's/[[:space:]]*$//' | tr -d "\"'"
}

# Mirror config.go's envInt exactly, including the part that bites: an
# unparseable or non-positive value falls back to the default *silently*. A
# typo'd cap therefore reverts to a default that may be far larger than
# intended, which is precisely how a ceiling derived from the file on disk
# would end up too low for the process actually running.
cap() {
    local key="$1" default="$2" value
    value="$(raw_value "$key")"
    if [ -z "$value" ]; then
        echo "$default"
        return
    fi
    if ! [[ "$value" =~ ^-?[0-9]+$ ]] || [ "$value" -le 0 ]; then
        echo "warning: $key=$value is not a positive integer; the node will" \
             "silently use $default and so does this calculation" >&2
        echo "$default"
        return
    fi
    echo "$value"
}

max_messages="$(cap DEE_NODE_MAX_MESSAGES 1000)"
max_acks="$(cap DEE_NODE_MAX_ACKS $((2 * max_messages)))"
max_purges="$(cap DEE_NODE_MAX_PURGES 1000)"
max_payload="$(cap DEE_NODE_MAX_PAYLOAD_BYTES 8192)"
max_chunk="$(cap DEE_NODE_MAX_CHUNK_BYTES 1048576)"
relay_window="$(cap DEE_NODE_RELAY_MAX_WINDOW 8)"
relay_sessions="$(cap DEE_NODE_RELAY_MAX_SESSIONS 256)"
max_prekey_buckets="$(cap DEE_NODE_MAX_PREKEY_BUCKETS 5000)"

# Envelope fields, map overhead, and the recipientTag beside the payload. The
# 2048 also absorbs queue.Store's per-record bookkeeping: the replication cursor
# (messageSeq/ackSeq), the write-authorization binding (messageTags) and the two
# deletion indexes /profile/purge runs on (messagesByPurge, acksByMessage).
# Each is at most one map entry per record, roughly 50 bytes including the key
# header, sharing the id's bytes rather than copying them — together well inside
# this figure. All of them are kept in lock-step with the record maps by the
# same four add/delete helpers (there is a test for the leak, because a leak
# here would be unbounded state this ceiling is not sized for).
readonly MESSAGE_OVERHEAD=2048
readonly ACK_BYTES=1024
readonly PURGE_BYTES=1024
# presence.NewStore is called with 5000 in cmd/dee-relay/main.go — not an
# env var. If that constant moves, this line has to move with it.
#
# Counted twice: the same 5000 bounds the heartbeat table and, separately, the
# revocation tombstones beside it (presence.Store.revocations, held to the
# lastSeenTTL). A full revocation map refuses a new entry; a full heartbeat table
# takes a slot from the record with the weakest claim on it, so the table's size
# is the same either way. The per-caller counter beside it holds at most one
# entry per record and shares the caller key's bytes, well inside the figure
# below.
readonly PRESENCE_RECORDS=5000
readonly PRESENCE_TABLES=2
readonly PRESENCE_BYTES=1024
# The admission gate's two ephemeral tables, from the constants in
# internal/admission/session.go — outstanding challenges (maxNonces, 30 s TTL)
# and live sessions (maxSessions, 15 min). POST /admission/challenge is
# necessarily unauthenticated, so the nonce table is the one table on this box
# any caller can push against; both are bounded there and counted here. Not env
# vars: if those constants move, these lines move with them.
readonly NONCE_ENTRIES=8192
readonly NONCE_BYTES=256
readonly SESSION_ENTRIES=16384
# A token, the credential id it belongs to, an expiry, and the second copy of
# the token that byCredential keeps to age a circle's oldest session out.
readonly SESSION_BYTES=512
# One pool per publishing device: up to prekey.defaultMaxPerRecipient one-time
# entries plus the single reusable last-resort prekey. That 100 is a constant in
# internal/prekey/store.go and not an env var — if it moves, this line moves with
# it, the same standing obligation as PRESENCE_RECORDS above. Per entry: an id, a
# base64 X25519 public half and a base64 Ed25519 signature, with map overhead.
readonly PREKEY_ENTRIES_PER_BUCKET=101
readonly PREKEY_BYTES=512
# The replay set a live attachment session keeps beside its window: one bit per
# chunk index the transfer may span, so it refuses a chunk already drained
# rather than delivering it twice. maxChunksPerTransfer in
# internal/attachment/relay.go, a constant and not an env var — if it moves,
# this line moves with it, the same standing obligation as PRESENCE_RECORDS
# above. A transfer declaring more indices than this is refused outright, which
# is what makes the term countable at all.
readonly CHUNK_INDEX_BITS=8192

messages_bytes=$((max_messages * (max_payload + MESSAGE_OVERHEAD)))
acks_bytes=$((max_acks * ACK_BYTES))
purges_bytes=$((max_purges * PURGE_BYTES))
presence_bytes=$((PRESENCE_TABLES * PRESENCE_RECORDS * PRESENCE_BYTES))
admission_bytes=$(((NONCE_ENTRIES * NONCE_BYTES) + (SESSION_ENTRIES * SESSION_BYTES)))
# The dominant term by an order of magnitude at the defaults: 256 concurrent
# sessions x 8 in-flight chunks x 1 MiB = 2 GiB.
attachment_bytes=$((relay_sessions * relay_window * max_chunk))
replay_bytes=$((relay_sessions * CHUNK_INDEX_BITS / 8))
prekey_bytes=$((max_prekey_buckets * PREKEY_ENTRIES_PER_BUCKET * PREKEY_BYTES))

live_bytes=$((messages_bytes + acks_bytes + purges_bytes + presence_bytes + admission_bytes + attachment_bytes + replay_bytes + prekey_bytes))
ceiling_bytes=$(( (live_bytes * HEADROOM_NUM / HEADROOM_DEN) + (BASELINE_MIB * MIB) ))

# Round up to whole MiB.
ceiling_mib=$(( (ceiling_bytes + MIB - 1) / MIB ))
soft_mib=$((ceiling_mib * SOFT_LIMIT_PCT / 100))

mib() { printf '%d MiB' $(( ($1 + MIB - 1) / MIB )); }

cat <<EOF
Derived from $env_file

  messages     $(mib $messages_bytes)	($max_messages x $((max_payload + MESSAGE_OVERHEAD)) B)
  acks         $(mib $acks_bytes)	($max_acks x $ACK_BYTES B)
  purges       $(mib $purges_bytes)	($max_purges x $PURGE_BYTES B)
  presence     $(mib $presence_bytes)	($PRESENCE_TABLES x $PRESENCE_RECORDS x $PRESENCE_BYTES B, not configurable)
  admission    $(mib $admission_bytes)	($NONCE_ENTRIES nonces x $NONCE_BYTES B + $SESSION_ENTRIES sessions x $SESSION_BYTES B, not configurable)
  attachments  $(mib $attachment_bytes)	($relay_sessions sessions x $relay_window chunks x $max_chunk B)
  replay sets  $(mib $replay_bytes)	($relay_sessions sessions x $CHUNK_INDEX_BITS chunk indices / 8, not configurable)
  prekeys      $(mib $prekey_bytes)	($max_prekey_buckets pools x $PREKEY_ENTRIES_PER_BUCKET x $PREKEY_BYTES B)
  ------------------------------------------------------------
  live set     $(mib $live_bytes)
  + ${HEADROOM_NUM}/${HEADROOM_DEN} GC headroom, + ${BASELINE_MIB} MiB runtime baseline

Put these in the unit and the env file:

  MemoryMax=${ceiling_mib}M
  MemorySwapMax=0
  GOMEMLIMIT=${soft_mib}MiB

Every store a caller can grow is counted above, and none of them grows past the
cap counted here. All but one answer a full store by refusing the new entry: a
pool refused at DEE_NODE_MAX_PREKEY_BUCKETS, like a queue refused at
DEE_NODE_MAX_MESSAGES, is back-pressure the client retries against. A transfer
sliced past CHUNK_INDEX_BITS is the one refusal a client cannot retry into — it
has to send larger chunks — which is the price of the replay sets line being a
number. The exception is the presence heartbeat table, which at capacity takes
the slot from the lease with the weakest claim on it rather than refusing the
newcomer: a presence record outlives its own five-minute online window by a day,
so refusing there meant one burst could lock new identities out for that day.

What is not listed at all is sized by the operator's own configuration rather
than by traffic — the peer table and its replication cursors (one entry per
DEE_NODE_MESH_PEERS entry), and the per-credential counters that carry one
integer each for the credentials in the admission file. Those live in the
runtime baseline above.
EOF

if [ -n "$unit_file" ]; then
    [ -f "$unit_file" ] || { echo "no such unit file: $unit_file" >&2; exit 2; }
    declared="$(sed -n 's/^MemoryMax=//p' "$unit_file" | tail -n 1)"
    if [ -z "$declared" ] || [ "$declared" = "REPLACE_ME" ]; then
        echo >&2
        echo "FAIL: $unit_file has no MemoryMax set" >&2
        exit 1
    fi
    # Accept 1234M / 1234M / 1G / plain bytes.
    number="${declared%[KMGkmg]}"
    case "$declared" in
        *[Gg]) declared_mib=$((number * 1024)) ;;
        *[Mm]) declared_mib=$number ;;
        *[Kk]) declared_mib=$((number / 1024)) ;;
        *) declared_mib=$((number / MIB)) ;;
    esac
    echo
    if [ "$declared_mib" -lt "$ceiling_mib" ]; then
        echo "FAIL: $unit_file declares MemoryMax=$declared (${declared_mib} MiB)," \
             "below the derived ${ceiling_mib} MiB" >&2
        echo "      Raise MemoryMax, or lower the caps in $env_file." >&2
        exit 1
    fi
    echo "OK: $unit_file declares MemoryMax=$declared (>= ${ceiling_mib} MiB derived)"
fi
