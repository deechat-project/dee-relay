#!/usr/bin/env bash
#
# Print a relay's endpoint fingerprint: the base64 SHA-256 of its TLS
# certificate's SubjectPublicKeyInfo, with the expiry that fingerprint is good
# until.
#
#   deploy/spki-hash.sh relay-1.example.org
#   deploy/spki-hash.sh relay-1.example.org:8443
#   deploy/spki-hash.sh relay-1.example.org --expect <base64>
#
# Exit 0 fine, 1 could not reach or parse the certificate, 2 usage,
# 3 --expect given and the fingerprint has changed.
#
# The value rotates. Caddy generates a new certificate key on every renewal by
# default, so this fingerprint changes roughly every 60 days on its own — which is
# why the output carries `valid to` and why deploy/FINGERPRINTS.md publishes it as
# a dated observation rather than a pin. A mismatch *before* the printed expiry
# is worth investigating; one after it is probably just a renewal, and the
# published record needs refreshing.

set -euo pipefail

host=""
expect=""
while [ $# -gt 0 ]; do
    case "$1" in
        --expect) expect="$2"; shift 2 ;;
        -*) echo "usage: spki-hash.sh <host[:port]> [--expect <base64>]" >&2; exit 2 ;;
        *) if [ -n "$host" ]; then echo "one host at a time" >&2; exit 2; fi; host="$1"; shift ;;
    esac
done

[ -n "$host" ] || { echo "usage: spki-hash.sh <host[:port]> [--expect <base64>]" >&2; exit 2; }

command -v openssl >/dev/null 2>&1 || { echo "openssl not found" >&2; exit 1; }

case "$host" in
    *:*) connect="$host"; servername="${host%%:*}" ;;
    *)   connect="$host:443"; servername="$host" ;;
esac

pem="$(mktemp -t dee-spki.XXXXXX)"
trap 'rm -f "$pem"' EXIT

# -servername so a proxy serving several hosts hands back the right certificate;
# without it a shared front end answers with its default and the fingerprint
# published for this relay would be some other relay's.
if ! openssl s_client -connect "$connect" -servername "$servername" \
        </dev/null 2>/dev/null | openssl x509 -outform pem >"$pem" 2>/dev/null; then
    echo "could not retrieve a certificate from $connect" >&2
    exit 1
fi

[ -s "$pem" ] || { echo "no certificate returned by $connect" >&2; exit 1; }

spki="$(openssl x509 -in "$pem" -pubkey -noout \
    | openssl pkey -pubin -outform der \
    | openssl dgst -sha256 -binary \
    | openssl base64)"

not_after="$(openssl x509 -in "$pem" -noout -enddate | sed 's/^notAfter=//')"
subject="$(openssl x509 -in "$pem" -noout -subject | sed 's/^subject= *//')"
issuer="$(openssl x509 -in "$pem" -noout -issuer | sed 's/^issuer= *//')"

echo "endpoint   $connect (SNI $servername)"
echo "subject    $subject"
echo "issuer     $issuer"
echo "valid to   $not_after"
echo "spki       $spki"

if [ -n "$expect" ]; then
    if [ "$spki" = "$expect" ]; then
        echo "expect     MATCH"
    else
        echo "expect     CHANGED" >&2
        echo "           published $expect" >&2
        echo "           observed  $spki" >&2
        echo "           If the published record is older than this certificate," >&2
        echo "           this is a renewal, not an attack. Refresh the record." >&2
        exit 3
    fi
fi
