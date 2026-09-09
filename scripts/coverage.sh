#!/usr/bin/env bash
# Do the probes see every packet, or only some of them?
#
#   sudo bash scripts/coverage.sh
#
# Send an exact, known number of datagrams and connections from a container to
# a blackhole address, then count what arrived. Anything less than the number
# sent is a coverage gap, and a monitor that is cheap because it is blind is
# worse than no monitor at all.
#
# TEST-NET-3 (203.0.113.0/24, RFC 5737) is reserved and unrouted, so the sends
# leave the host and go nowhere. Nothing here depends on a reply.

set -uo pipefail

BIN=${BIN:-./target/debug/quasar}
UDP_N=${UDP_N:-100}
TCP_N=${TCP_N:-20}
DEST=203.0.113.5
IMAGE=python:3-alpine
NAME=quasar-coverage
OUT=$(mktemp -d)

[ "$(id -u)" -eq 0 ] || { echo "needs root" >&2; exit 1; }
[ -x "$BIN" ] || { echo "$BIN not found (make dev)" >&2; exit 1; }

cleanup() {
    [ -n "${QPID:-}" ] && kill -INT "$QPID" 2>/dev/null && wait "$QPID" 2>/dev/null
    docker rm -f "$NAME" >/dev/null 2>&1
    rm -rf "$OUT"
}
trap cleanup EXIT INT TERM

docker rm -f "$NAME" >/dev/null 2>&1
docker image inspect "$IMAGE" >/dev/null 2>&1 || docker pull -q "$IMAGE" >/dev/null

# No policy: everything must reach userspace, so the count is unambiguous.
"$BIN" run --quiet --jsonl "$OUT/events.jsonl" > "$OUT/quasar.log" 2>&1 &
QPID=$!
sleep 4
kill -0 "$QPID" 2>/dev/null || { echo "quasar died:"; cat "$OUT/quasar.log"; exit 1; }

docker run --rm --name "$NAME" "$IMAGE" python -c "
import socket
u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
for _ in range($UDP_N):
    u.sendto(b'x', ('$DEST', 9999))
for _ in range($TCP_N):
    t = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    t.settimeout(0.01)
    try: t.connect(('$DEST', 9999))
    except OSError: pass
    t.close()
" >/dev/null 2>&1

sleep 2
kill -INT "$QPID"; wait "$QPID" 2>/dev/null; QPID=""

# Parse rather than grep: field order in the record is not a contract.
read -r UDP_SEEN TCP_SEEN <<< "$(python3 -c "
import json, sys
udp = tcp = 0
for line in open('$OUT/events.jsonl'):
    r = json.loads(line)
    if r.get('kind') != 'connect' or r.get('dest') != '$DEST': continue
    if r['proto'] == 'udp': udp += 1
    elif r['proto'] == 'tcp': tcp += 1
print(udp, tcp)
")"

echo
echo "===================== COVERAGE ====================="
printf '  udp  sent %4d  seen %4d   %s\n' "$UDP_N" "$UDP_SEEN" \
    "$([ "$UDP_SEEN" -ge "$UDP_N" ] && echo PASS || echo "MISSING $((UDP_N - UDP_SEEN))")"
printf '  tcp  sent %4d  seen %4d   %s\n' "$TCP_N" "$TCP_SEEN" \
    "$([ "$TCP_SEEN" -ge "$TCP_N" ] && echo PASS || echo "MISSING $((TCP_N - TCP_SEEN))")"
echo
grep -E 'dropped' "$OUT/quasar.log" | sed 's/^/  /' || echo "  no losses reported"
