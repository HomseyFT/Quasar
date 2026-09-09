#!/usr/bin/env bash
# Every phase's acceptance criteria, as assertions.
#
#   sudo QUASAR_TEST_ROOT=1 bash scripts/acceptance.sh          # all phases
#   sudo QUASAR_TEST_ROOT=1 bash scripts/acceptance.sh 3 4b     # just these
#
# Needs root (BPF), docker, and python3. Spins up throwaway containers, does
# known things inside them, and asserts on the JSONL log -- not on the printed
# output, which is a display concern and free to change.
#
# Every assertion that proves an absence is paired with one that proves a
# presence. A monitor that reports nothing passes every "must not appear" test
# ever written, so those alone prove nothing.
set -uo pipefail

REPO=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$REPO" || exit 1

BIN=${BIN:-./target/debug/quasar}
PHASES=("$@")
[ ${#PHASES[@]} -eq 0 ] && PHASES=(1 2 3 4a 4b 4c 5 6a)

[ "${QUASAR_TEST_ROOT:-}" = 1 ] || {
    echo "refusing to run without QUASAR_TEST_ROOT=1 -- this starts and removes containers" >&2
    exit 2
}
[ "$(id -u)" -eq 0 ] || { echo "needs root" >&2; exit 1; }
[ -x "$BIN" ] || { echo "$BIN not found (make dev)" >&2; exit 1; }
command -v docker >/dev/null || { echo "docker not found" >&2; exit 1; }

WORK=$(mktemp -d)
CONTAINERS=()
PASSED=0
FAILED=0
QPID=""
RPID=""

cleanup() {
    [ -n "$QPID" ] && kill -INT "$QPID" 2>/dev/null && wait "$QPID" 2>/dev/null
    [ -n "$RPID" ] && kill "$RPID" 2>/dev/null
    [ ${#CONTAINERS[@]} -gt 0 ] && docker rm -f "${CONTAINERS[@]}" >/dev/null 2>&1
    rm -rf "$WORK"
}
trap cleanup EXIT INT TERM

# -- reporting --------------------------------------------------------------

section() { printf '\n\033[1m== phase %s: %s\033[0m\n' "$1" "$2"; }
ok()   { PASSED=$((PASSED + 1)); printf '  \033[32mPASS\033[0m  %s\n' "$1"; }
bad()  { FAILED=$((FAILED + 1)); printf '  \033[31mFAIL\033[0m  %s\n' "$1"; }
note() { printf '        %s\n' "$1"; }

# -- the system under test --------------------------------------------------

JSONL=""
start_quasar() {
    JSONL=$WORK/events-$RANDOM.jsonl
    "$BIN" run --quiet --jsonl "$JSONL" "$@" > "$WORK/quasar.log" 2>&1 &
    QPID=$!
    sleep 4
    if ! kill -0 "$QPID" 2>/dev/null; then
        bad "quasar did not start"
        sed 's/^/        /' "$WORK/quasar.log"
        QPID=""
        return 1
    fi
}

stop_quasar() {
    [ -n "$QPID" ] || return 0
    kill -INT "$QPID"
    wait "$QPID" 2>/dev/null
    QPID=""
}

boot() {
    local name=$1; shift
    CONTAINERS+=("$name")
    docker rm -f "$name" >/dev/null 2>&1
    docker run -d --name "$name" "$@" >/dev/null
    sleep 1
}

# -- assertions over the log ------------------------------------------------

# Count records for which the python expression over `r` is true.
count() {
    python3 -c '
import json, sys
expr, path = sys.argv[1], sys.argv[2]
n = 0
try:
    lines = open(path)
except OSError:
    print(0); raise SystemExit
for line in lines:
    line = line.strip()
    if not line:
        continue
    try:
        if eval(expr, {"r": json.loads(line)}):
            n += 1
    except Exception:
        pass
print(n)
' "$1" "$JSONL"
}

assert_some() {
    local what=$1 expr=$2 n
    n=$(count "$expr")
    [ "$n" -gt 0 ] && ok "$what" || { bad "$what"; note "nothing matched: $expr"; }
}

assert_none() {
    local what=$1 expr=$2 n
    n=$(count "$expr")
    [ "$n" -eq 0 ] && ok "$what" || { bad "$what"; note "$n records matched: $expr"; }
}

assert_count() {
    local want=$1 what=$2 expr=$3 n
    n=$(count "$expr")
    [ "$n" -eq "$want" ] && ok "$what" || { bad "$what"; note "wanted $want, got $n"; }
}

want_phase() {
    local p
    for p in "${PHASES[@]}"; do [ "$p" = "$1" ] && return 0; done
    return 1
}

docker image inspect alpine >/dev/null 2>&1 || docker pull -q alpine >/dev/null

# ---------------------------------------------------------------------------
# Phase 1 -- an exec inside a container produces an event.
# ---------------------------------------------------------------------------
if want_phase 1; then
    section 1 "exec events reach userspace"
    start_quasar && {
        boot quasar-p1 alpine sleep 60
        docker exec quasar-p1 /bin/echo hello >/dev/null 2>&1
        sleep 2
        stop_quasar

        assert_some "an exec inside a container is captured" \
            'r["kind"] == "exec" and r["path"] == "/bin/echo"'
        assert_some "the event carries a pid, ppid and comm" \
            'r["kind"] == "exec" and r["path"] == "/bin/echo" and r["pid"] > 0 and r["ppid"] > 0 and r["comm"] == "echo"'
        assert_none "no event has a truncated or empty path" \
            'r["kind"] == "exec" and not r["path"].startswith("/")'
    }
fi

# ---------------------------------------------------------------------------
# Phase 2 -- attribution: the right container, and no stale names.
# ---------------------------------------------------------------------------
if want_phase 2; then
    section 2 "attribution"
    start_quasar && {
        boot quasar-p2a alpine sleep 60
        docker exec quasar-p2a /bin/echo from-a >/dev/null 2>&1
        sleep 1

        # If the cgroup cache went stale, b's execs come back named as a.
        docker rm -f quasar-p2a >/dev/null 2>&1
        sleep 1
        boot quasar-p2b alpine sleep 60
        docker exec quasar-p2b /bin/echo from-b >/dev/null 2>&1
        sleep 1

        # An entrypoint that execs before the docker event stream has
        # necessarily reported the container.
        docker run --rm --name quasar-p2fast alpine /bin/echo fast >/dev/null 2>&1
        sleep 2
        stop_quasar

        assert_some "a container exec names its container" \
            'r["source"] == "quasar-p2a" and r.get("path") == "/bin/echo"'
        assert_some "a replacement container is named correctly" \
            'r["source"] == "quasar-p2b" and r.get("path") == "/bin/echo"'
        # quasar-p2a ran exactly one /bin/echo. A stale cgroup cache would
        # attribute quasar-p2b's echo to it as well, making two.
        assert_count 1 "a dead container's name is not reused for a live one" \
            'r["source"] == "quasar-p2a" and r.get("path") == "/bin/echo"'
        assert_some "an immediate exec is still attributed to a container" \
            'r["attributed"] in ("named", "container") and r.get("path") == "/bin/echo"'
        assert_some "host processes are labelled host, not unknown" \
            'r["attributed"] == "host"'
        assert_none "nothing is attributed to a container id that is also a host path" \
            'r["attributed"] == "named" and r["source"].startswith("host:")'
    }
fi

# ---------------------------------------------------------------------------
# Phase 3 -- egress, with exact destinations on v4 and v6, tcp and udp.
# ---------------------------------------------------------------------------
if want_phase 3; then
    section 3 "egress destinations are exact"
    start_quasar && {
        # Loopback with distinctive ports: every expected event is exact rather
        # than "something plausible happened". Nothing needs to be listening --
        # the probes fire on the attempt.
        python3 - <<'PY' >/dev/null 2>&1
import socket

def attempt(family, kind, addr):
    s = socket.socket(family, kind)
    s.settimeout(0.5)
    try:
        s.connect(addr)
        if kind == socket.SOCK_DGRAM:
            s.send(b"x")
    except Exception:
        pass
    s.close()

attempt(socket.AF_INET,  socket.SOCK_STREAM, ("127.0.0.1", 9101))
attempt(socket.AF_INET6, socket.SOCK_STREAM, ("::1", 9102))

u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)      # msg_name branch
u.sendto(b"x", ("127.0.0.1", 9103)); u.close()
attempt(socket.AF_INET, socket.SOCK_DGRAM, ("127.0.0.1", 9104))   # skc_daddr

u6 = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)    # v6 msg_name branch
u6.sendto(b"x", ("::1", 9105)); u6.close()
attempt(socket.AF_INET6, socket.SOCK_DGRAM, ("::1", 9106))        # skc_v6_daddr
PY
        sleep 2
        stop_quasar

        assert_some "tcp v4 destination and port"  'r.get("proto") == "tcp" and r.get("dest") == "127.0.0.1" and r.get("port") == 9101'
        assert_some "tcp v6 destination and port"  'r.get("proto") == "tcp" and r.get("dest") == "::1" and r.get("port") == 9102'
        assert_some "udp v4 via msg_name"          'r.get("proto") == "udp" and r.get("dest") == "127.0.0.1" and r.get("port") == 9103'
        assert_some "udp v4 via the socket"        'r.get("proto") == "udp" and r.get("dest") == "127.0.0.1" and r.get("port") == 9104'
        assert_some "udp v6 via msg_name"          'r.get("proto") == "udp" and r.get("dest") == "::1" and r.get("port") == 9105'
        assert_some "udp v6 via the socket"        'r.get("proto") == "udp" and r.get("dest") == "::1" and r.get("port") == 9106'

        # The failure these catch is reading the wrong struct field, which
        # yields plausible-looking events with a zero address or port.
        assert_none "no connect event has a zero destination" \
            'r["kind"] == "connect" and r["dest"] in ("0.0.0.0", "::")'
        assert_none "no connect event has a zero port" \
            'r["kind"] == "connect" and r["port"] == 0'
    }
fi

# ---------------------------------------------------------------------------
# Phase 4a -- the durable log, and learn against real events.
# ---------------------------------------------------------------------------
if want_phase 4a; then
    section 4a "the log is durable and learnable"
    start_quasar && {
        boot quasar-p4a alpine sleep 60
        docker exec quasar-p4a /bin/sh -c \
            'echo hi; wget -q -T 2 -O /dev/null http://1.1.1.1/ 2>/dev/null' >/dev/null 2>&1
        sleep 2
        stop_quasar

        malformed=$(python3 -c '
import json, sys
bad = 0
for line in open(sys.argv[1]):
    if not line.strip(): continue
    try: json.loads(line)
    except Exception: bad += 1
print(bad)
' "$JSONL")
        [ "$malformed" -eq 0 ] && ok "every line is valid JSON" \
                               || bad "$malformed malformed JSON lines"

        # The timestamp is a monotonic clock reading offset to wall time. If
        # the offset is wrong it lands in 1970 or in the far future, and the
        # log becomes unusable for anything time-ordered.
        recent=$(python3 -c '
import json, sys, datetime, re
now = datetime.datetime.now(datetime.timezone.utc)
n = 0
for line in open(sys.argv[1]):
    line = line.strip()
    if not line:
        continue
    stamp = json.loads(line).get("time", "")
    # fromisoformat takes microseconds at most; the log carries nanoseconds.
    stamp = re.sub(r"(\.\d{6})\d+", r"\1", stamp).replace("Z", "+00:00")
    try:
        when = datetime.datetime.fromisoformat(stamp)
    except ValueError:
        continue
    if abs((now - when).total_seconds()) < 3600:
        n += 1
print(n)
' "$JSONL")
        [ "$recent" -gt 0 ] \
            && ok "timestamps are wall clock, not uptime" \
            || bad "no timestamp landed within an hour of now"

        POLICY=$WORK/p4a-policy
        "$BIN" learn --from "$JSONL" --out "$POLICY" > "$WORK/learn.log" 2>&1
        if [ -f "$POLICY/quasar-p4a.toml" ]; then
            ok "learn produced a policy for the container"
            grep -q '/bin/sh' "$POLICY/quasar-p4a.toml" \
                && ok "the policy baselined an observed binary" \
                || bad "the policy is missing /bin/sh"
            grep -q '1.1.1.1/32' "$POLICY/quasar-p4a.toml" \
                && ok "the policy baselined an observed destination" \
                || bad "the policy is missing 1.1.1.1/32"
            grep -q '/proc/' "$POLICY/quasar-p4a.toml" \
                && bad "a /proc path was baselined" \
                || ok "no /proc path was baselined"
        else
            bad "learn produced no policy for the container"
            sed 's/^/        /' "$WORK/learn.log"
        fi
    }
fi

# ---------------------------------------------------------------------------
# Phase 4b -- kernel-side filtering.
# ---------------------------------------------------------------------------
if want_phase 4b; then
    section 4b "known-good events die in the kernel"
    # One long-lived container across both runs, so the cgroup id the
    # allowlist is keyed on does not change underneath us.
    boot quasar-p4b alpine sleep 300

    baseline_p4b() {
        docker exec quasar-p4b /bin/echo baseline >/dev/null 2>&1
        docker exec quasar-p4b /bin/sh -c \
            'wget -q -T 2 -O /dev/null http://1.1.1.1/ 2>/dev/null' >/dev/null 2>&1
    }

    start_quasar && {
        baseline_p4b
        sleep 2
        stop_quasar
        BEFORE=$JSONL

        POLICY=$WORK/p4b-policy
        "$BIN" learn --from "$BEFORE" --out "$POLICY" >/dev/null 2>&1

        start_quasar --policy "$POLICY" && {
            baseline_p4b
            docker exec quasar-p4b /bin/date >/dev/null 2>&1
            docker exec quasar-p4b /bin/sh -c \
                'wget -q -T 2 -O /dev/null http://9.9.9.9/ 2>/dev/null' >/dev/null 2>&1
            sleep 2
            stop_quasar

            assert_none "an allowed exec never reaches userspace" \
                'r["source"] == "quasar-p4b" and r.get("path") == "/bin/echo"'
            assert_none "an allowed destination never reaches userspace" \
                'r["source"] == "quasar-p4b" and r.get("dest") == "1.1.1.1"'

            # The control. A filter that drops everything passes both of the
            # assertions above and is worthless.
            assert_some "an unallowed exec still arrives" \
                'r["source"] == "quasar-p4b" and r.get("path") == "/bin/date"'
            assert_some "an unallowed destination still arrives" \
                'r["source"] == "quasar-p4b" and r.get("dest") == "9.9.9.9"'
        }
    }
fi

# ---------------------------------------------------------------------------
# Phase 4c -- alerting.
# ---------------------------------------------------------------------------
if want_phase 4c; then
    section 4c "alerting"
    ALERTS=$WORK/alerts.jsonl
    PORT=$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()')

    # A local receiver rather than ntfy.sh: nothing here needs to leave the
    # machine, and it lets us assert on the exact notification.
    cat > "$WORK/receiver.py" <<'PY'
import json, sys
from http.server import BaseHTTPRequestHandler, HTTPServer

class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
        with open(sys.argv[2], "a") as f:
            f.write(json.dumps({
                "title": self.headers.get("Title"),
                "priority": self.headers.get("Priority"),
                "tags": self.headers.get("Tags"),
                "body": body.decode("utf-8", "replace"),
            }) + "\n")
        self.send_response(200)
        self.end_headers()

    def log_message(self, *args):
        pass

HTTPServer(("127.0.0.1", int(sys.argv[1])), Handler).serve_forever()
PY
    python3 "$WORK/receiver.py" "$PORT" "$ALERTS" &
    RPID=$!
    sleep 1

    alerts() {
        [ -f "$ALERTS" ] || { echo 0; return; }
        grep -cF -- "$1" "$ALERTS" || true
    }

    boot quasar-p4c alpine sleep 300
    baseline_p4c() {
        docker exec quasar-p4c /bin/echo baseline >/dev/null 2>&1
        docker exec quasar-p4c /bin/sh -c \
            'wget -q -T 2 -O /dev/null http://1.1.1.1/ 2>/dev/null' >/dev/null 2>&1
    }

    start_quasar && {
        baseline_p4c
        sleep 2
        stop_quasar
        POLICY=$WORK/p4c-policy
        "$BIN" learn --from "$JSONL" --out "$POLICY" >/dev/null 2>&1

        start_quasar --policy "$POLICY" --ntfy "http://127.0.0.1:$PORT/quasar-test" && {
            baseline_p4c
            sleep 2
            quiet=$(alerts '')

            # A container nobody has baselined must not page anyone.
            boot quasar-p4c-none alpine sleep 120
            docker exec quasar-p4c-none /bin/date >/dev/null 2>&1
            sleep 2
            unbaselined_container=$(alerts '')

            docker exec quasar-p4c /bin/date >/dev/null 2>&1
            docker exec quasar-p4c /bin/sh -c \
                'wget -q -T 2 -O /dev/null http://9.9.9.9/ 2>/dev/null' >/dev/null 2>&1
            sleep 3
            for _ in $(seq 9); do docker exec quasar-p4c /bin/date >/dev/null 2>&1; done
            sleep 3
            stop_quasar

            [ "$quiet" -eq 0 ] && ok "a normal day raises no alert" \
                               || bad "baselined activity raised $quiet alerts"
            [ "$unbaselined_container" -eq "$quiet" ] \
                && ok "a container with no policy raises no alert" \
                || bad "a container with no policy raised $((unbaselined_container - quiet)) alerts"

            [ "$(alerts '/proc/self/fd/')" -eq 0 ] \
                && ok "runc's memfd re-exec raises no alert" \
                || bad "runc's memfd re-exec raised an alert"

            [ "$(alerts 'unbaselined exec /bin/date')" -gt 0 ] \
                && ok "an unbaselined exec pages" \
                || bad "an unbaselined exec never paged"
            [ "$(alerts 'unbaselined connect tcp 9.9.9.9:80')" -gt 0 ] \
                && ok "an unbaselined destination pages" \
                || bad "an unbaselined destination never paged"

            n=$(alerts 'unbaselined exec /bin/date')
            [ "$n" -eq 1 ] \
                && ok "ten identical execs collapse into one notification" \
                || bad "ten identical execs produced $n notifications"
        }
    }
fi

# ---------------------------------------------------------------------------
# Phase 5 -- the daemon is unaffected by clients.
# ---------------------------------------------------------------------------
if want_phase 5; then
    section 5 "clients cannot affect the daemon"
    SOCK=$WORK/quasar.sock
    boot quasar-p5 alpine sleep 300

    start_quasar --socket "$SOCK" && {
        # Headless first: no client has ever attached.
        docker exec quasar-p5 /bin/echo headless >/dev/null 2>&1
        sleep 2
        assert_some "the daemon logs with no client attached" \
            'r["source"] == "quasar-p5" and r.get("path") == "/bin/echo"'

        [ -S "$SOCK" ] && ok "the socket exists" || bad "no socket at $SOCK"
        mode=$(stat -c '%a' "$SOCK" 2>/dev/null)
        [ "$mode" = "600" ] \
            && ok "the socket is not readable by others" \
            || bad "the socket mode is $mode, wanted 600"

        # Two clients at once, both fed from the same stream. --plain because
        # asserting on a rendered screen would test the drawing, which the unit
        # tests cover, rather than the daemon property this phase is about.
        "$BIN" top --socket "$SOCK" --plain > "$WORK/client-a.out" 2>/dev/null &
        CLIENT_A=$!
        "$BIN" top --socket "$SOCK" --plain > "$WORK/client-b.out" 2>/dev/null &
        CLIENT_B=$!

        sleep 2

        docker exec quasar-p5 /bin/date >/dev/null 2>&1
        sleep 2

        # The screen needs a real terminal, which a test harness has no
        # business faking. What matters here is that it says so rather than
        # panicking out of ratatui -- the rendering itself is covered by
        # tests/tui.rs, which needs no terminal at all.
        "$BIN" top --socket "$SOCK" > "$WORK/client-tui.out" 2>&1
        grep -q 'needs a terminal' "$WORK/client-tui.out" \
            && ok "the screen explains itself with no terminal" \
            || bad "the screen did not say why it could not start"
        grep -q 'panicked' "$WORK/client-tui.out" \
            && bad "the screen panicked instead of failing cleanly" \
            || ok "the screen does not panic with no terminal"

        grep -q '/bin/date' "$WORK/client-a.out" \
            && ok "an attached client sees events" \
            || bad "the client saw nothing"
        grep -q '/bin/date' "$WORK/client-b.out" \
            && ok "a second client sees the same events" \
            || bad "the second client saw nothing"
        grep -q 'execs' "$WORK/client-a.out" \
            && ok "the client receives counter snapshots" \
            || bad "the client received no counters"

        # Without a policy loaded nothing is judged, so nothing is marked --
        # the control for the highlighting assertion in the policy run below.
        grep -q 'UNBASELINED\|DENIED' "$WORK/client-a.out" \
            && bad "events were marked with no policy loaded" \
            || ok "nothing is marked when no policy governs the container"

        # The criterion: kill a client mid-stream and the daemon does not care.
        kill -9 "$CLIENT_A" 2>/dev/null
        kill -9 "$CLIENT_B" 2>/dev/null
        wait "$CLIENT_A" "$CLIENT_B" 2>/dev/null
        sleep 1

        kill -0 "$QPID" 2>/dev/null \
            && ok "the daemon survives a client being killed" \
            || bad "the daemon died when a client was killed"

        docker exec quasar-p5 /bin/sh -c 'echo after-the-client-died' >/dev/null 2>&1
        sleep 2
        stop_quasar

        assert_some "the daemon keeps logging after every client is gone" \
            'r["source"] == "quasar-p5" and r.get("path") == "/bin/sh"'
    }

    # Highlighting needs a policy to judge against, so learn one and run again.
    POLICY=$WORK/p5-policy
    "$BIN" learn --from "$JSONL" --out "$POLICY" >/dev/null 2>&1

    start_quasar --socket "$SOCK" --policy "$POLICY" && {
        "$BIN" top --socket "$SOCK" --plain > "$WORK/client-c.out" 2>/dev/null &
        CLIENT_C=$!
        sleep 2

        # Something the first run never did, so the learned policy cannot
        # already allow it -- an allowed exec dies in the kernel and would
        # never reach the client to be marked at all.
        docker exec quasar-p5 /bin/uname -a >/dev/null 2>&1
        sleep 2
        kill -9 "$CLIENT_C" 2>/dev/null
        wait "$CLIENT_C" 2>/dev/null
        stop_quasar

        grep -q 'UNBASELINED.*exec /bin/uname' "$WORK/client-c.out" \
            && ok "an unbaselined event is marked for the client" \
            || bad "the client did not mark an unbaselined event"

        # The other half: what the policy allows is filtered in the kernel and
        # never reaches the client at all.
        grep -q 'exec /bin/date' "$WORK/client-c.out" \
            && bad "an allowed exec still reached the client" \
            || ok "an allowed exec never reaches the client"
    }
fi

# ---------------------------------------------------------------------------
# Phase 6a -- the LSM hook, reporting only.
# ---------------------------------------------------------------------------
if want_phase 6a; then
    section 6a "the LSM hook reports without preventing"

    if ! grep -q '\bbpf\b' /sys/kernel/security/lsm 2>/dev/null; then
        bad "BPF LSM is not in the active list -- add ',bpf' to lsm= and reboot"
        printf '        active: %s\n' "$(cat /sys/kernel/security/lsm 2>/dev/null)"
    else
        ok "BPF LSM is in the kernel's active list"

        boot quasar-p6 alpine sleep 300

        # A policy first, so there is something for an exec to fail to match.
        start_quasar && {
            docker exec quasar-p6 /bin/echo baseline >/dev/null 2>&1
            sleep 2
            stop_quasar
        }
        POLICY=$WORK/p6-policy
        "$BIN" learn --from "$JSONL" --out "$POLICY" >/dev/null 2>&1

        start_quasar --policy "$POLICY" --dry-run quasar-p6 && {
            # The whole point: it is reported AND it runs.
            OUT=$(docker exec quasar-p6 /bin/uname -a 2>&1)
            docker exec quasar-p6 /bin/echo baseline >/dev/null 2>&1
            sleep 2
            stop_quasar

            [ -n "$OUT" ] \
                && ok "the exec still ran -- nothing was prevented" \
                || bad "the exec produced no output; it may have been blocked"

            assert_some "an unallowed exec is reported as would-block" \
                'r["source"] == "quasar-p6" and r.get("path") == "/bin/uname" and r.get("outcome") == "would_block"'

            # The control: what the policy allows is still silent, so the hook
            # has not simply started reporting everything.
            assert_none "an allowed exec stays silent" \
                'r["source"] == "quasar-p6" and r.get("path") == "/bin/echo"'

            # One exec, one event. The tracepoint and the LSM hook both see it,
            # and reporting both would double every count and alert.
            assert_count 1 "an armed exec is reported once, not twice" \
                'r["source"] == "quasar-p6" and r.get("path") == "/bin/uname"'
        }

        # An unarmed container must report nothing about enforcement at all.
        boot quasar-p6-unarmed alpine sleep 120
        start_quasar --policy "$POLICY" --dry-run quasar-p6 && {
            docker exec quasar-p6-unarmed /bin/uname -a >/dev/null 2>&1
            sleep 2
            stop_quasar

            assert_none "an unarmed container is never reported as would-block" \
                'r["source"] == "quasar-p6-unarmed" and r.get("outcome") == "would_block"'
            assert_some "an unarmed container is still observed normally" \
                'r["source"] == "quasar-p6-unarmed" and r.get("path") == "/bin/uname"'
        }

        # The lease. Killing quasar leaves the arming in the map with an expiry
        # the kernel checks for itself, so it stops being honoured without
        # anyone cleaning up. Proving it needs the map to outlive the process,
        # which it does not -- so what is provable here is the other half: a
        # fresh daemon that arms nothing reports nothing.
        start_quasar --policy "$POLICY" && {
            docker exec quasar-p6 /bin/uname -a >/dev/null 2>&1
            sleep 2
            stop_quasar

            assert_none "arming does not survive into a daemon that did not ask for it" \
                'r.get("outcome") == "would_block"'
        }
    fi
fi

# ---------------------------------------------------------------------------

printf '\n\033[1m===================== %d passed, %d failed =====================\033[0m\n' \
    "$PASSED" "$FAILED"
[ "$FAILED" -eq 0 ]
