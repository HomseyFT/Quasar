#!/usr/bin/env bash
# Measure quasar's overhead on the deployment target.
#
#   scp scripts/soak.sh nathan1@100.77.169.69:/tmp/
#   ssh -t nathan1@100.77.169.69 'sudo bash /tmp/soak.sh --minutes 60'
#   ssh -t nathan1@100.77.169.69 'sudo bash /tmp/soak.sh --minutes 60 --policy /etc/quasar/policy'
#
# The spec's 2% budget is a cost to the *host*, and quasar's own process is only
# half of it. The probes run in the context of whatever process execs or sends,
# so their time is charged to pihole, not to quasar -- `top` on the quasar pid
# undercounts. The kernel half comes from run_time_ns, which the kernel only
# accounts for while kernel.bpf_stats_enabled is on.
#
# bpf_stats itself costs two ktime reads per program run, so on a hot probe the
# number it reports is an over-estimate. That is the right direction to be wrong
# in for a budget check.
#
# Run it twice: once with no policy (worst case, every event reaches userspace)
# and once with one (the steady state). The gap between them is the whole
# argument for or against a rate limiter.

set -uo pipefail

BIN=${BIN:-/usr/local/bin/quasar}
OUT=${OUT:-/var/tmp/quasar-soak}
MINUTES=60
INTERVAL=60
POLICY=""
JSONL=""

while [ $# -gt 0 ]; do
    case "$1" in
        --minutes)  MINUTES=$2; shift 2 ;;
        --interval) INTERVAL=$2; shift 2 ;;
        --policy)   POLICY=$2; shift 2 ;;
        --no-jsonl) JSONL=none; shift ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
done

[ "$(id -u)" -eq 0 ] || { echo "needs root" >&2; exit 1; }
command -v bpftool >/dev/null || { echo "bpftool not found" >&2; exit 1; }
[ -x "$BIN" ] || { echo "$BIN not found -- run 'make deploy' first" >&2; exit 1; }

mkdir -p "$OUT"
STAMP=$(date +%Y%m%d-%H%M%S)
TAG=$([ -n "$POLICY" ] && echo policy || echo nopolicy)
RUN=$OUT/$STAMP-$TAG
mkdir -p "$RUN"
[ "$JSONL" = none ] || JSONL=$RUN/events.jsonl
CSV=$RUN/samples.csv
LOG=$RUN/quasar.log

NCPU=$(nproc)
TICK=$(getconf CLK_TCK)
SECONDS_TOTAL=$((MINUTES * 60))

# An unfiltered run on this box writes fast: pihole alone is thousands of
# udp_sendmsg per second. Projecting from a measured rate is done below, once
# there is a rate to project from; this is just the floor.
FREE_KB=$(df -Pk "$RUN" | awk 'NR==2 {print $4}')
if [ "$JSONL" != none ] && [ "$FREE_KB" -lt 2097152 ]; then
    echo "only $((FREE_KB / 1024)) MB free on $(df -Ph "$RUN" | awk 'NR==2 {print $6}') -- use --no-jsonl" >&2
    exit 1
fi

STATS_WAS=$(cat /proc/sys/kernel/bpf_stats_enabled 2>/dev/null || echo 0)
QPID=""

cleanup() {
    [ -n "$QPID" ] && kill -INT "$QPID" 2>/dev/null && wait "$QPID" 2>/dev/null
    echo "$STATS_WAS" > /proc/sys/kernel/bpf_stats_enabled 2>/dev/null
}
trap cleanup EXIT INT TERM

echo 1 > /proc/sys/kernel/bpf_stats_enabled || {
    echo "cannot enable kernel.bpf_stats_enabled -- kernel-side cost is unmeasurable" >&2
    exit 1
}

# Sum run_cnt and run_time_ns over every quasar program. BPF program names are
# truncated to 15 characters in the kernel, so match on the prefix, not on the
# full name from the source.
bpf_totals() {
    bpftool prog show 2>/dev/null | awk '
        /name quasar_/ {
            for (i = 1; i < NF; i++) {
                if ($i == "run_time_ns") ns  += $(i+1)
                if ($i == "run_cnt")     cnt += $(i+1)
            }
        }
        END { printf "%d %d\n", cnt + 0, ns + 0 }'
}

proc_cpu() { awk '{print $14 + $15}' "/proc/$1/stat" 2>/dev/null || echo 0; }
proc_rss() { awk '/^VmRSS:/ {print $2}' "/proc/$1/status" 2>/dev/null || echo 0; }
lines()    { if [ "$JSONL" = none ]; then echo 0; else wc -l < "$JSONL" 2>/dev/null || echo 0; fi; }

ARGS=(run --quiet)
[ "$JSONL" = none ] || ARGS+=(--jsonl "$JSONL")
[ -z "$POLICY" ]    || ARGS+=(--policy "$POLICY")

echo "== quasar overhead soak =="
echo "   binary     $BIN"
echo "   policy     ${POLICY:-none (worst case: every event reaches userspace)}"
echo "   duration   $MINUTES min, sampling every ${INTERVAL}s"
echo "   output     $RUN"
echo "   cpus       $NCPU"
echo

"$BIN" "${ARGS[@]}" > "$LOG" 2>&1 &
QPID=$!
sleep 5
kill -0 "$QPID" 2>/dev/null || { echo "quasar died at startup:"; cat "$LOG"; exit 1; }
sed -n '1,20p' "$LOG" | sed 's/^/   /'
echo

read -r PREV_CNT PREV_NS <<< "$(bpf_totals)"
PREV_CPU=$(proc_cpu "$QPID")
PREV_LINES=$(lines)
PREV_WALL=$(date +%s%N)
START_WALL=$PREV_WALL
START_CNT=$PREV_CNT
START_NS=$PREV_NS
START_LINES=$PREV_LINES

echo "elapsed_s,quasar_cpu_pct_host,probe_cpu_pct_host,total_pct_host,rss_kb,events_per_s,probe_runs_per_s,ns_per_run" > "$CSV"

MAX_RSS=0
ELAPSED=0
while [ "$ELAPSED" -lt "$SECONDS_TOTAL" ]; do
    sleep "$INTERVAL"
    kill -0 "$QPID" 2>/dev/null || { echo "quasar exited early:"; tail -20 "$LOG"; break; }

    NOW_WALL=$(date +%s%N)
    read -r NOW_CNT NOW_NS <<< "$(bpf_totals)"
    NOW_CPU=$(proc_cpu "$QPID")
    NOW_LINES=$(lines)
    RSS=$(proc_rss "$QPID")
    [ "$RSS" -gt "$MAX_RSS" ] && MAX_RSS=$RSS

    ELAPSED=$(( (NOW_WALL - START_WALL) / 1000000000 ))
    awk -v w="$(( NOW_WALL - PREV_WALL ))" -v ncpu="$NCPU" -v tick="$TICK" \
        -v dcpu="$(( NOW_CPU - PREV_CPU ))" -v dns="$(( NOW_NS - PREV_NS ))" \
        -v dcnt="$(( NOW_CNT - PREV_CNT ))" -v dl="$(( NOW_LINES - PREV_LINES ))" \
        -v rss="$RSS" -v el="$ELAPSED" '
        BEGIN {
            secs = w / 1e9
            user = (dcpu / tick) / secs * 100 / ncpu
            kern = (dns / 1e9)  / secs * 100 / ncpu
            printf "%d,%.3f,%.3f,%.3f,%d,%.1f,%.1f,%.0f\n",
                el, user, kern, user + kern, rss, dl / secs, dcnt / secs,
                (dcnt > 0 ? dns / dcnt : 0)
        }' | tee -a "$CSV" | awk -F, '{
            printf "   %5ss  quasar %5.2f%%  probes %5.2f%%  total %5.2f%%  rss %5dMB  %8.1f ev/s  %8.1f runs/s\n",
                $1, $2, $3, $4, $5 / 1024, $6, $7
        }'

    PREV_WALL=$NOW_WALL; PREV_CPU=$NOW_CPU; PREV_LINES=$NOW_LINES
    PREV_CNT=$NOW_CNT;   PREV_NS=$NOW_NS
done

TOTAL_CPU=$(proc_cpu "$QPID")
END_WALL=$(date +%s%N)
read -r END_CNT END_NS <<< "$(bpf_totals)"
END_LINES=$(lines)

kill -INT "$QPID" 2>/dev/null
wait "$QPID" 2>/dev/null
QPID=""

echo
echo "===================== RESULTS ====================="
awk -v w="$(( END_WALL - START_WALL ))" -v ncpu="$NCPU" -v tick="$TICK" \
    -v cpu="$TOTAL_CPU" -v dns="$(( END_NS - START_NS ))" \
    -v dcnt="$(( END_CNT - START_CNT ))" -v dl="$(( END_LINES - START_LINES ))" -v rss="$MAX_RSS" '
    BEGIN {
        secs = w / 1e9
        user = (cpu / tick) / secs * 100 / ncpu
        kern = (dns / 1e9)  / secs * 100 / ncpu
        printf "\n  window            %.1f min over %d cpus\n", secs / 60, ncpu
        printf "  probe runs        %d  (%.1f/s, %.0f ns each)\n", dcnt, dcnt / secs, (dcnt > 0 ? dns / dcnt : 0)
        printf "  events surfaced   %d  (%.1f/s)\n", dl, dl / secs
        printf "  peak rss          %.1f MB\n", rss / 1024
        printf "\n  quasar userspace  %.3f%% of the host\n", user
        printf "  probes in-kernel  %.3f%% of the host  (charged to the traced process, not to quasar)\n", kern
        printf "  ------------------------------\n"
        printf "  total             %.3f%% of the host   %s the 2%% budget\n", user + kern,
            (user + kern < 2 ? "UNDER" : "OVER")
    }'

echo
echo "  --- drop accounting (a full ring buffer means the numbers above are floors) ---"
grep -E 'dropped' "$LOG" | sed 's/^/  /' || echo "  no losses reported"

[ "$JSONL" = none ] || {
    echo
    echo "  --- busiest sources ---"
    awk -F'"source":"' 'NF>1 {split($2, a, "\""); print a[1]}' "$JSONL" | sort | uniq -c | sort -rn | head -10 | sed 's/^/  /'
    echo
    echo "  log: $JSONL ($(du -h "$JSONL" | cut -f1)) -- feed it to 'quasar learn --from'"
}
echo "  samples: $CSV"
