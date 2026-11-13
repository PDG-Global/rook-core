#!/bin/sh
# soak.sh — 24-hour stability soak for a running rookd (plan §10).
#
# A soak that ends in a human eyeballing a graph is a story, not a test.
# This script encodes its pass criteria so the verdict reproduces from the
# log without whoever watched it:
#
#   * Load CYCLES: ~55 minutes on, 5 minutes fully idle, hourly. "Connections
#     return to baseline when load stops" is then tested 24 times, not once —
#     a leak that only frees on the first quiesce is visible in cycle 2.
#   * Sampled every 60s: rook's own memory gauge (primary RSS — `ps` includes
#     shared pages rook does not control, and is corroboration only), fd count,
#     active connections, upstream latency histogram, strike counters.
#   * Verdict: least-squares slope per hour over the post-warmup samples for
#     RSS and fds; FAIL if either exceeds 1% of its post-warmup baseline per
#     hour. The slope is printed with the verdict.
#   * Every 30 minutes an adversarial burst runs (tools/soak_burst.py):
#     an HTTP/2 rapid-reset burst and a CONTINUATION flood. A burst is INVALID
#     unless h2 was actually negotiated (no ALPN, no test). The refusal kind is
#     recorded — GOAWAY(ENHANCE_YOUR_CALM) and a bare close are different
#     answers, and a change between runs is a behaviour change — along with the
#     RSS delta across the burst and the seconds until normal throughput
#     recovers. On-box bursts are labelled path=on-box and count as LIMITER
#     coverage: from 127.0.0.1 the per-IP rate/connection limits answer before
#     hyper's rapid-reset classifier does, so the classification evidence
#     (GOAWAY vs close) comes from the remote phase, not from this script.
#
# The load generator runs on the same box as rookd by design. That would
# poison a benchmark (the generator competes for CPU); a soak watches rook's
# own state drift, not its speed, and an on-box generator keeps a 24-hour run
# independent of anyone's laptop staying awake.
#
# FreeBSD: pkg install nghttp2 python3 && python3 -m pip install "h2==4.4.1"
# Usage: soak.sh --host smoke.rookserver.app --metrics http://127.0.0.1:9188/metrics \
#          [--hours 24] [--work /home/rooksmoke/soak]
set -eu

HOST=""
METRICS=""
HOURS=24
WORK=""
WARMUP_MIN=${SOAK_WARMUP_MIN:-60}   # samples before this minute are excluded from the slope
SLOPE_FAIL_PCT=1       # FAIL if RSS or fds grow faster than this % of baseline per hour
IDLE_SECONDS=${SOAK_IDLE_SECONDS:-300} # tail of every cycle with all load stopped
CYCLE_SECONDS=${SOAK_CYCLE_SECONDS:-3600}   # one load+idle cycle
BURST_INTERVAL=${SOAK_BURST_INTERVAL:-1800} # seconds between burst pairs
# The SOAK_* overrides exist for dry-runs: a 24-hour script whose
# mechanics have never run breaks at hour 23. A 20-minute dry run with
# SOAK_CYCLE_SECONDS=300 SOAK_BURST_INTERVAL=240 SOAK_WARMUP_MIN=5
# exercises every path before the real run.

while [ $# -gt 0 ]; do
    case "$1" in
        --host) HOST=$2; shift 2 ;;
        --metrics) METRICS=$2; shift 2 ;;
        --hours) HOURS=$2; shift 2 ;;
        --work) WORK=$2; shift 2 ;;
        -h|--help) sed -n '2,32p' "$0"; exit 0 ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
done
[ -n "$HOST" ] && [ -n "$METRICS" ] || { echo "need --host and --metrics" >&2; exit 2; }
[ -n "$WORK" ] || WORK=$(mktemp -d "${TMPDIR:-/tmp}/soak.XXXXXX")
mkdir -p "$WORK"
for bin in curl h2load python3; do
    command -v "$bin" >/dev/null 2>&1 || {
        echo "need $bin (FreeBSD: pkg install nghttp2 python3 && python3 -m pip install 'h2==4.4.1')" >&2
        exit 2
    }
done
python3 -c 'import h2; assert h2.__version__ == "4.4.1", h2.__version__' 2>/dev/null || {
    echo "need python module h2==4.4.1 (python3 -m pip install 'h2==4.4.1')" >&2
    echo "the pin keeps the soak and gen-01 runs on the library the record names" >&2
    exit 2
}
HERE=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)

LOG="$WORK/soak.log"          # one line per event, timestamped
SAMPLES="$WORK/samples.csv"   # ts,gauge_rss,ps_rss,fds,active_conns
BURSTS="$WORK/bursts.log"     # one line per burst with its evidence
: > "$LOG"; : > "$SAMPLES"; : > "$BURSTS"

say() { printf '%s %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*" | tee -a "$LOG"; }

LOAD_PIDS=""
stop_load() {
    for pid in $LOAD_PIDS; do kill "$pid" 2>/dev/null || true; done
    LOAD_PIDS=""
    TRAP_PID=""   # cleared: a stale pid could name a reused process later
    wait 2>/dev/null || true
}
cleanup() { stop_load; }
trap cleanup EXIT INT TERM

# --- load -------------------------------------------------------------------
# HTTP/1.1 keep-alive: one curl process chains requests on one connection.
start_h1() {
    while :; do
        i=0
        urls=""
        while [ $i -lt 50 ]; do
            # -o is per-URL in curl: without one per URL, every body but
            # the first lands on stdout.
            urls="$urls -o /dev/null --resolve $HOST:443:127.0.0.1 https://$HOST/"
            i=$((i + 1))
        done
        # shellcheck disable=SC2086
        curl -s -o /dev/null $urls || true
    done &
    LOAD_PIDS="$LOAD_PIDS $!"
}

# HTTP/2: h2load at a fixed rate against the TLS listener.
start_h2() {
    h2load --resolve "$HOST:443:127.0.0.1" -r20 -D 3600 -c4 -m8 \
        "https://$HOST/" >/dev/null 2>&1 &
    LOAD_PIDS="$LOAD_PIDS $!"
    h2load --resolve "$HOST:443:127.0.0.1" -r20 -D 3600 -c4 -m8 \
        "https://$HOST/" >/dev/null 2>&1 &
    LOAD_PIDS="$LOAD_PIDS $!"
}

# WebSocket: long-lived tunnels through the proxy, echoing every few seconds;
# rook's websocket_max_lifetime forces clean rotation.
start_ws() {
    i=0
    while [ $i -lt 10 ]; do
        python3 "$HERE/soak_ws.py" --host "$HOST" --port 443 --path /ws \
            --interval 5 --duration 3600 >>"$WORK/ws.log" 2>&1 &
        LOAD_PIDS="$LOAD_PIDS $!"
        i=$((i + 1))
    done
}

# Strike exercise: a slow trickle of trap-path hits keeps the strike path warm
# without tripping the ban threshold in any window. Tracked separately so a
# burst can pause it: a trickle 404 lands in the same 4xx bucket the burst's
# server-side delta reads, and the delta must be zero-or-burst-sized.
TRAP_PID=""
start_traps() {
    while :; do
        curl -s -o /dev/null --resolve "$HOST:443:127.0.0.1" \
            "https://$HOST/wp-admin" || true
        sleep 90
    done &
    TRAP_PID=$!
    LOAD_PIDS="$LOAD_PIDS $TRAP_PID"
}

stop_traps() {
    [ -n "$TRAP_PID" ] && kill "$TRAP_PID" 2>/dev/null || true
    TRAP_PID=""
}

start_load() {
    start_h1; start_h2; start_ws; start_traps
}

# --- sampling ---------------------------------------------------------------
sample() {
    ts=$(date -u +%s)
    rookd_pid=$(pgrep rookd | head -1)
    gauge=$(curl -s --max-time 5 "$METRICS" \
        | awk '/^rook_process_resident_memory_bytes/ {print $2}' || true)
    ps_rss=$(ps -o rss= -p "$rookd_pid" 2>/dev/null | awk '{s+=$1} END {print s*1024}' || true)
    fds=$(procstat -f "$rookd_pid" 2>/dev/null | tail -n +3 | wc -l | tr -d ' ' || true)
    conns=$(curl -s --max-time 5 "$METRICS" \
        | awk '/^rook_connections_active/ {s+=$2} END {print s+0}' || true)
    printf '%s,%s,%s,%s,%s\n' "$ts" "${gauge:-0}" "${ps_rss:-0}" "${fds:-0}" "${conns:-0}" \
        >> "$SAMPLES"
}

# --- bursts -----------------------------------------------------------------
# Server-side response codes, not client-observed ones: a rapid-reset client
# RSTs before reading, so codes it saw are weak evidence. The 4xx counter
# delta across the burst is what the server actually answered — and it settled
# the loopback question: delta 0 on both paths, so hyper closes the connection
# and rook's limiter never fires (measured 2026-11-12 against rook-test-01).
responses_4xx() {
    curl -s --max-time 5 "$METRICS" \
        | awk '/^rook_responses_total\{class="4xx"\}/ {print $2}'
}

# An empty read must never silently become 0: "server_4xx_delta=0" reads
# as "the limiter never fired", and an empty rss_before reads as a jump
# from nothing. Any missing input makes the field INVALID, and the
# verdict treats an INVALID burst line as a failure.
run_burst() { # mode
    mode=$1
    say "burst start: $mode"
    # Pause the trap trickle and let any in-flight hit land BEFORE the
    # first counter read, so the delta across the burst is the burst's
    # alone.
    stop_traps
    sleep 2
    rss_before=$(awk -F, 'END {print $2}' "$SAMPLES")
    r4_before=$(responses_4xx)
    out=$(python3 "$HERE/soak_burst.py" --host "$HOST" --port 443 --mode "$mode" 2>&1) || true
    r4_after=$(responses_4xx)
    start_traps
    if [ -n "$r4_before" ] && [ -n "$r4_after" ]; then
        delta=$(( r4_after - r4_before ))
    else
        delta=INVALID
    fi
    rss_before=${rss_before:-INVALID}
    echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) path=on-box $mode $out server_4xx_delta=$delta rss_before=$rss_before" >> "$BURSTS"
    say "burst done: $mode $out server_4xx_delta=$delta"
    # Recovery probe: seconds until a normal request succeeds again,
    # capped at 60s. A server that survives the burst but takes a minute
    # to answer ordinary traffic has still been hurt.
    t0=$(date -u +%s)
    while :; do
        code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 2 \
            --resolve "$HOST:443:127.0.0.1" "https://$HOST/" || echo 000)
        [ "$code" = "200" ] && break
        now=$(date -u +%s); [ $((now - t0)) -gt 60 ] && break
        sleep 1
    done
    recovery=$(( $(date -u +%s) - t0 ))
    sleep 5
    sample
    rss_after=$(awk -F, 'END {print $2}' "$SAMPLES")
    echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) path=on-box $mode recovery_seconds=$recovery rss_before=$rss_before rss_after=${rss_after:-INVALID}" \
        >> "$BURSTS"
    say "burst recovery: $mode ${recovery}s rss $rss_before -> ${rss_after:-INVALID}"
}

# --- main loop --------------------------------------------------------------
say "soak starting: host=$HOST hours=$HOURS work=$WORK"
say "criteria: post-warmup (${WARMUP_MIN}m) RSS+fd slope < ${SLOPE_FAIL_PCT}%/hr of baseline; bursts valid + recover"
# Some soak properties are inherited from dependencies (the rapid-reset
# classification is hyper/h2's, not rook's), so the run records what it
# measured: a dependency bump that changes the behaviour shows up as a
# diff between run headers, not as a surprise in production.
LOCKFILE=${LOCKFILE:-$HOME/rook-core/Cargo.lock}
if [ -f "$LOCKFILE" ]; then
    hyper_v=$(awk '/^name = "hyper"$/{getline; print $3; exit}' "$LOCKFILE" | tr -d '"')
    h2_v=$(awk '/^name = "h2"$/{getline; print $3; exit}' "$LOCKFILE" | tr -d '"')
    say "dependency versions from $LOCKFILE: hyper=${hyper_v:-unknown} h2=${h2_v:-unknown}"
else
    say "no Cargo.lock at $LOCKFILE; dependency versions unrecorded"
fi

end=$(( $(date -u +%s) + ${SOAK_TOTAL_SECONDS:-$((HOURS * 3600))} ))
next_burst=$(( $(date -u +%s) + BURST_INTERVAL ))
cycle=0
while [ "$(date -u +%s)" -lt "$end" ]; do
    cycle=$((cycle + 1))
    say "cycle $cycle: load on"
    start_load
    cycle_end=$(( $(date -u +%s) + CYCLE_SECONDS - IDLE_SECONDS ))
    while [ "$(date -u +%s)" -lt "$cycle_end" ] && [ "$(date -u +%s)" -lt "$end" ]; do
        sample
        if [ "$(date -u +%s)" -ge "$next_burst" ]; then
            run_burst rapid-reset
            run_burst continuation
            next_burst=$(( $(date -u +%s) + BURST_INTERVAL ))
        fi
        sleep 60 &
        wait $! 2>/dev/null || true
    done
    say "cycle $cycle: idle ${IDLE_SECONDS}s"
    stop_load
    # The idle window is itself the experiment: sample through it so the
    # verdict sees whether connections/fds return to baseline every hour.
    idle_end=$(( $(date -u +%s) + IDLE_SECONDS ))
    while [ "$(date -u +%s)" -lt "$idle_end" ]; do
        sample
        sleep 60 &
        wait $! 2>/dev/null || true
    done
    conns=$(awk -F, 'END {print $5}' "$SAMPLES")
    say "cycle $cycle: idle done, active connections at end of idle: ${conns:-?}"
done
stop_load

say "soak complete; computing verdict"
python3 "$HERE/soak_verdict.py" --samples "$SAMPLES" --bursts "$BURSTS" \
    --warmup-min "$WARMUP_MIN" --slope-fail-pct "$SLOPE_FAIL_PCT" | tee -a "$LOG"
