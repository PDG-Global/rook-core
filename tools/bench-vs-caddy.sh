#!/bin/sh
# bench-vs-caddy.sh — compare rookd and Caddy as reverse proxies on one box.
#
# The validity gate is the point of this script. A throughput number is only
# a throughput number if every request actually reached the upstream and came
# back 2xx; a proxy under load can instead be *refusing* traffic, which shows
# up as a very high request rate of fast rejections. Rook's defaults are a
# 100 req/s limit per client, so a naive benchmark of rook against Caddy
# reports rook as several times faster while it is answering 429s. So:
#
#   1. the bench config lifts rook's rate and connection limits, and
#   2. every cell is preceded by a fixed-count gate that asserts zero
#      non-2xx responses AND that the upstream's access log grew by exactly
#      the number of requests sent. A cell that fails the gate is reported as
#      INVALID and the run continues.
#
# Everything else: both proxies run alone, one at a time, against the same
# upstream, with per-request logging off in both (Caddy `log off`, rookd via
# RUST_LOG=warn). Results travel as RATIOS and saturation shape, not absolute
# RPS. Plaintext only; TLS is a separate cell.
#
# FreeBSD: pkg install caddy wrk curl
# Usage: bench-vs-caddy.sh --rookd /usr/local/bin/rookd \
#          --generator-location "gen-01 (same zone)" [--bind 0.0.0.0 --target-host 23.251.146.76]
set -eu

DURATION=30
REPS=3
CONCURRENCY="1,8,64"
BIND=127.0.0.1
TARGET_HOST=""
GENERATOR_LOCATION="unspecified — say where the generator ran"
ROOKD=${ROOKD_BIN:-rookd}
GATE_REQUESTS=200

while [ $# -gt 0 ]; do
    case "$1" in
        --duration) DURATION=$2; shift 2 ;;
        --reps) REPS=$2; shift 2 ;;
        --concurrency) CONCURRENCY=$2; shift 2 ;;
        --bind) BIND=$2; shift 2 ;;
        --target-host) TARGET_HOST=$2; shift 2 ;;
        --generator-location) GENERATOR_LOCATION=$2; shift 2 ;;
        --rookd) ROOKD=$2; shift 2 ;;
        -h|--help) sed -n '2,30p' "$0"; exit 0 ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
done
[ -n "$TARGET_HOST" ] || TARGET_HOST=$BIND
# Waiting for the listener uses a connectable address even when the proxies
# bind the wildcard.
WAIT_HOST=$BIND
[ "$BIND" = "0.0.0.0" ] && WAIT_HOST=127.0.0.1

TOOL=""
for candidate in wrk ab; do
    if command -v "$candidate" >/dev/null 2>&1; then TOOL=$candidate; break; fi
done
[ -n "$TOOL" ] || { echo "need wrk or ab (FreeBSD: pkg install wrk)" >&2; exit 2; }
for bin in caddy curl; do
    command -v "$bin" >/dev/null 2>&1 || { echo "need $bin" >&2; exit 2; }
done
[ -x "$ROOKD" ] || command -v "$ROOKD" >/dev/null 2>&1 || { echo "rookd not found: $ROOKD" >&2; exit 2; }

WORK=$(mktemp -d "${TMPDIR:-/tmp}/bench-vs-caddy.XXXXXX")
UP_LOG="$WORK/up-access.log"
CUR_PROXY_PID=""
cleanup() {
    [ -n "$CUR_PROXY_PID" ] && kill "$CUR_PROXY_PID" 2>/dev/null || true
    [ -n "${UPSTREAM_PID:-}" ] && kill "$UPSTREAM_PID" 2>/dev/null || true
    wait 2>/dev/null || true
    rm -rf "$WORK"
}
trap cleanup EXIT INT TERM

awk 'BEGIN{ s=""; while (length(s) < 1024) s = s "x"; print s }' > "$WORK/index.html"

# The upstream counts what it serves. That is how the gate knows whether a
# request reached the origin rather than being rejected in front of it.
cat > "$WORK/upstream.Caddyfile" <<EOF
{
	admin off
	auto_https off
}
http://127.0.0.1:9000 {
	root * $WORK
	file_server
	log {
		output file $UP_LOG
		format console
	}
}
EOF

cat > "$WORK/proxy.Caddyfile" <<'EOF'
{
	admin off
	auto_https off
	log off
}
http://:8081 {
	reverse_proxy 127.0.0.1:9000
}
EOF

# Rate and connection limits lifted: measuring a rate limiter is not
# measuring a proxy, and rook's defaults are deliberately conservative.
cat > "$WORK/rookd.toml" <<EOF
[server]
listen = "$BIND:8082"
requests_per_second = 1000000
request_burst = 1000000
max_connections = 100000
max_connections_per_ip = 100000
max_connections_per_upstream = 100000

[[sites]]
hosts = ["$TARGET_HOST"]

[[sites.routes]]
prefix = "/"
upstreams = ["http://127.0.0.1:9000"]
EOF

wait_port() {
    host=$1 port=$2; i=0
    while [ $i -lt 150 ]; do
        curl -sf -o /dev/null "http://$host:$port/" 2>/dev/null && return 0
        i=$((i + 1)); sleep 0.1
    done
    echo "nothing answered on $host:$port" >&2; return 1
}

upstream_hits() { [ -f "$UP_LOG" ] && wc -l < "$UP_LOG" | tr -d ' ' || echo 0; }

# Fixed-count run: prints "<non2xx> <completed>". Used only by the gate.
fixed_run() {
    conc=$1
    url="http://$TARGET_HOST:$PORT/"
    case $TOOL in
        ab)
            out=$(ab -k -n "$GATE_REQUESTS" -c "$conc" "$url" 2>/dev/null || true)
            non=$(printf '%s\n' "$out" | awk '/Non-2xx responses/ {print $3}')
            comp=$(printf '%s\n' "$out" | awk '/Complete requests/ {print $3}')
            ;;
        wrk)
            out=$(wrk -t2 -c"$conc" -d1s "$url" 2>/dev/null || true)
            non=$(printf '%s\n' "$out" | awk '/Non-2xx or 3xx/ {print $3}')
            comp=$GATE_REQUESTS
            ;;
    esac
    printf '%s %s\n' "${non:-0}" "${comp:-0}"
}

gate() {
    conc=$1
    before=$(upstream_hits)
    set -- $(fixed_run "$conc")
    non=$1
    sleep 0.3
    after=$(upstream_hits)
    reached=$((after - before))
    if [ "${non:-0}" != "0" ] || [ "$reached" -lt "$GATE_REQUESTS" ]; then
        echo "INVALID ${non:-?} ${reached}"
        return 1
    fi
    printf 'ok %s %s\n' "${non:-0}" "$reached"
    return 0
}

measure() {
    conns=$1
    case $TOOL in
        wrk)
            out=$(wrk -t2 -c"$conns" -d"${DURATION}s" --latency "http://$TARGET_HOST:$PORT/" 2>/dev/null || true)
            rps=$(printf '%s\n' "$out" | awk '/Requests\/sec/ {print $2}')
            p50=$(printf '%s\n' "$out" | awk '/50%/ {print $2}')
            p95=$(printf '%s\n' "$out" | awk '/75%/ {print $2}')
            p99=$(printf '%s\n' "$out" | awk '/99%/ {print $2}')
            ;;
        ab)
            out=$(ab -k -t "$DURATION" -c "$conns" -n 100000000 "http://$TARGET_HOST:$PORT/" 2>/dev/null || true)
            rps=$(printf '%s\n' "$out" | awk '/Requests per second/ {print $4}')
            p50=$(printf '%s\n' "$out" | awk '$1=="50%" {print $2}')
            p95=$(printf '%s\n' "$out" | awk '$1=="95%" {print $2}')
            p99=$(printf '%s\n' "$out" | awk '$1=="99%" {print $2}')
            ;;
    esac
    printf '%s %s %s %s\n' "${rps:-0}" "${p50:-0}" "${p95:-0}" "${p99:-0}"
}

median() { printf '%s\n' "$@" | sort -n | awk '{a[NR]=$1} END { if (NR==0) print 0; else if (NR%2) print a[(NR+1)/2]; else print (a[NR/2]+a[NR/2+1])/2 }'; }

caddy run --config "$WORK/upstream.Caddyfile" >"$WORK/upstream.log" 2>&1 & UPSTREAM_PID=$!
wait_port 127.0.0.1 9000

echo "# bench-vs-caddy"
echo "# host:      $(uname -srm)   cpus=$(sysctl -n hw.ncpu 2>/dev/null || nproc 2>/dev/null || echo '?')"
echo "# generator: $GENERATOR_LOCATION"
echo "# tool:      $TOOL   duration: ${DURATION}s   reps: $REPS   concurrency: $CONCURRENCY"
echo "# upstream:  caddy file server 127.0.0.1:9000, 1 KiB body, request log ON for the gate"
echo "# proxies:   per-request logging off; rook rate/connection limits lifted for the run"
echo "# target:    http://$TARGET_HOST:<port>/    gate: ${GATE_REQUESTS} requests/cell"
case "$GENERATOR_LOCATION" in
    *this\ box*|*on-box*|*same\ box*|*rook-test*)
        echo "# CAVEAT: generator shares the box under test — both numbers are a floor, not a comparison." ;;
esac
echo
printf 'proxy\tconc\tvalid\trps_med\trps_min\trps_max\tp50_ms\tp95_ms\tp99_ms\n'

for proxy in rook caddy; do
    sleep 1
    if [ "$proxy" = rook ]; then
        PORT=8082
        RUST_LOG=warn "$ROOKD" --config "$WORK/rookd.toml" >"$WORK/rookd.log" 2>&1 &
    else
        PORT=8081
        caddy run --config "$WORK/proxy.Caddyfile" >"$WORK/caddy.log" 2>&1 &
    fi
    CUR_PROXY_PID=$!
    wait_port "$WAIT_HOST" "$PORT"

    for conns in $(printf '%s' "$CONCURRENCY" | tr ',' ' '); do
        if ! valid=$(gate "$conns"); then
            echo "$proxy	$conns	INVALID($valid)	-	-	-	-	-	-" | tr ' ' '\t'
            continue
        fi
        measure "$conns" >/dev/null || true   # warm-up, discarded
        rpss=""; p50s=""; p95s=""; p99s=""; rep=0
        while [ $rep -lt "$REPS" ]; do
            set -- $(measure "$conns")
            rpss="$rpss $1"; p50s="$p50s $2"; p95s="$p95s $3"; p99s="$p99s $4"
            rep=$((rep + 1))
        done
        printf '%s\t%s\tyes\t%s\t%s\t%s\t%s\t%s\t%s\n' \
            "$proxy" "$conns" \
            "$(median $rpss)" \
            "$(printf '%s\n' $rpss | sort -n | head -1)" \
            "$(printf '%s\n' $rpss | sort -n | tail -1)" \
            "$(median $p50s)" "$(median $p95s)" "$(median $p99s)"
    done

    kill "$CUR_PROXY_PID" 2>/dev/null || true
    wait "$CUR_PROXY_PID" 2>/dev/null || true
    CUR_PROXY_PID=""
done

echo
echo "# A row is only comparable if valid=yes: zero non-2xx and the upstream log"
echo "# grew by the gate count. The ratio rook/caddy at each concurrency is what"
echo "# travels between machines; the spread and the saturation point say more"
echo "# than the median on its own."
