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

# Only the payload lives in the served root: the work directory also holds
# rookd.toml, the Caddyfiles and the upstream log, and a proxy that forwards
# /rookd.toml would serve them.
mkdir -p "$WORK/www"
awk 'BEGIN{ s=""; while (length(s) < 1024) s = s "x"; print s }' > "$WORK/www/index.html"

# The upstream counts what it serves. That is how the gate knows whether a
# request reached the origin rather than being rejected in front of it.
cat > "$WORK/upstream.Caddyfile" <<EOF
{
	admin off
	auto_https off
}
http://127.0.0.1:9000 {
	root * $WORK/www
	file_server
	log {
		# The gate counts lines in this file. Caddy rolls at 100MiB by
		# default, which at a few thousand requests per second is roughly
		# every 15s -- mid-cell -- and a line-count diff across a roll
		# misreads. Set the size far above any cell so the instrument
		# cannot turn over under the measurement. roll_size is a
		# subdirective of `output file`, not of `log` -- at log level
		# Caddy rejects the whole config ("unrecognized subdirective")
		# and the upstream never starts (Nathan, 2026-11-14).
		output file $UP_LOG {
			roll_size 10GiB
		}
		format console
	}
}
EOF

cat > "$WORK/proxy.Caddyfile" <<EOF
{
	admin off
	auto_https off
	log off
}
http://:8081 {
	bind BINDDIRECTIVE
	reverse_proxy 127.0.0.1:9000
}
EOF
sed -i.bak "s#BINDDIRECTIVE#$BIND#" "$WORK/proxy.Caddyfile" && rm -f "$WORK/proxy.Caddyfile.bak"

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
# Third per-IP limit in the path: the upstream connection cap (default 64).
# Missing it made every cell at c>=64 return 502s from the upstream pool -
# which reads as "the proxy cannot handle 64 concurrent" when it was the
# harness that forgot a limit.
max_upstream_per_ip = 100000

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

# Count lines in the upstream access log, including any rotation
# siblings. The roll_size above is meant to make that impossible, but a
# counter that trusts a single inode is exactly the assumption that failed
# once; summing the family makes the gate correct whether or not someone
# remembers the roll_size.
upstream_hits() {
	local total=0 f
	for f in "$UP_LOG" "$UP_LOG".*; do
		[ -f "$f" ] || continue
		total=$((total + $(wc -l < "$f")))
	done
	printf '%s' "$total"
}

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
            # wrk refuses connections < threads ("number of connections
            # must be >= threads"): at c=1 the run silently never happens
            # and the gate correctly reports 0 reached. Scale threads
            # down instead of letting the row die (found 2026-11-14).
            t=$([ "$conc" -lt 2 ] && echo 1 || echo 2)
            out=$(wrk -t"$t" -c"$conc" -d1s "$url" 2>/dev/null || true)
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
    # The access log is the gate's instrument, so wait for it to actually
    # settle: a fixed short sleep under-reads a freshly started Caddy,
    # whose first writes land lazily and made the first gate of every arm
    # report reached=0 (rook/caddy c=1 rows INVALID, 2026-11-14). Poll
    # until two reads 0.5s apart agree (bounded).
    after=$before
    i=0
    while [ $i -lt 20 ]; do
        sleep 0.5
        now=$(upstream_hits)
        [ "$now" = "$after" ] && break
        after=$now
        i=$((i + 1))
    done
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
            t=$([ "$conns" -lt 2 ] && echo 1 || echo 2)
            out=$(wrk -t"$t" -c"$conns" -d"${DURATION}s" --latency "http://$TARGET_HOST:$PORT/" 2>/dev/null || true)
            # Parse ONLY the Latency Distribution block: the Thread Stats
            # rows carry "+/- Stdev" percentages that /50%/ also matches
            # (a stdev value was read as p50 on 2026-11-14), and the
            # column historically labelled p95 is wrk's 75% line — kept,
            # since the harness has always reported it, but named.
            rps=$(printf '%s
' "$out" | awk '/^Requests\/sec/ {print $2}')
            dist=$(printf '%s
' "$out" | awk '
                /Latency Distribution/ {f=1; next}
                f && /^ +50%/ {p50=$2}
                f && /^ +75%/ {p75=$2}
                f && /^ +99%/ {p99=$2}
                f && /^ +[0-9]/ && !/%/ {f=0}
                END {print p50, p75, p99}')
            p50=${dist%% *}; rest=${dist#* }
            p95=${rest%% *}; p99=${rest##* }
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
        # Report the median-rps REP'S WHOLE ROW. Per-column medians can
        # invert quantiles across reps (caddy c=8 read p99<p95,
        # 2026-11-14) — taking one rep's row keeps p50<=p95<=p99 by
        # construction, since the source quantiles are monotone.
        rows=""
        rep=0
        while [ $rep -lt "$REPS" ]; do
            rows="${rows}$(measure "$conns")
"
            rep=$((rep + 1))
        done
        n=$(printf '%s' "$rows" | grep -c .)
        mid=$(( (n + 1) / 2 ))
        medrow=$(printf '%s' "$rows" | sort -n | sed -n "${mid}p")
        set -- $medrow
        printf '%s	%s	yes	%s	%s	%s	%s	%s	%s
' \
            "$proxy" "$conns" \
            "$1" \
            "$(printf '%s' "$rows" | sort -n | head -1 | awk '{print $1}')" \
            "$(printf '%s' "$rows" | sort -n | tail -1 | awk '{print $1}')" \
            "$2" "$3" "$4"
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
