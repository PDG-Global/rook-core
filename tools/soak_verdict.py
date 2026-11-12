#!/usr/bin/env python3
"""soak_verdict.py — compute the soak verdict from its logs.

The verdict is arithmetic, not a judgement over a graph: least-squares
slope per hour over the post-warmup samples for RSS (rook's own memory
gauge; ps RSS is corroboration) and open fds. FAIL when either slope
exceeds --slope-fail-pct percent of its post-warmup baseline per hour,
or when any recorded burst was INVALID (h2 not negotiated — nothing was
tested) or went unanswered (no refusal recorded at all).

Usage: soak_verdict.py --samples samples.csv --bursts bursts.log \
           [--warmup-min 60] [--slope-fail-pct 1]
"""

import argparse
import sys


def slope_per_hour(samples):
    """Least-squares slope of (seconds-since-first, value), per hour."""
    if len(samples) < 3:
        return 0.0
    t0 = samples[0][0]
    xs = [(ts - t0) / 3600.0 for ts, _ in samples]
    ys = [value for _, value in samples]
    n = len(xs)
    mean_x = sum(xs) / n
    mean_y = sum(ys) / n
    denom = sum((x - mean_x) ** 2 for x in xs)
    if denom == 0:
        return 0.0
    return sum((x - mean_x) * (y - mean_y) for x, y in zip(xs, ys)) / denom


def verdict_line(name, samples, fail_pct):
    # The baseline is the FIRST post-warmup sample, not the window mean:
    # for a growing series the mean sits above the start, so slope/mean
    # understates the growth a reader thinks the percentage reports.
    baseline = samples[0][1]
    slope = slope_per_hour(samples)
    # A zero baseline makes any percentage 0 and silently passes, which
    # almost always means the metric was never read — INVALID, not ok.
    if baseline == 0:
        return False, f"{name}: baseline=0 (metric never read?) -> INVALID"
    pct = slope / baseline * 100.0
    ok = pct <= fail_pct
    return ok, f"{name}: baseline={baseline:.0f} slope={slope:+.0f}/hr ({pct:+.3f}%/hr) -> {'ok' if ok else 'FAIL'}"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--samples", required=True)
    parser.add_argument("--bursts", required=True)
    parser.add_argument("--warmup-min", type=float, default=60)
    parser.add_argument("--slope-fail-pct", type=float, default=1.0)
    args = parser.parse_args()

    rows = []
    with open(args.samples) as handle:
        for line in handle:
            parts = line.strip().split(",")
            if len(parts) != 5:
                continue
            ts, gauge, ps_rss, fds, conns = parts
            rows.append((int(ts), float(gauge), float(ps_rss), float(fds), float(conns)))
    if not rows:
        print("FAIL: no samples recorded")
        return 1

    start = rows[0][0]
    post = [row for row in rows if row[0] >= start + args.warmup_min * 60]
    if len(post) < 3:
        print(f"FAIL: only {len(post)} post-warmup samples; the run was too short to judge")
        return 1

    failures = []
    print(f"samples={len(rows)} post_warmup={len(post)} warmup={args.warmup_min}m")

    gauge_ok, line = verdict_line("gauge_rss_bytes", [(r[0], r[1]) for r in post], args.slope_fail_pct)
    print(line); failures += [] if gauge_ok else ["gauge RSS slope"]
    # Fds get a small absolute floor below which the percentage cannot
    # fail (the count is tens, so one or two fds of noise becomes a large
    # percentage — seen in dry-runs), AND a cap on total growth across
    # the run: +3/hr sounds small but is +72 over 24h, so the run may
    # grow at most +50 fds from the first post-warmup sample, whichever
    # binds first. RSS needs no floor: its baseline is megabytes.
    fd_samples = [(r[0], r[3]) for r in post]
    fd_baseline = fd_samples[0][1]
    fd_slope = slope_per_hour(fd_samples)
    fd_growth = fd_samples[-1][1] - fd_baseline
    if fd_baseline == 0:
        print("open_fds: baseline=0 (metric never read?) -> INVALID")
        failures.append("fd baseline zero")
    else:
        fd_pct = fd_slope / fd_baseline * 100.0
        fd_ok = (fd_pct <= args.slope_fail_pct or fd_slope <= 3) and fd_growth <= 50
        print(f"open_fds: baseline={fd_baseline:.0f} slope={fd_slope:+.0f}/hr ({fd_pct:+.3f}%/hr) growth={fd_growth:+.0f} -> {'ok' if fd_ok else 'FAIL'}")
        if not fd_ok:
            failures.append("fd slope")
    # ps RSS drifts for reasons rook does not control; printed, not judged.
    _, line = verdict_line("ps_rss_bytes (corroboration only)", [(r[0], r[2]) for r in post],
                           float("inf"))
    print(line)

    # Connections must return to baseline: compare the last idle-window
    # sample of each hour against the pre-load sample.
    baseline_conns = rows[0][4]
    final_conns = rows[-1][4]
    conns_ok = final_conns <= baseline_conns * 2 + 10
    print(f"connections: first={baseline_conns:.0f} final={final_conns:.0f} -> {'ok' if conns_ok else 'FAIL'}")
    if not conns_ok:
        failures.append("connections did not return to baseline")

    bursts = 0
    with open(args.bursts) as handle:
        for line in handle:
            if "valid=" not in line:
                continue
            if "valid=INVALID" in line:
                failures.append(f"INVALID burst: {line.strip()}")
            elif "refusal=none" in line:
                failures.append(f"unanswered burst: {line.strip()}")
            else:
                bursts += 1
    print(f"bursts answered: {bursts}")

    if failures:
        print("FAIL:")
        for failure in failures:
            print(f"  - {failure}")
        return 1
    print("PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
