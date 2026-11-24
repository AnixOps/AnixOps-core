#!/usr/bin/env python3
"""Desktop local proxy soak (F9, docs/performance-ci.md) on Linux, macOS and
Windows.

Starts `proxy_soak peer` (echo server, Shadowsocks 2022 server and the load)
and `proxy_soak proxy` (one LocalProxy, the measured process), connects them,
samples the proxy process with psutil while the peer drives it, and fails
when, after warm-up:

- resident memory grows faster than --max-slope-mb-per-h,
- open descriptors (Unix) or handles (Windows) grow faster than
  --max-handle-slope-per-h,
- the peer reports more than 0.1% failed connections (its own exit code),
- 10 s after the load stops, the proxy still counts active connections, or
  holds more descriptors or handles than before the load began plus
  --handle-slack.

Writes the samples and the verdict to --json.
"""

import argparse
import json
import subprocess
import sys
import threading
import time

import psutil


def slope(points):
    """Least-squares slope of (x, y) points, or None with fewer than 3."""
    if len(points) < 3:
        return None
    n = len(points)
    mean_x = sum(p[0] for p in points) / n
    mean_y = sum(p[1] for p in points) / n
    covariance = sum((x - mean_x) * (y - mean_y) for x, y in points)
    variance = sum((x - mean_x) ** 2 for x, _ in points)
    return covariance / variance if variance > 0 else None


def handles(process):
    if sys.platform == "win32":
        return process.num_handles()
    return process.num_fds()


def sample(process):
    with process.oneshot():
        return {
            "rss_mb": process.memory_info().rss / (1 << 20),
            "handles": handles(process),
            "threads": process.num_threads(),
        }


def read_line(stream, prefix, timeout):
    """The rest of the first line of `stream` that starts with `prefix`."""
    found = {}

    def read():
        for line in stream:
            if line.startswith(prefix):
                found["value"] = line[len(prefix):].strip()
                return

    reader = threading.Thread(target=read, daemon=True)
    reader.start()
    reader.join(timeout)
    if "value" not in found:
        raise SystemExit(f"no '{prefix.strip()}' line within {timeout} s")
    return found["value"]


def proxy_stats(proxy):
    proxy.stdin.write("stats\n")
    proxy.stdin.flush()
    return json.loads(proxy.stdout.readline())


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", required=True)
    parser.add_argument("--hours", type=float, required=True)
    parser.add_argument("--sample-secs", type=float, default=30)
    parser.add_argument("--warmup-share", type=float, default=0.15)
    parser.add_argument("--max-slope-mb-per-h", type=float, required=True)
    parser.add_argument("--max-handle-slope-per-h", type=float, required=True)
    parser.add_argument("--handle-slack", type=int, default=8)
    parser.add_argument("--json", required=True)
    args = parser.parse_args()

    minutes = max(1, round(args.hours * 60))
    peer = subprocess.Popen(
        [args.binary, "peer", "--minutes", str(minutes)],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        text=True,
    )
    ss_port = read_line(peer.stdout, "SS ", 60)
    proxy = subprocess.Popen(
        [args.binary, "proxy", "--ss-port", ss_port],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        text=True,
    )
    proxy_port = read_line(proxy.stdout, "READY ", 60)
    measured = psutil.Process(proxy.pid)
    time.sleep(2)
    before = sample(measured)

    peer_lines = []
    peer_reader = threading.Thread(
        target=lambda: peer_lines.extend(line.rstrip() for line in peer.stdout),
        daemon=True,
    )
    peer_reader.start()
    peer.stdin.write(f"PROXY {proxy_port}\n")
    peer.stdin.flush()

    begin = time.monotonic()
    samples = []
    while peer.poll() is None:
        time.sleep(args.sample_secs)
        if proxy.poll() is not None:
            break
        point = sample(measured)
        point["hours"] = (time.monotonic() - begin) / 3600
        samples.append(point)
        print(json.dumps(point), flush=True)
    peer_code = peer.wait()
    peer_reader.join(10)

    failures = []
    if proxy.poll() is not None:
        failures.append(f"the proxy exited with {proxy.returncode} during the soak")
        after, stats = None, None
    else:
        time.sleep(10)
        after = sample(measured)
        stats = proxy_stats(proxy)
        proxy.stdin.close()
        try:
            proxy.wait(30)
        except subprocess.TimeoutExpired:
            proxy.kill()
            failures.append("the proxy did not stop at end of input")

    skip = int(len(samples) * args.warmup_share)
    trend = samples[skip:]
    rss_slope = slope([(p["hours"], p["rss_mb"]) for p in trend])
    handle_slope = slope([(p["hours"], p["handles"]) for p in trend])

    if peer_code != 0:
        failures.append(f"the load failed (peer exit code {peer_code}): {peer_lines[-1:]}")
    if rss_slope is None:
        failures.append("too few samples for a memory trend")
    elif rss_slope > args.max_slope_mb_per_h:
        failures.append(
            f"RSS grows {rss_slope:.3f} MiB/h after warm-up, above {args.max_slope_mb_per_h} MiB/h"
        )
    if handle_slope is not None and handle_slope > args.max_handle_slope_per_h:
        failures.append(
            f"handles grow {handle_slope:.2f}/h after warm-up, above {args.max_handle_slope_per_h}/h"
        )
    if stats is not None and stats["active"] != 0:
        failures.append(f"{stats['active']} connections still active after the load stopped")
    if after is not None and after["handles"] > before["handles"] + args.handle_slack:
        failures.append(
            f"{after['handles']} handles after the load, {before['handles']} before it"
        )

    result = {
        "platform": sys.platform,
        "minutes": minutes,
        "before": before,
        "after": after,
        "proxy_stats": stats,
        "peer_summary": next((l for l in reversed(peer_lines) if l.startswith("DONE ")), None),
        "warmup_samples": skip,
        "rss_slope_mb_per_h": rss_slope,
        "handle_slope_per_h": handle_slope,
        "max_slope_mb_per_h": args.max_slope_mb_per_h,
        "max_handle_slope_per_h": args.max_handle_slope_per_h,
        "samples": samples,
        "failures": failures,
    }
    with open(args.json, "w", encoding="utf-8") as out:
        json.dump(result, out, indent=2)
    for failure in failures:
        print(f"::error::{failure}")
    print(json.dumps({k: v for k, v in result.items() if k != "samples"}, indent=2))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
