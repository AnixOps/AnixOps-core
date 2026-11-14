#!/usr/bin/env python3
"""Capture quality and overhead gates (decisions I3 / I4, docs/performance-ci.md).

Drives crates/engine-embedded/examples/capture_bench.rs on a GitHub Actions
Linux runner:

- The tunnel process opens a fresh TUN device, which is then moved into the
  network namespace ``capbench``; clients (curl, a raw TCP reader) run in
  that namespace, so every packet they send goes through the tunnel, while
  the tunnel's own outbound sockets stay in the root namespace.
- decrypt: every host of the site list is fetched once directly and once
  through the tunnel with HTTPS decryption on (production upstream TLS
  client). A site passes when curl, trusting only the device root, gets the
  same status class as directly and the decrypted exchange is in the capture
  (HAR export). Gate: passed / answered-directly >= --min-decrypt-percent.
- overhead: fresh tunnel processes with capture off and on (default budget)
  download --mib MiB raw TCP, plain HTTP (rewrite hook) and HTTPS (decrypted)
  from a local origin, then run --requests short HTTPS and HTTP requests and
  --conns raw connections. Rounds alternate the order. Gates: median
  throughput with capture on is at most --max-throughput-drop-percent below
  off, for every workload; the median peak RSS (VmHWM) with capture on is at
  most --max-memory-increase-mb above off.

Subcommand ``raw-client`` is the raw TCP reader run inside the namespace.
"""

import argparse
import base64
import json
import os
import socket
import statistics
import subprocess
import sys
import threading
import time
from urllib.parse import urlparse

NS = "capbench"
RAW = "198.18.0.2:5201"
ORIGIN_IP = "198.18.0.3"
BENCH_HOST = "bench.test"
UA = (
    "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1"
)
MIB = 1024 * 1024


def run(cmd, check=True, timeout=None):
    result = subprocess.run(cmd, text=True, capture_output=True, timeout=timeout)
    if check and result.returncode != 0:
        raise RuntimeError(f"{' '.join(cmd)} failed ({result.returncode}): {result.stderr.strip()}")
    return result


def sudo(*cmd, check=True):
    return run(["sudo", *cmd], check=check)


def in_ns(*cmd, check=False, timeout=None):
    return run(["sudo", "ip", "netns", "exec", NS, *cmd], check=check, timeout=timeout)


def spawn(cmd):
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, text=True)
    words = (proc.stdout.readline() or "").split()
    if not words or words[0] != "READY":
        proc.kill()
        raise RuntimeError(f"{cmd[1]} did not start: {words}")
    return proc, [int(word) for word in words[1:]]


class Origin:
    def __init__(self, bench, out):
        self.root = os.path.join(out, "origin-root.pem")
        self.proc, (self.raw, self.http, self.https) = spawn(
            [bench, "origin", "--root-out", self.root]
        )

    def stop(self):
        self.proc.kill()
        self.proc.wait()


class Tunnel:
    serial = 0

    def __init__(self, bench, out, capture, hosts=None, origin=None, capture_bytes=None):
        Tunnel.serial += 1
        self.dev = f"cap{Tunnel.serial}"
        self.root = os.path.join(out, f"device-root-{self.dev}.pem")
        sudo("ip", "tuntap", "add", "dev", self.dev, "mode", "tun", "user", str(os.getuid()))
        cmd = [bench, "tunnel", "--tun", self.dev, "--device-root-out", self.root,
               "--capture", "on" if capture else "off"]
        if hosts:
            cmd += ["--hosts", hosts]
        if origin:
            cmd += ["--raw", str(origin.raw), "--http", str(origin.http),
                    "--https", str(origin.https), "--origin-root", origin.root]
        if capture_bytes:
            cmd += ["--capture-bytes", str(capture_bytes)]
        self.proc, (self.port,) = spawn(cmd)
        # The tunnel holds the device open; from here on its packets belong to
        # the namespace, the tunnel's own sockets stay outside.
        sudo("ip", "link", "set", self.dev, "netns", NS)
        in_ns("ip", "addr", "add", "198.18.0.1/16", "dev", self.dev, check=True)
        in_ns("ip", "link", "set", self.dev, "mtu", "1500", "up", check=True)
        in_ns("ip", "route", "replace", "default", "dev", self.dev, check=True)

    def control(self, line, timeout=120):
        with socket.create_connection(("127.0.0.1", self.port), timeout=timeout) as stream:
            stream.sendall(line.encode() + b"\n")
            data = bytearray()
            while True:
                chunk = stream.recv(1 << 20)
                if not chunk:
                    break
                data += chunk
        return json.loads(data)

    def har_entries(self):
        answer = self.control('{"cmd":"export_capture","format":"har"}')
        har = json.loads(base64.b64decode(answer["data_base64"]))
        return har["log"]["entries"]

    def stop(self):
        self.proc.kill()
        self.proc.wait()
        in_ns("ip", "link", "del", self.dev)


def curl(*args, ns=True, timeout=180):
    cmd = ["curl", "-4", "-sS", "-o", "/dev/null", "-w", "%{http_code} %{size_download} %{time_total}\\n", *args]
    try:
        result = in_ns(*cmd, timeout=timeout) if ns else run(cmd, check=False, timeout=timeout)
    except subprocess.TimeoutExpired:
        return {"exit": -1, "error": "timeout", "lines": []}
    lines = []
    for line in result.stdout.splitlines():
        parts = line.split()
        if len(parts) == 3:
            lines.append({"code": parts[0], "bytes": int(parts[1]), "seconds": float(parts[2])})
    return {"exit": result.returncode, "error": result.stderr.strip()[-300:], "lines": lines}


# ---- overhead ---------------------------------------------------------------


def download(tunnel, kind, size):
    if kind == "raw":
        result = in_ns("python3", "-I", os.path.abspath(__file__), "raw-client",
                       "--addr", RAW, "--bytes", str(size), check=True, timeout=300)
        data = json.loads(result.stdout)
        got, seconds = data["bytes"], data["seconds"]
    else:
        scheme, port = ("http", 80) if kind == "http" else ("https", 443)
        args = ["--max-time", "240", "--resolve", f"{BENCH_HOST}:{port}:{ORIGIN_IP}"]
        if kind == "https":
            args += ["--cacert", tunnel.root]
        result = curl(*args, f"{scheme}://{BENCH_HOST}/bytes/{size}")
        if result["exit"] != 0 or not result["lines"] or result["lines"][0]["code"] != "200":
            raise RuntimeError(f"{kind} download failed: {result}")
        got, seconds = result["lines"][0]["bytes"], result["lines"][0]["seconds"]
    if got != size:
        raise RuntimeError(f"{kind} download got {got} of {size} bytes")
    return size / MIB / seconds


def many_requests(tunnel, requests, conns, size):
    """Short connections: fills the capture budget so eviction runs."""
    failures = 0
    for scheme, port in (("https", 443), ("http", 80)):
        args = ["--max-time", "240", "-Z", "--parallel-max", "16", "-H", "Connection: close",
                "--resolve", f"{BENCH_HOST}:{port}:{ORIGIN_IP}"]
        if scheme == "https":
            args += ["--cacert", tunnel.root]
        result = curl(*args, f"{scheme}://{BENCH_HOST}/bytes/{size}?i=[1-{requests}]")
        ok = sum(1 for line in result["lines"] if line["code"] == "200" and line["bytes"] == size)
        failures += requests - ok
    result = in_ns("python3", "-I", os.path.abspath(__file__), "raw-client", "--addr", RAW,
                   "--bytes", str(size), "--count", str(conns), "--parallel", "16",
                   check=True, timeout=300)
    failures += json.loads(result.stdout)["failed"]
    return failures


def overhead(bench, out, args):
    origin = Origin(bench, out)
    size = args.mib * MIB
    kinds = ("raw", "http", "https")
    samples = {"off": [], "on": []}
    try:
        for round_index in range(args.rounds):
            order = ("off", "on") if round_index % 2 == 0 else ("on", "off")
            for mode in order:
                tunnel = Tunnel(bench, out, capture=mode == "on", origin=origin)
                try:
                    idle = tunnel.control("sample")
                    throughput = {kind: download(tunnel, kind, size) for kind in kinds}
                    failures = many_requests(tunnel, args.requests, args.conns, args.request_kib * 1024)
                    end = tunnel.control("sample")
                finally:
                    tunnel.stop()
                record = {
                    "round": round_index + 1,
                    "throughput_mib_s": throughput,
                    "request_failures": failures,
                    "idle_rss_kb": idle["rss_kb"],
                    "peak_rss_kb": end["hwm_kb"],
                    "end_rss_kb": end["rss_kb"],
                    "cpu_us": end["cpu_us"],
                    "mitm_flows": end["tunnel"].get("mitm_flows"),
                    "capture": end["capture"],
                }
                print(f"round {round_index + 1} capture {mode}: {json.dumps(record)}", flush=True)
                samples[mode].append(record)
    finally:
        origin.stop()

    def median(mode, pick):
        return statistics.median(pick(record) for record in samples[mode])

    result = {"rounds": samples, "throughput": {}, "failures": []}
    for kind in kinds:
        off = median("off", lambda r: r["throughput_mib_s"][kind])
        on = median("on", lambda r: r["throughput_mib_s"][kind])
        drop = (off - on) / off * 100
        result["throughput"][kind] = {"off": off, "on": on, "drop_percent": drop}
        if drop > args.max_throughput_drop_percent:
            result["failures"].append(
                f"{kind} throughput with capture on is {drop:.1f}% below off "
                f"(limit {args.max_throughput_drop_percent:g}%)"
            )
    peak_off = median("off", lambda r: r["peak_rss_kb"]) / 1024
    peak_on = median("on", lambda r: r["peak_rss_kb"]) / 1024
    result["memory"] = {
        "peak_off_mb": peak_off,
        "peak_on_mb": peak_on,
        "increase_mb": peak_on - peak_off,
        "idle_off_mb": median("off", lambda r: r["idle_rss_kb"]) / 1024,
        "idle_on_mb": median("on", lambda r: r["idle_rss_kb"]) / 1024,
    }
    if peak_on - peak_off > args.max_memory_increase_mb:
        result["failures"].append(
            f"peak RSS with capture on is {peak_on - peak_off:.1f} MiB above off "
            f"(limit {args.max_memory_increase_mb:g} MiB)"
        )
    if args.max_peak_mb and peak_on > args.max_peak_mb:
        result["failures"].append(
            f"peak RSS with capture on is {peak_on:.1f} MiB (limit {args.max_peak_mb:g} MiB)"
        )
    failed_requests = sum(r["request_failures"] for mode in samples for r in samples[mode])
    if failed_requests:
        result["failures"].append(f"{failed_requests} short requests failed")
    return result


# ---- decryption -------------------------------------------------------------


def sites(path):
    hosts = []
    with open(path) as handle:
        for line in handle:
            host = line.split("#", 1)[0].strip()
            if host and host not in hosts:
                hosts.append(host)
    return hosts


def fetch(host, ip, ns, cacert=None):
    args = ["--max-time", "20", "-A", UA, "--resolve", f"{host}:443:{ip}"]
    if cacert:
        args += ["--cacert", cacert]
    for attempt in range(2):
        result = curl(*args, f"https://{host}/", ns=ns, timeout=40)
        code = result["lines"][0]["code"] if result["lines"] else "000"
        if result["exit"] == 0 and code != "000":
            return code, ""
        if attempt == 0:
            time.sleep(1)
    return None, result["error"] or f"curl exit {result['exit']}"


def decrypt(bench, out, args):
    hosts = sites(args.sites)
    tunnel = Tunnel(bench, out, capture=True, hosts=args.sites, capture_bytes=16 * MIB)
    records = []
    try:
        for host in hosts:
            record = {"host": host}
            try:
                ip = socket.getaddrinfo(host, 443, socket.AF_INET, socket.SOCK_STREAM)[0][4][0]
            except OSError as err:
                record.update(status="unreachable", detail=f"resolve: {err}")
                records.append(record)
                continue
            record["ip"] = ip
            direct, error = fetch(host, ip, ns=False)
            record["direct"] = direct
            if direct is None:
                record.update(status="unreachable", detail=error)
                records.append(record)
                continue
            tunnel.control('{"cmd":"clear_capture"}')
            via, error = fetch(host, ip, ns=True, cacert=tunnel.root)
            record["decrypted"] = via
            captured = False
            if via is not None:
                for _ in range(20):
                    entries = tunnel.har_entries()
                    captured = any(
                        urlparse(entry["request"]["url"]).hostname == host
                        and str(entry["response"]["status"]) == via
                        for entry in entries
                    )
                    if captured:
                        break
                    time.sleep(0.1)
            if via is None:
                record.update(status="fail", detail=error)
            elif via[0] != direct[0]:
                record.update(status="fail", detail=f"status {via} through the tunnel, {direct} directly")
            elif not captured:
                record.update(status="fail", detail="exchange missing from the capture")
            else:
                record["status"] = "pass"
            print(f"{host}: {json.dumps(record)}", flush=True)
            records.append(record)
        end = tunnel.control("sample")
    finally:
        tunnel.stop()
    answered = [r for r in records if r["status"] != "unreachable"]
    passed = [r for r in answered if r["status"] == "pass"]
    rate = len(passed) / len(answered) * 100 if answered else 0.0
    result = {
        "sites": len(hosts),
        "answered": len(answered),
        "passed": len(passed),
        "rate_percent": rate,
        "records": records,
        "peak_rss_kb": end["hwm_kb"],
        "failures": [],
    }
    if len(answered) < args.min_answered:
        result["failures"].append(
            f"only {len(answered)} of {len(hosts)} sites answered directly "
            f"(need {args.min_answered}); runner network problem, result inconclusive"
        )
    if rate < args.min_decrypt_percent:
        result["failures"].append(
            f"HTTPS decryption success {rate:.1f}% (limit {args.min_decrypt_percent:g}%)"
        )
    return result


# ---- report -----------------------------------------------------------------


def summary(result, args):
    lines = ["### Capture quality and overhead (I3 / I4)", ""]
    decrypt_result = result.get("decrypt")
    if decrypt_result:
        lines += [
            f"**HTTPS decryption**: {decrypt_result['passed']} / {decrypt_result['answered']} "
            f"sites = **{decrypt_result['rate_percent']:.1f}%** (gate ≥ {args.min_decrypt_percent:g}%; "
            f"{decrypt_result['sites'] - decrypt_result['answered']} of {decrypt_result['sites']} "
            "did not answer directly and are left out)",
            "",
        ]
        bad = [r for r in decrypt_result["records"] if r["status"] != "pass"]
        if bad:
            lines += ["| Site | Result | Direct | Decrypted | Detail |", "| --- | --- | --- | --- | --- |"]
            for r in bad:
                detail = str(r.get("detail", "")).replace("|", "/").replace("\n", " ")[:160]
                lines.append(
                    f"| {r['host']} | {r['status']} | {r.get('direct') or ''} | "
                    f"{r.get('decrypted') or ''} | {detail} |"
                )
            lines.append("")
    overhead_result = result.get("overhead")
    if overhead_result:
        lines += [
            f"**Capture on vs off** (median of {args.rounds} rounds, {args.mib} MiB per download)",
            "",
            "| Workload | Off MiB/s | On MiB/s | Drop | Gate |",
            "| --- | ---: | ---: | ---: | ---: |",
        ]
        for kind, row in overhead_result["throughput"].items():
            lines.append(
                f"| {kind} | {row['off']:.1f} | {row['on']:.1f} | {row['drop_percent']:.1f}% | "
                f"≤ {args.max_throughput_drop_percent:g}% |"
            )
        memory = overhead_result["memory"]
        lines += [
            "",
            "| Tunnel process memory | Off | On | Increase | Gate |",
            "| --- | ---: | ---: | ---: | ---: |",
            f"| Peak RSS (VmHWM) | {memory['peak_off_mb']:.1f} MiB | {memory['peak_on_mb']:.1f} MiB | "
            f"{memory['increase_mb']:.1f} MiB | ≤ {args.max_memory_increase_mb:g} MiB |",
            f"| Idle RSS after start | {memory['idle_off_mb']:.1f} MiB | {memory['idle_on_mb']:.1f} MiB | | |",
            "",
        ]
    failures = result["failures"]
    lines.append("**Result**: " + ("pass" if not failures else "FAIL"))
    lines += [f"- {failure}" for failure in failures]
    return "\n".join(lines) + "\n"


def raw_client(args):
    addr, port = args.addr.rsplit(":", 1)
    failed = 0
    lock = threading.Lock()
    timing = {}

    def one():
        nonlocal failed
        started = time.monotonic()
        got = 0
        try:
            with socket.create_connection((addr, int(port)), timeout=60) as stream:
                stream.sendall(args.bytes.to_bytes(8, "big"))
                buf = bytearray(1 << 20)
                while got < args.bytes:
                    n = stream.recv_into(buf)
                    if n == 0:
                        break
                    got += n
        except OSError:
            pass
        with lock:
            if got != args.bytes:
                failed += 1
            timing.setdefault("bytes", got)
            timing.setdefault("seconds", time.monotonic() - started)

    pending = list(range(args.count))
    workers = []

    def worker():
        while True:
            with lock:
                if not pending:
                    return
                pending.pop()
            one()

    for _ in range(min(args.parallel, args.count)):
        thread = threading.Thread(target=worker)
        thread.start()
        workers.append(thread)
    for thread in workers:
        thread.join()
    print(json.dumps({"bytes": timing.get("bytes", 0), "seconds": timing.get("seconds", 0.0),
                      "failed": failed}))


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="command", required=True)
    gates = sub.add_parser("run")
    gates.add_argument("--bench", required=True)
    gates.add_argument("--sites", required=True)
    gates.add_argument("--out", required=True)
    gates.add_argument("--only", choices=["all", "decrypt", "overhead"], default="all")
    gates.add_argument("--rounds", type=int, default=3)
    gates.add_argument("--mib", type=int, default=256)
    gates.add_argument("--requests", type=int, default=200)
    gates.add_argument("--conns", type=int, default=200)
    gates.add_argument("--request-kib", type=int, default=256)
    gates.add_argument("--min-decrypt-percent", type=float, default=95)
    gates.add_argument("--min-answered", type=int, default=40)
    gates.add_argument("--max-throughput-drop-percent", type=float, default=15)
    gates.add_argument("--max-memory-increase-mb", type=float, default=10)
    gates.add_argument("--max-peak-mb", type=float, default=0, help="0 = report only")
    client = sub.add_parser("raw-client")
    client.add_argument("--addr", required=True)
    client.add_argument("--bytes", type=int, required=True)
    client.add_argument("--count", type=int, default=1)
    client.add_argument("--parallel", type=int, default=1)
    args = parser.parse_args()
    if args.command == "raw-client":
        raw_client(args)
        return 0

    out = os.path.abspath(args.out)
    os.makedirs(out, exist_ok=True)
    bench = os.path.abspath(args.bench)
    sudo("ip", "netns", "add", NS, check=False)
    in_ns("ip", "link", "set", "lo", "up", check=True)
    result = {"failures": []}
    try:
        if args.only in ("all", "decrypt"):
            result["decrypt"] = decrypt(bench, out, args)
            result["failures"] += result["decrypt"]["failures"]
        if args.only in ("all", "overhead"):
            result["overhead"] = overhead(bench, out, args)
            result["failures"] += result["overhead"]["failures"]
    except Exception as err:  # noqa: BLE001 - reported as a gate failure
        result["failures"].append(f"benchmark error: {err}")
    with open(os.path.join(out, "capture-gates.json"), "w") as handle:
        json.dump(result, handle, indent=2)
    report = summary(result, args)
    with open(os.path.join(out, "summary.md"), "w") as handle:
        handle.write(report)
    print(report)
    for failure in result["failures"]:
        print(f"::error::{failure}")
    return 1 if result["failures"] else 0


if __name__ == "__main__":
    sys.exit(main())
