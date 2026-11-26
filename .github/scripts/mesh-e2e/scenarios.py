#!/usr/bin/env python3
"""Mesh end-to-end scenarios on the namespace testbed (docs/testing/mesh-e2e.md).

Usage:
  sudo scenarios.py --binary PATH [--only E01,E03] [--repeat N] [--results FILE] [--keep]
  scenarios.py --list
  scenarios.py --check-docs docs/testing/mesh-e2e.md

Every scenario is either enabled (runs, and any failure fails the run) or
pending (its feature is not merged yet; listed in the results as pending,
never counted as passed). A pending scenario is enabled by moving it to
`ENABLED` together with its docs row; its assertions are not relaxed.
"""

import argparse
import json
import os
import re
import sys
import time
import traceback

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from lab import Lab, LabError, mesh_config  # noqa: E402

NETWORK = "eu"
# Underlay segments: documentation-free benchmarking space, outside the
# intranet allow list, so the node never treats it as a mesh overlap.
WAN1, WAN2 = "198.18.1", "198.18.2"
# Virtual addresses of the region network.
VA, VB, VC, VD, VX = "10.144.1.1", "10.144.1.2", "10.144.1.3", "10.144.1.4", "10.144.1.9"
LAN = "192.168.10"

REACH = 45  # seconds for a first answer after the nodes start
SILENCE = 15  # seconds that a must-not-reach address stays silent


def va(address):
    return f"{address}/24"


def two_nodes(lab, transport="tcp", **extra):
    """A listens on wan1; B connects to A over `transport`."""
    a, b = lab.machine("a"), lab.machine("b")
    lab.segment("wan1", WAN1)
    _, wa = lab.attach(a, "wan1", 1)
    lab.attach(b, "wan1", 2)
    # Member key lists only exist in managed networks.
    members = ["A", "B"] if extra.get("kind", "managed") == "managed" else None
    na = lab.node(a, "A", mesh_config(lab, "A", NETWORK, va(VA), members=members, **extra)).start()
    nb = lab.node(b, "B", mesh_config(lab, "B", NETWORK, va(VB), members=members,
                                      peers=[(wa, transport)], **extra)).start()
    return a, b, na, nb


# -- enabled scenarios --------------------------------------------------------


def e01_tcp(lab):
    a, b, _, _ = two_nodes(lab, "tcp")
    b.reach(VA, REACH)
    a.reach(VB, REACH)


def e02_udp(lab):
    a, b, _, _ = two_nodes(lab, "udp")
    b.reach(VA, REACH)
    a.reach(VB, REACH)


def relay_topology(lab, relay=None):
    """B (wan1) and C (wan2) only reach each other's underlay through nothing;
    A sits on both segments."""
    a, b, c = lab.machine("a"), lab.machine("b"), lab.machine("c")
    lab.segment("wan1", WAN1)
    lab.segment("wan2", WAN2)
    _, wa1 = lab.attach(a, "wan1", 1)
    _, wa2 = lab.attach(a, "wan2", 1)
    lab.attach(b, "wan1", 2)
    lab.attach(c, "wan2", 3)
    members = ["A", "B", "C"]
    lab.node(a, "A", mesh_config(lab, "A", NETWORK, va(VA), members=members, relay=relay)).start()
    lab.node(b, "B", mesh_config(lab, "B", NETWORK, va(VB), members=members,
                                 peers=[(wa1, "tcp")])).start()
    lab.node(c, "C", mesh_config(lab, "C", NETWORK, va(VC), members=members,
                                 peers=[(wa2, "tcp")])).start()
    return a, b, c


def e03_relay(lab):
    a, b, c = relay_topology(lab)
    # B and C share no underlay segment: only A can carry their traffic.
    b.unreachable(f"{WAN2}.3", 2)
    b.reach(VC, REACH)
    c.reach(VB, REACH)


def e04_relay_off(lab):
    a, b, c = relay_topology(lab, relay=False)
    # A still answers as a destination ...
    b.reach(VA, REACH)
    c.reach(VA, REACH)
    # ... but does not carry B <-> C.
    b.unreachable(VC, SILENCE)
    c.unreachable(VB, 3)


def e05_access_node(lab):
    a, b, d = lab.machine("a"), lab.machine("b"), lab.machine("d")
    lab.segment("wan1", WAN1)
    _, wa = lab.attach(a, "wan1", 1)
    lab.attach(b, "wan1", 2)
    lab.attach(d, "wan1", 4)
    members = ["A", "B", "D"]
    lab.node(a, "A", mesh_config(lab, "A", NETWORK, va(VA), members=members)).start()
    lab.node(b, "B", mesh_config(lab, "B", NETWORK, va(VB), members=members,
                                 peers=[(wa, "tcp")])).start()
    lab.node(d, "D", mesh_config(lab, "D", NETWORK, va(VD), members=members, role="access",
                                 peers=[(wa, "tcp")])).start()
    d.reach(VA, REACH)
    d.reach(VB, REACH)
    b.reach(VD, REACH)
    # An access node cannot listen (R10): such a configuration is refused.
    bad = mesh_config(lab, "D", NETWORK, va(VD), members=members, role="access",
                      peers=[(wa, "tcp")])
    bad["node"]["listen"] = [{"transport": "tcp", "port": 11011}]
    expect_config_refused(lab, d, "D-listen", bad)


def e06_subnet(lab):
    g, h, b = lab.machine("g"), lab.machine("h"), lab.machine("b")
    lab.segment("wan1", WAN1)
    _, wg = lab.attach(g, "wan1", 1)
    lab.attach(b, "wan1", 2)
    host = lab.lan(g, h, LAN)
    # Linux host forwarding is not done by the node yet (mesh-module.md:
    # Linux prints "off"); the testbed switches it on in the gateway's
    # namespace. Everything else is the mesh's own doing.
    g.sysctl("net.ipv4.ip_forward", 1)
    members = ["G", "B"]
    lab.node(g, "G", mesh_config(lab, "G", NETWORK, va(VA), members=members,
                                 advertise=[f"{LAN}.0/24"])).start()
    nb = lab.node(b, "B", mesh_config(lab, "B", NETWORK, va(VB), members=members,
                                      peers=[(wg, "tcp")])).start()
    nb.wait_status(lambda s: f"{LAN}.0/24" in s.get("system_routes", []), REACH,
                   f"system route {LAN}.0/24")
    b.reach(host, REACH)


def e07_public_subnet(lab):
    a = lab.machine("a")
    lab.segment("wan1", WAN1)
    lab.attach(a, "wan1", 1)
    config = mesh_config(lab, "A", NETWORK, va(VA), members=["A"], advertise=["8.8.8.0/24"])
    expect_config_refused(lab, a, "A", config)


def e08_wrong_secret(lab):
    a, b, c = lab.machine("a"), lab.machine("b"), lab.machine("c")
    lab.segment("wan1", WAN1)
    _, wa = lab.attach(a, "wan1", 1)
    lab.attach(b, "wan1", 2)
    lab.attach(c, "wan1", 3)
    members = ["A", "B", "C"]
    lab.node(a, "A", mesh_config(lab, "A", NETWORK, va(VA), members=members)).start()
    nb = lab.node(b, "B", mesh_config(lab, "B", NETWORK, va(VB), members=members,
                                      peers=[(wa, "tcp")], secret="another-secret")).start()
    # Control: C has the right secret, so A is up and reachable.
    lab.node(c, "C", mesh_config(lab, "C", NETWORK, va(VC), members=members,
                                 peers=[(wa, "tcp")])).start()
    c.reach(VA, REACH)
    b.unreachable(VA, SILENCE)
    a.unreachable(VB, 3)
    status = nb.last_status()
    if status and status.get("neighbours"):
        raise LabError(f"B has neighbours with a wrong network secret: {status}")


def e09_not_native(lab):
    a, b, x = lab.machine("a"), lab.machine("b"), lab.machine("x")
    lab.segment("wan1", WAN1)
    _, wa = lab.attach(a, "wan1", 1)
    lab.attach(b, "wan1", 2)
    lab.attach(x, "wan1", 9)
    members = ["A", "B"]
    na = lab.node(a, "A", mesh_config(lab, "A", NETWORK, va(VA), members=members)).start()
    lab.node(b, "B", mesh_config(lab, "B", NETWORK, va(VB), members=members,
                                 peers=[(wa, "tcp")])).start()
    # X knows the secret and lists itself, but A and B do not list X.
    lab.node(x, "X", mesh_config(lab, "X", NETWORK, va(VX), members=["A", "B", "X"],
                                 peers=[(wa, "tcp")])).start()
    b.reach(VA, REACH)
    x.unreachable(VA, SILENCE)
    x.unreachable(VB, 3)
    na.wait_status(lambda s: s.get("not_native") is not None, REACH, "not_native set")


def e10_startup_conflict(lab):
    a = lab.machine("a")
    lab.segment("wan1", WAN1)
    lab.attach(a, "wan1", 1)
    first = lab.node(a, "A", mesh_config(lab, "A", NETWORK, va(VA), members=["A"])).start()
    time.sleep(3)
    if not first.alive():
        raise LabError(f"A exited {first.process.returncode} on its own")
    # Same port, other interface: port_in_use.
    second = lab.node(a, "A2", mesh_config(lab, "A2", NETWORK, va(VB), members=["A2"]),
                      interface="anixmesh1").start()
    expect_exit(second, 3, {"error": "conflict", "conflict": "port_in_use"})
    # Other port, same interface: tun_in_use.
    config = mesh_config(lab, "A3", NETWORK, va(VC), members=["A3"])
    for listen in config["node"]["listen"]:
        listen["port"] = 11020
    third = lab.node(a, "A3", config).start()
    expect_exit(third, 3, {"error": "conflict", "conflict": "tun_in_use"})
    if not first.alive():
        raise LabError("the running node stopped because of a refused second start")


def e11_legacy_mode(lab):
    a, b, _, _ = two_nodes(lab, "tcp", kind="legacy", secure=False, cipher="aes-gcm")
    b.reach(VA, REACH)
    a.reach(VB, REACH)


def e12_unencrypted(lab):
    a, b, c = lab.machine("a"), lab.machine("b"), lab.machine("c")
    lab.segment("wan1", WAN1)
    _, wa = lab.attach(a, "wan1", 1)
    lab.attach(b, "wan1", 2)
    lab.attach(c, "wan1", 3)
    plain = {"kind": "legacy", "secure": False, "cipher": "none"}
    lab.node(a, "A", mesh_config(lab, "A", NETWORK, va(VA), **plain)).start()
    lab.node(b, "B", mesh_config(lab, "B", NETWORK, va(VB), peers=[(wa, "tcp")], **plain)).start()
    # C has not chosen "none": it drops the network's plain traffic (R14).
    lab.node(c, "C", mesh_config(lab, "C", NETWORK, va(VC), peers=[(wa, "tcp")],
                                 kind="legacy", secure=False)).start()
    b.reach(VA, REACH)
    c.unreachable(VA, SILENCE)


# -- helpers -----------------------------------------------------------------


def expect_exit(node, code, fields):
    got = node.exit_code(REACH)
    if got != code:
        raise LabError(f"{node.name} exited {got}, expected {code}")
    line = node.stderr_json()
    if line is None:
        raise LabError(f"{node.name}: last stderr line is not JSON")
    for key, value in fields.items():
        if line.get(key) != value:
            raise LabError(f"{node.name}: stderr {line} has {key}={line.get(key)!r}, expected {value!r}")


def expect_config_refused(lab, machine, name, config):
    node = lab.node(machine, name, config, interface="anixmesh9").start()
    expect_exit(node, 2, {"error": "config"})


# -- registry ----------------------------------------------------------------

# id: (function, title, requirements)
ENABLED = {
    "E01": (e01_tcp, "同区两完整节点经 TCP 直连互访（安全模式）", ["R2", "R3", "R30"]),
    "E02": (e02_udp, "同区两完整节点经 UDP 直连互访（安全模式）", ["R2", "R3", "R30"]),
    "E03": (e03_relay, "底层不通的两节点经完整节点中转互访", ["R7", "R10"]),
    "E04": (e04_relay_off, "关闭中转的完整节点只作目的、不替他人转发", ["R10"]),
    "E05": (e05_access_node, "接入节点经完整节点入网，且不能监听", ["R10"]),
    "E06": (e06_subnet, "完整节点通告局域网子网，远端节点经组网访问局域网主机", ["R10", "R17"]),
    "E07": (e07_public_subnet, "通告公网网段的配置被拒绝", ["R5", "R17"]),
    "E08": (e08_wrong_secret, "网络密钥不同的节点无法入网", ["R2", "R30"]),
    "E09": (e09_not_native, "不在成员公钥清单中的节点被拒并在状态中标出", ["R30"]),
    "E10": (e10_startup_conflict, "端口或虚拟网卡被占用时拒绝启动并给出冲突原因", ["R12"]),
    "E11": (e11_legacy_mode, "旧网（默认模式）中我方节点互访", ["R2"]),
    "E12": (e12_unencrypted, "未加密网络须显式选择，未选择的节点丢弃明文流量", ["R14"]),
}

# id: (title, requirements, what it waits for)
PENDING = {
    "P01": ("两地区各两台边界节点经骨干互联，跨地区互访", ["R18", "R19", "R22"],
            "骨干与边界节点（core #342）、区域迁区线程；专线链路场景在 anx 私有仓库运行"),
    "P02": ("一台边界节点下线后跨地区流量改走同区另一台边界节点", ["R19"],
            "骨干与边界节点（core #342）"),
    "P03": ("地区间直连劣化时经第三地区绕行，恢复后切回", ["R19"],
            "骨干与边界节点（core #342）、测量与绕行"),
    "P04": ("宿主组网关通告组地址段，网关下线后改走备用网关", ["R21", "R25"],
            "宿主组线程的 host_groups 运行时"),
    "P05": ("旧版节点与我方节点黑盒互通（两种模式）", ["R1", "R2"],
            "M3 黑盒互通：仓库变量 MESH_PEER_URL、MESH_PEER_SHA256（docs/manual-intervention.md）"),
    "P06": ("旧版节点留在旧网，经我方桥接节点访问区域网络", ["R1", "R30"],
            "P05 与桥接迁移（规范 §15.11）"),
    "P07": ("自定义路径：全为我方途经点时严格按路径转发", ["R8"],
            "自定义路径接入驱动（core #346 为第一部分，转发尚未接入）"),
    "P08": ("自定义路径途经点不可达时回落默认路由并报告", ["R9"],
            "同 P07"),
    "P09": ("外部网络桥接：白名单成员经桥接节点访问外部网段，其余被丢弃", ["R36"],
            "外部网络桥接运行时（Linux 完整节点）"),
    "P10": ("内网域名：节点按后缀本机应答成员名字", ["R28"],
            "独立节点的固定解析地址（dns.resolver_address，内核 0.4）"),
    "P11": ("OpenWrt 设备（QEMU）安装软件包后入网并通告局域网", ["R32", "R35"],
            "OpenWrt 镜像与 QEMU 接入实验床"),
}


def run_one(binary, sid, keep):
    function = ENABLED[sid][0]
    lab = Lab(binary, keep=keep)
    started = time.monotonic()
    failed = True
    try:
        function(lab)
        failed = False
        return {"id": sid, "result": "passed", "seconds": round(time.monotonic() - started, 1)}
    except (LabError, OSError, Exception) as error:  # noqa: BLE001 - report every failure
        traceback.print_exc()
        return {"id": sid, "result": "failed", "error": str(error),
                "seconds": round(time.monotonic() - started, 1)}
    finally:
        lab.close(failed)


def check_docs(path):
    """The docs table and this registry must list the same scenarios."""
    rows = {}
    with open(path, encoding="utf-8") as handle:
        for line in handle:
            match = re.match(r"^\|\s*([EP]\d\d)\s*\|([^|]*)\|([^|]*)\|([^|]*)\|", line)
            if match:
                sid, _, reqs, status = (part.strip() for part in match.groups())
                rows[sid] = (sorted(re.findall(r"R\d+", reqs)), status)
    errors = []
    expected = {sid: (sorted(entry[2]), "启用") for sid, entry in ENABLED.items()}
    expected.update({sid: (sorted(entry[1]), "待启用") for sid, entry in PENDING.items()})
    for sid, (reqs, status) in expected.items():
        if sid not in rows:
            errors.append(f"{sid} missing from {path}")
            continue
        if rows[sid][0] != reqs:
            errors.append(f"{sid}: docs requirements {rows[sid][0]} != {reqs}")
        if rows[sid][1] != status:
            errors.append(f"{sid}: docs status {rows[sid][1]!r} != {status!r}")
    for sid in rows:
        if sid not in expected:
            errors.append(f"{sid} is in {path} but not in scenarios.py")
    for message in errors:
        print(message, file=sys.stderr)
    return not errors


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary")
    parser.add_argument("--only", default="")
    parser.add_argument("--repeat", type=int, default=1)
    parser.add_argument("--results")
    parser.add_argument("--keep", action="store_true")
    parser.add_argument("--list", action="store_true")
    parser.add_argument("--check-docs")
    args = parser.parse_args()

    if args.list:
        for sid, entry in ENABLED.items():
            print(f"{sid}  启用    {'、'.join(entry[2])}  {entry[1]}")
        for sid, entry in PENDING.items():
            print(f"{sid}  待启用  {'、'.join(entry[1])}  {entry[0]}（等待：{entry[2]}）")
        return 0
    if args.check_docs:
        return 0 if check_docs(args.check_docs) else 1
    if not args.binary:
        parser.error("--binary is required")
    if os.geteuid() != 0:
        parser.error("the testbed needs root (network namespaces)")

    selected = [sid.strip() for sid in args.only.split(",") if sid.strip()] or list(ENABLED)
    unknown = [sid for sid in selected if sid not in ENABLED]
    if unknown:
        parser.error(f"not enabled scenarios: {', '.join(unknown)}")

    results = []
    for round_number in range(1, args.repeat + 1):
        for sid in selected:
            print(f"::group::{sid} round {round_number}: {ENABLED[sid][1]}", flush=True)
            result = run_one(args.binary, sid, args.keep)
            result["round"] = round_number
            print(f"{sid} round {round_number}: {result['result']} ({result['seconds']} s)", flush=True)
            print("::endgroup::", flush=True)
            results.append(result)
    pending = [{"id": sid, "result": "pending", "waits_for": entry[2]}
               for sid, entry in PENDING.items()]
    if args.results:
        with open(args.results, "w", encoding="utf-8") as handle:
            json.dump({"results": results, "pending": pending}, handle, ensure_ascii=False, indent=2)
    failed = [r for r in results if r["result"] != "passed"]
    for result in failed:
        print(f"FAILED {result['id']} round {result['round']}: {result['error']}", file=sys.stderr)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
