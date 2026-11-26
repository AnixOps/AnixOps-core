"""Network-namespace testbed for the mesh end-to-end scenarios.

Every machine of a scenario is its own network namespace. Underlay
segments (stand-ins for the internet between sites) are Linux bridges in a
dedicated switch namespace; each machine joins a segment with a veth pair.
A LAN behind a gateway is a direct veth pair between the gateway and the
LAN host. Optional netem delay and loss sit on the machine side of a
segment link.

Nodes are real `anixops-mesh run` processes, one per namespace, started
from configurations written by the scenario. Nothing here imitates mesh
behaviour: the testbed only builds the wires, starts programs and observes
them from outside (ping, status lines on stdout, exit codes).

Must run as root (CI uses sudo). Only the standard library and the `ip`,
`ping`, `sysctl` and `openssl` programs are used.
"""

import base64
import json
import os
import shutil
import signal
import subprocess
import tempfile
import time

UNDERLAY_PREFIX = 24
LISTEN_PORT = 11010


class LabError(Exception):
    """A scenario assertion or a testbed step failed."""


def run(args, check=True, capture=True, timeout=30):
    result = subprocess.run(
        args,
        check=False,
        stdout=subprocess.PIPE if capture else None,
        stderr=subprocess.PIPE if capture else None,
        text=True,
        timeout=timeout,
    )
    if check and result.returncode != 0:
        raise LabError(
            f"{' '.join(args)} exited {result.returncode}: {(result.stderr or '').strip()}"
        )
    return result


def x25519_keypair(workdir, name):
    """A static key pair as standard base64 (private, public)."""
    der = os.path.join(workdir, f"{name}.der")
    run(["openssl", "genpkey", "-algorithm", "X25519", "-outform", "DER", "-out", der])
    with open(der, "rb") as handle:
        private = handle.read()[-32:]
    # Binary DER on stdout, so not through run() (text mode).
    public = subprocess.run(
        ["openssl", "pkey", "-inform", "DER", "-in", der, "-pubout", "-outform", "DER"],
        check=True,
        stdout=subprocess.PIPE,
    ).stdout[-32:]
    os.remove(der)
    if len(private) != 32 or len(public) != 32:
        raise LabError("openssl gave a key of the wrong length")
    return base64.b64encode(private).decode(), base64.b64encode(public).decode()


class Node:
    """One `anixops-mesh run` process inside a machine's namespace."""

    def __init__(self, lab, machine, name, config, interface):
        self.lab = lab
        self.machine = machine
        self.name = name
        self.config = config
        self.interface = interface
        self.path = os.path.join(lab.workdir, f"{name}.json")
        self.stdout_path = os.path.join(lab.workdir, f"{name}.stdout")
        self.stderr_path = os.path.join(lab.workdir, f"{name}.stderr")
        self.process = None

    def start(self):
        with open(self.path, "w", encoding="utf-8") as handle:
            json.dump(self.config, handle, indent=2)
        os.chmod(self.path, 0o600)
        stdout = open(self.stdout_path, "w", encoding="utf-8")
        stderr = open(self.stderr_path, "w", encoding="utf-8")
        self.process = subprocess.Popen(
            [
                "ip", "netns", "exec", self.machine.ns,
                self.lab.binary, "run", "--config", self.path, "--interface", self.interface,
            ],
            stdout=stdout,
            stderr=stderr,
            start_new_session=True,
        )
        stdout.close()
        stderr.close()
        return self

    def stop(self):
        if self.process and self.process.poll() is None:
            os.killpg(self.process.pid, signal.SIGTERM)
            try:
                self.process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                os.killpg(self.process.pid, signal.SIGKILL)
                self.process.wait(timeout=5)

    def exit_code(self, timeout):
        """Waits for the process to end on its own and returns its exit code."""
        try:
            return self.process.wait(timeout=timeout)
        except subprocess.TimeoutExpired as error:
            raise LabError(f"{self.name} still runs after {timeout} s") from error

    def alive(self):
        return self.process is not None and self.process.poll() is None

    def statuses(self):
        """The JSON status lines written so far, oldest first."""
        lines = []
        with open(self.stdout_path, encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                try:
                    lines.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
        return lines

    def last_status(self):
        for line in reversed(self.statuses()):
            if "peer_id" in line:
                return line
        return None

    def stderr_json(self):
        """The last stderr line as JSON (the exit contract), or None."""
        with open(self.stderr_path, encoding="utf-8") as handle:
            lines = [line.strip() for line in handle if line.strip()]
        if not lines:
            return None
        try:
            return json.loads(lines[-1])
        except json.JSONDecodeError:
            return None

    def wait_status(self, predicate, timeout, what):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if not self.alive():
                raise LabError(f"{self.name} exited {self.process.returncode} while waiting for {what}")
            status = self.last_status()
            if status is not None and predicate(status):
                return status
            time.sleep(0.5)
        raise LabError(f"{self.name}: no status with {what} within {timeout} s (last: {self.last_status()})")

    def logs(self):
        parts = []
        for path in (self.stdout_path, self.stderr_path):
            if os.path.exists(path):
                with open(path, encoding="utf-8") as handle:
                    parts.append(f"--- {os.path.basename(path)}\n{handle.read()}")
        return "\n".join(parts)


class Machine:
    """A network namespace standing for one host."""

    def __init__(self, lab, name):
        self.lab = lab
        self.name = name
        self.ns = f"{lab.prefix}-{name}"
        self.addresses = {}
        self.links = 0
        run(["ip", "netns", "add", self.ns])
        self.exec(["ip", "link", "set", "lo", "up"])

    def exec(self, args, check=True, timeout=30):
        return run(["ip", "netns", "exec", self.ns, *args], check=check, timeout=timeout)

    def sysctl(self, key, value):
        self.exec(["sysctl", "-q", "-w", f"{key}={value}"])

    def next_link(self):
        self.links += 1
        return f"e{self.links}"

    def ping(self, address, count=1, wait=1):
        result = self.exec(
            ["ping", "-n", "-q", "-c", str(count), "-W", str(wait), address],
            check=False,
            timeout=count * wait + 10,
        )
        return result.returncode == 0

    def reach(self, address, timeout=30):
        """Pings until one answer comes back; fails after `timeout` seconds."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self.ping(address):
                return
            time.sleep(0.5)
        raise LabError(f"{self.name} cannot reach {address} within {timeout} s")

    def unreachable(self, address, window=10):
        """No answer from `address` during the whole window."""
        deadline = time.monotonic() + window
        while time.monotonic() < deadline:
            if self.ping(address):
                raise LabError(f"{self.name} reached {address}, which must stay unreachable")
            time.sleep(0.5)

    def link_bytes(self, link):
        """(rx, tx) byte counters of one of this machine's links."""
        out = self.exec(["cat", f"/sys/class/net/{link}/statistics/rx_bytes",
                         f"/sys/class/net/{link}/statistics/tx_bytes"]).stdout.split()
        return int(out[0]), int(out[1])


class Lab:
    """Builds and tears down one scenario's machines, segments and nodes."""

    def __init__(self, binary, keep=False):
        self.binary = os.path.abspath(binary)
        self.keep = keep
        # Namespace names are short and unique per run.
        self.prefix = f"me{os.getpid() % 100000}"
        self.workdir = tempfile.mkdtemp(prefix="mesh-e2e-")
        self.machines = {}
        self.nodes = []
        self.switch = Machine(self, "sw")
        self.segments = {}
        self.veths = 0
        self.keys = {}

    # -- wires -------------------------------------------------------------

    def _veth(self):
        self.veths += 1
        return f"{self.prefix}v{self.veths}a", f"{self.prefix}v{self.veths}b"

    def machine(self, name):
        machine = Machine(self, name)
        self.machines[name] = machine
        return machine

    def segment(self, name, cidr_base):
        """An underlay segment: `cidr_base` is the first three octets, e.g. 198.18.1."""
        bridge = f"br{len(self.segments)}"
        self.switch.exec(["ip", "link", "add", bridge, "type", "bridge"])
        self.switch.exec(["ip", "link", "set", bridge, "up"])
        self.segments[name] = {"bridge": bridge, "base": cidr_base}

    def attach(self, machine, segment, host, delay_ms=None, loss=None):
        """Puts `machine` on `segment` with address base.host; returns (link, address)."""
        seg = self.segments[segment]
        outer, inner = self._veth()
        run(["ip", "link", "add", outer, "type", "veth", "peer", "name", inner])
        run(["ip", "link", "set", outer, "netns", self.switch.ns])
        run(["ip", "link", "set", inner, "netns", machine.ns])
        link = machine.next_link()
        machine.exec(["ip", "link", "set", inner, "name", link])
        address = f"{seg['base']}.{host}"
        machine.exec(["ip", "addr", "add", f"{address}/{UNDERLAY_PREFIX}", "dev", link])
        machine.exec(["ip", "link", "set", link, "up"])
        self.switch.exec(["ip", "link", "set", outer, "master", seg["bridge"]])
        self.switch.exec(["ip", "link", "set", outer, "up"])
        if delay_ms is not None or loss is not None:
            netem = ["tc", "qdisc", "add", "dev", link, "root", "netem"]
            if delay_ms is not None:
                netem += ["delay", f"{delay_ms}ms"]
            if loss is not None:
                netem += ["loss", f"{loss}%"]
            machine.exec(netem)
        machine.addresses[segment] = address
        return link, address

    def lan(self, gateway, host, cidr_base):
        """A LAN cidr_base.0/24 behind `gateway` (.1) with `host` (.10) on it.

        The host's default route points at the gateway, as a LAN device's
        would. Returns the host's address.
        """
        outer, inner = self._veth()
        run(["ip", "link", "add", outer, "type", "veth", "peer", "name", inner])
        run(["ip", "link", "set", outer, "netns", gateway.ns])
        run(["ip", "link", "set", inner, "netns", host.ns])
        glink, hlink = gateway.next_link(), host.next_link()
        gateway.exec(["ip", "link", "set", outer, "name", glink])
        host.exec(["ip", "link", "set", inner, "name", hlink])
        gateway.exec(["ip", "addr", "add", f"{cidr_base}.1/24", "dev", glink])
        host.exec(["ip", "addr", "add", f"{cidr_base}.10/24", "dev", hlink])
        gateway.exec(["ip", "link", "set", glink, "up"])
        host.exec(["ip", "link", "set", hlink, "up"])
        host.exec(["ip", "route", "add", "default", "via", f"{cidr_base}.1"])
        return f"{cidr_base}.10"

    def set_link(self, machine, link, up):
        machine.exec(["ip", "link", "set", link, "up" if up else "down"])

    # -- nodes -------------------------------------------------------------

    def key(self, name):
        if name not in self.keys:
            self.keys[name] = x25519_keypair(self.workdir, name)
        return self.keys[name]

    def node(self, machine, name, config, interface="anixmesh0"):
        node = Node(self, machine, name, config, interface)
        self.nodes.append(node)
        return node

    # -- teardown ----------------------------------------------------------

    def close(self, failed):
        for node in self.nodes:
            node.stop()
        if failed:
            for node in self.nodes:
                print(f"=== {node.name} ({node.machine.name})")
                print(node.logs())
        for machine in list(self.machines.values()) + [self.switch]:
            run(["ip", "netns", "del", machine.ns], check=False)
        if self.keep:
            print(f"kept {self.workdir}")
        else:
            shutil.rmtree(self.workdir, ignore_errors=True)


def mesh_config(lab, name, network, address, *, kind="managed", secure=None, cipher=None,
                members=None, listen=True, role="full", peers=(), relay=None,
                advertise=(), accept=None, secret=None, hostname=None):
    """A node configuration in the format of docs/architecture/mesh-module.md.

    `members` names the nodes whose static keys go into `native_keys`
    (managed networks); the node's own key is always set as `private_key`.
    `peers` is a list of (address, transport) pairs.
    """
    private, _ = lab.key(name)
    net = {"name": network, "secret": secret or f"{network}-secret", "kind": kind}
    if secure is not None:
        net["secure_mode"] = secure
    if cipher is not None:
        net["cipher"] = cipher
    if members is not None:
        net["native_keys"] = [lab.key(member)[1] for member in members]
    node = {"address": address, "role": role, "hostname": hostname or name}
    if kind == "managed" or secure:
        node["private_key"] = private
    if listen and role == "full":
        node["listen"] = [{"transport": "tcp", "port": LISTEN_PORT},
                          {"transport": "udp", "port": LISTEN_PORT}]
    if relay is not None:
        node["relay"] = relay
    config = {
        "config_version": 1,
        "network": net,
        "node": node,
        "peers": [{"server": server, "port": LISTEN_PORT, "transport": transport}
                  for server, transport in peers],
    }
    subnets = {}
    if advertise:
        subnets["advertise"] = list(advertise)
    if accept is not None:
        subnets["accept"] = list(accept)
    if subnets:
        config["subnets"] = subnets
    return config
