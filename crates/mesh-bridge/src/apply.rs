//! Installing, replacing and removing one network's bridge on the host.
//!
//! [`Bridge`] owns the nftables table of one mesh interface. Its
//! [`Bridge::status`] changes only after a new rule set loaded completely
//! (`docs/architecture/mesh-status.md`: `externalBridge`); a failed load
//! leaves the old rules and the old status in place and raises
//! `external_bridge_apply_failed`.
//!
//! IPv4 forwarding is needed for the bridge to forward at all. The shared
//! [`Forwarding`] turns it on while at least one bridge with IPv4 routes is
//! installed, and back off afterwards only if it was off before. IPv6
//! forwarding is never changed: turning it on makes Linux ignore router
//! advertisements on every interface (`accept_ra = 1`), which can take the
//! host's own IPv6 default route away. When a bridge has IPv6 routes and
//! IPv6 forwarding is off, the bridge raises
//! `external_bridge_ipv6_forwarding_off` and its IPv6 entries do not work
//! until an operator enables it.

use std::io;
use std::net::IpAddr;
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use std::io::Write as _;

use outbound_mesh::IpNet;

use crate::config::{valid_interface, BridgeError, ExternalBridge};
use crate::conntrack::{self, Flow};
use crate::ruleset::{self, COUNTER_INBOUND_DENIED, COUNTER_SOURCE_DENIED};
use crate::status::BridgeStatus;

/// `/proc/sys` path of the IPv4 forwarding switch.
pub const IPV4_FORWARD: &str = "/proc/sys/net/ipv4/ip_forward";
/// `/proc/sys` path of the IPv6 forwarding switch.
pub const IPV6_FORWARD: &str = "/proc/sys/net/ipv6/conf/all/forwarding";

/// Alert: loading the rules failed; the detail says why.
pub const ALERT_APPLY_FAILED: &str = "external_bridge_apply_failed";
/// Alert: the bridge has IPv6 entries and IPv6 forwarding is off.
pub const ALERT_IPV6_FORWARDING_OFF: &str = "external_bridge_ipv6_forwarding_off";

/// Where `nft` is looked for. A fixed list, not `PATH`: the node program
/// runs as root and must not run whatever an environment puts first.
pub const NFT_PATHS: [&str; 3] = ["/usr/sbin/nft", "/sbin/nft", "/usr/bin/nft"];

/// What the bridge needs from the host. [`SystemHost`] is the real one;
/// tests use a double.
pub trait Host: Send + Sync {
    /// Runs `nft` with `args`, writing `stdin` to it when given; the
    /// standard output on success, an error with the standard error
    /// otherwise.
    fn nft(&self, args: &[&str], stdin: Option<&str>) -> io::Result<String>;
    /// Reads a `/proc/sys` value, trimmed.
    fn read_sysctl(&self, path: &str) -> io::Result<String>;
    fn write_sysctl(&self, path: &str, value: &str) -> io::Result<()>;
    /// Every tracked connection (both address families).
    fn conntrack_flows(&self) -> io::Result<Vec<Flow>>;
    /// Deletes these tracked connections; one already gone is not an error.
    fn conntrack_delete(&self, flows: &[&Flow]) -> io::Result<()>;
}

/// The host itself.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemHost;

impl SystemHost {
    fn nft_path() -> io::Result<&'static str> {
        NFT_PATHS
            .iter()
            .copied()
            .find(|path| std::path::Path::new(path).is_file())
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "nft is not installed"))
    }
}

impl Host for SystemHost {
    fn nft(&self, args: &[&str], stdin: Option<&str>) -> io::Result<String> {
        let mut child = Command::new(Self::nft_path()?)
            .args(args)
            .env_clear()
            .stdin(if stdin.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        if let Some(input) = stdin {
            let mut pipe = child.stdin.take().expect("stdin is piped");
            pipe.write_all(input.as_bytes())?;
        }
        let output = child.wait_with_output()?;
        if output.status.success() {
            Ok(String::from_utf8_lossy(&output.stdout).into_owned())
        } else {
            let detail = String::from_utf8_lossy(&output.stderr);
            Err(io::Error::other(format!(
                "nft exited with {}: {}",
                output.status,
                detail.trim()
            )))
        }
    }

    fn read_sysctl(&self, path: &str) -> io::Result<String> {
        Ok(std::fs::read_to_string(path)?.trim().to_owned())
    }

    fn write_sysctl(&self, path: &str, value: &str) -> io::Result<()> {
        std::fs::write(path, value)
    }

    #[cfg(target_os = "linux")]
    fn conntrack_flows(&self) -> io::Result<Vec<Flow>> {
        conntrack::sys::flows()
    }

    #[cfg(target_os = "linux")]
    fn conntrack_delete(&self, flows: &[&Flow]) -> io::Result<()> {
        conntrack::sys::delete(flows)
    }

    #[cfg(not(target_os = "linux"))]
    fn conntrack_flows(&self) -> io::Result<Vec<Flow>> {
        Err(io::Error::from(io::ErrorKind::Unsupported))
    }

    #[cfg(not(target_os = "linux"))]
    fn conntrack_delete(&self, _flows: &[&Flow]) -> io::Result<()> {
        Err(io::Error::from(io::ErrorKind::Unsupported))
    }
}

/// Deletes the tracked connections from any of `pairs` (sources,
/// destinations). One dump, then one delete per selected entry.
fn flush(host: &dyn Host, pairs: &[(Vec<IpNet>, Vec<IpNet>)]) -> io::Result<usize> {
    if pairs.iter().all(|(s, d)| s.is_empty() || d.is_empty()) {
        return Ok(0);
    }
    let flows = host.conntrack_flows()?;
    let mut selected: Vec<&Flow> = Vec::new();
    for (sources, destinations) in pairs {
        for flow in conntrack::select(&flows, sources, destinations) {
            if !selected.iter().any(|seen| std::ptr::eq(*seen, flow)) {
                selected.push(flow);
            }
        }
    }
    host.conntrack_delete(&selected)?;
    Ok(selected.len())
}

/// The process-wide IPv4 forwarding switch, shared by all bridges.
pub struct Forwarding {
    host: Arc<dyn Host>,
    state: Mutex<ForwardingState>,
}

#[derive(Default)]
struct ForwardingState {
    holders: usize,
    /// Whether this process turned forwarding on and so must turn it off.
    turned_on: bool,
}

impl Forwarding {
    pub fn new(host: Arc<dyn Host>) -> Arc<Self> {
        Arc::new(Self {
            host,
            state: Mutex::new(ForwardingState::default()),
        })
    }

    /// Holds IPv4 forwarding on until the guard is dropped.
    pub fn hold(self: &Arc<Self>) -> io::Result<ForwardingGuard> {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if state.holders == 0 {
            let current = self.host.read_sysctl(IPV4_FORWARD)?;
            if current != "1" {
                self.host.write_sysctl(IPV4_FORWARD, "1")?;
                state.turned_on = true;
            }
        }
        state.holders += 1;
        Ok(ForwardingGuard {
            forwarding: Arc::clone(self),
        })
    }

    fn release(&self) {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        state.holders = state.holders.saturating_sub(1);
        if state.holders == 0 && state.turned_on {
            // Best effort: a failure leaves forwarding on, which only keeps
            // the host as it was while the bridge ran.
            let _ = self.host.write_sysctl(IPV4_FORWARD, "0");
            state.turned_on = false;
        }
    }

    /// Whether IPv6 forwarding is on; `false` when it cannot be read.
    pub fn ipv6_on(&self) -> bool {
        self.host
            .read_sysctl(IPV6_FORWARD)
            .map(|value| value == "1")
            .unwrap_or(false)
    }
}

/// Keeps IPv4 forwarding on while it lives.
pub struct ForwardingGuard {
    forwarding: Arc<Forwarding>,
}

impl Drop for ForwardingGuard {
    fn drop(&mut self) {
        self.forwarding.release();
    }
}

/// Why applying failed.
#[derive(Debug)]
pub enum ApplyError {
    /// The section does not fit the network (`invalid_argument`).
    Invalid(BridgeError),
    /// Forwarding or nftables failed; the old rules stay.
    Host(io::Error),
}

impl std::fmt::Display for ApplyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Invalid(error) => write!(f, "{error}"),
            Self::Host(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for ApplyError {}

/// One alert for the status API.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BridgeAlert {
    pub code: &'static str,
    pub detail: String,
}

/// Drop counters of one bridge.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Counters {
    /// Packets from the mesh refused by source or destination.
    pub source_denied: u64,
    /// New connections from the external network refused.
    pub inbound_denied: u64,
}

/// The bridge of one network on one mesh interface.
pub struct Bridge {
    host: Arc<dyn Host>,
    forwarding: Arc<Forwarding>,
    mesh_interface: String,
    installed: bool,
    guard: Option<ForwardingGuard>,
    status: Option<BridgeStatus>,
    failure: Option<String>,
    ipv6_off: bool,
    /// (allow, routes) of the rules now installed.
    rules: Option<(Vec<IpNet>, Vec<IpNet>)>,
    /// Tracked connections still to delete: from rules that were narrowed
    /// or removed while deleting them failed. Retried on every change; the
    /// status moves only once this is empty.
    pending: Vec<(Vec<IpNet>, Vec<IpNet>)>,
}

impl Bridge {
    /// Nothing is installed until [`Bridge::apply`].
    pub fn new(
        host: Arc<dyn Host>,
        forwarding: Arc<Forwarding>,
        mesh_interface: &str,
    ) -> Result<Self, BridgeError> {
        if !valid_interface(mesh_interface) {
            return Err(BridgeError::Interface);
        }
        Ok(Self {
            host,
            forwarding,
            mesh_interface: mesh_interface.to_owned(),
            installed: false,
            guard: None,
            status: None,
            failure: None,
            ipv6_off: false,
            rules: None,
            pending: Vec::new(),
        })
    }

    /// Installs `bridge`, or replaces what is installed, in one
    /// transaction. `local_addresses` are this node's own addresses in the
    /// network. On failure the previous rules, forwarding and status stay.
    pub fn apply(
        &mut self,
        bridge: &ExternalBridge,
        virtual_subnets: &[outbound_mesh::IpNet],
        local_addresses: &[IpAddr],
    ) -> Result<(), ApplyError> {
        bridge
            .check_mesh(&self.mesh_interface, virtual_subnets, local_addresses)
            .map_err(ApplyError::Invalid)?;
        let wants_v4 = bridge.routes().iter().any(|net| net.is_ipv4());
        let wants_v6 = bridge.routes().iter().any(|net| !net.is_ipv4());

        let new_guard = if wants_v4 && self.guard.is_none() {
            match self.forwarding.hold() {
                Ok(guard) => Some(guard),
                Err(error) => return Err(self.failed(error)),
            }
        } else {
            None
        };
        // A table this bridge did not install (left by an earlier process
        // of the same node) is replaced too; its lists are the old ones.
        if self.rules.is_none() {
            let table = ruleset::table_name(&self.mesh_interface);
            self.rules = self
                .host
                .nft(&["-j", "list", "table", "inet", &table], None)
                .ok()
                .and_then(|json| table_lists(&json).ok());
            self.installed |= self.rules.is_some();
        }
        let script = ruleset::render(bridge, &self.mesh_interface, local_addresses);
        if let Err(error) = self.host.nft(&["-f", "-"], Some(&script)) {
            // `new_guard` drops here, so forwarding goes back if this
            // attempt turned it on.
            drop(new_guard);
            return Err(self.failed(error));
        }
        self.installed = true;
        if let Some(guard) = new_guard {
            self.guard = Some(guard);
        } else if !wants_v4 {
            self.guard = None;
        }
        self.ipv6_off = wants_v6 && !self.forwarding.ipv6_on();
        // Connections set up under the old lists that the new ones no
        // longer allow would otherwise keep going (recheck #356 X3).
        if let Some((old_allow, old_routes)) = self.rules.take() {
            self.pending.extend(conntrack::narrowed(
                &old_allow,
                &old_routes,
                Some((bridge.allow(), bridge.routes())),
            ));
        }
        self.rules = Some((bridge.allow().to_vec(), bridge.routes().to_vec()));
        self.flush_pending().map_err(|error| self.failed(error))?;
        self.failure = None;
        self.status = Some(BridgeStatus::new(
            bridge.routes(),
            bridge.allow(),
            SystemTime::now(),
        ));
        Ok(())
    }

    /// Deletes the pending tracked connections; the status may move only
    /// when this succeeds.
    fn flush_pending(&mut self) -> io::Result<()> {
        if self.pending.is_empty() {
            return Ok(());
        }
        flush(self.host.as_ref(), &self.pending)
            .map_err(|error| io::Error::new(error.kind(), format!("conntrack: {error}")))?;
        self.pending.clear();
        Ok(())
    }

    fn failed(&mut self, error: io::Error) -> ApplyError {
        self.failure = Some(error.to_string());
        ApplyError::Host(error)
    }

    /// Removes the rules and releases forwarding. The status becomes `None`
    /// only once the table is gone.
    pub fn remove(&mut self) -> io::Result<()> {
        if self.installed {
            self.host
                .nft(
                    &["-f", "-"],
                    Some(&ruleset::render_removal(&self.mesh_interface)),
                )
                .inspect_err(|error| self.failure = Some(error.to_string()))?;
            self.installed = false;
        }
        self.guard = None;
        if let Some((old_allow, old_routes)) = self.rules.take() {
            self.pending
                .extend(conntrack::narrowed(&old_allow, &old_routes, None));
        }
        // Until the old connections are gone the status keeps the last
        // applied lists, so the panel does not release anything early.
        self.flush_pending()
            .inspect_err(|error| self.failure = Some(error.to_string()))?;
        self.status = None;
        self.failure = None;
        self.ipv6_off = false;
        Ok(())
    }

    /// `externalBridge` for the status API: `None` before the first
    /// successful apply and after removal.
    pub fn status(&self) -> Option<&BridgeStatus> {
        self.status.as_ref()
    }

    pub fn alerts(&self) -> Vec<BridgeAlert> {
        let mut alerts = Vec::new();
        if let Some(detail) = &self.failure {
            alerts.push(BridgeAlert {
                code: ALERT_APPLY_FAILED,
                detail: detail.clone(),
            });
        }
        if self.ipv6_off {
            alerts.push(BridgeAlert {
                code: ALERT_IPV6_FORWARDING_OFF,
                detail: IPV6_FORWARD.to_owned(),
            });
        }
        alerts
    }

    /// The drop counters; zero before anything is installed.
    pub fn counters(&self) -> io::Result<Counters> {
        if !self.installed {
            return Ok(Counters::default());
        }
        let table = ruleset::table_name(&self.mesh_interface);
        let json = self
            .host
            .nft(&["-j", "list", "counters", "table", "inet", &table], None)?;
        parse_counters(&json)
    }
}

impl Drop for Bridge {
    fn drop(&mut self) {
        let _ = self.remove();
    }
}

/// Whether this host can run a bridge (spec §15.12; recheck of #357 Y1):
/// `nft` is present and the kernel accepts what a bridge loads, `inet` NAT
/// with `masquerade` included. The probe table is created and deleted in
/// one transaction, so nothing stays. A node declares
/// [`crate::FEATURE`] only when this succeeds.
pub fn probe(host: &dyn Host) -> io::Result<()> {
    host.nft(&["-f", "-"], Some(&ruleset::render_probe()))
        .map(|_| ())
}

/// Removes every bridge table this program may have left on the host
/// (spec §15.12 item 9): at start-up, before anything is installed again,
/// to clear what a crashed run left; and at exit, after the bridges are
/// dropped. Only tables carrying our mark ([`ruleset::is_own_table`]) are
/// deleted, all in one transaction. Returns how many were removed; a host
/// without `nft` has none.
///
/// A crash also leaves IPv4 forwarding as the bridge set it; this function
/// does not change forwarding, because it cannot tell whether the host had
/// it on before (see `docs/architecture/mesh-bridge.md`).
pub fn cleanup_all(host: &dyn Host) -> io::Result<usize> {
    let json = match host.nft(&["-j", "list", "tables"], None) {
        Ok(json) => json,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(0),
        Err(error) => return Err(error),
    };
    let tables = parse_tables(&json)?;
    let refs = tables.iter().map(|(f, n)| (f.as_str(), n.as_str()));
    let Some(script) = ruleset::render_cleanup(refs) else {
        return Ok(0);
    };
    // The lists of each table, read before it goes, say which tracked
    // connections were set up through it (recheck #356 X3). A table whose
    // lists cannot be read still goes; the error is reported afterwards
    // rather than guessing a wider set of connections to cut.
    let mut pairs = Vec::new();
    let mut unread = None;
    for line in script.lines() {
        let name = line.trim_start_matches("delete table inet ");
        match host
            .nft(&["-j", "list", "table", "inet", name], None)
            .and_then(|json| table_lists(&json))
        {
            Ok(lists) => pairs.push(lists),
            Err(error) => unread = Some(error),
        }
    }
    let count = script.lines().count();
    host.nft(&["-f", "-"], Some(&script))?;
    flush(host, &pairs)
        .map_err(|error| io::Error::new(error.kind(), format!("conntrack: {error}")))?;
    if let Some(error) = unread {
        return Err(io::Error::new(
            error.kind(),
            format!(
                "rules removed, but their lists could not be read to clear tracked connections: {error}"
            ),
        ));
    }
    Ok(count)
}

/// (allow, routes) of one of our tables in `nft -j list table`.
pub fn table_lists(json: &str) -> io::Result<(Vec<IpNet>, Vec<IpNet>)> {
    let value: serde_json::Value = serde_json::from_str(json)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    let items = value
        .get("nftables")
        .and_then(|items| items.as_array())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "no nftables array"))?;
    let mut allow = Vec::new();
    let mut routes = Vec::new();
    for set in items.iter().filter_map(|item| item.get("set")) {
        let target = match set.get("name").and_then(|n| n.as_str()) {
            Some("allow_v4" | "allow_v6") => &mut allow,
            Some("routes_v4" | "routes_v6") => &mut routes,
            _ => continue,
        };
        let Some(elements) = set.get("elem").and_then(|e| e.as_array()) else {
            continue;
        };
        for element in elements {
            target.extend(element_nets(element).ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("unexpected set element {element}"),
                )
            })?);
        }
    }
    Ok((allow, routes))
}

/// One set element as networks: an address, `{"prefix": {addr, len}}`, or
/// `{"range": [first, last]}` split into prefixes.
fn element_nets(element: &serde_json::Value) -> Option<Vec<IpNet>> {
    if let Some(text) = element.as_str() {
        return Some(vec![IpNet::host(text.parse().ok()?)]);
    }
    if let Some(prefix) = element.get("prefix") {
        let address: IpAddr = prefix.get("addr")?.as_str()?.parse().ok()?;
        let len = u8::try_from(prefix.get("len")?.as_u64()?).ok()?;
        return Some(vec![IpNet::new(address, len)?]);
    }
    if let Some(range) = element.get("range").and_then(|r| r.as_array()) {
        let first: IpAddr = range.first()?.as_str()?.parse().ok()?;
        let last: IpAddr = range.get(1)?.as_str()?.parse().ok()?;
        return range_nets(first, last);
    }
    None
}

/// The prefixes that exactly cover `first..=last` (same family).
fn range_nets(first: IpAddr, last: IpAddr) -> Option<Vec<IpNet>> {
    let (mut start, end, bits, v4) = match (first, last) {
        (IpAddr::V4(a), IpAddr::V4(b)) => (
            u128::from(u32::from(a)),
            u128::from(u32::from(b)),
            32u32,
            true,
        ),
        (IpAddr::V6(a), IpAddr::V6(b)) => (u128::from(a), u128::from(b), 128u32, false),
        _ => return None,
    };
    if start > end {
        return None;
    }
    let mut nets = Vec::new();
    loop {
        // Largest block aligned at `start` that does not pass `end`.
        let mut size = if start == 0 {
            bits
        } else {
            start.trailing_zeros().min(bits)
        };
        while size > 0 && (size >= 128 || start + ((1u128 << size) - 1) > end) {
            size -= 1;
        }
        let address = if v4 {
            IpAddr::V4(std::net::Ipv4Addr::from(start as u32))
        } else {
            IpAddr::V6(std::net::Ipv6Addr::from(start))
        };
        nets.push(IpNet::new(address, (bits - size) as u8)?);
        let block_end = start + ((1u128 << size) - 1);
        if block_end >= end {
            break;
        }
        start = block_end + 1;
    }
    Some(nets)
}

/// (family, name) of each table in `nft -j list tables`.
pub fn parse_tables(json: &str) -> io::Result<Vec<(String, String)>> {
    let value: serde_json::Value = serde_json::from_str(json)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    let items = value
        .get("nftables")
        .and_then(|items| items.as_array())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "no nftables array"))?;
    Ok(items
        .iter()
        .filter_map(|item| item.get("table"))
        .filter_map(|table| {
            let family = table.get("family")?.as_str()?;
            let name = table.get("name")?.as_str()?;
            Some((family.to_owned(), name.to_owned()))
        })
        .collect())
}

/// Reads our two counters from `nft -j list counters`.
pub fn parse_counters(json: &str) -> io::Result<Counters> {
    let value: serde_json::Value = serde_json::from_str(json)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    let mut counters = Counters::default();
    let items = value
        .get("nftables")
        .and_then(|items| items.as_array())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "no nftables array"))?;
    for item in items {
        let Some(counter) = item.get("counter") else {
            continue;
        };
        let packets = counter.get("packets").and_then(|p| p.as_u64()).unwrap_or(0);
        match counter.get("name").and_then(|n| n.as_str()) {
            Some(COUNTER_SOURCE_DENIED) => counters.source_denied = packets,
            Some(COUNTER_INBOUND_DENIED) => counters.inbound_denied = packets,
            _ => {}
        }
    }
    Ok(counters)
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;
    use crate::config::ExternalBridgeConfig;
    use crate::status::digest;

    #[derive(Default)]
    struct FakeHost {
        sysctl: Mutex<HashMap<String, String>>,
        scripts: Mutex<Vec<String>>,
        fail_nft: Mutex<bool>,
        /// (family, name) of the tables "on the host".
        tables: Mutex<Vec<(String, String)>>,
        /// The last script that created each table, to list its sets.
        table_scripts: Mutex<HashMap<String, String>>,
        /// Tracked connections "in the kernel".
        flows: Mutex<Vec<Flow>>,
        fail_conntrack: Mutex<bool>,
    }

    impl FakeHost {
        fn with_forwarding(v4: &str, v6: &str) -> Arc<Self> {
            let host = Self::default();
            host.sysctl
                .lock()
                .unwrap()
                .insert(IPV4_FORWARD.into(), v4.into());
            host.sysctl
                .lock()
                .unwrap()
                .insert(IPV6_FORWARD.into(), v6.into());
            Arc::new(host)
        }
        fn v4(&self) -> String {
            self.sysctl.lock().unwrap()[IPV4_FORWARD].clone()
        }
    }

    impl Host for FakeHost {
        fn nft(&self, args: &[&str], stdin: Option<&str>) -> io::Result<String> {
            if *self.fail_nft.lock().unwrap() {
                return Err(io::Error::other("nft exited with 1: Error: syntax error"));
            }
            if args == ["-j", "list", "tables"] {
                let tables: Vec<String> = self
                    .tables
                    .lock()
                    .unwrap()
                    .iter()
                    .map(|(family, name)| {
                        format!(r#"{{"table":{{"family":"{family}","name":"{name}","handle":1}}}}"#)
                    })
                    .collect();
                return Ok(format!(
                    r#"{{"nftables":[{{"metainfo":{{"json_schema_version":1}}}},{}]}}"#,
                    tables.join(",")
                ));
            }
            if let ["-j", "list", "table", "inet", name] = args {
                let scripts = self.table_scripts.lock().unwrap();
                let script = scripts
                    .get(*name)
                    .ok_or_else(|| io::Error::other("no such table"))?;
                return Ok(fake_table_json(script));
            }
            if args[0] == "-j" {
                return Ok(r#"{"nftables":[{"metainfo":{}},{"counter":{"name":"source_denied","packets":3,"bytes":180}},{"counter":{"name":"inbound_denied","packets":7,"bytes":420}}]}"#.into());
            }
            // Keep the table list in step with the scripts, as nft would.
            let script = stdin.unwrap_or_default();
            let mut tables = self.tables.lock().unwrap();
            for line in script.lines() {
                if let Some(name) = line.strip_prefix("delete table inet ") {
                    tables.retain(|(f, n)| !(f == "inet" && n == name));
                    self.table_scripts.lock().unwrap().remove(name);
                } else if let Some(rest) = line.strip_prefix("table inet ") {
                    if rest.ends_with(" {") {
                        self.table_scripts
                            .lock()
                            .unwrap()
                            .insert(rest.trim_end_matches(" {").to_owned(), script.to_owned());
                    }
                    let name = rest.trim_end_matches(" {").to_owned();
                    if !tables.iter().any(|(f, n)| f == "inet" && *n == name) {
                        tables.push(("inet".into(), name));
                    }
                }
            }
            drop(tables);
            self.scripts
                .lock()
                .unwrap()
                .push(stdin.unwrap_or_default().into());
            Ok(String::new())
        }
        fn read_sysctl(&self, path: &str) -> io::Result<String> {
            self.sysctl
                .lock()
                .unwrap()
                .get(path)
                .cloned()
                .ok_or_else(|| io::Error::from(io::ErrorKind::NotFound))
        }
        fn write_sysctl(&self, path: &str, value: &str) -> io::Result<()> {
            self.sysctl
                .lock()
                .unwrap()
                .insert(path.into(), value.into());
            Ok(())
        }
        fn conntrack_flows(&self) -> io::Result<Vec<Flow>> {
            if *self.fail_conntrack.lock().unwrap() {
                return Err(io::Error::from(io::ErrorKind::PermissionDenied));
            }
            Ok(self.flows.lock().unwrap().clone())
        }
        fn conntrack_delete(&self, flows: &[&Flow]) -> io::Result<()> {
            self.flows
                .lock()
                .unwrap()
                .retain(|flow| !flows.contains(&flow));
            Ok(())
        }
    }

    /// `nft -j list table` for a table the fake created: its sets with the
    /// elements of the script, prefixes as nft prints them.
    fn fake_table_json(script: &str) -> String {
        let mut sets = Vec::new();
        let mut current: Option<&str> = None;
        for line in script.lines() {
            let line = line.trim();
            if let Some(name) = line.strip_prefix("set ").and_then(|l| l.strip_suffix(" {")) {
                current = Some(name);
            } else if let (Some(name), Some(list)) = (
                current,
                line.strip_prefix("elements = { ")
                    .and_then(|l| l.strip_suffix(" }")),
            ) {
                let elements: Vec<String> = list
                    .split(", ")
                    .map(|element| match element.split_once('/') {
                        Some((addr, len)) if len != "32" && len != "128" => {
                            format!(r#"{{"prefix":{{"addr":"{addr}","len":{len}}}}}"#)
                        }
                        Some((addr, _)) => format!(r#""{addr}""#),
                        None => format!(r#""{element}""#),
                    })
                    .collect();
                sets.push(format!(
                    r#"{{"set":{{"family":"inet","name":"{name}","elem":[{}]}}}}"#,
                    elements.join(",")
                ));
            } else if line == "}" {
                current = None;
            }
        }
        format!(r#"{{"nftables":[{{"metainfo":{{}}}},{}]}}"#, sets.join(","))
    }

    fn flow(src: &str, dst: &str) -> Flow {
        conntrack::test_flow(src.parse().unwrap(), dst.parse().unwrap())
    }

    fn flows(host: &FakeHost) -> Vec<(String, String)> {
        host.flows
            .lock()
            .unwrap()
            .iter()
            .map(|f| (f.source.to_string(), f.destination.to_string()))
            .collect()
    }

    fn pair(a: &str, b: &str) -> (String, String) {
        (a.to_string(), b.to_string())
    }

    #[test]
    fn narrowing_the_lists_cuts_the_connections_they_no_longer_allow() {
        let (host, forwarding) = setup("1", "1");
        let mut bridge = Bridge::new(host.clone(), forwarding, "anixmesh-0").unwrap();
        bridge
            .apply(
                &checked(
                    &["100.64.0.5", "100.64.0.6"],
                    &["10.150.0.2/32", "10.150.0.3/32"],
                ),
                &subnet(),
                &[],
            )
            .unwrap();
        host.flows.lock().unwrap().extend([
            flow("10.150.0.2", "100.64.0.5"),
            flow("10.150.0.3", "100.64.0.5"),
            flow("10.150.0.2", "100.64.0.6"),
            // Not through the bridge.
            flow("10.150.0.3", "10.150.0.1"),
            flow("100.64.0.5", "100.100.0.1"),
        ]);
        // 10.150.0.3 leaves the list.
        bridge
            .apply(
                &checked(&["100.64.0.5", "100.64.0.6"], &["10.150.0.2/32"]),
                &subnet(),
                &[],
            )
            .unwrap();
        assert_eq!(
            flows(&host),
            [
                pair("10.150.0.2", "100.64.0.5"),
                pair("10.150.0.2", "100.64.0.6"),
                pair("10.150.0.3", "10.150.0.1"),
                pair("100.64.0.5", "100.100.0.1"),
            ]
        );
        // 100.64.0.6 leaves the routes.
        bridge
            .apply(
                &checked(&["100.64.0.5"], &["10.150.0.2/32"]),
                &subnet(),
                &[],
            )
            .unwrap();
        assert_eq!(flows(&host).len(), 3);
        // Removal cuts the rest of the bridged ones.
        bridge.remove().unwrap();
        assert_eq!(
            flows(&host),
            [
                pair("10.150.0.3", "10.150.0.1"),
                pair("100.64.0.5", "100.100.0.1"),
            ]
        );
    }

    #[test]
    fn the_probe_leaves_no_table_and_reports_a_refusal() {
        let (host, _) = setup("0", "0");
        probe(host.as_ref()).unwrap();
        assert!(host.tables.lock().unwrap().is_empty());
        *host.fail_nft.lock().unwrap() = true;
        assert!(probe(host.as_ref()).is_err());
    }

    #[test]
    fn a_table_left_by_an_earlier_process_counts_as_the_old_lists() {
        let (host, forwarding) = setup("1", "1");
        let mut earlier = Bridge::new(host.clone(), forwarding.clone(), "anixmesh-0").unwrap();
        earlier
            .apply(
                &checked(&["100.64.0.5"], &["10.150.0.2/32", "10.150.0.3/32"]),
                &subnet(),
                &[],
            )
            .unwrap();
        std::mem::forget(earlier);
        host.flows.lock().unwrap().extend([
            flow("10.150.0.2", "100.64.0.5"),
            flow("10.150.0.3", "100.64.0.5"),
        ]);
        let mut bridge = Bridge::new(host.clone(), forwarding, "anixmesh-0").unwrap();
        bridge
            .apply(
                &checked(&["100.64.0.5"], &["10.150.0.2/32"]),
                &subnet(),
                &[],
            )
            .unwrap();
        assert_eq!(flows(&host), [pair("10.150.0.2", "100.64.0.5")]);
        // The adopted table is this bridge's to remove.
        bridge.remove().unwrap();
        assert!(flows(&host).is_empty());
        assert!(host.tables.lock().unwrap().is_empty());
    }

    #[test]
    fn the_status_waits_until_the_old_connections_are_gone() {
        let (host, forwarding) = setup("1", "1");
        let mut bridge = Bridge::new(host.clone(), forwarding, "anixmesh-0").unwrap();
        let wide = checked(&["100.64.0.5"], &["10.150.0.2/32", "10.150.0.3/32"]);
        bridge.apply(&wide, &subnet(), &[]).unwrap();
        let before = bridge.status().unwrap().clone();
        host.flows
            .lock()
            .unwrap()
            .push(flow("10.150.0.3", "100.64.0.5"));

        *host.fail_conntrack.lock().unwrap() = true;
        let narrow = checked(&["100.64.0.5"], &["10.150.0.2/32"]);
        assert!(bridge.apply(&narrow, &subnet(), &[]).is_err());
        assert_eq!(bridge.status(), Some(&before), "not applied yet");
        assert_eq!(bridge.alerts()[0].code, ALERT_APPLY_FAILED);
        assert!(bridge.alerts()[0].detail.starts_with("conntrack:"));

        // The next attempt retries what is pending.
        *host.fail_conntrack.lock().unwrap() = false;
        bridge.apply(&narrow, &subnet(), &[]).unwrap();
        assert_eq!(bridge.status().unwrap().allow_count, 1);
        assert!(flows(&host).is_empty());

        // Removal keeps the status until the connections are gone too.
        host.flows
            .lock()
            .unwrap()
            .push(flow("10.150.0.2", "100.64.0.5"));
        *host.fail_conntrack.lock().unwrap() = true;
        assert!(bridge.remove().is_err());
        assert!(bridge.status().is_some());
        *host.fail_conntrack.lock().unwrap() = false;
        bridge.remove().unwrap();
        assert!(bridge.status().is_none());
        assert!(flows(&host).is_empty());
    }

    #[test]
    fn startup_cleanup_also_cuts_the_crashed_runs_connections() {
        let (host, forwarding) = setup("1", "1");
        let mut crashed = Bridge::new(host.clone(), forwarding, "anixmesh-0").unwrap();
        crashed
            .apply(
                &checked(
                    &["100.64.0.5", "192.168.50.0/24"],
                    &["10.127.0.0/24", "10.150.0.2/32"],
                ),
                &subnet(),
                &[],
            )
            .unwrap();
        std::mem::forget(crashed);
        host.flows.lock().unwrap().extend([
            flow("10.127.0.9", "192.168.50.7"),
            flow("10.150.0.2", "100.64.0.5"),
            flow("10.150.0.4", "100.64.0.5"),
        ]);
        assert_eq!(cleanup_all(host.as_ref()).unwrap(), 1);
        assert_eq!(flows(&host), [pair("10.150.0.4", "100.64.0.5")]);
    }

    #[test]
    fn set_elements_are_read_in_every_form_nft_prints() {
        let json = r#"{"nftables":[{"metainfo":{}},
            {"set":{"family":"inet","name":"allow_v4","elem":["10.150.0.2",{"prefix":{"addr":"10.127.0.0","len":24}},{"range":["10.0.0.1","10.0.0.6"]}]}},
            {"set":{"family":"inet","name":"routes_v6","elem":["fd7a:115c:a1e0::9"]}},
            {"set":{"family":"inet","name":"local_v4","elem":["10.150.0.1"]}},
            {"set":{"family":"inet","name":"routes_v4"}}]}"#;
        let (allow, routes) = table_lists(json).unwrap();
        let allow: Vec<String> = allow.iter().map(|n| n.to_string()).collect();
        assert_eq!(
            allow,
            [
                "10.150.0.2/32",
                "10.127.0.0/24",
                "10.0.0.1/32",
                "10.0.0.2/31",
                "10.0.0.4/31",
                "10.0.0.6/32"
            ]
        );
        let routes: Vec<String> = routes.iter().map(|n| n.to_string()).collect();
        assert_eq!(routes, ["fd7a:115c:a1e0::9/128"]);
        assert!(
            table_lists(r#"{"nftables":[{"set":{"name":"allow_v4","elem":[{"weird":1}]}}]}"#)
                .is_err()
        );
        let all: Vec<String> = range_nets(
            "0.0.0.0".parse().unwrap(),
            "255.255.255.255".parse().unwrap(),
        )
        .unwrap()
        .iter()
        .map(|n| n.to_string())
        .collect();
        assert_eq!(all, ["0.0.0.0/0"]);
        assert!(range_nets("10.0.0.2".parse().unwrap(), "10.0.0.1".parse().unwrap()).is_none());
    }

    fn checked(routes: &[&str], allow: &[&str]) -> ExternalBridge {
        ExternalBridgeConfig {
            interface: "ext0".into(),
            routes: routes.iter().map(|s| s.to_string()).collect(),
            allow: allow.iter().map(|s| s.to_string()).collect(),
        }
        .validate()
        .unwrap()
    }

    fn setup(v4: &str, v6: &str) -> (Arc<FakeHost>, Arc<Forwarding>) {
        let host = FakeHost::with_forwarding(v4, v6);
        let forwarding = Forwarding::new(host.clone());
        (host, forwarding)
    }

    fn subnet() -> Vec<outbound_mesh::IpNet> {
        vec![outbound_mesh::IpNet::parse("10.150.0.0/16").unwrap()]
    }

    #[test]
    fn status_follows_a_successful_apply_only() {
        let (host, forwarding) = setup("0", "0");
        let mut bridge = Bridge::new(host.clone(), forwarding, "anixmesh-0").unwrap();
        assert!(bridge.status().is_none());

        let first = checked(&["100.64.0.1"], &["10.150.0.2/32"]);
        bridge.apply(&first, &subnet(), &[]).unwrap();
        let status = bridge.status().unwrap().clone();
        assert_eq!(status.allow_digest, digest(first.allow()));
        assert_eq!(status.routes_digest, digest(first.routes()));
        assert_eq!(status.allow_count, 1);

        *host.fail_nft.lock().unwrap() = true;
        let second = checked(&["100.64.0.1"], &[]);
        assert!(matches!(
            bridge.apply(&second, &subnet(), &[]),
            Err(ApplyError::Host(_))
        ));
        assert_eq!(bridge.status(), Some(&status), "old status stays");
        assert_eq!(bridge.alerts()[0].code, ALERT_APPLY_FAILED);

        *host.fail_nft.lock().unwrap() = false;
        bridge.apply(&second, &subnet(), &[]).unwrap();
        assert_eq!(bridge.status().unwrap().allow_count, 0);
        assert!(bridge.alerts().is_empty());

        bridge.remove().unwrap();
        assert!(bridge.status().is_none());
        let scripts = host.scripts.lock().unwrap();
        assert!(scripts
            .last()
            .unwrap()
            .ends_with("delete table inet anixops_bridge_616e69786d6573682d30\n"));
    }

    #[test]
    fn forwarding_is_turned_on_once_and_back_off_after_the_last_bridge() {
        let (host, forwarding) = setup("0", "1");
        let mut a = Bridge::new(host.clone(), forwarding.clone(), "anixmesh-0").unwrap();
        let mut b = Bridge::new(host.clone(), forwarding.clone(), "anixmesh-1").unwrap();
        let config = checked(&["100.64.0.1"], &["10.150.0.2/32"]);
        a.apply(&config, &subnet(), &[]).unwrap();
        b.apply(&config, &subnet(), &[]).unwrap();
        a.apply(&config, &subnet(), &[]).unwrap();
        assert_eq!(host.v4(), "1");
        a.remove().unwrap();
        assert_eq!(host.v4(), "1", "b still needs it");
        drop(b);
        assert_eq!(host.v4(), "0");
    }

    #[test]
    fn forwarding_that_was_on_stays_on() {
        let (host, forwarding) = setup("1", "1");
        let mut bridge = Bridge::new(host.clone(), forwarding, "anixmesh-0").unwrap();
        bridge
            .apply(&checked(&["100.64.0.1"], &[]), &subnet(), &[])
            .unwrap();
        bridge.remove().unwrap();
        assert_eq!(host.v4(), "1");
    }

    #[test]
    fn a_failed_first_apply_gives_forwarding_back() {
        let (host, forwarding) = setup("0", "1");
        *host.fail_nft.lock().unwrap() = true;
        let mut bridge = Bridge::new(host.clone(), forwarding, "anixmesh-0").unwrap();
        assert!(bridge
            .apply(&checked(&["100.64.0.1"], &[]), &subnet(), &[])
            .is_err());
        assert_eq!(host.v4(), "0");
        assert!(bridge.status().is_none());
    }

    #[test]
    fn ipv6_forwarding_is_reported_not_changed() {
        let (host, forwarding) = setup("1", "0");
        let mut bridge = Bridge::new(host.clone(), forwarding, "anixmesh-0").unwrap();
        bridge
            .apply(&checked(&["fd7a:115c:a1e0::1"], &[]), &subnet(), &[])
            .unwrap();
        assert_eq!(bridge.alerts()[0].code, ALERT_IPV6_FORWARDING_OFF);
        assert_eq!(host.sysctl.lock().unwrap()[IPV6_FORWARD], "0");
    }

    #[test]
    fn mesh_conflicts_are_invalid_and_change_nothing() {
        let (host, forwarding) = setup("0", "0");
        let mut bridge = Bridge::new(host.clone(), forwarding, "ext0").unwrap();
        assert!(matches!(
            bridge.apply(&checked(&["100.64.0.1"], &[]), &subnet(), &[]),
            Err(ApplyError::Invalid(BridgeError::SameInterface))
        ));
        assert!(host.scripts.lock().unwrap().is_empty());
        assert_eq!(host.v4(), "0");
    }

    #[test]
    fn counters_are_read_from_the_table() {
        let (host, forwarding) = setup("1", "1");
        let mut bridge = Bridge::new(host, forwarding, "anixmesh-0").unwrap();
        assert_eq!(bridge.counters().unwrap(), Counters::default());
        bridge
            .apply(&checked(&["100.64.0.1"], &[]), &subnet(), &[])
            .unwrap();
        assert_eq!(
            bridge.counters().unwrap(),
            Counters {
                source_denied: 3,
                inbound_denied: 7
            }
        );
    }

    fn tables(host: &FakeHost) -> Vec<(String, String)> {
        host.tables.lock().unwrap().clone()
    }

    #[test]
    fn startup_cleanup_removes_what_a_crashed_run_left() {
        let (host, forwarding) = setup("1", "1");
        host.tables.lock().unwrap().extend([
            ("inet".to_string(), "filter".to_string()),
            ("ip".to_string(), "nat".to_string()),
            // Another program's table that only looks similar.
            ("inet".to_string(), "anixops_bridge_other".to_string()),
        ]);
        let config = checked(&["100.64.0.1"], &["10.150.0.2/32"]);
        // A run that crashed: its rules stay on the host.
        let mut crashed = Bridge::new(host.clone(), forwarding.clone(), "anixmesh-0").unwrap();
        crashed.apply(&config, &subnet(), &[]).unwrap();
        let mut second = Bridge::new(host.clone(), forwarding.clone(), "anixmesh-1").unwrap();
        second.apply(&config, &subnet(), &[]).unwrap();
        std::mem::forget(crashed);
        std::mem::forget(second);
        assert_eq!(tables(&host).len(), 5);

        // The next start clears them before installing anything.
        assert_eq!(cleanup_all(host.as_ref()).unwrap(), 2);
        let left = tables(&host);
        assert_eq!(
            left,
            [
                ("inet".to_string(), "filter".to_string()),
                ("ip".to_string(), "nat".to_string()),
                ("inet".to_string(), "anixops_bridge_other".to_string()),
            ]
        );
        // Both deletions went in one transaction.
        let scripts = host.scripts.lock().unwrap();
        assert_eq!(scripts.last().unwrap().lines().count(), 2);
        drop(scripts);
        // Nothing left: no script is run.
        let before = host.scripts.lock().unwrap().len();
        assert_eq!(cleanup_all(host.as_ref()).unwrap(), 0);
        assert_eq!(host.scripts.lock().unwrap().len(), before);

        // Reinstalling after the cleanup works as on a clean host.
        let mut fresh = Bridge::new(host.clone(), forwarding, "anixmesh-0").unwrap();
        fresh.apply(&config, &subnet(), &[]).unwrap();
        assert_eq!(tables(&host).len(), 4);
    }

    #[test]
    fn exit_cleanup_removes_every_bridge_and_only_ours() {
        let (host, forwarding) = setup("0", "1");
        host.tables
            .lock()
            .unwrap()
            .push(("inet".to_string(), "filter".to_string()));
        let config = checked(&["100.64.0.1"], &["10.150.0.2/32"]);
        let mut a = Bridge::new(host.clone(), forwarding.clone(), "anixmesh-0").unwrap();
        let mut b = Bridge::new(host.clone(), forwarding.clone(), "anixmesh-1").unwrap();
        a.apply(&config, &subnet(), &[]).unwrap();
        b.apply(&config, &subnet(), &[]).unwrap();
        // Exit: the bridges are dropped, then everything marked is cleared.
        drop(a);
        drop(b);
        assert_eq!(cleanup_all(host.as_ref()).unwrap(), 0);
        assert_eq!(tables(&host), [("inet".to_string(), "filter".to_string())]);
        assert_eq!(host.v4(), "0");
    }

    #[test]
    fn a_host_without_nft_has_nothing_to_clean() {
        struct NoNft;
        impl Host for NoNft {
            fn nft(&self, _: &[&str], _: Option<&str>) -> io::Result<String> {
                Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    "nft is not installed",
                ))
            }
            fn read_sysctl(&self, _: &str) -> io::Result<String> {
                Ok("0".into())
            }
            fn write_sysctl(&self, _: &str, _: &str) -> io::Result<()> {
                Ok(())
            }
            fn conntrack_flows(&self) -> io::Result<Vec<Flow>> {
                Ok(Vec::new())
            }
            fn conntrack_delete(&self, _: &[&Flow]) -> io::Result<()> {
                Ok(())
            }
        }
        assert_eq!(cleanup_all(&NoNft).unwrap(), 0);
    }

    #[test]
    fn tables_are_read_from_nft_json() {
        let json = r#"{"nftables":[{"metainfo":{"version":"1.1.1"}},{"table":{"family":"inet","name":"anixops_bridge_6130","handle":3}},{"table":{"family":"ip","name":"nat","handle":4}}]}"#;
        assert_eq!(
            parse_tables(json).unwrap(),
            [
                ("inet".to_string(), "anixops_bridge_6130".to_string()),
                ("ip".to_string(), "nat".to_string())
            ]
        );
        assert!(parse_tables("{}").is_err());
    }

    #[test]
    fn bad_mesh_interface_names_are_refused() {
        let (host, forwarding) = setup("1", "1");
        assert!(Bridge::new(host, forwarding, "a\"b").is_err());
    }
}
