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

use crate::config::{valid_interface, BridgeError, ExternalBridge};
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
        self.failure = None;
        self.status = Some(BridgeStatus::new(
            bridge.routes(),
            bridge.allow(),
            SystemTime::now(),
        ));
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
    let count = script.lines().count();
    host.nft(&["-f", "-"], Some(&script))?;
    Ok(count)
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
            if args[0] == "-j" {
                return Ok(r#"{"nftables":[{"metainfo":{}},{"counter":{"name":"source_denied","packets":3,"bytes":180}},{"counter":{"name":"inbound_denied","packets":7,"bytes":420}}]}"#.into());
            }
            // Keep the table list in step with the scripts, as nft would.
            let script = stdin.unwrap_or_default();
            let mut tables = self.tables.lock().unwrap();
            for line in script.lines() {
                if let Some(name) = line.strip_prefix("delete table inet ") {
                    tables.retain(|(f, n)| !(f == "inet" && n == name));
                } else if let Some(rest) = line.strip_prefix("table inet ") {
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
