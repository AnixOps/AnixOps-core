//! Host changes a macOS full node needs to carry its advertised subnets
//! (spec §15.1, requirement R10): IP forwarding, and source address
//! translation of mesh traffic leaving through the LAN interface, so that
//! hosts on the LAN answer this machine instead of needing a route back.
//!
//! - Forwarding is the system-wide `net.inet.ip.forwarding` (and
//!   `net.inet6.ip6.forwarding` when the node has IPv6). The original values
//!   and every process holding them are kept in one state file under a lock;
//!   the last holder to leave restores them. A holder that died is dropped
//!   at the next change, so a crash never leaves forwarding on for good.
//! - Translation is a pf anchor below `com.apple/`, which the system's
//!   `/etc/pf.conf` already evaluates (`nat-anchor "com.apple/*"`). The
//!   anchor holds only `nat` rules: from the mesh (the virtual subnets and
//!   the subnets routed into the mesh) to the advertised subnets, on the LAN
//!   interfaces that carry them. pf is enabled with a reference token
//!   (`pfctl -E`) and the token released on the way out (`pfctl -X`), so a
//!   pf another program enabled stays enabled. Rules are replaced as a
//!   whole when the routed subnets change.
//!
//! `pfctl` runs from its fixed path with fixed arguments; the rules go to
//! its standard input and contain only addresses and interface names read
//! from the system.

use std::collections::BTreeSet;
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, Write};
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use outbound_mesh::IpNet;
use serde::{Deserialize, Serialize};

/// Where the shared state file lives.
pub const STATE_DIR: &str = "/Library/AnixOps/mesh";
/// The shared state file.
pub const STATE_FILE: &str = "host-forwarding.json";

const PFCTL: &str = "/sbin/pfctl";
const FORWARDING_V4: &str = "net.inet.ip.forwarding";
const FORWARDING_V6: &str = "net.inet6.ip6.forwarding";
const ANCHOR_PREFIX: &str = "com.apple/anixops-mesh";

/// One process holding forwarding on, with the pf anchor and token it owns.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Holder {
    pub pid: u32,
    pub sysctls: Vec<String>,
    pub anchor: Option<String>,
    pub token: Option<String>,
}

/// The shared state: original sysctl values, and who holds them.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    pub original: std::collections::BTreeMap<String, i32>,
    pub holders: Vec<Holder>,
}

impl State {
    /// Holders `keep` rejects (their process is gone, or they are leaving),
    /// removed from the state.
    pub fn take_dead(&mut self, keep: impl Fn(&Holder) -> bool) -> Vec<Holder> {
        let (live, dead) = self.holders.drain(..).partition(keep);
        self.holders = live;
        dead
    }

    /// The sysctls no live holder needs any more, with their originals.
    pub fn released(&mut self) -> Vec<(String, i32)> {
        let wanted: BTreeSet<&String> = self
            .holders
            .iter()
            .flat_map(|holder| holder.sysctls.iter())
            .collect();
        let gone: Vec<String> = self
            .original
            .keys()
            .filter(|name| !wanted.contains(name))
            .cloned()
            .collect();
        gone.into_iter()
            .filter_map(|name| self.original.remove(&name).map(|value| (name, value)))
            .collect()
    }
}

/// The anchor of one network: our prefix and a label made of the
/// network name's letters, digits, `-` and `_`, with a short hash when the
/// name needed changing.
pub fn anchor_for(network: &str) -> String {
    let label: String = network
        .chars()
        .take(32)
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect();
    if label == network && !label.is_empty() {
        return format!("{ANCHOR_PREFIX}.{label}");
    }
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(network.as_bytes());
    let suffix: String = digest[..4].iter().map(|b| format!("{b:02x}")).collect();
    format!("{ANCHOR_PREFIX}.{label}-{suffix}")
}

/// Interface names pf accepts: letters and digits, at most 15 bytes.
fn valid_interface(name: &str) -> bool {
    !name.is_empty() && name.len() < 16 && name.bytes().all(|b| b.is_ascii_alphanumeric())
}

/// The `nat` rules: for each LAN interface and family, mesh sources to the
/// advertised subnets it carries, translated to the interface's address.
pub fn nat_rules(lan: &[(String, IpNet)], sources: &[IpNet]) -> String {
    let mut rules = String::new();
    let mut interfaces: Vec<&String> = lan.iter().map(|(name, _)| name).collect();
    interfaces.sort();
    interfaces.dedup();
    for interface in interfaces {
        if !valid_interface(interface) {
            continue;
        }
        for (family, v6) in [("inet", false), ("inet6", true)] {
            let targets: BTreeSet<String> = lan
                .iter()
                .filter(|(name, net)| name == interface && net.network().is_ipv6() == v6)
                .map(|(_, net)| net.trunc().to_string())
                .collect();
            let from: BTreeSet<String> = sources
                .iter()
                .filter(|net| net.network().is_ipv6() == v6)
                .map(|net| net.trunc().to_string())
                .collect();
            if targets.is_empty() || from.is_empty() {
                continue;
            }
            let list = |set: &BTreeSet<String>| set.iter().cloned().collect::<Vec<_>>().join(", ");
            rules.push_str(&format!(
                "nat on {interface} {family} from {{ {} }} to {{ {} }} -> ({interface})\n",
                list(&from),
                list(&targets)
            ));
        }
    }
    rules
}

/// The token in `pfctl -E` output (`Token : 12345`).
pub fn parse_token(output: &str) -> Option<String> {
    output.lines().find_map(|line| {
        let (key, value) = line.split_once(':')?;
        let value = value.trim();
        (key.trim() == "Token" && !value.is_empty() && value.bytes().all(|b| b.is_ascii_digit()))
            .then(|| value.to_owned())
    })
}

fn pfctl(args: &[&str], input: Option<&str>) -> io::Result<String> {
    let mut child = Command::new(PFCTL)
        .args(args)
        .env_clear()
        .stdin(if input.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    if let (Some(text), Some(mut stdin)) = (input, child.stdin.take()) {
        stdin.write_all(text.as_bytes())?;
    }
    let output = child.wait_with_output()?;
    // pfctl writes its messages, the token among them, to standard error.
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    if output.status.success() {
        Ok(text)
    } else {
        Err(io::Error::other(format!(
            "pfctl {}: {}",
            args.join(" "),
            text.trim()
        )))
    }
}

fn sysctl_name(name: &str) -> io::Result<std::ffi::CString> {
    std::ffi::CString::new(name).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))
}

fn read_sysctl(name: &str) -> io::Result<i32> {
    let c_name = sysctl_name(name)?;
    let mut value: libc::c_int = 0;
    let mut length = std::mem::size_of::<libc::c_int>();
    // SAFETY: the buffer is one integer, its length given.
    let result = unsafe {
        libc::sysctlbyname(
            c_name.as_ptr(),
            std::ptr::from_mut(&mut value).cast(),
            &mut length,
            std::ptr::null_mut(),
            0,
        )
    };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(value)
}

fn write_sysctl(name: &str, value: i32) -> io::Result<()> {
    let c_name = sysctl_name(name)?;
    let mut value: libc::c_int = value;
    // SAFETY: the new value is one integer, its length given.
    let result = unsafe {
        libc::sysctlbyname(
            c_name.as_ptr(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::from_mut(&mut value).cast(),
            std::mem::size_of::<libc::c_int>(),
        )
    };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn process_alive(pid: u32) -> bool {
    let Ok(pid) = libc::pid_t::try_from(pid) else {
        return false;
    };
    // SAFETY: signal 0 only checks that the process exists.
    let result = unsafe { libc::kill(pid, 0) };
    result == 0 || io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
}

/// The state file, locked for this process until dropped.
struct Locked {
    file: File,
}

impl Locked {
    fn open(dir: &Path) -> io::Result<Self> {
        std::fs::create_dir_all(dir)?;
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(dir.join(STATE_FILE))?;
        // SAFETY: plain lock call on an open descriptor.
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self { file })
    }

    fn read(&mut self) -> io::Result<State> {
        let mut text = String::new();
        self.file.rewind()?;
        self.file.read_to_string(&mut text)?;
        if text.trim().is_empty() {
            return Ok(State::default());
        }
        serde_json::from_str(&text).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
    }

    fn write(&mut self, state: &State) -> io::Result<()> {
        let text = serde_json::to_vec_pretty(state).map_err(io::Error::other)?;
        self.file.set_len(0)?;
        self.file.rewind()?;
        self.file.write_all(&text)?;
        self.file.sync_all()
    }
}

/// Undoes what dead holders left behind: their anchors and tokens, and the
/// sysctls nobody holds any more. Returns problems as warnings; the caller
/// writes the state back.
fn clean(state: &mut State, keep: impl Fn(&Holder) -> bool) -> Vec<String> {
    let mut warnings = Vec::new();
    for holder in state.take_dead(keep) {
        if let Some(anchor) = &holder.anchor {
            if let Err(error) = pfctl(&["-a", anchor, "-F", "all"], None) {
                warnings.push(error.to_string());
            }
        }
        if let Some(token) = &holder.token {
            if let Err(error) = pfctl(&["-X", token], None) {
                warnings.push(error.to_string());
            }
        }
    }
    for (name, value) in state.released() {
        if let Err(error) = write_sysctl(&name, value) {
            warnings.push(format!("{name}: {error}"));
        }
    }
    warnings
}

/// Forwarding and translation held for one network of this process.
/// Dropping it removes the rules, releases the pf token and puts the
/// sysctls back when no other process holds them.
pub struct HostForwarding {
    dir: PathBuf,
    anchor: String,
    lan: Vec<(String, IpNet)>,
    sources: Vec<IpNet>,
}

impl HostForwarding {
    /// Switches forwarding on and loads the translation rules for the
    /// `advertised` subnets of `network`, from `sources` (the virtual
    /// subnets and the subnets routed into the mesh). `interfaces` are the
    /// machine's (name, address network) pairs; `ipv6` whether the node has
    /// an IPv6 virtual address.
    pub fn start(
        dir: &Path,
        network: &str,
        mesh_interface: &str,
        interfaces: &[(String, IpNet)],
        advertised: &[IpNet],
        sources: &[IpNet],
        ipv6: bool,
    ) -> io::Result<(Self, Vec<String>)> {
        let lan = crate::host_routes::lan_interfaces(interfaces, advertised, mesh_interface);
        let mut warnings: Vec<String> = advertised
            .iter()
            .filter(|subnet| !lan.iter().any(|(_, net)| net == *subnet))
            .map(|subnet| format!("{subnet}: no interface of this machine is on it"))
            .collect();
        let mut sysctls = vec![FORWARDING_V4.to_owned()];
        if ipv6 {
            sysctls.push(FORWARDING_V6.to_owned());
        }
        let anchor = anchor_for(network);
        let mut locked = Locked::open(dir)?;
        let mut state = locked.read().unwrap_or_default();
        warnings.extend(clean(&mut state, |holder| process_alive(holder.pid)));
        // Originals are recorded before the first change, and never from a
        // value we set ourselves.
        for name in &sysctls {
            if !state.original.contains_key(name) {
                state.original.insert(name.clone(), read_sysctl(name)?);
            }
        }
        let pid = std::process::id();
        state
            .holders
            .retain(|holder| holder.pid != pid || holder.anchor.as_ref() != Some(&anchor));
        state.holders.push(Holder {
            pid,
            sysctls: sysctls.clone(),
            anchor: Some(anchor.clone()),
            token: None,
        });
        locked.write(&state)?;
        let this = Self {
            dir: dir.to_path_buf(),
            anchor: anchor.clone(),
            lan,
            sources: sources.to_vec(),
        };
        // From here a failure drops `this`, which undoes what changed.
        for name in &sysctls {
            write_sysctl(name, 1)?;
        }
        pfctl(&["-a", &anchor, "-N", "-f", "-"], Some(&this.rules()))?;
        let token = parse_token(&pfctl(&["-E"], None)?)
            .ok_or_else(|| io::Error::other("pfctl -E gave no token"))?;
        if let Some(holder) = state
            .holders
            .iter_mut()
            .find(|holder| holder.pid == pid && holder.anchor.as_ref() == Some(&anchor))
        {
            holder.token = Some(token);
        }
        locked.write(&state)?;
        Ok((this, warnings))
    }

    fn rules(&self) -> String {
        nat_rules(&self.lan, &self.sources)
    }

    /// Replaces the rules when the mesh sources change.
    pub fn set_sources(&mut self, sources: &[IpNet]) -> io::Result<()> {
        if self.sources == sources {
            return Ok(());
        }
        self.sources = sources.to_vec();
        pfctl(&["-a", &self.anchor, "-N", "-f", "-"], Some(&self.rules())).map(|_| ())
    }

    /// The LAN interfaces and the subnets they carry.
    pub fn lan(&self) -> &[(String, IpNet)] {
        &self.lan
    }
}

impl Drop for HostForwarding {
    fn drop(&mut self) {
        let Ok(mut locked) = Locked::open(&self.dir) else {
            return;
        };
        let mut state = locked.read().unwrap_or_default();
        let pid = std::process::id();
        // This holder leaves; the others stay while their process lives.
        let leaving = |holder: &Holder| {
            holder.pid == pid && holder.anchor.as_deref() == Some(self.anchor.as_str())
        };
        let mut warnings = clean(&mut state, |holder| {
            !leaving(holder) && process_alive(holder.pid)
        });
        if let Err(error) = locked.write(&state) {
            warnings.push(error.to_string());
        }
        for warning in warnings {
            eprintln!(
                "{}",
                serde_json::json!({ "warning": "forwarding", "detail": warning })
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn net(text: &str) -> IpNet {
        IpNet::parse(text).unwrap()
    }

    #[test]
    fn rules_translate_mesh_sources_to_the_lan_only() {
        let lan = vec![
            ("en0".to_string(), net("192.168.1.0/24")),
            ("en0".to_string(), net("fd12::/64")),
            ("en5".to_string(), net("10.20.0.0/16")),
        ];
        let sources = [
            net("10.144.0.0/24"),
            net("fd00:144::/64"),
            net("192.168.2.0/24"),
        ];
        assert_eq!(
            nat_rules(&lan, &sources),
            "nat on en0 inet from { 10.144.0.0/24, 192.168.2.0/24 } to { 192.168.1.0/24 } -> (en0)\n\
             nat on en0 inet6 from { fd00:144::/64 } to { fd12::/64 } -> (en0)\n\
             nat on en5 inet from { 10.144.0.0/24, 192.168.2.0/24 } to { 10.20.0.0/16 } -> (en5)\n"
        );
        // No IPv6 source: no IPv6 rule.
        assert!(!nat_rules(&lan, &[net("10.144.0.0/24")]).contains("inet6"));
        // An interface name pf would misread is skipped.
        let odd = vec![("en0; pass".to_string(), net("192.168.1.0/24"))];
        assert_eq!(nat_rules(&odd, &sources), "");
    }

    #[test]
    fn the_token_is_read_from_pfctl_output() {
        let output = "No ALTQ support in kernel\npf enabled\nToken : 1234567890\n";
        assert_eq!(parse_token(output), Some("1234567890".into()));
        assert_eq!(parse_token("pf enabled\n"), None);
        assert_eq!(parse_token("Token : 12; rm\n"), None);
    }

    #[test]
    fn anchors_stay_below_the_system_anchor() {
        assert_eq!(anchor_for("office"), "com.apple/anixops-mesh.office");
        let odd = anchor_for("家 office");
        assert!(odd.starts_with("com.apple/anixops-mesh.__office-"));
        assert_ne!(anchor_for("a b"), anchor_for("a_b"));
    }

    #[test]
    fn the_last_holder_gets_the_originals_back() {
        let mut state = State::default();
        state.original.insert(FORWARDING_V4.into(), 0);
        state.original.insert(FORWARDING_V6.into(), 0);
        let holder = |pid, sysctls: &[&str]| Holder {
            pid,
            sysctls: sysctls.iter().map(|s| s.to_string()).collect(),
            anchor: None,
            token: None,
        };
        state.holders = vec![
            holder(10, &[FORWARDING_V4, FORWARDING_V6]),
            holder(11, &[FORWARDING_V4]),
        ];
        // Process 10 died: IPv6 forwarding is nobody's any more.
        let dead = state.take_dead(|holder| holder.pid == 11);
        assert_eq!(dead.len(), 1);
        assert_eq!(state.released(), vec![(FORWARDING_V6.to_string(), 0)]);
        // Then 11 leaves too.
        state.take_dead(|_| false);
        assert_eq!(state.released(), vec![(FORWARDING_V4.to_string(), 0)]);
        assert!(state.original.is_empty());
    }

    #[test]
    fn the_state_file_round_trips_under_its_lock() {
        let dir = std::env::temp_dir().join(format!("mesh-forward-{}", std::process::id()));
        let mut locked = Locked::open(&dir).expect("lock");
        assert_eq!(locked.read().expect("empty"), State::default());
        let mut state = State::default();
        state.original.insert(FORWARDING_V4.into(), 0);
        state.holders.push(Holder {
            pid: 7,
            sysctls: vec![FORWARDING_V4.into()],
            anchor: Some(anchor_for("office")),
            token: Some("42".into()),
        });
        locked.write(&state).expect("write");
        assert_eq!(locked.read().expect("read"), state);
        drop(locked);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
