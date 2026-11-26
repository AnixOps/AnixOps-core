//! Host changes a macOS full node needs to carry its advertised subnets
//! (spec §15.1, requirement R10): IPv4 forwarding, and source address
//! translation of mesh traffic leaving through the LAN interface, so that
//! hosts on the LAN answer this machine instead of needing a route back.
//!
//! - Forwarding is the system-wide `net.inet.ip.forwarding`: once on, the
//!   machine forwards between all of its interfaces, other tunnels among
//!   them, and the node warns about those. IPv6 forwarding is never
//!   switched: with it on the system stops accepting router advertisements
//!   and can lose its own IPv6 default route, so IPv6 subnets are not
//!   advertised. The original value and every process holding it are kept in
//!   one state file under a lock; the last holder to leave restores it. A
//!   holder is the same process only when its PID, its start time and the
//!   boot session all match, so a reused PID or a reboot never keeps a dead
//!   holder alive. Dead holders are cleaned at every start of `run` and by
//!   `restore-host`. A state file that cannot be read is kept aside and the
//!   system default (off) is restored when the last holder leaves.
//! - Translation is a pf anchor below `com.apple/`, evaluated only when the
//!   main ruleset has `nat-anchor "com.apple/*"` (the system's
//!   `/etc/pf.conf` does); without it the node refuses rather than report
//!   rules that never apply. The anchor holds only `nat` rules: from the
//!   mesh (the virtual subnets and the subnets routed into the mesh) to the
//!   advertised subnets, on the LAN interfaces that carry them. pf is
//!   enabled with a reference token (`pfctl -E`, released with `pfctl -X`)
//!   only when it is off, or when it is on through one of our own tokens: a
//!   pf someone enabled without a token is never touched, since releasing
//!   the last token would stop it. Rules are replaced as a whole when the
//!   routed subnets change.
//! - A failure part-way through [`HostForwarding::start`] is undone under
//!   the lock the start already holds.
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
/// Where an unreadable state file is kept for inspection.
pub const CORRUPT_FILE: &str = "host-forwarding.json.corrupt";

const PFCTL: &str = "/sbin/pfctl";
const FORWARDING_V4: &str = "net.inet.ip.forwarding";
/// Switched by earlier versions; restored from old records only.
const FORWARDING_V6: &str = "net.inet6.ip6.forwarding";
const ANCHOR_PREFIX: &str = "com.apple/anixops-mesh";
/// The main ruleset line that makes our anchors count.
const SYSTEM_NAT_ANCHOR: &str = "nat-anchor \"com.apple/*\"";

/// What the host changes go through; [`MacSystem`] is the real one.
pub trait System: Send + Sync {
    fn read_sysctl(&self, name: &str) -> io::Result<i32>;
    fn write_sysctl(&self, name: &str, value: i32) -> io::Result<()>;
    /// Runs `pfctl` with `args`, `input` on its standard input; standard
    /// output and error together.
    fn pfctl(&self, args: &[&str], input: Option<&str>) -> io::Result<String>;
    /// Start time of process `pid` in microseconds, `None` when it is gone.
    fn process_start(&self, pid: u32) -> Option<u64>;
    /// An identifier of the current boot.
    fn boot_session(&self) -> io::Result<String>;
}

/// The running macOS system.
pub struct MacSystem;

impl System for MacSystem {
    fn read_sysctl(&self, name: &str) -> io::Result<i32> {
        read_sysctl(name)
    }

    fn write_sysctl(&self, name: &str, value: i32) -> io::Result<()> {
        write_sysctl(name, value)
    }

    fn pfctl(&self, args: &[&str], input: Option<&str>) -> io::Result<String> {
        pfctl(args, input)
    }

    fn process_start(&self, pid: u32) -> Option<u64> {
        process_start(pid)
    }

    fn boot_session(&self) -> io::Result<String> {
        read_sysctl_string("kern.bootsessionuuid")
    }
}

/// One process holding forwarding on, with the pf anchor and token it owns.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Holder {
    pub pid: u32,
    /// Start time of the process, microseconds; 0 in records of earlier
    /// versions, which never match.
    #[serde(default)]
    pub started: u64,
    /// Boot session the record was made in.
    #[serde(default)]
    pub boot: String,
    pub sysctls: Vec<String>,
    pub anchor: Option<String>,
    pub token: Option<String>,
}

impl Holder {
    /// Whether the process that made this record still runs.
    fn alive(&self, system: &dyn System, boot: &str) -> bool {
        self.started != 0
            && self.boot == boot
            && system.process_start(self.pid) == Some(self.started)
    }

    fn is(&self, pid: u32, started: u64, anchor: &str) -> bool {
        self.pid == pid && self.started == started && self.anchor.as_deref() == Some(anchor)
    }
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

    /// What is assumed when the state file cannot be read: nobody holds
    /// anything and both forwarding switches go back to the system default.
    fn reset() -> Self {
        let mut state = Self::default();
        state.original.insert(FORWARDING_V4.to_owned(), 0);
        state.original.insert(FORWARDING_V6.to_owned(), 0);
        state
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

/// Whether `pfctl -s info` reports pf enabled; `None` when the output has
/// no status line.
pub fn pf_enabled(info: &str) -> Option<bool> {
    info.lines().find_map(|line| {
        let rest = line.trim().strip_prefix("Status:")?;
        let state = rest.split_whitespace().next()?;
        match state {
            "Enabled" => Some(true),
            "Disabled" => Some(false),
            _ => None,
        }
    })
}

/// Whether the main ruleset (`pfctl -s nat`) evaluates the anchors below
/// `com.apple/`, ours among them.
pub fn evaluates_system_anchors(nat: &str) -> bool {
    nat.lines().any(|line| {
        line.trim()
            .strip_prefix(SYSTEM_NAT_ANCHOR)
            .is_some_and(|rest| rest.is_empty() || rest.starts_with(' '))
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

/// A string sysctl, such as `kern.bootsessionuuid`.
fn read_sysctl_string(name: &str) -> io::Result<String> {
    let c_name = sysctl_name(name)?;
    let mut buffer = [0u8; 128];
    let mut length = buffer.len();
    // SAFETY: the buffer and its length are given.
    let result = unsafe {
        libc::sysctlbyname(
            c_name.as_ptr(),
            buffer.as_mut_ptr().cast(),
            &mut length,
            std::ptr::null_mut(),
            0,
        )
    };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    let text = &buffer[..length.min(buffer.len())];
    let end = text.iter().position(|b| *b == 0).unwrap_or(text.len());
    Ok(String::from_utf8_lossy(&text[..end]).into_owned())
}

/// Start time of a running process in microseconds.
fn process_start(pid: u32) -> Option<u64> {
    let pid = libc::c_int::try_from(pid).ok()?;
    // SAFETY: an all-zero `proc_bsdinfo` is valid.
    let mut info: libc::proc_bsdinfo = unsafe { std::mem::zeroed() };
    let size = libc::c_int::try_from(std::mem::size_of::<libc::proc_bsdinfo>()).ok()?;
    // SAFETY: the buffer is one `proc_bsdinfo`, its size given.
    let written = unsafe {
        libc::proc_pidinfo(
            pid,
            libc::PROC_PIDTBSDINFO,
            0,
            std::ptr::from_mut(&mut info).cast(),
            size,
        )
    };
    if written != size {
        return None;
    }
    Some(
        info.pbi_start_tvsec
            .saturating_mul(1_000_000)
            .saturating_add(info.pbi_start_tvusec),
    )
}

/// The state file, locked for this process until dropped.
struct Locked {
    dir: PathBuf,
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
        Ok(Self {
            dir: dir.to_path_buf(),
            file,
        })
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

    /// The state, or [`State::reset`] when the file cannot be read; a copy
    /// of an unreadable file is kept next to it and a warning added.
    fn read_or_reset(&mut self, warnings: &mut Vec<String>) -> State {
        match self.read() {
            Ok(state) => state,
            Err(error) => {
                let mut raw = Vec::new();
                let kept = self
                    .file
                    .rewind()
                    .and_then(|()| self.file.read_to_end(&mut raw))
                    .and_then(|_| std::fs::write(self.dir.join(CORRUPT_FILE), &raw));
                warnings.push(format!(
                    "the forwarding state could not be read ({error}); forwarding goes back to off when the last holder leaves{}",
                    if kept.is_ok() {
                        format!(", the file is kept as {CORRUPT_FILE}")
                    } else {
                        String::new()
                    }
                ));
                State::reset()
            }
        }
    }

    fn write(&mut self, state: &State) -> io::Result<()> {
        let text = serde_json::to_vec_pretty(state).map_err(io::Error::other)?;
        self.file.set_len(0)?;
        self.file.rewind()?;
        self.file.write_all(&text)?;
        self.file.sync_all()
    }
}

/// Undoes what the holders `keep` rejects left behind: their anchors and
/// tokens, and the sysctls nobody holds any more. Returns problems as
/// warnings; the caller writes the state back.
fn clean(system: &dyn System, state: &mut State, keep: impl Fn(&Holder) -> bool) -> Vec<String> {
    let mut warnings = Vec::new();
    for holder in state.take_dead(keep) {
        if let Some(anchor) = &holder.anchor {
            if let Err(error) = system.pfctl(&["-a", anchor, "-F", "all"], None) {
                warnings.push(error.to_string());
            }
        }
        if let Some(token) = &holder.token {
            if let Err(error) = system.pfctl(&["-X", token], None) {
                warnings.push(error.to_string());
            }
        }
    }
    for (name, value) in state.released() {
        if let Err(error) = system.write_sysctl(&name, value) {
            warnings.push(format!("{name}: {error}"));
        }
    }
    warnings
}

/// Puts back what dead holders left: their rules, tokens and the sysctls
/// nobody holds. Runs at every start of `run`, whether or not the node
/// forwards, and from `restore-host`. Nothing happens when no state file
/// exists. Returns warnings.
pub fn recover(system: &dyn System, dir: &Path) -> io::Result<Vec<String>> {
    if !dir.join(STATE_FILE).exists() {
        return Ok(Vec::new());
    }
    let boot = system.boot_session()?;
    let mut locked = Locked::open(dir)?;
    let mut warnings = Vec::new();
    let mut state = locked.read_or_reset(&mut warnings);
    warnings.extend(clean(system, &mut state, |holder| {
        holder.alive(system, &boot)
    }));
    locked.write(&state)?;
    Ok(warnings)
}

/// Forwarding and translation held for one network of this process.
/// Dropping it removes the rules, releases the pf token and puts the
/// sysctl back when no other process holds it.
pub struct HostForwarding {
    system: Box<dyn System>,
    dir: PathBuf,
    anchor: String,
    started: u64,
    lan: Vec<(String, IpNet)>,
    sources: Vec<IpNet>,
}

impl HostForwarding {
    /// Switches IPv4 forwarding on and loads the translation rules of
    /// `network` for the IPv4 subnets in `lan` (LAN interface, advertised
    /// subnet), from `sources` (the virtual subnets and the subnets routed
    /// into the mesh). Returns warnings: dead holders that could not be
    /// cleaned, and an unreadable state file.
    pub fn start(
        system: Box<dyn System>,
        dir: &Path,
        network: &str,
        lan: Vec<(String, IpNet)>,
        sources: &[IpNet],
    ) -> io::Result<(Self, Vec<String>)> {
        let lan: Vec<(String, IpNet)> = lan
            .into_iter()
            .filter(|(_, subnet)| subnet.is_ipv4())
            .collect();
        let pid = std::process::id();
        let started = system
            .process_start(pid)
            .ok_or_else(|| io::Error::other("the start time of this process is unknown"))?;
        let boot = system.boot_session()?;
        let anchor = anchor_for(network);
        let mut warnings = Vec::new();

        let mut locked = Locked::open(dir)?;
        let mut state = locked.read_or_reset(&mut warnings);
        warnings.extend(clean(system.as_ref(), &mut state, |holder| {
            holder.alive(system.as_ref(), &boot) && !holder.is(pid, started, &anchor)
        }));
        locked.write(&state)?;

        // Checked before anything changes: rules in an anchor the main
        // ruleset never evaluates would do nothing.
        let nat = system.pfctl(&["-s", "nat"], None)?;
        if !evaluates_system_anchors(&nat) {
            return Err(io::Error::other(
                "the main pf ruleset has no nat-anchor \"com.apple/*\", so translation rules would not apply",
            ));
        }
        let info = system.pfctl(&["-s", "info"], None)?;
        let enabled =
            pf_enabled(&info).ok_or_else(|| io::Error::other("pfctl -s info gave no status"))?;
        // A token is taken when pf is off, or on through one of our tokens;
        // a pf enabled without a token is left alone.
        let take_token = !enabled || state.holders.iter().any(|holder| holder.token.is_some());

        // Originals are recorded before the first change, and never from a
        // value we set ourselves.
        if !state.original.contains_key(FORWARDING_V4) {
            let value = system.read_sysctl(FORWARDING_V4)?;
            state.original.insert(FORWARDING_V4.to_owned(), value);
        }
        state.holders.push(Holder {
            pid,
            started,
            boot,
            sysctls: vec![FORWARDING_V4.to_owned()],
            anchor: Some(anchor.clone()),
            token: None,
        });
        locked.write(&state)?;

        let this = Self {
            system,
            dir: dir.to_path_buf(),
            anchor,
            started,
            lan,
            sources: sources.to_vec(),
        };
        match this.apply(&mut state, take_token) {
            Ok(()) => match locked.write(&state) {
                Ok(()) => Ok((this, warnings)),
                Err(error) => Err(this.undo(&mut locked, &mut state, error)),
            },
            Err(error) => Err(this.undo(&mut locked, &mut state, error)),
        }
    }

    /// The changes, recorded in `state` as they are made.
    fn apply(&self, state: &mut State, take_token: bool) -> io::Result<()> {
        self.system.write_sysctl(FORWARDING_V4, 1)?;
        self.system
            .pfctl(&["-a", &self.anchor, "-N", "-f", "-"], Some(&self.rules()))?;
        if take_token {
            let token = parse_token(&self.system.pfctl(&["-E"], None)?)
                .ok_or_else(|| io::Error::other("pfctl -E gave no token"))?;
            let pid = std::process::id();
            if let Some(holder) = state
                .holders
                .iter_mut()
                .find(|holder| holder.is(pid, self.started, &self.anchor))
            {
                holder.token = Some(token);
            }
        }
        Ok(())
    }

    /// Takes this holder out under the lock `start` still holds, undoing
    /// what it changed, and returns `error` with any cleanup problems added.
    /// Undoing through [`Drop`] instead would take the same lock again and
    /// block for good.
    fn undo(mut self, locked: &mut Locked, state: &mut State, error: io::Error) -> io::Error {
        let pid = std::process::id();
        let (started, anchor) = (self.started, std::mem::take(&mut self.anchor));
        let mut problems = clean(self.system.as_ref(), state, |holder| {
            !holder.is(pid, started, &anchor)
        });
        if let Err(write) = locked.write(state) {
            problems.push(write.to_string());
        }
        // Nothing is left for `Drop` to do.
        self.dir = PathBuf::new();
        if problems.is_empty() {
            error
        } else {
            io::Error::new(
                error.kind(),
                format!("{error}; undoing it: {}", problems.join("; ")),
            )
        }
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
        self.system
            .pfctl(&["-a", &self.anchor, "-N", "-f", "-"], Some(&self.rules()))
            .map(|_| ())
    }

    /// The LAN interfaces and the subnets they carry.
    pub fn lan(&self) -> &[(String, IpNet)] {
        &self.lan
    }
}

impl Drop for HostForwarding {
    fn drop(&mut self) {
        if self.dir.as_os_str().is_empty() {
            return;
        }
        let Ok(mut locked) = Locked::open(&self.dir) else {
            return;
        };
        let mut warnings = Vec::new();
        let mut state = locked.read_or_reset(&mut warnings);
        let pid = std::process::id();
        let boot = self.system.boot_session().unwrap_or_default();
        let system = self.system.as_ref();
        // This holder leaves; the others stay while their process lives.
        warnings.extend(clean(system, &mut state, |holder| {
            !holder.is(pid, self.started, &self.anchor) && holder.alive(system, &boot)
        }));
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
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};

    fn net(text: &str) -> IpNet {
        IpNet::parse(text).unwrap()
    }

    /// A system whose sysctls, processes and pf answers are set by the test.
    #[derive(Default)]
    struct Fake {
        sysctls: Mutex<HashMap<String, i32>>,
        calls: Mutex<Vec<String>>,
        processes: Mutex<HashMap<u32, u64>>,
        fail_on: Mutex<Option<&'static str>>,
        pf_info: Mutex<String>,
        nat: Mutex<String>,
    }

    impl Fake {
        fn new() -> Arc<Self> {
            let fake = Arc::new(Self::default());
            fake.processes
                .lock()
                .unwrap()
                .insert(std::process::id(), 1_000);
            *fake.pf_info.lock().unwrap() = "Status: Disabled for 0 days\n".into();
            *fake.nat.lock().unwrap() = "nat-anchor \"com.apple/*\" all\n".into();
            fake
        }

        fn sysctl(&self, name: &str) -> Option<i32> {
            self.sysctls.lock().unwrap().get(name).copied()
        }

        fn called(&self, prefix: &str) -> bool {
            self.calls
                .lock()
                .unwrap()
                .iter()
                .any(|call| call.starts_with(prefix))
        }
    }

    struct Shared(Arc<Fake>);

    impl System for Shared {
        fn read_sysctl(&self, name: &str) -> io::Result<i32> {
            Ok(self.0.sysctl(name).unwrap_or(0))
        }

        fn write_sysctl(&self, name: &str, value: i32) -> io::Result<()> {
            self.0.sysctls.lock().unwrap().insert(name.into(), value);
            Ok(())
        }

        fn pfctl(&self, args: &[&str], _input: Option<&str>) -> io::Result<String> {
            let call = args.join(" ");
            self.0.calls.lock().unwrap().push(call.clone());
            if let Some(fail) = *self.0.fail_on.lock().unwrap() {
                if call.contains(fail) {
                    return Err(io::Error::other(format!("pfctl {call}: refused")));
                }
            }
            Ok(match args {
                ["-s", "info"] => self.0.pf_info.lock().unwrap().clone(),
                ["-s", "nat"] => self.0.nat.lock().unwrap().clone(),
                ["-E"] => "pf enabled\nToken : 77\n".into(),
                _ => String::new(),
            })
        }

        fn process_start(&self, pid: u32) -> Option<u64> {
            self.0.processes.lock().unwrap().get(&pid).copied()
        }

        fn boot_session(&self) -> io::Result<String> {
            Ok("boot-1".into())
        }
    }

    fn temp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("mesh-forward-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    fn read_state(dir: &Path) -> State {
        let text = std::fs::read_to_string(dir.join(STATE_FILE)).unwrap();
        serde_json::from_str(&text).unwrap()
    }

    fn start(fake: &Arc<Fake>, dir: &Path) -> io::Result<(HostForwarding, Vec<String>)> {
        HostForwarding::start(
            Box::new(Shared(fake.clone())),
            dir,
            "office",
            vec![("en0".into(), net("192.168.1.0/24"))],
            &[net("10.144.0.0/24")],
        )
    }

    #[test]
    fn a_failed_start_returns_and_puts_everything_back() {
        let fake = Fake::new();
        *fake.fail_on.lock().unwrap() = Some("-N -f -");
        let dir = temp_dir("fail");
        let (sender, receiver) = std::sync::mpsc::channel();
        {
            let fake = fake.clone();
            let dir = dir.clone();
            std::thread::spawn(move || {
                let _ = sender.send(start(&fake, &dir).map(|_| ()));
            });
        }
        let result = receiver
            .recv_timeout(std::time::Duration::from_secs(20))
            .expect("start returned instead of blocking on its own lock");
        assert!(result.is_err());
        assert_eq!(fake.sysctl(FORWARDING_V4), Some(0));
        assert!(fake.called("-a com.apple/anixops-mesh.office -F all"));
        let state = read_state(&dir);
        assert!(state.holders.is_empty());
        assert!(state.original.is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_failed_token_also_puts_everything_back() {
        let fake = Fake::new();
        *fake.fail_on.lock().unwrap() = Some("-E");
        let dir = temp_dir("token");
        assert!(start(&fake, &dir).is_err());
        assert_eq!(fake.sysctl(FORWARDING_V4), Some(0));
        assert!(read_state(&dir).holders.is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_started_holder_is_recorded_and_leaves_cleanly() {
        let fake = Fake::new();
        let dir = temp_dir("ok");
        let (forwarding, warnings) = start(&fake, &dir).expect("start");
        assert!(warnings.is_empty(), "{warnings:?}");
        assert_eq!(fake.sysctl(FORWARDING_V4), Some(1));
        let state = read_state(&dir);
        assert_eq!(state.holders.len(), 1);
        assert_eq!(state.holders[0].token.as_deref(), Some("77"));
        assert_eq!(state.holders[0].started, 1_000);
        assert_eq!(state.holders[0].boot, "boot-1");
        drop(forwarding);
        assert_eq!(fake.sysctl(FORWARDING_V4), Some(0));
        assert!(fake.called("-X 77"));
        assert!(read_state(&dir).holders.is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_pf_enabled_without_our_token_is_left_alone() {
        let fake = Fake::new();
        *fake.pf_info.lock().unwrap() = "Status: Enabled for 3 days\n".into();
        let dir = temp_dir("pf-on");
        let (forwarding, _) = start(&fake, &dir).expect("start");
        assert!(!fake.called("-E"));
        drop(forwarding);
        assert!(!fake.called("-X"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn rules_the_main_ruleset_ignores_are_refused_before_any_change() {
        let fake = Fake::new();
        *fake.nat.lock().unwrap() = "no nat proxy\n".into();
        let dir = temp_dir("no-anchor");
        assert!(start(&fake, &dir).is_err());
        assert_eq!(fake.sysctl(FORWARDING_V4), None);
        assert!(!fake.called("-a "));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_reused_pid_or_another_boot_does_not_keep_a_holder_alive() {
        let fake = Fake::new();
        fake.processes.lock().unwrap().insert(4242, 5);
        let system = Shared(fake.clone());
        let holder = |started, boot: &str| Holder {
            pid: 4242,
            started,
            boot: boot.into(),
            sysctls: vec![FORWARDING_V4.into()],
            anchor: None,
            token: None,
        };
        assert!(holder(5, "boot-1").alive(&system, "boot-1"));
        assert!(!holder(6, "boot-1").alive(&system, "boot-1"));
        assert!(!holder(5, "boot-0").alive(&system, "boot-1"));
        // Records of earlier versions carry no start time.
        assert!(!holder(0, "").alive(&system, "boot-1"));
    }

    #[test]
    fn recovery_restores_what_dead_holders_left() {
        let fake = Fake::new();
        let dir = temp_dir("recover");
        std::fs::create_dir_all(&dir).unwrap();
        let mut state = State::default();
        state.original.insert(FORWARDING_V4.into(), 0);
        state.holders.push(Holder {
            pid: 4243,
            started: 9,
            boot: "boot-1".into(),
            sysctls: vec![FORWARDING_V4.into()],
            anchor: Some(anchor_for("office")),
            token: Some("12".into()),
        });
        std::fs::write(dir.join(STATE_FILE), serde_json::to_vec(&state).unwrap()).unwrap();
        fake.sysctls.lock().unwrap().insert(FORWARDING_V4.into(), 1);
        let warnings = recover(&Shared(fake.clone()), &dir).expect("recover");
        assert!(warnings.is_empty(), "{warnings:?}");
        assert_eq!(fake.sysctl(FORWARDING_V4), Some(0));
        assert!(fake.called("-X 12"));
        assert!(read_state(&dir).holders.is_empty());
        // No state file: nothing to do and nothing created.
        let empty = temp_dir("recover-none");
        assert!(recover(&Shared(fake), &empty).unwrap().is_empty());
        assert!(!empty.exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_unreadable_state_is_kept_aside_and_forwarding_goes_back_off() {
        let fake = Fake::new();
        let dir = temp_dir("corrupt");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join(STATE_FILE), b"{ not json").unwrap();
        fake.sysctls.lock().unwrap().insert(FORWARDING_V4.into(), 1);
        let warnings = recover(&Shared(fake.clone()), &dir).expect("recover");
        assert_eq!(warnings.len(), 1, "{warnings:?}");
        assert_eq!(
            std::fs::read(dir.join(CORRUPT_FILE)).unwrap(),
            b"{ not json"
        );
        assert_eq!(fake.sysctl(FORWARDING_V4), Some(0));
        assert_eq!(fake.sysctl(FORWARDING_V6), Some(0));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn pf_answers_are_read() {
        assert_eq!(
            pf_enabled("Status: Enabled for 0 days 00:01:02  Debug: Urgent\n"),
            Some(true)
        );
        assert_eq!(
            pf_enabled("No ALTQ support in kernel\nStatus: Disabled\n"),
            Some(false)
        );
        assert_eq!(pf_enabled("nothing\n"), None);
        assert!(evaluates_system_anchors("nat-anchor \"com.apple/*\" all\n"));
        assert!(evaluates_system_anchors("  nat-anchor \"com.apple/*\"\n"));
        assert!(!evaluates_system_anchors(
            "nat-anchor \"com.apple/x\" all\n"
        ));
        assert!(!evaluates_system_anchors(
            "rdr-anchor \"com.apple/*\" all\n"
        ));
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
            started: 1,
            boot: String::new(),
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
    fn records_of_earlier_versions_still_parse() {
        let old = r#"{"original":{"net.inet.ip.forwarding":0},"holders":[{"pid":7,"sysctls":["net.inet.ip.forwarding"],"anchor":null,"token":"4"}]}"#;
        let state: State = serde_json::from_str(old).unwrap();
        assert_eq!(state.holders[0].started, 0);
        assert!(state.holders[0].boot.is_empty());
    }
}
