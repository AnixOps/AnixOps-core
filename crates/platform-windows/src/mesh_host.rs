//! Host changes a Windows mesh node needs when it advertises subnets or relays:
//! interface-level IP forwarding, inbound firewall rules and source address
//! translation (WinNAT) of the virtual subnet towards the advertised subnets.
//!
//! Both are owned by guards. Dropping a guard puts the host back; what a guard
//! changed is also written to a state directory, so a process that died with a
//! guard alive is cleaned up by [`recover_mesh_host`] on its next start.
//!
//! - Forwarding is switched per interface (`MIB_IPINTERFACE_ROW.ForwardingEnabled`)
//!   on the mesh adapter and the chosen LAN interfaces only; the global
//!   `IPEnableRouter` setting is never touched. Several guards may hold the same
//!   interface: the original value is restored when the last one is dropped.
//! - Firewall rules live in one rule group and are named from a fixed prefix
//!   and the network name. They allow inbound TCP/UDP to this program's listen
//!   ports, and inbound traffic to this program from the mesh adapter. Traffic
//!   the host forwards is not subject to host inbound rules, so no broader rule
//!   is added for it.
//! - Source address translation is one WinNAT object per network, named from
//!   the same prefix and label, whose internal prefix is the network's IPv4
//!   virtual subnet. Hosts on an advertised subnet then answer the machine's
//!   own LAN address and need no route back into the mesh.

#![cfg_attr(not(windows), allow(dead_code))]

use std::io;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// Rule group of every firewall rule this module creates.
pub const MESH_FIREWALL_GROUP: &str = "AnixOps Mesh";
/// Prefix of every firewall rule name this module creates.
pub const MESH_FIREWALL_RULE_PREFIX: &str = "AnixOpsMesh";
/// File in the state directory that holds original forwarding values.
pub const MESH_FORWARDING_STATE_FILE: &str = "mesh-forwarding.json";

const MAX_NETWORK_LABEL: usize = 48;

/// IP family of one interface entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum IpFamily {
    Ipv4,
    Ipv6,
}

/// Original forwarding value of one interface and family, as written to the
/// state directory.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ForwardingEntry {
    pub luid: u64,
    pub family: IpFamily,
    pub original: bool,
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ForwardingState {
    entries: Vec<ForwardingEntry>,
}

/// What [`recover_mesh_host`] put back.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct RecoveryReport {
    /// Interface entries whose forwarding value was restored.
    pub forwarding_restored: usize,
    /// Interface entries that could not be restored (gone or refused).
    pub forwarding_failed: usize,
    /// Whether leftover rules of [`MESH_FIREWALL_GROUP`] were removed.
    pub firewall_cleared: bool,
    /// Whether leftover translation objects named from
    /// [`MESH_FIREWALL_RULE_PREFIX`] were removed.
    pub nat_cleared: bool,
}

/// The part of a network name used in rule names: ASCII letters, digits, `-`
/// and `_` kept, everything else replaced by `_`, at most 48 characters. A
/// name that changes this way gets a short hash suffix so two networks never
/// share a label.
pub fn network_label(network: &str) -> String {
    let mut label: String = network
        .chars()
        .take(MAX_NETWORK_LABEL)
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect();
    if label != network || label.is_empty() {
        let digest = ring::digest::digest(&ring::digest::SHA256, network.as_bytes());
        let suffix: String = digest.as_ref()[..4]
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        label.truncate(MAX_NETWORK_LABEL - 9);
        label.push('-');
        label.push_str(&suffix);
    }
    label
}

/// Names of the firewall rules created for `network`, in creation order:
/// listen ports over UDP, listen ports over TCP, inbound from the mesh adapter.
pub fn firewall_rule_names(network: &str) -> [String; 3] {
    let label = network_label(network);
    [
        format!("{MESH_FIREWALL_RULE_PREFIX}-{label}-listen-udp"),
        format!("{MESH_FIREWALL_RULE_PREFIX}-{label}-listen-tcp"),
        format!("{MESH_FIREWALL_RULE_PREFIX}-{label}-adapter"),
    ]
}

/// Name of the WinNAT object created for `network`.
pub fn nat_name(network: &str) -> String {
    format!("{MESH_FIREWALL_RULE_PREFIX}-{}", network_label(network))
}

/// The internal prefix of a WinNAT object, `a.b.c.d/n`, for the IPv4 subnet
/// holding `address`. Errors for a prefix length WinNAT cannot take (only
/// /1 to /30 leave room for the host and a peer).
pub fn nat_prefix(address: Ipv4Addr, prefix: u8) -> io::Result<String> {
    if !(1..=30).contains(&prefix) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "the translated subnet must be /1 to /30",
        ));
    }
    let mask = u32::MAX << (32 - u32::from(prefix));
    let network = Ipv4Addr::from(u32::from(address) & mask);
    Ok(format!("{network}/{prefix}"))
}

/// Listen ports as a comma-separated list, sorted and without duplicates or
/// zero. Errors when nothing is left.
pub fn listen_port_list(ports: &[u16]) -> io::Result<String> {
    let mut ports: Vec<u16> = ports.iter().copied().filter(|p| *p != 0).collect();
    ports.sort_unstable();
    ports.dedup();
    if ports.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "no listen port to allow",
        ));
    }
    Ok(ports
        .iter()
        .map(u16::to_string)
        .collect::<Vec<_>>()
        .join(","))
}

/// Interface aliases must be non-empty, at most 256 characters and free of
/// control characters.
fn check_alias(alias: &str) -> io::Result<()> {
    if alias.is_empty() || alias.chars().count() > 256 || alias.chars().any(char::is_control) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid interface name",
        ));
    }
    Ok(())
}

fn state_path(state_dir: &Path) -> PathBuf {
    state_dir.join(MESH_FORWARDING_STATE_FILE)
}

fn read_state(state_dir: &Path) -> io::Result<ForwardingState> {
    match std::fs::read(state_path(state_dir)) {
        Ok(bytes) => serde_json::from_slice(&bytes)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string())),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(ForwardingState::default()),
        Err(e) => Err(e),
    }
}

/// Writes the state, or removes the file when nothing is held. The write goes
/// through a temporary file and a rename.
fn write_state(state_dir: &Path, state: &ForwardingState) -> io::Result<()> {
    let path = state_path(state_dir);
    if state.entries.is_empty() {
        return match std::fs::remove_file(&path) {
            Err(e) if e.kind() != io::ErrorKind::NotFound => Err(e),
            _ => Ok(()),
        };
    }
    std::fs::create_dir_all(state_dir)?;
    let temporary = state_dir.join(format!("{MESH_FORWARDING_STATE_FILE}.tmp"));
    let bytes = serde_json::to_vec(state).map_err(|e| io::Error::other(e.to_string()))?;
    std::fs::write(&temporary, bytes)?;
    std::fs::rename(&temporary, &path)
}

/// Book-keeping shared by every forwarding guard of the process: the original
/// value of each held entry and how many guards hold it.
#[derive(Debug, Default)]
struct Holdings {
    held: Vec<(ForwardingEntry, usize)>,
}

impl Holdings {
    /// Takes one hold on `(luid, family)`. `current` is read only for the first
    /// hold. Returns whether forwarding must be switched on now.
    fn hold(&mut self, luid: u64, family: IpFamily, current: impl FnOnce() -> bool) -> bool {
        if let Some((_, count)) = self
            .held
            .iter_mut()
            .find(|(e, _)| e.luid == luid && e.family == family)
        {
            *count += 1;
            return false;
        }
        let original = current();
        self.held.push((
            ForwardingEntry {
                luid,
                family,
                original,
            },
            1,
        ));
        !original
    }

    /// Drops one hold. Returns the entry to restore when it was the last one.
    fn release(&mut self, luid: u64, family: IpFamily) -> Option<ForwardingEntry> {
        let position = self
            .held
            .iter()
            .position(|(e, _)| e.luid == luid && e.family == family)?;
        self.held[position].1 -= 1;
        if self.held[position].1 > 0 {
            return None;
        }
        Some(self.held.remove(position).0)
    }

    fn state(&self) -> ForwardingState {
        ForwardingState {
            entries: self.held.iter().map(|(e, _)| *e).collect(),
        }
    }
}

#[cfg(windows)]
pub use native::{
    add_mesh_firewall_rules, add_mesh_nat, enable_mesh_forwarding, recover_mesh_host,
    FirewallGuard, ForwardingGuard, NatGuard,
};

#[cfg(not(windows))]
pub use unsupported::{
    add_mesh_firewall_rules, add_mesh_nat, enable_mesh_forwarding, recover_mesh_host,
    FirewallGuard, ForwardingGuard, NatGuard,
};

#[cfg(not(windows))]
mod unsupported {
    use super::*;

    fn unsupported() -> io::Error {
        io::Error::new(
            io::ErrorKind::Unsupported,
            "mesh host changes are only available on Windows",
        )
    }

    /// Holds interface forwarding on; Windows only.
    #[derive(Debug)]
    pub struct ForwardingGuard(());

    /// Holds the mesh firewall rules of one network; Windows only.
    #[derive(Debug)]
    pub struct FirewallGuard(());

    /// Holds the translation object of one network; Windows only.
    #[derive(Debug)]
    pub struct NatGuard(());

    pub fn add_mesh_nat(network: &str, address: Ipv4Addr, prefix: u8) -> io::Result<NatGuard> {
        let _ = (network, address, prefix);
        Err(unsupported())
    }

    pub fn enable_mesh_forwarding(
        state_dir: &Path,
        mesh_adapter: &str,
        lan_interfaces: &[String],
    ) -> io::Result<ForwardingGuard> {
        let _ = (state_dir, mesh_adapter, lan_interfaces);
        Err(unsupported())
    }

    pub fn add_mesh_firewall_rules(
        network: &str,
        program_path: &Path,
        listen_ports: &[u16],
        mesh_adapter: &str,
    ) -> io::Result<FirewallGuard> {
        let _ = (network, program_path, listen_ports, mesh_adapter);
        Err(unsupported())
    }

    pub fn recover_mesh_host(state_dir: &Path) -> io::Result<RecoveryReport> {
        let _ = state_dir;
        Err(unsupported())
    }
}

#[cfg(windows)]
mod native {
    use super::*;
    use std::mem::zeroed;
    use std::os::windows::ffi::OsStrExt;
    use std::process::Stdio;
    use std::sync::Mutex;

    use windows_sys::Win32::NetworkManagement::IpHelper::{
        ConvertInterfaceAliasToLuid, GetIpInterfaceEntry, InitializeIpInterfaceEntry,
        SetIpInterfaceEntry, MIB_IPINTERFACE_ROW,
    };
    use windows_sys::Win32::NetworkManagement::Ndis::NET_LUID_LH;
    use windows_sys::Win32::Networking::WinSock::{AF_INET, AF_INET6};

    use crate::trusted_command::native_windows_powershell_command;

    /// Process-wide holdings plus the state directory they are mirrored to.
    static HOLDINGS: Mutex<Option<(PathBuf, Holdings)>> = Mutex::new(None);

    fn address_family(family: IpFamily) -> u16 {
        match family {
            IpFamily::Ipv4 => AF_INET,
            IpFamily::Ipv6 => AF_INET6,
        }
    }

    fn win32(result: u32, message: &str) -> io::Result<()> {
        if result == 0 {
            Ok(())
        } else {
            Err(io::Error::new(
                io::Error::from_raw_os_error(result as i32).kind(),
                format!("{message} (Windows error {result})"),
            ))
        }
    }

    fn alias_luid(alias: &str) -> io::Result<u64> {
        check_alias(alias)?;
        let wide: Vec<u16> = std::ffi::OsStr::new(alias)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        let mut luid: NET_LUID_LH = unsafe { zeroed() };
        win32(
            unsafe { ConvertInterfaceAliasToLuid(wide.as_ptr(), &mut luid) },
            "the interface was not found",
        )?;
        Ok(unsafe { luid.Value })
    }

    /// The interface row of `luid` for `family`; `None` when the interface
    /// has no such family.
    fn interface_row(luid: u64, family: IpFamily) -> Option<MIB_IPINTERFACE_ROW> {
        let mut row: MIB_IPINTERFACE_ROW = unsafe { zeroed() };
        unsafe { InitializeIpInterfaceEntry(&mut row) };
        row.Family = address_family(family);
        row.InterfaceLuid.Value = luid;
        (unsafe { GetIpInterfaceEntry(&mut row) } == 0).then_some(row)
    }

    fn set_forwarding(luid: u64, family: IpFamily, enabled: bool) -> io::Result<()> {
        let mut row = interface_row(luid, family).ok_or_else(|| {
            io::Error::new(io::ErrorKind::NotFound, "the interface settings are gone")
        })?;
        if row.ForwardingEnabled == enabled {
            return Ok(());
        }
        row.ForwardingEnabled = enabled;
        if row.Family == AF_INET {
            // SetIpInterfaceEntry rejects a non-zero site prefix for IPv4.
            row.SitePrefixLength = 0;
        }
        win32(
            unsafe { SetIpInterfaceEntry(&mut row) },
            "interface forwarding could not be changed",
        )
    }

    /// Holds interface-level forwarding on for a set of interfaces. Dropping
    /// it restores each original value once no other guard holds it.
    #[derive(Debug)]
    pub struct ForwardingGuard {
        held: Vec<(u64, IpFamily)>,
    }

    impl Drop for ForwardingGuard {
        fn drop(&mut self) {
            let mut slot = HOLDINGS.lock().unwrap_or_else(|e| e.into_inner());
            let Some((dir, holdings)) = slot.as_mut() else {
                return;
            };
            for (luid, family) in self.held.drain(..) {
                if let Some(entry) = holdings.release(luid, family) {
                    let _ = set_forwarding(entry.luid, entry.family, entry.original);
                }
            }
            let _ = write_state(dir, &holdings.state());
        }
    }

    /// Switches forwarding on for the mesh adapter and `lan_interfaces` (by
    /// interface alias), for every IP family each one has. Original values are
    /// written to `state_dir` before anything changes. All interfaces of one
    /// process must use the same `state_dir`.
    pub fn enable_mesh_forwarding(
        state_dir: &Path,
        mesh_adapter: &str,
        lan_interfaces: &[String],
    ) -> io::Result<ForwardingGuard> {
        let mut luids = vec![alias_luid(mesh_adapter)?];
        for alias in lan_interfaces {
            let luid = alias_luid(alias)?;
            if !luids.contains(&luid) {
                luids.push(luid);
            }
        }
        let mut slot = HOLDINGS.lock().unwrap_or_else(|e| e.into_inner());
        match slot.as_ref() {
            Some((dir, holdings)) if dir != state_dir && !holdings.held.is_empty() => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "forwarding is already held with another state directory",
                ));
            }
            Some((dir, _)) if dir == state_dir => {}
            _ => *slot = Some((state_dir.to_path_buf(), Holdings::default())),
        }
        let (dir, holdings) = slot.as_mut().expect("holdings were just set");
        let mut guard = ForwardingGuard { held: Vec::new() };
        let mut switch = Vec::new();
        for luid in luids {
            for family in [IpFamily::Ipv4, IpFamily::Ipv6] {
                let Some(row) = interface_row(luid, family) else {
                    continue;
                };
                if holdings.hold(luid, family, || row.ForwardingEnabled) {
                    switch.push((luid, family));
                }
                guard.held.push((luid, family));
            }
        }
        if guard.held.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "no IP settings on the given interfaces",
            ));
        }
        // Originals are on disk before the first change.
        let written = write_state(dir, &holdings.state());
        drop(slot);
        written?;
        for (luid, family) in switch {
            // On error the guard drops and restores what already changed.
            set_forwarding(luid, family, true)?;
        }
        Ok(guard)
    }

    /// Holds the firewall rules of one network. Dropping it deletes them.
    #[derive(Debug)]
    pub struct FirewallGuard {
        names: [String; 3],
    }

    impl Drop for FirewallGuard {
        fn drop(&mut self) {
            let _ =
                run_firewall_script(REMOVE_SCRIPT, &[("ANIX_MESH_NAMES", self.names.join(","))]);
        }
    }

    const ADD_SCRIPT: &str = r#"$ErrorActionPreference = 'Stop'
$names = $env:ANIX_MESH_NAMES -split ','
Remove-NetFirewallRule -Name $names -ErrorAction SilentlyContinue
$ports = $env:ANIX_MESH_PORTS -split ','
$group = $env:ANIX_MESH_GROUP
$program = $env:ANIX_MESH_PROGRAM
New-NetFirewallRule -Name $names[0] -DisplayName $names[0] -Group $group -Direction Inbound -Action Allow -Program $program -Protocol UDP -LocalPort $ports -Profile Any | Out-Null
New-NetFirewallRule -Name $names[1] -DisplayName $names[1] -Group $group -Direction Inbound -Action Allow -Program $program -Protocol TCP -LocalPort $ports -Profile Any | Out-Null
New-NetFirewallRule -Name $names[2] -DisplayName $names[2] -Group $group -Direction Inbound -Action Allow -Program $program -InterfaceAlias $env:ANIX_MESH_ADAPTER -Profile Any | Out-Null
"#;

    const REMOVE_SCRIPT: &str = r#"$ErrorActionPreference = 'Stop'
Remove-NetFirewallRule -Name ($env:ANIX_MESH_NAMES -split ',') -ErrorAction SilentlyContinue
"#;

    const CLEAR_SCRIPT: &str = r#"$ErrorActionPreference = 'Stop'
Get-NetFirewallRule -Group $env:ANIX_MESH_GROUP -ErrorAction SilentlyContinue | Remove-NetFirewallRule
"#;

    /// Runs a fixed script; every variable value is passed through the
    /// environment, never spliced into the script text.
    fn run_firewall_script(script: &str, values: &[(&str, String)]) -> io::Result<()> {
        run_script(script, values, "the firewall rules could not be changed")
    }

    /// Runs a fixed script with `values` in the environment; `failure` is the
    /// error text when it does not succeed.
    fn run_script(script: &str, values: &[(&str, String)], failure: &str) -> io::Result<()> {
        let mut command = native_windows_powershell_command()?;
        command
            .args(["-NoProfile", "-NonInteractive", "-Command", script])
            .env("ANIX_MESH_GROUP", MESH_FIREWALL_GROUP)
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        for (name, value) in values {
            command.env(name, value);
        }
        if !command.status()?.success() {
            return Err(io::Error::other(failure.to_owned()));
        }
        Ok(())
    }

    /// Adds the rules of `network`: inbound UDP and TCP to `listen_ports` for
    /// `program_path`, and inbound from `mesh_adapter` to `program_path`.
    /// Rules of the same names left from an earlier run are replaced.
    pub fn add_mesh_firewall_rules(
        network: &str,
        program_path: &Path,
        listen_ports: &[u16],
        mesh_adapter: &str,
    ) -> io::Result<FirewallGuard> {
        check_alias(mesh_adapter)?;
        let ports = listen_port_list(listen_ports)?;
        if !program_path.is_absolute() || !program_path.is_file() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "the program path must be an existing absolute file",
            ));
        }
        let program = program_path.to_str().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "the program path is not Unicode",
            )
        })?;
        let guard = FirewallGuard {
            names: firewall_rule_names(network),
        };
        // A failure part-way drops the guard, which removes what was added.
        run_firewall_script(
            ADD_SCRIPT,
            &[
                ("ANIX_MESH_NAMES", guard.names.join(",")),
                ("ANIX_MESH_PORTS", ports),
                ("ANIX_MESH_PROGRAM", program.to_owned()),
                ("ANIX_MESH_ADAPTER", mesh_adapter.to_owned()),
            ],
        )?;
        Ok(guard)
    }

    /// Holds the WinNAT object of one network. Dropping it removes it.
    #[derive(Debug)]
    pub struct NatGuard {
        name: String,
    }

    impl Drop for NatGuard {
        fn drop(&mut self) {
            let _ = run_script(
                NAT_REMOVE_SCRIPT,
                &[("ANIX_MESH_NAT", self.name.clone())],
                "the address translation could not be removed",
            );
        }
    }

    const NAT_ADD_SCRIPT: &str = r#"$ErrorActionPreference = 'Stop'
Get-NetNat -Name $env:ANIX_MESH_NAT -ErrorAction SilentlyContinue | Remove-NetNat -Confirm:$false
New-NetNat -Name $env:ANIX_MESH_NAT -InternalIPInterfaceAddressPrefix $env:ANIX_MESH_PREFIX | Out-Null
"#;

    const NAT_REMOVE_SCRIPT: &str = r#"$ErrorActionPreference = 'Stop'
Get-NetNat -Name $env:ANIX_MESH_NAT -ErrorAction SilentlyContinue | Remove-NetNat -Confirm:$false
"#;

    const NAT_CLEAR_SCRIPT: &str = r#"$ErrorActionPreference = 'Stop'
Get-NetNat -ErrorAction SilentlyContinue | Where-Object { $_.Name -like ($env:ANIX_MESH_NAT_PREFIX + '-*') } | Remove-NetNat -Confirm:$false
"#;

    /// Translates the sources of `network`'s IPv4 virtual subnet (the subnet
    /// holding `address`) to the address of the interface they leave
    /// through. An object of the same name left from an earlier run is
    /// replaced. Fails where WinNAT is missing or takes no further object.
    pub fn add_mesh_nat(network: &str, address: Ipv4Addr, prefix: u8) -> io::Result<NatGuard> {
        let internal = nat_prefix(address, prefix)?;
        let guard = NatGuard {
            name: nat_name(network),
        };
        // A failure part-way drops the guard, which removes what was added.
        run_script(
            NAT_ADD_SCRIPT,
            &[
                ("ANIX_MESH_NAT", guard.name.clone()),
                ("ANIX_MESH_PREFIX", internal),
            ],
            "the address translation could not be added",
        )?;
        Ok(guard)
    }

    /// Puts back what a process that died with guards alive left behind:
    /// restores forwarding values recorded in `state_dir`, removes every
    /// rule of [`MESH_FIREWALL_GROUP`] and every WinNAT object whose name
    /// starts with [`MESH_FIREWALL_RULE_PREFIX`] and `-`. Call once at start, before any guard
    /// is taken.
    pub fn recover_mesh_host(state_dir: &Path) -> io::Result<RecoveryReport> {
        let slot = HOLDINGS.lock().unwrap_or_else(|e| e.into_inner());
        if slot.as_ref().is_some_and(|(_, h)| !h.held.is_empty()) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "recovery runs before any forwarding guard is taken",
            ));
        }
        let mut report = RecoveryReport::default();
        let state = read_state(state_dir)?;
        let mut left = ForwardingState::default();
        for entry in state.entries {
            match set_forwarding(entry.luid, entry.family, entry.original) {
                Ok(()) => report.forwarding_restored += 1,
                Err(e) if e.kind() == io::ErrorKind::NotFound => report.forwarding_failed += 1,
                Err(_) => {
                    // Kept for the next start; the interface may come back.
                    report.forwarding_failed += 1;
                    left.entries.push(entry);
                }
            }
        }
        write_state(state_dir, &left)?;
        drop(slot);
        report.firewall_cleared = run_firewall_script(CLEAR_SCRIPT, &[]).is_ok();
        report.nat_cleared = run_script(
            NAT_CLEAR_SCRIPT,
            &[("ANIX_MESH_NAT_PREFIX", MESH_FIREWALL_RULE_PREFIX.to_owned())],
            "the address translation could not be removed",
        )
        .is_ok();
        Ok(report)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_network_names_are_kept_in_rule_names() {
        assert_eq!(network_label("office-1"), "office-1");
        let names = firewall_rule_names("office-1");
        assert_eq!(names[0], "AnixOpsMesh-office-1-listen-udp");
        assert_eq!(names[1], "AnixOpsMesh-office-1-listen-tcp");
        assert_eq!(names[2], "AnixOpsMesh-office-1-adapter");
    }

    #[test]
    fn other_characters_are_replaced_and_the_label_gets_a_hash() {
        let label = network_label("a,b*c");
        assert!(label.starts_with("a_b_c-"), "{label}");
        assert_eq!(label.len(), "a_b_c-".len() + 8);
        assert!(label
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'));
        // Names that map to the same characters still differ.
        assert_ne!(network_label("a,b"), network_label("a.b"));
        assert_ne!(network_label("a,b"), "a_b");
        // Non-ASCII and empty names stay usable.
        assert!(network_label("办公室").len() > 8);
        assert!(!network_label("").is_empty());
    }

    #[test]
    fn long_names_are_cut_with_a_hash() {
        let long = "n".repeat(200);
        let label = network_label(&long);
        assert!(label.len() <= MAX_NETWORK_LABEL);
        assert_ne!(label, network_label(&"n".repeat(201)));
        assert!(!firewall_rule_names(&long)[0].contains(','));
    }

    #[test]
    fn translation_objects_are_named_and_cover_the_virtual_subnet() {
        assert_eq!(nat_name("office-1"), "AnixOpsMesh-office-1");
        assert!(nat_name("a,b").starts_with("AnixOpsMesh-a_b-"));
        assert_eq!(
            nat_prefix(Ipv4Addr::new(10, 144, 3, 7), 24).unwrap(),
            "10.144.3.0/24"
        );
        assert_eq!(
            nat_prefix(Ipv4Addr::new(100, 100, 255, 1), 10).unwrap(),
            "100.64.0.0/10"
        );
        assert!(nat_prefix(Ipv4Addr::new(10, 0, 0, 1), 0).is_err());
        assert!(nat_prefix(Ipv4Addr::new(10, 0, 0, 1), 31).is_err());
        assert!(nat_prefix(Ipv4Addr::new(10, 0, 0, 1), 32).is_err());
    }

    #[test]
    fn listen_ports_are_sorted_and_deduplicated() {
        assert_eq!(
            listen_port_list(&[11010, 0, 443, 11010]).unwrap(),
            "443,11010"
        );
        assert!(listen_port_list(&[]).is_err());
        assert!(listen_port_list(&[0]).is_err());
    }

    #[test]
    fn interface_names_are_checked() {
        assert!(check_alias("Ethernet 2").is_ok());
        assert!(check_alias("").is_err());
        assert!(check_alias("bad\nname").is_err());
        assert!(check_alias(&"x".repeat(257)).is_err());
    }

    #[test]
    fn the_first_hold_records_the_original_and_the_last_release_returns_it() {
        let mut holdings = Holdings::default();
        assert!(holdings.hold(7, IpFamily::Ipv4, || false));
        // A second hold neither reads the interface again nor switches it.
        assert!(!holdings.hold(7, IpFamily::Ipv4, || panic!("read twice")));
        // An interface that already forwards is not switched.
        assert!(!holdings.hold(9, IpFamily::Ipv6, || true));
        assert_eq!(holdings.state().entries.len(), 2);

        assert_eq!(holdings.release(7, IpFamily::Ipv4), None);
        assert_eq!(
            holdings.release(7, IpFamily::Ipv4),
            Some(ForwardingEntry {
                luid: 7,
                family: IpFamily::Ipv4,
                original: false,
            })
        );
        assert_eq!(holdings.release(7, IpFamily::Ipv4), None);
        assert_eq!(holdings.state().entries.len(), 1);
    }

    #[test]
    fn the_state_file_round_trips_and_is_removed_when_empty() {
        let dir = std::env::temp_dir().join(format!("mesh-host-state-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(read_state(&dir).unwrap(), ForwardingState::default());

        let state = ForwardingState {
            entries: vec![
                ForwardingEntry {
                    luid: u64::MAX,
                    family: IpFamily::Ipv4,
                    original: false,
                },
                ForwardingEntry {
                    luid: 1,
                    family: IpFamily::Ipv6,
                    original: true,
                },
            ],
        };
        write_state(&dir, &state).unwrap();
        assert_eq!(read_state(&dir).unwrap(), state);
        let text = std::fs::read_to_string(state_path(&dir)).unwrap();
        assert!(text.contains("\"ipv6\""), "{text}");

        write_state(&dir, &ForwardingState::default()).unwrap();
        assert!(!state_path(&dir).exists());
        std::fs::write(state_path(&dir), b"not json").unwrap();
        assert_eq!(
            read_state(&dir).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(not(windows))]
    #[test]
    fn other_systems_refuse_host_changes() {
        let dir = std::env::temp_dir();
        assert_eq!(
            enable_mesh_forwarding(&dir, "mesh0", &[])
                .unwrap_err()
                .kind(),
            io::ErrorKind::Unsupported
        );
        assert_eq!(
            add_mesh_firewall_rules("n", Path::new("/bin/true"), &[1], "mesh0")
                .unwrap_err()
                .kind(),
            io::ErrorKind::Unsupported
        );
        assert_eq!(
            recover_mesh_host(&dir).unwrap_err().kind(),
            io::ErrorKind::Unsupported
        );
        assert_eq!(
            add_mesh_nat("n", Ipv4Addr::new(10, 0, 0, 1), 24)
                .unwrap_err()
                .kind(),
            io::ErrorKind::Unsupported
        );
    }
}
