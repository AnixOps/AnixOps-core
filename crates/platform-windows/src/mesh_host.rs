//! Host changes a Windows mesh node needs when it advertises subnets or relays:
//! interface-level IP forwarding and inbound firewall rules.
//!
//! Both are owned by guards. Dropping a guard puts the host back; what a guard
//! changed is also written to a state directory, so a process that died with a
//! guard alive is cleaned up by [`recover_mesh_host`] on its next start.
//!
//! - One process per host holds these changes: the first call takes an
//!   exclusive lock file in the state directory and keeps it until the process
//!   exits, and a second process is refused instead of undoing the first one's
//!   changes.
//! - The state directory must lie under `%ProgramData%\AnixOps`; it is created
//!   or repaired with the protected access list of [`crate::managed_files`]
//!   (owner Administrators, SYSTEM and Administrators only, no reparse
//!   points), and the state file is written through a random, exclusively
//!   created temporary file. A standard user can therefore neither plant
//!   records that a privileged recovery would act on nor redirect a write.
//! - Forwarding is switched per interface (`MIB_IPINTERFACE_ROW.ForwardingEnabled`)
//!   on the mesh adapter and the chosen LAN interfaces only; the global
//!   `IPEnableRouter` setting is never touched. IPv6 is switched only when
//!   asked for. Windows forwards between every pair of interfaces that have
//!   forwarding on, so other interfaces that already forward (virtual
//!   switches, connection sharing) can reach the chosen LAN as well. Several
//!   guards may hold the same interface: the original value is restored when
//!   the last one is dropped. Records name the interface by LUID and GUID, and
//!   a record whose GUID no longer resolves to that LUID is not applied.
//! - Firewall rules live in one rule group and are named from a fixed prefix
//!   and the network name. They allow inbound TCP/UDP to this program's listen
//!   ports (the underlay, from any address), and block inbound traffic to this
//!   program arriving on the mesh adapter, so that no other service of the
//!   program (a proxy inbound, a control port) is reachable from mesh members
//!   (requirement R5). The mesh itself reads packets from the adapter and needs
//!   no socket there. Traffic the host forwards is not subject to host inbound
//!   rules; that members only reach advertised subnets is enforced by the
//!   mesh's receive check, which delivers only packets for this node's
//!   addresses and its own advertised subnets.

#![cfg_attr(not(windows), allow(dead_code))]

use std::io;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// Rule group of every firewall rule this module creates.
pub const MESH_FIREWALL_GROUP: &str = "AnixOps Mesh";
/// Prefix of every firewall rule name this module creates.
pub const MESH_FIREWALL_RULE_PREFIX: &str = "AnixOpsMesh";
/// File in the state directory that holds original forwarding values.
pub const MESH_FORWARDING_STATE_FILE: &str = "mesh-forwarding.json";
/// File in the state directory held open exclusively by the one process that
/// makes host changes.
pub const MESH_HOST_LOCK_FILE: &str = "mesh-host.lock";

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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ForwardingEntry {
    pub luid: u64,
    /// Interface GUID in braces; checked against the LUID before restoring.
    pub guid: String,
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
    /// Entries dropped: the interface is gone or is another one now.
    pub forwarding_gone: usize,
    /// Entries that could not be restored and stay recorded for next time.
    pub forwarding_kept: usize,
    /// The state file could not be parsed and was set aside.
    pub state_set_aside: bool,
    /// Whether leftover rules of [`MESH_FIREWALL_GROUP`] were removed.
    pub firewall_cleared: bool,
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
/// listen ports over UDP, listen ports over TCP, the block on the mesh
/// adapter.
pub fn firewall_rule_names(network: &str) -> [String; 3] {
    let label = network_label(network);
    [
        format!("{MESH_FIREWALL_RULE_PREFIX}-{label}-listen-udp"),
        format!("{MESH_FIREWALL_RULE_PREFIX}-{label}-listen-tcp"),
        format!("{MESH_FIREWALL_RULE_PREFIX}-{label}-adapter-block"),
    ]
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

/// Interface aliases must be non-empty, at most 256 characters, free of
/// control characters and of the wildcard characters `* ? [ ]` and the
/// backtick, which the firewall cmdlets would read as a pattern matching
/// other interfaces.
fn check_alias(alias: &str) -> io::Result<()> {
    if alias.is_empty()
        || alias.chars().count() > 256
        || alias
            .chars()
            .any(|c| c.is_control() || matches!(c, '*' | '?' | '[' | ']' | '`'))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid interface name",
        ));
    }
    Ok(())
}

/// The state directory must lie under `%ProgramData%\AnixOps`, where
/// [`crate::managed_files`] keeps folders protected.
fn check_state_dir(state_dir: &Path) -> io::Result<()> {
    if !crate::managed_files::is_within_managed_root(state_dir) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "the mesh host state directory must lie under %ProgramData%\\AnixOps",
        ));
    }
    Ok(())
}

fn state_path(state_dir: &Path) -> PathBuf {
    state_dir.join(MESH_FORWARDING_STATE_FILE)
}

fn parse_state(bytes: &[u8]) -> io::Result<ForwardingState> {
    serde_json::from_slice(bytes)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))
}

/// Book-keeping of the forwarding entries the process holds: the original
/// value of each, how many guards hold it, and entries whose restore failed.
#[derive(Debug, Default)]
struct Holdings {
    held: Vec<(ForwardingEntry, usize)>,
    /// Restores that failed for a reason other than the interface being
    /// gone; kept on disk for the next recovery.
    stuck: Vec<ForwardingEntry>,
}

impl Holdings {
    fn position(&self, luid: u64, family: IpFamily) -> Option<usize> {
        self.held
            .iter()
            .position(|(e, _)| e.luid == luid && e.family == family)
    }

    /// Takes one hold on `(luid, family)`. `current` is read only for the first
    /// hold. Returns whether forwarding must be switched on now.
    fn hold(
        &mut self,
        luid: u64,
        guid: &str,
        family: IpFamily,
        current: impl FnOnce() -> bool,
    ) -> bool {
        if let Some(position) = self.position(luid, family) {
            self.held[position].1 += 1;
            return false;
        }
        let original = current();
        self.held.push((
            ForwardingEntry {
                luid,
                guid: guid.to_owned(),
                family,
                original,
            },
            1,
        ));
        !original
    }

    /// Drops one hold. Returns the entry to restore when it was the last one.
    fn release(&mut self, luid: u64, family: IpFamily) -> Option<ForwardingEntry> {
        let position = self.position(luid, family)?;
        self.held[position].1 -= 1;
        if self.held[position].1 > 0 {
            return None;
        }
        Some(self.held.remove(position).0)
    }

    fn is_empty(&self) -> bool {
        self.held.is_empty()
    }

    fn state(&self) -> ForwardingState {
        ForwardingState {
            entries: self
                .held
                .iter()
                .map(|(e, _)| e.clone())
                .chain(self.stuck.iter().cloned())
                .collect(),
        }
    }
}

#[cfg(windows)]
pub use native::{
    add_mesh_firewall_rules, enable_mesh_forwarding, recover_mesh_host, FirewallGuard,
    ForwardingGuard,
};

#[cfg(not(windows))]
pub use unsupported::{
    add_mesh_firewall_rules, enable_mesh_forwarding, recover_mesh_host, FirewallGuard,
    ForwardingGuard,
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

    pub fn enable_mesh_forwarding(
        state_dir: &Path,
        mesh_adapter: &str,
        lan_interfaces: &[String],
        ipv6: bool,
    ) -> io::Result<ForwardingGuard> {
        let _ = (state_dir, mesh_adapter, lan_interfaces, ipv6);
        Err(unsupported())
    }

    pub fn add_mesh_firewall_rules(
        state_dir: &Path,
        network: &str,
        program_path: &Path,
        listen_ports: &[u16],
        mesh_adapter: &str,
    ) -> io::Result<FirewallGuard> {
        let _ = (state_dir, network, program_path, listen_ports, mesh_adapter);
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
    use std::fs::{File, OpenOptions};
    use std::mem::zeroed;
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::fs::OpenOptionsExt;
    use std::process::Stdio;
    use std::sync::{Mutex, MutexGuard};

    use windows_sys::core::GUID;
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        ConvertInterfaceAliasToLuid, ConvertInterfaceGuidToLuid, ConvertInterfaceLuidToGuid,
        GetIpInterfaceEntry, InitializeIpInterfaceEntry, SetIpInterfaceEntry, MIB_IPINTERFACE_ROW,
    };
    use windows_sys::Win32::NetworkManagement::Ndis::NET_LUID_LH;
    use windows_sys::Win32::Networking::WinSock::{AF_INET, AF_INET6};

    use crate::managed_files::{
        ensure_managed_directory, read_managed_file, write_managed_file_atomic,
    };
    use crate::trusted_command::native_windows_powershell_command;

    /// `FILE_FLAG_OPEN_REPARSE_POINT`: open a link itself, never its target.
    const OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    /// `ERROR_SHARING_VIOLATION`: another process holds the lock file.
    const SHARING_VIOLATION: i32 = 32;

    /// Everything this process holds on the host.
    struct Host {
        dir: PathBuf,
        /// Held open without sharing for the life of the process.
        _lock: File,
        holdings: Holdings,
        /// Networks with a live [`FirewallGuard`].
        networks: Vec<String>,
    }

    static HOST: Mutex<Option<Host>> = Mutex::new(None);

    /// The host state of this process, taking the lock file in `state_dir`
    /// on first use. Refused when another process holds the lock, or when
    /// this process already uses another state directory.
    fn host(state_dir: &Path) -> io::Result<MutexGuard<'static, Option<Host>>> {
        check_state_dir(state_dir)?;
        let mut slot = HOST.lock().unwrap_or_else(|e| e.into_inner());
        match slot.as_ref() {
            Some(host) if host.dir == state_dir => return Ok(slot),
            Some(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "mesh host changes already use another state directory",
                ))
            }
            None => {}
        }
        ensure_managed_directory(state_dir)?;
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .share_mode(0)
            .custom_flags(OPEN_REPARSE_POINT)
            .open(state_dir.join(MESH_HOST_LOCK_FILE))
            .map_err(|error| {
                if error.raw_os_error() == Some(SHARING_VIOLATION) {
                    io::Error::new(
                        io::ErrorKind::ResourceBusy,
                        "another process holds the mesh host changes",
                    )
                } else {
                    error
                }
            })?;
        *slot = Some(Host {
            dir: state_dir.to_path_buf(),
            _lock: lock,
            holdings: Holdings::default(),
            networks: Vec::new(),
        });
        Ok(slot)
    }

    fn read_state(state_dir: &Path) -> io::Result<ForwardingState> {
        match read_managed_file(&state_path(state_dir)) {
            Ok(bytes) => parse_state(&bytes),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(ForwardingState::default()),
            Err(e) => Err(e),
        }
    }

    /// Writes the state, or removes the file when nothing is recorded.
    fn write_state(state_dir: &Path, state: &ForwardingState) -> io::Result<()> {
        let path = state_path(state_dir);
        if state.entries.is_empty() {
            return match std::fs::remove_file(&path) {
                Err(e) if e.kind() != io::ErrorKind::NotFound => Err(e),
                _ => Ok(()),
            };
        }
        let bytes = serde_json::to_vec(state).map_err(|e| io::Error::other(e.to_string()))?;
        write_managed_file_atomic(&path, &bytes)
    }

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

    fn format_guid(guid: &GUID) -> String {
        format!(
            "{{{:08x}-{:04x}-{:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}}}",
            guid.data1,
            guid.data2,
            guid.data3,
            guid.data4[0],
            guid.data4[1],
            guid.data4[2],
            guid.data4[3],
            guid.data4[4],
            guid.data4[5],
            guid.data4[6],
            guid.data4[7]
        )
    }

    fn parse_guid(text: &str) -> Option<GUID> {
        let hex = text.strip_prefix('{')?.strip_suffix('}')?;
        let parts: Vec<&str> = hex.split('-').collect();
        if parts.len() != 5
            || [8, 4, 4, 4, 12] != [0, 1, 2, 3, 4].map(|i| parts[i].len())
            || !hex.chars().all(|c| c == '-' || c.is_ascii_hexdigit())
        {
            return None;
        }
        let tail = format!("{}{}", parts[3], parts[4]);
        let mut data4 = [0u8; 8];
        for (i, byte) in data4.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&tail[i * 2..i * 2 + 2], 16).ok()?;
        }
        Some(GUID {
            data1: u32::from_str_radix(parts[0], 16).ok()?,
            data2: u16::from_str_radix(parts[1], 16).ok()?,
            data3: u16::from_str_radix(parts[2], 16).ok()?,
            data4,
        })
    }

    fn luid_guid(luid: u64) -> io::Result<String> {
        let mut net_luid: NET_LUID_LH = unsafe { zeroed() };
        net_luid.Value = luid;
        let mut guid: GUID = unsafe { zeroed() };
        win32(
            unsafe { ConvertInterfaceLuidToGuid(&net_luid, &mut guid) },
            "the interface GUID could not be read",
        )?;
        Ok(format_guid(&guid))
    }

    /// Whether the interface recorded as `luid` is still the one with `guid`.
    fn same_interface(luid: u64, guid: &str) -> bool {
        let Some(guid) = parse_guid(guid) else {
            return false;
        };
        let mut found: NET_LUID_LH = unsafe { zeroed() };
        unsafe { ConvertInterfaceGuidToLuid(&guid, &mut found) == 0 && found.Value == luid }
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

    /// Restores `entry` when it still names the same interface. `Ok(false)`
    /// when the interface is gone or is another one now.
    fn restore(entry: &ForwardingEntry) -> io::Result<bool> {
        if !same_interface(entry.luid, &entry.guid) {
            return Ok(false);
        }
        match set_forwarding(entry.luid, entry.family, entry.original) {
            Ok(()) => Ok(true),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(e),
        }
    }

    /// Holds interface-level forwarding on for a set of interfaces. Dropping
    /// it restores each original value once no other guard holds it.
    #[derive(Debug)]
    pub struct ForwardingGuard {
        held: Vec<(u64, IpFamily)>,
    }

    impl Drop for ForwardingGuard {
        fn drop(&mut self) {
            // A guard emptied on an error path inside `enable_mesh_forwarding`
            // is dropped while that call still holds the lock.
            if self.held.is_empty() {
                return;
            }
            let mut slot = HOST.lock().unwrap_or_else(|e| e.into_inner());
            let Some(host) = slot.as_mut() else {
                return;
            };
            for (luid, family) in self.held.drain(..) {
                if let Some(entry) = host.holdings.release(luid, family) {
                    // A failed restore stays recorded for the next recovery.
                    if restore(&entry).is_err() {
                        host.holdings.stuck.push(entry);
                    }
                }
            }
            let _ = write_state(&host.dir, &host.holdings.state());
        }
    }

    /// Switches forwarding on for the mesh adapter and `lan_interfaces` (by
    /// interface alias) for IPv4, and for IPv6 too when `ipv6` is set, on
    /// each interface that has the family. Original values are written to
    /// `state_dir` before anything changes.
    pub fn enable_mesh_forwarding(
        state_dir: &Path,
        mesh_adapter: &str,
        lan_interfaces: &[String],
        ipv6: bool,
    ) -> io::Result<ForwardingGuard> {
        check_state_dir(state_dir)?;
        let mut luids = vec![alias_luid(mesh_adapter)?];
        for alias in lan_interfaces {
            let luid = alias_luid(alias)?;
            if !luids.contains(&luid) {
                luids.push(luid);
            }
        }
        let families: &[IpFamily] = if ipv6 {
            &[IpFamily::Ipv4, IpFamily::Ipv6]
        } else {
            &[IpFamily::Ipv4]
        };
        let mut interfaces = Vec::new();
        for luid in luids {
            interfaces.push((luid, luid_guid(luid)?));
        }

        let mut slot = host(state_dir)?;
        let host = slot.as_mut().expect("host state was just taken");
        // The whole change happens under the lock, so a second caller never
        // sees a hold whose switch has not happened yet.
        let mut guard = ForwardingGuard { held: Vec::new() };
        let mut switch = Vec::new();
        for (luid, guid) in &interfaces {
            for &family in families {
                let Some(row) = interface_row(*luid, family) else {
                    continue;
                };
                if host
                    .holdings
                    .hold(*luid, guid, family, || row.ForwardingEnabled)
                {
                    switch.push((*luid, family));
                }
                guard.held.push((*luid, family));
            }
        }
        let undo = |host: &mut Host, guard: &mut ForwardingGuard| {
            for (luid, family) in guard.held.drain(..) {
                if let Some(entry) = host.holdings.release(luid, family) {
                    if restore(&entry).is_err() {
                        host.holdings.stuck.push(entry);
                    }
                }
            }
            let _ = write_state(&host.dir, &host.holdings.state());
        };
        if guard.held.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "no IP settings on the given interfaces",
            ));
        }
        // Originals are on disk before the first change.
        if let Err(error) = write_state(&host.dir, &host.holdings.state()) {
            undo(host, &mut guard);
            return Err(error);
        }
        for (luid, family) in switch {
            if let Err(error) = set_forwarding(luid, family, true) {
                undo(host, &mut guard);
                return Err(error);
            }
        }
        Ok(guard)
    }

    /// Holds the firewall rules of one network. Dropping it deletes them.
    #[derive(Debug)]
    pub struct FirewallGuard {
        network: String,
        names: [String; 3],
    }

    impl Drop for FirewallGuard {
        fn drop(&mut self) {
            let _ =
                run_firewall_script(REMOVE_SCRIPT, &[("ANIX_MESH_NAMES", self.names.join(","))]);
            let mut slot = HOST.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(host) = slot.as_mut() {
                host.networks.retain(|network| *network != self.network);
            }
        }
    }

    const ADD_SCRIPT: &str = r#"$ErrorActionPreference = 'Stop'
$names = $env:ANIX_MESH_NAMES -split ','
Remove-NetFirewallRule -Name $names -PolicyStore PersistentStore -ErrorAction SilentlyContinue
$ports = $env:ANIX_MESH_PORTS -split ','
$group = $env:ANIX_MESH_GROUP
$program = $env:ANIX_MESH_PROGRAM
$adapter = [System.Management.Automation.WildcardPattern]::Escape($env:ANIX_MESH_ADAPTER)
if (@(Get-NetAdapter -InterfaceAlias $adapter -IncludeHidden -ErrorAction Stop).Count -ne 1) { throw 'adapter' }
New-NetFirewallRule -Name $names[0] -DisplayName $names[0] -Group $group -PolicyStore PersistentStore -Direction Inbound -Action Allow -Program $program -Protocol UDP -LocalPort $ports -Profile Any | Out-Null
New-NetFirewallRule -Name $names[1] -DisplayName $names[1] -Group $group -PolicyStore PersistentStore -Direction Inbound -Action Allow -Program $program -Protocol TCP -LocalPort $ports -Profile Any | Out-Null
New-NetFirewallRule -Name $names[2] -DisplayName $names[2] -Group $group -PolicyStore PersistentStore -Direction Inbound -Action Block -Program $program -InterfaceAlias $adapter -Profile Any | Out-Null
"#;

    const REMOVE_SCRIPT: &str = r#"$ErrorActionPreference = 'Stop'
Remove-NetFirewallRule -Name ($env:ANIX_MESH_NAMES -split ',') -PolicyStore PersistentStore -ErrorAction SilentlyContinue
"#;

    const CLEAR_SCRIPT: &str = r#"$ErrorActionPreference = 'Stop'
Get-NetFirewallRule -PolicyStore PersistentStore -Group $env:ANIX_MESH_GROUP -ErrorAction SilentlyContinue |
  Where-Object { $_.Name.StartsWith($env:ANIX_MESH_PREFIX + '-', [System.StringComparison]::Ordinal) } |
  Remove-NetFirewallRule
"#;

    /// Runs a fixed script; every variable value is passed through the
    /// environment, never spliced into the script text.
    fn run_firewall_script(script: &str, values: &[(&str, String)]) -> io::Result<()> {
        let mut command = native_windows_powershell_command()?;
        command
            .args(["-NoProfile", "-NonInteractive", "-Command", script])
            .env("ANIX_MESH_GROUP", MESH_FIREWALL_GROUP)
            .env("ANIX_MESH_PREFIX", MESH_FIREWALL_RULE_PREFIX)
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        for (name, value) in values {
            command.env(name, value);
        }
        if !command.status()?.success() {
            return Err(io::Error::other("the firewall rules could not be changed"));
        }
        Ok(())
    }

    /// Adds the rules of `network`: inbound UDP and TCP to `listen_ports` for
    /// `program_path`, and a block on inbound traffic to `program_path` that
    /// arrives on `mesh_adapter`. Rules of the same names left from an
    /// earlier run are replaced. One guard per network at a time.
    pub fn add_mesh_firewall_rules(
        state_dir: &Path,
        network: &str,
        program_path: &Path,
        listen_ports: &[u16],
        mesh_adapter: &str,
    ) -> io::Result<FirewallGuard> {
        check_state_dir(state_dir)?;
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
        {
            let mut slot = host(state_dir)?;
            let host = slot.as_mut().expect("host state was just taken");
            if host.networks.iter().any(|held| held == network) {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "the firewall rules of this network are already held",
                ));
            }
            host.networks.push(network.to_owned());
        }
        let guard = FirewallGuard {
            network: network.to_owned(),
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

    /// Puts back what a process that died with guards alive left behind:
    /// restores forwarding values recorded in `state_dir` (only for
    /// interfaces whose GUID still matches) and removes our rules of
    /// [`MESH_FIREWALL_GROUP`]. Call once at start, before any guard is taken,
    /// and from the uninstaller. A state file that cannot be parsed is set
    /// aside and the rules are still removed.
    pub fn recover_mesh_host(state_dir: &Path) -> io::Result<RecoveryReport> {
        let mut slot = host(state_dir)?;
        let host = slot.as_mut().expect("host state was just taken");
        if !host.holdings.is_empty() || !host.networks.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "recovery runs before any guard is taken",
            ));
        }
        let mut report = RecoveryReport::default();
        let state = match read_state(state_dir) {
            Ok(state) => state,
            Err(error) if error.kind() == io::ErrorKind::InvalidData => {
                let path = state_path(state_dir);
                let aside = state_dir.join(format!("{MESH_FORWARDING_STATE_FILE}.corrupt"));
                let _ = std::fs::remove_file(&aside);
                std::fs::rename(&path, &aside)?;
                report.state_set_aside = true;
                ForwardingState::default()
            }
            Err(error) => return Err(error),
        };
        let mut kept = Vec::new();
        for entry in state.entries {
            match restore(&entry) {
                Ok(true) => report.forwarding_restored += 1,
                Ok(false) => report.forwarding_gone += 1,
                Err(_) => {
                    report.forwarding_kept += 1;
                    kept.push(entry);
                }
            }
        }
        host.holdings.stuck = kept;
        write_state(state_dir, &host.holdings.state())?;
        drop(slot);
        report.firewall_cleared = run_firewall_script(CLEAR_SCRIPT, &[]).is_ok();
        Ok(report)
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn guids_round_trip() {
            let guid = GUID {
                data1: 0x0123_4567,
                data2: 0x89ab,
                data3: 0xcdef,
                data4: [0, 1, 2, 3, 4, 5, 6, 0xff],
            };
            let text = format_guid(&guid);
            assert_eq!(text, "{01234567-89ab-cdef-0001-0203040506ff}");
            let back = parse_guid(&text).unwrap();
            assert_eq!(
                (back.data1, back.data2, back.data3, back.data4),
                (guid.data1, guid.data2, guid.data3, guid.data4)
            );
            assert!(parse_guid("01234567-89ab-cdef-0001-0203040506ff").is_none());
            assert!(parse_guid("{0123456-89ab-cdef-0001-0203040506ff}").is_none());
            assert!(parse_guid("{0123456g-89ab-cdef-0001-0203040506ff}").is_none());
        }

        #[test]
        fn a_state_directory_outside_the_managed_root_is_refused() {
            let outside = std::env::temp_dir().join("mesh-host-outside");
            let error = enable_mesh_forwarding(&outside, "Loopback Pseudo-Interface 1", &[], false)
                .unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
            assert_eq!(
                recover_mesh_host(&outside).unwrap_err().kind(),
                io::ErrorKind::PermissionDenied
            );
        }
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
        assert_eq!(names[2], "AnixOpsMesh-office-1-adapter-block");
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
        assert!(check_alias("vEthernet (WSL)").is_ok());
        assert!(check_alias("").is_err());
        assert!(check_alias("bad\nname").is_err());
        assert!(check_alias(&"x".repeat(257)).is_err());
        // Wildcards would match other interfaces in the firewall cmdlets.
        for alias in ["*", "Ether?", "Ethernet [2]", "Eth`ernet"] {
            assert!(check_alias(alias).is_err(), "{alias}");
        }
    }

    #[test]
    fn the_state_directory_must_be_under_the_managed_root() {
        let root = crate::managed_files::windows_managed_root_directory();
        assert!(check_state_dir(&root.join("mesh")).is_ok());
        assert_eq!(
            check_state_dir(&std::env::temp_dir().join("mesh"))
                .unwrap_err()
                .kind(),
            io::ErrorKind::PermissionDenied
        );
        assert!(check_state_dir(&root.join("..").join("elsewhere")).is_err());
    }

    #[test]
    fn the_first_hold_records_the_original_and_the_last_release_returns_it() {
        let mut holdings = Holdings::default();
        assert!(holdings.hold(7, "{g7}", IpFamily::Ipv4, || false));
        // A second hold neither reads the interface again nor switches it.
        assert!(!holdings.hold(7, "{g7}", IpFamily::Ipv4, || panic!("read twice")));
        // An interface that already forwards is not switched.
        assert!(!holdings.hold(9, "{g9}", IpFamily::Ipv6, || true));
        assert_eq!(holdings.state().entries.len(), 2);

        assert_eq!(holdings.release(7, IpFamily::Ipv4), None);
        assert_eq!(
            holdings.release(7, IpFamily::Ipv4),
            Some(ForwardingEntry {
                luid: 7,
                guid: "{g7}".into(),
                family: IpFamily::Ipv4,
                original: false,
            })
        );
        assert_eq!(holdings.release(7, IpFamily::Ipv4), None);
        assert_eq!(holdings.state().entries.len(), 1);
    }

    #[test]
    fn stuck_restores_stay_in_the_state() {
        let mut holdings = Holdings::default();
        holdings.hold(7, "{g7}", IpFamily::Ipv4, || false);
        let entry = holdings.release(7, IpFamily::Ipv4).unwrap();
        holdings.stuck.push(entry.clone());
        assert!(holdings.is_empty());
        assert_eq!(holdings.state().entries, vec![entry]);
    }

    #[test]
    fn the_state_format_round_trips() {
        let state = ForwardingState {
            entries: vec![
                ForwardingEntry {
                    luid: u64::MAX,
                    guid: "{01234567-89ab-cdef-0001-0203040506ff}".into(),
                    family: IpFamily::Ipv4,
                    original: false,
                },
                ForwardingEntry {
                    luid: 1,
                    guid: "{00000000-0000-0000-0000-000000000001}".into(),
                    family: IpFamily::Ipv6,
                    original: true,
                },
            ],
        };
        let bytes = serde_json::to_vec(&state).unwrap();
        assert_eq!(parse_state(&bytes).unwrap(), state);
        assert!(String::from_utf8(bytes).unwrap().contains("\"ipv6\""));
        assert_eq!(
            parse_state(b"not json").unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        // Records without a GUID are refused, not applied blindly.
        assert!(
            parse_state(br#"{"entries":[{"luid":1,"family":"ipv4","original":true}]}"#).is_err()
        );
    }

    #[cfg(not(windows))]
    #[test]
    fn other_systems_refuse_host_changes() {
        let dir = std::env::temp_dir();
        assert_eq!(
            enable_mesh_forwarding(&dir, "mesh0", &[], false)
                .unwrap_err()
                .kind(),
            io::ErrorKind::Unsupported
        );
        assert_eq!(
            add_mesh_firewall_rules(&dir, "n", Path::new("/bin/true"), &[1], "mesh0")
                .unwrap_err()
                .kind(),
            io::ErrorKind::Unsupported
        );
        assert_eq!(
            recover_mesh_host(&dir).unwrap_err().kind(),
            io::ErrorKind::Unsupported
        );
    }
}
