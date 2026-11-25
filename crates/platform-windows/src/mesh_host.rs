//! Host changes a Windows mesh node needs when it advertises subnets or relays:
//! interface-level IP forwarding and inbound firewall rules.
//!
//! Both are owned by guards. Dropping a guard puts the host back; what a guard
//! changed is also written to a state directory, so a process that died with a
//! guard alive is cleaned up by [`recover_mesh_host`] on its next start.
//!
//! - One process per host holds these changes: the first call creates the
//!   host-wide named object [`MESH_HOST_MUTEX`] (open to SYSTEM and
//!   Administrators only) and keeps it until the process exits; a second
//!   process, whatever it was started with, is refused instead of undoing the
//!   first one's changes. A standard user can neither create nor open that
//!   name in the global namespace, so it cannot be held to block the module.
//! - The state directory is fixed: [`mesh_host_state_dir`], under
//!   `%ProgramData%\AnixOps`. It is created or repaired with the protected
//!   access list of [`crate::managed_files`] (owner Administrators, SYSTEM and
//!   Administrators only, no reparse points), the state file is written
//!   through a random, exclusively created temporary file, and it is read only
//!   when owned by SYSTEM or Administrators. A record owned by anyone else is
//!   set aside, not applied.
//! - Forwarding is switched per interface (`MIB_IPINTERFACE_ROW.ForwardingEnabled`)
//!   on the mesh adapter and the chosen LAN interfaces only; the global
//!   `IPEnableRouter` setting is never touched. IPv6 is switched only when
//!   asked for. Windows forwards between every pair of interfaces that have
//!   forwarding on, so other interfaces that already forward (virtual
//!   switches, connection sharing) can reach the chosen LAN as well;
//!   [`ForwardingGuard::other_forwarding_interfaces`] lists them so the caller
//!   can raise an alert. Several
//!   guards may hold the same interface: the original value is restored when
//!   the last one is dropped. Records name the interface by LUID and GUID, and
//!   a record whose GUID no longer resolves to that LUID is not applied. When
//!   an earlier restore of an interface failed, a new hold takes the original
//!   value from that record instead of the current (still switched) one.
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
//! - Dropping a [`FirewallGuard`] removes its rules on a separate thread, so
//!   that an async runtime is not blocked for the second the firewall cmdlets
//!   take; the network can be added again once that has finished. A failure
//!   is kept for [`last_firewall_error`]; [`FirewallGuard::remove`] removes
//!   synchronously and returns the error instead.

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
/// Folder under `%ProgramData%\AnixOps` that holds the state file.
pub const MESH_HOST_STATE_DIR: &str = "mesh-host";
/// Host-wide named object held by the one process that makes host changes.
pub const MESH_HOST_MUTEX: &str = r"Global\AnixOpsMeshHost";
/// Bytes of the firewall script's error output kept for diagnosis.
const MAX_SCRIPT_ERROR: usize = 512;

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

/// The one state directory of every caller on the host.
pub fn mesh_host_state_dir() -> PathBuf {
    crate::managed_files::windows_managed_root_directory().join(MESH_HOST_STATE_DIR)
}

/// The first `MAX_SCRIPT_ERROR` bytes of a script's error output, as text.
fn script_error(stderr: &[u8]) -> String {
    let cut = &stderr[..stderr.len().min(MAX_SCRIPT_ERROR)];
    String::from_utf8_lossy(cut).trim().to_owned()
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
    /// hold, and not at all when a failed restore of the same interface is on
    /// record: its value is still the switched one, so the recorded original
    /// is taken over (and the record leaves `stuck`). A record for the same
    /// LUID but another GUID names an interface that is gone and is dropped.
    /// Returns whether forwarding must be switched on now.
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
        let mut original = None;
        self.stuck.retain(|entry| {
            if entry.luid != luid || entry.family != family {
                return true;
            }
            if entry.guid == guid {
                original = Some(entry.original);
            }
            false
        });
        let original = original.unwrap_or_else(current);
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

    fn luids(&self) -> Vec<u64> {
        let mut luids: Vec<u64> = self.held.iter().map(|(e, _)| e.luid).collect();
        luids.sort_unstable();
        luids.dedup();
        luids
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
    add_mesh_firewall_rules, enable_mesh_forwarding, last_firewall_error, recover_mesh_host,
    FirewallGuard, ForwardingGuard,
};

#[cfg(not(windows))]
pub use unsupported::{
    add_mesh_firewall_rules, enable_mesh_forwarding, last_firewall_error, recover_mesh_host,
    FirewallGuard, ForwardingGuard,
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

    impl ForwardingGuard {
        /// Other interfaces that forward; Windows only.
        pub fn other_forwarding_interfaces(&self) -> io::Result<Vec<String>> {
            Err(unsupported())
        }
    }

    /// Holds the mesh firewall rules of one network; Windows only.
    #[derive(Debug)]
    pub struct FirewallGuard(());

    impl FirewallGuard {
        /// Removes the rules now; Windows only.
        pub fn remove(self) -> io::Result<()> {
            Err(unsupported())
        }
    }

    pub fn enable_mesh_forwarding(
        mesh_adapter: &str,
        lan_interfaces: &[String],
        ipv6: bool,
    ) -> io::Result<ForwardingGuard> {
        let _ = (mesh_adapter, lan_interfaces, ipv6);
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

    pub fn recover_mesh_host() -> io::Result<RecoveryReport> {
        Err(unsupported())
    }

    /// The last failure of a firewall removal done on drop; none here.
    pub fn last_firewall_error() -> Option<String> {
        None
    }
}

#[cfg(windows)]
mod native {
    use super::*;
    use std::mem::zeroed;
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::io::OwnedHandle;
    use std::process::Stdio;
    use std::sync::{Mutex, MutexGuard};

    use windows_sys::core::GUID;
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        ConvertInterfaceAliasToLuid, ConvertInterfaceGuidToLuid, ConvertInterfaceLuidToAlias,
        ConvertInterfaceLuidToGuid, FreeMibTable, GetIpInterfaceEntry, GetIpInterfaceTable,
        InitializeIpInterfaceEntry, SetIpInterfaceEntry, MIB_IPINTERFACE_ROW,
        MIB_IPINTERFACE_TABLE,
    };
    use windows_sys::Win32::NetworkManagement::Ndis::NET_LUID_LH;
    use windows_sys::Win32::Networking::WinSock::{AF_INET, AF_INET6, AF_UNSPEC};

    use crate::managed_files::{
        create_host_wide_object, ensure_managed_directory, read_admin_owned_file,
        write_managed_file_atomic,
    };
    use crate::trusted_command::native_windows_powershell_command;

    /// Everything this process holds on the host.
    struct Host {
        dir: PathBuf,
        /// The host-wide object, held for the life of the process.
        _lock: OwnedHandle,
        holdings: Holdings,
        /// Networks with a live [`FirewallGuard`], or whose rules are still
        /// being removed.
        networks: Vec<String>,
    }

    static HOST: Mutex<Option<Host>> = Mutex::new(None);
    static LAST_FIREWALL_ERROR: Mutex<Option<String>> = Mutex::new(None);

    /// The host state of this process, taking the host-wide object on first
    /// use. Refused when another process holds it.
    fn host() -> io::Result<MutexGuard<'static, Option<Host>>> {
        let mut slot = HOST.lock().unwrap_or_else(|e| e.into_inner());
        if slot.is_some() {
            return Ok(slot);
        }
        let lock = create_host_wide_object(MESH_HOST_MUTEX).map_err(|error| {
            if error.kind() == io::ErrorKind::ResourceBusy {
                io::Error::new(
                    io::ErrorKind::ResourceBusy,
                    "another process holds the mesh host changes",
                )
            } else {
                error
            }
        })?;
        let dir = mesh_host_state_dir();
        ensure_managed_directory(&dir)?;
        *slot = Some(Host {
            dir,
            _lock: lock,
            holdings: Holdings::default(),
            networks: Vec::new(),
        });
        Ok(slot)
    }

    fn read_state(state_dir: &Path) -> io::Result<ForwardingState> {
        match read_admin_owned_file(&state_path(state_dir)) {
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

    /// The alias of `luid`; the LUID in hex when it has none.
    fn luid_alias(luid: u64) -> String {
        let mut net_luid: NET_LUID_LH = unsafe { zeroed() };
        net_luid.Value = luid;
        // IF_MAX_STRING_SIZE + 1.
        let mut buffer = [0u16; 257];
        if unsafe { ConvertInterfaceLuidToAlias(&net_luid, buffer.as_mut_ptr(), buffer.len()) } != 0
        {
            return format!("{luid:#x}");
        }
        let end = buffer.iter().position(|&c| c == 0).unwrap_or(buffer.len());
        String::from_utf16_lossy(&buffer[..end])
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

    /// LUIDs of every interface that has forwarding on, in either family.
    fn forwarding_luids() -> io::Result<Vec<u64>> {
        let mut table: *mut MIB_IPINTERFACE_TABLE = std::ptr::null_mut();
        win32(
            unsafe { GetIpInterfaceTable(AF_UNSPEC, &mut table) },
            "the interface table could not be read",
        )?;
        let mut luids = Vec::new();
        if !table.is_null() {
            let count = unsafe { (*table).NumEntries } as usize;
            let rows = unsafe { std::ptr::addr_of!((*table).Table) as *const MIB_IPINTERFACE_ROW };
            for index in 0..count {
                let row = unsafe { &*rows.add(index) };
                if row.ForwardingEnabled {
                    luids.push(unsafe { row.InterfaceLuid.Value });
                }
            }
            unsafe { FreeMibTable(table as *const _) };
        }
        luids.sort_unstable();
        luids.dedup();
        Ok(luids)
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

    impl ForwardingGuard {
        /// Aliases of the interfaces that forward but that no guard of this
        /// process holds (virtual switches, connection sharing, other
        /// software). Windows forwards between all of them and the
        /// interfaces held here, so the caller should raise an alert when
        /// the list is not empty.
        pub fn other_forwarding_interfaces(&self) -> io::Result<Vec<String>> {
            let held = {
                let slot = HOST.lock().unwrap_or_else(|e| e.into_inner());
                slot.as_ref()
                    .map(|host| host.holdings.luids())
                    .unwrap_or_default()
            };
            Ok(forwarding_luids()?
                .into_iter()
                .filter(|luid| held.binary_search(luid).is_err())
                .map(luid_alias)
                .collect())
        }
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
    /// the state directory before anything changes.
    pub fn enable_mesh_forwarding(
        mesh_adapter: &str,
        lan_interfaces: &[String],
        ipv6: bool,
    ) -> io::Result<ForwardingGuard> {
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

        let mut slot = host()?;
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

    /// Holds the firewall rules of one network. Dropping it deletes them on
    /// a separate thread; [`FirewallGuard::remove`] deletes them now.
    #[derive(Debug)]
    pub struct FirewallGuard {
        network: String,
        names: [String; 3],
        removed: bool,
    }

    /// Removes the rules `names` of `network`, then lets the network be added
    /// again. A failure is also kept for [`last_firewall_error`].
    fn remove_rules(network: &str, names: &[String; 3]) -> io::Result<()> {
        let result = run_firewall_script(REMOVE_SCRIPT, &[("ANIX_MESH_NAMES", names.join(","))]);
        if let Err(error) = &result {
            *LAST_FIREWALL_ERROR
                .lock()
                .unwrap_or_else(|e| e.into_inner()) = Some(format!("{network}: {error}"));
        }
        let mut slot = HOST.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(host) = slot.as_mut() {
            host.networks.retain(|held| held != network);
        }
        result
    }

    impl FirewallGuard {
        /// Removes the rules now and returns what went wrong, with the start
        /// of the firewall script's error output.
        pub fn remove(mut self) -> io::Result<()> {
            self.removed = true;
            remove_rules(&self.network, &self.names)
        }
    }

    impl Drop for FirewallGuard {
        fn drop(&mut self) {
            if self.removed {
                return;
            }
            let network = std::mem::take(&mut self.network);
            let names = self.names.clone();
            let spawned = std::thread::Builder::new()
                .name("mesh-firewall-remove".into())
                .spawn({
                    let network = network.clone();
                    move || {
                        let _ = remove_rules(&network, &names);
                    }
                });
            if spawned.is_err() {
                // No thread: leave the rules to the next recovery, but do not
                // keep the network blocked for the rest of the process.
                *LAST_FIREWALL_ERROR
                    .lock()
                    .unwrap_or_else(|e| e.into_inner()) = Some(format!(
                    "{network}: the rules are left for the next recovery"
                ));
                let mut slot = HOST.lock().unwrap_or_else(|e| e.into_inner());
                if let Some(host) = slot.as_mut() {
                    host.networks.retain(|held| *held != network);
                }
            }
        }
    }

    /// The last failure of a firewall removal done when a guard was dropped,
    /// with the start of the script's error output.
    pub fn last_firewall_error() -> Option<String> {
        LAST_FIREWALL_ERROR
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    const ADD_SCRIPT: &str = r#"$ErrorActionPreference = 'Stop'
$names = $env:ANIX_MESH_NAMES -split ','
Remove-NetFirewallRule -Name $names -PolicyStore PersistentStore -ErrorAction SilentlyContinue
$ports = $env:ANIX_MESH_PORTS -split ','
$group = $env:ANIX_MESH_GROUP
$program = $env:ANIX_MESH_PROGRAM
$adapter = [System.Management.Automation.WildcardPattern]::Escape($env:ANIX_MESH_ADAPTER)
if (@(Get-NetAdapter -InterfaceAlias $adapter -IncludeHidden -ErrorAction Stop).Count -ne 1) { throw 'adapter' }
New-NetFirewallRule -Name $names[2] -DisplayName $names[2] -Group $group -PolicyStore PersistentStore -Direction Inbound -Action Block -Program $program -InterfaceAlias $adapter -Profile Any | Out-Null
New-NetFirewallRule -Name $names[0] -DisplayName $names[0] -Group $group -PolicyStore PersistentStore -Direction Inbound -Action Allow -Program $program -Protocol UDP -LocalPort $ports -Profile Any | Out-Null
New-NetFirewallRule -Name $names[1] -DisplayName $names[1] -Group $group -PolicyStore PersistentStore -Direction Inbound -Action Allow -Program $program -Protocol TCP -LocalPort $ports -Profile Any | Out-Null
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
    /// environment, never spliced into the script text. A failure carries
    /// the start of the script's error output.
    fn run_firewall_script(script: &str, values: &[(&str, String)]) -> io::Result<()> {
        let mut command = native_windows_powershell_command()?;
        command
            .args(["-NoProfile", "-NonInteractive", "-Command", script])
            .env("ANIX_MESH_GROUP", MESH_FIREWALL_GROUP)
            .env("ANIX_MESH_PREFIX", MESH_FIREWALL_RULE_PREFIX)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped());
        for (name, value) in values {
            command.env(name, value);
        }
        let output = command.output()?;
        if !output.status.success() {
            return Err(io::Error::other(format!(
                "the firewall rules could not be changed: {}",
                script_error(&output.stderr)
            )));
        }
        Ok(())
    }

    /// Adds the rules of `network`: a block on inbound traffic to
    /// `program_path` that arrives on `mesh_adapter`, then inbound UDP and TCP
    /// to `listen_ports` for `program_path`. Rules of the same names left
    /// from an earlier run are replaced. One guard per network at a time; a
    /// network whose rules are still being removed is refused until that
    /// has finished.
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
        {
            let mut slot = host()?;
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
            removed: false,
        };
        let added = run_firewall_script(
            ADD_SCRIPT,
            &[
                ("ANIX_MESH_NAMES", guard.names.join(",")),
                ("ANIX_MESH_PORTS", ports),
                ("ANIX_MESH_PROGRAM", program.to_owned()),
                ("ANIX_MESH_ADAPTER", mesh_adapter.to_owned()),
            ],
        );
        if let Err(error) = added {
            // Remove what was added before returning, not on another thread.
            let _ = guard.remove();
            return Err(error);
        }
        Ok(guard)
    }

    /// Puts back what a process that died with guards alive left behind:
    /// restores forwarding values recorded in the state directory (only for
    /// interfaces whose GUID still matches) and removes our rules of
    /// [`MESH_FIREWALL_GROUP`]. Call once at start, before any guard is taken,
    /// and from the uninstaller. A state file that cannot be parsed, or that
    /// is not owned by SYSTEM or Administrators, is set aside and the rules
    /// are still removed.
    pub fn recover_mesh_host() -> io::Result<RecoveryReport> {
        let mut slot = host()?;
        let host = slot.as_mut().expect("host state was just taken");
        if !host.holdings.is_empty() || !host.networks.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "recovery runs before any guard is taken",
            ));
        }
        let state_dir = host.dir.clone();
        let mut report = RecoveryReport::default();
        let state = match read_state(&state_dir) {
            Ok(state) => state,
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::InvalidData | io::ErrorKind::PermissionDenied
                ) =>
            {
                let path = state_path(&state_dir);
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
        write_state(&state_dir, &host.holdings.state())?;
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
        fn the_interface_table_can_be_read() {
            // The loopback interface always exists; reading the table and
            // naming an interface must not fail.
            forwarding_luids().unwrap();
            assert!(!luid_alias(u64::MAX).is_empty());
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
    fn the_state_directory_is_fixed_under_the_managed_root() {
        let dir = mesh_host_state_dir();
        assert!(crate::managed_files::is_within_managed_root(&dir));
        assert!(dir.ends_with(MESH_HOST_STATE_DIR));
        assert!(MESH_HOST_MUTEX.starts_with(r"Global\"));
    }

    #[test]
    fn script_errors_are_cut_and_kept() {
        assert_eq!(script_error(b"  denied\r\n"), "denied");
        assert_eq!(script_error(&[b'x'; 2000]).len(), MAX_SCRIPT_ERROR);
        // Cutting inside a multi-byte character stays valid text.
        let mut bytes = vec![b'x'; MAX_SCRIPT_ERROR - 1];
        bytes.extend_from_slice("办".as_bytes());
        assert!(script_error(&bytes).starts_with('x'));
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
    fn a_new_hold_takes_the_original_from_a_stuck_record() {
        let mut holdings = Holdings::default();
        holdings.stuck.push(ForwardingEntry {
            luid: 7,
            guid: "{g7}".into(),
            family: IpFamily::Ipv4,
            original: false,
        });
        // The interface still forwards because its restore failed; the
        // recorded original wins over the current value.
        assert!(holdings.hold(7, "{g7}", IpFamily::Ipv4, || panic!("read current")));
        assert!(holdings.stuck.is_empty());
        assert_eq!(holdings.state().entries.len(), 1);
        assert!(!holdings.release(7, IpFamily::Ipv4).unwrap().original);
    }

    #[test]
    fn a_stuck_record_of_another_interface_is_dropped_on_hold() {
        let mut holdings = Holdings::default();
        holdings.stuck.push(ForwardingEntry {
            luid: 7,
            guid: "{old}".into(),
            family: IpFamily::Ipv4,
            original: false,
        });
        holdings.stuck.push(ForwardingEntry {
            luid: 7,
            guid: "{g7}".into(),
            family: IpFamily::Ipv6,
            original: false,
        });
        assert!(!holdings.hold(7, "{g7}", IpFamily::Ipv4, || true));
        assert_eq!(holdings.stuck.len(), 1);
        assert_eq!(holdings.stuck[0].family, IpFamily::Ipv6);
        assert_eq!(holdings.luids(), vec![7]);
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
        assert_eq!(
            enable_mesh_forwarding("mesh0", &[], false)
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
            recover_mesh_host().unwrap_err().kind(),
            io::ErrorKind::Unsupported
        );
        assert!(last_firewall_error().is_none());
    }
}
