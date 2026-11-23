//! Keeps DNS inside the TUN adapter while it is open.
//!
//! The Windows DNS client asks the DNS servers of every connected interface
//! (smart multi-homed name resolution), and a query sourced from a physical
//! interface's address leaves through that interface, past the adapter: the
//! network's resolver sees every name, and its answer, when it comes first,
//! replaces the tunnel's. [`DnsGuard`] adds Windows Filtering Platform
//! filters, in a dynamic session, at the connect layers of both families:
//!
//! - permit remote port 53 through the TUN adapter (its local interface);
//! - permit remote port 53 from this process, whose engine sends its own
//!   upstream queries through the physical interface;
//! - permit remote port 53 on loopback (a local resolver);
//! - block every other connection to remote port 53.
//!
//! The filters live in a sublayer of their own and go away with the session:
//! when the guard is dropped, and also when the process ends without
//! dropping it, so a crash cannot leave DNS blocked. Blocks from other
//! sublayers (the Windows Firewall) still apply to what is permitted here.

use std::ffi::{c_void, OsStr};
use std::io;
use std::mem::zeroed;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;
use std::ptr::{null, null_mut};

use ring::rand::{SecureRandom, SystemRandom};
use windows_sys::core::GUID;
use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::{
    FwpmEngineClose0, FwpmEngineOpen0, FwpmFilterAdd0, FwpmFreeMemory0, FwpmGetAppIdFromFileName0,
    FwpmSubLayerAdd0, FwpmTransactionAbort0, FwpmTransactionBegin0, FwpmTransactionCommit0,
    FWPM_CONDITION_ALE_APP_ID, FWPM_CONDITION_FLAGS, FWPM_CONDITION_IP_LOCAL_INTERFACE,
    FWPM_CONDITION_IP_REMOTE_PORT, FWPM_FILTER0, FWPM_FILTER_CONDITION0,
    FWPM_LAYER_ALE_AUTH_CONNECT_V4, FWPM_LAYER_ALE_AUTH_CONNECT_V6, FWPM_SESSION0,
    FWPM_SESSION_FLAG_DYNAMIC, FWPM_SUBLAYER0, FWP_ACTION_BLOCK, FWP_ACTION_PERMIT,
    FWP_ACTION_TYPE, FWP_BYTE_BLOB, FWP_BYTE_BLOB_TYPE, FWP_CONDITION_FLAG_IS_LOOPBACK,
    FWP_MATCH_EQUAL, FWP_MATCH_FLAGS_ALL_SET, FWP_UINT16, FWP_UINT32, FWP_UINT64, FWP_UINT8,
};

/// `RPC_C_AUTHN_DEFAULT`: the engine picks the authentication service.
const RPC_C_AUTHN_DEFAULT: u32 = 0xFFFF_FFFF;
const ERROR_ACCESS_DENIED: u32 = 5;
const DNS_PORT: u16 = 53;

/// The guard's filters, removed when it is dropped (or the process ends).
pub(crate) struct DnsGuard {
    engine: HANDLE,
}

// SAFETY: a filter engine handle may be closed from any thread.
unsafe impl Send for DnsGuard {}
unsafe impl Sync for DnsGuard {}

impl Drop for DnsGuard {
    fn drop(&mut self) {
        // Closing a dynamic session deletes its sublayer and filters.
        unsafe { FwpmEngineClose0(self.engine) };
    }
}

impl DnsGuard {
    /// Adds the filters for the TUN adapter `tun_luid`, letting the
    /// executable `own_executable` (this process) reach any DNS server.
    /// Needs administrator rights.
    pub(crate) fn install(tun_luid: u64, own_executable: &Path) -> io::Result<Self> {
        let mut name = wide(OsStr::new("AnixOps Net DNS guard"));
        let mut description = wide(OsStr::new(
            "Keeps DNS queries inside the AnixOps Net tunnel while it is open",
        ));
        let mut session: FWPM_SESSION0 = unsafe { zeroed() };
        session.flags = FWPM_SESSION_FLAG_DYNAMIC;
        session.displayData.name = name.as_mut_ptr();
        session.displayData.description = description.as_mut_ptr();
        let mut engine: HANDLE = null_mut();
        check(
            unsafe { FwpmEngineOpen0(null(), RPC_C_AUTHN_DEFAULT, null(), &session, &mut engine) },
            "the filter engine could not be opened",
        )?;
        // From here on, dropping `guard` closes the session and removes
        // whatever was added.
        let guard = Self { engine };
        check(
            unsafe { FwpmTransactionBegin0(engine, 0) },
            "a filter transaction could not be started",
        )?;
        if let Err(error) = guard.add_filters(tun_luid, own_executable, &mut name, &mut description)
        {
            unsafe { FwpmTransactionAbort0(engine) };
            return Err(error);
        }
        check(
            unsafe { FwpmTransactionCommit0(engine) },
            "the DNS filters could not be committed",
        )?;
        Ok(guard)
    }

    fn add_filters(
        &self,
        tun_luid: u64,
        own_executable: &Path,
        name: &mut [u16],
        description: &mut [u16],
    ) -> io::Result<()> {
        let sublayer_key = random_guid()?;
        let mut sublayer: FWPM_SUBLAYER0 = unsafe { zeroed() };
        sublayer.subLayerKey = sublayer_key;
        sublayer.displayData.name = name.as_mut_ptr();
        sublayer.displayData.description = description.as_mut_ptr();
        sublayer.weight = u16::MAX;
        check(
            unsafe { FwpmSubLayerAdd0(self.engine, &sublayer, null_mut()) },
            "the DNS filter sublayer could not be added",
        )?;

        let app_id = AppId::of(own_executable)?;
        let mut luid = tun_luid;
        for layer in [
            FWPM_LAYER_ALE_AUTH_CONNECT_V4,
            FWPM_LAYER_ALE_AUTH_CONNECT_V6,
        ] {
            let filter = Filter {
                engine: self.engine,
                layer,
                sublayer: sublayer_key,
                name: name.as_mut_ptr(),
                description: description.as_mut_ptr(),
            };
            // Within the sublayer the highest weight that matches decides.
            filter.add(
                15,
                FWP_ACTION_PERMIT,
                &mut [remote_dns_port(), local_interface(&mut luid)],
            )?;
            filter.add(
                14,
                FWP_ACTION_PERMIT,
                &mut [remote_dns_port(), application(app_id.0)],
            )?;
            filter.add(13, FWP_ACTION_PERMIT, &mut [remote_dns_port(), loopback()])?;
            filter.add(0, FWP_ACTION_BLOCK, &mut [remote_dns_port()])?;
        }
        Ok(())
    }
}

/// Where the filters of one layer go.
struct Filter {
    engine: HANDLE,
    layer: GUID,
    sublayer: GUID,
    name: *mut u16,
    description: *mut u16,
}

impl Filter {
    fn add(
        &self,
        weight: u8,
        action: FWP_ACTION_TYPE,
        conditions: &mut [FWPM_FILTER_CONDITION0],
    ) -> io::Result<()> {
        let mut filter: FWPM_FILTER0 = unsafe { zeroed() };
        filter.displayData.name = self.name;
        filter.displayData.description = self.description;
        filter.layerKey = self.layer;
        filter.subLayerKey = self.sublayer;
        filter.weight.r#type = FWP_UINT8;
        filter.weight.Anonymous.uint8 = weight;
        filter.numFilterConditions = conditions.len() as u32;
        filter.filterCondition = conditions.as_mut_ptr();
        filter.action.r#type = action;
        let mut id = 0_u64;
        check(
            unsafe { FwpmFilterAdd0(self.engine, &filter, null_mut(), &mut id) },
            "a DNS filter could not be added",
        )
    }
}

fn remote_dns_port() -> FWPM_FILTER_CONDITION0 {
    let mut condition: FWPM_FILTER_CONDITION0 = unsafe { zeroed() };
    condition.fieldKey = FWPM_CONDITION_IP_REMOTE_PORT;
    condition.matchType = FWP_MATCH_EQUAL;
    condition.conditionValue.r#type = FWP_UINT16;
    condition.conditionValue.Anonymous.uint16 = DNS_PORT;
    condition
}

/// The connection goes out through the interface `luid`; the value is read
/// when the filter is added.
fn local_interface(luid: &mut u64) -> FWPM_FILTER_CONDITION0 {
    let mut condition: FWPM_FILTER_CONDITION0 = unsafe { zeroed() };
    condition.fieldKey = FWPM_CONDITION_IP_LOCAL_INTERFACE;
    condition.matchType = FWP_MATCH_EQUAL;
    condition.conditionValue.r#type = FWP_UINT64;
    condition.conditionValue.Anonymous.uint64 = luid as *mut u64;
    condition
}

fn application(app_id: *mut FWP_BYTE_BLOB) -> FWPM_FILTER_CONDITION0 {
    let mut condition: FWPM_FILTER_CONDITION0 = unsafe { zeroed() };
    condition.fieldKey = FWPM_CONDITION_ALE_APP_ID;
    condition.matchType = FWP_MATCH_EQUAL;
    condition.conditionValue.r#type = FWP_BYTE_BLOB_TYPE;
    condition.conditionValue.Anonymous.byteBlob = app_id;
    condition
}

fn loopback() -> FWPM_FILTER_CONDITION0 {
    let mut condition: FWPM_FILTER_CONDITION0 = unsafe { zeroed() };
    condition.fieldKey = FWPM_CONDITION_FLAGS;
    condition.matchType = FWP_MATCH_FLAGS_ALL_SET;
    condition.conditionValue.r#type = FWP_UINT32;
    condition.conditionValue.Anonymous.uint32 = FWP_CONDITION_FLAG_IS_LOOPBACK;
    condition
}

/// An executable's application id, as the connect layers match it.
struct AppId(*mut FWP_BYTE_BLOB);

impl AppId {
    fn of(executable: &Path) -> io::Result<Self> {
        let path = wide(executable.as_os_str());
        let mut blob: *mut FWP_BYTE_BLOB = null_mut();
        check(
            unsafe { FwpmGetAppIdFromFileName0(path.as_ptr(), &mut blob) },
            "the application id of this program could not be read",
        )?;
        Ok(Self(blob))
    }
}

impl Drop for AppId {
    fn drop(&mut self) {
        let mut pointer = self.0 as *mut c_void;
        if !pointer.is_null() {
            unsafe { FwpmFreeMemory0(&mut pointer) };
        }
    }
}

/// A fresh sublayer key, so two sessions never collide.
fn random_guid() -> io::Result<GUID> {
    let mut bytes = [0_u8; 16];
    SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| io::Error::other("no system randomness for a filter key"))?;
    Ok(GUID::from_u128(u128::from_be_bytes(bytes)))
}

fn check(result: u32, message: &str) -> io::Result<()> {
    match result {
        0 => Ok(()),
        ERROR_ACCESS_DENIED => Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("{message} (error {result:#x})"),
        )),
        _ => Err(io::Error::other(format!("{message} (error {result:#x})"))),
    }
}

fn wide(value: &OsStr) -> Vec<u16> {
    value.encode_wide().chain(Some(0)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::UdpSocket;
    use std::process::{Command, Stdio};
    use std::sync::{Mutex, MutexGuard, PoisonError};
    use std::time::Duration;

    /// The guard blocks DNS for every other program, so these tests run one
    /// at a time.
    static GUARD_TESTS: Mutex<()> = Mutex::new(());

    fn serial() -> MutexGuard<'static, ()> {
        GUARD_TESTS.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Sends an `A example.com` query to 1.1.1.1 from this process and waits
    /// for the answer.
    fn own_query_succeeds() -> bool {
        let query: &[u8] = &[
            0x4e, 0x43, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 7, b'e', b'x',
            b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0, 0x00, 0x01, 0x00, 0x01,
        ];
        let Ok(socket) = UdpSocket::bind("0.0.0.0:0") else {
            return false;
        };
        if socket
            .set_read_timeout(Some(Duration::from_secs(3)))
            .is_err()
            || socket.send_to(query, "1.1.1.1:53").is_err()
        {
            return false;
        }
        let mut reply = [0_u8; 512];
        matches!(socket.recv_from(&mut reply), Ok((length, _)) if length >= 12 && reply[..2] == query[..2])
    }

    /// Asks 1.1.1.1 directly from another process (PowerShell), as an
    /// application that ignores the adapter's DNS server would.
    fn outside_query_succeeds() -> bool {
        Command::new("powershell.exe")
            .args([
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                "try { Resolve-DnsName example.com -Server 1.1.1.1 -DnsOnly -QuickTimeout \
                 -ErrorAction Stop | Out-Null; exit 0 } catch { exit 1 }",
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map(|status| status.success())
            .unwrap_or(false)
    }

    /// CI runs elevated, as the client does when it opens the adapter.
    #[test]
    fn outside_dns_is_blocked_only_while_the_guard_lives() {
        let _serial = serial();
        let executable = std::env::current_exe().expect("test executable path should exist");
        // Before: whether this runner can reach a public resolver at all.
        let reachable = outside_query_succeeds();

        // No adapter has this LUID, so nothing is let through the tunnel.
        let guard = DnsGuard::install(0, &executable).expect("the DNS guard installs");
        if reachable {
            assert!(
                !outside_query_succeeds(),
                "a DNS query from another program left while the guard was in place"
            );
        }
        // This process (the engine) still reaches its upstream directly.
        if reachable {
            assert!(
                own_query_succeeds(),
                "this process lost its own DNS while the guard was in place"
            );
        }
        drop(guard);

        if reachable {
            assert!(
                outside_query_succeeds(),
                "DNS stayed blocked after the guard was dropped"
            );
        }
    }

    #[test]
    fn two_guards_do_not_collide() {
        let _serial = serial();
        let executable = std::env::current_exe().expect("test executable path should exist");
        let first = DnsGuard::install(0, &executable).expect("the first guard installs");
        let second = DnsGuard::install(0, &executable).expect("the second guard installs");
        drop(first);
        drop(second);
    }
}
