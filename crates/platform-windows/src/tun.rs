//! Windows TUN mode: a Wintun adapter that captures the system's traffic.
//!
//! [`WindowsTun::open`] loads `wintun.dll` from a path the caller gives (the
//! client's install directory, never the search path), creates the adapter,
//! gives it an address, points its DNS at the tunnel and adds the capture
//! routes (`0.0.0.0/1` + `128.0.0.0/1`, and `::/1` + `8000::/1` when IPv6 is
//! on) through it. They are more specific than any default route, so the
//! physical default route stays in place and comes back by itself when the
//! adapter goes away: closing the adapter deletes it together with its
//! address and routes.
//!
//! Before the routes go in, the physical interface for each family is
//! recorded ([`WindowsTun::physical_interface`]). The engine's own sockets
//! must be pinned to it with [`bind_socket_to_interface`] (`IP_UNICAST_IF`),
//! or they would loop back into the adapter.
//!
//! The physical interface follows the network: while the adapter is open a
//! watcher (`NotifyRouteChange2` + `NotifyIpInterfaceChange`) picks it again
//! from the default routes (`0.0.0.0/0`, `::/0`) of every connected interface
//! but the adapter, lowest route + interface metric first, whenever a
//! default route or an interface changes (Wi-Fi to Ethernet, a USB tether,
//! IPv6 arriving later). The routing table is read directly because the
//! capture routes make the adapter the best path for every destination.
//! The new pick lands in the shared [`PhysicalInterfaceHandle`] that the
//! socket protector reads on every socket
//! ([`PhysicalInterfaceHandle::bind_socket`]), and the callback given to
//! [`WindowsTun::on_physical_interface_change`] runs, so the host can move
//! long-lived sockets (`engine_outbound::protect::path_changed`) and close
//! the connections still pinned to the old interface (`reset_network`).
//!
//! Packets read from the adapter go to the callback given to
//! [`WindowsTun::start_reader`] on a dedicated thread; packets for the
//! adapter go through a [`WindowsTunWriter`], from any thread.

use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::Path;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

/// Name of the Wintun DLL the client ships next to its executable.
pub const WINTUN_DLL_NAME: &str = "wintun.dll";

/// Settings of the TUN adapter. The defaults are what the client uses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WindowsTunSettings {
    /// Adapter name shown in Windows network settings.
    pub adapter_name: String,
    /// The adapter's own IPv4 address and prefix length.
    pub ipv4: (Ipv4Addr, u8),
    /// DNS server the adapter announces. It is inside the adapter's subnet,
    /// so its queries enter the tunnel, which answers UDP/53 itself.
    pub dns: Ipv4Addr,
    /// The adapter's IPv6 address and prefix length; `None` leaves IPv6
    /// traffic on the physical interface.
    pub ipv6: Option<(Ipv6Addr, u8)>,
    /// Adapter MTU.
    pub mtu: u32,
    /// Wintun ring capacity in bytes: a power of two between 128 KiB and
    /// 64 MiB.
    pub ring_capacity: u32,
}

impl Default for WindowsTunSettings {
    fn default() -> Self {
        Self {
            adapter_name: "AnixOps Net".to_string(),
            ipv4: (Ipv4Addr::new(172, 19, 0, 1), 30),
            dns: Ipv4Addr::new(172, 19, 0, 2),
            ipv6: Some((Ipv6Addr::new(0xfdfe, 0xdcba, 0x9876, 0, 0, 0, 0, 1), 126)),
            mtu: 1500,
            ring_capacity: 0x0040_0000,
        }
    }
}

const MIN_RING_CAPACITY: u32 = 0x0002_0000;
const MAX_RING_CAPACITY: u32 = 0x0400_0000;

impl WindowsTunSettings {
    /// Checks the settings before anything on the system changes.
    pub fn validate(&self) -> io::Result<()> {
        let invalid = |message: &str| io::Error::new(io::ErrorKind::InvalidInput, message);
        let name_len = self.adapter_name.encode_utf16().count();
        if name_len == 0 || name_len >= 128 || self.adapter_name.contains('\0') {
            return Err(invalid("the TUN adapter name must be 1 to 127 characters"));
        }
        if !(8..=30).contains(&self.ipv4.1) {
            return Err(invalid("the TUN IPv4 prefix must be /8 to /30"));
        }
        if self.dns == self.ipv4.0 || !same_ipv4_subnet(self.dns, self.ipv4.0, self.ipv4.1) {
            return Err(invalid(
                "the TUN DNS address must be another address in the adapter subnet",
            ));
        }
        if let Some((_, prefix)) = self.ipv6 {
            if !(8..=126).contains(&prefix) {
                return Err(invalid("the TUN IPv6 prefix must be /8 to /126"));
            }
        }
        if !(576..=9000).contains(&self.mtu) {
            return Err(invalid("the TUN MTU must be 576 to 9000"));
        }
        if !self.ring_capacity.is_power_of_two()
            || !(MIN_RING_CAPACITY..=MAX_RING_CAPACITY).contains(&self.ring_capacity)
        {
            return Err(invalid(
                "the Wintun ring capacity must be a power of two from 128 KiB to 64 MiB",
            ));
        }
        Ok(())
    }
}

fn same_ipv4_subnet(a: Ipv4Addr, b: Ipv4Addr, prefix: u8) -> bool {
    let mask = u32::MAX.checked_shl(32 - u32::from(prefix)).unwrap_or(0);
    u32::from(a) & mask == u32::from(b) & mask
}

/// A route the adapter carries: the halves of each address space, so the
/// physical default route stays and wins again once the adapter is gone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CaptureRoute {
    V4(Ipv4Addr, u8),
    V6(Ipv6Addr, u8),
}

/// The capture routes for `settings`.
pub fn capture_routes(settings: &WindowsTunSettings) -> Vec<CaptureRoute> {
    let mut routes = vec![
        CaptureRoute::V4(Ipv4Addr::new(0, 0, 0, 0), 1),
        CaptureRoute::V4(Ipv4Addr::new(128, 0, 0, 0), 1),
    ];
    if settings.ipv6.is_some() {
        routes.push(CaptureRoute::V6(Ipv6Addr::UNSPECIFIED, 1));
        routes.push(CaptureRoute::V6(
            Ipv6Addr::new(0x8000, 0, 0, 0, 0, 0, 0, 0),
            1,
        ));
    }
    routes
}

/// The interfaces that carried each family's default route before the
/// capture routes went in. `None` when that family had no route.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PhysicalInterface {
    pub ipv4_index: Option<u32>,
    pub ipv6_index: Option<u32>,
}

impl PhysicalInterface {
    /// The interface for a destination of the given family.
    pub fn index_for(&self, ipv6: bool) -> Option<u32> {
        if ipv6 {
            self.ipv6_index
        } else {
            self.ipv4_index
        }
    }
}

/// One default route (`0.0.0.0/0` or `::/0`) of the routing table, as the
/// physical interface is picked again after a network change.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DefaultRoute {
    /// `true` for `::/0`.
    pub ipv6: bool,
    pub interface_index: u32,
    /// The route's own metric.
    pub route_metric: u32,
    /// The metric of the route's interface for that family.
    pub interface_metric: u32,
    /// Whether the interface is connected for that family.
    pub connected: bool,
}

/// Picks the physical interface of each family from the default routes:
/// the connected interface, other than the TUN adapter `tun_index`, whose
/// route + interface metric is lowest (the lower index on a tie), as
/// Windows weighs default routes. `None` for a family without one.
pub fn select_physical_interface(routes: &[DefaultRoute], tun_index: u32) -> PhysicalInterface {
    let best = |ipv6: bool| {
        routes
            .iter()
            .filter(|route| {
                route.ipv6 == ipv6
                    && route.connected
                    && route.interface_index != 0
                    && route.interface_index != tun_index
            })
            .min_by_key(|route| {
                (
                    route.route_metric.saturating_add(route.interface_metric),
                    route.interface_index,
                )
            })
            .map(|route| route.interface_index)
    };
    PhysicalInterface {
        ipv4_index: best(false),
        ipv6_index: best(true),
    }
}

/// The physical interface shared between the adapter's watcher and the
/// socket protector: the protector reads it on every socket, so a socket
/// made after a network change goes out through the new interface. Cheap
/// to clone; every clone sees the same value.
#[derive(Debug, Clone, Default)]
pub struct PhysicalInterfaceHandle(Arc<PhysicalInterfaceSlot>);

#[derive(Debug, Default)]
struct PhysicalInterfaceSlot {
    /// Interface indices; `0` is no interface (Windows never uses index 0).
    ipv4: AtomicU32,
    ipv6: AtomicU32,
    generation: AtomicU64,
}

impl PhysicalInterfaceHandle {
    pub fn new(physical: PhysicalInterface) -> Self {
        let handle = Self::default();
        handle.store(physical);
        handle
    }

    /// The interfaces sockets are pinned to now.
    pub fn get(&self) -> PhysicalInterface {
        let index =
            |slot: &AtomicU32| Some(slot.load(Ordering::Acquire)).filter(|&index| index != 0);
        PhysicalInterface {
            ipv4_index: index(&self.0.ipv4),
            ipv6_index: index(&self.0.ipv6),
        }
    }

    /// Moves on every change of [`Self::get`].
    pub fn generation(&self) -> u64 {
        self.0.generation.load(Ordering::Acquire)
    }

    /// Replaces the interfaces; `true` (and a new [`Self::generation`]) when
    /// they changed.
    pub fn set(&self, physical: PhysicalInterface) -> bool {
        if self.get() == physical {
            return false;
        }
        self.store(physical);
        self.0.generation.fetch_add(1, Ordering::AcqRel);
        true
    }

    fn store(&self, physical: PhysicalInterface) {
        self.0
            .ipv4
            .store(physical.ipv4_index.unwrap_or(0), Ordering::Release);
        self.0
            .ipv6
            .store(physical.ipv6_index.unwrap_or(0), Ordering::Release);
    }

    /// Pins `socket`, about to reach `target`, to the current physical
    /// interface of `target`'s family. `NetworkUnreachable` when that family
    /// has none right now, so the connection fails instead of looping into
    /// the adapter. This is the body of the host's socket protector.
    pub fn bind_socket(&self, socket: u64, target: SocketAddr) -> io::Result<()> {
        let ipv6 = target.is_ipv6();
        match self.get().index_for(ipv6) {
            Some(index) => bind_socket_to_interface(socket, index, ipv6),
            None => Err(io::Error::new(
                io::ErrorKind::NetworkUnreachable,
                "no physical interface for this address family",
            )),
        }
    }
}

/// Called with the new physical interface after it changed.
#[cfg_attr(not(windows), allow(dead_code))]
type PhysicalInterfaceCallback = Arc<dyn Fn(PhysicalInterface) + Send + Sync>;

#[cfg_attr(not(windows), allow(dead_code))]
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Applies a fresh read of the default routes to the shared handle and runs
/// the change callback when the pick moved.
#[cfg_attr(not(windows), allow(dead_code))]
struct PhysicalInterfaceTracker {
    tun_index: u32,
    handle: PhysicalInterfaceHandle,
    on_change: Mutex<Option<PhysicalInterfaceCallback>>,
    /// Keeps a refresh from the watcher and one asked by the host in order.
    applying: Mutex<()>,
}

#[cfg_attr(not(windows), allow(dead_code))]
impl PhysicalInterfaceTracker {
    fn new(tun_index: u32, initial: PhysicalInterface) -> Self {
        Self {
            tun_index,
            handle: PhysicalInterfaceHandle::new(initial),
            on_change: Mutex::new(None),
            applying: Mutex::new(()),
        }
    }

    fn set_on_change(&self, on_change: Option<PhysicalInterfaceCallback>) {
        *lock(&self.on_change) = on_change;
    }

    fn apply(&self, routes: &[DefaultRoute]) -> PhysicalInterface {
        let (selected, changed) = {
            let _applying = lock(&self.applying);
            let selected = select_physical_interface(routes, self.tun_index);
            (selected, self.handle.set(selected))
        };
        if changed {
            // Outside every lock: the callback may ask for a refresh itself.
            let on_change = lock(&self.on_change).clone();
            if let Some(on_change) = on_change {
                on_change(selected);
            }
        }
        selected
    }
}

/// How long the routing table must stay quiet after a change before the
/// interface is picked again: a network switch comes as a burst of route
/// and interface notifications, and may pass through a moment without any
/// default route.
#[cfg_attr(not(windows), allow(dead_code))]
const ROUTE_SETTLE: Duration = Duration::from_millis(500);
/// The longest a burst of changes delays the new pick.
#[cfg_attr(not(windows), allow(dead_code))]
const ROUTE_SETTLE_MAX: Duration = Duration::from_secs(3);

/// Wakes the watcher thread. The system's notification callbacks only set
/// a flag here; the routing table is read on the watcher thread.
#[derive(Default)]
#[cfg_attr(not(windows), allow(dead_code))]
struct WatchSignal {
    state: Mutex<WatchState>,
    wake: Condvar,
}

#[derive(Default)]
#[cfg_attr(not(windows), allow(dead_code))]
struct WatchState {
    pending: bool,
    quit: bool,
}

#[cfg_attr(not(windows), allow(dead_code))]
impl WatchSignal {
    fn notify(&self) {
        lock(&self.state).pending = true;
        self.wake.notify_all();
    }

    fn quit(&self) {
        lock(&self.state).quit = true;
        self.wake.notify_all();
    }

    /// Waits for a change, then until no other change came for `settle`
    /// (at most `settle_max` in all). `false` once [`Self::quit`] was called.
    fn wait_for_change(&self, settle: Duration, settle_max: Duration) -> bool {
        let mut state = lock(&self.state);
        while !state.pending && !state.quit {
            state = self
                .wake
                .wait(state)
                .unwrap_or_else(PoisonError::into_inner);
        }
        if state.quit {
            return false;
        }
        state.pending = false;
        let started = Instant::now();
        loop {
            let remaining = settle_max.saturating_sub(started.elapsed());
            if remaining.is_zero() {
                return true;
            }
            let (next, waited) = self
                .wake
                .wait_timeout_while(state, settle.min(remaining), |state| {
                    !state.pending && !state.quit
                })
                .unwrap_or_else(PoisonError::into_inner);
            state = next;
            if state.quit {
                return false;
            }
            if waited.timed_out() {
                return true;
            }
            state.pending = false;
        }
    }
}

/// `IP_UNICAST_IF` takes the IPv4 interface index in network byte order;
/// `IPV6_UNICAST_IF` takes it in host order.
pub fn unicast_if_option_value(index: u32, ipv6: bool) -> u32 {
    if ipv6 {
        index
    } else {
        index.to_be()
    }
}

/// Where `wintun.dll` is expected: next to the running executable.
pub fn default_wintun_dll_path() -> io::Result<std::path::PathBuf> {
    let exe = std::env::current_exe()?;
    let dir = exe
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "executable has no directory"))?;
    Ok(dir.join(WINTUN_DLL_NAME))
}

#[cfg(windows)]
pub use native::{bind_socket_to_interface, WindowsTun, WindowsTunWriter};

#[cfg(not(windows))]
pub use unsupported::{bind_socket_to_interface, WindowsTun, WindowsTunWriter};

#[cfg(not(windows))]
mod unsupported {
    use super::*;

    fn unsupported() -> io::Error {
        io::Error::new(io::ErrorKind::Unsupported, "TUN mode needs Windows")
    }

    pub struct WindowsTun(());

    impl WindowsTun {
        pub fn open(settings: &WindowsTunSettings, _wintun_dll: &Path) -> io::Result<Self> {
            settings.validate()?;
            Err(unsupported())
        }

        pub fn physical_interface(&self) -> PhysicalInterface {
            PhysicalInterface::default()
        }

        pub fn physical_interface_handle(&self) -> PhysicalInterfaceHandle {
            PhysicalInterfaceHandle::default()
        }

        pub fn on_physical_interface_change<F>(&self, _on_change: F)
        where
            F: Fn(PhysicalInterface) + Send + Sync + 'static,
        {
        }

        pub fn refresh_physical_interface(&self) -> io::Result<PhysicalInterface> {
            Err(unsupported())
        }

        pub fn interface_index(&self) -> u32 {
            0
        }

        pub fn writer(&self) -> WindowsTunWriter {
            WindowsTunWriter(())
        }

        pub fn start_reader<F>(&mut self, _on_packet: F) -> io::Result<()>
        where
            F: FnMut(&[u8]) + Send + 'static,
        {
            Err(unsupported())
        }
    }

    #[derive(Clone)]
    pub struct WindowsTunWriter(());

    impl WindowsTunWriter {
        pub fn write(&self, _packet: &[u8]) -> bool {
            false
        }
    }

    pub fn bind_socket_to_interface(_socket: u64, _index: u32, _ipv6: bool) -> io::Result<()> {
        Err(unsupported())
    }
}

#[cfg(windows)]
mod native {
    use super::*;
    use std::ffi::{c_void, OsStr, OsString};
    use std::mem::{size_of, transmute, zeroed};
    use std::os::windows::ffi::{OsStrExt, OsStringExt};
    use std::os::windows::io::RawSocket;
    use std::path::PathBuf;
    use std::process::{Command, Stdio};
    use std::ptr::{null, null_mut};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::thread;

    use windows_sys::core::GUID;
    use windows_sys::Win32::Foundation::{
        CloseHandle, FreeLibrary, GetLastError, HANDLE, HMODULE, WAIT_OBJECT_0,
    };
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        CancelMibChangeNotify2, ConvertInterfaceLuidToIndex, CreateIpForwardEntry2,
        CreateUnicastIpAddressEntry, FreeMibTable, GetBestInterfaceEx, GetIpForwardTable2,
        GetIpInterfaceEntry, InitializeIpForwardEntry, InitializeIpInterfaceEntry,
        InitializeUnicastIpAddressEntry, NotifyIpInterfaceChange, NotifyRouteChange2,
        SetIpInterfaceEntry, MIB_IPFORWARD_ROW2, MIB_IPFORWARD_TABLE2, MIB_IPINTERFACE_ROW,
        MIB_NOTIFICATION_TYPE, MIB_UNICASTIPADDRESS_ROW,
    };
    use windows_sys::Win32::NetworkManagement::Ndis::NET_LUID_LH;
    use windows_sys::Win32::Networking::WinSock::{
        setsockopt, AF_INET, AF_INET6, AF_UNSPEC, SOCKADDR, SOCKADDR_INET, SOCKET,
    };
    use windows_sys::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryExW};
    use windows_sys::Win32::System::SystemInformation::GetSystemDirectoryW;
    use windows_sys::Win32::System::Threading::{
        CreateEventW, SetEvent, WaitForMultipleObjects, INFINITE,
    };

    const ERROR_NO_MORE_ITEMS: u32 = 259;
    const ERROR_NOT_FOUND: u32 = 1168;
    const ERROR_OBJECT_ALREADY_EXISTS: u32 = 5010;
    const LOAD_WITH_ALTERED_SEARCH_PATH: u32 = 0x0000_0008;
    const IPPROTO_IP: i32 = 0;
    const IPPROTO_IPV6: i32 = 41;
    const IP_UNICAST_IF: i32 = 31;
    const IPV6_UNICAST_IF: i32 = 31;
    const IP_DAD_STATE_PREFERRED: i32 = 4;

    /// Fixed adapter GUID, so a stale adapter left by a crash is replaced
    /// instead of piling up. {4E3C5B8A-7D21-4F0B-9A6E-1C2D3E4F5A6B}
    const ADAPTER_GUID: GUID = GUID {
        data1: 0x4e3c_5b8a,
        data2: 0x7d21,
        data3: 0x4f0b,
        data4: [0x9a, 0x6e, 0x1c, 0x2d, 0x3e, 0x4f, 0x5a, 0x6b],
    };

    type AdapterHandle = *mut c_void;
    type SessionHandle = *mut c_void;

    type CreateAdapterFn =
        unsafe extern "system" fn(*const u16, *const u16, *const GUID) -> AdapterHandle;
    type CloseAdapterFn = unsafe extern "system" fn(AdapterHandle);
    type GetAdapterLuidFn = unsafe extern "system" fn(AdapterHandle, *mut NET_LUID_LH);
    type StartSessionFn = unsafe extern "system" fn(AdapterHandle, u32) -> SessionHandle;
    type EndSessionFn = unsafe extern "system" fn(SessionHandle);
    type GetReadWaitEventFn = unsafe extern "system" fn(SessionHandle) -> HANDLE;
    type ReceivePacketFn = unsafe extern "system" fn(SessionHandle, *mut u32) -> *mut u8;
    type ReleaseReceivePacketFn = unsafe extern "system" fn(SessionHandle, *const u8);
    type AllocateSendPacketFn = unsafe extern "system" fn(SessionHandle, u32) -> *mut u8;
    type SendPacketFn = unsafe extern "system" fn(SessionHandle, *const u8);

    struct WintunApi {
        module: HMODULE,
        create_adapter: CreateAdapterFn,
        close_adapter: CloseAdapterFn,
        get_adapter_luid: GetAdapterLuidFn,
        start_session: StartSessionFn,
        end_session: EndSessionFn,
        get_read_wait_event: GetReadWaitEventFn,
        receive_packet: ReceivePacketFn,
        release_receive_packet: ReleaseReceivePacketFn,
        allocate_send_packet: AllocateSendPacketFn,
        send_packet: SendPacketFn,
    }

    impl WintunApi {
        fn load(path: &Path) -> io::Result<Self> {
            if !path.is_absolute() || !path.is_file() {
                return Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    "wintun.dll is missing from the client directory",
                ));
            }
            let wide = wide(path.as_os_str());
            let module =
                unsafe { LoadLibraryExW(wide.as_ptr(), null_mut(), LOAD_WITH_ALTERED_SEARCH_PATH) };
            if module.is_null() {
                return Err(last_os_error("wintun.dll could not be loaded"));
            }
            macro_rules! symbol {
                ($name:literal, $type:ty) => {{
                    match unsafe { GetProcAddress(module, concat!($name, "\0").as_ptr()) } {
                        // SAFETY: the Wintun export has this signature
                        // (wintun.h, Wintun 0.14).
                        Some(function) => unsafe {
                            transmute::<unsafe extern "system" fn() -> isize, $type>(function)
                        },
                        None => {
                            unsafe { FreeLibrary(module) };
                            return Err(io::Error::new(
                                io::ErrorKind::NotFound,
                                concat!("wintun.dll has no ", $name),
                            ));
                        }
                    }
                }};
            }
            Ok(Self {
                module,
                create_adapter: symbol!("WintunCreateAdapter", CreateAdapterFn),
                close_adapter: symbol!("WintunCloseAdapter", CloseAdapterFn),
                get_adapter_luid: symbol!("WintunGetAdapterLUID", GetAdapterLuidFn),
                start_session: symbol!("WintunStartSession", StartSessionFn),
                end_session: symbol!("WintunEndSession", EndSessionFn),
                get_read_wait_event: symbol!("WintunGetReadWaitEvent", GetReadWaitEventFn),
                receive_packet: symbol!("WintunReceivePacket", ReceivePacketFn),
                release_receive_packet: symbol!(
                    "WintunReleaseReceivePacket",
                    ReleaseReceivePacketFn
                ),
                allocate_send_packet: symbol!("WintunAllocateSendPacket", AllocateSendPacketFn),
                send_packet: symbol!("WintunSendPacket", SendPacketFn),
            })
        }
    }

    impl Drop for WintunApi {
        fn drop(&mut self) {
            unsafe { FreeLibrary(self.module) };
        }
    }

    /// Adapter + session; dropped once the reader and every writer are gone.
    struct Session {
        api: WintunApi,
        adapter: AdapterHandle,
        session: SessionHandle,
        closed: AtomicBool,
    }

    // SAFETY: Wintun session and adapter handles may be used from any
    // thread; sends are thread-safe, receives happen on the reader thread.
    unsafe impl Send for Session {}
    unsafe impl Sync for Session {}

    impl Drop for Session {
        fn drop(&mut self) {
            unsafe {
                (self.api.end_session)(self.session);
                // Deletes the adapter and with it its address and routes.
                (self.api.close_adapter)(self.adapter);
            }
        }
    }

    struct Event(HANDLE);

    // SAFETY: an event handle may be signalled and waited on from any thread.
    unsafe impl Send for Event {}
    unsafe impl Sync for Event {}

    impl Event {
        fn new() -> io::Result<Self> {
            let handle = unsafe { CreateEventW(null(), 1, 0, null()) };
            if handle.is_null() {
                return Err(last_os_error("could not create an event"));
            }
            Ok(Self(handle))
        }
    }

    impl Drop for Event {
        fn drop(&mut self) {
            unsafe { CloseHandle(self.0) };
        }
    }

    pub struct WindowsTun {
        session: Arc<Session>,
        interface_index: u32,
        physical: Arc<PhysicalInterfaceTracker>,
        watch: Option<RouteWatch>,
        quit: Arc<Event>,
        reader: Option<thread::JoinHandle<()>>,
    }

    impl WindowsTun {
        /// Creates and configures the adapter. Needs administrator rights.
        pub fn open(settings: &WindowsTunSettings, wintun_dll: &Path) -> io::Result<Self> {
            settings.validate()?;
            let api = WintunApi::load(wintun_dll)?;
            // The physical interfaces, before our routes make the adapter the
            // best path everywhere. Later changes are picked from the routing
            // table by the watcher started below.
            let physical = PhysicalInterface {
                ipv4_index: best_interface_v4(Ipv4Addr::new(1, 1, 1, 1)),
                ipv6_index: best_interface_v6(Ipv6Addr::new(0x2606, 0x4700, 0, 0, 0, 0, 0, 0x1111)),
            };
            if physical.ipv4_index.is_none() && physical.ipv6_index.is_none() {
                return Err(io::Error::new(
                    io::ErrorKind::NotConnected,
                    "no network connection to route around the TUN adapter",
                ));
            }

            let name = wide(OsStr::new(&settings.adapter_name));
            let tunnel_type = wide(OsStr::new("AnixOps"));
            let adapter =
                unsafe { (api.create_adapter)(name.as_ptr(), tunnel_type.as_ptr(), &ADAPTER_GUID) };
            if adapter.is_null() {
                return Err(last_os_error("the Wintun adapter could not be created"));
            }
            let session = unsafe { (api.start_session)(adapter, settings.ring_capacity) };
            if session.is_null() {
                let error = last_os_error("the Wintun session could not be started");
                unsafe { (api.close_adapter)(adapter) };
                return Err(error);
            }
            let session = Arc::new(Session {
                api,
                adapter,
                session,
                closed: AtomicBool::new(false),
            });

            let mut luid: NET_LUID_LH = unsafe { zeroed() };
            unsafe { (session.api.get_adapter_luid)(session.adapter, &mut luid) };
            let mut interface_index = 0_u32;
            win32(
                unsafe { ConvertInterfaceLuidToIndex(&luid, &mut interface_index) },
                "the TUN adapter has no interface index",
            )?;

            // Any failure from here drops `session`, which deletes the adapter
            // and everything configured on it.
            configure_interface(&luid, AF_INET, settings.mtu)?;
            add_address(&luid, ipv4_sockaddr(settings.ipv4.0), settings.ipv4.1)?;
            if let Some((address, prefix)) = settings.ipv6 {
                configure_interface(&luid, AF_INET6, settings.mtu)?;
                add_address(&luid, ipv6_sockaddr(address), prefix)?;
            }
            set_dns(interface_index, settings.dns)?;
            for route in capture_routes(settings) {
                add_route(&luid, interface_index, route)?;
            }

            let physical = Arc::new(PhysicalInterfaceTracker::new(interface_index, physical));
            // Started after the capture routes, so their own notifications
            // do not count as a network change.
            let watch = RouteWatch::start(physical.clone())?;
            Ok(Self {
                session,
                interface_index,
                physical,
                watch: Some(watch),
                quit: Arc::new(Event::new()?),
                reader: None,
            })
        }

        /// The interfaces the engine's own sockets must use now. It changes
        /// with the network; a socket protector reads
        /// [`Self::physical_interface_handle`] instead of keeping this value.
        pub fn physical_interface(&self) -> PhysicalInterface {
            self.physical.handle.get()
        }

        /// The shared physical interface, updated in place when the network
        /// changes. The socket protector calls
        /// [`PhysicalInterfaceHandle::bind_socket`] on it for every socket.
        pub fn physical_interface_handle(&self) -> PhysicalInterfaceHandle {
            self.physical.handle.clone()
        }

        /// Runs `on_change` with the new physical interface each time it
        /// changes, on the adapter's watcher thread or on the thread calling
        /// [`Self::refresh_physical_interface`]. Sockets made before keep the
        /// old interface: the host reports the new path
        /// (`engine_outbound::protect::path_changed`) and closes the
        /// connections that still use it (`reset_network`). Replaces an
        /// earlier callback. `on_change` must not wait for whoever drops
        /// this adapter, which waits for the watcher thread to end.
        pub fn on_physical_interface_change<F>(&self, on_change: F)
        where
            F: Fn(PhysicalInterface) + Send + Sync + 'static,
        {
            self.physical.set_on_change(Some(Arc::new(on_change)));
        }

        /// Picks the physical interface again from the routing table now,
        /// as the watcher does after a change; for a host that learnt of a
        /// network change (or a wake from sleep) on its own. Runs the change
        /// callback when the pick moved.
        pub fn refresh_physical_interface(&self) -> io::Result<PhysicalInterface> {
            let routes = default_routes()?;
            Ok(self.physical.apply(&routes))
        }

        /// The adapter's interface index.
        pub fn interface_index(&self) -> u32 {
            self.interface_index
        }

        /// A handle that writes packets into the adapter.
        pub fn writer(&self) -> WindowsTunWriter {
            WindowsTunWriter {
                session: self.session.clone(),
            }
        }

        /// Starts the thread that hands every packet read from the adapter
        /// to `on_packet`. Called once.
        pub fn start_reader<F>(&mut self, mut on_packet: F) -> io::Result<()>
        where
            F: FnMut(&[u8]) + Send + 'static,
        {
            if self.reader.is_some() {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "the TUN reader is already running",
                ));
            }
            let session = self.session.clone();
            let quit = self.quit.clone();
            let read_event = unsafe { (session.api.get_read_wait_event)(session.session) };
            let read_event = read_event as usize;
            let reader = thread::Builder::new()
                .name("anixops-wintun-reader".to_string())
                .spawn(move || {
                    let events = [read_event as HANDLE, quit.0];
                    loop {
                        if session.closed.load(Ordering::Acquire) {
                            return;
                        }
                        let mut size = 0_u32;
                        let packet =
                            unsafe { (session.api.receive_packet)(session.session, &mut size) };
                        if packet.is_null() {
                            match unsafe { GetLastError() } {
                                ERROR_NO_MORE_ITEMS => {
                                    let wait = unsafe {
                                        WaitForMultipleObjects(2, events.as_ptr(), 0, INFINITE)
                                    };
                                    if wait != WAIT_OBJECT_0 {
                                        return;
                                    }
                                    continue;
                                }
                                // ERROR_HANDLE_EOF: the session ended.
                                _ => return,
                            }
                        }
                        // SAFETY: Wintun returned `size` readable bytes, valid
                        // until the packet is released below.
                        let bytes = unsafe { std::slice::from_raw_parts(packet, size as usize) };
                        on_packet(bytes);
                        unsafe { (session.api.release_receive_packet)(session.session, packet) };
                    }
                })?;
            self.reader = Some(reader);
            Ok(())
        }

        fn shutdown(&mut self) {
            // First, so closing the adapter (and its routes) is not taken
            // for a network change.
            self.watch = None;
            self.physical.set_on_change(None);
            self.session.closed.store(true, Ordering::Release);
            unsafe { SetEvent(self.quit.0) };
            if let Some(reader) = self.reader.take() {
                let _ = reader.join();
            }
        }
    }

    impl Drop for WindowsTun {
        fn drop(&mut self) {
            self.shutdown();
        }
    }

    /// A registration with the system's route or interface notifications;
    /// cancelled when dropped.
    struct Notification(HANDLE);

    // SAFETY: a notification handle may be cancelled from any thread.
    unsafe impl Send for Notification {}
    unsafe impl Sync for Notification {}

    impl Drop for Notification {
        fn drop(&mut self) {
            // Also waits for a callback that is running to return.
            unsafe { CancelMibChangeNotify2(self.0) };
        }
    }

    /// Picks the physical interface again whenever a default route or an
    /// interface changes, on its own thread.
    struct RouteWatch {
        signal: Arc<WatchSignal>,
        notifications: Vec<Notification>,
        thread: Option<thread::JoinHandle<()>>,
    }

    impl RouteWatch {
        fn start(tracker: Arc<PhysicalInterfaceTracker>) -> io::Result<Self> {
            let signal = Arc::new(WatchSignal::default());
            let thread = thread::Builder::new()
                .name("anixops-tun-route-watch".to_string())
                .spawn({
                    let signal = signal.clone();
                    move || {
                        while signal.wait_for_change(ROUTE_SETTLE, ROUTE_SETTLE_MAX) {
                            match default_routes() {
                                Ok(routes) => {
                                    tracker.apply(&routes);
                                }
                                // Read again once the table settles.
                                Err(_) => signal.notify(),
                            }
                        }
                    }
                })?;
            // A failure from here drops `watch`, which stops the thread.
            let mut watch = Self {
                signal,
                notifications: Vec::with_capacity(2),
                thread: Some(thread),
            };
            // The callbacks get a pointer to the signal, which `watch` keeps
            // alive until both registrations are cancelled.
            let context = Arc::as_ptr(&watch.signal).cast::<c_void>();
            let mut handle: HANDLE = null_mut();
            win32(
                unsafe {
                    NotifyRouteChange2(AF_UNSPEC, Some(route_changed), context, false, &mut handle)
                },
                "route changes could not be watched",
            )?;
            watch.notifications.push(Notification(handle));
            let mut handle: HANDLE = null_mut();
            win32(
                unsafe {
                    NotifyIpInterfaceChange(
                        AF_UNSPEC,
                        Some(interface_changed),
                        context,
                        false,
                        &mut handle,
                    )
                },
                "interface changes could not be watched",
            )?;
            watch.notifications.push(Notification(handle));
            Ok(watch)
        }
    }

    impl Drop for RouteWatch {
        fn drop(&mut self) {
            // No callback runs once the registrations are cancelled, so the
            // signal they point to may go.
            self.notifications.clear();
            self.signal.quit();
            if let Some(thread) = self.thread.take() {
                let _ = thread.join();
            }
        }
    }

    unsafe extern "system" fn route_changed(
        context: *const c_void,
        row: *const MIB_IPFORWARD_ROW2,
        _kind: MIB_NOTIFICATION_TYPE,
    ) {
        // Only default routes decide the physical interface; the row is
        // missing on some notifications, which count.
        if !row.is_null() && unsafe { (*row).DestinationPrefix.PrefixLength } != 0 {
            return;
        }
        // SAFETY: `context` is the `WatchSignal` the `RouteWatch` keeps
        // alive until this registration is cancelled.
        unsafe { (*context.cast::<WatchSignal>()).notify() };
    }

    unsafe extern "system" fn interface_changed(
        context: *const c_void,
        _row: *const MIB_IPINTERFACE_ROW,
        _kind: MIB_NOTIFICATION_TYPE,
    ) {
        // SAFETY: as in `route_changed`.
        unsafe { (*context.cast::<WatchSignal>()).notify() };
    }

    /// The default routes of both families with their interfaces' metric
    /// and state.
    fn default_routes() -> io::Result<Vec<DefaultRoute>> {
        let mut table: *mut MIB_IPFORWARD_TABLE2 = null_mut();
        let result = unsafe { GetIpForwardTable2(AF_UNSPEC, &mut table) };
        if result == ERROR_NOT_FOUND {
            return Ok(Vec::new());
        }
        win32(result, "the routing table could not be read")?;
        if table.is_null() {
            return Ok(Vec::new());
        }
        let mut routes = Vec::new();
        // SAFETY: GetIpForwardTable2 returned a table of `NumEntries` rows,
        // read here and freed once below.
        unsafe {
            let count = (*table).NumEntries as usize;
            let first = std::ptr::addr_of!((*table).Table).cast::<MIB_IPFORWARD_ROW2>();
            for row in std::slice::from_raw_parts(first, count) {
                if row.DestinationPrefix.PrefixLength != 0 || row.Loopback {
                    continue;
                }
                let family = row.DestinationPrefix.Prefix.si_family;
                let ipv6 = match family {
                    AF_INET => false,
                    AF_INET6 => true,
                    _ => continue,
                };
                let Some((interface_metric, connected)) =
                    interface_state(family, row.InterfaceIndex)
                else {
                    continue;
                };
                routes.push(DefaultRoute {
                    ipv6,
                    interface_index: row.InterfaceIndex,
                    route_metric: row.Metric,
                    interface_metric,
                    connected,
                });
            }
            FreeMibTable(table.cast_const().cast::<c_void>());
        }
        Ok(routes)
    }

    /// The metric and connected state of interface `index` for `family`;
    /// `None` when it is gone.
    fn interface_state(family: u16, index: u32) -> Option<(u32, bool)> {
        let mut row: MIB_IPINTERFACE_ROW = unsafe { zeroed() };
        unsafe { InitializeIpInterfaceEntry(&mut row) };
        row.Family = family;
        row.InterfaceIndex = index;
        (unsafe { GetIpInterfaceEntry(&mut row) } == 0).then_some((row.Metric, row.Connected))
    }

    /// Writes packets into the adapter. Cheap to clone; safe from any thread.
    #[derive(Clone)]
    pub struct WindowsTunWriter {
        session: Arc<Session>,
    }

    impl WindowsTunWriter {
        /// Queues one IP packet for the system. `false` when the ring is full
        /// or the adapter is closed; the packet is dropped like on a busy NIC.
        pub fn write(&self, packet: &[u8]) -> bool {
            if packet.is_empty() || self.session.closed.load(Ordering::Acquire) {
                return false;
            }
            let Ok(size) = u32::try_from(packet.len()) else {
                return false;
            };
            let session = &self.session;
            let buffer = unsafe { (session.api.allocate_send_packet)(session.session, size) };
            if buffer.is_null() {
                return false;
            }
            // SAFETY: Wintun allocated `size` writable bytes for this packet.
            unsafe {
                std::ptr::copy_nonoverlapping(packet.as_ptr(), buffer, packet.len());
                (session.api.send_packet)(session.session, buffer);
            }
            true
        }
    }

    /// Pins `socket` to interface `index` with `IP_UNICAST_IF` /
    /// `IPV6_UNICAST_IF`, so it leaves through that interface whatever the
    /// routing table says. Call before the socket connects or sends.
    pub fn bind_socket_to_interface(socket: RawSocket, index: u32, ipv6: bool) -> io::Result<()> {
        let value = unicast_if_option_value(index, ipv6);
        let (level, option) = if ipv6 {
            (IPPROTO_IPV6, IPV6_UNICAST_IF)
        } else {
            (IPPROTO_IP, IP_UNICAST_IF)
        };
        let result = unsafe {
            setsockopt(
                socket as SOCKET,
                level,
                option,
                (&value as *const u32).cast(),
                size_of::<u32>() as i32,
            )
        };
        if result != 0 {
            return Err(io::Error::last_os_error());
        }
        if ipv6 {
            // A dual-stack IPv6 socket may also send IPv4.
            let value = unicast_if_option_value(index, false);
            unsafe {
                setsockopt(
                    socket as SOCKET,
                    IPPROTO_IP,
                    IP_UNICAST_IF,
                    (&value as *const u32).cast(),
                    size_of::<u32>() as i32,
                )
            };
        }
        Ok(())
    }

    fn best_interface_v4(destination: Ipv4Addr) -> Option<u32> {
        let address = ipv4_sockaddr(destination);
        best_interface(&address)
    }

    fn best_interface_v6(destination: Ipv6Addr) -> Option<u32> {
        let address = ipv6_sockaddr(destination);
        best_interface(&address)
    }

    fn best_interface(address: &SOCKADDR_INET) -> Option<u32> {
        let mut index = 0_u32;
        let result = unsafe {
            GetBestInterfaceEx(
                (address as *const SOCKADDR_INET).cast::<SOCKADDR>(),
                &mut index,
            )
        };
        (result == 0 && index != 0).then_some(index)
    }

    fn ipv4_sockaddr(address: Ipv4Addr) -> SOCKADDR_INET {
        let mut sockaddr: SOCKADDR_INET = unsafe { zeroed() };
        sockaddr.Ipv4.sin_family = AF_INET;
        sockaddr.Ipv4.sin_addr.S_un.S_addr = u32::from_ne_bytes(address.octets());
        sockaddr
    }

    fn ipv6_sockaddr(address: Ipv6Addr) -> SOCKADDR_INET {
        let mut sockaddr: SOCKADDR_INET = unsafe { zeroed() };
        sockaddr.Ipv6.sin6_family = AF_INET6;
        sockaddr.Ipv6.sin6_addr.u.Byte = address.octets();
        sockaddr
    }

    fn configure_interface(luid: &NET_LUID_LH, family: u16, mtu: u32) -> io::Result<()> {
        let mut row: MIB_IPINTERFACE_ROW = unsafe { zeroed() };
        unsafe { InitializeIpInterfaceEntry(&mut row) };
        row.Family = family;
        row.InterfaceLuid = *luid;
        win32(
            unsafe { GetIpInterfaceEntry(&mut row) },
            "the TUN adapter settings could not be read",
        )?;
        // Lowest metric: the adapter's DNS server is asked first.
        row.UseAutomaticMetric = Default::default();
        row.Metric = 0;
        row.NlMtu = mtu;
        if family == AF_INET {
            // SetIpInterfaceEntry rejects a non-zero site prefix for IPv4.
            row.SitePrefixLength = 0;
        }
        win32(
            unsafe { SetIpInterfaceEntry(&mut row) },
            "the TUN adapter settings could not be changed",
        )
    }

    fn add_address(luid: &NET_LUID_LH, address: SOCKADDR_INET, prefix: u8) -> io::Result<()> {
        let mut row: MIB_UNICASTIPADDRESS_ROW = unsafe { zeroed() };
        unsafe { InitializeUnicastIpAddressEntry(&mut row) };
        row.InterfaceLuid = *luid;
        row.Address = address;
        row.OnLinkPrefixLength = prefix;
        row.DadState = IP_DAD_STATE_PREFERRED;
        let result = unsafe { CreateUnicastIpAddressEntry(&row) };
        if result == ERROR_OBJECT_ALREADY_EXISTS {
            return Ok(());
        }
        win32(result, "the TUN adapter address could not be set")
    }

    fn add_route(luid: &NET_LUID_LH, index: u32, route: CaptureRoute) -> io::Result<()> {
        let mut row: MIB_IPFORWARD_ROW2 = unsafe { zeroed() };
        unsafe { InitializeIpForwardEntry(&mut row) };
        row.InterfaceLuid = *luid;
        row.InterfaceIndex = index;
        match route {
            CaptureRoute::V4(prefix, length) => {
                row.DestinationPrefix.Prefix = ipv4_sockaddr(prefix);
                row.DestinationPrefix.PrefixLength = length;
                row.NextHop = ipv4_sockaddr(Ipv4Addr::UNSPECIFIED);
            }
            CaptureRoute::V6(prefix, length) => {
                row.DestinationPrefix.Prefix = ipv6_sockaddr(prefix);
                row.DestinationPrefix.PrefixLength = length;
                row.NextHop = ipv6_sockaddr(Ipv6Addr::UNSPECIFIED);
            }
        }
        row.Metric = 0;
        let result = unsafe { CreateIpForwardEntry2(&row) };
        if result == ERROR_OBJECT_ALREADY_EXISTS {
            return Ok(());
        }
        win32(result, "a TUN route could not be added")
    }

    /// Points the adapter's IPv4 DNS at `dns` with netsh from System32.
    fn set_dns(index: u32, dns: Ipv4Addr) -> io::Result<()> {
        let status = netsh_command()?
            .args([
                "interface",
                "ipv4",
                "set",
                "dnsservers",
                &format!("name={index}"),
                "source=static",
                &format!("address={dns}"),
                "register=none",
                "validate=no",
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()?;
        if !status.success() {
            return Err(io::Error::other("the TUN adapter DNS could not be set"));
        }
        Ok(())
    }

    fn netsh_command() -> io::Result<Command> {
        let mut buffer = vec![0_u16; 260];
        let length =
            unsafe { GetSystemDirectoryW(buffer.as_mut_ptr(), buffer.len() as u32) } as usize;
        if length == 0 || length >= buffer.len() {
            return Err(io::Error::other(
                "the Windows system directory is unavailable",
            ));
        }
        let system_directory = PathBuf::from(OsString::from_wide(&buffer[..length]));
        let executable = system_directory.join("netsh.exe");
        if !executable.is_file() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "netsh.exe is unavailable",
            ));
        }
        let system_root = system_directory
            .parent()
            .ok_or_else(|| io::Error::other("the Windows directory is unavailable"))?
            .to_path_buf();
        let mut command = Command::new(executable);
        command
            .env_clear()
            .env("SystemRoot", &system_root)
            .env("windir", &system_root)
            .env("PATH", &system_directory)
            .current_dir(&system_directory)
            .stdin(Stdio::null());
        Ok(command)
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

    fn last_os_error(message: &str) -> io::Error {
        let error = io::Error::last_os_error();
        io::Error::new(error.kind(), format!("{message}: {error}"))
    }

    fn wide(value: &OsStr) -> Vec<u16> {
        value.encode_wide().chain(Some(0)).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_settings_are_valid() {
        WindowsTunSettings::default().validate().unwrap();
    }

    #[test]
    fn dns_outside_the_adapter_subnet_is_rejected() {
        let settings = WindowsTunSettings {
            dns: Ipv4Addr::new(1, 1, 1, 1),
            ..WindowsTunSettings::default()
        };
        assert!(settings.validate().is_err());
        let settings = WindowsTunSettings {
            dns: WindowsTunSettings::default().ipv4.0,
            ..WindowsTunSettings::default()
        };
        assert!(settings.validate().is_err());
    }

    #[test]
    fn ring_capacity_must_be_a_power_of_two_in_range() {
        for capacity in [0, 0x1_0000, 0x30_0000, 0x800_0000] {
            let settings = WindowsTunSettings {
                ring_capacity: capacity,
                ..WindowsTunSettings::default()
            };
            assert!(settings.validate().is_err(), "{capacity:#x}");
        }
    }

    #[test]
    fn capture_routes_split_each_address_space_in_half() {
        let settings = WindowsTunSettings::default();
        assert_eq!(
            capture_routes(&settings),
            vec![
                CaptureRoute::V4(Ipv4Addr::new(0, 0, 0, 0), 1),
                CaptureRoute::V4(Ipv4Addr::new(128, 0, 0, 0), 1),
                CaptureRoute::V6(Ipv6Addr::UNSPECIFIED, 1),
                CaptureRoute::V6("8000::".parse().unwrap(), 1),
            ]
        );
        let v4_only = WindowsTunSettings {
            ipv6: None,
            ..settings
        };
        assert_eq!(capture_routes(&v4_only).len(), 2);
    }

    #[test]
    fn unicast_if_takes_network_order_for_ipv4_only() {
        assert_eq!(unicast_if_option_value(7, true), 7);
        assert_eq!(
            unicast_if_option_value(7, false).to_ne_bytes(),
            [0, 0, 0, 7]
        );
    }

    #[test]
    fn physical_interface_picks_by_family() {
        let physical = PhysicalInterface {
            ipv4_index: Some(4),
            ipv6_index: None,
        };
        assert_eq!(physical.index_for(false), Some(4));
        assert_eq!(physical.index_for(true), None);
    }

    const TUN: u32 = 40;

    fn route(
        ipv6: bool,
        interface_index: u32,
        route_metric: u32,
        interface_metric: u32,
    ) -> DefaultRoute {
        DefaultRoute {
            ipv6,
            interface_index,
            route_metric,
            interface_metric,
            connected: true,
        }
    }

    #[test]
    fn selection_never_picks_the_tun_adapter() {
        // The adapter's own routes are the best ones; a default route on it
        // (another tool, or a user's route) must not become the "physical"
        // interface, or every socket would loop back into the adapter.
        let routes = [route(false, TUN, 0, 0), route(false, 7, 25, 25)];
        assert_eq!(
            select_physical_interface(&routes, TUN),
            PhysicalInterface {
                ipv4_index: Some(7),
                ipv6_index: None,
            }
        );
        assert_eq!(
            select_physical_interface(&[route(false, TUN, 0, 0)], TUN),
            PhysicalInterface::default()
        );
    }

    #[test]
    fn selection_takes_the_lowest_route_plus_interface_metric_per_family() {
        let routes = [
            // Wi-Fi: 0 + 50; Ethernet: 0 + 25; a tether: 10 + 20.
            route(false, 12, 0, 50),
            route(false, 7, 0, 25),
            route(false, 30, 10, 20),
            route(true, 12, 256, 50),
            route(true, 7, 256, 75),
        ];
        assert_eq!(
            select_physical_interface(&routes, TUN),
            PhysicalInterface {
                ipv4_index: Some(7),
                ipv6_index: Some(12),
            }
        );
        // Equal weights pick the lower index, whatever the table order.
        let tie = [route(false, 9, 0, 10), route(false, 8, 5, 5)];
        assert_eq!(select_physical_interface(&tie, TUN).ipv4_index, Some(8));
    }

    #[test]
    fn selection_skips_disconnected_interfaces_and_index_zero() {
        let mut unplugged = route(false, 7, 0, 5);
        unplugged.connected = false;
        let routes = [unplugged, route(false, 0, 0, 0), route(false, 12, 0, 50)];
        assert_eq!(select_physical_interface(&routes, TUN).ipv4_index, Some(12));
    }

    #[test]
    fn handle_is_shared_and_moves_its_generation_on_change_only() {
        let handle = PhysicalInterfaceHandle::new(PhysicalInterface {
            ipv4_index: Some(12),
            ipv6_index: None,
        });
        let protector_copy = handle.clone();
        let before = handle.generation();
        assert!(!handle.set(PhysicalInterface {
            ipv4_index: Some(12),
            ipv6_index: None,
        }));
        assert_eq!(handle.generation(), before);
        assert!(handle.set(PhysicalInterface {
            ipv4_index: Some(7),
            ipv6_index: Some(7),
        }));
        assert!(handle.generation() > before);
        assert_eq!(
            protector_copy.get(),
            PhysicalInterface {
                ipv4_index: Some(7),
                ipv6_index: Some(7),
            }
        );
    }

    #[test]
    fn bind_socket_refuses_a_family_without_a_physical_interface() {
        let handle = PhysicalInterfaceHandle::new(PhysicalInterface {
            ipv4_index: Some(7),
            ipv6_index: None,
        });
        let error = handle
            .bind_socket(0, "[2606:4700::1111]:443".parse().unwrap())
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::NetworkUnreachable);
    }

    fn recording_tracker(
        initial: PhysicalInterface,
    ) -> (PhysicalInterfaceTracker, Arc<Mutex<Vec<PhysicalInterface>>>) {
        let tracker = PhysicalInterfaceTracker::new(TUN, initial);
        let seen = Arc::new(Mutex::new(Vec::new()));
        let record = seen.clone();
        tracker.set_on_change(Some(Arc::new(move |physical| {
            record.lock().unwrap().push(physical);
        })));
        (tracker, seen)
    }

    #[test]
    fn tracker_follows_a_switch_from_wifi_to_ethernet() {
        let wifi = PhysicalInterface {
            ipv4_index: Some(12),
            ipv6_index: None,
        };
        let (tracker, seen) = recording_tracker(wifi);
        let protector = tracker.handle.clone();

        // Same network after an unrelated notification: nothing to do.
        tracker.apply(&[route(false, 12, 0, 50), route(false, TUN, 0, 0)]);
        assert!(seen.lock().unwrap().is_empty());

        // Docked: Ethernet comes up, Wi-Fi goes away.
        let ethernet = PhysicalInterface {
            ipv4_index: Some(7),
            ipv6_index: None,
        };
        assert_eq!(
            tracker.apply(&[route(false, 7, 0, 25), route(false, TUN, 0, 0)]),
            ethernet
        );
        assert_eq!(protector.get(), ethernet);
        assert_eq!(*seen.lock().unwrap(), vec![ethernet]);
    }

    #[test]
    fn tracker_picks_up_ipv6_that_arrives_later() {
        let v4_only = PhysicalInterface {
            ipv4_index: Some(12),
            ipv6_index: None,
        };
        let (tracker, seen) = recording_tracker(v4_only);
        let dual = PhysicalInterface {
            ipv4_index: Some(12),
            ipv6_index: Some(12),
        };
        tracker.apply(&[route(false, 12, 0, 50), route(true, 12, 256, 50)]);
        assert_eq!(tracker.handle.get(), dual);
        assert_eq!(*seen.lock().unwrap(), vec![dual]);
    }

    #[test]
    fn tracker_reports_losing_every_physical_interface() {
        let (tracker, seen) = recording_tracker(PhysicalInterface {
            ipv4_index: Some(12),
            ipv6_index: None,
        });
        tracker.apply(&[route(false, TUN, 0, 0)]);
        assert_eq!(tracker.handle.get(), PhysicalInterface::default());
        assert_eq!(*seen.lock().unwrap(), vec![PhysicalInterface::default()]);
    }

    #[test]
    fn watch_signal_coalesces_a_burst_and_stops_on_quit() {
        let signal = Arc::new(WatchSignal::default());
        let settle = Duration::from_millis(300);
        let settle_max = Duration::from_secs(5);
        for _ in 0..5 {
            signal.notify();
        }
        assert!(signal.wait_for_change(settle, settle_max));

        let notifier = signal.clone();
        let burst = std::thread::spawn(move || {
            for _ in 0..3 {
                notifier.notify();
                std::thread::sleep(Duration::from_millis(5));
            }
        });
        assert!(signal.wait_for_change(settle, settle_max));
        burst.join().unwrap();
        // The whole burst was one change: nothing is left pending.
        assert!(!lock(&signal.state).pending);

        let quitter = signal.clone();
        let quit = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(20));
            quitter.quit();
        });
        assert!(!signal.wait_for_change(settle, settle_max));
        quit.join().unwrap();
    }

    #[test]
    fn watch_signal_gives_up_settling_after_the_maximum() {
        let signal = Arc::new(WatchSignal::default());
        let notifier = signal.clone();
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let stopping = stop.clone();
        let storm = std::thread::spawn(move || {
            while !stopping.load(Ordering::Acquire) {
                notifier.notify();
                std::thread::sleep(Duration::from_millis(5));
            }
        });
        let started = Instant::now();
        assert!(signal.wait_for_change(Duration::from_millis(100), Duration::from_millis(300)));
        assert!(started.elapsed() < Duration::from_secs(3));
        stop.store(true, Ordering::Release);
        storm.join().unwrap();
    }
}
