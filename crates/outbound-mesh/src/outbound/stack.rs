//! One mesh network inside the engine: the [`driver`](crate::driver) for the
//! network, and the node's private userspace TCP/IP stack (smoltcp) that
//! holds this node's virtual addresses in place of a virtual interface.
//!
//! The network starts with the first connection ([`Instance::ensure_running`])
//! or when the engine asks for it ([`Instance::start`]), and runs until the
//! instance is dropped: a mesh node also carries other members' traffic
//! (relay) and keeps its routes synchronised, so it does not stop when it
//! has no connection of its own. The stack outlives a driver that stopped on
//! an error; the next connection starts a new one.
//!
//! The pump task moves packets between the stack and the driver. It holds
//! the instance only weakly, so dropping the last outbound that uses the
//! network stops the pump, and dropping the shutdown sender stops the
//! driver.

use std::collections::{HashSet, VecDeque};
use std::hash::{BuildHasher, Hasher};
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, Weak};
use std::task::Poll as TaskPoll;
use std::time::{Duration, Instant};

use ring::rand::SystemRandom;
use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::socket::{tcp, udp, AnySocket};
use smoltcp::time::{Duration as SmolDuration, Instant as SmolInstant};
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr, IpEndpoint};
use tokio::sync::{mpsc, watch, Notify};

use crate::dns::DnsSettings;
use crate::driver::{self, Channels, Listeners, Snapshot};
use crate::secure::noise::KeyPair;
use crate::{IpNet, MeshSettings};

/// The longest the pump sleeps without a packet or a socket change.
const MAX_SLEEP: Duration = Duration::from_millis(250);
/// A closed TCP socket is removed after this long even without a final ACK.
const LINGER: Duration = Duration::from_secs(30);
/// Packets from the driver queued for the stack between two polls.
const STACK_QUEUE: usize = 1024;
/// Packets between the pump and the driver, each way.
const CHANNEL_PACKETS: usize = 1024;
const UDP_PACKETS: usize = 32;
pub(crate) const UDP_BUFFER: usize = 16 * 1024;
/// Receive buffer of each TCP connection; it bounds the window one
/// connection advertises. Same trade-off as the WireGuard outbound: iOS
/// keeps 64 KiB for the Network Extension's memory budget, Android takes
/// 256 KiB, desktops 512 KiB.
#[cfg(target_os = "ios")]
const TCP_RECEIVE_BUFFER: usize = 64 * 1024;
#[cfg(target_os = "android")]
const TCP_RECEIVE_BUFFER: usize = 256 * 1024;
#[cfg(not(any(target_os = "ios", target_os = "android")))]
const TCP_RECEIVE_BUFFER: usize = 512 * 1024;
/// Send buffer of each TCP connection: the stack runs no congestion
/// control, so a larger one would only send larger bursts.
const TCP_SEND_BUFFER: usize = 64 * 1024;
/// Most sockets (connections, flows, closing connections) one network's
/// stack holds; iOS is bounded by the Network Extension's memory.
#[cfg(target_os = "ios")]
pub(crate) const MAX_SOCKETS: usize = 128;
#[cfg(not(target_os = "ios"))]
pub(crate) const MAX_SOCKETS: usize = 1024;
const FIRST_LOCAL_PORT: u16 = 49152;

/// Packet queues between the stack and the driver.
struct QueueDevice {
    rx: VecDeque<Vec<u8>>,
    tx: VecDeque<Vec<u8>>,
    mtu: usize,
}

impl Device for QueueDevice {
    type RxToken<'a> = QueueRx;
    type TxToken<'a> = QueueTx<'a>;

    fn receive(&mut self, _now: SmolInstant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let packet = self.rx.pop_front()?;
        Some((QueueRx(packet), QueueTx(&mut self.tx)))
    }

    fn transmit(&mut self, _now: SmolInstant) -> Option<Self::TxToken<'_>> {
        Some(QueueTx(&mut self.tx))
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut capabilities = DeviceCapabilities::default();
        capabilities.medium = Medium::Ip;
        capabilities.max_transmission_unit = self.mtu;
        capabilities
    }
}

struct QueueRx(Vec<u8>);

impl RxToken for QueueRx {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(&self.0)
    }
}

struct QueueTx<'a>(&'a mut VecDeque<Vec<u8>>);

impl TxToken for QueueTx<'_> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut packet = vec![0u8; len];
        let result = f(&mut packet);
        self.0.push_back(packet);
        result
    }
}

/// The private stack with this node's virtual addresses.
struct Stack {
    iface: Interface,
    sockets: SocketSet<'static>,
    device: QueueDevice,
    /// TCP sockets whose stream was dropped, waiting for the close to finish.
    closing: Vec<(SocketHandle, Instant)>,
}

impl Stack {
    fn new(settings: &MeshSettings, now: SmolInstant, seed: u64) -> Self {
        let mut device = QueueDevice {
            rx: VecDeque::new(),
            tx: VecDeque::new(),
            mtu: usize::from(settings.mtu),
        };
        let mut config = Config::new(HardwareAddress::Ip);
        config.random_seed = seed;
        let mut iface = Interface::new(config, &mut device, now);
        let addresses = settings.local_addresses();
        iface.update_ip_addrs(|addrs| {
            for address in &addresses {
                let cidr = match address {
                    IpAddr::V4(v4) => IpCidr::new(IpAddress::Ipv4(*v4), 32),
                    IpAddr::V6(v6) => IpCidr::new(IpAddress::Ipv6(*v6), 128),
                };
                let _ = addrs.push(cidr);
            }
        });
        // Every destination is behind the driver, which checks it against
        // the mesh routes again; an IP medium needs no neighbour, so the
        // gateway is only a placeholder.
        for address in &addresses {
            match address {
                IpAddr::V4(v4) => {
                    let _ = iface.routes_mut().add_default_ipv4_route(*v4);
                }
                IpAddr::V6(v6) => {
                    let _ = iface.routes_mut().add_default_ipv6_route(*v6);
                }
            }
        }
        Self {
            iface,
            sockets: SocketSet::new(Vec::new()),
            device,
            closing: Vec::new(),
        }
    }

    /// Ends every connection, waking their tasks.
    fn abort_all(&mut self) {
        for (_, socket) in self.sockets.iter_mut() {
            match socket {
                smoltcp::socket::Socket::Tcp(socket) => socket.abort(),
                smoltcp::socket::Socket::Udp(socket) => socket.close(),
                #[allow(unreachable_patterns)]
                _ => {}
            }
        }
        self.device.rx.clear();
        self.device.tx.clear();
    }

    fn sweep(&mut self, now: Instant) {
        let sockets = &mut self.sockets;
        self.closing.retain(|(handle, since)| {
            let socket = sockets.get_mut::<tcp::Socket>(*handle);
            let done = matches!(socket.state(), tcp::State::Closed | tcp::State::TimeWait);
            if done || now.saturating_duration_since(*since) > LINGER {
                socket.abort();
                sockets.remove(*handle);
                false
            } else {
                true
            }
        });
    }
}

/// Why connections cannot use the network now.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Failure {
    /// A `managed` network whose `native_keys` do not list this node yet
    /// (spec §8.3.1): it opens no link until they do.
    NativeKeysPending,
    /// A listening port of the network is in use.
    PortInUse,
    /// The driver stopped on an error.
    Stopped,
    /// The engine built the network again with other settings; this
    /// instance stopped for good and the new one runs instead.
    Replaced,
    /// A `managed` network without `node.private_key`: its key must stay
    /// the one `native_keys` lists, so the engine does not make one
    /// (spec §8.1, §8.3.1).
    PrivateKeyRequired,
    /// A saved network whose `node.instance_id` differs from that of the
    /// profile adopted later: it does not run under a second identity
    /// until saved again with the current ID, or until a profile names
    /// its ID again (`mesh-status.md`).
    InstanceIdChanged,
}

impl Failure {
    /// The `network.failure.code` of the status (`mesh-status.md`).
    pub fn code(self) -> &'static str {
        match self {
            Self::NativeKeysPending => "native_keys_pending",
            Self::PortInUse => "port_in_use",
            Self::PrivateKeyRequired => "private_key_required",
            Self::InstanceIdChanged => "instance_id_changed",
            Self::Stopped | Self::Replaced => "start_refused",
        }
    }

    pub(crate) fn error(self) -> io::Error {
        match self {
            Self::NativeKeysPending => io::Error::new(
                io::ErrorKind::NotConnected,
                "mesh network is waiting for its key list",
            ),
            Self::PortInUse => io::Error::new(
                io::ErrorKind::AddrInUse,
                "mesh network listening port is in use",
            ),
            Self::Stopped => io::Error::new(io::ErrorKind::NotConnected, "mesh network stopped"),
            Self::Replaced => io::Error::new(
                io::ErrorKind::ConnectionReset,
                "mesh network settings changed",
            ),
            Self::PrivateKeyRequired => io::Error::new(
                io::ErrorKind::NotConnected,
                "mesh network needs its private key",
            ),
            Self::InstanceIdChanged => io::Error::new(
                io::ErrorKind::NotConnected,
                "mesh network carries another device instance ID",
            ),
        }
    }
}

struct Core {
    stack: Stack,
    /// Identifies the current driver; 0 before the first one.
    run: u64,
    running: bool,
    failure: Option<Failure>,
    /// Stops the current driver when dropped or set.
    shutdown: Option<watch::Sender<bool>>,
    /// The packets out of the stack go here, to the driver.
    to_driver: Option<mpsc::Sender<Vec<u8>>>,
    /// Networks of this machine; `None` until the engine reads them, and
    /// then no advertised subnet is routed (spec §15.4).
    local_networks: watch::Sender<Option<Vec<IpNet>>>,
    route_overrides: watch::Sender<Vec<IpNet>>,
    native_keys: watch::Sender<Option<Vec<[u8; 32]>>>,
    /// The `dns` settings in force: the settings' section with the local
    /// override (`mesh_set_dns`) applied, changed without a restart.
    dns: watch::Sender<DnsSettings>,
    next_port: u16,
    /// Stopped for good: newer settings replaced the network.
    retired: bool,
}

/// One network: its settings, static key, stack and driver.
pub struct Instance {
    settings: MeshSettings,
    static_key: KeyPair,
    core: Mutex<Core>,
    /// Shared with the pump, which holds the instance only weakly.
    wake: Arc<Notify>,
    snapshot: watch::Sender<Snapshot>,
    /// Ticks when a driver starts or stops, or the network retires.
    changes: watch::Sender<()>,
    epoch: Instant,
    /// The runtime drivers run on; `None` runs them on the caller's.
    runtime: Option<tokio::runtime::Handle>,
}

impl Instance {
    /// A stopped network. Without `node.private_key` a key is made for
    /// this instance only: a client that must keep its key (a `managed`
    /// network lists it in `native_keys`) passes it in the configuration.
    pub fn new(settings: MeshSettings) -> io::Result<Arc<Self>> {
        let static_key = match &settings.private_key {
            Some(private) => KeyPair::from_private_ref(private),
            None => KeyPair::generate(&SystemRandom::new())
                .map_err(|_| io::Error::other("mesh static key could not be made"))?,
        };
        Ok(Self::with_key(settings, static_key, None))
    }

    /// A stopped network with the static key `static_key`, whose drivers
    /// run on `runtime` (or on the caller's runtime for `None`).
    pub(crate) fn with_key(
        settings: MeshSettings,
        static_key: KeyPair,
        runtime: Option<tokio::runtime::Handle>,
    ) -> Arc<Self> {
        let epoch = Instant::now();
        let stack = Stack::new(&settings, SmolInstant::from_micros(0), random());
        let next_port = FIRST_LOCAL_PORT + (random() % 16384) as u16;
        let (local_networks, _) = watch::channel(None);
        let (route_overrides, _) = watch::channel(Vec::new());
        let (native_keys, _) = watch::channel(settings.native_keys.clone());
        let (dns, _) = watch::channel(settings.dns.clone());
        let (snapshot, _) = watch::channel(Snapshot::default());
        Arc::new(Self {
            settings,
            static_key,
            core: Mutex::new(Core {
                stack,
                run: 0,
                running: false,
                failure: None,
                shutdown: None,
                to_driver: None,
                local_networks,
                route_overrides,
                native_keys,
                dns,
                next_port,
                retired: false,
            }),
            wake: Arc::new(Notify::new()),
            snapshot,
            changes: watch::channel(()).0,
            epoch,
            runtime,
        })
    }

    pub fn settings(&self) -> &MeshSettings {
        &self.settings
    }

    /// This node's static public key in the network (spec §8.1).
    pub fn static_public_key(&self) -> [u8; 32] {
        self.static_key.public()
    }

    fn lock(&self) -> MutexGuard<'_, Core> {
        // The lock is never held across an await; a poisoned lock only means
        // a panic in smoltcp, and the state is still usable.
        self.core
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn now(&self) -> SmolInstant {
        let micros = Instant::now()
            .saturating_duration_since(self.epoch)
            .as_micros();
        SmolInstant::from_micros(i64::try_from(micros).unwrap_or(i64::MAX))
    }

    /// Asks the pump to poll the stack, after a socket changed.
    pub(crate) fn wake(&self) {
        self.wake.notify_one();
    }

    /// The driver's state after its last tick.
    pub fn snapshot(&self) -> watch::Receiver<Snapshot> {
        self.snapshot.subscribe()
    }

    /// Ticks when a driver starts or stops, or the network retires: the
    /// moments [`Self::state`] and [`Self::is_retired`] change.
    pub(crate) fn changes(&self) -> watch::Receiver<()> {
        self.changes.subscribe()
    }

    /// Test hook: marks the network running with `snapshot` as its
    /// driver's, without starting one.
    #[cfg(test)]
    pub(crate) fn pretend(&self, snapshot: Snapshot) {
        self.lock().running = true;
        self.snapshot.send_replace(snapshot);
        self.changes.send_replace(());
    }

    /// Test hook: the networks this machine's driver would see as local.
    #[cfg(test)]
    pub(crate) fn local_networks(&self) -> Option<Vec<IpNet>> {
        self.lock().local_networks.borrow().clone()
    }

    /// Whether [`Self::retire`] stopped the network for good.
    pub fn is_retired(&self) -> bool {
        self.lock().retired
    }

    /// Whether a driver runs, and why the last one could not.
    pub fn state(&self) -> (bool, Option<Failure>) {
        let core = self.lock();
        (core.running, core.failure)
    }

    /// The networks of this machine's interfaces, read by the engine.
    /// The driver is told only when they changed.
    pub fn set_local_networks(&self, networks: Option<Vec<IpNet>>) {
        self.lock().local_networks.send_if_modified(|current| {
            let changed = *current != networks;
            if changed {
                *current = networks;
            }
            changed
        });
    }

    /// Subnets the user routes through the mesh although they overlap a
    /// network of this machine (spec §15.4).
    pub fn set_route_overrides(&self, overrides: Vec<IpNet>) {
        self.lock().route_overrides.send_replace(overrides);
    }

    /// The `dns` settings in force, `mesh_set_dns` applied: a running
    /// driver takes them without a restart, a later one starts with them.
    pub fn set_dns(&self, dns: DnsSettings) {
        self.lock().dns.send_if_modified(|current| {
            let changed = *current != dns;
            if changed {
                *current = dns;
            }
            changed
        });
    }

    /// The `dns` settings in force.
    #[cfg(test)]
    pub(crate) fn dns(&self) -> DnsSettings {
        self.lock().dns.borrow().clone()
    }

    /// Starts the network if it does not run; needs a Tokio runtime unless
    /// the instance has its own.
    pub fn start(self: &Arc<Self>) {
        let _ = self.ensure_running();
    }

    /// Starts a driver unless one runs. Fails at once for a network that
    /// waits for its key list.
    pub(crate) fn ensure_running(self: &Arc<Self>) -> io::Result<()> {
        let waits = self
            .settings
            .waits_for_native_keys(&self.static_key.public());
        let run = {
            // One lock for the checks and the start, so that a retire()
            // in between cannot be undone.
            let mut core = self.lock();
            if core.retired {
                return Err(Failure::Replaced.error());
            }
            if waits {
                core.failure = Some(Failure::NativeKeysPending);
                return Err(Failure::NativeKeysPending.error());
            }
            if core.running {
                return Ok(());
            }
            core.running = true;
            core.run += 1;
            core.failure = None;
            core.run
        };
        self.changes.send_replace(());
        // The guard is made here and moved into the task, so that it also
        // records the run as stopped when the runtime drops the task before
        // it was ever polled.
        let guard = RunGuard {
            instance: Arc::downgrade(self),
            run,
        };
        let task = start_driver(self.clone(), run, guard);
        match &self.runtime {
            Some(runtime) => drop(runtime.spawn(task)),
            None => drop(tokio::spawn(task)),
        }
        Ok(())
    }

    /// The error a connection gets while no driver runs.
    fn not_running(&self) -> io::Error {
        self.lock().failure.unwrap_or(Failure::Stopped).error()
    }

    /// Whether connections may go to `address`: a virtual address of the
    /// network other than this node's own, or an address in a subnet the
    /// driver routes now. Anything else is refused before a packet is sent.
    pub fn reaches(&self, address: IpAddr) -> bool {
        if self.settings.local_addresses().contains(&address) {
            return false;
        }
        self.settings
            .virtual_subnets()
            .iter()
            .any(|subnet| subnet.contains(address))
            || self
                .snapshot
                .borrow()
                .system_routes
                .iter()
                .any(|subnet| subnet.contains(address))
    }

    /// Runs `f` on a socket of the stack.
    pub(crate) fn with_socket<T, R>(&self, handle: SocketHandle, f: impl FnOnce(&mut T) -> R) -> R
    where
        T: AnySocket<'static>,
    {
        let mut core = self.lock();
        f(core.stack.sockets.get_mut::<T>(handle))
    }

    /// Stops the network for good, after the engine built it again with
    /// other settings: the driver stops at once (it would keep the old
    /// `native_keys` and dial with the same identity as the new one) and
    /// every connection ends, however long it would have lived.
    pub fn retire(&self) {
        let mut core = self.lock();
        core.retired = true;
        core.running = false;
        core.failure = Some(Failure::Replaced);
        // A new run number ends the pump and makes the old driver's report
        // a no-op.
        core.run += 1;
        core.shutdown = None;
        core.to_driver = None;
        core.stack.abort_all();
        drop(core);
        self.changes.send_replace(());
    }

    /// Starts a TCP connection to `remote`.
    pub(crate) fn open_tcp(&self, remote: SocketAddr) -> io::Result<SocketHandle> {
        let mut guard = self.lock();
        if !guard.running {
            drop(guard);
            return Err(self.not_running());
        }
        let core = &mut *guard;
        check_capacity(&core.stack.sockets)?;
        let port = allocate_port(&mut core.next_port, &core.stack.sockets)?;
        let mut socket = new_tcp_socket();
        socket
            .connect(core.stack.iface.context(), endpoint(remote), port)
            .map_err(|_| unreachable_address())?;
        Ok(core.stack.sockets.add(socket))
    }

    /// Listens for one TCP connection on `port`; for tests that pass
    /// traffic between two nodes.
    pub(crate) fn listen_tcp(&self, port: u16) -> io::Result<SocketHandle> {
        let mut core = self.lock();
        check_capacity(&core.stack.sockets)?;
        let mut socket = new_tcp_socket();
        socket
            .listen(port)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "mesh cannot listen there"))?;
        Ok(core.stack.sockets.add(socket))
    }

    /// Binds a UDP socket on `port` or an ephemeral one.
    pub(crate) fn open_udp(&self, port: Option<u16>) -> io::Result<SocketHandle> {
        let mut guard = self.lock();
        let core = &mut *guard;
        check_capacity(&core.stack.sockets)?;
        let port = match port {
            Some(port) if udp_port_bound(&core.stack.sockets, port) => {
                return Err(udp_port_unavailable())
            }
            Some(port) => port,
            None => allocate_port(&mut core.next_port, &core.stack.sockets)?,
        };
        let buffer = || {
            udp::PacketBuffer::new(
                vec![udp::PacketMetadata::EMPTY; UDP_PACKETS],
                vec![0u8; UDP_BUFFER],
            )
        };
        let mut socket = udp::Socket::new(buffer(), buffer());
        socket.bind(port).map_err(|_| udp_port_unavailable())?;
        Ok(core.stack.sockets.add(socket))
    }

    /// Closes a TCP socket gracefully; it is removed once the close finishes.
    pub(crate) fn release_tcp(&self, handle: SocketHandle) {
        {
            let mut core = self.lock();
            core.stack.sockets.get_mut::<tcp::Socket>(handle).close();
            core.stack.closing.push((handle, Instant::now()));
        }
        self.wake();
    }

    pub(crate) fn release_udp(&self, handle: SocketHandle) {
        self.lock().stack.sockets.remove(handle);
    }

    /// Polls the stack and hands its packets to the driver. Returns how
    /// long the pump may sleep, or `None` when the driver `run` is over.
    fn poll(&self, run: u64) -> Option<Duration> {
        let now = Instant::now();
        let timestamp = self.now();
        let mut guard = self.lock();
        let core = &mut *guard;
        if core.run != run || !core.running {
            return None;
        }
        let stack = &mut core.stack;
        stack
            .iface
            .poll(timestamp, &mut stack.device, &mut stack.sockets);
        stack.sweep(now);
        if let Some(to_driver) = &core.to_driver {
            while let Some(packet) = stack.device.tx.pop_front() {
                // A full queue drops the packet as a congested link would;
                // TCP retransmits.
                let _ = to_driver.try_send(packet);
            }
        } else {
            stack.device.tx.clear();
        }
        let delay = stack
            .iface
            .poll_delay(timestamp, &stack.sockets)
            .map(|next| Duration::from_micros(next.total_micros()))
            .unwrap_or(MAX_SLEEP)
            .min(MAX_SLEEP);
        Some(delay)
    }

    /// Queues packets the driver delivered for this node.
    fn deliver(&self, packets: impl IntoIterator<Item = Vec<u8>>) {
        let mut core = self.lock();
        for packet in packets {
            if core.stack.device.rx.len() < STACK_QUEUE {
                core.stack.device.rx.push_back(packet);
            }
        }
    }

    /// Ends the driver `run`, failing every connection.
    fn stopped(&self, run: u64, failure: Failure) {
        let mut core = self.lock();
        // Only the first report of a run counts.
        if core.run != run || !core.running {
            return;
        }
        core.running = false;
        core.failure = Some(failure);
        core.shutdown = None;
        core.to_driver = None;
        core.stack.abort_all();
        drop(core);
        self.changes.send_replace(());
    }
}

/// Binds the listeners, then runs the driver and the pump for `run`.
///
/// `_guard` records the run as stopped if the task ends without doing so,
/// such as when its runtime shuts down; otherwise `running` would stay set
/// and every later connection would wait for a driver that is gone.
async fn start_driver(instance: Arc<Instance>, run: u64, _guard: RunGuard) {
    let mut settings = instance.settings.clone();
    let listeners = match Listeners::bind(&settings).await {
        Ok(listeners) => listeners,
        Err(_) => {
            instance.stopped(run, Failure::PortInUse);
            return;
        }
    };
    let (to_driver, from_interface) = mpsc::channel(CHANNEL_PACKETS);
    let (to_interface, from_driver) = mpsc::channel(CHANNEL_PACKETS);
    let (shutdown_tx, shutdown) = watch::channel(false);
    // The engine does not read other programs' routes: its stack is not the
    // system's, so they never compete with the mesh routes.
    let (foreign_routes_tx, foreign_routes) = watch::channel(Vec::new());
    // The engine restarts the instance for a new configuration, so the
    // host groups the settings carry never change while it runs; the
    // sender only keeps the receiver open. The `dns` settings change with
    // `mesh_set_dns` ([`Instance::set_dns`]).
    let (host_groups_tx, host_groups) = watch::channel(settings.host_groups.clone());
    // Custom paths likewise come with the settings.
    let (paths_tx, paths) = watch::channel(Vec::new());
    let channels = {
        let mut core = instance.lock();
        if core.run != run || !core.running {
            return;
        }
        core.shutdown = Some(shutdown_tx);
        core.to_driver = Some(to_driver);
        // The driver starts with the settings in force and ignores the
        // value it subscribed with: read under the lock `set_dns` takes,
        // so that no change falls in between.
        let dns = core.dns.subscribe();
        settings.dns = dns.borrow().clone();
        Channels {
            from_interface,
            to_interface,
            snapshots: instance.snapshot.clone(),
            local_networks: core.local_networks.subscribe(),
            native_keys: core.native_keys.subscribe(),
            dns,
            paths,
            host_groups,
            route_overrides: core.route_overrides.subscribe(),
            foreign_routes,
            shutdown,
            border: None,
        }
    };
    let key = KeyPair::from_private(*instance.static_key.private());
    let weak = Arc::downgrade(&instance);
    let wake = instance.wake.clone();
    drop(instance);
    tokio::spawn(pump(weak.clone(), wake, run, from_driver));
    let result = driver::run(settings, key, listeners, channels).await;
    drop((foreign_routes_tx, host_groups_tx, paths_tx));
    // The driver only ends on its own after an error: a shutdown comes from
    // dropping the instance, and then nobody is left to tell.
    let _ = result;
    if let Some(instance) = weak.upgrade() {
        instance.stopped(run, Failure::Stopped);
    }
}

struct RunGuard {
    instance: Weak<Instance>,
    run: u64,
}

impl Drop for RunGuard {
    fn drop(&mut self) {
        if let Some(instance) = self.instance.upgrade() {
            instance.stopped(self.run, Failure::Stopped);
        }
    }
}

/// Moves packets between the stack and the driver until the run ends or
/// the instance is dropped.
async fn pump(
    instance: Weak<Instance>,
    wake: Arc<Notify>,
    run: u64,
    mut from_driver: mpsc::Receiver<Vec<u8>>,
) {
    loop {
        let delay = {
            let Some(instance) = instance.upgrade() else {
                return;
            };
            match instance.poll(run) {
                Some(delay) => delay,
                None => return,
            }
        };
        tokio::select! {
            packet = from_driver.recv() => {
                let Some(packet) = packet else {
                    // The driver ended; `start_driver` records why.
                    return;
                };
                let mut packets = vec![packet];
                while packets.len() < STACK_QUEUE {
                    match from_driver.try_recv() {
                        Ok(packet) => packets.push(packet),
                        Err(_) => break,
                    }
                }
                let Some(instance) = instance.upgrade() else {
                    return;
                };
                instance.deliver(packets);
            }
            _ = wake.notified() => {}
            _ = tokio::time::sleep(delay) => {}
        }
    }
}

fn endpoint(address: SocketAddr) -> IpEndpoint {
    let ip = match address.ip() {
        IpAddr::V4(v4) => IpAddress::Ipv4(v4),
        IpAddr::V6(v6) => IpAddress::Ipv6(v6),
    };
    IpEndpoint::new(ip, address.port())
}

fn new_tcp_socket() -> tcp::Socket<'static> {
    let mut socket = tcp::Socket::new(
        tcp::SocketBuffer::new(vec![0u8; TCP_RECEIVE_BUFFER]),
        tcp::SocketBuffer::new(vec![0u8; TCP_SEND_BUFFER]),
    );
    socket.set_nagle_enabled(false);
    socket.set_keep_alive(Some(SmolDuration::from_secs(30)));
    socket.set_timeout(Some(SmolDuration::from_secs(120)));
    socket
}

/// Refuses a new socket when the stack holds [`MAX_SOCKETS`] already.
fn check_capacity(sockets: &SocketSet<'static>) -> io::Result<()> {
    if sockets.iter().count() >= MAX_SOCKETS {
        return Err(io::Error::new(
            io::ErrorKind::OutOfMemory,
            "mesh network has too many open connections",
        ));
    }
    Ok(())
}

/// The port after `port` in the local range, wrapping from 65535 to
/// [`FIRST_LOCAL_PORT`].
fn following_port(port: u16) -> u16 {
    if port == u16::MAX {
        FIRST_LOCAL_PORT
    } else {
        port + 1
    }
}

fn udp_port_bound(sockets: &SocketSet<'static>, port: u16) -> bool {
    sockets.iter().any(|(_, socket)| {
        udp::Socket::downcast(socket).is_some_and(|socket| socket.endpoint().port == port)
    })
}

/// The local ports the sockets hold: bound UDP sockets, and TCP sockets
/// connected or listening.
fn ports_in_use(sockets: &SocketSet<'static>) -> HashSet<u16> {
    let mut used = HashSet::new();
    for (_, socket) in sockets.iter() {
        if let Some(socket) = udp::Socket::downcast(socket) {
            let port = socket.endpoint().port;
            if port != 0 {
                used.insert(port);
            }
        } else if let Some(socket) = tcp::Socket::downcast(socket) {
            if let Some(local) = socket.local_endpoint() {
                used.insert(local.port);
            }
            let listening = socket.listen_endpoint().port;
            if listening != 0 {
                used.insert(listening);
            }
        }
    }
    used
}

/// The first free local port from `*next` on, wrapping once through the
/// range; `*next` moves past it.
fn allocate_port(next: &mut u16, sockets: &SocketSet<'static>) -> io::Result<u16> {
    let used = ports_in_use(sockets);
    let span = u32::from(u16::MAX - FIRST_LOCAL_PORT) + 1;
    let mut port = (*next).max(FIRST_LOCAL_PORT);
    for _ in 0..span {
        if !used.contains(&port) {
            *next = following_port(port);
            return Ok(port);
        }
        port = following_port(port);
    }
    Err(io::Error::new(
        io::ErrorKind::AddrInUse,
        "mesh has no free local port",
    ))
}

pub(crate) fn closed() -> io::Error {
    io::Error::new(io::ErrorKind::ConnectionReset, "mesh connection was closed")
}

pub(crate) fn unreachable_address() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        "mesh cannot reach this address",
    )
}

fn udp_port_unavailable() -> io::Error {
    io::Error::new(io::ErrorKind::AddrInUse, "mesh udp port is unavailable")
}

/// Process-local randomness for ports and the stack seed; none of it needs
/// to be unpredictable.
fn random() -> u64 {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let mut hasher = std::collections::hash_map::RandomState::new().build_hasher();
    hasher.write_u64(COUNTER.fetch_add(1, Ordering::Relaxed));
    hasher.finish()
}

/// A UDP socket of the private stack; removed when dropped.
pub(crate) struct UdpHandle {
    instance: Arc<Instance>,
    handle: SocketHandle,
}

impl UdpHandle {
    pub(crate) fn open(instance: &Arc<Instance>, port: Option<u16>) -> io::Result<Self> {
        let handle = instance.open_udp(port)?;
        Ok(Self {
            instance: instance.clone(),
            handle,
        })
    }

    pub(crate) async fn send_to(&self, payload: &[u8], target: SocketAddr) -> io::Result<()> {
        if payload.len() > UDP_BUFFER {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "datagram is too large",
            ));
        }
        let target = endpoint(target);
        std::future::poll_fn(|cx| {
            self.instance
                .with_socket::<udp::Socket, _>(self.handle, |socket| {
                    if !socket.is_open() {
                        return TaskPoll::Ready(Err(closed()));
                    }
                    match socket.send_slice(payload, target) {
                        Ok(()) => TaskPoll::Ready(Ok(())),
                        Err(udp::SendError::BufferFull) => {
                            socket.register_send_waker(cx.waker());
                            TaskPoll::Pending
                        }
                        Err(_) => TaskPoll::Ready(Err(unreachable_address())),
                    }
                })
        })
        .await?;
        self.instance.wake();
        Ok(())
    }

    /// The next datagram; with `from`, only one whose source is `from`
    /// (others are dropped), so that a member cannot answer for another.
    pub(crate) async fn recv(&self, from: Option<SocketAddr>) -> io::Result<Vec<u8>> {
        let from = from.map(endpoint);
        std::future::poll_fn(|cx| {
            self.instance
                .with_socket::<udp::Socket, _>(self.handle, |socket| {
                    if !socket.is_open() {
                        return TaskPoll::Ready(Err(closed()));
                    }
                    loop {
                        match socket.recv() {
                            Ok((payload, meta)) => {
                                if from.is_none_or(|from| meta.endpoint == from) {
                                    return TaskPoll::Ready(Ok(payload.to_vec()));
                                }
                            }
                            Err(_) => {
                                socket.register_recv_waker(cx.waker());
                                return TaskPoll::Pending;
                            }
                        }
                    }
                })
        })
        .await
    }
}

impl Drop for UdpHandle {
    fn drop(&mut self) {
        self.instance.release_udp(self.handle);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bound_udp(port: u16) -> udp::Socket<'static> {
        let buffer = || udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 1], vec![0u8; 64]);
        let mut socket = udp::Socket::new(buffer(), buffer());
        socket.bind(port).unwrap();
        socket
    }

    #[test]
    fn a_full_stack_refuses_new_sockets() {
        let mut sockets: SocketSet<'static> = SocketSet::new(Vec::new());
        for port in 0..MAX_SOCKETS {
            assert!(check_capacity(&sockets).is_ok());
            sockets.add(bound_udp(FIRST_LOCAL_PORT + port as u16));
        }
        let error = check_capacity(&sockets).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::OutOfMemory);
    }

    #[test]
    fn local_ports_skip_sockets_still_open_and_wrap() {
        let mut sockets: SocketSet<'static> = SocketSet::new(Vec::new());
        sockets.add(bound_udp(50000));
        let mut next = 50000;
        assert_eq!(allocate_port(&mut next, &sockets).unwrap(), 50001);
        assert_eq!(next, 50002);
        sockets.add(bound_udp(FIRST_LOCAL_PORT));
        let mut next = u16::MAX;
        assert_eq!(allocate_port(&mut next, &sockets).unwrap(), u16::MAX);
        assert_eq!(
            allocate_port(&mut next, &sockets).unwrap(),
            FIRST_LOCAL_PORT + 1
        );
        assert!(udp_port_bound(&sockets, 50000));
        assert!(!udp_port_bound(&sockets, 50001));
    }
}
