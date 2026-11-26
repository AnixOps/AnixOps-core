//! `run`: the node itself. Reads the mesh configuration the importer or the
//! panel wrote, binds the listeners, creates the virtual interface and runs
//! the mesh module's socket driver until SIGTERM or SIGINT.
//!
//! Exit codes: 0 stopped by a signal, 2 configuration, 3 a port or the
//! interface is taken (another program still runs), 1 anything else.

use std::collections::{BTreeMap, HashSet};
use std::io;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use outbound_mesh::config::{encode_key, CustomPath, HostGroup, NetworkKind};
use outbound_mesh::driver::{self, Channels, Listeners, Snapshot};
use outbound_mesh::secure::noise::{KeyPair, LEN};
use outbound_mesh::{IpNet, MeshConfig, MeshSettings};
use ring::rand::SystemRandom;
#[cfg(unix)]
use tokio::signal::unix::{signal, SignalKind};
use tokio::sync::{mpsc, watch};
use zeroize::Zeroizing;

use crate::host_routes;
use crate::tun::{self, Tun};

/// Interface name when the configuration names none.
pub const DEFAULT_INTERFACE: &str = "anixmesh0";

/// Packets queued between the interface and the driver in each direction.
const QUEUE: usize = 256;

/// How often the networks of the other interfaces are read again.
const LOCAL_NETWORKS_EVERY: Duration = Duration::from_secs(30);

/// How soon the interfaces are read again while they could not be read
/// yet: no subnet is installed until then.
const LOCAL_NETWORKS_RETRY: Duration = Duration::from_secs(5);

/// How long one read of the interfaces, or of the routes, may take.
const SCAN_TIMEOUT: Duration = Duration::from_secs(10);

/// The networks of the other interfaces (spec §15.4). Our own mesh
/// interfaces, and `device`, are left out.
fn read_local_networks(device: &str) -> io::Result<Vec<IpNet>> {
    let own = |name: &str| host_routes::is_own_interface(name, &[device]);
    Ok(tun::local_networks(own)?
        .into_iter()
        .filter_map(|(address, prefix)| IpNet::new(address, prefix))
        .collect())
}

/// Clears a read's busy flag when the read ends, however it ends.
struct Reading(Arc<AtomicBool>);

impl Drop for Reading {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

/// Runs `read` off the packet loop, unless the previous read behind `busy`
/// still runs (a blocking read goes on past its timeout). `None` when
/// skipped, failed or longer than [`SCAN_TIMEOUT`].
async fn read_off_loop<T: Send + 'static>(
    busy: &Arc<AtomicBool>,
    what: &str,
    read: impl FnOnce() -> io::Result<T> + Send + 'static,
) -> Option<T> {
    if busy.swap(true, Ordering::AcqRel) {
        warn(what, "the previous read is still running");
        return None;
    }
    let reading = Reading(busy.clone());
    let task = tokio::task::spawn_blocking(move || {
        let _reading = reading;
        read()
    });
    match tokio::time::timeout(SCAN_TIMEOUT, task).await {
        Ok(Ok(Ok(found))) => Some(found),
        Ok(Ok(Err(error))) => {
            warn(what, &error.to_string());
            None
        }
        Ok(Err(error)) => {
            warn(what, &error.to_string());
            None
        }
        Err(_) => {
            warn(what, "the read timed out");
            None
        }
    }
}

/// What the host reaches without the mesh: the networks of the other
/// interfaces, and the routes of other mesh programs as the system selects
/// them. The two are read apart, so that the interfaces count even when
/// the routing tables cannot be read; a part that fails keeps its previous
/// result.
struct Scanner {
    device: String,
    interfaces: Arc<AtomicBool>,
    routes: Arc<AtomicBool>,
}

impl Scanner {
    fn new(device: &str) -> Self {
        Self {
            device: device.to_owned(),
            interfaces: Arc::default(),
            routes: Arc::default(),
        }
    }

    async fn interfaces(&self) -> Option<Vec<IpNet>> {
        let device = self.device.clone();
        read_off_loop(&self.interfaces, "interfaces", move || {
            read_local_networks(&device)
        })
        .await
    }

    async fn routes(&self) -> Option<Vec<IpNet>> {
        let device = self.device.clone();
        let found = read_off_loop(&self.routes, "routes", move || {
            host_routes::foreign_routes(&device)
        })
        .await?;
        if found.unchecked > 0 {
            warn(
                "routes",
                &format!(
                    "{} routes of other programs were not checked",
                    found.unchecked
                ),
            );
        }
        Some(found.routes)
    }

    async fn both(&self) -> (Option<Vec<IpNet>>, Option<Vec<IpNet>>) {
        tokio::join!(self.interfaces(), self.routes())
    }
}

/// Stores `fresh` when it differs, so that the driver wakes on changes only.
fn store<T: PartialEq>(sender: &watch::Sender<T>, fresh: T) {
    sender.send_if_modified(|current| {
        let changed = *current != fresh;
        if changed {
            *current = fresh;
        }
        changed
    });
}

/// `networks` with the routes the other networks of this process hold.
fn with_others(mut networks: Vec<IpNet>, others: Option<&(HostRoutes, String)>) -> Vec<IpNet> {
    if let Some((routes, owner)) = others {
        networks.extend(routes.others(owner));
    }
    networks
}

/// Aborts the task when dropped.
struct StopTask(tokio::task::JoinHandle<()>);

impl Drop for StopTask {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// Routes to add and to remove to go from `installed` to `wanted`, in
/// their given order; set lookups keep it linear.
fn route_changes(installed: &[IpNet], wanted: &[IpNet]) -> (Vec<IpNet>, Vec<IpNet>) {
    let installed_set: HashSet<&IpNet> = installed.iter().collect();
    let wanted_set: HashSet<&IpNet> = wanted.iter().collect();
    let add = wanted
        .iter()
        .filter(|net| !installed_set.contains(net))
        .copied()
        .collect();
    let remove = installed
        .iter()
        .filter(|net| !wanted_set.contains(net))
        .copied()
        .collect();
    (add, remove)
}

/// What one network of this process holds on the host.
#[derive(Debug, Default)]
struct Holder {
    /// A `managed` network: its claims take precedence over `legacy`
    /// networks' (spec §15.4).
    managed: bool,
    /// Its virtual address ranges, on its interface.
    interface: Vec<IpNet>,
    /// The subnets it installed as system routes, sorted.
    routes: Vec<IpNet>,
}

/// Sorted and without repeats, so that claims compare as sets.
fn sorted(mut nets: Vec<IpNet>) -> Vec<IpNet> {
    nets.sort_by_key(|net| (net.network(), net.prefix()));
    nets.dedup();
    nets
}

/// The system routes the networks of one process installed, and their
/// virtual address ranges, by network: shared so that no two networks
/// install overlapping subnets. Each network treats what the others hold
/// as one of this machine's networks (spec §15.4), which refuses it as an
/// overlap. A subnet goes to the first network to claim it, except that a
/// `managed` network takes it from a `legacy` one; a virtual address range
/// is never taken.
#[derive(Clone)]
pub(crate) struct HostRoutes {
    inner: Arc<HostRoutesInner>,
}

struct HostRoutesInner {
    holders: Mutex<BTreeMap<String, Holder>>,
    /// Counts changes, so that the other networks look again.
    changed: watch::Sender<u64>,
}

impl Default for HostRoutes {
    fn default() -> Self {
        Self {
            inner: Arc::new(HostRoutesInner {
                holders: Mutex::new(BTreeMap::new()),
                changed: watch::channel(0).0,
            }),
        }
    }
}

impl HostRoutes {
    fn holders(&self) -> std::sync::MutexGuard<'_, BTreeMap<String, Holder>> {
        self.inner
            .holders
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn notify(&self) {
        self.inner.changed.send_modify(|count| *count += 1);
    }

    /// Records `owner`, of the given kind and with its virtual address
    /// ranges, before it claims anything: the other networks see the
    /// ranges at once.
    pub(crate) fn join(&self, owner: &str, managed: bool, interface: &[IpNet]) {
        let mut holders = self.holders();
        let holder = holders.entry(owner.to_owned()).or_default();
        holder.managed = managed;
        holder.interface = sorted(interface.iter().map(IpNet::trunc).collect());
        drop(holders);
        self.notify();
    }

    /// Claims for `owner` the subnets of `wanted` that overlap neither
    /// another network's virtual range nor a subnet another network holds
    /// with the same or a higher precedence; a `managed` owner takes
    /// overlapping subnets from `legacy` networks. Gives up the rest of
    /// what it held and returns what it now holds, sorted. Others are told
    /// only when something changed.
    pub(crate) fn claim(&self, owner: &str, wanted: &[IpNet]) -> Vec<IpNet> {
        let mut holders = self.holders();
        let managed = holders.get(owner).is_some_and(|holder| holder.managed);
        let held = sorted(
            wanted
                .iter()
                .filter(|net| {
                    !holders
                        .iter()
                        .filter(|(other, _)| other.as_str() != owner)
                        .any(|(_, holder)| {
                            holder.interface.iter().any(|range| range.overlaps(net))
                                || ((holder.managed || !managed)
                                    && holder.routes.iter().any(|route| route.overlaps(net)))
                        })
                })
                .copied()
                .collect(),
        );
        let mut changed = false;
        if managed {
            for (other, holder) in holders.iter_mut() {
                if other.as_str() == owner || holder.managed {
                    continue;
                }
                let before = holder.routes.len();
                holder
                    .routes
                    .retain(|route| !held.iter().any(|net| net.overlaps(route)));
                changed |= holder.routes.len() != before;
            }
        }
        let holder = holders.entry(owner.to_owned()).or_default();
        if holder.routes != held {
            holder.routes = held.clone();
            changed = true;
        }
        drop(holders);
        if changed {
            self.notify();
        }
        held
    }

    /// Keeps of `owner`'s claim only what it installed.
    pub(crate) fn narrow(&self, owner: &str, installed: &[IpNet]) {
        let mut holders = self.holders();
        let Some(holder) = holders.get_mut(owner) else {
            return;
        };
        let before = holder.routes.len();
        holder.routes.retain(|route| installed.contains(route));
        let changed = holder.routes.len() != before;
        drop(holders);
        if changed {
            self.notify();
        }
    }

    /// What the networks other than `owner` hold: virtual ranges and
    /// subnets, sorted.
    pub(crate) fn others(&self, owner: &str) -> Vec<IpNet> {
        sorted(
            self.holders()
                .iter()
                .filter(|(other, _)| other.as_str() != owner)
                .flat_map(|(_, holder)| holder.interface.iter().chain(&holder.routes).copied())
                .collect(),
        )
    }

    /// What `owner` sees of the shared state: the others' holdings and its
    /// own claim. A change notice that leaves it the same, such as one
    /// `owner` caused itself, needs no new look.
    pub(crate) fn view(&self, owner: &str) -> (Vec<IpNet>, Vec<IpNet>) {
        let own = self
            .holders()
            .get(owner)
            .map(|holder| holder.routes.clone())
            .unwrap_or_default();
        (self.others(owner), own)
    }

    /// `owner` stopped: what it held is free.
    pub(crate) fn release(&self, owner: &str) {
        if self.holders().remove(owner).is_some() {
            self.notify();
        }
    }

    fn subscribe(&self) -> watch::Receiver<u64> {
        self.inner.changed.subscribe()
    }
}

/// Releases a network's routes in [`HostRoutes`] however its serving ends,
/// including when the task is cut off.
struct Claim {
    routes: HostRoutes,
    owner: String,
}

impl Drop for Claim {
    fn drop(&mut self) {
        self.routes.release(&self.owner);
    }
}

/// Aborts a task when dropped: the driver of a network that is cut off
/// stops with it and frees its sockets.
pub(crate) struct AbortOnDrop(pub(crate) tokio::task::AbortHandle);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// Why `run` stopped.
#[derive(Debug)]
pub enum Failure {
    /// Exit code 2.
    Config(String),
    /// Exit code 3: a startup conflict (requirement R12). `conflict` is one
    /// of the codes in `docs/architecture/mesh-module.md` (exit codes).
    Busy {
        conflict: &'static str,
        detail: String,
    },
    /// Exit code 1.
    Other(String),
}

impl Failure {
    pub fn exit_code(&self) -> u8 {
        match self {
            Self::Config(_) => 2,
            Self::Busy { .. } => 3,
            Self::Other(_) => 1,
        }
    }

    pub fn kind(&self) -> &'static str {
        match self {
            Self::Config(_) => "config",
            Self::Busy { .. } => "conflict",
            Self::Other(_) => "runtime",
        }
    }

    pub fn detail(&self) -> &str {
        match self {
            Self::Config(detail) | Self::Busy { detail, .. } | Self::Other(detail) => detail,
        }
    }

    /// The conflict code of a startup conflict, `None` otherwise.
    pub fn conflict(&self) -> Option<&'static str> {
        match self {
            Self::Busy { conflict, .. } => Some(conflict),
            Self::Config(_) | Self::Other(_) => None,
        }
    }

    /// The last line written to stderr when `run` fails (exit code
    /// contract in `docs/architecture/mesh-module.md`).
    pub fn json(&self) -> serde_json::Value {
        let mut line = serde_json::json!({ "error": self.kind(), "detail": self.detail() });
        if let Some(conflict) = self.conflict() {
            line["conflict"] = serde_json::Value::from(conflict);
        }
        line
    }
}

/// Parses and validates a configuration file's text.
pub fn settings_from_json(text: &str) -> Result<MeshSettings, Failure> {
    let config: MeshConfig =
        serde_json::from_str(text).map_err(|error| Failure::Config(error.to_string()))?;
    config
        .validate()
        .map_err(|error| Failure::Config(error.into()))
}

fn busy(conflict: &'static str, what: &str, error: &io::Error) -> Failure {
    let conflict = || Failure::Busy {
        conflict,
        detail: format!("{what}: {error}"),
    };
    match error.kind() {
        io::ErrorKind::AddrInUse | io::ErrorKind::ResourceBusy => conflict(),
        // The kernel answers EBUSY for an interface another program holds.
        #[cfg(unix)]
        _ if error.raw_os_error() == Some(libc::EBUSY) => conflict(),
        _ => Failure::Other(format!("{what}: {error}")),
    }
}

fn warn(kind: &str, detail: &str) {
    eprintln!(
        "{}",
        serde_json::json!({ "warning": kind, "detail": detail })
    );
}

/// One status line for the service log; only printed when it changes.
fn status_line(snapshot: &Snapshot, interface: &str) -> String {
    serde_json::json!({
        "interface": interface,
        "peer_id": snapshot.peer_id,
        "neighbours": snapshot.neighbours,
        "reachable": snapshot.routes.len(),
        "duplicate_id": snapshot.duplicate_id,
        "static_key": snapshot.static_key.as_ref().map(encode_key),
        "not_native": snapshot.not_native,
        "system_routes": snapshot
            .system_routes
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>(),
        "local_networks_read": snapshot.local_networks_read,
        "foreign_overlaps": snapshot
            .foreign_overlaps
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>(),
        // Measures a network before a bridge is built to it (spec §11.2).
        "sync_oversize": {
            "received": snapshot
                .sync_oversize
                .received
                .map(|(peer, bytes)| serde_json::json!({ "peer": peer, "bytes": bytes })),
            "undelivered": snapshot.sync_oversize.undelivered,
            "oversize_calls": snapshot.counters.oversize_calls,
            "graph_timeouts": snapshot.counters.graph_timeouts,
            "sync_errors": snapshot.counters.sync_errors,
            "cut_graphs": snapshot.counters.cut_graphs,
            "refused_at_capacity": snapshot.counters.refused_at_capacity,
            "refused_over_budget": snapshot.counters.refused_over_budget,
        },
    })
    .to_string()
}

/// Where the network's static key is kept: next to its configuration.
pub fn key_path(config: &Path) -> std::path::PathBuf {
    let mut name = config.file_name().unwrap_or_default().to_os_string();
    name.push(".key");
    config.with_file_name(name)
}

/// The network's static key, kept across restarts until the network is
/// removed (spec §8.2); node and route IDs are new at every start. A
/// missing file gets a new key, written readable by the owner only.
pub fn static_key(path: &Path) -> Result<KeyPair, Failure> {
    use std::io::Write;
    #[cfg(unix)]
    use std::os::unix::fs::OpenOptionsExt;

    match std::fs::read(path).map(Zeroizing::new) {
        Ok(bytes) => {
            let private: Zeroizing<[u8; LEN]> =
                Zeroizing::new(bytes.as_slice().try_into().map_err(|_| {
                    Failure::Config(format!("{}: not a {LEN}-byte key", path.display()))
                })?);
            return Ok(KeyPair::from_private(*private));
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(Failure::Other(format!("{}: {error}", path.display()))),
    }
    let key = KeyPair::generate(&SystemRandom::new())
        .map_err(|_| Failure::Other("no system randomness".into()))?;
    // Written whole to a temporary file and linked into place, so that a
    // crash or a full disk never leaves a short key behind, and a key
    // another process wrote first is kept.
    let mut name = path.file_name().unwrap_or_default().to_os_string();
    name.push(format!(".{}.tmp", std::process::id()));
    let temporary = path.with_file_name(name);
    let _ = std::fs::remove_file(&temporary);
    let failed = |error: io::Error| Failure::Other(format!("{}: {error}", path.display()));
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    // Readable by the owner only. On Windows the file takes the access
    // list of its directory, which the installer limits to SYSTEM and
    // Administrators.
    #[cfg(unix)]
    options.mode(0o600);
    let written = options
        .open(&temporary)
        .and_then(|mut file| {
            file.write_all(&key.private()[..])?;
            file.sync_all()
        })
        .and_then(|()| std::fs::hard_link(&temporary, path));
    let _ = std::fs::remove_file(&temporary);
    match written {
        Ok(()) => {
            if let Some(dir) = path.parent() {
                let _ = std::fs::File::open(dir).and_then(|dir| dir.sync_all());
            }
            Ok(key)
        }
        // Another process made the key meanwhile: use that one.
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => static_key(path),
        Err(error) => Err(failed(error)),
    }
}

/// Runs the node from the configuration at `path`.
pub fn run(path: &Path, interface: Option<&str>) -> Result<(), Failure> {
    let text = std::fs::read_to_string(path)
        .map_err(|error| Failure::Config(format!("{}: {error}", path.display())))?;
    let settings = settings_from_json(&text)?;
    let (address, address_v6) = tun::addresses(
        settings.address.address(),
        settings.address.prefix(),
        settings
            .address_v6
            .map(|address| (address.address(), address.prefix())),
    )
    .ok_or_else(|| Failure::Config("virtual address families are wrong".into()))?;
    let interface = interface.unwrap_or(DEFAULT_INTERFACE).to_owned();

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()
        .map_err(|error| Failure::Other(format!("runtime: {error}")))?;
    // The key the configuration carries (from the system key store), or
    // the one kept next to the configuration.
    let static_key = match &settings.private_key {
        Some(private) => KeyPair::from_private(**private),
        None => static_key(&key_path(path))?,
    };
    runtime.block_on(async move {
        if settings.waits_for_native_keys(&static_key.public()) {
            return wait_for_native_keys(&static_key).await;
        }
        let listeners = Listeners::bind(&settings)
            .await
            .map_err(|error| busy("port_in_use", "listen", &error))?;
        let device = Tun::create(&interface, address, address_v6, settings.mtu)
            .map_err(|error| busy("tun_in_use", &format!("interface {interface}"), &error))?;
        let stop = signals()?;
        let mut last = String::new();
        let mut listen_ports: Vec<u16> = listeners
            .local_addrs()
            .map_err(|error| Failure::Other(format!("listen: {error}")))?
            .iter()
            .map(|(_, address)| address.port())
            .collect();
        listen_ports.sort_unstable();
        listen_ports.dedup();
        let mut settings = settings;
        let host = start_host(&settings, device.name(), &listen_ports);
        if forwards(&settings) {
            withdraw_uncarried(&mut settings, &host.carried);
        }
        // Kept until the node stops, then undone before it reports so.
        let mut forwarding = host.forwarder;
        let virtual_subnets = settings.virtual_subnets();
        // Nothing updates the native key list of a standalone node: the
        // Agent writes a new configuration and starts it again.
        let (_keep, native_keys) = watch::channel(None);
        let (_keep_paths, paths) = watch::channel(Vec::new());
        let (_keep_groups, host_groups) = watch::channel(Vec::new());
        // Subnet route overrides belong to the managed networks
        // (`PUT /v1/mesh/subnet_route`); a standalone node has none.
        let (_keep_overrides, route_overrides) = watch::channel(Vec::new());
        let result = serve_with(
            settings,
            static_key,
            listeners,
            device,
            stop,
            Updates {
                native_keys,
                paths,
                host_groups,
                route_overrides,
            },
            None,
            None,
            |snapshot, name| {
                if let Some(forwarding) = forwarding.as_mut() {
                    let mut sources = virtual_subnets.clone();
                    sources.extend(snapshot.system_routes.iter().copied());
                    if let Err(error) = forwarding.set_sources(&sources) {
                        warn("forwarding", &error.to_string());
                    }
                }
                let line = status_line(snapshot, name);
                if line != last {
                    println!("{line}");
                    last = line;
                }
            },
        )
        .await;
        if let Some(forwarding) = forwarding.take() {
            for warning in forwarding.shutdown() {
                warn("host_changes", &warning);
            }
        }
        result
    })
}

/// The host side of carrying advertised subnets, held while the node runs.
trait HostForwarder {
    /// Replaces the mesh sources translated towards the advertised subnets.
    fn set_sources(&mut self, sources: &[IpNet]) -> io::Result<()>;

    /// Undoes the host changes now, before the node reports that it has
    /// stopped. Returns problems as warnings.
    fn shutdown(self: Box<Self>) -> Vec<String> {
        Vec::new()
    }
}

#[cfg(target_os = "macos")]
impl HostForwarder for crate::forward_macos::HostForwarding {
    fn set_sources(&mut self, sources: &[IpNet]) -> io::Result<()> {
        crate::forward_macos::HostForwarding::set_sources(self, sources)
    }
}

/// What the host side gave the node: the guard to hold, and the advertised
/// subnets the machine actually carries. The others are not advertised.
struct HostSide {
    forwarder: Option<Box<dyn HostForwarder>>,
    carried: Vec<IpNet>,
}

impl HostSide {
    fn none() -> Self {
        Self {
            forwarder: None,
            carried: Vec::new(),
        }
    }
}

/// Whether this node carries traffic to its advertised subnets: a full
/// node with subnets to advertise (requirement R10).
fn forwards(settings: &MeshSettings) -> bool {
    settings.role == outbound_mesh::Role::Full && !settings.carried_subnets().is_empty()
}

/// Keeps only the advertised subnets the machine carries. A subnet it does
/// not carry would draw traffic that is dropped, or forwarded by the host
/// outside our rules.
fn withdraw_uncarried(settings: &mut MeshSettings, carried: &[IpNet]) {
    let withdrawn: Vec<String> = settings
        .advertise_subnets
        .iter()
        .filter(|subnet| !carried.contains(subnet))
        .map(IpNet::to_string)
        .collect();
    if !withdrawn.is_empty() {
        warn(
            "advertise_withdrawn",
            &format!(
                "not advertised, this machine does not carry them: {}",
                withdrawn.join(", ")
            ),
        );
    }
    settings
        .advertise_subnets
        .retain(|subnet| carried.contains(subnet));
}

/// One line saying whether the host forwards for the advertised subnets
/// (`ipForwarding` in the status: `on`, `off` or `not_needed`).
fn forwarding_line(state: &str, detail: Option<&str>) {
    println!(
        "{}",
        serde_json::json!({ "ip_forwarding": state, "detail": detail })
    );
}

/// The advertised subnets of `lan`, once each.
#[cfg(any(target_os = "linux", target_os = "macos", windows))]
fn carried(lan: &[(String, IpNet)]) -> Vec<IpNet> {
    let mut subnets: Vec<IpNet> = lan.iter().map(|(_, subnet)| *subnet).collect();
    subnets.sort_by_key(IpNet::to_string);
    subnets.dedup();
    subnets
}

/// The machine's interfaces as the host side sees them.
#[cfg(any(target_os = "linux", target_os = "macos", windows))]
struct HostInterfaces {
    /// LAN interfaces as (name, address network) pairs.
    lan: Vec<(String, IpNet)>,
    /// Names of other programs' virtual interfaces. Only macOS reads it:
    /// forwarding there is system-wide. Windows forwards per interface and
    /// reports the interfaces that actually forward instead.
    #[cfg_attr(any(target_os = "linux", windows), allow(dead_code))]
    others: Vec<String>,
}

/// The machine's LAN interfaces and the names of other programs' virtual
/// interfaces. Neither list holds our own mesh interfaces; virtual
/// interfaces never count as LAN, so a subnet a VPN also covers is not
/// forwarded into that VPN.
#[cfg(any(target_os = "linux", target_os = "macos", windows))]
fn host_interfaces(interface: &str) -> io::Result<HostInterfaces> {
    let own = |name: &str| host_routes::is_own_interface(name, &[interface]);
    let mut others: Vec<String> = host_routes::host_links()?
        .into_values()
        .filter(|link| link.is_virtual && !own(&link.name))
        .map(|link| link.name)
        .collect();
    others.sort();
    others.dedup();
    let lan = tun::local_interfaces(|name| own(name) || others.iter().any(|other| other == name))?
        .into_iter()
        .filter_map(|(name, address, prefix)| Some((name, IpNet::new(address, prefix)?)))
        .collect();
    Ok(HostInterfaces { lan, others })
}

/// macOS: puts back what an earlier run left, then switches IPv4
/// forwarding on and translates mesh traffic to the advertised IPv4 subnets
/// (`forward_macos`). IPv6 subnets are not advertised: IPv6 forwarding
/// stays off. A failure is reported and the node runs on without
/// advertising subnets.
#[cfg(target_os = "macos")]
fn start_host(settings: &MeshSettings, interface: &str, _listen_ports: &[u16]) -> HostSide {
    use crate::forward_macos::{self as forward, HostForwarding, MacSystem};

    let dir = Path::new(forward::STATE_DIR);
    match forward::recover(&MacSystem, dir) {
        Ok(warnings) => {
            for warning in warnings {
                warn("forwarding", &warning);
            }
        }
        Err(error) => warn(
            "forwarding",
            &format!("what an earlier run left could not be checked: {error}"),
        ),
    }
    if !forwards(settings) {
        forwarding_line("not_needed", None);
        return HostSide::none();
    }
    let (v4, v6): (Vec<IpNet>, Vec<IpNet>) = settings
        .carried_subnets()
        .iter()
        .partition(|subnet| subnet.is_ipv4());
    if !v6.is_empty() {
        warn(
            "ipv6_forwarding_off",
            "IPv6 forwarding stays off, since it stops the system from accepting router advertisements",
        );
    }
    let HostInterfaces {
        lan: interfaces,
        others,
    } = match host_interfaces(interface) {
        Ok(found) => found,
        Err(error) => {
            forwarding_line("off", Some(&error.to_string()));
            return HostSide::none();
        }
    };
    let lan = host_routes::lan_interfaces(&interfaces, &v4, interface);
    for warning in host_routes::missing_interfaces(&lan, &v4) {
        warn("forwarding", &warning);
    }
    if lan.is_empty() {
        forwarding_line(
            "off",
            Some("no interface of this machine is on the advertised subnets"),
        );
        return HostSide::none();
    }
    if !others.is_empty() {
        warn(
            "forwarding",
            &format!(
                "forwarding is system-wide on macOS: traffic can also pass between the LAN and {}",
                others.join(", ")
            ),
        );
    }
    match HostForwarding::start(
        Box::new(MacSystem),
        dir,
        &settings.network_name,
        lan.clone(),
        &settings.virtual_subnets(),
    ) {
        Ok((forwarding, warnings)) => {
            for warning in warnings {
                warn("forwarding", &warning);
            }
            forwarding_line("on", None);
            HostSide {
                forwarder: Some(Box::new(forwarding)),
                carried: carried(&lan),
            }
        }
        Err(error) => {
            forwarding_line("off", Some(&error.to_string()));
            HostSide::none()
        }
    }
}

#[cfg(windows)]
impl HostForwarder for crate::forward_windows::HostChanges {
    /// WinNAT translates the IPv4 virtual subnet only; subnets routed in
    /// from other nodes are not translated (see `forward_windows`).
    fn set_sources(&mut self, _sources: &[IpNet]) -> io::Result<()> {
        Ok(())
    }

    fn shutdown(self: Box<Self>) -> Vec<String> {
        crate::forward_windows::HostChanges::shutdown(*self)
    }
}

/// Windows: puts back what an earlier run left, allows inbound traffic to a
/// listening full node, and for a full node with subnets to advertise
/// switches forwarding on and translates the virtual subnet
/// (`forward_windows`). One process per host makes these changes: when the
/// client (or another node) holds them, this node says so and runs without
/// them, advertising no subnets. Any other failure is reported and the node
/// runs on.
#[cfg(windows)]
fn start_host(settings: &MeshSettings, interface: &str, listen_ports: &[u16]) -> HostSide {
    use platform_windows::mesh_host;

    if let Err(error) = mesh_host::recover_mesh_host() {
        let detail = if error.kind() == io::ErrorKind::ResourceBusy {
            "another process (normally the client or another node) holds the host lock; what an earlier run left was not cleaned".to_owned()
        } else {
            format!("what an earlier run left could not be put back: {error}")
        };
        warn("host_changes", &detail);
        if forwards(settings) {
            // Without recovery, originals recorded now could be values an
            // earlier run set.
            forwarding_line("off", Some(&detail));
        } else {
            forwarding_line("not_needed", None);
        }
        return HostSide::none();
    }
    let mut host = crate::forward_windows::HostChanges::default();
    if settings.role == outbound_mesh::Role::Full && !listen_ports.is_empty() {
        if let Err(error) = host.allow_inbound(&settings.network_name, listen_ports, interface) {
            warn("firewall", &error.to_string());
        }
    }
    if !forwards(settings) {
        forwarding_line("not_needed", None);
        return HostSide {
            forwarder: Some(Box::new(host)),
            carried: Vec::new(),
        };
    }
    let ipv6 = settings.address_v6.is_some();
    let wanted: Vec<IpNet> = settings
        .carried_subnets()
        .iter()
        .copied()
        .filter(|subnet| ipv6 || subnet.is_ipv4())
        .collect();
    let lan = match host_interfaces(interface) {
        Ok(found) => host_routes::lan_interfaces(&found.lan, &wanted, interface),
        Err(error) => {
            forwarding_line("off", Some(&error.to_string()));
            return HostSide {
                forwarder: Some(Box::new(host)),
                carried: Vec::new(),
            };
        }
    };
    for warning in host_routes::missing_interfaces(&lan, &wanted) {
        warn("forwarding", &warning);
    }
    if lan.is_empty() {
        forwarding_line(
            "off",
            Some("no interface of this machine is on the advertised subnets"),
        );
        return HostSide {
            forwarder: Some(Box::new(host)),
            carried: Vec::new(),
        };
    }
    let carried = carried(&lan);
    match host.forward(
        &settings.network_name,
        interface,
        &lan,
        crate::forward_windows::ipv4(&settings.address),
        ipv6,
    ) {
        Ok(warnings) => {
            for warning in warnings {
                warn("forwarding", &warning);
            }
            forwarding_line("on", None);
            HostSide {
                forwarder: Some(Box::new(host)),
                carried,
            }
        }
        Err(error) => {
            forwarding_line("off", Some(&error.to_string()));
            HostSide {
                forwarder: Some(Box::new(host)),
                carried: Vec::new(),
            }
        }
    }
}

/// Linux: the node does not change the host's forwarding yet; it relies on
/// the host's own setting (`net.ipv4.ip_forward`,
/// `net.ipv6.conf.all.forwarding`), read once at start. An advertised
/// subnet is carried when a LAN interface is on it and its address family
/// is forwarded; the others are not advertised (requirement R10).
#[cfg(target_os = "linux")]
fn start_host(settings: &MeshSettings, interface: &str, _listen_ports: &[u16]) -> HostSide {
    if !forwards(settings) {
        forwarding_line("not_needed", None);
        return HostSide::none();
    }
    let interfaces = match host_interfaces(interface) {
        Ok(found) => found,
        Err(error) => {
            forwarding_line("off", Some(&error.to_string()));
            return HostSide::none();
        }
    };
    let advertised = &settings.advertise_subnets;
    let lan = host_routes::lan_interfaces(&interfaces.lan, advertised, interface);
    for warning in host_routes::missing_interfaces(&lan, advertised) {
        warn("forwarding", &warning);
    }
    let ipv4 = sysctl_on("/proc/sys/net/ipv4/ip_forward");
    let ipv6 = sysctl_on("/proc/sys/net/ipv6/conf/all/forwarding");
    let (carried, off) = linux_carried(carried(&lan), ipv4, ipv6);
    for family in &off {
        warn("forwarding", &format!("the host does not forward {family}"));
    }
    if carried.is_empty() {
        let detail = if lan.is_empty() {
            "no interface of this machine is on the advertised subnets".to_owned()
        } else {
            format!("the host does not forward {}", off.join(" or "))
        };
        forwarding_line("off", Some(&detail));
    } else {
        forwarding_line("on", Some("the host's own forwarding setting"));
    }
    HostSide {
        forwarder: None,
        carried,
    }
}

/// The subnets of `lan_subnets` whose address family the host forwards,
/// and the families it does not forward that some of them need.
#[cfg(any(target_os = "linux", test))]
fn linux_carried(
    lan_subnets: Vec<IpNet>,
    ipv4: bool,
    ipv6: bool,
) -> (Vec<IpNet>, Vec<&'static str>) {
    let mut off = Vec::new();
    if !ipv4 && lan_subnets.iter().any(IpNet::is_ipv4) {
        off.push("IPv4 (net.ipv4.ip_forward is 0)");
    }
    if !ipv6 && lan_subnets.iter().any(|subnet| !subnet.is_ipv4()) {
        off.push("IPv6 (net.ipv6.conf.all.forwarding is 0)");
    }
    let carried = lan_subnets
        .into_iter()
        .filter(|subnet| if subnet.is_ipv4() { ipv4 } else { ipv6 })
        .collect();
    (carried, off)
}

/// Whether a forwarding switch under `/proc/sys` reads 1; a missing one
/// (no IPv6) counts as off.
#[cfg(target_os = "linux")]
fn sysctl_on(path: &str) -> bool {
    std::fs::read_to_string(path).is_ok_and(|text| text.trim() == "1")
}

/// Puts back what a node that died left on the host (`anixops-mesh
/// restore-host`, run by the uninstallers after the service stops).
/// Returns warnings.
#[cfg(target_os = "macos")]
pub fn restore_host() -> io::Result<Vec<String>> {
    use crate::forward_macos::{recover, MacSystem, STATE_DIR};
    recover(&MacSystem, Path::new(STATE_DIR))
}

/// Puts back what a node that died left on the host (`anixops-mesh
/// restore-host`, run by the uninstallers after the service stops).
/// Returns warnings.
#[cfg(windows)]
pub fn restore_host() -> io::Result<Vec<String>> {
    let report = platform_windows::mesh_host::recover_mesh_host()?;
    let mut warnings = Vec::new();
    if report.forwarding_kept > 0 {
        warnings.push(format!(
            "{} interface forwarding values could not be restored and stay recorded",
            report.forwarding_kept
        ));
    }
    if report.state_set_aside {
        warnings.push("the forwarding record could not be read and was set aside".into());
    }
    if !report.firewall_cleared {
        warnings.push("leftover firewall rules could not be removed".into());
    }
    if !report.nat_cleared {
        warnings.push("leftover address translation could not be removed".into());
    }
    Ok(warnings)
}

/// Linux: the node makes no host changes yet, so nothing is left to put
/// back.
#[cfg(target_os = "linux")]
pub fn restore_host() -> io::Result<Vec<String>> {
    Ok(Vec::new())
}

/// Resolves on SIGTERM or SIGINT.
#[cfg(unix)]
fn signals() -> Result<impl std::future::Future<Output = ()>, Failure> {
    let mut terminate =
        signal(SignalKind::terminate()).map_err(|error| Failure::Other(error.to_string()))?;
    let mut interrupt =
        signal(SignalKind::interrupt()).map_err(|error| Failure::Other(error.to_string()))?;
    Ok(async move {
        tokio::select! {
            _ = terminate.recv() => {}
            _ = interrupt.recv() => {}
        }
    })
}

/// Resolves on Ctrl+C, or when the service manager stops the service.
#[cfg(windows)]
fn signals() -> Result<impl std::future::Future<Output = ()>, Failure> {
    Ok(async {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            () = crate::service_windows::stop_requested() => {}
        }
    })
}

/// A managed network whose native key list lacks this node (spec §8.3.1
/// rule 1): no listening, interface or routes. The status gives the public
/// key for the panel's list; the Agent writes the new configuration and
/// starts the node again.
async fn wait_for_native_keys(static_key: &KeyPair) -> Result<(), Failure> {
    println!(
        "{}",
        serde_json::json!({
            "state": "not_joined",
            "reason": "native_keys_pending",
            "static_key": encode_key(&static_key.public()),
        })
    );
    signals()?.await;
    Ok(())
}

/// What can change in a running network without a restart.
pub(crate) struct Updates {
    /// A new native key list (spec §8.3.1).
    pub native_keys: watch::Receiver<Option<Vec<[u8; 32]>>>,
    /// A new list of custom paths (spec §17.2.8).
    pub paths: watch::Receiver<Vec<CustomPath>>,
    /// New host groups (spec §15.7).
    pub host_groups: watch::Receiver<Vec<HostGroup>>,
    /// New subnet route overrides (spec §15.4, `PUT /v1/mesh/subnet_route`).
    pub route_overrides: watch::Receiver<Vec<IpNet>>,
}

/// Runs one network over `device` until `until` resolves: moves packets
/// between the interface and the driver, keeps the system routes in step
/// with the driver's snapshot and hands each new snapshot to `observe`.
/// `updates` carries new native keys, custom paths, host groups and subnet
/// route overrides into the running driver; `border` connects a border
/// node's network to its backbone.
/// With `host`, the network installs only routes no other network of the
/// process holds, under the given owner name.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn serve_with(
    settings: MeshSettings,
    static_key: KeyPair,
    listeners: Listeners,
    device: Tun,
    until: impl std::future::Future<Output = ()>,
    updates: Updates,
    border: Option<driver::Border>,
    host: Option<(HostRoutes, String)>,
    mut observe: impl FnMut(&Snapshot, &str),
) -> Result<(), Failure> {
    let Updates {
        native_keys,
        paths,
        host_groups,
        route_overrides,
    } = updates;
    let mtu = usize::from(settings.mtu);
    let (to_node, from_interface) = mpsc::channel::<Vec<u8>>(QUEUE);
    let (to_interface, mut from_node) = mpsc::channel::<Vec<u8>>(QUEUE);
    let (snapshots, mut status) = watch::channel(Snapshot::default());
    let (stop, shutdown) = watch::channel(false);
    let claim = host.map(|(routes, owner)| {
        let mut ranges = vec![settings.address.trunc()];
        ranges.extend(settings.address_v6.map(|net| net.trunc()));
        routes.join(&owner, settings.kind == NetworkKind::Managed, &ranges);
        Claim { routes, owner }
    });
    let mut others_changed = claim.as_ref().map(|claim| claim.routes.subscribe());
    // What this network last acted on, so that a notice it caused itself
    // does not wake it again.
    let mut seen = claim
        .as_ref()
        .map(|claim| claim.routes.view(&claim.owner))
        .unwrap_or_default();
    // Recorded as ours, so that no other network of this process takes
    // its routes for another program's.
    let _own = host_routes::claim_own_interface(device.name());
    // This machine's networks are its other interfaces and the routes the
    // other networks of this process hold.
    let others = claim
        .as_ref()
        .map(|claim| (claim.routes.clone(), claim.owner.clone()));
    let scanner = Scanner::new(device.name());
    let (mut interfaces, foreign) = scanner.both().await;
    // `None` until the interfaces were read once: the driver installs no
    // subnet before (spec §15.4).
    let (networks, local_networks) = watch::channel(
        interfaces
            .clone()
            .map(|found| with_others(found, others.as_ref())),
    );
    let (foreign_tx, foreign_routes) = watch::channel(foreign.unwrap_or_default());
    // Scanned again off the packet loop, one read of each kind at a time,
    // and whenever another network takes or frees routes.
    let _scanner = StopTask(tokio::spawn({
        let mut changed = others.as_ref().map(|(routes, _)| routes.subscribe());
        async move {
            let period = |known: bool| {
                if known {
                    LOCAL_NETWORKS_EVERY
                } else {
                    LOCAL_NETWORKS_RETRY
                }
            };
            let mut next = tokio::time::Instant::now() + period(interfaces.is_some());
            loop {
                tokio::select! {
                    () = tokio::time::sleep_until(next) => {
                        let (local, foreign) = scanner.both().await;
                        if local.is_some() {
                            interfaces = local;
                        }
                        if let Some(foreign) = foreign {
                            store(&foreign_tx, foreign);
                        }
                        next = tokio::time::Instant::now() + period(interfaces.is_some());
                    }
                    Some(Ok(())) = async {
                        match &mut changed {
                            Some(changed) => Some(changed.changed().await),
                            None => std::future::pending().await,
                        }
                    } => {}
                }
                // Only a change wakes the driver (spec §15.4).
                if let Some(found) = &interfaces {
                    store(&networks, Some(with_others(found.clone(), others.as_ref())));
                }
            }
        }
    }));
    let mut installed: Vec<IpNet> = Vec::new();
    let mut stopping = false;
    let mut wanted: Vec<IpNet> = Vec::new();
    tokio::pin!(until);

    let node = tokio::spawn(driver::run(
        settings,
        static_key,
        listeners,
        Channels {
            from_interface,
            to_interface,
            snapshots,
            local_networks,
            native_keys,
            paths,
            host_groups,
            route_overrides,
            foreign_routes,
            shutdown,
            border,
        },
    ));
    let _abort = AbortOnDrop(node.abort_handle());
    let mut node = node;
    // Installs what the driver wants, less what other networks hold.
    let reconcile = |installed: &mut Vec<IpNet>, wanted: &[IpNet]| {
        let allowed = match &claim {
            Some(claim) => claim.routes.claim(&claim.owner, wanted),
            None => wanted.to_vec(),
        };
        let (add, remove) = route_changes(installed, &allowed);
        let mut removed = HashSet::new();
        for net in remove {
            if let Err(error) = device.remove_route(net.network(), net.prefix()) {
                warn("route", &format!("{net}: {error}"));
            }
            removed.insert(net);
        }
        installed.retain(|net| !removed.contains(net));
        for net in add {
            match device.add_route(net.network(), net.prefix()) {
                Ok(()) => installed.push(net),
                Err(error) => warn("route", &format!("{net}: {error}")),
            }
        }
        if let Some(claim) = &claim {
            // Only what is installed stays claimed.
            claim.routes.narrow(&claim.owner, installed);
        }
    };
    // Room for one packet larger than the MTU, so that an oversized one is
    // read whole and refused by the node instead of being cut short.
    let mut buffer = vec![0u8; mtu + 1];
    loop {
        tokio::select! {
            read = device.recv(&mut buffer) => {
                let length = read.map_err(|error| Failure::Other(format!("interface: {error}")))?;
                // A full queue drops the packet like a full interface would.
                let _ = to_node.try_send(buffer[..length].to_vec());
            }
            Some(packet) = from_node.recv() => {
                if let Err(error) = device.send(&packet).await {
                    // A packet the kernel refuses (for example an address
                    // that is not configured) does not stop the node.
                    warn("interface", &error.to_string());
                }
            }
            changed = status.changed() => {
                if changed.is_err() {
                    break;
                }
                let snapshot = status.borrow_and_update().clone();
                wanted.clone_from(&snapshot.system_routes);
                reconcile(&mut installed, &wanted);
                if let Some(claim) = &claim {
                    seen = claim.routes.view(&claim.owner);
                }
                observe(&snapshot, device.name());
            }
            Some(Ok(())) = async {
                match &mut others_changed {
                    Some(changed) => Some(changed.changed().await),
                    None => std::future::pending().await,
                }
            } => {
                // Another network took or freed routes: freed ones may be
                // ours now (the scanner updates this machine's networks),
                // and a managed network may have taken ours.
                if let Some(claim) = &claim {
                    let now = claim.routes.view(&claim.owner);
                    if now != seen {
                        reconcile(&mut installed, &wanted);
                        seen = claim.routes.view(&claim.owner);
                    }
                }
            }
            // The node may keep running for a moment after withdrawing its
            // advertisements (spec §15.7 rule 6); the interface keeps
            // carrying its traffic until it ends.
            () = &mut until, if !stopping => {
                stopping = true;
                let _ = stop.send(true);
            }
            result = &mut node => {
                return match result {
                    Ok(Ok(())) if stopping => Ok(()),
                    Ok(Ok(())) => Err(Failure::Other("the node stopped".into())),
                    Ok(Err(error)) => Err(Failure::Other(error.to_string())),
                    Err(error) => Err(Failure::Other(error.to_string())),
                };
            }
        }
    }
    let _ = stop.send(true);
    match node.await {
        Ok(Ok(())) => Ok(()),
        Ok(Err(error)) => Err(Failure::Other(error.to_string())),
        Err(error) => Err(Failure::Other(error.to_string())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn linux_carries_only_the_families_the_host_forwards() {
        let net = |text: &str| IpNet::parse(text).unwrap();
        let lan = vec![net("192.168.10.0/24"), net("fd00:10::/64")];
        let (carried, off) = linux_carried(lan.clone(), true, true);
        assert_eq!(carried, lan);
        assert!(off.is_empty());
        let (carried, off) = linux_carried(lan.clone(), true, false);
        assert_eq!(carried, [net("192.168.10.0/24")]);
        assert_eq!(off.len(), 1);
        assert!(off[0].starts_with("IPv6"));
        let (carried, off) = linux_carried(lan, false, false);
        assert!(carried.is_empty());
        assert_eq!(off.len(), 2);
        // A family nothing needs is not reported.
        let (_, off) = linux_carried(vec![net("192.168.10.0/24")], true, false);
        assert!(off.is_empty());
    }

    fn config(address: &str) -> String {
        serde_json::json!({
            "config_version": 1,
            "network": { "name": "office", "secret": "s3cret", "kind": "legacy" },
            "node": { "address": address, "role": "access" },
            "peers": [{ "server": "peer.example", "port": 40000 }],
        })
        .to_string()
    }

    #[test]
    fn a_bad_configuration_is_a_configuration_failure() {
        let failure = settings_from_json("{").err().expect("not json");
        assert_eq!(failure.exit_code(), 2);
        assert_eq!(failure.kind(), "config");
        assert!(failure.json().get("conflict").is_none());
        let failure = settings_from_json("{\"config_version\": 999}")
            .err()
            .expect("missing fields");
        assert_eq!(failure.exit_code(), 2);
    }

    #[test]
    fn a_port_in_use_is_busy() {
        let error = io::Error::from(io::ErrorKind::AddrInUse);
        let failure = busy("port_in_use", "listen", &error);
        assert_eq!(failure.exit_code(), 3);
        let line = failure.json();
        assert_eq!(line["error"], "conflict");
        assert_eq!(line["conflict"], "port_in_use");
        #[cfg(unix)]
        {
            let error = io::Error::from_raw_os_error(libc::EBUSY);
            let failure = busy("tun_in_use", "interface", &error);
            assert_eq!(failure.exit_code(), 3);
            assert_eq!(failure.json()["conflict"], "tun_in_use");
        }
        let error = io::Error::from(io::ErrorKind::PermissionDenied);
        let failure = busy("tun_in_use", "interface", &error);
        assert_eq!(failure.exit_code(), 1);
        assert_eq!(failure.json()["error"], "runtime");
        assert!(failure.json().get("conflict").is_none());
    }

    #[test]
    fn the_status_line_names_the_interface_and_neighbours() {
        let snapshot = Snapshot {
            peer_id: 7,
            neighbours: vec![3, 9],
            routes: vec![(3, 3, 1), (9, 9, 1), (12, 9, 2)],
            ..Snapshot::default()
        };
        let line: serde_json::Value =
            serde_json::from_str(&status_line(&snapshot, "anixmesh0")).expect("json");
        assert_eq!(line["interface"], "anixmesh0");
        assert_eq!(line["neighbours"], serde_json::json!([3, 9]));
        assert_eq!(line["reachable"], 3);
        assert_eq!(line["duplicate_id"], false);
        assert_eq!(line["static_key"], serde_json::Value::Null);
        assert_eq!(line["local_networks_read"], false);
        assert_eq!(line["foreign_overlaps"], serde_json::json!([]));
        let read = Snapshot {
            local_networks_read: true,
            foreign_overlaps: vec![IpNet::parse("100.64.0.0/10").unwrap()],
            ..Snapshot::default()
        };
        let line: serde_json::Value =
            serde_json::from_str(&status_line(&read, "anixmesh0")).expect("json");
        assert_eq!(line["local_networks_read"], true);
        assert_eq!(
            line["foreign_overlaps"],
            serde_json::json!(["100.64.0.0/10"])
        );
        let secure = Snapshot {
            static_key: Some([7; 32]),
            not_native: Some(12),
            ..Snapshot::default()
        };
        let line: serde_json::Value =
            serde_json::from_str(&status_line(&secure, "anixmesh0")).expect("json");
        assert_eq!(line["static_key"], encode_key(&[7; 32]));
        assert_eq!(line["not_native"], 12);
        assert_eq!(line["sync_oversize"]["received"], serde_json::Value::Null);

        let mut oversize = Snapshot::default();
        oversize.sync_oversize.received = Some((9, 8_400_000));
        oversize.counters.refused_at_capacity = 3;
        let line: serde_json::Value =
            serde_json::from_str(&status_line(&oversize, "anixmesh0")).expect("json");
        assert_eq!(line["sync_oversize"]["received"]["peer"], 9);
        assert_eq!(line["sync_oversize"]["received"]["bytes"], 8_400_000);
        assert_eq!(line["sync_oversize"]["refused_at_capacity"], 3);
    }

    #[test]
    fn the_static_key_is_kept_next_to_the_configuration() {
        let dir = std::env::temp_dir().join(format!("mesh-key-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("temp dir");
        let config = dir.join("mesh.json");
        let path = key_path(&config);
        assert_eq!(path, dir.join("mesh.json.key"));
        let _ = std::fs::remove_file(&path);
        let first = static_key(&path).expect("new key");
        let second = static_key(&path).expect("same key");
        assert_eq!(first.public(), second.public());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path)
                .expect("key file")
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        std::fs::write(&path, b"short").expect("overwrite");
        assert_eq!(static_key(&path).err().map(|f| f.exit_code()), Some(2));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn route_changes_add_the_new_and_remove_the_gone() {
        let net = |text: &str| IpNet::parse(text).expect("network");
        let installed = [net("192.168.10.0/24"), net("172.16.0.0/16")];
        let wanted = [net("192.168.10.0/24"), net("10.20.0.0/16")];
        let (add, remove) = route_changes(&installed, &wanted);
        assert_eq!(add, [net("10.20.0.0/16")]);
        assert_eq!(remove, [net("172.16.0.0/16")]);
        let (add, remove) = route_changes(&wanted, &wanted);
        assert!(add.is_empty() && remove.is_empty());
    }

    #[test]
    fn claims_compare_as_sets_and_settle() {
        let net = |text: &str| IpNet::parse(text).expect("network");
        let routes = HostRoutes::default();
        routes.join("mesh-a", true, &[net("10.150.0.0/16")]);
        let mut changes = routes.subscribe();
        assert_eq!(
            routes.claim("mesh-a", &[net("192.168.2.0/24")]),
            [net("192.168.2.0/24")]
        );
        changes.mark_unchanged();
        // A subnet that sorts first arrives; installed in another order.
        let held = routes.claim("mesh-a", &[net("10.20.0.0/16"), net("192.168.2.0/24")]);
        assert_eq!(held, [net("10.20.0.0/16"), net("192.168.2.0/24")]);
        assert!(changes.has_changed().unwrap());
        changes.mark_unchanged();
        routes.narrow("mesh-a", &[net("192.168.2.0/24"), net("10.20.0.0/16")]);
        routes.claim("mesh-a", &[net("192.168.2.0/24"), net("10.20.0.0/16")]);
        assert!(!changes.has_changed().unwrap());
        // What failed to install is given up, once.
        routes.narrow("mesh-a", &[net("192.168.2.0/24")]);
        assert!(changes.has_changed().unwrap());
        assert_eq!(routes.view("mesh-a").1, [net("192.168.2.0/24")]);
        // The network's own claims leave what it sees of the others alone.
        assert_eq!(routes.view("mesh-a").0, Vec::<IpNet>::new());
    }

    #[test]
    fn a_managed_network_takes_a_subnet_from_a_legacy_one() {
        let net = |text: &str| IpNet::parse(text).expect("network");
        let routes = HostRoutes::default();
        routes.join("legacy", false, &[net("10.144.0.0/24")]);
        routes.join("managed", true, &[net("10.150.0.0/16")]);
        // The managed network restarted: the legacy one took the subnet.
        assert_eq!(
            routes.claim("legacy", &[net("192.168.50.0/24")]),
            [net("192.168.50.0/24")]
        );
        let (_, before) = routes.view("legacy");
        assert_eq!(
            routes.claim("managed", &[net("192.168.50.0/24")]),
            [net("192.168.50.0/24")]
        );
        // The legacy network lost it and cannot take it back.
        let (others, own) = routes.view("legacy");
        assert_ne!(own, before);
        assert!(own.is_empty());
        assert!(others.contains(&net("192.168.50.0/24")));
        assert!(routes.claim("legacy", &[net("192.168.50.0/24")]).is_empty());
        // Between networks of one kind the first keeps it.
        routes.join("managed-2", true, &[]);
        assert!(routes
            .claim("managed-2", &[net("192.168.50.0/24")])
            .is_empty());
    }

    #[test]
    fn a_virtual_range_is_never_claimed_by_another_network() {
        let net = |text: &str| IpNet::parse(text).expect("network");
        let routes = HostRoutes::default();
        routes.join("legacy", false, &[]);
        assert_eq!(
            routes.claim("legacy", &[net("10.150.0.0/16")]),
            [net("10.150.0.0/16")]
        );
        // A network on that range starts: the others see it at once.
        routes.join("managed", true, &[net("10.150.0.5/16")]);
        assert!(routes.others("legacy").contains(&net("10.150.0.0/16")));
        assert!(routes.claim("legacy", &[net("10.150.0.0/16")]).is_empty());
        // Nor by a managed network.
        routes.join("managed-2", true, &[]);
        assert!(routes
            .claim("managed-2", &[net("10.150.1.0/24")])
            .is_empty());
    }

    #[test]
    fn the_first_network_to_claim_a_subnet_keeps_it() {
        let net = |text: &str| IpNet::parse(text).expect("network");
        let routes = HostRoutes::default();
        let mut changes = routes.subscribe();
        let a = routes.claim("mesh-a", &[net("192.168.50.0/24"), net("172.16.0.0/16")]);
        assert_eq!(a.len(), 2);
        assert!(changes.has_changed().unwrap());
        changes.mark_unchanged();
        // Overlapping either way is refused; the rest is taken.
        let b = routes.claim(
            "mesh-b",
            &[
                net("192.168.50.128/25"),
                net("172.0.0.0/8"),
                net("10.9.0.0/16"),
            ],
        );
        assert_eq!(b, [net("10.9.0.0/16")]);
        assert_eq!(routes.others("mesh-b").len(), 2);
        assert!(routes.others("mesh-a").contains(&net("10.9.0.0/16")));
        // Claiming the same again changes nothing.
        changes.mark_unchanged();
        routes.claim("mesh-a", &a);
        assert!(!changes.has_changed().unwrap());
        // Once the first network stops, the subnet is free.
        drop(Claim {
            routes: routes.clone(),
            owner: "mesh-a".into(),
        });
        assert!(changes.has_changed().unwrap());
        let b = routes.claim("mesh-b", &[net("192.168.50.128/25")]);
        assert_eq!(b, [net("192.168.50.128/25")]);
    }

    #[test]
    fn a_key_file_is_written_whole_and_kept() {
        let dir = std::env::temp_dir().join(format!("mesh-key-whole-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("office.key");
        let first = static_key(&path).expect("made").public();
        assert_eq!(std::fs::read(&path).unwrap().len(), LEN);
        assert_eq!(static_key(&path).expect("read").public(), first);
        // No temporary file is left behind.
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_valid_configuration_gives_matching_interface_addresses() {
        let settings = settings_from_json(&config("10.144.0.5/24")).expect("valid");
        let (address, v6) =
            tun::addresses(settings.address.address(), settings.address.prefix(), None)
                .expect("IPv4 address");
        assert_eq!(address, (std::net::Ipv4Addr::new(10, 144, 0, 5), 24));
        assert!(v6.is_none());
    }
}
