//! `run`: the node itself. Reads the mesh configuration the importer or the
//! panel wrote, binds the listeners, creates the virtual interface and runs
//! the mesh module's socket driver until SIGTERM or SIGINT.
//!
//! Exit codes: 0 stopped by a signal, 2 configuration, 3 a port or the
//! interface is taken (another program still runs), 1 anything else.

use std::collections::HashSet;
use std::io;
use std::path::Path;

use std::time::Duration;

use outbound_mesh::config::encode_key;
use outbound_mesh::driver::{self, Channels, Listeners, Snapshot};
use outbound_mesh::secure::noise::{KeyPair, LEN};
use outbound_mesh::{IpNet, MeshConfig, MeshSettings, Role};
use ring::rand::SystemRandom;
#[cfg(unix)]
use tokio::signal::unix::{signal, SignalKind};
use tokio::sync::{mpsc, watch};

use crate::host_routes;
use crate::tun::{self, Tun};

/// Interface name when the configuration names none.
pub const DEFAULT_INTERFACE: &str = "anixmesh0";

/// Packets queued between the interface and the driver in each direction.
const QUEUE: usize = 256;

/// How often the networks of the other interfaces are read again.
const LOCAL_NETWORKS_EVERY: Duration = Duration::from_secs(30);

/// How long one scan of the interfaces and routes may take.
const SCAN_TIMEOUT: Duration = Duration::from_secs(10);

/// The networks of the other interfaces (spec §15.4). Our own mesh
/// interfaces, and `device`, are left out.
fn read_local_networks(device: &str) -> Vec<IpNet> {
    let own = |name: &str| host_routes::is_own_interface(name, &[device]);
    match tun::local_networks(own) {
        Ok(networks) => networks
            .into_iter()
            .filter_map(|(address, prefix)| IpNet::new(address, prefix))
            .collect(),
        Err(error) => {
            warn("interfaces", &error.to_string());
            Vec::new()
        }
    }
}

/// What the host reaches without the mesh: the networks of the other
/// interfaces, and the routes of other mesh programs as the system selects
/// them. `None` when a scan failed or took longer than [`SCAN_TIMEOUT`];
/// the previous result then stays.
async fn scan(device: String) -> Option<(Vec<IpNet>, Vec<IpNet>)> {
    let read = tokio::task::spawn_blocking(move || {
        let networks = read_local_networks(&device);
        match host_routes::foreign_routes(&device) {
            Ok(routes) => Some((networks, routes)),
            Err(error) => {
                warn("routes", &error.to_string());
                None
            }
        }
    });
    match tokio::time::timeout(SCAN_TIMEOUT, read).await {
        Ok(Ok(found)) => found,
        Ok(Err(error)) => {
            warn("routes", &error.to_string());
            None
        }
        Err(_) => {
            warn("routes", "the scan of the routing tables timed out");
            None
        }
    }
}

/// Stores `fresh` when it differs, so that the driver wakes on changes only.
fn store(sender: &watch::Sender<Vec<IpNet>>, fresh: Vec<IpNet>) {
    sender.send_if_modified(|current| {
        let changed = *current != fresh;
        if changed {
            *current = fresh;
        }
        changed
    });
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

/// Why `run` stopped.
#[derive(Debug)]
pub enum Failure {
    /// Exit code 2.
    Config(String),
    /// Exit code 3.
    Busy(String),
    /// Exit code 1.
    Other(String),
}

impl Failure {
    pub fn exit_code(&self) -> u8 {
        match self {
            Self::Config(_) => 2,
            Self::Busy(_) => 3,
            Self::Other(_) => 1,
        }
    }

    pub fn kind(&self) -> &'static str {
        match self {
            Self::Config(_) => "config",
            Self::Busy(_) => "busy",
            Self::Other(_) => "run",
        }
    }

    pub fn detail(&self) -> &str {
        match self {
            Self::Config(detail) | Self::Busy(detail) | Self::Other(detail) => detail,
        }
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

fn busy(what: &str, error: &io::Error) -> Failure {
    match error.kind() {
        io::ErrorKind::AddrInUse | io::ErrorKind::ResourceBusy => {
            Failure::Busy(format!("{what}: {error}"))
        }
        // The kernel answers EBUSY for an interface another program holds.
        #[cfg(unix)]
        _ if error.raw_os_error() == Some(libc::EBUSY) => Failure::Busy(format!("{what}: {error}")),
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

    match std::fs::read(path) {
        Ok(bytes) => {
            let private: [u8; LEN] = bytes.as_slice().try_into().map_err(|_| {
                Failure::Config(format!("{}: not a {LEN}-byte key", path.display()))
            })?;
            return Ok(KeyPair::from_private(private));
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(Failure::Other(format!("{}: {error}", path.display()))),
    }
    let key = KeyPair::generate(&SystemRandom::new())
        .map_err(|_| Failure::Other("no system randomness".into()))?;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    // Readable by the owner only. On Windows the file takes the access
    // list of its directory, which the installer limits to SYSTEM and
    // Administrators.
    #[cfg(unix)]
    options.mode(0o600);
    let mut file = options
        .open(path)
        .map_err(|error| Failure::Other(format!("{}: {error}", path.display())))?;
    file.write_all(&key.private()[..])
        .and_then(|()| file.sync_all())
        .map_err(|error| Failure::Other(format!("{}: {error}", path.display())))?;
    Ok(key)
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
            .map_err(|error| busy("listen", &error))?;
        let device = Tun::create(&interface, address, address_v6, settings.mtu)
            .map_err(|error| busy(&format!("interface {interface}"), &error))?;
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
        let result = serve_with(
            settings,
            static_key,
            listeners,
            device,
            stop,
            native_keys,
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
    settings.role == Role::Full && !settings.advertise_subnets.is_empty()
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
#[cfg(any(target_os = "macos", windows))]
fn carried(lan: &[(String, IpNet)]) -> Vec<IpNet> {
    let mut subnets: Vec<IpNet> = lan.iter().map(|(_, subnet)| *subnet).collect();
    subnets.sort_by_key(IpNet::to_string);
    subnets.dedup();
    subnets
}

/// The machine's interfaces as the host side sees them.
#[cfg(any(target_os = "macos", windows))]
struct HostInterfaces {
    /// LAN interfaces as (name, address network) pairs.
    lan: Vec<(String, IpNet)>,
    /// Names of other programs' virtual interfaces. Only macOS reads it:
    /// forwarding there is system-wide. Windows forwards per interface and
    /// reports the interfaces that actually forward instead.
    #[cfg_attr(windows, allow(dead_code))]
    others: Vec<String>,
}

/// The machine's LAN interfaces and the names of other programs' virtual
/// interfaces. Neither list holds our own mesh interfaces; virtual
/// interfaces never count as LAN, so a subnet a VPN also covers is not
/// forwarded into that VPN.
#[cfg(any(target_os = "macos", windows))]
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
        .advertise_subnets
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
            "another administrator process (the client or another node) holds the host changes; what an earlier run left was not cleaned".to_owned()
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
    if settings.role == Role::Full && !listen_ports.is_empty() {
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
        .advertise_subnets
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

/// Linux: the host side is not in place yet, so the node advertises no
/// subnets rather than draw traffic it does not carry.
#[cfg(target_os = "linux")]
fn start_host(settings: &MeshSettings, _interface: &str, _listen_ports: &[u16]) -> HostSide {
    if forwards(settings) {
        forwarding_line(
            "off",
            Some("host forwarding is not implemented on this system yet"),
        );
    } else {
        forwarding_line("not_needed", None);
    }
    HostSide::none()
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

/// Runs one network over `device` until `until` resolves: moves packets
/// between the interface and the driver, keeps the system routes in step
/// with the driver's snapshot and hands each new snapshot to `observe`.
/// `native_keys` carries a new native key list into the running driver.
pub(crate) async fn serve_with(
    settings: MeshSettings,
    static_key: KeyPair,
    listeners: Listeners,
    device: Tun,
    until: impl std::future::Future<Output = ()>,
    native_keys: watch::Receiver<Option<Vec<[u8; 32]>>>,
    mut observe: impl FnMut(&Snapshot, &str),
) -> Result<(), Failure> {
    let mtu = usize::from(settings.mtu);
    let (to_node, from_interface) = mpsc::channel::<Vec<u8>>(QUEUE);
    let (to_interface, mut from_node) = mpsc::channel::<Vec<u8>>(QUEUE);
    let (snapshots, mut status) = watch::channel(Snapshot::default());
    let (stop, shutdown) = watch::channel(false);
    // Recorded as ours, so that no other network of this process takes
    // its routes for another program's.
    let _own = host_routes::claim_own_interface(device.name());
    let (local, foreign) = scan(device.name().to_owned()).await.unwrap_or_default();
    let (networks, local_networks) = watch::channel(local);
    let (routes, foreign_routes) = watch::channel(foreign);
    // Scanned again off the packet loop, one scan at a time.
    let _scanner = StopTask(tokio::spawn({
        let device = device.name().to_owned();
        async move {
            let mut rescan = tokio::time::interval(LOCAL_NETWORKS_EVERY);
            rescan.tick().await;
            loop {
                rescan.tick().await;
                if let Some((local, foreign)) = scan(device.clone()).await {
                    store(&networks, local);
                    store(&routes, foreign);
                }
            }
        }
    }));
    // No entry point sets subnet route overrides here yet; the sender is
    // kept so that the driver sees an open, empty list.
    let (_route_overrides, route_overrides) = watch::channel(Vec::new());
    let mut installed: Vec<IpNet> = Vec::new();
    tokio::pin!(until);

    let mut node = tokio::spawn(driver::run(
        settings,
        static_key,
        listeners,
        Channels {
            from_interface,
            to_interface,
            snapshots,
            local_networks,
            native_keys,
            route_overrides,
            foreign_routes,
            shutdown,
        },
    ));
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
                let (add, remove) = route_changes(&installed, &snapshot.system_routes);
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
                observe(&snapshot, device.name());
            }
            () = &mut until => break,
            result = &mut node => {
                return match result {
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
        let failure = settings_from_json("{\"config_version\": 999}")
            .err()
            .expect("missing fields");
        assert_eq!(failure.exit_code(), 2);
    }

    #[test]
    fn a_port_in_use_is_busy() {
        let error = io::Error::from(io::ErrorKind::AddrInUse);
        assert_eq!(busy("listen", &error).exit_code(), 3);
        #[cfg(unix)]
        {
            let error = io::Error::from_raw_os_error(libc::EBUSY);
            assert_eq!(busy("interface", &error).exit_code(), 3);
        }
        let error = io::Error::from(io::ErrorKind::PermissionDenied);
        assert_eq!(busy("interface", &error).exit_code(), 1);
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
        let secure = Snapshot {
            static_key: Some([7; 32]),
            not_native: Some(12),
            ..Snapshot::default()
        };
        let line: serde_json::Value =
            serde_json::from_str(&status_line(&secure, "anixmesh0")).expect("json");
        assert_eq!(line["static_key"], encode_key(&[7; 32]));
        assert_eq!(line["not_native"], 12);
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
    fn a_valid_configuration_gives_matching_interface_addresses() {
        let settings = settings_from_json(&config("10.144.0.5/24")).expect("valid");
        let (address, v6) =
            tun::addresses(settings.address.address(), settings.address.prefix(), None)
                .expect("IPv4 address");
        assert_eq!(address, (std::net::Ipv4Addr::new(10, 144, 0, 5), 24));
        assert!(v6.is_none());
    }
}
