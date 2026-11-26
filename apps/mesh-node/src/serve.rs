//! `run`: the node itself. Reads the mesh configuration the importer or the
//! panel wrote, binds the listeners, creates the virtual interface and runs
//! the mesh module's socket driver until SIGTERM or SIGINT.
//!
//! Exit codes: 0 stopped by a signal, 2 configuration, 3 a port or the
//! interface is taken (another program still runs), 1 anything else.

use std::collections::{BTreeMap, HashSet};
use std::io;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use outbound_mesh::config::encode_key;
use outbound_mesh::driver::{self, Channels, Listeners, Snapshot};
use outbound_mesh::secure::noise::{KeyPair, LEN};
use outbound_mesh::{IpNet, MeshConfig, MeshSettings};
use ring::rand::SystemRandom;
use tokio::signal::unix::{signal, SignalKind};
use tokio::sync::{mpsc, watch};
use zeroize::Zeroizing;

use crate::tun::{self, Tun};

/// Interface name when the configuration names none.
pub const DEFAULT_INTERFACE: &str = "anixmesh0";

/// Packets queued between the interface and the driver in each direction.
const QUEUE: usize = 256;

/// How often the networks of the other interfaces are read again.
const LOCAL_NETWORKS_EVERY: Duration = Duration::from_secs(30);

fn read_local_networks(skip: &str) -> Vec<IpNet> {
    match tun::local_networks(skip) {
        Ok(networks) => networks
            .into_iter()
            .filter_map(|(address, prefix)| IpNet::new(address, prefix))
            .collect(),
        Err(error) => {
            eprintln!(
                "{}",
                serde_json::json!({ "warning": "interfaces", "detail": error.to_string() })
            );
            Vec::new()
        }
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

/// The system routes the networks of one process installed, by network,
/// shared so that no two networks install overlapping subnets: the first
/// to claim a subnet keeps it, and the others treat it as one of this
/// machine's networks (spec §15.4), which refuses it as an overlap.
#[derive(Clone)]
pub(crate) struct HostRoutes {
    inner: Arc<HostRoutesInner>,
}

struct HostRoutesInner {
    claimed: Mutex<BTreeMap<String, Vec<IpNet>>>,
    /// Counts changes, so that the other networks look again.
    changed: watch::Sender<u64>,
}

impl Default for HostRoutes {
    fn default() -> Self {
        Self {
            inner: Arc::new(HostRoutesInner {
                claimed: Mutex::new(BTreeMap::new()),
                changed: watch::channel(0).0,
            }),
        }
    }
}

impl HostRoutes {
    fn claimed(&self) -> std::sync::MutexGuard<'_, BTreeMap<String, Vec<IpNet>>> {
        self.inner
            .claimed
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Claims for `owner` the subnets of `wanted` that overlap none the
    /// other networks hold, gives up the rest of what it held, and returns
    /// what it now holds.
    pub(crate) fn claim(&self, owner: &str, wanted: &[IpNet]) -> Vec<IpNet> {
        let mut claimed = self.claimed();
        let held: Vec<IpNet> = wanted
            .iter()
            .filter(|net| {
                !claimed
                    .iter()
                    .filter(|(other, _)| other.as_str() != owner)
                    .any(|(_, theirs)| theirs.iter().any(|their| their.overlaps(net)))
            })
            .copied()
            .collect();
        let before = claimed.insert(owner.to_owned(), held.clone());
        if before.as_ref() != Some(&held) {
            self.inner.changed.send_modify(|count| *count += 1);
        }
        held
    }

    /// What the networks other than `owner` hold.
    pub(crate) fn others(&self, owner: &str) -> Vec<IpNet> {
        self.claimed()
            .iter()
            .filter(|(other, _)| other.as_str() != owner)
            .flat_map(|(_, theirs)| theirs.iter().copied())
            .collect()
    }

    /// `owner` stopped: what it held is free.
    pub(crate) fn release(&self, owner: &str) {
        if self.claimed().remove(owner).is_some() {
            self.inner.changed.send_modify(|count| *count += 1);
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
    let written = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
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
            .map_err(|error| busy("listen", &error))?;
        let device = Tun::create(&interface, address, address_v6, settings.mtu)
            .map_err(|error| busy(&format!("interface {interface}"), &error))?;
        let stop = signals()?;
        let mut last = String::new();
        // Nothing updates the native key list of a standalone node: the
        // Agent writes a new configuration and starts it again.
        let (_keep, native_keys) = watch::channel(None);
        serve_with(
            settings,
            static_key,
            listeners,
            device,
            stop,
            native_keys,
            None,
            |snapshot, name| {
                let line = status_line(snapshot, name);
                if line != last {
                    println!("{line}");
                    last = line;
                }
            },
        )
        .await
    })
}

/// Resolves on SIGTERM or SIGINT.
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
/// With `host`, the network installs only routes no other network of the
/// process holds, under the given owner name.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn serve_with(
    settings: MeshSettings,
    static_key: KeyPair,
    listeners: Listeners,
    device: Tun,
    until: impl std::future::Future<Output = ()>,
    native_keys: watch::Receiver<Option<Vec<[u8; 32]>>>,
    host: Option<(HostRoutes, String)>,
    mut observe: impl FnMut(&Snapshot, &str),
) -> Result<(), Failure> {
    let mtu = usize::from(settings.mtu);
    let (to_node, from_interface) = mpsc::channel::<Vec<u8>>(QUEUE);
    let (to_interface, mut from_node) = mpsc::channel::<Vec<u8>>(QUEUE);
    let (snapshots, mut status) = watch::channel(Snapshot::default());
    let (stop, shutdown) = watch::channel(false);
    let claim = host.map(|(routes, owner)| Claim { routes, owner });
    let mut others_changed = claim.as_ref().map(|claim| claim.routes.subscribe());
    let local = |device: &Tun| {
        let mut networks = read_local_networks(device.name());
        if let Some(claim) = &claim {
            networks.extend(claim.routes.others(&claim.owner));
        }
        networks
    };
    let (networks, local_networks) = watch::channel(local(&device));
    let mut rescan = tokio::time::interval(LOCAL_NETWORKS_EVERY);
    let mut installed: Vec<IpNet> = Vec::new();
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
            shutdown,
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
            claim.routes.claim(&claim.owner, installed);
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
                observe(&snapshot, device.name());
            }
            _ = rescan.tick() => {
                let _ = networks.send(local(&device));
            }
            Some(Ok(())) = async {
                match &mut others_changed {
                    Some(changed) => Some(changed.changed().await),
                    None => std::future::pending().await,
                }
            } => {
                // Another network took or freed routes: the driver sees
                // them as this machine's, and freed ones may be ours now.
                let _ = networks.send(local(&device));
                reconcile(&mut installed, &wanted);
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
        let error = io::Error::from_raw_os_error(libc::EBUSY);
        assert_eq!(busy("interface", &error).exit_code(), 3);
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
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&path)
            .expect("key file")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
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
        let dir = std::env::temp_dir().join(format!("mesh-key-{}", std::process::id()));
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
