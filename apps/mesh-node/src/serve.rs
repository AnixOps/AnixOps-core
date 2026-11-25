//! `run`: the node itself. Reads the mesh configuration the importer or the
//! panel wrote, binds the listeners, creates the virtual interface and runs
//! the mesh module's socket driver until SIGTERM or SIGINT.
//!
//! Exit codes: 0 stopped by a signal, 2 configuration, 3 a port or the
//! interface is taken (another program still runs), 1 anything else.

use std::io;
use std::path::Path;

use std::time::Duration;

use outbound_mesh::driver::{self, Channels, Listeners, Snapshot};
use outbound_mesh::secure::noise::{KeyPair, LEN};
use outbound_mesh::{IpNet, MeshConfig, MeshSettings};
use ring::rand::SystemRandom;
use tokio::signal::unix::{signal, SignalKind};
use tokio::sync::{mpsc, watch};

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

/// Routes to add and to remove to go from `installed` to `wanted`.
fn route_changes(installed: &[IpNet], wanted: &[IpNet]) -> (Vec<IpNet>, Vec<IpNet>) {
    let add = wanted
        .iter()
        .filter(|net| !installed.contains(net))
        .copied()
        .collect();
    let remove = installed
        .iter()
        .filter(|net| !wanted.contains(net))
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
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
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
    runtime.block_on(async move {
        let listeners = Listeners::bind(&settings)
            .await
            .map_err(|error| busy("listen", &error))?;
        let device = Tun::create(&interface, address, address_v6, settings.mtu)
            .map_err(|error| busy(&format!("interface {interface}"), &error))?;
        let static_key = static_key(&key_path(path))?;
        serve(settings, static_key, listeners, device).await
    })
}

async fn serve(
    settings: MeshSettings,
    static_key: KeyPair,
    listeners: Listeners,
    device: Tun,
) -> Result<(), Failure> {
    let mtu = usize::from(settings.mtu);
    let (to_node, from_interface) = mpsc::channel::<Vec<u8>>(QUEUE);
    let (to_interface, mut from_node) = mpsc::channel::<Vec<u8>>(QUEUE);
    let (snapshots, mut status) = watch::channel(Snapshot::default());
    let (stop, shutdown) = watch::channel(false);
    let (networks, local_networks) = watch::channel(read_local_networks(device.name()));
    let mut rescan = tokio::time::interval(LOCAL_NETWORKS_EVERY);
    let mut installed: Vec<IpNet> = Vec::new();
    let mut terminate =
        signal(SignalKind::terminate()).map_err(|error| Failure::Other(error.to_string()))?;
    let mut interrupt =
        signal(SignalKind::interrupt()).map_err(|error| Failure::Other(error.to_string()))?;

    let mut node = tokio::spawn(driver::run(
        settings,
        static_key,
        listeners,
        Channels {
            from_interface,
            to_interface,
            snapshots,
            local_networks,
            shutdown,
        },
    ));
    // Room for one packet larger than the MTU, so that an oversized one is
    // read whole and refused by the node instead of being cut short.
    let mut buffer = vec![0u8; mtu + 1];
    let mut last = String::new();
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
                for net in remove {
                    if let Err(error) = device.remove_route(net.network(), net.prefix()) {
                        warn("route", &format!("{net}: {error}"));
                    }
                    installed.retain(|other| *other != net);
                }
                for net in add {
                    match device.add_route(net.network(), net.prefix()) {
                        Ok(()) => installed.push(net),
                        Err(error) => warn("route", &format!("{net}: {error}")),
                    }
                }
                let line = status_line(&snapshot, device.name());
                if line != last {
                    println!("{line}");
                    last = line;
                }
            }
            _ = rescan.tick() => {
                let _ = networks.send(read_local_networks(device.name()));
            }
            _ = terminate.recv() => break,
            _ = interrupt.recv() => break,
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
    fn a_valid_configuration_gives_matching_interface_addresses() {
        let settings = settings_from_json(&config("10.144.0.5/24")).expect("valid");
        let (address, v6) =
            tun::addresses(settings.address.address(), settings.address.prefix(), None)
                .expect("IPv4 address");
        assert_eq!(address, (std::net::Ipv4Addr::new(10, 144, 0, 5), 24));
        assert!(v6.is_none());
    }
}
