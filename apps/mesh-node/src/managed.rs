//! The managed networks a node agent runs through the kernel's local
//! management API (`GET` / `PUT /v1/mesh`, `docs/architecture/mesh-status.md`
//! "节点程序管理 API"): one listener set, virtual interface and socket
//! driver per network, as `run` has for one.
//!
//! The kernel does not keep the networks: the agent sends its last `PUT`
//! again after a restart. What it does keep, in its state directory:
//!
//! - `instance_id`: this device's instance ID, made once and shared by all
//!   networks; it changes only when the directory is removed.
//! - `keys/<network>.key`: each network's static key (named by a digest of
//!   `network.name`, readable by the owner only), unless the configuration
//!   carries `node.private_key`. Keys stay when a network leaves the list,
//!   so that taking it back keeps the key the panel already lists.

use std::io;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use outbound_mesh::config::encode_key;
use outbound_mesh::dns::DnsSettings;
use outbound_mesh::driver::{Listeners, Snapshot};
use outbound_mesh::secure::noise::KeyPair;
use outbound_mesh::status::{
    Alert, AlertCode, ApplyError, BoxFuture, FailureCode, ManagedNetwork, ManagedNetworkStatus,
    ManagedPeer, ManagedStatus, MeshControl, NetworkFailure, NetworkStaticKey,
};
use outbound_mesh::MeshSettings;
use ring::rand::{SecureRandom, SystemRandom};
use sha2::{Digest, Sha256};
use tokio::sync::{oneshot, watch};
use tokio::task::JoinHandle;

use crate::serve::{self, Failure};
use crate::tun::{self, Tun};

/// Features this implementation adds to `GET /v1/status`. `mesh_dns` and
/// `mesh_resolver_address`: each network's `dns` section, with the
/// resolver address answered on the network's interface (spec §15.9.2).
/// `mesh_native_keys`
/// is listed because `network.kind` and `native_keys` are handled as spec
/// §8.3.1 asks: admission, waiting for the list (`native_keys_pending`),
/// refusing members off the list (`peer_not_native`) and `static_keys`.
pub const FEATURES: &[&str] = &[
    "mesh",
    "mesh_dns",
    "mesh_resolver_address",
    "mesh_native_keys",
];

/// Interface names: `anixmesh-<n>`, the lowest number free.
const INTERFACE_PREFIX: &str = "anixmesh-";

/// How long a stopped network may take to close before it is cut off.
const STOP_TIMEOUT: Duration = Duration::from_secs(5);

/// The managed mesh of one node program.
pub struct ManagedMesh {
    inner: Arc<Inner>,
}

struct Inner {
    dir: PathBuf,
    instance_id: String,
    networks: Mutex<Vec<Instance>>,
}

struct Instance {
    tag: String,
    settings: MeshSettings,
    /// The network's static public key; `None` when it could not be read.
    /// Listed in `static_keys` in the secure mode only.
    public: Option<[u8; 32]>,
    state: State,
}

enum State {
    /// A managed network whose native key list lacks this node; the
    /// detail is `empty` or `self_missing`.
    Waiting(&'static str),
    /// The network could not start.
    Refused(FailureCode, String),
    Running(Running),
}

struct Running {
    interface: String,
    /// Dropping or sending stops the network.
    stop: Option<oneshot::Sender<()>>,
    native_keys: watch::Sender<Option<Vec<[u8; 32]>>>,
    dns: watch::Sender<DnsSettings>,
    snapshot: watch::Receiver<Snapshot>,
    /// Why the network stopped on its own, once it has.
    exit: Arc<Mutex<Option<String>>>,
    task: JoinHandle<()>,
}

impl ManagedMesh {
    /// Opens the state directory `dir`, creating it and the instance ID
    /// when they are missing.
    pub fn open(dir: impl Into<PathBuf>) -> io::Result<Self> {
        let dir = dir.into();
        create_private_dir(&dir)?;
        create_private_dir(&dir.join("keys"))?;
        let instance_id = instance_id(&dir.join("instance_id"))?;
        Ok(Self {
            inner: Arc::new(Inner {
                dir,
                instance_id,
                networks: Mutex::new(Vec::new()),
            }),
        })
    }

    /// This device's instance ID.
    pub fn instance_id(&self) -> &str {
        &self.inner.instance_id
    }
}

impl Inner {
    fn key_path(&self, network: &str) -> PathBuf {
        let digest = Sha256::digest(network.as_bytes());
        let name: String = digest[..16].iter().map(|b| format!("{b:02x}")).collect();
        self.dir.join("keys").join(format!("{name}.key"))
    }

    fn static_key(&self, settings: &MeshSettings) -> Result<KeyPair, Failure> {
        match &settings.private_key {
            Some(private) => Ok(KeyPair::from_private(**private)),
            None => serve::static_key(&self.key_path(&settings.network_name)),
        }
    }

    async fn replace(&self, wanted: Vec<ManagedNetwork>) -> ManagedStatus {
        let mut current: Vec<Instance> = std::mem::take(&mut *lock(&self.networks));
        let mut next: Vec<Option<Instance>> = Vec::with_capacity(wanted.len());
        let mut starts = Vec::new();
        let mut stopping = Vec::new();
        for (index, network) in wanted.into_iter().enumerate() {
            let previous = current
                .iter()
                .position(|instance| instance.tag == network.tag)
                .map(|at| current.remove(at));
            let previous = previous.map(|mut instance| {
                let kept = keep(&mut instance, &network.settings);
                (instance, kept)
            });
            match previous {
                Some((instance, true)) => next.push(Some(instance)),
                Some((instance, false)) => {
                    stopping.push(instance);
                    next.push(None);
                    starts.push((index, network));
                }
                None => {
                    next.push(None);
                    starts.push((index, network));
                }
            }
        }
        // Whatever leaves or restarts stops first, so that its ports and
        // interface name are free for the networks that start.
        stopping.append(&mut current);
        for instance in stopping {
            stop(instance).await;
        }
        let mut taken: Vec<String> = next
            .iter()
            .flatten()
            .filter_map(|instance| match &instance.state {
                State::Running(running) => Some(running.interface.clone()),
                _ => None,
            })
            .collect();
        for (index, network) in starts {
            let instance = self.start(network, &mut taken).await;
            next[index] = Some(instance);
        }
        let networks: Vec<Instance> = next.into_iter().flatten().collect();
        let status = self.describe(&networks);
        *lock(&self.networks) = networks;
        status
    }

    async fn start(&self, network: ManagedNetwork, taken: &mut Vec<String>) -> Instance {
        let ManagedNetwork { tag, settings } = network;
        let key = match self.static_key(&settings) {
            Ok(key) => key,
            Err(failure) => {
                return Instance {
                    tag,
                    settings,
                    public: None,
                    state: State::Refused(FailureCode::StartRefused, failure.detail().to_owned()),
                }
            }
        };
        let public = key.public();
        let instance = |settings, state| Instance {
            tag: tag.clone(),
            settings,
            public: Some(public),
            state,
        };
        if settings.waits_for_native_keys(&public) {
            let detail = waiting_detail(&settings);
            return instance(settings, State::Waiting(detail));
        }
        match launch(&settings, key, taken).await {
            Ok(running) => {
                taken.push(running.interface.clone());
                instance(settings, State::Running(running))
            }
            Err((code, detail)) => instance(settings, State::Refused(code, detail)),
        }
    }

    fn describe(&self, networks: &[Instance]) -> ManagedStatus {
        ManagedStatus {
            instance_id: self.instance_id.clone(),
            networks: networks.iter().map(network_status).collect(),
            static_keys: networks
                .iter()
                .filter(|instance| instance.settings.security.has_forward_secrecy())
                .filter_map(|instance| {
                    instance.public.map(|public| NetworkStaticKey {
                        network: instance.settings.network_name.clone(),
                        static_key: encode_key(&public),
                    })
                })
                .collect(),
        }
    }
}

impl MeshControl for ManagedMesh {
    fn features(&self) -> &'static [&'static str] {
        FEATURES
    }

    fn status(&self) -> ManagedStatus {
        self.inner.describe(&lock(&self.inner.networks))
    }

    /// Runs on a task of its own, so that a caller that goes away midway
    /// does not leave the networks half replaced.
    fn apply(
        &self,
        networks: Vec<ManagedNetwork>,
    ) -> BoxFuture<'_, Result<ManagedStatus, ApplyError>> {
        let inner = Arc::clone(&self.inner);
        Box::pin(async move {
            tokio::spawn(async move { inner.replace(networks).await })
                .await
                .map_err(|error| ApplyError::Failed(format!("mesh apply: {error}")))
        })
    }
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Whether `instance` can go on under `settings` without a restart: the
/// same settings, or, while it runs, the same but for the native key list
/// and the `dns` section, which are handed to the running driver. A
/// network that failed to start is tried again. `false` means the
/// instance is to be stopped.
fn keep(instance: &mut Instance, settings: &MeshSettings) -> bool {
    let same = instance.settings == *settings;
    let update = match &instance.state {
        State::Waiting(_) => same,
        State::Refused(..) => false,
        State::Running(running) if !running_ok(running) => false,
        State::Running(running) => {
            if same {
                true
            } else if same_but_hot(&instance.settings, settings)
                && instance
                    .public
                    .is_some_and(|public| !settings.waits_for_native_keys(&public))
            {
                if instance.settings.native_keys != settings.native_keys {
                    let _ = running.native_keys.send(settings.native_keys.clone());
                }
                if instance.settings.dns != settings.dns {
                    let _ = running.dns.send(settings.dns.clone());
                }
                true
            } else {
                false
            }
        }
    };
    if update {
        instance.settings = settings.clone();
    }
    update
}

fn running_ok(running: &Running) -> bool {
    !running.task.is_finished()
}

/// The same settings but for what a running node takes without a restart:
/// the native key list and the `dns` section.
fn same_but_hot(old: &MeshSettings, new: &MeshSettings) -> bool {
    let mut old = old.clone();
    old.native_keys.clone_from(&new.native_keys);
    old.dns.clone_from(&new.dns);
    old == *new
}

fn waiting_detail(settings: &MeshSettings) -> &'static str {
    match &settings.native_keys {
        Some(keys) if !keys.is_empty() => "self_missing",
        _ => "empty",
    }
}

async fn stop(instance: Instance) {
    if let State::Running(mut running) = instance.state {
        if let Some(stop) = running.stop.take() {
            let _ = stop.send(());
        }
        if tokio::time::timeout(STOP_TIMEOUT, &mut running.task)
            .await
            .is_err()
        {
            running.task.abort();
        }
    }
}

/// Binds, creates the interface and starts the driver of one network.
async fn launch(
    settings: &MeshSettings,
    key: KeyPair,
    taken: &[String],
) -> Result<Running, (FailureCode, String)> {
    let (address, address_v6) = tun::addresses(
        settings.address.address(),
        settings.address.prefix(),
        settings
            .address_v6
            .map(|address| (address.address(), address.prefix())),
    )
    .ok_or_else(|| {
        (
            FailureCode::StartRefused,
            "virtual address families are wrong".to_owned(),
        )
    })?;
    let interface = (0..)
        .map(|n| format!("{INTERFACE_PREFIX}{n}"))
        .find(|name| !taken.contains(name))
        .unwrap_or_default();
    let listeners = Listeners::bind(settings)
        .await
        .map_err(|error| refusal("listen", &error, FailureCode::PortInUse))?;
    let device = Tun::create(&interface, address, address_v6, settings.mtu).map_err(|error| {
        refusal(
            &format!("interface {interface}"),
            &error,
            FailureCode::TunInUse,
        )
    })?;

    let (stop, stopped) = oneshot::channel::<()>();
    let (native_keys, keys) = watch::channel(settings.native_keys.clone());
    let (dns, dns_settings) = watch::channel(settings.dns.clone());
    let (snapshots, snapshot) = watch::channel(Snapshot::default());
    let exit = Arc::new(Mutex::new(None));
    let exit_of_task = Arc::clone(&exit);
    let settings = settings.clone();
    let task = tokio::spawn(async move {
        let until = async {
            let _ = stopped.await;
        };
        let result = serve::serve_with(
            settings,
            key,
            listeners,
            device,
            until,
            keys,
            dns_settings,
            move |next, _| {
                snapshots.send_replace(next.clone());
            },
        )
        .await;
        if let Err(failure) = result {
            *lock(&exit_of_task) = Some(failure.detail().to_owned());
        }
    });
    Ok(Running {
        interface,
        stop: Some(stop),
        native_keys,
        dns,
        snapshot,
        exit,
        task,
    })
}

/// A start failure: `busy` when the resource is taken.
fn refusal(what: &str, error: &io::Error, busy: FailureCode) -> (FailureCode, String) {
    let code = match error.kind() {
        io::ErrorKind::AddrInUse | io::ErrorKind::ResourceBusy => busy,
        io::ErrorKind::PermissionDenied => FailureCode::PermissionDenied,
        _ if error.raw_os_error() == Some(libc::EBUSY) => busy,
        _ if error.raw_os_error() == Some(libc::EPERM) => FailureCode::PermissionDenied,
        _ => FailureCode::StartRefused,
    };
    (code, format!("{what}: {error}"))
}

fn network_status(instance: &Instance) -> ManagedNetworkStatus {
    fn failure(code: FailureCode, detail: &str) -> Option<NetworkFailure> {
        Some(NetworkFailure {
            code,
            detail: detail.to_owned(),
        })
    }
    fn start_refused(detail: &str) -> Alert {
        Alert {
            code: AlertCode::StartRefused,
            address: None,
            peer: String::new(),
            detail: detail.to_owned(),
        }
    }
    let mut status = ManagedNetworkStatus::stopped(instance.tag.clone(), "");
    status.forward_secrecy = instance.settings.security.has_forward_secrecy();
    match &instance.state {
        State::Waiting(detail) => {
            status.error = "native_keys_pending".to_owned();
            status.failure = failure(FailureCode::NativeKeysPending, detail);
        }
        State::Refused(code, detail) => {
            status.error.clone_from(detail);
            status.failure = failure(*code, detail);
            status.alerts.push(start_refused(detail));
        }
        State::Running(running) => {
            if let Some(exit) = lock(&running.exit).clone() {
                status.error.clone_from(&exit);
                status.failure = failure(FailureCode::StartRefused, &exit);
                status.alerts.push(start_refused(&exit));
                return status;
            }
            if running.task.is_finished() {
                status.error = "stopped".to_owned();
                return status;
            }
            let snapshot = running.snapshot.borrow();
            fill_running(&mut status, &instance.settings, &snapshot);
        }
    }
    status
}

/// The status of a running network from its driver's snapshot.
fn fill_running(status: &mut ManagedNetworkStatus, settings: &MeshSettings, snapshot: &Snapshot) {
    status.running = true;
    status.address = Some(settings.address);
    let address_of = |peer: u32| -> Option<IpAddr> {
        snapshot
            .members
            .iter()
            .find(|member| member.peer_id == peer)
            .and_then(|member| member.addresses.first().copied())
    };
    status.peers = snapshot
        .members
        .iter()
        .filter_map(|member| {
            Some(ManagedPeer {
                address: *member.addresses.first()?,
                subnets: member.subnets.clone(),
                via: member
                    .via
                    .iter()
                    .filter_map(|&relay| address_of(relay))
                    .collect(),
                hops: member.hops,
                latency_ms: member.latency_ms,
                forward_secrecy: status.forward_secrecy,
            })
        })
        .collect();
    status.failure = snapshot.not_native.map(|peer| NetworkFailure {
        code: FailureCode::PeerNotNative,
        detail: peer.to_string(),
    });
    status.rejected_advertisements = snapshot.rejected_advertisements;
    status.overlaps.clone_from(&snapshot.overlaps);
    status.alerts = snapshot
        .address_conflicts
        .iter()
        .map(|&(_, address)| Alert {
            code: AlertCode::AddressConflict,
            address: Some(address),
            peer: String::new(),
            detail: String::new(),
        })
        .collect();
    // The panel's resolver address is this node's own: it is not
    // intercepted (spec §15.9.2 item 8).
    if snapshot
        .names
        .as_ref()
        .is_some_and(|names| names.resolver_conflict())
    {
        status.alerts.push(Alert {
            code: AlertCode::ResolverAddressConflict,
            address: settings.dns.resolver_address,
            peer: String::new(),
            detail: String::new(),
        });
    }
}

fn create_private_dir(dir: &Path) -> io::Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    match std::fs::DirBuilder::new().mode(0o700).create(dir) {
        Err(error) if error.kind() != io::ErrorKind::AlreadyExists => Err(error),
        _ => Ok(()),
    }
}

/// Whether `id` is an instance ID as the management API gives it:
/// `^[0-9A-Za-z][0-9A-Za-z-]{0,63}$`.
pub fn valid_instance_id(id: &str) -> bool {
    let bytes = id.as_bytes();
    (1..=64).contains(&bytes.len())
        && bytes[0].is_ascii_alphanumeric()
        && bytes
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || *b == b'-')
}

/// Reads the instance ID at `path`, or makes one: 32 lowercase hex digits
/// from the system's randomness, written next to a temporary file and
/// renamed into place.
fn instance_id(path: &Path) -> io::Result<String> {
    match std::fs::read_to_string(path) {
        Ok(text) => {
            let id = text.trim();
            if valid_instance_id(id) {
                return Ok(id.to_owned());
            }
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("{}: not an instance ID", path.display()),
            ));
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    let mut bytes = [0u8; 16];
    SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| io::Error::other("no system randomness"))?;
    let id: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    let temporary = path.with_extension("tmp");
    std::fs::write(&temporary, format!("{id}\n"))?;
    std::fs::rename(&temporary, path)?;
    Ok(id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use outbound_mesh::driver::Member;
    use outbound_mesh::{IpNet, MeshConfig};
    use serde_json::json;

    /// A managed network of the secure mode, without a native key list.
    fn settings() -> MeshSettings {
        let config = json!({
            "config_version": 1,
            "network": {"name": "office", "secret": "s3cret"},
            "node": {"address": "10.150.0.5/16", "role": "full"},
            "peers": [{"server": "203.0.113.10", "port": 11010}],
        });
        serde_json::from_value::<MeshConfig>(config)
            .unwrap()
            .validate()
            .unwrap()
    }

    fn temp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("mesh-managed-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    #[test]
    fn the_instance_id_is_made_once_and_kept() {
        let dir = temp_dir("id");
        let first = ManagedMesh::open(&dir).expect("open");
        assert!(valid_instance_id(first.instance_id()));
        assert_eq!(first.instance_id().len(), 32);
        let again = ManagedMesh::open(&dir).expect("open again");
        assert_eq!(first.instance_id(), again.instance_id());
        std::fs::write(dir.join("instance_id"), "-bad").unwrap();
        assert!(ManagedMesh::open(&dir).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn instance_ids_follow_the_contract() {
        for id in ["a", "0f3c", "node-1", &"a".repeat(64)] {
            assert!(valid_instance_id(id), "{id}");
        }
        for id in ["", "-a", "a_b", "a b", &"a".repeat(65)] {
            assert!(!valid_instance_id(id), "{id}");
        }
    }

    #[test]
    fn keys_are_kept_per_network_name() {
        let dir = temp_dir("keys");
        let mesh = ManagedMesh::open(&dir).expect("open");
        let office = settings();
        let first = mesh.inner.static_key(&office).unwrap().public();
        assert_eq!(mesh.inner.static_key(&office).unwrap().public(), first);
        let mut other = office.clone();
        other.network_name = "lab".into();
        assert_ne!(mesh.inner.static_key(&other).unwrap().public(), first);
        let path = mesh.inner.key_path("office");
        assert!(path.starts_with(dir.join("keys")));
        assert!(!path.to_string_lossy().contains("office"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn a_managed_network_off_its_list_waits_and_lists_its_key() {
        let dir = temp_dir("wait");
        let mesh = ManagedMesh::open(&dir).expect("open");
        let waiting = settings();
        let status = mesh
            .apply(vec![ManagedNetwork {
                tag: "mesh-cn".into(),
                settings: waiting,
            }])
            .await
            .unwrap();
        let network = &status.networks[0];
        assert!(!network.running);
        assert_eq!(
            network.failure,
            Some(NetworkFailure {
                code: FailureCode::NativeKeysPending,
                detail: "empty".into()
            })
        );
        assert_eq!(status.static_keys.len(), 1);
        assert_eq!(status.static_keys[0].network, "office");
        assert_eq!(status.instance_id, mesh.instance_id());
        assert_eq!(mesh.status(), status);

        let stopped = mesh.apply(Vec::new()).await.unwrap();
        assert!(stopped.networks.is_empty() && stopped.static_keys.is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn only_native_key_and_dns_changes_keep_a_network_running() {
        let base = settings();
        let mut listed = base.clone();
        listed.native_keys = Some(vec![[1; 32], [2; 32]]);
        assert!(same_but_hot(&base, &listed));
        let mut named = listed.clone();
        named.dns.enabled = true;
        named.dns.resolver_address = Some("10.150.255.254".parse().unwrap());
        assert!(same_but_hot(&base, &named));
        let mut moved = named.clone();
        moved.mtu -= 10;
        assert!(!same_but_hot(&base, &moved));
        assert_eq!(waiting_detail(&base), "empty");
        assert_eq!(waiting_detail(&listed), "self_missing");
    }

    #[test]
    fn a_running_status_names_members_by_address() {
        let base = settings();
        let member = |peer_id, address: &str, via: Vec<u32>, hops| Member {
            peer_id,
            addresses: vec![address.parse().unwrap()],
            subnets: Vec::new(),
            via,
            hops,
            latency_ms: (hops == 1).then_some(7),
        };
        let snapshot = Snapshot {
            members: vec![
                member(3, "10.150.0.3", Vec::new(), 1),
                member(9, "10.150.0.9", vec![3], 2),
                Member {
                    addresses: Vec::new(),
                    ..member(12, "10.150.0.12", Vec::new(), 1)
                },
            ],
            not_native: Some(44),
            rejected_advertisements: 2,
            overlaps: vec![IpNet::parse("192.168.1.0/24").unwrap()],
            address_conflicts: vec![(9, "10.150.0.5".parse().unwrap())],
            ..Snapshot::default()
        };
        let mut status = ManagedNetworkStatus::stopped("mesh-cn", "");
        fill_running(&mut status, &base, &snapshot);
        assert!(status.running);
        assert_eq!(status.address, Some(base.address));
        assert_eq!(status.peers.len(), 2);
        assert_eq!(
            status.peers[1].via,
            ["10.150.0.3".parse::<IpAddr>().unwrap()]
        );
        assert_eq!(status.peers[0].latency_ms, Some(7));
        assert_eq!(status.peers[1].latency_ms, None);
        assert_eq!(status.failure.as_ref().unwrap().detail, "44");
        assert_eq!(status.rejected_advertisements, 2);
        assert_eq!(status.alerts[0].code, AlertCode::AddressConflict);
    }
}
