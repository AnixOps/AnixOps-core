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
//!
//! A border node's request also carries a `backbone` section; its backbone
//! runs beside the networks and meets its region network through that
//! network's hub ([`crate::border`]).
//! External network bridges (spec §15.12, `docs/architecture/mesh-bridge.md`)
//! run beside the networks that carry an `external_bridge` section. The
//! node takes the host's bridge lock, probes nftables and clears what an
//! earlier run left before it lists `mesh_external_bridge`, and clears
//! again when it goes.

use std::collections::BTreeMap;
use std::io;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use mesh_bridge::apply::{ALERT_APPLY_FAILED, ALERT_IPV6_FORWARDING_OFF};
use mesh_bridge::{
    ApplyError as BridgeApplyError, Bridge, Forwarding, Host as BridgeHost, HostLock, SystemHost,
};
use outbound_mesh::bridge::ExternalBridge;
use outbound_mesh::config::encode_key;
use outbound_mesh::driver::{Listeners, Snapshot};
use outbound_mesh::node::SyncOversize;
use outbound_mesh::secure::noise::KeyPair;
use outbound_mesh::status::{
    Alert, AlertCode, ApplyError, BoxFuture, ExternalBridgeStatus, FailureCode, ManagedBackbone,
    ManagedNetwork, ManagedNetworkStatus, ManagedPeer, ManagedStatus, MeshControl, NetworkFailure,
    NetworkStaticKey,
};
use outbound_mesh::{IpNet, MeshSettings};
use ring::rand::{SecureRandom, SystemRandom};
use sha2::{Digest, Sha256};
use tokio::sync::{oneshot, watch};
use tokio::task::JoinHandle;

use crate::border::{BorderInstance, Hub, RegionView};
use crate::serve::{self, AbortOnDrop, Failure, HostRoutes};
use crate::tun::{self, Tun};

/// Features this implementation adds to `GET /v1/status`. `mesh_native_keys`
/// is listed because `network.kind` and `native_keys` are handled as spec
/// §8.3.1 asks: admission, waiting for the list (`native_keys_pending`),
/// refusing members off the list (`peer_not_native`) and `static_keys`.
/// `mesh_backbone`: `PUT /v1/mesh` takes the top-level `backbone` section
/// and `GET /v1/mesh` gives its status (spec §17.3, appendix B and C).
pub const FEATURES: &[&str] = &["mesh", "mesh_native_keys", "mesh_backbone"];

/// [`FEATURES`] once this process can bridge: it holds the host's bridge
/// lock, nftables took the probe and the start-up cleanup ran.
pub const FEATURES_WITH_BRIDGE: &[&str] = &["mesh", "mesh_native_keys", mesh_bridge::FEATURE];

/// Interface names: `anixmesh-<n>`, the lowest number free.
const INTERFACE_PREFIX: &str = "anixmesh-";

/// How long a stopped network may take to close before it is cut off.
const STOP_TIMEOUT: Duration = Duration::from_secs(5);

/// A running network that has reached none of its configured peers for
/// this long reports `unreachable_peers`.
const UNREACHABLE_AFTER: Duration = Duration::from_secs(30);

/// The managed mesh of one node program.
pub struct ManagedMesh {
    inner: Arc<Inner>,
}

struct Inner {
    dir: PathBuf,
    instance_id: String,
    networks: Mutex<Vec<Instance>>,
    /// One per network of the last request, by tag.
    hubs: Mutex<BTreeMap<String, Arc<Hub>>>,
    backbone: Mutex<Option<BorderInstance>>,
    bridging: Bridging,
    /// Held by the task that replaces the networks, not by the request:
    /// a request that times out does not let the next one start while
    /// the first is still at work.
    applying: tokio::sync::Mutex<()>,
    /// The status from before the replacement in progress, given while
    /// the networks are being replaced.
    previous: Mutex<Option<ManagedStatus>>,
    /// The system routes the running networks installed.
    routes: HostRoutes,
}

/// The host side of external bridges.
struct Bridging {
    host: Arc<dyn BridgeHost>,
    forwarding: Arc<Forwarding>,
    /// Held while this process may bridge; `None`: it does not.
    lock: Option<HostLock>,
    /// Another process holds the host's bridge lock.
    lock_held: bool,
}

impl Bridging {
    /// No bridges (tests, and hosts where the checks below fail).
    fn off() -> Self {
        let host: Arc<dyn BridgeHost> = Arc::new(SystemHost);
        Self {
            forwarding: Forwarding::new(host.clone()),
            host,
            lock: None,
            lock_held: false,
        }
    }

    /// Spec §15.12 item 9 and the recheck of #357 (Y1, Y2): the host lock
    /// first, so that a second node program neither declares the
    /// capability nor deletes the first one's tables; then the nftables
    /// probe; then the start-up cleanup of what an earlier run left.
    fn system() -> Self {
        let mut bridging = Self::off();
        let lock = match HostLock::acquire() {
            Ok(lock) => lock,
            Err(error) => {
                bridging.lock_held = error.kind() == io::ErrorKind::WouldBlock;
                eprintln!("mesh: external bridge unavailable: {error}");
                return bridging;
            }
        };
        if let Err(error) = mesh_bridge::probe(bridging.host.as_ref()) {
            eprintln!("mesh: external bridge unavailable: nftables probe: {error}");
            return bridging;
        }
        match mesh_bridge::cleanup_all(bridging.host.as_ref()) {
            Ok(0) => {}
            Ok(count) => eprintln!("mesh: removed {count} bridge table(s) an earlier run left"),
            Err(error) => {
                eprintln!("mesh: external bridge unavailable: start-up cleanup: {error}");
                return bridging;
            }
        }
        bridging.lock = Some(lock);
        bridging
    }

    fn available(&self) -> bool {
        self.lock.is_some()
    }
}

impl Drop for Inner {
    /// At exit the bridges go first (each removes its own table), then the
    /// cleanup runs once more (spec §15.12 item 9).
    fn drop(&mut self) {
        lock(&self.networks).clear();
        if self.bridging.available() {
            if let Err(error) = mesh_bridge::cleanup_all(self.bridging.host.as_ref()) {
                eprintln!("mesh: bridge cleanup at exit: {error}");
            }
        }
    }
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
    Running(Box<Running>),
}

struct Running {
    interface: String,
    /// Dropping or sending stops the network.
    stop: Option<oneshot::Sender<()>>,
    native_keys: watch::Sender<Option<Vec<[u8; 32]>>>,
    snapshot: watch::Receiver<Snapshot>,
    /// Why the network stopped on its own, once it has.
    exit: Arc<Mutex<Option<String>>>,
    task: JoinHandle<()>,
    /// The network's external bridge, when it has one.
    bridge: Option<Bridge>,
    started: Instant,
}

impl ManagedMesh {
    /// Opens the state directory `dir`, creating it and the instance ID
    /// when they are missing.
    pub fn open(dir: impl Into<PathBuf>) -> io::Result<Self> {
        Self::open_with(dir, Bridging::system())
    }

    fn open_with(dir: impl Into<PathBuf>, bridging: Bridging) -> io::Result<Self> {
        let dir = dir.into();
        create_private_dir(&dir)?;
        create_private_dir(&dir.join("keys"))?;
        let instance_id = instance_id(&dir.join("instance_id"))?;
        Ok(Self {
            inner: Arc::new(Inner {
                dir,
                instance_id,
                networks: Mutex::new(Vec::new()),
                hubs: Mutex::new(BTreeMap::new()),
                backbone: Mutex::new(None),
                bridging,
                applying: tokio::sync::Mutex::new(()),
                previous: Mutex::new(None),
                routes: HostRoutes::default(),
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

    /// Takes the running networks for a replacement; until
    /// [`Inner::finish`] the status still describes them.
    fn take_for_replace(&self) -> Vec<Instance> {
        let mut networks = lock(&self.networks);
        let mut previous = lock(&self.previous);
        if previous.is_none() {
            *previous = Some(self.describe(&networks));
        }
        std::mem::take(&mut *networks)
    }

    fn finish(&self, networks: Vec<Instance>) {
        *lock(&self.networks) = networks;
        *lock(&self.previous) = None;
    }

    fn status(&self) -> ManagedStatus {
        if let Some(previous) = lock(&self.previous).clone() {
            return previous;
        }
        self.describe(&lock(&self.networks))
    }

    async fn replace(
        &self,
        wanted: Vec<ManagedNetwork>,
        backbone: Option<ManagedBackbone>,
    ) -> ManagedStatus {
        // The status keeps describing the backbone being replaced too
        // (`replace_networks` clears it when done).
        {
            let networks = lock(&self.networks);
            *lock(&self.previous) = Some(self.describe(&networks));
        }
        // The backbone first: one that stays keeps running through the
        // network changes, the others stop before their network does.
        let current_backbone = lock(&self.backbone).take();
        let kept_backbone = match current_backbone {
            Some(mut running) => {
                if backbone.as_ref().is_some_and(|next| running.keep(next)) {
                    Some(running)
                } else {
                    let hub = lock(&self.hubs).get(&running.tag).cloned();
                    running.stop(hub.as_deref()).await;
                    None
                }
            }
            None => None,
        };
        let backbone = if kept_backbone.is_some() {
            None
        } else {
            backbone
        };
        let tags: Vec<String> = wanted.iter().map(|network| network.tag.clone()).collect();
        {
            let mut hubs = lock(&self.hubs);
            for tag in &tags {
                hubs.entry(tag.clone()).or_insert_with(Hub::new);
            }
        }
        let mut status = self.replace_networks(wanted).await;
        {
            let mut hubs = lock(&self.hubs);
            hubs.retain(|tag, hub| {
                let stays = tags.contains(tag);
                if !stays {
                    hub.withdraw();
                }
                stays
            });
        }
        let started = backbone.map(|backbone| {
            let tag = format!(
                "{}{}",
                outbound_mesh::status::TAG_PREFIX,
                backbone.settings.region
            );
            // The management API checked that the region network is in the
            // request, so its hub exists.
            let hub = lock(&self.hubs).get(&tag).cloned().unwrap_or_else(Hub::new);
            BorderInstance::start(backbone, &hub)
        });
        *lock(&self.backbone) = kept_backbone.or(started);
        status.backbone = lock(&self.backbone).as_ref().map(BorderInstance::status);
        status
    }

    async fn replace_networks(&self, wanted: Vec<ManagedNetwork>) -> ManagedStatus {
        // Should the replacement fail midway, the status stops describing
        // networks that are gone.
        struct Finished<'a>(&'a Inner);
        impl Drop for Finished<'_> {
            fn drop(&mut self) {
                *lock(&self.0.previous) = None;
            }
        }
        let _finished = Finished(self);
        let mut current: Vec<Instance> = self.take_for_replace();
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
            if let Some(hub) = lock(&self.hubs).get(&instance.tag) {
                hub.publish_region(RegionView::default());
            }
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
        // The virtual subnets in use: no two networks share one (spec
        // §15.4), or packets for one would go into the other.
        let mut occupied: Vec<IpNet> = next
            .iter()
            .flatten()
            .filter(|instance| matches!(instance.state, State::Running(_)))
            .flat_map(|instance| virtual_subnets(&instance.settings))
            .collect();
        for (index, network) in starts {
            let instance = self.start(network, &mut taken, &occupied).await;
            if let State::Running(_) = instance.state {
                occupied.extend(virtual_subnets(&instance.settings));
            }
            next[index] = Some(instance);
        }
        let networks: Vec<Instance> = next.into_iter().flatten().collect();
        let status = self.describe(&networks);
        self.finish(networks);
        status
    }

    async fn start(
        &self,
        network: ManagedNetwork,
        taken: &mut Vec<String>,
        occupied: &[IpNet],
    ) -> Instance {
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
        if let Some((code, detail)) = clash(&settings, occupied) {
            return instance(settings, State::Refused(code, detail));
        }
        let hub = lock(&self.hubs).get(&tag).cloned().unwrap_or_else(Hub::new);
        match launch(&settings, key, taken, &self.routes, &tag, hub).await {
            Ok(mut running) => {
                if let Some(section) = &settings.external_bridge {
                    if let Err(detail) = self.bridge_up(&mut running, section, &settings) {
                        stop_running(running).await;
                        return instance(
                            settings,
                            State::Refused(FailureCode::StartRefused, detail),
                        );
                    }
                }
                taken.push(running.interface.clone());
                instance(settings, State::Running(Box::new(running)))
            }
            Err((code, detail)) => instance(settings, State::Refused(code, detail)),
        }
    }

    /// Installs the bridge of a network that just started; the detail of
    /// the `start_refused` failure when it cannot.
    fn bridge_up(
        &self,
        running: &mut Running,
        section: &ExternalBridge,
        settings: &MeshSettings,
    ) -> Result<(), String> {
        if !self.bridging.available() {
            return Err(if self.bridging.lock_held {
                "external_bridge_lock_held".to_owned()
            } else {
                "external_bridge_unsupported".to_owned()
            });
        }
        let mut bridge = Bridge::new(
            self.bridging.host.clone(),
            self.bridging.forwarding.clone(),
            &running.interface,
        )
        .map_err(|error| error.reason().to_owned())?;
        bridge
            .apply(
                section,
                &settings.virtual_subnets(),
                &settings.local_addresses(),
            )
            .map_err(|error| bridge_failure(&error))?;
        running.bridge = Some(bridge);
        Ok(())
    }

    fn describe(&self, networks: &[Instance]) -> ManagedStatus {
        let lock_held = self.bridging.lock_held;
        ManagedStatus {
            instance_id: self.instance_id.clone(),
            networks: networks
                .iter()
                .map(|instance| {
                    let mut status = network_status(instance);
                    if lock_held {
                        // Unknown here: another process may bridge for it.
                        status.external_bridge = None;
                        status.alerts.push(lock_held_alert());
                    }
                    status
                })
                .collect(),
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
            backbone: lock(&self.backbone).as_ref().map(BorderInstance::status),
            alerts: if lock_held {
                vec![lock_held_alert()]
            } else {
                Vec::new()
            },
        }
    }
}

fn lock_held_alert() -> Alert {
    Alert {
        code: AlertCode::ExternalBridgeLockHeld,
        address: None,
        peer: String::new(),
        detail: mesh_bridge::lock::LOCK_PATH.to_owned(),
    }
}

/// The `start_refused` detail of a bridge that could not be installed:
/// the reason code, then nft's or the kernel's words.
fn bridge_failure(error: &BridgeApplyError) -> String {
    match error {
        BridgeApplyError::Invalid(error) => error.reason().to_owned(),
        BridgeApplyError::Host(error) => format!("{ALERT_APPLY_FAILED}: {error}"),
    }
}

impl MeshControl for ManagedMesh {
    fn features(&self) -> &'static [&'static str] {
        if self.inner.bridging.available() {
            FEATURES_WITH_BRIDGE
        } else {
            FEATURES
        }
    }

    /// While networks are being replaced: the status from before.
    fn status(&self) -> ManagedStatus {
        self.inner.status()
    }

    /// Runs on a task of its own, so that a caller that goes away midway
    /// does not leave the networks half replaced; the task, not the
    /// caller, holds the turn, so replacements never overlap.
    fn apply(
        &self,
        networks: Vec<ManagedNetwork>,
        backbone: Option<ManagedBackbone>,
    ) -> BoxFuture<'_, Result<ManagedStatus, ApplyError>> {
        let inner = Arc::clone(&self.inner);
        Box::pin(async move {
            tokio::spawn(async move {
                let _turn = inner.applying.lock().await;
                inner.replace(networks, backbone).await
            })
            .await
            .map_err(|error| {
                ApplyError::Failed(if error.is_panic() {
                    "mesh apply stopped unexpectedly".to_owned()
                } else {
                    format!("mesh apply: {error}")
                })
            })
        })
    }
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Whether `instance` can go on under `settings` without a restart: the
/// same settings, or, while it runs, the same but for the native key list,
/// which is handed to the running driver. A network that failed to start
/// is tried again. `false` means the instance is to be stopped.
fn keep(instance: &mut Instance, settings: &MeshSettings) -> bool {
    let same = instance.settings == *settings;
    let mut next = settings.clone();
    let update = match &mut instance.state {
        State::Waiting(_) => same,
        State::Refused(..) => false,
        State::Running(running) if !running_ok(running) => false,
        State::Running(running) => {
            if same {
                true
            } else if same_but_native_keys(&instance.settings, settings)
                && instance
                    .public
                    .is_some_and(|public| !settings.waits_for_native_keys(&public))
            {
                let _ = running.native_keys.send(settings.native_keys.clone());
                true
            } else if same_but_bridge_allow(&instance.settings, settings) {
                // Only the allow list moved: the bridge takes it without a
                // restart. If it fails, the old rules and status stay with
                // an alert, and the old list is kept so that the next PUT
                // tries again.
                if let (Some(bridge), Some(section)) =
                    (running.bridge.as_mut(), settings.external_bridge.as_ref())
                {
                    if bridge
                        .apply(
                            section,
                            &settings.virtual_subnets(),
                            &settings.local_addresses(),
                        )
                        .is_err()
                    {
                        next.external_bridge = instance.settings.external_bridge.clone();
                    }
                    true
                } else {
                    false
                }
            } else {
                false
            }
        }
    };
    if update {
        instance.settings = next;
    }
    update
}

/// Whether `new` differs from `old` only in the bridge's allow list: the
/// same interface and routes, so the advertisement does not move.
fn same_but_bridge_allow(old: &MeshSettings, new: &MeshSettings) -> bool {
    match (&old.external_bridge, &new.external_bridge) {
        (Some(before), Some(after))
            if before.interface() == after.interface() && before.routes() == after.routes() =>
        {
            let mut old = old.clone();
            old.external_bridge.clone_from(&new.external_bridge);
            old == *new
        }
        _ => false,
    }
}

fn running_ok(running: &Running) -> bool {
    !running.task.is_finished()
}

fn same_but_native_keys(old: &MeshSettings, new: &MeshSettings) -> bool {
    let mut old = old.clone();
    old.native_keys.clone_from(&new.native_keys);
    old == *new
}

fn waiting_detail(settings: &MeshSettings) -> &'static str {
    match &settings.native_keys {
        Some(keys) if !keys.is_empty() => "self_missing",
        _ => "empty",
    }
}

/// The virtual subnets of a network.
fn virtual_subnets(settings: &MeshSettings) -> Vec<IpNet> {
    std::iter::once(settings.address)
        .chain(settings.address_v6)
        .collect()
}

/// Why a network cannot start next to the running ones whose virtual
/// subnets are `occupied`: the same virtual address (`address_in_use`), or
/// overlapping subnets (`route_overlap`, the subnet as detail).
fn clash(settings: &MeshSettings, occupied: &[IpNet]) -> Option<(FailureCode, String)> {
    for own in virtual_subnets(settings) {
        for other in occupied {
            if other.address() == own.address() {
                return Some((FailureCode::AddressInUse, own.address().to_string()));
            }
            if other.trunc().overlaps(&own.trunc()) {
                return Some((FailureCode::RouteOverlap, own.trunc().to_string()));
            }
        }
    }
    None
}

async fn stop(instance: Instance) {
    if let State::Running(running) = instance.state {
        stop_running(*running).await;
    }
}

async fn stop_running(mut running: Running) {
    if let Some(mut bridge) = running.bridge.take() {
        // On failure the bridge's drop tries once more, and the next
        // start-up cleanup clears what is left.
        if let Err(error) = bridge.remove() {
            eprintln!(
                "mesh: removing the bridge of {}: {error}",
                running.interface
            );
        }
    }
    if let Some(stop) = running.stop.take() {
        let _ = stop.send(());
    }
    if tokio::time::timeout(STOP_TIMEOUT, &mut running.task)
        .await
        .is_err()
    {
        // Cutting the task off drops the serving, which aborts the
        // driver and frees its sockets and routes; wait for that.
        running.task.abort();
        let _ = (&mut running.task).await;
    }
}

/// Binds, creates the interface and starts the driver of one network.
async fn launch(
    settings: &MeshSettings,
    key: KeyPair,
    taken: &[String],
    routes: &HostRoutes,
    tag: &str,
    hub: Arc<Hub>,
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
    let (snapshots, snapshot) = watch::channel(Snapshot::default());
    let exit = Arc::new(Mutex::new(None));
    let exit_of_task = Arc::clone(&exit);
    let settings = settings.clone();
    let host = (routes.clone(), tag.to_owned());
    let task = tokio::spawn(async move {
        let until = async {
            let _ = stopped.await;
        };
        let border = hub.driver_side();
        let observed = settings.clone();
        // On a task of its own, so that a panic is seen and reported.
        let serving = tokio::spawn(serve::serve_with(
            settings,
            key,
            listeners,
            device,
            until,
            keys,
            Some(border),
            Some(host),
            move |next, _| {
                hub.publish_region(RegionView::of(&observed, next));
                snapshots.send_replace(next.clone());
            },
        ));
        let _cut_off_together = AbortOnDrop(serving.abort_handle());
        let exit = match serving.await {
            Ok(Ok(())) => None,
            Ok(Err(failure)) => Some(failure.detail().to_owned()),
            // The panic message is not shown: it may carry anything.
            Err(error) if error.is_panic() => Some("the network stopped unexpectedly".to_owned()),
            Err(error) => Some(error.to_string()),
        };
        if exit.is_some() {
            *lock(&exit_of_task) = exit;
        }
    });
    Ok(Running {
        interface,
        stop: Some(stop),
        native_keys,
        snapshot,
        exit,
        task,
        bridge: None,
        started: Instant::now(),
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
            // Nothing of a bridge stays for a network that did not start.
            status.external_bridge = Some(None);
        }
        State::Running(running) => {
            if let Some(exit) = lock(&running.exit).clone() {
                status.error.clone_from(&exit);
                status.failure = failure(FailureCode::StartRefused, &exit);
                status.alerts.push(start_refused(&exit));
            } else if running.task.is_finished() {
                status.error = "stopped".to_owned();
            } else {
                let snapshot = running.snapshot.borrow();
                fill_running(
                    &mut status,
                    &instance.settings,
                    &snapshot,
                    running.started.elapsed(),
                );
            }
            // The rules stay until the network is stopped or replaced.
            bridge_status(&mut status, running.bridge.as_ref());
        }
    }
    status
}

/// `externalBridge` and the bridge's alerts of a started network: `null`
/// without a bridge.
fn bridge_status(status: &mut ManagedNetworkStatus, bridge: Option<&Bridge>) {
    let Some(bridge) = bridge else {
        status.external_bridge = Some(None);
        return;
    };
    status.external_bridge = Some(bridge.status().map(|applied| ExternalBridgeStatus {
        allow_digest: applied.allow_digest.clone(),
        allow_count: applied.allow_count,
        routes_digest: applied.routes_digest.clone(),
        applied_at: applied.applied_at.clone(),
    }));
    for alert in bridge.alerts() {
        let code = match alert.code {
            ALERT_APPLY_FAILED => AlertCode::ExternalBridgeApplyFailed,
            ALERT_IPV6_FORWARDING_OFF => AlertCode::ExternalBridgeIpv6ForwardingOff,
            _ => continue,
        };
        status.alerts.push(Alert {
            code,
            address: None,
            peer: String::new(),
            detail: alert.detail,
        });
    }
}

/// The status of a running network from its driver's snapshot, `up` after
/// it started.
fn fill_running(
    status: &mut ManagedNetworkStatus,
    settings: &MeshSettings,
    snapshot: &Snapshot,
    up: Duration,
) {
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
    // One reason, the more pressing first: no configured peer reached,
    // then a refused member (docs/architecture/mesh-status.md).
    let unreachable =
        !settings.peers.is_empty() && snapshot.neighbours.is_empty() && up >= UNREACHABLE_AFTER;
    status.failure = if unreachable {
        Some(NetworkFailure {
            code: FailureCode::UnreachablePeers,
            detail: settings.peers.len().to_string(),
        })
    } else {
        snapshot.not_native.map(|peer| NetworkFailure {
            code: FailureCode::PeerNotNative,
            detail: peer.to_string(),
        })
    };
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
        .chain(snapshot.foreign_overlaps.iter().map(|subnet| Alert {
            code: AlertCode::ForeignRouteOverlap,
            address: None,
            peer: String::new(),
            detail: subnet.to_string(),
        }))
        .collect();
    for peer in &snapshot.refused_key_changes {
        status.alerts.push(Alert {
            code: AlertCode::PeerKeyChanged,
            address: address_of(*peer),
            peer: String::new(),
            detail: peer.to_string(),
        });
    }
    if snapshot.counters.oversize_rpc > 0 {
        status.alerts.push(Alert {
            code: AlertCode::RpcOversize,
            address: None,
            peer: String::new(),
            detail: snapshot.counters.oversize_rpc.to_string(),
        });
    }
    if snapshot.system_routes_truncated > 0 {
        status.alerts.push(Alert {
            code: AlertCode::SystemRoutesTruncated,
            address: None,
            peer: String::new(),
            detail: snapshot.system_routes_truncated.to_string(),
        });
    }
    if let Some(oversize) = snapshot.sync_oversize {
        let counters = &snapshot.counters;
        let detail = match oversize {
            SyncOversize::Received { peer, bytes } => format!(
                "received: rpc body of at least {bytes} bytes from node {peer} over the 8 MiB limit"
            ),
            SyncOversize::Undelivered { peer } => format!(
                "undelivered: connection graph not taken by node {peer} within 120 s, sync session closed"
            ),
        };
        status.alerts.push(Alert {
            code: AlertCode::SyncOversize,
            address: None,
            peer: String::new(),
            detail: format!(
                "{detail} ({} received over the limit, {} sessions closed)",
                counters.oversize_calls, counters.graph_timeouts
            ),
        });
    }
    let counters = &snapshot.counters;
    if counters.refused_at_capacity > 0 || counters.refused_over_budget > 0 {
        status.alerts.push(Alert {
            code: AlertCode::SyncOversize,
            address: None,
            peer: String::new(),
            detail: format!(
                "capacity: node table full ({} entries) or information budget (16 MiB) reached; \
                 {} refused or evicted at the table limit, {} refused over the budget",
                outbound_mesh::route::sync::MAX_NODES,
                counters.refused_at_capacity,
                counters.refused_over_budget
            ),
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

    /// Without the host's bridge lock, probe or cleanup.
    fn open(dir: &Path) -> io::Result<ManagedMesh> {
        ManagedMesh::open_with(dir, Bridging::off())
    }

    fn bridged(allow: &[&str]) -> MeshSettings {
        let config = json!({
            "config_version": 1,
            "network": {"name": "office", "secret": "s3cret"},
            "node": {"address": "10.150.0.5/16", "role": "full"},
            "peers": [{"server": "203.0.113.10", "port": 11010}],
            "external_bridge": {
                "interface": "ext0",
                "routes": ["100.100.0.5"],
                "allow": allow,
            },
        });
        serde_json::from_value::<MeshConfig>(config)
            .unwrap()
            .validate()
            .unwrap()
    }

    #[test]
    fn only_an_allow_list_change_keeps_a_bridge_running() {
        let before = bridged(&["10.150.0.2/32"]);
        let after = bridged(&["10.150.0.3/32"]);
        assert!(same_but_bridge_allow(&before, &after));
        let mut routes = after.clone();
        let mut config = json!({
            "config_version": 1,
            "network": {"name": "office", "secret": "s3cret"},
            "node": {"address": "10.150.0.5/16", "role": "full"},
            "peers": [{"server": "203.0.113.10", "port": 11010}],
            "external_bridge": {"interface": "ext0", "routes": ["100.100.0.6"]},
        });
        routes.external_bridge = serde_json::from_value::<MeshConfig>(config.take())
            .unwrap()
            .validate()
            .unwrap()
            .external_bridge;
        assert!(!same_but_bridge_allow(&before, &routes));
        assert!(!same_but_bridge_allow(&settings(), &after));
        let mut mtu = after.clone();
        mtu.mtu -= 10;
        assert!(!same_but_bridge_allow(&before, &mtu));
    }

    #[test]
    fn a_network_without_a_bridge_reports_null() {
        let mut status = ManagedNetworkStatus::stopped("mesh-cn", "");
        bridge_status(&mut status, None);
        assert_eq!(status.external_bridge, Some(None));
        assert!(status.alerts.is_empty());
    }

    #[tokio::test]
    async fn a_held_bridge_lock_is_a_node_alert_and_hides_the_capability() {
        let dir = temp_dir("lock");
        let bridging = Bridging {
            lock_held: true,
            ..Bridging::off()
        };
        let mesh = ManagedMesh::open_with(&dir, bridging).expect("open");
        assert_eq!(mesh.features(), FEATURES);
        // Also with no network at all.
        let status = mesh.status();
        assert!(status.networks.is_empty());
        assert_eq!(status.alerts.len(), 1);
        assert_eq!(status.alerts[0].code, AlertCode::ExternalBridgeLockHeld);
        let status = mesh
            .apply(
                vec![ManagedNetwork {
                    tag: "mesh-cn".into(),
                    settings: settings(),
                }],
                None,
            )
            .await
            .unwrap();
        let network = &status.networks[0];
        assert_eq!(network.external_bridge, None);
        assert!(network
            .alerts
            .iter()
            .any(|alert| alert.code == AlertCode::ExternalBridgeLockHeld));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn without_bridging_the_capability_is_not_listed() {
        let dir = temp_dir("features");
        let mesh = open(&dir).expect("open");
        assert_eq!(mesh.features(), FEATURES);
        assert!(!FEATURES.contains(&mesh_bridge::FEATURE));
        assert!(FEATURES_WITH_BRIDGE.contains(&mesh_bridge::FEATURE));
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn temp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("mesh-managed-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    #[test]
    fn the_instance_id_is_made_once_and_kept() {
        let dir = temp_dir("id");
        let first = open(&dir).expect("open");
        assert!(valid_instance_id(first.instance_id()));
        assert_eq!(first.instance_id().len(), 32);
        let again = open(&dir).expect("open again");
        assert_eq!(first.instance_id(), again.instance_id());
        std::fs::write(dir.join("instance_id"), "-bad").unwrap();
        assert!(open(&dir).is_err());
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
        let mesh = open(&dir).expect("open");
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
        let mesh = open(&dir).expect("open");
        let waiting = settings();
        let status = mesh
            .apply(
                vec![ManagedNetwork {
                    tag: "mesh-cn".into(),
                    settings: waiting,
                }],
                None,
            )
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

        assert_eq!(status.backbone, None);

        let stopped = mesh.apply(Vec::new(), None).await.unwrap();
        assert!(stopped.networks.is_empty() && stopped.static_keys.is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn backbone(kind: &str) -> ManagedBackbone {
        let config = json!({
            "id": 11,
            "region": "cn",
            "members": [
                { "id": 11, "region": "cn", "link": { "kind": kind } },
                { "id": 21, "region": "ap", "link": { "kind": kind, "params": { "key": "SECRET-VALUE" } } }
            ]
        });
        let config: outbound_mesh::backbone::BackboneConfig =
            serde_json::from_value(config).unwrap();
        ManagedBackbone {
            settings: config.validate().unwrap(),
            links: config.links(),
        }
    }

    #[tokio::test]
    async fn a_backbone_without_its_link_kind_reports_why_and_the_network_stays() {
        let dir = temp_dir("backbone");
        let mesh = ManagedMesh::open(&dir).expect("open");
        let network = || ManagedNetwork {
            tag: "mesh-cn".into(),
            settings: settings(),
        };
        let status = mesh
            .apply(vec![network()], Some(backbone("not-registered")))
            .await
            .unwrap();
        assert_eq!(status.networks.len(), 1);
        let backbone_status = status.backbone.clone().expect("backbone status");
        assert!(!backbone_status.running);
        assert_eq!(backbone_status.status.id, 11);
        assert_eq!(backbone_status.status.region, "cn");
        let failure = backbone_status.failure.expect("failure");
        assert_eq!(failure.code, "backbone_kind_unavailable");
        assert_eq!(failure.detail, "backbone.members[0].link.kind");
        let text = serde_json::to_string(&status).unwrap();
        assert!(!text.contains("SECRET-VALUE"), "{text}");
        assert_eq!(mesh.status(), status);
        assert!(FEATURES.contains(&"mesh_backbone"));

        // Without the section the backbone goes; the network stays.
        let status = mesh.apply(vec![network()], None).await.unwrap();
        assert_eq!(status.backbone, None);
        assert_eq!(status.networks.len(), 1);
        let _ = mesh.apply(Vec::new(), None).await.unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn only_a_native_key_change_keeps_a_network_running() {
        let base = settings();
        let mut listed = base.clone();
        listed.native_keys = Some(vec![[1; 32], [2; 32]]);
        assert!(same_but_native_keys(&base, &listed));
        let mut moved = listed.clone();
        moved.mtu -= 10;
        assert!(!same_but_native_keys(&base, &moved));
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
            foreign_overlaps: vec![IpNet::parse("192.168.1.0/24").unwrap()],
            address_conflicts: vec![(9, "10.150.0.5".parse().unwrap())],
            system_routes_truncated: 3,
            sync_oversize: Some(SyncOversize::Received {
                peer: 9,
                bytes: 8_400_000,
            }),
            ..Snapshot::default()
        };
        let mut status = ManagedNetworkStatus::stopped("mesh-cn", "");
        fill_running(&mut status, &base, &snapshot, Duration::ZERO);
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
        assert_eq!(status.alerts[1].code, AlertCode::ForeignRouteOverlap);
        assert_eq!(status.alerts[1].detail, "192.168.1.0/24");
        assert_eq!(status.alerts[2].code, AlertCode::SystemRoutesTruncated);
        assert_eq!(status.alerts[2].detail, "3");
        assert_eq!(status.alerts[3].code, AlertCode::SyncOversize);
        assert!(status.alerts[3].detail.contains("8400000"));
        assert!(status.alerts[3].detail.starts_with("received:"));
        assert!(status.alerts[3].detail.contains("node 9"));

        let undelivered = Snapshot {
            sync_oversize: Some(SyncOversize::Undelivered { peer: 4 }),
            ..Snapshot::default()
        };
        let mut status = ManagedNetworkStatus::stopped("mesh-cn", "");
        fill_running(&mut status, &base, &undelivered, Duration::ZERO);
        assert_eq!(status.alerts[0].code, AlertCode::SyncOversize);
        assert!(status.alerts[0].detail.starts_with("undelivered:"));

        let mut full = Snapshot::default();
        full.counters.refused_at_capacity = 3;
        let mut status = ManagedNetworkStatus::stopped("mesh-cn", "");
        fill_running(&mut status, &base, &full, Duration::ZERO);
        assert_eq!(status.alerts.len(), 1);
        assert_eq!(status.alerts[0].code, AlertCode::SyncOversize);
        assert!(status.alerts[0].detail.starts_with("capacity:"));
        assert!(status.alerts[0].detail.contains("3 refused"));
    }

    #[test]
    fn no_peer_reached_comes_before_a_refused_member() {
        let base = settings();
        let snapshot = Snapshot {
            not_native: Some(44),
            ..Snapshot::default()
        };
        let failure = |up, snapshot: &Snapshot| {
            let mut status = ManagedNetworkStatus::stopped("mesh-cn", "");
            fill_running(&mut status, &base, snapshot, up);
            status.failure.map(|failure| failure.code)
        };
        // Just started: not yet unreachable.
        assert_eq!(
            failure(Duration::from_secs(1), &snapshot),
            Some(FailureCode::PeerNotNative)
        );
        assert_eq!(
            failure(UNREACHABLE_AFTER, &snapshot),
            Some(FailureCode::UnreachablePeers)
        );
        let connected = Snapshot {
            neighbours: vec![3],
            ..snapshot
        };
        assert_eq!(
            failure(UNREACHABLE_AFTER, &connected),
            Some(FailureCode::PeerNotNative)
        );
        let quiet = Snapshot {
            neighbours: vec![3],
            ..Snapshot::default()
        };
        assert_eq!(failure(UNREACHABLE_AFTER, &quiet), None);
    }

    #[test]
    fn networks_may_not_share_a_virtual_subnet_or_address() {
        let base = settings();
        let net = |text: &str| IpNet::parse(text).unwrap();
        assert_eq!(clash(&base, &[net("10.151.0.1/16")]), None);
        assert_eq!(
            clash(&base, &[net("10.150.9.1/24")]),
            Some((FailureCode::RouteOverlap, "10.150.0.0/16".to_owned()))
        );
        assert_eq!(
            clash(&base, &[net("10.150.0.5/24")]),
            Some((FailureCode::AddressInUse, "10.150.0.5".to_owned()))
        );
    }

    fn waiting(tag: &str, name: &str) -> ManagedNetwork {
        let mut settings = settings();
        settings.network_name = name.into();
        ManagedNetwork {
            tag: tag.into(),
            settings,
        }
    }

    #[tokio::test]
    async fn the_status_keeps_the_old_networks_while_they_are_replaced() {
        let dir = temp_dir("previous");
        let mesh = open(&dir).expect("open");
        let before = mesh
            .apply(vec![waiting("mesh-cn", "office")], None)
            .await
            .unwrap();
        let taken = mesh.inner.take_for_replace();
        assert_eq!(mesh.status(), before);
        mesh.inner.finish(Vec::new());
        assert!(mesh.status().networks.is_empty());
        mesh.inner.finish(taken);
        assert_eq!(mesh.status(), before);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn a_replacement_keeps_its_turn_after_the_caller_gives_up() {
        let dir = temp_dir("turn");
        let mesh = open(&dir).expect("open");
        let held = mesh.inner.applying.lock().await;
        // The caller gives up: its replacement still waits for its turn.
        let gave_up = tokio::time::timeout(
            Duration::from_millis(50),
            mesh.apply(vec![waiting("mesh-cn", "office")], None),
        )
        .await;
        assert!(gave_up.is_err());
        assert!(mesh.status().networks.is_empty());
        drop(held);
        // The next one runs after it, never beside it.
        let after = mesh
            .apply(vec![waiting("mesh-hk", "lab")], None)
            .await
            .unwrap();
        assert_eq!(after.networks.len(), 1);
        assert_eq!(after.networks[0].tag, "mesh-hk");
        assert_eq!(mesh.status(), after);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
