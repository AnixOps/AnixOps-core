//! Node server runtime: the part of `anixcore` that a node agent drives.
//!
//! A [`Node`] runs inbounds by tag, each on its own TCP listener or UDP
//! socket, relaying through a direct outbound. Inbounds and their users can be
//! added and removed while the node runs; per-user traffic and online IPs are
//! read back for accounting. [`api`] exposes the same operations as a small
//! local HTTP/JSON management API for agents such as anix-agent.
//!
//! The direct outbound refuses loopback, private and link-local targets
//! unless `allow_private_targets` is set, so users cannot reach services on
//! the node or its network; an inbound's own `fallback`, `fallbacks` and
//! REALITY or ShadowTLS `handshake` addresses are always allowed.
//!
//! Every inbound relays through the node's [`egress::Router`]: the domain
//! egress routes of the panel ([`Node::apply_egress`]) send chosen domains
//! out through another node's Shadowsocks-2022 relay, and the relays this
//! node serves as an exit node run beside the inbounds.
//!
//! What no egress route takes leaves through the inbound's base outbound:
//! the direct outbound, or an outbound the embedding binary registered by
//! name ([`Node::with_outbound`]), such as a tunnel to another node. An
//! inbound picks one with its `outbound` key; without it the node's
//! default ([`Node::with_default_outbound`]) applies, else direct. A
//! registered outbound applies its own target policy:
//! `allow_private_targets` only governs the direct outbound.
//!
//! A `"type": "forward"` inbound ([`FORWARD_TYPE`]) is a panel forwarding
//! rule: its listen port relays TCP and UDP to one fixed `server:port`
//! through its base outbound only (egress routes do not apply), and the
//! inbound's bytes are read back with [`Node::inbound_traffic`]. A
//! `"type": "reverse_proxy"` inbound ([`REVERSE_PROXY_TYPE`]) dials its
//! upstreams the same way.
//!
//! The network model ([`network`], [`Node::apply_network`]) adds the
//! device's egresses and paths: each egress is a base outbound named
//! `egress:<id>`, bound to its source address and probed by the kernel, and
//! an inbound with an `ingress` key takes its ingress's active path, failing
//! over between egresses in pairing order.
//!
//! Mesh networking ([`mesh`], [`Node::with_mesh`]): the node program
//! installs the mesh, and the agent replaces its networks with
//! `PUT /v1/mesh`.

pub mod api;
pub mod config;
mod direct;
pub mod domains;
pub mod egress;
pub mod mesh;
pub mod network;

use std::collections::BTreeMap;
use std::fmt;
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use engine_inbound::health::TargetHealth;
use engine_inbound::qos;
pub use engine_inbound::qos::{QosConfig, QosStatus};
use engine_inbound::registry::{BuildError, Inbound, InboundRegistry};
use engine_inbound::server::{serve_with_udp, InboundStats, ServeSettings};
use engine_inbound::udp::UdpOutbound;
use engine_inbound::UserStore;
use engine_outbound::TcpOutbound;
use serde::Serialize;
use tokio::net::TcpListener;
use tokio::task::JoinHandle;

pub use config::{InboundConfig, ManagementError, ManagementSettings, NodeConfig};
pub use direct::DirectOutbound;
pub use egress::{Egress, EgressConfig, RulesConfig};
pub use network::{NetworkPlan, NetworkStatus};

use egress::{EgressRelay, Router};
use network::{EgressOutbound, IngressOutbound, Network, EGRESS_PREFIX};

/// The name an inbound's `outbound` key uses for the direct outbound.
pub const DIRECT_OUTBOUND: &str = "direct";

/// The `type` of fixed-target port forwards (`inbound-forward`): their
/// target is the operator's, so it passes the private-target filter, and
/// they leave through their base outbound without egress routes.
pub const FORWARD_TYPE: &str = "forward";

/// The inbound type of a panel reverse proxy; like a forward it dials its
/// upstreams through its base outbound only.
pub const REVERSE_PROXY_TYPE: &str = "reverse_proxy";

/// The `type` of the internal-network SOCKS5 inbound (`inbound-socks`). It
/// must listen on an internal address ([`inbound_socks::is_internal`]) and
/// carry `expires_at_ms` at most [`MAX_SOCKS_LIFETIME`] ahead, so it is
/// never reachable from the internet and never permanent.
pub const SOCKS_TYPE: &str = "socks";

/// Longest time ahead a `"type": "socks"` inbound may expire.
pub const MAX_SOCKS_LIFETIME: Duration = Duration::from_secs(7 * 24 * 60 * 60);

/// An inbound's base outbound, for TCP connections and UDP sessions.
#[derive(Clone)]
pub struct NodeOutbound {
    pub tcp: Arc<dyn TcpOutbound>,
    pub udp: Arc<dyn UdpOutbound>,
}

impl NodeOutbound {
    pub fn new(tcp: Arc<dyn TcpOutbound>, udp: Arc<dyn UdpOutbound>) -> Self {
        Self { tcp, udp }
    }

    pub fn direct(direct: DirectOutbound) -> Self {
        let direct = Arc::new(direct);
        Self {
            tcp: direct.clone(),
            udp: direct,
        }
    }
}

/// Builds the base outbound for the rest of a name after a registered
/// prefix ([`Node::with_outbound_prefix`]); `None` refuses the name.
pub type OutboundResolver = Arc<dyn Fn(&str) -> Option<NodeOutbound> + Send + Sync>;

/// Base outbounds the embedding binary registered: by name, and by prefix
/// for names it resolves on demand.
#[derive(Clone, Default)]
pub(crate) struct Outbounds {
    named: BTreeMap<String, NodeOutbound>,
    prefixes: Vec<(String, OutboundResolver)>,
}

impl Outbounds {
    /// A name registered as is wins over a prefix.
    pub(crate) fn get(&self, name: &str) -> Option<NodeOutbound> {
        if let Some(outbound) = self.named.get(name) {
            return Some(outbound.clone());
        }
        for (prefix, resolve) in &self.prefixes {
            if let Some(rest) = name.strip_prefix(prefix.as_str()) {
                if !rest.is_empty() {
                    return resolve(rest);
                }
            }
        }
        None
    }
}

/// The inbound protocols this build was compiled with.
pub fn default_registry() -> InboundRegistry {
    #[allow(unused_mut)]
    let mut registry = InboundRegistry::new();
    #[cfg(feature = "shadowsocks")]
    registry.register(Arc::new(inbound_shadowsocks::ShadowsocksInboundFactory));
    #[cfg(feature = "trojan")]
    registry.register(Arc::new(inbound_trojan::TrojanInboundFactory));
    #[cfg(feature = "snell")]
    registry.register(Arc::new(inbound_snell::SnellInboundFactory));
    #[cfg(feature = "vless")]
    registry.register(Arc::new(inbound_vless::VlessInboundFactory));
    #[cfg(feature = "vmess")]
    registry.register(Arc::new(inbound_vmess::VmessInboundFactory));
    #[cfg(feature = "hysteria2")]
    registry.register_packet(Arc::new(inbound_hysteria2::Hysteria2InboundFactory));
    #[cfg(feature = "tuic")]
    registry.register_packet(Arc::new(inbound_tuic::TuicInboundFactory));
    #[cfg(feature = "iwan")]
    registry.register_packet(Arc::new(inbound_iwan::IwanInboundFactory));
    #[cfg(feature = "forward")]
    registry.register(Arc::new(inbound_forward::ForwardInboundFactory));
    #[cfg(feature = "anytls")]
    registry.register(Arc::new(inbound_anytls::AnyTlsInboundFactory));
    #[cfg(feature = "naive")]
    registry.register(Arc::new(inbound_naive::NaiveInboundFactory));
    #[cfg(feature = "reverse_proxy")]
    registry.register(Arc::new(inbound_reverse_proxy::ReverseProxyInboundFactory));
    #[cfg(feature = "socks")]
    registry.register(Arc::new(inbound_socks::SocksInboundFactory));
    registry
}

#[derive(Debug)]
pub enum NodeError {
    NotFound,
    Exists,
    Invalid(BuildError),
    /// An egress configuration was refused; nothing of it was applied.
    Egress(String),
    /// A network plan was refused; nothing of it was applied.
    Network(String),
    /// Block rules were refused; the previous rules stay.
    Rules(String),
    /// An invalid traffic priority configuration (`PUT /v1/qos`).
    Qos(String),
    /// A fingerprint bundle was refused; the previous one stays.
    TlsFingerprints(String),
    /// A `PUT /v1/mesh` body was refused; nothing of it was applied.
    Mesh(String),
    /// The mesh failed to apply a valid `PUT /v1/mesh`.
    MeshFailed(String),
    /// This kernel runs no mesh ([`Node::with_mesh`] was not called).
    MeshUnavailable,
    Io(io::Error),
}

impl fmt::Display for NodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NodeError::NotFound => f.write_str("inbound not found"),
            NodeError::Exists => f.write_str("inbound tag already exists"),
            NodeError::Invalid(reason) => f.write_str(reason),
            NodeError::Egress(reason)
            | NodeError::Network(reason)
            | NodeError::Rules(reason)
            | NodeError::Qos(reason)
            | NodeError::TlsFingerprints(reason)
            | NodeError::Mesh(reason)
            | NodeError::MeshFailed(reason) => f.write_str(reason),
            NodeError::MeshUnavailable => {
                f.write_str("mesh networking is not available in this kernel")
            }
            NodeError::Io(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for NodeError {}

impl From<io::Error> for NodeError {
    fn from(error: io::Error) -> Self {
        NodeError::Io(error)
    }
}

/// Optional API capabilities this kernel has, answered in `GET /v1/status`
/// so an agent can tell whether it may send them. `shadow_tls` says the
/// `shadowsocks` inbound takes a `shadow_tls` object, `shadowsocks_plugins`
/// that it takes `obfs`, `transport` and `tls`, `reverse_proxy` that the
/// `reverse_proxy` inbound type is built in.
pub const FEATURES: &[&str] = &[
    "user_limits",
    "block_rules",
    "qos",
    "destinations",
    "block_cidrs",
    "tls_fingerprints",
    "accept_proxy_protocol",
    "sing_mux",
    "sing_mux_h2mux",
    "fallbacks",
    "xhttp_h3",
    "inbound_expiry",
    #[cfg(feature = "shadowsocks")]
    "shadow_tls",
    #[cfg(feature = "shadowsocks")]
    "shadowsocks_plugins",
    #[cfg(feature = "reverse_proxy")]
    "reverse_proxy",
];

/// The ClientHello fingerprint data in effect (`GET /v1/tls-fingerprints`).
#[derive(Clone, Debug, Serialize)]
pub struct TlsFingerprintStatus {
    /// The installed bundle's `revision`; empty without a bundle.
    pub revision: String,
    /// Fingerprints served from the bundle; the others use the data built
    /// into this kernel.
    pub replaced: Vec<&'static str>,
    /// Profile names of the bundle this kernel does not know (only in the
    /// answer to the `PUT` that delivered them).
    pub ignored: Vec<String>,
    /// Every fingerprint this kernel has.
    pub known: Vec<&'static str>,
}

impl TlsFingerprintStatus {
    fn from_installed(installed: tls_mimic::InstalledProfiles) -> Self {
        Self {
            revision: installed.revision,
            replaced: installed
                .replaced
                .into_iter()
                .map(tls_mimic::Fingerprint::name)
                .collect(),
            ignored: installed.ignored,
            known: tls_mimic::Fingerprint::ALL
                .into_iter()
                .map(tls_mimic::Fingerprint::name)
                .collect(),
        }
    }
}

/// The fingerprint bundle in effect.
pub fn tls_fingerprints() -> TlsFingerprintStatus {
    TlsFingerprintStatus::from_installed(tls_mimic::installed_profiles())
}

/// Installs a ClientHello fingerprint bundle (`tls_mimic::install_profiles`)
/// for every outbound of this process that imitates a browser: the data
/// behind `chrome`, `safari`, ... is replaced, so following a browser release
/// needs no new kernel. The bundle is the whole state (`{"format": 1,
/// "profiles": {}}` goes back to the built-in data); a bundle with a profile
/// this kernel cannot reproduce is refused and changes nothing. Connections
/// opened afterwards use the new data.
pub fn apply_tls_fingerprints(
    bundle: &serde_json::Value,
) -> Result<TlsFingerprintStatus, NodeError> {
    tls_mimic::install_profiles(&bundle.to_string())
        .map(TlsFingerprintStatus::from_installed)
        .map_err(|error| NodeError::TlsFingerprints(error.to_string()))
}

/// Counters of one running inbound.
#[derive(Clone, Debug, Serialize)]
pub struct InboundInfo {
    pub tag: String,
    #[serde(rename = "type")]
    pub kind: String,
    pub listen: SocketAddr,
    pub users: usize,
    pub accepted: u64,
    pub active: u64,
    pub handshake_failed: u64,
    /// Connections refused by a user's `device_limit`.
    pub device_limited: u64,
    pub bytes_up: u64,
    pub bytes_down: u64,
    /// The base outbound's name; [`DIRECT_OUTBOUND`] for direct,
    /// `ingress:<id>` for an inbound in an ingress.
    pub outbound: String,
    /// The network-model ingress the inbound belongs to.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ingress: Option<String>,
    /// When the inbound ends, in Unix milliseconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at_ms: Option<u64>,
}

/// Bytes relayed by one inbound, all users and none together.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
pub struct InboundTraffic {
    /// Client to target.
    pub up: u64,
    /// Target to client.
    pub down: u64,
}

/// What an egress configuration runs on this node.
#[derive(Clone, Debug, Serialize)]
pub struct EgressStatus {
    /// Route ids, in the order they are tried.
    pub routes: Vec<u64>,
    pub relays: Vec<RelayInfo>,
    /// Addresses the node's map (inbounds' own resolvers) currently maps
    /// to names. The maps UDP sessions keep of their own relayed answers are
    /// not counted.
    pub mapped_addresses: usize,
}

/// Counters of one egress relay; never its key.
#[derive(Clone, Debug, Serialize)]
pub struct RelayInfo {
    pub id: u64,
    pub listen: SocketAddr,
    pub accepted: u64,
    pub active: u64,
    pub handshake_failed: u64,
    pub bytes_up: u64,
    pub bytes_down: u64,
}

struct Running {
    kind: String,
    outbound: String,
    ingress: Option<String>,
    listen: SocketAddr,
    inbound: Inbound,
    stats: Arc<InboundStats>,
    task: JoinHandle<()>,
    /// Bytes up and down already reported by a resetting
    /// [`Node::inbound_traffic`] call.
    reported: Mutex<(u64, u64)>,
    /// When the inbound ends: its task stops serving at `deadline`, and
    /// the next look at the table drops it.
    expiry: Option<Expiry>,
}

#[derive(Clone, Copy)]
struct Expiry {
    at_ms: u64,
    deadline: tokio::time::Instant,
}

impl Expiry {
    /// `at_ms` as a deadline; refused unless it is in the future.
    fn new(at_ms: u64) -> Result<Self, NodeError> {
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|now| u64::try_from(now.as_millis()).unwrap_or(u64::MAX))
            .unwrap_or(0);
        if at_ms <= now_ms {
            return Err(NodeError::Invalid("expires_at_ms is not in the future"));
        }
        let deadline = tokio::time::Instant::now()
            .checked_add(Duration::from_millis(at_ms - now_ms))
            .ok_or(NodeError::Invalid("expires_at_ms is too far ahead"))?;
        Ok(Self { at_ms, deadline })
    }

    fn remaining(&self) -> Duration {
        self.deadline
            .saturating_duration_since(tokio::time::Instant::now())
    }

    fn passed(&self) -> bool {
        tokio::time::Instant::now() >= self.deadline
    }
}

struct RunningRelay {
    config: EgressRelay,
    running: Running,
}

pub struct Node {
    registry: InboundRegistry,
    serve_settings: ServeSettings,
    allow_private_targets: bool,
    inbounds: Mutex<BTreeMap<String, Running>>,
    egress: Arc<Egress>,
    network: Arc<Network>,
    /// Relays by id; also serializes [`Node::apply_egress`].
    relays: tokio::sync::Mutex<BTreeMap<u64, RunningRelay>>,
    /// The block rules last applied.
    rules: Mutex<RulesConfig>,
    /// Base outbounds the embedding binary registered, by name.
    outbounds: Outbounds,
    default_outbound: Option<String>,
    /// The mesh the node program installed; `None` without mesh support.
    mesh: Option<mesh::Mesh>,
}

impl Node {
    pub fn new(registry: InboundRegistry, allow_private_targets: bool) -> Self {
        Self {
            registry,
            serve_settings: ServeSettings::default(),
            allow_private_targets,
            inbounds: Mutex::new(BTreeMap::new()),
            egress: Arc::new(Egress::new()),
            network: Arc::new(Network::new(allow_private_targets)),
            relays: tokio::sync::Mutex::new(BTreeMap::new()),
            rules: Mutex::new(RulesConfig::default()),
            outbounds: Outbounds::default(),
            default_outbound: None,
            mesh: None,
        }
    }

    /// Installs the mesh `PUT` / `GET /v1/mesh` drive. With it the node
    /// lists the control's features (at least `mesh`) in `GET /v1/status`.
    pub fn with_mesh(mut self, control: Arc<dyn outbound_mesh::status::MeshControl>) -> Self {
        self.mesh = Some(mesh::Mesh::new(control));
        self
    }

    /// Stops the managed mesh networks before the node program exits, so
    /// that each withdraws its subnet advertisements first (spec §15.7
    /// rule 6); returns at once without a mesh.
    pub async fn stop_mesh(&self) {
        if let Some(mesh) = &self.mesh {
            mesh.stop_all().await;
        }
    }

    /// [`FEATURES`] and those of the installed mesh, as `GET /v1/status`
    /// lists them.
    pub fn features(&self) -> Vec<&'static str> {
        let mut features = FEATURES.to_vec();
        if let Some(mesh) = &self.mesh {
            for feature in mesh.features() {
                if !features.contains(feature) {
                    features.push(feature);
                }
            }
        }
        features
    }

    /// The managed mesh networks (`GET /v1/mesh`).
    pub fn mesh_state(&self) -> Result<outbound_mesh::status::ManagedStatus, NodeError> {
        self.mesh
            .as_ref()
            .map(mesh::Mesh::status)
            .ok_or(NodeError::MeshUnavailable)
    }

    /// Replaces the managed mesh networks with a `PUT /v1/mesh` body.
    pub async fn apply_mesh(
        &self,
        body: &[u8],
    ) -> Result<outbound_mesh::status::ManagedStatus, NodeError> {
        match &self.mesh {
            Some(mesh) => mesh.apply(body).await,
            None => Err(NodeError::MeshUnavailable),
        }
    }

    /// Saves a subnet route override (`PUT /v1/mesh/subnet_route`).
    pub async fn set_mesh_subnet_route(
        &self,
        body: &[u8],
    ) -> Result<outbound_mesh::status::ManagedStatus, NodeError> {
        match &self.mesh {
            Some(mesh) => mesh.set_subnet_route(body).await,
            None => Err(NodeError::MeshUnavailable),
        }
    }

    pub fn with_serve_settings(mut self, settings: ServeSettings) -> Self {
        self.serve_settings = settings;
        self
    }

    /// Registers a base outbound inbounds can name in their `outbound` key.
    /// A later registration under the same name replaces the earlier one;
    /// [`DIRECT_OUTBOUND`] always means the direct outbound and names
    /// starting with `egress:` the network plan's egresses. A transport's
    /// outbound is registered as `<kind>:<transport id>` (`anx-line:<id>`)
    /// for network paths to use it.
    pub fn with_outbound(mut self, name: impl Into<String>, outbound: NodeOutbound) -> Self {
        self.outbounds.named.insert(name.into(), outbound);
        self
    }

    /// Registers base outbounds by name prefix, built on demand from the
    /// rest of the name: `with_outbound_prefix("anx-line:", ..)` serves
    /// `anx-line:<id>` for links added after the node started. Inbounds'
    /// `outbound` keys and network paths into transports use them; a name
    /// registered with [`Node::with_outbound`] wins.
    pub fn with_outbound_prefix(
        mut self,
        prefix: impl Into<String>,
        resolver: OutboundResolver,
    ) -> Self {
        self.outbounds.prefixes.push((prefix.into(), resolver));
        self
    }

    /// The base outbound of inbounds without an `outbound` key; `None` (the
    /// default) is direct. An unknown name fails when an inbound is added.
    pub fn with_default_outbound(mut self, name: Option<String>) -> Self {
        self.default_outbound = name;
        self
    }

    /// Registered base outbound names, without [`DIRECT_OUTBOUND`].
    pub fn outbounds(&self) -> Vec<String> {
        self.outbounds.named.keys().cloned().collect()
    }

    /// The base outbound `name` stands for; `None` when it is unknown.
    fn base_outbound(&self, name: &str, config: &InboundConfig) -> Option<NodeOutbound> {
        if name == DIRECT_OUTBOUND {
            return Some(NodeOutbound::direct(DirectOutbound::new(
                self.allow_private_targets,
                config.allowed_targets(),
            )));
        }
        if let Some(id) = name.strip_prefix(EGRESS_PREFIX) {
            // Looked up when a connection opens: the plan can change.
            return valid_tag(id).then(|| {
                EgressOutbound::node_outbound(
                    self.network.clone(),
                    id.to_owned(),
                    config.allowed_targets(),
                )
            });
        }
        self.outbounds.get(name)
    }

    /// Builds, binds and starts an inbound. Returns the bound address.
    pub async fn add_inbound(&self, config: InboundConfig) -> Result<SocketAddr, NodeError> {
        if !valid_tag(&config.tag) {
            return Err(NodeError::Invalid(
                "inbound tag must be 1-64 letters, digits, '.', '_' or '-'",
            ));
        }
        if self.lock().contains_key(&config.tag) {
            return Err(NodeError::Exists);
        }
        let (outbound, base) = match &config.ingress {
            Some(_) if config.outbound.is_some() => {
                return Err(NodeError::Invalid(
                    "an inbound takes an ingress or an outbound, not both",
                ))
            }
            Some(ingress) if !valid_tag(ingress) => {
                return Err(NodeError::Invalid("the ingress id is not valid"))
            }
            // The plan may name the ingress later; until then its
            // connections are refused.
            Some(ingress) => (
                format!("ingress:{ingress}"),
                IngressOutbound::node_outbound(
                    self.network.clone(),
                    ingress.clone(),
                    config.allowed_targets(),
                    self.outbounds.clone(),
                ),
            ),
            None => {
                let outbound = config
                    .outbound
                    .clone()
                    .or_else(|| self.default_outbound.clone())
                    .unwrap_or_else(|| DIRECT_OUTBOUND.to_owned());
                let base = self
                    .base_outbound(&outbound, &config)
                    .ok_or(NodeError::Invalid("inbound names an unknown outbound"))?;
                (outbound, base)
            }
        };
        let expiry = config.expires_at_ms.map(Expiry::new).transpose()?;
        if config.kind == SOCKS_TYPE {
            check_socks(&config, expiry)?;
        }
        let inbound = self
            .registry
            .build(&config.kind, &config.settings)
            .map_err(NodeError::Invalid)?;
        if config.accept_proxy_protocol && matches!(inbound, Inbound::Packet(_)) {
            return Err(NodeError::Invalid(
                "accept_proxy_protocol needs an inbound on a TCP listener",
            ));
        }
        let address = SocketAddr::new(config.listen, config.listen_port);
        let (tcp_outbound, udp_outbound): (Arc<dyn TcpOutbound>, Arc<dyn UdpOutbound>) =
            if config.kind == FORWARD_TYPE || config.kind == REVERSE_PROXY_TYPE {
                (base.tcp, base.udp)
            } else {
                let router = Arc::new(Router::new(base, self.egress.clone()));
                (router.clone(), router)
            };
        // A replaced inbound's sockets close a moment after its removal:
        // its task is cancelled, not joined. Retry the port for a while
        // instead of failing the replacement.
        let mut waited = Duration::ZERO;
        let (listen, stats, task) = loop {
            match self.spawn(
                &inbound,
                address,
                tcp_outbound.clone(),
                udp_outbound.clone(),
                config.accept_proxy_protocol,
                expiry,
            ) {
                Err(error) if error.kind() == io::ErrorKind::AddrInUse && waited < REBIND_WAIT => {
                    tokio::time::sleep(REBIND_STEP).await;
                    waited += REBIND_STEP;
                }
                spawned => break spawned?,
            }
        };
        let mut inbounds = self.lock();
        if inbounds.contains_key(&config.tag) {
            task.abort();
            return Err(NodeError::Exists);
        }
        inbounds.insert(
            config.tag,
            Running {
                kind: config.kind,
                outbound,
                ingress: config.ingress,
                listen,
                inbound,
                stats,
                task,
                reported: Mutex::new((0, 0)),
                expiry,
            },
        );
        Ok(listen)
    }

    /// Binds `inbound` on `address` and starts serving it.
    fn spawn(
        &self,
        inbound: &Inbound,
        address: SocketAddr,
        outbound: Arc<dyn TcpOutbound>,
        udp: Arc<dyn UdpOutbound>,
        accept_proxy_protocol: bool,
        expiry: Option<Expiry>,
    ) -> io::Result<(SocketAddr, Arc<InboundStats>, JoinHandle<()>)> {
        let stats = Arc::new(InboundStats::default());
        let settings = ServeSettings {
            accept_proxy_protocol,
            ..self.serve_settings.clone()
        };
        let (listen, task) = match inbound {
            Inbound::Stream(stream) => {
                // UDP on the same port, for inbounds that take it: their
                // own datagrams, or QUIC (XHTTP over HTTP/3).
                let wants_udp = stream.datagram().is_some() || stream.packet().is_some();
                let (listener, socket) = bind_tcp_and_udp(address, wants_udp)?;
                let listen = listener.local_addr()?;
                let datagrams = match (stream.datagram(), stream.packet(), socket) {
                    (Some(datagram), _, Some(socket)) => {
                        Some(datagram.serve(socket, udp.clone(), stats.clone()))
                    }
                    (None, Some(packet), Some(socket)) => Some(packet.serve(
                        socket,
                        outbound.clone(),
                        Some(udp.clone()),
                        settings.clone(),
                        stats.clone(),
                    )),
                    _ => None,
                };
                let task = tokio::spawn(until(expiry, {
                    let (stream, stats) = (stream.clone(), stats.clone());
                    async move {
                        let streams =
                            serve_with_udp(listener, stream, outbound, Some(udp), settings, stats);
                        match datagrams {
                            Some(datagrams) => {
                                let _ = tokio::join!(streams, datagrams);
                            }
                            None => {
                                let _ = streams.await;
                            }
                        }
                    }
                }));
                (listen, task)
            }
            Inbound::Packet(packet) => {
                let socket = bind_udp(address)?;
                let listen = socket.local_addr()?;
                let served =
                    packet
                        .clone()
                        .serve(socket, outbound, Some(udp), settings, stats.clone());
                let task = tokio::spawn(until(expiry, async move {
                    let _ = served.await;
                }));
                (listen, task)
            }
        };
        Ok((listen, stats, task))
    }

    /// The node's egress routes and address-to-name map.
    pub fn egress(&self) -> &Arc<Egress> {
        &self.egress
    }

    /// Replaces the block rules with `config`: connections to a blocked
    /// domain, and connections whose first bytes are a blocked protocol,
    /// are refused on every inbound; direct dials to a blocked address
    /// range are refused in the whole process. Nothing changes when an
    /// entry is invalid; connections already open are not cut.
    pub fn apply_rules(&self, config: &RulesConfig) -> Result<RulesConfig, NodeError> {
        let mut rules = egress::compile_rules(config).map_err(NodeError::Rules)?;
        let mut current = self.rules.lock().unwrap_or_else(|p| p.into_inner());
        direct::set_blocked_cidrs(rules.cidrs.take());
        self.egress.set_blocks(rules);
        *current = config.clone();
        Ok(current.clone())
    }

    /// Replaces the traffic priorities ([`engine_inbound::qos`]) with
    /// `config`; `{}` turns them off. Nothing changes when an entry is
    /// invalid; connections already open keep the class they started
    /// with.
    pub fn apply_qos(&self, config: &QosConfig) -> Result<QosStatus, NodeError> {
        let policy = qos::Policy::compile(config).map_err(NodeError::Qos)?;
        let status = policy.status();
        qos::set(Some(policy));
        Ok(status)
    }

    /// The traffic priorities in force and the node scheduler's rates.
    pub fn qos(&self) -> QosStatus {
        qos::status()
    }

    /// Direct dials refused by the blocked address ranges since the last
    /// `reset`.
    pub fn blocked_cidrs(&self, reset: bool) -> u64 {
        direct::blocked_count(reset)
    }

    /// The block rules last applied.
    pub fn rules(&self) -> RulesConfig {
        self.rules.lock().unwrap_or_else(|p| p.into_inner()).clone()
    }

    /// Replaces the egress routes and relays with `config`. Nothing changes
    /// when an entry is invalid. Relays that are unchanged keep running and
    /// keep their connections; a relay whose port cannot be bound fails
    /// alone, after everything else was applied. Connections already open
    /// keep the path they took.
    pub async fn apply_egress(&self, config: &EgressConfig) -> Result<EgressStatus, NodeError> {
        let table = egress::compile(config).map_err(NodeError::Egress)?;
        let mut built = Vec::new();
        for relay in &config.relays {
            let (kind, settings) = relay.inbound();
            let inbound = self.registry.build(kind, &settings).map_err(|reason| {
                NodeError::Egress(format!("egress relay {}: {reason}", relay.id))
            })?;
            built.push((relay.clone(), inbound));
        }
        let mut relays = self.relays.lock().await;
        self.egress.set_table(table);
        let stale: Vec<u64> = relays
            .iter()
            .filter(|(id, running)| {
                !config
                    .relays
                    .iter()
                    .any(|relay| relay.id == **id && *relay == running.config)
            })
            .map(|(id, _)| *id)
            .collect();
        for id in stale {
            if let Some(relay) = relays.remove(&id) {
                // Wait for the listener to close: a changed relay binds the
                // same port again right after.
                relay.running.task.abort();
                let _ = relay.running.task.await;
            }
        }
        let mut failed = Vec::new();
        for (relay, inbound) in built {
            if relays.contains_key(&relay.id) {
                continue;
            }
            // A relay's traffic leaves here: direct, never another route.
            let direct = Arc::new(DirectOutbound::new(self.allow_private_targets, Vec::new()));
            let address = SocketAddr::new(
                relay.listen.unwrap_or(Ipv6Addr::UNSPECIFIED.into()),
                relay.port,
            );
            match self.spawn(&inbound, address, direct.clone(), direct, false, None) {
                Ok((listen, stats, task)) => {
                    relays.insert(
                        relay.id,
                        RunningRelay {
                            running: Running {
                                kind: relay.inbound().0.to_owned(),
                                outbound: DIRECT_OUTBOUND.to_owned(),
                                ingress: None,
                                listen,
                                inbound,
                                stats,
                                task,
                                reported: Mutex::new((0, 0)),
                                expiry: None,
                            },
                            config: relay,
                        },
                    );
                }
                Err(error) => failed.push(format!("egress relay {}: {error}", relay.id)),
            }
        }
        if !failed.is_empty() {
            return Err(NodeError::Io(io::Error::other(failed.join("; "))));
        }
        Ok(self.egress_status(&relays))
    }

    /// What the egress configuration runs now.
    pub async fn egress_state(&self) -> EgressStatus {
        let relays = self.relays.lock().await;
        self.egress_status(&relays)
    }

    fn egress_status(&self, relays: &BTreeMap<u64, RunningRelay>) -> EgressStatus {
        EgressStatus {
            routes: self.egress.route_ids(),
            relays: relays
                .iter()
                .map(|(id, relay)| {
                    let stats = &relay.running.stats;
                    RelayInfo {
                        id: *id,
                        listen: relay.running.listen,
                        accepted: stats.accepted.load(Ordering::Relaxed),
                        active: stats.active.load(Ordering::Relaxed),
                        handshake_failed: stats.handshake_failed.load(Ordering::Relaxed),
                        bytes_up: stats.bytes_up.load(Ordering::Relaxed),
                        bytes_down: stats.bytes_down.load(Ordering::Relaxed),
                    }
                })
                .collect(),
            mapped_addresses: self.egress.domains().len(),
        }
    }

    /// Replaces the network plan (egresses, ingresses, paths). Nothing
    /// changes when an entry is invalid, including a path into a transport
    /// whose outbound this binary did not register. Connections already
    /// open keep the path they took.
    pub async fn apply_network(&self, plan: &NetworkPlan) -> Result<NetworkStatus, NodeError> {
        self.network
            .apply(plan, &self.outbounds)
            .await
            .map_err(NodeError::Network)
    }

    /// What the network plan runs now, with the egresses' health.
    pub fn network_state(&self) -> NetworkStatus {
        self.network.status()
    }

    /// Stops an inbound and closes its users' connections.
    pub fn remove_inbound(&self, tag: &str) -> Result<(), NodeError> {
        let running = self.lock().remove(tag).ok_or(NodeError::NotFound)?;
        stop(running);
        Ok(())
    }

    /// The user table of an inbound.
    pub fn users(&self, tag: &str) -> Result<Arc<UserStore>, NodeError> {
        self.lock()
            .get(tag)
            .map(|running| running.inbound.users().clone())
            .ok_or(NodeError::NotFound)
    }

    /// Bytes an inbound relayed since the last call with `reset`, or since
    /// it started; `reset` starts the next interval. Unlike per-user
    /// traffic this covers inbounds without users, such as forwards.
    pub fn inbound_traffic(&self, tag: &str, reset: bool) -> Result<InboundTraffic, NodeError> {
        let inbounds = self.lock();
        let running = inbounds.get(tag).ok_or(NodeError::NotFound)?;
        let total = (
            running.stats.bytes_up.load(Ordering::Relaxed),
            running.stats.bytes_down.load(Ordering::Relaxed),
        );
        let mut reported = running
            .reported
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let traffic = InboundTraffic {
            up: total.0.saturating_sub(reported.0),
            down: total.1.saturating_sub(reported.1),
        };
        if reset {
            *reported = total;
        }
        Ok(traffic)
    }

    /// The health of the targets an inbound dials itself (a forward's), in
    /// their configured order; empty for other inbounds.
    pub fn target_health(&self, tag: &str) -> Result<Vec<TargetHealth>, NodeError> {
        self.lock()
            .get(tag)
            .map(|running| running.inbound.target_health().unwrap_or_default())
            .ok_or(NodeError::NotFound)
    }

    pub fn list(&self) -> Vec<InboundInfo> {
        self.lock()
            .iter()
            .map(|(tag, running)| {
                let stats = &running.stats;
                InboundInfo {
                    tag: tag.clone(),
                    kind: running.kind.clone(),
                    listen: running.listen,
                    users: running.inbound.users().len(),
                    accepted: stats.accepted.load(Ordering::Relaxed),
                    active: stats.active.load(Ordering::Relaxed),
                    handshake_failed: stats.handshake_failed.load(Ordering::Relaxed),
                    device_limited: stats.device_limited.load(Ordering::Relaxed),
                    bytes_up: stats.bytes_up.load(Ordering::Relaxed),
                    bytes_down: stats.bytes_down.load(Ordering::Relaxed),
                    outbound: running.outbound.clone(),
                    ingress: running.ingress.clone(),
                    expires_at_ms: running.expiry.map(|expiry| expiry.at_ms),
                }
            })
            .collect()
    }

    /// Registered inbound type names.
    pub fn types(&self) -> Vec<&'static str> {
        self.registry.type_names()
    }

    /// The inbound table, without the inbounds whose expiry passed: those
    /// are stopped and dropped here, so an expired tag is free again.
    fn lock(&self) -> std::sync::MutexGuard<'_, BTreeMap<String, Running>> {
        let mut inbounds = self
            .inbounds
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let expired: Vec<String> = inbounds
            .iter()
            .filter(|(_, running)| running.expiry.is_some_and(|expiry| expiry.passed()))
            .map(|(tag, _)| tag.clone())
            .collect();
        for tag in expired {
            if let Some(running) = inbounds.remove(&tag) {
                stop(running);
            }
        }
        inbounds
    }
}

/// Stops an inbound's task and closes its users' connections.
fn stop(running: Running) {
    running.task.abort();
    let users = running.inbound.users();
    for name in users.names() {
        users.remove(&name);
    }
}

/// Runs `serve` until `expiry` passes; dropping it then closes the
/// listener and every connection it accepted.
async fn until(expiry: Option<Expiry>, serve: impl std::future::Future<Output = ()>) {
    match expiry {
        Some(expiry) => {
            tokio::select! {
                _ = serve => {}
                _ = tokio::time::sleep(expiry.remaining()) => {}
            }
        }
        None => serve.await,
    }
}

/// The rules of `"type": "socks"`: an expiry at most
/// [`MAX_SOCKS_LIFETIME`] ahead and an internal listen address.
fn check_socks(config: &InboundConfig, expiry: Option<Expiry>) -> Result<(), NodeError> {
    let Some(expiry) = expiry else {
        return Err(NodeError::Invalid("a socks inbound needs expires_at_ms"));
    };
    if expiry.remaining() > MAX_SOCKS_LIFETIME {
        return Err(NodeError::Invalid(
            "a socks inbound expires at most seven days ahead",
        ));
    }
    if !is_internal(config.listen) {
        return Err(NodeError::Invalid(
            "a socks inbound listens on an internal address only",
        ));
    }
    Ok(())
}

#[cfg(feature = "socks")]
fn is_internal(ip: std::net::IpAddr) -> bool {
    inbound_socks::is_internal(ip)
}

/// Without the protocol no address is good enough; the registry refuses
/// the type anyway.
#[cfg(not(feature = "socks"))]
fn is_internal(_ip: std::net::IpAddr) -> bool {
    false
}

impl Drop for Node {
    fn drop(&mut self) {
        for running in self.lock().values() {
            running.task.abort();
        }
        for relay in self.relays.get_mut().values() {
            relay.running.task.abort();
        }
    }
}

/// Binds a TCP listener; `[::]` listens on IPv4 too (on every OS) and
/// falls back to `0.0.0.0` on a host without IPv6.
/// How long [`Node::add_inbound`] retries a port still held by an inbound
/// that was just removed, and its step.
const REBIND_WAIT: Duration = Duration::from_secs(3);
const REBIND_STEP: Duration = Duration::from_millis(100);

fn bind_tcp(address: SocketAddr) -> io::Result<TcpListener> {
    let socket = match bind(address, socket2::Type::STREAM) {
        Err(error) if is_any_v6(address) && error.kind() != io::ErrorKind::AddrInUse => {
            bind(any_v4(address), socket2::Type::STREAM)?
        }
        bound => bound?,
    };
    #[cfg(target_os = "linux")]
    prefer_congestion_control(&socket);
    socket.listen(1024)?;
    TcpListener::from_std(socket.into())
}

/// Congestion control asked for on inbound listeners (accepted connections
/// inherit it): BBR keeps a long-lived connection fast under random loss,
/// where CUBIC drops to roughly MSS/RTT x 1.22/sqrt(p). Set per socket, so it
/// works without changing the host default (and inside network namespaces);
/// `ANIXOPS_TCP_CONGESTION` picks another algorithm, empty or `default`
/// keeps the host's. Failure (module not available, not permitted) is
/// ignored: the host default applies.
#[cfg(target_os = "linux")]
const DEFAULT_CONGESTION: &str = "bbr";

#[cfg(target_os = "linux")]
fn prefer_congestion_control(socket: &socket2::Socket) {
    let name =
        std::env::var("ANIXOPS_TCP_CONGESTION").unwrap_or_else(|_| DEFAULT_CONGESTION.to_string());
    if name.is_empty() || name == "default" {
        return;
    }
    let _ = socket.set_tcp_congestion(name.as_bytes());
}

/// Binds a UDP socket like [`bind_tcp`].
/// Ephemeral ports tried for a TCP listener that needs UDP on the same
/// number.
const SAME_PORT_ATTEMPTS: usize = 32;

/// Binds TCP on `address` and, when `udp` is set, UDP on the same port.
/// With port 0 the number one protocol got may not be free for the other:
/// it may be taken, or on Windows fall in a range reserved for that protocol
/// only (os error 10013). Ephemeral ports there are handed out in order, so a
/// retry that always starts from TCP walks through the same reserved block;
/// attempts therefore alternate between letting TCP and letting UDP choose,
/// and rejected sockets stay bound until the end so no number comes back.
fn bind_tcp_and_udp(
    address: SocketAddr,
    udp: bool,
) -> io::Result<(TcpListener, Option<std::net::UdpSocket>)> {
    if !udp {
        return Ok((bind_tcp(address)?, None));
    }
    if address.port() != 0 {
        let listener = bind_tcp(address)?;
        let socket = bind_udp(listener.local_addr()?)?;
        return Ok((listener, Some(socket)));
    }
    let retryable = |error: &io::Error| {
        matches!(
            error.kind(),
            io::ErrorKind::AddrInUse | io::ErrorKind::PermissionDenied
        )
    };
    let mut rejected_tcp = Vec::new();
    let mut rejected_udp = Vec::new();
    let mut attempt = 1;
    loop {
        let last = attempt >= SAME_PORT_ATTEMPTS;
        if attempt % 2 == 1 {
            let listener = bind_tcp(address)?;
            let port = listener.local_addr()?.port();
            match bind_udp(SocketAddr::new(address.ip(), port)) {
                Ok(socket) => return Ok((listener, Some(socket))),
                Err(error) if !last && retryable(&error) => rejected_tcp.push(listener),
                Err(error) => return Err(error),
            }
        } else {
            let socket = bind_udp(address)?;
            let port = socket.local_addr()?.port();
            match bind_tcp(SocketAddr::new(address.ip(), port)) {
                Ok(listener) => return Ok((listener, Some(socket))),
                Err(error) if !last && retryable(&error) => rejected_udp.push(socket),
                Err(error) => return Err(error),
            }
        }
        attempt += 1;
    }
}

fn bind_udp(address: SocketAddr) -> io::Result<std::net::UdpSocket> {
    let socket = match bind(address, socket2::Type::DGRAM) {
        Err(error) if is_any_v6(address) && error.kind() != io::ErrorKind::AddrInUse => {
            bind(any_v4(address), socket2::Type::DGRAM)?
        }
        bound => bound?,
    };
    Ok(socket.into())
}

fn bind(address: SocketAddr, kind: socket2::Type) -> io::Result<socket2::Socket> {
    let socket = socket2::Socket::new(socket2::Domain::for_address(address), kind, None)?;
    if is_any_v6(address) {
        socket.set_only_v6(false)?;
    }
    // As tokio does; Windows' SO_REUSEADDR would let others share the port.
    if cfg!(unix) && kind == socket2::Type::STREAM {
        socket.set_reuse_address(true)?;
    }
    socket.set_nonblocking(true)?;
    socket.bind(&address.into())?;
    Ok(socket)
}

fn is_any_v6(address: SocketAddr) -> bool {
    address.is_ipv6() && address.ip().is_unspecified()
}

fn any_v4(address: SocketAddr) -> SocketAddr {
    SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), address.port())
}

fn valid_tag(tag: &str) -> bool {
    !tag.is_empty()
        && tag.len() <= 64
        && tag
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn tcp_and_udp_share_one_ephemeral_port() {
        let address: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let mut held = Vec::new();
        for _ in 0..64 {
            let (listener, socket) = bind_tcp_and_udp(address, true).unwrap();
            let socket = socket.unwrap();
            let port = listener.local_addr().unwrap().port();
            assert_ne!(port, 0);
            assert_eq!(socket.local_addr().unwrap().port(), port);
            held.push((listener, socket));
        }
        let (listener, socket) = bind_tcp_and_udp(address, false).unwrap();
        assert!(socket.is_none());
        assert_ne!(listener.local_addr().unwrap().port(), 0);
    }

    #[test]
    fn validates_tags() {
        assert!(valid_tag("ss-1.node_a"));
        assert!(!valid_tag(""));
        assert!(!valid_tag("a/b"));
        assert!(!valid_tag(&"x".repeat(65)));
    }
}
