//! One node of one network, without I/O: connections and their handshakes,
//! keep-alive (spec §10), peer RPC (spec §11) with route synchronisation
//! (spec §12) and the latency centre (spec §13.3), forwarding (spec §14) and
//! the virtual-network traffic with its intranet checks (spec §15).
//!
//! The driver owns the sockets and the virtual interface. It tells the node
//! about connections ([`Node::connect`], [`Node::accept`],
//! [`Node::receive`], [`Node::disconnected`]), hands it IP packets from the
//! interface ([`Node::send_ip`]), calls [`Node::tick`] about once a second,
//! and carries out the [`Action`]s the node queues.
//!
//! Broadcast and multicast go to every direct neighbour (spec §15.3).
//!
//! In the secure mode a node that is not a neighbour is reached over an
//! end-to-end relay session (spec §9): packets for it wait (at most
//! [`RELAY_QUEUE`]) while relay msg1 goes out, retried as new handshakes
//! after 200, 400 and 800 ms and given up 1.6 s after the last; when both
//! ends start at once the smaller node ID stays the initiator. The
//! answering side keeps its packets until the initiator's first packet
//! makes the pending session current.
//!
//! Not here yet: shared nodes (spec §16).

use std::collections::{BTreeMap, VecDeque};
use std::net::IpAddr;
use std::time::{Duration, Instant};

use ring::error::Unspecified;
use ring::rand::SecureRandom;

use crate::config::{MeshSettings, NetworkKind, Role, RoutePolicy, SecurityMode};
use crate::legacy::keys::digest;
use crate::legacy::LegacyCipher;
use crate::link::{self, CloseReason, Crypto, Dropped, Handshaking, Link, Step, Up};
use crate::net::IpNet;
use crate::route::center::{self, CentreServer, GlobalPeerMap, PeerMap, ReportPeers};
use crate::route::messages::{
    FeatureFlags, RoutePeerInfo, SyncRouteRequest, SyncRouteResponse, Uuid,
};
use crate::route::sync::{Notice, RouteSync};
use crate::route::topology::{Metric, Route};
use crate::routes::{self, Denied, PeerId, RouteTable};
use crate::rpc::packet::{
    split, Descriptor, RpcError, RpcPacket, RpcRequest, RpcResponse, DEFAULT_TIMEOUT_MS,
    ROUTE_SYNC_TIMEOUT_MS,
};
use crate::rpc::reassembly::Reassembler;
use crate::secure::handshake::{
    keeps_initiating, relay_respond, HandshakeError, Local, RelayAnswer, RelayInitiator,
};
use crate::secure::messages::Action as SessionAction;
use crate::secure::noise::{KeyPair, LEN};
use crate::secure::session::{Namespace, SessionKey, Sessions};
use crate::wire::header::relay_in_place;
use crate::wire::{flags, packet_type, NodeHeader, HEADER_LEN};

/// The driver's name for one connection.
pub type ConnId = u64;

/// Packets kept for one destination while its relay session is being set
/// up (spec §9).
pub const RELAY_QUEUE: usize = 32;
/// First wait for relay msg2; doubled for each new attempt (spec §9).
pub const RELAY_RETRY_START: Duration = Duration::from_millis(200);
/// New attempts after the first relay msg1 (spec §9).
pub const RELAY_RETRIES: u32 = 3;
/// How long packets wait for a session this node answered, pending until
/// the initiator's first packet arrives (spec §9 rule 2), before this node
/// starts a handshake of its own.
pub const RELAY_PENDING_WAIT: Duration = Duration::from_secs(10);

/// A relay session being set up with a node that is not a neighbour.
struct Relay {
    initiator: Option<RelayInitiator>,
    /// msg1 sent so far by this node.
    attempts: u32,
    /// When to send the next msg1 (or give up); `None` while waiting for
    /// nothing.
    due: Option<Instant>,
    queue: VecDeque<(u8, Vec<u8>)>,
}

/// A refusal for a key off the native key list is reported for this long
/// unless another follows (docs/architecture/mesh-status.md).
pub const NOT_NATIVE_HOLD: Duration = Duration::from_secs(10 * 60);

/// Most subnets installed as system routes for one network: as many as
/// [`routes::MAX_SUBNETS_PER_PEER`] for sixteen advertising members; any
/// further subnets are not installed.
pub const MAX_SYSTEM_ROUTES: usize = 16 * routes::MAX_SUBNETS_PER_PEER;

/// Route synchronisation service (spec §11.4).
pub const ROUTE_SERVICE: &str = "OspfRouteRpc";
/// `SyncRouteInfo` method.
pub const METHOD_SYNC_ROUTE_INFO: u32 = 1;
/// First keep-alive interval (spec §10).
pub const PING_START: Duration = Duration::from_secs(1);
/// Longest keep-alive interval (spec §10).
pub const PING_MAX: Duration = Duration::from_secs(32);
/// A ping unanswered this long is missed (spec §10).
pub const PING_TIMEOUT: Duration = Duration::from_secs(2);
/// Missed pings in a row that close a connection (spec §10).
pub const PING_MISSES: u32 = 5;
/// A node changes its ID because of a conflict at most this often; past
/// that it only warns, so that a member forging information cannot make
/// it change again and again (spec §12.3).
pub const ID_RENEW_INTERVAL: Duration = Duration::from_secs(600);
/// Version string announced in route information (spec §12.3).
pub const VERSION_STRING: &str = "2.6.4-compat";

/// Something the driver must do.
#[derive(Debug, PartialEq, Eq)]
pub enum Action {
    /// Write a node packet on a connection.
    Send { conn: ConnId, packet: Vec<u8> },
    /// Write an IP packet to the virtual interface.
    Deliver(Vec<u8>),
    /// Close a connection.
    Close { conn: ConnId, reason: CloseReason },
}

/// Counters for the status (requirement R16).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Counters {
    /// IP packets refused before sending: not intranet, no route.
    pub refused_outgoing: u64,
    /// IP packets from peers refused by the source and destination checks.
    pub refused_incoming: u64,
    /// Packets for this node that failed the receive checks.
    pub dropped: u64,
    /// Data or RPC that arrived without encryption (spec §7.6, §8.7).
    pub unencrypted: u64,
    /// Packets relayed for other nodes.
    pub relayed: u64,
    /// Packets that could not be relayed or sent: no route, hop limit.
    pub unroutable: u64,
    /// Times this node took new node and route IDs after a conflict.
    pub id_renewals: u64,
    /// Node information refused: over a limit or malformed (spec §12.3).
    pub refused_infos: u64,
    /// Information of new nodes refused past the storage budget.
    pub refused_over_budget: u64,
    /// Connection graphs refused: over the limits or malformed (§12.4).
    pub refused_graphs: u64,
    /// Connection rows refused past the stored edge limit (§12.4).
    pub refused_rows: u64,
    /// Connection graphs sent cut short to fit one request (§12.4).
    pub cut_graphs: u64,
    /// Node information off the native key list (spec §8.3.1 rule 4).
    pub refused_not_native: u64,
}

#[derive(Default)]
struct Ping {
    seq: u32,
    outstanding: Option<(u32, Instant)>,
    misses: u32,
    interval: Duration,
    next_at: Option<Instant>,
}

struct Conn {
    link: Link,
    peer: Option<u32>,
    ping: Ping,
    rtt: Option<Duration>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CallKind {
    SyncRoute,
    ReportPeers,
    GetPeerMap,
}

struct Outgoing {
    peer: u32,
    kind: CallKind,
    deadline: Instant,
}

/// The node's identity in its network: node ID, instance ID and route ID,
/// generated anew by [`Node::new`] at every start (spec §12.3). The static
/// key is kept per network by the caller and passed in.
struct Identity {
    peer_id: u32,
    inst_id: Uuid,
    route_id: u64,
}

impl Identity {
    fn generate(rng: &dyn SecureRandom) -> Result<Self, Unspecified> {
        let mut bytes = [0u8; 28];
        rng.fill(&mut bytes)?;
        let mut peer_id = [0u8; 4];
        peer_id.copy_from_slice(&bytes[..4]);
        let mut inst_id = [0u8; 16];
        inst_id.copy_from_slice(&bytes[4..20]);
        let mut route_id = [0u8; 8];
        route_id.copy_from_slice(&bytes[20..]);
        Ok(Self {
            // 0 is no node (spec §4.1).
            peer_id: u32::from_le_bytes(peer_id).max(1),
            inst_id: Uuid(inst_id),
            route_id: u64::from_le_bytes(route_id),
        })
    }
}

pub struct Node {
    settings: MeshSettings,
    local: Local,
    legacy: Option<LegacyCipher>,
    sessions: Sessions,
    sync: RouteSync,
    routes: RouteTable,
    conns: BTreeMap<ConnId, Conn>,
    reassembler: Reassembler,
    calls: BTreeMap<i64, Outgoing>,
    next_transaction: i64,
    centre: CentreServer,
    peer_map: GlobalPeerMap,
    /// When, to which centre and what this node last reported.
    last_report: Option<(Instant, u32, PeerMap)>,
    /// When and from which centre this node last fetched the map.
    last_fetch: Option<(Instant, u32)>,
    actions: VecDeque<Action>,
    counters: Counters,
    duplicate_id: bool,
    /// The last peer refused for a static key off the native key list
    /// (spec §8.3.1 rule 5), and when.
    not_native: Option<(u32, Instant)>,
    /// When this node last took a new identity after a conflict.
    renewed_at: Option<Instant>,
    /// Relay sessions being set up, by destination (secure mode only).
    relays: BTreeMap<u32, Relay>,
}

fn own_info(settings: &MeshSettings, identity: &Identity, static_key: &KeyPair) -> RoutePeerInfo {
    let ipv4 = match settings.address.address() {
        IpAddr::V4(v4) => Some(v4),
        IpAddr::V6(_) => None,
    };
    let ipv6 = settings.address_v6.and_then(|net| match net.address() {
        IpAddr::V6(v6) => Some((v6, u32::from(net.prefix()))),
        IpAddr::V4(_) => None,
    });
    let relays = settings.role == Role::Full && settings.relay;
    let advertise = if settings.role == Role::Full {
        settings
            .advertise_subnets
            .iter()
            .map(|net| net.to_string())
            .collect()
    } else {
        Vec::new()
    };
    RoutePeerInfo {
        peer_id: identity.peer_id,
        inst_id: identity.inst_id,
        cost: 1,
        ipv4,
        proxy_cidrs: advertise,
        hostname: settings.hostname.clone(),
        // IDs are new at every start, so the version starts at 1
        // (spec §12.3).
        version: 1,
        version_string: VERSION_STRING.into(),
        features: FeatureFlags::ours(relays),
        route_id: identity.route_id,
        network_length: u32::from(settings.address.prefix()),
        ipv6,
        noise_pubkey: match settings.security {
            SecurityMode::ForwardSecrecy => static_key.public().to_vec(),
            SecurityMode::Default => Vec::new(),
        },
        ..RoutePeerInfo::default()
    }
}

/// The static keys a managed network admits (spec §8.3.1); `None` for a
/// legacy network, which admits every key.
fn admitted_keys(settings: &MeshSettings) -> Option<Vec<[u8; LEN]>> {
    match settings.kind {
        NetworkKind::Managed => Some(settings.native_keys.clone().unwrap_or_default()),
        NetworkKind::Legacy => None,
    }
}

fn random_i64(rng: &dyn SecureRandom) -> Result<i64, Unspecified> {
    let mut bytes = [0u8; 8];
    rng.fill(&mut bytes)?;
    // Positive, with room to count up.
    Ok((u64::from_le_bytes(bytes) >> 2) as i64)
}

impl Node {
    /// A node of the network `settings` describes (already validated),
    /// with the network's static key. Node, instance and route IDs are new
    /// every time.
    pub fn new(
        settings: MeshSettings,
        static_key: KeyPair,
        rng: &dyn SecureRandom,
        now: Instant,
    ) -> Result<Self, Unspecified> {
        let identity = Identity::generate(rng)?;
        Self::with_identity(settings, identity, static_key, rng, now)
    }

    fn with_identity(
        settings: MeshSettings,
        identity: Identity,
        static_key: KeyPair,
        rng: &dyn SecureRandom,
        now: Instant,
    ) -> Result<Self, Unspecified> {
        let secret = settings.network_secret.as_bytes().to_vec();
        let legacy = match settings.security {
            SecurityMode::Default => {
                LegacyCipher::new(settings.cipher, &secret).map_err(|_| Unspecified)?
            }
            SecurityMode::ForwardSecrecy => None,
        };
        let info = own_info(&settings, &identity, &static_key);
        let local = Local {
            id: identity.peer_id,
            static_key,
            network_name: settings.network_name.clone(),
            node_name: settings
                .hostname
                .clone()
                .unwrap_or_else(|| format!("node-{}", identity.peer_id)),
            digest: Some(digest(settings.network_name.as_bytes(), &secret)),
            secret: Some(secret),
            cipher: settings.cipher,
            trusted_keys: Vec::new(),
            native_keys: admitted_keys(&settings),
        };
        let routes = RouteTable::new(&settings);
        Ok(Self {
            local,
            legacy,
            sessions: Sessions::new(),
            sync: {
                let mut sync = RouteSync::new(info, now);
                sync.set_admitted(admitted_keys(&settings));
                sync
            },
            routes,
            conns: BTreeMap::new(),
            reassembler: Reassembler::new(),
            calls: BTreeMap::new(),
            next_transaction: random_i64(rng)?,
            centre: CentreServer::new(),
            peer_map: GlobalPeerMap::default(),
            last_report: None,
            last_fetch: None,
            actions: VecDeque::new(),
            counters: Counters::default(),
            duplicate_id: false,
            not_native: None,
            renewed_at: None,
            relays: BTreeMap::new(),
            settings,
        })
    }

    pub fn id(&self) -> u32 {
        self.local.id
    }

    pub fn settings(&self) -> &MeshSettings {
        &self.settings
    }

    pub fn counters(&self) -> Counters {
        let refused = self.sync.refused();
        Counters {
            refused_infos: refused.infos,
            refused_over_budget: refused.over_budget,
            refused_graphs: refused.graphs,
            refused_rows: refused.rows,
            cut_graphs: refused.cut_graphs,
            refused_not_native: refused.not_native,
            ..self.counters
        }
    }

    pub fn route_table(&self) -> &RouteTable {
        &self.routes
    }

    /// Replaces the native key list of a managed network while it runs
    /// (spec §8.3.1): the panel lists a new member, or drops one. Route
    /// information, direct connections and relay sessions of keys no
    /// longer on the list go; the rest stay up. A list that no longer
    /// holds this node makes [`Node::waits_for_native_keys`] true, and the
    /// caller stops the node.
    pub fn set_native_keys(&mut self, keys: Option<Vec<[u8; LEN]>>, now: Instant) {
        self.settings.native_keys = keys;
        let admitted = admitted_keys(&self.settings);
        self.local.native_keys = admitted.clone();
        self.sync.set_admitted(admitted);
        let refused = self.sessions.refused_by(|key| self.settings.admits(key));
        for key in refused {
            let conns: Vec<ConnId> = match key.namespace {
                Namespace::Direct => self
                    .conns
                    .iter()
                    .filter(|(_, state)| state.peer == Some(key.peer_id))
                    .map(|(&conn, _)| conn)
                    .collect(),
                Namespace::Relay => Vec::new(),
            };
            for conn in conns {
                self.close(conn, CloseReason::NotNative(key.peer_id), now);
            }
            self.sessions.invalidate(&key);
            self.relays.remove(&key.peer_id);
        }
        // Answers not yet confirmed by a packet, and handshakes this node
        // started under the old list, go too.
        let settings = &self.settings;
        self.sessions
            .drop_pending_refused(|key| settings.admits(key));
        let stale: Vec<u32> = self
            .relays
            .iter()
            .filter(|(_, relay)| {
                relay
                    .initiator
                    .as_ref()
                    .is_some_and(|initiator| !settings.admits(&initiator.peer_static()))
            })
            .map(|(&peer, _)| peer)
            .collect();
        for peer in stale {
            self.drop_relay(peer);
        }
        // A new list is a new start for refusals (spec §8.3.1 rule 5).
        self.not_native = None;
        self.refresh_routes();
    }

    /// The networks of this machine's other interfaces (spec §15.4).
    pub fn set_local_networks(&mut self, interfaces: &[IpNet]) {
        self.routes.set_local_networks(interfaces, &[]);
    }

    /// Subnets to route into the virtual interface: accepted and routed,
    /// limited to `routing.system_routes` when it is set.
    /// At most [`MAX_SYSTEM_ROUTES`], in the table's stable order, so that
    /// the members cannot fill the system routing table.
    pub fn system_routes(&self) -> Vec<IpNet> {
        let routes = self.routes.system_routes().into_iter();
        match &self.settings.system_routes {
            None => routes.take(MAX_SYSTEM_ROUTES).collect(),
            Some(allowed) => routes
                .filter(|subnet| allowed.iter().any(|allowed| allowed.covers(subnet)))
                .take(MAX_SYSTEM_ROUTES)
                .collect(),
        }
    }

    pub fn route_sync(&self) -> &RouteSync {
        &self.sync
    }

    /// This node's ID is taken by another node and it could not change
    /// it yet (at most once in [`ID_RENEW_INTERVAL`], spec §12.3): a
    /// warning. Cleared when the node takes a new ID.
    pub fn duplicate_id(&self) -> bool {
        self.duplicate_id
    }

    /// The last peer refused because its static key is off the native key
    /// list (spec §8.3.1 rule 5), for the status reason `peer_not_native`.
    /// It clears when that peer completes a handshake, when the list
    /// changes, or [`NOT_NATIVE_HOLD`] after the last refusal.
    pub fn last_not_native(&self) -> Option<u32> {
        self.not_native.map(|(peer, _)| peer)
    }

    fn refused_not_native(&mut self, peer: u32, now: Instant) {
        self.not_native = Some((peer, now));
    }

    /// `peer` completed a handshake: a refusal of it is over.
    fn admitted_peer(&mut self, peer: u32) {
        if self.not_native.is_some_and(|(refused, _)| refused == peer) {
            self.not_native = None;
        }
    }

    /// This node's static public key in the network.
    pub fn static_public(&self) -> [u8; LEN] {
        self.local.static_key.public()
    }

    /// A managed network waits while its native key list lacks this
    /// node's key (spec §8.3.1 rule 1): the driver opens no links.
    pub fn waits_for_native_keys(&self) -> bool {
        self.settings.waits_for_native_keys(&self.static_public())
    }

    /// Another node holds this node's ID (spec §5.3, §12.2, §12.3): take
    /// new node, instance and route IDs, unless that happened less than
    /// [`ID_RENEW_INTERVAL`] ago; then only warn.
    fn id_conflict(&mut self, rng: &dyn SecureRandom, now: Instant) {
        let recent = self
            .renewed_at
            .is_some_and(|at| now.saturating_duration_since(at) < ID_RENEW_INTERVAL);
        if recent || self.renew_identity(rng, now).is_err() {
            self.duplicate_id = true;
        }
    }

    /// Starts again under a new identity: every connection closes (the
    /// driver dials again), and everything learnt under the old ID goes.
    /// The static key, the settings and this machine's networks stay.
    fn renew_identity(&mut self, rng: &dyn SecureRandom, now: Instant) -> Result<(), Unspecified> {
        let identity = Identity::generate(rng)?;
        let next_transaction = random_i64(rng)?;
        let conns: Vec<ConnId> = self.conns.keys().copied().collect();
        for conn in conns {
            self.close(conn, CloseReason::IdConflict, now);
        }
        self.local.id = identity.peer_id;
        if self.settings.hostname.is_none() {
            self.local.node_name = format!("node-{}", identity.peer_id);
        }
        self.sync = RouteSync::new(
            own_info(&self.settings, &identity, &self.local.static_key),
            now,
        );
        self.sync.set_admitted(admitted_keys(&self.settings));
        self.sessions = Sessions::new();
        self.reassembler = Reassembler::new();
        self.calls.clear();
        self.next_transaction = next_transaction;
        self.centre = CentreServer::new();
        self.peer_map = GlobalPeerMap::default();
        self.last_report = None;
        self.last_fetch = None;
        self.relays.clear();
        self.duplicate_id = false;
        self.renewed_at = Some(now);
        self.counters.id_renewals += 1;
        self.refresh_routes();
        Ok(())
    }

    /// Whether the connection finished its handshake.
    pub fn is_up(&self, conn: ConnId) -> bool {
        self.conns
            .get(&conn)
            .is_some_and(|state| state.peer.is_some())
    }

    /// Direct neighbours that have a connection up.
    pub fn neighbours(&self) -> Vec<u32> {
        let mut peers: Vec<u32> = self.conns.values().filter_map(|conn| conn.peer).collect();
        peers.sort_unstable();
        peers.dedup();
        peers
    }

    /// The latest round-trip time to a neighbour, from keep-alive.
    pub fn latency(&self, peer: u32) -> Option<Duration> {
        self.conns
            .values()
            .filter(|conn| conn.peer == Some(peer))
            .filter_map(|conn| conn.rtt)
            .min()
    }

    /// Routes to every reachable node, by the configured policy.
    pub fn paths(&self) -> BTreeMap<u32, Route> {
        self.compute_routes(self.policy_metric())
    }

    /// The next action to carry out.
    pub fn poll_action(&mut self) -> Option<Action> {
        self.actions.pop_front()
    }

    fn policy_metric(&self) -> Metric {
        match self.settings.route_policy {
            RoutePolicy::Hops => Metric::Hops,
            RoutePolicy::Latency => Metric::Latency,
        }
    }

    fn compute_routes(&self, metric: Metric) -> BTreeMap<u32, Route> {
        let map = &self.peer_map.map;
        self.sync.topology().routes(self.local.id, metric, |a, b| {
            map.get(&a)
                .and_then(|row| row.get(&b))
                .and_then(|&ms| u64::try_from(ms).ok())
        })
    }

    fn with_handshake<T>(
        &mut self,
        rng: &dyn SecureRandom,
        now: Instant,
        f: impl FnOnce(&mut Handshaking<'_>, &mut BTreeMap<ConnId, Conn>) -> T,
    ) -> T {
        let mut hs = Handshaking {
            local: &self.local,
            security: self.settings.security,
            sessions: &mut self.sessions,
            rng,
            now,
        };
        f(&mut hs, &mut self.conns)
    }

    /// The driver opened a connection; `known_peer` is the node it expects
    /// to reach, if known. The first packet is queued.
    pub fn connect(
        &mut self,
        conn: ConnId,
        known_peer: Option<u32>,
        rng: &dyn SecureRandom,
        now: Instant,
    ) -> Result<(), CloseReason> {
        let (link, first) = self.with_handshake(rng, now, |hs, _| Link::client(hs, known_peer))?;
        self.conns.insert(
            conn,
            Conn {
                link,
                peer: None,
                ping: Ping::default(),
                rtt: None,
            },
        );
        self.actions.push_back(Action::Send {
            conn,
            packet: first,
        });
        Ok(())
    }

    /// A peer opened a connection.
    pub fn accept(&mut self, conn: ConnId, now: Instant) {
        self.conns.insert(
            conn,
            Conn {
                link: Link::server(now),
                peer: None,
                ping: Ping::default(),
                rtt: None,
            },
        );
    }

    /// The connection closed on the driver's side.
    pub fn disconnected(&mut self, conn: ConnId, now: Instant) {
        let Some(mut state) = self.conns.remove(&conn) else {
            return;
        };
        state.link.close(&mut self.sessions);
        if let Some(peer) = state.peer {
            if self.settings.security == SecurityMode::ForwardSecrecy {
                self.sessions.release(&self.direct_key(peer), now);
            }
            if !self.conns.values().any(|other| other.peer == Some(peer)) {
                // A late answer or timeout must not land on the next
                // connection's synchronisation.
                self.calls
                    .retain(|_, call| !(call.peer == peer && call.kind == CallKind::SyncRoute));
                self.sync.neighbour_down(peer);
                self.refresh_routes();
            }
        }
    }

    fn close(&mut self, conn: ConnId, reason: CloseReason, now: Instant) {
        self.disconnected(conn, now);
        self.actions.push_back(Action::Close { conn, reason });
    }

    fn direct_key(&self, peer: u32) -> crate::secure::session::SessionKey {
        crate::secure::session::SessionKey {
            namespace: crate::secure::session::Namespace::Direct,
            network: self.settings.network_name.clone(),
            peer_id: peer,
        }
    }

    /// One node packet arrived on a connection.
    pub fn receive(&mut self, conn: ConnId, packet: &[u8], rng: &dyn SecureRandom, now: Instant) {
        let Some(state) = self.conns.get(&conn) else {
            return;
        };
        let peer = state.peer;
        match peer {
            None => self.handshake(conn, packet, rng, now),
            Some(neighbour) => self.receive_up(conn, neighbour, packet, rng, now),
        }
    }

    fn handshake(&mut self, conn: ConnId, packet: &[u8], rng: &dyn SecureRandom, now: Instant) {
        let step = self.with_handshake(rng, now, |hs, conns| {
            conns
                .get_mut(&conn)
                .map(|state| state.link.handshake(hs, packet))
        });
        let Some(step) = step else { return };
        match step {
            Step::Send(out) => {
                for packet in out {
                    self.actions.push_back(Action::Send { conn, packet });
                }
            }
            Step::Up(out, up) => {
                for packet in out {
                    self.actions.push_back(Action::Send { conn, packet });
                }
                self.connection_up(conn, up, rng, now);
            }
            Step::Close(out, reason) => {
                for packet in out {
                    self.actions.push_back(Action::Send { conn, packet });
                }
                self.close(conn, reason, now);
                if let CloseReason::NotNative(peer) = reason {
                    self.refused_not_native(peer, now);
                }
                // Only after the server proved the network secret (§5.3).
                if reason == CloseReason::IdConflict {
                    self.id_conflict(rng, now);
                }
            }
        }
    }

    fn connection_up(&mut self, conn: ConnId, up: Up, rng: &dyn SecureRandom, now: Instant) {
        let Some(state) = self.conns.get_mut(&conn) else {
            return;
        };
        state.peer = Some(up.peer_id);
        state.ping = Ping {
            interval: PING_START,
            next_at: Some(now + PING_START),
            ..Ping::default()
        };
        self.admitted_peer(up.peer_id);
        if self.sync.neighbour_up(up.peer_id, rng, now).is_err() {
            self.close(conn, CloseReason::Unexpected, now);
            return;
        }
        self.refresh_routes();
    }

    fn crypto(&mut self) -> Crypto<'_> {
        match self.settings.security {
            SecurityMode::Default => Crypto::Default(self.legacy.as_ref()),
            SecurityMode::ForwardSecrecy => Crypto::Secure {
                sessions: &mut self.sessions,
                network: &self.settings.network_name,
            },
        }
    }

    fn receive_up(
        &mut self,
        conn: ConnId,
        neighbour: u32,
        packet: &[u8],
        rng: &dyn SecureRandom,
        now: Instant,
    ) {
        let Some(header) = NodeHeader::decode(packet) else {
            self.counters.dropped += 1;
            return;
        };
        if header.to != self.local.id {
            self.forward(packet);
            return;
        }
        let mut crypto = self.crypto();
        let inbound = match link::open(&mut crypto, neighbour, packet, now) {
            Ok(inbound) => inbound,
            Err(Dropped::Unencrypted) => {
                self.counters.unencrypted += 1;
                return;
            }
            Err(_) => {
                self.counters.dropped += 1;
                return;
            }
        };
        let from = inbound.header.from;
        match inbound.header.packet_type {
            packet_type::PING => {
                // Same header, type changed (spec §10).
                let mut pong = packet[..HEADER_LEN].to_vec();
                pong[8] = packet_type::PONG;
                pong.extend_from_slice(&inbound.payload);
                self.actions.push_back(Action::Send { conn, packet: pong });
            }
            packet_type::PONG => self.pong(conn, &inbound.payload, now),
            packet_type::DATA => match self.routes.check_incoming(PeerId(from), &inbound.payload) {
                Ok(()) => self.actions.push_back(Action::Deliver(inbound.payload)),
                Err(_) => self.counters.refused_incoming += 1,
            },
            packet_type::RPC_REQ | packet_type::RPC_RESP => {
                self.rpc_piece(from, neighbour, &inbound.payload, rng, now)
            }
            packet_type::RELAY_HANDSHAKE => self.relay_msg1(from, &inbound.payload, rng, now),
            packet_type::RELAY_HANDSHAKE_ACK => self.relay_msg2(from, &inbound.payload, now),
            _ => self.counters.dropped += 1,
        }
        // A packet that decrypted under the session this node answered
        // makes it current (spec §9 rule 2): what waited can go now.
        if inbound.was_encrypted
            && from != neighbour
            && self
                .relays
                .get(&from)
                .is_some_and(|relay| relay.initiator.is_none())
        {
            self.flush_relay(from, now);
        }
        self.wake(rng, now);
    }

    fn pong(&mut self, conn: ConnId, payload: &[u8], now: Instant) {
        let Some(state) = self.conns.get_mut(&conn) else {
            return;
        };
        let Ok(seq) = <[u8; 4]>::try_from(payload).map(u32::from_le_bytes) else {
            return;
        };
        if let Some((expected, sent)) = state.ping.outstanding {
            if expected == seq {
                state.rtt = Some(now.saturating_duration_since(sent));
                state.ping.outstanding = None;
                state.ping.misses = 0;
                state.ping.interval = (state.ping.interval * 2).min(PING_MAX);
            }
        }
    }

    /// Relays a packet for another node (spec §14).
    fn forward(&mut self, packet: &[u8]) {
        if self.settings.role == Role::Access || !self.settings.relay {
            self.counters.unroutable += 1;
            return;
        }
        let mut packet = packet.to_vec();
        if !relay_in_place(&mut packet) {
            self.counters.unroutable += 1;
            return;
        }
        let Some(header) = NodeHeader::decode(&packet) else {
            return;
        };
        match self.next_hop_conn(header.to, header.has(flags::LATENCY_FIRST)) {
            Some(conn) => {
                self.counters.relayed += 1;
                self.actions.push_back(Action::Send { conn, packet });
            }
            None => self.counters.unroutable += 1,
        }
    }

    /// The connection to the next hop towards `to` (spec §13, §14): the
    /// neighbour itself when direct, with the lowest ping on that neighbour.
    fn next_hop_conn(&self, to: u32, latency_first: bool) -> Option<ConnId> {
        let next_hop = if self.conns.values().any(|conn| conn.peer == Some(to)) {
            to
        } else {
            let metric = if latency_first {
                Metric::Latency
            } else {
                Metric::Hops
            };
            self.compute_routes(metric).get(&to)?.next_hop
        };
        self.conns
            .iter()
            .filter(|(_, conn)| conn.peer == Some(next_hop))
            .min_by_key(|(_, conn)| conn.rtt.unwrap_or(Duration::MAX))
            .map(|(&id, _)| id)
    }

    /// Sends a packet this node originates (spec §7.5, §8.7, §14).
    fn originate(&mut self, to: u32, kind: u8, payload: &[u8], now: Instant) -> bool {
        let latency_first = self.settings.route_policy == RoutePolicy::Latency;
        let Some(conn) = self.next_hop_conn(to, latency_first) else {
            self.counters.unroutable += 1;
            return false;
        };
        let Some(next_hop) = self.conns.get(&conn).and_then(|c| c.peer) else {
            return false;
        };
        let from = self.local.id;
        let secure = self.settings.security == SecurityMode::ForwardSecrecy;
        let mut crypto = self.crypto();
        let mut packet = match link::seal(&mut crypto, from, to, next_hop, kind, payload, now) {
            Ok(packet) => packet,
            // No end-to-end session with a node behind a relay yet: keep the
            // packet and set one up (spec §9).
            Err(Dropped::NoSession | Dropped::SessionEnded) if secure && next_hop != to => {
                return self.queue_for_relay(to, kind, payload, now);
            }
            Err(_) => {
                self.counters.unroutable += 1;
                return false;
            }
        };
        if latency_first && packet.len() > 9 {
            packet[9] |= flags::LATENCY_FIRST;
        }
        self.actions.push_back(Action::Send { conn, packet });
        true
    }

    /// An IP packet from the virtual interface.
    ///
    /// A broadcast or multicast goes to every direct neighbour, addressed
    /// to each of them, and is not relayed further (spec §15.3).
    pub fn send_ip(&mut self, packet: &[u8], now: Instant) -> Result<(), Denied> {
        let outgoing = match self.routes.classify_outgoing(packet) {
            Ok(outgoing) => outgoing,
            Err(denied) => {
                self.counters.refused_outgoing += 1;
                return Err(denied);
            }
        };
        let sent = match outgoing {
            routes::Outgoing::Peer(peer) => self.originate(peer.0, packet_type::DATA, packet, now),
            routes::Outgoing::Neighbours => {
                let mut any = false;
                for neighbour in self.neighbours() {
                    any |= self.originate(neighbour, packet_type::DATA, packet, now);
                }
                any
            }
        };
        if !sent {
            return Err(Denied::NoRoute);
        }
        Ok(())
    }

    fn next_transaction(&mut self) -> i64 {
        self.next_transaction = self.next_transaction.wrapping_add(1).max(1);
        self.next_transaction
    }

    fn descriptor(&self, service: &str, method: u32) -> Descriptor {
        Descriptor {
            domain: self.settings.network_name.clone(),
            service: service.into(),
            method_index: method,
        }
    }

    fn send_rpc(
        &mut self,
        to: u32,
        transaction: i64,
        descriptor: &Descriptor,
        is_request: bool,
        body: &[u8],
        now: Instant,
    ) {
        for piece in split(self.local.id, to, transaction, descriptor, is_request, body) {
            let kind = if is_request {
                packet_type::RPC_REQ
            } else {
                packet_type::RPC_RESP
            };
            if !self.originate(to, kind, &piece.encode(), now) {
                return;
            }
        }
    }

    fn call(&mut self, to: u32, kind: CallKind, request: Vec<u8>, now: Instant) {
        let (service, method, timeout_ms) = match kind {
            CallKind::SyncRoute => (ROUTE_SERVICE, METHOD_SYNC_ROUTE_INFO, ROUTE_SYNC_TIMEOUT_MS),
            CallKind::ReportPeers => (
                center::SERVICE,
                center::METHOD_REPORT_PEERS,
                DEFAULT_TIMEOUT_MS,
            ),
            CallKind::GetPeerMap => (
                center::SERVICE,
                center::METHOD_GET_GLOBAL_PEER_MAP,
                DEFAULT_TIMEOUT_MS,
            ),
        };
        let transaction = self.next_transaction();
        let body = RpcRequest {
            request,
            timeout_ms: timeout_ms as i32,
        }
        .encode();
        let descriptor = self.descriptor(service, method);
        self.calls.insert(
            transaction,
            Outgoing {
                peer: to,
                kind,
                deadline: now + Duration::from_millis(u64::from(timeout_ms)),
            },
        );
        self.send_rpc(to, transaction, &descriptor, true, &body, now);
    }

    /// One RPC piece from `from` (the packet header) that arrived over a
    /// connection to `neighbour`.
    fn rpc_piece(
        &mut self,
        from: u32,
        neighbour: u32,
        payload: &[u8],
        rng: &dyn SecureRandom,
        now: Instant,
    ) {
        let Ok(piece) = RpcPacket::decode(payload) else {
            self.counters.dropped += 1;
            return;
        };
        let timeout = Duration::from_millis(u64::from(DEFAULT_TIMEOUT_MS));
        let call = match self.reassembler.push(from, piece, timeout, now) {
            Ok(Some(call)) => call,
            Ok(None) => return,
            Err(_) => {
                self.counters.dropped += 1;
                return;
            }
        };
        if call.is_request {
            // Route synchronisation only with the neighbour the connection
            // authenticated, never with a header `from` (spec §12.2).
            let route_sync = call.descriptor.service == ROUTE_SERVICE
                && call.descriptor.method_index == METHOD_SYNC_ROUTE_INFO;
            if route_sync && from != neighbour {
                self.counters.dropped += 1;
                return;
            }
            let result = self.serve(from, &call.descriptor, &call.body, now);
            let body = RpcResponse {
                result,
                runtime_us: 0,
            }
            .encode();
            self.send_rpc(
                from,
                call.transaction_id,
                &call.descriptor,
                false,
                &body,
                now,
            );
        } else {
            self.answered(from, neighbour, call.transaction_id, &call.body, rng, now);
        }
    }

    fn serve(
        &mut self,
        from: u32,
        descriptor: &Descriptor,
        body: &[u8],
        now: Instant,
    ) -> Result<Vec<u8>, RpcError> {
        let request = RpcRequest::decode(body).map_err(|_| RpcError::Decode)?;
        match (descriptor.service.as_str(), descriptor.method_index) {
            (ROUTE_SERVICE, METHOD_SYNC_ROUTE_INFO) => {
                // Only a direct neighbour synchronises with this node.
                let request =
                    SyncRouteRequest::decode(&request.request).map_err(|_| RpcError::Decode)?;
                let response = self.sync.on_request(from, request, now);
                self.refresh_routes();
                Ok(response.encode())
            }
            (ROUTE_SERVICE, _) => Err(RpcError::InvalidMethod),
            (center::SERVICE, center::METHOD_REPORT_PEERS) => {
                let report = ReportPeers::decode(&request.request).map_err(|_| RpcError::Decode)?;
                if report.my_peer_id != from {
                    return Err(RpcError::Decode);
                }
                let _ = self.centre.report(report, now);
                Ok(Vec::new())
            }
            (center::SERVICE, center::METHOD_GET_GLOBAL_PEER_MAP) => {
                let digest =
                    center::decode_get_request(&request.request).map_err(|_| RpcError::Decode)?;
                Ok(self.centre.get(digest).encode())
            }
            (center::SERVICE, _) => Err(RpcError::InvalidMethod),
            _ => Err(RpcError::InvalidService),
        }
    }

    /// An answer from `from` that arrived over the connection to
    /// `neighbour`. Route synchronisation answers count only from the
    /// neighbour the connection authenticated (spec §12.2), as requests do.
    fn answered(
        &mut self,
        from: u32,
        neighbour: u32,
        transaction: i64,
        body: &[u8],
        rng: &dyn SecureRandom,
        now: Instant,
    ) {
        let Some(outgoing) = self.calls.get(&transaction) else {
            return;
        };
        if outgoing.peer != from {
            return;
        }
        if outgoing.kind == CallKind::SyncRoute && from != neighbour {
            self.counters.dropped += 1;
            return;
        }
        let Some(outgoing) = self.calls.remove(&transaction) else {
            return;
        };
        let result = RpcResponse::decode(body).ok().and_then(|r| r.result.ok());
        match outgoing.kind {
            CallKind::SyncRoute => {
                let response = result.and_then(|bytes| SyncRouteResponse::decode(&bytes).ok());
                if let Ok(Some(Notice::DuplicatePeerId)) =
                    self.sync.on_response(from, response, rng, now)
                {
                    self.id_conflict(rng, now);
                }
            }
            CallKind::ReportPeers => {}
            CallKind::GetPeerMap => {
                if let Some(map) = result.and_then(|bytes| GlobalPeerMap::decode(&bytes).ok()) {
                    // An empty answer without a digest: nothing changed.
                    if map.digest.is_some() {
                        self.peer_map = map;
                    }
                }
            }
        }
    }

    /// Feeds route information into the route table (spec §15.1, §15.4).
    fn refresh_routes(&mut self) {
        if !self.sync.take_changed() {
            return;
        }
        let reachable = self.compute_routes(Metric::Hops);
        let mut known = Vec::new();
        for info in self.sync.infos() {
            if !reachable.contains_key(&info.peer_id) {
                continue;
            }
            let mut addresses: Vec<IpAddr> = info.ipv4.map(IpAddr::V4).into_iter().collect();
            addresses.extend(info.ipv6.map(|(v6, _)| IpAddr::V6(v6)));
            // Unknown forms are skipped (spec §15.1).
            let subnets: Vec<IpNet> = info
                .proxy_cidrs
                .iter()
                .filter_map(|text| IpNet::parse(text))
                .collect();
            known.push((PeerId(info.peer_id), addresses, subnets));
        }
        let current: Vec<PeerId> = known.iter().map(|(peer, _, _)| *peer).collect();
        for (peer, addresses, subnets) in known {
            self.routes.set_peer(peer, &addresses, &subnets);
        }
        let stale: Vec<PeerId> = self
            .routes
            .peers()
            .filter(|peer| !current.contains(peer))
            .collect();
        for peer in stale {
            self.routes.remove_peer(peer);
        }
    }

    /// Timers: keep-alive, handshake timeouts, route synchronisation, the
    /// latency centre and expiry. `unix_now` is the wall-clock time.
    pub fn tick(&mut self, rng: &dyn SecureRandom, now: Instant, unix_now: (i64, i32)) {
        self.handshake_timeouts(now);
        self.keep_alive(now);
        self.expire_calls(rng, now);

        for (peer, request) in self.sync.poll(now, unix_now) {
            self.call(peer, CallKind::SyncRoute, request.encode(), now);
        }
        // Rule 1 of spec §12.3, or this node's version ran out.
        if self.sync.take_conflict() {
            self.id_conflict(rng, now);
        }
        self.sync.expire(now);
        self.refresh_routes();
        self.centre_round(now);
        self.reassembler.expire(now);
        self.sessions.reclaim(now);
        if self
            .not_native
            .is_some_and(|(_, at)| now.saturating_duration_since(at) >= NOT_NATIVE_HOLD)
        {
            self.not_native = None;
        }
        self.wake(rng, now);
    }

    /// The next time [`wake`](Self::wake) has something to do, earlier
    /// than the next [`tick`](Self::tick): a relay msg1 to send again.
    pub fn next_wake(&self) -> Option<Instant> {
        self.relays.values().filter_map(|relay| relay.due).min()
    }

    /// Sends the relay handshakes that are due: first attempts for packets
    /// queued since, and retries. The driver calls it after
    /// [`send_ip`](Self::send_ip) and at [`next_wake`](Self::next_wake).
    pub fn wake(&mut self, rng: &dyn SecureRandom, now: Instant) {
        let due: Vec<u32> = self
            .relays
            .iter()
            .filter(|(_, relay)| relay.due.is_some_and(|due| due <= now))
            .map(|(&peer, _)| peer)
            .collect();
        for peer in due {
            self.start_relay(peer, rng, now);
        }
    }

    fn queue_for_relay(&mut self, to: u32, kind: u8, payload: &[u8], now: Instant) -> bool {
        let relay = self.relays.entry(to).or_insert_with(|| Relay {
            initiator: None,
            attempts: 0,
            due: Some(now),
            queue: VecDeque::new(),
        });
        if relay.queue.len() >= RELAY_QUEUE {
            self.counters.unroutable += 1;
            return false;
        }
        relay.queue.push_back((kind, payload.to_vec()));
        true
    }

    /// Gives up on `peer`: its queued packets count as unroutable.
    fn drop_relay(&mut self, peer: u32) {
        if let Some(relay) = self.relays.remove(&peer) {
            self.counters.unroutable += relay.queue.len() as u64;
        }
    }

    fn start_relay(&mut self, peer: u32, rng: &dyn SecureRandom, now: Instant) {
        let attempts = match self.relays.get(&peer) {
            Some(relay) => relay.attempts,
            None => return,
        };
        if attempts > RELAY_RETRIES {
            self.drop_relay(peer);
            return;
        }
        let Some(peer_static) = self.expected_key(peer) else {
            if self.peer_static(peer).is_some() {
                // Announced, but off the native key list (spec §8.3.1).
                self.refused_not_native(peer, now);
            }
            self.drop_relay(peer);
            return;
        };
        let Ok((initiator, msg1)) =
            RelayInitiator::start(&self.local, peer, peer_static, &self.sessions, rng)
        else {
            self.drop_relay(peer);
            return;
        };
        if let Some(relay) = self.relays.get_mut(&peer) {
            // Each attempt is a new handshake (spec §9).
            relay.initiator = Some(initiator);
            relay.attempts = attempts + 1;
            relay.due = Some(now + RELAY_RETRY_START * 2u32.pow(attempts));
        }
        self.originate(peer, packet_type::RELAY_HANDSHAKE, &msg1, now);
    }

    /// The static key `peer` announces in its route information.
    fn peer_static(&self, peer: u32) -> Option<[u8; LEN]> {
        self.sync
            .info(peer)
            .and_then(|info| <[u8; LEN]>::try_from(&info.noise_pubkey[..]).ok())
    }

    /// The static key a relay handshake with `peer` must use (spec §12.3):
    /// the key a handshake bound to the node ID while it has a session,
    /// otherwise the announced one, which a managed network takes only
    /// from its native key list.
    fn expected_key(&self, peer: u32) -> Option<[u8; LEN]> {
        for namespace in [Namespace::Direct, Namespace::Relay] {
            let key = SessionKey {
                namespace,
                network: self.local.network_name.clone(),
                peer_id: peer,
            };
            if let Some(session) = self.sessions.get(&key) {
                return Some(session.peer_static());
            }
        }
        self.peer_static(peer)
            .filter(|announced| self.settings.admits(announced))
    }

    /// Sends what waited for the relay session with `peer`.
    fn flush_relay(&mut self, peer: u32, now: Instant) {
        let Some(relay) = self.relays.remove(&peer) else {
            return;
        };
        for (kind, payload) in relay.queue {
            self.originate(peer, kind, &payload, now);
        }
    }

    /// Relay msg1 for this node (spec §9).
    fn relay_msg1(&mut self, from: u32, msg1: &[u8], rng: &dyn SecureRandom, now: Instant) {
        if self.settings.security != SecurityMode::ForwardSecrecy || from == self.local.id {
            self.counters.dropped += 1;
            return;
        }
        let initiating = self
            .relays
            .get(&from)
            .is_some_and(|relay| relay.initiator.is_some());
        if initiating && keeps_initiating(self.local.id, from) {
            // Both started: the smaller ID stays the initiator.
            return;
        }
        let expected = self.expected_key(from);
        let answer = relay_respond(
            &self.local,
            from,
            expected,
            msg1,
            &mut self.sessions,
            rng,
            now,
        );
        let (msg2, joined) = match answer {
            Ok(RelayAnswer::Reply(msg2, established)) => {
                self.admitted_peer(from);
                (msg2, established.action != SessionAction::Create)
            }
            Ok(RelayAnswer::Repeat(msg2)) => (msg2, false),
            Err(error) => {
                if error == HandshakeError::NotNative {
                    self.refused_not_native(from, now);
                }
                self.counters.dropped += 1;
                return;
            }
        };
        if let Some(relay) = self.relays.get_mut(&from) {
            // The peer is the initiator now; our packets wait for its
            // session, or for our own attempt if it never comes.
            relay.initiator = None;
            relay.attempts = 0;
            relay.due = Some(now + RELAY_PENDING_WAIT);
        }
        self.originate(from, packet_type::RELAY_HANDSHAKE_ACK, &msg2, now);
        if joined {
            self.flush_relay(from, now);
        }
    }

    /// Relay msg2 for this node (spec §9).
    fn relay_msg2(&mut self, from: u32, msg2: &[u8], now: Instant) {
        if from == self.local.id {
            self.counters.dropped += 1;
            return;
        }
        let Some(initiator) = self
            .relays
            .get_mut(&from)
            .and_then(|relay| relay.initiator.take())
        else {
            self.counters.dropped += 1;
            return;
        };
        match initiator.finish(&self.local, msg2, &mut self.sessions, now) {
            Ok(_) => {
                self.admitted_peer(from);
                self.flush_relay(from, now);
            }
            // Dropped from the native key list since msg1 (spec §8.3.1
            // rule 6): nothing waits for this session any more.
            Err(HandshakeError::NotNative) => {
                self.refused_not_native(from, now);
                self.counters.dropped += 1;
                self.drop_relay(from);
            }
            // The retry is a new handshake.
            Err(_) => self.counters.dropped += 1,
        }
    }

    fn handshake_timeouts(&mut self, now: Instant) {
        let sessions = &mut self.sessions;
        let expired: Vec<ConnId> = self
            .conns
            .iter_mut()
            .filter(|(_, conn)| conn.peer.is_none())
            .filter_map(|(&id, conn)| conn.link.timed_out(sessions, now).then_some(id))
            .collect();
        for conn in expired {
            self.close(conn, CloseReason::Timeout, now);
        }
    }

    fn keep_alive(&mut self, now: Instant) {
        let mut dead = Vec::new();
        let mut pings = Vec::new();
        for (&id, conn) in self.conns.iter_mut() {
            if conn.peer.is_none() {
                continue;
            }
            let ping = &mut conn.ping;
            if let Some((_, sent)) = ping.outstanding {
                if now.saturating_duration_since(sent) >= PING_TIMEOUT {
                    ping.outstanding = None;
                    ping.misses += 1;
                    ping.interval = PING_START;
                    if ping.misses >= PING_MISSES {
                        dead.push(id);
                        continue;
                    }
                }
            }
            if ping.outstanding.is_none() && ping.next_at.is_none_or(|at| now >= at) {
                ping.seq = ping.seq.wrapping_add(1);
                ping.outstanding = Some((ping.seq, now));
                ping.next_at = Some(now + ping.interval);
                pings.push((id, conn.peer.unwrap_or_default(), ping.seq));
            }
        }
        for conn in dead {
            self.close(conn, CloseReason::Timeout, now);
        }
        let from = self.local.id;
        for (conn, peer, seq) in pings {
            let packet = link::packet(from, peer, packet_type::PING, &seq.to_le_bytes());
            self.actions.push_back(Action::Send { conn, packet });
        }
    }

    fn expire_calls(&mut self, rng: &dyn SecureRandom, now: Instant) {
        let expired: Vec<i64> = self
            .calls
            .iter()
            .filter(|(_, call)| now >= call.deadline)
            .map(|(&id, _)| id)
            .collect();
        for transaction in expired {
            if let Some(call) = self.calls.remove(&transaction) {
                if call.kind == CallKind::SyncRoute {
                    let _ = self.sync.on_response(call.peer, None, rng, now);
                }
            }
        }
    }

    /// The latency centre (spec §13.3): report this node's neighbours to
    /// the centre and fetch the network's map.
    fn centre_round(&mut self, now: Instant) {
        self.centre.expire(now);
        let reachable = self.compute_routes(Metric::Hops);
        let candidates = reachable
            .keys()
            .copied()
            .filter(|peer| {
                self.sync
                    .info(*peer)
                    .is_none_or(|info| !info.features.is_public_server)
            })
            .chain(std::iter::once(self.local.id));
        let Some(centre) = center::centre(candidates) else {
            return;
        };
        let mut peers = PeerMap::new();
        for peer in self.neighbours() {
            if let Some(rtt) = self.latency(peer) {
                peers.insert(peer, i32::try_from(rtt.as_millis()).unwrap_or(i32::MAX));
            }
        }
        let report = ReportPeers {
            my_peer_id: self.local.id,
            peers,
        };
        let report_due = self.last_report.as_ref().is_none_or(|(at, to, sent)| {
            *to != centre
                || *sent != report.peers
                || now.saturating_duration_since(*at) >= center::REPORT_INTERVAL
        });
        let fetch_due = self.last_fetch.is_none_or(|(at, from)| {
            from != centre || now.saturating_duration_since(at) >= center::FETCH_INTERVAL
        });
        if self.last_fetch.is_some_and(|(_, from)| from != centre) {
            // Another centre's digest means nothing to this one.
            self.peer_map = GlobalPeerMap::default();
        }
        if report_due {
            self.last_report = Some((now, centre, report.peers.clone()));
        }
        if fetch_due {
            self.last_fetch = Some((now, centre));
        }
        let known = self.peer_map.digest.unwrap_or(0);
        if centre == self.local.id {
            let _ = self.centre.report(report, now);
            if fetch_due {
                let map = self.centre.get(known);
                if map.digest.is_some() {
                    self.peer_map = map;
                }
            }
            return;
        }
        if report_due {
            self.call(centre, CallKind::ReportPeers, report.encode(), now);
        }
        if fetch_due {
            self.call(
                centre,
                CallKind::GetPeerMap,
                center::encode_get_request(known),
                now,
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::MeshConfig;
    use ring::rand::SystemRandom;

    /// `secure`: a managed network (secure mode); otherwise a legacy
    /// network in the default mode.
    fn settings(address: &str, secure: bool) -> MeshSettings {
        let mut network = serde_json::json!({"name": "office", "secret": "s3cr3t"});
        if !secure {
            network["kind"] = serde_json::json!("legacy");
        }
        let config = serde_json::json!({
            "config_version": 1,
            "network": network,
            "node": {"address": address, "role": "full"},
            "peers": [{"server": "peer.example", "port": 40000}],
        });
        let config: MeshConfig = serde_json::from_value(config).expect("config parses");
        config.validate().expect("config is valid")
    }

    struct Net {
        nodes: Vec<Node>,
        /// (node index, conn) -> (node index, conn)
        wires: BTreeMap<(usize, ConnId), (usize, ConnId)>,
        delivered: Vec<(usize, Vec<u8>)>,
        now: Instant,
    }

    impl Net {
        fn new(addresses: &[&str], secure: bool) -> Self {
            Self::with(
                addresses
                    .iter()
                    .map(|address| settings(address, secure))
                    .collect(),
            )
        }

        fn with(settings: Vec<MeshSettings>) -> Self {
            let rng = SystemRandom::new();
            let now = Instant::now();
            let keys: Vec<KeyPair> = settings
                .iter()
                .map(|_| KeyPair::generate(&rng).unwrap())
                .collect();
            // A managed network lists every node of the test as ours.
            let native: Vec<[u8; LEN]> = keys.iter().map(KeyPair::public).collect();
            let nodes = settings
                .into_iter()
                .zip(keys)
                .enumerate()
                .map(|(i, (mut settings, key))| {
                    if settings.kind == NetworkKind::Managed {
                        settings.native_keys = Some(native.clone());
                    }
                    let mut identity = Identity::generate(&rng).unwrap();
                    identity.peer_id = 100 + i as u32;
                    Node::with_identity(settings, identity, key, &rng, now).unwrap()
                })
                .collect();
            Self {
                nodes,
                wires: BTreeMap::new(),
                delivered: Vec::new(),
                now,
            }
        }

        fn link(&mut self, a: usize, b: usize) {
            let rng = SystemRandom::new();
            let conn = (self.wires.len() as u64 + 1) * 10;
            self.wires.insert((a, conn), (b, conn + 1));
            self.wires.insert((b, conn + 1), (a, conn));
            self.nodes[b].accept(conn + 1, self.now);
            self.nodes[a].connect(conn, None, &rng, self.now).unwrap();
        }

        /// Moves packets until nothing is left to do.
        fn settle(&mut self) {
            let rng = SystemRandom::new();
            for _ in 0..10_000 {
                let mut moved = false;
                for i in 0..self.nodes.len() {
                    while let Some(action) = self.nodes[i].poll_action() {
                        moved = true;
                        match action {
                            Action::Send { conn, packet } => {
                                if let Some(&(j, peer_conn)) = self.wires.get(&(i, conn)) {
                                    self.nodes[j].receive(peer_conn, &packet, &rng, self.now);
                                }
                            }
                            Action::Deliver(packet) => self.delivered.push((i, packet)),
                            Action::Close { .. } => {}
                        }
                    }
                }
                if !moved {
                    return;
                }
            }
            panic!("the network did not settle");
        }

        fn tick(&mut self, by: Duration) {
            let rng = SystemRandom::new();
            self.now += by;
            for node in &mut self.nodes {
                node.tick(&rng, self.now, (0, 0));
            }
            self.settle();
        }
    }

    fn ipv4_packet(source: [u8; 4], destination: [u8; 4]) -> Vec<u8> {
        let mut packet = vec![0u8; 28];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&28u16.to_be_bytes());
        packet[8] = 64;
        packet[9] = 17;
        packet[12..16].copy_from_slice(&source);
        packet[16..20].copy_from_slice(&destination);
        packet
    }

    fn three_in_a_row(secure: bool) -> Net {
        let mut net = Net::new(&["10.144.0.1/24", "10.144.0.2/24", "10.144.0.3/24"], secure);
        net.link(0, 1);
        net.link(1, 2);
        net.settle();
        for _ in 0..6 {
            net.tick(Duration::from_secs(1));
        }
        net
    }

    #[test]
    fn nodes_learn_the_network_and_relay_data() {
        let mut net = three_in_a_row(false);
        assert_eq!(net.nodes[0].neighbours(), vec![101]);
        let paths = net.nodes[0].paths();
        assert_eq!(paths[&102].next_hop, 101);
        assert_eq!(paths[&102].hops, 2);

        let relayed = net.nodes[1].counters().relayed;
        let packet = ipv4_packet([10, 144, 0, 1], [10, 144, 0, 3]);
        net.nodes[0].send_ip(&packet, net.now).unwrap();
        net.settle();
        assert_eq!(net.delivered, vec![(2, packet)]);
        assert_eq!(net.nodes[1].counters().relayed, relayed + 1);
    }

    /// Takes node `j`'s static key off node `i`'s native key list.
    fn unlist(net: &mut Net, i: usize, j: usize) {
        let removed = net.nodes[j].static_public();
        let node = &mut net.nodes[i];
        let keep: Vec<[u8; LEN]> = node
            .settings
            .native_keys
            .clone()
            .unwrap_or_default()
            .into_iter()
            .filter(|key| *key != removed)
            .collect();
        let now = net.now;
        node.set_native_keys(Some(keep), now);
    }

    #[test]
    fn a_member_dropped_from_the_list_while_running_is_disconnected() {
        let mut net = Net::new(&["10.144.0.1/24", "10.144.0.2/24"], true);
        net.link(0, 1);
        net.settle();
        assert_eq!(net.nodes[0].neighbours(), vec![101]);
        unlist(&mut net, 0, 1);
        net.settle();
        assert!(net.nodes[0].neighbours().is_empty());
        assert!(net.nodes[0].route_sync().info(101).is_none());
        let packet = ipv4_packet([10, 144, 0, 1], [10, 144, 0, 2]);
        assert!(net.nodes[0].send_ip(&packet, net.now).is_err());
    }

    #[test]
    fn a_managed_network_refuses_peers_off_the_native_key_list() {
        // As the client: the server is refused after msg2.
        let mut net = Net::new(&["10.144.0.1/24", "10.144.0.2/24"], true);
        unlist(&mut net, 0, 1);
        net.link(0, 1);
        net.settle();
        assert!(net.nodes[0].neighbours().is_empty());
        assert_eq!(net.nodes[0].last_not_native(), Some(101));
        assert!(!net.nodes[0].waits_for_native_keys());

        // As the server: the client is refused after msg3.
        let mut net = Net::new(&["10.144.0.1/24", "10.144.0.2/24"], true);
        unlist(&mut net, 0, 1);
        net.link(1, 0);
        net.settle();
        assert!(net.nodes[0].neighbours().is_empty());
        assert_eq!(net.nodes[0].last_not_native(), Some(101));

        // Listed, the same nodes connect.
        let mut net = Net::new(&["10.144.0.1/24", "10.144.0.2/24"], true);
        net.link(0, 1);
        net.settle();
        assert_eq!(net.nodes[0].neighbours(), vec![101]);
        assert_eq!(net.nodes[0].last_not_native(), None);
    }

    #[test]
    fn a_refusal_is_reported_until_a_handshake_a_new_list_or_ten_minutes() {
        let refused = || {
            let mut net = Net::new(&["10.144.0.1/24", "10.144.0.2/24"], true);
            let full = net.nodes[0].settings.native_keys.clone();
            unlist(&mut net, 0, 1);
            net.link(0, 1);
            net.settle();
            assert_eq!(net.nodes[0].last_not_native(), Some(101));
            (net, full)
        };

        // Still reported just before ten minutes, gone at ten.
        let (mut net, _) = refused();
        net.tick(NOT_NATIVE_HOLD - Duration::from_secs(1));
        assert_eq!(net.nodes[0].last_not_native(), Some(101));
        net.tick(Duration::from_secs(1));
        assert_eq!(net.nodes[0].last_not_native(), None);

        // A new list clears it.
        let (mut net, full) = refused();
        let now = net.now;
        net.nodes[0].set_native_keys(full, now);
        assert_eq!(net.nodes[0].last_not_native(), None);

        // So does a handshake with the refused peer.
        let mut net = Net::new(&["10.144.0.1/24", "10.144.0.2/24"], true);
        net.nodes[0].not_native = Some((101, net.now));
        net.link(0, 1);
        net.settle();
        assert_eq!(net.nodes[0].neighbours(), vec![101]);
        assert_eq!(net.nodes[0].last_not_native(), None);
    }

    #[test]
    fn a_relay_handshake_started_before_the_list_changed_is_dropped() {
        let mut net = three_in_a_row(true);
        let packet = ipv4_packet([10, 144, 0, 1], [10, 144, 0, 3]);
        let _ = net.nodes[0].send_ip(&packet, net.now);
        assert!(net.nodes[0]
            .relays
            .get(&102)
            .is_some_and(|relay| relay.initiator.is_some()));
        // Node 2 is dropped while its msg2 is on the way.
        unlist(&mut net, 0, 2);
        assert!(!net.nodes[0].relays.contains_key(&102));
        net.settle();
        let key = SessionKey {
            namespace: Namespace::Relay,
            network: net.nodes[0].local.network_name.clone(),
            peer_id: 102,
        };
        assert!(net.nodes[0].sessions.get(&key).is_none());
        assert!(net.delivered.is_empty());
    }

    #[test]
    fn a_node_off_the_list_is_not_routed_to_or_relayed_to() {
        let mut net = three_in_a_row(true);
        assert!(net.nodes[0].paths().contains_key(&102));
        // Node 0 learns that node 2 is not ours: its information goes, and
        // no relay handshake starts towards it.
        unlist(&mut net, 0, 2);
        net.tick(Duration::from_secs(1));
        assert!(net.nodes[0].route_sync().info(102).is_none());
        let packet = ipv4_packet([10, 144, 0, 1], [10, 144, 0, 3]);
        assert!(net.nodes[0].send_ip(&packet, net.now).is_err());
    }

    #[test]
    fn a_managed_network_waits_without_its_own_key_on_the_list() {
        let mut net = Net::new(&["10.144.0.1/24"], true);
        assert!(!net.nodes[0].waits_for_native_keys());
        unlist(&mut net, 0, 0);
        assert!(net.nodes[0].waits_for_native_keys());
        let legacy = Net::new(&["10.144.0.1/24"], false);
        assert!(!legacy.nodes[0].waits_for_native_keys());
    }

    /// Node `i` receives, from its neighbour `from`, information under its
    /// own ID with another route ID and a newer version (spec §12.3 rule 1).
    fn forge_own_info(net: &mut Net, i: usize, from: u32) {
        let forged = RoutePeerInfo {
            peer_id: net.nodes[i].id(),
            route_id: 1,
            version: 50,
            ..RoutePeerInfo::default()
        };
        let request = SyncRouteRequest {
            my_peer_id: from,
            my_session_id: 1,
            peer_infos: vec![forged],
            ..SyncRouteRequest::default()
        };
        let now = net.now;
        net.nodes[i].sync.on_request(from, request, now);
    }

    #[test]
    fn a_taken_id_is_replaced_at_most_once_in_ten_minutes() {
        let mut net = three_in_a_row(false);
        let old = net.nodes[0].id();
        assert_eq!(net.nodes[0].route_sync().own().version, 1);
        forge_own_info(&mut net, 0, 101);
        net.tick(Duration::from_secs(1));
        let new = net.nodes[0].id();
        assert_ne!(new, old);
        assert_eq!(net.nodes[0].route_sync().own().peer_id, new);
        assert_eq!(net.nodes[0].route_sync().own().version, 1);
        assert_eq!(net.nodes[0].counters().id_renewals, 1);
        assert!(!net.nodes[0].duplicate_id());
        assert!(net.nodes[0].neighbours().is_empty());

        // The other side sees the close; the driver dials again.
        let now = net.now;
        net.nodes[1].disconnected(11, now);
        net.link(0, 1);
        net.settle();
        for _ in 0..6 {
            net.tick(Duration::from_secs(1));
        }
        assert_eq!(net.nodes[0].neighbours(), vec![101]);
        assert_eq!(net.nodes[2].paths()[&new].next_hop, 101);

        // Again within ten minutes: only a warning.
        forge_own_info(&mut net, 0, 101);
        net.tick(Duration::from_secs(1));
        assert_eq!(net.nodes[0].id(), new);
        assert!(net.nodes[0].duplicate_id());
        assert_eq!(net.nodes[0].counters().id_renewals, 1);

        // Later it changes again.
        net.now += ID_RENEW_INTERVAL;
        forge_own_info(&mut net, 0, 101);
        net.tick(Duration::from_secs(1));
        assert_ne!(net.nodes[0].id(), new);
        assert!(!net.nodes[0].duplicate_id());
        assert_eq!(net.nodes[0].counters().id_renewals, 2);
    }

    /// Nodes 0 and 2 already share a relay session once node 2 has
    /// reported to the latency centre, the smallest ID (node 0). Drops it
    /// on both ends so that a test sees a handshake from the start.
    fn without_relay_session(net: &mut Net) {
        let ids = [net.nodes[0].id(), net.nodes[2].id()];
        for (i, peer) in [(0, ids[1]), (2, ids[0])] {
            let node = &mut net.nodes[i];
            let key = SessionKey {
                namespace: Namespace::Relay,
                network: node.settings.network_name.clone(),
                peer_id: peer,
            };
            node.sessions.invalidate(&key);
        }
    }

    /// Sends `packet` from node `i` and lets any relay handshake run.
    fn send(net: &mut Net, i: usize, packet: &[u8]) {
        let rng = SystemRandom::new();
        net.nodes[i].send_ip(packet, net.now).unwrap();
        net.nodes[i].wake(&rng, net.now);
        net.settle();
    }

    #[test]
    fn secure_nodes_behind_a_relay_set_up_a_session_and_exchange_data() {
        let mut net = three_in_a_row(true);
        without_relay_session(&mut net);
        assert_eq!(net.nodes[0].neighbours(), vec![101]);
        assert_eq!(net.nodes[0].paths()[&102].next_hop, 101);

        let packet = ipv4_packet([10, 144, 0, 1], [10, 144, 0, 3]);
        send(&mut net, 0, &packet);
        assert_eq!(net.delivered, vec![(2, packet)]);
        assert_eq!(net.nodes[0].next_wake(), None);

        // The answering node's session became current with that packet.
        let reply = ipv4_packet([10, 144, 0, 3], [10, 144, 0, 1]);
        send(&mut net, 2, &reply);
        assert_eq!(net.delivered[1..], [(0, reply)]);
        assert_eq!(net.nodes[2].next_wake(), None);
        // The relay only carried packets.
        assert!(net.delivered.iter().all(|(i, _)| *i != 1));
    }

    #[test]
    fn both_ends_starting_at_once_end_with_one_session() {
        let mut net = three_in_a_row(true);
        without_relay_session(&mut net);
        let rng = SystemRandom::new();
        let there = ipv4_packet([10, 144, 0, 1], [10, 144, 0, 3]);
        let back = ipv4_packet([10, 144, 0, 3], [10, 144, 0, 1]);
        net.nodes[0].send_ip(&there, net.now).unwrap();
        net.nodes[2].send_ip(&back, net.now).unwrap();
        net.nodes[0].wake(&rng, net.now);
        net.nodes[2].wake(&rng, net.now);
        net.settle();
        net.delivered.sort();
        assert_eq!(net.delivered, vec![(0, back), (2, there)]);
        assert_eq!(net.nodes[0].next_wake(), None);
        assert_eq!(net.nodes[2].next_wake(), None);
    }

    #[test]
    fn an_unanswered_relay_handshake_is_retried_then_given_up() {
        let mut net = three_in_a_row(true);
        without_relay_session(&mut net);
        let rng = SystemRandom::new();
        // The relay loses everything towards node 2.
        net.wires
            .retain(|&(from, _), &mut (to, _)| !(from == 1 && to == 2));
        let unroutable = net.nodes[0].counters().unroutable;
        let packet = ipv4_packet([10, 144, 0, 1], [10, 144, 0, 3]);
        send(&mut net, 0, &packet);
        let mut waits = Vec::new();
        let mut last = net.now;
        while let Some(at) = net.nodes[0].next_wake() {
            waits.push(at - last);
            last = at;
            net.now = at;
            net.nodes[0].wake(&rng, net.now);
            net.settle();
            assert!(waits.len() <= 5, "never gives up");
        }
        assert_eq!(
            waits,
            [200, 400, 800, 1600].map(Duration::from_millis).to_vec()
        );
        assert!(net.delivered.is_empty());
        assert_eq!(net.nodes[0].counters().unroutable, unroutable + 1);
    }

    #[test]
    fn at_most_a_queue_of_packets_waits_for_a_relay_session() {
        let mut net = three_in_a_row(true);
        without_relay_session(&mut net);
        net.wires
            .retain(|&(from, _), &mut (to, _)| !(from == 1 && to == 2));
        let packet = ipv4_packet([10, 144, 0, 1], [10, 144, 0, 3]);
        for _ in 0..RELAY_QUEUE {
            net.nodes[0].send_ip(&packet, net.now).unwrap();
        }
        assert_eq!(net.nodes[0].send_ip(&packet, net.now), Err(Denied::NoRoute));
    }

    #[test]
    fn system_routes_skip_local_networks_and_follow_the_configured_limit() {
        let advertising = |address: &str, extra: serde_json::Value| {
            let mut config = serde_json::json!({
                "config_version": 1,
                "network": {"name": "office", "secret": "s3cr3t", "kind": "legacy"},
                "node": {"address": address, "role": "full"},
                "peers": [{"server": "peer.example", "port": 40000}],
            });
            for (key, value) in extra.as_object().unwrap() {
                config[key] = value.clone();
            }
            serde_json::from_value::<MeshConfig>(config)
                .unwrap()
                .validate()
                .unwrap()
        };
        let mut net = Net::with(vec![
            advertising(
                "10.144.0.1/24",
                serde_json::json!({"routing": {"system_routes": ["192.168.0.0/16"]}}),
            ),
            advertising(
                "10.144.0.2/24",
                serde_json::json!({"subnets": {"advertise": ["192.168.10.0/24", "172.16.5.0/24"]}}),
            ),
        ]);
        net.link(0, 1);
        net.settle();
        for _ in 0..4 {
            net.tick(Duration::from_secs(1));
        }
        let routes = |net: &Net| -> Vec<String> {
            net.nodes[0]
                .system_routes()
                .iter()
                .map(ToString::to_string)
                .collect()
        };
        // 172.16.5.0/24 is outside routing.system_routes.
        assert_eq!(routes(&net), ["192.168.10.0/24"]);
        assert!(net.nodes[0]
            .route_table()
            .lookup("172.16.5.9".parse().unwrap())
            .is_ok());
        // This machine sits on 192.168.10.0/24 itself.
        net.nodes[0].set_local_networks(&[IpNet::parse("192.168.10.7/24").unwrap()]);
        assert!(routes(&net).is_empty());
    }

    #[test]
    fn route_sync_is_only_served_to_the_connection_neighbour() {
        // Node 0 is not node 2's neighbour: its request arrives over the
        // connection to node 1 and is dropped without an answer.
        let mut net = three_in_a_row(false);
        let dropped = net.nodes[2].counters().dropped;
        let request = SyncRouteRequest {
            my_peer_id: 100,
            ..SyncRouteRequest::default()
        };
        net.nodes[0].call(102, CallKind::SyncRoute, request.encode(), net.now);
        net.settle();
        assert_eq!(net.nodes[2].counters().dropped, dropped + 1);
        assert!(net.nodes[0]
            .calls
            .values()
            .any(|call| call.peer == 102 && call.kind == CallKind::SyncRoute));
    }

    #[test]
    fn route_sync_answers_count_only_from_the_connection_neighbour() {
        // Node 0 has a route sync call out to node 2, which is not its
        // neighbour; an answer from node 2 arrives over the connection to
        // node 1 and is dropped, the call stays open.
        let mut net = three_in_a_row(false);
        net.nodes[0].call(
            102,
            CallKind::SyncRoute,
            SyncRouteRequest::default().encode(),
            net.now,
        );
        let transaction = *net.nodes[0]
            .calls
            .iter()
            .find(|(_, call)| call.peer == 102 && call.kind == CallKind::SyncRoute)
            .unwrap()
            .0;
        let descriptor = net.nodes[2].descriptor(ROUTE_SERVICE, METHOD_SYNC_ROUTE_INFO);
        let body = RpcResponse {
            result: Ok(SyncRouteResponse::default().encode()),
            runtime_us: 0,
        }
        .encode();
        let dropped = net.nodes[0].counters().dropped;
        let now = net.now;
        net.nodes[2].send_rpc(100, transaction, &descriptor, false, &body, now);
        net.settle();
        assert_eq!(net.nodes[0].counters().dropped, dropped + 1);
        assert!(net.nodes[0].calls.contains_key(&transaction));
    }

    #[test]
    fn a_lost_neighbour_takes_its_route_sync_calls_with_it() {
        let mut net = three_in_a_row(false);
        net.nodes[0].call(
            101,
            CallKind::SyncRoute,
            SyncRouteRequest::default().encode(),
            net.now,
        );
        assert!(net.nodes[0].calls.values().any(|call| call.peer == 101));
        let conns: Vec<ConnId> = net.nodes[0].conns.keys().copied().collect();
        for conn in conns {
            net.nodes[0].disconnected(conn, net.now);
        }
        assert!(!net.nodes[0]
            .calls
            .values()
            .any(|call| call.peer == 101 && call.kind == CallKind::SyncRoute));
    }

    #[test]
    fn every_start_gets_new_ids_and_keeps_the_static_key() {
        let rng = SystemRandom::new();
        let now = Instant::now();
        let key = KeyPair::generate(&rng).unwrap();
        let private = key.private();
        let first = Node::new(
            settings("10.144.0.1/24", true),
            KeyPair::from_private(*private),
            &rng,
            now,
        )
        .unwrap();
        let second = Node::new(settings("10.144.0.1/24", true), key, &rng, now).unwrap();
        let (a, b) = (first.sync.own(), second.sync.own());
        assert_ne!(first.id(), second.id());
        assert_ne!(a.route_id, b.route_id);
        assert_ne!(a.inst_id, b.inst_id);
        assert_eq!(a.noise_pubkey, b.noise_pubkey);
    }

    #[test]
    fn broadcasts_reach_direct_neighbours_only() {
        // Node 1 sits between nodes 0 and 2: its broadcast reaches both;
        // node 0's reaches node 1 and is not relayed to node 2.
        let mut net = three_in_a_row(false);
        let packet = ipv4_packet([10, 144, 0, 2], [10, 144, 0, 255]);
        net.nodes[1].send_ip(&packet, net.now).unwrap();
        net.settle();
        net.delivered.sort();
        assert_eq!(net.delivered, vec![(0, packet.clone()), (2, packet)]);

        net.delivered.clear();
        let relayed = net.nodes[1].counters().relayed;
        let packet = ipv4_packet([10, 144, 0, 1], [224, 0, 0, 251]);
        net.nodes[0].send_ip(&packet, net.now).unwrap();
        net.settle();
        assert_eq!(net.delivered, vec![(1, packet)]);
        assert_eq!(net.nodes[1].counters().relayed, relayed);
    }

    #[test]
    fn a_broadcast_without_neighbours_is_not_sent() {
        let mut net = Net::new(&["10.144.0.1/24"], false);
        let packet = ipv4_packet([10, 144, 0, 1], [255, 255, 255, 255]);
        assert_eq!(net.nodes[0].send_ip(&packet, net.now), Err(Denied::NoRoute));
        net.settle();
        assert!(net.delivered.is_empty());
    }

    #[test]
    fn public_destinations_never_leave() {
        let mut net = three_in_a_row(false);
        let packet = ipv4_packet([10, 144, 0, 1], [8, 8, 8, 8]);
        assert_eq!(
            net.nodes[0].send_ip(&packet, net.now),
            Err(Denied::NotIntranet)
        );
        assert_eq!(net.nodes[0].counters().refused_outgoing, 1);
    }

    #[test]
    fn spoofed_sources_are_refused_on_arrival() {
        let mut net = three_in_a_row(false);
        // Node 1 claims node 3's address as its source.
        let packet = ipv4_packet([10, 144, 0, 3], [10, 144, 0, 1]);
        assert!(net.nodes[1].originate(100, packet_type::DATA, &packet, net.now));
        net.settle();
        assert!(net.delivered.is_empty());
        assert_eq!(net.nodes[0].counters().refused_incoming, 1);
    }

    #[test]
    fn neighbours_in_the_secure_mode_exchange_data() {
        let mut net = Net::new(&["10.144.0.1/24", "10.144.0.2/24"], true);
        net.link(0, 1);
        net.settle();
        for _ in 0..4 {
            net.tick(Duration::from_secs(1));
        }
        let packet = ipv4_packet([10, 144, 0, 2], [10, 144, 0, 1]);
        net.nodes[1].send_ip(&packet, net.now).unwrap();
        net.settle();
        assert_eq!(net.delivered, vec![(0, packet)]);
    }

    #[test]
    fn keep_alive_measures_and_closes_silent_connections() {
        let mut net = three_in_a_row(false);
        assert!(net.nodes[0].latency(101).is_some());
        // Cut the wires: pings go unanswered.
        net.wires.clear();
        for _ in 0..(PING_MISSES * 40) {
            net.tick(Duration::from_secs(1));
            if net.nodes[0].neighbours().is_empty() {
                break;
            }
        }
        assert!(net.nodes[0].neighbours().is_empty());
    }

    #[test]
    fn unknown_services_get_an_error() {
        let mut net = three_in_a_row(false);
        let descriptor = net.nodes[0].descriptor("NoSuchRpc", 1);
        let request = RpcRequest {
            request: Vec::new(),
            timeout_ms: 1000,
        }
        .encode();
        assert_eq!(
            net.nodes[1].serve(100, &descriptor, &request, net.now),
            Err(RpcError::InvalidService)
        );
        let descriptor = net.nodes[0].descriptor(ROUTE_SERVICE, 9);
        assert_eq!(
            net.nodes[1].serve(100, &descriptor, &request, net.now),
            Err(RpcError::InvalidMethod)
        );
    }

    #[test]
    fn the_smallest_id_is_the_latency_centre() {
        let mut net = three_in_a_row(false);
        for _ in 0..20 {
            net.tick(Duration::from_secs(1));
        }
        // Node 100 serves the map; node 102 fetched it through node 101.
        assert!(net.nodes[2].peer_map.digest.is_some());
        assert!(net.nodes[2].peer_map.map.contains_key(&101));
    }
}
