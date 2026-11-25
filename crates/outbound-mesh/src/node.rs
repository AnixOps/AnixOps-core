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
//! Not here yet: relay sessions of the secure mode (spec §9), so in that
//! mode only direct neighbours are reached; shared nodes (spec §16).

use std::collections::{BTreeMap, VecDeque};
use std::net::IpAddr;
use std::time::{Duration, Instant};

use ring::error::Unspecified;
use ring::rand::SecureRandom;

use crate::config::{MeshSettings, Role, RoutePolicy, SecurityMode};
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
use crate::routes::{Denied, Outgoing, PeerId, RouteTable};
use crate::rpc::packet::{
    split, Descriptor, RpcError, RpcPacket, RpcRequest, RpcResponse, DEFAULT_TIMEOUT_MS,
    ROUTE_SYNC_TIMEOUT_MS,
};
use crate::rpc::reassembly::Reassembler;
use crate::secure::handshake::Local;
use crate::secure::noise::{KeyPair, LEN};
use crate::secure::session::Sessions;
use crate::wire::header::relay_in_place;
use crate::wire::{flags, packet_type, NodeHeader, HEADER_LEN};

/// The driver's name for one connection.
pub type ConnId = u64;

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

/// The node's identity in its network.
pub struct Identity {
    pub peer_id: u32,
    pub inst_id: Uuid,
    pub route_id: u64,
    pub static_key: KeyPair,
}

impl Identity {
    pub fn generate(rng: &dyn SecureRandom) -> Result<Self, Unspecified> {
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
            static_key: KeyPair::generate(rng).map_err(|_| Unspecified)?,
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
}

fn own_info(settings: &MeshSettings, identity: &Identity) -> RoutePeerInfo {
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
        // Seconds since 1970: a restarted node starts above the versions
        // its old information still has in the network (spec §12.3).
        version: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .ok()
            .and_then(|since| u32::try_from(since.as_secs()).ok())
            .unwrap_or(1)
            .max(1),
        version_string: VERSION_STRING.into(),
        features: FeatureFlags::ours(relays),
        route_id: identity.route_id,
        network_length: u32::from(settings.address.prefix()),
        ipv6,
        noise_pubkey: match settings.security {
            SecurityMode::ForwardSecrecy => identity.static_key.public().to_vec(),
            SecurityMode::Default => Vec::new(),
        },
        ..RoutePeerInfo::default()
    }
}

fn random_i64(rng: &dyn SecureRandom) -> Result<i64, Unspecified> {
    let mut bytes = [0u8; 8];
    rng.fill(&mut bytes)?;
    // Positive, with room to count up.
    Ok((u64::from_le_bytes(bytes) >> 2) as i64)
}

impl Node {
    /// A node of the network `settings` describes (already validated).
    pub fn new(
        settings: MeshSettings,
        identity: Identity,
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
        let info = own_info(&settings, &identity);
        let local = Local {
            id: identity.peer_id,
            static_key: identity.static_key,
            network_name: settings.network_name.clone(),
            node_name: settings
                .hostname
                .clone()
                .unwrap_or_else(|| format!("node-{}", identity.peer_id)),
            digest: Some(digest(settings.network_name.as_bytes(), &secret)),
            secret: Some(secret),
            cipher: settings.cipher,
            trusted_keys: Vec::new(),
        };
        let routes = RouteTable::new(&settings);
        Ok(Self {
            local,
            legacy,
            sessions: Sessions::new(),
            sync: RouteSync::new(info, now),
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
        self.counters
    }

    pub fn route_table(&self) -> &RouteTable {
        &self.routes
    }

    pub fn route_sync(&self) -> &RouteSync {
        &self.sync
    }

    /// A neighbour said this node's ID is taken (spec §12.2): the driver
    /// should start again with a new identity.
    pub fn duplicate_id(&self) -> bool {
        self.duplicate_id
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
        let sync = &self.sync;
        let peer_key = |peer: u32| -> Option<[u8; LEN]> {
            sync.info(peer)
                .and_then(|info| <[u8; LEN]>::try_from(&info.noise_pubkey[..]).ok())
        };
        let mut hs = Handshaking {
            local: &self.local,
            security: self.settings.security,
            sessions: &mut self.sessions,
            rng,
            peer_key: &peer_key,
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
        if self.sync.neighbour_up(up.peer_id, rng).is_err() {
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
                self.rpc_piece(from, &inbound.payload, rng, now)
            }
            _ => self.counters.dropped += 1,
        }
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
        let mut crypto = self.crypto();
        let Ok(mut packet) = link::seal(&mut crypto, from, to, next_hop, kind, payload, now) else {
            self.counters.unroutable += 1;
            return false;
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
            Outgoing::Peer(peer) => self.originate(peer.0, packet_type::DATA, packet, now),
            Outgoing::Neighbours => {
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

    fn rpc_piece(&mut self, from: u32, payload: &[u8], rng: &dyn SecureRandom, now: Instant) {
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
            self.answered(from, call.transaction_id, &call.body, rng, now);
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

    fn answered(
        &mut self,
        from: u32,
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
                    self.duplicate_id = true;
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
        self.sync.expire(now);
        self.refresh_routes();
        self.centre_round(now);
        self.reassembler.expire(now);
        self.sessions.reclaim(now);
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
            let rng = SystemRandom::new();
            let now = Instant::now();
            let nodes = addresses
                .iter()
                .enumerate()
                .map(|(i, address)| {
                    let mut identity = Identity::generate(&rng).unwrap();
                    identity.peer_id = 100 + i as u32;
                    Node::new(settings(address, secure), identity, &rng, now).unwrap()
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
