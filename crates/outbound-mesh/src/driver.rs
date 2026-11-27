//! The socket driver of one network (feature `runtime`): TCP and UDP
//! connections (spec §3.1, §3.2), dialing the configured peers again after a
//! loss, listening on full nodes, the handshake budget and the timers of
//! [`Node`]. IP packets come in and go out through two channels, so the
//! standalone node can attach a virtual interface and the client its own
//! TCP/IP stack.
//!
//! Every connection has a reader and a writer task; the node itself lives
//! in one task, so it needs no locks.

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use ring::rand::{SecureRandom, SystemRandom};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::{mpsc, watch, Notify};
use tokio::time::{interval, sleep, timeout, MissedTickBehavior};

use crate::config::{
    CustomPath, HostGroup, MeshSettings, PathTarget, PeerEndpoint, Role, SecurityMode, Transport,
};
use crate::dns::{DnsSettings, Names};
use crate::link::{self, Admission, CloseReason, HandshakeBudget, Ticket};
use crate::net::IpNet;
use crate::node::{Action, ConnId, Counters, Node, SyncOversize, WITHDRAW_WAIT};
use crate::paths::PathStatus;
use crate::routes::PeerId;
use crate::secure::noise::KeyPair;
use crate::wire::tcp::{encode_frame, FrameDecoder};
use crate::wire::udp::{self, Datagram};

/// First delay before dialing a peer again.
pub const REDIAL_MIN: Duration = Duration::from_secs(1);
/// Longest delay before dialing a peer again.
pub const REDIAL_MAX: Duration = Duration::from_secs(30);
/// A connection that lasted this long resets the dial delay.
const STABLE: Duration = Duration::from_secs(30);
/// First delay before dialing a peer this node refused for a static key
/// off the native key list (spec §8.3.1 rule 5).
pub const REFUSED_MIN: Duration = Duration::from_secs(5);
/// Longest delay before dialing such a peer again.
pub const REFUSED_MAX: Duration = Duration::from_secs(5 * 60);
/// A client waits this long for Sack and never sends Syn again (spec §3.2).
pub const SACK_TIMEOUT: Duration = Duration::from_secs(3);
/// Connection attempts that wait for another connection's session try again
/// after this long (spec §8.1).
const WAIT_FOR_SESSION_RETRY: Duration = Duration::from_millis(500);
/// Tries before such a connection is closed and redialled.
const WAIT_FOR_SESSION_TRIES: u32 = 20;
/// UDP sessions one listening socket keeps.
pub const MAX_UDP_SESSIONS: usize = 4096;
/// Packets queued for one connection before new ones are dropped.
const CONN_QUEUE: usize = 256;
/// Events queued for the node task.
const EVENT_QUEUE: usize = 4096;
/// Largest datagram read.
const MAX_DATAGRAM: usize = 65_535;

/// Sockets bound before the driver starts, so a caller can learn the ports
/// (a configured port 0) and fail early on a port in use.
pub struct Listeners {
    tcp: Vec<TcpListener>,
    udp: Vec<UdpSocket>,
}

impl Listeners {
    /// Binds every `listen` entry of a full node; access nodes listen on
    /// nothing (spec §1.3).
    pub async fn bind(settings: &MeshSettings) -> io::Result<Self> {
        let mut listeners = Self {
            tcp: Vec::new(),
            udp: Vec::new(),
        };
        if settings.role != Role::Full {
            return Ok(listeners);
        }
        for listen in &settings.listen {
            let address = SocketAddr::new(
                listen.address.unwrap_or(IpAddr::V6(Ipv6Addr::UNSPECIFIED)),
                listen.port,
            );
            match listen.transport {
                Transport::Tcp => listeners.tcp.push(TcpListener::bind(address).await?),
                Transport::Udp => listeners.udp.push(UdpSocket::bind(address).await?),
            }
        }
        Ok(listeners)
    }

    /// The bound addresses, TCP first.
    pub fn local_addrs(&self) -> io::Result<Vec<(Transport, SocketAddr)>> {
        let mut out = Vec::new();
        for listener in &self.tcp {
            out.push((Transport::Tcp, listener.local_addr()?));
        }
        for socket in &self.udp {
            out.push((Transport::Udp, socket.local_addr()?));
        }
        Ok(out)
    }
}

/// What the driver reports to whoever runs it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Snapshot {
    pub peer_id: u32,
    pub neighbours: Vec<u32>,
    /// Node ID, next hop and hop count of every reachable node.
    pub routes: Vec<(u32, u32, u32)>,
    pub counters: Counters,
    /// Oversized synchronisations, the last of each kind (spec §11.2,
    /// §12.2).
    pub sync_oversize: SyncOversize,
    /// This node's ID is taken and it changed ID less than ten minutes
    /// ago, so it only warns (spec §12.3).
    pub duplicate_id: bool,
    /// Subnets to route into the interface: accepted, not overlapping this
    /// machine's networks, within `routing.system_routes`. Empty until
    /// those networks were read once ([`Snapshot::local_networks_read`]).
    pub system_routes: Vec<IpNet>,
    /// The networks of this machine's other interfaces were read at least
    /// once. Until then no subnet is installed, so that a local network
    /// is never taken into the mesh (spec §15.4).
    pub local_networks_read: bool,
    /// This node's static public key in the network; `None` in the
    /// default mode, which has none.
    pub static_key: Option<[u8; 32]>,
    /// A managed network whose native key list lacks this node: no links
    /// are opened (spec §8.3.1 rule 1).
    pub waiting_for_native_keys: bool,
    /// The last peer refused for a key off the native key list.
    pub not_native: Option<u32>,
    /// Every reachable member, by node ID (requirement R16).
    pub members: Vec<Member>,
    /// Subnets refused from the members' current advertisements (R16, R17).
    pub rejected_advertisements: u64,
    /// Accepted subnets that overlap this node's own networks: kept, but
    /// neither routed nor installed (R17, spec §15.4).
    pub overlaps: Vec<IpNet>,
    /// Those of `overlaps` that overlap another mesh program's route
    /// rather than a network of this machine (spec §15.4).
    pub foreign_overlaps: Vec<IpNet>,
    /// Members that claim one of this node's virtual addresses (R29).
    pub address_conflicts: Vec<(u32, IpAddr)>,
    /// The intranet name list (R28): the names the status shows, and the
    /// answers for the engine's split DNS ([`Names::answer`]).
    pub names: Option<Arc<Names>>,
    /// The custom paths and their states, in configuration order (spec
    /// §17.2.7).
    pub paths: Vec<PathStatus>,
    /// What this node advertises now (field 5), host group ranges
    /// included (spec §15.7).
    pub advertising: Vec<IpNet>,
    /// Host group ranges this node advertises as the standby gateway
    /// because the gateway is not online (spec §15.7 rule 5).
    pub standing_in: Vec<IpNet>,
    /// The node is stopping: it withdrew its advertisements and closes its
    /// connections [`WITHDRAW_WAIT`] later (spec §15.7 rule 6).
    pub withdrawing: bool,
    /// The other regions' summary prefixes this border node carries
    /// ([`Border`]); empty on other nodes.
    pub border: Vec<IpNet>,
    /// Routable subnets not installed because [`Snapshot::system_routes`]
    /// is full.
    pub system_routes_truncated: usize,
    /// Members announcing another static key than the one bound to their
    /// node ID (spec §12.3).
    pub refused_key_changes: Vec<u32>,
    /// This node's instance ID in the network, as a UUID text.
    pub instance: String,
}

/// One reachable member, as [`Snapshot::members`] lists it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Member {
    pub peer_id: u32,
    /// Its instance ID, as a UUID text; empty before its route information
    /// arrived.
    pub instance: String,
    /// The host name it advertises, if any.
    pub hostname: Option<String>,
    /// Its virtual addresses, as accepted.
    pub addresses: Vec<IpAddr>,
    /// The subnets it advertises, as accepted.
    pub subnets: Vec<IpNet>,
    /// Node IDs of the relays on the path, first hop first; empty for a
    /// direct connection.
    pub via: Vec<u32>,
    /// 1 for a direct connection.
    pub hops: u32,
    /// The fewest hops to it, whatever the path policy; the driver picks
    /// among the advertisers of a subnet by this count (spec §15.2), while
    /// `hops` and `via` follow the policy's path.
    pub fewest_hops: u32,
    /// Round-trip time to a direct neighbour, in milliseconds; `None`
    /// before the first keep-alive answer and for members reached through
    /// relays.
    pub latency_ms: Option<u32>,
    /// `auto`, `custom`, `first_hop_only` or `fallback`: the state of the
    /// custom path to this member, if it has one (`mesh-status.md`,
    /// `members[].pathState`).
    pub path_state: &'static str,
    /// The node that path names as unreachable.
    pub unreachable: Option<IpAddr>,
}

enum Event {
    Opened {
        conn: ConnId,
        writer: mpsc::Sender<Vec<u8>>,
        closer: Arc<Notify>,
        /// The source of a connection a peer opened.
        inbound: Option<(SocketAddr, link::Transport)>,
        /// For a connection a dial task opened: set when the node refuses
        /// the peer as not native, so that the task backs off.
        refused: Option<Arc<AtomicBool>>,
    },
    /// The address the dial task of `peer` (its place in the peer list)
    /// connects to: a known member address for the handshake budget.
    Dialing {
        peer: usize,
        address: IpAddr,
    },
    Packet {
        conn: ConnId,
        packet: Vec<u8>,
    },
    Closed {
        conn: ConnId,
    },
}

struct Open {
    writer: mpsc::Sender<Vec<u8>>,
    closer: Arc<Notify>,
    ticket: Option<Ticket>,
    refused: Option<Arc<AtomicBool>>,
}

#[derive(Clone)]
struct Shared {
    events: mpsc::Sender<Event>,
    next_conn: Arc<AtomicU64>,
}

impl Shared {
    fn conn_id(&self) -> ConnId {
        self.next_conn.fetch_add(1, Ordering::Relaxed)
    }
}

fn unix_now() -> (i64, i32) {
    let since = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    (
        i64::try_from(since.as_secs()).unwrap_or(i64::MAX),
        i32::try_from(since.subsec_nanos()).unwrap_or(0),
    )
}

fn random_u32(rng: &dyn SecureRandom) -> u32 {
    let mut bytes = [0u8; 4];
    let _ = rng.fill(&mut bytes);
    u32::from_le_bytes(bytes)
}

fn random_u64(rng: &dyn SecureRandom) -> u64 {
    let mut bytes = [0u8; 8];
    let _ = rng.fill(&mut bytes);
    u64::from_le_bytes(bytes)
}

/// How [`run`] talks to the virtual interface and its owner.
pub struct Channels {
    /// IP packets for the mesh.
    pub from_interface: mpsc::Receiver<Vec<u8>>,
    /// IP packets for this node.
    pub to_interface: mpsc::Sender<Vec<u8>>,
    /// The state after every timer tick.
    pub snapshots: watch::Sender<Snapshot>,
    /// The networks of this machine's other interfaces: advertised subnets
    /// that overlap them are neither routed nor installed (spec §15.4).
    /// `None` while they could not be read yet: then no subnet is installed
    /// ([`Snapshot::system_routes`] stays empty).
    pub local_networks: watch::Receiver<Option<Vec<IpNet>>>,
    /// A new `network.native_keys` for a managed network, applied without
    /// a restart (spec §8.3.1); the value at start is ignored, the
    /// settings carry it.
    pub native_keys: watch::Receiver<Option<Vec<[u8; 32]>>>,
    /// A new `dns` section, applied without a restart (R28). The settings
    /// carry the value at start; a value the receiver has not seen yet when
    /// the driver starts is applied at once.
    pub dns: watch::Receiver<DnsSettings>,
    /// A new list of custom paths, already validated, which replaces the
    /// current one at once (spec §17.2.8); the value at start is ignored,
    /// the settings carry it.
    pub paths: watch::Receiver<Vec<CustomPath>>,
    /// New `host_groups`, applied without a restart (spec §15.7); the value
    /// at start is ignored, the settings carry it.
    pub host_groups: watch::Receiver<Vec<HostGroup>>,
    /// Advertised subnets the user routes through the mesh although they
    /// overlap a network of this machine (`mesh_set_subnet_route`,
    /// spec §15.4); the value at start applies too.
    pub route_overrides: watch::Receiver<Vec<IpNet>>,
    /// Routes other mesh programs' virtual interfaces carry on this
    /// machine, as the system selects them: handled like `local_networks`
    /// and reported apart (spec §15.4).
    pub foreign_routes: watch::Receiver<Vec<IpNet>>,
    /// Stops the node when it turns true. A node that advertises subnets
    /// first withdraws them and keeps running for [`WITHDRAW_WAIT`] (spec
    /// §15.7 rule 6); the caller should allow for that.
    pub shutdown: watch::Receiver<bool>,
    /// A border node's side of the backbone; `None` on other nodes.
    pub border: Option<Border>,
}

/// What a border node exchanges with the backbone (spec §15.6, §17.3).
pub struct Border {
    /// The other regions' summary prefixes to carry: advertised to the
    /// members, packets to them go to `to_backbone`. Empty withdraws them.
    pub prefixes: watch::Receiver<Vec<IpNet>>,
    /// IP packets from this network for another region.
    pub to_backbone: mpsc::Sender<Vec<u8>>,
    /// IP packets the backbone delivered for this network; their sources
    /// must lie in `prefixes`. Shared, so that the channel outlives a
    /// restart of either side: the running driver holds the lock.
    pub from_backbone: Arc<tokio::sync::Mutex<mpsc::Receiver<Vec<u8>>>>,
}

/// Runs one network until `shutdown` turns true.
pub async fn run(
    settings: MeshSettings,
    static_key: KeyPair,
    listeners: Listeners,
    channels: Channels,
) -> io::Result<()> {
    let Channels {
        mut from_interface,
        to_interface,
        snapshots,
        mut local_networks,
        mut native_keys,
        mut dns,
        mut paths,
        mut host_groups,
        mut route_overrides,
        mut foreign_routes,
        mut shutdown,
        border,
    } = channels;
    // Without a border the branches below never fire; the senders are kept
    // so that the receivers stay open.
    let (mut border_prefixes, to_backbone, from_backbone, _no_border) = match border {
        Some(border) => (
            border.prefixes,
            Some(border.to_backbone),
            border.from_backbone,
            None,
        ),
        None => {
            let (prefixes_tx, prefixes) = watch::channel(Vec::new());
            let (packets_tx, packets) = mpsc::channel(1);
            let packets = Arc::new(tokio::sync::Mutex::new(packets));
            (prefixes, None, packets, Some((prefixes_tx, packets_tx)))
        }
    };
    let mut from_backbone = from_backbone.lock_owned().await;
    native_keys.mark_unchanged();
    // Not `dns`: a value sent after the receiver was made (or subscribed)
    // and before this point is newer than the settings, and is applied as
    // soon as the loop runs (a receiver starts with its value seen).
    paths.mark_unchanged();
    host_groups.mark_unchanged();
    let rng = SystemRandom::new();
    let started = Instant::now();
    let peers = settings.peers.clone();
    let mut node = Node::new(settings, static_key, &rng, started)
        .map_err(|_| io::Error::other("mesh node keys could not be set up"))?;
    node.set_route_overrides(&route_overrides.borrow_and_update());
    node.set_foreign_routes(&foreign_routes.borrow_and_update());
    let mut local_read = false;
    if let Some(networks) = &*local_networks.borrow_and_update() {
        node.set_local_networks(networks);
        local_read = true;
    }
    let initial = border_prefixes.borrow_and_update().clone();
    if !initial.is_empty() {
        node.set_border(&initial, started);
    }
    if node.waits_for_native_keys() {
        // No listening, dialling or packets until the list holds this
        // node; the caller should not have bound listeners either.
        drop(listeners);
        publish(&snapshots, snapshot(&node, local_read));
        while !*shutdown.borrow_and_update() {
            if shutdown.changed().await.is_err() {
                break;
            }
        }
        return Ok(());
    }
    let (events, mut event_rx) = mpsc::channel(EVENT_QUEUE);
    let shared = Shared {
        events,
        next_conn: Arc::new(AtomicU64::new(1)),
    };
    // Aborted however `run` ends, even when its own task is aborted, so
    // that the listening sockets are freed.
    let mut tasks = AbortAll(Vec::new());
    for listener in listeners.tcp {
        tasks
            .0
            .push(tokio::spawn(accept_tcp(listener, shared.clone())));
    }
    for socket in listeners.udp {
        tasks
            .0
            .push(tokio::spawn(serve_udp(socket, shared.clone())));
    }
    for (index, peer) in peers.into_iter().enumerate() {
        tasks.0.push(tokio::spawn(dial(
            peer,
            index,
            shared.clone(),
            native_keys.clone(),
        )));
    }

    let mut conns: HashMap<ConnId, Open> = HashMap::new();
    let mut budget = HandshakeBudget::new();
    // Addresses the dial tasks connect to, by peer.
    let mut dialed: HashMap<usize, IpAddr> = HashMap::new();
    // Outgoing connections waiting for a session another connection is
    // setting up: (connection, when to try again, tries so far).
    let mut waiting: Vec<(ConnId, Instant, u32)> = Vec::new();
    let mut ticks = interval(Duration::from_secs(1));
    ticks.set_missed_tick_behavior(MissedTickBehavior::Delay);
    // Set once the node withdrew its advertisements to stop: it closes
    // then (spec §15.7 rule 6).
    let mut closing_at: Option<Instant> = None;

    loop {
        // Relay handshakes due before the next tick (spec §9 retries).
        let wake_at = node
            .next_wake()
            .into_iter()
            .chain(waiting.iter().map(|(_, at, _)| *at))
            .min();
        tokio::select! {
            changed = shutdown.changed(), if closing_at.is_none() => {
                if changed.is_err() || *shutdown.borrow() {
                    let now = Instant::now();
                    if !node.withdraw(now, unix_now()) {
                        break;
                    }
                    closing_at = Some(now + WITHDRAW_WAIT);
                    publish(&snapshots, snapshot(&node, local_read));
                }
            }
            _ = until(closing_at) => break,
            Ok(()) = host_groups.changed() => {
                let groups = host_groups.borrow_and_update().clone();
                node.set_host_groups(groups, Instant::now());
                publish(&snapshots, snapshot(&node, local_read));
            }
            Ok(()) = local_networks.changed() => {
                // Once read, a later `None` keeps the networks known.
                if let Some(networks) = &*local_networks.borrow_and_update() {
                    node.set_local_networks(networks);
                    local_read = true;
                }
            }
            Ok(()) = border_prefixes.changed() => {
                let prefixes = border_prefixes.borrow_and_update().clone();
                node.set_border(&prefixes, Instant::now());
                publish(&snapshots, snapshot(&node, local_read));
            }
            Some(packet) = from_backbone.recv() => {
                // Refusals are counted by the node.
                let now = Instant::now();
                let _ = node.send_from_backbone(&packet, now);
                node.wake(&rng, now);
            }
            Ok(()) = foreign_routes.changed() => {
                node.set_foreign_routes(&foreign_routes.borrow_and_update());
            }
            Ok(()) = route_overrides.changed() => {
                node.set_route_overrides(&route_overrides.borrow_and_update());
            }
            Ok(()) = native_keys.changed() => {
                let keys = native_keys.borrow_and_update().clone();
                node.set_native_keys(keys, Instant::now());
                publish(&snapshots, snapshot(&node, local_read));
            }
            Ok(()) = dns.changed() => {
                let settings = dns.borrow_and_update().clone();
                node.set_dns(settings);
                publish(&snapshots, snapshot(&node, local_read));
            }
            Ok(()) = paths.changed() => {
                let list = paths.borrow_and_update().clone();
                node.set_paths(list, &rng, Instant::now());
                publish(&snapshots, snapshot(&node, local_read));
            }
            event = event_rx.recv() => {
                let Some(event) = event else { break };
                let now = Instant::now();
                match event {
                    Event::Opened { conn, writer, closer, inbound, refused } => {
                        let mut open = Open { writer, closer, ticket: None, refused };
                        match inbound {
                            Some((address, transport)) => {
                                let member = dialed.values().any(|known| *known == address.ip());
                                match budget.admit(address, transport, member, now) {
                                    Admission::Dropped => {
                                        open.closer.notify_one();
                                        continue;
                                    }
                                    Admission::Admitted(ticket, evicted) => {
                                        open.ticket = Some(ticket);
                                        if let Some(evicted) = evicted {
                                            let victim = conns
                                                .iter()
                                                .find(|(_, other)| other.ticket == Some(evicted))
                                                .map(|(&id, _)| id);
                                            if let Some(victim) = victim {
                                                close(&mut conns, &mut node, &mut budget, victim, now);
                                            }
                                        }
                                    }
                                }
                                node.accept(conn, now);
                                conns.insert(conn, open);
                            }
                            None => {
                                conns.insert(conn, open);
                                match node.connect(conn, None, &rng, now) {
                                    Ok(()) => {}
                                    // Tried again shortly, without holding up the node.
                                    Err(CloseReason::WaitForSession) => {
                                        waiting.push((conn, now + WAIT_FOR_SESSION_RETRY, 1));
                                    }
                                    Err(_) => close(&mut conns, &mut node, &mut budget, conn, now),
                                }
                            }
                        }
                    }
                    Event::Packet { conn, packet } => {
                        if conns.contains_key(&conn) {
                            node.receive(conn, &packet, &rng, now);
                            if node.is_up(conn) {
                                if let Some(ticket) = conns.get_mut(&conn).and_then(|open| open.ticket.take()) {
                                    budget.finished(ticket, now);
                                }
                            }
                        }
                    }
                    Event::Dialing { peer, address } => {
                        dialed.insert(peer, address);
                    }
                    Event::Closed { conn } => {
                        waiting.retain(|(waiting_conn, _, _)| *waiting_conn != conn);
                        if let Some(open) = conns.remove(&conn) {
                            if let Some(ticket) = open.ticket {
                                budget.release(ticket);
                            }
                            node.disconnected(conn, now);
                        }
                    }
                }
            }
            packet = from_interface.recv() => {
                let Some(packet) = packet else { break };
                // Refusals are counted by the node.
                let now = Instant::now();
                let _ = node.send_ip(&packet, now);
                node.wake(&rng, now);
            }
            _ = until(wake_at) => {
                let now = Instant::now();
                node.wake(&rng, now);
                let due: Vec<(ConnId, u32)> = waiting
                    .iter()
                    .filter(|(_, at, _)| *at <= now)
                    .map(|(conn, _, tries)| (*conn, *tries))
                    .collect();
                waiting.retain(|(_, at, _)| *at > now);
                for (conn, tries) in due {
                    if !conns.contains_key(&conn) {
                        continue;
                    }
                    match node.connect(conn, None, &rng, now) {
                        Ok(()) => {}
                        Err(CloseReason::WaitForSession) if tries < WAIT_FOR_SESSION_TRIES => {
                            waiting.push((conn, now + WAIT_FOR_SESSION_RETRY, tries + 1));
                        }
                        Err(_) => close(&mut conns, &mut node, &mut budget, conn, now),
                    }
                }
            }
            _ = ticks.tick() => {
                node.tick(&rng, Instant::now(), unix_now());
                publish(&snapshots, snapshot(&node, local_read));
            }
        }
        carry_out(
            &mut node,
            &mut conns,
            &mut budget,
            &to_interface,
            to_backbone.as_ref(),
        );
    }

    for open in conns.values() {
        open.closer.notify_one();
    }
    drop(tasks);
    Ok(())
}

/// Sleeps until `at`, or forever without one.
async fn until(at: Option<Instant>) {
    match at {
        Some(at) => tokio::time::sleep_until(tokio::time::Instant::from_std(at)).await,
        None => std::future::pending().await,
    }
}

fn snapshot(node: &Node, local_read: bool) -> Snapshot {
    let paths = node.path_status(Instant::now());
    Snapshot {
        peer_id: node.id(),
        neighbours: node.neighbours(),
        routes: node
            .paths()
            .into_iter()
            .map(|(peer, route)| (peer, route.next_hop, route.hops))
            .collect(),
        counters: node.counters(),
        sync_oversize: node.sync_oversize().clone(),
        duplicate_id: node.duplicate_id(),
        system_routes: if local_read {
            node.system_routes()
        } else {
            Vec::new()
        },
        system_routes_truncated: if local_read {
            node.system_routes_truncated()
        } else {
            0
        },
        local_networks_read: local_read,
        refused_key_changes: node.refused_key_changes(),
        static_key: (node.settings().security == SecurityMode::ForwardSecrecy)
            .then(|| node.static_public()),
        waiting_for_native_keys: node.waits_for_native_keys(),
        not_native: node.last_not_native(),
        members: members(node, &paths),
        rejected_advertisements: node.route_table().refused_subnet_count(),
        overlaps: overlaps(node),
        foreign_overlaps: node.foreign_overlaps(),
        address_conflicts: node
            .route_table()
            .address_conflicts()
            .into_iter()
            .map(|(peer, address)| (peer.0, address))
            .collect(),
        names: Some(Arc::clone(node.names())),
        paths,
        advertising: node.advertising().to_vec(),
        standing_in: node.standing_in().to_vec(),
        withdrawing: node.is_withdrawn(),
        border: node.route_table().border().to_vec(),
        instance: node.own_info().inst_id.to_string(),
    }
}

/// `members[].pathState` and `unreachable` of a member with these
/// addresses: those of the `to_peer` path to it, if any. `active` is shown
/// as `custom` and `pending` as `auto`; a member that only a `to_subnet`
/// path covers stays `auto`.
fn member_path_state(paths: &[PathStatus], addresses: &[IpAddr]) -> (&'static str, Option<IpAddr>) {
    let path = paths.iter().find(|path| match path.target {
        PathTarget::Peer(address) => addresses.contains(&address),
        PathTarget::Subnet(_) => false,
    });
    match path {
        None => ("auto", None),
        Some(path) => {
            let state = match path.state {
                "active" => "custom",
                "pending" => "auto",
                other => other,
            };
            (state, path.unreachable)
        }
    }
}

fn members(node: &Node, paths: &[PathStatus]) -> Vec<Member> {
    let table = node.route_table();
    let fewest = node.fewest_hops();
    node.paths()
        .into_iter()
        .map(|(peer, route)| {
            let (addresses, subnets) = table
                .peer(PeerId(peer))
                .map(|view| (view.addresses.to_vec(), view.subnets.to_vec()))
                .unwrap_or_default();
            let via = match route.path.split_last() {
                Some((_, relays)) => relays.to_vec(),
                None => Vec::new(),
            };
            let rtt = if route.hops == 1 {
                node.latency(peer)
            } else {
                None
            };
            let latency_ms = rtt.map(|rtt| u32::try_from(rtt.as_millis()).unwrap_or(u32::MAX));
            let (path_state, unreachable) = member_path_state(paths, &addresses);
            let info = node.peer_info(peer);
            Member {
                peer_id: peer,
                instance: info
                    .map(|info| info.inst_id.to_string())
                    .unwrap_or_default(),
                hostname: info.and_then(|info| info.hostname.clone()),
                addresses,
                subnets,
                via,
                hops: route.hops,
                fewest_hops: fewest.get(&peer).copied().unwrap_or(route.hops),
                latency_ms,
                path_state,
                unreachable,
            }
        })
        .collect()
}

/// Accepted subnets overlapping this node's networks. The range of a host
/// group this node is a gateway of is not one: the other gateway
/// advertising it is expected (spec §15.7 rule 5).
fn overlaps(node: &Node) -> Vec<IpNet> {
    let groups: Vec<IpNet> = node
        .settings()
        .gateway_groups()
        .into_iter()
        .map(|(group, _)| group.cidr)
        .collect();
    let mut nets: Vec<IpNet> = node
        .route_table()
        .local_conflicts()
        .into_iter()
        .map(|(_, net)| net)
        .filter(|net| !groups.contains(net))
        .collect();
    nets.sort_by_key(ToString::to_string);
    nets.dedup();
    nets
}

/// Publishes `next` only when it differs, so that readers wake on changes.
fn publish(snapshots: &watch::Sender<Snapshot>, next: Snapshot) {
    snapshots.send_if_modified(|current| {
        if *current == next {
            false
        } else {
            *current = next;
            true
        }
    });
}

fn close(
    conns: &mut HashMap<ConnId, Open>,
    node: &mut Node,
    budget: &mut HandshakeBudget,
    conn: ConnId,
    now: Instant,
) {
    if let Some(open) = conns.remove(&conn) {
        open.closer.notify_one();
        if let Some(ticket) = open.ticket {
            budget.release(ticket);
        }
    }
    node.disconnected(conn, now);
}

fn carry_out(
    node: &mut Node,
    conns: &mut HashMap<ConnId, Open>,
    budget: &mut HandshakeBudget,
    to_interface: &mpsc::Sender<Vec<u8>>,
    to_backbone: Option<&mpsc::Sender<Vec<u8>>>,
) {
    while let Some(action) = node.poll_action() {
        match action {
            Action::Send { conn, packet } => {
                if let Some(open) = conns.get(&conn) {
                    // A full queue drops the packet, like a full link.
                    let _ = open.writer.try_send(packet);
                }
            }
            Action::Deliver(packet) => {
                let _ = to_interface.try_send(packet);
            }
            Action::ToBackbone(packet) => {
                // A full queue drops the packet, like a full link.
                if let Some(to_backbone) = to_backbone {
                    let _ = to_backbone.try_send(packet);
                }
            }
            Action::Close { conn, reason } => {
                if let Some(open) = conns.remove(&conn) {
                    note_refusal(reason, open.refused.as_ref());
                    open.closer.notify_one();
                    if let Some(ticket) = open.ticket {
                        budget.release(ticket);
                    }
                }
            }
        }
    }
}

async fn accept_tcp(listener: TcpListener, shared: Shared) {
    loop {
        let Ok((stream, address)) = listener.accept().await else {
            sleep(Duration::from_millis(100)).await;
            continue;
        };
        let shared = shared.clone();
        tokio::spawn(async move {
            run_tcp(stream, Some((address, link::Transport::Tcp)), None, shared).await;
        });
    }
}

/// Runs one TCP connection until it ends; returns how long it was open.
async fn run_tcp(
    stream: TcpStream,
    inbound: Option<(SocketAddr, link::Transport)>,
    refused: Option<Arc<AtomicBool>>,
    shared: Shared,
) -> Duration {
    let opened = Instant::now();
    let _ = stream.set_nodelay(true);
    let conn = shared.conn_id();
    let (mut reader, mut writer) = stream.into_split();
    let (tx, mut rx) = mpsc::channel::<Vec<u8>>(CONN_QUEUE);
    let closer = Arc::new(Notify::new());
    if shared
        .events
        .send(Event::Opened {
            conn,
            writer: tx,
            closer: closer.clone(),
            inbound,
            refused,
        })
        .await
        .is_err()
    {
        return opened.elapsed();
    }
    let write = tokio::spawn(async move {
        while let Some(packet) = rx.recv().await {
            let Ok(frame) = encode_frame(&packet) else {
                continue;
            };
            if writer.write_all(&frame).await.is_err() {
                break;
            }
        }
        let _ = writer.shutdown().await;
    });
    let mut decoder = FrameDecoder::new();
    let mut buffer = vec![0u8; 8192];
    'read: loop {
        let read = tokio::select! {
            read = reader.read(&mut buffer) => read,
            _ = closer.notified() => break 'read,
        };
        let Ok(n) = read else { break };
        if n == 0 || decoder.push(&buffer[..n]).is_err() {
            break;
        }
        loop {
            match decoder.next_packet() {
                Ok(Some(packet)) => {
                    if shared
                        .events
                        .send(Event::Packet { conn, packet })
                        .await
                        .is_err()
                    {
                        break 'read;
                    }
                }
                Ok(None) => break,
                Err(_) => break 'read,
            }
        }
    }
    write.abort();
    let _ = shared.events.send(Event::Closed { conn }).await;
    opened.elapsed()
}

/// Aborts its tasks when dropped.
struct AbortAll(Vec<tokio::task::JoinHandle<()>>);

impl Drop for AbortAll {
    fn drop(&mut self) {
        for task in &self.0 {
            task.abort();
        }
    }
}

/// How long a dial task waits before dialing its peer again.
#[derive(Debug, PartialEq, Eq)]
struct DialDelay {
    redial: Duration,
    /// Zero until the node refuses the peer as not native.
    refused: Duration,
}

impl DialDelay {
    fn new() -> Self {
        Self {
            redial: REDIAL_MIN,
            refused: Duration::ZERO,
        }
    }

    /// The wait after a connection that lasted `lasted`. A peer refused
    /// for a static key off the native key list waits from
    /// [`REFUSED_MIN`], doubling up to [`REFUSED_MAX`], and the refusal
    /// does not count as a failed connection (spec §8.3.1 rule 5).
    fn after(&mut self, lasted: Duration, refused: bool) -> Duration {
        if refused {
            self.refused = if self.refused.is_zero() {
                REFUSED_MIN
            } else {
                (self.refused * 2).min(REFUSED_MAX)
            };
            return self.refused;
        }
        self.refused = Duration::ZERO;
        self.redial = if lasted >= STABLE {
            REDIAL_MIN
        } else {
            (self.redial * 2).min(REDIAL_MAX)
        };
        self.redial
    }

    /// A new native key list: refusals start over (spec §8.3.1 rule 5).
    fn new_list(&mut self) {
        self.refused = Duration::ZERO;
    }
}

/// Keeps one configured peer connected (spec §3). A new native key list
/// ends the wait and dials at once.
async fn dial(
    peer: PeerEndpoint,
    index: usize,
    shared: Shared,
    mut native_keys: watch::Receiver<Option<Vec<[u8; 32]>>>,
) {
    let rng = SystemRandom::new();
    let mut delay = DialDelay::new();
    let refused = Arc::new(AtomicBool::new(false));
    loop {
        let lasted = match tokio::net::lookup_host((peer.server.as_str(), peer.port)).await {
            Ok(mut addresses) => match addresses.next() {
                Some(address) => match peer.transport {
                    _ if shared
                        .events
                        .send(Event::Dialing {
                            peer: index,
                            address: address.ip(),
                        })
                        .await
                        .is_err() =>
                    {
                        return;
                    }
                    Transport::Tcp => match TcpStream::connect(address).await {
                        Ok(stream) => {
                            run_tcp(stream, None, Some(refused.clone()), shared.clone()).await
                        }
                        Err(_) => Duration::ZERO,
                    },
                    Transport::Udp => {
                        let (conn_id, magic) = (random_u32(&rng), random_u64(&rng));
                        dial_udp(address, conn_id, magic, refused.clone(), shared.clone())
                            .await
                            .unwrap_or(Duration::ZERO)
                    }
                },
                None => Duration::ZERO,
            },
            Err(_) => Duration::ZERO,
        };
        if shared.events.is_closed() {
            return;
        }
        let wait = delay.after(lasted, refused.swap(false, Ordering::Relaxed));
        redial_wait(wait, &mut delay, &mut native_keys).await;
    }
}

/// Tells a dial task that its connection closed because the node refused
/// the peer's static key (spec §8.3.1 rule 5), so that it waits as a
/// refused peer.
fn note_refusal(reason: CloseReason, refused: Option<&Arc<AtomicBool>>) {
    if let (CloseReason::NotNative(_), Some(refused)) = (reason, refused) {
        refused.store(true, Ordering::Relaxed);
    }
}

/// Waits `wait` before the next dial. A new native key list ends the wait
/// at once and starts refusals over (spec §8.3.1 rule 5).
async fn redial_wait(
    wait: Duration,
    delay: &mut DialDelay,
    native_keys: &mut watch::Receiver<Option<Vec<[u8; 32]>>>,
) {
    tokio::select! {
        _ = sleep(wait) => {}
        changed = native_keys.changed() => match changed {
            Ok(()) => delay.new_list(),
            // Only fixed lists from here on.
            Err(_) => sleep(wait).await,
        },
    }
}

/// A UDP connection this node opens: its own socket, one Syn, no resend
/// (spec §3.2).
async fn dial_udp(
    address: SocketAddr,
    conn_id: u32,
    magic: u64,
    refused: Arc<AtomicBool>,
    shared: Shared,
) -> io::Result<Duration> {
    let local: SocketAddr = match address {
        SocketAddr::V4(_) => (Ipv4Addr::UNSPECIFIED, 0).into(),
        SocketAddr::V6(_) => (Ipv6Addr::UNSPECIFIED, 0).into(),
    };
    let socket = Arc::new(UdpSocket::bind(local).await?);
    socket.connect(address).await?;
    socket.send(&udp::syn(conn_id, magic)).await?;
    let mut buffer = vec![0u8; MAX_DATAGRAM];
    let answered = timeout(SACK_TIMEOUT, async {
        loop {
            let n = socket.recv(&mut buffer).await?;
            if udp::parse(&buffer[..n]) == (Datagram::Sack { conn_id, magic }) {
                return Ok::<(), io::Error>(());
            }
        }
    })
    .await;
    match answered {
        Ok(Ok(())) => {}
        Ok(Err(error)) => return Err(error),
        Err(_) => return Ok(Duration::ZERO),
    }

    let opened = Instant::now();
    let conn = shared.conn_id();
    let (tx, mut rx) = mpsc::channel::<Vec<u8>>(CONN_QUEUE);
    let closer = Arc::new(Notify::new());
    if shared
        .events
        .send(Event::Opened {
            conn,
            writer: tx,
            closer: closer.clone(),
            inbound: None,
            refused: Some(refused),
        })
        .await
        .is_err()
    {
        return Ok(opened.elapsed());
    }
    let sender = socket.clone();
    let write = tokio::spawn(async move {
        while let Some(packet) = rx.recv().await {
            if let Some(datagram) = udp::data(conn_id, &packet) {
                let _ = sender.send(&datagram).await;
            }
        }
    });
    loop {
        let received = tokio::select! {
            received = socket.recv(&mut buffer) => received,
            _ = closer.notified() => break,
        };
        let Ok(n) = received else { break };
        if let Datagram::Data {
            conn_id: id,
            packet,
        } = udp::parse(&buffer[..n])
        {
            if id == conn_id
                && shared
                    .events
                    .send(Event::Packet {
                        conn,
                        packet: packet.to_vec(),
                    })
                    .await
                    .is_err()
            {
                break;
            }
        }
    }
    write.abort();
    let _ = shared.events.send(Event::Closed { conn }).await;
    Ok(opened.elapsed())
}

struct UdpSession {
    conn: ConnId,
    magic: u64,
}

/// A listening UDP socket: sessions by (address, conn_id), a repeated Syn
/// answered with the same Sack (spec §3.2).
async fn serve_udp(socket: UdpSocket, shared: Shared) {
    let socket = Arc::new(socket);
    let mut sessions: HashMap<(SocketAddr, u32), UdpSession> = HashMap::new();
    let (gone_tx, mut gone_rx) = mpsc::channel::<(SocketAddr, u32)>(CONN_QUEUE);
    let mut buffer = vec![0u8; MAX_DATAGRAM];
    loop {
        let (n, from) = tokio::select! {
            received = socket.recv_from(&mut buffer) => match received {
                Ok(received) => received,
                Err(_) => continue,
            },
            gone = gone_rx.recv() => {
                if let Some(key) = gone {
                    if let Some(session) = sessions.remove(&key) {
                        let _ = shared.events.send(Event::Closed { conn: session.conn }).await;
                    }
                }
                continue;
            }
        };
        match udp::parse(&buffer[..n]) {
            Datagram::Syn { conn_id, magic } => {
                if let Some(session) = sessions.get(&(from, conn_id)) {
                    if session.magic == magic {
                        let _ = socket.send_to(&udp::sack(conn_id, magic), from).await;
                    }
                    continue;
                }
                if sessions.len() >= MAX_UDP_SESSIONS {
                    continue;
                }
                let conn = shared.conn_id();
                let (tx, mut rx) = mpsc::channel::<Vec<u8>>(CONN_QUEUE);
                let closer = Arc::new(Notify::new());
                if shared
                    .events
                    .send(Event::Opened {
                        conn,
                        writer: tx,
                        closer: closer.clone(),
                        inbound: Some((from, link::Transport::Udp)),
                        refused: None,
                    })
                    .await
                    .is_err()
                {
                    return;
                }
                sessions.insert((from, conn_id), UdpSession { conn, magic });
                let sender = socket.clone();
                let gone = gone_tx.clone();
                tokio::spawn(async move {
                    loop {
                        tokio::select! {
                            packet = rx.recv() => match packet {
                                Some(packet) => {
                                    if let Some(datagram) = udp::data(conn_id, &packet) {
                                        let _ = sender.send_to(&datagram, from).await;
                                    }
                                }
                                None => break,
                            },
                            _ = closer.notified() => break,
                        }
                    }
                    let _ = gone.send((from, conn_id)).await;
                });
                let _ = socket.send_to(&udp::sack(conn_id, magic), from).await;
            }
            Datagram::Data { conn_id, packet } => {
                if let Some(session) = sessions.get(&(from, conn_id)) {
                    let _ = shared
                        .events
                        .send(Event::Packet {
                            conn: session.conn,
                            packet: packet.to_vec(),
                        })
                        .await;
                }
            }
            // STUN and hole punching belong to direct connections (spec §20),
            // not built yet.
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{ListenConfig, MeshConfig};

    fn settings(address: &str, role: &str) -> MeshSettings {
        let config = serde_json::json!({
            "config_version": 1,
            "network": {"name": "office", "secret": "s3cr3t", "kind": "legacy"},
            "node": {"address": address, "role": role},
            "peers": [{"server": "peer.example", "port": 40000}],
        });
        let config: MeshConfig = serde_json::from_value(config).unwrap();
        config.validate().unwrap()
    }

    #[test]
    fn a_member_takes_the_state_of_its_to_peer_path() {
        let ip = |text: &str| -> IpAddr { text.parse().unwrap() };
        let path = |target, state, unreachable| PathStatus {
            id: String::new(),
            target,
            via: vec![ip("10.144.0.3")],
            state,
            reason: None,
            unreachable,
        };
        let seven = PathTarget::Peer(ip("10.144.0.7"));
        let subnet = PathTarget::Subnet(IpNet::parse("192.168.10.0/24").unwrap());
        let of = |state, unreachable| {
            member_path_state(
                &[
                    path(subnet, "fallback", None),
                    path(seven, state, unreachable),
                ],
                &[ip("10.144.0.7")],
            )
        };
        assert_eq!(of("active", None), ("custom", None));
        assert_eq!(of("pending", None), ("auto", None));
        assert_eq!(
            of("first_hop_only", Some(ip("10.144.0.4"))).0,
            "first_hop_only"
        );
        assert_eq!(
            of("fallback", Some(ip("10.144.0.3"))),
            ("fallback", Some(ip("10.144.0.3")))
        );
        // Another member, a node only a subnet path covers, and no paths.
        let paths = [path(seven, "active", None), path(subnet, "active", None)];
        assert_eq!(
            member_path_state(&paths, &[ip("10.144.0.8")]),
            ("auto", None)
        );
        assert_eq!(member_path_state(&[], &[ip("10.144.0.7")]), ("auto", None));
    }

    struct Running {
        to_mesh: mpsc::Sender<Vec<u8>>,
        from_mesh: mpsc::Receiver<Vec<u8>>,
        snapshots: watch::Receiver<Snapshot>,
        local_networks: watch::Sender<Option<Vec<IpNet>>>,
        _shutdown: watch::Sender<bool>,
    }

    async fn start(settings: MeshSettings, listeners: Listeners) -> Running {
        start_with(settings, listeners, Some(Vec::new())).await
    }

    async fn start_with(
        settings: MeshSettings,
        listeners: Listeners,
        local: Option<Vec<IpNet>>,
    ) -> Running {
        let rng = SystemRandom::new();
        let static_key = KeyPair::generate(&rng).unwrap();
        let (to_mesh, from_interface) = mpsc::channel(16);
        let (to_interface, from_mesh) = mpsc::channel(16);
        let (snapshot_tx, snapshots) = watch::channel(Snapshot::default());
        let (shutdown_tx, shutdown) = watch::channel(false);
        let (local_tx, local_networks) = watch::channel(local);
        let (_, native_keys) = watch::channel(None);
        let (_, dns) = watch::channel(DnsSettings::default());
        let (_, paths) = watch::channel(Vec::new());
        let (_, host_groups) = watch::channel(Vec::new());
        let (_, route_overrides) = watch::channel(Vec::new());
        let (_, foreign_routes) = watch::channel(Vec::new());
        tokio::spawn(run(
            settings,
            static_key,
            listeners,
            Channels {
                from_interface,
                to_interface,
                snapshots: snapshot_tx,
                local_networks,
                native_keys,
                dns,
                paths,
                host_groups,
                route_overrides,
                foreign_routes,
                shutdown,
                border: None,
            },
        ));
        Running {
            to_mesh,
            from_mesh,
            snapshots,
            local_networks: local_tx,
            _shutdown: shutdown_tx,
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

    async fn two_nodes(transport: Transport) {
        let mut server = settings("10.144.0.1/24", "full");
        server.peers.clear();
        server.listen = vec![ListenConfig {
            transport,
            port: 0,
            address: Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        }];
        let listeners = Listeners::bind(&server).await.unwrap();
        let port = listeners.local_addrs().unwrap()[0].1.port();
        let mut client = settings("10.144.0.2/24", "full");
        client.peers = vec![PeerEndpoint {
            server: "127.0.0.1".into(),
            port,
            transport,
        }];
        client.listen.clear();
        let client_listeners = Listeners::bind(&client).await.unwrap();

        let mut a = start(server, listeners).await;
        let b = start(client, client_listeners).await;

        // Node IDs are new every start; the first snapshot names them.
        let id_of = |running: &Running| {
            let mut snapshots = running.snapshots.clone();
            async move {
                loop {
                    let id = snapshots.borrow().peer_id;
                    if id != 0 {
                        return id;
                    }
                    snapshots.changed().await.unwrap();
                }
            }
        };
        let a_id = timeout(Duration::from_secs(5), id_of(&a)).await.unwrap();
        let b_id = timeout(Duration::from_secs(5), id_of(&b)).await.unwrap();

        // Wait until both know each other's address.
        timeout(Duration::from_secs(20), async {
            let mut snapshots = b.snapshots.clone();
            loop {
                if snapshots
                    .borrow()
                    .routes
                    .iter()
                    .any(|route| route.0 == a_id)
                {
                    break;
                }
                snapshots.changed().await.unwrap();
            }
        })
        .await
        .expect("the nodes find each other");
        sleep(Duration::from_secs(2)).await;

        let packet = ipv4_packet([10, 144, 0, 2], [10, 144, 0, 1]);
        b.to_mesh.send(packet.clone()).await.unwrap();
        let received = timeout(Duration::from_secs(5), a.from_mesh.recv())
            .await
            .expect("delivered in time");
        assert_eq!(received, Some(packet));
        assert_eq!(a.snapshots.borrow().neighbours, vec![b_id]);
        let members = b.snapshots.borrow().members.clone();
        let member = members
            .iter()
            .find(|member| member.peer_id == a_id)
            .expect("a is listed");
        assert_eq!(member.addresses, [IpAddr::V4(Ipv4Addr::new(10, 144, 0, 1))]);
        assert_eq!((member.hops, member.via.is_empty()), (1, true));
        assert_eq!(b.snapshots.borrow().rejected_advertisements, 0);
    }

    #[test]
    fn only_a_refusal_marks_the_dial_task() {
        let refused = Arc::new(AtomicBool::new(false));
        note_refusal(CloseReason::Timeout, Some(&refused));
        assert!(!refused.load(Ordering::Relaxed));
        note_refusal(CloseReason::NotNative(7), None);
        note_refusal(CloseReason::NotNative(7), Some(&refused));
        assert!(refused.load(Ordering::Relaxed));
        // The dial task reads it once, then waits as a refused peer.
        let mut delay = DialDelay::new();
        assert_eq!(
            delay.after(Duration::ZERO, refused.swap(false, Ordering::Relaxed)),
            REFUSED_MIN
        );
        assert!(!refused.load(Ordering::Relaxed));
    }

    #[tokio::test]
    async fn a_new_list_ends_the_wait_of_a_refused_peer() {
        let (keys_tx, mut keys) = watch::channel(None);
        let mut delay = DialDelay::new();
        let wait = delay.after(Duration::ZERO, true);
        assert_eq!(wait, REFUSED_MIN);
        let started = Instant::now();
        let waiting = redial_wait(REFUSED_MAX, &mut delay, &mut keys);
        let update = async {
            sleep(Duration::from_millis(50)).await;
            keys_tx.send(Some(vec![[1; 32]])).unwrap();
            std::future::pending::<()>().await;
        };
        tokio::select! {
            () = waiting => {}
            () = update => unreachable!(),
        }
        assert!(started.elapsed() < Duration::from_secs(5));
        // Refusals start over: the next one waits the least again.
        assert_eq!(delay.after(Duration::ZERO, true), REFUSED_MIN);
    }

    /// Waits until `running`'s snapshot passes `check`.
    async fn wait_for(running: &Running, check: impl Fn(&Snapshot) -> bool) {
        let mut snapshots = running.snapshots.clone();
        timeout(Duration::from_secs(20), async {
            loop {
                if check(&snapshots.borrow()) {
                    break;
                }
                snapshots.changed().await.unwrap();
            }
        })
        .await
        .expect("the snapshot comes in time");
    }

    #[tokio::test]
    async fn no_subnet_is_installed_before_the_local_networks_are_read() {
        let config = serde_json::json!({
            "config_version": 1,
            "network": {"name": "office", "secret": "s3cr3t", "kind": "legacy"},
            "node": {"address": "10.144.0.1/24", "role": "full"},
            "peers": [{"server": "peer.example", "port": 40000}],
            "subnets": {"advertise": ["192.168.10.0/24"]},
        });
        let mut server: MeshSettings = serde_json::from_value::<MeshConfig>(config)
            .unwrap()
            .validate()
            .unwrap();
        server.peers.clear();
        // Port 0 is refused in a configuration; a test binds any free one.
        server.listen = vec![ListenConfig {
            transport: Transport::Tcp,
            port: 0,
            address: Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        }];
        let listeners = Listeners::bind(&server).await.unwrap();
        let port = listeners.local_addrs().unwrap()[0].1.port();
        let mut client = settings("10.144.0.2/24", "full");
        client.peers = vec![PeerEndpoint {
            server: "127.0.0.1".into(),
            port,
            transport: Transport::Tcp,
        }];
        client.listen.clear();
        let client_listeners = Listeners::bind(&client).await.unwrap();
        let _a = start(server, listeners).await;
        let b = start_with(client, client_listeners, None).await;
        let subnet = IpNet::parse("192.168.10.0/24").unwrap();

        // The subnet is accepted, but the networks of this machine are not
        // known yet: nothing is installed.
        wait_for(&b, |snapshot| !snapshot.members.is_empty()).await;
        sleep(Duration::from_secs(2)).await;
        assert!(b.snapshots.borrow().system_routes.is_empty());
        assert!(!b.snapshots.borrow().local_networks_read);

        // Read: the subnet is not one of them, so it is installed.
        b.local_networks.send(Some(Vec::new())).unwrap();
        wait_for(&b, |snapshot| snapshot.system_routes == [subnet]).await;
        assert!(b.snapshots.borrow().local_networks_read);

        // A later failed read keeps what is known.
        b.local_networks.send(None).unwrap();
        sleep(Duration::from_secs(2)).await;
        assert_eq!(b.snapshots.borrow().system_routes, [subnet]);
        assert!(b.snapshots.borrow().local_networks_read);
    }

    #[tokio::test]
    async fn an_aborted_driver_frees_its_listening_port() {
        let mut server = settings("10.144.0.1/24", "full");
        server.peers.clear();
        server.listen = vec![ListenConfig {
            transport: Transport::Tcp,
            port: 0,
            address: Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        }];
        let listeners = Listeners::bind(&server).await.unwrap();
        let address = listeners.local_addrs().unwrap()[0].1;
        let rng = SystemRandom::new();
        let (_to_mesh, from_interface) = mpsc::channel(16);
        let (to_interface, _from_mesh) = mpsc::channel(16);
        let (snapshot_tx, mut snapshots) = watch::channel(Snapshot::default());
        let (_shutdown_tx, shutdown) = watch::channel(false);
        let (_local, local_networks) = watch::channel(Some(Vec::new()));
        let (_keys, native_keys) = watch::channel(None);
        let (_dns, dns) = watch::channel(DnsSettings::default());
        let (_groups, host_groups) = watch::channel(Vec::new());
        let (_paths, paths) = watch::channel(Vec::new());
        let (_overrides, route_overrides) = watch::channel(Vec::new());
        let (_foreign, foreign_routes) = watch::channel(Vec::new());
        let task = tokio::spawn(run(
            server,
            KeyPair::generate(&rng).unwrap(),
            listeners,
            Channels {
                from_interface,
                to_interface,
                snapshots: snapshot_tx,
                local_networks,
                native_keys,
                dns,
                paths,
                host_groups,
                route_overrides,
                foreign_routes,
                shutdown,
                border: None,
            },
        ));
        // Running: the first snapshot is out.
        timeout(Duration::from_secs(5), snapshots.changed())
            .await
            .expect("started")
            .unwrap();
        task.abort();
        let _ = task.await;
        // The accept loop went with it: the port can be bound again.
        timeout(Duration::from_secs(5), async {
            loop {
                if TcpListener::bind(address).await.is_ok() {
                    break;
                }
                sleep(Duration::from_millis(50)).await;
            }
        })
        .await
        .expect("the port is free again");
    }

    #[tokio::test]
    async fn a_dns_change_sent_before_the_driver_runs_is_applied() {
        let mut node = settings("10.144.0.1/24", "full");
        node.peers.clear();
        node.listen = vec![ListenConfig {
            transport: Transport::Tcp,
            port: 0,
            address: Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        }];
        let listeners = Listeners::bind(&node).await.unwrap();
        let rng = SystemRandom::new();
        let (_to_mesh, from_interface) = mpsc::channel(16);
        let (to_interface, _from_mesh) = mpsc::channel(16);
        let (snapshot_tx, mut snapshots) = watch::channel(Snapshot::default());
        let (_shutdown_tx, shutdown) = watch::channel(false);
        let (_local, local_networks) = watch::channel(Some(Vec::new()));
        let (_keys, native_keys) = watch::channel(None);
        let (dns_tx, dns) = watch::channel(node.dns.clone());
        let (_groups, host_groups) = watch::channel(Vec::new());
        let (_paths, paths) = watch::channel(Vec::new());
        let (_overrides, route_overrides) = watch::channel(Vec::new());
        let (_foreign, foreign_routes) = watch::channel(Vec::new());
        // `mesh_set_dns` right after the network was saved: sent after the
        // receiver was handed over, before the driver looked at it.
        dns_tx.send_replace(DnsSettings {
            enabled: true,
            suffix: "home.internal".into(),
            ..node.dns.clone()
        });
        let task = tokio::spawn(run(
            node,
            KeyPair::generate(&rng).unwrap(),
            listeners,
            Channels {
                from_interface,
                to_interface,
                snapshots: snapshot_tx,
                local_networks,
                native_keys,
                dns,
                paths,
                host_groups,
                route_overrides,
                foreign_routes,
                shutdown,
                border: None,
            },
        ));
        timeout(Duration::from_secs(5), async {
            loop {
                let applied = snapshots
                    .borrow_and_update()
                    .names
                    .as_ref()
                    .is_some_and(|names| names.enabled() && names.suffix() == "home.internal");
                if applied {
                    break;
                }
                snapshots.changed().await.unwrap();
            }
        })
        .await
        .expect("the change is applied");
        task.abort();
        let _ = task.await;
    }

    #[tokio::test]
    async fn two_nodes_over_tcp() {
        two_nodes(Transport::Tcp).await;
    }

    #[tokio::test]
    async fn two_nodes_over_udp() {
        two_nodes(Transport::Udp).await;
    }

    #[test]
    fn a_refused_peer_backs_off_from_five_seconds_to_five_minutes() {
        let mut delay = DialDelay::new();
        // Ordinary failures double from the first delay.
        assert_eq!(delay.after(Duration::ZERO, false), REDIAL_MIN * 2);
        let redial = delay.redial;
        let waits: Vec<u64> = (0..8)
            .map(|_| delay.after(Duration::ZERO, true).as_secs())
            .collect();
        assert_eq!(waits, vec![5, 10, 20, 40, 80, 160, 300, 300]);
        // Refusals are not failed connections.
        assert_eq!(delay.redial, redial);
        // A new list starts the refusals over.
        delay.new_list();
        assert_eq!(delay.after(Duration::ZERO, true), REFUSED_MIN);
        // So does a connection the node did not refuse.
        delay.after(STABLE, false);
        assert_eq!(delay.after(Duration::ZERO, true), REFUSED_MIN);
        assert_eq!(delay.after(STABLE, false), REDIAL_MIN);
    }

    #[tokio::test]
    async fn a_repeated_syn_gets_the_same_sack_and_no_new_session() {
        let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let address = socket.local_addr().unwrap();
        let (events, mut event_rx) = mpsc::channel(16);
        let shared = Shared {
            events,
            next_conn: Arc::new(AtomicU64::new(1)),
        };
        let server = tokio::spawn(serve_udp(socket, shared));
        let client = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        client.connect(address).await.unwrap();
        let mut buffer = [0u8; 64];
        for _ in 0..2 {
            client.send(&udp::syn(7, 99)).await.unwrap();
            let n = timeout(Duration::from_secs(2), client.recv(&mut buffer))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(
                udp::parse(&buffer[..n]),
                Datagram::Sack {
                    conn_id: 7,
                    magic: 99
                }
            );
        }
        let first = event_rx.recv().await.unwrap();
        assert!(matches!(first, Event::Opened { .. }));
        sleep(Duration::from_millis(100)).await;
        assert!(event_rx.try_recv().is_err(), "one session only");
        server.abort();
    }

    /// Runs a listening hub until shutdown and says how long it took to
    /// stop after the signal.
    async fn stop_time(advertise: &[&str]) -> Duration {
        let mut hub = settings("10.144.0.1/24", "full");
        hub.peers.clear();
        hub.listen = vec![ListenConfig {
            transport: Transport::Tcp,
            port: 0,
            address: Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        }];
        hub.advertise_subnets = advertise
            .iter()
            .map(|text| IpNet::parse(text).unwrap())
            .collect();
        let listeners = Listeners::bind(&hub).await.unwrap();
        let rng = SystemRandom::new();
        let (_to_mesh, from_interface) = mpsc::channel(16);
        let (to_interface, _from_mesh) = mpsc::channel(16);
        let (snapshot_tx, mut snapshots) = watch::channel(Snapshot::default());
        let (shutdown_tx, shutdown) = watch::channel(false);
        let (_keep_networks, local_networks) = watch::channel(Some(Vec::new()));
        let (_keep_keys, native_keys) = watch::channel(None);
        let (_keep_dns, dns) = watch::channel(DnsSettings::default());
        let (_keep_groups, host_groups) = watch::channel(Vec::new());
        let (_keep_paths, paths) = watch::channel(Vec::new());
        let (_keep_overrides, route_overrides) = watch::channel(Vec::new());
        let (_keep_routes, foreign_routes) = watch::channel(Vec::new());
        let task = tokio::spawn(run(
            hub,
            KeyPair::generate(&rng).unwrap(),
            listeners,
            Channels {
                from_interface,
                to_interface,
                snapshots: snapshot_tx,
                local_networks,
                native_keys,
                dns,
                paths,
                host_groups,
                route_overrides,
                foreign_routes,
                shutdown,
                border: None,
            },
        ));
        timeout(Duration::from_secs(5), async {
            while snapshots.borrow().peer_id == 0 {
                snapshots.changed().await.unwrap();
            }
        })
        .await
        .unwrap();
        let signalled = Instant::now();
        shutdown_tx.send(true).unwrap();
        timeout(Duration::from_secs(10), task)
            .await
            .expect("the node stops")
            .unwrap()
            .unwrap();
        let took = signalled.elapsed();
        if !advertise.is_empty() {
            assert!(snapshots.borrow().withdrawing);
            assert!(snapshots.borrow().advertising.is_empty());
        }
        took
    }

    #[tokio::test]
    async fn a_node_that_advertises_waits_after_withdrawing_before_it_stops() {
        // Spec §15.7 rule 6: withdraw, then close WITHDRAW_WAIT later.
        let took = stop_time(&["192.168.50.0/24"]).await;
        assert!(took >= WITHDRAW_WAIT, "{took:?}");
        assert!(took < WITHDRAW_WAIT + Duration::from_secs(2), "{took:?}");
        // Nothing to withdraw: it stops at once.
        let took = stop_time(&[]).await;
        assert!(took < Duration::from_secs(1), "{took:?}");
    }
}
