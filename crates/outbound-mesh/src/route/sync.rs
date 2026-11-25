//! Route synchronisation sessions (spec §12.2, §12.3).
//!
//! [`RouteSync`] keeps this node's information, the information and
//! connection rows learned from the network, one sync session per direct
//! neighbour, and the topology built from them (spec §12.5). It does no
//! I/O: the driver calls [`RouteSync::poll`] once a second, sends each
//! request it returns as a `SyncRouteInfo` RPC and reports the outcome with
//! [`RouteSync::on_response`]; requests from neighbours go to
//! [`RouteSync::on_request`], whose answer the driver sends back.
//!
//! Who pushes: among the direct neighbours that do not push to this node
//! themselves, this node picks one as its own target, preferring a
//! neighbour without port translation (spec §12.2). It also answers every
//! neighbour that pushes to it with its own changes, marked as not the
//! initiator. When two neighbours pick each other at the same time, the one
//! with the smaller node ID stays the initiator.

use std::collections::{BTreeMap, BTreeSet};
use std::time::{Duration, Instant};

use ring::error::Unspecified;
use ring::rand::SecureRandom;

use super::messages::{
    sync_error, ConnGraph, RoutePeerInfo, SyncRouteRequest, SyncRouteResponse, MAX_GRAPH_EDGES,
    MAX_GRAPH_NODES,
};
use super::topology::{Metric, NodeEntry, Topology};

/// How often the driver calls [`RouteSync::poll`] (spec §12.2).
pub const SYNC_INTERVAL: Duration = Duration::from_secs(1);
/// A session with nothing new still sends after this long (spec §12.2).
pub const REFRESH_INTERVAL: Duration = Duration::from_secs(10);
/// First retry delay after a failed request (spec §12.2).
pub const RETRY_MIN: Duration = Duration::from_millis(50);
/// Longest retry delay (spec §12.2).
pub const RETRY_MAX: Duration = Duration::from_secs(5);
/// This node's information gets a new version at least this often
/// (spec §12.3).
pub const OWN_REFRESH: Duration = Duration::from_secs(3600);
/// Information not updated for this long expires (spec §12.3).
pub const INFO_TTL: Duration = Duration::from_secs(3660);
/// A node unreachable in the topology for this long is removed
/// (spec §12.3).
pub const UNREACHABLE_TTL: Duration = Duration::from_secs(90);
/// Most other nodes kept: with this node, one connection graph's bound.
pub const MAX_NODES: usize = MAX_GRAPH_NODES - 1;
/// A neighbour that has not pushed as the initiator for this long no longer
/// counts as pushing.
pub const PUSH_EXPIRY: Duration = Duration::from_secs(30);

/// Something the driver must act on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Notice {
    /// The neighbour answered that this node's ID is already in use
    /// (spec §12.1 error 0).
    DuplicatePeerId,
}

struct Stored {
    info: RoutePeerInfo,
    /// Local time of receipt; replaces the sender's timestamp (spec §12.3).
    received: Instant,
}

#[derive(Default)]
struct Row {
    version: u32,
    neighbours: BTreeSet<u32>,
}

#[derive(Default)]
struct Sent {
    infos: BTreeMap<u32, u32>,
    rows: BTreeMap<u32, u32>,
}

struct Session {
    /// When the neighbour last asked as the initiator.
    pushed_at: Option<Instant>,
    mine: u64,
    theirs: Option<u64>,
    /// The neighbour pushes to this node as the initiator.
    they_initiate: bool,
    sent: Sent,
    in_flight: Option<Sent>,
    last_sent: Option<Instant>,
    retry: Duration,
    not_before: Option<Instant>,
}

impl Session {
    fn new(mine: u64) -> Self {
        Self {
            pushed_at: None,
            mine,
            theirs: None,
            they_initiate: false,
            sent: Sent::default(),
            in_flight: None,
            last_sent: None,
            retry: Duration::ZERO,
            not_before: None,
        }
    }

    /// Everything already sent is forgotten, so the next request is full.
    fn forget_sent(&mut self) {
        self.sent = Sent::default();
        self.in_flight = None;
    }
}

fn session_id(rng: &dyn SecureRandom) -> Result<u64, Unspecified> {
    let mut bytes = [0u8; 8];
    rng.fill(&mut bytes)?;
    Ok(u64::from_le_bytes(bytes))
}

/// NAT types without port translation, preferred as the push target
/// (spec §2.2, §12.2).
fn open_nat(nat: i32) -> bool {
    nat == 1 || nat == 2
}

/// Fields that make up the content of a node's information, without its
/// version and timestamp.
fn same_content(a: &RoutePeerInfo, b: &RoutePeerInfo) -> bool {
    let strip = |info: &RoutePeerInfo| RoutePeerInfo {
        version: 0,
        last_update: (0, 0),
        raw: Vec::new(),
        ..info.clone()
    };
    strip(a) == strip(b)
}

pub struct RouteSync {
    own: RoutePeerInfo,
    own_updated: Instant,
    own_row: Row,
    infos: BTreeMap<u32, Stored>,
    rows: BTreeMap<u32, Row>,
    unreachable_since: BTreeMap<u32, Instant>,
    sessions: BTreeMap<u32, Session>,
    target: Option<u32>,
    topology: Topology,
    changed: bool,
    conflicts: BTreeSet<u32>,
}

impl RouteSync {
    /// `own` is this node's information; its version starts at least at 1.
    pub fn new(mut own: RoutePeerInfo, now: Instant) -> Self {
        own.version = own.version.max(1);
        own.raw.clear();
        let mut sync = Self {
            // The connection row starts where the information does, so a
            // restart with a clock-based first version is not taken as old.
            own_row: Row {
                version: own.version,
                neighbours: BTreeSet::new(),
            },
            own,
            own_updated: now,
            infos: BTreeMap::new(),
            rows: BTreeMap::new(),
            unreachable_since: BTreeMap::new(),
            sessions: BTreeMap::new(),
            target: None,
            topology: Topology::new(),
            changed: false,
            conflicts: BTreeSet::new(),
        };
        sync.rebuild();
        sync
    }

    pub fn id(&self) -> u32 {
        self.own.peer_id
    }

    pub fn own(&self) -> &RoutePeerInfo {
        &self.own
    }

    /// Replaces this node's information; the version goes up when anything
    /// but the version and timestamp changed (spec §12.3).
    pub fn set_own(&mut self, info: RoutePeerInfo, now: Instant) {
        if same_content(&self.own, &info) {
            return;
        }
        let version = self.own.version.wrapping_add(1).max(1);
        self.own = RoutePeerInfo {
            version,
            raw: Vec::new(),
            ..info
        };
        self.own_updated = now;
        self.rebuild();
    }

    /// The neighbour this node pushes to as the initiator.
    pub fn target(&self) -> Option<u32> {
        self.target
    }

    pub fn topology(&self) -> &Topology {
        &self.topology
    }

    /// Information of every other node with a non-zero version.
    pub fn infos(&self) -> impl Iterator<Item = &RoutePeerInfo> {
        self.infos.values().map(|stored| &stored.info)
    }

    pub fn info(&self, peer: u32) -> Option<&RoutePeerInfo> {
        self.infos.get(&peer).map(|stored| &stored.info)
    }

    /// Node IDs announced by others with this node's ID but another route
    /// ID (spec §12.3).
    pub fn conflicts(&self) -> &BTreeSet<u32> {
        &self.conflicts
    }

    /// True once after the topology or the stored information changed.
    pub fn take_changed(&mut self) -> bool {
        std::mem::take(&mut self.changed)
    }

    /// A first connection to `peer` came up.
    pub fn neighbour_up(&mut self, peer: u32, rng: &dyn SecureRandom) -> Result<(), Unspecified> {
        if peer == self.id() || self.sessions.contains_key(&peer) {
            return Ok(());
        }
        self.sessions.insert(peer, Session::new(session_id(rng)?));
        if self.own_row.neighbours.insert(peer) {
            self.own_row.version = self.own_row.version.wrapping_add(1).max(1);
        }
        self.choose_target();
        self.rebuild();
        Ok(())
    }

    /// The last connection to `peer` went down.
    pub fn neighbour_down(&mut self, peer: u32) {
        self.sessions.remove(&peer);
        if self.own_row.neighbours.remove(&peer) {
            self.own_row.version = self.own_row.version.wrapping_add(1).max(1);
        }
        if self.target == Some(peer) {
            self.target = None;
        }
        self.choose_target();
        self.rebuild();
    }

    fn choose_target(&mut self) {
        if let Some(target) = self.target {
            if self
                .sessions
                .get(&target)
                .is_some_and(|session| !session.they_initiate)
            {
                return;
            }
        }
        self.target = self
            .sessions
            .iter()
            .filter(|(_, session)| !session.they_initiate)
            .map(|(&peer, _)| {
                let open = self.info(peer).is_some_and(|info| open_nat(info.udp_nat));
                (!open, peer)
            })
            .min()
            .map(|(_, peer)| peer);
    }

    /// The requests to send now, one per neighbour at most. `unix_now` is
    /// the wall-clock time put in this node's information (spec §12.3).
    pub fn poll(&mut self, now: Instant, unix_now: (i64, i32)) -> Vec<(u32, SyncRouteRequest)> {
        if now.saturating_duration_since(self.own_updated) >= OWN_REFRESH {
            self.own.version = self.own.version.wrapping_add(1).max(1);
            self.own_updated = now;
        }
        // A neighbour that stopped pushing is a candidate target again, so
        // no link stays synchronised one way only.
        let mut stale = false;
        for session in self.sessions.values_mut() {
            if session.they_initiate
                && session
                    .pushed_at
                    .is_none_or(|at| now.saturating_duration_since(at) >= PUSH_EXPIRY)
            {
                session.they_initiate = false;
                stale = true;
            }
        }
        if stale {
            self.choose_target();
        }
        let peers: Vec<u32> = self.sessions.keys().copied().collect();
        let mut out = Vec::new();
        for peer in peers {
            if let Some(request) = self.request_for(peer, now, unix_now) {
                out.push((peer, request));
            }
        }
        out
    }

    fn request_for(
        &mut self,
        peer: u32,
        now: Instant,
        unix_now: (i64, i32),
    ) -> Option<SyncRouteRequest> {
        let initiator = self.target == Some(peer);
        let session = self.sessions.get(&peer)?;
        if !(initiator || session.they_initiate)
            || session.in_flight.is_some()
            || session.not_before.is_some_and(|at| now < at)
        {
            return None;
        }

        let mut pending = Sent::default();
        let mut infos = Vec::new();
        if session.sent.infos.get(&self.own.peer_id) != Some(&self.own.version) {
            let mut own = self.own.clone();
            own.last_update = unix_now;
            pending.infos.insert(own.peer_id, own.version);
            infos.push(own);
        }
        for (&id, stored) in &self.infos {
            let version = stored.info.version;
            if id == peer || session.sent.infos.get(&id).is_some_and(|&v| v >= version) {
                continue;
            }
            pending.infos.insert(id, version);
            infos.push(stored.info.clone());
        }

        let all_rows = || {
            std::iter::once((self.own.peer_id, &self.own_row))
                .chain(self.rows.iter().map(|(&id, row)| (id, row)))
        };
        let rows_changed =
            all_rows().any(|(id, row)| session.sent.rows.get(&id).is_none_or(|&v| v < row.version));
        let conn_graph = rows_changed.then(|| {
            let mut index: BTreeMap<u32, usize> = BTreeMap::new();
            let mut graph = ConnGraph::default();
            for (id, row) in all_rows() {
                index.insert(id, graph.peers.len());
                graph.peers.push((id, row.version));
                pending.rows.insert(id, row.version);
            }
            for (_, row) in all_rows() {
                for neighbour in &row.neighbours {
                    if graph.peers.len() >= MAX_GRAPH_NODES {
                        break;
                    }
                    if !index.contains_key(neighbour) {
                        index.insert(*neighbour, graph.peers.len());
                        graph.peers.push((*neighbour, 0));
                    }
                }
            }
            'edges: for (id, row) in all_rows() {
                let from = index[&id];
                for neighbour in &row.neighbours {
                    if graph.edges.len() >= MAX_GRAPH_EDGES {
                        break 'edges;
                    }
                    if let Some(&to) = index.get(neighbour) {
                        graph.edges.push((from, to));
                    }
                }
            }
            graph
        });

        let due = session
            .last_sent
            .is_none_or(|at| now.saturating_duration_since(at) >= REFRESH_INTERVAL);
        if infos.is_empty() && conn_graph.is_none() && !due {
            return None;
        }
        let request = SyncRouteRequest {
            my_peer_id: self.own.peer_id,
            my_session_id: session.mine,
            is_initiator: initiator,
            peer_infos: infos,
            conn_graph,
            foreign_network_infos: None,
        };
        let session = self.sessions.get_mut(&peer)?;
        session.in_flight = Some(pending);
        session.last_sent = Some(now);
        Some(request)
    }

    /// The outcome of the request last sent to `peer`: its response, or
    /// `None` when it failed or timed out.
    pub fn on_response(
        &mut self,
        peer: u32,
        response: Option<SyncRouteResponse>,
        rng: &dyn SecureRandom,
        now: Instant,
    ) -> Result<Option<Notice>, Unspecified> {
        let Some(session) = self.sessions.get_mut(&peer) else {
            return Ok(None);
        };
        let Some(pending) = session.in_flight.take() else {
            return Ok(None);
        };
        let failed = |session: &mut Session| {
            session.retry = (session.retry * 2).clamp(RETRY_MIN, RETRY_MAX);
            session.not_before = Some(now + session.retry);
        };
        let Some(response) = response else {
            failed(session);
            return Ok(None);
        };
        match response.error {
            Some(sync_error::STOPPED) => {
                session.mine = session_id(rng)?;
                session.theirs = None;
                session.forget_sent();
                failed(session);
                Ok(None)
            }
            Some(sync_error::DUPLICATE_PEER_ID) => {
                failed(session);
                Ok(Some(Notice::DuplicatePeerId))
            }
            _ => {
                session.retry = Duration::ZERO;
                session.not_before = None;
                if session
                    .theirs
                    .is_some_and(|theirs| theirs != response.session_id)
                {
                    session.forget_sent();
                } else {
                    session.sent.infos.extend(pending.infos);
                    session.sent.rows.extend(pending.rows);
                }
                session.theirs = Some(response.session_id);
                Ok(None)
            }
        }
    }

    /// A `SyncRouteInfo` request from the direct neighbour `peer`; returns
    /// the response to send.
    pub fn on_request(
        &mut self,
        peer: u32,
        request: SyncRouteRequest,
        now: Instant,
    ) -> SyncRouteResponse {
        let my_id = self.own.peer_id;
        let stopped = SyncRouteResponse {
            is_initiator: false,
            session_id: 0,
            error: Some(sync_error::STOPPED),
        };
        if request.my_peer_id != peer {
            return stopped;
        }
        let target = self.target;
        let Some(session) = self.sessions.get_mut(&peer) else {
            return stopped;
        };
        if session
            .theirs
            .is_some_and(|theirs| theirs != request.my_session_id)
        {
            session.forget_sent();
        }
        session.theirs = Some(request.my_session_id);
        let keep_ours = request.is_initiator && target == Some(peer) && my_id < peer;
        session.they_initiate = request.is_initiator && !keep_ours;
        if session.they_initiate {
            session.pushed_at = Some(now);
        }
        let mine = session.mine;
        let they_initiate = session.they_initiate;

        let mut changed = false;
        for info in request.peer_infos {
            changed |= self.merge_info(info, now);
        }
        if let Some(graph) = request.conn_graph {
            changed |= self.merge_graph(&graph);
        }
        if changed {
            self.rebuild();
        }
        // Chosen after the merge, so the NAT types just learned count.
        if they_initiate && target == Some(peer) {
            self.target = None;
        }
        self.choose_target();
        SyncRouteResponse {
            is_initiator: self.target == Some(peer),
            session_id: mine,
            error: None,
        }
    }

    fn merge_info(&mut self, info: RoutePeerInfo, now: Instant) -> bool {
        if info.peer_id == self.own.peer_id {
            // An older version is this node's own information from before a
            // restart, still on its way out of the network.
            if info.route_id != self.own.route_id && info.version >= self.own.version {
                self.conflicts.insert(info.peer_id);
            }
            return false;
        }
        if info.version == 0 {
            return false;
        }
        match self.infos.get(&info.peer_id) {
            Some(stored) if stored.info.version >= info.version => return false,
            None if self.infos.len() >= MAX_NODES => {
                // Full: only a node already unreachable makes room, the one
                // unreachable longest.
                let Some(oldest) = self
                    .unreachable_since
                    .iter()
                    .filter(|(id, _)| self.infos.contains_key(*id))
                    .min_by_key(|(_, since)| **since)
                    .map(|(id, _)| *id)
                else {
                    return false;
                };
                self.infos.remove(&oldest);
                self.rows.remove(&oldest);
                self.unreachable_since.remove(&oldest);
            }
            _ => {}
        }
        self.infos.insert(
            info.peer_id,
            Stored {
                info,
                received: now,
            },
        );
        true
    }

    fn merge_graph(&mut self, graph: &ConnGraph) -> bool {
        let mut adjacency: Vec<BTreeSet<u32>> = vec![BTreeSet::new(); graph.peers.len()];
        for &(from, to) in &graph.edges {
            if let (Some(row), Some(&(peer, _))) = (adjacency.get_mut(from), graph.peers.get(to)) {
                row.insert(peer);
            }
        }
        let mut changed = false;
        for (row, &(id, version)) in graph.peers.iter().enumerate() {
            if id == self.own.peer_id {
                continue;
            }
            let known = self.rows.get(&id).map(|row| row.version);
            if known.is_some_and(|known| known >= version) {
                continue;
            }
            if known.is_none() && self.rows.len() >= MAX_NODES {
                continue;
            }
            let neighbours = std::mem::take(&mut adjacency[row]);
            self.rows.insert(
                id,
                Row {
                    version,
                    neighbours,
                },
            );
            changed = true;
        }
        changed
    }

    /// Drops information that expired or whose node stayed unreachable
    /// (spec §12.3). Call it once a second.
    pub fn expire(&mut self, now: Instant) {
        let before = self.infos.len();
        self.infos
            .retain(|_, stored| now.saturating_duration_since(stored.received) < INFO_TTL);
        let mut removed = self.infos.len() != before;

        let reachable = self
            .topology
            .routes(self.own.peer_id, Metric::Hops, |_, _| None);
        let known: Vec<u32> = self.infos.keys().chain(self.rows.keys()).copied().collect();
        for id in known {
            if reachable.contains_key(&id) {
                self.unreachable_since.remove(&id);
                continue;
            }
            let since = *self.unreachable_since.entry(id).or_insert(now);
            if now.saturating_duration_since(since) >= UNREACHABLE_TTL {
                self.infos.remove(&id);
                self.rows.remove(&id);
                self.unreachable_since.remove(&id);
                removed = true;
            }
        }
        self.unreachable_since
            .retain(|id, _| self.infos.contains_key(id) || self.rows.contains_key(id));
        if removed {
            self.rebuild();
        }
    }

    fn rebuild(&mut self) {
        let mut topology = Topology::new();
        topology.set(
            self.own.peer_id,
            NodeEntry {
                neighbours: self.own_row.neighbours.clone(),
                cost: self.own.cost,
                avoid_relay: self.own.features.avoid_relay_data,
            },
        );
        for (&id, stored) in &self.infos {
            topology.set(
                id,
                NodeEntry {
                    neighbours: self
                        .rows
                        .get(&id)
                        .map(|row| row.neighbours.clone())
                        .unwrap_or_default(),
                    cost: stored.info.cost,
                    avoid_relay: stored.info.features.avoid_relay_data,
                },
            );
        }
        self.topology = topology;
        self.changed = true;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ring::rand::SystemRandom;

    fn info(id: u32, route_id: u64) -> RoutePeerInfo {
        RoutePeerInfo {
            peer_id: id,
            cost: 1,
            version: 1,
            route_id,
            ipv4: Some(std::net::Ipv4Addr::new(10, 144, 0, id as u8)),
            network_length: 24,
            ..RoutePeerInfo::default()
        }
    }

    fn node(id: u32, now: Instant) -> RouteSync {
        RouteSync::new(info(id, u64::from(id) * 1000), now)
    }

    /// Sends `request` over the wire format and answers it.
    fn deliver(
        from: &mut RouteSync,
        to: &mut RouteSync,
        request: SyncRouteRequest,
        now: Instant,
    ) -> SyncRouteResponse {
        let request = SyncRouteRequest::decode(&request.encode()).unwrap();
        let response = to.on_request(from.id(), request, now);
        let response = SyncRouteResponse::decode(&response.encode()).unwrap();
        from.on_response(to.id(), Some(response), &SystemRandom::new(), now)
            .unwrap();
        response
    }

    /// Runs one sync round between every pair in both directions.
    fn round(nodes: &mut [RouteSync], now: Instant) {
        for i in 0..nodes.len() {
            let requests = nodes[i].poll(now, (0, 0));
            for (peer, request) in requests {
                let j = nodes.iter().position(|n| n.id() == peer).unwrap();
                let (a, b) = if i < j {
                    let (left, right) = nodes.split_at_mut(j);
                    (&mut left[i], &mut right[0])
                } else {
                    let (left, right) = nodes.split_at_mut(i);
                    (&mut right[0], &mut left[j])
                };
                deliver(a, b, request, now);
            }
        }
    }

    fn connect(a: &mut RouteSync, b: &mut RouteSync) {
        let rng = SystemRandom::new();
        a.neighbour_up(b.id(), &rng).unwrap();
        b.neighbour_up(a.id(), &rng).unwrap();
    }

    #[test]
    fn two_neighbours_learn_each_other() {
        let now = Instant::now();
        let mut nodes = [node(1, now), node(2, now)];
        let (a, b) = nodes.split_at_mut(1);
        connect(&mut a[0], &mut b[0]);
        round(&mut nodes, now);
        round(&mut nodes, now);
        assert_eq!(nodes[0].info(2).map(|i| i.version), Some(1));
        assert_eq!(nodes[1].info(1).map(|i| i.version), Some(1));
        let routes = nodes[0].topology().routes(1, Metric::Hops, |_, _| None);
        assert_eq!(routes[&2].next_hop, 2);
    }

    #[test]
    fn simultaneous_initiators_settle_on_the_smaller_id() {
        let now = Instant::now();
        let mut nodes = [node(1, now), node(2, now)];
        let (a, b) = nodes.split_at_mut(1);
        connect(&mut a[0], &mut b[0]);
        assert_eq!(nodes[0].target(), Some(2));
        assert_eq!(nodes[1].target(), Some(1));
        round(&mut nodes, now);
        assert_eq!(nodes[0].target(), Some(2));
        assert_eq!(nodes[1].target(), None);
        // The other side still answers with its own changes, not as initiator.
        let later = now + REFRESH_INTERVAL;
        let requests = nodes[1].poll(later, (0, 0));
        assert_eq!(requests.len(), 1);
        assert!(!requests[0].1.is_initiator);
    }

    #[test]
    fn nothing_new_waits_for_the_refresh_interval() {
        let now = Instant::now();
        let mut nodes = [node(1, now), node(2, now)];
        let (a, b) = nodes.split_at_mut(1);
        connect(&mut a[0], &mut b[0]);
        round(&mut nodes, now);
        round(&mut nodes, now);
        assert!(nodes[0].poll(now + SYNC_INTERVAL, (0, 0)).is_empty());
        let refresh = nodes[0].poll(now + REFRESH_INTERVAL, (0, 0));
        assert_eq!(refresh.len(), 1);
        assert!(refresh[0].1.peer_infos.is_empty());
        assert!(refresh[0].1.conn_graph.is_none());
    }

    #[test]
    fn information_crosses_a_relay_unchanged() {
        let now = Instant::now();
        let mut nodes = [node(1, now), node(2, now), node(3, now)];
        {
            let (a, rest) = nodes.split_at_mut(1);
            let (b, c) = rest.split_at_mut(1);
            connect(&mut a[0], &mut b[0]);
            connect(&mut b[0], &mut c[0]);
        }
        for _ in 0..4 {
            round(&mut nodes, now);
        }
        let from_relay = nodes[0].info(3).expect("node 1 learns node 3").raw.clone();
        let at_relay = nodes[1].info(3).unwrap().raw.clone();
        assert_eq!(from_relay, at_relay);
        let routes = nodes[0].topology().routes(1, Metric::Hops, |_, _| None);
        assert_eq!(routes[&3].next_hop, 2);
        assert_eq!(routes[&3].hops, 2);
    }

    #[test]
    fn older_versions_are_ignored() {
        let now = Instant::now();
        let mut a = node(1, now);
        let mut b = node(2, now);
        connect(&mut a, &mut b);
        let newer = RoutePeerInfo {
            version: 5,
            ..info(9, 9)
        };
        let older = RoutePeerInfo {
            version: 4,
            hostname: Some("old".into()),
            ..info(9, 9)
        };
        for item in [newer, older] {
            let request = SyncRouteRequest {
                my_peer_id: 2,
                my_session_id: 7,
                is_initiator: true,
                peer_infos: vec![item],
                ..SyncRouteRequest::default()
            };
            a.on_request(2, request, now);
        }
        assert_eq!(a.info(9).unwrap().version, 5);
        assert_eq!(a.info(9).unwrap().hostname, None);
    }

    #[test]
    fn a_new_peer_session_gets_everything_again() {
        let now = Instant::now();
        let mut nodes = [node(1, now), node(2, now)];
        let (a, b) = nodes.split_at_mut(1);
        connect(&mut a[0], &mut b[0]);
        round(&mut nodes, now);
        round(&mut nodes, now);
        // Node 2 restarts its session: its next request carries a new ID.
        let request = SyncRouteRequest {
            my_peer_id: 2,
            my_session_id: 0xDEAD,
            is_initiator: false,
            ..SyncRouteRequest::default()
        };
        nodes[0].on_request(2, request, now);
        let full = nodes[0].poll(now, (0, 0));
        assert_eq!(full.len(), 1);
        assert!(full[0].1.peer_infos.iter().any(|i| i.peer_id == 1));
        assert!(full[0].1.conn_graph.is_some());
    }

    #[test]
    fn failures_back_off_and_stopped_resets_the_session() {
        let now = Instant::now();
        let rng = SystemRandom::new();
        let mut a = node(1, now);
        a.neighbour_up(2, &rng).unwrap();
        assert_eq!(a.poll(now, (0, 0)).len(), 1);
        a.on_response(2, None, &rng, now).unwrap();
        assert!(a.poll(now + Duration::from_millis(49), (0, 0)).is_empty());
        let retry_at = now + RETRY_MIN;
        let first = a.poll(retry_at, (0, 0));
        assert_eq!(first.len(), 1);
        let session = first[0].1.my_session_id;
        let stopped = SyncRouteResponse {
            error: Some(sync_error::STOPPED),
            ..SyncRouteResponse::default()
        };
        a.on_response(2, Some(stopped), &rng, retry_at).unwrap();
        let again = a.poll(retry_at + RETRY_MIN * 2, (0, 0));
        assert_eq!(again.len(), 1);
        assert_ne!(again[0].1.my_session_id, session);
        assert!(again[0].1.peer_infos.iter().any(|i| i.peer_id == 1));
    }

    #[test]
    fn a_duplicate_id_is_reported() {
        let now = Instant::now();
        let rng = SystemRandom::new();
        let mut a = node(1, now);
        a.neighbour_up(2, &rng).unwrap();
        a.poll(now, (0, 0));
        let duplicate = SyncRouteResponse {
            error: Some(sync_error::DUPLICATE_PEER_ID),
            ..SyncRouteResponse::default()
        };
        assert_eq!(
            a.on_response(2, Some(duplicate), &rng, now).unwrap(),
            Some(Notice::DuplicatePeerId)
        );
        let mut b = node(2, now);
        b.neighbour_up(3, &rng).unwrap();
        let foreign = SyncRouteRequest {
            my_peer_id: 3,
            my_session_id: 1,
            peer_infos: vec![info(2, 777)],
            ..SyncRouteRequest::default()
        };
        b.on_request(3, foreign, now);
        assert!(b.conflicts().contains(&2));
    }

    #[test]
    fn requests_from_non_neighbours_are_stopped() {
        let now = Instant::now();
        let mut a = node(1, now);
        let request = SyncRouteRequest {
            my_peer_id: 5,
            my_session_id: 1,
            peer_infos: vec![info(5, 5)],
            ..SyncRouteRequest::default()
        };
        let response = a.on_request(5, request, now);
        assert_eq!(response.error, Some(sync_error::STOPPED));
        assert!(a.info(5).is_none());
    }

    #[test]
    fn unreachable_nodes_are_removed_after_the_grace_period() {
        let now = Instant::now();
        let mut nodes = [node(1, now), node(2, now), node(3, now)];
        {
            let (a, rest) = nodes.split_at_mut(1);
            let (b, c) = rest.split_at_mut(1);
            connect(&mut a[0], &mut b[0]);
            connect(&mut b[0], &mut c[0]);
        }
        for _ in 0..4 {
            round(&mut nodes, now);
        }
        assert!(nodes[0].info(3).is_some());
        nodes[0].neighbour_down(2);
        nodes[0].expire(now);
        assert!(nodes[0].info(3).is_some());
        nodes[0].expire(now + UNREACHABLE_TTL);
        assert!(nodes[0].info(3).is_none());
        assert!(nodes[0].info(2).is_none());
    }

    #[test]
    fn own_information_gets_a_new_version_on_change_and_hourly() {
        let now = Instant::now();
        let mut a = node(1, now);
        a.set_own(info(1, 1000), now);
        assert_eq!(a.own().version, 1);
        let renamed = RoutePeerInfo {
            hostname: Some("office".into()),
            ..info(1, 1000)
        };
        a.set_own(renamed, now);
        assert_eq!(a.own().version, 2);
        a.poll(now + OWN_REFRESH, (0, 0));
        assert_eq!(a.own().version, 3);
    }

    #[test]
    fn the_target_prefers_a_neighbour_without_port_translation() {
        let now = Instant::now();
        let rng = SystemRandom::new();
        let mut a = node(5, now);
        a.neighbour_up(3, &rng).unwrap();
        a.neighbour_up(4, &rng).unwrap();
        a.neighbour_up(9, &rng).unwrap();
        assert_eq!(a.target(), Some(3));
        // Node 3 starts pushing to this node, so a new target is chosen; node
        // 9 turns out to be on the open Internet and wins over node 4.
        let open = RoutePeerInfo {
            udp_nat: 1,
            ..info(9, 9)
        };
        let request = SyncRouteRequest {
            my_peer_id: 3,
            my_session_id: 1,
            is_initiator: true,
            peer_infos: vec![open],
            ..SyncRouteRequest::default()
        };
        a.on_request(3, request, now);
        assert_eq!(a.target(), Some(9));
    }

    #[test]
    fn old_own_information_after_a_restart_is_no_conflict() {
        let now = Instant::now();
        let rng = SystemRandom::new();
        let mut a = RouteSync::new(
            RoutePeerInfo {
                version: 200,
                ..info(1, 1)
            },
            now,
        );
        a.neighbour_up(2, &rng).unwrap();
        let old = RoutePeerInfo {
            version: 100,
            ..info(1, 555)
        };
        let request = SyncRouteRequest {
            my_peer_id: 2,
            my_session_id: 1,
            peer_infos: vec![old],
            ..SyncRouteRequest::default()
        };
        a.on_request(2, request, now);
        assert!(a.conflicts().is_empty());
    }

    #[test]
    fn a_neighbour_that_stops_pushing_becomes_a_target_again() {
        let now = Instant::now();
        let rng = SystemRandom::new();
        let mut a = node(5, now);
        a.neighbour_up(3, &rng).unwrap();
        let push = SyncRouteRequest {
            my_peer_id: 3,
            my_session_id: 1,
            is_initiator: true,
            ..SyncRouteRequest::default()
        };
        a.on_request(3, push, now);
        assert_eq!(a.target(), None);
        a.poll(now + PUSH_EXPIRY, (0, 0));
        assert_eq!(a.target(), Some(3));
    }

    #[test]
    fn a_full_table_makes_room_only_from_unreachable_nodes() {
        let now = Instant::now();
        let rng = SystemRandom::new();
        let mut a = node(1, now);
        a.neighbour_up(2, &rng).unwrap();
        let fill = SyncRouteRequest {
            my_peer_id: 2,
            my_session_id: 1,
            peer_infos: (0..MAX_NODES as u32).map(|n| info(10_000 + n, 1)).collect(),
            ..SyncRouteRequest::default()
        };
        a.on_request(2, fill, now);
        assert_eq!(a.infos().count(), MAX_NODES);
        let late = SyncRouteRequest {
            my_peer_id: 2,
            my_session_id: 1,
            peer_infos: vec![info(99_999, 1)],
            ..SyncRouteRequest::default()
        };
        // Every stored node is unreachable (no connection rows), but none
        // for long yet: once marked, the longest unreachable makes room.
        a.on_request(2, late.clone(), now);
        assert!(a.info(99_999).is_none());
        a.expire(now);
        a.on_request(2, late, now);
        assert!(a.info(99_999).is_some());
        assert_eq!(a.infos().count(), MAX_NODES);
    }
}
