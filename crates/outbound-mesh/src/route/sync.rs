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
//! Who pushes (spec §12.2): every direct link on its own. This node is the
//! initiator towards neighbour X when its node ID is smaller than X's, or
//! when X has not pushed to it as the initiator in the last 30 seconds, so
//! every link has at least one side pushing. It sends its own changes to
//! every neighbour either way, marked as not the initiator when it is not.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
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
/// counts as pushing; a connection must also be up this long before the
/// node with the greater ID starts pushing on it (spec §12.2).
pub const PUSH_EXPIRY: Duration = Duration::from_secs(30);
/// A full table makes room only from nodes unreachable at least this long,
/// so that a new node is not pushed out before its connection row arrives.
pub const EVICTION_GRACE: Duration = Duration::from_secs(5);
/// One request encoded is at most this long: the RPC send limit
/// (spec §11.2, §12.2). Node information that does not fit goes in the
/// next batches.
pub const MAX_REQUEST_BYTES: usize = 4 * 1024 * 1024;
/// Room kept in every batch for the headers (spec §12.2).
const REQUEST_RESERVE: usize = 64 * 1024;
/// A connection graph sent is at most this long, about 2.1 MiB: the
/// bitmap of the largest graph and its node list (spec §12.4). Past it the
/// farthest rows are cut.
pub const MAX_GRAPH_BYTES: usize = 2 * 1024 * 1024 + 100 * 1024;
/// Encoded node information one request carries at most, without a graph.
pub const REQUEST_INFO_BYTES: usize = MAX_REQUEST_BYTES - REQUEST_RESERVE;

/// Encoded node information all stored entries may take together
/// (spec §12.3). Past it, information of new nodes is refused; updates of
/// stored ones are still taken.
pub const MAX_STORED_INFO_BYTES: usize = 16 * 1024 * 1024;

/// Something the driver must act on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Notice {
    /// The neighbour answered that this node's ID is already in use
    /// (spec §12.1 error 0).
    DuplicatePeerId,
}

/// What the synchronisation refused, for the status (spec §12.3, §12.4).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Refused {
    /// Node information over a limit or malformed.
    pub infos: u64,
    /// Information of new nodes past [`MAX_STORED_INFO_BYTES`].
    pub over_budget: u64,
    /// Connection graphs over the limits or malformed.
    pub graphs: u64,
    /// Connection rows past [`MAX_GRAPH_EDGES`] stored edges.
    pub rows: u64,
    /// Connection graphs sent cut short to fit one request (spec §12.4).
    pub cut_graphs: u64,
    /// Node information whose own static key is off the native key list
    /// (spec §8.3.1 rule 4).
    pub not_native: u64,
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
    /// When the connection came up.
    since: Instant,
    /// When the neighbour last asked as the initiator.
    pushed_at: Option<Instant>,
    mine: u64,
    theirs: Option<u64>,
    sent: Sent,
    in_flight: Option<Sent>,
    last_sent: Option<Instant>,
    retry: Duration,
    not_before: Option<Instant>,
}

impl Session {
    fn new(mine: u64, since: Instant) -> Self {
        Self {
            since,
            pushed_at: None,
            mine,
            theirs: None,
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

/// The bytes a stored information takes: as received, or as encoded.
fn info_size(info: &RoutePeerInfo) -> usize {
    if info.raw.is_empty() {
        info.encode().len()
    } else {
        info.raw.len()
    }
}

fn session_id(rng: &dyn SecureRandom) -> Result<u64, Unspecified> {
    let mut bytes = [0u8; 8];
    rng.fill(&mut bytes)?;
    Ok(u64::from_le_bytes(bytes))
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
    topology: Topology,
    changed: bool,
    /// Another node holds this node's ID, or the version ran out: a new
    /// ID is needed (spec §12.3).
    conflict: bool,
    /// Encoded bytes of all stored information.
    stored_bytes: usize,
    refused: Refused,
    /// See [`RouteSync::set_admitted`].
    admitted: Option<Vec<[u8; 32]>>,
}

impl RouteSync {
    /// `own` is this node's information; its version starts at 1 (spec
    /// §12.3: node and route IDs are new at every start, so nothing older
    /// under them exists).
    pub fn new(mut own: RoutePeerInfo, now: Instant) -> Self {
        own.version = 1;
        own.raw.clear();
        let mut sync = Self {
            own_row: Row {
                version: 1,
                neighbours: BTreeSet::new(),
            },
            own,
            own_updated: now,
            infos: BTreeMap::new(),
            rows: BTreeMap::new(),
            unreachable_since: BTreeMap::new(),
            sessions: BTreeMap::new(),
            topology: Topology::new(),
            changed: false,
            conflict: false,
            stored_bytes: 0,
            refused: Refused::default(),
            admitted: None,
        };
        sync.rebuild();
        sync
    }

    pub fn id(&self) -> u32 {
        self.own.peer_id
    }

    /// `Some` in a managed network: information of other nodes is taken,
    /// used and passed on only when its own static key (field 18) is on
    /// this list (spec §8.3.1 rule 4). Stored information off a new list
    /// goes at once.
    pub fn set_admitted(&mut self, keys: Option<Vec<[u8; 32]>>) {
        self.admitted = keys;
        let refused: Vec<u32> = self
            .infos
            .iter()
            .filter(|(_, stored)| !self.admits(&stored.info))
            .map(|(&id, _)| id)
            .collect();
        if !refused.is_empty() {
            for id in refused {
                self.remove_node(id);
            }
            self.rebuild();
        }
    }

    fn admits(&self, info: &RoutePeerInfo) -> bool {
        self.admitted.as_ref().is_none_or(|keys| {
            <[u8; 32]>::try_from(&info.noise_pubkey[..]).is_ok_and(|key| keys.contains(&key))
        })
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
        let version = self.next_own_version();
        self.own = RoutePeerInfo {
            version,
            raw: Vec::new(),
            ..info
        };
        self.own_updated = now;
        self.rebuild();
    }

    /// The next own version: it never wraps; reaching the top counts as a
    /// restart, which needs new node and route IDs (spec §12.3).
    fn next_own_version(&mut self) -> u32 {
        let next = self.own.version.saturating_add(1);
        if next == u32::MAX {
            self.conflict = true;
        }
        next
    }

    /// Whether this node pushes to `peer` as the initiator (spec §12.2):
    /// the smaller ID does; the greater one only once the connection is up
    /// [`PUSH_EXPIRY`] and the neighbour has not pushed for as long.
    pub fn initiates(&self, peer: u32, now: Instant) -> bool {
        self.id() < peer
            || self.sessions.get(&peer).is_some_and(|session| {
                now.saturating_duration_since(session.since) >= PUSH_EXPIRY
                    && session
                        .pushed_at
                        .is_none_or(|at| now.saturating_duration_since(at) >= PUSH_EXPIRY)
            })
    }

    /// What was refused so far.
    pub fn refused(&self) -> Refused {
        self.refused
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

    /// True once after another node was seen holding this node's ID with
    /// a newer version, or this node's version ran out (spec §12.3): the
    /// node needs a new ID.
    pub fn take_conflict(&mut self) -> bool {
        std::mem::take(&mut self.conflict)
    }

    /// True once after the topology or the stored information changed.
    pub fn take_changed(&mut self) -> bool {
        std::mem::take(&mut self.changed)
    }

    /// A first connection to `peer` came up.
    pub fn neighbour_up(
        &mut self,
        peer: u32,
        rng: &dyn SecureRandom,
        now: Instant,
    ) -> Result<(), Unspecified> {
        if peer == self.id() || self.sessions.contains_key(&peer) {
            return Ok(());
        }
        self.sessions
            .insert(peer, Session::new(session_id(rng)?, now));
        if self.own_row.neighbours.insert(peer) {
            self.own_row.version = self.own_row.version.saturating_add(1);
        }
        self.rebuild();
        Ok(())
    }

    /// The last connection to `peer` went down.
    pub fn neighbour_down(&mut self, peer: u32) {
        self.sessions.remove(&peer);
        if self.own_row.neighbours.remove(&peer) {
            self.own_row.version = self.own_row.version.saturating_add(1);
        }
        self.rebuild();
    }

    /// The requests to send now, one per neighbour at most. `unix_now` is
    /// the wall-clock time put in this node's information (spec §12.3).
    pub fn poll(&mut self, now: Instant, unix_now: (i64, i32)) -> Vec<(u32, SyncRouteRequest)> {
        if now.saturating_duration_since(self.own_updated) >= OWN_REFRESH {
            self.own.version = self.next_own_version();
            self.own_updated = now;
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
        let initiator = self.initiates(peer, now);
        let session = self.sessions.get(&peer)?;
        if session.in_flight.is_some() || session.not_before.is_some_and(|at| now < at) {
            return None;
        }

        let mut pending = Sent::default();

        // Nearest first, so that a cut drops the farthest rows (spec §12.4).
        let hops = self.hops();
        let mut ordered: Vec<(u32, &Row)> = std::iter::once((self.own.peer_id, &self.own_row))
            .chain(self.rows.iter().map(|(&id, row)| (id, row)))
            .collect();
        ordered.sort_by_key(|(id, _)| (hops.get(id).copied().unwrap_or(u32::MAX), *id));
        let rows_changed = ordered
            .iter()
            .any(|(id, row)| session.sent.rows.get(id).is_none_or(|&v| v < row.version));
        let mut cut = false;
        let conn_graph = rows_changed.then(|| {
            let kept = graph_rows(&ordered, MAX_GRAPH_BYTES);
            cut = kept < ordered.len();
            // Rows cut are taken as sent: they would not fit the next time
            // either, and must not make every round send the graph.
            for (id, row) in &ordered {
                pending.rows.insert(*id, row.version);
            }
            build_graph(&ordered[..kept])
        });
        let graph_bytes = conn_graph
            .as_ref()
            .map_or(0, |graph| graph.encode_bitmap().len());

        let mut infos = Vec::new();
        let mut info_bytes = 0;
        if session.sent.infos.get(&self.own.peer_id) != Some(&self.own.version) {
            let mut own = self.own.clone();
            own.last_update = unix_now;
            pending.infos.insert(own.peer_id, own.version);
            info_bytes += own.encode().len();
            infos.push(own);
        }
        let info_budget = REQUEST_INFO_BYTES.saturating_sub(graph_bytes);
        for (&id, stored) in &self.infos {
            let version = stored.info.version;
            if id == peer || session.sent.infos.get(&id).is_some_and(|&v| v >= version) {
                continue;
            }
            // What does not fit is not marked as sent and goes next time.
            let size = stored.info.encode().len();
            if info_bytes + size > info_budget {
                break;
            }
            info_bytes += size;
            pending.infos.insert(id, version);
            infos.push(stored.info.clone());
        }

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
            ..SyncRouteRequest::default()
        };
        let session = self.sessions.get_mut(&peer)?;
        session.in_flight = Some(pending);
        session.last_sent = Some(now);
        if cut {
            self.refused.cut_graphs += 1;
        }
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
        let stopped = SyncRouteResponse {
            is_initiator: false,
            session_id: 0,
            error: Some(sync_error::STOPPED),
        };
        if request.my_peer_id != peer || !self.sessions.contains_key(&peer) {
            return stopped;
        }
        // Rule 2 of spec §12.3: the neighbour's own information with
        // another route ID and an older version than stored is a node
        // reusing its ID.
        let reused = request.peer_infos.iter().any(|info| {
            info.peer_id == peer
                && self.infos.get(&peer).is_some_and(|stored| {
                    stored.info.route_id != info.route_id && info.version < stored.info.version
                })
        });
        if reused {
            return SyncRouteResponse {
                is_initiator: false,
                session_id: 0,
                error: Some(sync_error::DUPLICATE_PEER_ID),
            };
        }
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
        if request.is_initiator {
            session.pushed_at = Some(now);
        }
        let mine = session.mine;

        self.refused.infos += u64::from(request.skipped_infos);
        if request.graph_dropped {
            self.refused.graphs += 1;
        }
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
        SyncRouteResponse {
            is_initiator: self.initiates(peer, now),
            session_id: mine,
            error: None,
        }
    }

    fn merge_info(&mut self, info: RoutePeerInfo, now: Instant) -> bool {
        if info.peer_id == self.own.peer_id {
            // Rule 1 of spec §12.3: only a newer version with another route
            // ID means another node holds this ID.
            if info.route_id != self.own.route_id && info.version > self.own.version {
                self.conflict = true;
            }
            return false;
        }
        if info.version == 0 {
            return false;
        }
        if !self.admits(&info) {
            self.refused.not_native += 1;
            return false;
        }
        let size = info_size(&info);
        match self.infos.get(&info.peer_id) {
            Some(stored) if stored.info.version >= info.version => return false,
            None if self.stored_bytes + size > MAX_STORED_INFO_BYTES => {
                self.refused.over_budget += 1;
                return false;
            }
            None if self.infos.len() >= MAX_NODES => {
                // Full: a node unreachable for a while makes room, the one
                // unreachable longest. A direct neighbour's information is
                // always taken: then the farthest other node goes.
                let unreachable = self
                    .unreachable_since
                    .iter()
                    .filter(|(id, since)| {
                        self.infos.contains_key(*id)
                            && now.saturating_duration_since(**since) >= EVICTION_GRACE
                    })
                    .min_by_key(|(_, since)| **since)
                    .map(|(id, _)| *id);
                let victim = match unreachable {
                    Some(id) => id,
                    None if self.sessions.contains_key(&info.peer_id) => {
                        match self.farthest_non_neighbour() {
                            Some(id) => id,
                            None => return false,
                        }
                    }
                    None => return false,
                };
                self.remove_node(victim);
            }
            _ => {}
        }
        if let Some(old) = self.infos.insert(
            info.peer_id,
            Stored {
                info,
                received: now,
            },
        ) {
            self.stored_bytes -= info_size(&old.info);
        }
        self.stored_bytes += size;
        true
    }

    fn remove_node(&mut self, id: u32) {
        if let Some(old) = self.infos.remove(&id) {
            self.stored_bytes -= info_size(&old.info);
        }
        self.rows.remove(&id);
        self.unreachable_since.remove(&id);
    }

    /// The stored node farthest from this one by hops (unreachable ones
    /// farthest of all) that is not a direct neighbour.
    fn farthest_non_neighbour(&self) -> Option<u32> {
        let hops = self.hops();
        self.infos
            .keys()
            .filter(|id| !self.sessions.contains_key(*id))
            .max_by_key(|id| (hops.get(*id).copied().unwrap_or(u32::MAX), **id))
            .copied()
    }

    /// Hops from this node to every node the connection rows reach.
    fn hops(&self) -> BTreeMap<u32, u32> {
        let mut hops: BTreeMap<u32, u32> = BTreeMap::new();
        let mut queue = VecDeque::new();
        hops.insert(self.own.peer_id, 0);
        queue.push_back(self.own.peer_id);
        while let Some(id) = queue.pop_front() {
            let distance = hops[&id];
            let neighbours = if id == self.own.peer_id {
                Some(&self.own_row.neighbours)
            } else {
                self.rows.get(&id).map(|row| &row.neighbours)
            };
            for &next in neighbours.into_iter().flatten() {
                if let std::collections::btree_map::Entry::Vacant(entry) = hops.entry(next) {
                    entry.insert(distance + 1);
                    queue.push_back(next);
                }
            }
        }
        hops
    }

    fn merge_graph(&mut self, graph: &ConnGraph) -> bool {
        let mut adjacency: Vec<BTreeSet<u32>> = vec![BTreeSet::new(); graph.peers.len()];
        for &(from, to) in &graph.edges {
            if let (Some(row), Some(&(peer, _))) = (adjacency.get_mut(from), graph.peers.get(to)) {
                row.insert(peer);
            }
        }
        let mut changed = false;
        let mut edges: usize = self.rows.values().map(|row| row.neighbours.len()).sum();
        for (row, &(id, version)) in graph.peers.iter().enumerate() {
            // Placeholder rows (version 0) are not kept (spec §12.4).
            if id == self.own.peer_id || version == 0 {
                continue;
            }
            let known = self.rows.get(&id);
            if known.is_some_and(|known| known.version >= version) {
                continue;
            }
            if known.is_none() && self.rows.len() >= MAX_NODES {
                continue;
            }
            let replaced = known.map_or(0, |known| known.neighbours.len());
            if edges - replaced + adjacency[row].len() > MAX_GRAPH_EDGES {
                self.refused.rows += 1;
                continue;
            }
            edges = edges - replaced + adjacency[row].len();
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
        let expired: Vec<u32> = self
            .infos
            .iter()
            .filter(|(_, stored)| now.saturating_duration_since(stored.received) >= INFO_TTL)
            .map(|(&id, _)| id)
            .collect();
        let mut removed = !expired.is_empty();
        for id in expired {
            if let Some(old) = self.infos.remove(&id) {
                self.stored_bytes -= info_size(&old.info);
            }
        }

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
                self.remove_node(id);
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

/// The longest encoded connection graph of `n` nodes, by the bitmap form:
/// each node item at most 14 bytes, the bitmap `n²` bits, and the field
/// headers.
fn graph_bound(n: usize) -> usize {
    n * 14 + (n * n).div_ceil(8) + 16
}

/// How many of the `ordered` rows a connection graph of at most `budget`
/// bytes, [`MAX_GRAPH_NODES`] nodes and [`MAX_GRAPH_EDGES`] edges holds,
/// counting the placeholder nodes their neighbours add.
fn graph_rows(ordered: &[(u32, &Row)], budget: usize) -> usize {
    let mut nodes: BTreeSet<u32> = BTreeSet::new();
    let mut edges = 0usize;
    for (kept, (id, row)) in ordered.iter().enumerate() {
        let added = std::iter::once(id)
            .chain(&row.neighbours)
            .collect::<BTreeSet<_>>()
            .into_iter()
            .filter(|node| !nodes.contains(node))
            .count();
        let total = nodes.len() + added;
        let edges_after = edges + row.neighbours.len();
        if total > MAX_GRAPH_NODES || edges_after > MAX_GRAPH_EDGES || graph_bound(total) > budget {
            return kept;
        }
        nodes.insert(*id);
        nodes.extend(row.neighbours.iter().copied());
        edges = edges_after;
    }
    ordered.len()
}

/// The connection graph of `rows`: one row each, then a version-0
/// placeholder for each neighbour without a row (spec §12.4).
fn build_graph(rows: &[(u32, &Row)]) -> ConnGraph {
    let mut index: BTreeMap<u32, usize> = BTreeMap::new();
    let mut graph = ConnGraph::default();
    for (id, row) in rows {
        index.insert(*id, graph.peers.len());
        graph.peers.push((*id, row.version));
    }
    for (_, row) in rows {
        for neighbour in &row.neighbours {
            if !index.contains_key(neighbour) {
                index.insert(*neighbour, graph.peers.len());
                graph.peers.push((*neighbour, 0));
            }
        }
    }
    for (id, row) in rows {
        let from = index[id];
        for neighbour in &row.neighbours {
            graph.edges.push((from, index[neighbour]));
        }
    }
    graph
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

    fn connect(a: &mut RouteSync, b: &mut RouteSync, now: Instant) {
        let rng = SystemRandom::new();
        a.neighbour_up(b.id(), &rng, now).unwrap();
        b.neighbour_up(a.id(), &rng, now).unwrap();
    }

    #[test]
    fn two_neighbours_learn_each_other() {
        let now = Instant::now();
        let mut nodes = [node(1, now), node(2, now)];
        let (a, b) = nodes.split_at_mut(1);
        connect(&mut a[0], &mut b[0], now);
        round(&mut nodes, now);
        round(&mut nodes, now);
        assert_eq!(nodes[0].info(2).map(|i| i.version), Some(1));
        assert_eq!(nodes[1].info(1).map(|i| i.version), Some(1));
        let routes = nodes[0].topology().routes(1, Metric::Hops, |_, _| None);
        assert_eq!(routes[&2].next_hop, 2);
    }

    #[test]
    fn information_off_the_native_key_list_is_refused_and_counted() {
        let now = Instant::now();
        let mut nodes = [node(1, now), node(2, now)];
        let (a, b) = nodes.split_at_mut(1);
        connect(&mut a[0], &mut b[0], now);
        let a = &mut nodes[0];
        a.set_admitted(Some(vec![[2; 32], [3; 32]]));
        let keyed = |id: u32, key: [u8; 32]| RoutePeerInfo {
            noise_pubkey: key.to_vec(),
            ..info(id, u64::from(id) * 1000)
        };
        let request = SyncRouteRequest {
            my_peer_id: 2,
            my_session_id: 1,
            peer_infos: vec![keyed(2, [2; 32]), keyed(3, [3; 32]), keyed(4, [4; 32])],
            ..SyncRouteRequest::default()
        };
        a.on_request(2, request, now);
        assert!(a.info(2).is_some());
        assert!(a.info(3).is_some());
        assert!(a.info(4).is_none());
        assert_eq!(a.refused().not_native, 1);
        // Taking a key off the list removes what was stored under it.
        a.set_admitted(Some(vec![[2; 32]]));
        assert!(a.info(3).is_none());
        assert!(a.info(2).is_some());
    }

    #[test]
    fn simultaneous_initiators_settle_on_the_smaller_id() {
        let now = Instant::now();
        let mut nodes = [node(1, now), node(2, now)];
        let (a, b) = nodes.split_at_mut(1);
        connect(&mut a[0], &mut b[0], now);
        // At first only the smaller ID pushes; the greater one would after
        // 30 seconds without being pushed to.
        assert!(nodes[0].initiates(2, now));
        assert!(!nodes[1].initiates(1, now));
        assert!(nodes[1].initiates(1, now + PUSH_EXPIRY));
        round(&mut nodes, now + PUSH_EXPIRY);
        assert!(nodes[0].initiates(2, now + PUSH_EXPIRY));
        assert!(!nodes[1].initiates(1, now + PUSH_EXPIRY));
        // The other side still answers with its own changes, not as initiator.
        let later = now + PUSH_EXPIRY + REFRESH_INTERVAL;
        let requests = nodes[1].poll(later, (0, 0));
        assert_eq!(requests.len(), 1);
        assert!(!requests[0].1.is_initiator);
    }

    #[test]
    fn nothing_new_waits_for_the_refresh_interval() {
        let now = Instant::now();
        let mut nodes = [node(1, now), node(2, now)];
        let (a, b) = nodes.split_at_mut(1);
        connect(&mut a[0], &mut b[0], now);
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
            connect(&mut a[0], &mut b[0], now);
            connect(&mut b[0], &mut c[0], now);
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
        connect(&mut a, &mut b, now);
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
        connect(&mut a[0], &mut b[0], now);
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
        a.neighbour_up(2, &rng, now).unwrap();
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
        a.neighbour_up(2, &rng, now).unwrap();
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
        b.neighbour_up(3, &rng, now).unwrap();
        let foreign = SyncRouteRequest {
            my_peer_id: 3,
            my_session_id: 1,
            peer_infos: vec![info(2, 777)],
            ..SyncRouteRequest::default()
        };
        // Another node's information under this ID, but not newer: no
        // conflict (rule 1 needs a strictly greater version).
        b.on_request(3, foreign, now);
        assert!(!b.take_conflict());
        let newer = SyncRouteRequest {
            my_peer_id: 3,
            my_session_id: 1,
            peer_infos: vec![RoutePeerInfo {
                version: 2,
                ..info(2, 777)
            }],
            ..SyncRouteRequest::default()
        };
        b.on_request(3, newer, now);
        assert!(b.take_conflict());
        assert!(!b.take_conflict());
    }

    #[test]
    fn a_neighbour_reusing_an_id_gets_error_zero() {
        let now = Instant::now();
        let rng = SystemRandom::new();
        let mut a = node(1, now);
        a.neighbour_up(2, &rng, now).unwrap();
        let first = SyncRouteRequest {
            my_peer_id: 2,
            my_session_id: 1,
            peer_infos: vec![RoutePeerInfo {
                version: 5,
                ..info(2, 222)
            }],
            ..SyncRouteRequest::default()
        };
        assert_eq!(a.on_request(2, first, now).error, None);
        // The neighbour's own information, another route ID, older version.
        let reused = SyncRouteRequest {
            my_peer_id: 2,
            my_session_id: 1,
            peer_infos: vec![RoutePeerInfo {
                version: 3,
                ..info(2, 333)
            }],
            ..SyncRouteRequest::default()
        };
        let response = a.on_request(2, reused, now);
        assert_eq!(response.error, Some(sync_error::DUPLICATE_PEER_ID));
        assert_eq!(a.info(2).unwrap().route_id, 222);
        // The same route ID with an older version is only stale.
        let stale = SyncRouteRequest {
            my_peer_id: 2,
            my_session_id: 1,
            peer_infos: vec![RoutePeerInfo {
                version: 4,
                ..info(2, 222)
            }],
            ..SyncRouteRequest::default()
        };
        assert_eq!(a.on_request(2, stale, now).error, None);
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
            connect(&mut a[0], &mut b[0], now);
            connect(&mut b[0], &mut c[0], now);
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
    fn own_versions_start_at_one_and_saturate() {
        let now = Instant::now();
        let mut a = RouteSync::new(
            RoutePeerInfo {
                version: 200,
                ..info(1, 1)
            },
            now,
        );
        assert_eq!(a.own().version, 1);
        a.own.version = u32::MAX - 2;
        a.poll(now + OWN_REFRESH, (0, 0));
        assert_eq!(a.own().version, u32::MAX - 1);
        assert!(!a.take_conflict());
        a.poll(now + OWN_REFRESH * 2, (0, 0));
        assert_eq!(a.own().version, u32::MAX);
        assert!(a.take_conflict());
        a.poll(now + OWN_REFRESH * 3, (0, 0));
        assert_eq!(a.own().version, u32::MAX);
    }

    #[test]
    fn older_own_information_under_another_route_id_is_no_conflict() {
        let now = Instant::now();
        let rng = SystemRandom::new();
        let mut a = node(1, now);
        a.set_own(
            RoutePeerInfo {
                hostname: Some("a".into()),
                ..info(1, 1000)
            },
            now,
        );
        assert_eq!(a.own().version, 2);
        a.neighbour_up(2, &rng, now).unwrap();
        let old = SyncRouteRequest {
            my_peer_id: 2,
            my_session_id: 1,
            peer_infos: vec![info(1, 555)],
            ..SyncRouteRequest::default()
        };
        a.on_request(2, old, now);
        assert!(!a.take_conflict());
    }

    #[test]
    fn every_neighbour_is_pushed_to() {
        let now = Instant::now();
        let rng = SystemRandom::new();
        let mut a = node(5, now);
        for peer in [3, 4, 9] {
            a.neighbour_up(peer, &rng, now).unwrap();
        }
        let initiator = |at: Instant| -> Vec<bool> {
            [3, 4, 9]
                .iter()
                .map(|&peer| a.initiates(peer, at))
                .collect()
        };
        assert_eq!(initiator(now), vec![false, false, true]);
        // Nobody pushed to this node for 30 seconds: it pushes to all.
        assert_eq!(initiator(now + PUSH_EXPIRY), vec![true, true, true]);
    }

    #[test]
    fn a_neighbour_that_stops_pushing_is_pushed_to_again() {
        let now = Instant::now();
        let rng = SystemRandom::new();
        let mut a = node(5, now);
        a.neighbour_up(3, &rng, now).unwrap();
        let push = SyncRouteRequest {
            my_peer_id: 3,
            my_session_id: 1,
            is_initiator: true,
            ..SyncRouteRequest::default()
        };
        let response = a.on_request(3, push, now);
        assert!(!response.is_initiator);
        assert!(!a.initiates(3, now));
        assert!(a.initiates(3, now + PUSH_EXPIRY));
    }

    #[test]
    fn two_triangles_joined_by_one_link_learn_everything() {
        let now = Instant::now();
        let mut nodes: Vec<RouteSync> = (1..=6).map(|id| node(id, now)).collect();
        let links = [(1, 2), (2, 3), (1, 3), (4, 5), (5, 6), (4, 6), (3, 6)];
        for (x, y) in links {
            let (left, right) = nodes.split_at_mut(y as usize - 1);
            connect(&mut left[x as usize - 1], &mut right[0], now);
        }
        for _ in 0..8 {
            round(&mut nodes, now);
        }
        for node in &nodes {
            assert_eq!(node.infos().count(), 5, "node {}", node.id());
            let routes = node.topology().routes(node.id(), Metric::Hops, |_, _| None);
            assert_eq!(routes.len(), 5, "node {}", node.id());
        }
    }

    #[test]
    fn a_large_graph_goes_whole_in_the_first_batch_only() {
        let now = Instant::now();
        let rng = SystemRandom::new();
        let mut a = node(1, now);
        a.neighbour_up(2, &rng, now).unwrap();
        // A chain 2 - 10000 - 10001 - ... of 4000 rows: about 2 MB as a
        // bitmap, within the graph limit.
        let count = 4000usize;
        let ids: Vec<u32> = std::iter::once(2)
            .chain((0..count as u32 - 1).map(|n| 10_000 + n))
            .collect();
        let mut graph = ConnGraph {
            peers: ids.iter().map(|&id| (id, 1)).collect(),
            edges: Vec::new(),
        };
        graph.peers.push((1, 0));
        for row in 0..count {
            if row + 1 < count {
                graph.edges.push((row, row + 1));
            }
            if row > 0 {
                graph.edges.push((row, row - 1));
            }
        }
        graph.edges.push((0, count));
        let request = SyncRouteRequest {
            my_peer_id: 2,
            my_session_id: 1,
            conn_graph: Some(graph),
            ..SyncRouteRequest::default()
        };
        a.on_request(2, request, now);
        assert_eq!(a.rows.len(), count);

        let requests = a.poll(now, (0, 0));
        assert_eq!(requests.len(), 1);
        let request = &requests[0].1;
        assert!(request.encode().len() <= MAX_REQUEST_BYTES);
        let sent = request.conn_graph.as_ref().unwrap();
        assert!(sent.encode_bitmap().len() <= MAX_GRAPH_BYTES);
        assert_eq!(sent.peers.iter().filter(|(_, v)| *v > 0).count(), count + 1);
        assert_eq!(a.refused().cut_graphs, 0);

        // Not again until a row changes. The response carries the session
        // the neighbour used above; another one would make it a new
        // session and send everything again (spec §12.2).
        let response = SyncRouteResponse {
            session_id: 1,
            ..SyncRouteResponse::default()
        };
        a.on_response(2, Some(response), &rng, now).unwrap();
        let next = a.poll(now + REFRESH_INTERVAL, (0, 0));
        assert_eq!(next.len(), 1);
        assert!(next[0].1.conn_graph.is_none());
    }

    #[test]
    fn a_graph_over_its_limit_keeps_the_nearest_rows() {
        let row = |neighbours: &[u32]| Row {
            version: 1,
            neighbours: neighbours.iter().copied().collect(),
        };
        let rows = [row(&[2]), row(&[1, 3]), row(&[2, 4]), row(&[3, 5])];
        let ordered: Vec<(u32, &Row)> = (1..=4).zip(rows.iter()).collect();
        assert_eq!(graph_rows(&ordered, MAX_GRAPH_BYTES), 4);
        // Room for three nodes: this node and its neighbour's row only.
        assert_eq!(graph_rows(&ordered, graph_bound(3)), 2);
        assert_eq!(graph_rows(&ordered, graph_bound(2)), 1);
        assert_eq!(graph_rows(&ordered, 0), 0);
        let graph = build_graph(&ordered[..2]);
        assert_eq!(graph.peers, vec![(1, 1), (2, 1), (3, 0)]);
        assert_eq!(graph.edges, vec![(0, 1), (1, 0), (1, 2)]);
    }

    #[test]
    fn new_nodes_past_the_storage_budget_are_refused() {
        let now = Instant::now();
        let rng = SystemRandom::new();
        let mut a = node(1, now);
        a.neighbour_up(2, &rng, now).unwrap();
        a.stored_bytes = MAX_STORED_INFO_BYTES - 10;
        let request = SyncRouteRequest {
            my_peer_id: 2,
            my_session_id: 1,
            peer_infos: vec![info(7, 7)],
            ..SyncRouteRequest::default()
        };
        a.on_request(2, request, now);
        assert!(a.info(7).is_none());
        assert_eq!(a.refused().over_budget, 1);
        // An update of a stored node is still taken.
        a.stored_bytes = 0;
        let first = SyncRouteRequest {
            my_peer_id: 2,
            my_session_id: 1,
            peer_infos: vec![info(8, 8)],
            ..SyncRouteRequest::default()
        };
        a.on_request(2, first, now);
        a.stored_bytes = MAX_STORED_INFO_BYTES;
        let update = SyncRouteRequest {
            my_peer_id: 2,
            my_session_id: 1,
            peer_infos: vec![RoutePeerInfo {
                version: 2,
                ..info(8, 8)
            }],
            ..SyncRouteRequest::default()
        };
        a.on_request(2, update, now);
        assert_eq!(a.info(8).unwrap().version, 2);
    }

    #[test]
    fn placeholder_rows_are_not_kept_and_edges_are_capped() {
        let now = Instant::now();
        let rng = SystemRandom::new();
        let mut a = node(1, now);
        a.neighbour_up(2, &rng, now).unwrap();
        let graph = ConnGraph {
            peers: vec![(2, 1), (7, 0), (8, 1)],
            edges: vec![(0, 1), (1, 0), (2, 0)],
        };
        let request = SyncRouteRequest {
            my_peer_id: 2,
            my_session_id: 1,
            conn_graph: Some(graph),
            ..SyncRouteRequest::default()
        };
        a.on_request(2, request, now);
        assert!(a.rows.contains_key(&2));
        assert!(a.rows.contains_key(&8));
        assert!(!a.rows.contains_key(&7));

        // A row that would take the stored edges past the cap is refused.
        let wide = ConnGraph {
            peers: std::iter::once((9, 1))
                .chain((0..MAX_GRAPH_EDGES as u32).map(|n| (20_000 + n, 0)))
                .collect(),
            edges: (1..=MAX_GRAPH_EDGES).map(|to| (0, to)).collect(),
        };
        let request = SyncRouteRequest {
            my_peer_id: 2,
            my_session_id: 1,
            conn_graph: Some(wide),
            ..SyncRouteRequest::default()
        };
        a.on_request(2, request, now);
        assert!(!a.rows.contains_key(&9));
        assert_eq!(a.refused().rows, 1);
    }

    #[test]
    fn large_tables_are_sent_in_parts() {
        let now = Instant::now();
        let rng = SystemRandom::new();
        let mut a = node(1, now);
        a.neighbour_up(2, &rng, now).unwrap();
        // Big entries, more than one request may carry.
        let big = |id: u32| RoutePeerInfo {
            proxy_cidrs: (0..200)
                .map(|n| format!("10.{}.{}.0/24", n % 250, id % 250))
                .collect(),
            ..info(id, 1)
        };
        let size = big(10_000).encode().len();
        let count = (REQUEST_INFO_BYTES / size) as u32 * 2 + 10;
        let fill = SyncRouteRequest {
            my_peer_id: 2,
            my_session_id: 1,
            peer_infos: (0..count).map(|n| big(10_000 + n)).collect(),
            ..SyncRouteRequest::default()
        };
        a.on_request(2, fill, now);
        assert_eq!(a.infos().count() as u32, count);

        let mut b = node(3, now);
        connect(&mut a, &mut b, now);
        let mut nodes = [a, b];
        let mut rounds = 0;
        let mut later = now;
        while nodes[1].infos().count() < count as usize + 1 {
            later += SYNC_INTERVAL;
            for i in 0..2 {
                let other = nodes[1 - i].id();
                let requests: Vec<SyncRouteRequest> = nodes[i]
                    .poll(later, (0, 0))
                    .into_iter()
                    .filter(|(peer, _)| *peer == other)
                    .map(|(_, request)| request)
                    .collect();
                for request in requests {
                    assert!(request.encode().len() <= MAX_REQUEST_BYTES);
                    let (left, right) = nodes.split_at_mut(1);
                    if i == 0 {
                        deliver(&mut left[0], &mut right[0], request, later);
                    } else {
                        deliver(&mut right[0], &mut left[0], request, later);
                    }
                }
            }
            rounds += 1;
            assert!(rounds < 20, "never finished");
        }
        assert!(rounds >= 3, "{rounds} rounds");
    }

    #[test]
    fn a_full_table_makes_room_only_from_unreachable_nodes() {
        let now = Instant::now();
        let rng = SystemRandom::new();
        let mut a = node(1, now);
        a.neighbour_up(2, &rng, now).unwrap();
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
        // Only after the grace period.
        a.on_request(2, late.clone(), now);
        assert!(a.info(99_999).is_none());
        let later = now + EVICTION_GRACE;
        a.on_request(2, late, later);
        assert!(a.info(99_999).is_some());
        assert_eq!(a.infos().count(), MAX_NODES);
    }

    #[test]
    fn a_direct_neighbours_information_is_taken_when_the_table_is_full() {
        let now = Instant::now();
        let rng = SystemRandom::new();
        let mut a = node(1, now);
        a.neighbour_up(2, &rng, now).unwrap();
        let fill = SyncRouteRequest {
            my_peer_id: 2,
            my_session_id: 1,
            peer_infos: (0..MAX_NODES as u32).map(|n| info(10_000 + n, 1)).collect(),
            ..SyncRouteRequest::default()
        };
        a.on_request(2, fill, now);
        assert_eq!(a.infos().count(), MAX_NODES);
        // A new neighbour's own information, with nothing unreachable for
        // long: the farthest non-neighbour makes room.
        a.neighbour_up(3, &rng, now).unwrap();
        let own = SyncRouteRequest {
            my_peer_id: 3,
            my_session_id: 1,
            peer_infos: vec![info(3, 1)],
            ..SyncRouteRequest::default()
        };
        a.on_request(3, own, now);
        assert!(a.info(3).is_some());
        assert_eq!(a.infos().count(), MAX_NODES);
        // A stranger's is still refused.
        let stranger = SyncRouteRequest {
            my_peer_id: 2,
            my_session_id: 1,
            peer_infos: vec![info(99_999, 1)],
            ..SyncRouteRequest::default()
        };
        a.on_request(2, stranger, now);
        assert!(a.info(99_999).is_none());
    }
}
