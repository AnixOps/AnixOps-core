//! Route synchronisation sessions (spec §12.2, §12.3).
//!
//! [`RouteSync`] keeps this node's information, the information and
//! connection rows learned from the network, one sync session per direct
//! neighbour, and the topology built from them (spec §12.5). It does no
//! I/O: the driver calls [`RouteSync::poll`] once a second, sends each
//! batch it returns as a `SyncRouteInfo` RPC and reports the outcome of
//! each with [`RouteSync::on_response`]; requests from neighbours go to
//! [`RouteSync::on_request`], whose answer the driver sends back.
//!
//! Who pushes (spec §12.2): every direct link on its own. This node is the
//! initiator towards neighbour X when its node ID is smaller than X's, or
//! when X has not pushed to it as the initiator in the last 30 seconds, so
//! every link has at least one side pushing. It sends its own changes to
//! every neighbour either way, marked as not the initiator when it is not.
//!
//! Batches (spec §12.2): what is new for a neighbour goes in batches of a
//! target size kept per neighbour, from [`BATCH_START`], halved on a
//! timeout down to [`BATCH_MIN`] and doubled after [`GROW_AFTER`] successes
//! in a row up to [`BATCH_MAX`]. A connection graph under half the target
//! rides in the first batch; a larger one goes alone, before the node
//! information. Information confirmed while the graph is not is only
//! "awaiting" and goes again if the graph fails. Versions count as sent
//! only once the neighbour confirmed them.

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
/// Rows cut from a connection graph are offered again as often.
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
/// (spec §11.2, §12.2).
pub const MAX_REQUEST_BYTES: usize = 4 * 1024 * 1024;
/// A connection graph sent is at most this long, about 2.1 MiB: the
/// bitmap of the largest graph and its node list (spec §12.4). Past it the
/// farthest rows are cut.
pub const MAX_GRAPH_BYTES: usize = 2 * 1024 * 1024 + 100 * 1024;

/// Target batch size of a new session (spec §12.2).
pub const BATCH_START: usize = 256 * 1024;
/// The target is halved on a timeout down to this (spec §12.2).
pub const BATCH_MIN: usize = 32 * 1024;
/// The target is doubled after [`GROW_AFTER`] successes up to this.
pub const BATCH_MAX: usize = 1024 * 1024;
/// Successful batches in a row that double the target (spec §12.2).
pub const GROW_AFTER: u32 = 3;
/// Room kept in every batch for the headers (spec §12.2).
const BATCH_RESERVE: usize = 4 * 1024;
/// Timeouts in a row of a batch carrying the connection graph after which
/// the farthest half of its rows is cut (spec §12.2).
pub const GRAPH_TIMEOUTS_TO_CUT: u32 = 3;
/// Encoded bytes of batches in flight to one neighbour at most; what does
/// not fit waits for a later check (spec §12.2). A single batch is always
/// let through, and none exceeds [`MAX_REQUEST_BYTES`].
pub const IN_FLIGHT_BYTES: usize = MAX_REQUEST_BYTES;
/// Batches in flight to one neighbour at most: half the calls a receiver
/// reassembles from one peer at once (spec §19.3).
pub const IN_FLIGHT_BATCHES: usize = 8;

/// A connection graph sent must be answered within this long; past it the
/// farthest half of its rows is cut, and past it again the session with
/// that neighbour is closed (spec §12.2). Shorter than the receiver's
/// [`UNREACHABLE_TTL`].
pub const GRAPH_DEADLINE: Duration = Duration::from_secs(60);
/// Wait before a session closed for an undelivered graph is rebuilt; it
/// doubles with each further closure up to [`REBUILD_MAX`] and resets once a
/// graph gets through (spec §12.2).
pub const REBUILD_FIRST: Duration = Duration::from_secs(30);
pub const REBUILD_MAX: Duration = Duration::from_secs(600);

/// Encoded node information all stored entries may take together
/// (spec §12.3). Past it, information of new nodes is refused, except a
/// direct neighbour's, for which others make room; updates of stored ones
/// are still taken.
pub const MAX_STORED_INFO_BYTES: usize = 16 * 1024 * 1024;

/// Something the driver must act on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Notice {
    /// The neighbour answered that this node's ID is already in use
    /// (spec §12.1 error 0).
    DuplicatePeerId,
}

/// Why a batch got no answer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Failure {
    /// The call failed: an RPC error, or an answer that does not decode.
    Error,
    /// No answer within the call's timeout: the batch size halves.
    Timeout,
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
    /// Connection graphs sent cut short, by the limits of spec §12.4 or
    /// halved for delivery (spec §12.2).
    pub cut_graphs: u64,
    /// Node information whose own static key is off the native key list
    /// (spec §8.3.1 rule 4).
    pub not_native: u64,
    /// Node information or connection rows of new nodes refused, or reachable
    /// nodes evicted, because [`MAX_NODES`] entries or
    /// [`MAX_STORED_INFO_BYTES`] are stored: the network is larger than one
    /// node keeps (spec §12.3, §12.4).
    pub at_capacity: u64,
    /// Sessions closed because a connection graph could not be delivered,
    /// even cut by half, within two [`GRAPH_DEADLINE`]s (spec §12.2).
    pub graph_timeouts: u64,
    /// Batches a neighbour answered with an error or a failed call: a
    /// closed session may come from the link or the neighbour rather than
    /// the size.
    pub error_answers: u64,
}

struct Stored {
    info: RoutePeerInfo,
    /// Local time of receipt; replaces the sender's timestamp (spec §12.3).
    received: Instant,
    /// The neighbour it came from (spec §12.2: its graphs extend the time
    /// this information survives being unreachable).
    from: u32,
}

#[derive(Default)]
struct Row {
    version: u32,
    neighbours: BTreeSet<u32>,
}

/// Versions the neighbour confirmed.
#[derive(Default)]
struct Sent {
    infos: BTreeMap<u32, u32>,
    rows: BTreeMap<u32, u32>,
}

/// One batch in flight.
#[derive(Default)]
struct Batch {
    infos: BTreeMap<u32, u32>,
    rows: BTreeMap<u32, u32>,
    /// It carries the connection graph.
    graph: bool,
    /// The batch carrying the connection graph that was unconfirmed when
    /// this one went: until that is confirmed, this one's information only
    /// awaits (spec §12.2).
    behind: Option<u64>,
    /// Encoded size, near enough: the information, the graph and the room
    /// kept for headers.
    bytes: usize,
}

struct Session {
    /// When the connection came up.
    since: Instant,
    /// When the neighbour last asked as the initiator.
    pushed_at: Option<Instant>,
    mine: u64,
    theirs: Option<u64>,
    sent: Sent,
    in_flight: BTreeMap<u64, Batch>,
    /// The batch in flight that carries the connection graph.
    graph_batch: Option<u64>,
    /// The latest batch carrying a connection graph that was confirmed.
    graph_confirmed: Option<u64>,
    /// Information versions confirmed behind a graph not yet confirmed
    /// ("待确认", spec §12.2): sent once it is, void if it fails.
    awaiting: BTreeMap<u32, u32>,
    /// Rows left out of the last graph sent, at the versions then: not sent,
    /// so offered again, but only every [`REFRESH_INTERVAL`].
    cut_rows: BTreeMap<u32, u32>,
    /// When a connection graph was last sent.
    graph_sent_at: Option<Instant>,
    last_sent: Option<Instant>,
    retry: Duration,
    not_before: Option<Instant>,
    /// When the connection graph now waiting for an answer was first sent.
    graph_since: Option<Instant>,
    /// Rows the graph is cut to after the first [`GRAPH_DEADLINE`] or
    /// [`GRAPH_TIMEOUTS_TO_CUT`] timeouts.
    graph_cut: Option<usize>,
    /// Rows of the graph last sent.
    graph_rows: usize,
    /// Timeouts in a row of batches carrying the graph.
    graph_timeouts: u32,
    /// Wait before the session is rebuilt after the last closure.
    rebuild_wait: Duration,
    /// Target batch size (spec §12.2).
    target: usize,
    /// Successful batches in a row.
    successes: u32,
    /// When this neighbour last sent a connection graph.
    graph_received: Option<Instant>,
}

impl Session {
    fn new(mine: u64, since: Instant) -> Self {
        Self {
            since,
            pushed_at: None,
            mine,
            theirs: None,
            sent: Sent::default(),
            in_flight: BTreeMap::new(),
            graph_batch: None,
            graph_confirmed: None,
            awaiting: BTreeMap::new(),
            cut_rows: BTreeMap::new(),
            graph_sent_at: None,
            last_sent: None,
            retry: Duration::ZERO,
            not_before: None,
            graph_since: None,
            graph_cut: None,
            graph_rows: 0,
            graph_timeouts: 0,
            rebuild_wait: Duration::ZERO,
            target: BATCH_START,
            successes: 0,
            graph_received: None,
        }
    }

    /// Everything already sent is forgotten, so the next request is full;
    /// answers to batches in flight are ignored.
    fn forget_sent(&mut self) {
        self.sent = Sent::default();
        self.in_flight.clear();
        self.graph_batch = None;
        self.awaiting.clear();
        self.cut_rows.clear();
    }

    /// Whether `version` of `id` is confirmed, awaiting or in flight.
    fn covers(&self, id: u32, version: u32) -> bool {
        let at_least = |map: &BTreeMap<u32, u32>| map.get(&id).is_some_and(|&v| v >= version);
        at_least(&self.sent.infos)
            || at_least(&self.awaiting)
            || self.in_flight.values().any(|batch| at_least(&batch.infos))
    }

    fn failed(&mut self, failure: Failure, batch: &Batch, now: Instant) {
        self.retry = (self.retry * 2).clamp(RETRY_MIN, RETRY_MAX);
        self.not_before = Some(now + self.retry);
        self.successes = 0;
        let timeout = failure == Failure::Timeout;
        if timeout {
            self.target = (self.target / 2).max(BATCH_MIN);
        }
        if batch.graph {
            // What awaited the graph is void; the graph and that
            // information go again at the next check (spec §12.2).
            self.graph_batch = None;
            self.awaiting.clear();
            if timeout {
                self.graph_timeouts += 1;
                if self.graph_timeouts >= GRAPH_TIMEOUTS_TO_CUT && self.graph_cut.is_none() {
                    // Cut now; the cut graph then has a whole deadline.
                    self.graph_cut = Some((self.graph_rows / 2).max(1));
                    self.graph_since = Some(now);
                    self.graph_timeouts = 0;
                }
            }
        }
    }
}

/// Raises every version in `into` to the one in `from`.
fn record(into: &mut BTreeMap<u32, u32>, from: BTreeMap<u32, u32>) {
    for (id, version) in from {
        let entry = into.entry(id).or_insert(version);
        *entry = (*entry).max(version);
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

/// One batch for the driver to send to `peer`; its outcome goes back with
/// `id` to [`RouteSync::on_response`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SyncBatch {
    pub peer: u32,
    pub id: u64,
    pub request: SyncRouteRequest,
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
    /// Another node holds this node's ID, or a version ran out: a new
    /// ID is needed (spec §12.3).
    conflict: bool,
    /// Encoded bytes of all stored information.
    stored_bytes: usize,
    refused: Refused,
    /// See [`RouteSync::set_admitted`].
    admitted: Option<Vec<[u8; 32]>>,
    /// See [`RouteSync::take_graph_timeouts`].
    graph_timeouts: Vec<u32>,
    /// The next batch ID.
    next_batch: u64,
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
            graph_timeouts: Vec::new(),
            next_batch: 0,
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

    /// The next version of this node's connection row, the same way: at
    /// the top the node needs new IDs, or its neighbour changes would no
    /// longer be taken.
    fn next_row_version(&mut self) {
        self.own_row.version = self.own_row.version.saturating_add(1);
        if self.own_row.version == u32::MAX {
            self.conflict = true;
        }
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
    /// a newer version, or one of this node's versions ran out (spec
    /// §12.3): the node needs a new ID.
    pub fn take_conflict(&mut self) -> bool {
        std::mem::take(&mut self.conflict)
    }

    /// The neighbours whose sessions were closed because a connection graph
    /// could not be delivered (spec §12.2: the alert for an oversized
    /// synchronisation), since the last call.
    pub fn take_graph_timeouts(&mut self) -> Vec<u32> {
        std::mem::take(&mut self.graph_timeouts)
    }

    /// True once after the topology or the stored information changed.
    pub fn take_changed(&mut self) -> bool {
        std::mem::take(&mut self.changed)
    }

    /// The target batch size towards `peer` (spec §12.2).
    pub fn batch_target(&self, peer: u32) -> Option<usize> {
        self.sessions.get(&peer).map(|session| session.target)
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
            self.next_row_version();
        }
        self.rebuild();
        Ok(())
    }

    /// The last connection to `peer` went down.
    pub fn neighbour_down(&mut self, peer: u32) {
        self.sessions.remove(&peer);
        if self.own_row.neighbours.remove(&peer) {
            self.next_row_version();
        }
        self.rebuild();
    }

    /// The batches to send now. `unix_now` is the wall-clock time put in
    /// this node's information (spec §12.3).
    pub fn poll(&mut self, now: Instant, unix_now: (i64, i32)) -> Vec<SyncBatch> {
        if now.saturating_duration_since(self.own_updated) >= OWN_REFRESH {
            self.own.version = self.next_own_version();
            self.own_updated = now;
        }
        let peers: Vec<u32> = self.sessions.keys().copied().collect();
        let mut out = Vec::new();
        for peer in peers {
            self.batches_for(peer, now, unix_now, &mut out);
        }
        out
    }

    fn batches_for(
        &mut self,
        peer: u32,
        now: Instant,
        unix_now: (i64, i32),
        out: &mut Vec<SyncBatch>,
    ) {
        self.graph_deadline(peer, now);
        let initiator = self.initiates(peer, now);
        let hops = self.hops();
        let base = self.next_batch;
        let Some(session) = self.sessions.get(&peer) else {
            return;
        };
        if session.not_before.is_some_and(|at| now < at) {
            return;
        }

        // The connection graph, when a row is newer than confirmed and no
        // graph is in flight. Rows cut last time come back only after the
        // refresh interval, so that a graph that never fits whole is not
        // sent every second.
        let mut ordered: Vec<(u32, &Row)> = std::iter::once((self.own.peer_id, &self.own_row))
            .chain(self.rows.iter().map(|(&id, row)| (id, row)))
            .collect();
        // Nearest first, so that a cut drops the farthest rows (spec §12.4).
        ordered.sort_by_key(|(id, _)| (hops.get(id).copied().unwrap_or(u32::MAX), *id));
        let retry_cut = session
            .graph_sent_at
            .is_none_or(|at| now.saturating_duration_since(at) >= REFRESH_INTERVAL);
        let graph_wanted = session.graph_batch.is_none()
            && ordered.iter().any(|(id, row)| {
                session.sent.rows.get(id).is_none_or(|&v| v < row.version)
                    && (retry_cut || session.cut_rows.get(id) != Some(&row.version))
            });
        let mut graph = None;
        let mut graph_rows = BTreeMap::new();
        let mut cut_rows = BTreeMap::new();
        let mut kept_rows = 0;
        if graph_wanted {
            let mut kept = graph_rows_within(&ordered, MAX_GRAPH_BYTES);
            if let Some(limit) = session.graph_cut {
                kept = kept.min(limit);
            }
            for (index, (id, row)) in ordered.iter().enumerate() {
                if index < kept {
                    graph_rows.insert(*id, row.version);
                } else {
                    cut_rows.insert(*id, row.version);
                }
            }
            kept_rows = kept;
            graph = Some(build_graph(&ordered[..kept]));
        }
        let graph_bytes = graph
            .as_ref()
            .map_or(0, |graph| graph.encode_bitmap().len());

        // Node information not confirmed, awaiting or in flight: this
        // node's own first.
        let mut candidates: Vec<(u32, u32, usize)> = Vec::new();
        if !session.covers(self.own.peer_id, self.own.version) {
            candidates.push((self.own.peer_id, self.own.version, self.own.encode().len()));
        }
        for (&id, stored) in &self.infos {
            if id != peer && !session.covers(id, stored.info.version) {
                candidates.push((id, stored.info.version, info_size(&stored.info)));
            }
        }

        let mut in_flight = session.in_flight.len();
        let mut in_flight_bytes: usize = session.in_flight.values().map(|b| b.bytes).sum();
        let fits = |in_flight: usize, in_flight_bytes: usize, bytes: usize| {
            in_flight == 0
                || (in_flight < IN_FLIGHT_BATCHES && in_flight_bytes + bytes <= IN_FLIGHT_BYTES)
        };
        let target = session.target;
        let mut planned: Vec<(Batch, Option<ConnGraph>, Vec<u32>)> = Vec::new();
        let mut behind = session.graph_batch;
        let mut graph_planned = false;

        if let Some(alone) = graph.take_if(|_| graph_bytes * 2 >= target) {
            // A large graph goes alone, ahead of the information.
            let bytes = graph_bytes + BATCH_RESERVE;
            if !fits(in_flight, in_flight_bytes, bytes) {
                // Not before it: wait for the batches in flight.
                return;
            }
            in_flight += 1;
            in_flight_bytes += bytes;
            behind = Some(base);
            graph_planned = true;
            planned.push((
                Batch {
                    rows: std::mem::take(&mut graph_rows),
                    graph: true,
                    bytes,
                    ..Batch::default()
                },
                Some(alone),
                Vec::new(),
            ));
        }
        let mut next = 0;
        loop {
            let mut batch = Batch {
                bytes: BATCH_RESERVE,
                ..Batch::default()
            };
            let combined = graph.take();
            if combined.is_some() {
                // A small graph rides in the first batch.
                batch.graph = true;
                batch.rows = std::mem::take(&mut graph_rows);
                batch.bytes += graph_bytes;
            }
            let mut ids = Vec::new();
            while let Some(&(id, version, size)) = candidates.get(next) {
                // At least one per batch, so that batching always advances.
                if !ids.is_empty() && batch.bytes + size > target {
                    break;
                }
                batch.bytes += size;
                batch.infos.insert(id, version);
                ids.push(id);
                next += 1;
            }
            if ids.is_empty() && combined.is_none() {
                break;
            }
            if !fits(in_flight, in_flight_bytes, batch.bytes) {
                // The rest waits for a later check, not marked as sent.
                break;
            }
            in_flight += 1;
            in_flight_bytes += batch.bytes;
            if batch.graph {
                // Later batches of this round follow it.
                behind = Some(base + planned.len() as u64);
                graph_planned = true;
            } else {
                batch.behind = behind;
            }
            planned.push((batch, combined, ids));
        }

        let due = session
            .last_sent
            .is_none_or(|at| now.saturating_duration_since(at) >= REFRESH_INTERVAL);
        if planned.is_empty() && due && session.in_flight.is_empty() {
            // Nothing new: the refresh still goes (spec §12.2).
            planned.push((Batch::default(), None, Vec::new()));
        }
        if planned.is_empty() {
            return;
        }

        let mine = session.mine;
        let requests: Vec<SyncRouteRequest> = planned
            .iter_mut()
            .map(|(_, conn_graph, ids)| SyncRouteRequest {
                my_peer_id: self.own.peer_id,
                my_session_id: mine,
                is_initiator: initiator,
                peer_infos: ids
                    .iter()
                    .filter_map(|&id| {
                        if id == self.own.peer_id {
                            let mut own = self.own.clone();
                            own.last_update = unix_now;
                            Some(own)
                        } else {
                            self.infos.get(&id).map(|stored| stored.info.clone())
                        }
                    })
                    .collect(),
                conn_graph: conn_graph.take(),
                foreign_network_infos: None,
                ..SyncRouteRequest::default()
            })
            .collect();

        let Some(session) = self.sessions.get_mut(&peer) else {
            return;
        };
        let count = planned.len() as u64;
        for (offset, ((batch, _, _), request)) in planned.into_iter().zip(requests).enumerate() {
            let id = base + offset as u64;
            if batch.graph {
                session.graph_batch = Some(id);
                session.graph_since.get_or_insert(now);
                session.graph_rows = kept_rows;
                session.graph_sent_at = Some(now);
            }
            session.in_flight.insert(id, batch);
            out.push(SyncBatch { peer, id, request });
        }
        session.last_sent = Some(now);
        if graph_planned {
            if !cut_rows.is_empty() {
                self.refused.cut_graphs += 1;
            }
            session.cut_rows = cut_rows;
        }
        self.next_batch = base + count;
    }

    /// A connection graph unanswered for [`GRAPH_DEADLINE`] is cut to half
    /// its rows, farthest first; unanswered again for as long, the session
    /// with `peer` is closed and rebuilt after a wait, with everything sent
    /// again (spec §12.2).
    fn graph_deadline(&mut self, peer: u32, now: Instant) {
        let Some(session) = self.sessions.get_mut(&peer) else {
            return;
        };
        let Some(since) = session.graph_since else {
            return;
        };
        if now.saturating_duration_since(since) < GRAPH_DEADLINE {
            return;
        }
        if session.graph_cut.is_none() {
            session.graph_cut = Some((session.graph_rows / 2).max(1));
            session.graph_since = Some(now);
            return;
        }
        // A new session number: the neighbour sees a new session and the
        // next request is full.
        session.mine = session.mine.wrapping_add(1);
        session.theirs = None;
        session.forget_sent();
        session.graph_since = None;
        session.graph_cut = None;
        session.graph_timeouts = 0;
        session.retry = Duration::ZERO;
        session.rebuild_wait = if session.rebuild_wait.is_zero() {
            REBUILD_FIRST
        } else {
            (session.rebuild_wait * 2).min(REBUILD_MAX)
        };
        session.not_before = Some(now + session.rebuild_wait);
        self.refused.graph_timeouts += 1;
        self.graph_timeouts.push(peer);
    }

    /// The outcome of batch `id` sent to `peer`: its response, or why there
    /// is none.
    pub fn on_response(
        &mut self,
        peer: u32,
        id: u64,
        outcome: Result<SyncRouteResponse, Failure>,
        rng: &dyn SecureRandom,
        now: Instant,
    ) -> Result<Option<Notice>, Unspecified> {
        let Some(session) = self.sessions.get_mut(&peer) else {
            return Ok(None);
        };
        let Some(batch) = session.in_flight.remove(&id) else {
            return Ok(None);
        };
        let response = match outcome {
            Ok(response) => response,
            Err(failure) => {
                if failure == Failure::Error {
                    self.refused.error_answers += 1;
                }
                session.failed(failure, &batch, now);
                return Ok(None);
            }
        };
        match response.error {
            Some(sync_error::STOPPED) => {
                self.refused.error_answers += 1;
                session.mine = session_id(rng)?;
                session.theirs = None;
                session.forget_sent();
                // A new session starts its deadline anew.
                session.graph_since = None;
                session.graph_cut = None;
                session.graph_timeouts = 0;
                session.failed(Failure::Error, &batch, now);
                Ok(None)
            }
            Some(sync_error::DUPLICATE_PEER_ID) => {
                session.failed(Failure::Error, &batch, now);
                Ok(Some(Notice::DuplicatePeerId))
            }
            _ => {
                session.retry = Duration::ZERO;
                session.not_before = None;
                session.successes += 1;
                if session.successes >= GROW_AFTER {
                    session.target = (session.target * 2).min(BATCH_MAX);
                    session.successes = 0;
                }
                if session
                    .theirs
                    .is_some_and(|theirs| theirs != response.session_id)
                {
                    session.forget_sent();
                } else if batch.graph {
                    if session.graph_batch == Some(id) {
                        session.graph_batch = None;
                    }
                    session.graph_confirmed = Some(id);
                    session.graph_since = None;
                    session.graph_cut = None;
                    session.graph_timeouts = 0;
                    session.rebuild_wait = Duration::ZERO;
                    record(&mut session.sent.rows, batch.rows);
                    record(&mut session.sent.infos, batch.infos);
                    let awaiting = std::mem::take(&mut session.awaiting);
                    record(&mut session.sent.infos, awaiting);
                } else {
                    match batch.behind {
                        Some(graph) if session.graph_batch == Some(graph) => {
                            record(&mut session.awaiting, batch.infos);
                        }
                        // The graph it followed failed and no later one got
                        // through: void, sent again.
                        Some(graph) if session.graph_confirmed.is_none_or(|c| c < graph) => {}
                        _ => record(&mut session.sent.infos, batch.infos),
                    }
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
        if request.conn_graph.is_some() {
            session.graph_received = Some(now);
        }
        let mine = session.mine;

        self.refused.infos += u64::from(request.skipped_infos);
        if request.graph_dropped {
            self.refused.graphs += 1;
        }
        let mut changed = false;
        for info in request.peer_infos {
            changed |= self.merge_info(info, peer, now);
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

    fn merge_info(&mut self, info: RoutePeerInfo, from: u32, now: Instant) -> bool {
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
            Some(_) => {}
            None => {
                if !self.make_room(info.peer_id, size, now) {
                    return false;
                }
            }
        }
        if let Some(old) = self.infos.insert(
            info.peer_id,
            Stored {
                info,
                received: now,
                from,
            },
        ) {
            self.stored_bytes -= info_size(&old.info);
        }
        self.stored_bytes += size;
        true
    }

    /// Room for the information of the new node `id`, `size` bytes, within
    /// [`MAX_NODES`] entries and [`MAX_STORED_INFO_BYTES`] (spec §12.3). A
    /// node unreachable for a while makes room, the one unreachable
    /// longest. A direct neighbour's information is always taken: then the
    /// farthest other nodes go until both limits hold. Other new nodes past
    /// the byte budget are refused.
    fn make_room(&mut self, id: u32, size: usize, now: Instant) -> bool {
        let neighbour = self.sessions.contains_key(&id);
        let mut counted = false;
        loop {
            let over_bytes = self.stored_bytes + size > MAX_STORED_INFO_BYTES;
            if over_bytes && !neighbour {
                self.refused.over_budget += 1;
                return false;
            }
            if !over_bytes && self.infos.len() < MAX_NODES {
                return true;
            }
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
                Some(victim) => victim,
                None => {
                    if !counted {
                        self.refused.at_capacity += 1;
                        counted = true;
                    }
                    match self.farthest_non_neighbour().filter(|_| neighbour) {
                        Some(victim) => victim,
                        None => return false,
                    }
                }
            };
            self.remove_node(victim);
        }
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
                self.refused.at_capacity += 1;
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
    /// (spec §12.3). Call it once a second. The time unreachable counts
    /// from the latest of: when the node became unreachable, when its
    /// information was last received, and when the neighbour it came from
    /// last sent a connection graph (spec §12.2), so that a graph arriving
    /// after the information does not lose it. Graphs from other neighbours
    /// do not count.
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
            let start = self.infos.get(&id).map_or(since, |stored| {
                let graph = self
                    .sessions
                    .get(&stored.from)
                    .and_then(|session| session.graph_received);
                since.max(stored.received).max(graph.unwrap_or(since))
            });
            if now.saturating_duration_since(start) >= UNREACHABLE_TTL {
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
fn graph_rows_within(ordered: &[(u32, &Row)], budget: usize) -> usize {
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
        batch: SyncBatch,
        now: Instant,
    ) -> SyncRouteResponse {
        let request = SyncRouteRequest::decode(&batch.request.encode()).unwrap();
        let response = to.on_request(from.id(), request, now);
        let response = SyncRouteResponse::decode(&response.encode()).unwrap();
        from.on_response(to.id(), batch.id, Ok(response), &SystemRandom::new(), now)
            .unwrap();
        response
    }

    /// The batch sent to `peer`, the first one when there are several.
    fn to(batches: &[SyncBatch], peer: u32) -> Option<&SyncBatch> {
        batches.iter().find(|batch| batch.peer == peer)
    }

    /// Runs one sync round between every pair in both directions.
    fn round(nodes: &mut [RouteSync], now: Instant) {
        for i in 0..nodes.len() {
            let requests = nodes[i].poll(now, (0, 0));
            for batch in requests {
                let j = nodes.iter().position(|n| n.id() == batch.peer).unwrap();
                let (a, b) = if i < j {
                    let (left, right) = nodes.split_at_mut(j);
                    (&mut left[i], &mut right[0])
                } else {
                    let (left, right) = nodes.split_at_mut(i);
                    (&mut right[0], &mut left[j])
                };
                deliver(a, b, batch, now);
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
        assert!(!requests[0].request.is_initiator);
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
        assert!(refresh[0].request.peer_infos.is_empty());
        assert!(refresh[0].request.conn_graph.is_none());
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
        assert!(full[0].request.peer_infos.iter().any(|i| i.peer_id == 1));
        assert!(full[0].request.conn_graph.is_some());
    }

    #[test]
    fn failures_back_off_and_stopped_resets_the_session() {
        let now = Instant::now();
        let rng = SystemRandom::new();
        let mut a = node(1, now);
        a.neighbour_up(2, &rng, now).unwrap();
        let sent = a.poll(now, (0, 0));
        assert_eq!(sent.len(), 1);
        a.on_response(2, sent[0].id, Err(Failure::Error), &rng, now)
            .unwrap();
        assert_eq!(a.refused().error_answers, 1);
        // An error is no timeout: the batch size stays.
        assert_eq!(a.batch_target(2), Some(BATCH_START));
        assert!(a.poll(now + Duration::from_millis(49), (0, 0)).is_empty());
        let retry_at = now + RETRY_MIN;
        let first = a.poll(retry_at, (0, 0));
        assert_eq!(first.len(), 1);
        let session = first[0].request.my_session_id;
        let stopped = SyncRouteResponse {
            error: Some(sync_error::STOPPED),
            ..SyncRouteResponse::default()
        };
        a.on_response(2, first[0].id, Ok(stopped), &rng, retry_at)
            .unwrap();
        let again = a.poll(retry_at + RETRY_MIN * 2, (0, 0));
        assert_eq!(again.len(), 1);
        assert_ne!(again[0].request.my_session_id, session);
        assert!(again[0].request.peer_infos.iter().any(|i| i.peer_id == 1));
        // An answer to a batch no longer in flight changes nothing.
        assert_eq!(
            a.on_response(2, first[0].id, Err(Failure::Timeout), &rng, retry_at),
            Ok(None)
        );
        assert_eq!(a.batch_target(2), Some(BATCH_START));
    }

    /// Rows (not placeholders) of the graph in the batch to `peer`.
    fn graph_rows_to(batches: &[SyncBatch], peer: u32) -> Option<usize> {
        let graph = batches
            .iter()
            .filter(|batch| batch.peer == peer)
            .find_map(|batch| batch.request.conn_graph.as_ref())?;
        Some(
            graph
                .peers
                .iter()
                .filter(|(_, version)| *version != 0)
                .count(),
        )
    }

    /// Fails every batch to `peer` with `failure`.
    fn fail(a: &mut RouteSync, batches: &[SyncBatch], peer: u32, failure: Failure, now: Instant) {
        for batch in batches.iter().filter(|batch| batch.peer == peer) {
            a.on_response(peer, batch.id, Err(failure), &SystemRandom::new(), now)
                .unwrap();
        }
    }

    #[test]
    fn an_undelivered_graph_is_cut_then_the_session_closed() {
        let now = Instant::now();
        let rng = SystemRandom::new();
        // A chain 1 - 2 - 3, so that node 1 holds three rows.
        let mut nodes = [node(1, now), node(2, now), node(3, now)];
        {
            let (left, right) = nodes.split_at_mut(1);
            connect(&mut left[0], &mut right[0], now);
            let (left, right) = nodes.split_at_mut(2);
            connect(&mut left[1], &mut right[0], now);
        }
        for _ in 0..4 {
            round(&mut nodes, now);
        }
        let mut a = std::mem::replace(&mut nodes[0], node(1, now));
        a.neighbour_up(9, &rng, now).unwrap();
        // Node 2 answers, so that only the session with node 9 times out.
        let mut two = std::mem::replace(&mut nodes[1], node(2, now));
        let mut poll = |a: &mut RouteSync, t: Instant| {
            let batches = a.poll(t, (0, 0));
            for batch in &batches {
                if batch.peer == 2 {
                    deliver(a, &mut two, batch.clone(), t);
                }
            }
            batches
        };

        // Node 9 never answers; the call fails without a timeout so that
        // only the deadline cuts.
        let first = poll(&mut a, now);
        assert_eq!(graph_rows_to(&first, 9), Some(3));
        let session = to(&first, 9).unwrap().request.my_session_id;
        fail(&mut a, &first, 9, Failure::Error, now);

        // Within the deadline the whole graph is retried.
        let t = now + Duration::from_secs(30);
        let retried = poll(&mut a, t);
        assert_eq!(graph_rows_to(&retried, 9), Some(3));
        fail(&mut a, &retried, 9, Failure::Error, t);

        // Past it, half the rows go, the farthest first.
        let t = now + GRAPH_DEADLINE;
        let cut = poll(&mut a, t);
        assert_eq!(graph_rows_to(&cut, 9), Some(1));
        let graph = cut
            .iter()
            .filter(|batch| batch.peer == 9)
            .find_map(|batch| batch.request.conn_graph.clone());
        assert_eq!(graph.unwrap().peers[0].0, 1);
        assert!(a.take_graph_timeouts().is_empty());
        assert_eq!(a.refused().cut_graphs, 1);
        fail(&mut a, &cut, 9, Failure::Error, t);

        // Past it again, the session is closed and waits 30 seconds.
        let t = now + GRAPH_DEADLINE * 2;
        assert!(graph_rows_to(&poll(&mut a, t), 9).is_none());
        assert_eq!(a.take_graph_timeouts(), vec![9]);
        assert!(a.take_graph_timeouts().is_empty());
        assert_eq!(a.refused().graph_timeouts, 1);
        let early = t + REBUILD_FIRST - Duration::from_secs(1);
        assert!(graph_rows_to(&poll(&mut a, early), 9).is_none());

        // Then everything goes again under a new session, uncut.
        let t = t + REBUILD_FIRST;
        let rebuilt = poll(&mut a, t);
        assert_eq!(graph_rows_to(&rebuilt, 9), Some(3));
        let request = &to(&rebuilt, 9).unwrap().request;
        assert_ne!(request.my_session_id, session);
        assert!(request.peer_infos.iter().any(|info| info.peer_id == 1));

        // A second closure waits twice as long.
        fail(&mut a, &rebuilt, 9, Failure::Error, t);
        let closed = t + GRAPH_DEADLINE * 2;
        let cut = poll(&mut a, t + GRAPH_DEADLINE);
        fail(&mut a, &cut, 9, Failure::Error, t + GRAPH_DEADLINE);
        poll(&mut a, closed);
        assert_eq!(a.take_graph_timeouts(), vec![9]);
        assert!(graph_rows_to(&poll(&mut a, closed + REBUILD_FIRST), 9).is_none());
        let t = closed + REBUILD_FIRST * 2;
        let again = poll(&mut a, t);
        assert_eq!(graph_rows_to(&again, 9), Some(3));

        // A graph that gets through resets the wait.
        let mut b = node(9, t);
        b.neighbour_up(1, &rng, t).unwrap();
        for batch in again.into_iter().filter(|batch| batch.peer == 9) {
            deliver(&mut a, &mut b, batch, t);
        }
        let session = a.sessions.get(&9).unwrap();
        assert!(session.graph_since.is_none() && session.graph_cut.is_none());
        assert!(session.rebuild_wait.is_zero());
    }

    #[test]
    fn rows_cut_from_a_delivered_graph_are_sent_again() {
        let now = Instant::now();
        // A chain 1 - 2 - 3 learned by node 1, then a new neighbour 9.
        let mut nodes = [node(1, now), node(2, now), node(3, now)];
        {
            let (left, right) = nodes.split_at_mut(1);
            connect(&mut left[0], &mut right[0], now);
            let (left, right) = nodes.split_at_mut(2);
            connect(&mut left[1], &mut right[0], now);
        }
        for _ in 0..4 {
            round(&mut nodes, now);
        }
        let mut a = std::mem::replace(&mut nodes[0], node(1, now));
        let mut b = node(9, now);
        connect(&mut a, &mut b, now);
        let first: Vec<SyncBatch> = a
            .poll(now, (0, 0))
            .into_iter()
            .filter(|batch| batch.peer == 9)
            .collect();
        fail(&mut a, &first, 9, Failure::Error, now);

        // Past the deadline the graph is cut to one row and delivered.
        let t = now + GRAPH_DEADLINE;
        let cut: Vec<SyncBatch> = a
            .poll(t, (0, 0))
            .into_iter()
            .filter(|batch| batch.peer == 9)
            .collect();
        assert_eq!(graph_rows_to(&cut, 9), Some(1));
        for batch in cut {
            deliver(&mut a, &mut b, batch, t);
        }
        // The rows cut are not taken as sent (spec §12.2, §12.4): offered
        // again, after the refresh interval, whole.
        let soon: Vec<SyncBatch> = a.poll(t + SYNC_INTERVAL, (0, 0));
        assert!(graph_rows_to(&soon, 9).is_none());
        let later = a.poll(t + REFRESH_INTERVAL, (0, 0));
        assert_eq!(graph_rows_to(&later, 9), Some(3));
        for batch in later.into_iter().filter(|batch| batch.peer == 9) {
            deliver(&mut a, &mut b, batch, t + REFRESH_INTERVAL);
        }
        assert!(b.rows.contains_key(&2) && b.rows.contains_key(&3));
        // Now all are sent: no graph at the next refresh.
        let after = a.poll(t + REFRESH_INTERVAL * 2, (0, 0));
        assert!(graph_rows_to(&after, 9).is_none());
    }

    #[test]
    fn a_duplicate_id_is_reported() {
        let now = Instant::now();
        let rng = SystemRandom::new();
        let mut a = node(1, now);
        a.neighbour_up(2, &rng, now).unwrap();
        let sent = a.poll(now, (0, 0));
        let duplicate = SyncRouteResponse {
            error: Some(sync_error::DUPLICATE_PEER_ID),
            ..SyncRouteResponse::default()
        };
        assert_eq!(
            a.on_response(2, sent[0].id, Ok(duplicate), &rng, now)
                .unwrap(),
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

        // About 2 MB: over half the target, so the graph goes alone, first,
        // and the information after it in batches of the target size.
        let batches = a.poll(now, (0, 0));
        assert!(batches.len() >= 2);
        let alone = &batches[0].request;
        assert!(alone.peer_infos.is_empty());
        assert!(alone.encode().len() <= MAX_REQUEST_BYTES);
        let sent = alone.conn_graph.as_ref().unwrap();
        assert!(sent.encode_bitmap().len() <= MAX_GRAPH_BYTES);
        assert_eq!(sent.peers.iter().filter(|(_, v)| *v > 0).count(), count + 1);
        assert_eq!(a.refused().cut_graphs, 0);
        assert!(batches[1..]
            .iter()
            .all(|batch| batch.request.conn_graph.is_none()));
        assert!(batches[1].request.peer_infos.iter().any(|i| i.peer_id == 1));

        // Not again until a row changes. The response carries the session
        // the neighbour used above; another one would make it a new
        // session and send everything again (spec §12.2).
        let response = SyncRouteResponse {
            session_id: 1,
            ..SyncRouteResponse::default()
        };
        for batch in &batches {
            a.on_response(2, batch.id, Ok(response), &rng, now).unwrap();
        }
        let next = a.poll(now + REFRESH_INTERVAL, (0, 0));
        assert_eq!(next.len(), 1);
        assert!(next[0].request.conn_graph.is_none());
        assert!(next[0].request.peer_infos.is_empty());
    }

    #[test]
    fn information_behind_an_unconfirmed_graph_awaits_it() {
        let now = Instant::now();
        let rng = SystemRandom::new();
        let mut a = node(1, now);
        a.neighbour_up(2, &rng, now).unwrap();
        // A chain of 1500 rows: about 280 KB as a bitmap, over half the
        // target, so the graph goes alone.
        let count = 1500usize;
        let ids: Vec<u32> = std::iter::once(2)
            .chain((0..count as u32 - 1).map(|n| 10_000 + n))
            .collect();
        let mut graph = ConnGraph {
            peers: ids.iter().map(|&id| (id, 1)).collect(),
            edges: Vec::new(),
        };
        graph.peers.push((1, 0));
        for row in 0..count - 1 {
            graph.edges.push((row, row + 1));
            graph.edges.push((row + 1, row));
        }
        graph.edges.push((0, count));
        let request = SyncRouteRequest {
            my_peer_id: 2,
            my_session_id: 1,
            conn_graph: Some(graph),
            peer_infos: vec![info(10_005, 5)],
            ..SyncRouteRequest::default()
        };
        a.on_request(2, request, now);
        let mut b = node(3, now);
        connect(&mut a, &mut b, now);

        let batches: Vec<SyncBatch> = a
            .poll(now, (0, 0))
            .into_iter()
            .filter(|batch| batch.peer == 3)
            .collect();
        assert_eq!(batches.len(), 2);
        let (graph, infos) = (&batches[0], &batches[1]);
        assert!(graph.request.conn_graph.is_some() && graph.request.peer_infos.is_empty());
        assert!(infos.request.conn_graph.is_none());
        // The information is answered first: it only awaits the graph.
        let ok = SyncRouteResponse {
            session_id: 7,
            ..SyncRouteResponse::default()
        };
        a.on_response(3, infos.id, Ok(ok), &rng, now).unwrap();
        assert!(a.sessions[&3].sent.infos.is_empty());
        assert_eq!(a.sessions[&3].awaiting.len(), 2);
        // The graph fails: what awaited it is void and goes again with it.
        a.on_response(3, graph.id, Err(Failure::Timeout), &rng, now)
            .unwrap();
        assert!(a.sessions[&3].awaiting.is_empty());
        let t = now + SYNC_INTERVAL;
        let again: Vec<SyncBatch> = a
            .poll(t, (0, 0))
            .into_iter()
            .filter(|batch| batch.peer == 3)
            .collect();
        assert!(again[0].request.conn_graph.is_some());
        assert!(again[1..].iter().any(|batch| batch
            .request
            .peer_infos
            .iter()
            .any(|i| i.peer_id == 10_005)));
        // This time the graph is confirmed first, then the rest is sent.
        for batch in &again {
            a.on_response(3, batch.id, Ok(ok), &rng, t).unwrap();
        }
        let session = &a.sessions[&3];
        assert!(session.awaiting.is_empty());
        assert_eq!(session.sent.infos.get(&10_005), Some(&1));
        assert_eq!(session.sent.infos.get(&1), Some(&1));
        assert!(session.graph_since.is_none());
    }

    #[test]
    fn the_batch_size_halves_on_timeouts_and_doubles_after_successes() {
        let now = Instant::now();
        let rng = SystemRandom::new();
        let mut a = node(1, now);
        a.neighbour_up(2, &rng, now).unwrap();
        let mut t = now;
        let timeout = |a: &mut RouteSync, t: Instant| {
            let batch = a.poll(t, (0, 0)).remove(0);
            a.on_response(2, batch.id, Err(Failure::Timeout), &rng, t)
                .unwrap();
        };
        assert_eq!(a.batch_target(2), Some(BATCH_START));
        for expected in [128, 64, 32, 32] {
            timeout(&mut a, t);
            assert_eq!(a.batch_target(2), Some(expected * 1024));
            t += RETRY_MAX;
        }
        // Three successes in a row double it, up to the top.
        let ok = SyncRouteResponse::default();
        let mut successes = 0;
        for _ in 0..40 {
            t += REFRESH_INTERVAL;
            for batch in a.poll(t, (0, 0)) {
                a.on_response(2, batch.id, Ok(ok), &rng, t).unwrap();
                successes += 1;
            }
            if successes == 3 {
                assert_eq!(a.batch_target(2), Some(64 * 1024));
            }
        }
        assert_eq!(a.batch_target(2), Some(BATCH_MAX));
        // A failure that is no timeout breaks the run but keeps the size.
        t += REFRESH_INTERVAL;
        let batch = a.poll(t, (0, 0)).remove(0);
        a.on_response(2, batch.id, Err(Failure::Error), &rng, t)
            .unwrap();
        assert_eq!(a.batch_target(2), Some(BATCH_MAX));
    }

    #[test]
    fn batches_keep_to_the_target_and_the_window() {
        let now = Instant::now();
        let rng = SystemRandom::new();
        let mut a = node(1, now);
        a.neighbour_up(2, &rng, now).unwrap();
        let big = |id: u32| RoutePeerInfo {
            proxy_cidrs: (0..200)
                .map(|n| format!("10.{}.{}.0/24", n % 250, id % 250))
                .collect(),
            ..info(id, 1)
        };
        let fill = SyncRouteRequest {
            my_peer_id: 2,
            my_session_id: 1,
            peer_infos: (0..2000).map(|n| big(10_000 + n)).collect(),
            ..SyncRouteRequest::default()
        };
        a.on_request(2, fill, now);
        let mut b = node(3, now);
        connect(&mut a, &mut b, now);
        let batches: Vec<SyncBatch> = a
            .poll(now, (0, 0))
            .into_iter()
            .filter(|batch| batch.peer == 3)
            .collect();
        assert!(batches.len() <= IN_FLIGHT_BATCHES);
        let mut total = 0;
        for batch in &batches {
            let size = batch.request.encode().len();
            // A batch with information keeps under the target, but always
            // carries at least one item.
            assert!(size <= BATCH_START || batch.request.peer_infos.len() == 1);
            total += size;
        }
        assert!(total <= IN_FLIGHT_BYTES);
        // Nothing more while the window is full.
        assert!(a
            .poll(now + SYNC_INTERVAL, (0, 0))
            .iter()
            .all(|batch| batch.peer != 3));
    }

    #[test]
    fn a_graph_over_its_limit_keeps_the_nearest_rows() {
        let row = |neighbours: &[u32]| Row {
            version: 1,
            neighbours: neighbours.iter().copied().collect(),
        };
        let rows = [row(&[2]), row(&[1, 3]), row(&[2, 4]), row(&[3, 5])];
        let ordered: Vec<(u32, &Row)> = (1..=4).zip(rows.iter()).collect();
        assert_eq!(graph_rows_within(&ordered, MAX_GRAPH_BYTES), 4);
        // Room for three nodes: this node and its neighbour's row only.
        assert_eq!(graph_rows_within(&ordered, graph_bound(3)), 2);
        assert_eq!(graph_rows_within(&ordered, graph_bound(2)), 1);
        assert_eq!(graph_rows_within(&ordered, 0), 0);
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
        let count = (IN_FLIGHT_BYTES / size) as u32 * 2 + 10;
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
                let batches: Vec<SyncBatch> = nodes[i]
                    .poll(later, (0, 0))
                    .into_iter()
                    .filter(|batch| batch.peer == other)
                    .collect();
                for batch in batches {
                    assert!(batch.request.encode().len() <= MAX_REQUEST_BYTES);
                    let (left, right) = nodes.split_at_mut(1);
                    if i == 0 {
                        deliver(&mut left[0], &mut right[0], batch, later);
                    } else {
                        deliver(&mut right[0], &mut left[0], batch, later);
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
        assert_eq!(a.refused().at_capacity, 0);
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
        // The refusal is counted: the network is larger than the table.
        assert_eq!(a.refused().at_capacity, 1);
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

    #[test]
    fn a_direct_neighbours_information_is_taken_past_the_byte_budget() {
        let now = Instant::now();
        let rng = SystemRandom::new();
        let mut a = node(1, now);
        a.neighbour_up(2, &rng, now).unwrap();
        let fill = SyncRouteRequest {
            my_peer_id: 2,
            my_session_id: 1,
            peer_infos: (0..10).map(|n| info(10_000 + n, 1)).collect(),
            ..SyncRouteRequest::default()
        };
        a.on_request(2, fill, now);
        a.neighbour_up(3, &rng, now).unwrap();
        let own = info(3, 1);
        // One byte short of room for the neighbour's information.
        a.stored_bytes = MAX_STORED_INFO_BYTES - own.encode().len() + 1;
        let request = SyncRouteRequest {
            my_peer_id: 3,
            my_session_id: 1,
            peer_infos: vec![own],
            ..SyncRouteRequest::default()
        };
        a.on_request(3, request, now);
        // Taken, and the farthest other node made room (spec §12.3).
        assert!(a.info(3).is_some());
        assert!(a.info(10_009).is_none());
        assert_eq!(a.infos().count(), 10);
        assert!(a.stored_bytes <= MAX_STORED_INFO_BYTES);
        assert_eq!(a.refused().at_capacity, 1);
        // A stranger's past the budget is refused.
        a.stored_bytes = MAX_STORED_INFO_BYTES;
        let stranger = SyncRouteRequest {
            my_peer_id: 2,
            my_session_id: 1,
            peer_infos: vec![info(99_999, 1)],
            ..SyncRouteRequest::default()
        };
        a.on_request(2, stranger, now);
        assert!(a.info(99_999).is_none());
        assert_eq!(a.refused().over_budget, 1);
    }

    #[test]
    fn the_connection_row_version_running_out_needs_a_new_id() {
        let now = Instant::now();
        let rng = SystemRandom::new();
        let mut a = node(1, now);
        a.own_row.version = u32::MAX - 2;
        a.neighbour_up(2, &rng, now).unwrap();
        assert!(!a.take_conflict());
        a.neighbour_down(2);
        assert_eq!(a.own_row.version, u32::MAX);
        assert!(a.take_conflict());
    }

    #[test]
    fn a_graph_from_the_same_neighbour_keeps_unreachable_information_longer() {
        let now = Instant::now();
        let rng = SystemRandom::new();
        let setup = || {
            let mut a = node(1, now);
            a.neighbour_up(2, &rng, now).unwrap();
            a.neighbour_up(4, &rng, now).unwrap();
            let request = SyncRouteRequest {
                my_peer_id: 2,
                my_session_id: 1,
                peer_infos: vec![info(50, 50)],
                ..SyncRouteRequest::default()
            };
            a.on_request(2, request, now);
            // Node 50 has no connection row yet: unreachable.
            a.expire(now);
            a
        };
        let graph_from = |a: &mut RouteSync, peer: u32, at: Instant| {
            let request = SyncRouteRequest {
                my_peer_id: peer,
                my_session_id: 1,
                conn_graph: Some(ConnGraph {
                    peers: vec![(peer, 1)],
                    edges: Vec::new(),
                }),
                ..SyncRouteRequest::default()
            };
            a.on_request(peer, request, at);
        };
        let graph_at = now + Duration::from_secs(80);

        // A graph from the neighbour that sent the information restarts
        // the 90 seconds (spec §12.2).
        let mut a = setup();
        graph_from(&mut a, 2, graph_at);
        a.expire(now + UNREACHABLE_TTL);
        assert!(a.info(50).is_some());
        a.expire(graph_at + UNREACHABLE_TTL);
        assert!(a.info(50).is_none());

        // One from another neighbour does not.
        let mut a = setup();
        graph_from(&mut a, 4, graph_at);
        a.expire(now + UNREACHABLE_TTL);
        assert!(a.info(50).is_none());
    }
}
