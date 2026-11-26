//! The node's side of custom paths (spec §17.2): the capability cache with
//! its query queue (§17.2.4), the state of every configured path with its
//! timers and hysteresis (§17.2.3), probing (§17.2.6) and the rate limits a
//! waypoint applies to errors and echoes (§17.2.5 rule 6, §17.2.6 rule 4).
//!
//! Free of I/O like [`crate::waypoint`]: the node describes the network
//! through [`Facts`], sends the queries, probes and packets that come out,
//! and feeds back answers, echoes and errors.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::net::IpAddr;
use std::ops::Bound;
use std::time::{Duration, Instant};

use crate::config::{CustomPath, PathTarget};
use crate::net::IpNet;
use crate::waypoint::{
    self, judge_error, Capabilities, Capability, Culprit, DestinationView, Echo, ErrorAction, Held,
    LivePath, Next, PathError, Plan, ProbeState, Reason, Transit, Verdict, WaypointContext,
    WaypointView, ECHO_BUDGET,
};

/// A capability query unanswered this long failed (spec §17.2.4).
pub const QUERY_TIMEOUT: Duration = Duration::from_secs(5);
/// Queries out at once per network (spec §17.2.4).
pub const MAX_QUERIES: usize = 16;
/// Capability entries per network (spec §17.2.4).
pub const MAX_CACHE: usize = 4096;
/// Node IDs waiting for a query triggered by type 40 (spec §17.2.4).
pub const MAX_QUEUE: usize = 256;
/// Queries triggered by type 40 per second (spec §17.2.4).
pub const TRIGGERED_PER_SECOND: u32 = 4;
/// "Supported" and "not relaying" answers are refreshed this often.
pub const REFRESH: Duration = Duration::from_secs(600);
/// First wait after "not supported", doubled each time up to
/// [`BACKOFF_MAX`]; "unknown" waits 5 s and 10 s before backing off too.
pub const BACKOFF_START: Duration = Duration::from_secs(60);
pub const BACKOFF_MAX: Duration = Duration::from_secs(600);
/// Entries used while relaying as a waypoint this recently are kept and
/// queried first (spec §17.2.4).
pub const FORWARDING_PROTECTION: Duration = Duration::from_secs(600);
/// Longest `pending` (spec §17.2.3).
pub const PENDING_LIMIT: Duration = Duration::from_secs(60);
/// How long an accepted path error holds the path in `fallback`.
pub const ERROR_HOLD: Duration = Duration::from_secs(30);
/// A topology or probe cause must stay away this long before a fallback
/// ends; also the least time between two states that are not `fallback`
/// (spec §17.2.3).
pub const RECOVERY: Duration = Duration::from_secs(10);
/// How long a probe waits for its echoes (spec §17.2.6 rule 3).
pub const PROBE_WAIT: Duration = Duration::from_secs(3);
/// Warm-up probes go out this often (spec §17.2.6 rule 7).
pub const WARMUP_INTERVAL: Duration = Duration::from_secs(1);
/// A path used this recently is probed (spec §17.2.6 rule 1).
pub const USED_WINDOW: Duration = Duration::from_secs(60);
/// Echoes per (source, outer sender) per second (spec §17.2.6 rule 4).
pub const ECHO_PAIR_RATE: u32 = 32;
/// Echoes per second for the whole process.
pub const ECHO_RATE: u32 = 1024;
/// Echoes per outer sender per second once the global bucket is below
/// half.
pub const ECHO_SOURCE_RATE: u32 = 64;
/// Path errors per second for the whole process (spec §17.2.5 rule 6).
pub const ERROR_RATE: u32 = 64;
/// Rate-limiter entries kept before idle ones are dropped.
const LIMITER_ENTRIES: usize = 4096;

/// A token bucket that refills `capacity` tokens a second.
#[derive(Clone, Copy, Debug)]
struct Bucket {
    capacity: u32,
    /// Thousandths of a token.
    milli: u64,
    at: Instant,
}

impl Bucket {
    fn full(capacity: u32, now: Instant) -> Self {
        Self {
            capacity,
            milli: u64::from(capacity) * 1000,
            at: now,
        }
    }

    fn refill(&mut self, now: Instant) {
        let elapsed = now.saturating_duration_since(self.at).as_millis();
        let elapsed = u64::try_from(elapsed).unwrap_or(u64::MAX);
        let max = u64::from(self.capacity) * 1000;
        self.milli = self
            .milli
            .saturating_add(elapsed.saturating_mul(u64::from(self.capacity)))
            .min(max);
        self.at = now;
    }

    /// Whole tokens left.
    fn level(&mut self, now: Instant) -> u32 {
        self.refill(now);
        (self.milli / 1000) as u32
    }

    fn take(&mut self, now: Instant) -> bool {
        self.refill(now);
        if self.milli < 1000 {
            return false;
        }
        self.milli -= 1000;
        true
    }

    fn is_full(&mut self, now: Instant) -> bool {
        self.level(now) >= self.capacity
    }
}

/// How a capability query ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Answer {
    Capabilities(Capabilities),
    /// Error 3: the service is unknown there (spec §11.4).
    InvalidService,
    /// A timeout or any other error.
    Failed,
}

#[derive(Clone, Debug)]
struct CapEntry {
    capability: Capability,
    /// The route information version (spec §12.3 field 9) when the last
    /// query went out.
    version: Option<u32>,
    /// When to query next; `None` while a query is out.
    due: Option<Instant>,
    asking: bool,
    /// Failed answers in a row.
    failures: u32,
    /// "Not supported" answers in a row.
    refusals: u32,
    used: Instant,
}

/// What this node knows about other nodes' capabilities (spec §17.2.4).
pub struct CapCache {
    entries: BTreeMap<u32, CapEntry>,
    /// Queries triggered by type 40: (outer sender of that packet, node).
    queue: VecDeque<(u32, u32)>,
    /// The outer sender served last, for the round robin.
    last_source: Option<u32>,
    /// When a node was last used while relaying as a waypoint.
    forwarded: BTreeMap<u32, Instant>,
    triggered: Bucket,
    /// Triggered queries dropped: not in the topology, queue or cache full.
    dropped: u64,
}

fn backoff(times: u32) -> Duration {
    let doublings = times.saturating_sub(1).min(4);
    BACKOFF_START
        .saturating_mul(1 << doublings)
        .min(BACKOFF_MAX)
}

impl CapCache {
    pub fn new(now: Instant) -> Self {
        Self {
            entries: BTreeMap::new(),
            queue: VecDeque::new(),
            last_source: None,
            forwarded: BTreeMap::new(),
            triggered: Bucket::full(TRIGGERED_PER_SECOND, now),
            dropped: 0,
        }
    }

    /// The capability of `id`; [`Capability::Pending`] while unknown.
    pub fn capability(&self, id: u32) -> Capability {
        self.entries
            .get(&id)
            .map_or(Capability::Pending, |entry| entry.capability)
    }

    /// Whether a query for `id` is queued or out without any answer yet.
    pub fn pending(&self, id: u32) -> bool {
        self.entries
            .get(&id)
            .is_some_and(|entry| entry.capability == Capability::Pending)
            || self.queue.iter().any(|(_, queued)| *queued == id)
    }

    /// Triggered queries dropped so far.
    pub fn dropped(&self) -> u64 {
        self.dropped
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    fn protected(&self, id: u32, now: Instant) -> bool {
        self.forwarded
            .get(&id)
            .is_some_and(|at| now.saturating_duration_since(*at) < FORWARDING_PROTECTION)
    }

    /// Adds an entry for `id`, due at once, making room by dropping the
    /// least recently used entry that is neither on a path of this node
    /// (`kept`), nor protected, nor being asked. `false` when the cache is
    /// full of such entries.
    fn insert(&mut self, id: u32, kept: &BTreeSet<u32>, now: Instant) -> bool {
        if self.entries.contains_key(&id) {
            return true;
        }
        if self.entries.len() >= MAX_CACHE {
            let victim = self
                .entries
                .iter()
                .filter(|(id, entry)| {
                    !entry.asking && !kept.contains(id) && !self.protected(**id, now)
                })
                .min_by_key(|(_, entry)| entry.used)
                .map(|(id, _)| *id);
            match victim {
                Some(victim) => {
                    self.entries.remove(&victim);
                }
                None => return false,
            }
        }
        self.entries.insert(
            id,
            CapEntry {
                capability: Capability::Pending,
                version: None,
                due: Some(now),
                asking: false,
                failures: 0,
                refusals: 0,
                used: now,
            },
        );
        true
    }

    /// A waypoint of one of this node's paths: asked at once, without the
    /// limit for triggered queries.
    pub fn want(&mut self, id: u32, kept: &BTreeSet<u32>, now: Instant) {
        if self.insert(id, kept, now) {
            if let Some(entry) = self.entries.get_mut(&id) {
                entry.used = now;
            }
        }
    }

    /// A query a type-40 packet from outer sender `source` calls for
    /// (spec §17.2.4, §17.2.5 rules 5 and 6, §17.2.6 rule 2). Nodes outside
    /// the topology are not asked; past the queue's room the request is
    /// dropped. Both count.
    pub fn trigger(&mut self, id: u32, source: u32, in_topology: bool) {
        if self.entries.contains_key(&id) || self.queue.iter().any(|(_, queued)| *queued == id) {
            return;
        }
        if !in_topology || self.queue.len() >= MAX_QUEUE {
            self.dropped += 1;
            return;
        }
        self.queue.push_back((source, id));
    }

    /// `id` was used while relaying as a waypoint: the next or previous
    /// waypoint, or the source.
    pub fn forwarded(&mut self, id: u32, now: Instant) {
        if self.forwarded.len() >= MAX_CACHE && !self.forwarded.contains_key(&id) {
            self.forwarded
                .retain(|_, at| now.saturating_duration_since(*at) < FORWARDING_PROTECTION);
            if self.forwarded.len() >= MAX_CACHE {
                return;
            }
        }
        self.forwarded.insert(id, now);
        if let Some(entry) = self.entries.get_mut(&id) {
            entry.used = now;
        }
    }

    /// Asks `id` again as soon as a slot is free (error code 3, a changed
    /// route information version).
    pub fn requery(&mut self, id: u32, now: Instant) {
        if let Some(entry) = self.entries.get_mut(&id) {
            if !entry.asking {
                entry.due = Some(now);
            }
        }
    }

    /// Drops what no longer is in the topology (spec §17.2.4), and stale
    /// protection marks.
    pub fn retain(&mut self, in_topology: impl Fn(u32) -> bool, now: Instant) {
        self.entries.retain(|id, _| in_topology(*id));
        self.queue.retain(|(_, id)| in_topology(*id));
        self.forwarded.retain(|id, at| {
            in_topology(*id) && now.saturating_duration_since(*at) < FORWARDING_PROTECTION
        });
    }

    /// The queries to send now: entries that are due, then the queue in
    /// its order (protected nodes first, then one per outer sender in
    /// turn) as far as the rate allows, at most [`MAX_QUERIES`] out at
    /// once. An entry whose route information version changed since its
    /// last query is due at once.
    pub fn take_due(
        &mut self,
        in_topology: impl Fn(u32) -> bool,
        version: impl Fn(u32) -> Option<u32>,
        kept: &BTreeSet<u32>,
        now: Instant,
    ) -> Vec<u32> {
        for (id, entry) in &mut self.entries {
            let current = version(*id);
            if !entry.asking
                && entry.version.is_some()
                && current.is_some()
                && entry.version != current
            {
                entry.due = Some(now);
            }
        }
        let out_now = self.entries.values().filter(|entry| entry.asking).count();
        let mut slots = MAX_QUERIES.saturating_sub(out_now);
        let mut due: Vec<(Instant, u32)> = self
            .entries
            .iter()
            .filter(|(_, entry)| !entry.asking)
            .filter_map(|(id, entry)| entry.due.filter(|due| *due <= now).map(|due| (due, *id)))
            .collect();
        due.sort();
        let mut out = Vec::new();
        for (_, id) in due {
            if slots == 0 {
                break;
            }
            if !in_topology(id) {
                continue;
            }
            self.start(id, version(id));
            out.push(id);
            slots -= 1;
        }
        while slots > 0 && !self.queue.is_empty() && self.triggered.level(now) >= 1 {
            let Some(at) = self.next_queued(now) else {
                break;
            };
            let Some((source, id)) = self.queue.remove(at) else {
                break;
            };
            self.last_source = Some(source);
            if self.entries.contains_key(&id) || !in_topology(id) {
                continue;
            }
            if !self.insert(id, kept, now) {
                self.dropped += 1;
                continue;
            }
            self.triggered.take(now);
            self.start(id, version(id));
            out.push(id);
            slots -= 1;
        }
        out
    }

    fn start(&mut self, id: u32, version: Option<u32>) {
        if let Some(entry) = self.entries.get_mut(&id) {
            entry.asking = true;
            entry.due = None;
            entry.version = version;
        }
    }

    /// The queue position to serve next: a protected node first, else the
    /// first node of the next outer sender after the one served last.
    fn next_queued(&self, now: Instant) -> Option<usize> {
        if let Some(at) = self
            .queue
            .iter()
            .position(|(_, id)| self.protected(*id, now))
        {
            return Some(at);
        }
        let sources: BTreeSet<u32> = self.queue.iter().map(|(source, _)| *source).collect();
        let source = self
            .last_source
            .and_then(|last| {
                sources
                    .range((Bound::Excluded(last), Bound::Unbounded))
                    .next()
                    .copied()
            })
            .or_else(|| sources.first().copied())?;
        self.queue.iter().position(|(from, _)| *from == source)
    }

    /// Records how the query for `id` ended and when to ask again (spec
    /// §17.2.4). Returns whether the capability changed.
    pub fn answered(&mut self, id: u32, answer: Answer, now: Instant) -> bool {
        let Some(entry) = self.entries.get_mut(&id) else {
            return false;
        };
        if !entry.asking {
            return false;
        }
        entry.asking = false;
        let capability = match answer {
            Answer::Capabilities(caps) => caps.capability(),
            Answer::InvalidService => Capability::Unsupported,
            Answer::Failed => Capability::Unknown,
        };
        let wait = match capability {
            Capability::Supported | Capability::NotRelay => {
                entry.failures = 0;
                entry.refusals = 0;
                REFRESH
            }
            Capability::Unsupported => {
                entry.failures = 0;
                entry.refusals = entry.refusals.saturating_add(1);
                backoff(entry.refusals)
            }
            Capability::Unknown | Capability::Pending => {
                entry.refusals = 0;
                entry.failures = entry.failures.saturating_add(1);
                match entry.failures {
                    1 => Duration::from_secs(5),
                    2 => Duration::from_secs(10),
                    n => backoff(n - 2),
                }
            }
        };
        entry.due = Some(now + wait);
        let changed = entry.capability != capability;
        entry.capability = capability;
        changed
    }
}

/// The rate limits of a waypoint on path errors and echoes.
struct Limits {
    errors_sent: BTreeMap<(u32, u8, u32), Instant>,
    errors: Bucket,
    echo_pairs: BTreeMap<(u32, u32), Bucket>,
    echo_sources: BTreeMap<u32, Bucket>,
    echoes: Bucket,
}

impl Limits {
    fn new(now: Instant) -> Self {
        Self {
            errors_sent: BTreeMap::new(),
            errors: Bucket::full(ERROR_RATE, now),
            echo_pairs: BTreeMap::new(),
            echo_sources: BTreeMap::new(),
            echoes: Bucket::full(ECHO_RATE, now),
        }
    }

    /// One error a second per (source, code, failed node), 64 a second in
    /// all (spec §17.2.5 rule 6).
    fn error(&mut self, error: &PathError, now: Instant) -> bool {
        let key = (error.origin, error.code as u8, error.failed);
        let second = Duration::from_secs(1);
        if self
            .errors_sent
            .get(&key)
            .is_some_and(|at| now.saturating_duration_since(*at) < second)
        {
            return false;
        }
        if !self.errors.take(now) {
            return false;
        }
        if self.errors_sent.len() >= LIMITER_ENTRIES {
            self.errors_sent
                .retain(|_, at| now.saturating_duration_since(*at) < second);
        }
        self.errors_sent.insert(key, now);
        true
    }

    /// The three layers of spec §17.2.6 rule 4: per (source, outer sender),
    /// for the whole process, and per outer sender other than the source
    /// once the process bucket is below half. Tokens are taken only when
    /// the echo goes out.
    fn echo(&mut self, origin: u32, outer: u32, now: Instant) -> bool {
        if self.echo_pairs.len() >= LIMITER_ENTRIES {
            self.echo_pairs.retain(|_, bucket| !bucket.is_full(now));
        }
        if self.echo_sources.len() >= LIMITER_ENTRIES {
            self.echo_sources.retain(|_, bucket| !bucket.is_full(now));
        }
        let global = self.echoes.level(now);
        if global == 0 {
            return false;
        }
        let pair = self
            .echo_pairs
            .entry((origin, outer))
            .or_insert_with(|| Bucket::full(ECHO_PAIR_RATE, now));
        if pair.level(now) == 0 {
            return false;
        }
        let from_source = outer == origin;
        if !from_source {
            let source = self
                .echo_sources
                .entry(outer)
                .or_insert_with(|| Bucket::full(ECHO_SOURCE_RATE, now));
            if global < ECHO_RATE / 2 && source.level(now) == 0 {
                return false;
            }
            source.take(now);
        }
        if let Some(pair) = self.echo_pairs.get_mut(&(origin, outer)) {
            pair.take(now);
        }
        self.echoes.take(now);
        true
    }
}

/// What the node knows about the network, for judging paths.
pub trait Facts {
    fn self_id(&self) -> u32;
    /// Reachable nodes whose route information claims `address`.
    fn owners(&self, address: IpAddr) -> Vec<u32>;
    /// Reachable in the topology with a connection to the next hop.
    fn reachable(&self, id: u32) -> bool;
    /// A direct neighbour.
    fn direct(&self, id: u32) -> bool;
    /// Hops of the default route between two nodes, if any.
    fn hops(&self, from: u32, to: u32) -> Option<u32>;
    /// The advertiser in use for `subnet` (spec §15.2).
    fn advertiser(&self, subnet: &IpNet) -> Option<u32>;
    /// Secure mode without `native_keys`: a direct destination falls back
    /// (spec §17.2.5, inner packet).
    fn unverified_direct(&self) -> bool;
    /// Listed in the topology (route information known).
    fn in_topology(&self, id: u32) -> bool;
    /// Route information version (spec §12.3 field 9).
    fn version(&self, id: u32) -> Option<u32>;
    /// A virtual address of a node, for the status.
    fn address(&self, id: u32) -> Option<IpAddr>;
}

/// Probing of one encapsulated waypoint sequence.
struct Sequence {
    probe: ProbeState,
    destination: u32,
    /// Tokens of the open rounds and when they close, oldest first.
    open: Vec<(u64, Instant)>,
    next_at: Option<Instant>,
    /// Periodic probing is needed (a path used recently or held by
    /// probes); warm-up probes regardless.
    needed: bool,
    /// A path would encapsulate through it now. One that is not (its
    /// waypoint briefly unreachable, say) keeps its probe state for
    /// [`USED_WINDOW`] without probing, so it need not warm up again.
    referenced: bool,
    last_referenced: Instant,
}

/// One configured path and its state.
struct Entry {
    path: CustomPath,
    destination: Option<u32>,
    plan: Plan,
    since: Instant,
    pending_since: Option<Instant>,
    /// The path timed out in `pending`: its fallback names this node until
    /// the sequence is ready (spec §17.2.3).
    timed_out: Option<Culprit>,
    error_hold: Option<(Held, Instant)>,
    /// The current fallback came from a path error (its hold is the wait).
    by_error: bool,
    /// Error code 2 while this node cannot reach B either (spec §17.2.5
    /// rule 7): the state stays, B is reported unreachable.
    destination_down: Option<Instant>,
    clear_since: Option<Instant>,
    used: Option<Instant>,
    /// The encapsulated waypoints of the plan before probes are judged.
    sequence: Option<Vec<u32>>,
    /// Waypoint node IDs as resolved last, in configured order.
    ids: Vec<Option<u32>>,
    /// The path left the `pending` it starts in at least once. Before
    /// that, an unreachable waypoint or destination keeps it `pending`
    /// (bounded by the 60 s timeout): right after start or a new list the
    /// topology is still being learnt (spec §17.2.8).
    started: bool,
}

impl Entry {
    fn new(path: CustomPath, now: Instant) -> Self {
        let ids = vec![None; path.via.len()];
        Self {
            path,
            destination: None,
            plan: Plan::Pending,
            since: now,
            pending_since: Some(now),
            timed_out: None,
            error_hold: None,
            by_error: false,
            destination_down: None,
            clear_since: None,
            used: None,
            sequence: None,
            ids,
            started: false,
        }
    }
}

/// How the node sends one IP packet that matched a path.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Route {
    /// Default routing (spec §13).
    Default,
    /// Encapsulate through these waypoints (spec §17.2.5).
    Encapsulate(Vec<u32>),
    /// Plain packet through the connection to this neighbour.
    FirstHop(u32),
}

/// What to do with an outgoing IP packet.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Outbound {
    pub route: Route,
    /// Lower the MSS of a TCP SYN or SYN-ACK to this (spec §17.2.5, size,
    /// rule 2).
    pub mss: Option<u16>,
}

impl Outbound {
    const DEFAULT: Self = Self {
        route: Route::Default,
        mss: None,
    };
}

/// A probe to send: to `waypoints[0]`, carrying the rest.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Probe {
    pub waypoints: Vec<u32>,
    pub destination: u32,
    pub token: u64,
}

/// The outer header of a type-40 packet that reached its waypoint.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Outer {
    pub from: u32,
    pub forward_counter: u8,
    pub latency_first: bool,
}

/// What a waypoint sends after a Forward or Probe (rate limits and the
/// source's capability already applied).
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Relayed {
    pub echo: Option<Echo>,
    pub error: Option<PathError>,
    pub next: Option<Next>,
    /// The inner packet to relay to (or handle as) its destination.
    pub release: Option<Vec<u8>>,
}

/// Counters for the status.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PathCounters {
    /// Type-40 packets a waypoint dropped: malformed, failed checks, or a
    /// next waypoint it has not confirmed.
    pub dropped: u64,
    /// Packets sent by default routing because the outer packet would
    /// exceed 1424 bytes (spec §17.2.5, size, rule 1).
    pub oversize: u64,
    /// Path errors refused by the source (spec §17.2.5 rule 7).
    pub refused_errors: u64,
    /// Echoes that matched no open probe.
    pub refused_echoes: u64,
    /// Errors and echoes over the rate limits.
    pub limited: u64,
    /// Triggered capability queries dropped (spec §17.2.4).
    pub dropped_queries: u64,
    /// Echoes with status 2 (spec §17.2.6 rule 3).
    pub not_encapsulable: u64,
}

/// One path in the status (`mesh-status.md`, `paths[]`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PathStatus {
    pub id: String,
    pub target: PathTarget,
    pub via: Vec<IpAddr>,
    pub state: &'static str,
    pub reason: Option<Reason>,
    /// The node the reason names.
    pub unreachable: Option<IpAddr>,
}

/// Custom paths of one network.
pub struct PathRuntime {
    paths: Vec<CustomPath>,
    entries: Vec<Entry>,
    caps: CapCache,
    sequences: BTreeMap<Vec<u32>, Sequence>,
    limits: Limits,
    /// Sequences in the current probe layout.
    layout: Vec<Vec<u32>>,
    /// Probes sent through each waypoint in the current second.
    budget: BTreeMap<u32, (Instant, u32)>,
    counters: PathCounters,
    /// Whether this network can carry type 40 at all: an inner packet must
    /// be encrypted (spec §17.2.5 rule 3), so a network without encryption
    /// does not relay it.
    encrypted: bool,
}

impl PathRuntime {
    pub fn new(paths: Vec<CustomPath>, encrypted: bool, now: Instant) -> Self {
        let entries = paths
            .iter()
            .cloned()
            .map(|path| Entry::new(path, now))
            .collect();
        Self {
            paths,
            entries,
            caps: CapCache::new(now),
            sequences: BTreeMap::new(),
            limits: Limits::new(now),
            layout: Vec::new(),
            budget: BTreeMap::new(),
            counters: PathCounters::default(),
            encrypted,
        }
    }

    pub fn paths(&self) -> &[CustomPath] {
        &self.paths
    }

    /// Replaces the path list (spec §17.2.8). A path whose target and
    /// waypoints did not change keeps its state; new ones start `pending`.
    pub fn set_paths(&mut self, paths: Vec<CustomPath>, now: Instant) {
        let mut old: Vec<Entry> = std::mem::take(&mut self.entries);
        self.entries = paths
            .iter()
            .cloned()
            .map(
                |path| match old.iter().position(|entry| entry.path == path) {
                    Some(at) => old.swap_remove(at),
                    None => Entry::new(path, now),
                },
            )
            .collect();
        self.paths = paths;
    }

    pub fn counters(&self) -> PathCounters {
        PathCounters {
            dropped_queries: self.caps.dropped(),
            ..self.counters
        }
    }

    pub fn count_dropped(&mut self) {
        self.counters.dropped += 1;
    }

    pub fn count_oversize(&mut self) {
        self.counters.oversize += 1;
    }

    pub fn capability(&self, id: u32) -> Capability {
        self.caps.capability(id)
    }

    /// Node IDs on this node's paths: their cache entries are kept.
    fn kept(&self) -> BTreeSet<u32> {
        self.entries
            .iter()
            .flat_map(|entry| entry.ids.iter().flatten().copied())
            .collect()
    }

    /// Re-judges every path (spec §17.2.3): after a topology change, a
    /// capability answer, an echo or error, and once a second.
    pub fn evaluate(&mut self, facts: &dyn Facts, now: Instant) {
        // Resolve the waypoints first so their queries go out at once.
        for entry in &mut self.entries {
            entry.ids = entry
                .path
                .via
                .iter()
                .map(|address| single(facts.owners(*address)))
                .collect();
        }
        let kept = self.kept();
        for id in &kept {
            self.caps.want(*id, &kept, now);
        }
        let Self {
            entries,
            caps,
            sequences,
            encrypted,
            ..
        } = self;
        for sequence in sequences.values_mut() {
            sequence.referenced = false;
        }
        for entry in entries.iter_mut() {
            judge(entry, caps, sequences, *encrypted, facts, now);
        }
        // Sequences no path has encapsulated through for a while go.
        sequences.retain(|_, sequence| {
            sequence.referenced
                || now.saturating_duration_since(sequence.last_referenced) < USED_WINDOW
        });
        for (key, sequence) in sequences.iter_mut() {
            sequence.needed = entries.iter().any(|entry| {
                entry.sequence.as_ref() == Some(key)
                    && (entry
                        .used
                        .is_some_and(|used| now.saturating_duration_since(used) < USED_WINDOW)
                        || matches!(sequence.probe.verdict(), Verdict::Held { .. }))
            });
        }
    }

    /// The capability queries to send now (spec §17.2.4).
    pub fn take_queries(&mut self, facts: &dyn Facts, now: Instant) -> Vec<u32> {
        let kept = self.kept();
        self.caps.retain(|id| facts.in_topology(id), now);
        self.caps.take_due(
            |id| facts.in_topology(id),
            |id| facts.version(id),
            &kept,
            now,
        )
    }

    /// A capability query ended. Sequences through a node whose capability
    /// changed warm up again (spec §17.2.6 rule 7).
    pub fn answered(&mut self, id: u32, answer: Answer, now: Instant) {
        if self.caps.answered(id, answer, now) {
            for (key, sequence) in &mut self.sequences {
                if key.contains(&id) {
                    sequence.probe.rewarm();
                    sequence.open.clear();
                    sequence.next_at = Some(now);
                }
            }
        }
    }

    /// Closes the probe rounds whose 3 s are up.
    pub fn close_rounds(&mut self, now: Instant) {
        for sequence in self.sequences.values_mut() {
            while let Some(&(token, deadline)) = sequence.open.first() {
                if deadline > now {
                    break;
                }
                sequence.open.remove(0);
                sequence.probe.finish(token);
            }
        }
    }

    /// The probes to send now (spec §17.2.6 rules 1 and 7). Warm-up sends
    /// one a second; periodic probes go every T seconds, spread over T in
    /// the order of the sequences with a small jitter. No waypoint gets
    /// more than 16 probes in one second; a probe over that waits for the
    /// next second (one at a time, so the wait does not bunch them).
    pub fn probes(&mut self, random: &mut dyn FnMut() -> u64, now: Instant) -> Vec<Probe> {
        let periodic: Vec<Vec<u32>> = self
            .sequences
            .iter()
            .filter(|(_, sequence)| {
                sequence.referenced && !sequence.probe.warming() && sequence.needed
            })
            .map(|(key, _)| key.clone())
            .collect();
        let mut per_waypoint: BTreeMap<u32, u32> = BTreeMap::new();
        for key in self
            .sequences
            .iter()
            .filter(|(_, sequence)| {
                sequence.referenced && (sequence.probe.warming() || sequence.needed)
            })
            .map(|(key, _)| key)
        {
            for id in key {
                *per_waypoint.entry(*id).or_default() += 1;
            }
        }
        let busiest = per_waypoint.values().copied().max().unwrap_or(0);
        let interval = Duration::from_secs(u64::from(waypoint::probe_interval(busiest)));
        if periodic != self.layout {
            // New phases: i × T / m plus up to T / (2m) of jitter.
            let m = periodic.len().max(1) as u32;
            let slot = interval / m;
            for (i, key) in periodic.iter().enumerate() {
                if let Some(sequence) = self.sequences.get_mut(key) {
                    let jitter_ms = (slot / 2).as_millis().max(1) as u64;
                    let jitter = Duration::from_millis(random() % jitter_ms);
                    sequence.next_at = Some(now + slot * i as u32 + jitter);
                }
            }
            self.layout = periodic;
        }
        let second = Duration::from_secs(1);
        self.budget
            .retain(|_, (start, _)| now.saturating_duration_since(*start) < second);
        let mut out = Vec::new();
        for (key, sequence) in &mut self.sequences {
            let warming = sequence.probe.warming();
            if !sequence.referenced || (!warming && !sequence.needed) {
                continue;
            }
            let due = sequence.next_at.is_none_or(|at| at <= now);
            if !due {
                continue;
            }
            let full = key.iter().any(|id| {
                self.budget
                    .get(id)
                    .is_some_and(|(_, sent)| *sent >= ECHO_BUDGET)
            });
            if full {
                sequence.next_at = Some(now + second);
                continue;
            }
            for id in key {
                let slot = self.budget.entry(*id).or_insert((now, 0));
                slot.1 += 1;
            }
            let token = random();
            if sequence.probe.start(token).is_some() {
                // The oldest round was closed to make room.
                sequence.open.remove(0);
            }
            sequence.open.push((token, now + PROBE_WAIT));
            let step = if warming { WARMUP_INTERVAL } else { interval };
            sequence.next_at = Some(match sequence.next_at {
                Some(at) if at + step > now => at + step,
                _ => now + step,
            });
            out.push(Probe {
                waypoints: key.clone(),
                destination: sequence.destination,
                token,
            });
        }
        out
    }

    /// An echo from outer sender `from` (spec §17.2.6 rule 4, last
    /// sentence). A round that now has every echo closes at once. Returns
    /// whether a round closed.
    pub fn on_echo(&mut self, echo: &Echo, from: u32, self_id: u32) -> bool {
        if echo.origin != self_id {
            self.counters.refused_echoes += 1;
            return false;
        }
        for sequence in self.sequences.values_mut() {
            if !sequence.probe.waypoints().contains(&from) || !sequence.probe.echo(echo, from) {
                continue;
            }
            if echo.status == waypoint::EchoStatus::NotEncapsulable {
                self.counters.not_encapsulable += 1;
            }
            if sequence.probe.answered_all(echo.token) {
                sequence.open.retain(|(token, _)| *token != echo.token);
                sequence.probe.finish(echo.token);
                return true;
            }
            return false;
        }
        self.counters.refused_echoes += 1;
        false
    }

    /// A path error from outer sender `reporter` (spec §17.2.5 rule 7).
    /// Returns whether it was accepted.
    pub fn on_error(
        &mut self,
        error: &PathError,
        reporter: u32,
        facts: &dyn Facts,
        now: Instant,
    ) -> bool {
        if error.origin != facts.self_id() {
            self.counters.refused_errors += 1;
            return false;
        }
        let mut accepted = false;
        let mut requery = Vec::new();
        for entry in &mut self.entries {
            if entry.destination != Some(error.destination) {
                continue;
            }
            let action = match entry.plan.encapsulated() {
                Some(waypoints) => judge_error(
                    error,
                    reporter,
                    &LivePath {
                        destination: error.destination,
                        waypoints,
                        destination_reachable: facts.reachable(error.destination),
                    },
                ),
                None => continue,
            };
            match action {
                ErrorAction::Ignore => {}
                ErrorAction::Fallback { reason, failed } => {
                    let culprit = if failed == error.destination {
                        Culprit::Destination
                    } else {
                        entry
                            .ids
                            .iter()
                            .position(|id| *id == Some(failed))
                            .map_or(Culprit::Destination, Culprit::Waypoint)
                    };
                    entry.error_hold = Some((Held { reason, culprit }, now + ERROR_HOLD));
                    accepted = true;
                }
                ErrorAction::DestinationDown => {
                    entry.destination_down = Some(now);
                    accepted = true;
                }
                ErrorAction::Requery(id) => {
                    requery.push(id);
                    accepted = true;
                }
            }
        }
        for id in requery {
            self.caps.requery(id, now);
        }
        if !accepted {
            self.counters.refused_errors += 1;
        }
        accepted
    }

    /// A Forward or Probe that reached this node as a waypoint (spec
    /// §17.2.5 rules 1–6, §17.2.6 rules 2 and 4).
    pub fn relay(
        &mut self,
        transit: &Transit<'_>,
        outer: Outer,
        relays: bool,
        facts: &dyn Facts,
        now: Instant,
    ) -> Relayed {
        let probe = matches!(transit.body, waypoint::Body::Probe(_));
        // Queries this packet calls for, before judging it, so that a probe
        // held up by one echoes status 1.
        let mut wanted = Vec::new();
        if probe && outer.from != transit.origin {
            wanted.push(outer.from);
        }
        if let Some(next) = transit.remaining.first() {
            wanted.push(*next);
        }
        wanted.push(transit.origin);
        for id in wanted {
            self.caps.trigger(id, outer.from, facts.in_topology(id));
        }
        let step = {
            let caps = &self.caps;
            let reachable = |id: u32| facts.reachable(id);
            let supported = |id: u32| caps.capability(id) == Capability::Supported;
            let pending = |id: u32| caps.pending(id);
            waypoint::step(
                transit,
                &WaypointContext {
                    self_id: facts.self_id(),
                    relays: relays && self.encrypted,
                    forward_counter: outer.forward_counter,
                    latency_first: outer.latency_first,
                    reachable: &reachable,
                    outer_from: outer.from,
                    supported: &supported,
                    pending: &pending,
                },
            )
        };
        if step.report.is_none()
            && step.echo.is_none()
            && step.next.is_none()
            && step.release.is_none()
        {
            self.counters.dropped += 1;
            return Relayed::default();
        }
        // Errors and echoes go only to a source that understands type 40;
        // its query was started above otherwise (spec §17.2.5 rule 6).
        let answers = self.caps.capability(transit.origin).understands_type_40();
        let mut out = Relayed {
            next: step.next,
            release: step.release,
            ..Relayed::default()
        };
        if out.next.is_some() || out.release.is_some() {
            self.caps.forwarded(transit.origin, now);
            self.caps.forwarded(outer.from, now);
            if let Some(next) = &out.next {
                self.caps.forwarded(next.to, now);
            }
        }
        if let (Some(echo), true) = (step.echo, answers) {
            if self.limits.echo(transit.origin, outer.from, now) {
                out.echo = Some(echo);
            } else {
                // Over the limit: the probe goes no further either.
                self.counters.limited += 1;
                out.next = None;
            }
        }
        if let Some(error) = step.report {
            self.counters.dropped += 1;
            if answers {
                if self.limits.error(&error, now) {
                    out.error = Some(error);
                } else {
                    self.counters.limited += 1;
                }
            }
        }
        out
    }

    /// How to send an IP packet to `destination` (an address) that goes to
    /// node `b`, whose virtual addresses are `owner` (spec §17.2.2). `member`
    /// tells whether `destination` is a member's virtual address. `None`
    /// when no path matches. A subnet path whose advertiser changed is
    /// judged again first.
    pub fn outbound(
        &mut self,
        destination: IpAddr,
        member: bool,
        b: u32,
        owner: &[IpAddr],
        facts: &dyn Facts,
        now: Instant,
    ) -> Option<Outbound> {
        let index = self.find(destination, member, owner)?;
        if self.entries[index].destination != Some(b) {
            self.entries[index].destination = Some(b);
            self.evaluate(facts, now);
        }
        let entry = &mut self.entries[index];
        entry.used = Some(now);
        let ipv6 = destination.is_ipv6();
        Some(match &entry.plan {
            Plan::Strict(waypoints) | Plan::Prefix { waypoints, .. } => Outbound {
                mss: Some(waypoint::max_mss(waypoints.len() - 1, ipv6)),
                route: Route::Encapsulate(waypoints.clone()),
            },
            Plan::FirstHop { neighbour, .. } => Outbound {
                route: Route::FirstHop(*neighbour),
                mss: None,
            },
            Plan::Pending => Outbound {
                route: Route::Default,
                mss: Some(waypoint::max_mss(
                    entry.path.via.len().saturating_sub(1),
                    ipv6,
                )),
            },
            Plan::Direct | Plan::Fallback { .. } => Outbound::DEFAULT,
        })
    }

    /// The MSS limit for a TCP SYN or SYN-ACK that arrived from the network
    /// with source address `source`, sent by a node whose virtual addresses
    /// are `sender` (spec §17.2.5, size, rule 2, matched by source).
    pub fn inbound_mss(&self, source: IpAddr, member: bool, sender: &[IpAddr]) -> Option<u16> {
        let index = self.find(source, member, sender)?;
        let entry = &self.entries[index];
        let ipv6 = source.is_ipv6();
        match &entry.plan {
            Plan::Strict(waypoints) | Plan::Prefix { waypoints, .. } => {
                Some(waypoint::max_mss(waypoints.len() - 1, ipv6))
            }
            Plan::Pending => Some(waypoint::max_mss(
                entry.path.via.len().saturating_sub(1),
                ipv6,
            )),
            _ => None,
        }
    }

    fn find(&self, address: IpAddr, member: bool, owner: &[IpAddr]) -> Option<usize> {
        if owner.is_empty() {
            return waypoint::match_path(&self.paths, address, member, None);
        }
        owner
            .iter()
            .find_map(|owner| waypoint::match_path(&self.paths, address, member, Some(*owner)))
    }

    /// The paths for the status (`mesh-status.md`, `paths[]`).
    pub fn status(&self, facts: &dyn Facts, now: Instant) -> Vec<PathStatus> {
        self.entries
            .iter()
            .map(|entry| {
                let named = |culprit: Culprit| match culprit {
                    Culprit::Waypoint(at) => entry.path.via.get(at).copied(),
                    Culprit::Destination => match entry.path.target {
                        PathTarget::Peer(address) => Some(address),
                        PathTarget::Subnet(_) => entry.destination.and_then(|b| facts.address(b)),
                    },
                };
                let (reason, culprit) = match &entry.plan {
                    Plan::Fallback { reason, culprit } => (Some(*reason), Some(*culprit)),
                    Plan::Prefix {
                        reason, culprit, ..
                    }
                    | Plan::FirstHop {
                        reason, culprit, ..
                    } => (Some(*reason), Some(Culprit::Waypoint(*culprit))),
                    _ => (None, None),
                };
                let down = entry
                    .destination_down
                    .is_some_and(|at| now.saturating_duration_since(at) < ERROR_HOLD);
                let (reason, culprit) = if down && reason.is_none() {
                    (Some(Reason::Unreachable), Some(Culprit::Destination))
                } else {
                    (reason, culprit)
                };
                PathStatus {
                    id: waypoint::status_id(&entry.path.target),
                    target: entry.path.target,
                    via: entry.path.via.clone(),
                    state: entry.plan.state(),
                    reason,
                    unreachable: culprit.and_then(named),
                }
            })
            .collect()
    }
}

fn single(ids: Vec<u32>) -> Option<u32> {
    match ids.as_slice() {
        [id] => Some(*id),
        _ => None,
    }
}

/// Judges one path and commits its new state under the hysteresis of spec
/// §17.2.3.
fn judge(
    entry: &mut Entry,
    caps: &CapCache,
    sequences: &mut BTreeMap<Vec<u32>, Sequence>,
    encrypted: bool,
    facts: &dyn Facts,
    now: Instant,
) {
    let destination = match entry.path.target {
        PathTarget::Peer(address) => single(facts.owners(address)),
        PathTarget::Subnet(subnet) => entry
            .destination
            .filter(|b| facts.reachable(*b))
            .or_else(|| facts.advertiser(&subnet)),
    };
    entry.destination = destination;
    if entry
        .destination_down
        .is_some_and(|at| now.saturating_duration_since(at) >= ERROR_HOLD)
        || destination.is_some_and(|b| facts.reachable(b))
    {
        entry.destination_down = None;
    }
    if entry.error_hold.is_some_and(|(_, until)| now >= until) {
        entry.error_hold = None;
    }
    let error_held = entry.error_hold.map(|(held, _)| held);
    let unheld = match destination {
        None => Plan::Fallback {
            reason: Reason::Unreachable,
            culprit: Culprit::Destination,
        },
        Some(b) => {
            let cut = entry
                .ids
                .iter()
                .position(|id| *id == Some(b))
                .unwrap_or(entry.ids.len());
            let mut views = Vec::with_capacity(cut);
            let mut previous = facts.self_id();
            for id in &entry.ids[..cut] {
                let id = *id;
                // Hop counts only estimate; one the topology cannot tell
                // counts as 0 and path errors cover the rest.
                let hops = |from: u32, to: u32| facts.hops(from, to).unwrap_or(0);
                views.push(WaypointView {
                    id,
                    reachable: id.is_some_and(|id| facts.reachable(id)),
                    direct: id.is_some_and(|id| facts.direct(id)),
                    capability: match id {
                        // A network without encryption cannot carry type 40.
                        Some(_) if !encrypted => Capability::Unsupported,
                        Some(id) => caps.capability(id),
                        None => Capability::Pending,
                    },
                    // A managed network admits native members only (spec
                    // §8.3.1); without native_keys there is no such check.
                    native: true,
                    hops_in: id.map_or(0, |id| hops(previous, id)),
                    hops_to_destination: id.map_or(0, |id| hops(id, b)),
                });
                if let Some(id) = id {
                    previous = id;
                }
            }
            let view = DestinationView {
                direct_unverified: facts.unverified_direct() && facts.direct(b),
            };
            waypoint::plan(&views, view, None)
        }
    };
    // An accepted path error holds the path; the sequence it would use
    // stays warm meanwhile, so the path comes back without warming up.
    let base = match error_held {
        Some(held) if unheld != Plan::Direct => Plan::Fallback {
            reason: held.reason,
            culprit: held.culprit,
        },
        _ => unheld.clone(),
    };
    let sequence = unheld.encapsulated().map(<[u32]>::to_vec);
    let mut candidate = base.clone();
    if let (Some(key), Some(b)) = (&sequence, destination) {
        let state = sequences.entry(key.clone()).or_insert_with(|| Sequence {
            probe: ProbeState::new(key.clone()),
            destination: b,
            open: Vec::new(),
            next_at: None,
            needed: false,
            referenced: true,
            last_referenced: now,
        });
        state.referenced = true;
        state.last_referenced = now;
        if entry.timed_out.is_some() {
            // No warm-up after a pending timeout (spec §17.2.3).
            state.probe.give_up();
        }
        let verdict = state.probe.verdict();
        match verdict {
            // Held by an error: that fallback stands.
            _ if base != unheld => {}
            Verdict::Warming => candidate = Plan::Pending,
            Verdict::Held { waypoint, reason } => {
                candidate = Plan::Fallback {
                    reason,
                    culprit: Culprit::Waypoint(waypoint),
                }
            }
            Verdict::Ready => entry.timed_out = None,
        }
    }
    entry.sequence = sequence;
    if let Some(culprit) = entry.timed_out {
        match candidate {
            Plan::Pending => {
                candidate = Plan::Fallback {
                    reason: Reason::PendingTimeout,
                    culprit,
                }
            }
            // Probes after the timeout have not recovered yet.
            Plan::Fallback {
                reason: Reason::NoEcho,
                ..
            } if entry.sequence.is_some() => {
                candidate = Plan::Fallback {
                    reason: Reason::PendingTimeout,
                    culprit,
                }
            }
            Plan::Fallback { .. } => {}
            _ => entry.timed_out = None,
        }
    }
    if !entry.started
        && matches!(
            candidate,
            Plan::Fallback {
                reason: Reason::Unreachable,
                ..
            }
        )
    {
        candidate = Plan::Pending;
    }
    if candidate == Plan::Pending {
        let since = *entry.pending_since.get_or_insert(now);
        if now.saturating_duration_since(since) >= PENDING_LIMIT {
            let probe = entry
                .sequence
                .as_ref()
                .and_then(|key| sequences.get_mut(key));
            let stalled = probe.as_ref().and_then(|state| state.probe.stalled());
            let culprit = stalled
                .or_else(|| {
                    entry.ids.iter().position(|id| {
                        id.is_none_or(|id| caps.capability(id) == Capability::Pending)
                    })
                })
                .unwrap_or(0);
            if let Some(state) = probe {
                state.probe.give_up();
            }
            let culprit = Culprit::Waypoint(culprit);
            entry.timed_out = Some(culprit);
            candidate = Plan::Fallback {
                reason: Reason::PendingTimeout,
                culprit,
            };
        }
    } else {
        entry.pending_since = None;
    }
    commit(entry, candidate, error_held.is_some(), now);
}

/// Commits `candidate` (spec §17.2.3): a fallback at once; out of a
/// fallback only after its cause stayed away 10 s (an error's own 30 s
/// hold is its wait); between two other states at most every 10 s;
/// `pending` at once.
fn commit(entry: &mut Entry, candidate: Plan, by_error: bool, now: Instant) {
    let to_fallback = matches!(candidate, Plan::Fallback { .. });
    if to_fallback {
        entry.clear_since = None;
    }
    if entry.plan == candidate {
        return;
    }
    let from_fallback = matches!(entry.plan, Plan::Fallback { .. });
    let pending = candidate == Plan::Pending || entry.plan == Plan::Pending;
    let ready = if to_fallback {
        true
    } else if from_fallback {
        entry.by_error || {
            let clear = *entry.clear_since.get_or_insert(now);
            now.saturating_duration_since(clear) >= RECOVERY
        }
    } else {
        pending || now.saturating_duration_since(entry.since) >= RECOVERY
    };
    if ready {
        entry.started |= candidate != Plan::Pending;
        entry.by_error = to_fallback && by_error;
        entry.plan = candidate;
        entry.since = now;
        entry.clear_since = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::waypoint::{Body, EchoStatus, ErrorCode};

    const A: u32 = 1;
    const W: u32 = 2;
    const B: u32 = 3;
    const X: u32 = 4;

    /// A network seen from node 1, every node reachable and one hop away
    /// unless changed.
    struct World {
        addresses: BTreeMap<u32, IpAddr>,
        unreachable: BTreeSet<u32>,
        direct: BTreeSet<u32>,
        unverified_direct: bool,
    }

    fn address(id: u32) -> IpAddr {
        IpAddr::from([10, 144, 0, id as u8])
    }

    impl World {
        fn new() -> Self {
            Self {
                addresses: [W, B, X].into_iter().map(|id| (id, address(id))).collect(),
                unreachable: BTreeSet::new(),
                direct: [W].into_iter().collect(),
                unverified_direct: false,
            }
        }
    }

    impl Facts for World {
        fn self_id(&self) -> u32 {
            A
        }
        fn owners(&self, address: IpAddr) -> Vec<u32> {
            self.addresses
                .iter()
                .filter(|(id, own)| **own == address && self.reachable(**id))
                .map(|(id, _)| *id)
                .collect()
        }
        fn reachable(&self, id: u32) -> bool {
            self.addresses.contains_key(&id) && !self.unreachable.contains(&id)
        }
        fn direct(&self, id: u32) -> bool {
            self.direct.contains(&id)
        }
        fn hops(&self, from: u32, to: u32) -> Option<u32> {
            Some(u32::from(from != to))
        }
        fn advertiser(&self, _subnet: &IpNet) -> Option<u32> {
            Some(B)
        }
        fn unverified_direct(&self) -> bool {
            self.unverified_direct
        }
        fn in_topology(&self, id: u32) -> bool {
            self.addresses.contains_key(&id)
        }
        fn version(&self, _id: u32) -> Option<u32> {
            Some(1)
        }
        fn address(&self, id: u32) -> Option<IpAddr> {
            self.addresses.get(&id).copied()
        }
    }

    fn path(via: &[u32]) -> CustomPath {
        CustomPath {
            target: PathTarget::Peer(address(B)),
            via: via.iter().map(|id| address(*id)).collect(),
        }
    }

    fn supported() -> Answer {
        Answer::Capabilities(Capabilities::local(true))
    }

    fn state(runtime: &PathRuntime, world: &World, now: Instant) -> (&'static str, Option<Reason>) {
        let status = runtime.status(world, now);
        (status[0].state, status[0].reason)
    }

    /// Answers every query from `answer` and every probe in full.
    fn answer_all(
        runtime: &mut PathRuntime,
        world: &World,
        answer: impl Fn(u32) -> Answer,
        now: Instant,
    ) {
        for id in runtime.take_queries(world, now) {
            runtime.answered(id, answer(id), now);
        }
        runtime.evaluate(world, now);
    }

    fn echo_all(runtime: &mut PathRuntime, probe: &Probe) -> bool {
        let mut closed = false;
        for waypoint in &probe.waypoints {
            let echo = Echo {
                origin: A,
                destination: probe.destination,
                waypoint: *waypoint,
                token: probe.token,
                status: EchoStatus::Forwarded,
            };
            closed |= runtime.on_echo(&echo, *waypoint, A);
        }
        closed
    }

    fn counter() -> impl FnMut() -> u64 {
        let mut next = 0u64;
        move || {
            next += 1;
            next
        }
    }

    #[test]
    fn a_path_warms_up_then_encapsulates_and_clamps() {
        let world = World::new();
        let t0 = Instant::now();
        let mut runtime = PathRuntime::new(vec![path(&[W, X])], true, t0);
        runtime.evaluate(&world, t0);
        assert_eq!(state(&runtime, &world, t0), ("pending", None));
        // Pending: default routing, MSS for the configured waypoints.
        let out = runtime
            .outbound(address(B), true, B, &[address(B)], &world, t0)
            .unwrap();
        assert_eq!(out.route, Route::Default);
        assert_eq!(out.mss, Some(waypoint::max_mss(1, false)));
        assert_eq!(runtime.take_queries(&world, t0), vec![W, X]);
        runtime.answered(W, supported(), t0);
        runtime.answered(X, supported(), t0);
        runtime.evaluate(&world, t0);
        // Warming up: still pending, a probe goes out at once.
        assert_eq!(state(&runtime, &world, t0).0, "pending");
        let mut random = counter();
        let probes = runtime.probes(&mut random, t0);
        assert_eq!(probes.len(), 1);
        assert_eq!(probes[0].waypoints, vec![W, X]);
        assert_eq!(probes[0].destination, B);
        // Only one a second while warming.
        assert!(runtime.probes(&mut random, t0).is_empty());
        assert!(echo_all(&mut runtime, &probes[0]));
        runtime.evaluate(&world, t0);
        assert_eq!(state(&runtime, &world, t0), ("active", None));
        let out = runtime
            .outbound(address(B), true, B, &[address(B)], &world, t0)
            .unwrap();
        assert_eq!(out.route, Route::Encapsulate(vec![W, X]));
        assert_eq!(out.mss, Some(waypoint::max_mss(1, false)));
        assert_eq!(
            runtime.inbound_mss(address(B), true, &[address(B)]),
            Some(waypoint::max_mss(1, false))
        );
        // Another destination has no path.
        assert!(runtime
            .outbound(address(X), true, X, &[address(X)], &world, t0)
            .is_none());
    }

    #[test]
    fn a_waypoint_that_never_answers_times_out_and_comes_back_slowly() {
        let world = World::new();
        let t0 = Instant::now();
        let mut runtime = PathRuntime::new(vec![path(&[W])], true, t0);
        runtime.evaluate(&world, t0);
        assert_eq!(runtime.take_queries(&world, t0), vec![W]);
        let t59 = t0 + Duration::from_secs(59);
        runtime.evaluate(&world, t59);
        assert_eq!(state(&runtime, &world, t59).0, "pending");
        let t60 = t0 + PENDING_LIMIT;
        runtime.evaluate(&world, t60);
        let status = runtime.status(&world, t60);
        assert_eq!(status[0].state, "fallback");
        assert_eq!(status[0].reason, Some(Reason::PendingTimeout));
        assert_eq!(status[0].unreachable, Some(address(W)));
        // The answer arrives: no warm-up and no pending again; two clean
        // probe rounds and 10 s are needed.
        runtime.answered(W, supported(), t60);
        runtime.evaluate(&world, t60);
        assert_eq!(state(&runtime, &world, t60).1, Some(Reason::PendingTimeout));
        let mut random = counter();
        let mut now = t60;
        let mut rounds = 0;
        while state(&runtime, &world, now).0 == "fallback" {
            now += Duration::from_secs(1);
            runtime.close_rounds(now);
            for probe in runtime.probes(&mut random, now) {
                echo_all(&mut runtime, &probe);
                rounds += 1;
            }
            runtime.evaluate(&world, now);
            assert_ne!(state(&runtime, &world, now).0, "pending");
            assert!(now < t60 + Duration::from_secs(60));
        }
        assert_eq!(state(&runtime, &world, now), ("active", None));
        assert!(rounds >= 2);
        assert!(now >= t60 + RECOVERY);
    }

    #[test]
    fn path_errors_hold_the_path_for_thirty_seconds() {
        let world = World::new();
        let t0 = Instant::now();
        let mut runtime = PathRuntime::new(vec![path(&[W, X])], true, t0);
        runtime.evaluate(&world, t0);
        answer_all(&mut runtime, &world, |_| supported(), t0);
        let probe = runtime.probes(&mut counter(), t0).remove(0);
        echo_all(&mut runtime, &probe);
        runtime.evaluate(&world, t0);
        assert_eq!(state(&runtime, &world, t0).0, "active");
        // An error that does not fit the path is refused.
        let wrong = PathError {
            code: ErrorCode::NextUnreachable,
            origin: A,
            destination: B,
            failed: B,
        };
        assert!(!runtime.on_error(&wrong, W, &world, t0));
        assert_eq!(runtime.counters().refused_errors, 1);
        let error = PathError { failed: X, ..wrong };
        assert!(runtime.on_error(&error, W, &world, t0));
        runtime.evaluate(&world, t0);
        let status = runtime.status(&world, t0);
        assert_eq!(status[0].state, "fallback");
        assert_eq!(status[0].reason, Some(Reason::Unreachable));
        assert_eq!(status[0].unreachable, Some(address(X)));
        let t29 = t0 + Duration::from_secs(29);
        runtime.evaluate(&world, t29);
        assert_eq!(state(&runtime, &world, t29).0, "fallback");
        // The hold is the wait: back at once when it ends.
        let t30 = t0 + ERROR_HOLD;
        runtime.evaluate(&world, t30);
        assert_eq!(state(&runtime, &world, t30), ("active", None));
        // Code 3 only asks again.
        let not_relay = PathError {
            code: ErrorCode::NotRelay,
            failed: W,
            ..error
        };
        assert!(runtime.on_error(&not_relay, W, &world, t30));
        assert_eq!(runtime.take_queries(&world, t30), vec![W]);
        runtime.evaluate(&world, t30);
        assert_eq!(state(&runtime, &world, t30).0, "active");
    }

    #[test]
    fn falling_back_is_immediate_and_recovery_waits_ten_seconds() {
        let mut world = World::new();
        let t0 = Instant::now();
        let mut runtime = PathRuntime::new(vec![path(&[W])], true, t0);
        runtime.evaluate(&world, t0);
        answer_all(&mut runtime, &world, |_| supported(), t0);
        let probe = runtime.probes(&mut counter(), t0).remove(0);
        echo_all(&mut runtime, &probe);
        runtime.evaluate(&world, t0);
        assert_eq!(state(&runtime, &world, t0).0, "active");
        world.unreachable.insert(W);
        let t1 = t0 + Duration::from_secs(1);
        runtime.evaluate(&world, t1);
        let status = runtime.status(&world, t1);
        assert_eq!(status[0].state, "fallback");
        assert_eq!(status[0].reason, Some(Reason::Unreachable));
        assert_eq!(status[0].unreachable, Some(address(W)));
        world.unreachable.clear();
        let t2 = t0 + Duration::from_secs(2);
        runtime.evaluate(&world, t2);
        assert_eq!(state(&runtime, &world, t2).0, "fallback");
        let t11 = t2 + Duration::from_secs(9);
        runtime.evaluate(&world, t11);
        assert_eq!(state(&runtime, &world, t11).0, "fallback");
        let t12 = t2 + RECOVERY;
        runtime.evaluate(&world, t12);
        assert_eq!(state(&runtime, &world, t12).0, "active");
    }

    #[test]
    fn partly_encapsulable_paths_and_first_hops() {
        let world = World::new();
        let t0 = Instant::now();
        let mut runtime = PathRuntime::new(vec![path(&[W, X])], true, t0);
        runtime.evaluate(&world, t0);
        answer_all(
            &mut runtime,
            &world,
            |id| {
                if id == W {
                    supported()
                } else {
                    Answer::InvalidService
                }
            },
            t0,
        );
        let probe = runtime.probes(&mut counter(), t0).remove(0);
        assert_eq!(probe.waypoints, vec![W]);
        echo_all(&mut runtime, &probe);
        runtime.evaluate(&world, t0);
        let status = runtime.status(&world, t0);
        assert_eq!(status[0].state, "first_hop_only");
        assert_eq!(status[0].reason, Some(Reason::Unsupported));
        assert_eq!(status[0].unreachable, Some(address(X)));
        let out = runtime
            .outbound(address(B), true, B, &[address(B)], &world, t0)
            .unwrap();
        assert_eq!(out.route, Route::Encapsulate(vec![W]));
        assert_eq!(out.mss, Some(waypoint::max_mss(0, false)));
        // Without encryption nothing is encapsulable: the first hop is
        // kept by the connection to the direct neighbour.
        let mut plain = PathRuntime::new(vec![path(&[W, X])], false, t0);
        plain.evaluate(&world, t0);
        answer_all(&mut plain, &world, |_| supported(), t0);
        let out = plain
            .outbound(address(B), true, B, &[address(B)], &world, t0)
            .unwrap();
        assert_eq!(out.route, Route::FirstHop(W));
        assert_eq!(out.mss, None);
    }

    #[test]
    fn a_direct_unverified_destination_falls_back() {
        let mut world = World::new();
        world.unverified_direct = true;
        world.direct.insert(B);
        let t0 = Instant::now();
        let mut runtime = PathRuntime::new(vec![path(&[W])], true, t0);
        runtime.evaluate(&world, t0);
        let status = runtime.status(&world, t0);
        assert_eq!(status[0].state, "fallback");
        assert_eq!(status[0].reason, Some(Reason::Unsupported));
        assert_eq!(status[0].unreachable, Some(address(B)));
    }

    #[test]
    fn capability_answers_back_off() {
        let t0 = Instant::now();
        let mut cache = CapCache::new(t0);
        let kept: BTreeSet<u32> = [W].into_iter().collect();
        let all = |_: u32| true;
        let version = |_: u32| Some(1);
        cache.want(W, &kept, t0);
        assert_eq!(cache.capability(W), Capability::Pending);
        assert!(cache.pending(W));
        let mut now = t0;
        let ask = |cache: &mut CapCache, now: Instant| cache.take_due(all, version, &kept, now);
        assert_eq!(ask(&mut cache, now), vec![W]);
        // Out already: not asked twice.
        assert!(ask(&mut cache, now).is_empty());
        for wait in [5u64, 10, 60, 120] {
            cache.answered(W, Answer::Failed, now);
            assert_eq!(cache.capability(W), Capability::Unknown);
            assert!(!cache.pending(W));
            assert!(ask(&mut cache, now + Duration::from_secs(wait - 1)).is_empty());
            now += Duration::from_secs(wait);
            assert_eq!(ask(&mut cache, now), vec![W]);
        }
        assert!(cache.answered(W, supported(), now));
        assert!(ask(&mut cache, now + REFRESH - Duration::from_secs(1)).is_empty());
        cache.requery(W, now);
        assert_eq!(ask(&mut cache, now), vec![W]);
        assert!(!cache.answered(W, supported(), now));
        // A changed route information version asks again at once.
        let newer =
            |cache: &mut CapCache, now: Instant| cache.take_due(all, |_: u32| Some(2), &kept, now);
        assert_eq!(newer(&mut cache, now), vec![W]);
        for wait in [60u64, 120, 240, 480, 600, 600] {
            cache.answered(W, Answer::InvalidService, now);
            assert_eq!(cache.capability(W), Capability::Unsupported);
            assert!(newer(&mut cache, now + Duration::from_secs(wait - 1)).is_empty());
            now += Duration::from_secs(wait);
            assert_eq!(newer(&mut cache, now), vec![W]);
        }
        // Gone from the topology: forgotten.
        cache.retain(|_| false, now);
        assert!(cache.is_empty());
    }

    #[test]
    fn at_most_sixteen_queries_are_out() {
        let t0 = Instant::now();
        let mut cache = CapCache::new(t0);
        let kept: BTreeSet<u32> = (100..120).collect();
        for id in &kept {
            cache.want(*id, &kept, t0);
        }
        let first = cache.take_due(|_| true, |_| None, &kept, t0);
        assert_eq!(first.len(), MAX_QUERIES);
        assert!(cache.take_due(|_| true, |_| None, &kept, t0).is_empty());
        cache.answered(first[0], Answer::Failed, t0);
        assert_eq!(cache.take_due(|_| true, |_| None, &kept, t0).len(), 1);
        // Nodes outside the topology are not asked.
        let mut other = CapCache::new(t0);
        other.want(7, &kept, t0);
        assert!(other.take_due(|_| false, |_| None, &kept, t0).is_empty());
    }

    #[test]
    fn triggered_queries_are_rate_limited_and_take_turns() {
        let t0 = Instant::now();
        let mut cache = CapCache::new(t0);
        let kept = BTreeSet::new();
        // Source 50 asks for many nodes, source 60 for one.
        for id in 1000..1300u32 {
            cache.trigger(id, 50, true);
        }
        assert_eq!(cache.dropped(), (300 - MAX_QUEUE) as u64);
        cache.trigger(5000, 60, true);
        assert_eq!(cache.dropped(), (300 - MAX_QUEUE + 1) as u64);
        // Off the topology: dropped, never queued.
        let mut fresh = CapCache::new(t0);
        fresh.trigger(9, 50, false);
        assert_eq!(fresh.dropped(), 1);
        assert!(!fresh.pending(9));
        // Make room for source 60 and a protected node.
        let mut cache = CapCache::new(t0);
        for id in 1000..1010u32 {
            cache.trigger(id, 50, true);
        }
        cache.trigger(5000, 60, true);
        cache.forwarded(1009, t0);
        cache.trigger(1009, 50, true);
        assert!(cache.pending(5000));
        let first = cache.take_due(|_| true, |_| None, &kept, t0);
        // Four a second: the protected node, then the sources in turn.
        assert_eq!(first, vec![1009, 5000, 1000, 1001]);
        assert!(cache.take_due(|_| true, |_| None, &kept, t0).is_empty());
        let later = cache.take_due(|_| true, |_| None, &kept, t0 + Duration::from_secs(1));
        assert_eq!(later.len(), 4);
    }

    #[test]
    fn echoes_are_limited_in_three_layers() {
        let t0 = Instant::now();
        let mut limits = Limits::new(t0);
        // (i) 32 per (source, outer sender).
        let sent = (0..40).filter(|_| limits.echo(A, A, t0)).count();
        assert_eq!(sent, ECHO_PAIR_RATE as usize);
        // Another pair is not affected.
        assert!(limits.echo(A, W, t0));
        // A second later the pair has its tokens again.
        assert!(limits.echo(A, A, t0 + Duration::from_secs(1)));
        // (ii) and (iii): one outer sender forging many sources is held to
        // 64 a second once the process bucket is below half; the first
        // waypoint's own echoes still pass.
        let mut limits = Limits::new(t0);
        let mut forged = 0;
        for origin in 0..2000u32 {
            if limits.echo(origin + 100, X, t0) {
                forged += 1;
            }
        }
        assert!(forged <= ECHO_SOURCE_RATE as usize + (ECHO_RATE / 2) as usize);
        let mut others = 0;
        for origin in 0..300u32 {
            if limits.echo(origin + 10_000, origin + 10_000, t0) {
                others += 1;
            }
        }
        assert!(others > 0);
        let total = forged + others;
        assert!(total <= ECHO_RATE as usize);
    }

    #[test]
    fn errors_are_limited_per_kind_and_overall() {
        let t0 = Instant::now();
        let mut limits = Limits::new(t0);
        let error = PathError {
            code: ErrorCode::NextUnreachable,
            origin: A,
            destination: B,
            failed: X,
        };
        assert!(limits.error(&error, t0));
        assert!(!limits.error(&error, t0 + Duration::from_millis(999)));
        assert!(limits.error(&error, t0 + Duration::from_secs(1)));
        let mut limits = Limits::new(t0);
        let sent = (0..100u32)
            .filter(|failed| {
                limits.error(
                    &PathError {
                        failed: *failed,
                        ..error
                    },
                    t0,
                )
            })
            .count();
        assert_eq!(sent, ERROR_RATE as usize);
    }

    #[test]
    fn a_waypoint_echoes_forwards_and_reports_only_to_known_sources() {
        let world = World::new();
        let t0 = Instant::now();
        let mut runtime = PathRuntime::new(Vec::new(), true, t0);
        // Probe from B (as source) through this node (1) to X.
        let transit = Transit {
            origin: B,
            destination: W,
            remaining: vec![X],
            body: Body::Probe(7),
        };
        let outer = Outer {
            from: B,
            forward_counter: 1,
            latency_first: false,
        };
        // Nothing known yet: X and B are queued; status 1, no echo sent.
        let out = runtime.relay(&transit, outer, true, &world, t0);
        assert_eq!(out, Relayed::default());
        assert!(runtime.caps.pending(X) && runtime.caps.pending(B));
        for id in runtime.take_queries(&world, t0) {
            runtime.answered(id, supported(), t0);
        }
        let out = runtime.relay(&transit, outer, true, &world, t0);
        let echo = out.echo.unwrap();
        assert_eq!((echo.waypoint, echo.token), (A, 7));
        assert_eq!(echo.status, EchoStatus::Forwarded);
        let next = out.next.unwrap();
        assert_eq!((next.to, next.forward_counter), (X, 2));
        // Not relaying: a probe is dropped without an error.
        let out = runtime.relay(&transit, outer, false, &world, t0);
        assert_eq!(out.next, None);
        assert_eq!(out.error, None, "probes never cause errors");
    }
}
