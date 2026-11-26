//! Custom paths (spec §17.2, requirements R7–R9, R25): which path a packet
//! takes, how a path's state follows the waypoints' reachability,
//! capability and probes, and the waypoint packet (type 40) that carries a
//! packet through every waypoint in order.
//!
//! Everything here is free of I/O and of the node's state: the node passes
//! in what it knows (topology, capability answers, path errors, probe
//! echoes) and sends what comes out. Timers (hold-downs, the probe wait)
//! and the decision whether a node may receive type 40 at all (its
//! capability answer, spec §17.2.5) are the node's.

use std::collections::BTreeSet;
use std::net::IpAddr;

use crate::config::{CustomPath, PathTarget};
use crate::wire::header::{
    flags, packet_type, NodeHeader, HEADER_LEN, LATENCY_FIRST_MAX_COUNTER, MAX_FORWARD_COUNTER,
};

/// Encapsulation version this node speaks (spec §17.2.5).
pub const VERSION: u8 = 1;
/// Most remaining waypoints one packet carries (spec §17.2.4, §17.2.5).
pub const MAX_REMAINING: usize = 6;
/// Bytes before the remaining waypoint list.
pub const PREFIX_LEN: usize = 12;
/// Bytes of a whole path error payload.
pub const ERROR_LEN: usize = PREFIX_LEN + 4;
/// Bytes of a whole echo payload.
pub const ECHO_LEN: usize = PREFIX_LEN + 4 + 8;
/// Encryption tail (spec §7.3, §8.6).
const TAIL: usize = 28;
/// Smallest inner packet: a node header and an encryption tail.
const MIN_INNER: usize = HEADER_LEN + TAIL;
/// Most segments a path may span: 7 relays (spec §4.4).
pub const MAX_SEGMENTS: u32 = MAX_FORWARD_COUNTER as u32 + 1;

const KIND_FORWARD: u8 = 1;
const KIND_ERROR: u8 = 2;
const KIND_PROBE: u8 = 3;
const KIND_ECHO: u8 = 4;

/// Name of the private capability service (spec §11.4, §17.2.4).
pub const RPC_SERVICE: &str = "MeshPathRpc";
/// Method number of `Capabilities`.
pub const RPC_CAPABILITIES: u32 = 1;

/// Path error codes (spec §17.2.5 rule 6).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ErrorCode {
    /// The next waypoint is unreachable from the reporting waypoint.
    NextUnreachable = 1,
    /// The destination is unreachable from the last waypoint.
    DestinationUnreachable = 2,
    /// The reporting waypoint does not relay.
    NotRelay = 3,
    /// The forward counter ran out.
    HopLimit = 4,
}

impl ErrorCode {
    fn from_u8(value: u8) -> Option<Self> {
        Some(match value {
            1 => Self::NextUnreachable,
            2 => Self::DestinationUnreachable,
            3 => Self::NotRelay,
            4 => Self::HopLimit,
            _ => return None,
        })
    }
}

/// What a Forward or a Probe carries after the waypoint list.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Body<'a> {
    /// The source's whole packet to the destination, header included,
    /// still encrypted for the destination.
    Data(&'a [u8]),
    /// A probe token (spec §17.2.6).
    Probe(u64),
}

/// A decoded Forward or Probe: travels through the remaining waypoints.
#[derive(Debug, PartialEq, Eq)]
pub struct Transit<'a> {
    pub origin: u32,
    pub destination: u32,
    pub remaining: Vec<u32>,
    pub body: Body<'a>,
}

/// A decoded path error (spec §17.2.5 rule 6).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PathError {
    pub code: ErrorCode,
    pub origin: u32,
    pub destination: u32,
    pub failed: u32,
}

/// What an echoing waypoint did with the probe towards its next waypoint
/// (offset 3 of an Echo, spec §17.2.6 rule 2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EchoStatus {
    /// Sent on, or this was the last waypoint.
    Forwarded,
    /// The next waypoint's capability query is queued or running.
    Pending,
    /// The next waypoint is not "supported" in this node's cache. Reserved
    /// values read as this one.
    NotEncapsulable,
    /// The next waypoint is unreachable in this node's topology.
    Unreachable,
}

impl EchoStatus {
    pub fn from_u8(value: u8) -> Self {
        match value {
            0 => Self::Forwarded,
            1 => Self::Pending,
            3 => Self::Unreachable,
            _ => Self::NotEncapsulable,
        }
    }

    pub fn as_u8(self) -> u8 {
        match self {
            Self::Forwarded => 0,
            Self::Pending => 1,
            Self::NotEncapsulable => 2,
            Self::Unreachable => 3,
        }
    }
}

/// A decoded probe echo (spec §17.2.6).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Echo {
    pub origin: u32,
    pub destination: u32,
    /// The waypoint that answered.
    pub waypoint: u32,
    pub token: u64,
    pub status: EchoStatus,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Payload<'a> {
    Transit(Transit<'a>),
    Error(PathError),
    Echo(Echo),
}

fn prefix(out: &mut Vec<u8>, kind: u8, count: usize, code: u8, origin: u32, destination: u32) {
    out.extend_from_slice(&[VERSION, kind, count as u8, code]);
    out.extend_from_slice(&origin.to_le_bytes());
    out.extend_from_slice(&destination.to_le_bytes());
}

/// Builds a Forward or Probe payload (spec §17.2.5).
pub fn encode_transit(origin: u32, destination: u32, remaining: &[u32], body: Body<'_>) -> Vec<u8> {
    assert!(remaining.len() <= MAX_REMAINING);
    let (kind, tail): (u8, &[u8]) = match body {
        Body::Data(inner) => (KIND_FORWARD, inner),
        Body::Probe(_) => (KIND_PROBE, &[]),
    };
    let mut out = Vec::with_capacity(PREFIX_LEN + 4 * remaining.len() + tail.len().max(8));
    prefix(&mut out, kind, remaining.len(), 0, origin, destination);
    for id in remaining {
        out.extend_from_slice(&id.to_le_bytes());
    }
    match body {
        Body::Data(inner) => out.extend_from_slice(inner),
        Body::Probe(token) => out.extend_from_slice(&token.to_le_bytes()),
    }
    out
}

/// Builds a path error payload (spec §17.2.5 rule 6).
pub fn encode_error(error: &PathError) -> Vec<u8> {
    let mut out = Vec::with_capacity(ERROR_LEN);
    prefix(
        &mut out,
        KIND_ERROR,
        0,
        error.code as u8,
        error.origin,
        error.destination,
    );
    out.extend_from_slice(&error.failed.to_le_bytes());
    out
}

/// Builds an echo payload (spec §17.2.6).
pub fn encode_echo(echo: &Echo) -> Vec<u8> {
    let mut out = Vec::with_capacity(ECHO_LEN);
    prefix(
        &mut out,
        KIND_ECHO,
        0,
        echo.status.as_u8(),
        echo.origin,
        echo.destination,
    );
    out.extend_from_slice(&echo.waypoint.to_le_bytes());
    out.extend_from_slice(&echo.token.to_le_bytes());
    out
}

fn u32_at(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap())
}

fn u64_at(bytes: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(bytes[at..at + 8].try_into().unwrap())
}

/// Reads a decrypted type-40 payload. Checks everything that does not need
/// the receiver's identity (spec §17.2.5 rules 2 and 3, the fixed lengths,
/// rule 7's shape); `None` means drop and count.
pub fn decode(payload: &[u8]) -> Option<Payload<'_>> {
    if payload.len() < PREFIX_LEN || payload[0] != VERSION {
        return None;
    }
    let count = usize::from(payload[2]);
    let origin = u32_at(payload, 4);
    let destination = u32_at(payload, 8);
    match payload[1] {
        KIND_ERROR => {
            if payload.len() != ERROR_LEN || count != 0 {
                return None;
            }
            Some(Payload::Error(PathError {
                code: ErrorCode::from_u8(payload[3])?,
                origin,
                destination,
                failed: u32_at(payload, 12),
            }))
        }
        KIND_ECHO => {
            if payload.len() != ECHO_LEN || count != 0 {
                return None;
            }
            Some(Payload::Echo(Echo {
                origin,
                destination,
                waypoint: u32_at(payload, 12),
                token: u64_at(payload, 16),
                status: EchoStatus::from_u8(payload[3]),
            }))
        }
        kind @ (KIND_FORWARD | KIND_PROBE) => {
            if payload[3] != 0 || count > MAX_REMAINING {
                return None;
            }
            let list_end = PREFIX_LEN + 4 * count;
            if payload.len() < list_end {
                return None;
            }
            let remaining: Vec<u32> = (0..count)
                .map(|i| u32_at(payload, PREFIX_LEN + 4 * i))
                .collect();
            let mut seen = BTreeSet::new();
            for id in &remaining {
                if *id == origin || *id == destination || !seen.insert(*id) {
                    return None;
                }
            }
            let rest = &payload[list_end..];
            let body = if kind == KIND_PROBE {
                if rest.len() != 8 {
                    return None;
                }
                Body::Probe(u64_at(rest, 0))
            } else {
                if rest.len() < MIN_INNER {
                    return None;
                }
                let header = NodeHeader::decode(rest)?;
                if header.from != origin
                    || header.to != destination
                    || header.packet_type != packet_type::DATA
                    || !header.has(flags::ENCRYPTED)
                {
                    return None;
                }
                Body::Data(rest)
            };
            Some(Payload::Transit(Transit {
                origin,
                destination,
                remaining,
                body,
            }))
        }
        _ => None,
    }
}

/// What a waypoint does with a Forward or Probe it received (spec §17.2.5
/// rules 1–6, §17.2.6 rule 2).
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Step {
    /// Send this error to the source; the transit is dropped. The node
    /// sends it only when the source's capability answer allows (rule 6).
    pub report: Option<PathError>,
    /// Send this echo to the source (probes only), under the same rule.
    pub echo: Option<Echo>,
    /// Wrap again for the next waypoint.
    pub next: Option<Next>,
    /// This was the last waypoint of a Forward: relay this packet (the
    /// inner packet with its counter rewritten) towards its destination as
    /// in spec §14, or handle it locally when the destination is this
    /// node.
    pub release: Option<Vec<u8>>,
}

/// A type-40 packet from this node to the next waypoint.
#[derive(Debug, PartialEq, Eq)]
pub struct Next {
    pub to: u32,
    pub forward_counter: u8,
    /// Keep LATENCY_FIRST on the outer header (spec §4.4 applied to the new
    /// counter).
    pub latency_first: bool,
    pub payload: Vec<u8>,
}

/// What the waypoint knows about itself and the topology.
pub struct WaypointContext<'a> {
    pub self_id: u32,
    /// Full node with relaying on.
    pub relays: bool,
    /// The outer header's forward counter.
    pub forward_counter: u8,
    /// The outer header's LATENCY_FIRST flag.
    pub latency_first: bool,
    /// Whether a node is reachable in this node's topology.
    pub reachable: &'a dyn Fn(u32) -> bool,
    /// The outer header's `from_peer_id`.
    pub outer_from: u32,
    /// Whether this node's capability cache holds "supported" for a node
    /// (and `native` where the network has `native_keys`): the next
    /// waypoint must be, and a probe's outer sender must be the source or
    /// such a node (spec §17.2.5 rule 5, §17.2.6 rule 2). The node starts
    /// a query for unknown members itself.
    pub supported: &'a dyn Fn(u32) -> bool,
    /// Whether this node's capability query for a node is queued or
    /// running; a probe held up by it echoes status 1 (spec §17.2.4,
    /// §17.2.6 rule 2).
    pub pending: &'a dyn Fn(u32) -> bool,
}

/// Decides what a waypoint does with `transit` (already decoded). An empty
/// step means drop and count.
pub fn step(transit: &Transit<'_>, cx: &WaypointContext<'_>) -> Step {
    let probe = matches!(transit.body, Body::Probe(_));
    let error = |code, failed| {
        // Probes never cause errors (spec §17.2.5 rule 6).
        let report = (!probe).then_some(PathError {
            code,
            origin: transit.origin,
            destination: transit.destination,
            failed,
        });
        Step {
            report,
            ..Step::default()
        }
    };
    if transit.remaining.contains(&cx.self_id)
        || transit.origin == cx.self_id
        // A packet that reached its destination while waypoints remain
        // is malformed: never forward it on (a probe ends there as well).
        || (transit.destination == cx.self_id && (probe || !transit.remaining.is_empty()))
        || (probe && cx.outer_from != transit.origin && !(cx.supported)(cx.outer_from))
    {
        return Step::default();
    }
    if !cx.relays {
        return error(ErrorCode::NotRelay, cx.self_id);
    }
    if cx.forward_counter > MAX_FORWARD_COUNTER {
        return error(ErrorCode::HopLimit, cx.self_id);
    }
    let echo = match transit.body {
        Body::Probe(token) => Some(Echo {
            origin: transit.origin,
            destination: transit.destination,
            waypoint: cx.self_id,
            token,
            status: EchoStatus::Forwarded,
        }),
        Body::Data(_) => None,
    };
    let held = |status| echo.map(|echo| Echo { status, ..echo });
    let counter = cx.forward_counter + 1;
    match (transit.remaining.split_first(), transit.body) {
        (Some((&next, rest)), body) => {
            if !(cx.reachable)(next) {
                let mut step = error(ErrorCode::NextUnreachable, next);
                step.echo = held(EchoStatus::Unreachable);
                return step;
            }
            if !(cx.supported)(next) {
                // Never send type 40 to an unconfirmed node; no error.
                let status = if (cx.pending)(next) {
                    EchoStatus::Pending
                } else {
                    EchoStatus::NotEncapsulable
                };
                return Step {
                    echo: held(status),
                    ..Step::default()
                };
            }
            Step {
                echo,
                next: Some(Next {
                    to: next,
                    forward_counter: counter,
                    latency_first: cx.latency_first && counter <= LATENCY_FIRST_MAX_COUNTER,
                    payload: encode_transit(transit.origin, transit.destination, rest, body),
                }),
                ..Step::default()
            }
        }
        (None, Body::Probe(_)) => Step {
            echo,
            ..Step::default()
        },
        (None, Body::Data(inner)) => {
            if transit.destination != cx.self_id && !(cx.reachable)(transit.destination) {
                return error(ErrorCode::DestinationUnreachable, transit.destination);
            }
            let mut packet = inner.to_vec();
            packet[10] = counter;
            Step {
                release: Some(packet),
                ..Step::default()
            }
        }
    }
}

/// The answer of `MeshPathRpc.Capabilities` (spec §17.2.4).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Capabilities {
    pub version: u32,
    pub max_waypoints: u32,
    pub relay: bool,
}

impl Capabilities {
    /// What this node answers.
    pub fn local(relays: bool) -> Self {
        Self {
            version: u32::from(VERSION),
            max_waypoints: MAX_REMAINING as u32,
            relay: relays,
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        if self.version != 0 {
            out.push(0x08);
            varint(&mut out, u64::from(self.version));
        }
        if self.max_waypoints != 0 {
            out.push(0x10);
            varint(&mut out, u64::from(self.max_waypoints));
        }
        if self.relay {
            out.extend_from_slice(&[0x18, 1]);
        }
        out
    }

    /// Reads an answer; unknown fields are skipped. `None` for bytes that
    /// are not a valid message.
    pub fn decode(mut bytes: &[u8]) -> Option<Self> {
        let mut caps = Self {
            version: 0,
            max_waypoints: 0,
            relay: false,
        };
        while !bytes.is_empty() {
            let key = read_varint(&mut bytes)?;
            let (field, wire) = (key >> 3, key & 7);
            match wire {
                0 => {
                    let value = read_varint(&mut bytes)?;
                    match field {
                        1 => caps.version = u32::try_from(value).ok()?,
                        2 => caps.max_waypoints = u32::try_from(value).ok()?,
                        3 => caps.relay = value != 0,
                        _ => {}
                    }
                }
                1 => bytes = bytes.get(8..)?,
                2 => {
                    let len = usize::try_from(read_varint(&mut bytes)?).ok()?;
                    bytes = bytes.get(len..)?;
                }
                5 => bytes = bytes.get(4..)?,
                _ => return None,
            }
        }
        Some(caps)
    }

    /// What the answer means for paths (spec §17.2.4): a node that does
    /// not relay is "not relaying" whatever its version, so the first-hop
    /// policy never sends through it; version 0 that relays (a network
    /// without encryption) is "not supported".
    pub fn capability(&self) -> Capability {
        match (self.version >= 1, self.relay) {
            (true, true) => Capability::Supported,
            (_, false) => Capability::NotRelay,
            (false, true) => Capability::Unsupported,
        }
    }
}

fn varint(out: &mut Vec<u8>, mut value: u64) {
    while value >= 0x80 {
        out.push(value as u8 | 0x80);
        value >>= 7;
    }
    out.push(value as u8);
}

fn read_varint(bytes: &mut &[u8]) -> Option<u64> {
    let mut value = 0u64;
    for i in 0..10 {
        let byte = *bytes.first()?;
        *bytes = &bytes[1..];
        value |= u64::from(byte & 0x7f) << (7 * i);
        if byte & 0x80 == 0 {
            return Some(value);
        }
    }
    None
}

/// What this node knows about another node's capability (spec §17.2.4).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Capability {
    /// Not asked yet or the answer is outstanding.
    Pending,
    /// Supports encapsulation and relays.
    Supported,
    /// Knows type 40 but does not relay.
    NotRelay,
    /// Error 3 or version 0: a reference node or an older one of ours.
    Unsupported,
    /// The query timed out or failed otherwise.
    Unknown,
}

impl Capability {
    /// Whether the node may be sent errors and echoes (spec §17.2.5 rule
    /// 6).
    pub fn understands_type_40(self) -> bool {
        matches!(self, Self::Supported | Self::NotRelay)
    }
}

/// One waypoint as the source sees it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WaypointView {
    /// Node ID; `None` when no member has the configured address.
    pub id: Option<u32>,
    /// Reachable in the topology with a connection to the next hop, and
    /// the address is claimed by one node ID only.
    pub reachable: bool,
    /// A direct neighbour of this node.
    pub direct: bool,
    /// The capability of the current node ID.
    pub capability: Capability,
    /// `false` when the network has `native_keys` and this node's
    /// implementation is not `native` (spec §17.2.3).
    pub native: bool,
    /// Hops of the default route from the previous point (this node, or
    /// the previous waypoint) to this waypoint.
    pub hops_in: u32,
    /// Hops of the default route from this waypoint to the destination.
    pub hops_to_destination: u32,
}

impl WaypointView {
    fn encapsulable(&self) -> bool {
        self.capability == Capability::Supported && self.native
    }

    /// Why this waypoint cannot be encapsulated through.
    fn refusal(&self) -> Reason {
        match self.capability {
            Capability::NotRelay => Reason::NotRelay,
            Capability::Unknown => Reason::Unreachable,
            _ => Reason::Unsupported,
        }
    }
}

/// Why a path fell back or is only partly kept (spec §17.2.7; status
/// `path.reason`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reason {
    Unreachable,
    Unsupported,
    NotRelay,
    HopLimit,
    /// Probes went unanswered while the waypoint stays reachable in the
    /// topology (spec §17.2.6 rule 3).
    NoEcho,
    /// The path stayed `pending` for 60 s (spec §17.2.3); the node keeps
    /// that timer.
    PendingTimeout,
}

impl Reason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Unreachable => "unreachable",
            Self::Unsupported => "unsupported",
            Self::NotRelay => "not_relay",
            Self::HopLimit => "hop_limit",
            Self::NoEcho => "no_echo",
            Self::PendingTimeout => "pending_timeout",
        }
    }
}

/// The node a state names (status `path.unreachable`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Culprit {
    /// Index in the configured `via` (after cutting at the destination).
    Waypoint(usize),
    /// The destination itself.
    Destination,
}

/// How a path is used right now (spec §17.2.3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Plan {
    /// A capability answer is outstanding: default routing, no notice.
    Pending,
    /// Encapsulate through all these waypoints (`active`).
    Strict(Vec<u32>),
    /// Encapsulate through this leading run only (`first_hop_only` (a));
    /// `culprit` is the first waypoint no longer kept.
    Prefix {
        waypoints: Vec<u32>,
        reason: Reason,
        culprit: usize,
    },
    /// Send a plain packet through the connection to this direct neighbour
    /// (`first_hop_only` (b)).
    FirstHop {
        neighbour: u32,
        reason: Reason,
        culprit: usize,
    },
    /// The destination is itself the first waypoint: default routing,
    /// `active` (spec §17.2.2 rule 7).
    Direct,
    /// Default routing.
    Fallback { reason: Reason, culprit: Culprit },
}

impl Plan {
    /// The status `path.state`.
    pub fn state(&self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Strict(_) | Self::Direct => "active",
            Self::Prefix { .. } | Self::FirstHop { .. } => "first_hop_only",
            Self::Fallback { .. } => "fallback",
        }
    }

    /// The waypoints a packet is encapsulated through, if any.
    pub fn encapsulated(&self) -> Option<&[u32]> {
        match self {
            Self::Strict(waypoints) | Self::Prefix { waypoints, .. } => Some(waypoints),
            _ => None,
        }
    }
}

/// A fallback held against a path by a timer the node keeps: an accepted
/// path error (30 s) or failed probes (until they recover).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Held {
    pub reason: Reason,
    pub culprit: Culprit,
}

/// What the source knows about the destination B.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DestinationView {
    /// Secure mode, B is a direct neighbour and its implementation is not
    /// `native`: the inner packet would use the direct session but arrive
    /// on another connection, which T17 has not confirmed for reference
    /// nodes (spec §17.2.5, inner packet).
    pub direct_unverified: bool,
}

/// Decides the plan for a path whose waypoints (configured order, already
/// cut before the destination by [`cut_at_destination`]) look like `via`.
pub fn plan(via: &[WaypointView], destination: DestinationView, held: Option<Held>) -> Plan {
    if via.is_empty() {
        return Plan::Direct;
    }
    if let Some(held) = held {
        return Plan::Fallback {
            reason: held.reason,
            culprit: held.culprit,
        };
    }
    for (index, waypoint) in via.iter().enumerate() {
        if waypoint.id.is_none() || !waypoint.reachable {
            return Plan::Fallback {
                reason: Reason::Unreachable,
                culprit: Culprit::Waypoint(index),
            };
        }
    }
    if destination.direct_unverified {
        return Plan::Fallback {
            reason: Reason::Unsupported,
            culprit: Culprit::Destination,
        };
    }
    if via.iter().any(|w| w.capability == Capability::Pending) {
        return Plan::Pending;
    }
    let ids: Vec<u32> = via.iter().map(|w| w.id.unwrap()).collect();
    let kept = via.iter().take_while(|w| w.encapsulable()).count();
    if kept > 0 {
        if let Some(culprit) = over_hop_limit(&via[..kept]) {
            return Plan::Fallback {
                reason: Reason::HopLimit,
                culprit: Culprit::Waypoint(culprit),
            };
        }
        if kept == via.len() {
            return Plan::Strict(ids);
        }
        return Plan::Prefix {
            waypoints: ids[..kept].to_vec(),
            reason: via[kept].refusal(),
            culprit: kept,
        };
    }
    let first = via[0];
    // A neighbour that does not relay drops everything it would pass on,
    // so the first-hop policy needs one that relays (spec §17.2.3).
    if first.direct && first.capability != Capability::NotRelay {
        return Plan::FirstHop {
            neighbour: ids[0],
            reason: first.refusal(),
            culprit: 0,
        };
    }
    Plan::Fallback {
        reason: first.refusal(),
        culprit: Culprit::Waypoint(0),
    }
}

/// The waypoint whose segment takes the estimated path over 8 segments
/// (spec §17.2.3, segment estimate), if any.
fn over_hop_limit(kept: &[WaypointView]) -> Option<usize> {
    let mut total = 0u32;
    for (index, waypoint) in kept.iter().enumerate() {
        total = total.saturating_add(waypoint.hops_in);
        if total > MAX_SEGMENTS {
            return Some(index);
        }
    }
    let last = kept.len() - 1;
    (total.saturating_add(kept[last].hops_to_destination) > MAX_SEGMENTS).then_some(last)
}

/// Cuts the waypoint list before the destination when the destination is
/// one of the waypoints (spec §17.2.2 rule 7).
pub fn cut_at_destination(via: &[u32], destination: u32) -> &[u32] {
    match via.iter().position(|id| *id == destination) {
        Some(at) => &via[..at],
        None => via,
    }
}

/// A path the source currently encapsulates, as seen when an error
/// arrives.
pub struct LivePath<'a> {
    pub destination: u32,
    /// The encapsulated waypoints ([`Plan::encapsulated`]).
    pub waypoints: &'a [u32],
    /// Whether this node's topology still reaches the destination.
    pub destination_reachable: bool,
}

/// What the source does with a path error (spec §17.2.5 rule 7).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ErrorAction {
    /// Inconsistent with the path, or a suspicious hop-limit error: drop
    /// and count.
    Ignore,
    /// Hold the path in fallback for 30 s.
    Fallback { reason: Reason, failed: u32 },
    /// Keep the path, report the destination as unreachable.
    DestinationDown,
    /// Query the reporter's capability again; do not fall back yet.
    Requery(u32),
}

/// Judges a path error from `reporter` (the outer `from_peer_id`) against
/// one live path.
pub fn judge_error(error: &PathError, reporter: u32, path: &LivePath<'_>) -> ErrorAction {
    if error.destination != path.destination {
        return ErrorAction::Ignore;
    }
    let Some(at) = path.waypoints.iter().position(|id| *id == reporter) else {
        return ErrorAction::Ignore;
    };
    let last = at + 1 == path.waypoints.len();
    match error.code {
        ErrorCode::NextUnreachable => match path.waypoints.get(at + 1) {
            Some(&next) if next == error.failed => ErrorAction::Fallback {
                reason: Reason::Unreachable,
                failed: next,
            },
            _ => ErrorAction::Ignore,
        },
        ErrorCode::DestinationUnreachable => {
            if !last || error.failed != path.destination {
                ErrorAction::Ignore
            } else if path.destination_reachable {
                ErrorAction::Fallback {
                    reason: Reason::Unreachable,
                    failed: path.destination,
                }
            } else {
                ErrorAction::DestinationDown
            }
        }
        ErrorCode::NotRelay if error.failed == reporter => ErrorAction::Requery(reporter),
        // The node already falls back on its own estimate (spec §17.2.3)
        // when a path exceeds 8 segments, so a hop-limit error on a live
        // path is suspicious.
        ErrorCode::NotRelay | ErrorCode::HopLimit => ErrorAction::Ignore,
    }
}

/// Probe bookkeeping for one encapsulated waypoint sequence (spec §17.2.6).
/// The node sends a probe, feeds back the echoes, and closes that probe's
/// round 3 s after sending it. Rounds overlap: during warm-up (rule 7) a
/// probe goes out every second while each still waits its full 3 s, so up
/// to three are open at once, each matched by its token. A new sequence
/// warms up first: until one round has every echo, judged by the number of
/// closed rounds, not by the clock.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProbeState {
    waypoints: Vec<u32>,
    /// Open rounds, oldest first.
    rounds: Vec<Round>,
    /// The latest echo status seen from each waypoint.
    last: Vec<Option<EchoStatus>>,
    /// Closed rounds in a row in which each waypoint echoed status 1.
    waiting_rounds: Vec<u8>,
    misses: Vec<u8>,
    clean_rounds: u8,
    warmup: Option<Warmup>,
    held: Option<(usize, Reason)>,
    /// Echo statuses of the round closed last.
    latest: Option<Vec<Option<EchoStatus>>>,
}

/// One probe waiting for its echoes.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Round {
    token: u64,
    /// Echo status per waypoint, `None` while unanswered.
    answered: Vec<Option<EchoStatus>>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Warmup {
    closed: u32,
    deadline: u32,
}

/// Where a probed sequence stands after a round.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// Still warming up: the paths stay `pending` on default routing.
    Warming,
    /// The paths may be `active` (or `first_hop_only` a).
    Ready,
    /// The paths fall back, naming this waypoint index.
    Held { waypoint: usize, reason: Reason },
}

/// Probes in a row without an echo before a waypoint counts as lost.
pub const PROBE_MISSES: u8 = 3;
/// Rounds in a row with every echo before the path recovers.
pub const PROBE_RECOVERY: u8 = 2;
/// Warm-up probes beyond the waypoint count before giving up (6 + k).
pub const WARMUP_PROBES: u32 = 6;
/// Extra warm-up probes allowed after a status-1 echo.
pub const WARMUP_GRACE: u32 = 3;
/// Rounds in a row a status-1 echo excuses the waypoints after it; beyond
/// that they count as missing (spec §17.2.6 rule 3).
pub const WAITING_GRACE: u8 = 3;
/// Most rounds open at once. Warm-up needs three (one a second, 3 s
/// each); starting a round beyond this closes the oldest first.
pub const MAX_OPEN_ROUNDS: usize = 4;
/// Echoes per second a source expects from one waypoint at most: half of
/// the waypoint's limit of 32 (spec §17.2.6 rules 1, 4).
pub const ECHO_BUDGET: u32 = 16;

impl ProbeState {
    /// A sequence that has to warm up first.
    pub fn new(waypoints: Vec<u32>) -> Self {
        let n = waypoints.len();
        let deadline = WARMUP_PROBES + n as u32;
        Self {
            waypoints,
            rounds: Vec::new(),
            last: vec![None; n],
            waiting_rounds: vec![0; n],
            misses: vec![0; n],
            clean_rounds: 0,
            warmup: Some(Warmup {
                closed: 0,
                deadline,
            }),
            held: None,
            latest: None,
        }
    }

    pub fn waypoints(&self) -> &[u32] {
        &self.waypoints
    }

    /// Rounds still waiting for their 3 s.
    pub fn open_rounds(&self) -> usize {
        self.rounds.len()
    }

    /// Opens a round for a probe sent with this token. A token already
    /// open is ignored. When [`MAX_OPEN_ROUNDS`] are open, the oldest is
    /// closed first and its verdict returned, to be acted on like one
    /// from [`finish`](Self::finish).
    #[must_use]
    pub fn start(&mut self, token: u64) -> Option<Verdict> {
        if self.rounds.iter().any(|round| round.token == token) {
            return None;
        }
        let closed = (self.rounds.len() >= MAX_OPEN_ROUNDS).then(|| {
            let oldest = self.rounds[0].token;
            self.finish(oldest)
        });
        self.rounds.push(Round {
            token,
            answered: vec![None; self.waypoints.len()],
        });
        closed
    }

    /// Takes an echo that arrived with outer `from_peer_id` = `from`.
    /// Returns whether it was accepted: its token must belong to an open
    /// round and its waypoint must be the sender and on the sequence.
    pub fn echo(&mut self, echo: &Echo, from: u32) -> bool {
        if echo.waypoint != from {
            return false;
        }
        let Some(at) = self.waypoints.iter().position(|id| *id == from) else {
            return false;
        };
        let Some(round) = self.rounds.iter_mut().find(|r| r.token == echo.token) else {
            return false;
        };
        round.answered[at] = Some(echo.status);
        self.last[at] = Some(echo.status);
        true
    }

    /// The current verdict without closing a round.
    pub fn verdict(&self) -> Verdict {
        if self.warmup.is_some() {
            return Verdict::Warming;
        }
        match self.held {
            Some((waypoint, reason)) => Verdict::Held { waypoint, reason },
            None => Verdict::Ready,
        }
    }

    /// The waypoint and reason for a fallback on lost waypoint `lost`
    /// (spec §17.2.6 rule 3): its predecessor's latest echo said the next
    /// one is unreachable (`unreachable`); or the predecessor kept waiting
    /// for its query, so the lost one never saw a probe and the waiting
    /// one is named (`no_echo`); or it simply did not answer (`no_echo`).
    fn held_on(&self, lost: usize) -> (usize, Reason) {
        match lost
            .checked_sub(1)
            .map(|before| (before, self.last[before]))
        {
            Some((_, Some(EchoStatus::Unreachable))) => (lost, Reason::Unreachable),
            Some((before, Some(EchoStatus::Pending))) => (before, Reason::NoEcho),
            _ => (lost, Reason::NoEcho),
        }
    }

    /// Closes the round of the probe sent with `token` (3 s after sending
    /// it) and returns the verdict (spec §17.2.6 rules 3 and 7). A token
    /// that is not open changes nothing.
    pub fn finish(&mut self, token: u64) -> Verdict {
        let Some(at) = self.rounds.iter().position(|r| r.token == token) else {
            return self.verdict();
        };
        let answered = self.rounds.remove(at).answered;
        // A probe answered in full supersedes the ones sent before it that
        // are still open: they no longer count as misses (spec §17.2.6
        // rule 3), so an early warm-up probe that went unanswered does not
        // count once warm-up is over.
        if answered.iter().all(Option::is_some) {
            self.rounds.drain(..at);
        }
        self.latest = Some(answered.clone());
        // Waypoints after one that echoed status 1 are not missing: that
        // one is still waiting for its query, for at most 3 rounds in a
        // row.
        let waiting = answered
            .iter()
            .position(|a| *a == Some(EchoStatus::Pending));
        for (rounds, answer) in self.waiting_rounds.iter_mut().zip(&answered) {
            match answer {
                Some(EchoStatus::Pending) => *rounds = rounds.saturating_add(1),
                Some(_) => *rounds = 0,
                None => {}
            }
        }
        let excused_from = waiting
            .filter(|at| self.waiting_rounds[*at] <= WAITING_GRACE)
            .map_or(answered.len(), |at| at + 1);
        for (at, (miss, answer)) in self.misses.iter_mut().zip(&answered).enumerate() {
            if answer.is_some() {
                *miss = 0;
            } else if at < excused_from {
                *miss = miss.saturating_add(1);
            }
        }
        let clean = answered.iter().all(Option::is_some);
        self.clean_rounds = if clean {
            self.clean_rounds.saturating_add(1)
        } else {
            0
        };
        if let Some(warmup) = self.warmup.as_mut() {
            warmup.closed += 1;
            if clean {
                self.warmup = None;
                self.held = None;
                return Verdict::Ready;
            }
            let base = WARMUP_PROBES + self.waypoints.len() as u32;
            if waiting.is_some() {
                warmup.deadline = warmup
                    .deadline
                    .max(warmup.closed + WARMUP_GRACE)
                    .min(base + WARMUP_GRACE);
            }
            if warmup.closed < warmup.deadline {
                return Verdict::Warming;
            }
            // Give up and go on probing under rule 3's recovery. Name the
            // waypoint still waiting for its query if one is (the ones
            // after it never saw the probe), else the first one without
            // an echo.
            self.warmup = None;
            self.held = Some(match waiting {
                Some(waypoint) => (waypoint, Reason::NoEcho),
                None => self.held_on(answered.iter().position(Option::is_none).unwrap_or(0)),
            });
            return self.verdict();
        }
        if let Some(lost) = self.misses.iter().position(|m| *m >= PROBE_MISSES) {
            self.held = Some(self.held_on(lost));
        } else if self.clean_rounds >= PROBE_RECOVERY {
            self.held = None;
        }
        self.verdict()
    }

    /// Whether every waypoint has answered the open round of `token`, so
    /// that it can be closed before its 3 s are up: warm-up ends as soon as
    /// one probe has all its echoes (spec §17.2.6 rule 7).
    pub fn answered_all(&self, token: u64) -> bool {
        self.rounds
            .iter()
            .any(|round| round.token == token && round.answered.iter().all(Option::is_some))
    }

    /// Whether warm-up is still going on.
    pub fn warming(&self) -> bool {
        self.warmup.is_some()
    }

    /// The waypoint holding the sequence up in the round closed last: the
    /// one that echoed status 1, else the first without an echo (spec
    /// §17.2.3, `pending_timeout`). `None` before any round closed or after
    /// a clean one.
    pub fn stalled(&self) -> Option<usize> {
        let latest = self.latest.as_ref()?;
        latest
            .iter()
            .position(|a| *a == Some(EchoStatus::Pending))
            .or_else(|| latest.iter().position(Option::is_none))
    }

    /// Ends warm-up at once because the path stayed `pending` for 60 s
    /// (spec §17.2.3): the sequence goes on under rule 3's recovery, two
    /// clean rounds in a row, and is not warmed up again. Outside warm-up
    /// nothing changes. Returns the verdict.
    pub fn give_up(&mut self) -> Verdict {
        if self.warmup.take().is_some() {
            self.clean_rounds = 0;
            let waiting = |at: usize| {
                self.latest
                    .as_ref()
                    .is_some_and(|latest| latest[at] == Some(EchoStatus::Pending))
            };
            let held = match self.stalled() {
                Some(at) if waiting(at) => (at, Reason::NoEcho),
                Some(at) => self.held_on(at),
                None => (0, Reason::NoEcho),
            };
            self.held = Some(held);
        }
        self.verdict()
    }

    /// Warm up again after a waypoint changed its ID or capability.
    pub fn rewarm(&mut self) {
        *self = Self::new(std::mem::take(&mut self.waypoints));
    }
}

/// Probe interval in seconds for a source whose busiest waypoint lies on
/// `sequences` probed sequences (spec §17.2.6 rule 1).
pub fn probe_interval(sequences: u32) -> u32 {
    10u32.max(sequences.div_ceil(ECHO_BUDGET))
}

/// The path a packet to `destination` uses (spec §17.2.2): a member's
/// virtual address uses that member's `to_peer` path; otherwise the
/// longest `to_subnet` holding the address, else the `to_peer` path of the
/// advertiser `owner`. `member` tells whether the address is a member's
/// virtual address. Returns the index in `paths`.
pub fn match_path(
    paths: &[CustomPath],
    destination: IpAddr,
    member: bool,
    owner: Option<IpAddr>,
) -> Option<usize> {
    let peer = |address: IpAddr| {
        paths
            .iter()
            .position(|path| path.target == PathTarget::Peer(address))
    };
    if member {
        return peer(destination);
    }
    paths
        .iter()
        .enumerate()
        .filter_map(|(index, path)| match path.target {
            PathTarget::Subnet(net) if net.contains(destination) => Some((net.prefix(), index)),
            _ => None,
        })
        .max_by_key(|(prefix, _)| *prefix)
        .map(|(_, index)| index)
        .or_else(|| peer(owner?))
}

/// The status `id` of a path: derived from its target, so it stays the
/// same when the list changes (`mesh-status.md`, `paths[]`).
pub fn status_id(target: &PathTarget) -> String {
    match target {
        PathTarget::Peer(address) => format!("peer:{address}"),
        PathTarget::Subnet(net) => format!("subnet:{}/{}", net.network(), net.prefix()),
    }
}

/// Largest outer packet (node header + payload): the size of a plain Data
/// packet at the default MTU, 16 + 1380 + 28 (spec §17.2.5, size, rule 1).
pub const MAX_OUTER: usize = 1424;

/// Whether an inner packet (node header + encrypted payload) of
/// `inner_len` bytes still fits once wrapped with `remaining` waypoints.
/// Larger packets take the default route.
pub fn fits(inner_len: usize, remaining: usize) -> bool {
    HEADER_LEN + PREFIX_LEN + 4 * remaining + inner_len + TAIL <= MAX_OUTER
}

/// Highest TCP MSS for a flow on a path whose first segment carries
/// `remaining` waypoints (spec §17.2.5, size, rule 2).
pub fn max_mss(remaining: usize, ipv6: bool) -> u16 {
    // Inner IP packet ≤ 1424 − (16 + 28) − (16 + 12 + 4n + 28).
    let ip = MAX_OUTER - (HEADER_LEN + TAIL) - (HEADER_LEN + PREFIX_LEN + 4 * remaining + TAIL);
    let headers = if ipv6 { 60 } else { 40 };
    (ip - headers) as u16
}

/// The source and destination addresses of a TCP SYN or SYN-ACK in `ip`
/// (no IPv6 extension headers, no IPv4 fragments), for matching paths
/// before [`clamp_mss`].
pub fn tcp_syn_addresses(ip: &[u8]) -> Option<(IpAddr, IpAddr)> {
    let (src, dst, _) = tcp_segment(ip)?;
    Some((src, dst))
}

/// Lowers the MSS option of a TCP SYN or SYN-ACK in the IP packet `ip` to
/// `max` and updates the TCP checksum incrementally (RFC 1624, eqn. 3; spec
/// §17.2.5, size, rule 2), so a segment that arrived with a bad checksum
/// stays bad instead of being repaired. The option may sit at any offset,
/// odd ones included. Returns whether the packet changed. Packets that are
/// not such a segment, carry no MSS option or a smaller one are left alone.
pub fn clamp_mss(ip: &mut [u8], max: u16) -> bool {
    let Some((_, _, tcp_at)) = tcp_segment(ip) else {
        return false;
    };
    let tcp = &ip[tcp_at..];
    let options_end = usize::from(tcp[12] >> 4) * 4;
    if options_end < 20 || options_end > tcp.len() {
        return false;
    }
    let mut at = 20;
    let mut field = None;
    while at < options_end {
        match tcp[at] {
            0 => break,
            1 => at += 1,
            kind => {
                let Some(&len) = tcp.get(at + 1) else {
                    return false;
                };
                let len = usize::from(len);
                if len < 2 || at + len > options_end {
                    return false;
                }
                if kind == 2 && len == 4 {
                    field = Some(tcp_at + at + 2);
                    break;
                }
                at += len;
            }
        }
    }
    let Some(field) = field else {
        return false;
    };
    let current = u16::from_be_bytes([ip[field], ip[field + 1]]);
    if current <= max {
        return false;
    }
    ip[field..field + 2].copy_from_slice(&max.to_be_bytes());
    // The checksum sums 16-bit words aligned to the TCP header (and so to
    // the packet start). A field at an odd offset straddles two of them,
    // and its bytes count swapped (RFC 1071 section 2, byte order
    // independence).
    let (old, new) = if (field - tcp_at) % 2 == 0 {
        (current, max)
    } else {
        (current.swap_bytes(), max.swap_bytes())
    };
    let stored = u16::from_be_bytes([ip[tcp_at + 16], ip[tcp_at + 17]]);
    let checksum = checksum_update(stored, old, new);
    ip[tcp_at + 16..tcp_at + 18].copy_from_slice(&checksum.to_be_bytes());
    true
}

/// HC' = ~(~HC + ~m + m') in one's complement arithmetic (RFC 1624, eqn.
/// 3): the checksum after one 16-bit word changed from `old` to `new`.
fn checksum_update(checksum: u16, old: u16, new: u16) -> u16 {
    let mut sum = u32::from(!checksum) + u32::from(!old) + u32::from(new);
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// Finds a TCP segment with SYN set: addresses and the offset of the TCP
/// header.
fn tcp_segment(ip: &[u8]) -> Option<(IpAddr, IpAddr, usize)> {
    let (src, dst, tcp_at, end) = match ip.first()? >> 4 {
        4 => {
            if ip.len() < 20 {
                return None;
            }
            let ihl = usize::from(ip[0] & 0x0f) * 4;
            let total = usize::from(u16::from_be_bytes([ip[2], ip[3]]));
            let fragment = u16::from_be_bytes([ip[6], ip[7]]) & 0x3fff;
            if ip[9] != 6 || ihl < 20 || fragment != 0 || total > ip.len() || total < ihl {
                return None;
            }
            let src: [u8; 4] = ip[12..16].try_into().ok()?;
            let dst: [u8; 4] = ip[16..20].try_into().ok()?;
            (IpAddr::from(src), IpAddr::from(dst), ihl, total)
        }
        6 => {
            if ip.len() < 40 || ip[6] != 6 {
                return None;
            }
            let end = 40 + usize::from(u16::from_be_bytes([ip[4], ip[5]]));
            if end > ip.len() {
                return None;
            }
            let src: [u8; 16] = ip[8..24].try_into().ok()?;
            let dst: [u8; 16] = ip[24..40].try_into().ok()?;
            (IpAddr::from(src), IpAddr::from(dst), 40, end)
        }
        _ => return None,
    };
    if end < tcp_at + 20 || ip[tcp_at + 13] & 0x02 == 0 {
        return None;
    }
    let options_end = usize::from(ip[tcp_at + 12] >> 4) * 4;
    if tcp_at + options_end > end {
        return None;
    }
    Some((src, dst, tcp_at))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::IpNet;

    /// A full recomputation, for building and verifying test segments.
    /// The TCP checksum of the segment at `tcp_at` with the checksum field
    /// taken as zero.
    fn tcp_checksum(ip: &[u8], tcp_at: usize) -> u16 {
        let mut sum = 0u32;
        let mut add = |bytes: &[u8]| {
            for pair in bytes.chunks(2) {
                let word = u16::from_be_bytes([pair[0], *pair.get(1).unwrap_or(&0)]);
                sum += u32::from(word);
            }
        };
        let end = if ip[0] >> 4 == 4 {
            let total = usize::from(u16::from_be_bytes([ip[2], ip[3]]));
            let len = (total - tcp_at) as u16;
            add(&ip[12..20]);
            add(&[0, 6]);
            add(&len.to_be_bytes());
            total
        } else {
            let end = 40 + usize::from(u16::from_be_bytes([ip[4], ip[5]]));
            let len = (end - tcp_at) as u32;
            add(&ip[8..40]);
            add(&len.to_be_bytes());
            add(&[0, 0, 0, 6]);
            end
        };
        add(&ip[tcp_at..tcp_at + 16]);
        add(&ip[tcp_at + 18..end]);
        while sum >> 16 != 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        !(sum as u16)
    }

    fn inner(from: u32, to: u32) -> Vec<u8> {
        let mut header = NodeHeader::new(from, to, packet_type::DATA, 4);
        header.flags = flags::ENCRYPTED;
        let mut packet = header.encode().to_vec();
        packet.extend_from_slice(&[0xaa; 4 + 28]);
        packet
    }

    fn transit(payload: &[u8]) -> Transit<'_> {
        match decode(payload) {
            Some(Payload::Transit(transit)) => transit,
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn forward_round_trip() {
        let packet = inner(1, 9);
        let payload = encode_transit(1, 9, &[3, 4], Body::Data(&packet));
        assert_eq!(&payload[..4], &[1, 1, 2, 0]);
        assert_eq!(payload.len(), PREFIX_LEN + 8 + packet.len());
        let forward = transit(&payload);
        assert_eq!((forward.origin, forward.destination), (1, 9));
        assert_eq!(forward.remaining, vec![3, 4]);
        assert_eq!(forward.body, Body::Data(&packet));
    }

    #[test]
    fn probe_and_echo_round_trip() {
        let payload = encode_transit(1, 9, &[3], Body::Probe(0x0102_0304_0506_0708));
        assert_eq!(&payload[..4], &[1, 3, 1, 0]);
        assert_eq!(payload.len(), PREFIX_LEN + 4 + 8);
        assert_eq!(transit(&payload).body, Body::Probe(0x0102_0304_0506_0708));
        // A probe has exactly 8 bytes after the list.
        assert_eq!(decode(&payload[..payload.len() - 1]), None);
        let echo = Echo {
            origin: 1,
            destination: 9,
            waypoint: 3,
            token: 77,
            status: EchoStatus::Forwarded,
        };
        let bytes = encode_echo(&echo);
        assert_eq!(bytes.len(), ECHO_LEN);
        assert_eq!(&bytes[..4], &[1, 4, 0, 0]);
        assert_eq!(decode(&bytes), Some(Payload::Echo(echo)));
        // Offset 3 carries the status; reserved values read as 2.
        for (byte, status) in [
            (1, EchoStatus::Pending),
            (2, EchoStatus::NotEncapsulable),
            (3, EchoStatus::Unreachable),
            (9, EchoStatus::NotEncapsulable),
        ] {
            let mut other = bytes.clone();
            other[3] = byte;
            let Some(Payload::Echo(read)) = decode(&other) else {
                panic!("status {byte}");
            };
            assert_eq!(read.status, status);
            if byte <= 3 {
                assert_eq!(encode_echo(&read), other);
            }
        }
        assert_eq!(decode(&bytes[..ECHO_LEN - 1]), None);
    }

    #[test]
    fn error_round_trip() {
        let error = PathError {
            code: ErrorCode::NextUnreachable,
            origin: 1,
            destination: 9,
            failed: 4,
        };
        let bytes = encode_error(&error);
        assert_eq!(&bytes[..4], &[1, 2, 0, 1]);
        assert_eq!(decode(&bytes), Some(Payload::Error(error)));
        // Wrong length, count or code.
        assert_eq!(decode(&bytes[..15]), None);
        let mut bad = bytes.clone();
        bad[2] = 1;
        assert_eq!(decode(&bad), None);
        let mut bad = bytes;
        bad[3] = 9;
        assert_eq!(decode(&bad), None);
    }

    #[test]
    fn rejects_bad_forward() {
        let packet = inner(1, 9);
        let data = Body::Data(&packet);
        // Version, reserved byte, too many waypoints.
        let mut bad = encode_transit(1, 9, &[3], data);
        bad[0] = 2;
        assert_eq!(decode(&bad), None);
        let mut bad = encode_transit(1, 9, &[3], data);
        bad[3] = 1;
        assert_eq!(decode(&bad), None);
        let mut bad = encode_transit(1, 9, &[3], data);
        bad[2] = 7;
        assert_eq!(decode(&bad), None);
        // Repeated waypoint, waypoint equal to origin or destination.
        assert_eq!(decode(&encode_transit(1, 9, &[3, 3], data)), None);
        assert_eq!(decode(&encode_transit(1, 9, &[1], data)), None);
        assert_eq!(decode(&encode_transit(1, 9, &[9], data)), None);
        // Inner header must match the source and destination, be Data and
        // be encrypted.
        assert_eq!(decode(&encode_transit(2, 9, &[3], data)), None);
        assert_eq!(decode(&encode_transit(1, 8, &[3], data)), None);
        let mut rpc = packet.clone();
        rpc[8] = packet_type::RPC_REQ;
        assert_eq!(decode(&encode_transit(1, 9, &[3], Body::Data(&rpc))), None);
        let mut plain = packet.clone();
        plain[9] = 0;
        assert_eq!(
            decode(&encode_transit(1, 9, &[3], Body::Data(&plain))),
            None
        );
        // The inner packet holds at least a header and an encryption tail.
        let short = encode_transit(1, 9, &[3], Body::Data(&packet[..MIN_INNER - 1]));
        assert_eq!(decode(&short), None);
        assert!(decode(&encode_transit(
            1,
            9,
            &[3],
            Body::Data(&packet[..MIN_INNER])
        ))
        .is_some());
        // Unknown kind.
        let mut bad = encode_transit(1, 9, &[], data);
        bad[1] = 5;
        assert_eq!(decode(&bad), None);
        // Shorter than the prefix.
        assert_eq!(decode(&bad[..PREFIX_LEN - 1]), None);
        assert_eq!(decode(&[]), None);
        // A list cut short: count 3, two IDs.
        let probe = encode_transit(1, 9, &[3, 4, 5], Body::Probe(1));
        assert_eq!(decode(&probe[..PREFIX_LEN + 8]), None);
        // Six waypoints is the most and is taken.
        let six = encode_transit(1, 9, &[2, 3, 4, 5, 6, 7], data);
        assert_eq!(transit(&six).remaining, vec![2, 3, 4, 5, 6, 7]);
    }

    fn cx<'a>(
        self_id: u32,
        counter: u8,
        reachable: &'a dyn Fn(u32) -> bool,
    ) -> WaypointContext<'a> {
        WaypointContext {
            self_id,
            relays: true,
            forward_counter: counter,
            latency_first: true,
            reachable,
            outer_from: 1,
            supported: &|_| true,
            pending: &|_| false,
        }
    }

    #[test]
    fn waypoint_checks_next_capability_and_probe_sender() {
        let all = |_: u32| true;
        let packet = inner(1, 9);
        let payload = encode_transit(1, 9, &[4], Body::Data(&packet));
        let only_two = |id: u32| id == 2;
        let asking = |id: u32| id == 4;
        let mut strict = cx(3, 1, &all);
        strict.supported = &only_two;
        // Next waypoint 4 not confirmed: dropped without an error.
        assert_eq!(step(&transit(&payload), &strict), Step::default());
        // A probe there echoes why it stopped: 2, or 1 while the query for
        // 4 is queued or running.
        let onward = encode_transit(1, 9, &[4], Body::Probe(1));
        let stopped = step(&transit(&onward), &strict);
        assert_eq!(stopped.next, None);
        assert_eq!(stopped.echo.unwrap().status, EchoStatus::NotEncapsulable);
        strict.pending = &asking;
        let stopped = step(&transit(&onward), &strict);
        assert_eq!(stopped.echo.unwrap().status, EchoStatus::Pending);
        // A probe whose outer sender is neither the source nor confirmed.
        let probe = encode_transit(1, 9, &[], Body::Probe(1));
        strict.outer_from = 7;
        assert_eq!(step(&transit(&probe), &strict), Step::default());
        // From a confirmed previous waypoint, or from the source: echoed.
        strict.outer_from = 2;
        assert!(step(&transit(&probe), &strict).echo.is_some());
        strict.outer_from = 1;
        assert!(step(&transit(&probe), &strict).echo.is_some());
    }

    #[test]
    fn waypoint_wraps_for_the_next_one() {
        let packet = inner(1, 9);
        let payload = encode_transit(1, 9, &[4, 5], Body::Data(&packet));
        let all = |_: u32| true;
        let step = step(&transit(&payload), &cx(3, 1, &all));
        let next = step.next.expect("next");
        assert_eq!(
            (next.to, next.forward_counter, next.latency_first),
            (4, 2, true)
        );
        let wrapped = transit(&next.payload);
        assert_eq!(wrapped.remaining, vec![5]);
        assert_eq!(wrapped.body, Body::Data(&packet));
        assert_eq!((step.report, step.echo, step.release), (None, None, None));
        // LATENCY_FIRST clears once the counter passes 2 (spec §4.4).
        let payload = encode_transit(1, 9, &[4], Body::Data(&packet));
        let next = super::step(&transit(&payload), &cx(3, 2, &all))
            .next
            .unwrap();
        assert!(!next.latency_first);
    }

    #[test]
    fn last_waypoint_releases_inner_with_counter() {
        let packet = inner(1, 9);
        let payload = encode_transit(1, 9, &[], Body::Data(&packet));
        let all = |_: u32| true;
        let out = step(&transit(&payload), &cx(3, 4, &all))
            .release
            .expect("release");
        assert_eq!(out[10], 5);
        assert_eq!(&out[..10], &packet[..10]);
        assert_eq!(&out[11..], &packet[11..]);
    }

    #[test]
    fn waypoint_reports() {
        let packet = inner(1, 9);
        let none = |_: u32| false;
        let all = |_: u32| true;
        let payload = encode_transit(1, 9, &[4], Body::Data(&packet));
        let forward = transit(&payload);
        let error = |code, failed| {
            Some(PathError {
                code,
                origin: 1,
                destination: 9,
                failed,
            })
        };
        assert_eq!(
            step(&forward, &cx(3, 1, &none)).report,
            error(ErrorCode::NextUnreachable, 4)
        );
        assert_eq!(
            step(&forward, &cx(3, 8, &all)).report,
            error(ErrorCode::HopLimit, 3)
        );
        let mut access = cx(3, 1, &all);
        access.relays = false;
        assert_eq!(
            step(&forward, &access).report,
            error(ErrorCode::NotRelay, 3)
        );
        // Listed again further on, or the source itself: dropped silently.
        assert_eq!(step(&forward, &cx(4, 1, &all)), Step::default());
        assert_eq!(step(&forward, &cx(1, 1, &all)), Step::default());
        // Last waypoint, destination gone.
        let payload = encode_transit(1, 9, &[], Body::Data(&packet));
        let only_self = |id: u32| id == 3;
        assert_eq!(
            step(&transit(&payload), &cx(3, 1, &only_self)).report,
            error(ErrorCode::DestinationUnreachable, 9)
        );
        // At the destination with waypoints left: dropped, never sent on.
        let early = encode_transit(1, 3, &[4], Body::Data(&inner(1, 3)));
        assert_eq!(step(&transit(&early), &cx(3, 1, &all)), Step::default());
        // At the destination as the last waypoint: handled locally.
        let here = encode_transit(1, 3, &[], Body::Data(&inner(1, 3)));
        assert!(step(&transit(&here), &cx(3, 1, &none)).release.is_some());
    }

    #[test]
    fn probes_echo_at_every_waypoint_and_never_report() {
        let all = |_: u32| true;
        let none = |_: u32| false;
        let payload = encode_transit(1, 9, &[4], Body::Probe(5));
        let probe = transit(&payload);
        let echo = Echo {
            origin: 1,
            destination: 9,
            waypoint: 3,
            token: 5,
            status: EchoStatus::Forwarded,
        };
        let step3 = step(&probe, &cx(3, 1, &all));
        assert_eq!(step3.echo, Some(echo));
        assert_eq!(transit(&step3.next.unwrap().payload).body, Body::Probe(5));
        // Next unreachable: still echoes with status 3, no error.
        let lost = step(&probe, &cx(3, 1, &none));
        let unreachable = Echo {
            status: EchoStatus::Unreachable,
            ..echo
        };
        assert_eq!(
            (lost.echo, lost.report, lost.next),
            (Some(unreachable), None, None)
        );
        // Over the counter or not relaying: nothing at all.
        assert_eq!(step(&probe, &cx(3, 8, &all)), Step::default());
        let mut access = cx(3, 1, &all);
        access.relays = false;
        assert_eq!(step(&probe, &access), Step::default());
        // A probe addressed to this node: dropped.
        let mine = encode_transit(1, 3, &[], Body::Probe(5));
        assert_eq!(step(&transit(&mine), &cx(3, 1, &all)), Step::default());
        // Last waypoint: echo only, nothing released.
        let payload = encode_transit(1, 9, &[], Body::Probe(5));
        let last = step(&transit(&payload), &cx(4, 2, &all));
        assert_eq!(last.echo.unwrap().waypoint, 4);
        assert_eq!((last.next, last.release), (None, None));
    }

    #[test]
    fn hop_budget_bounds_the_whole_path() {
        // Six waypoints, each directly after the other: the counter climbs
        // by one per segment and the packet still arrives within 7 relays.
        let packet = inner(1, 99);
        let mut payload = encode_transit(1, 99, &[11, 12, 13, 14, 15], Body::Data(&packet));
        let mut counter = 1u8;
        let all = |_: u32| true;
        for id in 10..=15u32 {
            let step = step(&transit(&payload), &cx(id, counter, &all));
            if let Some(next) = step.next {
                payload = next.payload;
                counter = next.forward_counter;
            } else {
                assert_eq!(id, 15);
                assert_eq!(step.release.unwrap()[10], 7);
                return;
            }
        }
        panic!("never released");
    }

    #[test]
    fn capabilities_round_trip() {
        let local = Capabilities::local(true);
        assert_eq!(local.encode(), vec![0x08, 1, 0x10, 6, 0x18, 1]);
        assert_eq!(Capabilities::decode(&local.encode()), Some(local));
        assert_eq!(local.capability(), Capability::Supported);
        let access = Capabilities::decode(&Capabilities::local(false).encode()).unwrap();
        assert_eq!(access.capability(), Capability::NotRelay);
        assert!(access.capability().understands_type_40());
        // Empty message: version 0 and no relaying.
        let empty = Capabilities::decode(&[]).unwrap();
        assert_eq!(empty.capability(), Capability::NotRelay);
        // Version 0 that relays: not supported, the first hop may be kept.
        let plain = Capabilities {
            version: 0,
            max_waypoints: 0,
            relay: true,
        };
        assert_eq!(
            Capabilities::decode(&plain.encode()).unwrap().capability(),
            Capability::Unsupported
        );
        assert!(!Capability::Unsupported.understands_type_40());
        assert!(!Capability::Unknown.understands_type_40());
        // Unknown fields are skipped.
        let mut extended = local.encode();
        extended.extend_from_slice(&[0x22, 2, 0xff, 0xff, 0x28, 5]);
        assert_eq!(Capabilities::decode(&extended), Some(local));
        assert_eq!(Capabilities::decode(&[0x08]), None);
        // A version beyond 32 bits, and group wire types 3 and 4.
        assert_eq!(
            Capabilities::decode(&[0x08, 0x80, 0x80, 0x80, 0x80, 0x10]),
            None
        );
        assert_eq!(Capabilities::decode(&[0x23, 0x24]), None);
        assert_eq!(Capabilities::decode(&[0x24]), None);
    }

    fn view(id: u32, capability: Capability) -> WaypointView {
        WaypointView {
            id: Some(id),
            reachable: true,
            direct: false,
            capability,
            native: true,
            hops_in: 1,
            hops_to_destination: 1,
        }
    }

    const OK: DestinationView = DestinationView {
        direct_unverified: false,
    };

    fn fallback(reason: Reason, culprit: Culprit) -> Plan {
        Plan::Fallback { reason, culprit }
    }

    #[test]
    fn plans() {
        use Capability::*;
        use Culprit::Waypoint;
        assert_eq!(plan(&[], OK, None), Plan::Direct);
        assert_eq!(
            plan(&[view(3, Supported), view(4, Supported)], OK, None),
            Plan::Strict(vec![3, 4])
        );
        assert_eq!(
            plan(&[view(3, Supported), view(4, Pending)], OK, None),
            Plan::Pending
        );
        assert_eq!(
            plan(&[view(3, Supported), view(4, Unsupported)], OK, None),
            Plan::Prefix {
                waypoints: vec![3],
                reason: Reason::Unsupported,
                culprit: 1
            }
        );
        // Not native under a key list: not encapsulable.
        let mut foreign = view(4, Supported);
        foreign.native = false;
        assert_eq!(
            plan(&[view(3, Supported), foreign], OK, None),
            Plan::Prefix {
                waypoints: vec![3],
                reason: Reason::Unsupported,
                culprit: 1
            }
        );
        // (a) wins over (b): a direct, encapsulable first waypoint keeps
        // encapsulating.
        let mut near = view(3, Supported);
        near.direct = true;
        assert_eq!(
            plan(&[near, view(4, NotRelay)], OK, None),
            Plan::Prefix {
                waypoints: vec![3],
                reason: Reason::NotRelay,
                culprit: 1
            }
        );
        // (b) with an unknown first waypoint: unreachable.
        let mut silent = view(3, Unknown);
        silent.direct = true;
        assert_eq!(
            plan(&[silent], OK, None),
            Plan::FirstHop {
                neighbour: 3,
                reason: Reason::Unreachable,
                culprit: 0
            }
        );
        // A direct neighbour that does not relay would drop the packets.
        let mut direct = view(3, NotRelay);
        direct.direct = true;
        assert_eq!(
            plan(&[direct, view(4, Supported)], OK, None),
            fallback(Reason::NotRelay, Waypoint(0))
        );
        assert_eq!(
            plan(&[view(3, Unsupported)], OK, None),
            fallback(Reason::Unsupported, Waypoint(0))
        );
        assert_eq!(
            plan(&[view(3, NotRelay)], OK, None),
            fallback(Reason::NotRelay, Waypoint(0))
        );
        assert_eq!(
            plan(&[view(3, Unknown)], OK, None),
            fallback(Reason::Unreachable, Waypoint(0))
        );
        // Unreachable beats pending; an unknown address is unreachable.
        let mut gone = view(4, Supported);
        gone.reachable = false;
        assert_eq!(
            plan(&[view(3, Pending), gone], OK, None),
            fallback(Reason::Unreachable, Waypoint(1))
        );
        let mut missing = view(0, Pending);
        missing.id = None;
        assert_eq!(
            plan(&[missing], OK, None),
            fallback(Reason::Unreachable, Waypoint(0))
        );
        // Destination direct and unverified.
        let unverified = DestinationView {
            direct_unverified: true,
        };
        assert_eq!(
            plan(&[view(3, Supported)], unverified, None),
            fallback(Reason::Unsupported, Culprit::Destination)
        );
        // A held fallback wins over everything else.
        let held = Held {
            reason: Reason::Unreachable,
            culprit: Waypoint(1),
        };
        assert_eq!(
            plan(&[view(3, Supported), view(4, Supported)], OK, Some(held)),
            fallback(Reason::Unreachable, Waypoint(1))
        );
        assert_eq!(Plan::Strict(vec![]).state(), "active");
        assert_eq!(Plan::Pending.state(), "pending");
    }

    #[test]
    fn plans_estimate_segments() {
        use Capability::Supported;
        // 3 + 3 + 2 = 8 segments: fine.
        let mut a = view(3, Supported);
        a.hops_in = 3;
        let mut b = view(4, Supported);
        b.hops_in = 3;
        b.hops_to_destination = 2;
        assert_eq!(plan(&[a, b], OK, None), Plan::Strict(vec![3, 4]));
        // One more on the last leg: over, named at the last waypoint.
        b.hops_to_destination = 3;
        assert_eq!(
            plan(&[a, b], OK, None),
            fallback(Reason::HopLimit, Culprit::Waypoint(1))
        );
        // Over already on the way in to the second waypoint.
        b.hops_in = 6;
        assert_eq!(
            plan(&[a, b], OK, None),
            fallback(Reason::HopLimit, Culprit::Waypoint(1))
        );
        a.hops_in = 9;
        assert_eq!(
            plan(&[a, b], OK, None),
            fallback(Reason::HopLimit, Culprit::Waypoint(0))
        );
    }

    #[test]
    fn errors_must_match_the_path() {
        let path = LivePath {
            destination: 9,
            waypoints: &[3, 4],
            destination_reachable: true,
        };
        let error = |code, failed| PathError {
            code,
            origin: 1,
            destination: 9,
            failed,
        };
        use ErrorCode::*;
        assert_eq!(
            judge_error(&error(NextUnreachable, 4), 3, &path),
            ErrorAction::Fallback {
                reason: Reason::Unreachable,
                failed: 4
            }
        );
        // Not the waypoint after the reporter, or a reporter off the path.
        assert_eq!(
            judge_error(&error(NextUnreachable, 7), 3, &path),
            ErrorAction::Ignore
        );
        assert_eq!(
            judge_error(&error(NextUnreachable, 4), 8, &path),
            ErrorAction::Ignore
        );
        assert_eq!(
            judge_error(&error(NextUnreachable, 5), 4, &path),
            ErrorAction::Ignore
        );
        // Destination errors only from the last waypoint, naming B.
        assert_eq!(
            judge_error(&error(DestinationUnreachable, 9), 4, &path),
            ErrorAction::Fallback {
                reason: Reason::Unreachable,
                failed: 9
            }
        );
        assert_eq!(
            judge_error(&error(DestinationUnreachable, 9), 3, &path),
            ErrorAction::Ignore
        );
        let down = LivePath {
            destination_reachable: false,
            ..path
        };
        assert_eq!(
            judge_error(&error(DestinationUnreachable, 9), 4, &down),
            ErrorAction::DestinationDown
        );
        // Not relaying: ask again; hop limit: suspicious.
        assert_eq!(
            judge_error(&error(NotRelay, 3), 3, &path),
            ErrorAction::Requery(3)
        );
        assert_eq!(
            judge_error(&error(NotRelay, 4), 3, &path),
            ErrorAction::Ignore
        );
        assert_eq!(
            judge_error(&error(HopLimit, 3), 3, &path),
            ErrorAction::Ignore
        );
        // Another destination.
        let mut other = error(NextUnreachable, 4);
        other.destination = 8;
        assert_eq!(judge_error(&other, 3, &path), ErrorAction::Ignore);
    }

    fn echo_from(waypoint: u32, token: u64, status: EchoStatus) -> Echo {
        Echo {
            origin: 1,
            destination: 9,
            waypoint,
            token,
            status,
        }
    }

    /// One round in which `answers` echo with their status.
    fn round(probe: &mut ProbeState, token: u64, answers: &[(u32, EchoStatus)]) -> Verdict {
        assert_eq!(probe.start(token), None);
        for (waypoint, status) in answers {
            assert!(probe.echo(&echo_from(*waypoint, token, *status), *waypoint));
        }
        probe.finish(token)
    }

    fn warmed(waypoints: Vec<u32>) -> ProbeState {
        let mut probe = ProbeState::new(waypoints);
        let all: Vec<_> = probe
            .waypoints()
            .iter()
            .map(|id| (*id, EchoStatus::Forwarded))
            .collect();
        assert_eq!(round(&mut probe, 1000, &all), Verdict::Ready);
        probe
    }

    #[test]
    fn probes_fail_after_three_misses_and_recover_after_two_clean_rounds() {
        use EchoStatus::Forwarded;
        let mut probe = warmed(vec![3, 4]);
        for token in 0..3u64 {
            assert_eq!(probe.start(token), None);
            assert!(probe.echo(&echo_from(3, token, Forwarded), 3));
            // Wrong token, or a waypoint field that is not the sender.
            assert!(!probe.echo(&echo_from(4, token + 100, Forwarded), 4));
            assert!(!probe.echo(&echo_from(4, token, Forwarded), 3));
            let verdict = probe.finish(token);
            let expected = if token == 2 {
                Verdict::Held {
                    waypoint: 1,
                    reason: Reason::NoEcho,
                }
            } else {
                Verdict::Ready
            };
            assert_eq!(verdict, expected);
        }
        // One clean round is not enough.
        let clean = [(3, Forwarded), (4, Forwarded)];
        assert!(matches!(
            round(&mut probe, 10, &clean),
            Verdict::Held { waypoint: 1, .. }
        ));
        assert_eq!(round(&mut probe, 11, &clean), Verdict::Ready);
        // Finishing a round that is not open changes nothing.
        assert_eq!(probe.finish(11), Verdict::Ready);
        assert_eq!(probe.waypoints(), &[3, 4]);
    }

    #[test]
    fn echo_status_names_the_reason_and_excuses_later_waypoints() {
        use EchoStatus::{Forwarded, NotEncapsulable, Pending, Unreachable};
        // 3 says 4 is unreachable: 4 is held as unreachable.
        let mut probe = warmed(vec![3, 4, 5]);
        for token in 0..3 {
            round(&mut probe, token, &[(3, Unreachable)]);
        }
        assert_eq!(
            probe.verdict(),
            Verdict::Held {
                waypoint: 1,
                reason: Reason::Unreachable
            }
        );
        // 3 says 4 is not encapsulable: no_echo.
        let mut probe = warmed(vec![3, 4, 5]);
        for token in 0..3 {
            round(&mut probe, token, &[(3, NotEncapsulable)]);
        }
        assert_eq!(
            probe.verdict(),
            Verdict::Held {
                waypoint: 1,
                reason: Reason::NoEcho
            }
        );
        // 4 waits for its query of 5: 5 is not missing meanwhile.
        let mut probe = warmed(vec![3, 4, 5]);
        for token in 0..3 {
            let verdict = round(&mut probe, token, &[(3, Forwarded), (4, Pending)]);
            assert_eq!(verdict, Verdict::Ready);
        }
        // Then 5 stays silent with 4 forwarding: three misses count.
        for token in 3..6 {
            round(&mut probe, token, &[(3, Forwarded), (4, Forwarded)]);
        }
        assert_eq!(
            probe.verdict(),
            Verdict::Held {
                waypoint: 2,
                reason: Reason::NoEcho
            }
        );
    }

    #[test]
    fn waiting_excuses_for_three_rounds_only() {
        use EchoStatus::{Forwarded, Pending};
        let mut probe = warmed(vec![3, 4, 5]);
        let waiting = [(3, Forwarded), (4, Pending)];
        for token in 0..WAITING_GRACE as u64 + 2 {
            assert_eq!(round(&mut probe, token, &waiting), Verdict::Ready);
        }
        // The third round beyond the grace: 5 counts as lost, and 4, which
        // kept waiting, is named.
        assert_eq!(
            round(&mut probe, 10, &waiting),
            Verdict::Held {
                waypoint: 1,
                reason: Reason::NoEcho
            }
        );
        // An echo of another status resets the count.
        let mut probe = warmed(vec![3, 4, 5]);
        for token in 0..20 {
            let answers: &[(u32, EchoStatus)] = if token % 3 == 2 {
                &[(3, Forwarded), (4, Forwarded), (5, Forwarded)]
            } else {
                &waiting
            };
            assert_eq!(round(&mut probe, token, answers), Verdict::Ready);
        }
        assert_eq!(Reason::PendingTimeout.as_str(), "pending_timeout");
    }

    #[test]
    fn warmup_counts_probes_and_waits_for_pending_queries() {
        use EchoStatus::{Forwarded, Pending};
        // Ready on the first round with every echo.
        let mut probe = ProbeState::new(vec![3, 4]);
        assert_eq!(probe.verdict(), Verdict::Warming);
        assert_eq!(round(&mut probe, 0, &[(3, Forwarded)]), Verdict::Warming);
        assert_eq!(
            round(&mut probe, 1, &[(3, Forwarded), (4, Forwarded)]),
            Verdict::Ready
        );
        // Gives up after 6 + k probes, naming the first silent waypoint.
        let mut probe = ProbeState::new(vec![3, 4]);
        for token in 0..7 {
            assert_eq!(
                round(&mut probe, token, &[(3, Forwarded)]),
                Verdict::Warming
            );
        }
        assert_eq!(
            round(&mut probe, 7, &[(3, Forwarded)]),
            Verdict::Held {
                waypoint: 1,
                reason: Reason::NoEcho
            }
        );
        // Rounds not closed do not count: no clock involved.
        let mut probe = ProbeState::new(vec![3, 4]);
        for token in 0..20 {
            assert_eq!(probe.finish(token), Verdict::Warming);
        }
        // A status-1 echo on the last counted probe waits at most 3 more.
        let mut probe = ProbeState::new(vec![3, 4]);
        for token in 0..10 {
            assert_eq!(round(&mut probe, token, &[(3, Pending)]), Verdict::Warming);
        }
        // It names the waypoint that was waiting, not the one after it
        // that never saw a probe.
        assert_eq!(
            round(&mut probe, 10, &[(3, Pending)]),
            Verdict::Held {
                waypoint: 0,
                reason: Reason::NoEcho
            }
        );
        // After giving up, rule 3's recovery applies.
        let clean = [(3, Forwarded), (4, Forwarded)];
        assert!(matches!(
            round(&mut probe, 11, &clean),
            Verdict::Held { .. }
        ));
        assert_eq!(round(&mut probe, 12, &clean), Verdict::Ready);
        // A changed waypoint warms up again.
        probe.rewarm();
        assert_eq!(probe.verdict(), Verdict::Warming);
        assert_eq!(probe.waypoints(), &[3, 4]);
    }

    #[test]
    fn warmup_overlaps_probes_on_a_slow_path() {
        use EchoStatus::Forwarded;
        // One probe a second, each answered 2.5 s later and closed after
        // 3 s: three rounds are open at once and none falls back.
        let mut probe = ProbeState::new(vec![3, 4, 5]);
        let probes = 12u64;
        let mut ready = false;
        // Half-second ticks.
        for tick in 0..2 * probes + 6 {
            if tick % 2 == 0 && tick / 2 < probes {
                assert_eq!(probe.start(tick / 2), None);
            }
            if tick >= 5 && (tick - 5) % 2 == 0 && (tick - 5) / 2 < probes {
                let token = (tick - 5) / 2;
                for waypoint in [3, 4, 5] {
                    assert!(probe.echo(&echo_from(waypoint, token, Forwarded), waypoint));
                }
            }
            if tick >= 6 && tick % 2 == 0 && (tick - 6) / 2 < probes {
                let verdict = probe.finish((tick - 6) / 2);
                assert!(!matches!(verdict, Verdict::Held { .. }), "tick {tick}");
                ready |= verdict == Verdict::Ready;
            }
            assert!(probe.open_rounds() <= 3);
        }
        assert!(ready);
        assert_eq!(probe.verdict(), Verdict::Ready);
        // An echo for a round already closed is not taken.
        assert!(!probe.echo(&echo_from(3, 0, Forwarded), 3));
    }

    #[test]
    fn a_clean_round_supersedes_older_open_rounds() {
        use EchoStatus::Forwarded;
        let mut probe = ProbeState::new(vec![3]);
        // The first warm-up probe goes unanswered; the second is answered.
        assert_eq!(probe.start(1), None);
        assert_eq!(probe.start(2), None);
        assert!(probe.echo(&echo_from(3, 2, Forwarded), 3));
        assert_eq!(probe.finish(2), Verdict::Ready);
        assert_eq!(probe.open_rounds(), 0);
        // Closing the superseded round later changes nothing.
        assert_eq!(probe.finish(1), Verdict::Ready);
        // Two misses, then a clean round: the count starts again.
        let mut probe = warmed(vec![3]);
        for token in [10, 11] {
            assert_eq!(probe.start(token), None);
            assert_eq!(probe.finish(token), Verdict::Ready);
        }
        assert_eq!(round(&mut probe, 12, &[(3, Forwarded)]), Verdict::Ready);
        for token in [13, 14] {
            assert_eq!(probe.start(token), None);
            assert_eq!(probe.finish(token), Verdict::Ready);
        }
        assert_eq!(probe.start(15), None);
        assert!(matches!(probe.finish(15), Verdict::Held { .. }));
    }

    #[test]
    fn open_rounds_are_bounded() {
        let held = Verdict::Held {
            waypoint: 0,
            reason: Reason::NoEcho,
        };
        let mut probe = warmed(vec![3]);
        for token in 0..MAX_OPEN_ROUNDS as u64 {
            assert_eq!(probe.start(token), None);
        }
        // Each start beyond the limit closes the oldest round (here as a
        // miss) and hands back its verdict: the third miss holds the path
        // at once instead of on a later finish (review of #360, Q2).
        let tokens = MAX_OPEN_ROUNDS as u64..MAX_OPEN_ROUNDS as u64 + 3;
        let closed: Vec<_> = tokens.map(|token| probe.start(token)).collect();
        assert_eq!(
            closed,
            vec![Some(Verdict::Ready), Some(Verdict::Ready), Some(held)]
        );
        assert_eq!(probe.open_rounds(), MAX_OPEN_ROUNDS);
        assert_eq!(probe.verdict(), held);
        assert!(!probe.echo(&echo_from(3, 2, EchoStatus::Forwarded), 3));
        assert!(probe.echo(&echo_from(3, 3, EchoStatus::Forwarded), 3));
        // Starting an open token again changes nothing.
        assert_eq!(probe.start(3), None);
        assert_eq!(probe.open_rounds(), MAX_OPEN_ROUNDS);
        // One clean round is not yet a recovery.
        assert_eq!(probe.finish(3), held);
        // A forced close during warm-up reports warming.
        let mut warming = ProbeState::new(vec![3]);
        for token in 0..MAX_OPEN_ROUNDS as u64 {
            assert_eq!(warming.start(token), None);
        }
        assert_eq!(warming.start(99), Some(Verdict::Warming));
    }

    #[test]
    fn giving_up_warm_up_needs_two_clean_rounds() {
        use EchoStatus::{Forwarded, Pending};
        let mut probe = ProbeState::new(vec![3, 4, 5]);
        assert_eq!(probe.stalled(), None);
        // Waypoint 4 keeps waiting for its query; 5 never sees a probe.
        assert_eq!(
            round(&mut probe, 1, &[(3, Forwarded), (4, Pending)]),
            Verdict::Warming
        );
        assert_eq!(probe.stalled(), Some(1));
        assert!(probe.warming());
        assert_eq!(
            probe.give_up(),
            Verdict::Held {
                waypoint: 1,
                reason: Reason::NoEcho
            }
        );
        assert!(!probe.warming());
        // Giving up again changes nothing.
        assert!(matches!(probe.give_up(), Verdict::Held { .. }));
        let clean = [(3, Forwarded), (4, Forwarded), (5, Forwarded)];
        assert!(matches!(round(&mut probe, 2, &clean), Verdict::Held { .. }));
        assert_eq!(round(&mut probe, 3, &clean), Verdict::Ready);
        assert_eq!(probe.stalled(), None);
        // Without an answer, the first silent waypoint is named.
        let mut silent = ProbeState::new(vec![3, 4]);
        assert_eq!(round(&mut silent, 1, &[(3, Forwarded)]), Verdict::Warming);
        assert_eq!(
            silent.give_up(),
            Verdict::Held {
                waypoint: 1,
                reason: Reason::NoEcho
            }
        );
        // Before any round closed, the first waypoint.
        let mut fresh = ProbeState::new(vec![3, 4]);
        assert_eq!(
            fresh.give_up(),
            Verdict::Held {
                waypoint: 0,
                reason: Reason::NoEcho
            }
        );
    }

    #[test]
    fn probe_interval_keeps_echoes_under_budget() {
        assert_eq!(probe_interval(0), 10);
        assert_eq!(probe_interval(160), 10);
        assert_eq!(probe_interval(161), 11);
        assert_eq!(probe_interval(1000), 63);
        for sequences in [1u32, 50, 161, 999, 5000] {
            assert!(sequences <= ECHO_BUDGET * probe_interval(sequences));
        }
    }

    #[test]
    fn cut_before_destination() {
        assert_eq!(cut_at_destination(&[3, 4, 5], 4), &[3]);
        assert_eq!(cut_at_destination(&[3, 4, 5], 3), &[] as &[u32]);
        assert_eq!(cut_at_destination(&[3, 4, 5], 9), &[3, 4, 5]);
    }

    #[test]
    fn matching() {
        let addr = |s: &str| s.parse::<IpAddr>().unwrap();
        let paths = vec![
            CustomPath {
                target: PathTarget::Peer(addr("10.144.0.7")),
                via: vec![addr("10.144.0.3")],
            },
            CustomPath {
                target: PathTarget::Subnet(IpNet::parse("192.168.0.0/16").unwrap()),
                via: vec![addr("10.144.0.3")],
            },
            CustomPath {
                target: PathTarget::Subnet(IpNet::parse("192.168.20.0/24").unwrap()),
                via: vec![addr("10.144.0.4")],
            },
        ];
        let owner = Some(addr("10.144.0.7"));
        assert_eq!(
            match_path(&paths, addr("192.168.20.5"), false, owner),
            Some(2)
        );
        assert_eq!(
            match_path(&paths, addr("192.168.30.5"), false, owner),
            Some(1)
        );
        assert_eq!(
            match_path(&paths, addr("172.16.0.1"), false, owner),
            Some(0)
        );
        // A member's address uses only its own to_peer path.
        assert_eq!(match_path(&paths, addr("10.144.0.7"), true, None), Some(0));
        assert_eq!(match_path(&paths, addr("10.144.0.8"), true, None), None);
        assert_eq!(
            match_path(&paths, addr("172.16.0.1"), false, Some(addr("10.144.0.8"))),
            None
        );
        assert_eq!(status_id(&paths[0].target), "peer:10.144.0.7");
        assert_eq!(status_id(&paths[2].target), "subnet:192.168.20.0/24");
    }

    #[test]
    fn size_limit() {
        // A full plain Data packet never fits; the MSS bound makes TCP fit.
        assert!(!fits(16 + 1380 + 28, 0));
        for n in 0..=MAX_REMAINING {
            let ip = usize::from(max_mss(n, false)) + 40;
            assert!(fits(16 + ip + 28, n));
            assert!(!fits(16 + ip + 1 + 28, n));
            assert_eq!(max_mss(n, true) + 20, max_mss(n, false));
        }
        assert_eq!(max_mss(0, false), 1284);
        assert_eq!(max_mss(5, false), 1264);
        assert_eq!(max_mss(0, true), 1264);
    }

    /// An IPv4 TCP SYN with options MSS 1460, NOP, NOP, SACK permitted and
    /// a correct checksum.
    fn syn_v4() -> Vec<u8> {
        let mut ip = vec![
            0x45, 0, 0, 48, 0, 1, 0x40, 0, 64, 6, 0, 0, 10, 144, 0, 2, 10, 144, 0, 7,
        ];
        let tcp = [
            0x30, 0x39, 0x00, 0x50, 0, 0, 0, 1, 0, 0, 0, 0, 0x70, 0x02, 0xff, 0xff, 0, 0, 0, 0, 2,
            4, 0x05, 0xb4, 1, 1, 4, 2,
        ];
        ip.extend_from_slice(&tcp);
        let checksum = tcp_checksum(&ip, 20);
        ip[36..38].copy_from_slice(&checksum.to_be_bytes());
        ip
    }

    /// Verifies the TCP checksum the way a receiver does.
    fn checksum_ok(ip: &[u8], tcp_at: usize) -> bool {
        let stored = u16::from_be_bytes([ip[tcp_at + 16], ip[tcp_at + 17]]);
        tcp_checksum(ip, tcp_at) == stored
    }

    #[test]
    fn clamps_ipv4_syn() {
        let mut ip = syn_v4();
        assert!(checksum_ok(&ip, 20));
        assert_eq!(
            tcp_syn_addresses(&ip),
            Some((addr4(10, 144, 0, 2), addr4(10, 144, 0, 7)))
        );
        assert!(clamp_mss(&mut ip, 1280));
        assert_eq!(&ip[42..44], &1280u16.to_be_bytes());
        assert!(checksum_ok(&ip, 20));
        // Already small enough.
        assert!(!clamp_mss(&mut ip, 1300));
        // Not a SYN.
        let mut ack = syn_v4();
        ack[33] = 0x10;
        assert!(!clamp_mss(&mut ack, 1000));
        assert_eq!(tcp_syn_addresses(&ack), None);
        // A fragment.
        let mut fragment = syn_v4();
        fragment[6] = 0x20;
        assert!(!clamp_mss(&mut fragment, 1000));
    }

    fn addr4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::from([a, b, c, d])
    }

    /// An IPv6 TCP SYN-ACK with options NOP, NOP, SACK permitted, MSS 1440
    /// and a correct checksum.
    fn syn_ack_v6() -> Vec<u8> {
        let mut ip = vec![0x60, 0, 0, 0, 0, 28, 6, 64];
        let mut src = [0u8; 16];
        src[0] = 0xfd;
        src[15] = 2;
        let mut dst = [0u8; 16];
        dst[0] = 0xfd;
        dst[15] = 7;
        ip.extend_from_slice(&src);
        ip.extend_from_slice(&dst);
        let tcp = [
            0x00, 0x50, 0x30, 0x39, 0, 0, 0, 9, 0, 0, 0, 2, 0x70, 0x12, 0xff, 0xff, 0, 0, 0, 0, 1,
            1, 4, 2, 2, 4, 0x05, 0xa0,
        ];
        ip.extend_from_slice(&tcp);
        let checksum = tcp_checksum(&ip, 40);
        ip[56..58].copy_from_slice(&checksum.to_be_bytes());
        ip
    }

    #[test]
    fn clamps_ipv6_syn_ack_with_option_after_nops() {
        let mut ip = syn_ack_v6();
        assert!(clamp_mss(&mut ip, max_mss(2, true)));
        assert_eq!(&ip[66..68], &max_mss(2, true).to_be_bytes());
        assert!(checksum_ok(&ip, 40));
    }

    #[test]
    fn checksum_matches_known_values() {
        // Worked out by hand from the one's complement sum of the pseudo
        // header and segment, independently of this module.
        let mut ip = syn_v4();
        assert_eq!(&ip[36..38], &[0x3d, 0x6d]);
        assert!(clamp_mss(&mut ip, 1280));
        assert_eq!(&ip[36..38], &[0x3e, 0x21]);
        let mut ip = syn_ack_v6();
        assert_eq!(&ip[56..58], &[0x58, 0x85]);
        assert!(clamp_mss(&mut ip, 1256));
        assert_eq!(&ip[56..58], &[0x59, 0x3d]);
        // RFC 1624 section 4 example: the old HC0 = 0xDD2F, m = 0x5555,
        // m' = 0x3285 gives 0x0000, never 0xFFFF.
        assert_eq!(checksum_update(0xdd2f, 0x5555, 0x3285), 0x0000);
        // A flipped bit is caught, and an update keeps it broken.
        let mut broken = syn_v4();
        broken[45] ^= 1;
        assert!(!checksum_ok(&broken, 20));
        assert!(clamp_mss(&mut broken, 1280));
        assert!(!checksum_ok(&broken, 20));
    }

    /// `syn_v4` with its options replaced, checksum recomputed.
    fn syn_v4_with(options: [u8; 8]) -> Vec<u8> {
        let mut ip = syn_v4();
        ip[40..48].copy_from_slice(&options);
        ip[36..38].copy_from_slice(&[0, 0]);
        let checksum = tcp_checksum(&ip, 20);
        ip[36..38].copy_from_slice(&checksum.to_be_bytes());
        ip
    }

    /// `syn_ack_v6` with its options replaced, checksum recomputed.
    fn syn_ack_v6_with(options: [u8; 8]) -> Vec<u8> {
        let mut ip = syn_ack_v6();
        ip[60..68].copy_from_slice(&options);
        ip[56..58].copy_from_slice(&[0, 0]);
        let checksum = tcp_checksum(&ip, 40);
        ip[56..58].copy_from_slice(&checksum.to_be_bytes());
        ip
    }

    #[test]
    fn clamps_mss_at_odd_offsets() {
        // NOP, MSS 1460, NOP, NOP, NOP: the value sits at TCP offset 23
        // and straddles two checksum words. Known values worked out
        // independently (review of #360, Q1): 0x901e before, 0x441f after.
        let mut ip = syn_v4_with([1, 2, 4, 0x05, 0xb4, 1, 1, 1]);
        assert_eq!(&ip[36..38], &[0x90, 0x1e]);
        assert!(clamp_mss(&mut ip, 1280));
        assert_eq!(&ip[43..45], &1280u16.to_be_bytes());
        assert_eq!(&ip[36..38], &[0x44, 0x1f]);
        assert!(checksum_ok(&ip, 20));
        // IPv6 SYN-ACK: NOP, NOP, NOP, MSS 1440, NOP (offset 25); 0xbf22
        // before, 0x7723 after lowering to 1256.
        let mut ip = syn_ack_v6_with([1, 1, 1, 2, 4, 0x05, 0xa0, 1]);
        assert_eq!(&ip[56..58], &[0xbf, 0x22]);
        assert!(clamp_mss(&mut ip, 1256));
        assert_eq!(&ip[65..67], &1256u16.to_be_bytes());
        assert_eq!(&ip[56..58], &[0x77, 0x23]);
        assert!(checksum_ok(&ip, 40));
        // Every NOP padding from 0 to 4 in both families, against a full
        // recomputation, for several targets.
        for pad in 0..=4usize {
            let mut options = [1u8; 8];
            options[pad..pad + 4].copy_from_slice(&[2, 4, 0x05, 0xb4]);
            for max in [1200u16, 1264, 1284, 0x05b3, 0x00ff, 0x0100] {
                let mut v4 = syn_v4_with(options);
                assert!(clamp_mss(&mut v4, max));
                assert!(checksum_ok(&v4, 20), "v4 pad {pad} max {max}");
                let mut v6 = syn_ack_v6_with(options);
                assert!(clamp_mss(&mut v6, max));
                assert!(checksum_ok(&v6, 40), "v6 pad {pad} max {max}");
            }
        }
        // A bad checksum stays bad at an odd offset too.
        let mut broken = syn_v4_with([1, 2, 4, 0x05, 0xb4, 1, 1, 1]);
        broken[45] ^= 1;
        assert!(clamp_mss(&mut broken, 1280));
        assert!(!checksum_ok(&broken, 20));
    }

    #[test]
    fn mss_leaves_odd_segments_alone() {
        // IPv4 options (IHL 6) before TCP: still found and fixed.
        let syn = syn_v4();
        let mut ip = syn[..20].to_vec();
        ip[0] = 0x46;
        ip[3] = 52;
        ip.extend_from_slice(&[1, 1, 1, 0]);
        ip.extend_from_slice(&syn[20..]);
        ip[40..42].copy_from_slice(&[0, 0]);
        let checksum = tcp_checksum(&ip, 24);
        ip[40..42].copy_from_slice(&checksum.to_be_bytes());
        assert!(clamp_mss(&mut ip, 1280));
        assert_eq!(&ip[46..48], &1280u16.to_be_bytes());
        assert!(checksum_ok(&ip, 24));
        // IPv6 with an extension header: skipped.
        let mut ext = syn_ack_v6();
        ext[6] = 0;
        assert!(!clamp_mss(&mut ext, 1000));
        // No MSS option.
        let mut none = syn_v4();
        none[40..44].copy_from_slice(&[1, 1, 1, 1]);
        assert!(!clamp_mss(&mut none, 1000));
        // An option running past the header.
        let mut long = syn_v4();
        long[41] = 40;
        assert!(!clamp_mss(&mut long, 1000));
        // Total length beyond the buffer.
        let mut short = syn_v4();
        short[3] = 200;
        assert!(!clamp_mss(&mut short, 1000));
        assert_eq!(tcp_syn_addresses(&short), None);
    }
}
