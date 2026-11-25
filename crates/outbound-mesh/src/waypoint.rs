//! Custom paths (spec §17.2, requirements R7–R9, R25): which path a packet
//! takes, how a path's state follows the waypoints' reachability and
//! capability, and the waypoint packet (type 40) that carries a packet
//! through every waypoint in order.
//!
//! Everything here is free of I/O and of the node's state: the node passes
//! in what it knows (topology, capability answers, recent path errors) and
//! sends what comes out.

use std::collections::BTreeSet;
use std::net::IpAddr;

use crate::config::{CustomPath, PathTarget};
use crate::wire::header::{flags, packet_type, NodeHeader, HEADER_LEN, MAX_FORWARD_COUNTER};

/// Encapsulation version this node speaks (spec §17.2.5).
pub const VERSION: u8 = 1;
/// Most remaining waypoints one packet carries (spec §17.2.4, §17.2.5).
pub const MAX_REMAINING: usize = 6;
/// Bytes before the remaining waypoint list.
pub const PREFIX_LEN: usize = 12;
/// Bytes of a whole path error payload.
pub const ERROR_LEN: usize = PREFIX_LEN + 4;

const KIND_FORWARD: u8 = 1;
const KIND_ERROR: u8 = 2;

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

/// A decoded Forward payload. `inner` is the source's whole packet to the
/// destination, header included, still encrypted for the destination.
#[derive(Debug, PartialEq, Eq)]
pub struct Forward<'a> {
    pub origin: u32,
    pub destination: u32,
    pub remaining: Vec<u32>,
    pub inner: &'a [u8],
}

/// A decoded path error (spec §17.2.5 rule 6).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PathError {
    pub code: ErrorCode,
    pub origin: u32,
    pub destination: u32,
    pub failed: u32,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Payload<'a> {
    Forward(Forward<'a>),
    Error(PathError),
}

/// Builds a Forward payload (spec §17.2.5).
pub fn encode_forward(origin: u32, destination: u32, remaining: &[u32], inner: &[u8]) -> Vec<u8> {
    assert!(remaining.len() <= MAX_REMAINING);
    let mut out = Vec::with_capacity(PREFIX_LEN + 4 * remaining.len() + inner.len());
    out.extend_from_slice(&[VERSION, KIND_FORWARD, remaining.len() as u8, 0]);
    out.extend_from_slice(&origin.to_le_bytes());
    out.extend_from_slice(&destination.to_le_bytes());
    for id in remaining {
        out.extend_from_slice(&id.to_le_bytes());
    }
    out.extend_from_slice(inner);
    out
}

/// Builds a path error payload (spec §17.2.5 rule 6).
pub fn encode_error(error: &PathError) -> [u8; ERROR_LEN] {
    let mut out = [0u8; ERROR_LEN];
    out[..4].copy_from_slice(&[VERSION, KIND_ERROR, 0, error.code as u8]);
    out[4..8].copy_from_slice(&error.origin.to_le_bytes());
    out[8..12].copy_from_slice(&error.destination.to_le_bytes());
    out[12..16].copy_from_slice(&error.failed.to_le_bytes());
    out
}

fn u32_at(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap())
}

/// Reads a decrypted type-40 payload. Checks everything that does not need
/// the receiver's identity (spec §17.2.5 rules 2 and 3, rule 7's shape);
/// `None` means drop and count.
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
        KIND_FORWARD => {
            if payload[3] != 0 || count > MAX_REMAINING {
                return None;
            }
            let list_end = PREFIX_LEN + 4 * count;
            if payload.len() < list_end + HEADER_LEN {
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
            let inner = &payload[list_end..];
            let header = NodeHeader::decode(inner)?;
            if header.from != origin
                || header.to != destination
                || header.packet_type != packet_type::DATA
                || !header.has(flags::ENCRYPTED)
            {
                return None;
            }
            Some(Payload::Forward(Forward {
                origin,
                destination,
                remaining,
                inner,
            }))
        }
        _ => None,
    }
}

/// What a waypoint does with a Forward it received (spec §17.2.5 rules
/// 1–6).
#[derive(Debug, PartialEq, Eq)]
pub enum Step {
    /// Drop and count, nothing to report.
    Drop,
    /// Drop and send this error to `error.origin`.
    Report(PathError),
    /// Wrap again for the next waypoint `to`: send a type-40 packet from
    /// this node with this payload and forward counter.
    Next {
        to: u32,
        forward_counter: u8,
        payload: Vec<u8>,
    },
    /// This was the last waypoint: relay `packet` (the inner packet with its
    /// counter rewritten) towards its destination as in spec §14, or handle
    /// it locally when the destination is this node.
    Release { packet: Vec<u8> },
}

/// What the waypoint knows about itself and the topology.
pub struct WaypointContext<'a> {
    pub self_id: u32,
    /// Full node with relaying on.
    pub relays: bool,
    /// The outer header's forward counter.
    pub forward_counter: u8,
    /// Whether a node is reachable in this node's topology (this node
    /// itself counts as reachable).
    pub reachable: &'a dyn Fn(u32) -> bool,
}

/// Decides what a waypoint does with `forward` (already decoded).
pub fn step(forward: &Forward<'_>, cx: &WaypointContext<'_>) -> Step {
    let report = |code, failed| {
        Step::Report(PathError {
            code,
            origin: forward.origin,
            destination: forward.destination,
            failed,
        })
    };
    if forward.remaining.contains(&cx.self_id) || forward.origin == cx.self_id {
        return Step::Drop;
    }
    if !cx.relays {
        return report(ErrorCode::NotRelay, cx.self_id);
    }
    if cx.forward_counter > MAX_FORWARD_COUNTER {
        return report(ErrorCode::HopLimit, cx.self_id);
    }
    let counter = cx.forward_counter + 1;
    match forward.remaining.split_first() {
        Some((&next, rest)) => {
            if !(cx.reachable)(next) {
                return report(ErrorCode::NextUnreachable, next);
            }
            Step::Next {
                to: next,
                forward_counter: counter,
                payload: encode_forward(forward.origin, forward.destination, rest, forward.inner),
            }
        }
        None => {
            if forward.destination != cx.self_id && !(cx.reachable)(forward.destination) {
                return report(ErrorCode::DestinationUnreachable, forward.destination);
            }
            let mut packet = forward.inner.to_vec();
            packet[10] = counter;
            Step::Release { packet }
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

    /// Whether the node can be a strict waypoint.
    pub fn supported(&self) -> bool {
        self.version >= 1 && self.relay
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

/// What the source knows about one waypoint's capability (spec §17.2.4).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Capability {
    /// Not asked yet or the answer is outstanding.
    Pending,
    /// Answered: supports encapsulation and relays.
    Supported,
    /// Answered with Error 3 or version 0 (reference node or an older one
    /// of ours).
    Unsupported,
    /// Answered `relay = false`.
    NotRelay,
    /// The query timed out or failed otherwise.
    Unknown,
}

/// One waypoint as the source sees it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WaypointView {
    /// Node ID; `None` when no member has the configured address.
    pub id: Option<u32>,
    /// Reachable in the topology with at least one connection on the way.
    pub reachable: bool,
    /// A direct neighbour of this node.
    pub direct: bool,
    pub capability: Capability,
}

/// Why a path fell back (spec §17.2.7; status `path.reason`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reason {
    Unreachable,
    Unsupported,
    NotRelay,
    HopLimit,
}

impl Reason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Unreachable => "unreachable",
            Self::Unsupported => "unsupported",
            Self::NotRelay => "not_relay",
            Self::HopLimit => "hop_limit",
        }
    }

    /// The fallback a path error from a waypoint causes (spec §17.2.5 rule
    /// 7); `None` for errors that only report (destination unreachable).
    pub fn of_error(code: ErrorCode) -> Option<Self> {
        match code {
            ErrorCode::NextUnreachable => Some(Self::Unreachable),
            ErrorCode::DestinationUnreachable => None,
            ErrorCode::NotRelay => Some(Self::NotRelay),
            ErrorCode::HopLimit => Some(Self::HopLimit),
        }
    }
}

/// How a path is used right now (spec §17.2.3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Plan {
    /// Capability answers outstanding: default routing, no notice.
    Pending,
    /// Encapsulate through all these waypoints (`active`).
    Strict(Vec<u32>),
    /// Encapsulate through this leading run only (`first_hop_only` (a)).
    Prefix(Vec<u32>),
    /// Send a plain packet through the connection to this direct neighbour
    /// (`first_hop_only` (b)).
    FirstHop(u32),
    /// The destination is itself the first waypoint: default routing,
    /// `active` (spec §17.2.2 rule 6).
    Direct,
    /// Default routing, naming the node at fault.
    Fallback { reason: Reason, node: Culprit },
}

/// The node a fallback names (status `path.unreachable`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Culprit {
    /// Index in the configured `via`.
    Waypoint(usize),
    /// The destination itself (secure mode, direct and not native).
    Destination,
}

impl Plan {
    /// The status `path.state`.
    pub fn state(&self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Strict(_) | Self::Direct => "active",
            Self::Prefix(_) | Self::FirstHop(_) => "first_hop_only",
            Self::Fallback { .. } => "fallback",
        }
    }
}

/// A recent path error held against a path for 30 s (spec §17.2.5 rule 7):
/// the reason and the index in `via` of the node it names.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HeldError {
    pub reason: Reason,
    pub node: Culprit,
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
pub fn plan(via: &[WaypointView], destination: DestinationView, held: Option<HeldError>) -> Plan {
    if via.is_empty() {
        return Plan::Direct;
    }
    if let Some(held) = held {
        return Plan::Fallback {
            reason: held.reason,
            node: held.node,
        };
    }
    for (index, waypoint) in via.iter().enumerate() {
        if waypoint.id.is_none() || !waypoint.reachable {
            return Plan::Fallback {
                reason: Reason::Unreachable,
                node: Culprit::Waypoint(index),
            };
        }
    }
    if destination.direct_unverified {
        return Plan::Fallback {
            reason: Reason::Unsupported,
            node: Culprit::Destination,
        };
    }
    if via.iter().any(|w| w.capability == Capability::Pending) {
        return Plan::Pending;
    }
    let ids: Vec<u32> = via.iter().map(|w| w.id.unwrap()).collect();
    let supported = via
        .iter()
        .take_while(|w| w.capability == Capability::Supported)
        .count();
    if supported == via.len() {
        return Plan::Strict(ids);
    }
    if supported > 0 {
        return Plan::Prefix(ids[..supported].to_vec());
    }
    let first = via[0];
    if first.direct {
        return Plan::FirstHop(ids[0]);
    }
    let reason = match first.capability {
        Capability::NotRelay => Reason::NotRelay,
        Capability::Unknown => Reason::Unreachable,
        _ => Reason::Unsupported,
    };
    Plan::Fallback {
        reason,
        node: Culprit::Waypoint(0),
    }
}

/// Cuts the waypoint list before the destination when the destination is
/// one of the waypoints (spec §17.2.2 rule 6).
pub fn cut_at_destination(via: &[u32], destination: u32) -> &[u32] {
    match via.iter().position(|id| *id == destination) {
        Some(at) => &via[..at],
        None => via,
    }
}

/// The path a packet to `destination` uses (spec §17.2.2): the longest
/// `to_subnet` holding the address, else the `to_peer` path of the owner
/// (`owner`, the virtual address of the node the packet goes to). Returns
/// the index in `paths`.
pub fn match_path(
    paths: &[CustomPath],
    destination: IpAddr,
    owner: Option<IpAddr>,
) -> Option<usize> {
    let subnet = paths
        .iter()
        .enumerate()
        .filter_map(|(index, path)| match path.target {
            PathTarget::Subnet(net) if net.contains(destination) => Some((net.prefix(), index)),
            _ => None,
        })
        .max_by_key(|(prefix, _)| *prefix)
        .map(|(_, index)| index);
    subnet.or_else(|| {
        let owner = owner?;
        paths
            .iter()
            .position(|path| path.target == PathTarget::Peer(owner))
    })
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
/// Encryption tail (spec §7.3, §8.6).
const TAIL: usize = 28;

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::IpNet;

    fn inner(from: u32, to: u32) -> Vec<u8> {
        let mut header = NodeHeader::new(from, to, packet_type::DATA, 4);
        header.flags = flags::ENCRYPTED;
        header.forward_counter = 1;
        let mut packet = header.encode().to_vec();
        packet.extend_from_slice(&[0xaa; 4 + 28]);
        packet
    }

    #[test]
    fn forward_round_trip() {
        let packet = inner(1, 9);
        let payload = encode_forward(1, 9, &[3, 4], &packet);
        assert_eq!(&payload[..4], &[1, 1, 2, 0]);
        assert_eq!(payload.len(), PREFIX_LEN + 8 + packet.len());
        let Some(Payload::Forward(forward)) = decode(&payload) else {
            panic!("not a forward");
        };
        assert_eq!(forward.origin, 1);
        assert_eq!(forward.destination, 9);
        assert_eq!(forward.remaining, vec![3, 4]);
        assert_eq!(forward.inner, &packet[..]);
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
        let mut bad = bytes;
        bad[2] = 1;
        assert_eq!(decode(&bad), None);
        let mut bad = bytes;
        bad[3] = 9;
        assert_eq!(decode(&bad), None);
    }

    #[test]
    fn rejects_bad_forward() {
        let packet = inner(1, 9);
        // Version, reserved byte, too many waypoints.
        let mut bad = encode_forward(1, 9, &[3], &packet);
        bad[0] = 2;
        assert_eq!(decode(&bad), None);
        let mut bad = encode_forward(1, 9, &[3], &packet);
        bad[3] = 1;
        assert_eq!(decode(&bad), None);
        let mut bad = encode_forward(1, 9, &[3], &packet);
        bad[2] = 7;
        assert_eq!(decode(&bad), None);
        // Repeated waypoint, waypoint equal to origin or destination.
        assert_eq!(decode(&encode_forward(1, 9, &[3, 3], &packet)), None);
        assert_eq!(decode(&encode_forward(1, 9, &[1], &packet)), None);
        assert_eq!(decode(&encode_forward(1, 9, &[9], &packet)), None);
        // Inner header must match the source and destination, be Data and
        // be encrypted.
        assert_eq!(decode(&encode_forward(2, 9, &[3], &packet)), None);
        assert_eq!(decode(&encode_forward(1, 8, &[3], &packet)), None);
        let mut rpc = packet.clone();
        rpc[8] = packet_type::RPC_REQ;
        assert_eq!(decode(&encode_forward(1, 9, &[3], &rpc)), None);
        let mut plain = packet.clone();
        plain[9] = 0;
        assert_eq!(decode(&encode_forward(1, 9, &[3], &plain)), None);
        // List longer than the payload.
        let short = encode_forward(1, 9, &[3], &packet[..10]);
        assert_eq!(decode(&short), None);
        // Unknown kind.
        let mut bad = encode_forward(1, 9, &[], &packet);
        bad[1] = 3;
        assert_eq!(decode(&bad), None);
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
            reachable,
        }
    }

    #[test]
    fn waypoint_wraps_for_the_next_one() {
        let packet = inner(1, 9);
        let payload = encode_forward(1, 9, &[4, 5], &packet);
        let Some(Payload::Forward(forward)) = decode(&payload) else {
            panic!()
        };
        let all = |_: u32| true;
        let Step::Next {
            to,
            forward_counter,
            payload,
        } = step(&forward, &cx(3, 2, &all))
        else {
            panic!("not next");
        };
        assert_eq!((to, forward_counter), (4, 3));
        let Some(Payload::Forward(next)) = decode(&payload) else {
            panic!()
        };
        assert_eq!(next.remaining, vec![5]);
        assert_eq!(next.inner, &packet[..]);
    }

    #[test]
    fn last_waypoint_releases_inner_with_counter() {
        let packet = inner(1, 9);
        let payload = encode_forward(1, 9, &[], &packet);
        let Some(Payload::Forward(forward)) = decode(&payload) else {
            panic!()
        };
        let all = |_: u32| true;
        let Step::Release { packet: out } = step(&forward, &cx(3, 4, &all)) else {
            panic!("not release");
        };
        assert_eq!(out[10], 5);
        assert_eq!(&out[..10], &packet[..10]);
        assert_eq!(&out[11..], &packet[11..]);
    }

    #[test]
    fn waypoint_reports() {
        let packet = inner(1, 9);
        let none = |_: u32| false;
        let all = |_: u32| true;
        let payload = encode_forward(1, 9, &[4], &packet);
        let Some(Payload::Forward(forward)) = decode(&payload) else {
            panic!()
        };
        let error = |code, failed| {
            Step::Report(PathError {
                code,
                origin: 1,
                destination: 9,
                failed,
            })
        };
        assert_eq!(
            step(&forward, &cx(3, 1, &none)),
            error(ErrorCode::NextUnreachable, 4)
        );
        assert_eq!(
            step(&forward, &cx(3, 8, &all)),
            error(ErrorCode::HopLimit, 3)
        );
        let mut access = cx(3, 1, &all);
        access.relays = false;
        assert_eq!(step(&forward, &access), error(ErrorCode::NotRelay, 3));
        // Listed again further on, or the source itself: dropped silently.
        assert_eq!(step(&forward, &cx(4, 1, &all)), Step::Drop);
        assert_eq!(step(&forward, &cx(1, 1, &all)), Step::Drop);
        // Last waypoint, destination gone.
        let payload = encode_forward(1, 9, &[], &packet);
        let Some(Payload::Forward(last)) = decode(&payload) else {
            panic!()
        };
        let only_self = |id: u32| id == 3;
        assert_eq!(
            step(&last, &cx(3, 1, &only_self)),
            error(ErrorCode::DestinationUnreachable, 9)
        );
    }

    #[test]
    fn hop_budget_bounds_the_whole_path() {
        // Six waypoints, each directly after the other: the counter climbs
        // by one per segment and the packet still arrives within 7 relays.
        let packet = inner(1, 99);
        let mut payload = encode_forward(1, 99, &[11, 12, 13, 14, 15], &packet);
        let mut counter = 1u8;
        let all = |_: u32| true;
        for id in 10..=15u32 {
            let Some(Payload::Forward(forward)) = decode(&payload) else {
                panic!()
            };
            match step(&forward, &cx(id, counter, &all)) {
                Step::Next {
                    payload: next,
                    forward_counter,
                    ..
                } => {
                    payload = next;
                    counter = forward_counter;
                }
                Step::Release { packet } => {
                    assert_eq!(id, 15);
                    assert_eq!(packet[10], 7);
                    return;
                }
                other => panic!("{other:?}"),
            }
        }
        panic!("never released");
    }

    #[test]
    fn capabilities_round_trip() {
        let local = Capabilities::local(true);
        assert_eq!(local.encode(), vec![0x08, 1, 0x10, 6, 0x18, 1]);
        assert_eq!(Capabilities::decode(&local.encode()), Some(local));
        assert!(local.supported());
        let access = Capabilities::local(false);
        assert!(!Capabilities::decode(&access.encode()).unwrap().supported());
        // Empty message: version 0, not supported.
        assert!(!Capabilities::decode(&[]).unwrap().supported());
        // Unknown fields are skipped.
        let mut extended = local.encode();
        extended.extend_from_slice(&[0x22, 2, 0xff, 0xff, 0x28, 5]);
        assert_eq!(Capabilities::decode(&extended), Some(local));
        assert_eq!(Capabilities::decode(&[0x08]), None);
    }

    fn view(id: u32, capability: Capability) -> WaypointView {
        WaypointView {
            id: Some(id),
            reachable: true,
            direct: false,
            capability,
        }
    }

    const OK: DestinationView = DestinationView {
        direct_unverified: false,
    };

    #[test]
    fn plans() {
        use Capability::*;
        assert_eq!(
            plan(
                &[view(3, Supported)],
                DestinationView {
                    direct_unverified: true
                },
                None
            ),
            Plan::Fallback {
                reason: Reason::Unsupported,
                node: Culprit::Destination
            }
        );
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
            Plan::Prefix(vec![3])
        );
        let mut direct = view(3, Unsupported);
        direct.direct = true;
        assert_eq!(
            plan(&[direct, view(4, Supported)], OK, None),
            Plan::FirstHop(3)
        );
        assert_eq!(
            plan(&[view(3, Unsupported)], OK, None),
            Plan::Fallback {
                reason: Reason::Unsupported,
                node: Culprit::Waypoint(0)
            }
        );
        assert_eq!(
            plan(&[view(3, NotRelay)], OK, None),
            Plan::Fallback {
                reason: Reason::NotRelay,
                node: Culprit::Waypoint(0)
            }
        );
        assert_eq!(
            plan(&[view(3, Unknown)], OK, None),
            Plan::Fallback {
                reason: Reason::Unreachable,
                node: Culprit::Waypoint(0)
            }
        );
        // Unreachable beats pending; an unknown address is unreachable.
        let mut gone = view(4, Supported);
        gone.reachable = false;
        assert_eq!(
            plan(&[view(3, Pending), gone], OK, None),
            Plan::Fallback {
                reason: Reason::Unreachable,
                node: Culprit::Waypoint(1)
            }
        );
        let missing = WaypointView {
            id: None,
            reachable: false,
            direct: false,
            capability: Pending,
        };
        assert_eq!(
            plan(&[missing], OK, None),
            Plan::Fallback {
                reason: Reason::Unreachable,
                node: Culprit::Waypoint(0)
            }
        );
        // A held path error wins over everything else.
        let held = HeldError {
            reason: Reason::HopLimit,
            node: Culprit::Waypoint(1),
        };
        assert_eq!(
            plan(&[view(3, Supported), view(4, Supported)], OK, Some(held)),
            Plan::Fallback {
                reason: Reason::HopLimit,
                node: Culprit::Waypoint(1)
            }
        );
        assert_eq!(Plan::Strict(vec![]).state(), "active");
        assert_eq!(Plan::FirstHop(3).state(), "first_hop_only");
    }

    #[test]
    fn cut_before_destination() {
        assert_eq!(cut_at_destination(&[3, 4, 5], 4), &[3]);
        assert_eq!(cut_at_destination(&[3, 4, 5], 3), &[] as &[u32]);
        assert_eq!(cut_at_destination(&[3, 4, 5], 9), &[3, 4, 5]);
    }

    #[test]
    fn matching_prefers_longest_subnet_then_owner() {
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
        assert_eq!(match_path(&paths, addr("192.168.20.5"), owner), Some(2));
        assert_eq!(match_path(&paths, addr("192.168.30.5"), owner), Some(1));
        assert_eq!(match_path(&paths, addr("172.16.0.1"), owner), Some(0));
        assert_eq!(match_path(&paths, addr("10.144.0.7"), owner), Some(0));
        assert_eq!(
            match_path(&paths, addr("172.16.0.1"), Some(addr("10.144.0.8"))),
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
}
