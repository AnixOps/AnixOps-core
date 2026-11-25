//! One direct connection to a neighbour, after framing (spec §5, §6, §8.1,
//! §7.5–§7.6, §8.7): the handshake of the network's mode, then the checks
//! and the encryption of every packet that starts or ends here.
//!
//! Sans I/O: the driver feeds whole packets (node header and payload) and
//! writes back what this module returns. The mode is the network's, never
//! negotiated per connection (spec §5.2): a server that receives the first
//! packet of the other mode closes the connection and reports a mode
//! mismatch, and no client ever falls back.
//!
//! On receive this node is stricter than the reference behaviour (spec
//! §7.6, §8.7): Data and RPC packets for this node must be encrypted unless
//! the network was explicitly configured without encryption; handshake
//! packets are accepted only during the handshake; exit-node traffic is
//! dropped (spec §1.4).
//!
//! Handshakes still waiting for the peer are limited by source address,
//! never by the unauthenticated node ID (spec §8.1): see
//! [`HandshakeBudget`].

use std::collections::{HashMap, VecDeque};
use std::io::Read;
use std::net::IpAddr;
use std::time::{Duration, Instant};

use ring::rand::SecureRandom;

use crate::config::SecurityMode;
use crate::legacy::cipher::LegacyCipher;
use crate::legacy::handshake::{self as legacy, HandshakeMessage, DIGEST_LEN};
use crate::secure::handshake::{Auth, Client, HandshakeError, Local, Server};
use crate::secure::noise::LEN;
use crate::secure::session::{Namespace, SessionError, SessionKey, Sessions};
use crate::secure::traffic::TrafficError;
use crate::wire::header::{flags, packet_type, NodeHeader, HEADER_LEN};

/// Every handshake step must finish within this (spec §5.3).
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);
/// Largest original payload length accepted, compressed or not.
pub const MAX_PAYLOAD_LEN: u32 = 64 * 1024;
/// Largest window a compressed payload may ask for.
const MAX_ZSTD_WINDOW: u64 = 1 << 20;
/// Trailer byte of a zstd-compressed payload (spec §7.4).
const ZSTD: u8 = 1;

/// Why a connection is closed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CloseReason {
    /// The peer used the other security mode (spec §5.2): reported as
    /// "encryption mode mismatch".
    ModeMismatch,
    /// The peer is in another network.
    ForeignNetwork,
    /// The peer uses this node's ID and is not authenticated: only the
    /// connection closes (spec §8.1).
    SameNodeId,
    /// A server proved the network secret under this node's ID: an ID
    /// conflict (spec §5.3).
    IdConflict,
    /// Another connection to the same peer is creating the session: open
    /// this one again once that is up or closed (spec §8.1).
    WaitForSession,
    /// Pushed out by newer handshakes from the same source address, or by
    /// the limit in all ([`HandshakeBudget`]).
    Evicted,
    /// A handshake step did not finish in [`HANDSHAKE_TIMEOUT`].
    Timeout,
    /// A packet that has no place in the handshake.
    Unexpected,
    /// The default handshake failed.
    Legacy(legacy::HandshakeError),
    /// The secure handshake failed.
    Secure(HandshakeError),
}

/// What the handshake settled on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Up {
    pub peer_id: u32,
    pub security: SecurityMode,
    /// The peer's static key; secure mode only.
    pub peer_static: Option<[u8; LEN]>,
    /// How the peer was authenticated; secure mode only. The default mode
    /// only compares network digests.
    pub auth: Option<Auth>,
}

/// The result of one handshake packet.
#[derive(Debug, PartialEq, Eq)]
pub enum Step {
    /// Write these packets, in order, and keep going.
    Send(Vec<Vec<u8>>),
    /// Write these packets; the connection is up.
    Up(Vec<Vec<u8>>, Up),
    /// Write these packets, then close.
    Close(Vec<Vec<u8>>, CloseReason),
}

/// What the handshake needs from the node. `peer_key` gives the static key
/// a node ID's route information announces, if known.
pub struct Handshaking<'a> {
    pub local: &'a Local,
    pub security: SecurityMode,
    pub sessions: &'a mut Sessions,
    pub rng: &'a dyn SecureRandom,
    pub peer_key: &'a dyn Fn(u32) -> Option<[u8; LEN]>,
    pub now: Instant,
}

enum Phase {
    ServerWaiting,
    ClientLegacy,
    ClientSecure(Box<Client>),
    ServerSecure(Box<Server>),
    Up(Up),
    Closed,
}

/// One direct connection.
pub struct Link {
    phase: Phase,
    deadline: Instant,
}

/// Encodes a node packet; `len` is the payload's length.
pub fn packet(from: u32, to: u32, kind: u8, payload: &[u8]) -> Vec<u8> {
    let header = NodeHeader::new(from, to, kind, payload.len() as u32);
    let mut out = Vec::with_capacity(HEADER_LEN + payload.len());
    out.extend_from_slice(&header.encode());
    out.extend_from_slice(payload);
    out
}

fn legacy_hello(local: &Local) -> HandshakeMessage {
    HandshakeMessage {
        peer_id: local.id,
        network_name: local.network_name.clone(),
        digest: local.digest.unwrap_or([0; DIGEST_LEN]),
    }
}

impl Link {
    /// A connection this node opened; returns it and the first packet.
    /// `known_peer` is the node ID it is expected to reach, if any.
    pub fn client(
        hs: &mut Handshaking<'_>,
        known_peer: Option<u32>,
    ) -> Result<(Self, Vec<u8>), CloseReason> {
        let deadline = hs.now + HANDSHAKE_TIMEOUT;
        match hs.security {
            SecurityMode::Default => {
                if known_peer == Some(hs.local.id) {
                    return Err(CloseReason::SameNodeId);
                }
                let hello = legacy_hello(hs.local).encode();
                let first = packet(hs.local.id, 0, packet_type::HANDSHAKE, &hello);
                Ok((
                    Self {
                        phase: Phase::ClientLegacy,
                        deadline,
                    },
                    first,
                ))
            }
            SecurityMode::ForwardSecrecy => {
                let (client, msg1) =
                    Client::start(hs.local, known_peer, hs.sessions, hs.rng, hs.now)
                        .map_err(secure_close)?;
                let first = packet(hs.local.id, 0, packet_type::SECURE_MSG1, &msg1);
                Ok((
                    Self {
                        phase: Phase::ClientSecure(Box::new(client)),
                        deadline,
                    },
                    first,
                ))
            }
        }
    }

    /// A connection a peer opened.
    pub fn server(now: Instant) -> Self {
        Self {
            phase: Phase::ServerWaiting,
            deadline: now + HANDSHAKE_TIMEOUT,
        }
    }

    /// The handshake result once the connection is up.
    pub fn up(&self) -> Option<&Up> {
        match &self.phase {
            Phase::Up(up) => Some(up),
            _ => None,
        }
    }

    pub fn is_closed(&self) -> bool {
        matches!(self.phase, Phase::Closed)
    }

    /// Whether the handshake ran out of time; the connection is then
    /// closed.
    pub fn timed_out(&mut self, now: Instant) -> bool {
        let waiting = !matches!(self.phase, Phase::Up(_) | Phase::Closed);
        if waiting && now >= self.deadline {
            self.phase = Phase::Closed;
            return true;
        }
        false
    }

    /// Feeds one packet received during the handshake.
    pub fn handshake(&mut self, hs: &mut Handshaking<'_>, received: &[u8]) -> Step {
        let step = self.advance(hs, received);
        match &step {
            Step::Send(_) => {
                self.deadline = hs.now + HANDSHAKE_TIMEOUT;
            }
            Step::Up(_, up) => self.phase = Phase::Up(*up),
            Step::Close(..) => self.phase = Phase::Closed,
        }
        step
    }

    fn advance(&mut self, hs: &mut Handshaking<'_>, received: &[u8]) -> Step {
        let Some(header) = NodeHeader::decode(received) else {
            return Step::Close(Vec::new(), CloseReason::Unexpected);
        };
        let payload = &received[HEADER_LEN..];
        let kind = header.packet_type;
        let local = hs.local;
        match std::mem::replace(&mut self.phase, Phase::Closed) {
            Phase::ServerWaiting => match (hs.security, kind) {
                (SecurityMode::Default, packet_type::HANDSHAKE) => {
                    legacy_server(hs, header.from, payload)
                }
                (SecurityMode::ForwardSecrecy, packet_type::SECURE_MSG1) => {
                    if header.from == local.id {
                        return Step::Close(Vec::new(), CloseReason::SameNodeId);
                    }
                    match Server::respond(local, header.from, payload, hs.sessions, hs.rng) {
                        Ok((server, msg2)) => {
                            let reply = packet(local.id, 0, packet_type::SECURE_MSG2, &msg2);
                            if server.is_foreign() {
                                return Step::Close(vec![reply], CloseReason::ForeignNetwork);
                            }
                            self.phase = Phase::ServerSecure(Box::new(server));
                            Step::Send(vec![reply])
                        }
                        Err(error) => Step::Close(Vec::new(), secure_close(error)),
                    }
                }
                (SecurityMode::Default, packet_type::SECURE_MSG1)
                | (SecurityMode::ForwardSecrecy, packet_type::HANDSHAKE) => {
                    Step::Close(Vec::new(), CloseReason::ModeMismatch)
                }
                _ => Step::Close(Vec::new(), CloseReason::Unexpected),
            },
            Phase::ClientLegacy => match kind {
                packet_type::HANDSHAKE => legacy_client(local, payload),
                packet_type::SECURE_MSG2 => Step::Close(Vec::new(), CloseReason::ModeMismatch),
                _ => Step::Close(Vec::new(), CloseReason::Unexpected),
            },
            Phase::ClientSecure(client) => match kind {
                packet_type::SECURE_MSG2 => {
                    let expected = (hs.peer_key)(header.from);
                    match (*client).finish(
                        local,
                        header.from,
                        expected,
                        payload,
                        hs.sessions,
                        hs.now,
                    ) {
                        Ok((msg3, established)) => Step::Up(
                            vec![packet(local.id, 0, packet_type::SECURE_MSG3, &msg3)],
                            Up {
                                peer_id: header.from,
                                security: SecurityMode::ForwardSecrecy,
                                peer_static: Some(established.peer_static),
                                auth: Some(established.auth),
                            },
                        ),
                        Err(error) => Step::Close(Vec::new(), secure_close(error)),
                    }
                }
                packet_type::HANDSHAKE => Step::Close(Vec::new(), CloseReason::ModeMismatch),
                _ => Step::Close(Vec::new(), CloseReason::Unexpected),
            },
            Phase::ServerSecure(server) => match kind {
                packet_type::SECURE_MSG3 => {
                    let peer_id = server.peer_id();
                    let expected = (hs.peer_key)(peer_id);
                    match (*server).finish(local, expected, payload, hs.sessions, hs.now) {
                        Ok(established) => Step::Up(
                            Vec::new(),
                            Up {
                                peer_id: established.key.peer_id,
                                security: SecurityMode::ForwardSecrecy,
                                peer_static: Some(established.peer_static),
                                auth: Some(established.auth),
                            },
                        ),
                        Err(error) => Step::Close(Vec::new(), secure_close(error)),
                    }
                }
                _ => Step::Close(Vec::new(), CloseReason::Unexpected),
            },
            Phase::Up(up) => {
                self.phase = Phase::Up(up);
                Step::Send(Vec::new())
            }
            Phase::Closed => Step::Close(Vec::new(), CloseReason::Unexpected),
        }
    }
}

fn secure_close(error: HandshakeError) -> CloseReason {
    match error {
        HandshakeError::SameNodeId => CloseReason::SameNodeId,
        HandshakeError::IdConflict => CloseReason::IdConflict,
        HandshakeError::Session(SessionError::Busy) => CloseReason::WaitForSession,
        HandshakeError::ForeignNetwork => CloseReason::ForeignNetwork,
        other => CloseReason::Secure(other),
    }
}

/// Spec §6.2 for a node that is not a shared node: answer, then close when
/// the client is in another network.
fn legacy_server(hs: &Handshaking<'_>, from: u32, payload: &[u8]) -> Step {
    let local = hs.local;
    let hello = match HandshakeMessage::decode(payload) {
        Ok(hello) => hello,
        Err(error) => return Step::Close(Vec::new(), CloseReason::Legacy(error)),
    };
    if hello.peer_id == local.id || from == local.id {
        return Step::Close(Vec::new(), CloseReason::SameNodeId);
    }
    let own = legacy_hello(local);
    let reply = legacy::server_reply(&hello, local.id, &own.network_name, &own.digest).encode();
    let reply = vec![packet(local.id, 0, packet_type::HANDSHAKE, &reply)];
    if !legacy::same_network(&own.network_name, &own.digest, &hello) {
        return Step::Close(reply, CloseReason::ForeignNetwork);
    }
    Step::Up(
        reply,
        Up {
            peer_id: hello.peer_id,
            security: SecurityMode::Default,
            peer_static: None,
            auth: None,
        },
    )
}

fn legacy_client(local: &Local, payload: &[u8]) -> Step {
    let reply = match HandshakeMessage::decode(payload) {
        Ok(reply) => reply,
        Err(error) => return Step::Close(Vec::new(), CloseReason::Legacy(error)),
    };
    let own = legacy_hello(local);
    if !legacy::same_network(&own.network_name, &own.digest, &reply) {
        return Step::Close(Vec::new(), CloseReason::ForeignNetwork);
    }
    if reply.peer_id == local.id {
        return Step::Close(Vec::new(), CloseReason::SameNodeId);
    }
    Step::Up(
        Vec::new(),
        Up {
            peer_id: reply.peer_id,
            security: SecurityMode::Default,
            peer_static: None,
            auth: None,
        },
    )
}

/// The traffic encryption of a network.
pub enum Crypto<'a> {
    /// The default mode: the network's static key, or `None` for a network
    /// explicitly configured without encryption.
    Default(Option<&'a LegacyCipher>),
    /// The secure mode: sessions with neighbours and relay peers.
    Secure {
        sessions: &'a mut Sessions,
        network: &'a str,
    },
}

/// Why a packet for this node was dropped.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Dropped {
    /// Shorter than a node header.
    Truncated,
    /// Data or RPC without encryption (spec §7.6, §8.7): counted and
    /// reported as "peer not encrypting".
    Unencrypted,
    /// A handshake packet after the handshake.
    HandshakeAfterUp,
    /// Exit-node traffic (spec §1.4).
    ExitNode,
    /// A type this node does not take (spec §4.2).
    Unsupported,
    /// Decryption failed.
    Decrypt,
    /// No session with the sender: a relay handshake is needed first.
    NoSession,
    /// [`TrafficError::SessionEnded`]: the session was dropped and the next
    /// handshake makes a new one.
    SessionEnded,
    /// Bad compression trailer, an lzo payload, or a size that does not
    /// match the header (spec §4.1, §7.4).
    Malformed,
}

/// A packet for this node, decrypted and decompressed. The header's
/// [`flags::ENCRYPTED`] and [`flags::COMPRESSED`] are cleared.
#[derive(Debug, PartialEq, Eq)]
pub struct Inbound {
    pub header: NodeHeader,
    pub payload: Vec<u8>,
    /// Whether it arrived encrypted.
    pub was_encrypted: bool,
}

fn needs_encryption(kind: u8) -> bool {
    matches!(
        kind,
        packet_type::DATA | packet_type::RPC_REQ | packet_type::RPC_RESP
    )
}

fn session_key(network: &str, neighbour: u32, from: u32) -> SessionKey {
    SessionKey {
        namespace: if from == neighbour {
            Namespace::Direct
        } else {
            Namespace::Relay
        },
        network: network.to_owned(),
        peer_id: from,
    }
}

/// Checks, decrypts and decompresses a packet addressed to this node that
/// arrived from `neighbour` (the peer of the connection).
pub fn open(
    crypto: &mut Crypto<'_>,
    neighbour: u32,
    packet: &[u8],
    now: Instant,
) -> Result<Inbound, Dropped> {
    let mut header = NodeHeader::decode(packet).ok_or(Dropped::Truncated)?;
    if header.has(flags::EXIT_NODE) {
        return Err(Dropped::ExitNode);
    }
    match header.packet_type {
        packet_type::DATA
        | packet_type::RPC_REQ
        | packet_type::RPC_RESP
        | packet_type::PING
        | packet_type::PONG
        | packet_type::RELAY_HANDSHAKE
        | packet_type::RELAY_HANDSHAKE_ACK => {}
        packet_type::HANDSHAKE
        | packet_type::SECURE_MSG1
        | packet_type::SECURE_MSG2
        | packet_type::SECURE_MSG3 => return Err(Dropped::HandshakeAfterUp),
        _ => return Err(Dropped::Unsupported),
    }
    if header.len > MAX_PAYLOAD_LEN {
        return Err(Dropped::Malformed);
    }
    let mut payload = packet[HEADER_LEN..].to_vec();
    let encrypted = header.has(flags::ENCRYPTED);
    let unencrypted_network = matches!(crypto, Crypto::Default(None));
    if !encrypted && needs_encryption(header.packet_type) && !unencrypted_network {
        return Err(Dropped::Unencrypted);
    }
    if encrypted {
        match crypto {
            Crypto::Default(Some(cipher)) => {
                cipher.open(&mut payload).map_err(|_| Dropped::Decrypt)?;
            }
            Crypto::Default(None) => return Err(Dropped::Decrypt),
            Crypto::Secure { sessions, network } => {
                let key = session_key(network, neighbour, header.from);
                sessions
                    .open(&key, &mut payload, now)
                    .map_err(session_dropped)?;
            }
        }
        header.flags &= !flags::ENCRYPTED;
    }
    if header.has(flags::COMPRESSED) {
        payload = decompress(&payload, header.len)?;
        header.flags &= !flags::COMPRESSED;
    }
    if payload.len() != header.len as usize {
        return Err(Dropped::Malformed);
    }
    Ok(Inbound {
        header,
        payload,
        was_encrypted: encrypted,
    })
}

fn session_dropped(error: SessionError) -> Dropped {
    match error {
        SessionError::NoSession => Dropped::NoSession,
        SessionError::Traffic(TrafficError::SessionEnded) => Dropped::SessionEnded,
        _ => Dropped::Decrypt,
    }
}

/// zstd only; lzo is dropped (spec §7.4). The result must be exactly
/// `len` bytes.
fn decompress(payload: &[u8], len: u32) -> Result<Vec<u8>, Dropped> {
    let (&algorithm, body) = payload.split_last().ok_or(Dropped::Malformed)?;
    if algorithm != ZSTD {
        return Err(Dropped::Malformed);
    }
    let mut source = body;
    let decoder =
        ruzstd::decoding::StreamingDecoder::new_with_max_window_size(&mut source, MAX_ZSTD_WINDOW)
            .map_err(|_| Dropped::Malformed)?;
    let mut out = Vec::with_capacity(len as usize);
    // One byte more than expected tells a payload that is too long.
    decoder
        .take(u64::from(len) + 1)
        .read_to_end(&mut out)
        .map_err(|_| Dropped::Malformed)?;
    if out.len() != len as usize {
        return Err(Dropped::Malformed);
    }
    Ok(out)
}

/// Builds a packet this node originates for `to`, sent to `next_hop`
/// (spec §7.5, §8.7): Data and RPC are encrypted, with the neighbour's
/// session when `to` is the next hop and the relay session with `to`
/// otherwise; Ping, Pong and handshakes never are. Never compresses.
pub fn seal(
    crypto: &mut Crypto<'_>,
    from: u32,
    to: u32,
    next_hop: u32,
    kind: u8,
    payload: &[u8],
    now: Instant,
) -> Result<Vec<u8>, Dropped> {
    let mut header = NodeHeader::new(from, to, kind, payload.len() as u32);
    let mut body = payload.to_vec();
    if needs_encryption(kind) {
        match crypto {
            Crypto::Default(None) => {}
            Crypto::Default(Some(cipher)) => {
                cipher.seal(&mut body).map_err(|_| Dropped::Decrypt)?;
                header.flags |= flags::ENCRYPTED;
            }
            Crypto::Secure { sessions, network } => {
                let key = session_key(network, next_hop, to);
                sessions
                    .seal(&key, &mut body, now)
                    .map_err(session_dropped)?;
                header.flags |= flags::ENCRYPTED;
            }
        }
    }
    let mut out = Vec::with_capacity(HEADER_LEN + body.len());
    out.extend_from_slice(&header.encode());
    out.extend_from_slice(&body);
    Ok(out)
}

/// Handshakes waiting for the peer from one source address at most.
pub const HANDSHAKES_PER_SOURCE: usize = 8;
/// Handshakes waiting for the peer in all.
pub const MAX_HANDSHAKES: usize = 1024;
/// Of [`MAX_HANDSHAKES`], the ones kept for sources at known member
/// addresses.
pub const RESERVED_FOR_MEMBERS: usize = 256;
/// msg1 per second each source may start, on average.
pub const MSG1_PER_SECOND: f64 = 5.0;
/// msg1 a source may start at once.
pub const MSG1_BURST: f64 = 20.0;
/// Sources whose rate and history are remembered.
const MAX_SOURCES: usize = 4096;

/// A handshake admitted by [`HandshakeBudget`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Ticket(u64);

/// The transport a handshake arrived on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Transport {
    Tcp,
    Udp,
}

/// What [`HandshakeBudget::admit`] decided.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Admission {
    /// Go ahead; close the connection of the second ticket, if any, with
    /// [`CloseReason::Evicted`] to make room.
    Admitted(Ticket, Option<Ticket>),
    /// The source sends msg1 too fast, or every place is taken by
    /// handshakes that may not be pushed out: drop the msg1 without an
    /// answer.
    Dropped,
}

struct Waiting {
    ticket: Ticket,
    source: IpAddr,
    transport: Transport,
    member: bool,
}

struct Bucket {
    tokens: f64,
    at: Instant,
}

/// Limits the handshakes this node answers (spec §8.1), by source address
/// (an IPv6 address by its /64) and in all, never by the node ID the peer
/// claims:
///
/// - each source starts at most [`MSG1_PER_SECOND`] msg1 a second, in
///   bursts of [`MSG1_BURST`], which also bounds msg2 sent back to forged
///   sources;
/// - each source has at most [`HANDSHAKES_PER_SOURCE`] waiting, its oldest
///   pushed out by a newer one;
/// - [`MAX_HANDSHAKES`] wait in all, [`RESERVED_FOR_MEMBERS`] of them only
///   for sources at known member addresses (route information, the peer
///   list or a recent connection); when full, a handshake over UDP from a
///   source that never finished one goes first, then one of the source
///   holding the most, the oldest first.
///
/// A pushed-out handshake's connection is closed with
/// [`CloseReason::Evicted`], which drops and wipes its state.
#[derive(Default)]
pub struct HandshakeBudget {
    waiting: VecDeque<Waiting>,
    buckets: HashMap<IpAddr, Bucket>,
    /// Sources that finished a handshake, by when.
    finished: HashMap<IpAddr, u64>,
    next: u64,
}

/// The address a source is counted under.
fn source_of(address: IpAddr) -> IpAddr {
    match address {
        IpAddr::V4(_) => address,
        IpAddr::V6(v6) => {
            let mut octets = v6.octets();
            octets[8..].fill(0);
            IpAddr::from(octets)
        }
    }
}

impl HandshakeBudget {
    pub fn new() -> Self {
        Self::default()
    }

    /// Handshakes not finished.
    pub fn len(&self) -> usize {
        self.waiting.len()
    }

    pub fn is_empty(&self) -> bool {
        self.waiting.is_empty()
    }

    fn take_token(&mut self, source: IpAddr, now: Instant) -> bool {
        if !self.buckets.contains_key(&source) && self.buckets.len() >= MAX_SOURCES {
            // Forget sources whose bucket has filled up again.
            self.buckets.retain(|_, bucket| {
                let refill = now.saturating_duration_since(bucket.at).as_secs_f64();
                bucket.tokens + refill * MSG1_PER_SECOND < MSG1_BURST
            });
        }
        let bucket = self.buckets.entry(source).or_insert(Bucket {
            tokens: MSG1_BURST,
            at: now,
        });
        let refill = now.saturating_duration_since(bucket.at).as_secs_f64();
        bucket.tokens = (bucket.tokens + refill * MSG1_PER_SECOND).min(MSG1_BURST);
        bucket.at = now;
        if bucket.tokens < 1.0 {
            return false;
        }
        bucket.tokens -= 1.0;
        true
    }

    /// The handshake to push out among those `eligible` (spec §8.1): over
    /// UDP from a source that never finished one, then of the source
    /// holding the most, the oldest first.
    fn victim(&self, eligible: impl Fn(&Waiting) -> bool) -> Option<usize> {
        let stranger = self.waiting.iter().position(|waiting| {
            eligible(waiting)
                && waiting.transport == Transport::Udp
                && !self.finished.contains_key(&waiting.source)
        });
        if stranger.is_some() {
            return stranger;
        }
        let mut held: HashMap<IpAddr, usize> = HashMap::new();
        for waiting in self.waiting.iter().filter(|waiting| eligible(waiting)) {
            *held.entry(waiting.source).or_default() += 1;
        }
        let most = held.values().copied().max()?;
        self.waiting
            .iter()
            .position(|waiting| eligible(waiting) && held.get(&waiting.source) == Some(&most))
    }

    /// Admits a msg1 from `address`. `member` tells whether the address is
    /// a known member address.
    pub fn admit(
        &mut self,
        address: IpAddr,
        transport: Transport,
        member: bool,
        now: Instant,
    ) -> Admission {
        let source = source_of(address);
        if !self.take_token(source, now) {
            return Admission::Dropped;
        }
        let of_source = self
            .waiting
            .iter()
            .filter(|waiting| waiting.source == source)
            .count();
        let strangers = self
            .waiting
            .iter()
            .filter(|waiting| !waiting.member)
            .count();
        let at = if of_source >= HANDSHAKES_PER_SOURCE {
            self.waiting
                .iter()
                .position(|waiting| waiting.source == source)
        } else if !member && strangers >= MAX_HANDSHAKES - RESERVED_FOR_MEMBERS {
            match self.victim(|waiting| !waiting.member) {
                Some(at) => Some(at),
                None => return Admission::Dropped,
            }
        } else if self.waiting.len() >= MAX_HANDSHAKES {
            match self.victim(|_| true) {
                Some(at) => Some(at),
                None => return Admission::Dropped,
            }
        } else {
            None
        };
        let evicted = at
            .and_then(|at| self.waiting.remove(at))
            .map(|waiting| waiting.ticket);
        self.next += 1;
        let ticket = Ticket(self.next);
        self.waiting.push_back(Waiting {
            ticket,
            source,
            transport,
            member,
        });
        Admission::Admitted(ticket, evicted)
    }

    /// The handshake of `ticket` failed or timed out.
    pub fn release(&mut self, ticket: Ticket) {
        self.waiting.retain(|waiting| waiting.ticket != ticket);
    }

    /// The handshake of `ticket` finished: its source is no longer a
    /// stranger.
    pub fn finished(&mut self, ticket: Ticket) {
        let Some(at) = self
            .waiting
            .iter()
            .position(|waiting| waiting.ticket == ticket)
        else {
            return;
        };
        let source = self.waiting[at].source;
        self.waiting.remove(at);
        self.next += 1;
        if !self.finished.contains_key(&source) && self.finished.len() >= MAX_SOURCES {
            let oldest = self
                .finished
                .iter()
                .min_by_key(|(_, when)| **when)
                .map(|(oldest, _)| *oldest);
            if let Some(oldest) = oldest {
                self.finished.remove(&oldest);
            }
        }
        self.finished.insert(source, self.next);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Cipher;
    use crate::legacy::keys::digest;
    use crate::secure::noise::KeyPair;
    use ring::rand::SystemRandom;

    const NETWORK: &str = "office";

    fn local(id: u32, secret: &[u8]) -> Local {
        Local {
            id,
            static_key: KeyPair::generate(&SystemRandom::new()).unwrap(),
            network_name: NETWORK.into(),
            node_name: format!("node{id}"),
            secret: Some(secret.to_vec()),
            digest: Some(digest(NETWORK.as_bytes(), secret)),
            cipher: Cipher::Aes128Gcm,
            trusted_keys: Vec::new(),
        }
    }

    fn no_keys(_: u32) -> Option<[u8; LEN]> {
        None
    }

    struct Side {
        local: Local,
        sessions: Sessions,
        security: SecurityMode,
    }

    impl Side {
        fn new(id: u32, secret: &[u8], security: SecurityMode) -> Self {
            Self {
                local: local(id, secret),
                sessions: Sessions::new(),
                security,
            }
        }
    }

    fn with<T>(side: &mut Side, f: impl FnOnce(&mut Handshaking<'_>) -> T) -> T {
        let rng = SystemRandom::new();
        let mut hs = Handshaking {
            local: &side.local,
            security: side.security,
            sessions: &mut side.sessions,
            rng: &rng,
            peer_key: &no_keys,
            now: Instant::now(),
        };
        f(&mut hs)
    }

    /// Runs a whole handshake; returns both links' last steps.
    fn connect(client: &mut Side, server: &mut Side) -> (Step, Step) {
        let (mut at_client, first) = with(client, |hs| Link::client(hs, None)).unwrap();
        let mut at_server = Link::server(Instant::now());
        let mut to_server = vec![first];
        let mut last = (Step::Send(Vec::new()), Step::Send(Vec::new()));
        for _ in 0..3 {
            let mut to_client = Vec::new();
            for received in to_server.drain(..) {
                let step = with(server, |hs| at_server.handshake(hs, &received));
                let (Step::Send(out) | Step::Up(out, _) | Step::Close(out, _)) = &step;
                to_client.extend(out.iter().cloned());
                last.1 = step;
            }
            for received in to_client {
                let step = with(client, |hs| at_client.handshake(hs, &received));
                let (Step::Send(out) | Step::Up(out, _) | Step::Close(out, _)) = &step;
                to_server.extend(out.iter().cloned());
                last.0 = step;
            }
        }
        (last.0, last.1)
    }

    fn is_up(step: &Step, peer: u32, security: SecurityMode) -> bool {
        matches!(step, Step::Up(_, up) if up.peer_id == peer && up.security == security)
    }

    #[test]
    fn secure_links_come_up_and_carry_encrypted_data() {
        let mut a = Side::new(1, b"s3cr3t", SecurityMode::ForwardSecrecy);
        let mut b = Side::new(2, b"s3cr3t", SecurityMode::ForwardSecrecy);
        let (at_a, at_b) = connect(&mut a, &mut b);
        assert!(is_up(&at_a, 2, SecurityMode::ForwardSecrecy));
        assert!(is_up(&at_b, 1, SecurityMode::ForwardSecrecy));

        let now = Instant::now();
        let sent = {
            let mut crypto = Crypto::Secure {
                sessions: &mut a.sessions,
                network: NETWORK,
            };
            seal(&mut crypto, 1, 2, 2, packet_type::DATA, b"ip packet", now).unwrap()
        };
        assert!(NodeHeader::decode(&sent).unwrap().has(flags::ENCRYPTED));
        let mut crypto = Crypto::Secure {
            sessions: &mut b.sessions,
            network: NETWORK,
        };
        let inbound = open(&mut crypto, 1, &sent, now).unwrap();
        assert_eq!(inbound.payload, b"ip packet");
        assert!(inbound.was_encrypted);
        assert!(!inbound.header.has(flags::ENCRYPTED));

        // Plain Data is refused; plain Ping is fine.
        let plain = packet(1, 2, packet_type::DATA, b"forged");
        assert_eq!(open(&mut crypto, 1, &plain, now), Err(Dropped::Unencrypted));
        let ping = packet(1, 2, packet_type::PING, &7u32.to_le_bytes());
        assert!(open(&mut crypto, 1, &ping, now).is_ok());
        let late = packet(1, 0, packet_type::SECURE_MSG1, b"x");
        assert_eq!(
            open(&mut crypto, 1, &late, now),
            Err(Dropped::HandshakeAfterUp)
        );
        let mut exit = packet(1, 2, packet_type::PING, b"x");
        exit[9] = flags::EXIT_NODE;
        assert_eq!(open(&mut crypto, 1, &exit, now), Err(Dropped::ExitNode));
        // A relayed packet from a node without a relay session.
        let mut far = sent.clone();
        far[0..4].copy_from_slice(&9u32.to_le_bytes());
        assert_eq!(open(&mut crypto, 1, &far, now), Err(Dropped::NoSession));
    }

    #[test]
    fn default_links_come_up_and_carry_encrypted_data() {
        let mut a = Side::new(1, b"s3cr3t", SecurityMode::Default);
        let mut b = Side::new(2, b"s3cr3t", SecurityMode::Default);
        let (at_a, at_b) = connect(&mut a, &mut b);
        assert!(is_up(&at_a, 2, SecurityMode::Default));
        assert!(is_up(&at_b, 1, SecurityMode::Default));

        let cipher = LegacyCipher::new(Cipher::Aes128Gcm, b"s3cr3t")
            .unwrap()
            .unwrap();
        let mut crypto = Crypto::Default(Some(&cipher));
        let now = Instant::now();
        let sent = seal(&mut crypto, 1, 2, 2, packet_type::RPC_REQ, b"rpc", now).unwrap();
        assert_eq!(open(&mut crypto, 1, &sent, now).unwrap().payload, b"rpc");
        let plain = packet(1, 2, packet_type::RPC_REQ, b"rpc");
        assert_eq!(open(&mut crypto, 1, &plain, now), Err(Dropped::Unencrypted));

        // Only an explicitly unencrypted network takes plain Data.
        let mut none = Crypto::Default(None);
        let plain = packet(1, 2, packet_type::DATA, b"ip");
        assert_eq!(open(&mut none, 1, &plain, now).unwrap().payload, b"ip");
        assert_eq!(
            seal(&mut none, 1, 2, 2, packet_type::DATA, b"ip", now).unwrap(),
            plain
        );
    }

    #[test]
    fn the_other_mode_is_refused_both_ways() {
        let mut secure = Side::new(1, b"s3cr3t", SecurityMode::ForwardSecrecy);
        let mut default = Side::new(2, b"s3cr3t", SecurityMode::Default);
        let (_, at_server) = connect(&mut secure, &mut default);
        assert_eq!(
            at_server,
            Step::Close(Vec::new(), CloseReason::ModeMismatch)
        );

        let mut secure = Side::new(1, b"s3cr3t", SecurityMode::ForwardSecrecy);
        let mut default = Side::new(2, b"s3cr3t", SecurityMode::Default);
        let (_, at_server) = connect(&mut default, &mut secure);
        assert_eq!(
            at_server,
            Step::Close(Vec::new(), CloseReason::ModeMismatch)
        );
    }

    #[test]
    fn another_network_or_the_same_id_closes() {
        let mut a = Side::new(1, b"s3cr3t", SecurityMode::Default);
        let mut b = Side::new(2, b"other", SecurityMode::Default);
        // The server answers, then closes (spec §6.2).
        let (_, at_b) = connect(&mut a, &mut b);
        assert!(
            matches!(at_b, Step::Close(ref out, CloseReason::ForeignNetwork) if out.len() == 1)
        );

        let mut a = Side::new(3, b"s3cr3t", SecurityMode::Default);
        let mut b = Side::new(3, b"s3cr3t", SecurityMode::Default);
        let (_, at_b) = connect(&mut a, &mut b);
        assert_eq!(at_b, Step::Close(Vec::new(), CloseReason::SameNodeId));

        let mut a = Side::new(3, b"s3cr3t", SecurityMode::ForwardSecrecy);
        let mut b = Side::new(3, b"s3cr3t", SecurityMode::ForwardSecrecy);
        let (_, at_b) = connect(&mut a, &mut b);
        assert_eq!(at_b, Step::Close(Vec::new(), CloseReason::SameNodeId));
    }

    #[test]
    fn a_second_connection_waits_then_joins() {
        let mut a = Side::new(1, b"s3cr3t", SecurityMode::ForwardSecrecy);
        let mut b = Side::new(2, b"s3cr3t", SecurityMode::ForwardSecrecy);
        let (mut first, msg1) = with(&mut a, |hs| Link::client(hs, Some(2))).unwrap();
        assert_eq!(
            with(&mut a, |hs| Link::client(hs, Some(2))).err(),
            Some(CloseReason::WaitForSession)
        );
        let mut at_b = Link::server(Instant::now());
        let Step::Send(msg2) = with(&mut b, |hs| at_b.handshake(hs, &msg1)) else {
            panic!("msg2 expected");
        };
        let Step::Up(msg3, _) = with(&mut a, |hs| first.handshake(hs, &msg2[0])) else {
            panic!("up expected");
        };
        assert!(matches!(
            with(&mut b, |hs| at_b.handshake(hs, &msg3[0])),
            Step::Up(..)
        ));
        // Now the second connection asks to join the session.
        let (mut second, msg1) = with(&mut a, |hs| Link::client(hs, Some(2))).unwrap();
        let mut at_b_too = Link::server(Instant::now());
        let Step::Send(msg2) = with(&mut b, |hs| at_b_too.handshake(hs, &msg1)) else {
            panic!("msg2 expected");
        };
        let Step::Up(msg3, _) = with(&mut a, |hs| second.handshake(hs, &msg2[0])) else {
            panic!("up expected");
        };
        assert!(matches!(
            with(&mut b, |hs| at_b_too.handshake(hs, &msg3[0])),
            Step::Up(..)
        ));
        let key = SessionKey {
            namespace: Namespace::Direct,
            network: NETWORK.into(),
            peer_id: 1,
        };
        assert_eq!(b.sessions.get(&key).unwrap().connections(), 2);
    }

    fn admitted(admission: Admission) -> (Ticket, Option<Ticket>) {
        match admission {
            Admission::Admitted(ticket, evicted) => (ticket, evicted),
            Admission::Dropped => panic!("dropped"),
        }
    }

    #[test]
    fn handshakes_are_limited_by_source_address() {
        let now = Instant::now();
        let mut budget = HandshakeBudget::new();
        let forger: IpAddr = "203.0.113.7".parse().unwrap();
        let first = admitted(budget.admit(forger, Transport::Tcp, false, now)).0;
        for _ in 1..HANDSHAKES_PER_SOURCE {
            assert_eq!(
                admitted(budget.admit(forger, Transport::Tcp, false, now)).1,
                None
            );
        }
        // The ninth from the same address pushes out its own oldest.
        assert_eq!(
            admitted(budget.admit(forger, Transport::Tcp, false, now)).1,
            Some(first)
        );
        assert_eq!(budget.len(), HANDSHAKES_PER_SOURCE);
        // Another source is not held back by it.
        let peer: IpAddr = "198.51.100.1".parse().unwrap();
        let (ticket, evicted) = admitted(budget.admit(peer, Transport::Tcp, true, now));
        assert_eq!(evicted, None);
        budget.finished(ticket);
        assert_eq!(budget.len(), HANDSHAKES_PER_SOURCE);

        // IPv6 counts by /64.
        let mut budget = HandshakeBudget::new();
        let base: IpAddr = "2001:db8:1:2::1".parse().unwrap();
        let first = admitted(budget.admit(base, Transport::Tcp, false, now)).0;
        for n in 2..=HANDSHAKES_PER_SOURCE as u16 {
            let address: IpAddr = format!("2001:db8:1:2::{n:x}").parse().unwrap();
            assert_eq!(
                admitted(budget.admit(address, Transport::Tcp, false, now)).1,
                None
            );
        }
        let same_64: IpAddr = "2001:db8:1:2:ffff::9".parse().unwrap();
        assert_eq!(
            admitted(budget.admit(same_64, Transport::Tcp, false, now)).1,
            Some(first)
        );
        budget.release(first);
    }

    #[test]
    fn a_source_starts_a_limited_number_of_handshakes_a_second() {
        let now = Instant::now();
        let mut budget = HandshakeBudget::new();
        let source: IpAddr = "203.0.113.9".parse().unwrap();
        let mut admitted_now = 0;
        for _ in 0..40 {
            if let Admission::Admitted(ticket, _) = budget.admit(source, Transport::Udp, false, now)
            {
                admitted_now += 1;
                budget.release(ticket);
            }
        }
        assert_eq!(admitted_now, MSG1_BURST as usize);
        let later = now + Duration::from_secs(1);
        let mut admitted_later = 0;
        for _ in 0..40 {
            if let Admission::Admitted(ticket, _) =
                budget.admit(source, Transport::Udp, false, later)
            {
                admitted_later += 1;
                budget.release(ticket);
            }
        }
        assert_eq!(admitted_later, MSG1_PER_SECOND as usize);
    }

    #[test]
    fn members_keep_their_places_and_strangers_over_udp_go_first() {
        let now = Instant::now();
        let mut budget = HandshakeBudget::new();
        // Strangers over TCP, one per source, fill what is not reserved.
        let mut n = 0u32;
        let mut stranger = || {
            n += 1;
            IpAddr::from((0x0a00_0000 + n).to_be_bytes())
        };
        for _ in 0..MAX_HANDSHAKES - RESERVED_FOR_MEMBERS {
            admitted(budget.admit(stranger(), Transport::Tcp, false, now));
        }
        // One more stranger pushes out the oldest stranger.
        let (_, evicted) = admitted(budget.admit(stranger(), Transport::Tcp, false, now));
        assert!(evicted.is_some());
        assert_eq!(budget.len(), MAX_HANDSHAKES - RESERVED_FOR_MEMBERS);
        // Members still get in without pushing anyone out.
        for m in 0..RESERVED_FOR_MEMBERS as u32 {
            let member = IpAddr::from((0xc000_0200 + m).to_be_bytes());
            assert_eq!(
                admitted(budget.admit(member, Transport::Tcp, true, now)).1,
                None
            );
        }
        assert_eq!(budget.len(), MAX_HANDSHAKES);

        // Full: a UDP handshake from a source that never finished one goes
        // before older TCP ones.
        let mut budget = HandshakeBudget::new();
        let mut n = 0u32;
        let mut udp_ticket = None;
        while budget.len() < MAX_HANDSHAKES {
            n += 1;
            let address = IpAddr::from((0x0a00_0000 + n).to_be_bytes());
            let member = budget.len() >= MAX_HANDSHAKES - RESERVED_FOR_MEMBERS;
            let transport = if n == 500 {
                Transport::Udp
            } else {
                Transport::Tcp
            };
            let (ticket, _) = admitted(budget.admit(address, transport, member, now));
            if n == 500 {
                udp_ticket = Some(ticket);
            }
        }
        let member: IpAddr = "192.0.2.200".parse().unwrap();
        assert_eq!(
            admitted(budget.admit(member, Transport::Tcp, true, now)).1,
            udp_ticket
        );
        assert!(!budget.is_empty());
    }

    #[test]
    fn handshakes_time_out() {
        let start = Instant::now();
        let mut link = Link::server(start);
        assert!(!link.timed_out(start + HANDSHAKE_TIMEOUT / 2));
        assert!(link.timed_out(start + HANDSHAKE_TIMEOUT));
        assert!(link.is_closed());
    }

    #[test]
    fn compressed_payloads_are_checked() {
        let now = Instant::now();
        let mut crypto = Crypto::Default(None);
        let body = vec![7u8; 900];
        let mut compressed = ruzstd::encoding::compress_to_vec(
            &body[..],
            ruzstd::encoding::CompressionLevel::Fastest,
        );
        compressed.push(ZSTD);
        let mut header = NodeHeader::new(1, 2, packet_type::DATA, body.len() as u32);
        header.flags = flags::COMPRESSED;
        let mut sent = header.encode().to_vec();
        sent.extend_from_slice(&compressed);
        assert_eq!(open(&mut crypto, 1, &sent, now).unwrap().payload, body);

        // A length that does not match, and lzo.
        header.len = 800;
        let mut wrong = header.encode().to_vec();
        wrong.extend_from_slice(&compressed);
        assert_eq!(open(&mut crypto, 1, &wrong, now), Err(Dropped::Malformed));
        let mut lzo = sent.clone();
        *lzo.last_mut().unwrap() = 2;
        assert_eq!(open(&mut crypto, 1, &lzo, now), Err(Dropped::Malformed));
    }
}
