//! The two secure handshakes end to end: the direct one between neighbours
//! (Noise XX, spec §8.1–§8.4) and the relay one between nodes that are not
//! neighbours (Noise IK, spec §9). Each side is a small state machine fed
//! the payloads of the handshake packets; the caller frames them and reads
//! the peer's node ID from the packet header.
//!
//! Authentication (spec §8.3): a direct peer must prove the network secret,
//! or have a static key this node trusts. The weakest level of the
//! specification, encrypted but unauthenticated, is never accepted. A
//! relay peer's static key must be the one its route information
//! announces; the IK pattern proves possession of it. A direct peer's
//! static key is checked the same way when the caller knows it.
//!
//! A peer that uses this node's own ID is refused (spec §5.3, §8.1): both
//! directions would derive the same key and nonces. Before the peer is
//! authenticated that only closes the connection
//! ([`HandshakeError::SameNodeId`]); a server that proved the network
//! secret under this node's ID is an ID conflict
//! ([`HandshakeError::IdConflict`]).

use std::time::Instant;

use ring::rand::SecureRandom;
use zeroize::Zeroizing;

use crate::config::Cipher;
use crate::legacy::handshake::FOREIGN_PREFIX;
use crate::route::messages::Uuid;

use super::messages::{Action, MessageError, Msg1, Msg2, Msg3, RelayMsg1, RelayMsg2, RoleHint};
use super::noise::{HandshakeState, KeyPair, NoiseError, Pattern, LEN};
use super::proof::{self, PROOF_LEN};
use super::session::{
    seen_digest, Agreement, Ciphers, Namespace, RelayLookup, SessionError, SessionKey, Sessions,
    Side,
};
use super::{PROLOGUE_CONN, PROLOGUE_RELAY};

/// This node as the handshakes see it. Has no `Debug`: it holds the
/// secret and the private key.
pub struct Local {
    pub id: u32,
    pub static_key: KeyPair,
    pub network_name: String,
    /// The name put after the foreign prefix for a client of another
    /// network (spec §8.1 msg2 field 1).
    pub node_name: String,
    pub secret: Option<Vec<u8>>,
    /// The network digest (spec §6.3), sent in msg3 with the secret.
    pub digest: Option<[u8; 32]>,
    /// The cipher this node sends with.
    pub cipher: Cipher,
    /// Static keys accepted without a secret proof (spec §8.3 level 2).
    pub trusted_keys: Vec<[u8; LEN]>,
}

/// How the peer was authenticated (spec §8.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Auth {
    /// The peer proved the network secret.
    SecretConfirmed,
    /// The peer holds a static key this node trusts.
    PeerVerified,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HandshakeError {
    Noise(NoiseError),
    Message(MessageError),
    Session(SessionError),
    /// A connection ID was not echoed back.
    ConnIdMismatch,
    /// The peer is in another network; close the connection.
    ForeignNetwork,
    /// The peer's secret proof is wrong: it holds another secret.
    BadProof,
    /// The peer neither proved the secret nor holds a trusted key.
    Unauthenticated,
    /// The system random source failed.
    Random,
    /// The peer uses this node's ID and is not authenticated: close the
    /// connection, change nothing (spec §8.1).
    SameNodeId,
    /// The server proved the network secret under this node's ID: an ID
    /// conflict (spec §5.3).
    IdConflict,
    /// A relay msg1 seen before and no longer pending: dropped without an
    /// answer (spec §9).
    Replayed,
    /// The peer's static key is not the one its route information
    /// announces.
    UnexpectedStaticKey,
}

impl From<NoiseError> for HandshakeError {
    fn from(error: NoiseError) -> Self {
        HandshakeError::Noise(error)
    }
}

impl From<MessageError> for HandshakeError {
    fn from(error: MessageError) -> Self {
        HandshakeError::Message(error)
    }
}

impl From<SessionError> for HandshakeError {
    fn from(error: SessionError) -> Self {
        HandshakeError::Session(error)
    }
}

/// A finished handshake; the session is installed in [`Sessions`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Established {
    pub key: SessionKey,
    pub peer_static: [u8; LEN],
    pub auth: Auth,
    /// For the relay responder, Create means pending: the session is
    /// installed when the first packet decrypts under it.
    pub action: Action,
    pub generation: u32,
}

fn other_node(local: &Local, peer_id: u32) -> Result<(), HandshakeError> {
    if peer_id == local.id {
        Err(HandshakeError::SameNodeId)
    } else {
        Ok(())
    }
}

/// Checks `peer_static` against the key the peer's route information
/// announces, when the caller knows it.
fn expected_key(
    expected_static: Option<[u8; LEN]>,
    peer_static: &[u8; LEN],
) -> Result<(), HandshakeError> {
    match expected_static {
        Some(expected) if expected != *peer_static => Err(HandshakeError::UnexpectedStaticKey),
        _ => Ok(()),
    }
}

fn random_uuid(rng: &dyn SecureRandom) -> Result<Uuid, HandshakeError> {
    let mut id = [0u8; 16];
    rng.fill(&mut id).map_err(|_| HandshakeError::Random)?;
    Ok(Uuid(id))
}

fn session_key(namespace: Namespace, local: &Local, peer_id: u32) -> SessionKey {
    SessionKey {
        namespace,
        network: local.network_name.clone(),
        peer_id,
    }
}

/// Spec §8.3 for a direct peer: a proof is checked when this node holds
/// the secret, and a wrong one is final; otherwise the peer's key must be
/// trusted.
fn authenticate(
    local: &Local,
    received: Option<&[u8; PROOF_LEN]>,
    challenge: &[u8; LEN],
    peer_static: &[u8; LEN],
) -> Result<Auth, HandshakeError> {
    if let (Some(secret), Some(received)) = (&local.secret, received) {
        return if proof::verify(secret, challenge, received) {
            Ok(Auth::SecretConfirmed)
        } else {
            Err(HandshakeError::BadProof)
        };
    }
    if local.trusted_keys.contains(peer_static) {
        Ok(Auth::PeerVerified)
    } else {
        Err(HandshakeError::Unauthenticated)
    }
}

fn own_proof(local: &Local, challenge: &[u8; LEN]) -> Option<[u8; PROOF_LEN]> {
    local
        .secret
        .as_deref()
        .map(|secret| proof::proof(secret, challenge))
}

/// The client of a direct handshake: sends msg1, reads msg2, sends msg3.
pub struct Client {
    noise: HandshakeState,
    conn_id: Uuid,
    /// The handshake hash after msg1: the server proves over it.
    after_msg1: [u8; LEN],
    /// The session this handshake asks to create, if any (spec §8.1).
    creating: Option<SessionKey>,
}

impl Client {
    /// `known_peer` is the node ID this connection is expected to reach, if
    /// any; its session's generation goes into msg1. Without a session,
    /// only one connection to the peer at a time asks for one: the others
    /// get [`SessionError::Busy`] and start again once it is up (spec
    /// §8.1). Returns msg1.
    pub fn start(
        local: &Local,
        known_peer: Option<u32>,
        sessions: &mut Sessions,
        rng: &dyn SecureRandom,
        now: Instant,
    ) -> Result<(Self, Vec<u8>), HandshakeError> {
        if let Some(peer) = known_peer {
            other_node(local, peer)?;
        }
        let mut noise = HandshakeState::new(
            Pattern::Xx,
            true,
            &PROLOGUE_CONN,
            local.static_key.clone(),
            None,
        )?;
        let conn_id = random_uuid(rng)?;
        let known_key = known_peer.map(|peer| session_key(Namespace::Direct, local, peer));
        let session_generation = match &known_key {
            Some(key) => sessions.client_start(key, now)?,
            None => None,
        };
        let creating = known_key.filter(|_| session_generation.is_none());
        let payload = Msg1 {
            network_name: local.network_name.clone(),
            session_generation,
            conn_id,
            cipher: local.cipher,
        }
        .encode()?;
        let message = noise.write_message(&payload);
        let message = match message {
            Ok(message) => message,
            Err(error) => {
                if let Some(key) = &creating {
                    sessions.client_done(key);
                }
                return Err(error.into());
            }
        };
        let after_msg1 = noise.handshake_hash();
        Ok((
            Self {
                noise,
                conn_id,
                after_msg1,
                creating,
            },
            message,
        ))
    }

    /// The connection ends before msg2: another connection to the peer may
    /// ask for the session at once.
    pub fn abandon(mut self, sessions: &mut Sessions) {
        if let Some(key) = self.creating.take() {
            sessions.client_done(&key);
        }
    }

    /// Reads msg2 from `peer_id` (its packet header) and returns msg3.
    /// `expected_static` is the key `peer_id`'s route information announces,
    /// if known.
    pub fn finish(
        mut self,
        local: &Local,
        peer_id: u32,
        expected_static: Option<[u8; LEN]>,
        msg2: &[u8],
        sessions: &mut Sessions,
        now: Instant,
    ) -> Result<(Vec<u8>, Established), HandshakeError> {
        if let Some(key) = self.creating.take() {
            sessions.client_done(&key);
        }
        let read = self.read_msg2(local, expected_static, msg2);
        if peer_id == local.id {
            // Nothing is sent or installed either way.
            return Err(match read {
                Ok(_) => HandshakeError::IdConflict,
                Err(_) => HandshakeError::SameNodeId,
            });
        }
        let (msg2, peer_static, auth) = read?;

        let key = session_key(Namespace::Direct, local, peer_id);
        let ciphers = Ciphers {
            local: local.cipher,
            peer: msg2.cipher,
        };
        let agreement = sessions.client_agreement(
            &key,
            msg2.action,
            msg2.session_generation,
            msg2.root_key.as_deref().copied(),
            msg2.initial_epoch,
            ciphers,
        )?;

        let after_msg2 = self.noise.handshake_hash();
        let payload = Msg3 {
            client_conn_id_echo: self.conn_id,
            server_conn_id_echo: msg2.conn_id,
            secret_proof: own_proof(local, &after_msg2),
            secret_digest: local.secret.as_ref().and(local.digest),
        }
        .encode();
        let message = self.noise.write_message(&payload)?;
        sessions.install(
            key.clone(),
            &agreement,
            local.id,
            ciphers,
            peer_static,
            Side::Client,
            now,
        )?;
        Ok((
            message,
            Established {
                key,
                peer_static,
                auth,
                action: agreement.action,
                generation: agreement.generation,
            },
        ))
    }

    /// Decrypts and checks msg2: connection ID, network, static key and
    /// the server's proof.
    fn read_msg2(
        &mut self,
        local: &Local,
        expected_static: Option<[u8; LEN]>,
        msg2: &[u8],
    ) -> Result<(Msg2, [u8; LEN], Auth), HandshakeError> {
        let plain = Zeroizing::new(self.noise.read_message(msg2)?);
        let msg2 = Msg2::decode(&plain)?;
        if msg2.peer_conn_id_echo != self.conn_id {
            return Err(HandshakeError::ConnIdMismatch);
        }
        if msg2.role_hint != RoleHint::SameNetwork || msg2.network_name != local.network_name {
            return Err(HandshakeError::ForeignNetwork);
        }
        let peer_static = self
            .noise
            .remote_static()
            .ok_or(HandshakeError::Noise(NoiseError::OutOfTurn))?;
        expected_key(expected_static, &peer_static)?;
        let auth = authenticate(
            local,
            msg2.secret_proof.as_ref(),
            &self.after_msg1,
            &peer_static,
        )?;
        Ok((msg2, peer_static, auth))
    }
}

/// The server of a direct handshake: reads msg1, sends msg2, reads msg3.
pub struct Server {
    noise: HandshakeState,
    conn_id: Uuid,
    client_conn_id: Uuid,
    peer_id: u32,
    /// `None` for a client of another network.
    pending: Option<(SessionKey, Agreement, Ciphers)>,
    /// The handshake hash after msg2: the client proves over it.
    after_msg2: [u8; LEN],
}

impl Server {
    /// Reads msg1 from `peer_id` (its packet header) and returns msg2. The
    /// session is chosen now and installed only by [`Server::finish`]. A
    /// Create is this handshake's alone: other msg1 from the same node ID
    /// run in parallel with their own (spec §8.1).
    pub fn respond(
        local: &Local,
        peer_id: u32,
        msg1: &[u8],
        sessions: &mut Sessions,
        rng: &dyn SecureRandom,
    ) -> Result<(Self, Vec<u8>), HandshakeError> {
        other_node(local, peer_id)?;
        let mut noise = HandshakeState::new(
            Pattern::Xx,
            false,
            &PROLOGUE_CONN,
            local.static_key.clone(),
            None,
        )?;
        let msg1 = Msg1::decode(&noise.read_message(msg1)?)?;
        let after_msg1 = noise.handshake_hash();
        let conn_id = random_uuid(rng)?;

        let (reply, pending) = if msg1.network_name == local.network_name {
            let key = session_key(Namespace::Direct, local, peer_id);
            let ciphers = Ciphers {
                local: local.cipher,
                peer: msg1.cipher,
            };
            let agreement = sessions.server_choice(&key, msg1.session_generation, ciphers, rng)?;
            let reply = Msg2 {
                network_name: local.network_name.clone(),
                role_hint: RoleHint::SameNetwork,
                action: agreement.action,
                session_generation: agreement.generation,
                root_key: agreement
                    .action
                    .carries_root_key()
                    .then(|| Zeroizing::new(agreement.root_key)),
                initial_epoch: agreement.initial_epoch,
                conn_id,
                peer_conn_id_echo: msg1.conn_id,
                secret_proof: own_proof(local, &after_msg1),
                cipher: local.cipher,
            };
            (reply, Some((key, agreement, ciphers)))
        } else {
            let mut name = String::from_utf8(FOREIGN_PREFIX.to_vec()).expect("ASCII prefix");
            name.push_str(&local.node_name);
            let reply = Msg2 {
                network_name: name,
                role_hint: RoleHint::Other,
                action: Action::Join,
                session_generation: 0,
                root_key: None,
                initial_epoch: 0,
                conn_id,
                peer_conn_id_echo: msg1.conn_id,
                secret_proof: None,
                cipher: local.cipher,
            };
            (reply, None)
        };
        let encoded = Zeroizing::new(reply.encode()?);
        let message = noise.write_message(&encoded)?;
        let after_msg2 = noise.handshake_hash();
        Ok((
            Self {
                noise,
                conn_id,
                client_conn_id: msg1.conn_id,
                peer_id,
                pending,
                after_msg2,
            },
            message,
        ))
    }

    /// Whether msg2 told the client it is in another network; the
    /// connection closes after msg2 is sent.
    pub fn is_foreign(&self) -> bool {
        self.pending.is_none()
    }

    /// The node ID msg1 came from.
    pub fn peer_id(&self) -> u32 {
        self.peer_id
    }

    /// Reads msg3, authenticates the client and installs the session: a
    /// Create only over a session of a lower generation (spec §8.1).
    /// `expected_static` is the key the client's route information
    /// announces, if known.
    pub fn finish(
        mut self,
        local: &Local,
        expected_static: Option<[u8; LEN]>,
        msg3: &[u8],
        sessions: &mut Sessions,
        now: Instant,
    ) -> Result<Established, HandshakeError> {
        let (key, agreement, ciphers) =
            self.pending.take().ok_or(HandshakeError::ForeignNetwork)?;
        let (peer_static, auth) = self.check_msg3(local, expected_static, msg3)?;
        sessions.install(
            key.clone(),
            &agreement,
            local.id,
            ciphers,
            peer_static,
            Side::Server,
            now,
        )?;
        Ok(Established {
            key,
            peer_static,
            auth,
            action: agreement.action,
            generation: agreement.generation,
        })
    }

    fn check_msg3(
        &mut self,
        local: &Local,
        expected_static: Option<[u8; LEN]>,
        msg3: &[u8],
    ) -> Result<([u8; LEN], Auth), HandshakeError> {
        let plain = Zeroizing::new(self.noise.read_message(msg3)?);
        let msg3 = Msg3::decode(&plain)?;
        if msg3.client_conn_id_echo != self.client_conn_id
            || msg3.server_conn_id_echo != self.conn_id
        {
            return Err(HandshakeError::ConnIdMismatch);
        }
        let peer_static = self
            .noise
            .remote_static()
            .ok_or(HandshakeError::Noise(NoiseError::OutOfTurn))?;
        expected_key(expected_static, &peer_static)?;
        let auth = authenticate(
            local,
            msg3.secret_proof.as_ref(),
            &self.after_msg2,
            &peer_static,
        )?;
        Ok((peer_static, auth))
    }
}

/// When both nodes start a relay handshake at once, the one with the
/// smaller node ID stays the initiator (spec §9).
pub fn keeps_initiating(local_id: u32, peer_id: u32) -> bool {
    local_id < peer_id
}

/// The initiator of a relay handshake.
pub struct RelayInitiator {
    noise: HandshakeState,
    conn_id: Uuid,
    peer_id: u32,
    peer_static: [u8; LEN],
}

impl RelayInitiator {
    /// `peer_static` is the key in the peer's route information. Returns
    /// relay msg1.
    pub fn start(
        local: &Local,
        peer_id: u32,
        peer_static: [u8; LEN],
        sessions: &Sessions,
        rng: &dyn SecureRandom,
    ) -> Result<(Self, Vec<u8>), HandshakeError> {
        other_node(local, peer_id)?;
        let mut noise = HandshakeState::new(
            Pattern::Ik,
            true,
            &PROLOGUE_RELAY,
            local.static_key.clone(),
            Some(peer_static),
        )?;
        let conn_id = random_uuid(rng)?;
        let payload = RelayMsg1 {
            session_generation: sessions.generation(&session_key(Namespace::Relay, local, peer_id)),
            conn_id,
            cipher: local.cipher,
        }
        .encode()?;
        let message = noise.write_message(&payload)?;
        Ok((
            Self {
                noise,
                conn_id,
                peer_id,
                peer_static,
            },
            message,
        ))
    }

    pub fn peer_id(&self) -> u32 {
        self.peer_id
    }

    /// Reads relay msg2 and installs the session.
    pub fn finish(
        mut self,
        local: &Local,
        msg2: &[u8],
        sessions: &mut Sessions,
        now: Instant,
    ) -> Result<Established, HandshakeError> {
        let plain = Zeroizing::new(self.noise.read_message(msg2)?);
        let msg2 = RelayMsg2::decode(&plain)?;
        if msg2.peer_conn_id_echo != self.conn_id {
            return Err(HandshakeError::ConnIdMismatch);
        }
        let key = session_key(Namespace::Relay, local, self.peer_id);
        let ciphers = Ciphers {
            local: local.cipher,
            peer: msg2.cipher,
        };
        let agreement = sessions.client_agreement(
            &key,
            msg2.action,
            msg2.session_generation,
            msg2.root_key.as_deref().copied(),
            msg2.initial_epoch,
            ciphers,
        )?;
        sessions.install(
            key.clone(),
            &agreement,
            local.id,
            ciphers,
            self.peer_static,
            Side::Client,
            now,
        )?;
        Ok(Established {
            key,
            peer_static: self.peer_static,
            auth: Auth::PeerVerified,
            action: agreement.action,
            generation: agreement.generation,
        })
    }
}

/// What a relay responder sends back.
#[derive(Debug, PartialEq, Eq)]
pub enum RelayAnswer {
    /// A new answer: Join, or a Create now pending until the first packet
    /// decrypts under it (spec §9).
    Reply(Vec<u8>, Established),
    /// The msg1 of a session still pending, relayed again or replayed:
    /// the same msg2 again, nothing changed.
    Repeat(Vec<u8>),
}

/// Answers relay msg1 from `peer_id` (its packet header), whose route
/// information announces `expected_static` (spec §9). This node never
/// syncs: a msg1 without the current generation gets a Create, kept
/// pending until a packet decrypts under it, so a replayed msg1 can neither
/// move the session on nor replace it. A msg1 is known by its ephemeral
/// key: one seen before gets its msg2 again while its session is pending
/// and [`HandshakeError::Replayed`] after.
pub fn relay_respond(
    local: &Local,
    peer_id: u32,
    expected_static: Option<[u8; LEN]>,
    msg1: &[u8],
    sessions: &mut Sessions,
    rng: &dyn SecureRandom,
    now: Instant,
) -> Result<RelayAnswer, HandshakeError> {
    other_node(local, peer_id)?;
    let key = session_key(Namespace::Relay, local, peer_id);
    let ephemeral = msg1
        .get(..LEN)
        .ok_or(HandshakeError::Noise(NoiseError::Truncated))?;
    let seen = seen_digest(ephemeral);
    match sessions.relay_lookup(&key, &seen, now) {
        RelayLookup::New => {}
        RelayLookup::Repeat(msg2) => return Ok(RelayAnswer::Repeat(msg2)),
        RelayLookup::Replayed => return Err(HandshakeError::Replayed),
    }
    let mut noise = HandshakeState::new(
        Pattern::Ik,
        false,
        &PROLOGUE_RELAY,
        local.static_key.clone(),
        None,
    )?;
    let plain = Zeroizing::new(noise.read_message(msg1)?);
    let msg1 = RelayMsg1::decode(&plain)?;
    let peer_static = noise
        .remote_static()
        .ok_or(HandshakeError::Noise(NoiseError::OutOfTurn))?;
    if expected_static != Some(peer_static) {
        return Err(HandshakeError::Unauthenticated);
    }
    sessions.remember_seen(&key, seen);
    let ciphers = Ciphers {
        local: local.cipher,
        peer: msg1.cipher,
    };
    let agreement = sessions.server_choice(&key, msg1.session_generation, ciphers, rng)?;
    let reply = RelayMsg2 {
        action: agreement.action,
        session_generation: agreement.generation,
        root_key: agreement
            .action
            .carries_root_key()
            .then(|| Zeroizing::new(agreement.root_key)),
        initial_epoch: agreement.initial_epoch,
        conn_id: random_uuid(rng)?,
        peer_conn_id_echo: msg1.conn_id,
        cipher: local.cipher,
    };
    let encoded = Zeroizing::new(reply.encode()?);
    let message = noise.write_message(&encoded)?;
    if agreement.action == Action::Create {
        sessions.add_pending(
            &key,
            seen,
            &agreement,
            local.id,
            ciphers,
            peer_static,
            message.clone(),
            now,
        )?;
    }
    Ok(RelayAnswer::Reply(
        message,
        Established {
            key,
            peer_static,
            auth: Auth::PeerVerified,
            action: agreement.action,
            generation: agreement.generation,
        },
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ring::rand::SystemRandom;

    fn local(id: u32, secret: Option<&[u8]>, cipher: Cipher) -> Local {
        Local {
            id,
            static_key: KeyPair::generate(&SystemRandom::new()).unwrap(),
            network_name: "office".into(),
            node_name: format!("node{id}"),
            secret: secret.map(<[u8]>::to_vec),
            digest: secret.map(|_| [5; 32]),
            cipher,
            trusted_keys: Vec::new(),
        }
    }

    struct Pair {
        client: Local,
        server: Local,
        at_client: Sessions,
        at_server: Sessions,
    }

    impl Pair {
        fn new(client: Local, server: Local) -> Self {
            Self {
                client,
                server,
                at_client: Sessions::new(),
                at_server: Sessions::new(),
            }
        }

        fn run(&mut self) -> Result<(Established, Established), HandshakeError> {
            let rng = SystemRandom::new();
            let now = Instant::now();
            let (client, msg1) = Client::start(
                &self.client,
                Some(self.server.id),
                &mut self.at_client,
                &rng,
                now,
            )?;
            let (server, msg2) = Server::respond(
                &self.server,
                self.client.id,
                &msg1,
                &mut self.at_server,
                &rng,
            )?;
            let (msg3, at_client) = client.finish(
                &self.client,
                self.server.id,
                Some(self.server.static_key.public()),
                &msg2,
                &mut self.at_client,
                now,
            )?;
            let at_server = server.finish(
                &self.server,
                Some(self.client.static_key.public()),
                &msg3,
                &mut self.at_server,
                now,
            )?;
            Ok((at_client, at_server))
        }

        fn check_traffic(&mut self) {
            let now = Instant::now();
            let client_key = session_key(Namespace::Direct, &self.client, self.server.id);
            let server_key = session_key(Namespace::Direct, &self.server, self.client.id);
            let mut packet = b"ping".to_vec();
            self.at_client.seal(&client_key, &mut packet, now).unwrap();
            self.at_server.open(&server_key, &mut packet, now).unwrap();
            assert_eq!(packet, b"ping");
        }
    }

    #[test]
    fn same_secret_creates_then_joins() {
        let mut pair = Pair::new(
            local(1, Some(b"s3cr3t"), Cipher::Aes128Gcm),
            local(2, Some(b"s3cr3t"), Cipher::ChaCha20Poly1305),
        );
        let (at_client, at_server) = pair.run().unwrap();
        assert_eq!(at_client.auth, Auth::SecretConfirmed);
        assert_eq!(at_server.auth, Auth::SecretConfirmed);
        assert_eq!(at_client.action, Action::Create);
        assert_eq!(at_client.peer_static, pair.server.static_key.public());
        assert_eq!(at_server.peer_static, pair.client.static_key.public());
        let generation = at_server.generation;
        pair.check_traffic();

        let (at_client, at_server) = pair.run().unwrap();
        assert_eq!(at_client.action, Action::Join);
        assert_eq!(at_server.generation, generation);
        pair.check_traffic();
    }

    #[test]
    fn a_lost_session_is_replaced_not_synced() {
        let mut pair = Pair::new(
            local(1, Some(b"s3cr3t"), Cipher::Aes128Gcm),
            local(2, Some(b"s3cr3t"), Cipher::Aes128Gcm),
        );
        let (first, _) = pair.run().unwrap();
        let client_key = session_key(Namespace::Direct, &pair.client, 2);
        pair.at_client.invalidate(&client_key);
        let (at_client, _) = pair.run().unwrap();
        assert_eq!(at_client.action, Action::Create);
        assert_eq!(at_client.generation, first.generation + 1);
        pair.check_traffic();
    }

    #[test]
    fn a_different_secret_is_refused_by_the_client() {
        let mut pair = Pair::new(
            local(1, Some(b"s3cr3t"), Cipher::Aes128Gcm),
            local(2, Some(b"other"), Cipher::Aes128Gcm),
        );
        assert_eq!(pair.run().err(), Some(HandshakeError::BadProof));
        assert!(pair.at_client.is_empty());
        assert!(pair.at_server.is_empty());
        // The failed attempt does not hold back the next one.
        assert_eq!(pair.run().err(), Some(HandshakeError::BadProof));
    }

    #[test]
    fn without_a_secret_only_trusted_keys_pass() {
        let client = local(1, None, Cipher::Aes128Gcm);
        let mut server = local(2, Some(b"s3cr3t"), Cipher::Aes128Gcm);
        let mut untrusted = Pair::new(
            local(1, None, Cipher::Aes128Gcm),
            local(2, None, Cipher::Aes128Gcm),
        );
        assert_eq!(untrusted.run().err(), Some(HandshakeError::Unauthenticated));

        server.trusted_keys.push(client.static_key.public());
        let mut client = client;
        client.trusted_keys.push(server.static_key.public());
        let mut pair = Pair::new(client, server);
        let (at_client, at_server) = pair.run().unwrap();
        assert_eq!(at_client.auth, Auth::PeerVerified);
        assert_eq!(at_server.auth, Auth::PeerVerified);
        pair.check_traffic();
    }

    #[test]
    fn another_network_gets_the_foreign_name() {
        let rng = SystemRandom::new();
        let now = Instant::now();
        let client = local(1, Some(b"s3cr3t"), Cipher::Aes128Gcm);
        let mut server = local(2, Some(b"s3cr3t"), Cipher::Aes128Gcm);
        server.network_name = "lab".into();
        let (client_side, msg1) =
            Client::start(&client, None, &mut Sessions::new(), &rng, now).unwrap();
        let (server_side, msg2) =
            Server::respond(&server, 1, &msg1, &mut Sessions::new(), &rng).unwrap();
        assert!(server_side.is_foreign());
        let mut sessions = Sessions::new();
        assert_eq!(
            client_side
                .finish(&client, 2, None, &msg2, &mut sessions, now)
                .err(),
            Some(HandshakeError::ForeignNetwork)
        );
        assert!(sessions.is_empty());
    }

    #[test]
    fn tampered_messages_fail() {
        let rng = SystemRandom::new();
        let now = Instant::now();
        let client = local(1, Some(b"s3cr3t"), Cipher::Aes128Gcm);
        let server = local(2, Some(b"s3cr3t"), Cipher::Aes128Gcm);
        let (client_side, msg1) =
            Client::start(&client, None, &mut Sessions::new(), &rng, now).unwrap();
        let (_, mut msg2) = Server::respond(&server, 1, &msg1, &mut Sessions::new(), &rng).unwrap();
        let last = msg2.len() - 1;
        msg2[last] ^= 1;
        assert_eq!(
            client_side
                .finish(&client, 2, None, &msg2, &mut Sessions::new(), now)
                .err(),
            Some(HandshakeError::Noise(NoiseError::Decrypt))
        );
    }

    #[test]
    fn the_own_node_id_is_refused_and_a_proven_one_is_a_conflict() {
        let rng = SystemRandom::new();
        let now = Instant::now();
        let a = local(4, Some(b"s3cr3t"), Cipher::Aes128Gcm);
        let b = local(4, Some(b"s3cr3t"), Cipher::Aes128Gcm);
        let mut sessions = Sessions::new();
        assert_eq!(
            Client::start(&a, Some(4), &mut sessions, &rng, now).err(),
            Some(HandshakeError::SameNodeId)
        );
        let (client, msg1) = Client::start(&a, None, &mut sessions, &rng, now).unwrap();
        assert_eq!(
            Server::respond(&b, 4, &msg1, &mut sessions, &rng).err(),
            Some(HandshakeError::SameNodeId)
        );
        // A server that proves the secret under this node's ID.
        let (_, msg2) = Server::respond(&b, 5, &msg1, &mut sessions, &rng).unwrap();
        let mut at_a = Sessions::new();
        assert_eq!(
            client.finish(&a, 4, None, &msg2, &mut at_a, now).err(),
            Some(HandshakeError::IdConflict)
        );
        // One that does not: only closed.
        let (client, msg1) = Client::start(&a, None, &mut sessions, &rng, now).unwrap();
        let stranger = local(4, Some(b"other"), Cipher::Aes128Gcm);
        let (_, msg2) = Server::respond(&stranger, 5, &msg1, &mut sessions, &rng).unwrap();
        assert_eq!(
            client.finish(&a, 4, None, &msg2, &mut at_a, now).err(),
            Some(HandshakeError::SameNodeId)
        );
        assert_eq!(
            RelayInitiator::start(&a, 4, b.static_key.public(), &sessions, &rng).err(),
            Some(HandshakeError::SameNodeId)
        );
        let (_, relay_msg1) =
            RelayInitiator::start(&a, 9, b.static_key.public(), &sessions, &rng).unwrap();
        assert_eq!(
            relay_respond(
                &b,
                4,
                Some(a.static_key.public()),
                &relay_msg1,
                &mut at_a,
                &rng,
                now
            )
            .err(),
            Some(HandshakeError::SameNodeId)
        );
        assert!(at_a.is_empty());
    }

    #[test]
    fn a_direct_peer_must_hold_its_announced_key() {
        let rng = SystemRandom::new();
        let now = Instant::now();
        let client = local(1, Some(b"s3cr3t"), Cipher::Aes128Gcm);
        let server = local(2, Some(b"s3cr3t"), Cipher::Aes128Gcm);
        let announced = KeyPair::generate(&rng).unwrap().public();
        let mut at_server = Sessions::new();

        let (client_side, msg1) =
            Client::start(&client, None, &mut Sessions::new(), &rng, now).unwrap();
        let (_, msg2) = Server::respond(&server, 1, &msg1, &mut Sessions::new(), &rng).unwrap();
        assert_eq!(
            client_side
                .finish(
                    &client,
                    2,
                    Some(announced),
                    &msg2,
                    &mut Sessions::new(),
                    now
                )
                .err(),
            Some(HandshakeError::UnexpectedStaticKey)
        );

        let (client_side, msg1) =
            Client::start(&client, None, &mut Sessions::new(), &rng, now).unwrap();
        let (server_side, msg2) = Server::respond(&server, 1, &msg1, &mut at_server, &rng).unwrap();
        let (msg3, _) = client_side
            .finish(&client, 2, None, &msg2, &mut Sessions::new(), now)
            .unwrap();
        assert_eq!(
            server_side
                .finish(&server, Some(announced), &msg3, &mut at_server, now)
                .err(),
            Some(HandshakeError::UnexpectedStaticKey)
        );
        assert!(at_server.is_empty());
    }

    #[test]
    fn another_key_cannot_take_over_a_session_in_use() {
        let mut pair = Pair::new(
            local(1, Some(b"s3cr3t"), Cipher::Aes128Gcm),
            local(2, Some(b"s3cr3t"), Cipher::Aes128Gcm),
        );
        pair.run().unwrap();
        // Another member of the network claims node 1's ID, with its own
        // key; the server does not know node 1's key from route
        // information yet.
        let rng = SystemRandom::new();
        let now = Instant::now();
        let impostor = local(1, Some(b"s3cr3t"), Cipher::Aes128Gcm);
        let (client_side, msg1) =
            Client::start(&impostor, None, &mut Sessions::new(), &rng, now).unwrap();
        let (server_side, msg2) =
            Server::respond(&pair.server, 1, &msg1, &mut pair.at_server, &rng).unwrap();
        let (msg3, _) = client_side
            .finish(&impostor, 2, None, &msg2, &mut Sessions::new(), now)
            .unwrap();
        assert_eq!(
            server_side
                .finish(&pair.server, None, &msg3, &mut pair.at_server, now)
                .err(),
            Some(HandshakeError::Session(SessionError::StaticKeyMismatch))
        );
        pair.check_traffic();
    }

    #[test]
    fn forged_msg1_under_a_peers_id_do_not_hold_it_back() {
        let mut pair = Pair::new(
            local(1, Some(b"s3cr3t"), Cipher::Aes128Gcm),
            local(2, Some(b"s3cr3t"), Cipher::Aes128Gcm),
        );
        let rng = SystemRandom::new();
        let now = Instant::now();
        // Someone without the secret keeps sending msg1 as node 1 and never
        // answers msg2.
        let forger = local(1, None, Cipher::Aes128Gcm);
        let mut forged = Vec::new();
        for _ in 0..20 {
            let (_, msg1) = Client::start(&forger, None, &mut Sessions::new(), &rng, now).unwrap();
            forged
                .push(Server::respond(&pair.server, 1, &msg1, &mut pair.at_server, &rng).unwrap());
        }
        // The real node 1 still gets its session, and a late forged msg3
        // cannot replace it.
        let (at_client, at_server) = pair.run().unwrap();
        assert_eq!(at_client.action, Action::Create);
        assert!(forged.iter().all(|(_, msg2)| !msg2.is_empty()));
        assert!(at_server.generation > 0);
        pair.check_traffic();
    }

    #[test]
    fn a_client_asks_for_one_new_session_at_a_time() {
        let rng = SystemRandom::new();
        let now = Instant::now();
        let client = local(1, Some(b"s3cr3t"), Cipher::Aes128Gcm);
        let server = local(2, Some(b"s3cr3t"), Cipher::Aes128Gcm);
        let (mut at_client, mut at_server) = (Sessions::new(), Sessions::new());
        let (first, msg1) = Client::start(&client, Some(2), &mut at_client, &rng, now).unwrap();
        assert_eq!(
            Client::start(&client, Some(2), &mut at_client, &rng, now).err(),
            Some(HandshakeError::Session(SessionError::Busy))
        );
        let (server_side, msg2) = Server::respond(&server, 1, &msg1, &mut at_server, &rng).unwrap();
        let (msg3, _) = first
            .finish(&client, 2, None, &msg2, &mut at_client, now)
            .unwrap();
        server_side
            .finish(&server, None, &msg3, &mut at_server, now)
            .unwrap();
        // The second connection now joins.
        let (second, msg1) = Client::start(&client, Some(2), &mut at_client, &rng, now).unwrap();
        let (_, msg2) = Server::respond(&server, 1, &msg1, &mut at_server, &rng).unwrap();
        let (_, joined) = second
            .finish(&client, 2, None, &msg2, &mut at_client, now)
            .unwrap();
        assert_eq!(joined.action, Action::Join);
    }

    fn relay_pair() -> (Local, Local, Sessions, Sessions) {
        (
            local(1, Some(b"s3cr3t"), Cipher::Aes128Gcm),
            local(9, Some(b"s3cr3t"), Cipher::Aes256Gcm),
            Sessions::new(),
            Sessions::new(),
        )
    }

    fn reply(answer: RelayAnswer) -> (Vec<u8>, Established) {
        match answer {
            RelayAnswer::Reply(msg2, established) => (msg2, established),
            RelayAnswer::Repeat(_) => panic!("a repeat"),
        }
    }

    #[test]
    fn relay_handshake_pins_the_announced_key_and_creates_on_the_first_packet() {
        let rng = SystemRandom::new();
        let now = Instant::now();
        let (a, b, mut at_a, mut at_b) = relay_pair();
        let a_key = session_key(Namespace::Relay, &a, b.id);
        let b_key = session_key(Namespace::Relay, &b, a.id);

        let (initiator, msg1) =
            RelayInitiator::start(&a, b.id, b.static_key.public(), &at_a, &rng).unwrap();
        let wrong = Some(KeyPair::generate(&rng).unwrap().public());
        assert_eq!(
            relay_respond(&b, a.id, wrong, &msg1, &mut at_b, &rng, now).err(),
            Some(HandshakeError::Unauthenticated)
        );
        let (msg2, at_responder) = reply(
            relay_respond(
                &b,
                a.id,
                Some(a.static_key.public()),
                &msg1,
                &mut at_b,
                &rng,
                now,
            )
            .unwrap(),
        );
        assert_eq!(at_responder.action, Action::Create);
        assert_eq!(at_responder.peer_static, a.static_key.public());
        assert!(at_b.get(&b_key).is_none(), "pending until the first packet");
        let at_initiator = initiator.finish(&a, &msg2, &mut at_a, now).unwrap();
        assert_eq!(at_initiator.action, Action::Create);

        let mut packet = b"far".to_vec();
        at_a.seal(&a_key, &mut packet, now).unwrap();
        at_b.open(&b_key, &mut packet, now).unwrap();
        assert_eq!(packet, b"far");
        assert_eq!(at_b.generation(&b_key), Some(at_responder.generation));

        // A second handshake without the generation creates again: never
        // Sync.
        at_a.invalidate(&a_key);
        let (initiator, msg1) =
            RelayInitiator::start(&a, b.id, b.static_key.public(), &at_a, &rng).unwrap();
        let (msg2, again) = reply(
            relay_respond(
                &b,
                a.id,
                Some(a.static_key.public()),
                &msg1,
                &mut at_b,
                &rng,
                now,
            )
            .unwrap(),
        );
        assert_eq!(again.action, Action::Create);
        assert_eq!(again.generation, at_responder.generation + 1);
        initiator.finish(&a, &msg2, &mut at_a, now).unwrap();
        let mut packet = b"again".to_vec();
        at_a.seal(&a_key, &mut packet, now).unwrap();
        at_b.open(&b_key, &mut packet, now).unwrap();
        assert_eq!(packet, b"again");

        assert!(keeps_initiating(1, 9));
        assert!(!keeps_initiating(9, 1));
    }

    #[test]
    fn a_replayed_relay_msg1_changes_nothing() {
        let rng = SystemRandom::new();
        let now = Instant::now();
        let (a, b, mut at_a, mut at_b) = relay_pair();
        let a_key = session_key(Namespace::Relay, &a, b.id);
        let b_key = session_key(Namespace::Relay, &b, a.id);
        let respond = |msg1: &[u8], at_b: &mut Sessions| {
            relay_respond(&b, a.id, Some(a.static_key.public()), msg1, at_b, &rng, now)
        };

        let (initiator, msg1) =
            RelayInitiator::start(&a, b.id, b.static_key.public(), &at_a, &rng).unwrap();
        let (msg2, _) = reply(respond(&msg1, &mut at_b).unwrap());
        // Relayed again while pending: the same msg2, nothing new.
        assert_eq!(
            respond(&msg1, &mut at_b).unwrap(),
            RelayAnswer::Repeat(msg2.clone())
        );
        assert_eq!(at_b.pending_len(&b_key), 1);
        initiator.finish(&a, &msg2, &mut at_a, now).unwrap();
        let mut packet = b"x".to_vec();
        at_a.seal(&a_key, &mut packet, now).unwrap();
        at_b.open(&b_key, &mut packet, now).unwrap();
        let generation = at_b.generation(&b_key);

        // Replayed later, many times: dropped, the session stays.
        for _ in 0..8 {
            assert_eq!(
                respond(&msg1, &mut at_b).err(),
                Some(HandshakeError::Replayed)
            );
        }
        assert_eq!(at_b.generation(&b_key), generation);
        assert_eq!(at_b.pending_len(&b_key), 0);

        // A msg1 with the current generation joins and changes nothing.
        let (initiator, msg1) =
            RelayInitiator::start(&a, b.id, b.static_key.public(), &at_a, &rng).unwrap();
        let (msg2, joined) = reply(respond(&msg1, &mut at_b).unwrap());
        assert_eq!(joined.action, Action::Join);
        initiator.finish(&a, &msg2, &mut at_a, now).unwrap();
        let mut packet = b"back".to_vec();
        at_b.seal(&b_key, &mut packet, now).unwrap();
        at_a.open(&a_key, &mut packet, now).unwrap();
        assert_eq!(packet, b"back");
        assert_eq!(at_b.get(&b_key).unwrap().connections(), 0);
    }
}
