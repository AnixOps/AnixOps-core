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
//! A peer that uses this node's own ID is refused (spec §5.3): both
//! directions would derive the same key and nonces.

use std::time::Instant;

use ring::rand::SecureRandom;

use crate::config::Cipher;
use crate::legacy::handshake::FOREIGN_PREFIX;
use crate::route::messages::Uuid;

use super::messages::{Action, MessageError, Msg1, Msg2, Msg3, RelayMsg1, RelayMsg2, RoleHint};
use super::noise::{HandshakeState, KeyPair, NoiseError, Pattern, LEN};
use super::proof::{self, PROOF_LEN};
use super::session::{Agreement, Ciphers, Namespace, SessionError, SessionKey, Sessions};
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
    /// The peer uses this node's ID (spec §5.3).
    SameNodeId,
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
    pub action: Action,
    pub generation: u32,
    /// A repeated relay msg1 answered as before: nothing was installed and
    /// no connection was counted.
    pub repeated: bool,
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
}

impl Client {
    /// `known_peer` is the node ID this connection is expected to reach, if
    /// any; its session's generation goes into msg1. Returns msg1.
    pub fn start(
        local: &Local,
        known_peer: Option<u32>,
        sessions: &Sessions,
        rng: &dyn SecureRandom,
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
        let session_generation = known_peer
            .and_then(|peer| sessions.generation(&session_key(Namespace::Direct, local, peer)));
        let payload = Msg1 {
            network_name: local.network_name.clone(),
            session_generation,
            conn_id,
            cipher: local.cipher,
        }
        .encode()?;
        let message = noise.write_message(&payload)?;
        let after_msg1 = noise.handshake_hash();
        Ok((
            Self {
                noise,
                conn_id,
                after_msg1,
            },
            message,
        ))
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
        other_node(local, peer_id)?;
        let msg2 = Msg2::decode(&self.noise.read_message(msg2)?)?;
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

        let key = session_key(Namespace::Direct, local, peer_id);
        let ciphers = Ciphers {
            local: local.cipher,
            peer: msg2.cipher,
        };
        let agreement = sessions.client_agreement(
            &key,
            msg2.action,
            msg2.session_generation,
            msg2.root_key,
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
        sessions.install(key.clone(), &agreement, local.id, ciphers, peer_static, now)?;
        Ok((
            message,
            Established {
                key,
                peer_static,
                auth,
                action: agreement.action,
                generation: agreement.generation,
                repeated: false,
            },
        ))
    }
}

/// The server of a direct handshake: reads msg1, sends msg2, reads msg3.
pub struct Server {
    noise: HandshakeState,
    conn_id: Uuid,
    client_conn_id: Uuid,
    /// `None` for a client of another network.
    pending: Option<(SessionKey, Agreement, Ciphers)>,
    /// The handshake hash after msg2: the client proves over it.
    after_msg2: [u8; LEN],
}

impl Server {
    /// Reads msg1 from `peer_id` (its packet header) and returns msg2. The
    /// session is chosen now and installed only by [`Server::finish`].
    pub fn respond(
        local: &Local,
        peer_id: u32,
        msg1: &[u8],
        sessions: &Sessions,
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
                    .then_some(agreement.root_key),
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
        let message = noise.write_message(&reply.encode()?)?;
        let after_msg2 = noise.handshake_hash();
        Ok((
            Self {
                noise,
                conn_id,
                client_conn_id: msg1.conn_id,
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

    /// Reads msg3, authenticates the client and installs the session.
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
        let msg3 = Msg3::decode(&self.noise.read_message(msg3)?)?;
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
        sessions.install(key.clone(), &agreement, local.id, ciphers, peer_static, now)?;
        Ok(Established {
            key,
            peer_static,
            auth,
            action: agreement.action,
            generation: agreement.generation,
            repeated: false,
        })
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
        let msg2 = RelayMsg2::decode(&self.noise.read_message(msg2)?)?;
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
            msg2.root_key,
            msg2.initial_epoch,
            ciphers,
        )?;
        sessions.install(
            key.clone(),
            &agreement,
            local.id,
            ciphers,
            self.peer_static,
            now,
        )?;
        Ok(Established {
            key,
            peer_static: self.peer_static,
            auth: Auth::PeerVerified,
            action: agreement.action,
            generation: agreement.generation,
            repeated: false,
        })
    }
}

/// Answers relay msg1 from `peer_id` (its packet header), whose route
/// information announces `expected_static`. Installs the session and
/// returns relay msg2. A msg1 answered before (relayed again, or replayed
/// by a node on the path) gets the same answer and changes nothing.
pub fn relay_respond(
    local: &Local,
    peer_id: u32,
    expected_static: Option<[u8; LEN]>,
    msg1: &[u8],
    sessions: &mut Sessions,
    rng: &dyn SecureRandom,
    now: Instant,
) -> Result<(Vec<u8>, Established), HandshakeError> {
    other_node(local, peer_id)?;
    let mut noise = HandshakeState::new(
        Pattern::Ik,
        false,
        &PROLOGUE_RELAY,
        local.static_key.clone(),
        None,
    )?;
    let msg1 = RelayMsg1::decode(&noise.read_message(msg1)?)?;
    let peer_static = noise
        .remote_static()
        .ok_or(HandshakeError::Noise(NoiseError::OutOfTurn))?;
    if expected_static != Some(peer_static) {
        return Err(HandshakeError::Unauthenticated);
    }
    let key = session_key(Namespace::Relay, local, peer_id);
    let ciphers = Ciphers {
        local: local.cipher,
        peer: msg1.cipher,
    };
    let repeated = sessions.answered(&key, msg1.conn_id);
    let is_repeat = repeated.is_some();
    let agreement = match repeated {
        Some(agreement) => agreement,
        None => sessions.server_choice(&key, msg1.session_generation, ciphers, rng)?,
    };
    let reply = RelayMsg2 {
        action: agreement.action,
        session_generation: agreement.generation,
        root_key: agreement
            .action
            .carries_root_key()
            .then_some(agreement.root_key),
        initial_epoch: agreement.initial_epoch,
        conn_id: random_uuid(rng)?,
        peer_conn_id_echo: msg1.conn_id,
        cipher: local.cipher,
    };
    let message = noise.write_message(&reply.encode()?)?;
    if !is_repeat {
        sessions.install(key.clone(), &agreement, local.id, ciphers, peer_static, now)?;
        sessions.remember_answer(&key, msg1.conn_id, &agreement);
    }
    Ok((
        message,
        Established {
            key,
            peer_static,
            auth: Auth::PeerVerified,
            action: agreement.action,
            generation: agreement.generation,
            repeated: is_repeat,
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
            let (client, msg1) =
                Client::start(&self.client, Some(self.server.id), &self.at_client, &rng)?;
            let (server, msg2) =
                Server::respond(&self.server, self.client.id, &msg1, &self.at_server, &rng)?;
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
            let sending = self.at_client.get_mut(&client_key).unwrap();
            sending.sender.seal(&mut packet, now).unwrap();
            let receiving = self.at_server.get_mut(&server_key).unwrap();
            receiving.receiver.open(&mut packet).unwrap();
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
        pair.check_traffic();

        let (at_client, at_server) = pair.run().unwrap();
        assert_eq!(at_client.action, Action::Join);
        assert_eq!(at_server.generation, 1);
        pair.check_traffic();
    }

    #[test]
    fn a_lost_session_is_replaced_not_synced() {
        let mut pair = Pair::new(
            local(1, Some(b"s3cr3t"), Cipher::Aes128Gcm),
            local(2, Some(b"s3cr3t"), Cipher::Aes128Gcm),
        );
        pair.run().unwrap();
        let client_key = session_key(Namespace::Direct, &pair.client, 2);
        pair.at_client.invalidate(&client_key);
        let (at_client, _) = pair.run().unwrap();
        assert_eq!(at_client.action, Action::Create);
        assert_eq!(at_client.generation, 2);
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
        let client = local(1, Some(b"s3cr3t"), Cipher::Aes128Gcm);
        let mut server = local(2, Some(b"s3cr3t"), Cipher::Aes128Gcm);
        server.network_name = "lab".into();
        let (client_side, msg1) = Client::start(&client, None, &Sessions::new(), &rng).unwrap();
        let (server_side, msg2) =
            Server::respond(&server, 1, &msg1, &Sessions::new(), &rng).unwrap();
        assert!(server_side.is_foreign());
        let mut sessions = Sessions::new();
        assert_eq!(
            client_side
                .finish(&client, 2, None, &msg2, &mut sessions, Instant::now())
                .err(),
            Some(HandshakeError::ForeignNetwork)
        );
        assert!(sessions.is_empty());
    }

    #[test]
    fn tampered_messages_fail() {
        let rng = SystemRandom::new();
        let client = local(1, Some(b"s3cr3t"), Cipher::Aes128Gcm);
        let server = local(2, Some(b"s3cr3t"), Cipher::Aes128Gcm);
        let (client_side, msg1) = Client::start(&client, None, &Sessions::new(), &rng).unwrap();
        let (_, mut msg2) = Server::respond(&server, 1, &msg1, &Sessions::new(), &rng).unwrap();
        let last = msg2.len() - 1;
        msg2[last] ^= 1;
        assert_eq!(
            client_side
                .finish(
                    &client,
                    2,
                    None,
                    &msg2,
                    &mut Sessions::new(),
                    Instant::now()
                )
                .err(),
            Some(HandshakeError::Noise(NoiseError::Decrypt))
        );
    }

    #[test]
    fn the_own_node_id_is_refused() {
        let rng = SystemRandom::new();
        let now = Instant::now();
        let a = local(4, Some(b"s3cr3t"), Cipher::Aes128Gcm);
        let b = local(4, Some(b"s3cr3t"), Cipher::Aes128Gcm);
        let sessions = Sessions::new();
        assert_eq!(
            Client::start(&a, Some(4), &sessions, &rng).err(),
            Some(HandshakeError::SameNodeId)
        );
        let (client, msg1) = Client::start(&a, None, &sessions, &rng).unwrap();
        assert_eq!(
            Server::respond(&b, 4, &msg1, &sessions, &rng).err(),
            Some(HandshakeError::SameNodeId)
        );
        let other = local(5, Some(b"s3cr3t"), Cipher::Aes128Gcm);
        let (_, msg2) = Server::respond(&other, 4, &msg1, &sessions, &rng).unwrap();
        let mut at_a = Sessions::new();
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
        let (at_client, mut at_server) = (Sessions::new(), Sessions::new());

        let (client_side, msg1) = Client::start(&client, Some(2), &at_client, &rng).unwrap();
        let (_, msg2) = Server::respond(&server, 1, &msg1, &at_server, &rng).unwrap();
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

        let (client_side, msg1) = Client::start(&client, Some(2), &at_client, &rng).unwrap();
        let (server_side, msg2) = Server::respond(&server, 1, &msg1, &at_server, &rng).unwrap();
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
        let (client_side, msg1) = Client::start(&impostor, None, &Sessions::new(), &rng).unwrap();
        let (server_side, msg2) =
            Server::respond(&pair.server, 1, &msg1, &pair.at_server, &rng).unwrap();
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
    fn a_replayed_relay_msg1_changes_nothing() {
        let rng = SystemRandom::new();
        let now = Instant::now();
        let a = local(1, Some(b"s3cr3t"), Cipher::Aes128Gcm);
        let b = local(9, Some(b"s3cr3t"), Cipher::Aes128Gcm);
        let (mut at_a, mut at_b) = (Sessions::new(), Sessions::new());
        let b_key = session_key(Namespace::Relay, &b, a.id);

        let (initiator, msg1) =
            RelayInitiator::start(&a, b.id, b.static_key.public(), &at_a, &rng).unwrap();
        let respond = |at_b: &mut Sessions| {
            relay_respond(
                &b,
                a.id,
                Some(a.static_key.public()),
                &msg1,
                at_b,
                &rng,
                now,
            )
            .unwrap()
        };
        let (msg2, first) = respond(&mut at_b);
        assert!(!first.repeated);
        initiator.finish(&a, &msg2, &mut at_a, now).unwrap();
        let epoch = at_b.get(&b_key).unwrap().sender.epoch();
        let connections = at_b.get(&b_key).unwrap().connections();

        // The same msg1 again, many times: same answer, nothing moves.
        for _ in 0..8 {
            let (_, again) = respond(&mut at_b);
            assert!(again.repeated);
            assert_eq!(again.action, Action::Create);
        }
        let session = at_b.get(&b_key).unwrap();
        assert_eq!(session.sender.epoch(), epoch);
        assert_eq!(session.connections(), connections);

        // Traffic still flows both ways.
        let a_key = session_key(Namespace::Relay, &a, b.id);
        let mut packet = b"back".to_vec();
        at_b.get_mut(&b_key)
            .unwrap()
            .sender
            .seal(&mut packet, now)
            .unwrap();
        at_a.get_mut(&a_key)
            .unwrap()
            .receiver
            .open(&mut packet)
            .unwrap();
        assert_eq!(packet, b"back");
    }

    #[test]
    fn relay_handshake_pins_the_announced_key() {
        let rng = SystemRandom::new();
        let now = Instant::now();
        let a = local(1, Some(b"s3cr3t"), Cipher::Aes128Gcm);
        let b = local(9, Some(b"s3cr3t"), Cipher::Aes256Gcm);
        let (mut at_a, mut at_b) = (Sessions::new(), Sessions::new());

        let (initiator, msg1) =
            RelayInitiator::start(&a, b.id, b.static_key.public(), &at_a, &rng).unwrap();
        let wrong = Some(KeyPair::generate(&rng).unwrap().public());
        assert_eq!(
            relay_respond(&b, a.id, wrong, &msg1, &mut at_b, &rng, now).err(),
            Some(HandshakeError::Unauthenticated)
        );
        let (msg2, at_responder) = relay_respond(
            &b,
            a.id,
            Some(a.static_key.public()),
            &msg1,
            &mut at_b,
            &rng,
            now,
        )
        .unwrap();
        let at_initiator = initiator.finish(&a, &msg2, &mut at_a, now).unwrap();
        assert_eq!(at_initiator.action, Action::Create);
        assert_eq!(at_responder.peer_static, a.static_key.public());

        let mut packet = b"far".to_vec();
        let a_key = session_key(Namespace::Relay, &a, b.id);
        let b_key = session_key(Namespace::Relay, &b, a.id);
        at_a.get_mut(&a_key)
            .unwrap()
            .sender
            .seal(&mut packet, now)
            .unwrap();
        at_b.get_mut(&b_key)
            .unwrap()
            .receiver
            .open(&mut packet)
            .unwrap();
        assert_eq!(packet, b"far");

        // A second handshake without the generation syncs the same root key.
        at_a.invalidate(&a_key);
        let (initiator, msg1) =
            RelayInitiator::start(&a, b.id, b.static_key.public(), &at_a, &rng).unwrap();
        let (msg2, _) = relay_respond(
            &b,
            a.id,
            Some(a.static_key.public()),
            &msg1,
            &mut at_b,
            &rng,
            now,
        )
        .unwrap();
        let synced = initiator.finish(&a, &msg2, &mut at_a, now).unwrap();
        assert_eq!(synced.action, Action::Sync);
        let mut packet = b"again".to_vec();
        at_a.get_mut(&a_key)
            .unwrap()
            .sender
            .seal(&mut packet, now)
            .unwrap();
        at_b.get_mut(&b_key)
            .unwrap()
            .receiver
            .open(&mut packet)
            .unwrap();
        assert_eq!(packet, b"again");

        assert!(keeps_initiating(1, 9));
        assert!(!keeps_initiating(9, 1));
    }
}
