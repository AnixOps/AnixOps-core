//! Sessions of the secure mode (spec §8.4, §9): one per pair of nodes and
//! namespace, shared by every connection between them.
//!
//! The server's choice follows the table of spec §8.4 with one hardening
//! for direct handshakes. msg2 is sent before the client has proved
//! anything (its proof is in msg3), so this node never puts an existing
//! session's root key into a direct msg2: where the table says Sync, it
//! creates a new session instead, and installs it only once msg3 checks
//! out. The specification allows creating every time. Relay handshakes
//! authenticate the initiator in their first message, so they keep Sync.
//!
//! A Sync moves both directions to an epoch above any either side has
//! been seen to use, so the peer that lost the session never seals under a
//! nonce it used before. Relay msg1 is relayed in the clear and can be
//! replayed: a session remembers the msg1 it answered and answers a repeat
//! the same way without touching the session.
//!
//! A session is bound to the static key of the peer that set it up. A
//! handshake with another key under the same node ID cannot take over a
//! session in use (spec §8.3 leaves this open; the peer may hold the
//! network secret and still not be that node).
//!
//! Root keys are compared in constant time and wiped on drop.

use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

use ring::rand::SecureRandom;

use zeroize::Zeroize;

use crate::config::Cipher;
use crate::route::messages::Uuid;

use super::messages::Action;
use super::noise::LEN;
use super::traffic::{keys_equal, Receiver, Sender, TrafficError, ROOT_KEY_LEN};

/// A session no connection has used for this long is dropped (spec §8.6).
pub const IDLE_TIMEOUT: Duration = Duration::from_secs(60);
/// Most sessions held at once, over both namespaces.
pub const MAX_SESSIONS: usize = 4096;
/// Relay msg1 remembered per session to answer repeats.
pub const REMEMBERED_ANSWERS: usize = 16;

/// Direct sessions are with neighbours; relay sessions are end to end
/// (spec §9). They are kept apart.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Namespace {
    Direct,
    Relay,
}

/// The key of a session.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct SessionKey {
    pub namespace: Namespace,
    pub network: String,
    pub peer_id: u32,
}

/// The ciphers of a session: each side sends with the one it announced
/// (spec §8.5).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ciphers {
    pub local: Cipher,
    pub peer: Cipher,
}

/// What a handshake settles on, before it is installed. Has no `Debug` and
/// no `Clone`: it holds the root key, which is wiped on drop.
pub struct Agreement {
    pub action: Action,
    pub generation: u32,
    pub root_key: [u8; ROOT_KEY_LEN],
    pub initial_epoch: u32,
}

impl Drop for Agreement {
    fn drop(&mut self) {
        self.root_key.zeroize();
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SessionError {
    /// The system random source failed.
    Random,
    /// The server said Join, but this node has no session of that
    /// generation and ciphers: close and handshake again without one.
    NothingToJoin,
    /// [`MAX_SESSIONS`] are held.
    Full,
    /// The session of this node ID is in use and was set up by a peer with
    /// another static key.
    StaticKeyMismatch,
    Traffic(TrafficError),
}

impl From<TrafficError> for SessionError {
    fn from(error: TrafficError) -> Self {
        SessionError::Traffic(error)
    }
}

/// A relay msg1 a session answered, by its connection ID.
#[derive(Clone, Copy)]
struct Answer {
    conn_id: Uuid,
    action: Action,
    initial_epoch: u32,
}

/// One session. Has no `Debug`: it holds the root key, which is wiped on
/// drop.
pub struct Session {
    generation: u32,
    root_key: [u8; ROOT_KEY_LEN],
    ciphers: Ciphers,
    peer_static: [u8; LEN],
    pub sender: Sender,
    pub receiver: Receiver,
    connections: usize,
    idle_since: Instant,
    answers: VecDeque<Answer>,
}

impl Session {
    pub fn generation(&self) -> u32 {
        self.generation
    }

    pub fn ciphers(&self) -> Ciphers {
        self.ciphers
    }

    /// The static key of the peer that set the session up.
    pub fn peer_static(&self) -> [u8; LEN] {
        self.peer_static
    }

    pub fn connections(&self) -> usize {
        self.connections
    }

    /// The epoch a Sync moves both directions to: above any this node has
    /// sent in or seen the peer send in. `None` when the epochs are used
    /// up.
    fn sync_epoch(&self) -> Option<u32> {
        self.sender
            .epoch()
            .max(self.receiver.newest())
            .checked_add(1)
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        self.root_key.zeroize();
    }
}

fn random_root_key(rng: &dyn SecureRandom) -> Result<[u8; ROOT_KEY_LEN], SessionError> {
    let mut key = [0u8; ROOT_KEY_LEN];
    rng.fill(&mut key).map_err(|_| SessionError::Random)?;
    Ok(key)
}

fn next_generation(existing: Option<&Session>) -> u32 {
    existing.map_or(1, |session| session.generation.wrapping_add(1).max(1))
}

/// The sessions of this node.
#[derive(Default)]
pub struct Sessions {
    map: HashMap<SessionKey, Session>,
}

impl Sessions {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    pub fn get(&self, key: &SessionKey) -> Option<&Session> {
        self.map.get(key)
    }

    pub fn get_mut(&mut self, key: &SessionKey) -> Option<&mut Session> {
        self.map.get_mut(key)
    }

    /// The generation a client puts in msg1: that of the session it holds,
    /// if any.
    pub fn generation(&self, key: &SessionKey) -> Option<u32> {
        self.map.get(key).map(Session::generation)
    }

    /// The server's choice on msg1 (spec §8.4, hardened as the module says
    /// for [`Namespace::Direct`]). `ciphers.local` is what this node will
    /// announce in msg2, `ciphers.peer` what msg1 announced.
    pub fn server_choice(
        &self,
        key: &SessionKey,
        client_generation: Option<u32>,
        ciphers: Ciphers,
        rng: &dyn SecureRandom,
    ) -> Result<Agreement, SessionError> {
        let existing = self.map.get(key);
        if let Some(session) = existing {
            if client_generation == Some(session.generation) && session.ciphers == ciphers {
                return Ok(Agreement {
                    action: Action::Join,
                    generation: session.generation,
                    root_key: session.root_key,
                    initial_epoch: session.sender.epoch(),
                });
            }
            if key.namespace == Namespace::Relay {
                if let Some(initial_epoch) = session.sync_epoch() {
                    return Ok(Agreement {
                        action: Action::Sync,
                        generation: session.generation,
                        root_key: session.root_key,
                        initial_epoch,
                    });
                }
            }
        }
        Ok(Agreement {
            action: Action::Create,
            generation: next_generation(existing),
            root_key: random_root_key(rng)?,
            initial_epoch: 0,
        })
    }

    /// The client's view of msg2: what to install. `root_key` is msg2's.
    pub fn client_agreement(
        &self,
        key: &SessionKey,
        action: Action,
        generation: u32,
        root_key: Option<[u8; ROOT_KEY_LEN]>,
        initial_epoch: u32,
        ciphers: Ciphers,
    ) -> Result<Agreement, SessionError> {
        match (action, root_key) {
            (Action::Join, _) => {
                let session = self
                    .map
                    .get(key)
                    .filter(|session| {
                        session.generation == generation && session.ciphers == ciphers
                    })
                    .ok_or(SessionError::NothingToJoin)?;
                Ok(Agreement {
                    action,
                    generation,
                    root_key: session.root_key,
                    initial_epoch: session.sender.epoch(),
                })
            }
            (Action::Sync | Action::Create, Some(root_key)) => Ok(Agreement {
                action,
                generation,
                root_key,
                initial_epoch,
            }),
            // msg2 decoding refuses this already.
            (Action::Sync | Action::Create, None) => Err(SessionError::NothingToJoin),
        }
    }

    /// The answer given before to the relay msg1 with `conn_id`, if the
    /// session still has it: a repeat gets the same answer and changes
    /// nothing.
    pub fn answered(&self, key: &SessionKey, conn_id: Uuid) -> Option<Agreement> {
        let session = self.map.get(key)?;
        let answer = session
            .answers
            .iter()
            .find(|answer| answer.conn_id == conn_id)?;
        Some(Agreement {
            action: answer.action,
            generation: session.generation,
            root_key: session.root_key,
            initial_epoch: answer.initial_epoch,
        })
    }

    /// Remembers the answer to a relay msg1, after [`Sessions::install`].
    pub fn remember_answer(&mut self, key: &SessionKey, conn_id: Uuid, agreement: &Agreement) {
        if let Some(session) = self.map.get_mut(key) {
            if session.answers.len() == REMEMBERED_ANSWERS {
                session.answers.pop_front();
            }
            session.answers.push_back(Answer {
                conn_id,
                action: agreement.action,
                initial_epoch: agreement.initial_epoch,
            });
        }
    }

    /// Installs a finished handshake with the peer holding `peer_static`
    /// and counts one more connection on the session. Join keeps the
    /// session as it is; Create replaces it; Sync keeps the root key and
    /// moves both directions to the agreed epoch. A session in use that
    /// another static key set up is never touched.
    pub fn install(
        &mut self,
        key: SessionKey,
        agreement: &Agreement,
        local_id: u32,
        ciphers: Ciphers,
        peer_static: [u8; LEN],
        now: Instant,
    ) -> Result<(), SessionError> {
        if !self.map.contains_key(&key) && self.map.len() >= MAX_SESSIONS {
            return Err(SessionError::Full);
        }
        if let Some(session) = self.map.get_mut(&key) {
            let same_peer = session.peer_static == peer_static;
            if !same_peer && session.connections > 0 {
                return Err(SessionError::StaticKeyMismatch);
            }
            let same = same_peer
                && session.generation == agreement.generation
                && keys_equal(&session.root_key, &agreement.root_key)
                && session.ciphers == ciphers;
            if same {
                session.sender.advance_to(agreement.initial_epoch, now)?;
                if agreement.action == Action::Sync {
                    session.receiver.advance_to(agreement.initial_epoch)?;
                }
                session.connections += 1;
                return Ok(());
            }
        }
        // The session joined was replaced while the handshake ran, or was
        // another peer's.
        if agreement.action == Action::Join {
            return Err(SessionError::NothingToJoin);
        }
        let peer_id = key.peer_id;
        let session = Session {
            generation: agreement.generation,
            root_key: agreement.root_key,
            ciphers,
            peer_static,
            sender: Sender::new(
                ciphers.local,
                agreement.root_key,
                local_id,
                peer_id,
                agreement.initial_epoch,
                now,
            )?,
            receiver: Receiver::new(
                ciphers.peer,
                agreement.root_key,
                local_id,
                peer_id,
                agreement.initial_epoch,
            )?,
            connections: 1,
            idle_since: now,
            answers: VecDeque::new(),
        };
        self.map.insert(key, session);
        Ok(())
    }

    /// A connection that used the session closed.
    pub fn release(&mut self, key: &SessionKey, now: Instant) {
        if let Some(session) = self.map.get_mut(key) {
            session.connections = session.connections.saturating_sub(1);
            if session.connections == 0 {
                session.idle_since = now;
            }
        }
    }

    /// Drops a session after [`TrafficError::SessionEnded`]: the next
    /// handshake goes without a generation (spec §8.6).
    pub fn invalidate(&mut self, key: &SessionKey) {
        self.map.remove(key);
    }

    /// Drops sessions without connections for [`IDLE_TIMEOUT`].
    pub fn reclaim(&mut self, now: Instant) {
        self.map.retain(|_, session| {
            session.connections > 0
                || now.saturating_duration_since(session.idle_since) < IDLE_TIMEOUT
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ring::rand::SystemRandom;

    fn key(namespace: Namespace) -> SessionKey {
        SessionKey {
            namespace,
            network: "office".into(),
            peer_id: 7,
        }
    }

    const AES: Cipher = Cipher::Aes128Gcm;
    const CHACHA: Cipher = Cipher::ChaCha20Poly1305;
    const PEER: [u8; LEN] = [7; LEN];
    const OTHER: [u8; LEN] = [8; LEN];

    fn c(local: Cipher, peer: Cipher) -> Ciphers {
        Ciphers { local, peer }
    }

    #[test]
    fn server_creates_joins_and_never_syncs_a_direct_session() {
        let rng = SystemRandom::new();
        let now = Instant::now();
        let mut sessions = Sessions::new();
        let direct = key(Namespace::Direct);

        let first = sessions
            .server_choice(&direct, None, c(AES, CHACHA), &rng)
            .unwrap();
        assert_eq!(first.action, Action::Create);
        assert_eq!((first.generation, first.initial_epoch), (1, 0));
        sessions
            .install(direct.clone(), &first, 1, c(AES, CHACHA), PEER, now)
            .unwrap();

        let join = sessions
            .server_choice(&direct, Some(1), c(AES, CHACHA), &rng)
            .unwrap();
        assert_eq!(join.action, Action::Join);
        assert_eq!(join.root_key, first.root_key);

        // Another generation, none, or other ciphers: a new session.
        for (generation, peer_cipher) in [(Some(5), CHACHA), (None, CHACHA), (Some(1), AES)] {
            let choice = sessions
                .server_choice(&direct, generation, c(AES, peer_cipher), &rng)
                .unwrap();
            assert_eq!(choice.action, Action::Create);
            assert_eq!(choice.generation, 2);
            assert_ne!(choice.root_key, first.root_key);
        }
    }

    #[test]
    fn relay_sessions_sync_at_the_next_epoch() {
        let rng = SystemRandom::new();
        let now = Instant::now();
        let mut sessions = Sessions::new();
        let relay = key(Namespace::Relay);
        let first = sessions
            .server_choice(&relay, None, c(AES, AES), &rng)
            .unwrap();
        sessions
            .install(relay.clone(), &first, 1, c(AES, AES), PEER, now)
            .unwrap();
        let sync = sessions
            .server_choice(&relay, None, c(AES, AES), &rng)
            .unwrap();
        assert_eq!(sync.action, Action::Sync);
        assert_eq!(sync.root_key, first.root_key);
        assert_eq!((sync.generation, sync.initial_epoch), (1, 1));
        sessions
            .install(relay.clone(), &sync, 1, c(AES, AES), PEER, now)
            .unwrap();
        let session = sessions.get(&relay).unwrap();
        assert_eq!(session.sender.epoch(), 1);
        assert_eq!(session.connections, 2);
        // The direct namespace is separate.
        assert!(sessions.get(&key(Namespace::Direct)).is_none());
    }

    #[test]
    fn a_relay_sync_skips_every_epoch_either_side_used() {
        let rng = SystemRandom::new();
        let now = Instant::now();
        let (mut at_a, mut at_b) = (Sessions::new(), Sessions::new());
        let a_key = SessionKey {
            peer_id: 9,
            ..key(Namespace::Relay)
        };
        let b_key = SessionKey {
            peer_id: 1,
            ..key(Namespace::Relay)
        };
        let created = at_b.server_choice(&b_key, None, c(AES, AES), &rng).unwrap();
        let agreed = at_a
            .client_agreement(
                &a_key,
                created.action,
                created.generation,
                Some(created.root_key),
                created.initial_epoch,
                c(AES, AES),
            )
            .unwrap();
        at_b.install(b_key.clone(), &created, 9, c(AES, AES), PEER, now)
            .unwrap();
        at_a.install(a_key.clone(), &agreed, 1, c(AES, AES), OTHER, now)
            .unwrap();

        // The initiator rotated to epoch 2 and sent packets the responder
        // saw; then it lost the session.
        let mut sent = Vec::new();
        let sender = &mut at_a.get_mut(&a_key).unwrap().sender;
        sender.advance_to(2, now).unwrap();
        for _ in 0..3 {
            let mut packet = b"old".to_vec();
            sender.seal(&mut packet, now).unwrap();
            sent.push(packet);
        }
        for packet in &sent {
            let mut packet = packet.clone();
            at_b.get_mut(&b_key)
                .unwrap()
                .receiver
                .open(&mut packet)
                .unwrap();
        }
        at_a.invalidate(&a_key);

        let sync = at_b.server_choice(&b_key, None, c(AES, AES), &rng).unwrap();
        assert_eq!(sync.action, Action::Sync);
        assert_eq!(sync.initial_epoch, 3, "above the initiator's epoch 2");
        let agreed = at_a
            .client_agreement(
                &a_key,
                sync.action,
                sync.generation,
                Some(sync.root_key),
                sync.initial_epoch,
                c(AES, AES),
            )
            .unwrap();
        at_b.install(b_key.clone(), &sync, 9, c(AES, AES), PEER, now)
            .unwrap();
        at_a.install(a_key.clone(), &agreed, 1, c(AES, AES), OTHER, now)
            .unwrap();

        // No nonce is used twice, and both directions work at once.
        let mut packet = b"new".to_vec();
        at_a.get_mut(&a_key)
            .unwrap()
            .sender
            .seal(&mut packet, now)
            .unwrap();
        for old in &sent {
            assert_ne!(old[old.len() - 12..], packet[packet.len() - 12..]);
        }
        let at_responder = at_b.get_mut(&b_key).unwrap();
        at_responder.receiver.open(&mut packet).unwrap();
        assert_eq!(at_responder.receiver.newest(), 3);
        let mut back = b"back".to_vec();
        at_responder.sender.seal(&mut back, now).unwrap();
        at_a.get_mut(&a_key)
            .unwrap()
            .receiver
            .open(&mut back)
            .unwrap();
        assert_eq!(back, b"back");
    }

    #[test]
    fn a_session_in_use_keeps_its_static_key() {
        let rng = SystemRandom::new();
        let now = Instant::now();
        let mut sessions = Sessions::new();
        let direct = key(Namespace::Direct);
        let first = sessions
            .server_choice(&direct, None, c(AES, AES), &rng)
            .unwrap();
        sessions
            .install(direct.clone(), &first, 1, c(AES, AES), PEER, now)
            .unwrap();

        // Another key under the same node ID can neither join nor replace
        // it while it is in use.
        let join = sessions
            .server_choice(&direct, Some(1), c(AES, AES), &rng)
            .unwrap();
        assert_eq!(join.action, Action::Join);
        assert_eq!(
            sessions.install(direct.clone(), &join, 1, c(AES, AES), OTHER, now),
            Err(SessionError::StaticKeyMismatch)
        );
        let create = sessions
            .server_choice(&direct, None, c(AES, AES), &rng)
            .unwrap();
        assert_eq!(
            sessions.install(direct.clone(), &create, 1, c(AES, AES), OTHER, now),
            Err(SessionError::StaticKeyMismatch)
        );
        assert_eq!(sessions.get(&direct).unwrap().peer_static(), PEER);

        // Once idle, a new key may set up a new session, but not join.
        sessions.release(&direct, now);
        assert_eq!(
            sessions.install(direct.clone(), &join, 1, c(AES, AES), OTHER, now),
            Err(SessionError::NothingToJoin)
        );
        sessions
            .install(direct.clone(), &create, 1, c(AES, AES), OTHER, now)
            .unwrap();
        assert_eq!(sessions.get(&direct).unwrap().peer_static(), OTHER);
    }

    #[test]
    fn a_repeated_relay_msg1_gets_the_same_answer() {
        let rng = SystemRandom::new();
        let now = Instant::now();
        let mut sessions = Sessions::new();
        let relay = key(Namespace::Relay);
        let first = sessions
            .server_choice(&relay, None, c(AES, AES), &rng)
            .unwrap();
        sessions
            .install(relay.clone(), &first, 1, c(AES, AES), PEER, now)
            .unwrap();
        let first_id = Uuid([1; 16]);
        sessions.remember_answer(&relay, first_id, &first);
        let sync = sessions
            .server_choice(&relay, None, c(AES, AES), &rng)
            .unwrap();
        sessions
            .install(relay.clone(), &sync, 1, c(AES, AES), PEER, now)
            .unwrap();
        sessions.remember_answer(&relay, Uuid([2; 16]), &sync);

        let again = sessions.answered(&relay, first_id).unwrap();
        assert_eq!(again.action, Action::Create);
        assert_eq!(again.initial_epoch, 0);
        assert_eq!(again.root_key, first.root_key);
        let again = sessions.answered(&relay, Uuid([2; 16])).unwrap();
        assert_eq!((again.action, again.initial_epoch), (Action::Sync, 1));
        assert!(sessions.answered(&relay, Uuid([3; 16])).is_none());

        // Only the latest answers are kept.
        for n in 0..REMEMBERED_ANSWERS as u8 {
            sessions.remember_answer(&relay, Uuid([10 + n; 16]), &sync);
        }
        assert!(sessions.answered(&relay, first_id).is_none());
        assert!(sessions.answered(&relay, Uuid([10; 16])).is_some());
    }

    #[test]
    fn client_join_needs_the_same_session() {
        let now = Instant::now();
        let mut sessions = Sessions::new();
        let direct = key(Namespace::Direct);
        assert_eq!(
            sessions
                .client_agreement(&direct, Action::Join, 1, None, 0, c(AES, AES))
                .err(),
            Some(SessionError::NothingToJoin)
        );
        let created = sessions
            .client_agreement(&direct, Action::Create, 3, Some([1; 32]), 0, c(AES, AES))
            .unwrap();
        sessions
            .install(direct.clone(), &created, 1, c(AES, AES), PEER, now)
            .unwrap();
        assert_eq!(sessions.generation(&direct), Some(3));
        let joined = sessions
            .client_agreement(&direct, Action::Join, 3, None, 0, c(AES, AES))
            .unwrap();
        assert_eq!(joined.root_key, [1; 32]);
        assert!(sessions
            .client_agreement(&direct, Action::Join, 2, None, 0, c(AES, AES))
            .is_err());
        assert!(sessions
            .client_agreement(&direct, Action::Join, 3, None, 0, c(AES, CHACHA))
            .is_err());
    }

    #[test]
    fn both_sides_derive_matching_traffic_keys() {
        let rng = SystemRandom::new();
        let now = Instant::now();
        let (mut server, mut client) = (Sessions::new(), Sessions::new());
        let at_server = SessionKey {
            peer_id: 20,
            ..key(Namespace::Direct)
        };
        let at_client = SessionKey {
            peer_id: 10,
            ..key(Namespace::Direct)
        };
        let choice = server
            .server_choice(&at_server, None, c(CHACHA, AES), &rng)
            .unwrap();
        let agreed = client
            .client_agreement(
                &at_client,
                choice.action,
                choice.generation,
                Some(choice.root_key),
                choice.initial_epoch,
                c(AES, CHACHA),
            )
            .unwrap();
        server
            .install(at_server.clone(), &choice, 10, c(CHACHA, AES), PEER, now)
            .unwrap();
        client
            .install(at_client.clone(), &agreed, 20, c(AES, CHACHA), PEER, now)
            .unwrap();

        let mut packet = b"hello".to_vec();
        client
            .get_mut(&at_client)
            .unwrap()
            .sender
            .seal(&mut packet, now)
            .unwrap();
        let receiving = &mut server.get_mut(&at_server).unwrap().receiver;
        receiving.open(&mut packet).unwrap();
        assert_eq!(packet, b"hello");

        let mut packet = b"back".to_vec();
        server
            .get_mut(&at_server)
            .unwrap()
            .sender
            .seal(&mut packet, now)
            .unwrap();
        let receiving = &mut client.get_mut(&at_client).unwrap().receiver;
        receiving.open(&mut packet).unwrap();
        assert_eq!(packet, b"back");
    }

    #[test]
    fn idle_sessions_are_reclaimed_and_the_count_is_bounded() {
        let now = Instant::now();
        let mut sessions = Sessions::new();
        let direct = key(Namespace::Direct);
        let agreement = Agreement {
            action: Action::Create,
            generation: 1,
            root_key: [2; 32],
            initial_epoch: 0,
        };
        sessions
            .install(direct.clone(), &agreement, 1, c(AES, AES), PEER, now)
            .unwrap();
        sessions.reclaim(now + IDLE_TIMEOUT * 2);
        assert_eq!(sessions.len(), 1, "in use");
        sessions.release(&direct, now);
        sessions.reclaim(now + IDLE_TIMEOUT / 2);
        assert_eq!(sessions.len(), 1, "not idle long enough");
        sessions.reclaim(now + IDLE_TIMEOUT);
        assert!(sessions.is_empty());

        for peer_id in 0..MAX_SESSIONS as u32 {
            let key = SessionKey {
                peer_id,
                ..direct.clone()
            };
            sessions
                .install(key, &agreement, 1, c(AES, AES), PEER, now)
                .unwrap();
        }
        let extra = SessionKey {
            peer_id: u32::MAX,
            ..direct.clone()
        };
        assert_eq!(
            sessions.install(extra, &agreement, 1, c(AES, AES), PEER, now),
            Err(SessionError::Full)
        );
        sessions.invalidate(&SessionKey {
            peer_id: 0,
            ..direct
        });
        assert_eq!(sessions.len(), MAX_SESSIONS - 1);
    }
}
