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

use std::collections::HashMap;
use std::time::{Duration, Instant};

use ring::rand::SecureRandom;

use crate::config::Cipher;

use super::messages::Action;
use super::traffic::{Receiver, Sender, TrafficError, ROOT_KEY_LEN};

/// A session no connection has used for this long is dropped (spec §8.6).
pub const IDLE_TIMEOUT: Duration = Duration::from_secs(60);
/// Most sessions held at once, over both namespaces.
pub const MAX_SESSIONS: usize = 4096;

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

/// What a handshake settles on, before it is installed. Has no `Debug`:
/// it holds the root key.
#[derive(Clone)]
pub struct Agreement {
    pub action: Action,
    pub generation: u32,
    pub root_key: [u8; ROOT_KEY_LEN],
    pub initial_epoch: u32,
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
    Traffic(TrafficError),
}

impl From<TrafficError> for SessionError {
    fn from(error: TrafficError) -> Self {
        SessionError::Traffic(error)
    }
}

/// One session. Has no `Debug`: it holds the root key.
pub struct Session {
    generation: u32,
    root_key: [u8; ROOT_KEY_LEN],
    ciphers: Ciphers,
    pub sender: Sender,
    pub receiver: Receiver,
    connections: usize,
    idle_since: Instant,
}

impl Session {
    pub fn generation(&self) -> u32 {
        self.generation
    }

    pub fn ciphers(&self) -> Ciphers {
        self.ciphers
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
                return Ok(Agreement {
                    action: Action::Sync,
                    generation: session.generation,
                    root_key: session.root_key,
                    initial_epoch: session.sender.epoch().saturating_add(1),
                });
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

    /// Installs a finished handshake and counts one more connection on the
    /// session. Join keeps the session as it is; Create replaces it; Sync
    /// keeps the root key and moves to the agreed epoch.
    pub fn install(
        &mut self,
        key: SessionKey,
        agreement: &Agreement,
        local_id: u32,
        ciphers: Ciphers,
        now: Instant,
    ) -> Result<(), SessionError> {
        if !self.map.contains_key(&key) && self.map.len() >= MAX_SESSIONS {
            return Err(SessionError::Full);
        }
        if let Some(session) = self.map.get_mut(&key) {
            let same = session.generation == agreement.generation
                && session.root_key == agreement.root_key
                && session.ciphers == ciphers;
            if same {
                session.sender.advance_to(agreement.initial_epoch, now)?;
                session.connections += 1;
                return Ok(());
            }
        }
        // The session joined was replaced while the handshake ran.
        if agreement.action == Action::Join {
            return Err(SessionError::NothingToJoin);
        }
        let peer_id = key.peer_id;
        let session = Session {
            generation: agreement.generation,
            root_key: agreement.root_key,
            ciphers,
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
            .install(direct.clone(), &first, 1, c(AES, CHACHA), now)
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
            .install(relay.clone(), &first, 1, c(AES, AES), now)
            .unwrap();
        let sync = sessions
            .server_choice(&relay, None, c(AES, AES), &rng)
            .unwrap();
        assert_eq!(sync.action, Action::Sync);
        assert_eq!(sync.root_key, first.root_key);
        assert_eq!((sync.generation, sync.initial_epoch), (1, 1));
        sessions
            .install(relay.clone(), &sync, 1, c(AES, AES), now)
            .unwrap();
        let session = sessions.get(&relay).unwrap();
        assert_eq!(session.sender.epoch(), 1);
        assert_eq!(session.connections, 2);
        // The direct namespace is separate.
        assert!(sessions.get(&key(Namespace::Direct)).is_none());
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
            .install(direct.clone(), &created, 1, c(AES, AES), now)
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
            .install(at_server.clone(), &choice, 10, c(CHACHA, AES), now)
            .unwrap();
        client
            .install(at_client.clone(), &agreed, 20, c(AES, CHACHA), now)
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
            .install(direct.clone(), &agreement, 1, c(AES, AES), now)
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
                .install(key, &agreement, 1, c(AES, AES), now)
                .unwrap();
        }
        let extra = SessionKey {
            peer_id: u32::MAX,
            ..direct.clone()
        };
        assert_eq!(
            sessions.install(extra, &agreement, 1, c(AES, AES), now),
            Err(SessionError::Full)
        );
        sessions.invalidate(&SessionKey {
            peer_id: 0,
            ..direct
        });
        assert_eq!(sessions.len(), MAX_SESSIONS - 1);
    }
}
