//! Sessions of the secure mode (spec §8.1, §8.4, §9): one per pair of
//! nodes and namespace, shared by every connection between them.
//!
//! As server or relay responder this node never sends Sync (spec §8.4 rule
//! 1): a msg1 without the generation of the installed session gets a new
//! session, with a fresh root key that appears in one msg2 only. msg2 goes
//! out before the peer is authenticated and "the same peer" is only the
//! unauthenticated node ID in the header, so handshakes with one peer run
//! in parallel, each with its own Create, and nothing here is keyed or
//! limited by that ID. Direct: a Create is installed once msg3 checks out,
//! and only over a session of a lower generation. Relay: a Create is kept
//! pending, with its msg2, until a packet decrypts under it; msg1 is
//! deduplicated by its ephemeral key.
//!
//! Generations go up by one per Create and peer within the process, from a
//! random start in [1, 2^31).
//!
//! As client or relay initiator this node may receive Sync from a node of
//! the reference behaviour (spec §8.4 rule 2): every session dropped leaves
//! a record of the epochs it used, by the digest of its root key, and a
//! Sync of a recorded root key that would make this node send in an epoch
//! it used before is refused. Without a record the peer's epoch comes from
//! its first packet, and for a minute any packet that authenticates may
//! move it ahead.
//!
//! A direct session is bound to the static key of the peer that set it up.
//! A handshake with another key under the same node ID cannot take over a
//! session in use (spec §8.3 leaves this open; the peer may hold the
//! network secret and still not be that node).
//!
//! Root keys are compared in constant time and wiped on drop.

use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

use ring::digest::{digest, SHA256};
use ring::rand::SecureRandom;

use zeroize::Zeroize;

use crate::config::Cipher;

use super::messages::Action;
use super::noise::LEN;
use super::traffic::{keys_equal, Receiver, ReplayWindow, Sender, TrafficError, ROOT_KEY_LEN};

/// A session no connection has used for this long is dropped (spec §8.6).
/// A relay session counts as used when it seals or opens a packet.
pub const IDLE_TIMEOUT: Duration = Duration::from_secs(60);
/// Most sessions held at once, over both namespaces.
pub const MAX_SESSIONS: usize = 4096;
/// Most peers whose last generation is remembered.
pub const MAX_GENERATIONS: usize = MAX_SESSIONS * 4;
/// How long a direct client waits for another connection to the same peer
/// that is creating the session: the handshake timeout (spec §5.3).
pub const CLIENT_CREATE_TIMEOUT: Duration = Duration::from_secs(5);
/// Records of dropped sessions per peer and namespace (spec §8.4 rule 2).
pub const RECORDS_PER_PEER: usize = 4;
/// Records of dropped sessions in all.
pub const MAX_RECORDS: usize = 4096;
/// How many epochs past the one a Sync names this node may start sending
/// in. 0 until the reference server's receive base is measured (spec §23
/// T21).
pub const SYNC_SKIP_LIMIT: u32 = 0;
/// After a Sync without a record, packets that authenticate may move the
/// receive epoch any distance ahead for this long (spec §8.4 rule 2).
pub const SYNC_RELAX_PERIOD: Duration = Duration::from_secs(60);
/// A pending relay session that no packet decrypts under within this is
/// dropped (spec §9).
pub const PENDING_TIMEOUT: Duration = Duration::from_secs(10);
/// Pending relay sessions per initiator.
pub const PENDING_PER_PEER: usize = 4;
/// Pending relay sessions in all.
pub const MAX_PENDING: usize = 256;
/// After a pending session of an initiator was dropped to make room, its
/// packets that fail on the current session do not count as failures for
/// this long (spec §9).
pub const EVICTION_GRACE: Duration = Duration::from_secs(10);
/// Relay msg1 ephemeral keys remembered per initiator (spec §9).
pub const SEEN_PER_PEER: usize = 4096;
/// Relay msg1 ephemeral keys remembered in all, unless configured.
pub const DEFAULT_MAX_SEEN: usize = 65536;
/// Bytes of the SHA-256 of an ephemeral key that are remembered.
pub const SEEN_LEN: usize = 16;

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

/// Which end of the handshake installs a session.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Side {
    /// The server or relay responder: it chose the action.
    Server,
    /// The client or relay initiator: the peer chose it.
    Client,
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
    /// No session with the peer.
    NoSession,
    /// [`MAX_SESSIONS`] are held, or the peer's generations are used up.
    Full,
    /// Another connection to the same peer is creating the session: start
    /// this one again once it is up, with its generation, or after
    /// [`CLIENT_CREATE_TIMEOUT`] (spec §8.1).
    Busy,
    /// The session of this node ID is in use and was set up by a peer with
    /// another static key.
    StaticKeyMismatch,
    /// A Create of a generation not above the installed session's: the
    /// connection closes and nothing changes (spec §8.1).
    NotNewer,
    /// The peer handed out a root key this node already used with it
    /// (spec §8.1): nothing is installed, the connection closes.
    RootKeyReused,
    /// A Sync would make this node send in an epoch it already used under
    /// that root key (spec §8.4 rule 2): reported as "session sync failed";
    /// the driver closes every direct connection to the peer, or stops
    /// starting relay handshakes with it, and waits at least 90 seconds,
    /// doubling up to 10 minutes, before a new handshake.
    SyncFailed,
    Traffic(TrafficError),
}

impl From<TrafficError> for SessionError {
    fn from(error: TrafficError) -> Self {
        SessionError::Traffic(error)
    }
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
    /// Until when the receiver follows the peer any distance ahead.
    relaxed_until: Option<Instant>,
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

    fn in_use(&self) -> bool {
        self.connections > 0
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

/// The first generation with a peer: random in [1, 2^31) (spec §8.1).
fn random_generation(rng: &dyn SecureRandom) -> Result<u32, SessionError> {
    let mut bytes = [0u8; 4];
    rng.fill(&mut bytes).map_err(|_| SessionError::Random)?;
    Ok((u32::from_be_bytes(bytes) & 0x7fff_ffff).max(1))
}

fn root_digest(root_key: &[u8; ROOT_KEY_LEN]) -> [u8; 32] {
    digest(&SHA256, root_key)
        .as_ref()
        .try_into()
        .expect("SHA-256 is 32 bytes")
}

/// The digest an ephemeral key is remembered by.
pub fn seen_digest(ephemeral: &[u8]) -> [u8; SEEN_LEN] {
    digest(&SHA256, ephemeral).as_ref()[..SEEN_LEN]
        .try_into()
        .expect("SEEN_LEN bytes")
}

/// What a dropped session leaves behind (spec §8.4 rule 2): never the root
/// key itself.
struct Record {
    key: SessionKey,
    digest: [u8; 32],
    send_epoch: u32,
    receive_newest: u32,
    receive_window: ReplayWindow,
    used: u64,
}

struct Remembered {
    last: u32,
    used: u64,
}

/// A relay Create waiting for its first packet (spec §9).
struct Pending {
    seen: [u8; SEEN_LEN],
    session: Session,
    msg2: Vec<u8>,
    until: Instant,
}

/// What became of a relay msg1, before any expensive work (spec §9).
#[derive(Debug, PartialEq, Eq)]
pub enum RelayLookup {
    /// Not seen before: handle it.
    New,
    /// The msg1 of a session still pending: send this msg2 again.
    Repeat(Vec<u8>),
    /// Seen before and no longer pending: drop it without an answer.
    Replayed,
}

/// The sessions of this node.
pub struct Sessions {
    map: HashMap<SessionKey, Session>,
    generations: HashMap<SessionKey, Remembered>,
    records: VecDeque<Record>,
    pending: HashMap<SessionKey, VecDeque<Pending>>,
    pending_count: usize,
    /// When a pending session of a peer was last dropped to make room.
    evicted: HashMap<SessionKey, Instant>,
    seen: HashMap<SessionKey, HashMap<[u8; SEEN_LEN], u64>>,
    seen_count: usize,
    max_seen: usize,
    /// Direct peers this node is creating a session with as client.
    creating: HashMap<SessionKey, Instant>,
    tick: u64,
}

impl Default for Sessions {
    fn default() -> Self {
        Self::with_seen_limit(DEFAULT_MAX_SEEN)
    }
}

impl Sessions {
    pub fn new() -> Self {
        Self::default()
    }

    /// Remembers at most `max_seen` relay msg1 ephemeral keys in all, for
    /// devices with little memory (spec §9).
    pub fn with_seen_limit(max_seen: usize) -> Self {
        Self {
            map: HashMap::new(),
            generations: HashMap::new(),
            records: VecDeque::new(),
            pending: HashMap::new(),
            pending_count: 0,
            evicted: HashMap::new(),
            seen: HashMap::new(),
            seen_count: 0,
            max_seen: max_seen.max(1),
            creating: HashMap::new(),
            tick: 0,
        }
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

    /// Pending relay sessions with the peer.
    pub fn pending_len(&self, key: &SessionKey) -> usize {
        self.pending.get(key).map_or(0, VecDeque::len)
    }

    fn next_tick(&mut self) -> u64 {
        self.tick += 1;
        self.tick
    }

    /// The next generation with the peer: one above the last, or a random
    /// start (spec §8.1). Past [`MAX_GENERATIONS`] peers, the one used
    /// longest ago without a session is forgotten.
    fn next_generation(
        &mut self,
        key: &SessionKey,
        rng: &dyn SecureRandom,
    ) -> Result<u32, SessionError> {
        let tick = self.next_tick();
        let last = self
            .generations
            .get(key)
            .map(|remembered| remembered.last)
            .max(self.generation(key));
        let next = match last.map(|last| last.checked_add(1)) {
            Some(Some(next)) => next,
            // Never wraps: the installed session goes, and a new random
            // start follows (spec §8.1).
            Some(None) => {
                self.retire(key);
                random_generation(rng)?
            }
            None => random_generation(rng)?,
        };
        if !self.generations.contains_key(key) && self.generations.len() >= MAX_GENERATIONS {
            let map = &self.map;
            let oldest = self
                .generations
                .iter()
                .filter(|(peer, _)| !map.contains_key(*peer))
                .min_by_key(|(_, remembered)| remembered.used)
                .map(|(key, _)| key.clone());
            if let Some(oldest) = oldest {
                self.generations.remove(&oldest);
            }
        }
        self.generations.insert(
            key.clone(),
            Remembered {
                last: next,
                used: tick,
            },
        );
        Ok(next)
    }

    /// The server's choice on msg1 (spec §8.4 rule 1): Join when msg1
    /// carries the installed session's generation and the ciphers match,
    /// otherwise a Create with a new root key and the next generation.
    /// `ciphers.local` is what this node will announce in msg2,
    /// `ciphers.peer` what msg1 announced.
    pub fn server_choice(
        &mut self,
        key: &SessionKey,
        client_generation: Option<u32>,
        ciphers: Ciphers,
        rng: &dyn SecureRandom,
    ) -> Result<Agreement, SessionError> {
        if let Some(session) = self.map.get(key) {
            if client_generation == Some(session.generation) && session.ciphers == ciphers {
                return Ok(Agreement {
                    action: Action::Join,
                    generation: session.generation,
                    root_key: session.root_key,
                    initial_epoch: session.sender.epoch(),
                });
            }
        }
        let root_key = random_root_key(rng)?;
        let generation = self.next_generation(key, rng)?;
        Ok(Agreement {
            action: Action::Create,
            generation,
            root_key,
            initial_epoch: 0,
        })
    }

    /// A direct client about to send msg1 to `key`'s peer: the generation
    /// to put in it. Without a session only one connection at a time asks
    /// for a new one (spec §8.1); the others get [`SessionError::Busy`].
    pub fn client_start(
        &mut self,
        key: &SessionKey,
        now: Instant,
    ) -> Result<Option<u32>, SessionError> {
        if let Some(generation) = self.generation(key) {
            return Ok(Some(generation));
        }
        if self.creating.get(key).is_some_and(|until| now < *until) {
            return Err(SessionError::Busy);
        }
        self.creating
            .insert(key.clone(), now + CLIENT_CREATE_TIMEOUT);
        Ok(None)
    }

    /// The client's handshake with `key`'s peer ended, installed or not.
    pub fn client_done(&mut self, key: &SessionKey) {
        self.creating.remove(key);
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

    fn has_record(&self, key: &SessionKey, digest: &[u8; 32]) -> bool {
        self.records
            .iter()
            .any(|record| record.key == *key && keys_equal(&record.digest, digest))
    }

    /// Drops the session of `key`, leaving a record of it (spec §8.4 rule
    /// 2). Pending relay sessions are not touched.
    fn retire(&mut self, key: &SessionKey) {
        let Some(session) = self.map.remove(key) else {
            return;
        };
        let used = self.next_tick();
        let record = Record {
            key: key.clone(),
            digest: root_digest(&session.root_key),
            send_epoch: session.sender.epoch(),
            receive_newest: session.receiver.newest(),
            receive_window: session.receiver.newest_window(),
            used,
        };
        let digest = record.digest;
        self.records
            .retain(|old| !(old.key == *key && keys_equal(&old.digest, &digest)));
        let of_peer = self.records.iter().filter(|old| old.key == *key).count();
        if of_peer >= RECORDS_PER_PEER {
            if let Some(at) = self
                .records
                .iter()
                .enumerate()
                .filter(|(_, old)| old.key == *key)
                .min_by_key(|(_, old)| old.used)
                .map(|(at, _)| at)
            {
                self.records.remove(at);
            }
        }
        if self.records.len() >= MAX_RECORDS {
            if let Some(at) = self
                .records
                .iter()
                .enumerate()
                .min_by_key(|(_, old)| old.used)
                .map(|(at, _)| at)
            {
                self.records.remove(at);
            }
        }
        self.records.push_back(record);
    }

    /// The record of `digest`, taken out: it is written again when the
    /// session that replaces it is dropped.
    fn take_record(&mut self, key: &SessionKey, digest: &[u8; 32]) -> Option<Record> {
        let at = self
            .records
            .iter()
            .position(|record| record.key == *key && keys_equal(&record.digest, digest))?;
        self.records.remove(at)
    }

    #[allow(clippy::too_many_arguments)]
    fn new_session(
        key: &SessionKey,
        agreement: &Agreement,
        local_id: u32,
        ciphers: Ciphers,
        peer_static: [u8; LEN],
        receiver: Receiver,
        send_epoch: u32,
        now: Instant,
    ) -> Result<Session, SessionError> {
        Ok(Session {
            generation: agreement.generation,
            root_key: agreement.root_key,
            ciphers,
            peer_static,
            sender: Sender::new(
                ciphers.local,
                agreement.root_key,
                local_id,
                key.peer_id,
                send_epoch,
                now,
            )?,
            receiver,
            connections: usize::from(key.namespace == Namespace::Direct),
            idle_since: now,
            relaxed_until: None,
        })
    }

    /// Installs a finished handshake with the peer holding `peer_static`
    /// and, for a direct session, counts one more connection on it.
    ///
    /// - Join keeps the session as it is.
    /// - Create replaces it. As [`Side::Server`] only a lower generation
    ///   is replaced (spec §8.1). A root key this node already used with
    ///   the peer is refused.
    /// - Sync (from a peer of the reference behaviour, as [`Side::Client`]
    ///   only) keeps the root key: a recorded one goes on from its record
    ///   and is refused when that would reuse an epoch; otherwise this node
    ///   sends from the agreed epoch and takes the peer's epoch from its
    ///   first packet (spec §8.4 rule 2).
    ///
    /// A direct session in use that another static key set up is never
    /// touched.
    #[allow(clippy::too_many_arguments)]
    pub fn install(
        &mut self,
        key: SessionKey,
        agreement: &Agreement,
        local_id: u32,
        ciphers: Ciphers,
        peer_static: [u8; LEN],
        side: Side,
        now: Instant,
    ) -> Result<(), SessionError> {
        if let Some(session) = self.map.get(&key) {
            if session.peer_static != peer_static && session.in_use() {
                return Err(SessionError::StaticKeyMismatch);
            }
        }
        match agreement.action {
            Action::Join => {
                let session = self
                    .map
                    .get_mut(&key)
                    .filter(|session| {
                        session.generation == agreement.generation
                            && session.ciphers == ciphers
                            && session.peer_static == peer_static
                            && keys_equal(&session.root_key, &agreement.root_key)
                    })
                    .ok_or(SessionError::NothingToJoin)?;
                if key.namespace == Namespace::Direct {
                    session.connections += 1;
                }
                session.idle_since = now;
                Ok(())
            }
            Action::Create => {
                if let Some(session) = self.map.get(&key) {
                    if side == Side::Server && agreement.generation <= session.generation {
                        return Err(SessionError::NotNewer);
                    }
                    if keys_equal(&session.root_key, &agreement.root_key) {
                        return Err(SessionError::RootKeyReused);
                    }
                }
                if self.has_record(&key, &root_digest(&agreement.root_key)) {
                    return Err(SessionError::RootKeyReused);
                }
                if !self.map.contains_key(&key) && self.map.len() >= MAX_SESSIONS {
                    return Err(SessionError::Full);
                }
                let receiver = Receiver::new(
                    ciphers.peer,
                    agreement.root_key,
                    local_id,
                    key.peer_id,
                    agreement.initial_epoch,
                )?;
                let mut session = Self::new_session(
                    &key,
                    agreement,
                    local_id,
                    ciphers,
                    peer_static,
                    receiver,
                    agreement.initial_epoch,
                    now,
                )?;
                // The other connections of the replaced session go on with
                // this one (spec §8.1).
                if let Some(old) = self.map.get(&key) {
                    session.connections += old.connections;
                }
                self.retire(&key);
                self.map.insert(key, session);
                Ok(())
            }
            Action::Sync => {
                if side == Side::Server {
                    // This node never sends Sync (spec §8.4 rule 1).
                    return Err(SessionError::NothingToJoin);
                }
                if !self.map.contains_key(&key) && self.map.len() >= MAX_SESSIONS {
                    return Err(SessionError::Full);
                }
                let carried = self.map.get(&key).map_or(0, |old| old.connections);
                self.retire(&key);
                let digest = root_digest(&agreement.root_key);
                let record = self.take_record(&key, &digest);
                let send_epoch = match &record {
                    Some(record) => agreement
                        .initial_epoch
                        .max(record.send_epoch.saturating_add(1)),
                    None => agreement.initial_epoch,
                };
                if send_epoch - agreement.initial_epoch > SYNC_SKIP_LIMIT {
                    if let Some(record) = record {
                        self.records.push_back(record);
                    }
                    return Err(SessionError::SyncFailed);
                }
                let receiver = match &record {
                    Some(record) => Receiver::restored(
                        ciphers.peer,
                        agreement.root_key,
                        local_id,
                        key.peer_id,
                        record.receive_newest,
                        record.receive_window.clone(),
                    )?,
                    None => Receiver::unanchored(
                        ciphers.peer,
                        agreement.root_key,
                        local_id,
                        key.peer_id,
                        0,
                    )?,
                };
                let relaxed_until = record.is_none().then(|| now + SYNC_RELAX_PERIOD);
                let mut session = Self::new_session(
                    &key,
                    agreement,
                    local_id,
                    ciphers,
                    peer_static,
                    receiver,
                    send_epoch,
                    now,
                )?;
                session.connections += carried;
                session.relaxed_until = relaxed_until;
                self.map.insert(key, session);
                Ok(())
            }
        }
    }

    /// What to do with a relay msg1 whose ephemeral key has `seen` as its
    /// digest (spec §9 item 1).
    pub fn relay_lookup(
        &self,
        key: &SessionKey,
        seen: &[u8; SEEN_LEN],
        now: Instant,
    ) -> RelayLookup {
        let pending = self
            .pending
            .get(key)
            .and_then(|pending| pending.iter().find(|p| p.seen == *seen && now < p.until));
        if let Some(pending) = pending {
            return RelayLookup::Repeat(pending.msg2.clone());
        }
        if self
            .seen
            .get(key)
            .is_some_and(|seen_of_peer| seen_of_peer.contains_key(seen))
        {
            return RelayLookup::Replayed;
        }
        RelayLookup::New
    }

    /// Remembers the ephemeral key of a relay msg1 that authenticated, for
    /// as long as the process runs or until pushed out (spec §9 item 1).
    pub fn remember_seen(&mut self, key: &SessionKey, seen: [u8; SEEN_LEN]) {
        let tick = self.next_tick();
        let known = self
            .seen
            .get(key)
            .is_some_and(|seen_of_peer| seen_of_peer.contains_key(&seen));
        if !known {
            let of_peer = self.seen.get(key).map_or(0, HashMap::len);
            if of_peer >= SEEN_PER_PEER {
                self.forget_oldest_seen(key);
            } else if self.seen_count >= self.max_seen {
                let busiest = self
                    .seen
                    .iter()
                    .max_by_key(|(_, seen_of_peer)| seen_of_peer.len())
                    .map(|(busiest, _)| busiest.clone());
                if let Some(busiest) = busiest {
                    self.forget_oldest_seen(&busiest);
                }
            }
            self.seen_count += 1;
        }
        self.seen.entry(key.clone()).or_default().insert(seen, tick);
    }

    fn forget_oldest_seen(&mut self, key: &SessionKey) {
        let Some(seen_of_peer) = self.seen.get_mut(key) else {
            return;
        };
        let oldest = seen_of_peer
            .iter()
            .min_by_key(|(_, used)| **used)
            .map(|(seen, _)| *seen);
        if let Some(oldest) = oldest {
            seen_of_peer.remove(&oldest);
            self.seen_count -= 1;
        }
        if seen_of_peer.is_empty() {
            self.seen.remove(key);
        }
    }

    /// Keeps a relay Create pending with the msg2 that answered it (spec §9
    /// item 2). Nothing changes for the current session.
    #[allow(clippy::too_many_arguments)]
    pub fn add_pending(
        &mut self,
        key: &SessionKey,
        seen: [u8; SEEN_LEN],
        agreement: &Agreement,
        local_id: u32,
        ciphers: Ciphers,
        peer_static: [u8; LEN],
        msg2: Vec<u8>,
        now: Instant,
    ) -> Result<(), SessionError> {
        let receiver = Receiver::new(
            ciphers.peer,
            agreement.root_key,
            local_id,
            key.peer_id,
            agreement.initial_epoch,
        )?;
        let session = Self::new_session(
            key,
            agreement,
            local_id,
            ciphers,
            peer_static,
            receiver,
            agreement.initial_epoch,
            now,
        )?;
        self.drop_expired_pending(key, now);
        if self.pending_len(key) >= PENDING_PER_PEER {
            self.evict_pending(key, now);
        } else if self.pending_count >= MAX_PENDING {
            let busiest = self
                .pending
                .iter()
                .max_by_key(|(_, pending)| pending.len())
                .map(|(busiest, _)| busiest.clone());
            if let Some(busiest) = busiest {
                self.evict_pending(&busiest, now);
            }
        }
        self.pending
            .entry(key.clone())
            .or_default()
            .push_back(Pending {
                seen,
                session,
                msg2,
                until: now + PENDING_TIMEOUT,
            });
        self.pending_count += 1;
        Ok(())
    }

    fn evict_pending(&mut self, key: &SessionKey, now: Instant) {
        if let Some(pending) = self.pending.get_mut(key) {
            if pending.pop_front().is_some() {
                self.pending_count -= 1;
                self.evicted.insert(key.clone(), now);
            }
            if pending.is_empty() {
                self.pending.remove(key);
            }
        }
    }

    fn drop_expired_pending(&mut self, key: &SessionKey, now: Instant) {
        if let Some(pending) = self.pending.get_mut(key) {
            let before = pending.len();
            pending.retain(|p| now < p.until);
            self.pending_count -= before - pending.len();
            if pending.is_empty() {
                self.pending.remove(key);
            }
        }
    }

    fn in_grace(&self, key: &SessionKey, now: Instant) -> bool {
        self.evicted
            .get(key)
            .is_some_and(|at| now.saturating_duration_since(*at) < EVICTION_GRACE)
    }

    /// Decrypts a packet from `key`'s peer in place. A relay packet that
    /// fails on the current session is tried on the peer's pending
    /// sessions; the first that opens it replaces the current session, the
    /// others are dropped, and the failure on the old one does not count
    /// (spec §9 item 2). A session that ends is dropped.
    pub fn open(
        &mut self,
        key: &SessionKey,
        payload: &mut Vec<u8>,
        now: Instant,
    ) -> Result<(), SessionError> {
        self.drop_expired_pending(key, now);
        let original = (self.pending_len(key) > 0).then(|| payload.clone());
        let current = self.map.get_mut(key).map(|session| {
            let relaxed = session.relaxed_until.is_some_and(|until| now < until);
            session.receiver.relax_ahead(relaxed);
            session.receiver.open_uncounted(payload)
        });
        if let Some(Ok(())) = current {
            if let Some(session) = self.map.get_mut(key) {
                session.idle_since = now;
            }
            return Ok(());
        }
        if let Some(original) = original {
            let mut promoted = None;
            if let Some(pending) = self.pending.get_mut(key) {
                for (at, candidate) in pending.iter_mut().enumerate() {
                    let mut attempt = original.clone();
                    if candidate.session.receiver.open(&mut attempt).is_ok() {
                        promoted = Some((at, attempt));
                        break;
                    }
                }
            }
            if let Some((at, attempt)) = promoted {
                let mut pending = self.pending.remove(key).unwrap_or_default();
                self.pending_count -= pending.len();
                let mut chosen = pending.remove(at).expect("found above").session;
                drop(pending);
                chosen.idle_since = now;
                self.retire(key);
                self.map.insert(key.clone(), chosen);
                *payload = attempt;
                return Ok(());
            }
        }
        let grace = self.in_grace(key, now);
        let Some(Err((error, counts))) = current else {
            return Err(SessionError::NoSession);
        };
        let session = self.map.get_mut(key).expect("opened above");
        let error = if counts && !grace {
            session.receiver.count_failure(error)
        } else {
            error
        };
        if error == TrafficError::SessionEnded {
            self.retire(key);
        }
        Err(error.into())
    }

    /// Encrypts a packet for `key`'s peer in place. A session that ends is
    /// dropped.
    pub fn seal(
        &mut self,
        key: &SessionKey,
        payload: &mut Vec<u8>,
        now: Instant,
    ) -> Result<(), SessionError> {
        let session = self.map.get_mut(key).ok_or(SessionError::NoSession)?;
        session.idle_since = now;
        match session.sender.seal(payload, now) {
            Ok(()) => Ok(()),
            Err(TrafficError::SessionEnded) => {
                self.retire(key);
                Err(TrafficError::SessionEnded.into())
            }
            Err(error) => Err(error.into()),
        }
    }

    /// A direct connection that used the session closed.
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
        self.retire(key);
    }

    /// Drops sessions unused for [`IDLE_TIMEOUT`], pending relay sessions
    /// past [`PENDING_TIMEOUT`] and other expired state.
    pub fn reclaim(&mut self, now: Instant) {
        let idle: Vec<SessionKey> = self
            .map
            .iter()
            .filter(|(_, session)| {
                !session.in_use()
                    && now.saturating_duration_since(session.idle_since) >= IDLE_TIMEOUT
            })
            .map(|(key, _)| key.clone())
            .collect();
        for key in idle {
            self.retire(&key);
        }
        let peers: Vec<SessionKey> = self.pending.keys().cloned().collect();
        for key in peers {
            self.drop_expired_pending(&key, now);
        }
        self.evicted
            .retain(|_, at| now.saturating_duration_since(*at) < EVICTION_GRACE);
        self.creating.retain(|_, until| now < *until);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secure::traffic::MAX_FAILURES;
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
    const LOCAL_ID: u32 = 1;

    fn c(local: Cipher, peer: Cipher) -> Ciphers {
        Ciphers { local, peer }
    }

    fn agreement(action: Action, generation: u32, root: u8, initial_epoch: u32) -> Agreement {
        Agreement {
            action,
            generation,
            root_key: [root; ROOT_KEY_LEN],
            initial_epoch,
        }
    }

    /// A packet the peer (node 7) seals for this node (node 1).
    fn from_peer(root: u8, epoch: u32, now: Instant) -> Vec<u8> {
        let mut sender = Sender::new(AES, [root; ROOT_KEY_LEN], 7, LOCAL_ID, epoch, now).unwrap();
        let mut packet = b"p".to_vec();
        sender.seal(&mut packet, now).unwrap();
        packet
    }

    #[test]
    fn the_server_creates_then_joins_and_never_syncs() {
        let rng = SystemRandom::new();
        let now = Instant::now();
        for namespace in [Namespace::Direct, Namespace::Relay] {
            let mut sessions = Sessions::new();
            let key = key(namespace);
            let first = sessions
                .server_choice(&key, None, c(AES, AES), &rng)
                .unwrap();
            assert_eq!(first.action, Action::Create);
            assert!((1..1 << 31).contains(&first.generation));
            sessions
                .install(
                    key.clone(),
                    &first,
                    LOCAL_ID,
                    c(AES, AES),
                    PEER,
                    Side::Server,
                    now,
                )
                .unwrap();
            let join = sessions
                .server_choice(&key, Some(first.generation), c(AES, AES), &rng)
                .unwrap();
            assert_eq!(join.action, Action::Join);
            assert!(keys_equal(&join.root_key, &first.root_key));
            for (generation, ciphers) in [
                (None, c(AES, AES)),
                (Some(first.generation + 9), c(AES, AES)),
                (Some(first.generation), c(AES, CHACHA)),
            ] {
                let other = sessions
                    .server_choice(&key, generation, ciphers, &rng)
                    .unwrap();
                assert_eq!(other.action, Action::Create, "never Sync");
                assert!(!keys_equal(&other.root_key, &first.root_key));
            }
        }
    }

    #[test]
    fn parallel_creates_replace_only_a_lower_generation() {
        let rng = SystemRandom::new();
        let now = Instant::now();
        let mut sessions = Sessions::new();
        let key = key(Namespace::Direct);
        // Two msg1 at once, say over TCP and UDP, or one forged: each gets
        // its own Create.
        let early = sessions
            .server_choice(&key, None, c(AES, AES), &rng)
            .unwrap();
        let late = sessions
            .server_choice(&key, None, c(AES, AES), &rng)
            .unwrap();
        assert_eq!(late.generation, early.generation + 1);
        assert!(!keys_equal(&early.root_key, &late.root_key));
        sessions
            .install(
                key.clone(),
                &late,
                LOCAL_ID,
                c(AES, AES),
                PEER,
                Side::Server,
                now,
            )
            .unwrap();
        assert_eq!(
            sessions.install(
                key.clone(),
                &early,
                LOCAL_ID,
                c(AES, AES),
                PEER,
                Side::Server,
                now
            ),
            Err(SessionError::NotNewer)
        );
        assert_eq!(sessions.generation(&key), Some(late.generation));
        assert_eq!(sessions.get(&key).unwrap().connections(), 1);
    }

    #[test]
    fn generations_never_go_back() {
        let rng = SystemRandom::new();
        let now = Instant::now();
        let mut sessions = Sessions::new();
        let key = key(Namespace::Direct);
        let first = sessions
            .server_choice(&key, None, c(AES, AES), &rng)
            .unwrap();
        sessions
            .install(
                key.clone(),
                &first,
                LOCAL_ID,
                c(AES, AES),
                PEER,
                Side::Server,
                now,
            )
            .unwrap();
        sessions.invalidate(&key);
        sessions.reclaim(now + IDLE_TIMEOUT * 2);
        let next = sessions
            .server_choice(&key, None, c(AES, AES), &rng)
            .unwrap();
        assert_eq!(next.generation, first.generation + 1);
        // A failed handshake leaves no trace but the generation it used.
        let after = sessions
            .server_choice(&key, None, c(AES, AES), &rng)
            .unwrap();
        assert_eq!(after.generation, first.generation + 2);
    }

    #[test]
    fn a_root_key_used_before_with_the_peer_is_refused() {
        let now = Instant::now();
        let mut sessions = Sessions::new();
        let key = key(Namespace::Direct);
        sessions
            .install(
                key.clone(),
                &agreement(Action::Create, 5, 1, 0),
                LOCAL_ID,
                c(AES, AES),
                PEER,
                Side::Client,
                now,
            )
            .unwrap();
        assert_eq!(
            sessions.install(
                key.clone(),
                &agreement(Action::Create, 6, 1, 0),
                LOCAL_ID,
                c(AES, AES),
                PEER,
                Side::Client,
                now
            ),
            Err(SessionError::RootKeyReused)
        );
        sessions.invalidate(&key);
        assert_eq!(
            sessions.install(
                key.clone(),
                &agreement(Action::Create, 7, 1, 0),
                LOCAL_ID,
                c(AES, AES),
                PEER,
                Side::Client,
                now
            ),
            Err(SessionError::RootKeyReused)
        );
        sessions
            .install(
                key.clone(),
                &agreement(Action::Create, 7, 2, 0),
                LOCAL_ID,
                c(AES, AES),
                PEER,
                Side::Client,
                now,
            )
            .unwrap();
    }

    #[test]
    fn a_client_asks_for_one_new_session_at_a_time() {
        let now = Instant::now();
        let mut sessions = Sessions::new();
        let key = key(Namespace::Direct);
        assert_eq!(sessions.client_start(&key, now), Ok(None));
        assert_eq!(sessions.client_start(&key, now), Err(SessionError::Busy));
        assert_eq!(
            sessions.client_start(&key, now + CLIENT_CREATE_TIMEOUT),
            Ok(None),
            "the first one timed out"
        );
        sessions.client_done(&key);
        sessions
            .install(
                key.clone(),
                &agreement(Action::Create, 3, 1, 0),
                LOCAL_ID,
                c(AES, AES),
                PEER,
                Side::Client,
                now,
            )
            .unwrap();
        assert_eq!(sessions.client_start(&key, now), Ok(Some(3)));
        assert_eq!(sessions.client_start(&key, now), Ok(Some(3)));
    }

    #[test]
    fn a_sync_of_an_unknown_root_key_learns_the_peers_epoch() {
        let now = Instant::now();
        let mut sessions = Sessions::new();
        let key = key(Namespace::Direct);
        sessions
            .install(
                key.clone(),
                &agreement(Action::Sync, 4, 3, 7),
                LOCAL_ID,
                c(AES, AES),
                PEER,
                Side::Client,
                now,
            )
            .unwrap();
        assert_eq!(sessions.get(&key).unwrap().sender.epoch(), 7);
        // The peer kept its own epoch, far below the agreed one.
        let mut packet = from_peer(3, 2, now);
        sessions.open(&key, &mut packet, now).unwrap();
        assert_eq!(packet, b"p");
        assert_eq!(sessions.get(&key).unwrap().receiver.newest(), 2);
        // That may have been a replay: for a minute, the real epoch still
        // gets through however far ahead.
        let mut packet = from_peer(3, 20, now);
        sessions.open(&key, &mut packet, now).unwrap();
        assert_eq!(sessions.get(&key).unwrap().receiver.newest(), 20);
        let later = now + SYNC_RELAX_PERIOD;
        let mut packet = from_peer(3, 30, later);
        assert_eq!(
            sessions.open(&key, &mut packet, later),
            Err(SessionError::Traffic(TrafficError::EpochTooFarAhead))
        );
        assert_eq!(
            sessions.install(
                key.clone(),
                &agreement(Action::Sync, 4, 3, 7),
                LOCAL_ID,
                c(AES, AES),
                PEER,
                Side::Server,
                now
            ),
            Err(SessionError::NothingToJoin),
            "a server never installs a Sync"
        );
    }

    #[test]
    fn a_replacing_create_keeps_the_other_connections() {
        let rng = SystemRandom::new();
        let now = Instant::now();
        let mut sessions = Sessions::new();
        let key = key(Namespace::Direct);
        let first = sessions
            .server_choice(&key, None, c(AES, AES), &rng)
            .unwrap();
        sessions
            .install(
                key.clone(),
                &first,
                LOCAL_ID,
                c(AES, AES),
                PEER,
                Side::Server,
                now,
            )
            .unwrap();
        let join = sessions
            .server_choice(&key, Some(first.generation), c(AES, AES), &rng)
            .unwrap();
        sessions
            .install(
                key.clone(),
                &join,
                LOCAL_ID,
                c(AES, AES),
                PEER,
                Side::Server,
                now,
            )
            .unwrap();
        let next = sessions
            .server_choice(&key, None, c(AES, AES), &rng)
            .unwrap();
        sessions
            .install(
                key.clone(),
                &next,
                LOCAL_ID,
                c(AES, AES),
                PEER,
                Side::Server,
                now,
            )
            .unwrap();
        assert_eq!(sessions.get(&key).unwrap().connections(), 3);
        assert_eq!(sessions.generation(&key), Some(next.generation));
    }

    #[test]
    fn generations_do_not_wrap() {
        let rng = SystemRandom::new();
        let now = Instant::now();
        let mut sessions = Sessions::new();
        let key = key(Namespace::Direct);
        sessions
            .install(
                key.clone(),
                &agreement(Action::Create, u32::MAX, 1, 0),
                LOCAL_ID,
                c(AES, AES),
                PEER,
                Side::Server,
                now,
            )
            .unwrap();
        let next = sessions
            .server_choice(&key, None, c(AES, AES), &rng)
            .unwrap();
        assert!((1..1 << 31).contains(&next.generation));
        assert!(sessions.get(&key).is_none(), "the old session went first");
    }

    #[test]
    fn a_sync_that_would_reuse_an_epoch_fails() {
        let now = Instant::now();
        let mut sessions = Sessions::new();
        let key = key(Namespace::Direct);
        sessions
            .install(
                key.clone(),
                &agreement(Action::Create, 4, 3, 0),
                LOCAL_ID,
                c(AES, AES),
                PEER,
                Side::Client,
                now,
            )
            .unwrap();
        sessions
            .get_mut(&key)
            .unwrap()
            .sender
            .advance_to(4, now)
            .unwrap();
        let mut packet = from_peer(3, 1, now);
        sessions.open(&key, &mut packet, now).unwrap();
        sessions.invalidate(&key);

        // The peer still has the session and syncs it at an epoch this
        // node sent in already.
        assert_eq!(
            sessions.install(
                key.clone(),
                &agreement(Action::Sync, 4, 3, 3),
                LOCAL_ID,
                c(AES, AES),
                PEER,
                Side::Client,
                now
            ),
            Err(SessionError::SyncFailed)
        );
        assert!(sessions.get(&key).is_none());
        // Above it, the session goes on from the record.
        sessions
            .install(
                key.clone(),
                &agreement(Action::Sync, 4, 3, 5),
                LOCAL_ID,
                c(AES, AES),
                PEER,
                Side::Client,
                now,
            )
            .unwrap();
        assert_eq!(sessions.get(&key).unwrap().sender.epoch(), 5);
        let mut replayed = from_peer(3, 1, now);
        assert_eq!(
            sessions.open(&key, &mut replayed, now),
            Err(SessionError::Traffic(TrafficError::Replay))
        );
        let mut older = from_peer(3, 0, now);
        assert_eq!(
            sessions.open(&key, &mut older, now),
            Err(SessionError::Traffic(TrafficError::StaleEpoch))
        );
    }

    #[test]
    fn a_relay_create_waits_for_its_first_packet() {
        let rng = SystemRandom::new();
        let now = Instant::now();
        let mut sessions = Sessions::new();
        let key = key(Namespace::Relay);
        sessions
            .install(
                key.clone(),
                &agreement(Action::Create, 2, 1, 0),
                LOCAL_ID,
                c(AES, AES),
                PEER,
                Side::Server,
                now,
            )
            .unwrap();
        let seen = seen_digest(b"ephemeral");
        assert_eq!(sessions.relay_lookup(&key, &seen, now), RelayLookup::New);
        let choice = sessions
            .server_choice(&key, None, c(AES, AES), &rng)
            .unwrap();
        sessions.remember_seen(&key, seen);
        sessions
            .add_pending(
                &key,
                seen,
                &choice,
                LOCAL_ID,
                c(AES, AES),
                PEER,
                b"msg2".to_vec(),
                now,
            )
            .unwrap();
        assert_eq!(
            sessions.relay_lookup(&key, &seen, now),
            RelayLookup::Repeat(b"msg2".to_vec())
        );
        // The old session still works and nothing moved.
        assert_eq!(sessions.generation(&key), Some(2));
        let mut old = from_peer(1, 0, now);
        sessions.open(&key, &mut old, now).unwrap();

        // The first packet under the new root key makes it current.
        let mut sender = Sender::new(AES, choice.root_key, 7, LOCAL_ID, 0, now).unwrap();
        let mut packet = b"new".to_vec();
        sender.seal(&mut packet, now).unwrap();
        sessions.open(&key, &mut packet, now).unwrap();
        assert_eq!(packet, b"new");
        assert_eq!(sessions.generation(&key), Some(choice.generation));
        assert_eq!(sessions.pending_len(&key), 0);
        assert_eq!(
            sessions.relay_lookup(&key, &seen, now),
            RelayLookup::Replayed
        );
        let mut stale = from_peer(1, 0, now);
        assert!(sessions.open(&key, &mut stale, now).is_err());
    }

    #[test]
    fn pending_relay_sessions_are_bounded_and_expire() {
        let rng = SystemRandom::new();
        let now = Instant::now();
        let mut sessions = Sessions::new();
        let busy = key(Namespace::Relay);
        sessions
            .install(
                busy.clone(),
                &agreement(Action::Create, 2, 1, 0),
                LOCAL_ID,
                c(AES, AES),
                PEER,
                Side::Server,
                now,
            )
            .unwrap();
        for n in 0..PENDING_PER_PEER as u8 + 1 {
            let choice = sessions
                .server_choice(&busy, None, c(AES, AES), &rng)
                .unwrap();
            sessions
                .add_pending(
                    &busy,
                    seen_digest(&[n]),
                    &choice,
                    LOCAL_ID,
                    c(AES, AES),
                    PEER,
                    Vec::new(),
                    now,
                )
                .unwrap();
        }
        assert_eq!(sessions.pending_len(&busy), PENDING_PER_PEER);
        assert_eq!(
            sessions.relay_lookup(&busy, &seen_digest(&[0]), now),
            RelayLookup::New,
            "the oldest made room"
        );
        // A pending session of this peer was pushed out a moment ago: its
        // packets failing on the current session do not end it.
        for _ in 0..MAX_FAILURES * 2 {
            let mut garbage = from_peer(9, 0, now);
            assert!(sessions.open(&busy, &mut garbage, now).is_err());
        }
        assert!(sessions.get(&busy).is_some());

        let later = now + PENDING_TIMEOUT;
        sessions.reclaim(later);
        assert_eq!(sessions.pending_len(&busy), 0);

        // In all: the peer holding the most makes room.
        for peer_id in 100..100 + (MAX_PENDING / PENDING_PER_PEER) as u32 {
            let peer = SessionKey {
                peer_id,
                ..key(Namespace::Relay)
            };
            for n in 0..PENDING_PER_PEER as u8 {
                let choice = sessions
                    .server_choice(&peer, None, c(AES, AES), &rng)
                    .unwrap();
                sessions
                    .add_pending(
                        &peer,
                        seen_digest(&[n]),
                        &choice,
                        LOCAL_ID,
                        c(AES, AES),
                        PEER,
                        Vec::new(),
                        later,
                    )
                    .unwrap();
            }
        }
        let choice = sessions
            .server_choice(&busy, None, c(AES, AES), &rng)
            .unwrap();
        sessions
            .add_pending(
                &busy,
                seen_digest(b"x"),
                &choice,
                LOCAL_ID,
                c(AES, AES),
                PEER,
                Vec::new(),
                later,
            )
            .unwrap();
        assert_eq!(sessions.pending_len(&busy), 1);
        assert_eq!(sessions.pending_count, MAX_PENDING);
    }

    #[test]
    fn seen_ephemeral_keys_are_bounded_per_peer_and_in_all() {
        let mut sessions = Sessions::with_seen_limit(3);
        let a = key(Namespace::Relay);
        let b = SessionKey {
            peer_id: 8,
            ..a.clone()
        };
        let now = Instant::now();
        for n in 0..3u8 {
            sessions.remember_seen(&a, seen_digest(&[n]));
        }
        sessions.remember_seen(&b, seen_digest(b"b"));
        assert_eq!(
            sessions.relay_lookup(&a, &seen_digest(&[0]), now),
            RelayLookup::New
        );
        assert_eq!(
            sessions.relay_lookup(&a, &seen_digest(&[1]), now),
            RelayLookup::Replayed
        );
        assert_eq!(
            sessions.relay_lookup(&b, &seen_digest(b"b"), now),
            RelayLookup::Replayed
        );
        assert_eq!(sessions.seen_count, 3);
    }

    #[test]
    fn a_session_in_use_keeps_its_static_key() {
        let now = Instant::now();
        let mut sessions = Sessions::new();
        let key = key(Namespace::Direct);
        sessions
            .install(
                key.clone(),
                &agreement(Action::Create, 3, 1, 0),
                LOCAL_ID,
                c(AES, AES),
                PEER,
                Side::Server,
                now,
            )
            .unwrap();
        assert_eq!(
            sessions.install(
                key.clone(),
                &agreement(Action::Create, 4, 2, 0),
                LOCAL_ID,
                c(AES, AES),
                OTHER,
                Side::Server,
                now
            ),
            Err(SessionError::StaticKeyMismatch)
        );
        sessions.release(&key, now);
        sessions
            .install(
                key.clone(),
                &agreement(Action::Create, 4, 2, 0),
                LOCAL_ID,
                c(AES, AES),
                OTHER,
                Side::Server,
                now,
            )
            .unwrap();
        assert_eq!(sessions.get(&key).unwrap().peer_static(), OTHER);
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
            .install(
                at_server.clone(),
                &choice,
                10,
                c(CHACHA, AES),
                PEER,
                Side::Server,
                now,
            )
            .unwrap();
        client
            .install(
                at_client.clone(),
                &agreed,
                20,
                c(AES, CHACHA),
                PEER,
                Side::Client,
                now,
            )
            .unwrap();

        let mut packet = b"hello".to_vec();
        client.seal(&at_client, &mut packet, now).unwrap();
        server.open(&at_server, &mut packet, now).unwrap();
        assert_eq!(packet, b"hello");
        let mut packet = b"back".to_vec();
        server.seal(&at_server, &mut packet, now).unwrap();
        client.open(&at_client, &mut packet, now).unwrap();
        assert_eq!(packet, b"back");
    }

    #[test]
    fn idle_sessions_are_reclaimed_and_the_count_is_bounded() {
        let now = Instant::now();
        let mut sessions = Sessions::new();
        let direct = key(Namespace::Direct);
        let relay = key(Namespace::Relay);
        sessions
            .install(
                direct.clone(),
                &agreement(Action::Create, 1, 1, 0),
                LOCAL_ID,
                c(AES, AES),
                PEER,
                Side::Client,
                now,
            )
            .unwrap();
        sessions
            .install(
                relay.clone(),
                &agreement(Action::Create, 1, 2, 0),
                LOCAL_ID,
                c(AES, AES),
                PEER,
                Side::Client,
                now,
            )
            .unwrap();
        assert_eq!(sessions.get(&relay).unwrap().connections(), 0);
        let mut packet = b"p".to_vec();
        sessions
            .seal(&relay, &mut packet, now + IDLE_TIMEOUT / 2)
            .unwrap();
        sessions.reclaim(now + IDLE_TIMEOUT);
        assert_eq!(sessions.len(), 2, "direct in use, relay used lately");
        sessions.reclaim(now + IDLE_TIMEOUT * 2);
        assert_eq!(sessions.len(), 1, "relay idle");
        sessions.release(&direct, now);
        sessions.reclaim(now + IDLE_TIMEOUT);
        assert!(sessions.is_empty());

        for peer_id in 0..MAX_SESSIONS as u32 {
            let key = SessionKey {
                peer_id,
                ..direct.clone()
            };
            let mut create = agreement(Action::Create, 1, 0, 0);
            create.root_key[..4].copy_from_slice(&peer_id.to_be_bytes());
            create.root_key[4] = 0xee;
            sessions
                .install(key, &create, LOCAL_ID, c(AES, AES), PEER, Side::Client, now)
                .unwrap();
        }
        let extra = SessionKey {
            peer_id: u32::MAX,
            ..direct.clone()
        };
        assert_eq!(
            sessions.install(
                extra,
                &agreement(Action::Create, 1, 9, 0),
                LOCAL_ID,
                c(AES, AES),
                PEER,
                Side::Client,
                now
            ),
            Err(SessionError::Full)
        );
        sessions.invalidate(&SessionKey {
            peer_id: 0,
            ..direct
        });
        assert_eq!(sessions.len(), MAX_SESSIONS - 1);
    }
}
