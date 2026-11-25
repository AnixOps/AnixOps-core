//! Traffic encryption of the secure mode (spec §8.5, §8.6).
//!
//! A session has one random root key. Each direction and epoch gets its own
//! key, `HKDF-SHA256(salt = 0³², ikm = root_key, info = TRAFFIC_INFO ‖
//! BE32(epoch) ‖ [dir])`. A packet is sealed like the default mode (`ciphertext
//! ‖ tag(16) ‖ nonce(12)`, no AAD), with the nonce `BE32(epoch) ‖ BE64(seq)`.
//! The sender moves to the next epoch after 1,000,000 packets or 10 minutes;
//! the receiver accepts epochs at most 3 ahead of the newest it has seen and
//! rejects replays with a 256-packet window per epoch.
//!
//! Root keys and derived keys are wiped when they are dropped. The AEAD
//! key schedules inside `ring` cannot be wiped from here.

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use ring::aead::{self, Aad, LessSafeKey, Nonce, UnboundKey};
use ring::hkdf;
use zeroize::Zeroize;

use super::TRAFFIC_INFO;
use crate::config::Cipher;
use crate::legacy::cipher::{NONCE_LEN, TAG_LEN, TAIL_LEN};

/// Packets per epoch before rotating (spec §8.6).
pub const MAX_PACKETS_PER_EPOCH: u64 = 1_000_000;
/// Time per epoch before rotating (spec §8.6).
pub const EPOCH_DURATION: Duration = Duration::from_secs(600);
/// How far ahead of the newest known epoch a packet may be (spec §8.6).
pub const MAX_EPOCHS_AHEAD: u32 = 3;
/// Width of the replay window in packets (spec §8.6).
pub const REPLAY_WINDOW: u64 = 256;
/// Consecutive decryption failures that end a session (spec §8.6).
pub const MAX_FAILURES: u32 = 10;
/// Root key length.
pub const ROOT_KEY_LEN: usize = 32;

/// The direction byte of the key derivation: 0 when the sender's node ID is
/// the smaller one (spec §8.5).
pub fn direction(sender: u32, receiver: u32) -> u8 {
    u8::from(sender >= receiver)
}

struct Len32;

impl hkdf::KeyType for Len32 {
    fn len(&self) -> usize {
        32
    }
}

/// The 32-byte key of one direction and epoch.
pub fn traffic_key(root_key: &[u8; ROOT_KEY_LEN], epoch: u32, dir: u8) -> [u8; 32] {
    let salt = hkdf::Salt::new(hkdf::HKDF_SHA256, &[0u8; 32]);
    let prk = salt.extract(root_key);
    let epoch = epoch.to_be_bytes();
    let info: [&[u8]; 3] = [&TRAFFIC_INFO, &epoch, &[dir]];
    let mut key = [0u8; 32];
    prk.expand(&info, Len32)
        .and_then(|okm| okm.fill(&mut key))
        .expect("32 bytes is within the HKDF output limit");
    key
}

/// The AEAD key of `cipher` for one direction and epoch; AES-128-GCM takes
/// the first 16 bytes (spec §8.5). `None` for [`Cipher::None`], which the
/// secure mode never uses.
fn aead_key(
    cipher: Cipher,
    root_key: &[u8; ROOT_KEY_LEN],
    epoch: u32,
    dir: u8,
) -> Option<LessSafeKey> {
    let algorithm = match cipher {
        Cipher::None | Cipher::Xor => return None,
        Cipher::Aes128Gcm => &aead::AES_128_GCM,
        Cipher::Aes256Gcm => &aead::AES_256_GCM,
        Cipher::ChaCha20Poly1305 => &aead::CHACHA20_POLY1305,
    };
    let mut key = traffic_key(root_key, epoch, dir);
    let unbound = UnboundKey::new(algorithm, &key[..algorithm.key_len()]);
    key.zeroize();
    Some(LessSafeKey::new(
        unbound.expect("traffic keys have the algorithm's length"),
    ))
}

/// Compares two keys without stopping at the first difference.
pub fn keys_equal(a: &[u8; ROOT_KEY_LEN], b: &[u8; ROOT_KEY_LEN]) -> bool {
    let difference = a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y));
    std::hint::black_box(difference) == 0
}

fn nonce(epoch: u32, seq: u64) -> [u8; NONCE_LEN] {
    let mut nonce = [0u8; NONCE_LEN];
    nonce[..4].copy_from_slice(&epoch.to_be_bytes());
    nonce[4..].copy_from_slice(&seq.to_be_bytes());
    nonce
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TrafficError {
    /// Shorter than the tail.
    Truncated,
    /// Authentication failed.
    Open,
    /// The packet was already received, or is older than the window.
    Replay,
    /// The packet's epoch is too old to keep a window for.
    StaleEpoch,
    /// The packet's epoch is more than [`MAX_EPOCHS_AHEAD`] ahead. Counts
    /// as a failure: a peer stuck there gets a new handshake.
    EpochTooFarAhead,
    /// Every epoch is used up, or [`MAX_FAILURES`] decryptions failed in a
    /// row: the session must be replaced by a new handshake.
    SessionEnded,
    /// The cipher cannot be used in the secure mode.
    Cipher,
}

/// The sending half of a session for one neighbour or relay peer. Wipes
/// its root key on drop.
pub struct Sender {
    cipher: Cipher,
    root_key: [u8; ROOT_KEY_LEN],
    dir: u8,
    epoch: u32,
    seq: u64,
    epoch_started: Instant,
    key: LessSafeKey,
}

impl Sender {
    /// `cipher` is the one this side announced in the handshake.
    pub fn new(
        cipher: Cipher,
        root_key: [u8; ROOT_KEY_LEN],
        local_id: u32,
        peer_id: u32,
        initial_epoch: u32,
        now: Instant,
    ) -> Result<Self, TrafficError> {
        let dir = direction(local_id, peer_id);
        let key = aead_key(cipher, &root_key, initial_epoch, dir).ok_or(TrafficError::Cipher)?;
        Ok(Self {
            cipher,
            root_key,
            dir,
            epoch: initial_epoch,
            seq: 0,
            epoch_started: now,
            key,
        })
    }

    pub fn epoch(&self) -> u32 {
        self.epoch
    }

    /// Whether this sender derives from `root_key`, compared in constant
    /// time.
    pub fn uses_root_key(&self, root_key: &[u8; ROOT_KEY_LEN]) -> bool {
        keys_equal(&self.root_key, root_key)
    }

    /// Moves to `epoch` with the sequence back at 0, as after a Sync told
    /// the peer to expect that epoch (spec §8.4). Never moves backwards.
    pub fn advance_to(&mut self, epoch: u32, now: Instant) -> Result<(), TrafficError> {
        if epoch <= self.epoch {
            return Ok(());
        }
        self.key =
            aead_key(self.cipher, &self.root_key, epoch, self.dir).ok_or(TrafficError::Cipher)?;
        self.epoch = epoch;
        self.seq = 0;
        self.epoch_started = now;
        Ok(())
    }

    fn rotate_if_due(&mut self, now: Instant) -> Result<(), TrafficError> {
        let due = self.seq >= MAX_PACKETS_PER_EPOCH
            || now.saturating_duration_since(self.epoch_started) >= EPOCH_DURATION;
        if !due {
            return Ok(());
        }
        let epoch = self
            .epoch
            .checked_add(1)
            .ok_or(TrafficError::SessionEnded)?;
        self.key =
            aead_key(self.cipher, &self.root_key, epoch, self.dir).ok_or(TrafficError::Cipher)?;
        self.epoch = epoch;
        self.seq = 0;
        self.epoch_started = now;
        Ok(())
    }

    /// Encrypts `payload` in place and appends the tail.
    pub fn seal(&mut self, payload: &mut Vec<u8>, now: Instant) -> Result<(), TrafficError> {
        self.rotate_if_due(now)?;
        let nonce = nonce(self.epoch, self.seq);
        let tag = self
            .key
            .seal_in_place_separate_tag(Nonce::assume_unique_for_key(nonce), Aad::empty(), payload)
            .map_err(|_| TrafficError::Truncated)?;
        payload.extend_from_slice(tag.as_ref());
        payload.extend_from_slice(&nonce);
        self.seq += 1;
        Ok(())
    }
}

impl Drop for Sender {
    fn drop(&mut self) {
        self.root_key.zeroize();
    }
}

/// A 256-packet sliding window over sequence numbers.
#[derive(Clone, Debug, Default)]
pub struct ReplayWindow {
    /// One more than the highest sequence number accepted; 0 before any.
    next: u64,
    /// Bit `i` is set when `next - 1 - i` was accepted.
    bits: [u64; 4],
}

impl ReplayWindow {
    /// Whether `seq` would be accepted; does not record it.
    pub fn check(&self, seq: u64) -> Result<(), TrafficError> {
        // No sender gets near it (it rotates after a million packets), and
        // recording it would overflow the window.
        if seq == u64::MAX {
            return Err(TrafficError::Replay);
        }
        if seq >= self.next {
            return Ok(());
        }
        let age = self.next - 1 - seq;
        if age >= REPLAY_WINDOW {
            return Err(TrafficError::Replay);
        }
        if self.bits[(age / 64) as usize] & (1 << (age % 64)) != 0 {
            return Err(TrafficError::Replay);
        }
        Ok(())
    }

    /// Records `seq`, which [`check`](Self::check) accepted.
    pub fn record(&mut self, seq: u64) {
        if seq >= self.next {
            let shift = seq - self.next + 1;
            self.shift(shift);
            self.next = seq + 1;
            self.bits[0] |= 1;
        } else {
            let age = self.next - 1 - seq;
            self.bits[(age / 64) as usize] |= 1 << (age % 64);
        }
    }

    /// Ages every recorded packet by `by`.
    fn shift(&mut self, by: u64) {
        if by >= REPLAY_WINDOW {
            self.bits = [0; 4];
            return;
        }
        let words = (by / 64) as usize;
        let bits = (by % 64) as u32;
        let mut shifted = [0u64; 4];
        for (index, word) in self.bits.iter().enumerate() {
            let to = index + words;
            if to < 4 {
                shifted[to] |= word << bits;
                if bits > 0 && to + 1 < 4 {
                    shifted[to + 1] |= word >> (64 - bits);
                }
            }
        }
        self.bits = shifted;
    }
}

/// The receiving half of a session. Wipes its root key on drop.
pub struct Receiver {
    cipher: Cipher,
    root_key: [u8; ROOT_KEY_LEN],
    dir: u8,
    newest: u32,
    /// Packets of an earlier epoch are refused.
    floor: u32,
    /// Whether a packet has set the newest epoch. After a Sync without a
    /// record of the session (spec §8.4 rule 2) the first packet that
    /// authenticates sets it.
    anchored: bool,
    /// Whether a packet that authenticates may move the newest epoch more
    /// than [`MAX_EPOCHS_AHEAD`] at once: for a while after such a Sync, so
    /// a replayed old packet that came first cannot hold the peer back.
    relaxed: bool,
    /// Keys and windows of the newest epoch and the one before it, so
    /// packets in flight across a rotation still arrive.
    epochs: BTreeMap<u32, (LessSafeKey, ReplayWindow)>,
    failures: u32,
}

impl Receiver {
    /// `cipher` is the one the peer announced in the handshake.
    pub fn new(
        cipher: Cipher,
        root_key: [u8; ROOT_KEY_LEN],
        local_id: u32,
        peer_id: u32,
        initial_epoch: u32,
    ) -> Result<Self, TrafficError> {
        let dir = direction(peer_id, local_id);
        let key = aead_key(cipher, &root_key, initial_epoch, dir).ok_or(TrafficError::Cipher)?;
        let mut epochs = BTreeMap::new();
        epochs.insert(initial_epoch, (key, ReplayWindow::default()));
        Ok(Self {
            cipher,
            root_key,
            dir,
            newest: initial_epoch,
            floor: 0,
            anchored: true,
            relaxed: false,
            epochs,
            failures: 0,
        })
    }

    /// A receiver that does not know the peer's epoch yet: the first packet
    /// that authenticates in `floor` or later sets it, and earlier packets
    /// are dropped without counting as failures. After a Sync without a
    /// record the floor is 0 (spec §8.4 rule 2).
    pub fn unanchored(
        cipher: Cipher,
        root_key: [u8; ROOT_KEY_LEN],
        local_id: u32,
        peer_id: u32,
        floor: u32,
    ) -> Result<Self, TrafficError> {
        aead_key(cipher, &root_key, floor, 0).ok_or(TrafficError::Cipher)?;
        Ok(Self {
            cipher,
            root_key,
            dir: direction(peer_id, local_id),
            newest: floor,
            floor,
            anchored: false,
            relaxed: false,
            epochs: BTreeMap::new(),
            failures: 0,
        })
    }

    /// A receiver that goes on from a record of the same root key: `newest`
    /// and its window as they were, and nothing earlier than `newest`
    /// (spec §8.4 rule 2).
    pub fn restored(
        cipher: Cipher,
        root_key: [u8; ROOT_KEY_LEN],
        local_id: u32,
        peer_id: u32,
        newest: u32,
        window: ReplayWindow,
    ) -> Result<Self, TrafficError> {
        let mut receiver = Self::new(cipher, root_key, local_id, peer_id, newest)?;
        receiver.floor = newest;
        if let Some(entry) = receiver.epochs.get_mut(&newest) {
            entry.1 = window;
        }
        Ok(receiver)
    }

    pub fn ended(&self) -> bool {
        self.failures >= MAX_FAILURES
    }

    /// Lets a packet that authenticates move the newest epoch however far
    /// ahead it is, with a new window, while `relaxed` (spec §8.4 rule 2:
    /// the first 60 seconds after a Sync without a record).
    pub fn relax_ahead(&mut self, relaxed: bool) {
        self.relaxed = relaxed;
    }

    /// The newest epoch a packet authenticated in, or the initial one.
    pub fn newest(&self) -> u32 {
        self.newest
    }

    /// The replay window of the newest epoch, for a record of the session.
    pub fn newest_window(&self) -> ReplayWindow {
        self.epochs
            .get(&self.newest)
            .map(|(_, window)| window.clone())
            .unwrap_or_default()
    }

    fn fail(&mut self, error: TrafficError) -> TrafficError {
        self.failures += 1;
        if self.ended() {
            TrafficError::SessionEnded
        } else {
            error
        }
    }

    /// Counts a failure [`Receiver::open_uncounted`] left uncounted.
    pub fn count_failure(&mut self, error: TrafficError) -> TrafficError {
        self.fail(error)
    }

    /// Decrypts a sealed payload in place, removing the tail. Only a packet
    /// that authenticates moves the window or the newest epoch.
    pub fn open(&mut self, payload: &mut Vec<u8>) -> Result<(), TrafficError> {
        match self.open_uncounted(payload) {
            Ok(()) => Ok(()),
            Err((error, true)) => Err(self.fail(error)),
            Err((error, false)) => Err(error),
        }
    }

    /// Like [`Receiver::open`], but a failure is returned with whether it
    /// counts towards [`MAX_FAILURES`] instead of being counted.
    pub fn open_uncounted(&mut self, payload: &mut Vec<u8>) -> Result<(), (TrafficError, bool)> {
        if self.ended() {
            return Err((TrafficError::SessionEnded, false));
        }
        if payload.len() < TAIL_LEN {
            return Err((TrafficError::Truncated, true));
        }
        let nonce_at = payload.len() - NONCE_LEN;
        let nonce: [u8; NONCE_LEN] = payload[nonce_at..].try_into().expect("NONCE_LEN bytes");
        let epoch = u32::from_be_bytes(nonce[..4].try_into().expect("4 bytes"));
        let seq = u64::from_be_bytes(nonce[4..].try_into().expect("8 bytes"));

        if epoch < self.floor {
            return Err((TrafficError::StaleEpoch, false));
        }
        if self.anchored {
            if epoch > self.newest {
                if epoch - self.newest > MAX_EPOCHS_AHEAD && !self.relaxed {
                    return Err((TrafficError::EpochTooFarAhead, true));
                }
            } else if self.newest - epoch > 1 {
                return Err((TrafficError::StaleEpoch, false));
            }
        }

        let fresh = if self.epochs.contains_key(&epoch) {
            None
        } else {
            Some(
                aead_key(self.cipher, &self.root_key, epoch, self.dir)
                    .ok_or((TrafficError::Cipher, false))?,
            )
        };
        let window = match (&fresh, self.epochs.get(&epoch)) {
            (None, Some((_, window))) => window,
            _ => &ReplayWindow::default(),
        };
        window.check(seq).map_err(|error| (error, false))?;

        let key = match &fresh {
            Some(key) => key,
            None => &self.epochs[&epoch].0,
        };
        let mut body = payload[..nonce_at].to_vec();
        let opened = key
            .open_in_place(Nonce::assume_unique_for_key(nonce), Aad::empty(), &mut body)
            .map(|plain| plain.len());
        let plain_len = match opened {
            Ok(len) => len,
            Err(_) => return Err((TrafficError::Open, true)),
        };
        debug_assert_eq!(plain_len + TAG_LEN, nonce_at);

        self.failures = 0;
        if let Some(key) = fresh {
            self.epochs.insert(epoch, (key, ReplayWindow::default()));
        }
        if epoch > self.newest || !self.anchored {
            self.newest = epoch;
            self.anchored = true;
            let oldest_kept = epoch.saturating_sub(1);
            self.epochs.retain(|&kept, _| kept >= oldest_kept);
        }
        self.epochs
            .get_mut(&epoch)
            .expect("inserted above")
            .1
            .record(seq);
        body.truncate(plain_len);
        *payload = body;
        Ok(())
    }
}

impl Drop for Receiver {
    fn drop(&mut self) {
        self.root_key.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    fn root() -> [u8; 32] {
        (0u8..32).collect::<Vec<_>>().try_into().unwrap()
    }

    // Spec §22.3.
    #[test]
    fn traffic_key_vectors() {
        assert_eq!(
            hex(&traffic_key(&root(), 0, 0)),
            "5f6aeafd4b1a023ef03ae837e7138631a416a1629d0cd3a97ec039d39c04add7"
        );
        assert_eq!(
            hex(&traffic_key(&root(), 0, 1)),
            "d94974e68e9f7b5756f7111b449bfec914c42a27be833a47897d69a85f887f9e"
        );
        assert_eq!(
            hex(&traffic_key(&root(), 1, 0)),
            "70ce34993a1713e067ba760fae72f30d5560254a3a6204522e134202f795f3f8"
        );
        assert_eq!(direction(3, 9), 0);
        assert_eq!(direction(9, 3), 1);
    }

    fn pair(cipher: Cipher, now: Instant) -> (Sender, Receiver) {
        (
            Sender::new(cipher, root(), 3, 9, 0, now).unwrap(),
            Receiver::new(cipher, root(), 9, 3, 0).unwrap(),
        )
    }

    #[test]
    fn round_trip_with_each_cipher() {
        let now = Instant::now();
        for cipher in [
            Cipher::Aes128Gcm,
            Cipher::Aes256Gcm,
            Cipher::ChaCha20Poly1305,
        ] {
            let (mut sender, mut receiver) = pair(cipher, now);
            for i in 0..5u8 {
                let mut packet = vec![i; 40];
                sender.seal(&mut packet, now).unwrap();
                assert_eq!(packet.len(), 40 + TAIL_LEN);
                assert_eq!(&packet[packet.len() - 12..][..4], &[0, 0, 0, 0]);
                receiver.open(&mut packet).unwrap();
                assert_eq!(packet, vec![i; 40]);
            }
        }
        assert!(Sender::new(Cipher::None, root(), 1, 2, 0, now).is_err());
    }

    #[test]
    fn the_other_direction_does_not_decrypt() {
        let now = Instant::now();
        let mut sender = Sender::new(Cipher::Aes128Gcm, root(), 3, 9, 0, now).unwrap();
        // A receiver that expects packets from 9 to 3 uses the other key.
        let mut wrong = Receiver::new(Cipher::Aes128Gcm, root(), 3, 9, 0).unwrap();
        let mut packet = b"hello".to_vec();
        sender.seal(&mut packet, now).unwrap();
        assert_eq!(wrong.open(&mut packet), Err(TrafficError::Open));
    }

    #[test]
    fn replays_are_refused() {
        let now = Instant::now();
        let (mut sender, mut receiver) = pair(Cipher::ChaCha20Poly1305, now);
        let mut packets = Vec::new();
        for _ in 0..300 {
            let mut packet = b"x".to_vec();
            sender.seal(&mut packet, now).unwrap();
            packets.push(packet);
        }
        // Out of order inside the window is fine, once.
        let mut late = packets[290].clone();
        let mut later = packets[299].clone();
        receiver.open(&mut later).unwrap();
        receiver.open(&mut late).unwrap();
        let mut again = packets[290].clone();
        assert_eq!(receiver.open(&mut again), Err(TrafficError::Replay));
        // Older than the window.
        let mut old = packets[10].clone();
        assert_eq!(receiver.open(&mut old), Err(TrafficError::Replay));
        // Replays are not failures: the session survives many of them.
        for _ in 0..20 {
            let mut again = packets[299].clone();
            assert_eq!(receiver.open(&mut again), Err(TrafficError::Replay));
        }
        let mut next = b"y".to_vec();
        sender.seal(&mut next, now).unwrap();
        receiver.open(&mut next).unwrap();
    }

    #[test]
    fn window_bits() {
        let mut window = ReplayWindow::default();
        for seq in [0, 1, 2, 64, 65, 200] {
            window.check(seq).unwrap();
            window.record(seq);
        }
        for seq in [0, 1, 2, 64, 65, 200] {
            assert_eq!(window.check(seq), Err(TrafficError::Replay), "{seq}");
        }
        for seq in [3, 63, 66, 199, 201] {
            assert!(window.check(seq).is_ok(), "{seq}");
        }
        window.record(455);
        assert_eq!(window.check(199), Err(TrafficError::Replay));
        assert!(window.check(200).is_ok() || window.check(200).is_err());
        assert!(window.check(201).is_ok());
        assert_eq!(window.check(455), Err(TrafficError::Replay));
        window.record(1000);
        assert!(window.check(999).is_ok());
        assert_eq!(window.check(744), Err(TrafficError::Replay));
        assert!(window.check(745).is_ok());
    }

    #[test]
    fn rotation_by_time_and_count() {
        let start = Instant::now();
        let (mut sender, mut receiver) = pair(Cipher::Aes128Gcm, start);
        let mut packet = b"a".to_vec();
        sender.seal(&mut packet, start + EPOCH_DURATION).unwrap();
        assert_eq!(sender.epoch(), 1);
        assert_eq!(&packet[packet.len() - 12..][..4], &[0, 0, 0, 1]);
        receiver.open(&mut packet).unwrap();

        sender.seq = MAX_PACKETS_PER_EPOCH;
        let mut packet = b"b".to_vec();
        sender.seal(&mut packet, start + EPOCH_DURATION).unwrap();
        assert_eq!(sender.epoch(), 2);
        receiver.open(&mut packet).unwrap();

        sender.epoch = u32::MAX;
        sender.seq = MAX_PACKETS_PER_EPOCH;
        let mut packet = b"c".to_vec();
        assert_eq!(
            sender.seal(&mut packet, start + EPOCH_DURATION),
            Err(TrafficError::SessionEnded)
        );
    }

    #[test]
    fn epoch_limits() {
        let now = Instant::now();
        let mut receiver = Receiver::new(Cipher::Aes128Gcm, root(), 9, 3, 5).unwrap();
        let seal = |epoch: u32| {
            let mut sender = Sender::new(Cipher::Aes128Gcm, root(), 3, 9, epoch, now).unwrap();
            let mut packet = b"p".to_vec();
            sender.seal(&mut packet, now).unwrap();
            packet
        };
        // Up to 3 ahead is accepted and becomes the newest.
        assert_eq!(
            receiver.open(&mut seal(9)),
            Err(TrafficError::EpochTooFarAhead)
        );
        receiver.open(&mut seal(8)).unwrap();
        // The previous epoch still works; older ones do not.
        receiver.open(&mut seal(7)).unwrap();
        assert_eq!(receiver.open(&mut seal(6)), Err(TrafficError::StaleEpoch));
        assert_eq!(receiver.open(&mut seal(5)), Err(TrafficError::StaleEpoch));
    }

    #[test]
    fn the_last_sequence_number_is_refused() {
        let mut window = ReplayWindow::default();
        assert_eq!(window.check(u64::MAX), Err(TrafficError::Replay));
        window.check(u64::MAX - 1).unwrap();
        window.record(u64::MAX - 1);
        assert_eq!(window.check(u64::MAX - 1), Err(TrafficError::Replay));
        assert_eq!(window.check(u64::MAX), Err(TrafficError::Replay));
    }

    #[test]
    fn a_peer_stuck_too_far_ahead_ends_the_session() {
        let now = Instant::now();
        let mut receiver = Receiver::new(Cipher::Aes128Gcm, root(), 9, 3, 0).unwrap();
        let mut sender = Sender::new(Cipher::Aes128Gcm, root(), 3, 9, 0, now).unwrap();
        sender.advance_to(MAX_EPOCHS_AHEAD + 1, now).unwrap();
        for attempt in 1..=MAX_FAILURES {
            let mut packet = b"p".to_vec();
            sender.seal(&mut packet, now).unwrap();
            let expected = if attempt == MAX_FAILURES {
                TrafficError::SessionEnded
            } else {
                TrafficError::EpochTooFarAhead
            };
            assert_eq!(receiver.open(&mut packet), Err(expected), "{attempt}");
        }
    }

    fn sealed(epoch: u32, now: Instant) -> Vec<u8> {
        let mut sender = Sender::new(Cipher::Aes128Gcm, root(), 3, 9, epoch, now).unwrap();
        let mut packet = b"p".to_vec();
        sender.seal(&mut packet, now).unwrap();
        packet
    }

    #[test]
    fn an_unanchored_receiver_takes_the_first_packet_at_or_above_its_floor() {
        let now = Instant::now();
        let mut receiver = Receiver::unanchored(Cipher::Aes128Gcm, root(), 9, 3, 6).unwrap();
        // Older packets, replayed or not, neither count nor set the epoch.
        for _ in 0..MAX_FAILURES + 2 {
            assert_eq!(
                receiver.open(&mut sealed(2, now)),
                Err(TrafficError::StaleEpoch)
            );
        }
        assert!(!receiver.ended());
        // The peer's real epoch may be far above the floor.
        receiver.open(&mut sealed(20, now)).unwrap();
        assert_eq!(receiver.newest(), 20);
        receiver.open(&mut sealed(19, now)).unwrap();
        assert_eq!(
            receiver.open(&mut sealed(6, now)),
            Err(TrafficError::StaleEpoch)
        );
        assert!(keys_equal(&root(), &root()));
        assert!(!keys_equal(&root(), &[0; 32]));
    }

    #[test]
    fn a_relaxed_receiver_follows_the_peer_far_ahead() {
        let now = Instant::now();
        let mut receiver = Receiver::unanchored(Cipher::Aes128Gcm, root(), 9, 3, 0).unwrap();
        // A replayed old packet came first and set the epoch low.
        receiver.open(&mut sealed(1, now)).unwrap();
        receiver.relax_ahead(true);
        receiver.open(&mut sealed(30, now)).unwrap();
        assert_eq!(receiver.newest(), 30);
        receiver.relax_ahead(false);
        assert_eq!(
            receiver.open(&mut sealed(40, now)),
            Err(TrafficError::EpochTooFarAhead)
        );
    }

    #[test]
    fn a_restored_receiver_keeps_its_window_and_refuses_older_epochs() {
        let now = Instant::now();
        let mut sender = Sender::new(Cipher::Aes128Gcm, root(), 3, 9, 4, now).unwrap();
        let mut packets = Vec::new();
        for _ in 0..3 {
            let mut packet = b"p".to_vec();
            sender.seal(&mut packet, now).unwrap();
            packets.push(packet);
        }
        let mut first = Receiver::new(Cipher::Aes128Gcm, root(), 9, 3, 4).unwrap();
        first.open(&mut packets[0].clone()).unwrap();
        let window = first.newest_window();
        let mut receiver =
            Receiver::restored(Cipher::Aes128Gcm, root(), 9, 3, first.newest(), window).unwrap();
        assert_eq!(
            receiver.open(&mut packets[0].clone()),
            Err(TrafficError::Replay)
        );
        receiver.open(&mut packets[1].clone()).unwrap();
        assert_eq!(
            receiver.open(&mut sealed(3, now)),
            Err(TrafficError::StaleEpoch)
        );
    }

    #[test]
    fn ten_failures_end_the_session() {
        let now = Instant::now();
        let (mut sender, mut receiver) = pair(Cipher::Aes128Gcm, now);
        let mut good = b"ok".to_vec();
        sender.seal(&mut good, now).unwrap();
        for attempt in 1..=MAX_FAILURES {
            let mut bad = good.clone();
            bad[0] ^= 0xff;
            let expected = if attempt == MAX_FAILURES {
                TrafficError::SessionEnded
            } else {
                TrafficError::Open
            };
            assert_eq!(receiver.open(&mut bad), Err(expected), "{attempt}");
        }
        assert!(receiver.ended());
        assert_eq!(receiver.open(&mut good), Err(TrafficError::SessionEnded));
    }

    #[test]
    fn a_success_resets_the_failure_count() {
        let now = Instant::now();
        let (mut sender, mut receiver) = pair(Cipher::Aes128Gcm, now);
        for _ in 0..3 {
            for _ in 0..MAX_FAILURES - 1 {
                let mut bad = vec![0u8; TAIL_LEN + 4];
                assert!(receiver.open(&mut bad).is_err());
            }
            let mut good = b"ok".to_vec();
            sender.seal(&mut good, now).unwrap();
            receiver.open(&mut good).unwrap();
        }
        assert!(!receiver.ended());
    }
}
