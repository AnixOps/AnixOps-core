//! The region probe packet (appendix D.3), without I/O.
//!
//! A node sends a 128-byte request to a border node's probe responder; the
//! responder answers with 44 bytes, so it never sends more than it gets.
//! The answer carries `tag = HMAC-SHA256(K, answer[0..28])[0..16]` with
//! `K = HKDF-SHA256(salt = "mesh-region-probe/v1", ikm = X25519(s, E),
//! info = S ‖ E)`, so only the holder of the responder's private key can
//! answer: someone on the path can delay or drop answers, never make a
//! region look closer than it is.
//!
//! Keys and shared secrets are wiped when dropped. Nothing here logs.

use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::time::{Duration, Instant};

use ring::{hkdf, hmac};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, Zeroizing};

/// First four bytes of every probe packet.
pub const MAGIC: [u8; 4] = [0xA7, 0x1C, 0x5E, 0x02];
/// Version byte.
pub const VERSION: u8 = 1;
/// Type byte of a request.
pub const TYPE_REQUEST: u8 = 1;
/// Type byte of an answer.
pub const TYPE_ANSWER: u8 = 2;
/// Exact request length.
pub const REQUEST_LEN: usize = 128;
/// Exact answer length.
pub const ANSWER_LEN: usize = 44;
/// HKDF salt.
pub const SALT: &[u8] = b"mesh-region-probe/v1";
/// Length of the nonce of one probe.
pub const NONCE_LEN: usize = 16;
/// Length of the answer's tag.
pub const TAG_LEN: usize = 16;
/// Bytes of the answer the tag covers.
const TAGGED_LEN: usize = ANSWER_LEN - TAG_LEN;

/// Per-source budget: tokens per second and burst (D.3).
pub const SOURCE_RATE: u32 = 50;
pub const SOURCE_BURST: u32 = 20;
/// Global budget in requests per second (D.3).
pub const GLOBAL_RATE: u32 = 5000;
/// Derived keys the responder keeps, by ephemeral key (D.3).
pub const KEY_CACHE: usize = 1024;
/// Sources the responder tracks before it forgets the oldest.
pub const MAX_SOURCES: usize = 65_536;

/// A probe request as sent by a node.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Request {
    pub ephemeral: [u8; 32],
    pub nonce: [u8; NONCE_LEN],
    pub seq: u32,
}

impl Request {
    pub fn encode(&self) -> [u8; REQUEST_LEN] {
        let mut out = [0u8; REQUEST_LEN];
        out[0..4].copy_from_slice(&MAGIC);
        out[4] = VERSION;
        out[5] = TYPE_REQUEST;
        out[8..40].copy_from_slice(&self.ephemeral);
        out[40..56].copy_from_slice(&self.nonce);
        out[56..60].copy_from_slice(&self.seq.to_be_bytes());
        out
    }

    /// The request in `packet`, or `None` for anything that is not exactly
    /// a well-formed version-1 request (reserved and padding bytes zero).
    pub fn decode(packet: &[u8]) -> Option<Self> {
        if packet.len() != REQUEST_LEN
            || packet[0..4] != MAGIC
            || packet[4] != VERSION
            || packet[5] != TYPE_REQUEST
            || packet[6..8] != [0, 0]
            || packet[60..].iter().any(|&b| b != 0)
        {
            return None;
        }
        let mut ephemeral = [0u8; 32];
        ephemeral.copy_from_slice(&packet[8..40]);
        let mut nonce = [0u8; NONCE_LEN];
        nonce.copy_from_slice(&packet[40..56]);
        let seq = u32::from_be_bytes([packet[56], packet[57], packet[58], packet[59]]);
        Some(Self {
            ephemeral,
            nonce,
            seq,
        })
    }
}

/// The fields of an answer before its tag is checked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Answer {
    pub nonce: [u8; NONCE_LEN],
    pub seq: u32,
    pub tag: [u8; TAG_LEN],
}

impl Answer {
    /// The answer in `packet`, or `None` unless it is exactly a well-formed
    /// version-1 answer. The tag is not checked here.
    pub fn decode(packet: &[u8]) -> Option<Self> {
        if packet.len() != ANSWER_LEN
            || packet[0..4] != MAGIC
            || packet[4] != VERSION
            || packet[5] != TYPE_ANSWER
            || packet[6..8] != [0, 0]
        {
            return None;
        }
        let mut nonce = [0u8; NONCE_LEN];
        nonce.copy_from_slice(&packet[8..24]);
        let seq = u32::from_be_bytes([packet[24], packet[25], packet[26], packet[27]]);
        let mut tag = [0u8; TAG_LEN];
        tag.copy_from_slice(&packet[28..44]);
        Some(Self { nonce, seq, tag })
    }
}

fn header(nonce: &[u8; NONCE_LEN], seq: u32) -> [u8; TAGGED_LEN] {
    let mut out = [0u8; TAGGED_LEN];
    out[0..4].copy_from_slice(&MAGIC);
    out[4] = VERSION;
    out[5] = TYPE_ANSWER;
    out[8..24].copy_from_slice(nonce);
    out[24..28].copy_from_slice(&seq.to_be_bytes());
    out
}

/// The answer key `K` of one responder key `S` and one ephemeral key `E`.
/// Wiped when dropped.
pub struct AnswerKey(hmac::Key);

struct Len32;

impl hkdf::KeyType for Len32 {
    fn len(&self) -> usize {
        32
    }
}

/// `K` from the X25519 result, or `None` when the result is all zero (a
/// low-order point: the answer would prove nothing).
pub fn answer_key(
    shared: &[u8; 32],
    responder: &[u8; 32],
    ephemeral: &[u8; 32],
) -> Option<AnswerKey> {
    let raw = derive(shared, responder, ephemeral)?;
    Some(AnswerKey(hmac::Key::new(hmac::HMAC_SHA256, &raw[..])))
}

fn derive(
    shared: &[u8; 32],
    responder: &[u8; 32],
    ephemeral: &[u8; 32],
) -> Option<Zeroizing<[u8; 32]>> {
    // Constant time is not needed: the all-zero result is public anyway.
    if shared.iter().all(|&b| b == 0) {
        return None;
    }
    let prk = hkdf::Salt::new(hkdf::HKDF_SHA256, SALT).extract(shared);
    let info: [&[u8]; 2] = [responder, ephemeral];
    let mut key = Zeroizing::new([0u8; 32]);
    prk.expand(&info, Len32)
        .and_then(|okm| okm.fill(&mut key[..]))
        .ok()?;
    Some(key)
}

impl AnswerKey {
    /// The 44-byte answer to `nonce` and `seq`.
    pub fn answer(&self, nonce: &[u8; NONCE_LEN], seq: u32) -> [u8; ANSWER_LEN] {
        let head = header(nonce, seq);
        let tag = hmac::sign(&self.0, &head);
        let mut out = [0u8; ANSWER_LEN];
        out[..TAGGED_LEN].copy_from_slice(&head);
        out[TAGGED_LEN..].copy_from_slice(&tag.as_ref()[..TAG_LEN]);
        out
    }

    /// Whether `answer` carries the right tag for its nonce and seq, in
    /// constant time.
    pub fn verify(&self, answer: &Answer) -> bool {
        let head = header(&answer.nonce, answer.seq);
        let tag = hmac::sign(&self.0, &head);
        ring::constant_time::verify_slices_are_equal(&tag.as_ref()[..TAG_LEN], &answer.tag).is_ok()
    }
}

/// The node's side of one round towards one responder: a fresh ephemeral
/// key and the answer key, both wiped when dropped (D.3: never stored).
pub struct Prober {
    ephemeral: [u8; 32],
    key: AnswerKey,
}

impl Prober {
    /// A prober from a fresh 32-byte secret, or `None` when the responder's
    /// key is a low-order point.
    pub fn new(secret: [u8; 32], responder: &[u8; 32]) -> Option<Self> {
        let secret = StaticSecret::from(secret);
        let ephemeral = PublicKey::from(&secret).to_bytes();
        let shared = Zeroizing::new(
            secret
                .diffie_hellman(&PublicKey::from(*responder))
                .to_bytes(),
        );
        let key = answer_key(&shared, responder, &ephemeral)?;
        Some(Self { ephemeral, key })
    }

    /// The request for one probe.
    pub fn request(&self, nonce: [u8; NONCE_LEN], seq: u32) -> [u8; REQUEST_LEN] {
        Request {
            ephemeral: self.ephemeral,
            nonce,
            seq,
        }
        .encode()
    }

    /// The nonce and seq of `packet` when it is an authentic answer.
    pub fn check(&self, packet: &[u8]) -> Option<([u8; NONCE_LEN], u32)> {
        let answer = Answer::decode(packet)?;
        self.key
            .verify(&answer)
            .then_some((answer.nonce, answer.seq))
    }
}

/// Why a request was not answered (the responder's counters, D.9.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    Malformed,
    RateLimited,
    LowOrder,
}

/// Counters of a responder (D.9.3).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Counters {
    pub answered: u64,
    pub malformed: u64,
    pub rate_limited: u64,
    pub low_order: u64,
}

struct Bucket {
    tokens: f64,
    at: Instant,
}

impl Bucket {
    fn take(&mut self, now: Instant, rate: f64, burst: f64) -> bool {
        let elapsed = now.saturating_duration_since(self.at).as_secs_f64();
        self.tokens = (self.tokens + elapsed * rate).min(burst);
        self.at = now;
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

/// The source key of the per-source budget: the IPv4 address, or the /64
/// of an IPv6 address.
pub fn source_key(ip: IpAddr) -> u128 {
    match ip {
        IpAddr::V4(v4) => match v4.to_ipv6_mapped().octets() {
            octets => u128::from_be_bytes(octets),
        },
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => u128::from_be_bytes(v4.to_ipv6_mapped().octets()),
            None => u128::from_be_bytes(v6.octets()) & !((1u128 << 64) - 1),
        },
    }
}

/// The responder (border node side) without I/O: checks, budgets, the key
/// cache and the answer.
pub struct Responder {
    secret: StaticSecret,
    public: [u8; 32],
    sources: HashMap<u128, Bucket>,
    order: VecDeque<u128>,
    global: Bucket,
    cache: HashMap<[u8; 32], AnswerKey>,
    cache_order: VecDeque<[u8; 32]>,
    pub counters: Counters,
}

impl Responder {
    pub fn new(private: [u8; 32], now: Instant) -> Self {
        let secret = StaticSecret::from(private);
        let public = PublicKey::from(&secret).to_bytes();
        Self {
            secret,
            public,
            sources: HashMap::new(),
            order: VecDeque::new(),
            global: Bucket {
                tokens: f64::from(GLOBAL_RATE),
                at: now,
            },
            cache: HashMap::new(),
            cache_order: VecDeque::new(),
            counters: Counters::default(),
        }
    }

    /// The responder's public key `S`.
    pub fn public(&self) -> [u8; 32] {
        self.public
    }

    /// The answer to `packet` from `source`, or why there is none. Budgets
    /// are charged before any X25519 is done.
    pub fn handle(
        &mut self,
        packet: &[u8],
        source: IpAddr,
        now: Instant,
    ) -> Result<[u8; ANSWER_LEN], Refusal> {
        let result = self.answer(packet, source, now);
        match result {
            Ok(_) => self.counters.answered += 1,
            Err(Refusal::Malformed) => self.counters.malformed += 1,
            Err(Refusal::RateLimited) => self.counters.rate_limited += 1,
            Err(Refusal::LowOrder) => self.counters.low_order += 1,
        }
        result
    }

    fn answer(
        &mut self,
        packet: &[u8],
        source: IpAddr,
        now: Instant,
    ) -> Result<[u8; ANSWER_LEN], Refusal> {
        let request = Request::decode(packet).ok_or(Refusal::Malformed)?;
        if !self.charge(source_key(source), now) {
            return Err(Refusal::RateLimited);
        }
        if let Some(key) = self.cache.get(&request.ephemeral) {
            return Ok(key.answer(&request.nonce, request.seq));
        }
        let shared = Zeroizing::new(
            self.secret
                .diffie_hellman(&PublicKey::from(request.ephemeral))
                .to_bytes(),
        );
        let key = answer_key(&shared, &self.public, &request.ephemeral).ok_or(Refusal::LowOrder)?;
        let answer = key.answer(&request.nonce, request.seq);
        if self.cache_order.len() >= KEY_CACHE {
            if let Some(old) = self.cache_order.pop_front() {
                self.cache.remove(&old);
            }
        }
        self.cache_order.push_back(request.ephemeral);
        self.cache.insert(request.ephemeral, key);
        Ok(answer)
    }

    fn charge(&mut self, source: u128, now: Instant) -> bool {
        let bucket = match self.sources.get_mut(&source) {
            Some(bucket) => bucket,
            None => {
                if self.order.len() >= MAX_SOURCES {
                    if let Some(old) = self.order.pop_front() {
                        self.sources.remove(&old);
                    }
                }
                self.order.push_back(source);
                self.sources.entry(source).or_insert(Bucket {
                    tokens: f64::from(SOURCE_BURST),
                    at: now,
                })
            }
        };
        if !bucket.take(now, f64::from(SOURCE_RATE), f64::from(SOURCE_BURST)) {
            return false;
        }
        self.global
            .take(now, f64::from(GLOBAL_RATE), f64::from(GLOBAL_RATE))
    }

    /// Forgets sources idle for longer than `idle` (their bucket is full
    /// again anyway).
    pub fn prune(&mut self, now: Instant, idle: Duration) {
        let sources = &mut self.sources;
        self.order.retain(|key| match sources.get(key) {
            Some(bucket) if now.saturating_duration_since(bucket.at) < idle => true,
            _ => {
                sources.remove(key);
                false
            }
        });
    }
}

impl Drop for Responder {
    fn drop(&mut self) {
        self.public.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn hex(text: &str) -> Vec<u8> {
        (0..text.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
            .collect()
    }

    fn arr(text: &str) -> [u8; 32] {
        hex(text).try_into().unwrap()
    }

    const SERVER_PRIV: &str = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";
    const SERVER_PUB: &str = "07a37cbc142093c8b755dc1b10e86cb426374ad16aa853ed0bdfc0b2b86d1c7c";
    const EPH_PRIV: &str = "2122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40";
    const EPH_PUB: &str = "5869aff450549732cbaaed5e5df9b30a6da31cb0e5742bad5ad4a1a768f1a67b";
    const SHARED: &str = "a84dc7c3c8f058b1b2dc4cd1e9b5dc0a7987f88b6a9564cde3391fc421159e77";
    const K: &str = "e1589e21b1ec4979c4a1c4e9b8d524d3519d4bc1fb491fa7ce8ac99259bbbf30";
    const ANSWER: &str =
        "a71c5e0201020000a0a1a2a3a4a5a6a7a8a9aaabacadaeaf0000000796fb4ca5af635be623a7d3159246f17a";

    fn nonce() -> [u8; 16] {
        hex("a0a1a2a3a4a5a6a7a8a9aaabacadaeaf").try_into().unwrap()
    }

    #[test]
    fn appendix_test_vectors() {
        let server = arr(SERVER_PUB);
        let ephemeral = arr(EPH_PUB);
        let secret = StaticSecret::from(arr(EPH_PRIV));
        assert_eq!(PublicKey::from(&secret).to_bytes(), ephemeral);
        assert_eq!(
            PublicKey::from(&StaticSecret::from(arr(SERVER_PRIV))).to_bytes(),
            server
        );
        let shared = secret.diffie_hellman(&PublicKey::from(server)).to_bytes();
        assert_eq!(shared, arr(SHARED));
        assert_eq!(*derive(&shared, &server, &ephemeral).unwrap(), arr(K));

        let prober = Prober::new(arr(EPH_PRIV), &server).unwrap();
        let request = prober.request(nonce(), 7);
        let mut expected = hex("a71c5e0201010000");
        expected.extend_from_slice(&ephemeral);
        expected.extend_from_slice(&nonce());
        expected.extend_from_slice(&[0, 0, 0, 7]);
        expected.resize(REQUEST_LEN, 0);
        assert_eq!(request.to_vec(), expected);

        let now = Instant::now();
        let mut responder = Responder::new(arr(SERVER_PRIV), now);
        let answer = responder
            .handle(&request, IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), now)
            .unwrap();
        assert_eq!(answer.to_vec(), hex(ANSWER));
        assert_eq!(prober.check(&answer), Some((nonce(), 7)));
    }

    #[test]
    fn answers_are_smaller_than_requests() {
        assert!(ANSWER_LEN < REQUEST_LEN);
    }

    #[test]
    fn a_forged_or_altered_answer_is_refused() {
        let server = arr(SERVER_PUB);
        let prober = Prober::new(arr(EPH_PRIV), &server).unwrap();
        let mut answer = hex(ANSWER);
        for at in 0..ANSWER_LEN {
            answer[at] ^= 1;
            assert!(prober.check(&answer).is_none(), "byte {at}");
            answer[at] ^= 1;
        }
        // An answer computed with another responder key.
        let other = PublicKey::from(&StaticSecret::from([9u8; 32])).to_bytes();
        let impostor = Prober::new(arr(EPH_PRIV), &other).unwrap();
        assert!(impostor.check(&answer).is_none());
        assert!(prober.check(&answer[..43]).is_none());
        let mut longer = answer.clone();
        longer.push(0);
        assert!(prober.check(&longer).is_none());
    }

    #[test]
    fn malformed_requests_are_dropped_before_any_work() {
        let now = Instant::now();
        let mut responder = Responder::new(arr(SERVER_PRIV), now);
        let source = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
        let good = Prober::new(arr(EPH_PRIV), &arr(SERVER_PUB))
            .unwrap()
            .request(nonce(), 1);
        let mut cases: Vec<Vec<u8>> = vec![good[..127].to_vec(), {
            let mut v = good.to_vec();
            v.push(0);
            v
        }];
        for at in [0usize, 4, 5, 6, 7, 60, 127] {
            let mut v = good.to_vec();
            v[at] ^= 0x40;
            cases.push(v);
        }
        for case in &cases {
            assert_eq!(responder.handle(case, source, now), Err(Refusal::Malformed));
        }
        assert_eq!(responder.counters.malformed, cases.len() as u64);
        assert_eq!(responder.counters.rate_limited, 0);
    }

    #[test]
    fn low_order_ephemeral_keys_get_no_answer() {
        let now = Instant::now();
        let mut responder = Responder::new(arr(SERVER_PRIV), now);
        let request = Request {
            ephemeral: [0u8; 32],
            nonce: nonce(),
            seq: 0,
        }
        .encode();
        let source = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
        assert_eq!(
            responder.handle(&request, source, now),
            Err(Refusal::LowOrder)
        );
        assert!(Prober::new(arr(EPH_PRIV), &[0u8; 32]).is_none());
    }

    #[test]
    fn each_source_has_a_budget_and_ipv6_counts_by_64() {
        let now = Instant::now();
        let mut responder = Responder::new(arr(SERVER_PRIV), now);
        let request = Prober::new(arr(EPH_PRIV), &arr(SERVER_PUB))
            .unwrap()
            .request(nonce(), 1);
        let a: IpAddr = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 1, 0, 0, 0, 1));
        let b: IpAddr = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 1, 0xffff, 0, 0, 2));
        let c: IpAddr = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 2, 0, 0, 0, 1));
        for _ in 0..SOURCE_BURST {
            assert!(responder.handle(&request, a, now).is_ok());
        }
        assert_eq!(
            responder.handle(&request, b, now),
            Err(Refusal::RateLimited)
        );
        assert!(responder.handle(&request, c, now).is_ok());
        // Refilled at SOURCE_RATE per second.
        let later = now + Duration::from_millis(100);
        let mut answered = 0;
        for _ in 0..SOURCE_BURST {
            if responder.handle(&request, a, later).is_ok() {
                answered += 1;
            }
        }
        assert_eq!(answered, (SOURCE_RATE / 10) as usize);
        // An IPv4-mapped IPv6 source is the IPv4 address.
        assert_eq!(
            source_key(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 9))),
            source_key("::ffff:192.0.2.9".parse().unwrap())
        );
        assert_ne!(
            source_key(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 9))),
            source_key(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)))
        );
    }

    #[test]
    fn the_global_budget_holds_across_sources() {
        let now = Instant::now();
        let mut responder = Responder::new(arr(SERVER_PRIV), now);
        let request = Prober::new(arr(EPH_PRIV), &arr(SERVER_PUB))
            .unwrap()
            .request(nonce(), 1);
        let mut answered = 0u32;
        for i in 0..(GLOBAL_RATE + 100) {
            let source = IpAddr::V4(Ipv4Addr::from(0x0a00_0000u32 + i));
            if responder.handle(&request, source, now).is_ok() {
                answered += 1;
            }
        }
        assert_eq!(answered, GLOBAL_RATE);
    }

    #[test]
    fn the_key_cache_is_bounded() {
        let now = Instant::now();
        let mut responder = Responder::new(arr(SERVER_PRIV), now);
        let server = arr(SERVER_PUB);
        for i in 0..(KEY_CACHE + 10) {
            let mut secret = [7u8; 32];
            secret[..8].copy_from_slice(&(i as u64).to_be_bytes());
            let prober = Prober::new(secret, &server).unwrap();
            let source = IpAddr::V4(Ipv4Addr::from(0x0a00_0000u32 + i as u32));
            let answer = responder
                .handle(&prober.request(nonce(), 0), source, now)
                .unwrap();
            assert!(prober.check(&answer).is_some());
        }
        assert_eq!(responder.cache.len(), KEY_CACHE);
        assert_eq!(responder.cache_order.len(), KEY_CACHE);
    }
}
