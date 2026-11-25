//! The two Noise handshakes of the secure mode (spec §8.1, §9):
//! `Noise_XX_25519_ChaChaPoly_SHA256` between neighbours and
//! `Noise_IK_25519_ChaChaPoly_SHA256` for relay sessions. Written from the
//! public Noise Protocol Framework (revision 34); no PSK, no fallback.
//!
//! Only the handshake is needed: once it is done the mode derives its own
//! traffic keys from a root key sent inside the handshake (spec §8.5), so
//! [`HandshakeState::split`] is not part of the protocol and exists for the
//! framework's test vectors.
//!
//! Keys, chaining keys, DH results and the handshake hash are wiped when
//! they are dropped or replaced.

use ring::aead::{self, Aad, LessSafeKey, Nonce, UnboundKey};
use ring::digest;
use ring::hmac;
use ring::rand::{SecureRandom, SystemRandom};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, Zeroizing};

/// Length of a hash, a chaining key, a key and a public key.
pub const LEN: usize = 32;
/// Bytes the AEAD adds.
pub const TAG_LEN: usize = 16;
/// Largest Noise message (framework §3).
pub const MAX_MESSAGE: usize = 65535;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NoiseError {
    /// A message is shorter than its pattern requires.
    Truncated,
    /// A message failed authentication.
    Decrypt,
    /// A Diffie-Hellman result was all zero: a low-order public key.
    WeakKey,
    /// Called out of turn, or after the handshake finished.
    OutOfTurn,
    /// A message would exceed [`MAX_MESSAGE`].
    TooLong,
    /// The system random source failed.
    Random,
}

/// Which handshake.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Pattern {
    /// `-> e`, `<- e, ee, s, es`, `-> s, se`.
    Xx,
    /// `<- s` known beforehand; `-> e, es, s, ss`, `<- e, ee, se`.
    Ik,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Token {
    E,
    S,
    Ee,
    Es,
    Se,
    Ss,
}

impl Pattern {
    fn name(self) -> &'static [u8] {
        match self {
            Pattern::Xx => b"Noise_XX_25519_ChaChaPoly_SHA256",
            Pattern::Ik => b"Noise_IK_25519_ChaChaPoly_SHA256",
        }
    }

    fn messages(self) -> &'static [&'static [Token]] {
        use Token::*;
        match self {
            Pattern::Xx => &[&[E], &[E, Ee, S, Es], &[S, Se]],
            Pattern::Ik => &[&[E, Es, S, Ss], &[E, Ee, Se]],
        }
    }
}

/// A long-term or ephemeral X25519 key pair. Has no `Debug`: it holds the
/// private key.
#[derive(Clone)]
pub struct KeyPair {
    secret: StaticSecret,
    public: [u8; LEN],
}

impl KeyPair {
    pub fn from_private(mut private: [u8; LEN]) -> Self {
        let secret = StaticSecret::from(private);
        private.zeroize();
        let public = PublicKey::from(&secret).to_bytes();
        Self { secret, public }
    }

    pub fn generate(rng: &dyn SecureRandom) -> Result<Self, NoiseError> {
        let mut private = Zeroizing::new([0u8; LEN]);
        rng.fill(&mut private[..]).map_err(|_| NoiseError::Random)?;
        Ok(Self::from_private(*private))
    }

    pub fn public(&self) -> [u8; LEN] {
        self.public
    }

    /// The private key, for storing a node's long-term key; wiped when
    /// dropped.
    pub fn private(&self) -> Zeroizing<[u8; LEN]> {
        Zeroizing::new(self.secret.to_bytes())
    }

    fn dh(&self, public: &[u8; LEN]) -> Result<Zeroizing<[u8; LEN]>, NoiseError> {
        let shared = self.secret.diffie_hellman(&PublicKey::from(*public));
        if !shared.was_contributory() {
            return Err(NoiseError::WeakKey);
        }
        Ok(Zeroizing::new(shared.to_bytes()))
    }
}

fn hmac(key: &[u8], parts: &[&[u8]]) -> [u8; LEN] {
    let key = hmac::Key::new(hmac::HMAC_SHA256, key);
    let mut context = hmac::Context::with_key(&key);
    for part in parts {
        context.update(part);
    }
    context.sign().as_ref().try_into().expect("SHA-256 output")
}

/// The framework's HKDF with two outputs (§4.3).
fn hkdf2(chaining_key: &[u8; LEN], input: &[u8]) -> ([u8; LEN], [u8; LEN]) {
    let temp = Zeroizing::new(hmac(chaining_key, &[input]));
    let first = hmac(&temp[..], &[&[1]]);
    let second = hmac(&temp[..], &[&first, &[2]]);
    (first, second)
}

/// One direction's cipher during the handshake (framework §5.1). The key
/// is wiped on drop.
#[derive(Default)]
pub struct CipherState {
    key: Option<[u8; LEN]>,
    n: u64,
}

impl Drop for CipherState {
    fn drop(&mut self) {
        if let Some(key) = self.key.as_mut() {
            key.zeroize();
        }
    }
}

impl CipherState {
    fn nonce(&self) -> Result<Nonce, NoiseError> {
        // 2^64 - 1 is reserved (framework §5.1).
        if self.n == u64::MAX {
            return Err(NoiseError::OutOfTurn);
        }
        let mut nonce = [0u8; 12];
        nonce[4..].copy_from_slice(&self.n.to_le_bytes());
        Ok(Nonce::assume_unique_for_key(nonce))
    }

    fn sealing_key(key: &[u8; LEN]) -> LessSafeKey {
        LessSafeKey::new(
            UnboundKey::new(&aead::CHACHA20_POLY1305, key).expect("32-byte ChaCha20 key"),
        )
    }

    pub fn encrypt(&mut self, ad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, NoiseError> {
        let Some(key) = self.key.as_ref() else {
            return Ok(plaintext.to_vec());
        };
        let nonce = self.nonce()?;
        let mut buffer = plaintext.to_vec();
        Self::sealing_key(key)
            .seal_in_place_append_tag(nonce, Aad::from(ad), &mut buffer)
            .map_err(|_| NoiseError::TooLong)?;
        self.n += 1;
        Ok(buffer)
    }

    pub fn decrypt(&mut self, ad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, NoiseError> {
        let Some(key) = self.key.as_ref() else {
            return Ok(ciphertext.to_vec());
        };
        let nonce = self.nonce()?;
        let mut buffer = ciphertext.to_vec();
        let plain_len = Self::sealing_key(key)
            .open_in_place(nonce, Aad::from(ad), &mut buffer)
            .map_err(|_| NoiseError::Decrypt)?
            .len();
        buffer.truncate(plain_len);
        self.n += 1;
        Ok(buffer)
    }
}

/// Framework §5.2. The chaining key and hash are wiped on drop.
struct SymmetricState {
    cipher: CipherState,
    chaining_key: [u8; LEN],
    h: [u8; LEN],
}

impl Drop for SymmetricState {
    fn drop(&mut self) {
        self.chaining_key.zeroize();
        self.h.zeroize();
    }
}

impl SymmetricState {
    fn new(name: &[u8]) -> Self {
        let mut h = [0u8; LEN];
        if name.len() <= LEN {
            h[..name.len()].copy_from_slice(name);
        } else {
            h.copy_from_slice(digest::digest(&digest::SHA256, name).as_ref());
        }
        Self {
            cipher: CipherState::default(),
            chaining_key: h,
            h,
        }
    }

    fn mix_hash(&mut self, data: &[u8]) {
        let mut context = digest::Context::new(&digest::SHA256);
        context.update(&self.h);
        context.update(data);
        self.h.copy_from_slice(context.finish().as_ref());
    }

    fn mix_key(&mut self, input: &[u8]) {
        let (mut chaining_key, mut key) = hkdf2(&self.chaining_key, input);
        self.chaining_key = chaining_key;
        // The old cipher is wiped as it is dropped.
        self.cipher = CipherState {
            key: Some(key),
            n: 0,
        };
        chaining_key.zeroize();
        key.zeroize();
    }

    fn encrypt_and_hash(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, NoiseError> {
        let ciphertext = self.cipher.encrypt(&self.h, plaintext)?;
        self.mix_hash(&ciphertext);
        Ok(ciphertext)
    }

    fn decrypt_and_hash(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, NoiseError> {
        let plaintext = self.cipher.decrypt(&self.h, ciphertext)?;
        self.mix_hash(ciphertext);
        Ok(plaintext)
    }

    fn has_key(&self) -> bool {
        self.cipher.key.is_some()
    }
}

/// One side of a handshake (framework §5.3).
pub struct HandshakeState {
    pattern: Pattern,
    initiator: bool,
    symmetric: SymmetricState,
    s: KeyPair,
    e: Option<KeyPair>,
    rs: Option<[u8; LEN]>,
    re: Option<[u8; LEN]>,
    /// Ephemeral private key to use instead of a random one; test vectors only.
    fixed_ephemeral: Option<[u8; LEN]>,
    message: usize,
}

impl HandshakeState {
    /// `remote_static` is the responder's public key for [`Pattern::Ik`]
    /// on the initiator; `None` otherwise.
    pub fn new(
        pattern: Pattern,
        initiator: bool,
        prologue: &[u8],
        s: KeyPair,
        remote_static: Option<[u8; LEN]>,
    ) -> Result<Self, NoiseError> {
        let mut symmetric = SymmetricState::new(pattern.name());
        symmetric.mix_hash(prologue);
        let rs = match pattern {
            Pattern::Xx => {
                if remote_static.is_some() {
                    return Err(NoiseError::OutOfTurn);
                }
                None
            }
            Pattern::Ik => {
                // The pre-message `<- s`: both sides hash the responder's key.
                let responder = if initiator {
                    remote_static.ok_or(NoiseError::OutOfTurn)?
                } else {
                    s.public()
                };
                symmetric.mix_hash(&responder);
                if initiator {
                    Some(responder)
                } else {
                    None
                }
            }
        };
        Ok(Self {
            pattern,
            initiator,
            symmetric,
            s,
            e: None,
            rs,
            re: None,
            fixed_ephemeral: None,
            message: 0,
        })
    }

    /// Uses `private` as this side's ephemeral key; test vectors only.
    #[cfg(test)]
    fn with_ephemeral(mut self, private: [u8; LEN]) -> Self {
        self.fixed_ephemeral = Some(private);
        self
    }

    fn my_turn(&self) -> bool {
        self.message.is_multiple_of(2) == self.initiator
    }

    fn tokens(&self) -> Result<&'static [Token], NoiseError> {
        self.pattern
            .messages()
            .get(self.message)
            .copied()
            .ok_or(NoiseError::OutOfTurn)
    }

    pub fn is_finished(&self) -> bool {
        self.message == self.pattern.messages().len()
    }

    /// The handshake hash `h` at this point (spec §8.2 proves over it).
    pub fn handshake_hash(&self) -> [u8; LEN] {
        self.symmetric.h
    }

    /// The peer's static public key, once received.
    pub fn remote_static(&self) -> Option<[u8; LEN]> {
        self.rs
    }

    fn ephemeral(&self) -> Result<&KeyPair, NoiseError> {
        self.e.as_ref().ok_or(NoiseError::OutOfTurn)
    }

    fn remote_ephemeral(&self) -> Result<&[u8; LEN], NoiseError> {
        self.re.as_ref().ok_or(NoiseError::OutOfTurn)
    }

    fn remote_static_key(&self) -> Result<&[u8; LEN], NoiseError> {
        self.rs.as_ref().ok_or(NoiseError::OutOfTurn)
    }

    fn mix_dh(&mut self, token: Token) -> Result<(), NoiseError> {
        // `es`: the initiator's ephemeral with the responder's static, and
        // so on; each side computes the same product from its half.
        let shared = match (token, self.initiator) {
            (Token::Ee, _) => self.ephemeral()?.dh(self.remote_ephemeral()?)?,
            (Token::Es, true) | (Token::Se, false) => {
                self.ephemeral()?.dh(self.remote_static_key()?)?
            }
            (Token::Es, false) | (Token::Se, true) => self.s.dh(self.remote_ephemeral()?)?,
            (Token::Ss, _) => self.s.dh(self.remote_static_key()?)?,
            (Token::E | Token::S, _) => unreachable!("not a DH token"),
        };
        self.symmetric.mix_key(&shared[..]);
        Ok(())
    }

    /// Writes the next message carrying `payload`. After an error the state
    /// is not usable any more and the handshake must be dropped.
    pub fn write_message(&mut self, payload: &[u8]) -> Result<Vec<u8>, NoiseError> {
        if !self.my_turn() {
            return Err(NoiseError::OutOfTurn);
        }
        let mut out = Vec::new();
        for &token in self.tokens()? {
            match token {
                Token::E => {
                    let e = match self.fixed_ephemeral.take() {
                        Some(private) => KeyPair::from_private(private),
                        None => KeyPair::generate(&SystemRandom::new())?,
                    };
                    out.extend_from_slice(&e.public());
                    self.symmetric.mix_hash(&e.public());
                    self.e = Some(e);
                }
                Token::S => {
                    let public = self.s.public();
                    let sealed = self.symmetric.encrypt_and_hash(&public)?;
                    out.extend_from_slice(&sealed);
                }
                dh => self.mix_dh(dh)?,
            }
        }
        out.extend_from_slice(&self.symmetric.encrypt_and_hash(payload)?);
        if out.len() > MAX_MESSAGE {
            return Err(NoiseError::TooLong);
        }
        self.message += 1;
        Ok(out)
    }

    /// Reads the next message and returns its payload.
    pub fn read_message(&mut self, message: &[u8]) -> Result<Vec<u8>, NoiseError> {
        if self.my_turn() {
            return Err(NoiseError::OutOfTurn);
        }
        if message.len() > MAX_MESSAGE {
            return Err(NoiseError::TooLong);
        }
        let mut rest = message;
        for &token in self.tokens()? {
            match token {
                Token::E => {
                    let (key, tail) = split_at(rest, LEN)?;
                    let key: [u8; LEN] = key.try_into().expect("split at LEN");
                    self.symmetric.mix_hash(&key);
                    self.re = Some(key);
                    rest = tail;
                }
                Token::S => {
                    let len = if self.symmetric.has_key() {
                        LEN + TAG_LEN
                    } else {
                        LEN
                    };
                    let (sealed, tail) = split_at(rest, len)?;
                    let key = self.symmetric.decrypt_and_hash(sealed)?;
                    self.rs = Some(key.as_slice().try_into().expect("LEN bytes"));
                    rest = tail;
                }
                dh => self.mix_dh(dh)?,
            }
        }
        if self.symmetric.has_key() && rest.len() < TAG_LEN {
            return Err(NoiseError::Truncated);
        }
        let payload = self.symmetric.decrypt_and_hash(rest)?;
        self.message += 1;
        Ok(payload)
    }

    /// The two transport ciphers, initiator-to-responder first (framework
    /// §5.2 `Split`). The secure mode does not use them (see the module
    /// documentation).
    pub fn split(&self) -> Result<(CipherState, CipherState), NoiseError> {
        if !self.is_finished() {
            return Err(NoiseError::OutOfTurn);
        }
        let (mut first, mut second) = hkdf2(&self.symmetric.chaining_key, &[]);
        let states = (
            CipherState {
                key: Some(first),
                n: 0,
            },
            CipherState {
                key: Some(second),
                n: 0,
            },
        );
        first.zeroize();
        second.zeroize();
        Ok(states)
    }
}

fn split_at(data: &[u8], at: usize) -> Result<(&[u8], &[u8]), NoiseError> {
    if data.len() < at {
        return Err(NoiseError::Truncated);
    }
    Ok(data.split_at(at))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unhex(text: &str) -> Vec<u8> {
        (0..text.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
            .collect()
    }

    fn key(text: &str) -> [u8; LEN] {
        unhex(text).try_into().unwrap()
    }

    // Public test vectors of the Noise framework.
    const PROLOGUE: &str = "4a6f686e2047616c74";
    const INIT_STATIC: &str = "e61ef9919cde45dd5f82166404bd08e38bceb5dfdfded0a34c8df7ed542214d1";
    const INIT_EPHEMERAL: &str = "893e28b9dc6ca8d611ab664754b8ceb7bac5117349a4439a6b0569da977c464a";
    const RESP_STATIC: &str = "4a3acbfdb163dec651dfa3194dece676d437029c62a408b4c5ea9114246e4893";
    const RESP_EPHEMERAL: &str = "bbdb4cdbd309f1a1f2e1456967fe288cadd6f712d65dc7b7793d5e63da6b375b";

    struct Vector {
        pattern: Pattern,
        handshake_hash: &'static str,
        messages: &'static [(&'static str, &'static str)],
    }

    const XX: Vector = Vector {
        pattern: Pattern::Xx,
        handshake_hash: "c8e5f64e846193be2a834104c2a009868d6c9f3bd3c186299888b488b2f1f58e",
        messages: &[
            (
                "4c756477696720766f6e204d69736573",
                "ca35def5ae56cec33dc2036731ab14896bc4c75dbb07a61f879f8e3afa4c79444c756477696720766f6e204d69736573",
            ),
            (
                "4d757272617920526f746862617264",
                "95ebc60d2b1fa672c1f46a8aa265ef51bfe38e7ccb39ec5be34069f14480884381cbad1f276e038c48378ffce2b65285e08d6b68aaa3629a5a8639392490e5b9bd5269c2f1e4f488ed8831161f19b7815528f8982ffe09be9b5c412f8a0db50f8814c7194e83f23dbd8d162c9326ad",
            ),
            (
                "462e20412e20486179656b",
                "c7195ffacac1307ff99046f219750fc47693e23c3cb08b89c2af808b444850a80ae475b9df0f169ae80a89be0865b57f58c9fea0d4ec82a286427402f113e4b6ae769a1d95941d49b25030",
            ),
            (
                "4361726c204d656e676572",
                "96763ed773f8e47bb3712f0e29b3060ffc956ffc146cee53d5e1df",
            ),
            (
                "4a65616e2d426170746973746520536179",
                "3e40f15f6f3a46ae446b253bf8b1d9ffb6ed9b174d272328ff91a7e2e5c79c07f5",
            ),
        ],
    };

    const IK: Vector = Vector {
        pattern: Pattern::Ik,
        handshake_hash: "0b0f68fb0c27e03ce9b97565995ed4838cc0581b762ef72b062f6a546419fad7",
        messages: &[
            (
                "4c756477696720766f6e204d69736573",
                "ca35def5ae56cec33dc2036731ab14896bc4c75dbb07a61f879f8e3afa4c7944718da798efbcd91528520204f904b9bd6c7413dccdc214d951e15253e39987f18146e8cd0873654207148333479d4d16c289f0294b29960a72f48e0b7bba2e89083169825e59642148d492020664ccf7",
            ),
            (
                "4d757272617920526f746862617264",
                "95ebc60d2b1fa672c1f46a8aa265ef51bfe38e7ccb39ec5be34069f1448088435361e70b2ed446e6c9ec387d1d6b3b840f194e373979d241b203c4acafccf5",
            ),
            (
                "462e20412e20486179656b",
                "050e9f3c8fac16b68dbce8f8c4bfbf6617c897f9ada4aa29aa19c8",
            ),
            (
                "4361726c204d656e676572",
                "344233a6cabb7141d80f3da2fedc311d9646bbb0f505afe403a667",
            ),
        ],
    };

    fn run(vector: &Vector) {
        let prologue = unhex(PROLOGUE);
        let init_static = KeyPair::from_private(key(INIT_STATIC));
        let resp_static = KeyPair::from_private(key(RESP_STATIC));
        let remote = (vector.pattern == Pattern::Ik).then(|| resp_static.public());
        let mut initiator =
            HandshakeState::new(vector.pattern, true, &prologue, init_static.clone(), remote)
                .unwrap()
                .with_ephemeral(key(INIT_EPHEMERAL));
        let mut responder =
            HandshakeState::new(vector.pattern, false, &prologue, resp_static.clone(), None)
                .unwrap()
                .with_ephemeral(key(RESP_EPHEMERAL));

        let handshake_len = vector.pattern.messages().len();
        let (mut to_responder, mut to_initiator) = (None, None);
        for (index, (payload, expected)) in vector.messages.iter().enumerate() {
            let payload = unhex(payload);
            let from_initiator = index.is_multiple_of(2);
            let (sent, received) = if index < handshake_len {
                let (writer, reader) = if from_initiator {
                    (&mut initiator, &mut responder)
                } else {
                    (&mut responder, &mut initiator)
                };
                let sent = writer.write_message(&payload).unwrap();
                let received = reader.read_message(&sent).unwrap();
                if index + 1 == handshake_len {
                    assert!(initiator.is_finished() && responder.is_finished());
                    assert_eq!(initiator.handshake_hash(), key(vector.handshake_hash));
                    assert_eq!(responder.handshake_hash(), key(vector.handshake_hash));
                    assert_eq!(responder.remote_static(), Some(init_static.public()));
                    assert_eq!(initiator.remote_static(), Some(resp_static.public()));
                    let (a, b) = initiator.split().unwrap();
                    let (c, d) = responder.split().unwrap();
                    to_responder = Some((a, c));
                    to_initiator = Some((d, b));
                }
                (sent, received)
            } else {
                let (send, receive) = if from_initiator {
                    to_responder.as_mut().unwrap()
                } else {
                    to_initiator.as_mut().unwrap()
                };
                let sent = send.encrypt(&[], &payload).unwrap();
                let received = receive.decrypt(&[], &sent).unwrap();
                (sent, received)
            };
            assert_eq!(sent, unhex(expected), "message {index}");
            assert_eq!(received, payload, "message {index}");
        }
    }

    #[test]
    fn xx_vector() {
        run(&XX);
    }

    #[test]
    fn ik_vector() {
        run(&IK);
    }

    #[test]
    fn rejects_tampering_and_turn_errors() {
        let mut initiator = HandshakeState::new(
            Pattern::Xx,
            true,
            b"p",
            KeyPair::from_private([1; LEN]),
            None,
        )
        .unwrap();
        let mut responder = HandshakeState::new(
            Pattern::Xx,
            false,
            b"p",
            KeyPair::from_private([2; LEN]),
            None,
        )
        .unwrap();
        assert_eq!(responder.write_message(b""), Err(NoiseError::OutOfTurn));
        let first = initiator.write_message(b"").unwrap();
        assert_eq!(
            responder.read_message(&first[..10]),
            Err(NoiseError::Truncated)
        );
        // A failed read leaves the responder unusable only for this attempt;
        // start again with a fresh state.
        let mut responder = HandshakeState::new(
            Pattern::Xx,
            false,
            b"p",
            KeyPair::from_private([2; LEN]),
            None,
        )
        .unwrap();
        responder.read_message(&first).unwrap();
        let mut second = responder.write_message(b"hello").unwrap();
        let last = second.len() - 1;
        second[last] ^= 1;
        assert_eq!(initiator.read_message(&second), Err(NoiseError::Decrypt));
    }

    #[test]
    fn different_prologues_do_not_agree() {
        let mut initiator = HandshakeState::new(
            Pattern::Xx,
            true,
            b"one",
            KeyPair::from_private([1; LEN]),
            None,
        )
        .unwrap();
        let mut responder = HandshakeState::new(
            Pattern::Xx,
            false,
            b"two",
            KeyPair::from_private([2; LEN]),
            None,
        )
        .unwrap();
        let first = initiator.write_message(b"").unwrap();
        responder.read_message(&first).unwrap();
        let second = responder.write_message(b"").unwrap();
        assert_eq!(initiator.read_message(&second), Err(NoiseError::Decrypt));
    }

    #[test]
    fn low_order_ephemeral_is_refused() {
        let mut responder = HandshakeState::new(
            Pattern::Xx,
            false,
            b"p",
            KeyPair::from_private([2; LEN]),
            None,
        )
        .unwrap();
        // An all-zero ephemeral key makes every DH result zero.
        responder.read_message(&[0; LEN]).unwrap();
        assert_eq!(responder.write_message(b""), Err(NoiseError::WeakKey));
    }
}
