//! Payload encryption of the default handshake mode (spec §7): one static
//! key for the whole network, a random 12-byte nonce per packet, and the
//! tail `tag(16) ‖ nonce(12)` after the ciphertext. The node header is not
//! authenticated (spec §19.1).

use ring::aead::{self, Aad, LessSafeKey, Nonce, UnboundKey};
use ring::rand::{SecureRandom, SystemRandom};

use super::keys::{key128, key256};
use crate::config::Cipher;

pub const TAG_LEN: usize = 16;
pub const NONCE_LEN: usize = 12;
/// Bytes encryption adds to a payload.
pub const TAIL_LEN: usize = TAG_LEN + NONCE_LEN;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CipherError {
    /// Shorter than the tail.
    Truncated,
    /// Authentication failed: wrong key or cipher, or a tampered packet.
    Open,
    /// The system random source failed.
    Random,
}

/// The network's static traffic key.
pub struct LegacyCipher {
    key: LessSafeKey,
    rng: SystemRandom,
}

impl LegacyCipher {
    /// Derives the key of `cipher` from the network secret (spec §7.1);
    /// `None` for an unencrypted network.
    pub fn new(cipher: Cipher, secret: &[u8]) -> Option<Self> {
        let unbound = match cipher {
            Cipher::None => return None,
            Cipher::Aes128Gcm => UnboundKey::new(&aead::AES_128_GCM, &key128(secret)),
            Cipher::Aes256Gcm => UnboundKey::new(&aead::AES_256_GCM, &key256(secret)),
            Cipher::ChaCha20Poly1305 => UnboundKey::new(&aead::CHACHA20_POLY1305, &key256(secret)),
        }
        .expect("derived keys have the algorithm's length");
        Some(Self {
            key: LessSafeKey::new(unbound),
            rng: SystemRandom::new(),
        })
    }

    /// Encrypts `payload` in place and appends the tail, with a fresh random
    /// nonce.
    pub fn seal(&self, payload: &mut Vec<u8>) -> Result<(), CipherError> {
        let mut nonce = [0u8; NONCE_LEN];
        self.rng.fill(&mut nonce).map_err(|_| CipherError::Random)?;
        self.seal_with_nonce(payload, nonce);
        Ok(())
    }

    /// [`seal`](Self::seal) with a given nonce; for test vectors.
    pub fn seal_with_nonce(&self, payload: &mut Vec<u8>, nonce: [u8; NONCE_LEN]) {
        let tag = self
            .key
            .seal_in_place_separate_tag(Nonce::assume_unique_for_key(nonce), Aad::empty(), payload)
            .expect("payloads are far below the AEAD length limit");
        payload.extend_from_slice(tag.as_ref());
        payload.extend_from_slice(&nonce);
    }

    /// Decrypts a sealed payload in place, removing the tail.
    pub fn open(&self, payload: &mut Vec<u8>) -> Result<(), CipherError> {
        if payload.len() < TAIL_LEN {
            return Err(CipherError::Truncated);
        }
        let nonce_at = payload.len() - NONCE_LEN;
        let nonce: [u8; NONCE_LEN] = payload[nonce_at..].try_into().unwrap();
        payload.truncate(nonce_at);
        let plain_len = self
            .key
            .open_in_place(Nonce::assume_unique_for_key(nonce), Aad::empty(), payload)
            .map_err(|_| CipherError::Open)?
            .len();
        payload.truncate(plain_len);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::{flags, packet_type, tcp, NodeHeader};

    fn unhex(text: &str) -> Vec<u8> {
        let text: String = text.split_whitespace().collect();
        (0..text.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
            .collect()
    }

    const ICMP: &str = "4500001c000040004001b6ce0a7e00010a7e00020800f7ff00000000";

    // Spec §22.4: the whole TCP frame of one encrypted Data packet.
    #[test]
    fn tcp_frame_vector() {
        let cipher = LegacyCipher::new(Cipher::Aes128Gcm, b"s3cr3t").unwrap();
        let plain = unhex(ICMP);
        let mut payload = plain.clone();
        let nonce: [u8; 12] = (0u8..12).collect::<Vec<_>>().try_into().unwrap();
        cipher.seal_with_nonce(&mut payload, nonce);

        let mut header = NodeHeader::new(
            0x1111_1111,
            0x2222_2222,
            packet_type::DATA,
            plain.len() as u32,
        );
        header.flags = flags::ENCRYPTED;
        let mut packet = header.encode().to_vec();
        packet.extend_from_slice(&payload);
        let frame = tcp::encode_frame(&packet).unwrap();
        assert_eq!(
            frame,
            unhex(
                "48000000 11111111 22222222 01 01 01 00 1c000000
                 8f11d274277e07d7d37cb801434cd6673c917c6995d6794a9742afb5
                 597512edfec12a676eb1d45965271def
                 000102030405060708090a0b"
            )
        );

        cipher.open(&mut payload).unwrap();
        assert_eq!(payload, plain);
    }

    #[test]
    fn every_cipher_round_trips_with_random_nonces() {
        for kind in [
            Cipher::Aes128Gcm,
            Cipher::Aes256Gcm,
            Cipher::ChaCha20Poly1305,
        ] {
            let cipher = LegacyCipher::new(kind, b"secret").unwrap();
            let mut a = b"hello mesh".to_vec();
            let mut b = a.clone();
            cipher.seal(&mut a).unwrap();
            cipher.seal(&mut b).unwrap();
            assert_eq!(a.len(), 10 + TAIL_LEN);
            assert_ne!(a, b, "{kind:?} nonces must differ");
            cipher.open(&mut a).unwrap();
            assert_eq!(a, b"hello mesh");
        }
    }

    #[test]
    fn wrong_key_cipher_or_tampering_fails() {
        let cipher = LegacyCipher::new(Cipher::Aes128Gcm, b"secret").unwrap();
        let mut sealed = b"payload".to_vec();
        cipher.seal(&mut sealed).unwrap();

        let mut other = sealed.clone();
        assert_eq!(
            LegacyCipher::new(Cipher::Aes128Gcm, b"other")
                .unwrap()
                .open(&mut other),
            Err(CipherError::Open)
        );
        let mut other = sealed.clone();
        assert_eq!(
            LegacyCipher::new(Cipher::Aes256Gcm, b"secret")
                .unwrap()
                .open(&mut other),
            Err(CipherError::Open)
        );
        let mut tampered = sealed.clone();
        tampered[0] ^= 1;
        assert_eq!(cipher.open(&mut tampered), Err(CipherError::Open));
        let mut short = vec![0u8; TAIL_LEN - 1];
        assert_eq!(cipher.open(&mut short), Err(CipherError::Truncated));
        assert!(LegacyCipher::new(Cipher::None, b"secret").is_none());
        // An empty payload still carries a tag.
        let mut empty = Vec::new();
        cipher.seal(&mut empty).unwrap();
        cipher.open(&mut empty).unwrap();
        assert!(empty.is_empty());
    }
}
