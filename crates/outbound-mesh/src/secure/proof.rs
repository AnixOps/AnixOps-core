//! Proof of the network secret inside the secure handshake (spec §8.2):
//! `HMAC-SHA256(key = secret, PROOF_PREFIX ‖ challenge)`, where the
//! challenge is the Noise handshake hash at the message boundary.

use ring::hmac;

use super::PROOF_PREFIX;

pub const PROOF_LEN: usize = 32;

pub fn proof(secret: &[u8], challenge: &[u8]) -> [u8; PROOF_LEN] {
    let key = hmac::Key::new(hmac::HMAC_SHA256, secret);
    let mut context = hmac::Context::with_key(&key);
    context.update(&PROOF_PREFIX);
    context.update(challenge);
    context.sign().as_ref().try_into().expect("SHA-256 output")
}

/// Checks a received proof in constant time.
pub fn verify(secret: &[u8], challenge: &[u8], received: &[u8]) -> bool {
    let key = hmac::Key::new(hmac::HMAC_SHA256, secret);
    let message = [&PROOF_PREFIX[..], challenge].concat();
    hmac::verify(&key, &message, received).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    // Spec §22.2.
    #[test]
    fn proof_vector() {
        let challenge: Vec<u8> = (0u8..32).collect();
        let proof = proof(b"s3cr3t", &challenge);
        assert_eq!(
            hex(&proof),
            "2049f9321cb5b020cfb16623e1b81fb576b8fde5dc1e507a34dea6cabda3011b"
        );
        assert!(verify(b"s3cr3t", &challenge, &proof));
        assert!(!verify(b"other", &challenge, &proof));
        assert!(!verify(b"s3cr3t", &challenge[1..], &proof));
        assert!(!verify(b"s3cr3t", &challenge, &proof[..31]));
    }
}
