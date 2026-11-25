//! Network digest and static keys of the default handshake mode (spec §6.3).
//!
//! H is SipHash-1-3 with both keys zero over an accumulated byte stream;
//! every value is encoded big-endian. These keys are shared by the whole
//! network and give no forward secrecy (spec §19.1).

/// Salt of the 256-bit key derivation (spec §2.3, `C_KEY256_SALT`).
const KEY256_SALT: [u8; 19] = [
    0x65, 0x61, 0x73, 0x79, 0x74, 0x69, 0x65, 0x72, 0x2d, 0x32, 0x35, 0x36, 0x62, 0x69, 0x74, 0x2d,
    0x6b, 0x65, 0x79,
];

/// SipHash-1-3 with `k0 = k1 = 0`.
pub fn siphash13(data: &[u8]) -> u64 {
    let mut v0: u64 = 0x736f_6d65_7073_6575;
    let mut v1: u64 = 0x646f_7261_6e64_6f6d;
    let mut v2: u64 = 0x6c79_6765_6e65_7261;
    let mut v3: u64 = 0x7465_6462_7974_6573;

    fn round(v0: &mut u64, v1: &mut u64, v2: &mut u64, v3: &mut u64) {
        *v0 = v0.wrapping_add(*v1);
        *v1 = v1.rotate_left(13);
        *v1 ^= *v0;
        *v0 = v0.rotate_left(32);
        *v2 = v2.wrapping_add(*v3);
        *v3 = v3.rotate_left(16);
        *v3 ^= *v2;
        *v0 = v0.wrapping_add(*v3);
        *v3 = v3.rotate_left(21);
        *v3 ^= *v0;
        *v2 = v2.wrapping_add(*v1);
        *v1 = v1.rotate_left(17);
        *v1 ^= *v2;
        *v2 = v2.rotate_left(32);
    }

    let (blocks, tail) = data.as_chunks::<8>();
    for chunk in blocks {
        let m = u64::from_le_bytes(*chunk);
        v3 ^= m;
        round(&mut v0, &mut v1, &mut v2, &mut v3);
        v0 ^= m;
    }
    let mut last = [0u8; 8];
    last[..tail.len()].copy_from_slice(tail);
    last[7] = data.len() as u8;
    let b = u64::from_le_bytes(last);
    v3 ^= b;
    round(&mut v0, &mut v1, &mut v2, &mut v3);
    v0 ^= b;
    v2 ^= 0xff;
    for _ in 0..3 {
        round(&mut v0, &mut v1, &mut v2, &mut v3);
    }
    v0 ^ v1 ^ v2 ^ v3
}

fn h(stream: &[u8]) -> [u8; 8] {
    siphash13(stream).to_be_bytes()
}

/// The 32-byte network digest sent in the default handshake.
pub fn digest(name: &[u8], secret: &[u8]) -> [u8; 32] {
    let mut stream = [name, secret].concat();
    let mut d = Vec::with_capacity(32);
    for _ in 0..4 {
        d.extend_from_slice(&h(&stream));
        stream.extend_from_slice(&d);
    }
    d.try_into().expect("four 8-byte values")
}

/// The 128-bit static key (AES-128-GCM).
pub fn key128(secret: &[u8]) -> [u8; 16] {
    let mut stream = secret.to_vec();
    let k0 = h(&stream);
    stream.extend_from_slice(&k0);
    let k1 = h(&stream);
    let mut key = [0u8; 16];
    key[..8].copy_from_slice(&k0);
    key[8..].copy_from_slice(&k1);
    key
}

/// The 256-bit static key (AES-256-GCM, ChaCha20-Poly1305).
pub fn key256(secret: &[u8]) -> [u8; 32] {
    let mut stream = [secret, &KEY256_SALT[..]].concat();
    let mut key = Vec::with_capacity(32);
    for i in 0..4u8 {
        stream.extend_from_slice(&key);
        stream.push(i);
        key.extend_from_slice(&h(&stream));
    }
    key.try_into().expect("four 8-byte values")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    // Spec §22.1.
    #[test]
    fn hash_vectors() {
        assert_eq!(hex(&h(b"")), "d1fba762150c532c");
        assert_eq!(hex(&h(b"abc")), "c03bc3a0042630f2");
    }

    #[test]
    fn digest_vectors() {
        assert_eq!(
            hex(&digest(b"net", b"secret")),
            "aa5d4c9d51dad76c940518e9cba13dd7ae5e01dafbc4bdbb678abeb24c34c164"
        );
        assert_eq!(
            hex(&digest(b"office", b"s3cr3t")),
            "46216cf51fc9235a13b385031e7b2212659ae8d7ffad2b8b9e44b28ee9e05356"
        );
    }

    #[test]
    fn key_vectors() {
        assert_eq!(hex(&key128(b"secret")), "565a19db4ef0c121a8ac580edaf84ea6");
        assert_eq!(hex(&key128(b"s3cr3t")), "72323a157966d67bc44bf57e062d3769");
        assert_eq!(hex(&key128(b"")), "d1fba762150c532c4cf426633e76377d");
        assert_eq!(
            hex(&key256(b"secret")),
            "c7cdf85ec265618a4f45a7f88c05a5a3c08ba6d9a6981ce6926d96c442f2e78c"
        );
        assert_eq!(
            hex(&key256(b"s3cr3t")),
            "fc6deeebaf3f0486ca9218187101a169f24382140d4c6ff0ae6ef7123351f5ce"
        );
    }

    #[test]
    fn siphash_covers_every_tail_length() {
        // Inputs of 0..=16 bytes exercise each remainder length and the
        // two-block path; distinct inputs must give distinct hashes.
        let data: Vec<u8> = (0u8..16).collect();
        let hashes: std::collections::HashSet<u64> =
            (0..=16).map(|n| siphash13(&data[..n])).collect();
        assert_eq!(hashes.len(), 17);
    }
}
