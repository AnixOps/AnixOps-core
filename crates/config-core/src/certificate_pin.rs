//! SHA-256 certificate pins as subscriptions spell them.
//!
//! A pin is the SHA-256 digest of the server's leaf certificate (DER) or of
//! that certificate's SubjectPublicKeyInfo (DER). Formats write it in hex,
//! upper or lower case, sometimes with `:` or `-` between the bytes (as
//! OpenSSL prints fingerprints), or in base64. The two spellings never
//! collide: 64 hex digits decode as base64 to 48 bytes, not 32.

use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
use base64::Engine as _;

/// A SHA-256 digest.
pub type Sha256Digest = [u8; 32];

/// `text` as 64 hex digits, optionally with `:` or `-` between them.
pub fn parse_hex(text: &str) -> Option<Sha256Digest> {
    let digits: Vec<u8> = text
        .trim()
        .bytes()
        .filter(|byte| !matches!(byte, b':' | b'-'))
        .collect();
    if digits.len() != 64 {
        return None;
    }
    let mut digest = [0u8; 32];
    let (pairs, _) = digits.as_chunks::<2>();
    for (byte, [high, low]) in digest.iter_mut().zip(pairs) {
        let high = char::from(*high).to_digit(16)?;
        let low = char::from(*low).to_digit(16)?;
        *byte = ((high << 4) | low) as u8;
    }
    Some(digest)
}

/// `text` as base64 (standard or URL-safe, with or without padding).
pub fn parse_base64(text: &str) -> Option<Sha256Digest> {
    let text = text.trim().as_bytes();
    let bytes = STANDARD
        .decode(text)
        .or_else(|_| STANDARD_NO_PAD.decode(text))
        .or_else(|_| URL_SAFE.decode(text))
        .or_else(|_| URL_SAFE_NO_PAD.decode(text))
        .ok()?;
    bytes.try_into().ok()
}

/// `text` in either spelling.
pub fn parse(text: &str) -> Option<Sha256Digest> {
    parse_hex(text).or_else(|| parse_base64(text))
}

/// Lowercase hex without separators.
pub fn to_hex(digest: &Sha256Digest) -> String {
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Standard base64 with padding.
pub fn to_base64(digest: &Sha256Digest) -> String {
    STANDARD.encode(digest)
}

#[cfg(test)]
mod tests {
    use super::*;

    const HEX: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    #[test]
    fn hex_takes_either_case_and_byte_separators() {
        let digest = parse_hex(HEX).unwrap();
        assert_eq!(digest[0], 0x01);
        assert_eq!(digest[31], 0xef);
        assert_eq!(to_hex(&digest), HEX);
        let colons = HEX
            .to_ascii_uppercase()
            .as_bytes()
            .chunks(2)
            .map(|pair| std::str::from_utf8(pair).unwrap())
            .collect::<Vec<_>>()
            .join(":");
        assert_eq!(parse_hex(&colons), Some(digest));
        assert_eq!(parse_hex(&colons.replace(':', "-")), Some(digest));
        assert_eq!(parse_hex(&format!(" {HEX} ")), Some(digest));
        assert_eq!(parse_hex(&HEX[..62]), None);
        assert_eq!(parse_hex(&format!("{HEX}00")), None);
        assert_eq!(parse_hex(&HEX.replace('a', "g")), None);
    }

    #[test]
    fn base64_takes_both_alphabets_with_or_without_padding() {
        let digest = parse_hex(HEX).unwrap();
        let standard = to_base64(&digest);
        assert_eq!(standard.len(), 44);
        assert_eq!(parse_base64(&standard), Some(digest));
        assert_eq!(parse_base64(standard.trim_end_matches('=')), Some(digest));
        let url_safe = URL_SAFE_NO_PAD.encode([0xfb; 32]);
        assert_eq!(parse_base64(&url_safe), Some([0xfb; 32]));
        // Right alphabet, wrong length.
        assert_eq!(parse_base64("AAAA"), None);
        assert_eq!(parse_base64("pin-A"), None);
    }

    #[test]
    fn spellings_never_collide() {
        let digest = parse_hex(HEX).unwrap();
        // 64 hex digits are valid base64, but of 48 bytes.
        assert_eq!(parse_base64(HEX), None);
        assert_eq!(parse_hex(&to_base64(&digest)), None);
        assert_eq!(parse(HEX), Some(digest));
        assert_eq!(parse(&to_base64(&digest)), Some(digest));
        assert_eq!(parse("not a digest"), None);
    }
}
