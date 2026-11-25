//! The default handshake (spec §6.1, §6.2, §6.4): one message each way,
//! carried in a node packet of type 2 with `to = 0`, never encrypted.

use crate::wire::pb::{PbError, Reader, Writer};

/// `C_HS_MAGIC` (spec §2.3).
pub const MAGIC: u32 = 0xD1E1_A5E1;
pub const VERSION: u32 = 1;
pub const DIGEST_LEN: usize = 32;
/// Prefix 2.7.x servers put before their own name when the client asked for
/// another network (spec §2.3 `C_FOREIGN_PREFIX`, §6.2).
pub const FOREIGN_PREFIX: [u8; 3] = [0x66, 0x67, 0x2d];

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HandshakeMessage {
    pub peer_id: u32,
    pub network_name: String,
    /// All zero from a server that does not share the client's secret, and
    /// from credential nodes (spec §6.4).
    pub digest: [u8; DIGEST_LEN],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HandshakeError {
    Decode(PbError),
    BadMagic,
    BadVersion,
    BadDigest,
}

impl From<PbError> for HandshakeError {
    fn from(error: PbError) -> Self {
        HandshakeError::Decode(error)
    }
}

impl HandshakeMessage {
    /// Encodes with an empty feature list, which every version accepts.
    pub fn encode(&self) -> Vec<u8> {
        let mut writer = Writer::new();
        writer
            .u32(1, MAGIC)
            .u32(2, self.peer_id)
            .u32(3, VERSION)
            .str(5, &self.network_name)
            .bytes(6, &self.digest);
        writer.finish()
    }

    /// Decodes and checks magic, version and digest length; features and
    /// unknown fields are ignored.
    pub fn decode(message: &[u8]) -> Result<Self, HandshakeError> {
        let mut magic = 0;
        let mut version = 0;
        let mut peer_id = 0;
        let mut network_name = String::new();
        let mut digest: Option<&[u8]> = None;
        let mut reader = Reader::new(message);
        while let Some((field, value)) = reader.next()? {
            match field {
                1 => magic = value.u32(field)?,
                2 => peer_id = value.u32(field)?,
                3 => version = value.u32(field)?,
                4 => {
                    value.str(field)?;
                }
                5 => network_name = value.str(field)?.to_owned(),
                6 => digest = Some(value.bytes(field)?),
                _ => {}
            }
        }
        if magic != MAGIC {
            return Err(HandshakeError::BadMagic);
        }
        if version != VERSION {
            return Err(HandshakeError::BadVersion);
        }
        // An absent field is an empty one, which is not 32 bytes either.
        let digest: [u8; DIGEST_LEN] = digest
            .unwrap_or_default()
            .try_into()
            .map_err(|_| HandshakeError::BadDigest)?;
        Ok(Self {
            peer_id,
            network_name,
            digest,
        })
    }

    pub fn has_zero_digest(&self) -> bool {
        self.digest == [0; DIGEST_LEN]
    }
}

/// The server's answer to a client handshake (spec §6.2) for a node that is
/// not a shared node: same name gets this network's name and, when the
/// digests match, this network's digest; another name gets this node's own
/// name and a zero digest.
pub fn server_reply(
    client: &HandshakeMessage,
    own_peer_id: u32,
    own_name: &str,
    own_digest: &[u8; DIGEST_LEN],
) -> HandshakeMessage {
    let digest = if client.network_name == own_name && digests_equal(&client.digest, own_digest) {
        *own_digest
    } else {
        [0; DIGEST_LEN]
    };
    HandshakeMessage {
        peer_id: own_peer_id,
        network_name: own_name.to_owned(),
        digest,
    }
}

/// Same-network test (spec §6.4): equal names, and equal digests or either
/// one all zero (a credential node).
pub fn same_network(
    own_name: &str,
    own_digest: &[u8; DIGEST_LEN],
    peer: &HandshakeMessage,
) -> bool {
    peer.network_name == own_name
        && (digests_equal(&peer.digest, own_digest)
            || peer.has_zero_digest()
            || own_digest == &[0; DIGEST_LEN])
}

/// Compares two digests in time independent of where they differ, so a
/// peer cannot learn a digest byte by byte from response timing.
pub fn digests_equal(a: &[u8; DIGEST_LEN], b: &[u8; DIGEST_LEN]) -> bool {
    let difference = a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y));
    std::hint::black_box(difference) == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::legacy::keys::digest;

    fn message(name: &str, secret: &str) -> HandshakeMessage {
        HandshakeMessage {
            peer_id: 0xdead_beef,
            network_name: name.into(),
            digest: digest(name.as_bytes(), secret.as_bytes()),
        }
    }

    #[test]
    fn round_trips_and_starts_with_magic() {
        let hello = message("office", "s3cr3t");
        let bytes = hello.encode();
        // Field 1 varint 0xD1E1A5E1.
        assert_eq!(&bytes[..6], &[0x08, 0xe1, 0xcb, 0x86, 0x8f, 0x0d]);
        assert_eq!(HandshakeMessage::decode(&bytes).unwrap(), hello);
    }

    #[test]
    fn ignores_features_and_unknown_fields() {
        let hello = message("office", "s3cr3t");
        let mut bytes = hello.encode();
        let mut extra = Writer::new();
        extra.opt_bytes(4, b"some-feature").u32(99, 7);
        bytes.extend_from_slice(&extra.finish());
        assert_eq!(HandshakeMessage::decode(&bytes).unwrap(), hello);
    }

    #[test]
    fn rejects_bad_magic_version_or_digest() {
        let encode = |magic: u32, version: u32, digest: &[u8]| {
            let mut writer = Writer::new();
            writer
                .u32(1, magic)
                .u32(2, 1)
                .u32(3, version)
                .str(5, "n")
                .bytes(6, digest);
            writer.finish()
        };
        assert_eq!(
            HandshakeMessage::decode(&encode(1, 1, &[1; 32])),
            Err(HandshakeError::BadMagic)
        );
        assert_eq!(
            HandshakeMessage::decode(&encode(MAGIC, 2, &[1; 32])),
            Err(HandshakeError::BadVersion)
        );
        assert_eq!(
            HandshakeMessage::decode(&encode(MAGIC, 1, &[1; 31])),
            Err(HandshakeError::BadDigest)
        );
        assert_eq!(
            HandshakeMessage::decode(&encode(MAGIC, 1, &[])),
            Err(HandshakeError::BadDigest)
        );
        assert!(matches!(
            HandshakeMessage::decode(&[0x0a, 9]),
            Err(HandshakeError::Decode(_))
        ));
    }

    #[test]
    fn server_reply_follows_spec() {
        let own = message("office", "s3cr3t");
        // Same network, right secret.
        let reply = server_reply(&message("office", "s3cr3t"), 7, "office", &own.digest);
        assert_eq!(reply.digest, own.digest);
        assert_eq!(reply.peer_id, 7);
        // Same name, wrong secret.
        let reply = server_reply(&message("office", "nope"), 7, "office", &own.digest);
        assert!(reply.has_zero_digest());
        assert_eq!(reply.network_name, "office");
        // Another network: own name, zero digest.
        let reply = server_reply(&message("lab", "s3cr3t"), 7, "office", &own.digest);
        assert_eq!(reply.network_name, "office");
        assert!(reply.has_zero_digest());
    }

    #[test]
    fn same_network_test() {
        let own = message("office", "s3cr3t");
        assert!(same_network(
            "office",
            &own.digest,
            &message("office", "s3cr3t")
        ));
        assert!(!same_network(
            "office",
            &own.digest,
            &message("office", "nope")
        ));
        assert!(!same_network(
            "office",
            &own.digest,
            &message("lab", "s3cr3t")
        ));
        let mut credential = message("office", "x");
        credential.digest = [0; 32];
        assert!(same_network("office", &own.digest, &credential));
        // A 2.7.x foreign echo name never matches.
        let mut foreign = message("office", "s3cr3t");
        foreign.network_name = format!("{}office", std::str::from_utf8(&FOREIGN_PREFIX).unwrap());
        assert!(!same_network("office", &own.digest, &foreign));
    }
}
