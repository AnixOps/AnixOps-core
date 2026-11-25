//! The protobuf payloads of the secure handshake (spec §8.1) and of the
//! relay handshake (spec §9). They travel inside Noise messages; this module
//! only encodes and decodes them.

use crate::config::Cipher;
use crate::route::messages::Uuid;
use crate::wire::pb::{PbError, Reader, Writer};

use super::proof::PROOF_LEN;
use super::traffic::ROOT_KEY_LEN;

/// `version` of msg1 and relay msg1.
pub const VERSION: u32 = 1;
/// Most `features` entries read from a peer; this node sends none.
pub const MAX_FEATURES: usize = 64;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MessageError {
    Decode(PbError),
    BadVersion,
    /// A cipher name this node does not know, or one the secure mode cannot
    /// use (`none`, `xor`).
    BadCipher,
    /// `root_key` or `secret_proof` is not 32 bytes, or `secret_digest`
    /// is neither empty nor 32 bytes.
    BadLength,
    /// `root_key` is missing for Create or Sync, or present for Join.
    RootKeyMismatch,
    /// `action` or `role_hint` has a value outside the table.
    BadEnum,
}

impl From<PbError> for MessageError {
    fn from(error: PbError) -> Self {
        MessageError::Decode(error)
    }
}

/// What the server did with the session (spec §8.4).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    Join,
    Sync,
    Create,
}

impl Action {
    fn code(self) -> u32 {
        match self {
            Action::Join => 0,
            Action::Sync => 1,
            Action::Create => 2,
        }
    }

    fn from_code(code: u32) -> Result<Self, MessageError> {
        match code {
            0 => Ok(Action::Join),
            1 => Ok(Action::Sync),
            2 => Ok(Action::Create),
            _ => Err(MessageError::BadEnum),
        }
    }

    /// Whether msg2 carries the root key with this action.
    pub fn carries_root_key(self) -> bool {
        !matches!(self, Action::Join)
    }
}

/// `role_hint` of msg2.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RoleHint {
    SameNetwork,
    Other,
}

impl RoleHint {
    fn code(self) -> u32 {
        match self {
            RoleHint::SameNetwork => 1,
            RoleHint::Other => 2,
        }
    }

    fn from_code(code: u32) -> Result<Self, MessageError> {
        match code {
            1 => Ok(RoleHint::SameNetwork),
            2 => Ok(RoleHint::Other),
            _ => Err(MessageError::BadEnum),
        }
    }
}

/// The wire name of a cipher (spec §7.1). `None` for those the secure mode
/// cannot use.
pub fn cipher_name(cipher: Cipher) -> Option<&'static str> {
    match cipher {
        Cipher::Aes128Gcm => Some("aes-gcm"),
        Cipher::Aes256Gcm => Some("aes-256-gcm"),
        Cipher::ChaCha20Poly1305 => Some("chacha20"),
        Cipher::None | Cipher::Xor => None,
    }
}

/// Parses a cipher name announced by a peer: only the names of the table
/// of spec §7.1. Unknown names are refused rather than guessed.
pub fn parse_cipher(name: &str) -> Result<Cipher, MessageError> {
    match name {
        "aes-gcm" => Ok(Cipher::Aes128Gcm),
        "aes-256-gcm" => Ok(Cipher::Aes256Gcm),
        "chacha20" | "chacha20-poly1305" => Ok(Cipher::ChaCha20Poly1305),
        _ => Err(MessageError::BadCipher),
    }
}

fn write_cipher(writer: &mut Writer, field: u32, cipher: Cipher) -> Result<(), MessageError> {
    writer.str(field, cipher_name(cipher).ok_or(MessageError::BadCipher)?);
    Ok(())
}

fn fixed<const N: usize>(bytes: &[u8]) -> Result<[u8; N], MessageError> {
    bytes.try_into().map_err(|_| MessageError::BadLength)
}

fn uuid(writer: &mut Writer, field: u32, id: &Uuid) {
    writer.message(field, &id.encode());
}

/// Counts `features` entries without keeping them.
fn feature(count: &mut usize, field: u32) -> Result<(), MessageError> {
    *count += 1;
    if *count > MAX_FEATURES {
        return Err(PbError::TooMany(field).into());
    }
    Ok(())
}

/// msg1, client to server, packet type 13. Its Noise payload is plaintext.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Msg1 {
    pub network_name: String,
    pub session_generation: Option<u32>,
    pub conn_id: Uuid,
    /// The cipher the client sends with.
    pub cipher: Cipher,
}

impl Msg1 {
    pub fn encode(&self) -> Result<Vec<u8>, MessageError> {
        let mut writer = Writer::new();
        writer.u32(1, VERSION).str(2, &self.network_name);
        if let Some(generation) = self.session_generation {
            writer.opt_u32(3, generation);
        }
        uuid(&mut writer, 4, &self.conn_id);
        write_cipher(&mut writer, 5, self.cipher)?;
        Ok(writer.finish())
    }

    pub fn decode(message: &[u8]) -> Result<Self, MessageError> {
        let mut version = 0;
        let mut network_name = String::new();
        let mut session_generation = None;
        let mut conn_id = Uuid::default();
        let mut cipher = "";
        let mut features = 0;
        let mut reader = Reader::new(message);
        while let Some((field, value)) = reader.next()? {
            match field {
                1 => version = value.u32(field)?,
                2 => network_name = value.str(field)?.to_owned(),
                3 => session_generation = Some(value.u32(field)?),
                4 => conn_id = Uuid::decode(value.bytes(field)?)?,
                5 => cipher = value.str(field)?,
                6 => {
                    value.str(field)?;
                    feature(&mut features, field)?;
                }
                _ => {}
            }
        }
        if version != VERSION {
            return Err(MessageError::BadVersion);
        }
        Ok(Self {
            network_name,
            session_generation,
            conn_id,
            cipher: parse_cipher(cipher)?,
        })
    }
}

/// msg2, server to client, packet type 14.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Msg2 {
    pub network_name: String,
    pub role_hint: RoleHint,
    pub action: Action,
    pub session_generation: u32,
    /// Present exactly for Create and Sync.
    pub root_key: Option<[u8; ROOT_KEY_LEN]>,
    pub initial_epoch: u32,
    pub conn_id: Uuid,
    pub peer_conn_id_echo: Uuid,
    pub secret_proof: Option<[u8; PROOF_LEN]>,
    /// The cipher the server sends with.
    pub cipher: Cipher,
}

impl Msg2 {
    pub fn encode(&self) -> Result<Vec<u8>, MessageError> {
        if self.root_key.is_some() != self.action.carries_root_key() {
            return Err(MessageError::RootKeyMismatch);
        }
        let mut writer = Writer::new();
        writer
            .str(1, &self.network_name)
            .u32(2, self.role_hint.code())
            .u32(3, self.action.code())
            .u32(4, self.session_generation);
        if let Some(root_key) = &self.root_key {
            writer.opt_bytes(5, root_key);
        }
        writer.u32(6, self.initial_epoch);
        uuid(&mut writer, 7, &self.conn_id);
        uuid(&mut writer, 8, &self.peer_conn_id_echo);
        if let Some(proof) = &self.secret_proof {
            writer.opt_bytes(9, proof);
        }
        write_cipher(&mut writer, 10, self.cipher)?;
        Ok(writer.finish())
    }

    pub fn decode(message: &[u8]) -> Result<Self, MessageError> {
        let mut network_name = String::new();
        let mut role_hint = 0;
        let mut action = 0;
        let mut session_generation = 0;
        let mut root_key = None;
        let mut initial_epoch = 0;
        let mut conn_id = Uuid::default();
        let mut peer_conn_id_echo = Uuid::default();
        let mut secret_proof = None;
        let mut cipher = "";
        let mut features = 0;
        let mut reader = Reader::new(message);
        while let Some((field, value)) = reader.next()? {
            match field {
                1 => network_name = value.str(field)?.to_owned(),
                2 => role_hint = value.u32(field)?,
                3 => action = value.u32(field)?,
                4 => session_generation = value.u32(field)?,
                5 => root_key = Some(fixed(value.bytes(field)?)?),
                6 => initial_epoch = value.u32(field)?,
                7 => conn_id = Uuid::decode(value.bytes(field)?)?,
                8 => peer_conn_id_echo = Uuid::decode(value.bytes(field)?)?,
                9 => secret_proof = Some(fixed(value.bytes(field)?)?),
                10 => cipher = value.str(field)?,
                11 => {
                    value.str(field)?;
                    feature(&mut features, field)?;
                }
                _ => {}
            }
        }
        let action = Action::from_code(action)?;
        if root_key.is_some() != action.carries_root_key() {
            return Err(MessageError::RootKeyMismatch);
        }
        Ok(Self {
            network_name,
            role_hint: RoleHint::from_code(role_hint)?,
            action,
            session_generation,
            root_key,
            initial_epoch,
            conn_id,
            peer_conn_id_echo,
            secret_proof,
            cipher: parse_cipher(cipher)?,
        })
    }
}

/// msg3, client to server, packet type 15.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Msg3 {
    pub client_conn_id_echo: Uuid,
    pub server_conn_id_echo: Uuid,
    pub secret_proof: Option<[u8; PROOF_LEN]>,
    /// The network digest (spec §6.3), or `None` without a secret.
    pub secret_digest: Option<[u8; 32]>,
}

impl Msg3 {
    pub fn encode(&self) -> Vec<u8> {
        let mut writer = Writer::new();
        uuid(&mut writer, 1, &self.client_conn_id_echo);
        uuid(&mut writer, 2, &self.server_conn_id_echo);
        if let Some(proof) = &self.secret_proof {
            writer.opt_bytes(3, proof);
        }
        if let Some(digest) = &self.secret_digest {
            writer.bytes(4, digest);
        }
        writer.finish()
    }

    pub fn decode(message: &[u8]) -> Result<Self, MessageError> {
        let mut client_conn_id_echo = Uuid::default();
        let mut server_conn_id_echo = Uuid::default();
        let mut secret_proof = None;
        let mut secret_digest = None;
        let mut reader = Reader::new(message);
        while let Some((field, value)) = reader.next()? {
            match field {
                1 => client_conn_id_echo = Uuid::decode(value.bytes(field)?)?,
                2 => server_conn_id_echo = Uuid::decode(value.bytes(field)?)?,
                3 => secret_proof = Some(fixed(value.bytes(field)?)?),
                4 => {
                    let digest = value.bytes(field)?;
                    secret_digest = if digest.is_empty() {
                        None
                    } else {
                        Some(fixed(digest)?)
                    };
                }
                _ => {}
            }
        }
        Ok(Self {
            client_conn_id_echo,
            server_conn_id_echo,
            secret_proof,
            secret_digest,
        })
    }
}

/// Relay msg1, packet type 20 (spec §9).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RelayMsg1 {
    pub session_generation: Option<u32>,
    pub conn_id: Uuid,
    pub cipher: Cipher,
}

impl RelayMsg1 {
    pub fn encode(&self) -> Result<Vec<u8>, MessageError> {
        let mut writer = Writer::new();
        writer.u32(1, VERSION);
        if let Some(generation) = self.session_generation {
            writer.opt_u32(3, generation);
        }
        uuid(&mut writer, 4, &self.conn_id);
        write_cipher(&mut writer, 5, self.cipher)?;
        Ok(writer.finish())
    }

    pub fn decode(message: &[u8]) -> Result<Self, MessageError> {
        let mut version = 0;
        let mut session_generation = None;
        let mut conn_id = Uuid::default();
        let mut cipher = "";
        let mut reader = Reader::new(message);
        while let Some((field, value)) = reader.next()? {
            match field {
                1 => version = value.u32(field)?,
                3 => session_generation = Some(value.u32(field)?),
                4 => conn_id = Uuid::decode(value.bytes(field)?)?,
                5 => cipher = value.str(field)?,
                _ => {}
            }
        }
        if version != VERSION {
            return Err(MessageError::BadVersion);
        }
        Ok(Self {
            session_generation,
            conn_id,
            cipher: parse_cipher(cipher)?,
        })
    }
}

/// Relay msg2, packet type 21 (spec §9).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RelayMsg2 {
    pub action: Action,
    pub session_generation: u32,
    pub root_key: Option<[u8; ROOT_KEY_LEN]>,
    pub initial_epoch: u32,
    pub conn_id: Uuid,
    pub peer_conn_id_echo: Uuid,
    pub cipher: Cipher,
}

impl RelayMsg2 {
    pub fn encode(&self) -> Result<Vec<u8>, MessageError> {
        if self.root_key.is_some() != self.action.carries_root_key() {
            return Err(MessageError::RootKeyMismatch);
        }
        let mut writer = Writer::new();
        writer
            .u32(3, self.action.code())
            .u32(4, self.session_generation);
        if let Some(root_key) = &self.root_key {
            writer.opt_bytes(5, root_key);
        }
        writer.u32(6, self.initial_epoch);
        uuid(&mut writer, 7, &self.conn_id);
        uuid(&mut writer, 8, &self.peer_conn_id_echo);
        write_cipher(&mut writer, 10, self.cipher)?;
        Ok(writer.finish())
    }

    pub fn decode(message: &[u8]) -> Result<Self, MessageError> {
        let mut action = 0;
        let mut session_generation = 0;
        let mut root_key = None;
        let mut initial_epoch = 0;
        let mut conn_id = Uuid::default();
        let mut peer_conn_id_echo = Uuid::default();
        let mut cipher = "";
        let mut reader = Reader::new(message);
        while let Some((field, value)) = reader.next()? {
            match field {
                3 => action = value.u32(field)?,
                4 => session_generation = value.u32(field)?,
                5 => root_key = Some(fixed(value.bytes(field)?)?),
                6 => initial_epoch = value.u32(field)?,
                7 => conn_id = Uuid::decode(value.bytes(field)?)?,
                8 => peer_conn_id_echo = Uuid::decode(value.bytes(field)?)?,
                10 => cipher = value.str(field)?,
                _ => {}
            }
        }
        let action = Action::from_code(action)?;
        if root_key.is_some() != action.carries_root_key() {
            return Err(MessageError::RootKeyMismatch);
        }
        Ok(Self {
            action,
            session_generation,
            root_key,
            initial_epoch,
            conn_id,
            peer_conn_id_echo,
            cipher: parse_cipher(cipher)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(byte: u8) -> Uuid {
        Uuid([byte; 16])
    }

    #[test]
    fn msg1_round_trips_and_checks_version_and_cipher() {
        let msg = Msg1 {
            network_name: "office".into(),
            session_generation: Some(0),
            conn_id: id(1),
            cipher: Cipher::ChaCha20Poly1305,
        };
        let encoded = msg.encode().unwrap();
        assert_eq!(Msg1::decode(&encoded).unwrap(), msg);
        let fresh = Msg1 {
            session_generation: None,
            ..msg.clone()
        };
        assert_eq!(Msg1::decode(&fresh.encode().unwrap()).unwrap(), fresh);

        let mut writer = Writer::new();
        writer.u32(1, 2).str(5, "aes-gcm");
        assert_eq!(
            Msg1::decode(&writer.finish()),
            Err(MessageError::BadVersion)
        );
        let mut writer = Writer::new();
        writer.u32(1, 1).str(5, "xor");
        assert_eq!(Msg1::decode(&writer.finish()), Err(MessageError::BadCipher));
        let none = Msg1 {
            cipher: Cipher::None,
            ..msg
        };
        assert_eq!(none.encode(), Err(MessageError::BadCipher));
    }

    #[test]
    fn cipher_names_are_those_of_the_table() {
        assert_eq!(parse_cipher("aes-gcm"), Ok(Cipher::Aes128Gcm));
        assert_eq!(parse_cipher("aes-256-gcm"), Ok(Cipher::Aes256Gcm));
        assert_eq!(parse_cipher("chacha20"), Ok(Cipher::ChaCha20Poly1305));
        assert_eq!(
            parse_cipher("chacha20-poly1305"),
            Ok(Cipher::ChaCha20Poly1305)
        );
        for name in ["", "none", "xor", "openssl-aes-gcm"] {
            assert_eq!(parse_cipher(name), Err(MessageError::BadCipher), "{name}");
        }
    }

    #[test]
    fn features_are_skipped_but_bounded() {
        let msg = Msg1 {
            network_name: "office".into(),
            session_generation: None,
            conn_id: id(1),
            cipher: Cipher::Aes128Gcm,
        };
        let mut encoded = msg.encode().unwrap();
        let mut writer = Writer::new();
        for _ in 0..MAX_FEATURES {
            writer.opt_bytes(6, b"x");
        }
        encoded.extend_from_slice(&writer.finish());
        assert_eq!(Msg1::decode(&encoded).unwrap(), msg);
        let mut writer = Writer::new();
        writer.opt_bytes(6, b"x");
        encoded.extend_from_slice(&writer.finish());
        assert_eq!(
            Msg1::decode(&encoded),
            Err(MessageError::Decode(PbError::TooMany(6)))
        );
    }

    #[test]
    fn msg2_root_key_follows_the_action() {
        let msg = Msg2 {
            network_name: "office".into(),
            role_hint: RoleHint::SameNetwork,
            action: Action::Create,
            session_generation: 1,
            root_key: Some([7; 32]),
            initial_epoch: 0,
            conn_id: id(2),
            peer_conn_id_echo: id(1),
            secret_proof: Some([9; 32]),
            cipher: Cipher::Aes256Gcm,
        };
        assert_eq!(Msg2::decode(&msg.encode().unwrap()).unwrap(), msg);
        let join = Msg2 {
            action: Action::Join,
            root_key: None,
            secret_proof: None,
            ..msg.clone()
        };
        assert_eq!(Msg2::decode(&join.encode().unwrap()).unwrap(), join);

        let bad = Msg2 {
            root_key: None,
            ..msg.clone()
        };
        assert_eq!(bad.encode(), Err(MessageError::RootKeyMismatch));
        let bad = Msg2 {
            action: Action::Join,
            ..msg.clone()
        };
        assert_eq!(bad.encode(), Err(MessageError::RootKeyMismatch));

        // A short root key, an unknown action and a missing role hint.
        let mut writer = Writer::new();
        writer
            .u32(2, 1)
            .u32(3, 2)
            .bytes(5, &[1; 31])
            .str(10, "aes-gcm");
        assert_eq!(Msg2::decode(&writer.finish()), Err(MessageError::BadLength));
        let mut writer = Writer::new();
        writer.u32(2, 1).u32(3, 3).str(10, "aes-gcm");
        assert_eq!(Msg2::decode(&writer.finish()), Err(MessageError::BadEnum));
        let mut writer = Writer::new();
        writer.str(10, "aes-gcm");
        assert_eq!(Msg2::decode(&writer.finish()), Err(MessageError::BadEnum));
    }

    #[test]
    fn msg3_round_trips_with_and_without_a_secret() {
        let msg = Msg3 {
            client_conn_id_echo: id(1),
            server_conn_id_echo: id(2),
            secret_proof: Some([3; 32]),
            secret_digest: Some([4; 32]),
        };
        assert_eq!(Msg3::decode(&msg.encode()).unwrap(), msg);
        let bare = Msg3 {
            secret_proof: None,
            secret_digest: None,
            ..msg
        };
        assert_eq!(Msg3::decode(&bare.encode()).unwrap(), bare);
        let mut writer = Writer::new();
        writer.bytes(4, &[1; 16]);
        assert_eq!(Msg3::decode(&writer.finish()), Err(MessageError::BadLength));
    }

    #[test]
    fn relay_messages_round_trip() {
        let msg1 = RelayMsg1 {
            session_generation: Some(4),
            conn_id: id(5),
            cipher: Cipher::Aes128Gcm,
        };
        assert_eq!(RelayMsg1::decode(&msg1.encode().unwrap()).unwrap(), msg1);
        let msg2 = RelayMsg2 {
            action: Action::Sync,
            session_generation: 4,
            root_key: Some([6; 32]),
            initial_epoch: 9,
            conn_id: id(6),
            peer_conn_id_echo: id(5),
            cipher: Cipher::ChaCha20Poly1305,
        };
        assert_eq!(RelayMsg2::decode(&msg2.encode().unwrap()).unwrap(), msg2);
        let mut writer = Writer::new();
        writer.u32(3, 1).str(10, "aes-gcm");
        assert_eq!(
            RelayMsg2::decode(&writer.finish()),
            Err(MessageError::RootKeyMismatch)
        );
    }
}
