//! The default handshake mode (spec §6, §7): a plaintext handshake that
//! proves knowledge of the network secret by digest, and one static traffic
//! key for the whole network. It has no forward secrecy; sessions in this
//! mode are reported so the interface can say so.

pub mod cipher;
pub mod handshake;
pub mod keys;

pub use cipher::{CipherError, LegacyCipher};
pub use handshake::{HandshakeError, HandshakeMessage};
