//! The secure mode (spec §8, §9): a Noise handshake per connection, a
//! random root key per session and per-epoch traffic keys derived from it,
//! which gives forward secrecy at session granularity (spec §19.2).
//!
//! - [`noise`]: the XX and IK handshakes.
//! - [`proof`]: the network secret proof carried in the handshake (§8.2).
//! - [`messages`]: the handshake payloads (§8.1, §9).
//! - [`session`]: sessions shared by the connections of a pair of nodes,
//!   and the Create, Join and Sync choice (§8.4).
//! - [`handshake`]: the direct and relay handshakes end to end, with
//!   authentication (§8.3).
//! - [`traffic`]: traffic keys, packet sealing with epoch and sequence
//!   nonces, rotation and the replay window (§8.5, §8.6).

pub mod handshake;
pub mod messages;
pub mod noise;
pub mod proof;
pub mod session;
pub mod traffic;

/// Noise prologue of the direct handshake (spec §2.3, `C_PROLOGUE_CONN`).
pub const PROLOGUE_CONN: [u8; 23] = [
    0x65, 0x61, 0x73, 0x79, 0x74, 0x69, 0x65, 0x72, 0x2d, 0x70, 0x65, 0x65, 0x72, 0x63, 0x6f, 0x6e,
    0x6e, 0x2d, 0x6e, 0x6f, 0x69, 0x73, 0x65,
];

/// Noise prologue of the relay handshake (spec §2.3, `C_PROLOGUE_RELAY`).
pub const PROLOGUE_RELAY: [u8; 20] = [
    0x65, 0x61, 0x73, 0x79, 0x74, 0x69, 0x65, 0x72, 0x2d, 0x72, 0x65, 0x6c, 0x61, 0x79, 0x2d, 0x6e,
    0x6f, 0x69, 0x73, 0x65,
];

/// Prefix of the secret proof (spec §2.3, `C_PROOF_PREFIX`).
pub const PROOF_PREFIX: [u8; 21] = [
    0x65, 0x61, 0x73, 0x79, 0x74, 0x69, 0x65, 0x72, 0x20, 0x73, 0x65, 0x63, 0x72, 0x65, 0x74, 0x20,
    0x70, 0x72, 0x6f, 0x6f, 0x66,
];

/// HKDF info prefix of the traffic keys (spec §2.3, `C_TRAFFIC_INFO`).
pub const TRAFFIC_INFO: [u8; 10] = [0x65, 0x74, 0x2d, 0x74, 0x72, 0x61, 0x66, 0x66, 0x69, 0x63];
