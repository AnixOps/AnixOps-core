//! Byte-level formats (spec §2–§4, §11.1): framing, the node header and the
//! protobuf subset. Nothing here does I/O or cryptography.

pub mod header;
pub mod pb;
pub mod tcp;
pub mod udp;

pub use header::{flags, packet_type, NodeHeader, HEADER_LEN};
