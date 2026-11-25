//! The 16-byte node header in front of every packet (spec §4).

/// Bytes in a node header.
pub const HEADER_LEN: usize = 16;
/// A relay drops a packet whose counter is already above this (spec §4.4).
pub const MAX_FORWARD_COUNTER: u8 = 7;
/// Above this counter a relay clears [`flags::LATENCY_FIRST`] (spec §4.4).
pub const LATENCY_FIRST_MAX_COUNTER: u8 = 2;

/// Packet types (spec §4.2).
pub mod packet_type {
    pub const DATA: u8 = 1;
    pub const HANDSHAKE: u8 = 2;
    pub const PING: u8 = 4;
    pub const PONG: u8 = 5;
    pub const RPC_REQ: u8 = 8;
    pub const RPC_RESP: u8 = 9;
    pub const FOREIGN_NETWORK: u8 = 10;
    pub const SECURE_MSG1: u8 = 13;
    pub const SECURE_MSG2: u8 = 14;
    pub const SECURE_MSG3: u8 = 15;
    pub const RELAY_HANDSHAKE: u8 = 20;
    pub const RELAY_HANDSHAKE_ACK: u8 = 21;
    /// Our extension: waypoint encapsulation (spec §17.2.5).
    pub const WAYPOINT: u8 = 40;
}

/// Header flags (spec §4.3).
pub mod flags {
    pub const ENCRYPTED: u8 = 0x01;
    pub const LATENCY_FIRST: u8 = 0x02;
    /// Public traffic for an exit node. Never sent; received packets with it
    /// are dropped (spec §1.4).
    pub const EXIT_NODE: u8 = 0x04;
    pub const NO_PROXY: u8 = 0x08;
    pub const COMPRESSED: u8 = 0x10;
    pub const NOT_SEND_TO_TUN: u8 = 0x40;
    /// The only flags this node ever sets (spec §4.3).
    pub const SENDABLE: u8 = ENCRYPTED | LATENCY_FIRST | NO_PROXY | COMPRESSED | NOT_SEND_TO_TUN;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NodeHeader {
    /// Original sender.
    pub from: u32,
    /// Final destination; 0 during handshakes.
    pub to: u32,
    pub packet_type: u8,
    pub flags: u8,
    pub forward_counter: u8,
    /// Payload length before compression and encryption.
    pub len: u32,
}

impl NodeHeader {
    /// A header for a packet this node originates.
    pub fn new(from: u32, to: u32, packet_type: u8, len: u32) -> Self {
        Self {
            from,
            to,
            packet_type,
            flags: 0,
            forward_counter: 1,
            len,
        }
    }

    pub fn has(&self, flag: u8) -> bool {
        self.flags & flag != 0
    }

    pub fn encode(&self) -> [u8; HEADER_LEN] {
        let mut out = [0u8; HEADER_LEN];
        out[0..4].copy_from_slice(&self.from.to_le_bytes());
        out[4..8].copy_from_slice(&self.to.to_le_bytes());
        out[8] = self.packet_type;
        out[9] = self.flags;
        out[10] = self.forward_counter;
        out[11] = 0;
        out[12..16].copy_from_slice(&self.len.to_le_bytes());
        out
    }

    /// Reads a header from the start of `packet`; the reserved byte is
    /// ignored.
    pub fn decode(packet: &[u8]) -> Option<Self> {
        let bytes: &[u8; HEADER_LEN] = packet.get(..HEADER_LEN)?.try_into().ok()?;
        Some(Self {
            from: u32::from_le_bytes(bytes[0..4].try_into().unwrap()),
            to: u32::from_le_bytes(bytes[4..8].try_into().unwrap()),
            packet_type: bytes[8],
            flags: bytes[9],
            forward_counter: bytes[10],
            len: u32::from_le_bytes(bytes[12..16].try_into().unwrap()),
        })
    }

    /// Prepares a packet for the next hop when relaying (spec §4.4, §14):
    /// `false` means drop it. Only the counter and the latency flag change.
    pub fn relay(&mut self) -> bool {
        if self.forward_counter > MAX_FORWARD_COUNTER {
            return false;
        }
        self.forward_counter += 1;
        if self.forward_counter > LATENCY_FIRST_MAX_COUNTER {
            self.flags &= !flags::LATENCY_FIRST;
        }
        true
    }
}

/// Rewrites the header bytes at the start of a relayed packet in place.
/// `false` means drop it.
pub fn relay_in_place(packet: &mut [u8]) -> bool {
    let Some(mut header) = NodeHeader::decode(packet) else {
        return false;
    };
    if !header.relay() {
        return false;
    }
    packet[9] = header.flags;
    packet[10] = header.forward_counter;
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn layout_is_little_endian() {
        let header = NodeHeader {
            from: 0x1111_1111,
            to: 0x2222_2222,
            packet_type: packet_type::DATA,
            flags: flags::ENCRYPTED,
            forward_counter: 1,
            len: 28,
        };
        let bytes = header.encode();
        // Spec §22.4, the header part of the frame.
        assert_eq!(
            bytes,
            [0x11, 0x11, 0x11, 0x11, 0x22, 0x22, 0x22, 0x22, 1, 1, 1, 0, 0x1c, 0, 0, 0]
        );
        assert_eq!(NodeHeader::decode(&bytes), Some(header));
        let header = NodeHeader::new(0x0403_0201, 0, packet_type::HANDSHAKE, 0x0807_0605);
        assert_eq!(
            header.encode(),
            [1, 2, 3, 4, 0, 0, 0, 0, 2, 0, 1, 0, 5, 6, 7, 8]
        );
    }

    #[test]
    fn decode_needs_sixteen_bytes_and_ignores_reserved() {
        assert_eq!(NodeHeader::decode(&[0; 15]), None);
        let mut bytes = NodeHeader::new(1, 2, 4, 4).encode();
        bytes[11] = 0xaa;
        assert_eq!(
            NodeHeader::decode(&bytes),
            Some(NodeHeader::new(1, 2, 4, 4))
        );
    }

    #[test]
    fn relay_counts_hops_and_drops_latency_first() {
        let mut header = NodeHeader::new(1, 2, packet_type::DATA, 0);
        header.flags = flags::LATENCY_FIRST | flags::ENCRYPTED;
        assert!(header.relay());
        assert_eq!(header.forward_counter, 2);
        assert!(header.has(flags::LATENCY_FIRST));
        assert!(header.relay());
        assert_eq!(header.forward_counter, 3);
        assert!(!header.has(flags::LATENCY_FIRST));
        assert!(header.has(flags::ENCRYPTED));

        header.forward_counter = 7;
        assert!(header.relay());
        assert_eq!(header.forward_counter, 8);
        assert!(!header.relay());
    }

    #[test]
    fn relay_in_place_rewrites_only_counter_and_flags() {
        let mut header = NodeHeader::new(5, 6, packet_type::RPC_REQ, 3);
        header.flags = flags::LATENCY_FIRST;
        header.forward_counter = 2;
        let mut packet = header.encode().to_vec();
        packet.extend_from_slice(b"abc");
        assert!(relay_in_place(&mut packet));
        let relayed = NodeHeader::decode(&packet).unwrap();
        assert_eq!(relayed.forward_counter, 3);
        assert_eq!(relayed.flags, 0);
        assert_eq!(&packet[16..], b"abc");
        assert!(!relay_in_place(&mut [0u8; 4]));
    }
}
