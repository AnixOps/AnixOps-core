//! UDP sessions (spec §3.2): an 8-byte header in front of every datagram.

use super::header::HEADER_LEN;

pub const UDP_HEADER_LEN: usize = 8;
/// Largest header-plus-payload this node puts in one Data datagram when it
/// can choose (spec §3.2); packets up to the TCP send limit still go out.
pub const PREFERRED_DATA_LEN: usize = 1300;
/// How long a client waits for Sack, in milliseconds (spec §3.2).
pub const SACK_TIMEOUT_MS: u64 = 3000;
const STUN_COOKIE: [u8; 4] = [0x21, 0x12, 0xa4, 0x42];

/// UDP message types (spec §3.2).
pub mod msg_type {
    pub const SYN: u8 = 1;
    pub const SACK: u8 = 2;
    pub const DATA: u8 = 3;
    pub const FIN: u8 = 4;
    pub const HOLE_PUNCH: u8 = 5;
}

/// One received datagram.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Datagram<'a> {
    Syn {
        conn_id: u32,
        magic: u64,
    },
    Sack {
        conn_id: u32,
        magic: u64,
    },
    /// Node header and payload.
    Data {
        conn_id: u32,
        packet: &'a [u8],
    },
    /// Opens a NAT mapping; the content is ignored (spec §20.3).
    HolePunch {
        conn_id: u32,
    },
    /// A STUN message on the listening port (spec §20.1); handled apart.
    Stun(&'a [u8]),
    /// Anything else: Fin, process-internal types, bad lengths. Dropped.
    Ignored,
}

/// Classifies one datagram.
pub fn parse(datagram: &[u8]) -> Datagram<'_> {
    if datagram.len() >= 8 && datagram[0] & 0xc0 == 0 && datagram[4..8] == STUN_COOKIE {
        return Datagram::Stun(datagram);
    }
    if datagram.len() < UDP_HEADER_LEN {
        return Datagram::Ignored;
    }
    let conn_id = u32::from_le_bytes(datagram[0..4].try_into().unwrap());
    let kind = datagram[4];
    let len = u16::from_le_bytes([datagram[6], datagram[7]]) as usize;
    let body = &datagram[UDP_HEADER_LEN..];
    if len != body.len() {
        return Datagram::Ignored;
    }
    let magic = || -> Option<u64> { Some(u64::from_le_bytes(body.try_into().ok()?)) };
    match kind {
        msg_type::SYN => {
            magic().map_or(Datagram::Ignored, |magic| Datagram::Syn { conn_id, magic })
        }
        msg_type::SACK => {
            magic().map_or(Datagram::Ignored, |magic| Datagram::Sack { conn_id, magic })
        }
        msg_type::DATA if body.len() >= HEADER_LEN => Datagram::Data {
            conn_id,
            packet: body,
        },
        msg_type::HOLE_PUNCH => Datagram::HolePunch { conn_id },
        _ => Datagram::Ignored,
    }
}

fn encode(conn_id: u32, kind: u8, body: &[u8]) -> Option<Vec<u8>> {
    let len = u16::try_from(body.len()).ok()?;
    let mut out = Vec::with_capacity(UDP_HEADER_LEN + body.len());
    out.extend_from_slice(&conn_id.to_le_bytes());
    out.push(kind);
    out.push(0);
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(body);
    Some(out)
}

pub fn syn(conn_id: u32, magic: u64) -> Vec<u8> {
    encode(conn_id, msg_type::SYN, &magic.to_le_bytes()).expect("8 bytes fit")
}

pub fn sack(conn_id: u32, magic: u64) -> Vec<u8> {
    encode(conn_id, msg_type::SACK, &magic.to_le_bytes()).expect("8 bytes fit")
}

/// A Data datagram; `None` when the packet does not fit the length field.
pub fn data(conn_id: u32, packet: &[u8]) -> Option<Vec<u8>> {
    encode(conn_id, msg_type::DATA, packet)
}

/// A hole-punching datagram with 16 random bytes (spec §20.3).
pub fn hole_punch(conn_id: u32, random: [u8; 16]) -> Vec<u8> {
    encode(conn_id, msg_type::HOLE_PUNCH, &random).expect("16 bytes fit")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn syn_and_sack_round_trip() {
        let bytes = syn(0x0102_0304, 0x1122_3344_5566_7788);
        assert_eq!(&bytes[..8], &[4, 3, 2, 1, 1, 0, 8, 0]);
        assert_eq!(
            parse(&bytes),
            Datagram::Syn {
                conn_id: 0x0102_0304,
                magic: 0x1122_3344_5566_7788
            }
        );
        assert_eq!(
            parse(&sack(7, 9)),
            Datagram::Sack {
                conn_id: 7,
                magic: 9
            }
        );
    }

    #[test]
    fn data_carries_a_node_packet() {
        let packet = [0xabu8; 20];
        let bytes = data(5, &packet).unwrap();
        assert_eq!(
            parse(&bytes),
            Datagram::Data {
                conn_id: 5,
                packet: &packet
            }
        );
        // Shorter than a node header.
        assert_eq!(parse(&data(5, &[0; 15]).unwrap()), Datagram::Ignored);
    }

    #[test]
    fn length_mismatch_and_unknown_types_are_ignored() {
        let mut bytes = data(5, &[0; 20]).unwrap();
        bytes.push(0);
        assert_eq!(parse(&bytes), Datagram::Ignored);
        for kind in [msg_type::FIN, 6, 7, 0, 200] {
            assert_eq!(
                parse(&encode(1, kind, &[0; 8]).unwrap()),
                Datagram::Ignored,
                "{kind}"
            );
        }
        assert_eq!(parse(&[1, 2, 3]), Datagram::Ignored);
        // Syn with a short magic.
        assert_eq!(
            parse(&encode(1, msg_type::SYN, &[0; 7]).unwrap()),
            Datagram::Ignored
        );
    }

    #[test]
    fn padding_byte_is_ignored_on_receive() {
        let mut bytes = sack(1, 2);
        bytes[5] = 0xff;
        assert_eq!(
            parse(&bytes),
            Datagram::Sack {
                conn_id: 1,
                magic: 2
            }
        );
    }

    #[test]
    fn stun_is_recognised_first() {
        // A Binding request header: type 0x0001, length 0, magic cookie.
        let mut stun = vec![0x00, 0x01, 0x00, 0x00, 0x21, 0x12, 0xa4, 0x42];
        stun.extend_from_slice(&[0; 12]);
        assert!(matches!(parse(&stun), Datagram::Stun(_)));
        // Top bits set: not STUN.
        stun[0] = 0x40;
        assert!(!matches!(parse(&stun), Datagram::Stun(_)));
    }

    #[test]
    fn hole_punch_is_recognised() {
        assert_eq!(
            parse(&hole_punch(9, [1; 16])),
            Datagram::HolePunch { conn_id: 9 }
        );
    }
}
