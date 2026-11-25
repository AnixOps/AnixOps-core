//! Source and destination of a raw IP packet. Only the fixed headers are
//! read; anything shorter than its header or claiming more bytes than it has
//! is malformed.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

const IPV4_MIN_HEADER: usize = 20;
const IPV6_HEADER: usize = 40;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Addresses {
    pub source: IpAddr,
    pub destination: IpAddr,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Malformed {
    Empty,
    UnknownVersion(u8),
    Truncated,
    BadHeaderLength,
}

/// Reads the addresses of one IPv4 or IPv6 packet.
pub fn addresses(packet: &[u8]) -> Result<Addresses, Malformed> {
    let first = *packet.first().ok_or(Malformed::Empty)?;
    match first >> 4 {
        4 => {
            if packet.len() < IPV4_MIN_HEADER {
                return Err(Malformed::Truncated);
            }
            let header = usize::from(first & 0x0f) * 4;
            if header < IPV4_MIN_HEADER {
                return Err(Malformed::BadHeaderLength);
            }
            let total = usize::from(u16::from_be_bytes([packet[2], packet[3]]));
            if total < header || total > packet.len() {
                return Err(Malformed::Truncated);
            }
            let source = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
            let destination = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
            Ok(Addresses {
                source: source.into(),
                destination: destination.into(),
            })
        }
        6 => {
            if packet.len() < IPV6_HEADER {
                return Err(Malformed::Truncated);
            }
            let payload = usize::from(u16::from_be_bytes([packet[4], packet[5]]));
            if IPV6_HEADER + payload > packet.len() {
                return Err(Malformed::Truncated);
            }
            let mut source = [0u8; 16];
            source.copy_from_slice(&packet[8..24]);
            let mut destination = [0u8; 16];
            destination.copy_from_slice(&packet[24..40]);
            Ok(Addresses {
                source: Ipv6Addr::from(source).into(),
                destination: Ipv6Addr::from(destination).into(),
            })
        }
        version => Err(Malformed::UnknownVersion(version)),
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// A minimal IPv4 packet (no checksum) with `payload` zero bytes.
    pub(crate) fn ipv4(source: [u8; 4], destination: [u8; 4], payload: usize) -> Vec<u8> {
        let total = (IPV4_MIN_HEADER + payload) as u16;
        let mut packet = vec![0u8; usize::from(total)];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&total.to_be_bytes());
        packet[8] = 64;
        packet[9] = 17;
        packet[12..16].copy_from_slice(&source);
        packet[16..20].copy_from_slice(&destination);
        packet
    }

    /// A minimal IPv6 packet with `payload` zero bytes.
    pub(crate) fn ipv6(source: Ipv6Addr, destination: Ipv6Addr, payload: usize) -> Vec<u8> {
        let mut packet = vec![0u8; IPV6_HEADER + payload];
        packet[0] = 0x60;
        packet[4..6].copy_from_slice(&(payload as u16).to_be_bytes());
        packet[6] = 17;
        packet[7] = 64;
        packet[8..24].copy_from_slice(&source.octets());
        packet[24..40].copy_from_slice(&destination.octets());
        packet
    }

    #[test]
    fn reads_ipv4_addresses() {
        let packet = ipv4([10, 0, 0, 1], [10, 0, 0, 2], 8);
        let addresses = addresses(&packet).unwrap();
        assert_eq!(addresses.source, "10.0.0.1".parse::<IpAddr>().unwrap());
        assert_eq!(addresses.destination, "10.0.0.2".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn reads_ipv6_addresses() {
        let packet = ipv6("fd00::1".parse().unwrap(), "fd00::2".parse().unwrap(), 4);
        let addresses = addresses(&packet).unwrap();
        assert_eq!(addresses.source, "fd00::1".parse::<IpAddr>().unwrap());
        assert_eq!(addresses.destination, "fd00::2".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn rejects_malformed_packets() {
        assert_eq!(addresses(&[]), Err(Malformed::Empty));
        assert_eq!(addresses(&[0x50; 40]), Err(Malformed::UnknownVersion(5)));
        assert_eq!(addresses(&[0x45; 10]), Err(Malformed::Truncated));

        let mut short_header = ipv4([10, 0, 0, 1], [10, 0, 0, 2], 0);
        short_header[0] = 0x44;
        assert_eq!(addresses(&short_header), Err(Malformed::BadHeaderLength));

        let mut overlong = ipv4([10, 0, 0, 1], [10, 0, 0, 2], 0);
        overlong[2..4].copy_from_slice(&100u16.to_be_bytes());
        assert_eq!(addresses(&overlong), Err(Malformed::Truncated));

        let mut too_short_total = ipv4([10, 0, 0, 1], [10, 0, 0, 2], 0);
        too_short_total[2..4].copy_from_slice(&10u16.to_be_bytes());
        assert_eq!(addresses(&too_short_total), Err(Malformed::Truncated));

        let mut v6 = ipv6("fd00::1".parse().unwrap(), "fd00::2".parse().unwrap(), 0);
        v6[4..6].copy_from_slice(&1u16.to_be_bytes());
        assert_eq!(addresses(&v6), Err(Malformed::Truncated));
        assert_eq!(addresses(&[0x60; 39]), Err(Malformed::Truncated));
    }
}
