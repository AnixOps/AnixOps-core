use std::net::IpAddr;

use smoltcp::wire::{IpProtocol, IpVersion, Ipv4Packet, Ipv6Packet, IPV4_HEADER_LEN};

pub type AnyIpPktFrame = Vec<u8>;

#[derive(Debug)]
pub(super) enum IpPacket<T: AsRef<[u8]>> {
    Ipv4(Ipv4Packet<T>),
    Ipv6(Ipv6Packet<T>),
}

impl<T: AsRef<[u8]> + Copy> IpPacket<T> {
    pub fn new_checked(packet: T) -> smoltcp::wire::Result<IpPacket<T>> {
        let buffer = packet.as_ref();
        match IpVersion::of_packet(buffer)? {
            IpVersion::Ipv4 => {
                let packet = Ipv4Packet::new_checked(packet)?;
                // smoltcp checks that the header fits, not that it is as long
                // as every IPv4 header is; a shorter one would put the
                // payload inside the header.
                if usize::from(packet.header_len()) < IPV4_HEADER_LEN {
                    return Err(smoltcp::wire::Error);
                }
                Ok(IpPacket::Ipv4(packet))
            }
            IpVersion::Ipv6 => Ok(IpPacket::Ipv6(Ipv6Packet::new_checked(packet)?)),
        }
    }

    pub fn src_addr(&self) -> IpAddr {
        match *self {
            IpPacket::Ipv4(ref packet) => IpAddr::from(packet.src_addr()),
            IpPacket::Ipv6(ref packet) => IpAddr::from(packet.src_addr()),
        }
    }

    pub fn dst_addr(&self) -> IpAddr {
        match *self {
            IpPacket::Ipv4(ref packet) => IpAddr::from(packet.dst_addr()),
            IpPacket::Ipv6(ref packet) => IpAddr::from(packet.dst_addr()),
        }
    }

    pub fn protocol(&self) -> IpProtocol {
        match *self {
            IpPacket::Ipv4(ref packet) => packet.next_header(),
            IpPacket::Ipv6(ref packet) => packet.next_header(),
        }
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> IpPacket<&'a T> {
    /// Return a pointer to the payload.
    #[inline]
    pub fn payload(&self) -> &'a [u8] {
        match *self {
            IpPacket::Ipv4(ref packet) => packet.payload(),
            IpPacket::Ipv6(ref packet) => packet.payload(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reassembly::testing::udp4;

    #[test]
    fn an_ipv4_header_shorter_than_20_bytes_is_refused() {
        let mut packet = udp4(b"query", 1);
        assert!(IpPacket::new_checked(packet.as_slice()).is_ok());
        // IHL 4: a header of 16 bytes, which smoltcp alone lets through.
        packet[0] = 0x44;
        assert!(Ipv4Packet::new_checked(packet.as_slice()).is_ok());
        assert!(IpPacket::new_checked(packet.as_slice()).is_err());
    }
}
