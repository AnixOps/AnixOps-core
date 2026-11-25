//! What counts as intranet.
//!
//! The mesh only connects private networks: every address it sends to, every
//! network a peer may advertise and every source a peer may deliver from must
//! lie inside one of the ranges below. Public addresses, a default route and
//! special-purpose ranges (loopback, link-local, multicast, documentation)
//! are refused, so a peer can never turn this node into a path to the
//! Internet and the node never acts as an exit for anyone.

use std::net::IpAddr;

use crate::net::IpNet;

/// Private ranges a mesh may use:
///
/// - `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`: private IPv4 (RFC 1918).
/// - `100.64.0.0/10`: shared address space (RFC 6598), common for overlay
///   networks.
/// - `fc00::/7`: unique local IPv6 (RFC 4193).
pub const INTRANET_RANGES: [&str; 5] = [
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "100.64.0.0/10",
    "fc00::/7",
];

fn ranges() -> impl Iterator<Item = IpNet> {
    INTRANET_RANGES
        .iter()
        .map(|range| IpNet::parse(range).expect("intranet range table is valid"))
}

/// Whether one address is intranet.
pub fn is_intranet_address(address: IpAddr) -> bool {
    let address = match address {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6(v6),
        },
        v4 => v4,
    };
    ranges().any(|range| range.contains(address))
}

/// Whether a whole network is intranet: it must sit inside a single range,
/// so `0.0.0.0/0`, `10.0.0.0/7` or `172.0.0.0/8` are refused even though
/// they include private addresses.
pub fn is_intranet_network(net: &IpNet) -> bool {
    ranges().any(|range| range.covers(net))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn net(text: &str) -> IpNet {
        IpNet::parse(text).unwrap()
    }

    #[test]
    fn private_ranges_are_intranet() {
        for text in [
            "10.0.0.0/8",
            "10.144.144.0/24",
            "172.16.0.0/12",
            "172.31.255.255/32",
            "192.168.1.0/24",
            "100.64.0.0/10",
            "100.127.0.1/32",
            "fd00:1234::/64",
            "fc00::/7",
        ] {
            assert!(is_intranet_network(&net(text)), "{text}");
            assert!(is_intranet_address(net(text).address()), "{text}");
        }
    }

    #[test]
    fn public_default_and_special_ranges_are_not() {
        for text in [
            "0.0.0.0/0",
            "::/0",
            "0.0.0.0/1",
            "10.0.0.0/7",
            "172.0.0.0/8",
            "172.32.0.0/16",
            "100.128.0.0/16",
            "8.8.8.8/32",
            "1.1.1.0/24",
            "127.0.0.1/32",
            "169.254.0.0/16",
            "224.0.0.0/4",
            "255.255.255.255/32",
            "198.18.0.0/15",
            "192.0.2.0/24",
            "fe80::/10",
            "ff02::1/128",
            "::1/128",
            "2001:db8::/32",
            "2606:4700::/32",
            "fc00::/6",
        ] {
            assert!(!is_intranet_network(&net(text)), "{text}");
        }
    }

    #[test]
    fn ipv4_mapped_addresses_follow_their_ipv4_address() {
        assert!(is_intranet_address("::ffff:10.0.0.1".parse().unwrap()));
        assert!(!is_intranet_address("::ffff:8.8.8.8".parse().unwrap()));
    }
}
