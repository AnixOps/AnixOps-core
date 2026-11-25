//! Addresses and networks as the importer needs them: parsing, the
//! intranet scope of requirement R17 and endpoint parsing.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// An address with a prefix length, as written in a configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cidr {
    pub address: IpAddr,
    pub prefix: u8,
}

impl Cidr {
    pub fn parse(text: &str) -> Option<Self> {
        let (address, prefix) = text.trim().split_once('/')?;
        let address: IpAddr = address.parse().ok()?;
        let prefix: u8 = prefix.parse().ok()?;
        let max = if address.is_ipv4() { 32 } else { 128 };
        (prefix <= max).then_some(Cidr { address, prefix })
    }

    /// The network address (host bits cleared).
    pub fn network(&self) -> IpAddr {
        match self.address {
            IpAddr::V4(address) => {
                let bits = u32::from(address);
                let mask = if self.prefix == 0 {
                    0
                } else {
                    u32::MAX << (32 - u32::from(self.prefix))
                };
                IpAddr::V4(Ipv4Addr::from(bits & mask))
            }
            IpAddr::V6(address) => {
                let bits = u128::from(address);
                let mask = if self.prefix == 0 {
                    0
                } else {
                    u128::MAX << (128 - u32::from(self.prefix))
                };
                IpAddr::V6(Ipv6Addr::from(bits & mask))
            }
        }
    }

    /// Whether the two networks share at least one address.
    pub fn overlaps(&self, other: &Cidr) -> bool {
        if self.address.is_ipv4() != other.address.is_ipv4() {
            return false;
        }
        let prefix = self.prefix.min(other.prefix);
        let shorter = |cidr: &Cidr| {
            Cidr {
                address: cidr.address,
                prefix,
            }
            .network()
        };
        shorter(self) == shorter(other)
    }

    /// The network in canonical text form, `10.1.0.0/16`.
    pub fn network_text(&self) -> String {
        format!("{}/{}", self.network(), self.prefix)
    }
}

impl std::fmt::Display for Cidr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.address, self.prefix)
    }
}

/// Private ranges a mesh may carry (requirement R17).
const INTRANET_V4: [([u8; 4], u8); 4] = [
    ([10, 0, 0, 0], 8),
    ([172, 16, 0, 0], 12),
    ([192, 168, 0, 0], 16),
    ([100, 64, 0, 0], 10),
];

/// Whether the whole network lies inside the intranet scope.
pub fn is_intranet(cidr: &Cidr) -> bool {
    match cidr.network() {
        IpAddr::V4(network) => INTRANET_V4.iter().any(|(base, prefix)| {
            cidr.prefix >= *prefix
                && Cidr {
                    address: IpAddr::V4(network),
                    prefix: *prefix,
                }
                .network()
                    == IpAddr::V4(Ipv4Addr::from(*base))
        }),
        IpAddr::V6(network) => cidr.prefix >= 7 && (network.segments()[0] & 0xfe00) == 0xfc00,
    }
}

/// A transport endpoint such as `tcp://host:port`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Endpoint {
    pub scheme: String,
    /// Host name or address, without IPv6 brackets.
    pub host: String,
    pub port: Option<u16>,
}

impl Endpoint {
    /// Parses `scheme://host[:port][/...]`. Returns `None` for anything else.
    pub fn parse(text: &str) -> Option<Self> {
        let (scheme, rest) = text.trim().split_once("://")?;
        if scheme.is_empty()
            || !scheme
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '+')
        {
            return None;
        }
        let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
        // Credentials in the address are not supported.
        if authority.contains('@') {
            return None;
        }
        let (host, port) = if let Some(after) = authority.strip_prefix('[') {
            let (host, tail) = after.split_once(']')?;
            host.parse::<Ipv6Addr>().ok()?;
            let port: Option<u16> = match tail {
                "" => None,
                tail => Some(tail.strip_prefix(':')?.parse().ok()?),
            };
            (host.to_string(), port)
        } else {
            match authority.rsplit_once(':') {
                Some((host, port)) if !host.contains(':') => {
                    (host.to_string(), Some(port.parse().ok()?))
                }
                Some(_) => return None,
                None => (authority.to_string(), None),
            }
        };
        if host.is_empty() || port == Some(0) {
            return None;
        }
        Some(Endpoint {
            scheme: scheme.to_ascii_lowercase(),
            host,
            port,
        })
    }

    /// Whether the host is "every address".
    pub fn is_wildcard(&self) -> bool {
        matches!(
            self.host.parse::<IpAddr>(),
            Ok(address) if address.is_unspecified()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_cidrs() {
        let cidr = Cidr::parse("10.1.2.3/16").unwrap();
        assert_eq!(cidr.network_text(), "10.1.0.0/16");
        assert_eq!(cidr.to_string(), "10.1.2.3/16");
        assert!(Cidr::parse("10.1.2.3").is_none());
        assert!(Cidr::parse("10.1.2.3/33").is_none());
        assert_eq!(
            Cidr::parse("fd00::1/64").unwrap().network_text(),
            "fd00::/64"
        );
        assert_eq!(
            Cidr::parse("0.0.0.0/0").unwrap().network_text(),
            "0.0.0.0/0"
        );
        let a = Cidr::parse("10.126.0.5/16").unwrap();
        assert!(a.overlaps(&Cidr::parse("10.126.3.0/24").unwrap()));
        assert!(Cidr::parse("10.0.0.0/8").unwrap().overlaps(&a));
        assert!(!a.overlaps(&Cidr::parse("10.127.0.0/24").unwrap()));
        assert!(!a.overlaps(&Cidr::parse("fd00::/8").unwrap()));
    }

    #[test]
    fn intranet_scope() {
        for inside in [
            "10.0.0.0/8",
            "10.126.0.0/16",
            "172.16.0.0/12",
            "172.31.255.0/24",
            "192.168.1.0/24",
            "100.64.0.0/10",
            "fd00::/64",
            "fc00::/7",
        ] {
            assert!(is_intranet(&Cidr::parse(inside).unwrap()), "{inside}");
        }
        for outside in [
            "0.0.0.0/0",
            "8.8.8.0/24",
            "172.32.0.0/16",
            "10.0.0.0/7",
            "100.128.0.0/16",
            "2001:db8::/32",
            "fc00::/6",
        ] {
            assert!(!is_intranet(&Cidr::parse(outside).unwrap()), "{outside}");
        }
    }

    #[test]
    fn parses_endpoints() {
        assert_eq!(
            Endpoint::parse("tcp://1.2.3.4:11010").unwrap(),
            Endpoint {
                scheme: "tcp".into(),
                host: "1.2.3.4".into(),
                port: Some(11010)
            }
        );
        assert_eq!(
            Endpoint::parse("UDP://[fd00::1]:9/x").unwrap(),
            Endpoint {
                scheme: "udp".into(),
                host: "fd00::1".into(),
                port: Some(9)
            }
        );
        assert_eq!(Endpoint::parse("ws://peer.example").unwrap().port, None);
        assert!(Endpoint::parse("1.2.3.4:5").is_none());
        assert!(Endpoint::parse("tcp://fd00::1:5").is_none());
        assert!(Endpoint::parse("tcp://u:p@h:5").is_none());
        assert!(Endpoint::parse("tcp://h:0").is_none());
        assert!(Endpoint::parse("tcp://:5").is_none());
        assert!(Endpoint::parse("tcp://0.0.0.0:1").unwrap().is_wildcard());
        assert!(Endpoint::parse("tcp://[::]:1").unwrap().is_wildcard());
    }
}
