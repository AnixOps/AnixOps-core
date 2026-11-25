//! IPv4 and IPv6 networks in `address/prefix` form.

use std::fmt;
use std::hash::{Hash, Hasher};
use std::net::IpAddr;

/// One network. The address is kept as written; [`IpNet::network`] gives the
/// masked form, and equality compares the masked form.
#[derive(Clone, Copy, Debug, Eq)]
pub struct IpNet {
    address: IpAddr,
    prefix: u8,
}

impl PartialEq for IpNet {
    fn eq(&self, other: &Self) -> bool {
        self.prefix == other.prefix && self.network() == other.network()
    }
}

impl Hash for IpNet {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.network().hash(state);
        self.prefix.hash(state);
    }
}

impl IpNet {
    /// `None` when the prefix is longer than the family allows.
    pub fn new(address: IpAddr, prefix: u8) -> Option<Self> {
        (prefix <= max_prefix(address)).then_some(Self { address, prefix })
    }

    /// A host route: `/32` or `/128`.
    pub fn host(address: IpAddr) -> Self {
        Self {
            address,
            prefix: max_prefix(address),
        }
    }

    /// Parses `10.0.0.0/8`, `fd00::/8`, `10.0.0.1` or `[fd00::1]`; a bare
    /// address is a host route. IPv4-mapped IPv6 addresses are refused so
    /// one network has one spelling.
    pub fn parse(text: &str) -> Option<Self> {
        let text = text.trim();
        let (address, prefix) = match text.split_once('/') {
            Some((address, prefix)) => (address, Some(prefix.trim())),
            None => (text, None),
        };
        let address = address.trim();
        let address = address
            .strip_prefix('[')
            .and_then(|inner| inner.strip_suffix(']'))
            .unwrap_or(address);
        let address: IpAddr = address.parse().ok()?;
        if let IpAddr::V6(v6) = address {
            if v6.to_ipv4_mapped().is_some() {
                return None;
            }
        }
        let prefix = match prefix {
            Some(prefix) if !prefix.is_empty() && prefix.bytes().all(|b| b.is_ascii_digit()) => {
                prefix.parse().ok()?
            }
            Some(_) => return None,
            None => max_prefix(address),
        };
        Self::new(address, prefix)
    }

    /// The address as written (for an interface address, the host itself).
    pub fn address(&self) -> IpAddr {
        self.address
    }

    pub fn prefix(&self) -> u8 {
        self.prefix
    }

    pub fn is_ipv4(&self) -> bool {
        self.address.is_ipv4()
    }

    /// The network with the host bits cleared.
    pub fn network(&self) -> IpAddr {
        match self.address {
            IpAddr::V4(v4) => IpAddr::V4((u32::from(v4) & mask32(self.prefix)).into()),
            IpAddr::V6(v6) => IpAddr::V6((u128::from(v6) & mask128(self.prefix)).into()),
        }
    }

    /// Whether `address` is a usable host address in this network: inside
    /// it and neither the network address nor, for IPv4 networks of /30 and
    /// wider, the broadcast address.
    pub fn is_host(&self, address: IpAddr) -> bool {
        if !self.contains(address) || address == self.network() {
            return false;
        }
        match address {
            IpAddr::V4(v4) if self.prefix <= 30 => u32::from(v4) | mask32(self.prefix) != u32::MAX,
            _ => true,
        }
    }

    /// The same network with the host bits cleared.
    pub fn trunc(&self) -> Self {
        Self {
            address: self.network(),
            prefix: self.prefix,
        }
    }

    pub fn contains(&self, address: IpAddr) -> bool {
        match (self.address, address) {
            (IpAddr::V4(net), IpAddr::V4(address)) => {
                let mask = mask32(self.prefix);
                u32::from(net) & mask == u32::from(address) & mask
            }
            (IpAddr::V6(net), IpAddr::V6(address)) => {
                let mask = mask128(self.prefix);
                u128::from(net) & mask == u128::from(address) & mask
            }
            _ => false,
        }
    }

    /// Whether every address of `other` is inside this network.
    pub fn covers(&self, other: &IpNet) -> bool {
        self.prefix <= other.prefix && self.contains(other.address)
    }

    /// Whether the two networks share at least one address.
    pub fn overlaps(&self, other: &IpNet) -> bool {
        self.covers(other) || other.covers(self)
    }
}

impl fmt::Display for IpNet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.network(), self.prefix)
    }
}

fn max_prefix(address: IpAddr) -> u8 {
    match address {
        IpAddr::V4(_) => 32,
        IpAddr::V6(_) => 128,
    }
}

fn mask32(prefix: u8) -> u32 {
    if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - u32::from(prefix))
    }
}

fn mask128(prefix: u8) -> u128 {
    if prefix == 0 {
        0
    } else {
        u128::MAX << (128 - u32::from(prefix))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(text: &str) -> IpAddr {
        text.parse().unwrap()
    }

    #[test]
    fn parses_networks_and_hosts() {
        let net = IpNet::parse("10.144.0.7/16").unwrap();
        assert_eq!(net.address(), ip("10.144.0.7"));
        assert_eq!(net.network(), ip("10.144.0.0"));
        assert_eq!(net.to_string(), "10.144.0.0/16");
        assert_eq!(IpNet::parse("10.0.0.1").unwrap().prefix(), 32);
        assert_eq!(IpNet::parse("[fd00::1]").unwrap().prefix(), 128);
        assert_eq!(IpNet::parse(" fd00::/8 ").unwrap().to_string(), "fd00::/8");
    }

    #[test]
    fn refuses_malformed_networks() {
        for text in [
            "",
            "10.0.0.0/33",
            "fd00::/129",
            "10.0.0.0/",
            "10.0.0.0/+8",
            "10.0.0.0/8/8",
            "host.example/24",
            "::ffff:10.0.0.1/128",
            "[10.0.0.1]/8x",
        ] {
            assert!(IpNet::parse(text).is_none(), "{text}");
        }
    }

    #[test]
    fn host_addresses() {
        let net = IpNet::parse("10.144.144.0/24").unwrap();
        for (address, host) in [
            ("10.144.144.0", false),
            ("10.144.144.1", true),
            ("10.144.144.254", true),
            ("10.144.144.255", false),
            ("10.144.145.1", false),
        ] {
            assert_eq!(net.is_host(address.parse().unwrap()), host, "{address}");
        }
        let v6 = IpNet::parse("fd00::/64").unwrap();
        assert!(!v6.is_host("fd00::".parse().unwrap()));
        assert!(v6.is_host("fd00::ffff:ffff:ffff:ffff".parse().unwrap()));
    }

    #[test]
    fn contains_covers_and_overlaps() {
        let wide = IpNet::parse("10.0.0.0/8").unwrap();
        let narrow = IpNet::parse("10.1.0.0/16").unwrap();
        let other = IpNet::parse("192.168.0.0/16").unwrap();
        assert!(wide.contains(ip("10.255.0.1")));
        assert!(!wide.contains(ip("11.0.0.1")));
        assert!(!wide.contains(ip("::a00:1")));
        assert!(wide.covers(&narrow));
        assert!(!narrow.covers(&wide));
        assert!(wide.overlaps(&narrow) && narrow.overlaps(&wide));
        assert!(!wide.overlaps(&other));
        let all = IpNet::parse("0.0.0.0/0").unwrap();
        assert!(all.covers(&wide));
    }

    #[test]
    fn equality_ignores_host_bits() {
        assert_eq!(
            IpNet::parse("10.1.2.3/16").unwrap(),
            IpNet::parse("10.1.0.0/16").unwrap()
        );
        assert_ne!(
            IpNet::parse("10.1.0.0/16").unwrap(),
            IpNet::parse("10.1.0.0/24").unwrap()
        );
    }
}
