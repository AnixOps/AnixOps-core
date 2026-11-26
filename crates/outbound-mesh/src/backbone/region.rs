//! Region IDs and summary prefixes (appendix A.1, A.2).

use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::net::IpAddr;

use crate::net::IpNet;
use crate::scope;

/// A region ID: the panel's region code (appendix A.1). 2–16 bytes of
/// lowercase ASCII letters, digits or `-`, starting with a letter and not
/// ending with `-`.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct RegionId(String);

impl RegionId {
    pub const MIN_LEN: usize = 2;
    pub const MAX_LEN: usize = 16;

    pub fn parse(text: &str) -> Option<Self> {
        let bytes = text.as_bytes();
        if !(Self::MIN_LEN..=Self::MAX_LEN).contains(&bytes.len()) {
            return None;
        }
        if !bytes[0].is_ascii_lowercase() || bytes[bytes.len() - 1] == b'-' {
            return None;
        }
        if !bytes
            .iter()
            .all(|&b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        {
            return None;
        }
        Some(Self(text.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for RegionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Shortest IPv4 summary prefix (appendix A.2).
pub const MIN_PREFIX_V4: u8 = 8;
/// Shortest IPv6 summary prefix (appendix A.2).
pub const MIN_PREFIX_V6: u8 = 16;

/// Whether `net` may appear as a summary prefix: written in canonical form
/// (host bits zero), not shorter than /8 (IPv4) or /16 (IPv6), and inside
/// the intranet ranges.
pub fn is_summary_prefix(net: &IpNet) -> bool {
    let min = if net.is_ipv4() {
        MIN_PREFIX_V4
    } else {
        MIN_PREFIX_V6
    };
    net.address() == net.network() && net.prefix() >= min && scope::is_intranet_network(net)
}

/// Parses one summary prefix as it appears on the wire or in the config:
/// `address/len` with an explicit length.
pub fn parse_summary_prefix(text: &str) -> Option<IpNet> {
    if !text.contains('/') || text.trim() != text {
        return None;
    }
    let net = IpNet::parse(text)?;
    is_summary_prefix(&net).then_some(net)
}

/// Longest-prefix-match table from prefixes to values. Lookups cost one hash
/// probe per distinct prefix length present.
#[derive(Clone, Debug)]
pub struct Lpm<V> {
    // Prefix length → masked network → value, lengths visited longest first.
    v4: BTreeMap<u8, HashMap<IpAddr, V>>,
    v6: BTreeMap<u8, HashMap<IpAddr, V>>,
}

impl<V> Default for Lpm<V> {
    fn default() -> Self {
        Self {
            v4: BTreeMap::new(),
            v6: BTreeMap::new(),
        }
    }
}

impl<V> Lpm<V> {
    pub fn new() -> Self {
        Self::default()
    }

    fn family(&self, v4: bool) -> &BTreeMap<u8, HashMap<IpAddr, V>> {
        if v4 {
            &self.v4
        } else {
            &self.v6
        }
    }

    /// Inserts `net`, returning the value it replaced.
    pub fn insert(&mut self, net: IpNet, value: V) -> Option<V> {
        let family = if net.is_ipv4() {
            &mut self.v4
        } else {
            &mut self.v6
        };
        family
            .entry(net.prefix())
            .or_default()
            .insert(net.network(), value)
    }

    /// The exact entry for `net`.
    pub fn get(&self, net: &IpNet) -> Option<&V> {
        self.family(net.is_ipv4())
            .get(&net.prefix())?
            .get(&net.network())
    }

    /// The value of the longest prefix containing `address`, with that prefix.
    pub fn lookup(&self, address: IpAddr) -> Option<(IpNet, &V)> {
        for (&len, entries) in self.family(address.is_ipv4()).iter().rev() {
            let key = IpNet::new(address, len)?.network();
            if let Some(value) = entries.get(&key) {
                return Some((IpNet::new(key, len)?, value));
            }
        }
        None
    }

    pub fn is_empty(&self) -> bool {
        self.v4.is_empty() && self.v6.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn region_ids_follow_the_panel_rule() {
        for good in [
            "cn",
            "eu",
            "ap",
            "na",
            "east-asia",
            "a1",
            "abcdefghijklmnop",
        ] {
            assert!(RegionId::parse(good).is_some(), "{good}");
        }
        for bad in [
            "",
            "c",
            "1cn",
            "-cn",
            "cn-",
            "CN",
            "c_n",
            "c n",
            "abcdefghijklmnopq",
            "中国",
        ] {
            assert!(RegionId::parse(bad).is_none(), "{bad}");
        }
    }

    #[test]
    fn summary_prefixes_are_canonical_intranet_and_not_too_short() {
        for good in [
            "10.0.0.0/8",
            "10.20.0.0/16",
            "192.168.1.0/24",
            "fd00:1::/32",
        ] {
            assert!(parse_summary_prefix(good).is_some(), "{good}");
        }
        for bad in [
            "10.0.0.1/8",
            "10.0.0.0",
            "8.8.8.0/24",
            "0.0.0.0/0",
            "10.0.0.0/7",
            "fd00::/8",
            "2001:db8::/32",
            " 10.0.0.0/8",
            "10.0.0.0/33",
        ] {
            assert!(parse_summary_prefix(bad).is_none(), "{bad}");
        }
    }

    #[test]
    fn lpm_prefers_the_longest_prefix() {
        let mut table = Lpm::new();
        table.insert(parse_summary_prefix("10.0.0.0/8").unwrap(), 1);
        table.insert(parse_summary_prefix("10.20.0.0/16").unwrap(), 2);
        table.insert(parse_summary_prefix("fd00:1::/32").unwrap(), 3);
        let hit = |a: &str| table.lookup(a.parse().unwrap()).map(|(_, v)| *v);
        assert_eq!(hit("10.20.3.4"), Some(2));
        assert_eq!(hit("10.21.3.4"), Some(1));
        assert_eq!(hit("fd00:1::5"), Some(3));
        assert_eq!(hit("172.16.0.1"), None);
        let (net, _) = table.lookup("10.20.9.9".parse().unwrap()).unwrap();
        assert_eq!(net.to_string(), "10.20.0.0/16");
    }
}
