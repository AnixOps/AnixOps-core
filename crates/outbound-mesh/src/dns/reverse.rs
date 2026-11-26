//! The reverse zones of a network (spec §15.9.2 items 1 and 7): worked out
//! from its ranges, never configured. A range counts only where it lies in
//! the private address list of §15.4, and only from /8 (IPv4) or /7 (IPv6)
//! on. Zones end on label boundaries, every 8 bits under `in-addr.arpa` and
//! every 4 bits under `ip6.arpa`; a prefix between two boundaries opens
//! every zone of the next one (`10.128.0.0/9` gives `128.10.in-addr.arpa`
//! to `255.10.in-addr.arpa`). At most [`MAX_REVERSE_ZONES`] per network, in
//! the order of the ranges; the rest are not worked out and are counted.

use std::net::IpAddr;

use crate::net::IpNet;
use crate::scope::INTRANET_RANGES;

/// Reverse zones per network.
pub const MAX_REVERSE_ZONES: usize = 256;

/// The reverse zones of one network.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ReverseZones {
    /// Each zone's labels, from the leftmost to `arpa`.
    zones: Vec<Vec<Vec<u8>>>,
    /// Zones left out over [`MAX_REVERSE_ZONES`].
    truncated: usize,
}

impl ReverseZones {
    /// The zones of `ranges`, in their order: the region's virtual subnets
    /// first, then host group ranges, then summary ranges.
    pub fn of(ranges: impl IntoIterator<Item = IpNet>) -> Self {
        let private: Vec<IpNet> = INTRANET_RANGES
            .iter()
            .map(|range| IpNet::parse(range).expect("intranet range table is valid"))
            .collect();
        let mut out = Self::default();
        for range in ranges {
            let range = range.trunc();
            for block in &private {
                let part = if block.covers(&range) {
                    range
                } else if range.covers(block) {
                    *block
                } else {
                    continue;
                };
                out.add(part);
            }
        }
        out
    }

    fn add(&mut self, net: IpNet) {
        let (step, bits, least) = if net.is_ipv4() {
            (8, 32, 8)
        } else {
            (4, 128, 7)
        };
        let prefix = u32::from(net.prefix());
        if prefix < least {
            return;
        }
        let boundary = prefix.div_ceil(step) * step;
        let count = 1u32 << (boundary - prefix);
        let base = match net.network() {
            IpAddr::V4(v4) => u128::from(u32::from(v4)),
            IpAddr::V6(v6) => u128::from(v6),
        };
        for i in 0..count {
            let start = base | (u128::from(i) << (bits - boundary));
            let labels = zone_labels(start, boundary, step, bits, net.is_ipv4());
            if self.covered(&labels) {
                continue;
            }
            if self.zones.len() == MAX_REVERSE_ZONES {
                self.truncated += 1;
                continue;
            }
            self.zones.push(labels);
        }
    }

    /// Whether `labels` is one of the zones or lies under one.
    fn covered(&self, labels: &[Vec<u8>]) -> bool {
        self.zone_of(labels).is_some()
    }

    /// The zone `labels` lies in (or is), when any.
    pub fn zone_of(&self, labels: &[Vec<u8>]) -> Option<&[Vec<u8>]> {
        self.zones
            .iter()
            .find(|zone| {
                labels.len() >= zone.len() && labels[labels.len() - zone.len()..] == zone[..]
            })
            .map(Vec::as_slice)
    }

    /// The zone names, without the final dot.
    pub fn names(&self) -> Vec<String> {
        self.zones
            .iter()
            .map(|zone| {
                zone.iter()
                    .map(|label| String::from_utf8_lossy(label).into_owned())
                    .collect::<Vec<_>>()
                    .join(".")
            })
            .collect()
    }

    /// How many zones were left out over [`MAX_REVERSE_ZONES`].
    pub fn truncated(&self) -> usize {
        self.truncated
    }
}

/// The labels of the zone holding the first `boundary` bits of `start`.
fn zone_labels(start: u128, boundary: u32, step: u32, bits: u32, v4: bool) -> Vec<Vec<u8>> {
    let mut labels: Vec<Vec<u8>> = (0..boundary / step)
        .map(|i| {
            let shift = bits - step * (i + 1);
            let value = (start >> shift) & ((1u128 << step) - 1);
            if v4 {
                value.to_string().into_bytes()
            } else {
                format!("{value:x}").into_bytes()
            }
        })
        .rev()
        .collect();
    let tail: [&[u8]; 2] = if v4 {
        [b"in-addr", b"arpa"]
    } else {
        [b"ip6", b"arpa"]
    };
    labels.extend(tail.iter().map(|label| label.to_vec()));
    labels
}

#[cfg(test)]
mod tests {
    use super::*;

    fn zones(ranges: &[&str]) -> ReverseZones {
        ReverseZones::of(ranges.iter().map(|range| IpNet::parse(range).unwrap()))
    }

    #[test]
    fn zones_end_on_label_boundaries() {
        assert_eq!(zones(&["10.150.0.0/16"]).names(), ["150.10.in-addr.arpa"]);
        assert_eq!(zones(&["10.150.3.0/24"]).names(), ["3.150.10.in-addr.arpa"]);
        assert_eq!(zones(&["10.0.0.0/8"]).names(), ["10.in-addr.arpa"]);
        let nine = zones(&["10.128.0.0/9"]).names();
        assert_eq!(nine.len(), 128);
        assert_eq!(nine[0], "128.10.in-addr.arpa");
        assert_eq!(nine[127], "255.10.in-addr.arpa");
        assert_eq!(
            zones(&["10.150.4.0/23"]).names(),
            ["4.150.10.in-addr.arpa", "5.150.10.in-addr.arpa"]
        );
        assert_eq!(
            zones(&["fd00:150::/64"]).names(),
            ["0.0.0.0.0.0.0.0.0.5.1.0.0.0.d.f.ip6.arpa"]
        );
        let quarter: Vec<String> = (0..4)
            .map(|x| format!("{x}.0.0.0.0.0.0.0.0.5.1.0.0.0.d.f.ip6.arpa"))
            .collect();
        assert_eq!(zones(&["fd00:150::/62"]).names(), quarter);
        // A host part in the range is ignored.
        assert_eq!(zones(&["10.150.7.9/16"]).names(), ["150.10.in-addr.arpa"]);
    }

    #[test]
    fn only_private_ranges_from_8_and_7_bits() {
        // fc00::/7 is the private block itself: two zones of /8.
        assert_eq!(
            zones(&["fc00::/7"]).names(),
            ["c.f.ip6.arpa", "d.f.ip6.arpa"]
        );
        // Wider ranges count only where they meet the private list.
        assert_eq!(zones(&["::/0"]).names(), ["c.f.ip6.arpa", "d.f.ip6.arpa"]);
        let all_v4 = zones(&["0.0.0.0/0"]);
        assert_eq!(
            all_v4.names()[..3],
            [
                "10.in-addr.arpa",
                "16.172.in-addr.arpa",
                "17.172.in-addr.arpa"
            ]
        );
        assert_eq!(all_v4.names().len(), 1 + 16 + 1 + 64);
        assert_eq!(zones(&["10.0.0.0/7"]).names(), ["10.in-addr.arpa"]);
        // Public, loopback and link-local ranges give none.
        for range in [
            "8.8.8.0/24",
            "127.0.0.0/8",
            "169.254.0.0/16",
            "2001:db8::/32",
            "fe80::/10",
        ] {
            assert!(zones(&[range]).names().is_empty(), "{range}");
        }
    }

    #[test]
    fn duplicates_and_nested_ranges_count_once() {
        let nested = zones(&["10.150.0.0/16", "10.150.5.0/24", "10.150.0.0/16"]);
        assert_eq!(nested.names(), ["150.10.in-addr.arpa"]);
        assert_eq!(nested.truncated(), 0);
    }

    #[test]
    fn at_most_256_zones_in_range_order() {
        let many = zones(&[
            "10.0.0.0/9",
            "10.128.0.0/9",
            "192.168.0.0/16",
            "172.16.0.0/12",
        ]);
        assert_eq!(many.names().len(), MAX_REVERSE_ZONES);
        assert_eq!(many.names()[0], "0.10.in-addr.arpa");
        assert_eq!(many.names()[255], "255.10.in-addr.arpa");
        // 192.168/16 (1 zone) and 172.16/12 (16 zones) are left out.
        assert_eq!(many.truncated(), 17);
    }

    #[test]
    fn finds_the_zone_of_a_name() {
        let zones = zones(&["10.150.0.0/16"]);
        let labels = |name: &str| -> Vec<Vec<u8>> {
            name.split('.')
                .map(|label| label.as_bytes().to_vec())
                .collect()
        };
        assert!(zones.zone_of(&labels("7.0.150.10.in-addr.arpa")).is_some());
        assert!(zones.zone_of(&labels("150.10.in-addr.arpa")).is_some());
        assert!(zones.zone_of(&labels("10.in-addr.arpa")).is_none());
        assert!(zones.zone_of(&labels("7.0.151.10.in-addr.arpa")).is_none());
    }
}
