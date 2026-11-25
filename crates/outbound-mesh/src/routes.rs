//! The route table: which peer carries which intranet address.
//!
//! A peer contributes its virtual addresses and the subnets it advertises.
//! Every entry passes the intranet scope of [`crate::scope`], so nothing a
//! peer says can route public traffic into the mesh. Outgoing traffic is
//! checked with [`RouteTable::lookup`] or [`RouteTable::check_outgoing`]
//! before it is handed to any session; packets a peer delivers are checked
//! with [`RouteTable::check_incoming`], which drops spoofed sources and
//! anything not addressed to this node's stack (the node is never an exit;
//! relaying for other peers happens on mesh frames in the session layer).
//!
//! A [`PeerId`] here is the peer that owns an address, not the next hop: when
//! a packet travels through relay peers, the session layer resolves the path
//! to the owner and reports the originating peer of what it delivers. Path
//! choice (lowest latency or fewest hops, or a path the user fixed) belongs
//! to that layer; a custom path for a subnet first finds the owner here by
//! longest prefix and then uses that owner's path policy.

use std::collections::BTreeMap;
use std::fmt;
use std::net::IpAddr;

use crate::config::MeshSettings;
use crate::net::IpNet;
use crate::packet::{self, Malformed};
use crate::scope::{is_intranet_address, is_intranet_network};

/// Most subnets one peer may advertise; the rest are refused.
pub const MAX_SUBNETS_PER_PEER: usize = 256;
/// Most virtual addresses one peer may claim.
pub const MAX_ADDRESSES_PER_PEER: usize = 4;

/// A peer as the session layer identifies it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PeerId(pub u64);

/// Why traffic or a route was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Denied {
    /// The address or network is outside the intranet ranges.
    NotIntranet,
    /// One of this node's own addresses.
    Local,
    /// Intranet, but no peer carries it.
    NoRoute,
    /// Outside the `allowed_subnets` the user configured.
    NotAllowed,
    /// A virtual address outside the virtual subnets, or a subnet that
    /// overlaps them.
    VirtualSubnet,
    /// Another peer already holds this virtual address.
    Conflict,
    /// The peer advertised more than its share.
    TooMany,
    /// A delivered packet whose source the peer does not own.
    Spoofed,
    /// A delivered packet not addressed to this node.
    NotForUs,
    /// A packet whose source is not this node.
    ForeignSource,
    Malformed(Malformed),
}

impl fmt::Display for Denied {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Denied::NotIntranet => "destination is outside the mesh's intranet ranges",
            Denied::Local => "destination is this mesh node",
            Denied::NoRoute => "no mesh peer carries this destination",
            Denied::NotAllowed => "destination is outside the configured allowed_subnets",
            Denied::VirtualSubnet => "address conflicts with the virtual subnet",
            Denied::Conflict => "virtual address is held by another peer",
            Denied::TooMany => "peer advertised too many routes",
            Denied::Spoofed => "packet source does not belong to the delivering peer",
            Denied::NotForUs => "packet is not addressed to this mesh node",
            Denied::ForeignSource => "packet source is not this mesh node",
            Denied::Malformed(_) => "malformed IP packet",
        })
    }
}

impl std::error::Error for Denied {}

/// What [`RouteTable::set_peer`] kept and what it refused.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct PeerUpdate {
    pub addresses: Vec<IpAddr>,
    pub subnets: Vec<IpNet>,
    pub refused_addresses: Vec<(IpAddr, Denied)>,
    pub refused_subnets: Vec<(IpNet, Denied)>,
}

#[derive(Default)]
struct PeerRoutes {
    addresses: Vec<IpAddr>,
    /// Subnets with the order they were first accepted in, which breaks
    /// ties between peers advertising the same subnet.
    subnets: Vec<(IpNet, u64)>,
}

pub struct RouteTable {
    local: Vec<IpAddr>,
    virtual_subnets: Vec<IpNet>,
    allowed: Vec<IpNet>,
    peers: BTreeMap<PeerId, PeerRoutes>,
    next_order: u64,
}

impl RouteTable {
    pub fn new(settings: &MeshSettings) -> Self {
        Self {
            local: settings.local_addresses(),
            virtual_subnets: settings.virtual_subnets(),
            allowed: settings.allowed_subnets.clone(),
            peers: BTreeMap::new(),
            next_order: 0,
        }
    }

    /// Replaces everything `peer` advertises. Entries that fail a check are
    /// refused one by one; the rest take effect.
    pub fn set_peer(
        &mut self,
        peer: PeerId,
        addresses: &[IpAddr],
        subnets: &[IpNet],
    ) -> PeerUpdate {
        let previous = self.peers.remove(&peer).unwrap_or_default();
        let mut update = PeerUpdate::default();
        let mut routes = PeerRoutes::default();

        for &address in addresses {
            let verdict = if routes.addresses.len() >= MAX_ADDRESSES_PER_PEER {
                Err(Denied::TooMany)
            } else {
                self.admit_address(address)
            };
            match verdict {
                Ok(()) if routes.addresses.contains(&address) => {}
                Ok(()) => {
                    routes.addresses.push(address);
                    update.addresses.push(address);
                }
                Err(denied) => update.refused_addresses.push((address, denied)),
            }
        }

        for subnet in subnets {
            let subnet = subnet.trunc();
            let verdict = if routes.subnets.len() >= MAX_SUBNETS_PER_PEER {
                Err(Denied::TooMany)
            } else {
                self.admit_subnet(&subnet)
            };
            match verdict {
                Ok(()) if routes.subnets.iter().any(|(held, _)| *held == subnet) => {}
                Ok(()) => {
                    let order = previous
                        .subnets
                        .iter()
                        .find(|(held, _)| *held == subnet)
                        .map(|(_, order)| *order)
                        .unwrap_or_else(|| {
                            self.next_order += 1;
                            self.next_order
                        });
                    routes.subnets.push((subnet, order));
                    update.subnets.push(subnet);
                }
                Err(denied) => update.refused_subnets.push((subnet, denied)),
            }
        }

        self.peers.insert(peer, routes);
        update
    }

    /// Forgets a peer and everything it advertised.
    pub fn remove_peer(&mut self, peer: PeerId) {
        self.peers.remove(&peer);
    }

    pub fn peer_count(&self) -> usize {
        self.peers.len()
    }

    fn admit_address(&self, address: IpAddr) -> Result<(), Denied> {
        if !is_intranet_address(address) {
            return Err(Denied::NotIntranet);
        }
        if self.local.contains(&address) {
            return Err(Denied::Local);
        }
        let subnet = self
            .virtual_subnets
            .iter()
            .find(|subnet| subnet.contains(address))
            .ok_or(Denied::VirtualSubnet)?;
        if address == subnet.network() {
            return Err(Denied::VirtualSubnet);
        }
        if self
            .peers
            .values()
            .any(|peer| peer.addresses.contains(&address))
        {
            return Err(Denied::Conflict);
        }
        Ok(())
    }

    fn admit_subnet(&self, subnet: &IpNet) -> Result<(), Denied> {
        if !is_intranet_network(subnet) {
            return Err(Denied::NotIntranet);
        }
        if self.virtual_subnets.iter().any(|own| own.overlaps(subnet)) {
            return Err(Denied::VirtualSubnet);
        }
        if !self.allowed.is_empty() && !self.allowed.iter().any(|allowed| allowed.covers(subnet)) {
            return Err(Denied::NotAllowed);
        }
        Ok(())
    }

    /// The peer that carries `destination`: the holder of a virtual address,
    /// else the longest advertised subnet (the earliest advertised wins a
    /// tie).
    pub fn lookup(&self, destination: IpAddr) -> Result<PeerId, Denied> {
        let destination = unmap(destination);
        if !is_intranet_address(destination) {
            return Err(Denied::NotIntranet);
        }
        if self.local.contains(&destination) {
            return Err(Denied::Local);
        }
        if self
            .virtual_subnets
            .iter()
            .any(|subnet| subnet.contains(destination))
        {
            return self
                .peers
                .iter()
                .find(|(_, routes)| routes.addresses.contains(&destination))
                .map(|(peer, _)| *peer)
                .ok_or(Denied::NoRoute);
        }
        if !self.allowed.is_empty() && !self.allowed.iter().any(|net| net.contains(destination)) {
            return Err(Denied::NotAllowed);
        }
        self.peers
            .iter()
            .flat_map(|(peer, routes)| routes.subnets.iter().map(move |entry| (*peer, entry)))
            .filter(|(_, (subnet, _))| subnet.contains(destination))
            .max_by(|(_, (a, a_order)), (_, (b, b_order))| {
                a.prefix().cmp(&b.prefix()).then(b_order.cmp(a_order))
            })
            .map(|(peer, _)| peer)
            .ok_or(Denied::NoRoute)
    }

    /// Checks a packet this node is about to send: it must come from one of
    /// this node's virtual addresses and go to a routed intranet address.
    pub fn check_outgoing(&self, packet: &[u8]) -> Result<PeerId, Denied> {
        let addresses = packet::addresses(packet).map_err(Denied::Malformed)?;
        if !self.local.contains(&addresses.source) {
            return Err(Denied::ForeignSource);
        }
        self.lookup(addresses.destination)
    }

    /// Checks a packet `peer` delivered: its source must be one of the
    /// peer's virtual addresses or inside a subnet the peer advertised, and
    /// it must be addressed to this node.
    pub fn check_incoming(&self, peer: PeerId, packet: &[u8]) -> Result<(), Denied> {
        let addresses = packet::addresses(packet).map_err(Denied::Malformed)?;
        if !self.local.contains(&addresses.destination) {
            return Err(Denied::NotForUs);
        }
        let routes = self.peers.get(&peer).ok_or(Denied::Spoofed)?;
        let source = addresses.source;
        let owned = routes.addresses.contains(&source)
            || routes
                .subnets
                .iter()
                .any(|(subnet, _)| subnet.contains(source));
        if owned {
            Ok(())
        } else {
            Err(Denied::Spoofed)
        }
    }
}

fn unmap(address: IpAddr) -> IpAddr {
    match address {
        IpAddr::V6(v6) => v6
            .to_ipv4_mapped()
            .map(IpAddr::V4)
            .unwrap_or(IpAddr::V6(v6)),
        v4 => v4,
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::config::MeshConfig;
    use crate::packet::tests::{ipv4, ipv6};

    fn settings(extra: serde_json::Value) -> MeshSettings {
        let mut config = json!({
            "network_name": "office",
            "network_secret": "s3cret",
            "address": "10.144.144.5/24",
            "address_v6": "fd00:aa::5/64",
            "peers": [{"server": "peer.example", "port": 40000}],
        });
        for (key, value) in extra.as_object().unwrap() {
            config[key] = value.clone();
        }
        serde_json::from_value::<MeshConfig>(config)
            .unwrap()
            .validate()
            .unwrap()
    }

    fn ip(text: &str) -> IpAddr {
        text.parse().unwrap()
    }

    fn net(text: &str) -> IpNet {
        IpNet::parse(text).unwrap()
    }

    const A: PeerId = PeerId(1);
    const B: PeerId = PeerId(2);

    #[test]
    fn routes_virtual_addresses_and_advertised_subnets() {
        let mut table = RouteTable::new(&settings(json!({})));
        let update = table.set_peer(A, &[ip("10.144.144.6")], &[net("192.168.10.0/24")]);
        assert!(update.refused_addresses.is_empty() && update.refused_subnets.is_empty());
        table.set_peer(
            B,
            &[ip("10.144.144.7"), ip("fd00:aa::7")],
            &[net("192.168.0.0/16")],
        );

        assert_eq!(table.lookup(ip("10.144.144.6")), Ok(A));
        assert_eq!(table.lookup(ip("fd00:aa::7")), Ok(B));
        assert_eq!(table.lookup(ip("::ffff:10.144.144.7")), Ok(B));
        // Longest prefix wins.
        assert_eq!(table.lookup(ip("192.168.10.20")), Ok(A));
        assert_eq!(table.lookup(ip("192.168.20.20")), Ok(B));
        // Inside the virtual subnet but held by nobody.
        assert_eq!(table.lookup(ip("10.144.144.99")), Err(Denied::NoRoute));
        assert_eq!(table.lookup(ip("172.16.0.1")), Err(Denied::NoRoute));
        assert_eq!(table.lookup(ip("10.144.144.5")), Err(Denied::Local));
    }

    #[test]
    fn never_routes_public_destinations() {
        let mut table = RouteTable::new(&settings(json!({})));
        let update = table.set_peer(
            A,
            &[ip("10.144.144.6"), ip("8.8.8.8")],
            &[
                net("0.0.0.0/0"),
                net("::/0"),
                net("1.1.1.0/24"),
                net("10.0.0.0/7"),
            ],
        );
        assert_eq!(
            update.refused_addresses,
            vec![(ip("8.8.8.8"), Denied::NotIntranet)]
        );
        assert_eq!(update.refused_subnets.len(), 4);
        assert!(update
            .refused_subnets
            .iter()
            .all(|(_, denied)| *denied == Denied::NotIntranet));
        for destination in [
            "8.8.8.8",
            "1.1.1.1",
            "2606:4700::1111",
            "127.0.0.1",
            "169.254.1.1",
        ] {
            assert_eq!(
                table.lookup(ip(destination)),
                Err(Denied::NotIntranet),
                "{destination}"
            );
        }
    }

    #[test]
    fn refuses_virtual_subnet_abuse_and_conflicts() {
        let mut table = RouteTable::new(&settings(json!({})));
        table.set_peer(A, &[ip("10.144.144.6")], &[]);
        let update = table.set_peer(
            B,
            &[
                ip("10.144.144.6"),
                ip("10.144.144.5"),
                ip("10.144.144.0"),
                ip("10.9.9.9"),
            ],
            &[net("10.144.0.0/16"), net("10.144.144.128/25")],
        );
        assert_eq!(
            update.refused_addresses,
            vec![
                (ip("10.144.144.6"), Denied::Conflict),
                (ip("10.144.144.5"), Denied::Local),
                (ip("10.144.144.0"), Denied::VirtualSubnet),
                (ip("10.9.9.9"), Denied::VirtualSubnet),
            ]
        );
        assert_eq!(
            update.refused_subnets,
            vec![
                (net("10.144.0.0/16"), Denied::VirtualSubnet),
                (net("10.144.144.128/25"), Denied::VirtualSubnet),
            ]
        );
        assert_eq!(table.lookup(ip("10.144.144.6")), Ok(A));
    }

    #[test]
    fn allowed_subnets_narrow_what_is_accepted() {
        let mut table = RouteTable::new(&settings(json!({"allowed_subnets": ["192.168.10.0/24"]})));
        let update = table.set_peer(
            A,
            &[ip("10.144.144.6")],
            &[net("192.168.0.0/16"), net("192.168.10.0/25")],
        );
        assert_eq!(update.subnets, vec![net("192.168.10.0/25")]);
        assert_eq!(
            update.refused_subnets,
            vec![(net("192.168.0.0/16"), Denied::NotAllowed)]
        );
        assert_eq!(table.lookup(ip("192.168.10.1")), Ok(A));
        assert_eq!(table.lookup(ip("192.168.10.200")), Err(Denied::NoRoute));
        assert_eq!(table.lookup(ip("192.168.11.1")), Err(Denied::NotAllowed));
        // Virtual addresses are always reachable.
        assert_eq!(table.lookup(ip("10.144.144.6")), Ok(A));
    }

    #[test]
    fn earliest_advertiser_wins_a_tie_and_keeps_its_place() {
        let mut table = RouteTable::new(&settings(json!({})));
        table.set_peer(B, &[], &[net("192.168.5.0/24")]);
        table.set_peer(A, &[], &[net("192.168.5.0/24")]);
        assert_eq!(table.lookup(ip("192.168.5.1")), Ok(B));
        // Re-advertising the same subnet keeps B first.
        table.set_peer(B, &[], &[net("192.168.5.0/24"), net("192.168.6.0/24")]);
        assert_eq!(table.lookup(ip("192.168.5.1")), Ok(B));
        table.remove_peer(B);
        assert_eq!(table.lookup(ip("192.168.5.1")), Ok(A));
        assert_eq!(table.peer_count(), 1);
    }

    #[test]
    fn caps_what_one_peer_may_advertise() {
        let mut table = RouteTable::new(&settings(json!({})));
        // 172.16.0.0/24, 172.16.1.0/24, ... one more than the cap.
        let subnets: Vec<IpNet> = (0..=MAX_SUBNETS_PER_PEER as u32)
            .map(|i| IpNet::new(IpAddr::V4((0xac10_0000 | (i << 8)).into()), 24).unwrap())
            .collect();
        let update = table.set_peer(A, &[], &subnets);
        assert_eq!(update.subnets.len(), MAX_SUBNETS_PER_PEER);
        assert_eq!(
            update.refused_subnets,
            vec![(subnets[MAX_SUBNETS_PER_PEER], Denied::TooMany)]
        );
        let addresses: Vec<IpAddr> = (10..20).map(|i| ip(&format!("10.144.144.{i}"))).collect();
        let update = table.set_peer(B, &addresses, &[]);
        assert_eq!(update.addresses.len(), MAX_ADDRESSES_PER_PEER);
    }

    #[test]
    fn outgoing_packets_must_come_from_this_node() {
        let mut table = RouteTable::new(&settings(json!({})));
        table.set_peer(A, &[ip("10.144.144.6")], &[]);
        assert_eq!(
            table.check_outgoing(&ipv4([10, 144, 144, 5], [10, 144, 144, 6], 0)),
            Ok(A)
        );
        assert_eq!(
            table.check_outgoing(&ipv4([10, 144, 144, 9], [10, 144, 144, 6], 0)),
            Err(Denied::ForeignSource)
        );
        assert_eq!(
            table.check_outgoing(&ipv4([10, 144, 144, 5], [8, 8, 8, 8], 0)),
            Err(Denied::NotIntranet)
        );
        assert!(matches!(
            table.check_outgoing(&[0x45]),
            Err(Denied::Malformed(_))
        ));
    }

    #[test]
    fn incoming_packets_drop_spoofed_and_transit_traffic() {
        let mut table = RouteTable::new(&settings(json!({})));
        table.set_peer(
            A,
            &[ip("10.144.144.6"), ip("fd00:aa::6")],
            &[net("192.168.10.0/24")],
        );
        table.set_peer(B, &[ip("10.144.144.7")], &[]);

        let to_us = |source: [u8; 4]| ipv4(source, [10, 144, 144, 5], 4);
        assert_eq!(table.check_incoming(A, &to_us([10, 144, 144, 6])), Ok(()));
        assert_eq!(table.check_incoming(A, &to_us([192, 168, 10, 9])), Ok(()));
        assert_eq!(
            table.check_incoming(
                A,
                &ipv6(
                    "fd00:aa::6".parse().unwrap(),
                    "fd00:aa::5".parse().unwrap(),
                    0
                )
            ),
            Ok(())
        );
        // B's address, delivered by A.
        assert_eq!(
            table.check_incoming(A, &to_us([10, 144, 144, 7])),
            Err(Denied::Spoofed)
        );
        // Public source.
        assert_eq!(
            table.check_incoming(A, &to_us([8, 8, 8, 8])),
            Err(Denied::Spoofed)
        );
        // Unknown peer.
        assert_eq!(
            table.check_incoming(PeerId(9), &to_us([10, 144, 144, 6])),
            Err(Denied::Spoofed)
        );
        // Transit through this node is never allowed.
        assert_eq!(
            table.check_incoming(A, &ipv4([10, 144, 144, 6], [10, 144, 144, 7], 0)),
            Err(Denied::NotForUs)
        );
        assert_eq!(
            table.check_incoming(A, &ipv4([10, 144, 144, 6], [1, 1, 1, 1], 0)),
            Err(Denied::NotForUs)
        );
    }
}
