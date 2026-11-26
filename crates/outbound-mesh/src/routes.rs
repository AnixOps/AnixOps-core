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
//! The one exception is a border node (spec §15.6, §17.3): it advertises
//! the other regions' summary prefixes ([`RouteTable::set_border`]), takes
//! packets addressed to them for the backbone, and sends packets from them
//! that the backbone delivered ([`RouteTable::classify_from_backbone`]).
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
pub struct PeerId(pub u32);

/// Where an outgoing packet goes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outgoing {
    Peer(PeerId),
    /// A copy to every direct neighbour (spec §15.3).
    Neighbours,
}

/// Why traffic or a route was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Denied {
    /// The address or network is outside the intranet ranges.
    NotIntranet,
    /// One of this node's own addresses.
    Local,
    /// Intranet, but no peer carries it.
    NoRoute,
    /// Outside the `subnets.accept` the user configured.
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
    /// A subnet that overlaps one of this node's own networks: the subnets
    /// it advertises or the networks of its interfaces (spec §15.4). Such a
    /// subnet is kept and shown as a conflict, but neither routed nor
    /// installed as a system route, which would take traffic away from the
    /// local network; see [`RouteTable::local_conflicts`].
    LocalNetwork,
    Malformed(Malformed),
}

impl fmt::Display for Denied {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Denied::NotIntranet => "destination is outside the mesh's intranet ranges",
            Denied::Local => "destination is this mesh node",
            Denied::NoRoute => "no mesh peer carries this destination",
            Denied::NotAllowed => "destination is outside the configured subnets.accept",
            Denied::VirtualSubnet => "address conflicts with the virtual subnet",
            Denied::Conflict => "virtual address is held by another peer",
            Denied::TooMany => "peer advertised too many routes",
            Denied::Spoofed => "packet source does not belong to the delivering peer",
            Denied::NotForUs => "packet is not addressed to this mesh node",
            Denied::ForeignSource => "packet source is not this mesh node",
            Denied::LocalNetwork => "subnet overlaps a network of this node",
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
    /// Kept in `subnets` but not routed: they overlap a network of this
    /// node ([`Denied::LocalNetwork`]).
    pub local_conflicts: Vec<IpNet>,
}

#[derive(Default)]
struct PeerRoutes {
    addresses: Vec<IpAddr>,
    subnets: Vec<IpNet>,
    /// Subnets of the peer's last advertisement that were refused.
    refused_subnets: u64,
    /// This node's own virtual addresses the peer also claims (R29).
    claims_local: Vec<IpAddr>,
}

/// What one peer contributes to the table, for the status.
#[derive(Clone, Copy, Debug)]
pub struct PeerView<'a> {
    /// Its virtual addresses, as accepted.
    pub addresses: &'a [IpAddr],
    /// The subnets it advertises, as accepted (routed or not).
    pub subnets: &'a [IpNet],
}

pub struct RouteTable {
    local: Vec<IpAddr>,
    virtual_subnets: Vec<IpNet>,
    allowed: Vec<IpNet>,
    /// Subnets this node advertises; never accepted from a peer.
    advertised: Vec<IpNet>,
    /// Networks of this node's interfaces, as the driver reports them.
    interfaces: Vec<IpNet>,
    /// Advertised subnets the user chose to reach through the mesh even
    /// though they overlap an interface network.
    mesh_overrides: Vec<IpNet>,
    /// Other regions' summary prefixes this border node carries to the
    /// backbone; advertised like `advertised` and never accepted from a peer.
    border: Vec<IpNet>,
    peers: BTreeMap<PeerId, PeerRoutes>,
}

impl RouteTable {
    pub fn new(settings: &MeshSettings) -> Self {
        Self {
            local: settings.local_addresses(),
            virtual_subnets: settings.virtual_subnets(),
            allowed: settings.accept_subnets.clone(),
            advertised: settings.advertise_subnets.clone(),
            interfaces: Vec::new(),
            mesh_overrides: Vec::new(),
            border: Vec::new(),
            peers: BTreeMap::new(),
        }
    }

    /// Sets the other regions' summary prefixes this border node carries
    /// (empty: none, the backbone is down or this is no border node). Only
    /// intranet prefixes outside this network's virtual subnets are kept,
    /// and no more than the members accept from one peer together with the
    /// subnets this node advertises itself ([`MAX_SUBNETS_PER_PEER`]).
    /// Returns how many usable prefixes were left out by that limit.
    pub fn set_border(&mut self, prefixes: &[IpNet]) -> usize {
        let mut border: Vec<IpNet> = prefixes
            .iter()
            .map(IpNet::trunc)
            .filter(|net| {
                is_intranet_network(net)
                    && !self.virtual_subnets.iter().any(|own| own.overlaps(net))
            })
            .collect();
        border.sort();
        border.dedup();
        let room = MAX_SUBNETS_PER_PEER.saturating_sub(self.advertised.len());
        let left_out = border.len().saturating_sub(room);
        border.truncate(room);
        self.border = border;
        left_out
    }

    /// The prefixes [`set_border`](Self::set_border) kept.
    pub fn border(&self) -> &[IpNet] {
        &self.border
    }

    fn in_border(&self, address: IpAddr) -> bool {
        let address = unmap(address);
        self.border.iter().any(|net| net.contains(address))
    }

    /// Whether a packet [`check_incoming`](Self::check_incoming) accepted
    /// goes to the backbone rather than to this node's interface.
    pub fn for_backbone(&self, packet: &[u8]) -> bool {
        packet::addresses(packet).is_ok_and(|addresses| {
            !self.is_ours(unmap(addresses.destination)) && self.in_border(addresses.destination)
        })
    }

    /// Sets the networks of this node's interfaces and the subnets the user
    /// routes through the mesh anyway (`mesh_set_subnet_route`). Accepted
    /// subnets that now overlap stop being routed at once and start again
    /// when the overlap is gone; the conflicts are returned for the status.
    pub fn set_local_networks(
        &mut self,
        interfaces: &[IpNet],
        mesh_overrides: &[IpNet],
    ) -> Vec<(PeerId, IpNet)> {
        self.interfaces = interfaces.iter().map(IpNet::trunc).collect();
        self.mesh_overrides = mesh_overrides.iter().map(IpNet::trunc).collect();
        self.local_conflicts()
    }

    /// Accepted subnets that overlap a network of this node (spec §15.4):
    /// shown as conflicts, not routed, not installed as system routes.
    pub fn local_conflicts(&self) -> Vec<(PeerId, IpNet)> {
        self.peers
            .iter()
            .flat_map(|(peer, routes)| routes.subnets.iter().map(move |subnet| (*peer, *subnet)))
            .filter(|(_, subnet)| !self.routable(subnet))
            .collect()
    }

    /// The subnets to install as system routes: every accepted subnet that
    /// is routed, once each. The driver further limits them to
    /// `routing.system_routes`.
    pub fn system_routes(&self) -> Vec<IpNet> {
        let mut routes: Vec<IpNet> = self
            .peers
            .values()
            .flat_map(|routes| routes.subnets.iter().copied())
            .filter(|subnet| self.routable(subnet))
            .collect();
        routes.sort_by_key(|subnet| subnet.to_string());
        routes.dedup();
        routes
    }

    fn routable(&self, subnet: &IpNet) -> bool {
        !self.overlaps_local(subnet)
    }

    fn overlaps_local(&self, subnet: &IpNet) -> bool {
        if self
            .advertised
            .iter()
            .chain(&self.border)
            .any(|own| own.overlaps(subnet))
        {
            return true;
        }
        self.interfaces.iter().any(|own| own.overlaps(subnet))
            && !self.mesh_overrides.contains(subnet)
    }

    /// Replaces everything `peer` advertises. Entries that fail a check are
    /// refused one by one; the rest take effect.
    pub fn set_peer(
        &mut self,
        peer: PeerId,
        addresses: &[IpAddr],
        subnets: &[IpNet],
    ) -> PeerUpdate {
        self.peers.remove(&peer);
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
                Err(denied) => {
                    if denied == Denied::Local {
                        routes.claims_local.push(address);
                    }
                    update.refused_addresses.push((address, denied));
                }
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
                Ok(()) if routes.subnets.contains(&subnet) => {}
                Ok(()) => {
                    if !self.routable(&subnet) {
                        update.local_conflicts.push(subnet);
                    }
                    routes.subnets.push(subnet);
                    update.subnets.push(subnet);
                }
                Err(denied) => {
                    routes.refused_subnets += 1;
                    update.refused_subnets.push((subnet, denied));
                }
            }
        }

        self.peers.insert(peer, routes);
        update
    }

    /// Peers with routes in the table.
    pub fn peers(&self) -> impl Iterator<Item = PeerId> + '_ {
        self.peers.keys().copied()
    }

    /// Forgets a peer and everything it advertised.
    pub fn remove_peer(&mut self, peer: PeerId) {
        self.peers.remove(&peer);
    }

    pub fn peer_count(&self) -> usize {
        self.peers.len()
    }

    /// What `peer` contributes, if it is in the table.
    pub fn peer(&self, peer: PeerId) -> Option<PeerView<'_>> {
        self.peers.get(&peer).map(|routes| PeerView {
            addresses: &routes.addresses,
            subnets: &routes.subnets,
        })
    }

    /// Subnets refused from the peers' current advertisements: outside
    /// the intranet ranges, the accepted subnets or the virtual subnets,
    /// or past a peer's share (R16, R17).
    pub fn refused_subnet_count(&self) -> u64 {
        self.peers
            .values()
            .map(|routes| routes.refused_subnets)
            .sum()
    }

    /// Peers that claim one of this node's own virtual addresses (R29).
    pub fn address_conflicts(&self) -> Vec<(PeerId, IpAddr)> {
        self.peers
            .iter()
            .flat_map(|(peer, routes)| {
                routes
                    .claims_local
                    .iter()
                    .map(move |address| (*peer, *address))
            })
            .collect()
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
        // The network and broadcast addresses are nobody's (spec §15.3).
        if !subnet.is_host(address) {
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
        // Overlap with this node's own networks is kept, as a conflict
        // (spec §15.4); the same subnet as this node advertises is how
        // several advertisers are detected (spec §15.4, R16).
        Ok(())
    }

    /// The peer that owns `destination` (spec §15.2): the holder of a virtual
    /// address, else the longest advertised subnet; among peers advertising
    /// that subnet, the fewest hops away and then the smallest ID. `hops`
    /// gives a peer's distance, `None` when it is unreachable (it is then
    /// skipped).
    pub fn lookup_by(
        &self,
        destination: IpAddr,
        hops: impl Fn(PeerId) -> Option<u32>,
    ) -> Result<PeerId, Denied> {
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
            .flat_map(|(peer, routes)| routes.subnets.iter().map(move |subnet| (*peer, subnet)))
            .filter(|(_, subnet)| subnet.contains(destination) && self.routable(subnet))
            .filter_map(|(peer, subnet)| Some((peer, subnet.prefix(), hops(peer)?)))
            // Longest prefix, then fewest hops, then smallest ID.
            .min_by_key(|(peer, prefix, hops)| (std::cmp::Reverse(*prefix), *hops, *peer))
            .map(|(peer, _, _)| peer)
            .ok_or(Denied::NoRoute)
    }

    /// [`lookup_by`](Self::lookup_by) with every peer at the same distance.
    pub fn lookup(&self, destination: IpAddr) -> Result<PeerId, Denied> {
        self.lookup_by(destination, |_| Some(0))
    }

    /// Destinations every direct neighbour gets a copy of (spec §15.3):
    /// multicast, the limited broadcast and the broadcast address of the
    /// IPv4 virtual subnet (/30 and wider).
    pub fn is_flood(&self, address: IpAddr) -> bool {
        match unmap(address) {
            IpAddr::V4(v4) => {
                v4.is_multicast()
                    || v4.is_broadcast()
                    || self.virtual_subnets.iter().any(|subnet| {
                        subnet.is_ipv4()
                            && subnet.prefix() <= 30
                            && subnet.contains(IpAddr::V4(v4))
                            && !subnet.is_host(IpAddr::V4(v4))
                            && IpAddr::V4(v4) != subnet.network()
                    })
            }
            IpAddr::V6(v6) => v6.is_multicast(),
        }
    }

    /// Where a packet this node is about to send goes: one peer
    /// ([`check_outgoing`](Self::check_outgoing)), or every direct
    /// neighbour for a broadcast or multicast destination. A broadcast or
    /// multicast must come from one of this node's virtual addresses (spec
    /// §15.3); a unicast may also come from a subnet this node advertises.
    pub fn classify_outgoing(&self, packet: &[u8]) -> Result<Outgoing, Denied> {
        let addresses = packet::addresses(packet).map_err(Denied::Malformed)?;
        if self.is_flood(addresses.destination) {
            if !self.local.contains(&addresses.source) {
                return Err(Denied::ForeignSource);
            }
            return Ok(Outgoing::Neighbours);
        }
        self.check_outgoing(packet).map(Outgoing::Peer)
    }

    /// Checks a unicast packet this node is about to send: it must come from
    /// one of this node's virtual addresses or a subnet it advertises, and go
    /// to a routed intranet address.
    pub fn check_outgoing(&self, packet: &[u8]) -> Result<PeerId, Denied> {
        let addresses = packet::addresses(packet).map_err(Denied::Malformed)?;
        if !self.is_ours(unmap(addresses.source)) {
            return Err(Denied::ForeignSource);
        }
        self.lookup(addresses.destination)
    }

    /// Where a packet the backbone delivered goes (spec §17.3.6): its source
    /// lies in another region's summary prefix this node carries, and its
    /// destination is a routed address of this network, never a flood and
    /// never back into the border prefixes.
    pub fn classify_from_backbone(&self, packet: &[u8]) -> Result<PeerId, Denied> {
        let addresses = packet::addresses(packet).map_err(Denied::Malformed)?;
        if !self.in_border(addresses.source) {
            return Err(Denied::ForeignSource);
        }
        if self.in_border(addresses.destination) || self.is_flood(addresses.destination) {
            return Err(Denied::NoRoute);
        }
        self.lookup(addresses.destination)
    }

    /// Whether `address` is this node's: one of its virtual addresses, or
    /// inside a subnet it advertises (a full node proxying its LAN: the
    /// interface forwards those packets on, and replies from the LAN leave
    /// with their own source address).
    fn is_ours(&self, address: IpAddr) -> bool {
        self.local.contains(&address)
            || self
                .advertised
                .iter()
                .any(|subnet| subnet.contains(address))
    }

    /// Checks a packet `peer` delivered: it must be addressed to this node or
    /// a subnet it advertises (or be a broadcast or multicast,
    /// [`is_flood`](Self::is_flood)),
    /// and its source must belong to `peer` by the same rule outgoing
    /// traffic is routed with (a reverse-path check). The source is one of
    /// the peer's virtual addresses, or lies in the longest advertised subnet
    /// that contains it and the peer is one of that subnet's advertisers. A
    /// peer advertising a wider subnet cannot use the source addresses of a
    /// narrower subnet another peer advertises.
    pub fn check_incoming(&self, peer: PeerId, packet: &[u8]) -> Result<(), Denied> {
        let addresses = packet::addresses(packet).map_err(Denied::Malformed)?;
        if !self.is_ours(unmap(addresses.destination))
            && !self.is_flood(addresses.destination)
            && !self.in_border(addresses.destination)
        {
            return Err(Denied::NotForUs);
        }
        let routes = self.peers.get(&peer).ok_or(Denied::Spoofed)?;
        let source = unmap(addresses.source);
        if routes.addresses.contains(&source) {
            return Ok(());
        }
        if self
            .virtual_subnets
            .iter()
            .any(|subnet| subnet.contains(source))
        {
            return Err(Denied::Spoofed);
        }
        let longest = self
            .peers
            .values()
            .flat_map(|routes| routes.subnets.iter())
            .filter(|subnet| subnet.contains(source) && self.routable(subnet))
            .map(IpNet::prefix)
            .max();
        let owned = longest.is_some_and(|longest| {
            routes.subnets.iter().any(|subnet| {
                subnet.prefix() == longest && subnet.contains(source) && self.routable(subnet)
            })
        });
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
            "config_version": 1,
            "network": {"name": "office", "secret": "s3cret"},
            "node": {"address": "10.144.144.5/24", "address_v6": "fd00:aa::5/64", "role": "access"},
            "peers": [{"server": "peer.example"}],
        });
        if let Some(accept) = extra.get("accept") {
            config["subnets"] = json!({"accept": accept});
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
    fn the_status_view_counts_refusals_and_claims_on_own_addresses() {
        let mut table = RouteTable::new(&settings(json!({})));
        table.set_peer(
            A,
            &[ip("10.144.144.5"), ip("10.144.144.6")],
            &[net("192.168.10.0/24"), net("8.8.8.0/24")],
        );
        table.set_peer(B, &[ip("10.144.144.7")], &[net("0.0.0.0/0")]);
        let view = table.peer(A).unwrap();
        assert_eq!(view.addresses, [ip("10.144.144.6")]);
        assert_eq!(view.subnets, [net("192.168.10.0/24")]);
        assert_eq!(table.refused_subnet_count(), 2);
        assert_eq!(table.address_conflicts(), [(A, ip("10.144.144.5"))]);

        // A new advertisement replaces the old counts.
        table.set_peer(A, &[ip("10.144.144.6")], &[]);
        table.remove_peer(B);
        assert_eq!(table.refused_subnet_count(), 0);
        assert!(table.address_conflicts().is_empty());
        assert!(table.peer(B).is_none());
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
        let mut table = RouteTable::new(&settings(json!({"accept": ["192.168.10.0/24"]})));
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
    fn same_subnet_goes_to_the_nearest_then_smallest_id() {
        let mut table = RouteTable::new(&settings(json!({})));
        table.set_peer(B, &[], &[net("192.168.5.0/24")]);
        table.set_peer(A, &[], &[net("192.168.5.0/24")]);
        let c = PeerId(3);
        table.set_peer(c, &[], &[net("192.168.5.0/24")]);
        assert_eq!(table.lookup(ip("192.168.5.1")), Ok(A));
        let hops = |peer: PeerId| match peer.0 {
            1 => Some(3),
            2 => Some(1),
            _ => Some(1),
        };
        assert_eq!(table.lookup_by(ip("192.168.5.1"), hops), Ok(B));
        // An unreachable advertiser is skipped.
        let hops = |peer: PeerId| (peer != B).then_some(1);
        assert_eq!(table.lookup_by(ip("192.168.5.1"), hops), Ok(A));
        assert_eq!(
            table.lookup_by(ip("192.168.5.1"), |_| None),
            Err(Denied::NoRoute)
        );
        table.remove_peer(A);
        assert_eq!(table.lookup(ip("192.168.5.1")), Ok(B));
        assert_eq!(table.peer_count(), 2);
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
    fn a_node_advertising_a_subnet_carries_its_traffic_both_ways() {
        let mut config = settings(json!({}));
        config.advertise_subnets = vec![net("192.168.50.0/24")];
        let mut table = RouteTable::new(&config);
        table.set_peer(A, &[ip("10.144.144.6")], &[net("192.168.60.0/24")]);

        // From a peer to a host behind this node.
        assert_eq!(
            table.check_incoming(A, &ipv4([10, 144, 144, 6], [192, 168, 50, 20], 4)),
            Ok(())
        );
        // From the peer's own LAN to ours.
        assert_eq!(
            table.check_incoming(A, &ipv4([192, 168, 60, 9], [192, 168, 50, 20], 4)),
            Ok(())
        );
        // The source check still holds.
        assert_eq!(
            table.check_incoming(A, &ipv4([192, 168, 70, 9], [192, 168, 50, 20], 4)),
            Err(Denied::Spoofed)
        );
        // Outside what this node advertises.
        assert_eq!(
            table.check_incoming(A, &ipv4([10, 144, 144, 6], [192, 168, 51, 20], 4)),
            Err(Denied::NotForUs)
        );

        // Replies from a host behind this node leave with their own source.
        assert_eq!(
            table.check_outgoing(&ipv4([192, 168, 50, 20], [10, 144, 144, 6], 4)),
            Ok(A)
        );
        assert_eq!(
            table.check_outgoing(&ipv4([192, 168, 50, 20], [192, 168, 60, 9], 4)),
            Ok(A)
        );
        assert_eq!(
            table.check_outgoing(&ipv4([192, 168, 51, 20], [10, 144, 144, 6], 4)),
            Err(Denied::ForeignSource)
        );

        assert_eq!(
            table.classify_outgoing(&ipv4([192, 168, 50, 20], [10, 144, 144, 6], 4)),
            Ok(Outgoing::Peer(A))
        );
        // Broadcasts and multicasts still only from this node's address.
        assert_eq!(
            table.classify_outgoing(&ipv4([192, 168, 50, 20], [224, 0, 0, 251], 4)),
            Err(Denied::ForeignSource)
        );

        // A node that advertises nothing still only takes its own address.
        let plain = RouteTable::new(&settings(json!({})));
        assert_eq!(
            plain.check_outgoing(&ipv4([192, 168, 50, 20], [10, 144, 144, 6], 4)),
            Err(Denied::ForeignSource)
        );
    }

    #[test]
    fn local_networks_are_never_taken_over() {
        let mut config = settings(json!({}));
        config.advertise_subnets = vec![net("192.168.50.0/24")];
        let mut table = RouteTable::new(&config);
        let update = table.set_peer(
            A,
            &[ip("10.144.144.6")],
            &[
                net("192.168.50.128/25"),
                net("192.168.60.0/24"),
                net("192.168.70.0/24"),
            ],
        );
        // Kept and shown, but not routed (spec §15.4).
        assert!(update.refused_subnets.is_empty());
        assert_eq!(update.local_conflicts, vec![net("192.168.50.128/25")]);
        assert_eq!(table.lookup(ip("192.168.50.200")), Err(Denied::NoRoute));
        assert_eq!(table.local_conflicts(), vec![(A, net("192.168.50.128/25"))]);
        // An interface network appears later: the overlapping route stops.
        let conflicts = table.set_local_networks(&[net("192.168.60.7/24")], &[]);
        assert_eq!(conflicts.len(), 2);
        assert!(conflicts.contains(&(A, net("192.168.60.0/24"))));
        assert_eq!(table.lookup(ip("192.168.60.1")), Err(Denied::NoRoute));
        assert_eq!(table.lookup(ip("192.168.70.1")), Ok(A));
        assert_eq!(table.system_routes(), vec![net("192.168.70.0/24")]);
        let from_lan = ipv4([192, 168, 60, 9], [10, 144, 144, 5], 0);
        assert_eq!(table.check_incoming(A, &from_lan), Err(Denied::Spoofed));
        // The user routes that subnet through the mesh after all; no new
        // advertisement is needed.
        table.set_local_networks(&[net("192.168.60.0/24")], &[net("192.168.60.0/24")]);
        assert_eq!(table.lookup(ip("192.168.60.1")), Ok(A));
        // An override never applies to what this node advertises itself.
        table.set_local_networks(&[], &[net("192.168.50.128/25")]);
        assert_eq!(table.lookup(ip("192.168.50.200")), Err(Denied::NoRoute));
    }

    #[test]
    fn the_same_subnet_as_this_node_is_kept_for_detection() {
        let mut config = settings(json!({}));
        config.advertise_subnets = vec![net("192.168.50.0/24")];
        let mut table = RouteTable::new(&config);
        let update = table.set_peer(A, &[ip("10.144.144.6")], &[net("192.168.50.0/24")]);
        assert_eq!(update.subnets, vec![net("192.168.50.0/24")]);
        assert_eq!(update.local_conflicts, vec![net("192.168.50.0/24")]);
        assert!(table.system_routes().is_empty());
    }

    #[test]
    fn broadcast_addresses_belong_to_nobody() {
        let mut table = RouteTable::new(&settings(json!({})));
        let update = table.set_peer(A, &[ip("10.144.144.255"), ip("10.144.144.0")], &[]);
        assert_eq!(update.refused_addresses.len(), 2);
    }

    #[test]
    fn broadcast_and_multicast_go_to_every_neighbour() {
        let mut table = RouteTable::new(&settings(json!({})));
        table.set_peer(A, &[ip("10.144.144.6")], &[net("192.168.10.0/24")]);
        let from_us = |destination: [u8; 4]| ipv4([10, 144, 144, 5], destination, 4);
        for destination in [[10, 144, 144, 255], [255, 255, 255, 255], [224, 0, 0, 251]] {
            assert_eq!(
                table.classify_outgoing(&from_us(destination)),
                Ok(Outgoing::Neighbours),
                "{destination:?}"
            );
        }
        assert_eq!(
            table.classify_outgoing(&from_us([10, 144, 144, 6])),
            Ok(Outgoing::Peer(A))
        );
        // The network address and a directed broadcast of an advertised
        // subnet are not flooded.
        assert_eq!(
            table.classify_outgoing(&from_us([10, 144, 144, 0])),
            Err(Denied::NoRoute)
        );
        assert_eq!(
            table.classify_outgoing(&from_us([192, 168, 10, 255])),
            Ok(Outgoing::Peer(A))
        );
        let multicast_v6 = ipv6(
            "fd00:aa::5".parse().unwrap(),
            "ff02::fb".parse().unwrap(),
            0,
        );
        assert_eq!(
            table.classify_outgoing(&multicast_v6),
            Ok(Outgoing::Neighbours)
        );
        // Only this node's own packets.
        assert_eq!(
            table.classify_outgoing(&ipv4([10, 144, 144, 6], [255, 255, 255, 255], 4)),
            Err(Denied::ForeignSource)
        );
    }

    #[test]
    fn delivered_broadcasts_still_need_the_peers_own_source() {
        let mut table = RouteTable::new(&settings(json!({})));
        table.set_peer(A, &[ip("10.144.144.6")], &[]);
        table.set_peer(B, &[ip("10.144.144.7")], &[]);
        let broadcast = |source: [u8; 4]| ipv4(source, [10, 144, 144, 255], 4);
        assert_eq!(
            table.check_incoming(A, &broadcast([10, 144, 144, 6])),
            Ok(())
        );
        assert_eq!(
            table.check_incoming(A, &ipv4([10, 144, 144, 6], [224, 0, 0, 251], 4)),
            Ok(())
        );
        assert_eq!(
            table.check_incoming(A, &broadcast([10, 144, 144, 7])),
            Err(Denied::Spoofed)
        );
        assert_eq!(
            table.check_incoming(A, &broadcast([8, 8, 8, 8])),
            Err(Denied::Spoofed)
        );
        // Another node's unicast is still not ours.
        assert_eq!(
            table.check_incoming(A, &ipv4([10, 144, 144, 6], [10, 144, 144, 7], 4)),
            Err(Denied::NotForUs)
        );
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
        // Reverse path: B advertises a wider subnet that covers A's; B may
        // not use sources in A's subnet, A may, and B keeps the rest.
        table.set_peer(B, &[ip("10.144.144.7")], &[net("192.168.0.0/16")]);
        assert_eq!(
            table.check_incoming(B, &to_us([192, 168, 10, 9])),
            Err(Denied::Spoofed)
        );
        assert_eq!(table.check_incoming(A, &to_us([192, 168, 10, 9])), Ok(()));
        assert_eq!(table.check_incoming(B, &to_us([192, 168, 20, 9])), Ok(()));
        assert_eq!(
            table.check_incoming(A, &to_us([192, 168, 20, 9])),
            Err(Denied::Spoofed)
        );
        // Two advertisers of the same subnet may both deliver from it.
        table.set_peer(B, &[ip("10.144.144.7")], &[net("192.168.10.0/24")]);
        assert_eq!(table.check_incoming(B, &to_us([192, 168, 10, 9])), Ok(()));
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

    #[test]
    fn a_border_node_carries_the_other_regions_prefixes() {
        let mut table = RouteTable::new(&settings(json!({})));
        table.set_peer(A, &[ip("10.144.144.6")], &[net("192.168.10.0/24")]);
        // Another border node of this region advertises the same summary.
        table.set_peer(B, &[ip("10.144.144.7")], &[net("10.20.0.0/16")]);
        assert_eq!(table.lookup(ip("10.20.1.1")), Ok(B));
        // Public, this network's own and duplicate prefixes are left out.
        let left_out = table.set_border(&[
            net("10.20.0.0/16"),
            net("10.20.0.0/16"),
            net("8.8.0.0/16"),
            net("10.144.0.0/16"),
        ]);
        assert_eq!(left_out, 0);
        assert_eq!(table.border(), &[net("10.20.0.0/16")]);
        // What this node carries is not routed to the other advertiser.
        assert_eq!(table.lookup(ip("10.20.1.1")), Err(Denied::NoRoute));

        let to_region = ipv4([10, 144, 144, 6], [10, 20, 1, 1], 0);
        assert_eq!(table.check_incoming(A, &to_region), Ok(()));
        assert!(table.for_backbone(&to_region));
        assert!(!table.for_backbone(&ipv4([10, 144, 144, 6], [10, 144, 144, 5], 0)));
        // The source check still applies to packets for the backbone.
        assert_eq!(
            table.check_incoming(A, &ipv4([10, 144, 144, 7], [10, 20, 1, 1], 0)),
            Err(Denied::Spoofed)
        );
        // Other transit is still refused.
        assert_eq!(
            table.check_incoming(A, &ipv4([10, 144, 144, 6], [10, 30, 1, 1], 0)),
            Err(Denied::NotForUs)
        );

        // From the backbone: a source in a carried prefix, to this network.
        assert_eq!(
            table.classify_from_backbone(&ipv4([10, 20, 1, 1], [10, 144, 144, 6], 0)),
            Ok(A)
        );
        assert_eq!(
            table.classify_from_backbone(&ipv4([10, 20, 1, 1], [192, 168, 10, 3], 0)),
            Ok(A)
        );
        assert_eq!(
            table.classify_from_backbone(&ipv4([10, 30, 1, 1], [10, 144, 144, 6], 0)),
            Err(Denied::ForeignSource)
        );
        assert_eq!(
            table.classify_from_backbone(&ipv4([10, 20, 1, 1], [10, 20, 2, 2], 0)),
            Err(Denied::NoRoute)
        );
        assert_eq!(
            table.classify_from_backbone(&ipv4([10, 20, 1, 1], [10, 144, 144, 255], 0)),
            Err(Denied::NoRoute)
        );
        assert_eq!(
            table.classify_from_backbone(&ipv4([10, 20, 1, 1], [10, 144, 144, 5], 0)),
            Err(Denied::Local)
        );
        // The interface path still refuses foreign sources.
        assert_eq!(
            table.check_outgoing(&ipv4([10, 20, 1, 1], [10, 144, 144, 6], 0)),
            Err(Denied::ForeignSource)
        );

        // At most what one peer may advertise.
        let many: Vec<IpNet> = (0..=MAX_SUBNETS_PER_PEER as u32)
            .map(|i| net(&format!("10.{}.{}.0/24", 30 + i / 256, i % 256)))
            .collect();
        assert_eq!(table.set_border(&many), 1);
        assert_eq!(table.border().len(), MAX_SUBNETS_PER_PEER);

        // Withdrawn: the other advertiser is used again, nothing is taken.
        assert_eq!(table.set_border(&[]), 0);
        assert_eq!(table.lookup(ip("10.20.1.1")), Ok(B));
        assert_eq!(table.check_incoming(A, &to_region), Err(Denied::NotForUs));
    }
}
