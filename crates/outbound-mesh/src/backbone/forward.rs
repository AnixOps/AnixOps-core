//! Forwarding decisions for IP packets on the backbone (appendix A.7) and
//! the receive policy of each link (appendix A.8).

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;

use super::config::BackboneSettings;
use super::region::RegionId;
use super::select::{LocalLink, Selector};
use super::topology::Topology;
use super::BackboneId;
use crate::net::IpNet;

/// Why a packet was dropped (the counters of appendix C.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DropReason {
    /// No summary prefix or no path for the destination.
    NoRoute,
    /// No access rule allows this direction (B.4).
    Access,
    /// The previous hop is not in the source's region, or the source or
    /// destination region is unknown (A.7 step 2).
    Inconsistent,
    /// The previous hop handed over a packet for its own region.
    NotForUs,
    /// No exit of the destination region is usable from this transit.
    RelayUnreachable,
}

impl DropReason {
    pub fn as_str(&self) -> &'static str {
        match self {
            DropReason::NoRoute => "no_route",
            DropReason::Access => "access",
            DropReason::Inconsistent => "inconsistent",
            DropReason::NotForUs => "not_for_us",
            DropReason::RelayUnreachable => "relay_unreachable",
        }
    }
}

/// What to do with one packet.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// Hand it to this region's network (this node is the exit).
    Deliver,
    /// Send it on the link to this member.
    Send(BackboneId),
    Drop(DropReason),
    /// Drop it and tell the previous hop with RelayUnreachable (A.5).
    DropAndNotify {
        peer: BackboneId,
        region: RegionId,
    },
}

/// A packet from this region's network for a foreign destination (A.7,
/// ingress).
pub fn ingress(
    settings: &BackboneSettings,
    topology: &Topology,
    selector: &Selector,
    src: IpAddr,
    dst: IpAddr,
) -> Verdict {
    let Some((prefix, region)) = topology.region_of(dst) else {
        return Verdict::Drop(DropReason::NoRoute);
    };
    if *region == settings.region {
        return Verdict::Drop(DropReason::NoRoute);
    }
    if !settings.access_allows(src, dst) {
        return Verdict::Drop(DropReason::Access);
    }
    match selector.first_hop(&prefix) {
        Some(hop) => Verdict::Send(hop),
        None => Verdict::Drop(DropReason::NoRoute),
    }
}

/// The exit a transit uses for `region`: reachable, over a usable link that
/// is not forbidden, cheapest first, then the smaller ID (A.7 step 3).
pub fn transit_exit(
    settings: &BackboneSettings,
    topology: &Topology,
    links: &BTreeMap<BackboneId, LocalLink>,
    region: &RegionId,
) -> Option<BackboneId> {
    if settings.link_denied(&settings.region, region) {
        return None;
    }
    topology
        .region_exits(region)
        .into_iter()
        .filter(|id| *id != settings.id && settings.region_of(*id) == Some(region))
        .filter_map(|id| links.get(&id).map(|l| (l.cost, id)))
        .min_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal))
        .map(|(_, id)| id)
}

/// A packet received on the link to `from` (A.7, receiving side).
pub fn receive(
    settings: &BackboneSettings,
    topology: &Topology,
    links: &BTreeMap<BackboneId, LocalLink>,
    from: BackboneId,
    src: IpAddr,
    dst: IpAddr,
) -> Verdict {
    let dst_region = topology.region_of(dst).map(|(_, r)| r);
    if dst_region == Some(&settings.region) {
        return Verdict::Deliver;
    }
    let src_region = topology.region_of(src).map(|(_, r)| r);
    let (Some(src_region), Some(dst_region), Some(from_region)) =
        (src_region, dst_region, settings.region_of(from))
    else {
        return Verdict::Drop(DropReason::Inconsistent);
    };
    if from_region != src_region {
        return Verdict::Drop(DropReason::Inconsistent);
    }
    if dst_region == src_region {
        return Verdict::Drop(DropReason::NotForUs);
    }
    match transit_exit(settings, topology, links, dst_region) {
        Some(exit) => Verdict::Send(exit),
        None => Verdict::DropAndNotify {
            peer: from,
            region: dst_region.clone(),
        },
    }
}

/// Source and destination allow lists for the link to a peer in
/// `peer_region` (A.8). Empty lists make the link drop every IP packet.
pub fn receive_policy(
    settings: &BackboneSettings,
    topology: &Topology,
    peer_region: &RegionId,
) -> (Vec<IpNet>, Vec<IpNet>) {
    let own: BTreeSet<IpNet> = topology.region_prefixes(&settings.region);
    let foreign: BTreeSet<IpNet> = topology.foreign_prefixes().into_keys().collect();
    if *peer_region == settings.region {
        (own.into_iter().collect(), foreign.into_iter().collect())
    } else {
        let all: BTreeSet<IpNet> = own.union(&foreign).copied().collect();
        (foreign.into_iter().collect(), all.into_iter().collect())
    }
}

#[cfg(test)]
mod tests {
    use super::super::msg::RegionAdvert;
    use super::super::select::{Path, Selector};
    use super::super::testutil::{net, rid, settings};
    use super::*;
    use std::time::Instant;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    // This node: 11 in eu (10.20/16). ap = 21, 22 (10.30/16), cn = 31 (10.40/16).
    fn world() -> (BackboneSettings, Topology) {
        let mut s = settings();
        s.access = vec![super::super::config::AccessRule {
            from: vec![net("10.20.0.0/16")],
            to: vec![net("10.30.0.0/16"), net("10.40.0.0/16")],
        }];
        let mut t = Topology::new(&s);
        t.set_own_prefixes(vec![net("10.20.0.0/16")]);
        let now = Instant::now();
        for (origin, region, prefix) in [
            (21, "ap", "10.30.0.0/16"),
            (22, "ap", "10.30.0.0/16"),
            (31, "cn", "10.40.0.0/16"),
        ] {
            t.on_region_advert(
                RegionAdvert {
                    origin,
                    region: rid(region),
                    seq: 1,
                    prefixes: vec![net(prefix)],
                    reachable: true,
                    lifetime_s: 90,
                },
                now,
            );
        }
        (s, t)
    }

    fn link(cost: f64) -> LocalLink {
        LocalLink {
            cost,
            loss: 0.0,
            congested: false,
        }
    }

    #[test]
    fn ingress_checks_route_access_and_path() {
        let (s, t) = world();
        let mut sel = Selector::new();
        assert_eq!(
            ingress(&s, &t, &sel, ip("10.20.0.5"), ip("10.30.0.9")),
            Verdict::Drop(DropReason::NoRoute),
            "no path chosen yet"
        );
        let path = Path {
            egress: 22,
            via: Some(31),
            cost: 1.0,
            effective: 1.0,
            loss: 0.0,
            congested: false,
        };
        sel.evaluate(
            net("10.30.0.0/16"),
            &rid("ap"),
            &[path],
            None,
            Instant::now(),
        );
        assert_eq!(
            ingress(&s, &t, &sel, ip("10.20.0.5"), ip("10.30.0.9")),
            Verdict::Send(31)
        );
        assert_eq!(
            ingress(&s, &t, &sel, ip("10.20.0.5"), ip("10.20.0.9")),
            Verdict::Drop(DropReason::NoRoute),
            "own region"
        );
        assert_eq!(
            ingress(&s, &t, &sel, ip("10.20.0.5"), ip("10.50.0.9")),
            Verdict::Drop(DropReason::NoRoute)
        );
        assert_eq!(
            ingress(&s, &t, &sel, ip("10.21.0.5"), ip("10.30.0.9")),
            Verdict::Drop(DropReason::Access)
        );
    }

    #[test]
    fn exit_delivers_and_transit_forwards_only_first_hops() {
        let (s, t) = world();
        let mut links = BTreeMap::new();
        links.insert(21, link(30.0));
        links.insert(22, link(20.0));
        links.insert(31, link(5.0));
        // Exit: destination in this region.
        assert_eq!(
            receive(&s, &t, &links, 31, ip("10.40.0.1"), ip("10.20.0.1")),
            Verdict::Deliver
        );
        // Transit for cn → ap, from cn's border: cheapest ap exit.
        assert_eq!(
            receive(&s, &t, &links, 31, ip("10.40.0.1"), ip("10.30.0.1")),
            Verdict::Send(22)
        );
        // From an ap border with a cn source: a second transit, refused.
        assert_eq!(
            receive(&s, &t, &links, 21, ip("10.40.0.1"), ip("10.30.0.1")),
            Verdict::Drop(DropReason::Inconsistent)
        );
        // Unknown source region.
        assert_eq!(
            receive(&s, &t, &links, 31, ip("10.99.0.1"), ip("10.30.0.1")),
            Verdict::Drop(DropReason::Inconsistent)
        );
        // Previous hop's own region as destination.
        assert_eq!(
            receive(&s, &t, &links, 31, ip("10.40.0.1"), ip("10.40.0.2")),
            Verdict::Drop(DropReason::NotForUs)
        );
        // No usable exit: drop and notify.
        links.remove(&21);
        links.remove(&22);
        assert_eq!(
            receive(&s, &t, &links, 31, ip("10.40.0.1"), ip("10.30.0.1")),
            Verdict::DropAndNotify {
                peer: 31,
                region: rid("ap")
            }
        );
    }

    #[test]
    fn transit_respects_forbidden_region_pairs() {
        let (mut s, t) = world();
        s.deny_link.insert((rid("ap"), rid("eu")));
        let mut links = BTreeMap::new();
        links.insert(21, link(30.0));
        assert_eq!(transit_exit(&s, &t, &links, &rid("ap")), None);
    }

    #[test]
    fn receive_policy_depends_on_the_peer_region() {
        let (s, t) = world();
        let (src, dst) = receive_policy(&s, &t, &rid("eu"));
        assert_eq!(src, vec![net("10.20.0.0/16")]);
        assert_eq!(dst, vec![net("10.30.0.0/16"), net("10.40.0.0/16")]);
        let (src, dst) = receive_policy(&s, &t, &rid("cn"));
        assert_eq!(src, vec![net("10.30.0.0/16"), net("10.40.0.0/16")]);
        assert_eq!(
            dst,
            vec![
                net("10.20.0.0/16"),
                net("10.30.0.0/16"),
                net("10.40.0.0/16")
            ]
        );
    }
}
