//! What the backbone knows about the other border nodes: their region
//! adverts and link states, with sequence numbers, lifetimes and flooding
//! decisions (spec §17.3.3, §17.3.4, appendix A.1–A.3).

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;
use std::time::{Duration, Instant};

use super::config::BackboneSettings;
use super::msg::{LinkState, RegionAdvert};
use super::region::{Lpm, RegionId};
use super::BackboneId;
use crate::net::IpNet;

/// Why a received advert or link state was not taken.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reject {
    /// `origin` is not a member (or is this node).
    NotMember,
    /// `region` differs from the member list.
    RegionMismatch,
    /// Another region advertises a prefix overlapping this region's summary.
    PrefixConflict,
    /// Same sequence number, different content: the stored copy is kept.
    SeqDuplicate,
    /// A link state names a neighbour that is not a member.
    UnknownNeighbor,
}

/// What happened to a received advert or link state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// Newer than the stored copy: stored, and to be flooded to every
    /// backbone neighbour except the one it came from.
    New,
    /// Not newer: dropped silently, not flooded.
    Stale,
    Rejected(Reject),
}

#[derive(Clone, Debug)]
struct Stored<T> {
    message: T,
    expires: Instant,
}

/// The stored adverts and link states, and the summary table built from
/// them.
#[derive(Clone, Debug)]
pub struct Topology {
    me: BackboneId,
    region: RegionId,
    members: BTreeMap<BackboneId, RegionId>,
    own_prefixes: Vec<IpNet>,
    adverts: BTreeMap<BackboneId, Stored<RegionAdvert>>,
    states: BTreeMap<BackboneId, Stored<LinkState>>,
    summary: Lpm<RegionId>,
    conflicts: BTreeSet<IpNet>,
}

impl Topology {
    pub fn new(settings: &BackboneSettings) -> Self {
        Self {
            me: settings.id,
            region: settings.region.clone(),
            members: settings.members.clone(),
            own_prefixes: Vec::new(),
            adverts: BTreeMap::new(),
            states: BTreeMap::new(),
            summary: Lpm::new(),
            conflicts: BTreeSet::new(),
        }
    }

    /// Applies a new member list: state of former members is dropped, as is
    /// state whose region no longer matches.
    pub fn set_members(&mut self, settings: &BackboneSettings) {
        self.me = settings.id;
        self.region = settings.region.clone();
        self.members = settings.members.clone();
        let members = &self.members;
        self.adverts
            .retain(|id, a| members.get(id) == Some(&a.message.region));
        self.states.retain(|id, _| members.contains_key(id));
        self.rebuild();
    }

    /// This region's own summary prefixes (spec §17.3.3 field 4): its
    /// virtual subnet, the members' advertised subnets and the extra
    /// prefixes. Stored adverts of other regions that now overlap them are
    /// dropped.
    pub fn set_own_prefixes(&mut self, prefixes: Vec<IpNet>) {
        self.own_prefixes = prefixes;
        let own_region = self.region.clone();
        let own = self.own_prefixes.clone();
        self.adverts.retain(|_, a| {
            a.message.region == own_region || !overlaps_any(&a.message.prefixes, &own)
        });
        self.rebuild();
    }

    pub fn own_prefixes(&self) -> &[IpNet] {
        &self.own_prefixes
    }

    pub fn region(&self) -> &RegionId {
        &self.region
    }

    pub fn me(&self) -> BackboneId {
        self.me
    }

    pub fn member_region(&self, id: BackboneId) -> Option<&RegionId> {
        self.members.get(&id)
    }

    pub fn members(&self) -> impl Iterator<Item = (BackboneId, &RegionId)> {
        self.members.iter().map(|(id, region)| (*id, region))
    }

    fn check_origin(&self, origin: BackboneId) -> Result<&RegionId, Reject> {
        if origin == self.me {
            return Err(Reject::NotMember);
        }
        self.members.get(&origin).ok_or(Reject::NotMember)
    }

    /// Takes one RegionAdvert (appendix A.2).
    pub fn on_region_advert(&mut self, advert: RegionAdvert, now: Instant) -> Outcome {
        let region = match self.check_origin(advert.origin) {
            Ok(region) => region,
            Err(e) => return Outcome::Rejected(e),
        };
        if *region != advert.region {
            return Outcome::Rejected(Reject::RegionMismatch);
        }
        if advert.region != self.region && overlaps_any(&advert.prefixes, &self.own_prefixes) {
            return Outcome::Rejected(Reject::PrefixConflict);
        }
        if let Some(stored) = self.adverts.get(&advert.origin) {
            if let Some(outcome) = compare(stored.message.seq, advert.seq, stored.message == advert)
            {
                return outcome;
            }
        }
        let expires = now + Duration::from_secs(u64::from(advert.lifetime_s));
        self.adverts.insert(
            advert.origin,
            Stored {
                message: advert,
                expires,
            },
        );
        self.rebuild();
        Outcome::New
    }

    /// Takes one LinkState (appendix A.3).
    pub fn on_link_state(&mut self, state: LinkState, now: Instant) -> Outcome {
        if let Err(e) = self.check_origin(state.origin) {
            return Outcome::Rejected(e);
        }
        if state
            .links
            .iter()
            .any(|l| !self.members.contains_key(&l.neighbor))
        {
            return Outcome::Rejected(Reject::UnknownNeighbor);
        }
        if let Some(stored) = self.states.get(&state.origin) {
            if let Some(outcome) = compare(stored.message.seq, state.seq, stored.message == state) {
                return outcome;
            }
        }
        let expires = now + Duration::from_secs(u64::from(state.lifetime_s));
        self.states.insert(
            state.origin,
            Stored {
                message: state,
                expires,
            },
        );
        Outcome::New
    }

    /// Drops what outlived its lifetime. Returns whether anything changed.
    pub fn expire(&mut self, now: Instant) -> bool {
        let adverts = self.adverts.len();
        let states = self.states.len();
        self.adverts.retain(|_, a| a.expires > now);
        self.states.retain(|_, s| s.expires > now);
        let changed = adverts != self.adverts.len() || states != self.states.len();
        if adverts != self.adverts.len() {
            self.rebuild();
        }
        changed
    }

    fn rebuild(&mut self) {
        let mut summary = Lpm::new();
        let mut owner: BTreeMap<IpNet, RegionId> = BTreeMap::new();
        let mut conflicts = BTreeSet::new();
        for net in &self.own_prefixes {
            owner.insert(net.trunc(), self.region.clone());
        }
        for stored in self.adverts.values() {
            let advert = &stored.message;
            if advert.region == self.region {
                continue;
            }
            for net in &advert.prefixes {
                match owner.get(net) {
                    Some(region) if *region != advert.region => {
                        conflicts.insert(*net);
                        // Deterministic: the smaller region ID keeps it.
                        if advert.region < *region {
                            owner.insert(*net, advert.region.clone());
                        }
                    }
                    Some(_) => {}
                    None => {
                        owner.insert(*net, advert.region.clone());
                    }
                }
            }
        }
        // Overlapping (not equal) prefixes of different regions are routed
        // by longest prefix but still reported.
        let nets: Vec<(&IpNet, &RegionId)> = owner.iter().collect();
        for (i, (a, ra)) in nets.iter().enumerate() {
            for (b, rb) in &nets[i + 1..] {
                if ra != rb && a.overlaps(b) {
                    conflicts.insert(**a);
                    conflicts.insert(**b);
                }
            }
        }
        for (net, region) in owner {
            summary.insert(net, region);
        }
        self.summary = summary;
        self.conflicts = conflicts;
    }

    /// The region an address belongs to, by longest prefix over this
    /// region's own prefixes and every other region's adverts.
    pub fn region_of(&self, address: IpAddr) -> Option<(IpNet, &RegionId)> {
        self.summary.lookup(address)
    }

    /// Prefixes advertised by more than one region (alerted).
    pub fn conflicts(&self) -> &BTreeSet<IpNet> {
        &self.conflicts
    }

    /// Every other region's summary prefix with the region that owns it.
    pub fn foreign_prefixes(&self) -> BTreeMap<IpNet, RegionId> {
        let mut out = BTreeMap::new();
        for stored in self.adverts.values() {
            let advert = &stored.message;
            if advert.region == self.region {
                continue;
            }
            for net in &advert.prefixes {
                if self
                    .summary
                    .get(net)
                    .is_some_and(|owner| *owner == advert.region)
                {
                    out.insert(*net, advert.region.clone());
                }
            }
        }
        out
    }

    /// Summary prefixes of one region (this region: the own prefixes).
    pub fn region_prefixes(&self, region: &RegionId) -> BTreeSet<IpNet> {
        if *region == self.region {
            return self.own_prefixes.iter().map(IpNet::trunc).collect();
        }
        self.adverts
            .values()
            .filter(|a| a.message.region == *region)
            .flat_map(|a| a.message.prefixes.iter().copied())
            .collect()
    }

    /// All known regions other than this one.
    pub fn foreign_regions(&self) -> BTreeSet<RegionId> {
        self.adverts
            .values()
            .map(|a| a.message.region.clone())
            .filter(|r| *r != self.region)
            .collect()
    }

    /// Border nodes that advertise `prefix` and are reachable: candidate
    /// exits for it (appendix A.2 rule 4).
    pub fn exits_for(&self, prefix: &IpNet) -> Vec<BackboneId> {
        self.adverts
            .values()
            .filter(|a| a.message.reachable && a.message.prefixes.contains(prefix))
            .map(|a| a.message.origin)
            .collect()
    }

    /// Reachable border nodes of a region (exits a transit may use).
    pub fn region_exits(&self, region: &RegionId) -> Vec<BackboneId> {
        self.adverts
            .values()
            .filter(|a| a.message.reachable && a.message.region == *region)
            .map(|a| a.message.origin)
            .collect()
    }

    /// The stored advert of a member, with its remaining lifetime.
    pub fn advert(&self, origin: BackboneId, now: Instant) -> Option<(&RegionAdvert, Duration)> {
        self.adverts
            .get(&origin)
            .map(|s| (&s.message, s.expires.saturating_duration_since(now)))
    }

    /// The cost `from → to` that `from` last published, in cost units;
    /// `None` when it lists no usable link to `to`.
    pub fn link_cost(&self, from: BackboneId, to: BackboneId) -> Option<f64> {
        self.states
            .get(&from)?
            .message
            .links
            .iter()
            .find(|l| l.neighbor == to)
            .map(|l| f64::from(l.cost_milli) / 1000.0)
    }

    /// The sequence number of the stored link state of `origin`.
    pub fn link_state_seq(&self, origin: BackboneId) -> Option<u64> {
        self.states.get(&origin).map(|s| s.message.seq)
    }
}

fn overlaps_any(prefixes: &[IpNet], others: &[IpNet]) -> bool {
    prefixes
        .iter()
        .any(|p| others.iter().any(|o| p.overlaps(o)))
}

/// `None`: the received copy is newer and replaces the stored one.
fn compare(stored: u64, received: u64, same: bool) -> Option<Outcome> {
    if received > stored {
        None
    } else if received == stored && !same {
        Some(Outcome::Rejected(Reject::SeqDuplicate))
    } else {
        Some(Outcome::Stale)
    }
}

#[cfg(test)]
mod tests {
    use super::super::msg::LinkCost;
    use super::super::testutil::{net, rid, settings};
    use super::*;

    fn advert(origin: u32, region: &str, seq: u64, prefixes: &[&str]) -> RegionAdvert {
        RegionAdvert {
            origin,
            region: rid(region),
            seq,
            prefixes: prefixes.iter().copied().map(net).collect(),
            reachable: true,
            lifetime_s: 90,
        }
    }

    fn topo() -> Topology {
        let mut t = Topology::new(&settings());
        t.set_own_prefixes(vec![net("10.20.0.0/16")]);
        t
    }

    #[test]
    fn newer_adverts_replace_and_flood_older_are_stale() {
        let now = Instant::now();
        let mut t = topo();
        assert_eq!(
            t.on_region_advert(advert(21, "ap", 5, &["10.30.0.0/16"]), now),
            Outcome::New
        );
        assert_eq!(
            t.on_region_advert(advert(21, "ap", 5, &["10.30.0.0/16"]), now),
            Outcome::Stale
        );
        assert_eq!(
            t.on_region_advert(advert(21, "ap", 4, &["10.31.0.0/16"]), now),
            Outcome::Stale
        );
        assert_eq!(
            t.on_region_advert(advert(21, "ap", 5, &["10.31.0.0/16"]), now),
            Outcome::Rejected(Reject::SeqDuplicate)
        );
        assert_eq!(
            t.on_region_advert(advert(21, "ap", 6, &["10.31.0.0/16"]), now),
            Outcome::New
        );
        let (prefix, region) = t.region_of("10.31.1.1".parse().unwrap()).unwrap();
        assert_eq!((prefix, region.clone()), (net("10.31.0.0/16"), rid("ap")));
        assert!(t.region_of("10.30.1.1".parse().unwrap()).is_none());
        assert_eq!(
            t.region_of("10.20.1.1".parse().unwrap()).unwrap().1,
            &rid("eu")
        );
    }

    #[test]
    fn membership_region_and_conflicts_are_checked() {
        let now = Instant::now();
        let mut t = topo();
        assert_eq!(
            t.on_region_advert(advert(99, "ap", 1, &[]), now),
            Outcome::Rejected(Reject::NotMember)
        );
        assert_eq!(
            t.on_region_advert(advert(11, "eu", 1, &[]), now),
            Outcome::Rejected(Reject::NotMember),
            "own origin"
        );
        assert_eq!(
            t.on_region_advert(advert(21, "cn", 1, &[]), now),
            Outcome::Rejected(Reject::RegionMismatch)
        );
        assert_eq!(
            t.on_region_advert(advert(21, "ap", 1, &["10.20.5.0/24"]), now),
            Outcome::Rejected(Reject::PrefixConflict)
        );
        // Same-region adverts are not checked against the own prefixes.
        assert_eq!(
            t.on_region_advert(advert(12, "eu", 1, &["10.20.0.0/16"]), now),
            Outcome::New
        );
        // Two foreign regions with the same prefix: reported, smaller ID wins.
        t.on_region_advert(advert(31, "cn", 1, &["10.40.0.0/16"]), now);
        t.on_region_advert(advert(21, "ap", 1, &["10.40.0.0/16"]), now);
        assert!(t.conflicts().contains(&net("10.40.0.0/16")));
        assert_eq!(
            t.region_of("10.40.0.1".parse().unwrap()).unwrap().1,
            &rid("ap")
        );
        let foreign = t.foreign_prefixes();
        assert_eq!(foreign.get(&net("10.40.0.0/16")), Some(&rid("ap")));
        assert!(!foreign.contains_key(&net("10.20.0.0/16")));
    }

    #[test]
    fn adverts_expire_and_exits_follow_reachability() {
        let now = Instant::now();
        let mut t = topo();
        let mut a = advert(21, "ap", 1, &["10.30.0.0/16"]);
        a.lifetime_s = 30;
        t.on_region_advert(a, now);
        let mut b = advert(22, "ap", 1, &["10.30.0.0/16"]);
        b.reachable = false;
        t.on_region_advert(b, now);
        assert_eq!(t.exits_for(&net("10.30.0.0/16")), vec![21]);
        assert_eq!(t.region_exits(&rid("ap")), vec![21]);
        assert!(!t.expire(now + Duration::from_secs(29)));
        assert!(t.expire(now + Duration::from_secs(30)));
        assert!(t.exits_for(&net("10.30.0.0/16")).is_empty());
        assert!(
            t.region_of("10.30.0.1".parse().unwrap()).is_some(),
            "22 still advertises it"
        );
    }

    #[test]
    fn link_states_and_costs() {
        let now = Instant::now();
        let mut t = topo();
        let state = LinkState {
            origin: 21,
            seq: 3,
            links: vec![LinkCost {
                neighbor: 31,
                cost_milli: 25_500,
                loss_ppm: None,
            }],
            lifetime_s: 60,
        };
        assert_eq!(t.on_link_state(state.clone(), now), Outcome::New);
        assert_eq!(t.on_link_state(state.clone(), now), Outcome::Stale);
        assert_eq!(t.link_cost(21, 31), Some(25.5));
        assert_eq!(t.link_cost(21, 22), None);
        assert_eq!(t.link_state_seq(21), Some(3));
        let mut bad = state;
        bad.seq = 4;
        bad.links[0].neighbor = 77;
        assert_eq!(
            t.on_link_state(bad, now),
            Outcome::Rejected(Reject::UnknownNeighbor)
        );
        assert!(t.expire(now + Duration::from_secs(60)));
        assert_eq!(t.link_cost(21, 31), None);
    }

    #[test]
    fn own_prefix_changes_drop_conflicting_foreign_adverts() {
        let now = Instant::now();
        let mut t = topo();
        t.on_region_advert(advert(21, "ap", 1, &["10.30.0.0/16"]), now);
        t.set_own_prefixes(vec![net("10.20.0.0/16"), net("10.30.0.0/24")]);
        assert!(t.advert(21, now).is_none());
    }
}
