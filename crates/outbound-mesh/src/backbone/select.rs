//! Path choice for each foreign summary prefix: direct or through one
//! transit, region policy, and the hysteresis of switching (spec §17.3.5,
//! appendix A.6 item 3, A.9).

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use super::config::BackboneSettings;
use super::region::RegionId;
use super::topology::Topology;
use super::BackboneId;
use crate::net::IpNet;

/// A direct link is healthy at or below this loss (spec §17.3.5 step 4).
pub const HEALTHY_LOSS: f64 = 0.05;
/// Switching back to direct needs at most this loss.
pub const RECOVERY_LOSS: f64 = 0.01;
/// Factor on transits through a preferred region.
pub const PREFERRED_FACTOR: f64 = 0.8;
/// A better path must cost at most this share of the current one...
pub const SWITCH_RATIO: f64 = 0.7;
/// ...and at least this much less.
pub const SWITCH_MIN_GAIN: f64 = 20.0;
/// Back to direct when it costs at most this share of the transit.
pub const RECOVERY_RATIO: f64 = 0.9;
pub const SWITCH_HOLD: Duration = Duration::from_secs(5);
pub const RECOVERY_HOLD: Duration = Duration::from_secs(30);
pub const MIN_SWITCH_INTERVAL: Duration = Duration::from_secs(60);

/// The local view of one link to a member, when it is usable.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct LocalLink {
    pub cost: f64,
    pub loss: f64,
    /// Utilisation above 0.8 raises the cost (spec §17.3.4).
    pub congested: bool,
}

/// One candidate path towards an exit.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Path {
    pub egress: BackboneId,
    pub via: Option<BackboneId>,
    /// Sum of the link costs.
    pub cost: f64,
    /// `cost`, times [`PREFERRED_FACTOR`] for a preferred transit.
    pub effective: f64,
    /// Loss of the first link.
    pub loss: f64,
    pub congested: bool,
}

impl Path {
    pub fn is_direct(&self) -> bool {
        self.via.is_none()
    }

    /// The link the ingress sends on.
    pub fn first_hop(&self) -> BackboneId {
        self.via.unwrap_or(self.egress)
    }

    fn same_route(&self, other: &Path) -> bool {
        self.egress == other.egress && self.via == other.via
    }

    fn healthy_direct(&self) -> bool {
        self.is_direct() && self.loss <= HEALTHY_LOSS
    }

    /// Order for ties: cost, then exit ID, then transit ID (direct first).
    fn order_key(&self, cost: f64) -> (f64, BackboneId, BackboneId) {
        (cost, self.egress, self.via.unwrap_or(0))
    }
}

fn min_by(paths: impl Iterator<Item = Path>, cost: impl Fn(&Path) -> f64) -> Option<Path> {
    paths.min_by(|a, b| {
        a.order_key(cost(a))
            .partial_cmp(&b.order_key(cost(b)))
            .unwrap_or(std::cmp::Ordering::Equal)
    })
}

/// Inputs of one evaluation.
pub struct View<'a> {
    pub settings: &'a BackboneSettings,
    pub topology: &'a Topology,
    /// This node's usable links.
    pub links: &'a BTreeMap<BackboneId, LocalLink>,
    /// Transits marked unusable for a region by RelayUnreachable (A.5).
    pub blocked: &'a dyn Fn(BackboneId, &RegionId) -> bool,
}

impl View<'_> {
    fn region_of(&self, id: BackboneId) -> Option<&RegionId> {
        self.settings.region_of(id)
    }

    /// Every allowed path to `prefix` in `region` (spec §17.3.5 steps 1–3).
    pub fn candidates(&self, prefix: &IpNet, region: &RegionId) -> Vec<Path> {
        let me = self.settings.id;
        let home = &self.settings.region;
        let mut out = Vec::new();
        // A forbidden region pair removes the direct paths only; transits
        // through an allowed region remain.
        for egress in self.topology.exits_for(prefix) {
            if egress == me || self.region_of(egress) != Some(region) {
                continue;
            }
            if !self.settings.link_denied(home, region) {
                if let Some(link) = self.links.get(&egress) {
                    out.push(Path {
                        egress,
                        via: None,
                        cost: link.cost,
                        effective: link.cost,
                        loss: link.loss,
                        congested: link.congested,
                    });
                }
            }
            for (&via, link) in self.links {
                if via == egress || via == me {
                    continue;
                }
                let Some(via_region) = self.region_of(via) else {
                    continue;
                };
                // A transit inside the destination region would deliver
                // itself: that is a direct path to it, not a transit.
                if via_region == region
                    || self.settings.link_denied(home, via_region)
                    || self.settings.link_denied(via_region, region)
                    || (self.blocked)(via, region)
                {
                    continue;
                }
                let Some(second) = self.topology.link_cost(via, egress) else {
                    continue;
                };
                let cost = link.cost + second;
                let effective = if self.settings.transit_preferred(home, via_region) {
                    cost * PREFERRED_FACTOR
                } else {
                    cost
                };
                out.push(Path {
                    egress,
                    via: Some(via),
                    cost,
                    effective,
                    loss: link.loss,
                    congested: link.congested,
                });
            }
        }
        out
    }
}

/// Initial choice (spec §17.3.5 step 4): the cheapest healthy direct path,
/// else the cheapest path by effective cost.
pub fn initial(candidates: &[Path]) -> Option<Path> {
    min_by(
        candidates.iter().copied().filter(Path::healthy_direct),
        |p| p.cost,
    )
    .or_else(|| min_by(candidates.iter().copied(), |p| p.effective))
}

/// Why a path changed (appendix C.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reason {
    Initial,
    Latency,
    Loss,
    Congestion,
    Down,
    Recovered,
    RelayUnreachable,
    Policy,
}

impl Reason {
    pub fn as_str(&self) -> &'static str {
        match self {
            Reason::Initial => "initial",
            Reason::Latency => "latency",
            Reason::Loss => "loss",
            Reason::Congestion => "congestion",
            Reason::Down => "down",
            Reason::Recovered => "recovered",
            Reason::RelayUnreachable => "relay_unreachable",
            Reason::Policy => "policy",
        }
    }
}

/// A path change to report.
#[derive(Clone, Debug, PartialEq)]
pub struct Change {
    pub prefix: IpNet,
    pub region: RegionId,
    pub from: Option<Path>,
    pub to: Option<Path>,
    pub reason: Reason,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Pending {
    Switch,
    Recovery,
}

/// The chosen path of one prefix.
#[derive(Clone, Debug)]
pub struct Route {
    pub region: RegionId,
    pub path: Option<Path>,
    /// When `path` was chosen.
    pub since: Instant,
    last_switch: Option<Instant>,
    pending: Option<(Pending, Instant)>,
}

/// Paths of every foreign prefix.
#[derive(Clone, Debug, Default)]
pub struct Selector {
    routes: BTreeMap<IpNet, Route>,
}

/// What [`Selector::evaluate`] decided for the current path.
fn switch_target(current: &Path, candidates: &[Path]) -> Option<(Pending, Path, Reason)> {
    let others = || {
        candidates
            .iter()
            .copied()
            .filter(|p| !p.same_route(current))
    };
    let latency_reason = if current.congested {
        Reason::Congestion
    } else {
        Reason::Latency
    };
    let better = |alt: &Path, base: f64| {
        alt.effective <= base * SWITCH_RATIO && base - alt.effective >= SWITCH_MIN_GAIN
    };
    if current.is_direct() {
        let healthy = min_by(others().filter(Path::healthy_direct), |p| p.cost);
        if current.loss > HEALTHY_LOSS {
            let target =
                healthy.or_else(|| min_by(others().filter(|p| !p.is_direct()), |p| p.effective))?;
            return Some((Pending::Switch, target, Reason::Loss));
        }
        let transit = min_by(others().filter(|p| !p.is_direct()), |p| p.effective);
        let best = [healthy, transit]
            .into_iter()
            .flatten()
            .filter(|p| better(p, current.cost));
        let target = min_by(best, |p| p.effective)?;
        return Some((Pending::Switch, target, latency_reason));
    }
    let recovery = min_by(
        others().filter(|p| {
            p.is_direct() && p.loss <= RECOVERY_LOSS && p.cost <= current.effective * RECOVERY_RATIO
        }),
        |p| p.cost,
    );
    if let Some(target) = recovery {
        return Some((Pending::Recovery, target, Reason::Recovered));
    }
    let target = min_by(
        others().filter(|p| !p.is_direct() && better(p, current.effective)),
        |p| p.effective,
    )?;
    Some((Pending::Switch, target, latency_reason))
}

impl Selector {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn route(&self, prefix: &IpNet) -> Option<&Route> {
        self.routes.get(prefix)
    }

    pub fn routes(&self) -> impl Iterator<Item = (&IpNet, &Route)> {
        self.routes.iter()
    }

    /// The link to send a packet for `prefix` on.
    pub fn first_hop(&self, prefix: &IpNet) -> Option<BackboneId> {
        self.routes.get(prefix)?.path.map(|p| p.first_hop())
    }

    /// Drops prefixes no longer advertised (or now owned by another
    /// region) and returns them.
    pub fn retain(&mut self, prefixes: &BTreeMap<IpNet, RegionId>) -> Vec<(IpNet, Route)> {
        let gone: Vec<IpNet> = self
            .routes
            .iter()
            .filter(|(prefix, route)| prefixes.get(prefix) != Some(&route.region))
            .map(|(prefix, _)| *prefix)
            .collect();
        gone.into_iter()
            .filter_map(|prefix| self.routes.remove(&prefix).map(|route| (prefix, route)))
            .collect()
    }

    /// Re-evaluates one prefix against its current candidates. `hint` names
    /// the reason when the current path disappears for a known cause
    /// (RelayUnreachable, a policy change); otherwise it is `Down`.
    pub fn evaluate(
        &mut self,
        prefix: IpNet,
        region: &RegionId,
        candidates: &[Path],
        hint: Option<Reason>,
        now: Instant,
    ) -> Option<Change> {
        let route = self.routes.entry(prefix).or_insert_with(|| Route {
            region: region.clone(),
            path: None,
            since: now,
            last_switch: None,
            pending: None,
        });
        if route.region != *region {
            *route = Route {
                region: region.clone(),
                path: None,
                since: now,
                last_switch: None,
                pending: None,
            };
        }
        let Some(current) = route.path else {
            let to = initial(candidates)?;
            route.path = Some(to);
            route.since = now;
            route.last_switch = Some(now);
            route.pending = None;
            return Some(Change {
                prefix,
                region: region.clone(),
                from: None,
                to: Some(to),
                reason: Reason::Initial,
            });
        };
        let Some(fresh) = candidates.iter().copied().find(|p| p.same_route(&current)) else {
            // The current path is gone: choose again at once.
            let to = initial(candidates);
            route.path = to;
            route.since = now;
            route.last_switch = Some(now);
            route.pending = None;
            return Some(Change {
                prefix,
                region: region.clone(),
                from: Some(current),
                to,
                reason: hint.unwrap_or(Reason::Down),
            });
        };
        route.path = Some(fresh);
        let Some((kind, target, reason)) = switch_target(&fresh, candidates) else {
            route.pending = None;
            return None;
        };
        let started = match route.pending {
            Some((pending, since)) if pending == kind => since,
            _ => {
                route.pending = Some((kind, now));
                now
            }
        };
        let hold = match kind {
            Pending::Switch => SWITCH_HOLD,
            Pending::Recovery => RECOVERY_HOLD,
        };
        if now.saturating_duration_since(started) < hold {
            return None;
        }
        if route
            .last_switch
            .is_some_and(|last| now.saturating_duration_since(last) < MIN_SWITCH_INTERVAL)
        {
            return None;
        }
        route.path = Some(target);
        route.since = now;
        route.last_switch = Some(now);
        route.pending = None;
        Some(Change {
            prefix,
            region: region.clone(),
            from: Some(fresh),
            to: Some(target),
            reason,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::super::msg::{LinkCost, LinkState, RegionAdvert};
    use super::super::testutil::{net, rid, settings_json};
    use super::*;
    use serde_json::json;

    fn cn_settings() -> BackboneSettings {
        settings_json(json!({
            "id": 31,
            "region": "cn",
            "members": [
                { "id": 31, "region": "cn", "link": {} },
                { "id": 32, "region": "cn", "link": {} },
                { "id": 21, "region": "ap", "link": {} },
                { "id": 22, "region": "ap", "link": {} },
                { "id": 11, "region": "eu", "link": {} },
                { "id": 12, "region": "eu", "link": {} },
                { "id": 41, "region": "na", "link": {} }
            ],
            "policy": {
                "deny_link": [["cn", "eu"], ["cn", "na"]],
                "preferred_transit": { "cn": ["ap"] }
            }
        }))
    }

    fn eu_settings() -> BackboneSettings {
        let mut s = cn_settings();
        s.id = 11;
        s.region = rid("eu");
        s.deny_link.clear();
        s.preferred_transit.clear();
        s
    }

    struct World {
        settings: BackboneSettings,
        topology: Topology,
        links: BTreeMap<BackboneId, LocalLink>,
    }

    impl World {
        fn new(settings: BackboneSettings) -> Self {
            let mut topology = Topology::new(&settings);
            let own = if settings.region.as_str() == "cn" {
                "10.31.0.0/16"
            } else {
                "10.11.0.0/16"
            };
            topology.set_own_prefixes(vec![net(own)]);
            Self {
                settings,
                topology,
                links: BTreeMap::new(),
            }
        }

        fn advert(&mut self, origin: u32, region: &str, prefix: &str) {
            let seq = self
                .topology
                .advert(origin, Instant::now())
                .map_or(1, |(a, _)| a.seq + 1);
            self.topology.on_region_advert(
                RegionAdvert {
                    origin,
                    region: rid(region),
                    seq,
                    prefixes: vec![net(prefix)],
                    reachable: true,
                    lifetime_s: 600,
                },
                Instant::now(),
            );
        }

        fn state(&mut self, origin: u32, links: &[(u32, f64)]) {
            let seq = self.topology.link_state_seq(origin).unwrap_or(0) + 1;
            self.topology.on_link_state(
                LinkState {
                    origin,
                    seq,
                    links: links
                        .iter()
                        .map(|&(neighbor, cost)| LinkCost {
                            neighbor,
                            cost_milli: (cost * 1000.0) as u32,
                            loss_ppm: None,
                        })
                        .collect(),
                    lifetime_s: 600,
                },
                Instant::now(),
            );
        }

        fn link(&mut self, peer: u32, cost: f64, loss: f64) {
            self.links.insert(
                peer,
                LocalLink {
                    cost,
                    loss,
                    congested: false,
                },
            );
        }

        fn candidates(&self, prefix: &str, region: &str) -> Vec<Path> {
            let blocked = |_: BackboneId, _: &RegionId| false;
            View {
                settings: &self.settings,
                topology: &self.topology,
                links: &self.links,
                blocked: &blocked,
            }
            .candidates(&net(prefix), &rid(region))
        }
    }

    fn route(p: &Path) -> (BackboneId, Option<BackboneId>) {
        (p.egress, p.via)
    }

    #[test]
    fn mainland_to_europe_only_through_asia_pacific() {
        let mut w = World::new(cn_settings());
        w.advert(11, "eu", "10.11.0.0/16");
        w.advert(12, "eu", "10.11.0.0/16");
        w.link(11, 50.0, 0.0); // forbidden direct link, ignored
        w.link(21, 30.0, 0.0);
        w.link(32, 1.0, 0.0); // same-region transit, but 32 → eu is forbidden
        w.link(41, 10.0, 0.0); // forbidden region as transit
        w.state(21, &[(11, 200.0), (12, 150.0)]);
        w.state(32, &[(11, 10.0)]);
        w.state(41, &[(11, 10.0)]);
        let c = w.candidates("10.11.0.0/16", "eu");
        let routes: Vec<_> = c.iter().map(route).collect();
        assert_eq!(routes, vec![(11, Some(21)), (12, Some(21))]);
        let chosen = initial(&c).unwrap();
        assert_eq!(route(&chosen), (12, Some(21)));
        assert!((chosen.effective - 180.0 * PREFERRED_FACTOR).abs() < 1e-9);
    }

    #[test]
    fn healthy_direct_wins_initially_even_if_a_transit_is_cheaper() {
        let mut w = World::new(eu_settings());
        w.advert(21, "ap", "10.21.0.0/16");
        w.link(21, 200.0, 0.0);
        w.link(41, 10.0, 0.0);
        w.state(41, &[(21, 10.0)]);
        let c = w.candidates("10.21.0.0/16", "ap");
        assert_eq!(route(&initial(&c).unwrap()), (21, None));
        // Unhealthy direct: the cheapest by effective cost.
        w.link(21, 200.0, 0.06);
        let c = w.candidates("10.21.0.0/16", "ap");
        assert_eq!(route(&initial(&c).unwrap()), (21, Some(41)));
    }

    #[test]
    fn ties_go_to_the_smaller_exit_then_transit() {
        let a = Path {
            egress: 22,
            via: None,
            cost: 10.0,
            effective: 10.0,
            loss: 0.0,
            congested: false,
        };
        let b = Path { egress: 21, ..a };
        assert_eq!(initial(&[a, b]).unwrap().egress, 21);
        let t1 = Path {
            via: Some(42),
            loss: 0.5,
            ..b
        };
        let t2 = Path {
            via: Some(41),
            ..t1
        };
        assert_eq!(initial(&[t1, t2]).unwrap().via, Some(41));
    }

    fn direct(egress: u32, cost: f64, loss: f64) -> Path {
        Path {
            egress,
            via: None,
            cost,
            effective: cost,
            loss,
            congested: false,
        }
    }

    fn transit(egress: u32, via: u32, cost: f64) -> Path {
        Path {
            egress,
            via: Some(via),
            cost,
            effective: cost,
            loss: 0.0,
            congested: false,
        }
    }

    #[test]
    fn direct_to_transit_needs_a_clear_gain_for_five_seconds_and_sixty_since_the_last() {
        let t0 = Instant::now();
        let p = net("10.21.0.0/16");
        let r = rid("ap");
        let mut s = Selector::new();
        let change = s
            .evaluate(p, &r, &[direct(21, 100.0, 0.0)], None, t0)
            .unwrap();
        assert_eq!(change.reason, Reason::Initial);
        // Not enough gain (75 > 70).
        let c = [direct(21, 100.0, 0.0), transit(21, 41, 75.0)];
        assert!(s.evaluate(p, &r, &c, None, t0 + secs(61)).is_none());
        // Enough gain, but only after 5 s.
        let c = [direct(21, 100.0, 0.0), transit(21, 41, 60.0)];
        assert!(s.evaluate(p, &r, &c, None, t0 + secs(62)).is_none());
        assert!(s.evaluate(p, &r, &c, None, t0 + secs(66)).is_none());
        let change = s.evaluate(p, &r, &c, None, t0 + secs(67)).unwrap();
        assert_eq!(change.reason, Reason::Latency);
        assert_eq!(change.to.map(|p| route(&p)), Some((21, Some(41))));
        assert_eq!(s.first_hop(&p), Some(41));
    }

    #[test]
    fn condition_interruptions_restart_the_timer_and_the_interval_holds() {
        let t0 = Instant::now();
        let p = net("10.21.0.0/16");
        let r = rid("ap");
        let mut s = Selector::new();
        s.evaluate(p, &r, &[direct(21, 100.0, 0.0)], None, t0);
        let good = [direct(21, 100.0, 0.0), transit(21, 41, 60.0)];
        let bad = [direct(21, 100.0, 0.0), transit(21, 41, 90.0)];
        // Hold satisfied but the 60 s interval since the initial choice is not.
        assert!(s.evaluate(p, &r, &good, None, t0 + secs(1)).is_none());
        assert!(s.evaluate(p, &r, &good, None, t0 + secs(30)).is_none());
        assert!(s.evaluate(p, &r, &bad, None, t0 + secs(59)).is_none());
        assert!(s.evaluate(p, &r, &good, None, t0 + secs(60)).is_none());
        assert!(s.evaluate(p, &r, &good, None, t0 + secs(64)).is_none());
        assert!(s.evaluate(p, &r, &good, None, t0 + secs(65)).is_some());
    }

    #[test]
    fn loss_moves_off_direct_and_recovery_needs_thirty_seconds() {
        let t0 = Instant::now();
        let p = net("10.21.0.0/16");
        let r = rid("ap");
        let mut s = Selector::new();
        s.evaluate(p, &r, &[direct(21, 100.0, 0.0)], None, t0);
        // Lossy direct, transit more expensive: still switches after 5 s.
        let lossy = [direct(21, 100.0, 0.08), transit(21, 41, 150.0)];
        assert!(s.evaluate(p, &r, &lossy, None, t0 + secs(60)).is_none());
        let change = s.evaluate(p, &r, &lossy, None, t0 + secs(65)).unwrap();
        assert_eq!(change.reason, Reason::Loss);
        // Back to direct: loss ≤ 1 % and cost ≤ 0.9 × transit, for 30 s, and
        // 60 s after the last switch.
        let recovered = [direct(21, 100.0, 0.005), transit(21, 41, 150.0)];
        assert!(s
            .evaluate(p, &r, &recovered, None, t0 + secs(100))
            .is_none());
        assert!(s
            .evaluate(p, &r, &recovered, None, t0 + secs(129))
            .is_none());
        let change = s.evaluate(p, &r, &recovered, None, t0 + secs(130)).unwrap();
        assert_eq!(change.reason, Reason::Recovered);
        assert_eq!(change.to.map(|p| route(&p)), Some((21, None)));
        // Loss 2 %: not a recovery.
        let mut s2 = Selector::new();
        s2.evaluate(p, &r, &[transit(21, 41, 150.0)], None, t0);
        let partial = [direct(21, 100.0, 0.02), transit(21, 41, 150.0)];
        assert!(s2.evaluate(p, &r, &partial, None, t0 + secs(100)).is_none());
        assert!(s2.evaluate(p, &r, &partial, None, t0 + secs(200)).is_none());
    }

    #[test]
    fn a_vanished_path_is_replaced_at_once_with_the_hint() {
        let t0 = Instant::now();
        let p = net("10.21.0.0/16");
        let r = rid("ap");
        let mut s = Selector::new();
        s.evaluate(
            p,
            &r,
            &[transit(21, 41, 100.0), transit(21, 42, 120.0)],
            None,
            t0,
        );
        let change = s
            .evaluate(
                p,
                &r,
                &[transit(21, 42, 120.0)],
                Some(Reason::RelayUnreachable),
                t0 + secs(1),
            )
            .unwrap();
        assert_eq!(change.reason, Reason::RelayUnreachable);
        assert_eq!(s.first_hop(&p), Some(42));
        let change = s.evaluate(p, &r, &[], None, t0 + secs(2)).unwrap();
        assert_eq!((change.reason, change.to), (Reason::Down, None));
        assert_eq!(s.first_hop(&p), None);
        // A path comes back: a fresh initial choice.
        let change = s
            .evaluate(p, &r, &[direct(21, 10.0, 0.0)], None, t0 + secs(3))
            .unwrap();
        assert_eq!(change.reason, Reason::Initial);
    }

    #[test]
    fn direct_to_direct_and_transit_to_transit() {
        let t0 = Instant::now();
        let p = net("10.21.0.0/16");
        let r = rid("ap");
        let mut s = Selector::new();
        s.evaluate(p, &r, &[direct(21, 100.0, 0.0)], None, t0);
        let c = [direct(21, 100.0, 0.0), direct(22, 60.0, 0.0)];
        s.evaluate(p, &r, &c, None, t0 + secs(60));
        let change = s.evaluate(p, &r, &c, None, t0 + secs(65)).unwrap();
        assert_eq!(change.to.unwrap().egress, 22);
        let mut s = Selector::new();
        s.evaluate(p, &r, &[transit(21, 41, 200.0)], None, t0);
        let c = [transit(21, 41, 200.0), transit(21, 42, 130.0)];
        s.evaluate(p, &r, &c, None, t0 + secs(60));
        let change = s.evaluate(p, &r, &c, None, t0 + secs(65)).unwrap();
        assert_eq!(change.to.unwrap().via, Some(42));
    }

    fn secs(n: u64) -> Duration {
        Duration::from_secs(n)
    }
}
