//! One border node's backbone without I/O: links, control messages,
//! timers, path choice and forwarding decisions (spec §17.3, appendix A–C).
//!
//! The runtime feeds it link reports, received control messages and IP
//! packet addresses, calls [`Backbone::tick`] about once a second, and sends
//! what [`Backbone::drain_outputs`] returns. Nothing here blocks or touches
//! a socket.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::net::IpAddr;
use std::time::{Duration, Instant};

use serde::Serialize;

use super::config::BackboneSettings;
use super::forward::{self, DropReason, Verdict};
use super::metrics::{cost_milli, LinkReport, LinkTracker};
use super::msg::{
    LinkCost, LinkState, Message, RegionAdvert, SeqCounter, LINK_STATE_LIFETIME_S, MAX_PREFIXES,
    REGION_ADVERT_LIFETIME_S,
};
use super::region::{is_summary_prefix, RegionId};
use super::select::{Change, LocalLink, Path, Reason, Selector, View};
use super::topology::{Outcome, Reject, Topology};
use super::BackboneId;
use crate::net::IpNet;

/// Region advert refresh (spec §17.3.3).
pub const ADVERT_INTERVAL: Duration = Duration::from_secs(30);
/// Link state refresh (spec §17.3.4).
pub const LINK_STATE_INTERVAL: Duration = Duration::from_secs(10);
/// A transit named by RelayUnreachable stays blocked at least this long.
pub const RELAY_BLOCK: Duration = Duration::from_secs(10);
/// At most one RelayUnreachable per (peer, region) per this interval.
pub const RELAY_NOTICE_INTERVAL: Duration = Duration::from_secs(1);
/// Path changes reported per second, at most (appendix C.2).
pub const MAX_EVENTS_PER_SECOND: usize = 50;
/// Alerts that clear after this long without a recurrence.
pub const ALERT_QUIET: Duration = Duration::from_secs(300);

/// Something to send.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Output {
    /// A control message on the link to `peer`.
    Control { peer: BackboneId, bytes: Vec<u8> },
    /// A control message of a type this module does not handle (NameAdvert),
    /// for the module that does.
    Unhandled {
        peer: BackboneId,
        kind: u8,
        payload: Vec<u8>,
    },
}

/// Drop counters (appendix C.1).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
pub struct Counters {
    pub no_route: u64,
    pub access: u64,
    pub relay_unreachable: u64,
    pub inconsistent: u64,
    pub not_for_us: u64,
    pub bad_message: u64,
    pub unknown_type: u64,
    pub link_send: u64,
    pub events_dropped: u64,
}

/// One current alert (appendix C.1, C.2).
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Alert {
    pub code: &'static str,
    pub peer: BackboneId,
    pub detail: String,
}

/// A path change as reported (appendix C.2).
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct RouteEvent {
    pub kind: &'static str,
    #[serde(serialize_with = "display")]
    pub prefix: IpNet,
    pub region: String,
    pub from: Option<PathView>,
    pub to: Option<PathView>,
    pub reason: &'static str,
}

#[derive(Clone, Copy, Debug, PartialEq, Serialize)]
pub struct PathView {
    pub egress: BackboneId,
    pub via: Option<BackboneId>,
}

impl From<&Path> for PathView {
    fn from(p: &Path) -> Self {
        Self {
            egress: p.egress,
            via: p.via,
        }
    }
}

fn display<S: serde::Serializer, T: std::fmt::Display>(v: &T, s: S) -> Result<S::Ok, S::Error> {
    s.collect_str(v)
}

fn display_all<S: serde::Serializer>(v: &[IpNet], s: S) -> Result<S::Ok, S::Error> {
    s.collect_seq(v.iter().map(ToString::to_string))
}

/// The `backbone` status object (appendix C.1); the runtime adds
/// `running` and `failure`.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct Status {
    pub id: BackboneId,
    pub region: String,
    pub links: Vec<LinkStatus>,
    pub regions: Vec<RegionStatus>,
    pub routes: Vec<RouteStatus>,
    pub withdrawn: bool,
    pub counters: Counters,
    pub alerts: Vec<Alert>,
}

impl Status {
    /// The status of a backbone that does not run: nothing known, the
    /// summaries withdrawn.
    pub fn idle(id: BackboneId, region: &RegionId) -> Self {
        Self {
            id,
            region: region.to_string(),
            links: Vec::new(),
            regions: Vec::new(),
            routes: Vec::new(),
            withdrawn: true,
            counters: Counters::default(),
            alerts: Vec::new(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct LinkStatus {
    pub peer: BackboneId,
    pub region: String,
    /// The link's transport name, filled in by the runtime from the link's
    /// own report; empty until then.
    pub transport: String,
    pub up: bool,
    pub forward_secrecy: bool,
    pub rtt_ms: Option<f64>,
    pub loss_ppm: Option<u32>,
    pub jitter_ms: Option<f64>,
    pub cost: Option<f64>,
    pub usable: bool,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct RegionStatus {
    pub region: String,
    #[serde(serialize_with = "display_all")]
    pub prefixes: Vec<IpNet>,
    pub borders: Vec<BorderStatus>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct BorderStatus {
    pub id: BackboneId,
    pub reachable: bool,
    pub expires_in_s: u64,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct RouteStatus {
    #[serde(serialize_with = "display")]
    pub prefix: IpNet,
    pub region: String,
    pub egress: Option<BackboneId>,
    pub via: Option<BackboneId>,
    pub cost: Option<f64>,
    /// Seconds since this path was chosen.
    pub since_s: u64,
}

#[derive(Clone, Copy, Debug)]
struct Block {
    until: Instant,
    seq: Option<u64>,
}

/// The backbone of one border node.
pub struct Backbone {
    settings: BackboneSettings,
    topology: Topology,
    selector: Selector,
    trackers: BTreeMap<BackboneId, LinkTracker>,
    advert_seq: SeqCounter,
    state_seq: SeqCounter,
    own_prefixes: Vec<IpNet>,
    reachable: bool,
    last_advert: Option<Instant>,
    advert_dirty: bool,
    last_state: Option<Instant>,
    published_costs: BTreeMap<BackboneId, f64>,
    blocked: BTreeMap<(BackboneId, RegionId), Block>,
    hints: BTreeMap<RegionId, Reason>,
    relay_notices: BTreeMap<(BackboneId, RegionId), Instant>,
    last_inconsistent: Option<(Instant, BackboneId)>,
    last_seq_duplicate: Option<(Instant, BackboneId)>,
    counters: Counters,
    outbox: Vec<Output>,
    events: VecDeque<RouteEvent>,
    event_window: (Instant, usize),
}

impl Backbone {
    /// `unix_ms` is the current Unix time in milliseconds, for sequence
    /// numbers.
    pub fn new(settings: BackboneSettings, now: Instant, unix_ms: u64) -> Self {
        let topology = Topology::new(&settings);
        let trackers = settings
            .members
            .keys()
            .filter(|id| **id != settings.id)
            .map(|id| (*id, LinkTracker::new(now)))
            .collect();
        Self {
            settings,
            topology,
            selector: Selector::new(),
            trackers,
            advert_seq: SeqCounter::new(unix_ms),
            state_seq: SeqCounter::new(unix_ms),
            own_prefixes: Vec::new(),
            reachable: false,
            last_advert: None,
            advert_dirty: true,
            last_state: None,
            published_costs: BTreeMap::new(),
            blocked: BTreeMap::new(),
            hints: BTreeMap::new(),
            relay_notices: BTreeMap::new(),
            last_inconsistent: None,
            last_seq_duplicate: None,
            counters: Counters::default(),
            outbox: Vec::new(),
            events: VecDeque::new(),
            event_window: (now, 0),
        }
    }

    pub fn settings(&self) -> &BackboneSettings {
        &self.settings
    }

    pub fn topology(&self) -> &Topology {
        &self.topology
    }

    /// Replaces the settings (a new `backbone` section with the same ID).
    /// Links of removed members are dropped, new members get fresh links,
    /// and every path is chosen again under the new policy.
    pub fn set_settings(&mut self, settings: BackboneSettings, now: Instant) {
        self.trackers
            .retain(|id, _| *id != settings.id && settings.members.contains_key(id));
        for id in settings.members.keys() {
            if *id != settings.id {
                self.trackers
                    .entry(*id)
                    .or_insert_with(|| LinkTracker::new(now));
            }
        }
        self.topology.set_members(&settings);
        self.settings = settings;
        for region in self.topology.foreign_regions() {
            self.hints.insert(region, Reason::Policy);
        }
        self.set_prefixes_inner();
        self.advert_dirty = true;
        self.reselect(now);
    }

    /// This region's summary from the region network: its virtual subnet and
    /// its members' advertised subnets and host-group ranges; and whether
    /// this node is connected to that network. The configured extra
    /// prefixes are added here. Prefixes that cannot be summaries are left
    /// out.
    pub fn set_region(&mut self, prefixes: Vec<IpNet>, reachable: bool, now: Instant) {
        let changed_reach = reachable != self.reachable;
        self.reachable = reachable;
        let before = self.own_prefixes.clone();
        self.own_prefixes = prefixes;
        self.set_prefixes_inner();
        if changed_reach || before != self.own_prefixes {
            self.advert_dirty = true;
            self.reselect(now);
        }
    }

    fn set_prefixes_inner(&mut self) {
        let mut set: BTreeSet<IpNet> = self
            .own_prefixes
            .iter()
            .chain(self.settings.extra_prefixes.iter())
            .map(IpNet::trunc)
            .filter(is_summary_prefix)
            .collect();
        while set.len() > MAX_PREFIXES {
            set.pop_last();
        }
        self.own_prefixes = set.into_iter().collect();
        self.topology.set_own_prefixes(self.own_prefixes.clone());
    }

    /// Whether any backbone link is usable. When none is, the runtime
    /// withdraws the foreign summaries from the region network within 3 s
    /// (spec §15.6 item 6).
    pub fn connected(&self) -> bool {
        self.trackers.values().any(LinkTracker::usable)
    }

    /// Foreign summary prefixes this node advertises into its region network
    /// (spec §15.6 item 3): those with a chosen path, and none while the
    /// backbone is disconnected.
    pub fn region_advertisement(&self) -> Vec<IpNet> {
        if !self.connected() {
            return Vec::new();
        }
        self.selector
            .routes()
            .filter(|(_, route)| route.path.is_some())
            .map(|(prefix, _)| *prefix)
            .collect()
    }

    /// The source and destination allow lists for the link to `peer` (A.8).
    pub fn receive_policy(&self, peer: BackboneId) -> (Vec<IpNet>, Vec<IpNet>) {
        match self.settings.region_of(peer) {
            Some(region) => forward::receive_policy(&self.settings, &self.topology, region),
            None => (Vec::new(), Vec::new()),
        }
    }

    /// Takes a link's latest report.
    pub fn on_link_report(&mut self, peer: BackboneId, report: LinkReport, now: Instant) {
        let Some(tracker) = self.trackers.get_mut(&peer) else {
            return;
        };
        if tracker.update(report, now) {
            self.reselect(now);
            self.publish_link_state(now, true);
        }
    }

    fn control_peers(&self) -> Vec<BackboneId> {
        self.trackers
            .iter()
            .filter(|(_, t)| t.report().up && t.report().forward_secrecy)
            .map(|(id, _)| *id)
            .collect()
    }

    fn send(&mut self, peer: BackboneId, message: &Message) {
        self.outbox.push(Output::Control {
            peer,
            bytes: message.encode(),
        });
    }

    fn flood(&mut self, bytes: &[u8], except: &[BackboneId]) {
        for peer in self.control_peers() {
            if !except.contains(&peer) {
                self.outbox.push(Output::Control {
                    peer,
                    bytes: bytes.to_vec(),
                });
            }
        }
    }

    /// Takes one control message received on the link to `peer`.
    pub fn on_control(&mut self, peer: BackboneId, bytes: &[u8], now: Instant) {
        // Nothing is taken over a link without forward secrecy (A.6 item 1).
        let Some(tracker) = self.trackers.get(&peer) else {
            self.counters.bad_message += 1;
            return;
        };
        if !(tracker.report().up && tracker.report().forward_secrecy) {
            self.counters.bad_message += 1;
            return;
        }
        let message = match Message::decode(bytes) {
            Ok(message) => message,
            Err(_) => {
                self.counters.bad_message += 1;
                return;
            }
        };
        match message {
            Message::Probe(probe) => self.send(peer, &Message::ProbeAck(probe)),
            Message::ProbeAck(probe) => {
                if let Some(t) = self.trackers.get_mut(&peer) {
                    t.on_probe_ack(probe, now);
                }
            }
            Message::RegionAdvert(advert) => {
                let origin = advert.origin;
                match self.topology.on_region_advert(advert, now) {
                    Outcome::New => {
                        self.flood(bytes, &[peer, origin]);
                        self.reselect(now);
                    }
                    Outcome::Stale => {}
                    Outcome::Rejected(reason) => self.rejected(reason, peer, now),
                }
            }
            Message::LinkState(state) => {
                let origin = state.origin;
                match self.topology.on_link_state(state, now) {
                    Outcome::New => {
                        self.flood(bytes, &[peer, origin]);
                        self.unblock(now);
                        self.reselect(now);
                    }
                    Outcome::Stale => {}
                    Outcome::Rejected(reason) => self.rejected(reason, peer, now),
                }
            }
            Message::RelayUnreachable { region } => {
                let seq = self.topology.link_state_seq(peer);
                self.blocked.insert(
                    (peer, region.clone()),
                    Block {
                        until: now + RELAY_BLOCK,
                        seq,
                    },
                );
                self.hints.insert(region, Reason::RelayUnreachable);
                self.reselect(now);
            }
            Message::Other { kind, payload } => {
                if kind == super::msg::kind::NAME_ADVERT {
                    self.outbox.push(Output::Unhandled {
                        peer,
                        kind,
                        payload,
                    });
                } else {
                    self.counters.unknown_type += 1;
                }
            }
        }
    }

    fn rejected(&mut self, reason: Reject, peer: BackboneId, now: Instant) {
        self.counters.bad_message += 1;
        if reason == Reject::SeqDuplicate {
            self.last_seq_duplicate = Some((now, peer));
        }
    }

    fn unblock(&mut self, now: Instant) {
        let topology = &self.topology;
        self.blocked.retain(|(via, _), block| {
            now < block.until || topology.link_state_seq(*via) <= block.seq
        });
    }

    /// Timers: probes, expiry, refreshes and path re-evaluation. Call about
    /// once a second.
    pub fn tick(&mut self, now: Instant, unix_ms: u64) {
        let probes: Vec<(BackboneId, Message)> = self
            .trackers
            .iter_mut()
            .filter_map(|(id, t)| t.probe_due(now).map(|p| (*id, Message::Probe(p))))
            .collect();
        for (peer, message) in probes {
            self.send(peer, &message);
        }
        // Probed metrics change with time (timeouts count as loss).
        let reports: Vec<(BackboneId, LinkReport)> = self
            .trackers
            .iter()
            .map(|(id, t)| (*id, *t.report()))
            .collect();
        for (id, report) in reports {
            if let Some(t) = self.trackers.get_mut(&id) {
                t.update(report, now);
            }
        }
        self.topology.expire(now);
        self.unblock(now);
        self.relay_notices
            .retain(|_, at| now.saturating_duration_since(*at) < RELAY_NOTICE_INTERVAL);
        let advert_due = self
            .last_advert
            .is_none_or(|at| now.saturating_duration_since(at) >= ADVERT_INTERVAL);
        if self.advert_dirty || advert_due {
            self.publish_advert(now, unix_ms);
        }
        self.reselect(now);
        self.publish_link_state_at(now, unix_ms, false);
    }

    fn publish_advert(&mut self, now: Instant, unix_ms: u64) {
        let advert = RegionAdvert {
            origin: self.settings.id,
            region: self.settings.region.clone(),
            seq: self.advert_seq.next(unix_ms),
            prefixes: self.own_prefixes.clone(),
            reachable: self.reachable,
            lifetime_s: REGION_ADVERT_LIFETIME_S,
        };
        let bytes = Message::RegionAdvert(advert).encode();
        self.flood(&bytes, &[]);
        self.last_advert = Some(now);
        self.advert_dirty = false;
    }

    fn own_links(&self) -> BTreeMap<BackboneId, f64> {
        self.trackers
            .iter()
            .filter_map(|(id, t)| t.cost().map(|c| (*id, c)))
            .collect()
    }

    fn publish_link_state(&mut self, now: Instant, force: bool) {
        // Sequence numbers need wall time; a forced publish uses the last
        // sequence plus one, which is always newer.
        self.publish_link_state_at(now, 0, force);
    }

    fn publish_link_state_at(&mut self, now: Instant, unix_ms: u64, force: bool) {
        let links = self.own_links();
        let significant = links.len() != self.published_costs.len()
            || links
                .iter()
                .any(|(id, cost)| match self.published_costs.get(id) {
                    None => true,
                    Some(old) => {
                        let diff = (cost - old).abs();
                        diff > 0.2 * old.abs() && diff > 10.0
                    }
                });
        let due = self
            .last_state
            .is_none_or(|at| now.saturating_duration_since(at) >= LINK_STATE_INTERVAL);
        if !(force || significant || due) {
            return;
        }
        let state = LinkState {
            origin: self.settings.id,
            seq: self.state_seq.next(unix_ms),
            links: links
                .iter()
                .map(|(id, cost)| LinkCost {
                    neighbor: *id,
                    cost_milli: cost_milli(*cost),
                    loss_ppm: self.trackers[id]
                        .loss()
                        .map(|l| (l * 1_000_000.0).round() as u32),
                })
                .collect(),
            lifetime_s: LINK_STATE_LIFETIME_S,
        };
        let bytes = Message::LinkState(state).encode();
        self.flood(&bytes, &[]);
        self.published_costs = links;
        self.last_state = Some(now);
    }

    fn local_links(&self) -> BTreeMap<BackboneId, LocalLink> {
        self.trackers
            .iter()
            .filter_map(|(id, t)| {
                let metrics = t.metrics()?;
                Some((
                    *id,
                    LocalLink {
                        cost: t.cost()?,
                        loss: t.loss()?,
                        congested: metrics.congestion_factor() > 1.0,
                    },
                ))
            })
            .collect()
    }

    /// Chooses paths again for every foreign prefix.
    fn reselect(&mut self, now: Instant) {
        let foreign = self.topology.foreign_prefixes();
        for (prefix, route) in self.selector.retain(&foreign) {
            if let Some(from) = route.path {
                self.push_event(
                    Change {
                        prefix,
                        region: route.region,
                        from: Some(from),
                        to: None,
                        reason: Reason::Down,
                    },
                    now,
                );
            }
        }
        let links = self.local_links();
        let blocked = &self.blocked;
        let is_blocked =
            |via: BackboneId, region: &RegionId| blocked.contains_key(&(via, region.clone()));
        let view = View {
            settings: &self.settings,
            topology: &self.topology,
            links: &links,
            blocked: &is_blocked,
        };
        let mut changes = Vec::new();
        for (prefix, region) in &foreign {
            let candidates = view.candidates(prefix, region);
            let hint = self.hints.get(region).copied();
            if let Some(change) = self
                .selector
                .evaluate(*prefix, region, &candidates, hint, now)
            {
                changes.push(change);
            }
        }
        self.hints.clear();
        for change in changes {
            self.push_event(change, now);
        }
    }

    fn push_event(&mut self, change: Change, now: Instant) {
        if now.saturating_duration_since(self.event_window.0) >= Duration::from_secs(1) {
            self.event_window = (now, 0);
        }
        if self.event_window.1 >= MAX_EVENTS_PER_SECOND {
            self.counters.events_dropped += 1;
            return;
        }
        self.event_window.1 += 1;
        self.events.push_back(RouteEvent {
            kind: "backbone_route_changed",
            prefix: change.prefix,
            region: change.region.to_string(),
            from: change.from.as_ref().map(PathView::from),
            to: change.to.as_ref().map(PathView::from),
            reason: change.reason.as_str(),
        });
    }

    /// A packet from the region network for a foreign destination.
    pub fn ingress(&mut self, src: IpAddr, dst: IpAddr) -> Verdict {
        let verdict = forward::ingress(&self.settings, &self.topology, &self.selector, src, dst);
        self.count(&verdict);
        verdict
    }

    /// A packet received on the link to `from`. A RelayUnreachable for the
    /// previous hop is queued when due.
    pub fn receive(&mut self, from: BackboneId, src: IpAddr, dst: IpAddr, now: Instant) -> Verdict {
        let links = self.local_links();
        let verdict = forward::receive(&self.settings, &self.topology, &links, from, src, dst);
        self.count(&verdict);
        match &verdict {
            Verdict::DropAndNotify { peer, region } => {
                let key = (*peer, region.clone());
                if let std::collections::btree_map::Entry::Vacant(slot) =
                    self.relay_notices.entry(key)
                {
                    slot.insert(now);
                    let message = Message::RelayUnreachable {
                        region: region.clone(),
                    };
                    self.send(*peer, &message);
                }
            }
            Verdict::Drop(DropReason::Inconsistent) => {
                self.last_inconsistent = Some((now, from));
            }
            _ => {}
        }
        verdict
    }

    /// Counts a failed `try_send` on a link (appendix A.7 ingress step 4).
    pub fn link_send_failed(&mut self) {
        self.counters.link_send += 1;
    }

    /// Counts a packet for this region dropped because the node is not
    /// connected to its region network.
    pub fn exit_failed(&mut self) {
        self.counters.no_route += 1;
    }

    fn count(&mut self, verdict: &Verdict) {
        let reason = match verdict {
            Verdict::Drop(reason) => *reason,
            Verdict::DropAndNotify { .. } => DropReason::RelayUnreachable,
            _ => return,
        };
        let c = &mut self.counters;
        match reason {
            DropReason::NoRoute => c.no_route += 1,
            DropReason::Access => c.access += 1,
            DropReason::Inconsistent => c.inconsistent += 1,
            DropReason::NotForUs => c.not_for_us += 1,
            DropReason::RelayUnreachable => c.relay_unreachable += 1,
        }
    }

    /// What to send, in order.
    pub fn drain_outputs(&mut self) -> Vec<Output> {
        std::mem::take(&mut self.outbox)
    }

    /// Path changes since the last call.
    pub fn drain_events(&mut self) -> Vec<RouteEvent> {
        self.events.drain(..).collect()
    }

    /// The current alerts (appendix C.2).
    pub fn alerts(&self, now: Instant) -> Vec<Alert> {
        let mut alerts = Vec::new();
        for (id, t) in &self.trackers {
            if t.insecure() {
                alerts.push(Alert {
                    code: "backbone_link_insecure",
                    peer: *id,
                    detail: String::new(),
                });
            }
        }
        if let Some((at, peer)) = self.last_inconsistent {
            if now.saturating_duration_since(at) < ALERT_QUIET {
                alerts.push(Alert {
                    code: "backbone_forward_inconsistent",
                    peer,
                    detail: String::new(),
                });
            }
        }
        for net in self.topology.conflicts() {
            alerts.push(Alert {
                code: "backbone_prefix_conflict",
                peer: 0,
                detail: net.to_string(),
            });
        }
        if let Some((at, peer)) = self.last_seq_duplicate {
            if now.saturating_duration_since(at) < ALERT_QUIET {
                alerts.push(Alert {
                    code: "backbone_seq_duplicate",
                    peer,
                    detail: String::new(),
                });
            }
        }
        let mut reachable: BTreeMap<String, bool> = BTreeMap::new();
        for (_, route) in self.selector.routes() {
            *reachable.entry(route.region.to_string()).or_default() |= route.path.is_some();
        }
        for (region, ok) in reachable {
            if !ok {
                alerts.push(Alert {
                    code: "backbone_region_unreachable",
                    peer: 0,
                    detail: region,
                });
            }
        }
        alerts
    }

    /// The status object (appendix C.1).
    pub fn status(&self, now: Instant) -> Status {
        let links = self
            .trackers
            .iter()
            .map(|(id, t)| {
                let metrics = t.metrics();
                LinkStatus {
                    peer: *id,
                    region: self
                        .settings
                        .region_of(*id)
                        .map(ToString::to_string)
                        .unwrap_or_default(),
                    transport: String::new(),
                    up: t.report().up,
                    forward_secrecy: t.report().forward_secrecy,
                    rtt_ms: metrics.map(|m| m.rtt_ms),
                    loss_ppm: metrics.map(|m| (m.loss * 1_000_000.0).round() as u32),
                    jitter_ms: metrics.map(|m| m.jitter_ms),
                    cost: t.cost(),
                    usable: t.usable(),
                }
            })
            .collect();
        let regions = self
            .topology
            .foreign_regions()
            .into_iter()
            .map(|region| {
                let borders = self
                    .topology
                    .members()
                    .filter(|(_, r)| **r == region)
                    .filter_map(|(id, _)| {
                        let (advert, left) = self.topology.advert(id, now)?;
                        Some(BorderStatus {
                            id,
                            reachable: advert.reachable,
                            expires_in_s: left.as_secs(),
                        })
                    })
                    .collect();
                RegionStatus {
                    prefixes: self.topology.region_prefixes(&region).into_iter().collect(),
                    region: region.to_string(),
                    borders,
                }
            })
            .collect();
        let routes = self
            .selector
            .routes()
            .map(|(prefix, route)| RouteStatus {
                prefix: *prefix,
                region: route.region.to_string(),
                egress: route.path.map(|p| p.egress),
                via: route.path.and_then(|p| p.via),
                cost: route.path.map(|p| p.cost),
                since_s: now.saturating_duration_since(route.since).as_secs(),
            })
            .collect();
        Status {
            id: self.settings.id,
            region: self.settings.region.to_string(),
            links,
            regions,
            routes,
            withdrawn: !self.connected(),
            counters: self.counters,
            alerts: self.alerts(now),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::msg::{kind, Probe};
    use super::super::testutil::{net, rid, settings};
    use super::*;

    fn good() -> LinkReport {
        LinkReport {
            up: true,
            forward_secrecy: true,
            rtt_ms: Some(20.0),
            loss: Some(0.0),
            jitter_ms: Some(1.0),
            utilization: None,
        }
    }

    fn secs(n: u64) -> Duration {
        Duration::from_secs(n)
    }

    fn controls(outputs: &[Output]) -> Vec<(BackboneId, Message)> {
        outputs
            .iter()
            .filter_map(|o| match o {
                Output::Control { peer, bytes } => Some((*peer, Message::decode(bytes).unwrap())),
                _ => None,
            })
            .collect()
    }

    fn advert_bytes(origin: u32, region: &str, seq: u64, prefix: &str) -> Vec<u8> {
        Message::RegionAdvert(RegionAdvert {
            origin,
            region: rid(region),
            seq,
            prefixes: vec![net(prefix)],
            reachable: true,
            lifetime_s: 90,
        })
        .encode()
    }

    /// This node 11 (eu, 10.20/16); peers 12 (eu), 21/22 (ap), 31 (cn).
    fn backbone(t0: Instant) -> Backbone {
        let mut s = settings();
        s.access = vec![super::super::config::AccessRule {
            from: vec![net("10.20.0.0/16")],
            to: vec![net("10.30.0.0/16")],
        }];
        let mut b = Backbone::new(s, t0, 1_000);
        b.set_region(vec![net("10.20.0.0/16")], true, t0);
        for peer in [12, 21, 22, 31] {
            b.on_link_report(peer, good(), t0);
        }
        b
    }

    #[test]
    fn publishes_its_advert_and_link_state_once_links_are_up() {
        let t0 = Instant::now();
        let mut b = backbone(t0);
        b.drain_outputs();
        b.tick(t0, 1_000);
        let sent = controls(&b.drain_outputs());
        let adverts: Vec<_> = sent
            .iter()
            .filter_map(|(peer, m)| match m {
                Message::RegionAdvert(a) => Some((*peer, a.clone())),
                _ => None,
            })
            .collect();
        assert_eq!(adverts.len(), 4, "one per link with forward secrecy");
        assert_eq!(adverts[0].1.prefixes, vec![net("10.20.0.0/16")]);
        assert!(adverts[0].1.reachable);
        // Links are not usable for 10 s: the first link state is empty.
        let states: Vec<_> = sent
            .iter()
            .filter_map(|(_, m)| match m {
                Message::LinkState(s) => Some(s.clone()),
                _ => None,
            })
            .collect();
        assert!(states.iter().all(|s| s.links.is_empty()));
        // After 10 s the links are usable and announced.
        for peer in [12, 21, 22, 31] {
            b.on_link_report(peer, good(), t0 + secs(10));
        }
        let sent = controls(&b.drain_outputs());
        let state = sent
            .iter()
            .rev()
            .find_map(|(_, m)| match m {
                Message::LinkState(s) => Some(s.clone()),
                _ => None,
            })
            .unwrap();
        assert_eq!(state.links.len(), 4);
        assert_eq!(state.links[0].cost_milli, 22_000);
        assert!(b.connected());
    }

    #[test]
    fn adverts_are_flooded_once_and_routes_follow() {
        let t0 = Instant::now();
        let mut b = backbone(t0);
        for peer in [12, 21, 22, 31] {
            b.on_link_report(peer, good(), t0 + secs(10));
        }
        b.drain_outputs();
        let bytes = advert_bytes(21, "ap", 5, "10.30.0.0/16");
        b.on_control(21, &bytes, t0 + secs(11));
        let flooded: Vec<_> = controls(&b.drain_outputs())
            .into_iter()
            .filter(|(_, m)| matches!(m, Message::RegionAdvert(_)))
            .map(|(peer, _)| peer)
            .collect();
        assert_eq!(flooded, vec![12, 22, 31]);
        b.on_control(31, &bytes, t0 + secs(11));
        assert!(
            controls(&b.drain_outputs()).is_empty(),
            "stale: not flooded again"
        );
        // Direct path to 21 chosen.
        let events = b.drain_events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].reason, "initial");
        assert_eq!(
            events[0].to,
            Some(PathView {
                egress: 21,
                via: None
            })
        );
        assert_eq!(
            b.ingress("10.20.0.1".parse().unwrap(), "10.30.0.1".parse().unwrap()),
            Verdict::Send(21)
        );
        assert_eq!(b.region_advertisement(), vec![net("10.30.0.0/16")]);
        // All links lost: summaries withdrawn.
        for peer in [12, 21, 22, 31] {
            b.on_link_report(peer, LinkReport::default(), t0 + secs(12));
        }
        assert!(b.region_advertisement().is_empty());
        assert!(b.status(t0 + secs(12)).withdrawn);
    }

    #[test]
    fn probes_are_answered_and_insecure_links_refused() {
        let t0 = Instant::now();
        let mut b = backbone(t0);
        b.drain_outputs();
        let probe = Message::Probe(Probe { seq: 1, sent_us: 9 }).encode();
        b.on_control(21, &probe, t0);
        assert_eq!(
            controls(&b.drain_outputs()),
            vec![(21, Message::ProbeAck(Probe { seq: 1, sent_us: 9 }))]
        );
        let insecure = LinkReport {
            forward_secrecy: false,
            ..good()
        };
        b.on_link_report(21, insecure, t0);
        b.on_control(21, &probe, t0);
        assert!(b.drain_outputs().is_empty());
        assert_eq!(b.status(t0).counters.bad_message, 1);
        assert!(b
            .alerts(t0)
            .iter()
            .any(|a| a.code == "backbone_link_insecure" && a.peer == 21));
    }

    #[test]
    fn relay_unreachable_blocks_the_transit_and_name_adverts_pass_through() {
        let t0 = Instant::now();
        let mut b = backbone(t0);
        b.on_control(21, &advert_bytes(21, "ap", 1, "10.30.0.0/16"), t0);
        b.on_control(31, &[kind::RELAY_UNREACHABLE, 0x0a, 2, b'a', b'p'], t0);
        assert!(b.blocked.contains_key(&(31, rid("ap"))));
        b.tick(t0 + secs(11), 2_000);
        assert!(
            b.blocked.contains_key(&(31, rid("ap"))),
            "kept until a newer link state from 31"
        );
        let state = Message::LinkState(LinkState {
            origin: 31,
            seq: 10,
            links: vec![],
            lifetime_s: 60,
        })
        .encode();
        b.on_control(31, &state, t0 + secs(12));
        assert!(!b.blocked.contains_key(&(31, rid("ap"))));
        b.drain_outputs();
        b.on_control(22, &[kind::NAME_ADVERT, 1], t0);
        assert_eq!(
            b.drain_outputs(),
            vec![Output::Unhandled {
                peer: 22,
                kind: kind::NAME_ADVERT,
                payload: vec![1]
            }]
        );
        b.on_control(22, &[99], t0);
        assert_eq!(b.status(t0).counters.unknown_type, 1);
    }

    #[test]
    fn transit_notices_are_rate_limited() {
        let t0 = Instant::now();
        let mut b = backbone(t0);
        // cn advertises 10.40/16; ap has no exit known: a cn → ap packet
        // cannot be relayed.
        b.on_control(31, &advert_bytes(31, "cn", 1, "10.40.0.0/16"), t0);
        b.on_control(22, &advert_bytes(22, "ap", 1, "10.30.0.0/16"), t0);
        b.on_link_report(22, LinkReport::default(), t0);
        b.drain_outputs();
        let src = "10.40.0.1".parse().unwrap();
        let dst = "10.30.0.1".parse().unwrap();
        for _ in 0..3 {
            assert!(matches!(
                b.receive(31, src, dst, t0),
                Verdict::DropAndNotify { peer: 31, .. }
            ));
        }
        let notices = controls(&b.drain_outputs());
        assert_eq!(
            notices,
            vec![(31, Message::RelayUnreachable { region: rid("ap") })]
        );
        assert_eq!(b.status(t0).counters.relay_unreachable, 3);
    }

    #[test]
    fn status_serializes_with_snake_case_fields() {
        let t0 = Instant::now();
        let b = backbone(t0);
        let json = serde_json::to_value(b.status(t0)).unwrap();
        assert_eq!(json["region"], "eu");
        assert!(json["links"][0].get("forward_secrecy").is_some());
        assert!(json["links"][0].get("rtt_ms").is_some());
        assert!(json["counters"].get("no_route").is_some());
    }
}
