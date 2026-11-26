//! A border node's backbone (spec §15.6, §17.3; requirements R18, R19, R22):
//! the backbone links to the other border nodes, the backbone module's
//! route choice and forwarding, and the exchange with this region's managed
//! network (`docs/protocols/intranet-mesh-appendix.md`).
//!
//! Every managed network has a [`Hub`], made with the network and kept while
//! its tag stays in the request, so that the backbone and the network can
//! each restart without the other:
//!
//! - the network's driver takes the other regions' summary prefixes to
//!   carry (`prefixes`), hands packets for them to the backbone and sends
//!   what the backbone delivers ([`Hub::driver_side`]);
//! - the network publishes what the backbone advertises for this region
//!   ([`RegionView`]): its virtual subnets, the subnets its members
//!   advertise, and whether this node is connected to it.
//!
//! The backbone opens one link to each other member through the kernel's
//! registry of link kinds ([`engine_outbound::backbone`]), with that
//! member's `link` from the request: `kind` and the opaque `params`. The
//! open kernel registers no kind, so there the backbone reports
//! `backbone_kind_unavailable` and the region network runs as usual. Link
//! parameters are never stored beyond the open call, printed or echoed:
//! failures name the field path and a fixed reason only.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use engine_outbound::backbone::{
    backbone_factory, BackboneLink, BackbonePacket, BackboneStats, IpPrefix, PacketPolicy,
};
use outbound_mesh::backbone::config::LinkConfig;
use outbound_mesh::backbone::engine::{Output, Status};
use outbound_mesh::backbone::{Backbone, BackboneId, BackboneSettings, LinkReport, Verdict};
use outbound_mesh::driver::{Border, Snapshot};
use outbound_mesh::packet;
use outbound_mesh::status::{
    BackboneEvent, BackboneFailure, ManagedBackbone, ManagedBackboneStatus,
};
use outbound_mesh::{IpNet, MeshSettings};
use tokio::sync::{mpsc, oneshot, watch};
use tokio::task::JoinHandle;

/// Packets queued between a network and its backbone, each way.
const QUEUE: usize = 1024;
/// Packets queued from all links of a backbone towards its task.
const LINK_QUEUE: usize = 4096;
/// The backbone's timer: probes, reports, route choice; also how soon the
/// summaries are withdrawn after the last link is lost (at most 3 s, spec
/// §15.6 item 6).
const TICK: Duration = Duration::from_secs(1);
/// Path changes kept in the status for the agent (appendix C.2).
const EVENTS_KEPT: usize = 64;
/// How long a stopped backbone may take to close before it is cut off.
const STOP_TIMEOUT: Duration = Duration::from_secs(5);

/// What a region network tells its backbone.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct RegionView {
    /// The network's virtual subnets and its members' advertised subnets.
    pub prefixes: Vec<IpNet>,
    /// This node is connected to at least one member.
    pub reachable: bool,
}

impl RegionView {
    /// The view of a running network from its driver's snapshot. Subnets
    /// this node carries for other regions are left out here; the backbone
    /// further leaves out every subnet that overlaps another region's
    /// summary, since the other border nodes of this region advertise
    /// those too.
    pub fn of(settings: &MeshSettings, snapshot: &Snapshot) -> Self {
        let mut prefixes: BTreeSet<IpNet> = std::iter::once(settings.address)
            .chain(settings.address_v6)
            .map(|net| net.trunc())
            .collect();
        for member in &snapshot.members {
            for subnet in &member.subnets {
                if !snapshot.border.iter().any(|own| own.overlaps(subnet)) {
                    prefixes.insert(subnet.trunc());
                }
            }
        }
        Self {
            prefixes: prefixes.into_iter().collect(),
            reachable: !snapshot.neighbours.is_empty(),
        }
    }
}

/// The meeting point of one managed network and the backbone.
pub(crate) struct Hub {
    prefixes: watch::Sender<Vec<IpNet>>,
    region: watch::Sender<RegionView>,
    to_backbone: mpsc::Sender<Vec<u8>>,
    from_region: Arc<tokio::sync::Mutex<mpsc::Receiver<Vec<u8>>>>,
    to_region: mpsc::Sender<Vec<u8>>,
    from_backbone: Arc<tokio::sync::Mutex<mpsc::Receiver<Vec<u8>>>>,
}

impl Hub {
    pub fn new() -> Arc<Self> {
        let (prefixes, _) = watch::channel(Vec::new());
        let (region, _) = watch::channel(RegionView::default());
        let (to_backbone, from_region) = mpsc::channel(QUEUE);
        let (to_region, from_backbone) = mpsc::channel(QUEUE);
        Arc::new(Self {
            prefixes,
            region,
            to_backbone,
            from_region: Arc::new(tokio::sync::Mutex::new(from_region)),
            to_region,
            from_backbone: Arc::new(tokio::sync::Mutex::new(from_backbone)),
        })
    }

    /// The channels the network's driver takes.
    pub fn driver_side(&self) -> Border {
        Border {
            prefixes: self.prefixes.subscribe(),
            to_backbone: self.to_backbone.clone(),
            from_backbone: Arc::clone(&self.from_backbone),
        }
    }

    /// The network's latest view; [`RegionView::default`] when it stops.
    pub fn publish_region(&self, view: RegionView) {
        self.region.send_if_modified(|current| {
            let changed = *current != view;
            *current = view;
            changed
        });
    }

    /// The other regions' prefixes the network now carries.
    #[cfg(test)]
    pub fn carried(&self) -> Vec<IpNet> {
        self.prefixes.borrow().clone()
    }

    /// Withdraws everything carried for other regions.
    pub fn withdraw(&self) {
        self.set_prefixes(Vec::new());
    }

    fn set_prefixes(&self, prefixes: Vec<IpNet>) {
        self.prefixes.send_if_modified(|current| {
            let changed = *current != prefixes;
            *current = prefixes;
            changed
        });
    }
}

/// The backbone of a border node, as the managed mesh keeps it.
pub(crate) struct BorderInstance {
    /// The region network's tag, `mesh-<region>`.
    pub tag: String,
    settings: BackboneSettings,
    links: Vec<(BackboneId, LinkConfig)>,
    state: BorderState,
}

enum BorderState {
    Failed(BackboneFailure),
    Running(RunningBorder),
}

struct RunningBorder {
    settings: watch::Sender<BackboneSettings>,
    stop: Option<oneshot::Sender<()>>,
    shared: Arc<Mutex<Shared>>,
    task: JoinHandle<()>,
}

/// What the backbone task publishes for the status.
struct Shared {
    status: Status,
    events: VecDeque<BackboneEvent>,
    next_event: u64,
}

impl BorderInstance {
    /// Starts the backbone of `backbone` against the network hub `hub`.
    pub fn start(backbone: ManagedBackbone, hub: &Arc<Hub>) -> Self {
        let ManagedBackbone { settings, links } = backbone;
        let tag = format!("{}{}", outbound_mesh::status::TAG_PREFIX, settings.region);
        let state = match open_links(&settings, &links) {
            Ok(opened) => BorderState::Running(spawn(settings.clone(), opened, Arc::clone(hub))),
            Err(failure) => {
                hub.withdraw();
                BorderState::Failed(failure)
            }
        };
        Self {
            tag,
            settings,
            links,
            state,
        }
    }

    /// Takes a new request without a restart when only the policy changed:
    /// the same ID, region and links. `false` means the instance is to be
    /// stopped and started again.
    pub fn keep(&mut self, backbone: &ManagedBackbone) -> bool {
        let same_links = self.links == backbone.links;
        let same_identity = self.settings.id == backbone.settings.id
            && self.settings.region == backbone.settings.region;
        match &self.state {
            BorderState::Running(running)
                if same_links && same_identity && !running.task.is_finished() =>
            {
                if self.settings != backbone.settings {
                    self.settings = backbone.settings.clone();
                    running.settings.send_replace(backbone.settings.clone());
                }
                true
            }
            _ => false,
        }
    }

    /// The `backbone` object of the status (appendix C.1).
    pub fn status(&self) -> ManagedBackboneStatus {
        match &self.state {
            BorderState::Failed(failure) => ManagedBackboneStatus {
                running: false,
                failure: Some(failure.clone()),
                status: Status::idle(self.settings.id, &self.settings.region),
                events: Vec::new(),
            },
            BorderState::Running(running) => {
                let shared = lock(&running.shared);
                let finished = running.task.is_finished();
                ManagedBackboneStatus {
                    running: !finished,
                    failure: finished.then(|| BackboneFailure {
                        code: "backbone_stopped",
                        detail: String::new(),
                    }),
                    status: shared.status.clone(),
                    events: shared.events.iter().cloned().collect(),
                }
            }
        }
    }

    /// Stops the backbone; the links close as they are dropped.
    pub async fn stop(self, hub: Option<&Hub>) {
        if let BorderState::Running(mut running) = self.state {
            if let Some(stop) = running.stop.take() {
                let _ = stop.send(());
            }
            if tokio::time::timeout(STOP_TIMEOUT, &mut running.task)
                .await
                .is_err()
            {
                running.task.abort();
            }
        }
        if let Some(hub) = hub {
            hub.withdraw();
        }
    }
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

/// The ID a link is opened with: the same at both ends.
fn link_id(a: BackboneId, b: BackboneId) -> String {
    format!("backbone-{}-{}", a.min(b), a.max(b))
}

/// Opens a link to every other member. The first failure stops the lot:
/// a kind nobody registered, or parameters the kind refused.
fn open_links(
    settings: &BackboneSettings,
    links: &[(BackboneId, LinkConfig)],
) -> Result<BTreeMap<BackboneId, Arc<dyn BackboneLink>>, BackboneFailure> {
    let mut opened = BTreeMap::new();
    for (index, (peer, link)) in links.iter().enumerate() {
        let Some(factory) = backbone_factory(&link.kind) else {
            return Err(BackboneFailure {
                code: "backbone_kind_unavailable",
                detail: format!("backbone.members[{index}].link.kind"),
            });
        };
        if *peer == settings.id {
            continue;
        }
        // The reason is a fixed text from the implementation, which must
        // not carry credentials (`BackboneOpenError`).
        let link = factory
            .open(&link_id(settings.id, *peer), &link.params)
            .map_err(|reason| BackboneFailure {
                code: "backbone_link_refused",
                detail: format!("backbone.members[{index}].link.params: {reason}"),
            })?;
        opened.insert(*peer, link);
    }
    Ok(opened)
}

fn spawn(
    settings: BackboneSettings,
    links: BTreeMap<BackboneId, Arc<dyn BackboneLink>>,
    hub: Arc<Hub>,
) -> RunningBorder {
    let now = Instant::now();
    let shared = Arc::new(Mutex::new(Shared {
        status: Status::idle(settings.id, &settings.region),
        events: VecDeque::new(),
        // Rises across restarts too, so that the agent can tell new events.
        next_event: unix_ms(),
    }));
    let (settings_tx, settings_rx) = watch::channel(settings.clone());
    let (stop, stopped) = oneshot::channel();
    let engine = Backbone::new(settings, now, unix_ms());
    let task = tokio::spawn(run(
        engine,
        links,
        hub,
        settings_rx,
        stopped,
        Arc::clone(&shared),
    ));
    RunningBorder {
        settings: settings_tx,
        stop: Some(stop),
        shared,
        task,
    }
}

/// The backbone task: moves packets between the region network and the
/// links, feeds the engine and publishes its status.
async fn run(
    mut engine: Backbone,
    links: BTreeMap<BackboneId, Arc<dyn BackboneLink>>,
    hub: Arc<Hub>,
    mut settings: watch::Receiver<BackboneSettings>,
    mut stopped: oneshot::Receiver<()>,
    shared: Arc<Mutex<Shared>>,
) {
    let mut from_region = Arc::clone(&hub.from_region).lock_owned().await;
    let mut region = hub.region.subscribe();
    let (to_task, mut from_links) = mpsc::channel::<(BackboneId, BackbonePacket)>(LINK_QUEUE);
    let readers: Vec<JoinHandle<()>> = links
        .iter()
        .map(|(peer, link)| tokio::spawn(read_link(*peer, Arc::clone(link), to_task.clone())))
        .collect();
    drop(to_task);
    let mut state = Task {
        policies: BTreeMap::new(),
        carried: Vec::new(),
        foreign_seen: BTreeSet::new(),
    };
    let mut ticks = tokio::time::interval(TICK);
    ticks.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            _ = &mut stopped => break,
            Ok(()) = settings.changed() => {
                let next = settings.borrow_and_update().clone();
                engine.set_settings(next, Instant::now());
                state.policies.clear();
            }
            Ok(()) = region.changed() => {
                let view = region.borrow_and_update().clone();
                state.set_region(&mut engine, view, Instant::now());
            }
            Some(packet) = from_region.recv() => {
                ingress(&mut engine, &links, packet);
            }
            Some((peer, packet)) = from_links.recv() => {
                let now = Instant::now();
                match packet {
                    BackbonePacket::Control(bytes) => engine.on_control(peer, &bytes, now),
                    BackbonePacket::Ip(packet) => receive(&mut engine, &links, &hub, peer, packet, now),
                }
            }
            _ = ticks.tick() => {
                let now = Instant::now();
                for (peer, link) in &links {
                    engine.on_link_report(*peer, report(&link.stats()), now);
                }
                engine.tick(now, unix_ms());
                let view = region.borrow().clone();
                state.set_region(&mut engine, view, now);
                state.apply_policies(&engine, &links);
                state.carry(&engine, &hub);
                publish(&mut engine, &links, &shared, now);
            }
        }
        send_outputs(&mut engine, &links);
    }
    hub.withdraw();
    for reader in readers {
        reader.abort();
    }
}

/// What the task remembers between events.
struct Task {
    /// The receive policy last set on each link.
    policies: BTreeMap<BackboneId, PacketPolicy>,
    /// The summaries last handed to the region network.
    carried: Vec<IpNet>,
    /// Every summary prefix learnt from another region while this task
    /// runs. A member subnet that overlaps one is never advertised as this
    /// region's: the other border nodes of this region advertise those
    /// prefixes into the region network too, also after the adverts here
    /// have expired.
    foreign_seen: BTreeSet<IpNet>,
}

impl Task {
    fn set_region(&mut self, engine: &mut Backbone, view: RegionView, now: Instant) {
        self.foreign_seen
            .extend(engine.topology().foreign_prefixes().into_keys());
        let prefixes = view
            .prefixes
            .into_iter()
            .filter(|net| {
                !self
                    .foreign_seen
                    .iter()
                    .any(|foreign| foreign.overlaps(net))
            })
            .collect();
        engine.set_region(prefixes, view.reachable, now);
    }

    fn apply_policies(
        &mut self,
        engine: &Backbone,
        links: &BTreeMap<BackboneId, Arc<dyn BackboneLink>>,
    ) {
        let settings = engine.settings();
        for (peer, link) in links {
            let (sources, destinations) = engine.receive_policy(*peer);
            let policy = PacketPolicy {
                src_allow: prefixes(&sources),
                dst_allow: prefixes(&destinations),
                ip_pps: settings.ip_pps,
                ip_bps: settings.ip_bps,
                ..PacketPolicy::default()
            };
            if self.policies.get(peer) != Some(&policy) {
                link.set_policy(policy.clone());
                self.policies.insert(*peer, policy);
            }
        }
    }

    /// Hands the summaries with a path to the region network; none while
    /// the backbone is disconnected (spec §15.6 items 3 and 6).
    fn carry(&mut self, engine: &Backbone, hub: &Hub) {
        let advertised = engine.region_advertisement();
        if advertised != self.carried {
            self.carried.clone_from(&advertised);
            hub.set_prefixes(advertised);
        }
    }
}

fn prefixes(nets: &[IpNet]) -> Vec<IpPrefix> {
    nets.iter()
        .filter_map(|net| IpPrefix::new(net.network(), net.prefix()))
        .collect()
}

/// A link's report in the backbone module's terms: what the link measures,
/// the rest from the module's own probes.
fn report(stats: &BackboneStats) -> LinkReport {
    LinkReport {
        up: stats.up,
        forward_secrecy: stats.forward_secrecy,
        rtt_ms: stats.rtt_ms.map(f64::from),
        loss: stats.loss_ppm.map(|ppm| f64::from(ppm) / 1_000_000.0),
        jitter_ms: None,
        utilization: None,
    }
}

async fn read_link(
    peer: BackboneId,
    link: Arc<dyn BackboneLink>,
    to_task: mpsc::Sender<(BackboneId, BackbonePacket)>,
) {
    while let Some(packet) = link.recv().await {
        if to_task.send((peer, packet)).await.is_err() {
            return;
        }
    }
}

/// A packet from the region network for another region (appendix A.7).
fn ingress(
    engine: &mut Backbone,
    links: &BTreeMap<BackboneId, Arc<dyn BackboneLink>>,
    packet: Vec<u8>,
) {
    let Ok(addresses) = packet::addresses(&packet) else {
        return;
    };
    let verdict = engine.ingress(addresses.source, addresses.destination);
    if let Verdict::Send(peer) = verdict {
        send_ip(engine, links, peer, packet);
    }
}

/// A packet a link delivered (appendix A.7).
fn receive(
    engine: &mut Backbone,
    links: &BTreeMap<BackboneId, Arc<dyn BackboneLink>>,
    hub: &Hub,
    from: BackboneId,
    packet: Vec<u8>,
    now: Instant,
) {
    let Ok(addresses) = packet::addresses(&packet) else {
        return;
    };
    match engine.receive(from, addresses.source, addresses.destination, now) {
        Verdict::Deliver => {
            if !hub.region.borrow().reachable || hub.to_region.try_send(packet).is_err() {
                engine.exit_failed();
            }
        }
        Verdict::Send(peer) => send_ip(engine, links, peer, packet),
        Verdict::Drop(_) | Verdict::DropAndNotify { .. } => {}
    }
}

fn send_ip(
    engine: &mut Backbone,
    links: &BTreeMap<BackboneId, Arc<dyn BackboneLink>>,
    peer: BackboneId,
    packet: Vec<u8>,
) {
    let sent = links
        .get(&peer)
        .is_some_and(|link| link.try_send(BackbonePacket::Ip(packet)).is_ok());
    if !sent {
        engine.link_send_failed();
    }
}

fn send_outputs(engine: &mut Backbone, links: &BTreeMap<BackboneId, Arc<dyn BackboneLink>>) {
    for output in engine.drain_outputs() {
        match output {
            Output::Control { peer, bytes } => {
                if let Some(link) = links.get(&peer) {
                    // A full or broken link loses the message; the module
                    // sends its state again on its own timers.
                    let _ = link.try_send(BackbonePacket::Control(bytes));
                }
            }
            // No module here handles the other control types yet; the
            // backbone module has counted them.
            Output::Unhandled { .. } => {}
        }
    }
}

fn publish(
    engine: &mut Backbone,
    links: &BTreeMap<BackboneId, Arc<dyn BackboneLink>>,
    shared: &Mutex<Shared>,
    now: Instant,
) {
    let mut status = engine.status(now);
    for link in &mut status.links {
        if let Some(open) = links.get(&link.peer) {
            link.transport = open.stats().transport;
        }
    }
    let events = engine.drain_events();
    let mut shared = lock(shared);
    shared.status = status;
    for event in events {
        let seq = shared.next_event;
        shared.next_event += 1;
        shared.events.push_back(BackboneEvent { seq, event });
        while shared.events.len() > EVENTS_KEPT {
            shared.events.pop_front();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use outbound_mesh::driver::Member;
    use outbound_mesh::MeshConfig;
    use serde_json::json;

    fn net(text: &str) -> IpNet {
        IpNet::parse(text).unwrap()
    }

    fn settings() -> MeshSettings {
        let config = json!({
            "config_version": 1,
            "network": {"name": "eu", "secret": "s3cret"},
            "node": {"address": "10.150.0.5/16", "address_v6": "fd00:150::5/64", "role": "full"},
            "peers": [{"server": "203.0.113.10", "port": 11010}],
        });
        serde_json::from_value::<MeshConfig>(config)
            .unwrap()
            .validate()
            .unwrap()
    }

    fn member(subnets: &[&str]) -> Member {
        Member {
            peer_id: 7,
            addresses: vec!["10.150.0.7".parse().unwrap()],
            subnets: subnets.iter().map(|s| net(s)).collect(),
            via: Vec::new(),
            hops: 1,
            latency_ms: None,
        }
    }

    #[test]
    fn the_region_view_leaves_out_what_this_node_carries() {
        let snapshot = Snapshot {
            neighbours: vec![7],
            members: vec![member(&["192.168.10.0/24", "10.20.0.0/16"])],
            border: vec![net("10.20.0.0/16")],
            ..Snapshot::default()
        };
        let view = RegionView::of(&settings(), &snapshot);
        assert!(view.reachable);
        assert_eq!(
            view.prefixes,
            [
                net("10.150.0.0/16"),
                net("192.168.10.0/24"),
                net("fd00:150::/64")
            ]
        );
        let alone = RegionView::of(&settings(), &Snapshot::default());
        assert!(!alone.reachable);
        assert_eq!(alone.prefixes, [net("10.150.0.0/16"), net("fd00:150::/64")]);
    }

    #[test]
    fn link_ids_are_the_same_at_both_ends() {
        assert_eq!(link_id(11, 21), "backbone-11-21");
        assert_eq!(link_id(21, 11), "backbone-11-21");
    }

    #[test]
    fn reports_take_what_the_link_measures() {
        let stats = BackboneStats {
            up: true,
            forward_secrecy: true,
            rtt_ms: Some(30),
            loss_ppm: Some(20_000),
            ..BackboneStats::default()
        };
        let report = report(&stats);
        assert!(report.up && report.forward_secrecy);
        assert_eq!(report.rtt_ms, Some(30.0));
        assert_eq!(report.loss, Some(0.02));
        assert!(report.needs_probe());
    }

    #[tokio::test]
    async fn an_unregistered_kind_does_not_run_and_withdraws() {
        let config = json!({
            "id": 11,
            "region": "eu",
            "members": [
                { "id": 11, "region": "eu", "link": { "kind": "nothing-registered" } },
                { "id": 21, "region": "ap", "link": { "kind": "nothing-registered", "params": { "key": "SECRET-VALUE" } } }
            ]
        });
        let config: outbound_mesh::backbone::BackboneConfig =
            serde_json::from_value(config).unwrap();
        let backbone = ManagedBackbone {
            settings: config.validate().unwrap(),
            links: config.links(),
        };
        let hub = Hub::new();
        hub.set_prefixes(vec![net("10.20.0.0/16")]);
        let instance = BorderInstance::start(backbone, &hub);
        assert_eq!(instance.tag, "mesh-eu");
        let status = instance.status();
        assert!(!status.running);
        let failure = status.failure.clone().unwrap();
        assert_eq!(failure.code, "backbone_kind_unavailable");
        assert_eq!(failure.detail, "backbone.members[0].link.kind");
        assert!(hub.prefixes.borrow().is_empty());
        let text = serde_json::to_string(&status).unwrap();
        assert!(!text.contains("SECRET-VALUE"), "{text}");
    }
}
