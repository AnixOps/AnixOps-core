//! Rule-based outbound: picks a node per connection with the shared
//! `config-core` routing model.
//!
//! The tunnel only sees destination addresses, so domain rules match a
//! [`TargetAddr::Domain`] (the desktop local proxy passes one) or the host
//! name the tunnel sniffed from the flow, given to
//! [`RoutedOutbound::route_flow`]; with Fake-IP the dispatcher hands over the
//! name of a fake address as a domain target (see [`crate::fake_ip`]). A domain target that reaches
//! an IP rule without `no-resolve` is resolved once with the
//! [`DomainResolver`] (the config's `dns` section through
//! [`crate::dns_resolver::PolicyResolver`] in a built runtime, never the
//! system resolver, so a proxied name is not looked up in the clear), and that address is
//! matched by every later IP rule; the connection itself still goes out by
//! name, so a proxy node resolves it remotely. A failed lookup rejects the
//! connection, the same result sing-box gives. GeoIP rules never match
//! because the runtime ships no GeoIP database. `RULE-SET` rules match the
//! named [`RuleSet`] from the config, never resolving a domain for its
//! networks. Select groups use their configured default (or first member)
//! until [`RoutedOutbound::select`] switches them while the engine runs. The
//! global mode skips the rules for one target ([`RoutedOutbound::with_global`]).
//! url-test, fallback, load-balance and round-robin groups use the latencies
//! measured by [`RoutedOutbound::run_health_checks`]: url-test takes the
//! fastest member, fallback the first that answered, load-balance hashes the
//! destination host over the members that answered (one site keeps one
//! member) and round-robin takes them in turn; all of them use every member
//! (url-test and fallback their first) until a check has finished.
//!
//! Health checks are lazy, as Clash's `lazy: true`: after the first round a
//! group is measured again only when a flow went through it since the last
//! round. A phone in a pocket then stops dialing every member of every
//! url-test group every few minutes; each dial through a node keeps that
//! node's session (and the radio) awake for minutes after it. Within a
//! round a member listed by several groups with the same check URL is
//! probed once and every group takes the result, and at most
//! [`MAX_CONCURRENT_PROBES`] probes run at once (the groups a connection
//! waits on first), so a subscription that lists 150 nodes in five groups
//! does not open hundreds of handshakes at once and inflate every latency.
//! Each group settles as soon as its own members are measured.
//!
//! ## Self-healing groups
//!
//! - **A failed connection retests its member.** When a connection through
//!   a health-checked group fails to open
//!   ([`RoutedOutbound::report_failure`]), the member it used is probed at
//!   once instead of at the next interval (at most once per
//!   [`FAILURE_RETEST_COOLDOWN`] per member). A member that fails the probe
//!   loses its result, so the next connection takes another member; one
//!   that passes keeps it, so a site that refuses connections does not
//!   push the group off a good node. Only that member is probed, never the
//!   whole group, so a dead site cannot make the phone dial every node.
//! - **A network change forgets every result**
//!   ([`RoutedOutbound::forget_health`], sent with `reset_network`):
//!   latencies measured on the old network say nothing about the new one.
//!   A group without a result is checked as soon as a connection goes
//!   through it, and a check that started on the old network records
//!   nothing.
//! - **Evaluate before use.** A group with `evaluate_before_use` holds a
//!   connection while it has no result (first use, or after a network
//!   change) until its check finishes, at most [`EVALUATE_WAIT`], instead of
//!   sending it through the first member, which may be dead.
//! - **Url-test tolerance.** A url-test group keeps its member until another
//!   is faster by more than the group's `tolerance_ms`, so near-equal
//!   members do not trade places (and drop pooled sessions) on every check.
//! - **Subnet groups** pick a target from the network the client reports
//!   with [`RoutedOutbound::set_network`]: Wi-Fi name, access point, router,
//!   an address range of the device or the interface type, else their
//!   default. A connection decides once; `reset_network` closes the old
//!   ones so they reconnect through the new pick.
//!
//! ## Hot reload
//!
//! The compiled rules live in a [`RoutingTable`] behind one pointer: every
//! routing decision takes the current table once and keeps it until the
//! decision is described, so a decision never mixes two rule lists.
//! [`RoutedOutbound::reload_rules`] compiles a new table from new rule lines
//! off to the side (the standby buffer), with the same checks a start runs,
//! and only then swaps the pointer. Nothing else changes: nodes, groups,
//! select choices, latencies, rule sets and every open connection stay as
//! they are, so a reload drops no connection and no packet. Connections
//! opened before the swap keep the outbound they were given; later ones use
//! the new rules. A rule list that does not compile leaves the running table
//! untouched and names the first bad line.

use std::collections::{BTreeMap, BTreeSet};
use std::io;
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use config_core::routing::{
    parse_rule_line, NetworkContext, PolicyGroupKind, PolicyGroupSpec, PolicyTarget, RejectKind,
    RouteMatch, RouteNetwork, RouteOutcome, RouteQuery, RouteResolution, RoutingEnvironment,
    RoutingModel, RoutingRule, RoutingSpec, RuleIndex, RuleLine, RuleMatcher, RuleProtocol,
};
use config_core::rule_set::RuleSet;
use engine_outbound::sniff::HttpRequestHead;
use engine_outbound::{BoxFuture, BoxStream, TargetAddr, TcpOutbound, UdpFlow};
use serde::Serialize;

use crate::reject::RejectStorm;
use crate::rule_scripts::RuleScripts;
use crate::rule_sets::RuleSetStore;
use crate::{RuntimeError, RuntimeErrorCode};

pub const PROTOCOL: &str = "routed";

pub struct RoutedOutbound {
    /// The active rule table; [`RoutedOutbound::reload_rules`] swaps it.
    table: RwLock<Arc<RoutingTable>>,
    /// Policy groups as configured, to compile reloaded rules against.
    group_specs: Vec<PolicyGroupSpec>,
    /// MITM plugin rules as given, put ahead of reloaded rules again.
    plugin_rules: Vec<RoutingRule>,
    /// The configured global target, applied to reloaded tables again.
    global_name: Option<String>,
    rule_sets: Arc<RuleSetStore>,
    direct: Arc<dyn TcpOutbound>,
    nodes: BTreeMap<String, Arc<dyn TcpOutbound>>,
    resolver: Arc<dyn DomainResolver>,
    latencies: Arc<RwLock<Latencies>>,
    /// Members picked at runtime in select groups, by group id.
    selected: RwLock<BTreeMap<String, String>>,
    /// Connections routed by round-robin groups so far.
    round_robin: AtomicUsize,
    /// Groups a flow went through since the last health check round, by id
    /// (see [`RoutedOutbound::run_health_checks`]).
    used_groups: Mutex<BTreeSet<String>>,
    /// The member each url-test group uses now, kept until another member
    /// is faster by more than the tolerance.
    url_test_now: RwLock<BTreeMap<String, String>>,
    /// The network the client reported, for subnet groups.
    network: RwLock<Option<NetworkContext>>,
    /// Names the user gave devices by address, for `DEVICE-NAME` rules
    /// ([`RoutedOutbound::set_devices`]).
    devices: RwLock<BTreeMap<IpAddr, String>>,
    health: Mutex<HealthState>,
    /// Wakes the check loop for a check asked for out of turn.
    health_wake: tokio::sync::Notify,
    /// Signalled after every check round.
    health_done: tokio::sync::Notify,
    /// Whether [`RoutedOutbound::run_health_checks`] runs, so a connection
    /// never waits for a check nobody will make.
    checks_running: AtomicBool,
    /// Recent plain-REJECT flows per host, to drop retry storms (see
    /// [`crate::reject`]).
    reject_storm: RejectStorm,
    /// Scripts that `SCRIPT` rules name (see [`crate::rule_scripts`]).
    scripts: Arc<RuleScripts>,
}

/// Probing one member gives up after this long.
pub const PROBE_TIMEOUT: Duration = Duration::from_secs(5);

/// Longest a connection waits for the check of an `evaluate_before_use`
/// group: one probe and a little slack.
pub const EVALUATE_WAIT: Duration = Duration::from_secs(6);

/// A member whose connection failed is probed again at most this often.
pub const FAILURE_RETEST_COOLDOWN: Duration = Duration::from_secs(10);

/// What the check loop knows besides the latencies.
#[derive(Default)]
struct HealthState {
    /// Groups whose check finished since the start or the last
    /// [`RoutedOutbound::forget_health`].
    checked: BTreeSet<String>,
    /// Groups being checked now.
    in_flight: BTreeSet<String>,
    /// Groups to check at once, ahead of the interval.
    pending_groups: BTreeSet<String>,
    /// `(group, member)` to probe at once: a connection through it failed.
    pending_members: BTreeSet<(String, String)>,
    /// When a failed connection last asked to probe a member, by node or
    /// DIRECT name.
    failure_retests: BTreeMap<String, Instant>,
    /// Grows on every [`RoutedOutbound::forget_health`]; a probe that
    /// started before records nothing.
    epoch: u64,
}

impl HealthState {
    #[cfg(feature = "local-proxy")]
    fn has_pending(&self) -> bool {
        !self.pending_groups.is_empty() || !self.pending_members.is_empty()
    }
}

/// One compiled rule list: the model, where the global mode goes, and
/// whether a rule needs the local process. Immutable once built; a reload
/// builds a new one and swaps it in.
#[derive(Clone, Debug)]
pub struct RoutingTable {
    pub model: RoutingModel,
    /// Domain lookup for `model`, built with it.
    pub index: RuleIndex,
    /// Where the global mode sends every connection.
    pub global: PolicyTarget,
    /// Whether a rule matches the local process, so callers that can look
    /// it up should.
    pub uses_process: bool,
    /// Whether a rule matches the URL or `User-Agent` of a request, so a
    /// decrypted connection routes each request on its own.
    pub uses_request: bool,
    /// 0 for the table the engine started with, then one more per reload.
    pub generation: u64,
    /// How often each rule of `model`, then FINAL, decided a flow; a reload
    /// starts from zero.
    pub hits: Arc<RuleHits>,
}

/// Per-rule hit counters of one [`RoutingTable`]: one slot per rule, the
/// last for FINAL. Counted on the flow path with relaxed atomics, never a
/// lock.
#[derive(Debug, Default)]
pub struct RuleHits {
    counts: Box<[AtomicU64]>,
    /// Unix milliseconds of the latest hit, 0 for none.
    last_at_ms: Box<[AtomicU64]>,
}

impl RuleHits {
    fn new(slots: usize) -> Self {
        Self {
            counts: (0..slots).map(|_| AtomicU64::new(0)).collect(),
            last_at_ms: (0..slots).map(|_| AtomicU64::new(0)).collect(),
        }
    }

    fn record(&self, slot: usize) {
        if let (Some(count), Some(last)) = (self.counts.get(slot), self.last_at_ms.get(slot)) {
            count.fetch_add(1, Ordering::Relaxed);
            last.store(unix_millis(), Ordering::Relaxed);
        }
    }

    fn clear(&self) {
        for slot in self.counts.iter().chain(self.last_at_ms.iter()) {
            slot.store(0, Ordering::Relaxed);
        }
    }

    fn view(&self, slot: usize, rule: String, target: &PolicyTarget) -> RuleHit {
        let load = |slots: &[AtomicU64]| {
            slots
                .get(slot)
                .map_or(0, |value| value.load(Ordering::Relaxed))
        };
        RuleHit {
            rule,
            target: target.name().to_string(),
            hits: load(&self.counts),
            last_hit_at_ms: Some(load(&self.last_at_ms)).filter(|at| *at != 0),
        }
    }
}

fn unix_millis() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| {
            u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX)
        })
}

/// One rule, or FINAL, with how often it decided a flow.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct RuleHit {
    /// The rule as the connection list shows it (`DOMAIN-SUFFIX,example.com`),
    /// or `FINAL`.
    pub rule: String,
    /// The policy it sends to: a group, a node, `DIRECT` or a REJECT policy.
    pub target: String,
    pub hits: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_hit_at_ms: Option<u64>,
}

/// Every rule in order (plugin rules first, as they match), then FINAL, with
/// their hits since the table was built ([`RoutedOutbound::rule_hits`]).
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct RuleHitsView {
    pub generation: u64,
    pub rules: Vec<RuleHit>,
    #[serde(rename = "final")]
    pub final_rule: RuleHit,
}

/// What [`RoutedOutbound::test_route`] decided for a made-up connection.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct RouteTest {
    /// Index of the deciding rule in [`RuleHitsView::rules`]; `None` for
    /// FINAL.
    pub rule_index: Option<usize>,
    pub rule: String,
    /// Policy groups from the rule's target to the outbound, then the
    /// outbound.
    pub chain: Vec<String>,
    /// A node id, `DIRECT` or a REJECT policy.
    pub outbound: String,
    /// The rule at `rule_index` needs the destination's address, which the
    /// test was not given: `chain` and `outbound` are what a failed lookup
    /// would do (reject). Test again with the address.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub needs_address: bool,
}

/// What a successful [`RoutedOutbound::reload_rules`] did.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct RulesReload {
    /// Rules now in force, plugin rules and the FINAL line included.
    pub rules: usize,
    /// Generation of the table now in force.
    pub generation: u64,
    /// `false` for a dry run: the rules were only checked.
    pub applied: bool,
}

/// Why a rule list was refused. `line` is the 0-based index of the first
/// bad line in the list the client sent (`None` when the list as a whole is
/// wrong, such as a missing FINAL). Carries a stable code, never the text
/// of the line.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct RulesRejection {
    pub line: Option<usize>,
    pub code: &'static str,
}

/// Codes of a [`RulesRejection`].
pub mod reject_code {
    pub const TOO_MANY: &str = "too_many_rules";
    pub const LINE_TOO_LONG: &str = "line_too_long";
    pub const SYNTAX: &str = "syntax";
    pub const UNKNOWN_TARGET: &str = "unknown_target";
    pub const UNKNOWN_RULE_SET: &str = "unknown_rule_set";
    pub const UNKNOWN_SCRIPT: &str = "unknown_script";
    pub const FINAL_NOT_LAST: &str = "final_not_last";
    pub const FINAL_MISSING: &str = "final_missing";
    pub const INVALID: &str = "invalid";
}

/// Longest rule line a reload accepts.
pub const MAX_RULE_LINE_LEN: usize = 2048;

/// Last measured latency per url-test or fallback group, keyed by member name.
/// A member that failed its last check is absent.
type Latencies = BTreeMap<String, BTreeMap<String, u32>>;

/// Looks up a domain for IP rules that allow resolution.
pub trait DomainResolver: Send + Sync {
    fn resolve<'a>(&'a self, domain: &'a str) -> BoxFuture<'a, io::Result<IpAddr>>;

    /// [`Self::resolve`] for the direct mode, where nothing goes through a
    /// node: a resolver that reaches `proxy` DNS servers through the proxy
    /// asks every server directly instead. The default is [`Self::resolve`],
    /// for resolvers that never use the proxy.
    fn resolve_direct<'a>(&'a self, domain: &'a str) -> BoxFuture<'a, io::Result<IpAddr>> {
        self.resolve(domain)
    }

    /// The device changed networks: drop the addresses kept and the upstream
    /// connections kept for reuse, which belong to the old network (see
    /// [`crate::connections::Dispatcher::reset_dns`]). The default keeps
    /// nothing to drop.
    fn reset_network(&self) -> crate::dns_cache::DnsReset {
        crate::dns_cache::DnsReset::default()
    }
}

/// The operating system resolver (`getaddrinfo`), first address returned.
/// Only for tests and callers without a `dns` section: on a device in a
/// filtered network it sends the name in the clear to the local resolver.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemResolver;

impl DomainResolver for SystemResolver {
    fn resolve<'a>(&'a self, domain: &'a str) -> BoxFuture<'a, io::Result<IpAddr>> {
        Box::pin(async move {
            tokio::net::lookup_host((domain, 0))
                .await?
                .next()
                .map(|addr| addr.ip())
                .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "domain has no address"))
        })
    }
}

/// The most device names [`RoutedOutbound::set_devices`] takes.
pub const MAX_DEVICES: usize = 256;

/// Where a flow came from, for `SRC-IP`, `SRC-PORT` and `IN-PORT` rules:
/// the address and port of the app or device that opened it and the local
/// port of the listener it came in on (none for the packet tunnel).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FlowSource {
    pub address: Option<IpAddr>,
    pub in_port: Option<u16>,
    pub port: Option<u16>,
}

/// Why a flow went where it did: the matched rule (`FINAL` when none did),
/// the policy groups passed through and the outbound picked, ending with it.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct RouteInfo {
    pub rule: String,
    pub chain: Vec<String>,
    /// A node id, `DIRECT`, or a REJECT policy (`REJECT`, `REJECT-NO-DROP`,
    /// `REJECT-DROP`, `REJECT-TINYGIF`); a `REJECT` retry storm shows as
    /// `REJECT-DROP`.
    pub outbound: String,
    /// How the flow is rejected, when it is.
    #[serde(skip)]
    pub reject: Option<RejectKind>,
}

/// What the model sees while routing one connection: the rule sets, the
/// group latencies, and the address looked up for it, if any.
struct QueryEnvironment<'a> {
    rule_sets: &'a BTreeMap<String, Arc<RuleSet>>,
    latencies: &'a Latencies,
    selected: &'a BTreeMap<String, String>,
    url_test_now: &'a BTreeMap<String, String>,
    network: Option<&'a NetworkContext>,
    devices: &'a BTreeMap<IpAddr, String>,
    resolved: Option<IpAddr>,
    round_robin: &'a AtomicUsize,
    /// Verdicts of the rule scripts run for this connection so far; `None`
    /// when deciding without a connection, where no script matches.
    scripts: Option<&'a BTreeMap<String, bool>>,
}

impl RoutingEnvironment for QueryEnvironment<'_> {
    fn rule_set_matches(&self, name: &str, domain: Option<&str>, ip: Option<IpAddr>) -> bool {
        self.rule_sets
            .get(name)
            .is_some_and(|set| set.matches(domain, ip))
    }

    fn rule_set_needs_address(&self, name: &str) -> bool {
        self.rule_sets
            .get(name)
            .is_some_and(|set| set.needs_address())
    }

    fn rule_set_rules(&self, name: &str) -> &[RuleMatcher] {
        self.rule_sets
            .get(name)
            .map(|set| set.rules())
            .unwrap_or(&[])
    }

    fn geosite_matches(&self, category: &str, domain: &str) -> bool {
        self.rule_set_matches(&format!("geosite-{category}"), Some(domain), None)
    }

    fn geoip_matches(&self, country: &str, ip: IpAddr) -> bool {
        let name = format!("geoip-{}", country.to_ascii_lowercase());
        self.rule_set_matches(&name, None, Some(ip))
    }

    fn ip_asn_matches(&self, number: u32, ip: IpAddr) -> bool {
        self.rule_set_matches(&format!("asn-{number}"), None, Some(ip))
    }

    fn resolve(&self, _domain: &str) -> Option<IpAddr> {
        self.resolved
    }

    fn script_matches(&self, name: &str) -> Option<bool> {
        match self.scripts {
            Some(verdicts) => verdicts.get(name).copied(),
            None => Some(false),
        }
    }

    fn member_latency_ms(&self, group_id: &str, member: &PolicyTarget) -> Option<u32> {
        self.latencies.get(group_id)?.get(member.name()).copied()
    }

    fn selected_member(&self, group_id: &str) -> Option<String> {
        self.selected.get(group_id).cloned()
    }

    fn round_robin(&self, _group_id: &str) -> usize {
        self.round_robin.fetch_add(1, Ordering::Relaxed)
    }

    fn url_test_current(&self, group_id: &str) -> Option<String> {
        self.url_test_now.get(group_id).cloned()
    }

    fn network(&self) -> Option<&NetworkContext> {
        self.network
    }

    fn device_name(&self, source: IpAddr) -> Option<&str> {
        self.devices.get(&source).map(String::as_str)
    }
}

/// One policy group as the client's policy page shows it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct GroupView {
    pub id: String,
    #[serde(rename = "type")]
    pub kind: &'static str,
    /// The member the group picks now.
    pub now: String,
    pub members: Vec<MemberView>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct MemberView {
    pub name: String,
    /// Last health check result of a url-test or fallback member; `None`
    /// when untested, failed, or in a select group.
    pub latency_ms: Option<u32>,
}

impl RoutedOutbound {
    /// Validates `spec` against the node ids in `nodes`. The error message is
    /// fixed so rule text and node settings never reach status or logs.
    pub fn new(
        spec: &RoutingSpec,
        direct: Arc<dyn TcpOutbound>,
        nodes: BTreeMap<String, Arc<dyn TcpOutbound>>,
    ) -> Result<Self, RuntimeError> {
        Self::with_rule_sets(spec, direct, nodes, BTreeMap::new())
    }

    /// As [`RoutedOutbound::new`], with the sets `RULE-SET` and `GEOSITE`
    /// rules name; a rule naming a missing set is rejected.
    pub fn with_rule_sets(
        spec: &RoutingSpec,
        direct: Arc<dyn TcpOutbound>,
        nodes: BTreeMap<String, Arc<dyn TcpOutbound>>,
        rule_sets: BTreeMap<String, RuleSet>,
    ) -> Result<Self, RuntimeError> {
        Self::with_rule_set_store(
            spec,
            direct,
            nodes,
            RuleSetStore::new(rule_sets, Vec::new()),
        )
    }

    /// As [`RoutedOutbound::with_rule_sets`], with remote sets the engine
    /// downloads itself; each one's `via` must name a group, a node or DIRECT.
    pub fn with_rule_set_store(
        spec: &RoutingSpec,
        direct: Arc<dyn TcpOutbound>,
        nodes: BTreeMap<String, Arc<dyn TcpOutbound>>,
        rule_sets: RuleSetStore,
    ) -> Result<Self, RuntimeError> {
        let node_ids: BTreeSet<String> = nodes.keys().cloned().collect();
        let table = compile_table(spec, &node_ids, &rule_sets, None, &[], 0)?;
        let model = &table.model;
        let invalid_via = rule_sets.remotes().iter().any(|remote| {
            !matches!(
                model.target_named(&remote.via, &node_ids),
                Some(PolicyTarget::Direct | PolicyTarget::Node(_) | PolicyTarget::Group(_))
            )
        });
        if invalid_via {
            return Err(RuntimeError::new(
                RuntimeErrorCode::ConfigRejected,
                "a remote rule set downloads through a target that is not a group, a node or DIRECT",
            ));
        }
        Ok(Self {
            table: RwLock::new(Arc::new(table)),
            group_specs: spec.groups.clone(),
            plugin_rules: Vec::new(),
            global_name: None,
            rule_sets: Arc::new(rule_sets),
            direct,
            nodes,
            resolver: Arc::new(SystemResolver),
            latencies: Arc::default(),
            selected: RwLock::default(),
            round_robin: AtomicUsize::new(0),
            used_groups: Mutex::default(),
            url_test_now: RwLock::default(),
            network: RwLock::default(),
            devices: RwLock::default(),
            health: Mutex::default(),
            health_wake: tokio::sync::Notify::new(),
            health_done: tokio::sync::Notify::new(),
            checks_running: AtomicBool::new(false),
            reject_storm: RejectStorm::default(),
            scripts: Arc::default(),
        })
    }

    /// The rule table in force now. A caller that routes and then describes
    /// one connection keeps this one snapshot for both.
    pub fn table(&self) -> Arc<RoutingTable> {
        self.table
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    fn node_ids(&self) -> BTreeSet<String> {
        self.nodes.keys().cloned().collect()
    }

    /// Replaces the user's rule lines while the engine runs (see the module
    /// docs): `rules` must end with a `FINAL` line and may only name the
    /// configured nodes, groups and rule sets. The new table is compiled
    /// first and swapped in one step; on any error the running rules stay.
    /// With `dry_run` the rules are only checked.
    pub fn reload_rules(
        &self,
        rules: &[String],
        dry_run: bool,
    ) -> Result<RulesReload, RulesRejection> {
        let node_ids = self.node_ids();
        let current = self.table();
        check_rule_lines(
            rules,
            &node_ids,
            &current.model,
            &self.rule_sets,
            &self.scripts,
        )?;
        let spec = RoutingSpec {
            rules: rules.to_vec(),
            groups: self.group_specs.clone(),
        };
        let table = compile_table(
            &spec,
            &node_ids,
            &self.rule_sets,
            self.global_name.as_deref(),
            &self.plugin_rules,
            current.generation,
        )
        .map_err(|_| RulesRejection {
            line: None,
            code: reject_code::INVALID,
        })?;
        let rules = table.model.rules.len() + 1;
        if !dry_run {
            let mut slot = self
                .table
                .write()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            // Two reloads at once: the later swap wins, with its own count.
            let generation = slot.generation.max(current.generation) + 1;
            *slot = Arc::new(RoutingTable {
                generation,
                ..table
            });
            return Ok(RulesReload {
                rules,
                generation,
                applied: true,
            });
        }
        Ok(RulesReload {
            rules,
            generation: current.generation,
            applied: false,
        })
    }

    /// Whether a `PROCESS-NAME` rule exists, alone or inside a logical rule.
    pub fn uses_process(&self) -> bool {
        self.table().uses_process || self.rule_sets.uses_process()
    }

    /// Whether a `URL-REGEX` or `USER-AGENT` rule exists (plugin rules
    /// included), alone or inside a logical rule.
    pub fn uses_request(&self) -> bool {
        self.table().uses_request || self.rule_sets.uses_request()
    }

    /// Puts MITM plugin rules ahead of the user's rules. A plugin names a
    /// policy it cannot know (`PROXY`, or a module argument such as a group
    /// name): a group or node of that name is used when one exists, else the
    /// target the global mode uses. Rules naming a rule set that is not
    /// configured are left out.
    pub fn with_plugin_rules(mut self, rules: &[RoutingRule]) -> Self {
        let node_ids = self.node_ids();
        self.plugin_rules = rules.to_vec();
        let table = Arc::make_mut(
            self.table
                .get_mut()
                .unwrap_or_else(|poisoned| poisoned.into_inner()),
        );
        add_plugin_rules(table, rules, &node_ids, &self.rule_sets);
        self
    }

    /// Gives `SCRIPT` rules their scripts. Every `SCRIPT` rule must name
    /// one of them, now and in every reload. Without this call no script is
    /// known and a `SCRIPT` rule never matches.
    pub fn with_rule_scripts(mut self, scripts: RuleScripts) -> Result<Self, RuntimeError> {
        let unknown = self
            .table()
            .model
            .rules
            .iter()
            .filter_map(|rule| script_name(&rule.matcher))
            .any(|name| !scripts.contains(name));
        if unknown {
            return Err(RuntimeError::new(
                RuntimeErrorCode::ConfigRejected,
                "a SCRIPT rule names a script that is not configured",
            ));
        }
        self.scripts = Arc::new(scripts);
        Ok(self)
    }

    /// Sets where the global mode sends connections: a policy group, a node
    /// or DIRECT. Without one it is the first group, else the first node.
    pub fn with_global(mut self, name: &str) -> Result<Self, RuntimeError> {
        let node_ids = self.node_ids();
        let table = Arc::make_mut(
            self.table
                .get_mut()
                .unwrap_or_else(|poisoned| poisoned.into_inner()),
        );
        table.global = global_target(&table.model, name, &node_ids)?;
        self.global_name = Some(name.to_string());
        Ok(self)
    }

    /// The rule sets, for their status and manual refreshes.
    pub fn rule_sets(&self) -> &Arc<RuleSetStore> {
        &self.rule_sets
    }

    /// Every rule in force, then FINAL, with how often each decided a flow
    /// since the rules were loaded (a reload starts from zero; see
    /// `generation`).
    pub fn rule_hits(&self) -> RuleHitsView {
        let table = self.table();
        let rules = table
            .model
            .rules
            .iter()
            .enumerate()
            .map(|(index, rule)| {
                table
                    .hits
                    .view(index, rule.matcher.to_string(), &rule.target)
            })
            .collect();
        let final_rule = table.hits.view(
            table.model.rules.len(),
            "FINAL".to_string(),
            &table.model.final_target,
        );
        RuleHitsView {
            generation: table.generation,
            rules,
            final_rule,
        }
    }

    /// Sets every rule's hits back to zero.
    pub fn clear_rule_hits(&self) {
        self.table().hits.clear();
    }

    /// Which rule would decide a connection described by `query`, and where
    /// it would go, without opening or counting anything: the rule tester.
    /// `address` is the destination's address for a domain `query`, as a
    /// lookup would give it; without one, a rule that needs it stops the test
    /// ([`RouteTest::needs_address`]). Rule scripts are not run and count as
    /// not matching. Groups pick their member as they would now; a round-robin
    /// group counts the test as one of its connections.
    pub fn test_route(&self, query: &RouteQuery, address: Option<IpAddr>) -> RouteTest {
        let table = self.table();
        let resolution = self.decide(&table, query, address, None);
        let info = describe(&table, &resolution);
        let (rule_index, needs_address) = match resolution.matched {
            RouteMatch::Rule(index) | RouteMatch::ScriptPending(index) => (Some(index), false),
            RouteMatch::ResolveFailed(index) | RouteMatch::FinalAfterResolveFailed(index) => {
                (Some(index), address.is_none() && query.ip.is_none())
            }
            RouteMatch::Final => (None, false),
        };
        let rule = match rule_index {
            Some(index) if needs_address => table.model.rules[index].matcher.to_string(),
            _ => info.rule,
        };
        RouteTest {
            rule_index,
            rule,
            chain: info.chain,
            outbound: info.outbound,
            needs_address,
        }
    }

    /// The sets `GEOIP` and `IP-ASN` rules look addresses up in
    /// (`geoip-<cc>`, `asn-<number>`), in the rules or inside a rule set,
    /// that the engine does not have: those rules never match, so the client
    /// shows them instead of letting them fail silently. Sorted, at most
    /// [`MAX_MISSING_DATA_SETS`].
    pub fn missing_data_sets(&self) -> Vec<String> {
        let table = self.table();
        let sets = self.rule_sets.read();
        let mut names = BTreeSet::new();
        for rule in &table.model.rules {
            data_sets(&rule.matcher, &mut names);
        }
        for set in sets.values() {
            for rule in set.rules() {
                data_sets(rule, &mut names);
            }
        }
        names
            .into_iter()
            .filter(|name| !sets.contains_key(name))
            .take(MAX_MISSING_DATA_SETS)
            .collect()
    }

    /// Downloads every remote rule set when it is due, forever: first as
    /// [`RuleSetStore::first_update_delay`] says (right away when the set
    /// starts empty, or an interval after the download the cache directory
    /// kept), then every interval, sooner after a failure or when
    /// [`RuleSetStore::refresh_now`] asks. Never returns when there are no
    /// remote sets.
    #[cfg(feature = "local-proxy")]
    pub async fn run_rule_set_updates(self: Arc<Self>) {
        use crate::rule_sets::RETRY_INTERVAL_SECS;
        use std::time::Duration;
        use tokio::time::Instant;

        let remotes = self.rule_sets.remotes().to_vec();
        if remotes.is_empty() {
            return std::future::pending().await;
        }
        let now = Instant::now();
        let mut due: Vec<Instant> = remotes
            .iter()
            .map(|remote| now + self.rule_sets.first_update_delay(remote))
            .collect();
        loop {
            for (remote, due) in remotes.iter().zip(due.iter_mut()) {
                if *due > Instant::now() {
                    continue;
                }
                let interval = match self.update_rule_set(remote).await {
                    Ok(()) => remote.interval_secs,
                    Err(error) => {
                        self.rule_sets.record_failure(&remote.name, error);
                        remote.interval_secs.min(RETRY_INTERVAL_SECS)
                    }
                };
                *due = Instant::now() + Duration::from_secs(u64::from(interval));
            }
            let next = due.iter().copied().min().unwrap_or_else(Instant::now);
            tokio::select! {
                _ = tokio::time::sleep_until(next) => {}
                _ = self.rule_sets.refresh_requested() => {
                    let now = Instant::now();
                    due.iter_mut().for_each(|due| *due = now);
                }
            }
        }
    }

    /// Downloads one remote set through its `via` target and installs it,
    /// after keeping it in the cache directory when the config names one.
    #[cfg(feature = "local-proxy")]
    async fn update_rule_set(
        &self,
        remote: &crate::rule_sets::RemoteRuleSet,
    ) -> Result<(), &'static str> {
        use crate::rule_sets::MAX_LIST_BYTES;
        use config_core::rule_set::{RuleSetBuilder, MAX_RULE_SET_ENTRIES};
        use std::time::Duration;

        const FETCH_TIMEOUT: Duration = Duration::from_secs(60);

        let node_ids = self.node_ids();
        let table = self.table();
        let target = table
            .model
            .target_named(&remote.via, &node_ids)
            .ok_or("via_unknown")?;
        let resolution = self.with_environment(None, |environment| {
            table.model.route_to(&target, environment)
        });
        let outbound = self
            .outbound_of(&resolution.outcome)
            .ok_or("via_rejected")?;
        let body = crate::fetch::fetch(&*outbound, &remote.url, FETCH_TIMEOUT, MAX_LIST_BYTES)
            .await
            .map_err(crate::fetch::FetchError::as_str)?;
        let detached = match &remote.signature {
            Some(signature) => {
                let detached = crate::fetch::fetch(
                    &*outbound,
                    &signature.url,
                    FETCH_TIMEOUT,
                    crate::rule_sets::MAX_SIGNATURE_BYTES,
                )
                .await
                .map_err(|_| "signature_missing")?;
                crate::rule_sets::verify_list_signature(&signature.public_key, &body, &detached)?;
                Some(detached)
            }
            None => None,
        };
        // Parsed straight into the compact tables; the body goes before they
        // are sorted and packed, so a large list never sits in memory twice.
        let (builder, _) = {
            let text = String::from_utf8_lossy(&body);
            RuleSetBuilder::parse_list(&text, remote.bare)
        };
        if builder.is_empty() {
            return Err("empty_list");
        }
        if builder.len() > MAX_RULE_SET_ENTRIES {
            return Err("too_many_entries");
        }
        // Only a list that passed every check above is kept for the next
        // start. The write runs on the blocking pool, off the threads that
        // move packets, and takes the body with it.
        let fetched_at_ms = crate::rule_sets::unix_millis();
        let cache_error = match self.rule_sets.cache().cloned() {
            Some(cache) => {
                let remote = remote.clone();
                tokio::task::spawn_blocking(move || {
                    cache.store(&remote, detached.as_deref(), &body, fetched_at_ms)
                })
                .await
                .unwrap_or(Err(crate::rule_set_cache::WRITE_FAILED))
                .err()
            }
            None => {
                drop(body);
                None
            }
        };
        let skipped = builder.skipped().clone();
        self.rule_sets.replace_downloaded(
            &remote.name,
            builder.build(),
            skipped,
            fetched_at_ms,
            cache_error,
        );
        Ok(())
    }

    /// [`TcpOutbound::health`] of every node that keeps one, by node id.
    pub fn node_health(&self) -> Vec<(String, &'static str, serde_json::Value)> {
        self.nodes
            .iter()
            .filter_map(|(id, node)| node.health().map(|h| (id.clone(), node.protocol(), h)))
            .collect()
    }

    /// [`TcpOutbound::reuse_stats`] of every node that keeps them, by node id.
    pub fn node_reuse_stats(&self) -> Vec<(String, &'static str, serde_json::Value)> {
        self.nodes
            .iter()
            .filter_map(|(id, node)| node.reuse_stats().map(|s| (id.clone(), node.protocol(), s)))
            .collect()
    }

    /// [`TcpOutbound::resume`] on node `id`; `None` when there is no such node.
    pub fn resume_node(&self, id: &str) -> Option<bool> {
        self.nodes.get(id).map(|node| node.resume())
    }

    /// [`TcpOutbound::reset_sessions`] on every node and the DIRECT
    /// outbound; returns the total dropped.
    pub fn reset_sessions(&self) -> usize {
        self.nodes
            .values()
            .map(|node| node.reset_sessions())
            .sum::<usize>()
            + self.direct.reset_sessions()
    }

    /// The outbound for connections that skip the rules (the direct mode).
    pub fn direct(&self) -> &Arc<dyn TcpOutbound> {
        &self.direct
    }

    /// The resolver of IP rules, also used for Fake-IP flows that go DIRECT
    /// ([`DomainResolver::resolve_direct`] in the direct mode).
    pub fn resolver(&self) -> &Arc<dyn DomainResolver> {
        &self.resolver
    }

    /// Replaces the resolver used for IP rules (tests inject a fixed one).
    pub fn with_resolver(mut self, resolver: Arc<dyn DomainResolver>) -> Self {
        self.resolver = resolver;
        self
    }

    /// Where a connection to `target` goes without resolving its domain: a
    /// domain that reaches an IP rule without `no-resolve` is rejected.
    pub fn route(&self, target: &TargetAddr) -> RouteOutcome {
        self.decide(&self.table(), &query(target), None, None)
            .outcome
    }

    fn decide(
        &self,
        table: &RoutingTable,
        query: &RouteQuery,
        resolved: Option<IpAddr>,
        scripts: Option<&BTreeMap<String, bool>>,
    ) -> RouteResolution {
        self.with_scripts(resolved, scripts, |environment| {
            table.model.decide_indexed(&table.index, query, environment)
        })
    }

    fn with_environment<T>(
        &self,
        resolved: Option<IpAddr>,
        body: impl FnOnce(&QueryEnvironment<'_>) -> T,
    ) -> T {
        self.with_scripts(resolved, None, body)
    }

    fn with_scripts<T>(
        &self,
        resolved: Option<IpAddr>,
        scripts: Option<&BTreeMap<String, bool>>,
        body: impl FnOnce(&QueryEnvironment<'_>) -> T,
    ) -> T {
        let latencies = self
            .latencies
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let rule_sets = self.rule_sets.read();
        let selected = self
            .selected
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let url_test_now = self
            .url_test_now
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let network = self
            .network
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let devices = self
            .devices
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        body(&QueryEnvironment {
            rule_sets: &rule_sets,
            latencies: &latencies,
            selected: &selected,
            url_test_now: &url_test_now,
            network: network.as_ref(),
            devices: &devices,
            resolved,
            round_robin: &self.round_robin,
            scripts,
        })
    }

    /// Picks `member` in the select group `group_id` for every later
    /// connection, without restarting. Returns the member's name.
    pub fn select(&self, group_id: &str, member: &str) -> Result<String, RuntimeError> {
        let invalid = |message| RuntimeError::new(RuntimeErrorCode::InvalidArgument, message);
        let table = self.table();
        let group = table
            .model
            .group(group_id)
            .ok_or_else(|| invalid("no policy group has that id"))?;
        if group.kind != PolicyGroupKind::Select {
            return Err(invalid("only select groups can be switched"));
        }
        let member = group
            .members
            .iter()
            .find(|candidate| candidate.name() == member.trim())
            .ok_or_else(|| invalid("the policy group has no such member"))?;
        self.selected
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert(group.id.clone(), member.name().to_string());
        Ok(member.name().to_string())
    }

    /// Every policy group with the member it picks now and the members'
    /// last measured latencies, in configuration order.
    pub fn groups(&self) -> Vec<GroupView> {
        let table = self.table();
        self.with_environment(None, |environment| {
            table
                .model
                .groups
                .iter()
                .map(|group| GroupView {
                    id: group.id.clone(),
                    kind: group.kind.as_str(),
                    now: table
                        .model
                        .group_member(&group.id, environment)
                        .map(|member| member.name().to_string())
                        .unwrap_or_default(),
                    members: group
                        .members
                        .iter()
                        .map(|member| MemberView {
                            name: member.name().to_string(),
                            latency_ms: environment.member_latency_ms(&group.id, member),
                        })
                        .collect(),
                })
                .collect()
        })
    }

    /// The outbound for a DNS server reached through the proxy: the node a
    /// rule picks for the server's address, else the global target. A rule
    /// that sends the server DIRECT (`FINAL,DIRECT` of a list-based config, a
    /// GeoIP rule for a domestic resolver) or REJECT never makes a proxied
    /// query go out in the clear, and a server name is never resolved here.
    /// `None` when the global target rejects. This is the rule mode's
    /// choice: the direct mode reaches every server directly and never asks.
    pub fn dns_outbound(&self, server: &TargetAddr) -> Option<Arc<dyn TcpOutbound>> {
        self.dns_outbound_as(server, None)
    }

    /// [`Self::dns_outbound`] for a query sent as `dns`
    /// ([`RuleProtocol::Doh`] or [`RuleProtocol::Doq`]), which
    /// `PROTOCOL,DOH` and `PROTOCOL,DOQ` rules match.
    pub fn dns_outbound_as(
        &self,
        server: &TargetAddr,
        dns: Option<RuleProtocol>,
    ) -> Option<Arc<dyn TcpOutbound>> {
        let mut query = query(server);
        if let Some(dns) = dns {
            query.dns = Some(dns);
            query.network = Some(if dns == RuleProtocol::Doq {
                RouteNetwork::Udp
            } else {
                RouteNetwork::Tcp
            });
        }
        let outcome = self.decide(&self.table(), &query, None, None).outcome;
        if let RouteOutcome::Node(id) = outcome {
            if let Some(node) = self.nodes.get(&id) {
                return Some(node.clone());
            }
        }
        self.route_global().1
    }

    /// Routes a flow of the global mode: every connection to the global
    /// target, through its groups.
    pub fn route_global(&self) -> (RouteInfo, Option<Arc<dyn TcpOutbound>>) {
        let table = self.table();
        let resolution = self.global_resolution(&table);
        self.note_used(&table, &resolution);
        self.global_route(&table, &resolution)
    }

    /// [`Self::route_global`] for a user flow, which waits for the check of
    /// an `evaluate_before_use` group without a result.
    pub async fn route_global_flow(&self) -> (RouteInfo, Option<Arc<dyn TcpOutbound>>) {
        let table = self.table();
        let mut resolution = self.global_resolution(&table);
        if self.evaluate_before_use(&table, &resolution).await {
            resolution = self.global_resolution(&table);
        }
        self.note_used(&table, &resolution);
        self.global_route(&table, &resolution)
    }

    fn global_resolution(&self, table: &RoutingTable) -> RouteResolution {
        self.with_environment(None, |environment| {
            table.model.route_to(&table.global, environment)
        })
    }

    fn global_route(
        &self,
        table: &RoutingTable,
        resolution: &RouteResolution,
    ) -> (RouteInfo, Option<Arc<dyn TcpOutbound>>) {
        let mut route = describe(table, resolution);
        route.rule = "MODE,global".to_string();
        (route, self.outbound_of(&resolution.outcome))
    }

    fn outbound_of(&self, outcome: &RouteOutcome) -> Option<Arc<dyn TcpOutbound>> {
        match outcome {
            RouteOutcome::Reject(_) => None,
            RouteOutcome::Direct => Some(self.direct.clone()),
            RouteOutcome::Node(id) => self.nodes.get(id).cloned(),
        }
    }

    /// Records a health check result for a group member; `None` marks it
    /// failed.
    pub fn record_latency(&self, group_id: &str, member: &str, latency_ms: Option<u32>) {
        self.store_latency(group_id, member, latency_ms);
        self.settle_url_test(group_id);
    }

    fn store_latency(&self, group_id: &str, member: &str, latency_ms: Option<u32>) {
        let mut latencies = self
            .latencies
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let group = latencies.entry(group_id.to_string()).or_default();
        match latency_ms {
            Some(latency) => group.insert(member.to_string(), latency),
            None => group.remove(member),
        };
    }

    /// Moves a url-test group to the member it picks with the latest
    /// results, keeping the current one within the tolerance.
    fn settle_url_test(&self, group_id: &str) {
        let table = self.table();
        if table
            .model
            .group(group_id)
            .is_none_or(|group| group.kind != PolicyGroupKind::UrlTest)
        {
            return;
        }
        let pick = self.with_environment(None, |environment| {
            table.model.group_member(group_id, environment)
        });
        let mut now = self
            .url_test_now
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        match pick {
            Some(member) => now.insert(group_id.to_string(), member.name().to_string()),
            None => now.remove(group_id),
        };
    }

    /// Records the results of one check round that started in `epoch`,
    /// unless the network changed since; marks `groups` checked and wakes
    /// the connections waiting for them.
    #[cfg(feature = "local-proxy")]
    fn finish_round(
        &self,
        epoch: u64,
        groups: &[String],
        results: Vec<(String, String, Option<u32>)>,
    ) {
        let current = self.lock_health().epoch == epoch;
        if current {
            let mut touched = BTreeSet::new();
            for (group_id, member, latency) in results {
                self.store_latency(&group_id, &member, latency);
                touched.insert(group_id);
            }
            // Once per group, with the whole round in: the url-test pick
            // never passes through a half-measured state.
            for group_id in touched {
                self.settle_url_test(&group_id);
            }
        }
        {
            let mut health = self.lock_health();
            for group in groups {
                health.in_flight.remove(group);
                if current {
                    health.checked.insert(group.clone());
                }
            }
        }
        self.health_done.notify_waiters();
    }

    /// Where a connection to `target` goes, resolving its domain only when an
    /// IP rule asks for an address before another rule matches. A plain
    /// `REJECT` of a host in a retry storm comes back as `REJECT-DROP`.
    pub async fn route_resolving(&self, target: &TargetAddr) -> RouteOutcome {
        self.resolve_query(&self.table(), &query(target))
            .await
            .outcome
    }

    /// Routes a flow to `target` and says why. For an address target,
    /// `sniffed` (a TLS SNI or HTTP `Host`) is matched by the domain rules
    /// while IP rules keep matching the address; the flow still connects to
    /// the address. `process` is the name of the local process that opened
    /// the flow, for `PROCESS-NAME` rules. A rejected flow gets no outbound.
    pub async fn route_flow(
        &self,
        target: &TargetAddr,
        sniffed: Option<&str>,
        process: Option<&str>,
    ) -> (RouteInfo, Option<Arc<dyn TcpOutbound>>) {
        self.route_network_flow(
            target,
            sniffed,
            process,
            RouteNetwork::Tcp,
            None,
            FlowSource::default(),
        )
        .await
    }

    /// [`Self::route_flow`] for a flow of the given transport, which
    /// `PROTOCOL` rules match, the head sniffed from a plain HTTP request,
    /// which `USER-AGENT` and `URL-REGEX` rules match, and where the flow
    /// came from, which `SRC-IP` and `IN-PORT` rules match.
    pub async fn route_network_flow(
        &self,
        target: &TargetAddr,
        sniffed: Option<&str>,
        process: Option<&str>,
        network: RouteNetwork,
        http: Option<&HttpRequestHead>,
        source: FlowSource,
    ) -> (RouteInfo, Option<Arc<dyn TcpOutbound>>) {
        let mut query = query(target)
            .with_network(network)
            .with_source(source.address, source.in_port)
            .with_source_port(source.port);
        if let Some(http) = http {
            query.user_agent.clone_from(&http.user_agent);
            query.url.clone_from(&http.url);
        }
        if query.domain.is_none() {
            query.domain = sniffed.map(str::to_string);
        }
        query.process = process.map(str::to_string);
        let table = self.table();
        let mut resolution = self.resolve_query(&table, &query).await;
        if self.evaluate_before_use(&table, &resolution).await {
            resolution = self.resolve_query(&table, &query).await;
        }
        count_hit(&table, &resolution);
        self.note_used(&table, &resolution);
        let outbound = self.outbound_of(&resolution.outcome);
        (describe(&table, &resolution), outbound)
    }

    /// Remembers the groups a user flow went through, for lazy health
    /// checks, and asks for a check of a health-checked group on the path
    /// that has no result yet (after a network change). Takes the locks only
    /// when the path has groups.
    fn note_used(&self, table: &RoutingTable, resolution: &RouteResolution) {
        if resolution.group_path.is_empty() {
            return;
        }
        {
            let mut used = self
                .used_groups
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            for group in &resolution.group_path {
                if !used.contains(group) {
                    used.insert(group.clone());
                }
            }
        }
        let unchecked = self.unchecked_groups(table, resolution, |_| true);
        self.request_group_checks(unchecked);
    }

    /// Health-checked groups on the path of `resolution`, picked by
    /// `filter`, with no finished check since the last network change.
    fn unchecked_groups(
        &self,
        table: &RoutingTable,
        resolution: &RouteResolution,
        filter: impl Fn(&config_core::routing::PolicyGroup) -> bool,
    ) -> Vec<String> {
        let health = self.lock_health();
        resolution
            .group_path
            .iter()
            .filter(|id| !health.checked.contains(*id))
            .filter(|id| {
                table
                    .model
                    .group(id)
                    .is_some_and(|group| group.kind.is_health_checked() && filter(group))
            })
            .cloned()
            .collect()
    }

    /// Holds a connection whose path has an `evaluate_before_use` group
    /// without a result until that group's check finishes, at most
    /// [`EVALUATE_WAIT`]. Returns whether it waited, so the caller routes
    /// again with the new results.
    async fn evaluate_before_use(
        &self,
        table: &RoutingTable,
        resolution: &RouteResolution,
    ) -> bool {
        if !self.checks_running.load(Ordering::Acquire) {
            return false;
        }
        let waiting = self.unchecked_groups(table, resolution, |group| group.evaluate_before_use);
        if waiting.is_empty() {
            return false;
        }
        let deadline = tokio::time::Instant::now() + EVALUATE_WAIT;
        loop {
            // Again on every wake: a round that started on the previous
            // network finished without a result.
            self.request_group_checks(waiting.clone());
            let done = self.health_done.notified();
            tokio::pin!(done);
            // Registered before the check below, so a round that ends in
            // between still wakes this flow.
            done.as_mut().enable();
            {
                let health = self.lock_health();
                if waiting.iter().all(|id| health.checked.contains(id)) {
                    return true;
                }
            }
            if tokio::time::timeout_at(deadline, done).await.is_err() {
                return true;
            }
        }
    }

    fn lock_health(&self) -> std::sync::MutexGuard<'_, HealthState> {
        self.health
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Asks the check loop to check `groups` now, unless a check of them
    /// is already due or running.
    fn request_group_checks(&self, groups: Vec<String>) {
        if groups.is_empty() {
            return;
        }
        let mut asked = false;
        {
            let mut health = self.lock_health();
            for group in groups {
                if !health.in_flight.contains(&group) && !health.pending_groups.contains(&group) {
                    health.pending_groups.insert(group);
                    asked = true;
                }
            }
        }
        if asked {
            self.health_wake.notify_one();
        }
    }

    /// A connection routed as `route` (its [`RouteInfo::chain`]) failed to
    /// open through its outbound: probe that outbound in each health-checked
    /// group on the path at once (see the module docs). Rate limited per
    /// outbound by [`FAILURE_RETEST_COOLDOWN`]. Returns whether a probe was
    /// asked for.
    pub fn report_failure(&self, route: &RouteInfo) -> bool {
        let Some((member, groups)) = route.chain.split_last() else {
            return false;
        };
        if groups.is_empty() || route.reject.is_some() || member.starts_with("REJECT") {
            return false;
        }
        let table = self.table();
        let checked_groups: Vec<&String> = groups
            .iter()
            .filter(|id| {
                table
                    .model
                    .group(id)
                    .is_some_and(|group| group.kind.is_health_checked())
            })
            .collect();
        if checked_groups.is_empty() {
            return false;
        }
        let now = Instant::now();
        {
            let mut health = self.lock_health();
            if health
                .failure_retests
                .get(member)
                .is_some_and(|last| now.duration_since(*last) < FAILURE_RETEST_COOLDOWN)
            {
                return false;
            }
            health.failure_retests.insert(member.clone(), now);
            for group in checked_groups {
                health
                    .pending_members
                    .insert((group.clone(), member.clone()));
            }
        }
        self.health_wake.notify_one();
        true
    }

    /// Forgets every health check result, url-test pick and failure
    /// cooldown: the network under the engine changed (see the module
    /// docs). Probes still running record nothing. Returns how many groups
    /// had results.
    pub fn forget_health(&self) -> usize {
        let forgotten = {
            let mut health = self.lock_health();
            health.epoch += 1;
            health.failure_retests.clear();
            health.pending_members.clear();
            std::mem::take(&mut health.checked).len()
        };
        self.latencies
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clear();
        self.url_test_now
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clear();
        forgotten
    }

    /// Checks device names given as address → name (config `devices`,
    /// control `set_devices`): at most [`MAX_DEVICES`], each address an IP
    /// and each name 1-64 characters without control characters.
    pub fn parse_devices(
        devices: &BTreeMap<String, String>,
    ) -> Result<BTreeMap<IpAddr, String>, &'static str> {
        if devices.len() > MAX_DEVICES {
            return Err("at most 256 device names");
        }
        devices
            .iter()
            .map(|(address, name)| {
                let address = address
                    .trim()
                    .parse::<IpAddr>()
                    .map_err(|_| "device addresses must be IP addresses")?
                    .to_canonical();
                let name = name.trim();
                if name.is_empty()
                    || name.chars().count() > 64
                    || name.chars().any(char::is_control)
                {
                    return Err("device names must be 1-64 characters");
                }
                Ok((address, name.to_lowercase()))
            })
            .collect()
    }

    /// Names devices by the address their connections come from, for
    /// `DEVICE-NAME` rules, replacing the names given before. Returns whether
    /// they changed. Connections already open keep their route.
    pub fn set_devices(&self, devices: BTreeMap<IpAddr, String>) -> bool {
        let mut current = self
            .devices
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if *current == devices {
            return false;
        }
        *current = devices;
        true
    }

    /// The device names in use, by address.
    pub fn devices(&self) -> BTreeMap<IpAddr, String> {
        self.devices
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    /// Sets the network the device is on, for subnet groups; `None` when
    /// the client does not know. Returns whether it changed. Connections
    /// already open keep their route.
    pub fn set_network(&self, network: Option<NetworkContext>) -> bool {
        let mut current = self
            .network
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if *current == network {
            return false;
        }
        *current = network;
        true
    }

    /// Whether a check of `group_id` finished since the start or the last
    /// [`Self::forget_health`].
    pub fn group_checked(&self, group_id: &str) -> bool {
        self.lock_health().checked.contains(group_id)
    }

    /// The groups used since the last call, and forgets them.
    #[cfg(any(feature = "local-proxy", test))]
    fn take_used_groups(&self) -> BTreeSet<String> {
        std::mem::take(
            &mut *self
                .used_groups
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner()),
        )
    }

    /// Decides a user flow, resolving a domain when an IP rule needs it,
    /// and drops a host's plain `REJECT` while it storms.
    async fn resolve_query(&self, table: &RoutingTable, query: &RouteQuery) -> RouteResolution {
        let mut resolution = self.decide_resolving(table, query).await;
        if resolution.outcome == RouteOutcome::Reject(RejectKind::Reject) {
            let host = query
                .domain
                .clone()
                .or_else(|| query.ip.map(|ip| ip.to_string()));
            if let Some(host) = host {
                let kind = self.reject_storm.settle(&host, std::time::Instant::now());
                resolution.outcome = RouteOutcome::Reject(kind);
            }
        }
        resolution
    }

    /// Decides `query`, resolving its domain once when an IP rule needs an
    /// address and running each `SCRIPT` rule the decision reaches, then
    /// deciding again with the address or the verdict. Every pass adds one
    /// of them, so this ends after at most one pass more than the scripts.
    async fn decide_resolving(&self, table: &RoutingTable, query: &RouteQuery) -> RouteResolution {
        let mut resolved = None;
        let mut verdicts = BTreeMap::new();
        loop {
            let resolution = self.decide(table, query, resolved, Some(&verdicts));
            match resolution.matched {
                // With `dns-failed` the first pass, which has no address yet,
                // already names FINAL: look the name up first all the same.
                RouteMatch::ResolveFailed(_) | RouteMatch::FinalAfterResolveFailed(_)
                    if resolved.is_none() =>
                {
                    let Some(domain) = query.domain.as_deref() else {
                        return resolution;
                    };
                    let Ok(address) = self.resolver.resolve(domain).await else {
                        return resolution;
                    };
                    resolved = Some(address);
                }
                RouteMatch::ScriptPending(index) => {
                    let Some(name) = script_name(&table.model.rules[index].matcher) else {
                        return resolution;
                    };
                    if verdicts.contains_key(name) {
                        return resolution;
                    }
                    let matched = self
                        .scripts
                        .matches(name, query, resolution.resolved_ip)
                        .await;
                    verdicts.insert(name.to_string(), matched);
                }
                _ => return resolution,
            }
        }
    }

    /// Measures every member of the health-checked groups through its
    /// outbound, then again after the shortest group interval, forever, but
    /// only the groups a flow went through since the previous round (lazy;
    /// a round with none measures nothing). Between rounds it checks at once
    /// what routing asks for: a group without a result that a flow went
    /// through, and a member whose connection failed (see the module docs).
    /// Group members that are groups themselves or REJECT are not measured.
    /// Never returns when no group needs checks.
    #[cfg(feature = "local-proxy")]
    pub async fn run_health_checks(self: Arc<Self>) {
        // Groups never change on a reload, so the first table's are the ones.
        let table = self.table();
        let checked: Vec<_> = table
            .model
            .groups
            .iter()
            .filter(|group| group.kind.is_health_checked())
            .filter_map(|group| Some((group, group.health_check.clone()?)))
            .collect();
        let Some(interval) = checked
            .iter()
            .map(|(_, check)| check.interval_secs.max(30))
            .min()
        else {
            return std::future::pending().await;
        };
        let interval = Duration::from_secs(u64::from(interval));
        self.checks_running.store(true, Ordering::Release);
        let mut first = true;
        let mut next_round = tokio::time::Instant::now();
        loop {
            if !first && !self.lock_health().has_pending() {
                tokio::select! {
                    () = tokio::time::sleep_until(next_round) => {}
                    () = self.health_wake.notified() => {}
                }
            }
            let scheduled = first || tokio::time::Instant::now() >= next_round;
            let used = if scheduled {
                self.take_used_groups()
            } else {
                BTreeSet::new()
            };
            let (epoch, groups, members, asked) = {
                let mut health = self.lock_health();
                let mut groups: Vec<(&config_core::routing::PolicyGroup, String)> = Vec::new();
                if scheduled {
                    for (group, check) in due_groups(&checked, first, &used) {
                        groups.push((group, check.url.clone()));
                    }
                }
                let pending = std::mem::take(&mut health.pending_groups);
                for (group, check) in &checked {
                    if pending.contains(&group.id)
                        && !groups.iter().any(|(due, _)| due.id == group.id)
                    {
                        groups.push((*group, check.url.clone()));
                    }
                }
                for (group, _) in &groups {
                    health.in_flight.insert(group.id.clone());
                }
                let members: Vec<(String, String, String)> =
                    std::mem::take(&mut health.pending_members)
                        .into_iter()
                        .filter(|(group_id, _)| !groups.iter().any(|(due, _)| &due.id == group_id))
                        .filter_map(|(group_id, member)| {
                            let (_, check) =
                                checked.iter().find(|(group, _)| group.id == group_id)?;
                            Some((group_id, member, check.url.clone()))
                        })
                        .collect();
                (health.epoch, groups, members, pending)
            };
            if scheduled {
                next_round = tokio::time::Instant::now() + interval;
            }
            first = false;

            // One probe per (member, URL), however many groups list the
            // member, and at most MAX_CONCURRENT_PROBES at once: a large
            // subscription lists the same nodes in several url-test and
            // fallback groups, and hundreds of handshakes at once inflate
            // every measured latency (and the network extension's memory).
            // A group settles as soon as its own members are measured; the
            // groups a connection waits on (asked for, `evaluate_before_use`,
            // a failed member) go first.
            let mut jobs: BTreeMap<(String, String), ProbeJob> = BTreeMap::new();
            let mut rounds: BTreeMap<String, GroupRound> = BTreeMap::new();
            let mut add = |group_id: &str, member: &PolicyTarget, url: &str, urgent: bool| {
                let outbound = match member {
                    PolicyTarget::Node(id) => self.nodes.get(id).cloned(),
                    PolicyTarget::Direct => Some(self.direct.clone()),
                    PolicyTarget::Reject(_) | PolicyTarget::Group(_) => None,
                };
                let Some(outbound) = outbound else { return };
                rounds.entry(group_id.to_string()).or_default().remaining += 1;
                let job = jobs
                    .entry((member.name().to_string(), url.to_string()))
                    .or_insert_with(|| ProbeJob {
                        outbound,
                        groups: Vec::new(),
                        urgent: false,
                    });
                job.groups.push(group_id.to_string());
                job.urgent |= urgent;
            };
            for (group, url) in &groups {
                let urgent = group.evaluate_before_use || asked.contains(&group.id);
                for member in &group.members {
                    add(&group.id, member, url, urgent);
                }
            }
            for (group_id, member, url) in &members {
                let target = table
                    .model
                    .group(group_id)
                    .and_then(|group| group.members.iter().find(|m| m.name() == member.as_str()));
                if let Some(target) = target {
                    add(group_id, target, url, true);
                }
            }
            for (group, _) in &groups {
                rounds.entry(group.id.clone()).or_default().whole = true;
            }
            for (group_id, _, _) in &members {
                rounds.entry(group_id.clone()).or_default();
            }

            // Groups with nothing to measure are done at once.
            let empty: Vec<String> = rounds
                .iter()
                .filter(|(_, round)| round.remaining == 0)
                .map(|(id, _)| id.clone())
                .collect();
            for group_id in empty {
                if let Some(round) = rounds.remove(&group_id) {
                    self.finish_group(epoch, &group_id, round);
                }
            }

            let mut queue: Vec<((String, String), ProbeJob)> = jobs.into_iter().collect();
            queue.sort_by_key(|(_, job)| !job.urgent);
            let mut queue = queue.into_iter();
            let mut probes = tokio::task::JoinSet::new();
            let mut stale = false;
            loop {
                while !stale && probes.len() < MAX_CONCURRENT_PROBES {
                    // After a network change the rest would record nothing:
                    // do not dial them.
                    if self.lock_health().epoch != epoch {
                        stale = true;
                        break;
                    }
                    let Some(((name, url), job)) = queue.next() else {
                        break;
                    };
                    let ProbeJob {
                        outbound, groups, ..
                    } = job;
                    probes.spawn(async move {
                        // Timed from here: the wait for a slot is not latency.
                        let latency = crate::delay::probe(&*outbound, &url, PROBE_TIMEOUT)
                            .await
                            .ok()
                            .map(|elapsed| u32::try_from(elapsed.as_millis()).unwrap_or(u32::MAX));
                        (name, groups, latency)
                    });
                }
                let Some(joined) = probes.join_next().await else {
                    break;
                };
                let Ok((name, groups, latency)) = joined else {
                    continue;
                };
                for group_id in groups {
                    let Some(round) = rounds.get_mut(&group_id) else {
                        continue;
                    };
                    round
                        .results
                        .push((group_id.clone(), name.clone(), latency));
                    round.remaining = round.remaining.saturating_sub(1);
                    if round.remaining == 0 {
                        if let Some(round) = rounds.remove(&group_id) {
                            self.finish_group(epoch, &group_id, round);
                        }
                    }
                }
            }
            // A network change stopped the round, or a probe task failed:
            // the groups still open finish with what came in (after a
            // network change, nothing is recorded).
            for (group_id, round) in std::mem::take(&mut rounds) {
                self.finish_group(epoch, &group_id, round);
            }
        }
    }

    /// Ends one group's part of a round: [`Self::finish_round`] with its
    /// results, marking it checked when the whole group was measured.
    #[cfg(feature = "local-proxy")]
    fn finish_group(&self, epoch: u64, group_id: &str, round: GroupRound) {
        let whole = [group_id.to_string()];
        let groups: &[String] = if round.whole { &whole } else { &[] };
        self.finish_round(epoch, groups, round.results);
    }
}

/// Health check probes run at once at most, over every group.
pub const MAX_CONCURRENT_PROBES: usize = 16;

/// One health check probe of a round: a member through its outbound, to
/// one URL, whose result every group in `groups` takes.
#[cfg(feature = "local-proxy")]
struct ProbeJob {
    outbound: Arc<dyn TcpOutbound>,
    /// The groups that take the result, a group once per listing.
    groups: Vec<String>,
    /// A group a connection may be waiting on takes it: probe first.
    urgent: bool,
}

/// One group's part of a round.
#[cfg(feature = "local-proxy")]
#[derive(Default)]
struct GroupRound {
    /// The whole group is measured (else only members a failed connection
    /// asked for).
    whole: bool,
    /// Probes still to come for this group.
    remaining: usize,
    results: Vec<(String, String, Option<u32>)>,
}

/// The health-checked groups to measure this round: all of them in the
/// first round, afterwards only those in `used` (lazy checks).
#[cfg(any(feature = "local-proxy", test))]
fn due_groups<'a>(
    checked: &'a [(
        &'a config_core::routing::PolicyGroup,
        config_core::routing::HealthCheck,
    )],
    first: bool,
    used: &BTreeSet<String>,
) -> Vec<(
    &'a config_core::routing::PolicyGroup,
    &'a config_core::routing::HealthCheck,
)> {
    checked
        .iter()
        .filter(|(group, _)| first || used.contains(&group.id))
        .map(|(group, check)| (*group, check))
        .collect()
}

/// Counts the rule, or FINAL, that decided a flow. A decision stopped at a
/// rule script never reaches a flow.
fn count_hit(table: &RoutingTable, resolution: &RouteResolution) {
    match resolution.matched {
        RouteMatch::Rule(index) | RouteMatch::ResolveFailed(index) => table.hits.record(index),
        RouteMatch::Final | RouteMatch::FinalAfterResolveFailed(_) => {
            table.hits.record(table.model.rules.len())
        }
        RouteMatch::ScriptPending(_) => {}
    }
}

/// The rule, group path and outbound of a decision, as the connection
/// list shows them.
fn describe(table: &RoutingTable, resolution: &RouteResolution) -> RouteInfo {
    let rule = match resolution.matched {
        RouteMatch::Rule(index) => table.model.rules[index].matcher.to_string(),
        RouteMatch::ResolveFailed(index) => {
            format!("{} (resolve failed)", table.model.rules[index].matcher)
        }
        RouteMatch::ScriptPending(index) => {
            format!("{} (script pending)", table.model.rules[index].matcher)
        }
        RouteMatch::FinalAfterResolveFailed(_) => "FINAL (dns-failed)".to_string(),
        RouteMatch::Final => "FINAL".to_string(),
    };
    let (outbound, reject) = match &resolution.outcome {
        RouteOutcome::Direct => ("DIRECT".to_string(), None),
        RouteOutcome::Reject(kind) => (kind.name().to_string(), Some(*kind)),
        RouteOutcome::Node(id) => (id.clone(), None),
    };
    let mut chain = resolution.group_path.clone();
    chain.push(outbound.clone());
    RouteInfo {
        rule,
        chain,
        outbound,
        reject,
    }
}

/// Compiles one rule table: the model, the global target (`global_name`,
/// else the first group, else the first node, else DIRECT), and the plugin
/// rules ahead of the user's. The error message is fixed so rule text and
/// node settings never reach status or logs.
fn compile_table(
    spec: &RoutingSpec,
    node_ids: &BTreeSet<String>,
    rule_sets: &RuleSetStore,
    global_name: Option<&str>,
    plugin_rules: &[RoutingRule],
    generation: u64,
) -> Result<RoutingTable, RuntimeError> {
    let model = RoutingModel::from_spec(spec, node_ids).map_err(|_| {
        RuntimeError::new(
            RuntimeErrorCode::ConfigRejected,
            "routing rules or policy groups are invalid",
        )
    })?;
    let mut named = Vec::new();
    for rule in &model.rules {
        named_sets(&rule.matcher, &mut named);
    }
    if named.iter().any(|name| !rule_sets.contains(name)) {
        return Err(RuntimeError::new(
            RuntimeErrorCode::ConfigRejected,
            "a routing rule names a rule set that is not configured",
        ));
    }
    let uses_process = model
        .rules
        .iter()
        .any(|rule| matches_process(&rule.matcher));
    let uses_request = model
        .rules
        .iter()
        .any(|rule| matches_request(&rule.matcher));
    let global = match global_name {
        Some(name) => global_target(&model, name, node_ids)?,
        None => match model.groups.first() {
            Some(group) => PolicyTarget::Group(group.id.clone()),
            None => node_ids
                .iter()
                .next()
                .map_or(PolicyTarget::Direct, |id| PolicyTarget::Node(id.clone())),
        },
    };
    let mut table = RoutingTable {
        model,
        index: RuleIndex::default(),
        global,
        uses_process,
        uses_request,
        generation,
        hits: Arc::default(),
    };
    add_plugin_rules(&mut table, plugin_rules, node_ids, rule_sets);
    table.hits = Arc::new(RuleHits::new(table.model.rules.len() + 1));
    Ok(table)
}

fn global_target(
    model: &RoutingModel,
    name: &str,
    node_ids: &BTreeSet<String>,
) -> Result<PolicyTarget, RuntimeError> {
    match model.target_named(name, node_ids) {
        Some(PolicyTarget::Reject(_)) | None => Err(RuntimeError::new(
            RuntimeErrorCode::ConfigRejected,
            "the global target must be a policy group, a node or DIRECT",
        )),
        Some(target) => Ok(target),
    }
}

/// Puts MITM plugin rules ahead of the table's rules (see
/// [`RoutedOutbound::with_plugin_rules`]).
fn add_plugin_rules(
    table: &mut RoutingTable,
    rules: &[RoutingRule],
    node_ids: &BTreeSet<String>,
    rule_sets: &RuleSetStore,
) {
    let mut added = Vec::new();
    for rule in rules {
        let mut named = Vec::new();
        named_sets(&rule.matcher, &mut named);
        // A plugin cannot bring rule scripts.
        if named.iter().any(|name| !rule_sets.contains(name))
            || script_name(&rule.matcher).is_some()
        {
            continue;
        }
        let target = match &rule.target {
            PolicyTarget::Direct | PolicyTarget::Reject(_) => rule.target.clone(),
            PolicyTarget::Group(name) | PolicyTarget::Node(name) => table
                .model
                .target_named(name, node_ids)
                .unwrap_or_else(|| table.global.clone()),
        };
        table.uses_process |= matches_process(&rule.matcher);
        table.uses_request |= matches_request(&rule.matcher);
        added.push(RoutingRule {
            matcher: rule.matcher.clone(),
            target,
            no_resolve: rule.no_resolve,
        });
    }
    added.append(&mut table.model.rules);
    table.model.rules = added;
    table.index = RuleIndex::new(&table.model);
}

/// Checks a reloaded rule list line by line, so the client can point at the
/// first bad line: size, syntax, target names, rule sets and FINAL last.
fn check_rule_lines(
    rules: &[String],
    node_ids: &BTreeSet<String>,
    model: &RoutingModel,
    rule_sets: &RuleSetStore,
    scripts: &RuleScripts,
) -> Result<(), RulesRejection> {
    let reject = |line: Option<usize>, code| Err(RulesRejection { line, code });
    if rules.len() > node_import::MAX_ROUTING_RULES {
        return reject(None, reject_code::TOO_MANY);
    }
    // Groups and nodes never change on a reload, so the running model
    // knows every name a new rule may use.
    let known_target = |name: &str| model.target_named(name, node_ids).is_some();
    let mut final_seen = false;
    for (index, line) in rules.iter().enumerate() {
        if line.len() > MAX_RULE_LINE_LEN {
            return reject(Some(index), reject_code::LINE_TOO_LONG);
        }
        if final_seen {
            return reject(Some(index), reject_code::FINAL_NOT_LAST);
        }
        let Ok(parsed) = parse_rule_line(line) else {
            return reject(Some(index), reject_code::SYNTAX);
        };
        match parsed {
            RuleLine::Rule {
                matcher, target, ..
            } => {
                if !known_target(&target) {
                    return reject(Some(index), reject_code::UNKNOWN_TARGET);
                }
                let mut named = Vec::new();
                named_sets(&matcher, &mut named);
                if named.iter().any(|name| !rule_sets.contains(name)) {
                    return reject(Some(index), reject_code::UNKNOWN_RULE_SET);
                }
                if script_name(&matcher).is_some_and(|name| !scripts.contains(name)) {
                    return reject(Some(index), reject_code::UNKNOWN_SCRIPT);
                }
            }
            RuleLine::Final { target, .. } => {
                if !known_target(&target) {
                    return reject(Some(index), reject_code::UNKNOWN_TARGET);
                }
                final_seen = true;
            }
        }
    }
    if !final_seen {
        return reject(None, reject_code::FINAL_MISSING);
    }
    Ok(())
}

fn query(target: &TargetAddr) -> RouteQuery {
    match target {
        TargetAddr::Ip(addr) => RouteQuery::ip(addr.ip()),
        TargetAddr::Domain(domain, _) => RouteQuery::domain(domain.clone()),
    }
    .with_port(target.port())
}

/// The script a `SCRIPT` rule names (never inside a logical rule).
fn script_name(matcher: &RuleMatcher) -> Option<&str> {
    match matcher {
        RuleMatcher::Script(name) => Some(name),
        _ => None,
    }
}

fn matches_process(matcher: &RuleMatcher) -> bool {
    match matcher {
        RuleMatcher::ProcessName(_) => true,
        RuleMatcher::And(rules) | RuleMatcher::Or(rules) => rules.iter().any(matches_process),
        RuleMatcher::Not(rule) => matches_process(rule),
        _ => false,
    }
}

fn matches_request(matcher: &RuleMatcher) -> bool {
    match matcher {
        RuleMatcher::UserAgent(_) | RuleMatcher::UrlRegex(_) => true,
        RuleMatcher::And(rules) | RuleMatcher::Or(rules) => rules.iter().any(matches_request),
        RuleMatcher::Not(rule) => matches_request(rule),
        _ => false,
    }
}

/// Most names [`RoutedOutbound::missing_data_sets`] lists.
pub const MAX_MISSING_DATA_SETS: usize = 64;

/// The sets the `GEOIP` and `IP-ASN` rules in `matcher` look addresses up in.
fn data_sets(matcher: &RuleMatcher, names: &mut BTreeSet<String>) {
    match matcher {
        RuleMatcher::GeoIp(country) => {
            names.insert(format!("geoip-{}", country.to_ascii_lowercase()));
        }
        RuleMatcher::IpAsn(number) => {
            names.insert(format!("asn-{number}"));
        }
        RuleMatcher::And(rules) | RuleMatcher::Or(rules) => {
            for rule in rules {
                data_sets(rule, names);
            }
        }
        RuleMatcher::Not(rule) => data_sets(rule, names),
        _ => {}
    }
}

/// The rule sets a rule needs: `RULE-SET` names and `geosite-<category>`.
fn named_sets(matcher: &RuleMatcher, names: &mut Vec<String>) {
    match matcher {
        RuleMatcher::RuleSet(name) => names.push(name.clone()),
        RuleMatcher::GeoSite(category) => names.push(format!("geosite-{category}")),
        RuleMatcher::And(rules) | RuleMatcher::Or(rules) => {
            for rule in rules {
                named_sets(rule, names);
            }
        }
        RuleMatcher::Not(rule) => named_sets(rule, names),
        _ => {}
    }
}

impl TcpOutbound for RoutedOutbound {
    fn protocol(&self) -> &'static str {
        PROTOCOL
    }

    fn connect<'a>(&'a self, target: &'a TargetAddr) -> BoxFuture<'a, io::Result<BoxStream>> {
        Box::pin(async move { self.outbound_for(target).await?.connect(target).await })
    }

    fn reset_sessions(&self) -> usize {
        RoutedOutbound::reset_sessions(self)
    }

    /// UDP follows the same rules as TCP, decided once per flow.
    fn open_udp<'a>(&'a self, target: &'a TargetAddr) -> BoxFuture<'a, io::Result<UdpFlow>> {
        Box::pin(async move { self.outbound_for(target).await?.open_udp(target).await })
    }
}

impl RoutedOutbound {
    async fn outbound_for(&self, target: &TargetAddr) -> io::Result<&Arc<dyn TcpOutbound>> {
        let table = self.table();
        let resolution = self.resolve_query(&table, &query(target)).await;
        count_hit(&table, &resolution);
        match resolution.outcome {
            RouteOutcome::Reject(kind) => Err(engine_outbound::reject::rejected(
                crate::reject::action(kind),
            )),
            RouteOutcome::Direct => Ok(&self.direct),
            RouteOutcome::Node(id) => self.nodes.get(&id).ok_or_else(|| {
                io::Error::new(io::ErrorKind::NotFound, "routed node is not configured")
            }),
        }
    }
}

#[cfg(test)]
mod lazy_health_tests {
    use super::*;

    struct Refuse;

    impl TcpOutbound for Refuse {
        fn protocol(&self) -> &'static str {
            "test-refuse"
        }

        fn connect<'a>(&'a self, _target: &'a TargetAddr) -> BoxFuture<'a, io::Result<BoxStream>> {
            Box::pin(async { Err(io::Error::other("refused")) })
        }
    }

    fn group(id: &str, kind: &str, members: &[&str]) -> PolicyGroupSpec {
        PolicyGroupSpec {
            id: id.to_string(),
            kind: kind.to_string(),
            members: members.iter().map(|m| m.to_string()).collect(),
            default: None,
            url: None,
            interval_secs: None,
            tolerance_ms: None,
            ..PolicyGroupSpec::default()
        }
    }

    fn routed() -> RoutedOutbound {
        let node = || -> Arc<dyn TcpOutbound> { Arc::new(Refuse) };
        let nodes = BTreeMap::from([("hk-1".to_string(), node()), ("jp-1".to_string(), node())]);
        let spec = RoutingSpec {
            rules: vec![
                "DOMAIN-SUFFIX,example.jp,JP".to_string(),
                "FINAL,Proxy".to_string(),
            ],
            groups: vec![
                group("Proxy", "select", &["HK", "JP"]),
                group("HK", "url-test", &["hk-1", "jp-1"]),
                group("JP", "url-test", &["jp-1", "hk-1"]),
            ],
        };
        RoutedOutbound::new(&spec, node(), nodes).expect("spec should validate")
    }

    fn checked(routed: &RoutedOutbound) -> Vec<String> {
        let table = routed.table();
        let checked: Vec<_> = table
            .model
            .groups
            .iter()
            .filter_map(|group| Some((group, group.health_check.clone()?)))
            .collect();
        let used = routed.take_used_groups();
        due_groups(&checked, false, &used)
            .into_iter()
            .map(|(group, _)| group.id.clone())
            .collect()
    }

    #[tokio::test]
    async fn only_groups_a_flow_went_through_are_due() {
        let routed = routed();
        // No traffic: nothing to measure after the first round.
        assert!(checked(&routed).is_empty());

        let target = TargetAddr::Domain("www.example.jp".to_string(), 443);
        let (route, _) = routed.route_flow(&target, None, None).await;
        assert_eq!(route.chain, vec!["JP".to_string(), "jp-1".to_string()]);
        assert_eq!(checked(&routed), vec!["JP".to_string()]);
        // Taken once: the next round without traffic is idle again.
        assert!(checked(&routed).is_empty());

        // FINAL goes through the select group into its first member, HK.
        let other = TargetAddr::Domain("other.example".to_string(), 443);
        routed.route_flow(&other, None, None).await;
        assert_eq!(checked(&routed), vec!["HK".to_string()]);
    }

    #[test]
    fn the_first_round_measures_every_checked_group() {
        let routed = routed();
        let table = routed.table();
        let checked: Vec<_> = table
            .model
            .groups
            .iter()
            .filter_map(|group| Some((group, group.health_check.clone()?)))
            .collect();
        let due = due_groups(&checked, true, &BTreeSet::new());
        assert_eq!(due.len(), 2);
    }
}
