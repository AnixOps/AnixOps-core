//! Converts normalized subscription nodes (`control_domain::NodeDescriptor`)
//! into outbound entries (`{"type": ..., ...}`) of the embedded engine's
//! config envelope, and turns pasted or downloaded subscription text into a
//! list of them, with the subscription's rules and policy groups when the
//! engine can run them.
//!
//! [`share_link`] goes the other way, from an outbound entry to a share link.
//!
//! This crate carries no protocol code and no runtime, so the iOS app can link
//! it (see [`ffi`]) to import nodes without linking the packet tunnel engine.
//! A node whose protocol or options cannot be carried is reported with a fixed
//! reason, never with its credentials.

pub mod ffi;
pub mod share_link;

pub use share_link::share_link;

use std::collections::{BTreeMap, BTreeSet};

use config_core::certificate_pin;
use config_core::routing::{parse_rule_line, RoutingSpec, RuleLine};
use config_core::routing_import::{
    import_subscription_routing, ImportedRuleSet, ROUTING_IMPORT_INVALID_CODE,
};
use control_domain::{
    NodeCatalog, NodeDescriptor, Protocol, SubscriptionService, SubscriptionSource,
    NODE_METADATA_ANX_ALPN, NODE_METADATA_ANX_BARE_PORT, NODE_METADATA_ANX_FINGERPRINT,
    NODE_METADATA_ANX_JACKET, NODE_METADATA_ANX_LICENSE_ORIGIN, NODE_METADATA_ANX_PUBLIC_KEY,
    NODE_METADATA_ANX_SERVER_NAME, NODE_METADATA_ANX_USER_KEY, NODE_METADATA_ANX_WG_PORT,
    NODE_METADATA_HYSTERIA2_OBFS_PASSWORD, NODE_METADATA_HYSTERIA2_OBFS_TYPE,
    NODE_METADATA_HYSTERIA2_PASSWORD, NODE_METADATA_IWAN_ENCRYPT, NODE_METADATA_IWAN_MTU,
    NODE_METADATA_IWAN_PASSWORD, NODE_METADATA_IWAN_USERNAME, NODE_METADATA_MIERU_PASSWORD,
    NODE_METADATA_MIERU_PORT_RANGE, NODE_METADATA_MIERU_TRANSPORT, NODE_METADATA_MIERU_USERNAME,
    NODE_METADATA_MULTIPLEX, NODE_METADATA_PATH, NODE_METADATA_PROXY_PASSWORD,
    NODE_METADATA_PROXY_USERNAME, NODE_METADATA_SHADOWSOCKS_METHOD,
    NODE_METADATA_SHADOWSOCKS_PASSWORD, NODE_METADATA_SHADOWSOCKS_PLUGIN, NODE_METADATA_SNELL_MODE,
    NODE_METADATA_SNELL_OBFS, NODE_METADATA_SNELL_OBFS_HOST, NODE_METADATA_SNELL_OBFS_URI,
    NODE_METADATA_SNELL_PSK, NODE_METADATA_SNELL_REUSE, NODE_METADATA_SNELL_USER_KEY,
    NODE_METADATA_SNELL_VERSION, NODE_METADATA_TLS_ALPN,
    NODE_METADATA_TLS_CERTIFICATE_PUBLIC_KEY_SHA256, NODE_METADATA_TLS_CERTIFICATE_SHA256,
    NODE_METADATA_TLS_ENABLED, NODE_METADATA_TLS_INSECURE, NODE_METADATA_TLS_REALITY_PUBLIC_KEY,
    NODE_METADATA_TLS_REALITY_SHORT_ID, NODE_METADATA_TLS_SERVER_NAME,
    NODE_METADATA_TLS_UTLS_FINGERPRINT, NODE_METADATA_TROJAN_PASSWORD,
    NODE_METADATA_TUIC_CONGESTION_CONTROL, NODE_METADATA_TUIC_PASSWORD, NODE_METADATA_TUIC_UUID,
    NODE_METADATA_UNSUPPORTED_OPTION, NODE_METADATA_V2RAY_TRANSPORT_EXTRA,
    NODE_METADATA_V2RAY_TRANSPORT_HOST, NODE_METADATA_V2RAY_TRANSPORT_MODE,
    NODE_METADATA_V2RAY_TRANSPORT_PATH, NODE_METADATA_V2RAY_TRANSPORT_SERVICE_NAME,
    NODE_METADATA_V2RAY_TRANSPORT_TYPE, NODE_METADATA_VIA, NODE_METADATA_VIA_UNRESOLVED,
    NODE_METADATA_VLESS_ENCRYPTION, NODE_METADATA_VLESS_FLOW, NODE_METADATA_VLESS_UUID,
    NODE_METADATA_VMESS_ALTER_ID, NODE_METADATA_VMESS_SECURITY, NODE_METADATA_VMESS_UUID,
    NODE_METADATA_WIREGUARD_ALLOWED_IPS, NODE_METADATA_WIREGUARD_LOCAL_ADDRESS,
    NODE_METADATA_WIREGUARD_MTU, NODE_METADATA_WIREGUARD_PEER_PUBLIC_KEY,
    NODE_METADATA_WIREGUARD_PRE_SHARED_KEY, NODE_METADATA_WIREGUARD_PRIVATE_KEY,
    NODE_METADATA_WIREGUARD_RESERVED, NODE_UNSUPPORTED_OPTION_ECH,
    NODE_UNSUPPORTED_OPTION_HTTP_OBFS, NODE_UNSUPPORTED_OPTION_HTTP_PROXY_HEADERS,
    NODE_UNSUPPORTED_OPTION_TRANSPORT, NODE_UNSUPPORTED_OPTION_XHTTP,
};
use serde::Serialize;
use serde_json::{json, Value};

/// Why a node cannot be converted. Fixed text, no node values.
pub type Unsupported = &'static str;

/// The outbound entry for one node. Whether this build's engine compiles the
/// protocol in is the engine's call (`engine_embedded::nodes::outbound_for_node`).
///
/// A node that connects through another one carries `via` with that node's
/// id; [`report`] keeps it only when that node can run too.
pub fn outbound_json(node: &NodeDescriptor) -> Result<Value, Unsupported> {
    if metadata(node, NODE_METADATA_VIA_UNRESOLVED).is_some() {
        return Err("it connects through an outbound that is not one of the imported nodes");
    }
    if let Some(option) = metadata(node, NODE_METADATA_UNSUPPORTED_OPTION) {
        return Err(unsupported_option_reason(option));
    }
    let mut outbound = match &node.protocol {
        Protocol::Shadowsocks => shadowsocks(node),
        Protocol::Vless => vless(node),
        Protocol::Trojan => trojan(node),
        Protocol::Vmess => vmess(node),
        Protocol::Hysteria2 => hysteria2(node),
        Protocol::Tuic => tuic(node),
        Protocol::Snell => snell(node),
        Protocol::Mieru => mieru(node),
        Protocol::Iwan => iwan(node),
        Protocol::Anx => anx(node),
        Protocol::WireGuard => wireguard(node),
        Protocol::Http => http(node),
        Protocol::Socks => socks(node),
        _ => Err("this protocol is not supported yet"),
    }?;
    if let Some(via) = metadata(node, NODE_METADATA_VIA) {
        // These dial their own UDP or tunnel and cannot ride another node
        // (the engine's `supports_via`); one in a routed config would fail
        // the whole tunnel.
        if matches!(
            node.protocol,
            Protocol::Hysteria2
                | Protocol::Tuic
                | Protocol::Iwan
                | Protocol::Anx
                | Protocol::WireGuard
        ) {
            return Err("this protocol cannot connect through another node");
        }
        outbound["via"] = json!(via);
    }
    if let Some(multiplex) = metadata(node, NODE_METADATA_MULTIPLEX) {
        // Only stream protocols whose servers take sing-mux, and not a
        // vless flow (the engine's rule); elsewhere the node runs without.
        let flow = outbound["flow"].as_str().unwrap_or_default();
        let multiplexed = match node.protocol {
            Protocol::Shadowsocks | Protocol::Trojan | Protocol::Vmess => true,
            Protocol::Vless => flow.is_empty() || flow == "none",
            _ => false,
        };
        if let (true, Ok(settings)) = (multiplexed, serde_json::from_str::<Value>(multiplex)) {
            outbound["multiplex"] = settings;
        }
    }
    Ok(outbound)
}

/// Why a node whose source names an option no node field carries
/// ([`NODE_METADATA_UNSUPPORTED_OPTION`]) cannot run.
fn unsupported_option_reason(option: &str) -> Unsupported {
    match option {
        NODE_UNSUPPORTED_OPTION_HTTP_OBFS => {
            "http header obfuscation transports are not implemented yet"
        }
        NODE_UNSUPPORTED_OPTION_TRANSPORT => {
            "transports other than tcp, ws, grpc and xhttp are not implemented yet"
        }
        NODE_UNSUPPORTED_OPTION_ECH => "encrypted client hello (ECH) is not implemented yet",
        NODE_UNSUPPORTED_OPTION_XHTTP => {
            "xhttp options other than path, host, mode and headers are not implemented yet"
        }
        NODE_UNSUPPORTED_OPTION_HTTP_PROXY_HEADERS => {
            "extra headers or a request path of an http proxy are not implemented yet"
        }
        _ => "an option of this node is not implemented yet",
    }
}

/// Largest subscription text [`import_text`] accepts.
pub const MAX_IMPORT_TEXT_LEN: usize = 4 * 1024 * 1024;

/// Most nodes, rules and policy groups a routed config may carry. The engine
/// (`engine_embedded::config`) enforces the same limits. 64 nodes is what
/// the iOS packet tunnel's memory budget is sized for (each routed node is
/// a live outbound, and health checks probe every member of a group at
/// once); a subscription with more nodes routes the ones its rules and
/// groups name (see [`ImportReport::routed_node_ids`]).
pub const MAX_ROUTED_OUTBOUNDS: usize = 64;
pub const MAX_ROUTING_RULES: usize = 4096;
pub const MAX_POLICY_GROUPS: usize = 64;
/// Most network rules one `subnet` group may have; the engine enforces the
/// same limit.
pub const MAX_NETWORK_RULES: usize = 64;
/// Longest `via` chain, the node itself included; the engine enforces the
/// same limit.
pub const MAX_VIA_CHAIN: usize = 4;

/// Nodes found in a subscription text, in its order.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ImportReport {
    pub nodes: Vec<ImportedNode>,
    pub unsupported: Vec<UnsupportedNode>,
    /// The subscription's rules, policy groups and remote rule sets as the
    /// engine's `routing` section without `outbounds` (see [`routing_json`]
    /// and [`rule_sets_json`]); rules and groups name nodes by
    /// [`ImportedNode::id`]. Nodes that cannot run (and nodes whose id is not
    /// a valid outbound id, or whose `via` chain cannot run) are left out of
    /// it: group members naming them are dropped, groups left without
    /// members are dropped, and rules sending traffic to either are skipped,
    /// each with a [`ImportReport::routing_warnings`] line. Absent when the
    /// subscription has no rules, or when what is left is not a valid
    /// routing (no FINAL rule, ...) or does not fit the limits above; a
    /// [`ImportReport::routing_warnings`] line then says why.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub routing: Option<Value>,
    /// With [`ImportReport::routing`], the ids of the nodes its
    /// `routing.outbounds` must hold, in subscription order: every node that
    /// can be routed when they are at most [`MAX_ROUTED_OUTBOUNDS`],
    /// otherwise only the nodes the rules, groups and rule set downloads
    /// name, with the nodes they connect through. A client adds the node it
    /// sends global mode to (and that node's `via` chain) when it is not
    /// listed; the list leaves room for that ([`MAX_VIA_CHAIN`] entries).
    /// Absent without routing.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub routed_node_ids: Option<Vec<String>>,
    /// What importing the subscription's rules left out, one line each
    /// (nodes that cannot run, counted; rules of unsupported types counted
    /// by type, Surge's built-in `RULE-SET,SYSTEM`, targets that were not
    /// imported, ...) and, when there is no routing, why, so a client can
    /// say so instead of the rules silently matching less or the
    /// subscription silently running one node. English, fixed wording with
    /// counts, limits, rule types, indexes and policy names; never a node's
    /// credentials or a list URL. The summary lines (nodes left out, why
    /// there is no routing) come first. Left out when nothing was.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub routing_warnings: Vec<String>,
    /// Subscription entries that could not be read and were left out so the
    /// others still import (a proxy type no reader knows, a malformed share
    /// link, a field of the wrong type), at most [`MAX_SKIPPED_ENTRIES`].
    /// Unlike [`ImportReport::unsupported`] these never became nodes, and
    /// they do not keep [`ImportReport::routing`] out: rules and group
    /// members that name them are left out with a
    /// [`ImportReport::routing_warnings`] line instead. Built-in policy
    /// entries (Surge's `DIRECT = direct`, a Clash `type: direct` proxy) are
    /// not listed. Left out when nothing was skipped.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub skipped: Vec<SkippedEntry>,
    /// How many entries were skipped, also those past
    /// [`MAX_SKIPPED_ENTRIES`]. Left out when none were.
    #[serde(skip_serializing_if = "is_zero")]
    pub skipped_count: usize,
}

/// A subscription entry left out of the import, with a fixed reason.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SkippedEntry {
    /// The stable reason code (`subscription.core.*`), such as
    /// `subscription.core.clash_yaml_unsupported`.
    pub code: String,
    /// English, fixed wording: the entry's format and position, its name
    /// and type when they read as labels, and why it was skipped. Never the
    /// entry's text or credentials.
    pub message: String,
}

/// Most [`ImportReport::skipped`] entries kept.
pub const MAX_SKIPPED_ENTRIES: usize = 32;

fn is_zero(value: &usize) -> bool {
    *value == 0
}

/// A node the engine can run. `outbound` holds its credentials.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ImportedNode {
    /// Stable node id: the same server keeps it when the subscription
    /// reorders, adds, removes or renames entries
    /// (`docs/architecture/subscription-node-ids.md`).
    pub id: String,
    /// The id earlier releases gave this node (name plus position), so a
    /// client can move a selection it saved under that id to [`Self::id`].
    /// Only reliable for the subscription content the client saved it with.
    /// Left out for nodes that never had another id.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub legacy_id: Option<String>,
    pub name: String,
    /// The outbound `type`.
    pub protocol: String,
    pub server: String,
    pub port: u16,
    pub outbound: Value,
    /// How the node crosses the border when the subscription says so:
    /// `trunk` for a domestic ingress on a shared link, which clients pick
    /// by default (anx FUTURE-IMPROVEMENTS F-51). Absent for other nodes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
}

/// A node that was recognized but cannot run, with a fixed reason.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct UnsupportedNode {
    pub name: String,
    pub protocol: String,
    pub reason: Unsupported,
}

/// Why a text yielded no node list. Fixed text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImportError {
    Empty,
    TooLarge,
    Unrecognized,
}

impl ImportError {
    pub fn as_str(self) -> &'static str {
        match self {
            ImportError::Empty => "subscription text is empty",
            ImportError::TooLarge => "subscription text is too large",
            ImportError::Unrecognized => "subscription text is not a supported format",
        }
    }
}

/// Parses share links, base64 link lists, Clash YAML, JSON outbound configs and
/// Surge, Loon or Quantumult X proxy lines.
pub fn import_text(text: &str) -> Result<ImportReport, ImportError> {
    if text.trim().is_empty() {
        return Err(ImportError::Empty);
    }
    if text.len() > MAX_IMPORT_TEXT_LEN {
        return Err(ImportError::TooLarge);
    }
    let service = config_core::CoreSubscriptionService::new();
    let source = SubscriptionSource {
        id: "import".to_string(),
        location: format!("inline:{text}"),
    };
    let document = service
        .fetch(&source)
        .and_then(|raw| service.parse(&raw))
        .map_err(|_| ImportError::Unrecognized)?;
    let catalog: NodeCatalog = service
        .normalize(&document)
        .map_err(|_| ImportError::Unrecognized)?;
    let mut report = report(&catalog.nodes);
    (report.skipped, report.skipped_count) = skipped_entries(&document.diagnostics);
    let fitted =
        fit_subscription_routing(text, &catalog.nodes, &|node| outbound_json(node).is_ok());
    report.routing = fitted.routing;
    report.routed_node_ids = fitted.routed_node_ids;
    report.routing_warnings = fitted.warnings;
    Ok(report)
}

/// `rules` and `groups` of the engine's `routing` section for `spec`.
pub fn routing_json(spec: &RoutingSpec) -> Value {
    let groups: Vec<Value> = spec
        .groups
        .iter()
        .map(|group| {
            let mut value = json!({
                "id": group.id,
                "type": group.kind,
                "members": group.members,
                "default": group.default,
                "url": group.url,
                "interval_secs": group.interval_secs,
                "tolerance_ms": group.tolerance_ms,
            });
            // Only when set, so a config without them stays as before.
            if group.evaluate_before_use {
                value["evaluate_before_use"] = json!(true);
            }
            if !group.network_rules.is_empty() {
                value["network_rules"] = group
                    .network_rules
                    .iter()
                    .map(|rule| json!({ "when": rule.when, "target": rule.target }))
                    .collect();
            }
            value
        })
        .collect();
    json!({ "rules": spec.rules, "groups": groups })
}

/// Most [`ImportReport::routing_warnings`] lines kept; one more says how many
/// were left out.
const MAX_ROUTING_WARNINGS: usize = 32;

/// A subscription's rules and policy groups fitted to the nodes that can
/// run; see [`fit_subscription_routing`].
#[derive(Debug, Clone, PartialEq)]
pub struct FittedRouting {
    /// As [`ImportReport::routing`].
    pub routing: Option<Value>,
    /// The rules and groups `routing` was built from, for an engine envelope
    /// (`engine_embedded::nodes::routing_envelope_with_sets`). `None`
    /// without routing.
    pub spec: Option<RoutingSpec>,
    /// The remote rule sets `spec` names; empty without routing.
    pub rule_sets: Vec<ImportedRuleSet>,
    /// As [`ImportReport::routed_node_ids`].
    pub routed_node_ids: Option<Vec<String>>,
    /// As [`ImportReport::routing_warnings`].
    pub warnings: Vec<String>,
}

/// Imports the rules and policy groups of subscription `text` for the
/// `nodes` read from it, keeping to the nodes the engine can route.
///
/// A node can be routed when `runnable` accepts it, its id is a valid
/// outbound id, and the nodes it connects through (`via`, at most
/// [`MAX_VIA_CHAIN`] including itself) can be routed too. The others are
/// left out of the import: group members and rules naming them are dropped
/// with a warning each, as for any target that was not imported, so one
/// node that cannot run no longer costs the whole subscription its rules.
/// When more than [`MAX_ROUTED_OUTBOUNDS`] nodes can be routed, only those
/// the rules, groups and rule sets name are
/// ([`ImportReport::routed_node_ids`]).
///
/// Routing is left out, with a warning line saying why, when the
/// subscription's rules do not form a valid routing, or the result exceeds
/// [`MAX_ROUTING_RULES`], [`MAX_POLICY_GROUPS`] or [`MAX_NETWORK_RULES`],
/// or names more nodes than fit. A subscription without rules gets neither
/// routing nor warnings.
pub fn fit_subscription_routing(
    text: &str,
    nodes: &[NodeDescriptor],
    runnable: &dyn Fn(&NodeDescriptor) -> bool,
) -> FittedRouting {
    let mut by_id: BTreeMap<&str, usize> = BTreeMap::new();
    for (index, node) in nodes.iter().enumerate() {
        by_id.entry(node.id.as_str()).or_insert(index);
    }
    let usable = nodes
        .iter()
        .map(|node| is_outbound_id(&node.id) && runnable(node))
        .collect::<Vec<_>>();
    let mut routable = Vec::new();
    let (mut cannot_run, mut invalid_ids, mut broken_chains) = (0usize, 0usize, 0usize);
    for (index, node) in nodes.iter().enumerate() {
        if !is_outbound_id(&node.id) {
            invalid_ids += 1;
        } else if !usable[index] {
            cannot_run += 1;
        } else if via_chain(nodes, &by_id, &usable, index).is_none() {
            broken_chains += 1;
        } else {
            routable.push(node.clone());
        }
    }

    let imported = import_subscription_routing(text, &routable);
    if imported.spec.is_none() && imported.diagnostics.is_empty() {
        // The subscription has no rules: nothing to say.
        return FittedRouting {
            routing: None,
            spec: None,
            rule_sets: Vec::new(),
            routed_node_ids: None,
            warnings: Vec::new(),
        };
    }
    let mut summary = Vec::new();
    for (count, what) in [
        (cannot_run, "that cannot run"),
        (invalid_ids, "whose ids are not valid outbound ids"),
        (broken_chains, "whose via chain cannot run or is too long"),
    ] {
        if count > 0 {
            summary.push(format!(
                "{count} {} {what} {} left out of the subscription's rules and policy groups",
                if count == 1 { "node" } else { "nodes" },
                if count == 1 { "was" } else { "were" },
            ));
        }
    }
    // The line saying why the import produced no routing leads, so the
    // cap on the other lines never cuts it.
    let (invalid, others): (Vec<_>, Vec<_>) = imported
        .diagnostics
        .iter()
        .cloned()
        .partition(|diagnostic| diagnostic.code == ROUTING_IMPORT_INVALID_CODE);
    let diagnostics = routing_warnings(&others);
    let invalid = invalid
        .into_iter()
        .last()
        .map(|diagnostic| diagnostic.message);
    let without = |summary: Vec<String>, reason: Option<String>| {
        let mut warnings = summary;
        warnings.extend(reason);
        warnings.extend(diagnostics.iter().cloned());
        FittedRouting {
            routing: None,
            spec: None,
            rule_sets: Vec::new(),
            routed_node_ids: None,
            warnings,
        }
    };
    let Some(spec) = imported.spec else {
        // The import's own warning says why.
        return without(summary, invalid);
    };
    if spec.rules.len() > MAX_ROUTING_RULES {
        let reason = format!("{} rules, more than {MAX_ROUTING_RULES}", spec.rules.len());
        return without(summary, Some(not_used(reason)));
    }
    if spec.groups.len() > MAX_POLICY_GROUPS {
        let reason = format!(
            "{} policy groups, more than {MAX_POLICY_GROUPS}",
            spec.groups.len()
        );
        return without(summary, Some(not_used(reason)));
    }
    if let Some(group) = spec
        .groups
        .iter()
        .find(|group| group.network_rules.len() > MAX_NETWORK_RULES)
    {
        let reason = format!(
            "policy group {} has {} network rules, more than {MAX_NETWORK_RULES}",
            group.id,
            group.network_rules.len()
        );
        return without(summary, Some(not_used(reason)));
    }
    if routable.is_empty() {
        return without(summary, Some(not_used("no node can run".to_string())));
    }

    let routed_node_ids = if routable.len() <= MAX_ROUTED_OUTBOUNDS {
        routable
            .iter()
            .map(|node| node.id.clone())
            .collect::<Vec<_>>()
    } else {
        let named = named_nodes(&spec, &imported.rule_sets, nodes, &by_id, &usable);
        // Room for the node global mode sends to, with its chain.
        let limit = MAX_ROUTED_OUTBOUNDS - MAX_VIA_CHAIN;
        if named.len() > limit {
            let reason = format!(
                "{} nodes can run and the rules and policy groups name {} of them, more than {limit}",
                routable.len(),
                named.len()
            );
            return without(summary, Some(not_used(reason)));
        }
        named
    };

    let mut routing = routing_json(&spec);
    if !imported.rule_sets.is_empty() {
        routing["rule_sets"] = rule_sets_json(&imported.rule_sets);
    }
    let mut warnings = summary;
    warnings.extend(diagnostics);
    FittedRouting {
        routing: Some(routing),
        spec: Some(spec),
        rule_sets: imported.rule_sets,
        routed_node_ids: Some(routed_node_ids),
        warnings,
    }
}

fn not_used(reason: String) -> String {
    format!("subscription rules and policy groups were not used: {reason}")
}

/// The indexes of node `index` and of the nodes it connects through, when
/// each is `usable` and the chain is at most [`MAX_VIA_CHAIN`] long; `None`
/// otherwise (a node it names is missing or unusable, a cycle, or a chain
/// the engine refuses).
fn via_chain(
    nodes: &[NodeDescriptor],
    by_id: &BTreeMap<&str, usize>,
    usable: &[bool],
    index: usize,
) -> Option<Vec<usize>> {
    let mut chain = vec![index];
    let mut current = index;
    while let Some(via) = metadata(&nodes[current], NODE_METADATA_VIA) {
        let next = *by_id.get(via)?;
        if !usable[next] || chain.len() >= MAX_VIA_CHAIN {
            return None;
        }
        chain.push(next);
        current = next;
    }
    Some(chain)
}

/// The ids of the routable nodes `spec` and `rule_sets` name (group
/// members, defaults and network rule targets, rule targets, rule set
/// download `via`), with the nodes they connect through, in subscription
/// order.
fn named_nodes(
    spec: &RoutingSpec,
    rule_sets: &[ImportedRuleSet],
    nodes: &[NodeDescriptor],
    by_id: &BTreeMap<&str, usize>,
    usable: &[bool],
) -> Vec<String> {
    let targets = spec
        .rules
        .iter()
        .filter_map(|rule| match parse_rule_line(rule) {
            Ok(RuleLine::Rule { target, .. }) | Ok(RuleLine::Final { target, .. }) => Some(target),
            Err(_) => None,
        })
        .collect::<Vec<_>>();
    let mut names: BTreeSet<&str> = BTreeSet::new();
    for group in &spec.groups {
        names.extend(group.members.iter().map(|member| member.trim()));
        names.extend(group.default.iter().map(|default| default.trim()));
        names.extend(group.network_rules.iter().map(|rule| rule.target.trim()));
    }
    names.extend(targets.iter().map(|target| target.trim()));
    names.extend(rule_sets.iter().filter_map(|set| set.via.as_deref()));
    let mut named = BTreeSet::new();
    for name in names {
        let Some(&index) = by_id.get(name) else {
            continue;
        };
        if let Some(chain) = via_chain(nodes, by_id, usable, index) {
            named.extend(chain);
        }
    }
    named
        .into_iter()
        .map(|index| nodes[index].id.clone())
        .collect()
}

/// The entries a subscription parser left out (its warnings), at most
/// [`MAX_SKIPPED_ENTRIES`], and how many there were.
fn skipped_entries(diagnostics: &[control_domain::Diagnostic]) -> (Vec<SkippedEntry>, usize) {
    let mut skipped = diagnostics
        .iter()
        .filter(|diagnostic| diagnostic.severity == control_domain::DiagnosticSeverity::Warning)
        .map(|diagnostic| SkippedEntry {
            code: diagnostic.code.clone(),
            message: diagnostic.message.clone(),
        })
        .collect::<Vec<_>>();
    let count = skipped.len();
    skipped.truncate(MAX_SKIPPED_ENTRIES);
    (skipped, count)
}

/// The warnings of a routing import, at most [`MAX_ROUTING_WARNINGS`].
fn routing_warnings(diagnostics: &[control_domain::Diagnostic]) -> Vec<String> {
    let mut warnings = diagnostics
        .iter()
        .filter(|diagnostic| diagnostic.severity == control_domain::DiagnosticSeverity::Warning)
        .map(|diagnostic| diagnostic.message.clone())
        .collect::<Vec<_>>();
    if warnings.len() > MAX_ROUTING_WARNINGS {
        let more = warnings.len() - MAX_ROUTING_WARNINGS;
        warnings.truncate(MAX_ROUTING_WARNINGS);
        warnings.push(format!("{more} more were left out"));
    }
    warnings
}

/// The engine's `routing.rule_sets` object for imported remote sets, keyed by
/// id; unset fields are left out so the engine defaults apply.
///
/// A list URL ending in `#anixops:pubkey=<base64 Ed25519 key>` asks for
/// signed downloads: the mark becomes the set's `public_key` (the signature
/// is then read from `<url>.sig`) and leaves the URL. Other fragments stay.
pub fn rule_sets_json(rule_sets: &[ImportedRuleSet]) -> Value {
    let mut object = serde_json::Map::new();
    for set in rule_sets {
        let mut entry = serde_json::Map::new();
        let (url, public_key) = split_public_key_mark(&set.url);
        entry.insert("url".to_string(), json!(url));
        if let Some(public_key) = public_key {
            entry.insert("public_key".to_string(), json!(public_key));
        }
        if let Some(format) = set.format {
            entry.insert("format".to_string(), json!(format));
        }
        if let Some(interval_secs) = set.interval_secs {
            entry.insert("interval_secs".to_string(), json!(interval_secs));
        }
        if let Some(via) = &set.via {
            entry.insert("via".to_string(), json!(via));
        }
        object.insert(set.id.clone(), Value::Object(entry));
    }
    Value::Object(object)
}

const PUBLIC_KEY_MARK: &str = "#anixops:pubkey=";

/// Splits `<url>#anixops:pubkey=<key>` into the URL and the key.
fn split_public_key_mark(url: &str) -> (&str, Option<&str>) {
    match url.rfind(PUBLIC_KEY_MARK) {
        Some(index) => {
            let key = url[index + PUBLIC_KEY_MARK.len()..].trim();
            let key = (!key.is_empty()).then_some(key);
            (&url[..index], key)
        }
        None => (url, None),
    }
}

/// Same rule as the engine's routing outbound ids: 1-128 of `[A-Za-z0-9._-]`.
fn is_outbound_id(id: &str) -> bool {
    (1..=128).contains(&id.len())
        && id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

/// Splits `nodes` into runnable entries and unsupported ones.
pub fn report(nodes: &[NodeDescriptor]) -> ImportReport {
    let mut report = ImportReport {
        nodes: Vec::new(),
        unsupported: Vec::new(),
        routing: None,
        routed_node_ids: None,
        routing_warnings: Vec::new(),
        skipped: Vec::new(),
        skipped_count: 0,
    };
    for node in nodes {
        match outbound_json(node) {
            Ok(outbound) => report.nodes.push(ImportedNode {
                id: node.id.clone(),
                legacy_id: config_core::node_id::legacy_node_id(node).map(str::to_string),
                name: node.name.clone(),
                protocol: outbound["type"].as_str().unwrap_or_default().to_string(),
                server: node.endpoint.host.clone(),
                port: node.endpoint.port,
                outbound,
                path: metadata(node, NODE_METADATA_PATH).map(str::to_string),
            }),
            Err(reason) => report.unsupported.push(UnsupportedNode {
                name: node.name.clone(),
                protocol: protocol_name(&node.protocol),
                reason,
            }),
        }
    }
    // A node whose `via` cannot run cannot run either; repeat for chains.
    loop {
        let ids: Vec<String> = report.nodes.iter().map(|node| node.id.clone()).collect();
        let Some(index) = report.nodes.iter().position(|node| {
            node.outbound["via"]
                .as_str()
                .is_some_and(|via| !ids.iter().any(|id| id == via))
        }) else {
            break;
        };
        let node = report.nodes.remove(index);
        report.unsupported.push(UnsupportedNode {
            name: node.name,
            protocol: node.protocol,
            reason: "it connects through a node that cannot run",
        });
    }
    report
}

fn protocol_name(protocol: &Protocol) -> String {
    match protocol {
        Protocol::Http => "http".to_string(),
        Protocol::Socks => "socks".to_string(),
        Protocol::Shadowsocks => "shadowsocks".to_string(),
        Protocol::Vmess => "vmess".to_string(),
        Protocol::Vless => "vless".to_string(),
        Protocol::Trojan => "trojan".to_string(),
        Protocol::Hysteria => "hysteria".to_string(),
        Protocol::Hysteria2 => "hysteria2".to_string(),
        Protocol::Tuic => "tuic".to_string(),
        Protocol::WireGuard => "wireguard".to_string(),
        Protocol::Mieru => "mieru".to_string(),
        Protocol::Snell => "snell".to_string(),
        Protocol::Iwan => "iwan".to_string(),
        Protocol::Anx => "anx".to_string(),
        Protocol::Other(name) => name.to_ascii_lowercase(),
    }
}

fn metadata<'a>(node: &'a NodeDescriptor, key: &str) -> Option<&'a str> {
    node.metadata
        .iter()
        .find(|entry| entry.key == key)
        .map(|entry| entry.value.trim())
        .filter(|value| !value.is_empty())
}

fn shadowsocks(node: &NodeDescriptor) -> Result<Value, Unsupported> {
    let method =
        metadata(node, NODE_METADATA_SHADOWSOCKS_METHOD).ok_or("shadowsocks method is missing")?;
    let password = metadata(node, NODE_METADATA_SHADOWSOCKS_PASSWORD)
        .ok_or("shadowsocks password is missing")?;
    // Without its plugin the server would only see bytes it drops.
    if metadata(node, NODE_METADATA_SHADOWSOCKS_PLUGIN).is_some() {
        return Err("shadowsocks plugins (obfs, websocket, shadow-tls) are not implemented yet");
    }
    if !matches!(
        method,
        "2022-blake3-aes-128-gcm"
            | "2022-blake3-aes-256-gcm"
            | "2022-blake3-chacha20-poly1305"
            | "aes-128-gcm"
            | "aes-256-gcm"
            | "chacha20-ietf-poly1305"
            | "chacha20-poly1305"
    ) {
        return Err("shadowsocks methods other than AEAD and 2022 ones are not implemented yet");
    }
    Ok(json!({
        "type": "shadowsocks",
        "server": node.endpoint.host,
        "port": node.endpoint.port,
        "method": method,
        "password": password,
    }))
}

fn vless(node: &NodeDescriptor) -> Result<Value, Unsupported> {
    let uuid = metadata(node, NODE_METADATA_VLESS_UUID).ok_or("vless uuid is missing")?;
    // Xray's VLESS Encryption (`encryption=mlkem768x25519plus...`) wraps the
    // whole connection; dialing it as plain VLESS only gets random bytes back.
    if metadata(node, NODE_METADATA_VLESS_ENCRYPTION).is_some_and(|value| value != "none") {
        return Err("vless encryption (VLESS Encryption) is not implemented yet");
    }
    let flow = metadata(node, NODE_METADATA_VLESS_FLOW).unwrap_or_default();
    let transport = v2ray_transport(node)?;
    if let Some(public_key) = metadata(node, NODE_METADATA_TLS_REALITY_PUBLIC_KEY) {
        let xhttp = transport["type"] == "xhttp";
        if !transport.is_null() && !xhttp {
            return Err(
                "vless REALITY over transports other than tcp and xhttp is not implemented yet",
            );
        }
        if xhttp && !flow.is_empty() && flow != "none" {
            return Err("vless flows over xhttp are not supported");
        }
        let server_name = metadata(node, NODE_METADATA_TLS_SERVER_NAME)
            .ok_or("vless REALITY server name is missing")?;
        // uTLS names that tls-mimic has a captured fingerprint for keep it
        // (Safari and iOS share Apple's network stack), a link that names
        // nothing gets the platform's own (`auto`), every other uTLS name
        // (android, 360, qq, random...) falls back to Chrome.
        let fingerprint = match metadata(node, NODE_METADATA_TLS_UTLS_FINGERPRINT)
            .map(|name| name.to_ascii_lowercase())
            .as_deref()
        {
            None | Some("" | "auto") => "auto",
            Some("safari" | "ios") => "safari",
            Some("firefox") => "firefox",
            Some("edge") => "edge",
            Some(_) => "chrome",
        };
        let mut outbound = json!({
            "type": "vless",
            "server": node.endpoint.host,
            "port": node.endpoint.port,
            "uuid": uuid,
            "flow": if xhttp { "" } else { flow },
            "reality": {
                "server_name": server_name,
                "public_key": public_key,
                "short_id": metadata(node, NODE_METADATA_TLS_REALITY_SHORT_ID).unwrap_or_default(),
                "fingerprint": fingerprint,
            },
        });
        if xhttp {
            outbound["transport"] = transport;
        }
        return Ok(outbound);
    }
    if !flow.is_empty() && flow != "none" {
        return Err("vless flows without REALITY are not implemented yet");
    }
    Ok(json!({
        "type": "vless",
        "server": node.endpoint.host,
        "port": node.endpoint.port,
        "uuid": uuid,
        "tls": standard_tls(node)?,
        "transport": transport,
    }))
}

fn vmess(node: &NodeDescriptor) -> Result<Value, Unsupported> {
    let uuid = metadata(node, NODE_METADATA_VMESS_UUID).ok_or("vmess uuid is missing")?;
    let security = metadata(node, NODE_METADATA_VMESS_SECURITY).unwrap_or("auto");
    if !matches!(
        security,
        "auto" | "aes-128-gcm" | "chacha20-poly1305" | "chacha20-ietf-poly1305"
    ) {
        return Err("vmess security other than auto, aes-128-gcm and chacha20-poly1305 is not implemented yet");
    }
    if !matches!(
        metadata(node, NODE_METADATA_VMESS_ALTER_ID),
        None | Some("0")
    ) {
        return Err("vmess alterId other than 0 (legacy headers) is not supported");
    }
    if metadata(node, NODE_METADATA_TLS_REALITY_PUBLIC_KEY).is_some() {
        return Err("vmess over REALITY is not supported");
    }
    let transport = v2ray_transport(node)?;
    Ok(json!({
        "type": "vmess",
        "server": node.endpoint.host,
        "port": node.endpoint.port,
        "uuid": uuid,
        "security": security,
        "tls": standard_tls(node)?,
        "transport": transport,
    }))
}

/// Hysteria2 always runs TLS 1.3 over QUIC. Port hopping ranges are ignored:
/// the outbound connects to the node's main port, which hopping servers also
/// listen on.
fn hysteria2(node: &NodeDescriptor) -> Result<Value, Unsupported> {
    let password =
        metadata(node, NODE_METADATA_HYSTERIA2_PASSWORD).ok_or("hysteria2 password is missing")?;
    let obfs = match metadata(node, NODE_METADATA_HYSTERIA2_OBFS_TYPE) {
        None => Value::Null,
        Some("salamander") => json!({
            "type": "salamander",
            "password": metadata(node, NODE_METADATA_HYSTERIA2_OBFS_PASSWORD)
                .ok_or("hysteria2 obfs password is missing")?,
        }),
        Some(_) => return Err("hysteria2 obfs other than salamander is not implemented yet"),
    };
    let pins = certificate_pins(node)?;
    let mut outbound = json!({
        "type": "hysteria2",
        "server": node.endpoint.host,
        "port": node.endpoint.port,
        "password": password,
        "server_name": metadata(node, NODE_METADATA_TLS_SERVER_NAME),
        "alpn": alpn_list(node),
        "insecure": metadata(node, NODE_METADATA_TLS_INSECURE) == Some("true"),
        "obfs": obfs,
    });
    pins.insert_into(&mut outbound);
    Ok(outbound)
}

/// TUIC v5 over QUIC (TLS 1.3 always on). The UDP relay mode does not matter
/// for TCP.
fn tuic(node: &NodeDescriptor) -> Result<Value, Unsupported> {
    let uuid = metadata(node, NODE_METADATA_TUIC_UUID).ok_or("tuic uuid is missing")?;
    let password = metadata(node, NODE_METADATA_TUIC_PASSWORD)
        .filter(|password| !password.is_empty())
        .ok_or("tuic password is missing (tuic v4 tokens are not supported)")?;
    let pins = certificate_pins(node)?;
    let mut outbound = json!({
        "type": "tuic",
        "server": node.endpoint.host,
        "port": node.endpoint.port,
        "uuid": uuid,
        "password": password,
        "server_name": metadata(node, NODE_METADATA_TLS_SERVER_NAME),
        "alpn": alpn_list(node),
        "insecure": metadata(node, NODE_METADATA_TLS_INSECURE) == Some("true"),
        "congestion_control": metadata(node, NODE_METADATA_TUIC_CONGESTION_CONTROL),
    });
    pins.insert_into(&mut outbound);
    Ok(outbound)
}

/// Snell v1–v4 and v6 (v5 runs as v4). A missing version means 1, as in
/// Surge and Clash.
fn snell(node: &NodeDescriptor) -> Result<Value, Unsupported> {
    let psk = metadata(node, NODE_METADATA_SNELL_PSK).ok_or("snell psk is missing")?;
    let version = match metadata(node, NODE_METADATA_SNELL_VERSION) {
        None => 1,
        Some(raw) => raw
            .parse::<u8>()
            .ok()
            .filter(|version| (1..=6).contains(version))
            .ok_or("snell version must be between 1 and 6")?,
    };
    let mode = metadata(node, NODE_METADATA_SNELL_MODE).unwrap_or("default");
    if !matches!(mode, "default" | "unshaped" | "unsafe-raw") {
        return Err("snell mode must be default, unshaped or unsafe-raw");
    }
    let obfs = match metadata(node, NODE_METADATA_SNELL_OBFS) {
        None | Some("none") | Some("off") => None,
        Some("http") if version <= 4 => Some("http"),
        Some("http") => return Err("snell obfs needs version 4 or earlier"),
        Some("tls") => return Err("snell tls obfs is not implemented yet"),
        Some(_) => return Err("snell obfs must be http"),
    };
    Ok(json!({
        "type": "snell",
        "server": node.endpoint.host,
        "port": node.endpoint.port,
        "psk": psk,
        "version": version,
        "mode": mode,
        "obfs": obfs,
        "obfs_host": obfs.and(metadata(node, NODE_METADATA_SNELL_OBFS_HOST)),
        "obfs_uri": obfs.and(metadata(node, NODE_METADATA_SNELL_OBFS_URI)),
        "reuse": metadata(node, NODE_METADATA_SNELL_REUSE) == Some("true"),
        "userkey": metadata(node, NODE_METADATA_SNELL_USER_KEY),
    }))
}

fn mieru(node: &NodeDescriptor) -> Result<Value, Unsupported> {
    let username =
        metadata(node, NODE_METADATA_MIERU_USERNAME).ok_or("mieru username is missing")?;
    let password =
        metadata(node, NODE_METADATA_MIERU_PASSWORD).ok_or("mieru password is missing")?;
    match metadata(node, NODE_METADATA_MIERU_TRANSPORT) {
        None => {}
        Some(transport) if transport.eq_ignore_ascii_case("tcp") => {}
        Some(transport) if transport.eq_ignore_ascii_case("udp") => {
            return Err("mieru udp transport is not implemented yet")
        }
        Some(_) => return Err("mieru transport must be TCP"),
    }
    // Multiplexing, handshake mode and traffic pattern only shape the
    // official client; the server accepts this client without them.
    Ok(json!({
        "type": "mieru",
        "server": node.endpoint.host,
        "port": node.endpoint.port,
        "username": username,
        "password": password,
        "port_range": metadata(node, NODE_METADATA_MIERU_PORT_RANGE),
        "transport": "TCP",
    }))
}

/// iWAN has no confidentiality (docs/protocols/iwan.md §9); a subscription
/// uses it as the line other nodes connect through.
fn iwan(node: &NodeDescriptor) -> Result<Value, Unsupported> {
    let username = metadata(node, NODE_METADATA_IWAN_USERNAME).ok_or("iwan username is missing")?;
    let password = metadata(node, NODE_METADATA_IWAN_PASSWORD).ok_or("iwan password is missing")?;
    let mut outbound = json!({
        "type": "iwan",
        "server": node.endpoint.host,
        "port": node.endpoint.port,
        "username": username,
        "password": password,
    });
    if let Some(mtu) = metadata(node, NODE_METADATA_IWAN_MTU) {
        let mtu: u16 = mtu.parse().map_err(|_| "iwan mtu is not a number")?;
        outbound["mtu"] = json!(mtu);
    }
    if let Some(encrypt) = metadata(node, NODE_METADATA_IWAN_ENCRYPT) {
        outbound["encrypt"] = json!(encrypt == "true");
    }
    Ok(outbound)
}

/// WireGuard as a routable node (`outbound-wireguard`). A routed config may
/// put it behind rules; a single node can also run as the whole-device tunnel.
fn wireguard(node: &NodeDescriptor) -> Result<Value, Unsupported> {
    let private_key = metadata(node, NODE_METADATA_WIREGUARD_PRIVATE_KEY)
        .ok_or("wireguard private key is missing")?;
    let peer_public_key = metadata(node, NODE_METADATA_WIREGUARD_PEER_PUBLIC_KEY)
        .ok_or("wireguard peer public key is missing")?;
    let local_address = metadata(node, NODE_METADATA_WIREGUARD_LOCAL_ADDRESS)
        .ok_or("wireguard local address is missing")?;
    let split = |list: &str| -> Vec<String> {
        list.split(',')
            .map(str::trim)
            .filter(|entry| !entry.is_empty())
            .map(str::to_owned)
            .collect()
    };
    let mut outbound = json!({
        "type": "wireguard",
        "server": node.endpoint.host,
        "port": node.endpoint.port,
        "private_key": private_key,
        "peer_public_key": peer_public_key,
        "local_address": split(local_address),
    });
    if let Some(preshared_key) = metadata(node, NODE_METADATA_WIREGUARD_PRE_SHARED_KEY) {
        outbound["preshared_key"] = json!(preshared_key);
    }
    if let Some(allowed_ips) = metadata(node, NODE_METADATA_WIREGUARD_ALLOWED_IPS) {
        outbound["allowed_ips"] = json!(split(allowed_ips));
    }
    if let Some(mtu) = metadata(node, NODE_METADATA_WIREGUARD_MTU) {
        let mtu: u16 = mtu.parse().map_err(|_| "wireguard mtu is not a number")?;
        outbound["mtu"] = json!(mtu);
    }
    if let Some(reserved) = metadata(node, NODE_METADATA_WIREGUARD_RESERVED) {
        let bytes = reserved
            .split(',')
            .map(|byte| byte.trim().parse::<u8>())
            .collect::<Result<Vec<u8>, _>>()
            .map_err(|_| "wireguard reserved is not three bytes")?;
        if bytes.len() != 3 {
            return Err("wireguard reserved is not three bytes");
        }
        outbound["reserved"] = json!(bytes);
    }
    Ok(outbound)
}

/// This device's ANX license for one subscription origin (anx spec §2.4.1):
/// the device key and where the license the panel signed for it is kept. The
/// client keeps one device key per origin, so two panels never see the same
/// key, and sets them with [`set_anx_licenses`]; an ANX outbound built
/// afterwards carries the license of its node's origin
/// (`anx.license_origin`), and reads the license file each time it connects,
/// so a refreshed license needs no new import. A node without a license for
/// its origin is as before: a node that does not require licenses never asks
/// for one.
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize)]
pub struct AnxLicense {
    /// The device's private key, PKCS#8 DER in hex.
    pub device_key: String,
    /// `ed25519` or `p256`.
    pub device_alg: String,
    /// The license file: the certificate in hex, as the subscription's
    /// `X-AnixOps-Anx-License` header carried it.
    pub license_cert_path: String,
}

static ANX_LICENSE: std::sync::RwLock<Option<AnxLicense>> = std::sync::RwLock::new(None);

type LicensesByOrigin = std::collections::BTreeMap<String, AnxLicense>;

static ANX_LICENSES: std::sync::RwLock<LicensesByOrigin> =
    std::sync::RwLock::new(std::collections::BTreeMap::new());

/// Sets (or with `None` clears) the license of the ANX outbounds whose node
/// names no origin (`anx.license_origin`). Older clients used it for every
/// node, which gave every panel the same device key; clients now use
/// [`set_anx_licenses`].
pub fn set_anx_license(license: Option<AnxLicense>) {
    if let Ok(mut current) = ANX_LICENSE.write() {
        *current = license;
    }
}

/// Replaces the licenses by subscription origin (`scheme://host:port`,
/// lowercased, as the client writes `anx.license_origin`). A node whose
/// origin has none here gets no license, never another origin's.
pub fn set_anx_licenses(licenses: LicensesByOrigin) {
    if let Ok(mut current) = ANX_LICENSES.write() {
        *current = licenses;
    }
}

/// The license `node`'s outbound carries: its origin's, or without an origin
/// the one [`set_anx_license`] set.
fn anx_license(node: &NodeDescriptor) -> Option<AnxLicense> {
    match metadata(node, NODE_METADATA_ANX_LICENSE_ORIGIN) {
        Some(origin) => ANX_LICENSES
            .read()
            .ok()
            .and_then(|licenses| licenses.get(origin).cloned()),
        None => ANX_LICENSE.read().ok().and_then(|current| current.clone()),
    }
}

/// ANX-A under the A2 jacket. The public engine does not compile the
/// protocol in; a client build that does reads this entry (`type = "anx"`:
/// `server_name`, `public_key`, `user_key`, optional `alpn`, `fingerprint`).
fn anx(node: &NodeDescriptor) -> Result<Value, Unsupported> {
    let user_key = metadata(node, NODE_METADATA_ANX_USER_KEY).ok_or("anx user key is missing")?;
    let public_key =
        metadata(node, NODE_METADATA_ANX_PUBLIC_KEY).ok_or("anx server public key is missing")?;
    let mut outbound = json!({
        "type": "anx",
        "server": node.endpoint.host,
        "port": node.endpoint.port,
        "public_key": public_key,
        "user_key": user_key,
    });
    // No server name means no SNI in the ClientHello.
    if let Some(server_name) = metadata(node, NODE_METADATA_ANX_SERVER_NAME) {
        outbound["server_name"] = json!(server_name);
    }
    if let Some(alpn) = metadata(node, NODE_METADATA_ANX_ALPN) {
        let alpn: Vec<&str> = alpn
            .split(',')
            .map(str::trim)
            .filter(|entry| !entry.is_empty())
            .collect();
        outbound["alpn"] = json!(alpn);
    }
    if let Some(fingerprint) = metadata(node, NODE_METADATA_ANX_FINGERPRINT) {
        outbound["fingerprint"] = json!(fingerprint);
    }
    if let Some(jacket) = metadata(node, NODE_METADATA_ANX_JACKET) {
        outbound["jacket"] = json!(jacket);
    }
    if let Some(port) =
        metadata(node, NODE_METADATA_ANX_WG_PORT).and_then(|p| p.parse::<u16>().ok())
    {
        outbound["wg_port"] = json!(port);
    }
    if let Some(port) =
        metadata(node, NODE_METADATA_ANX_BARE_PORT).and_then(|p| p.parse::<u16>().ok())
    {
        outbound["bare_port"] = json!(port);
    }
    if let Some(license) = anx_license(node) {
        outbound["device_key"] = json!(license.device_key);
        outbound["device_alg"] = json!(license.device_alg);
        outbound["license_cert_path"] = json!(license.license_cert_path);
    }
    Ok(outbound)
}

/// The standard TLS entry when the node enables TLS, otherwise `null`. A node
/// with certificate pins but without TLS is unsupported: there would be no
/// certificate to check them against.
fn standard_tls(node: &NodeDescriptor) -> Result<Value, Unsupported> {
    let pins = certificate_pins(node)?;
    if metadata(node, NODE_METADATA_TLS_ENABLED) != Some("true") {
        if !pins.is_empty() {
            return Err("certificate pins are set on a node without tls");
        }
        return Ok(Value::Null);
    }
    let mut tls = json!({
        "server_name": metadata(node, NODE_METADATA_TLS_SERVER_NAME),
        "alpn": alpn_list(node),
        "insecure": metadata(node, NODE_METADATA_TLS_INSECURE) == Some("true"),
    });
    pins.insert_into(&mut tls);
    Ok(tls)
}

/// A node's certificate pins as the engine's `pinned_certificate_sha256`
/// and `pinned_public_key_sha256` lists of lowercase hex digests.
#[derive(Default)]
struct CertificatePins {
    certificate: Vec<String>,
    public_key: Vec<String>,
}

impl CertificatePins {
    fn is_empty(&self) -> bool {
        self.certificate.is_empty() && self.public_key.is_empty()
    }

    /// Adds the lists to `tls`, an outbound or its `tls` entry; a node
    /// without pins gets the same entry as before pins existed.
    fn insert_into(self, tls: &mut Value) {
        if !self.certificate.is_empty() {
            tls["pinned_certificate_sha256"] = json!(self.certificate);
        }
        if !self.public_key.is_empty() {
            tls["pinned_public_key_sha256"] = json!(self.public_key);
        }
    }
}

/// The pins of `node`. A value that is not a SHA-256 digest makes the node
/// unsupported: running it without that pin would trust whichever server
/// answers, which is what the pin is there to prevent.
fn certificate_pins(node: &NodeDescriptor) -> Result<CertificatePins, Unsupported> {
    let mut pins = CertificatePins::default();
    for pin in metadata_list(node, NODE_METADATA_TLS_CERTIFICATE_SHA256) {
        let digest =
            certificate_pin::parse(pin).ok_or("tls certificate pin is not a sha-256 digest")?;
        push_unique(&mut pins.certificate, certificate_pin::to_hex(&digest));
    }
    for pin in metadata_list(node, NODE_METADATA_TLS_CERTIFICATE_PUBLIC_KEY_SHA256) {
        // Imports before `tls.certificate_sha256` existed kept Hysteria2
        // `pinSHA256` and Xray `pcs` certificate digests here, in hex. Public
        // key digests are kept in base64.
        if let Some(digest) = certificate_pin::parse_hex(pin) {
            push_unique(&mut pins.certificate, certificate_pin::to_hex(&digest));
        } else {
            let digest = certificate_pin::parse_base64(pin)
                .ok_or("tls public key pin is not a sha-256 digest")?;
            push_unique(&mut pins.public_key, certificate_pin::to_hex(&digest));
        }
    }
    Ok(pins)
}

/// The non-empty values of a comma-separated metadata entry.
fn metadata_list<'a>(node: &'a NodeDescriptor, key: &str) -> impl Iterator<Item = &'a str> {
    metadata(node, key)
        .into_iter()
        .flat_map(|list| list.split(','))
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

fn push_unique(list: &mut Vec<String>, value: String) {
    if !list.contains(&value) {
        list.push(value);
    }
}

/// `null` for tcp, the `ws` or `grpc` transport entry, or unsupported.
fn v2ray_transport(node: &NodeDescriptor) -> Result<Value, Unsupported> {
    match metadata(node, NODE_METADATA_V2RAY_TRANSPORT_TYPE) {
        None | Some("tcp") => Ok(Value::Null),
        Some("ws") => Ok(json!({
            "type": "ws",
            "path": metadata(node, NODE_METADATA_V2RAY_TRANSPORT_PATH).unwrap_or_default(),
            "host": metadata(node, NODE_METADATA_V2RAY_TRANSPORT_HOST).unwrap_or_default(),
        })),
        Some("grpc") => Ok(json!({
            "type": "grpc",
            "service_name": metadata(node, NODE_METADATA_V2RAY_TRANSPORT_SERVICE_NAME)
                .ok_or("grpc service name is missing")?,
        })),
        Some("xhttp") => xhttp_transport(node),
        Some(_) => Err("transports other than tcp, ws, grpc and xhttp are not implemented yet"),
    }
}

/// The `xhttp` transport entry. Of the share link's `extra` settings, the
/// client-side ones the transport implements are kept, connection reuse
/// (`xmux`) and server-only ones are dropped, and anything that changes the
/// wire format makes the node unsupported.
fn xhttp_transport(node: &NodeDescriptor) -> Result<Value, Unsupported> {
    let mut transport = json!({
        "type": "xhttp",
        "path": metadata(node, NODE_METADATA_V2RAY_TRANSPORT_PATH).unwrap_or("/"),
        "host": metadata(node, NODE_METADATA_V2RAY_TRANSPORT_HOST).unwrap_or_default(),
        "mode": metadata(node, NODE_METADATA_V2RAY_TRANSPORT_MODE).unwrap_or("auto"),
    });
    if !matches!(
        transport["mode"].as_str(),
        Some("auto" | "packet-up" | "stream-up" | "stream-one")
    ) {
        return Err("xhttp mode must be auto, packet-up, stream-up or stream-one");
    }
    let Some(extra) = metadata(node, NODE_METADATA_V2RAY_TRANSPORT_EXTRA) else {
        return Ok(transport);
    };
    let Ok(Value::Object(extra)) = serde_json::from_str::<Value>(extra) else {
        return Err("xhttp extra is not a JSON object");
    };
    for (key, value) in extra {
        let field = match key.as_str() {
            "headers" => "headers",
            "xPaddingBytes" => "x_padding_bytes",
            "scMaxEachPostBytes" => "sc_max_each_post_bytes",
            "scMinPostsIntervalMs" => "sc_min_posts_interval_ms",
            "noGRPCHeader" => "no_grpc_header",
            "xmux" | "noSSEHeader" | "scMaxBufferedPosts" | "scStreamUpServerSecs" => continue,
            "downloadSettings" => {
                return Err("xhttp downloadSettings (split download server) is not implemented yet")
            }
            _ => return Err("xhttp extra options other than headers, padding and post sizing are not implemented yet"),
        };
        transport[field] = value;
    }
    Ok(transport)
}

fn alpn_list(node: &NodeDescriptor) -> Vec<&str> {
    metadata(node, NODE_METADATA_TLS_ALPN)
        .map(|list| {
            list.split(',')
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .collect()
        })
        .unwrap_or_default()
}

/// An HTTP proxy (`outbound-http`), over TLS when the node enables it (an
/// HTTPS proxy). The credentials are checked here as the outbound checks
/// them, so a node it would refuse is reported instead of failing the
/// whole routed config.
fn http(node: &NodeDescriptor) -> Result<Value, Unsupported> {
    let username = metadata(node, NODE_METADATA_PROXY_USERNAME);
    let password = metadata(node, NODE_METADATA_PROXY_PASSWORD);
    match (username, password) {
        (None, Some(_)) => return Err("http proxy password is set without a username"),
        (Some(username), _) if username.contains(':') => {
            return Err("http proxy username cannot contain ':'")
        }
        _ => {}
    }
    if metadata(node, NODE_METADATA_TLS_REALITY_PUBLIC_KEY).is_some() {
        return Err("http proxy over REALITY is not supported");
    }
    let tls = metadata(node, NODE_METADATA_TLS_ENABLED) == Some("true");
    let pins = certificate_pins(node)?;
    if !tls && !pins.is_empty() {
        return Err("certificate pins are set on a node without tls");
    }
    // `tls` is a flag here, not the TLS object other outbounds take.
    let mut outbound = json!({
        "type": "http",
        "server": node.endpoint.host,
        "port": node.endpoint.port,
        "tls": tls,
    });
    if let Some(username) = username {
        outbound["username"] = json!(username);
    }
    if let Some(password) = password {
        outbound["password"] = json!(password);
    }
    if tls {
        if let Some(server_name) = metadata(node, NODE_METADATA_TLS_SERVER_NAME) {
            outbound["server_name"] = json!(server_name);
        }
        outbound["insecure"] = json!(metadata(node, NODE_METADATA_TLS_INSECURE) == Some("true"));
        pins.insert_into(&mut outbound);
    }
    Ok(outbound)
}

/// A SOCKS5 proxy (`outbound-socks`). The outbound has no TLS, so a node
/// that asks for it is reported rather than run in the clear.
fn socks(node: &NodeDescriptor) -> Result<Value, Unsupported> {
    if metadata(node, NODE_METADATA_TLS_ENABLED) == Some("true")
        || metadata(node, NODE_METADATA_TLS_REALITY_PUBLIC_KEY).is_some()
    {
        return Err("socks over tls is not supported");
    }
    if !certificate_pins(node)?.is_empty() {
        return Err("certificate pins are set on a node without tls");
    }
    let mut outbound = json!({
        "type": "socks",
        "server": node.endpoint.host,
        "port": node.endpoint.port,
    });
    match (
        metadata(node, NODE_METADATA_PROXY_USERNAME),
        metadata(node, NODE_METADATA_PROXY_PASSWORD),
    ) {
        (None, None) => {}
        (Some(username), Some(password)) => {
            // RFC 1929 carries each in one length byte.
            let fits = |value: &str| (1..=255).contains(&value.len());
            if !fits(username) || !fits(password) {
                return Err("socks username and password must be 1 to 255 bytes");
            }
            outbound["username"] = json!(username);
            outbound["password"] = json!(password);
        }
        _ => return Err("socks username and password must be set together"),
    }
    Ok(outbound)
}

fn trojan(node: &NodeDescriptor) -> Result<Value, Unsupported> {
    let password =
        metadata(node, NODE_METADATA_TROJAN_PASSWORD).ok_or("trojan password is missing")?;
    let transport = v2ray_transport(node)?;
    if metadata(node, NODE_METADATA_TLS_ENABLED) == Some("false") {
        return Err("trojan without tls is not supported");
    }
    // Running it as plain TLS would only reach the REALITY server's cover
    // site.
    if metadata(node, NODE_METADATA_TLS_REALITY_PUBLIC_KEY).is_some() {
        return Err("trojan over REALITY is not implemented yet");
    }
    let pins = certificate_pins(node)?;
    let mut outbound = json!({
        "type": "trojan",
        "server": node.endpoint.host,
        "port": node.endpoint.port,
        "password": password,
        "server_name": metadata(node, NODE_METADATA_TLS_SERVER_NAME),
        "alpn": alpn_list(node),
        "insecure": metadata(node, NODE_METADATA_TLS_INSECURE) == Some("true"),
        "transport": transport,
    });
    pins.insert_into(&mut outbound);
    Ok(outbound)
}
