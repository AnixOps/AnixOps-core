//! Converts normalized subscription nodes (`control_domain::NodeDescriptor`)
//! into this engine's config envelope. The per-node outbound entries come
//! from the `node-import` crate.
//!
//! Desktop clients parse subscriptions with `config-core` and hand the nodes
//! here instead of rendering a config for an external engine. A node whose
//! protocol or options this build cannot carry is reported as unsupported, so
//! the caller can say which node and why without exposing its credentials.

use std::collections::BTreeMap;

use config_core::routing::RoutingSpec;
use config_core::routing_import::ImportedRuleSet;
use control_domain::NodeDescriptor;
use serde_json::{json, Value};

use crate::config::{RuntimeConfig, CONFIG_SCHEMA_VERSION};
use crate::protocols;

pub use node_import::Unsupported;

/// The outbound entry (`{"type": ..., ...}`) for one node, if this build
/// compiles its protocol in.
pub fn outbound_for_node(node: &NodeDescriptor) -> Result<Value, Unsupported> {
    let outbound = node_import::outbound_json(node)?;
    let kind = outbound["type"].as_str().unwrap_or_default();
    if !protocols::default_registry().contains(kind) {
        return Err("protocol is not compiled into this build");
    }
    Ok(outbound)
}

/// Envelope with one outbound for the selected node, and that node.
///
/// The selection is looked up by node id, or else by the id the node had
/// before stable node ids ([`config_core::node_id::find_node`]); callers
/// should save the returned node's id. The previous id is only reliable for
/// the subscription content it was assigned from, so after a subscription
/// refresh a caller migrating saved selections should first check whether
/// the saved id is a current id of the refreshed nodes, and treat a match
/// found only through a previous id as a best-effort guess.
///
/// Without a selection it uses the first node this build can run, so one
/// unsupported node at the top of a subscription does not stop the rest
/// from running; if none can run, the first node's reason is returned.
pub fn single_node_envelope(
    profile_id: &str,
    nodes: &[NodeDescriptor],
    selected_node_id: Option<&str>,
) -> Result<(String, NodeDescriptor), Unsupported> {
    let (node, outbound) = match selected_node_id {
        Some(id) => {
            // A selection saved before stable node ids still finds its node
            // by the previous id; the returned node carries the current id.
            let node = config_core::node_id::find_node(nodes, id)
                .ok_or("the selected node is not in the subscription")?;
            (node, outbound_for_node(node)?)
        }
        None => first_runnable_node(nodes)?,
    };
    let envelope = json!({
        "schema_version": CONFIG_SCHEMA_VERSION,
        "profile_id": profile_id,
        "outbound": outbound,
    });
    Ok((envelope.to_string(), node.clone()))
}

/// The first node with an outbound this build can run, and that outbound. If
/// no node can run, the first node's reason.
fn first_runnable_node(nodes: &[NodeDescriptor]) -> Result<(&NodeDescriptor, Value), Unsupported> {
    let mut first_reason = None;
    for node in nodes {
        match outbound_for_node(node) {
            Ok(outbound) => return Ok((node, outbound)),
            Err(reason) => {
                first_reason.get_or_insert(reason);
            }
        }
    }
    Err(first_reason.unwrap_or("the subscription has no nodes"))
}

/// Envelope with every node as a routed outbound plus `routing`'s rules and
/// policy groups. Fails if any node is unsupported, since rules and groups may
/// refer to it; [`subscription_routing_envelope`] instead leaves such nodes
/// out of the rules and groups. Rules naming the subscription's own rule
/// sets need [`routing_envelope_with_sets`]: without the sets the engine
/// refuses them.
pub fn routing_envelope(
    profile_id: &str,
    nodes: &[NodeDescriptor],
    routing: &RoutingSpec,
) -> Result<String, Unsupported> {
    routing_envelope_with_sets(profile_id, nodes, routing, &[])
}

/// [`routing_envelope`] with the remote rule sets the subscription's rules
/// name (`ImportedRouting::rule_sets`) as `routing.rule_sets`, as
/// `node-import` writes them; the engine downloads them itself.
pub fn routing_envelope_with_sets(
    profile_id: &str,
    nodes: &[NodeDescriptor],
    routing: &RoutingSpec,
    rule_sets: &[ImportedRuleSet],
) -> Result<String, Unsupported> {
    let mut outbounds = BTreeMap::new();
    for node in nodes {
        outbounds.insert(node.id.clone(), outbound_for_node(node)?);
    }
    Ok(envelope_json(profile_id, outbounds, routing, rule_sets))
}

/// A subscription's routed envelope and what its rules left out; see
/// [`subscription_routing_envelope`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubscriptionRouting {
    /// The envelope, as [`routing_envelope_with_sets`] writes it, checked
    /// against the engine's own validation; `None` when the subscription
    /// has no rules or they cannot run, and `warnings` then says why.
    pub envelope: Option<String>,
    /// As `node_import::ImportReport::routing_warnings`, with a line first
    /// when the engine refused the result.
    pub warnings: Vec<String>,
}

/// The routed envelope for subscription `content` and its rules and policy
/// groups, keeping to the nodes this build can run
/// ([`node_import::fit_subscription_routing`]): a node that cannot run is
/// left out of the groups and rules that name it, with a warning, instead
/// of costing the subscription all of its rules.
///
/// `parsed` are the subscription's nodes as served, which its rules and
/// groups name; `nodes` are the ones to run (with the user's edits),
/// matched by id. When more than [`node_import::MAX_ROUTED_OUTBOUNDS`]
/// nodes can run, the envelope carries the nodes the rules and groups name
/// and the node `selected_node_id` names (where global mode goes), each
/// with the nodes it connects through.
pub fn subscription_routing_envelope(
    profile_id: &str,
    content: &str,
    parsed: &[NodeDescriptor],
    nodes: &[NodeDescriptor],
    selected_node_id: Option<&str>,
) -> SubscriptionRouting {
    let mut edited: BTreeMap<&str, &NodeDescriptor> = BTreeMap::new();
    for node in nodes {
        edited.entry(node.id.as_str()).or_insert(node);
    }
    let runnable = |node: &NodeDescriptor| {
        edited
            .get(node.id.as_str())
            .is_some_and(|node| outbound_for_node(node).is_ok())
    };
    let fitted = node_import::fit_subscription_routing(content, parsed, &runnable);
    let mut warnings = fitted.warnings;
    let (Some(spec), Some(mut ids)) = (fitted.spec, fitted.routed_node_ids) else {
        return SubscriptionRouting {
            envelope: None,
            warnings,
        };
    };
    if let Some(selected) =
        selected_node_id.and_then(|id| config_core::node_id::find_node(nodes, id))
    {
        let chain = selected_chain(selected, &edited);
        let missing = chain
            .iter()
            .filter(|id| !ids.contains(id))
            .cloned()
            .collect::<Vec<_>>();
        if ids.len() + missing.len() <= node_import::MAX_ROUTED_OUTBOUNDS {
            ids.extend(missing);
        }
    }
    let mut outbounds = BTreeMap::new();
    for id in &ids {
        let outbound = edited
            .get(id.as_str())
            .ok_or("the node is not in the subscription")
            .and_then(|node| outbound_for_node(node));
        match outbound {
            Ok(outbound) => {
                outbounds.insert(id.clone(), outbound);
            }
            Err(reason) => {
                warnings.insert(
                    0,
                    format!("subscription rules and policy groups were not used: {reason}"),
                );
                return SubscriptionRouting {
                    envelope: None,
                    warnings,
                };
            }
        }
    }
    let envelope = envelope_json(profile_id, outbounds, &spec, &fitted.rule_sets);
    if let Err(error) = RuntimeConfig::from_json(envelope.as_bytes()) {
        warnings.insert(
            0,
            format!(
                "subscription rules and policy groups were not used: {}",
                error.message
            ),
        );
        return SubscriptionRouting {
            envelope: None,
            warnings,
        };
    }
    SubscriptionRouting {
        envelope: Some(envelope),
        warnings,
    }
}

/// The ids of `node` and of the nodes it connects through that can run,
/// at most `node_import::MAX_VIA_CHAIN`; empty when any of them cannot run.
fn selected_chain(node: &NodeDescriptor, nodes: &BTreeMap<&str, &NodeDescriptor>) -> Vec<String> {
    let mut chain = Vec::new();
    let mut current = Some(node);
    while let Some(node) = current {
        if chain.len() >= node_import::MAX_VIA_CHAIN {
            return Vec::new();
        }
        let Ok(outbound) = outbound_for_node(node) else {
            return Vec::new();
        };
        chain.push(node.id.clone());
        current = match outbound["via"].as_str() {
            Some(via) => match nodes.get(via) {
                Some(next) => Some(*next),
                None => return Vec::new(),
            },
            None => None,
        };
    }
    chain
}

/// The routed envelope with `outbounds` and the rules, groups and rule sets.
fn envelope_json(
    profile_id: &str,
    outbounds: BTreeMap<String, Value>,
    routing: &RoutingSpec,
    rule_sets: &[ImportedRuleSet],
) -> String {
    let section = node_import::routing_json(routing);
    let mut envelope = json!({
        "schema_version": CONFIG_SCHEMA_VERSION,
        "profile_id": profile_id,
        "routing": {
            "outbounds": outbounds,
            "rules": section["rules"],
            "groups": section["groups"],
        },
    });
    if !rule_sets.is_empty() {
        envelope["routing"]["rule_sets"] = node_import::rule_sets_json(rule_sets);
    }
    envelope.to_string()
}
