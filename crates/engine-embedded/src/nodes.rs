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

use crate::config::CONFIG_SCHEMA_VERSION;
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

/// Envelope with one outbound for the selected node, and that node. Without a
/// selection it uses the first node this build can run, so one unsupported
/// node at the top of a subscription does not stop the rest from running; if
/// none can run, the first node's reason is returned.
pub fn single_node_envelope(
    profile_id: &str,
    nodes: &[NodeDescriptor],
    selected_node_id: Option<&str>,
) -> Result<(String, NodeDescriptor), Unsupported> {
    let (node, outbound) = match selected_node_id {
        Some(id) => {
            let node = nodes
                .iter()
                .find(|node| node.id == id)
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
/// refer to it. Rules naming the subscription's own rule sets need
/// [`routing_envelope_with_sets`]: without the sets the engine refuses them.
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
    Ok(envelope.to_string())
}
