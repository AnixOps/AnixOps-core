//! Desktop routing over an imported profile: the envelope an import produced
//! (one outbound, or every node with the subscription's rules and policy
//! groups) turned into the envelope for a routing mode, and the policy group
//! choices a client shows and switches. Pure JSON work, no files or network.
//! There are no preset list modes (预设名单分流): the rules are the
//! subscription's and the user's own (docs/no-presets.md).

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::config::RuntimeConfig;
use crate::connections::Mode;

/// The routed outbound a single-node profile gets when a mode adds rules.
pub const PROXY_OUTBOUND: &str = "proxy";

/// How traffic is split, as the desktop clients name the modes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RoutingMode {
    /// Everything direct: the engine starts in its direct mode
    /// ([`Mode::Direct`]), where every flow and every DNS query goes
    /// direct, whatever the rules say; only a flow to an address a joined
    /// mesh network routes still goes to that network (`mesh-status.md`).
    Direct,
    /// The subscription's own rules and policy groups; a single-node profile
    /// sends everything through its node.
    #[default]
    Rule,
    /// Everything through the node the rule mode's `FINAL` takes: the engine
    /// starts in its global mode ([`Mode::Global`]) with the routing's
    /// `global` target set to `FINAL`'s group (or node), so switching that
    /// group's choice still changes the node. Rules are kept but not used.
    Global,
}

impl RoutingMode {
    pub fn as_str(self) -> &'static str {
        match self {
            RoutingMode::Direct => "direct",
            RoutingMode::Rule => "rule",
            RoutingMode::Global => "global",
        }
    }

    /// Every mode, in the order clients list them.
    pub const ALL: [RoutingMode; 3] = [RoutingMode::Rule, RoutingMode::Global, RoutingMode::Direct];

    pub fn parse(value: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|mode| mode.as_str() == value)
    }
}

/// The envelope `profile` runs with in `mode`: rule mode keeps the profile;
/// global mode starts the engine in its global mode (top-level `"mode":
/// "global"`) aimed at `FINAL`'s target; direct mode starts the engine in its
/// direct mode (top-level `"mode": "direct"`) and replaces the rules with
/// `FINAL,DIRECT`.
pub fn envelope_for_mode(profile: &str, mode: RoutingMode) -> Result<String, String> {
    match mode {
        RoutingMode::Rule => {
            validate(profile)?;
            Ok(profile.to_string())
        }
        RoutingMode::Global => global_envelope(profile),
        RoutingMode::Direct => direct_envelope(profile),
    }
}

/// A single-node profile's engine sends everything to its one outbound; a
/// routed profile's to `FINAL`'s first group, or its node. A `global` the
/// profile already names is kept. When `FINAL` ends at `DIRECT` or `REJECT`
/// nothing is set and the engine picks its default (the first group, else
/// the first node), so the global mode never quietly goes direct.
fn global_envelope(profile: &str) -> Result<String, String> {
    let mut envelope: Value = serde_json::from_str(profile).map_err(|error| error.to_string())?;
    let target = global_target(&envelope);
    let object = envelope
        .as_object_mut()
        .ok_or("the profile must be a JSON object")?;
    if let (Some(target), Some(routing)) = (
        target,
        object.get_mut("routing").and_then(Value::as_object_mut),
    ) {
        routing
            .entry("global")
            .or_insert_with(|| Value::String(target));
    }
    object.insert("mode".to_string(), json!(Mode::Global));
    let rendered = envelope.to_string();
    validate(&rendered)?;
    Ok(rendered)
}

/// `FINAL`'s first group, else the node it names; nothing for `DIRECT`,
/// `REJECT` or a name the profile does not define.
fn global_target(profile: &Value) -> Option<String> {
    let (chain, target) = final_chain(profile);
    chain.into_iter().next().or_else(|| {
        target.filter(|id| {
            profile
                .pointer("/routing/outbounds")
                .and_then(Value::as_object)
                .is_some_and(|outbounds| outbounds.contains_key(id))
        })
    })
}

fn direct_envelope(profile: &str) -> Result<String, String> {
    let mut envelope: Value = serde_json::from_str(profile).map_err(|error| error.to_string())?;
    let object = envelope
        .as_object_mut()
        .ok_or("the profile must be a JSON object")?;
    let mut routing = match (object.remove("outbound"), object.remove("routing")) {
        (Some(outbound), None) => json!({ "outbounds": { PROXY_OUTBOUND: outbound } }),
        (None, Some(routing)) => routing,
        _ => return Err("the profile must carry one outbound or routing".to_string()),
    };
    let routing_object = routing
        .as_object_mut()
        .ok_or("the profile's routing must be a JSON object")?;
    routing_object.insert("rules".to_string(), json!(["FINAL,DIRECT"]));
    routing_object.insert("rule_sets".to_string(), json!({}));
    object.insert("routing".to_string(), routing);
    // The rules alone are not enough: in the rule mode a `proxy` DNS server
    // (the default 1.1.1.1:53 among them) never goes DIRECT because a rule
    // says so, and would still be asked through a node.
    object.insert("mode".to_string(), json!(Mode::Direct));
    let rendered = envelope.to_string();
    validate(&rendered)?;
    Ok(rendered)
}

fn validate(envelope: &str) -> Result<(), String> {
    RuntimeConfig::from_json(envelope.as_bytes())
        .map(|_| ())
        .map_err(|error| format!("the engine rejected the profile: {}", error.message))
}

/// A policy group as a client lists it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupView {
    pub id: String,
    /// `select`, `url-test` or `fallback`.
    pub kind: String,
    pub members: Vec<String>,
    /// What the group routes to before any health check: a select group's
    /// default, otherwise its first member.
    pub choice: Option<String>,
}

/// The routed profile's policy groups; none for a single-node profile.
pub fn groups(profile: &Value) -> Vec<GroupView> {
    raw_groups(profile)
        .iter()
        .filter_map(|group| {
            Some(GroupView {
                id: group.get("id")?.as_str()?.to_string(),
                kind: group.get("type")?.as_str()?.to_string(),
                members: members(group),
                choice: choice(group),
            })
        })
        .collect()
}

/// Makes `member` the default of the select group `group_id`.
pub fn set_group_default(profile: &mut Value, group_id: &str, member: &str) -> Result<(), String> {
    let group = profile
        .pointer_mut("/routing/groups")
        .and_then(Value::as_array_mut)
        .and_then(|groups| {
            groups
                .iter_mut()
                .find(|group| group.get("id").and_then(Value::as_str) == Some(group_id))
        })
        .ok_or_else(|| format!("policy group {group_id} is not in the profile"))?;
    if group.get("type").and_then(Value::as_str) != Some("select") {
        return Err(format!(
            "policy group {group_id} chooses by itself; only select groups can be switched"
        ));
    }
    if !members(group).iter().any(|candidate| candidate == member) {
        return Err(format!(
            "{member} is not a member of policy group {group_id}"
        ));
    }
    group
        .as_object_mut()
        .ok_or("a policy group must be a JSON object")?
        .insert("default".to_string(), Value::String(member.to_string()));
    Ok(())
}

/// The node FINAL ends at, following each group's choice, if it ends at a node.
pub fn selected_node(profile: &Value) -> Option<String> {
    let (_, target) = final_chain(profile);
    target.filter(|id| {
        profile
            .pointer("/routing/outbounds")
            .and_then(Value::as_object)
            .is_some_and(|outbounds| outbounds.contains_key(id))
    })
}

/// The first select group on FINAL's route with `node_id` as a member: the
/// group a node switch changes.
pub fn switch_group_for_node(profile: &Value, node_id: &str) -> Option<String> {
    let (chain, _) = final_chain(profile);
    chain.into_iter().find(|id| {
        group(profile, id).is_some_and(|group| {
            group.get("type").and_then(Value::as_str) == Some("select")
                && members(group).iter().any(|member| member == node_id)
        })
    })
}

fn raw_groups(profile: &Value) -> &[Value] {
    profile
        .pointer("/routing/groups")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or_default()
}

fn group<'a>(profile: &'a Value, id: &str) -> Option<&'a Value> {
    raw_groups(profile)
        .iter()
        .find(|group| group.get("id").and_then(Value::as_str) == Some(id))
}

fn members(group: &Value) -> Vec<String> {
    group
        .get("members")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(str::to_string)
        .collect()
}

fn choice(group: &Value) -> Option<String> {
    let members = members(group);
    group
        .get("default")
        .and_then(Value::as_str)
        .filter(|_| group.get("type").and_then(Value::as_str) == Some("select"))
        .filter(|default| members.iter().any(|member| member == default))
        .map(str::to_string)
        .or_else(|| members.into_iter().next())
}

/// FINAL's target, parsed the way the routing model parses it so options
/// after the target (`FINAL,<target>,dns-failed`) are not taken as part of
/// the name.
fn final_target(routing: &Value) -> Option<String> {
    let rule = routing
        .get("rules")
        .and_then(Value::as_array)
        .and_then(|rules| rules.last())
        .and_then(Value::as_str)?;
    match config_core::routing::parse_rule_line(rule).ok()? {
        config_core::routing::RuleLine::Final { target, .. } => Some(target),
        config_core::routing::RuleLine::Rule { .. } => None,
    }
}

/// The groups FINAL passes through and the target it ends at.
fn final_chain(profile: &Value) -> (Vec<String>, Option<String>) {
    let mut target = profile.get("routing").and_then(final_target);
    let mut chain = Vec::new();
    while let Some(id) = target.clone() {
        if chain.contains(&id) {
            break;
        }
        let Some(group) = group(profile, &id) else {
            break;
        };
        chain.push(id);
        target = choice(group);
    }
    (chain, target)
}
