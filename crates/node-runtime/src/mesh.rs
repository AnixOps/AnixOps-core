//! `GET` / `PUT /v1/mesh`: the managed mesh networks a node agent runs on
//! this node (`docs/architecture/mesh-status.md`, "节点程序管理 API").
//!
//! The node program installs an [`outbound_mesh::status::MeshControl`] with
//! [`crate::Node::with_mesh`]; without one the kernel does not list `mesh`
//! in its features and both endpoints answer 404.
//!
//! `PUT` takes `{"networks": [MeshConfig + "tag"]}`: each item is the
//! network's `config_version` 1 config (`docs/architecture/mesh-module.md`)
//! with a `tag` of `mesh-<region code>` beside it. The list replaces the
//! running networks as a whole; `{"networks": []}` stops them all. A border
//! node's body also carries a top-level `backbone` section
//! (`docs/protocols/intranet-mesh-appendix.md` B) whose `region` names one
//! of the networks by its tag `mesh-<region>`; without it the backbone
//! stops. One invalid item refuses the whole body with 400 and nothing
//! changes. Neither the network secret nor a backbone link parameter ever
//! appears in an answer: refusals name the item or field and the rule, not
//! the values.

use std::collections::BTreeSet;
use std::sync::Arc;

use outbound_mesh::backbone::BackboneConfig;
use outbound_mesh::status::{
    valid_tag, ApplyError, ManagedBackbone, ManagedNetwork, ManagedStatus, MeshControl,
    MAX_MANAGED_NETWORKS, TAG_PREFIX,
};
use outbound_mesh::MeshConfig;
use serde::Deserialize;
use serde_json::{Map, Value};

use crate::NodeError;

/// The feature a mesh lists when it takes a `backbone` section.
pub const BACKBONE_FEATURE: &str = "mesh_backbone";

/// The refusal of a `backbone` section on a mesh that does not list
/// [`BACKBONE_FEATURE`].
pub const BACKBONE_DISABLED: &str = "backbone_disabled";

/// The installed mesh, with the lock that keeps `PUT`s one at a time.
pub(crate) struct Mesh {
    control: Arc<dyn MeshControl>,
    apply: tokio::sync::Mutex<()>,
}

impl Mesh {
    pub(crate) fn new(control: Arc<dyn MeshControl>) -> Self {
        Self {
            control,
            apply: tokio::sync::Mutex::new(()),
        }
    }

    pub(crate) fn features(&self) -> &'static [&'static str] {
        self.control.features()
    }

    pub(crate) fn status(&self) -> ManagedStatus {
        self.control.status()
    }

    /// Parses, validates and applies a `PUT /v1/mesh` body.
    pub(crate) async fn apply(&self, body: &[u8]) -> Result<ManagedStatus, NodeError> {
        let request = parse(body).map_err(NodeError::Mesh)?;
        // A node that does not list the backbone never becomes a border
        // node: the whole body is refused and nothing changes.
        if request.backbone.is_some() && !self.features().contains(&BACKBONE_FEATURE) {
            return Err(NodeError::Mesh(format!(
                "{BACKBONE_DISABLED}: backbone: this node does not run a backbone ({BACKBONE_FEATURE} is not listed)"
            )));
        }
        let _one_at_a_time = self.apply.lock().await;
        self.control
            .apply(request.networks, request.backbone)
            .await
            .map_err(|error| match error {
                ApplyError::Invalid(message) => NodeError::Mesh(message),
                ApplyError::Failed(message) => NodeError::MeshFailed(message),
            })
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PutBody {
    networks: Vec<Map<String, Value>>,
    #[serde(default)]
    backbone: Option<Value>,
}

/// A validated `PUT /v1/mesh` body.
pub struct MeshRequest {
    pub networks: Vec<ManagedNetwork>,
    /// The border node's backbone; `None` when the body has none.
    pub backbone: Option<ManagedBackbone>,
}

/// Validates a `PUT /v1/mesh` body: every item, unique tags and unique
/// network names, and the `backbone` section with its region network.
/// Error messages carry no values from the body.
pub fn parse(body: &[u8]) -> Result<MeshRequest, String> {
    let body: PutBody = serde_json::from_slice(body)
        .map_err(|error| format!("invalid request body: {}", describe(&error)))?;
    if body.networks.len() > MAX_MANAGED_NETWORKS {
        return Err(format!(
            "at most {MAX_MANAGED_NETWORKS} mesh networks are allowed"
        ));
    }
    let mut tags = BTreeSet::new();
    let mut names = BTreeSet::new();
    let mut networks = Vec::with_capacity(body.networks.len());
    for (index, mut item) in body.networks.into_iter().enumerate() {
        let tag = match item.remove("tag") {
            Some(Value::String(tag)) if valid_tag(&tag) => tag,
            _ => {
                return Err(format!(
                    "networks[{index}]: tag must be mesh-<region code> (2-16 lowercase letters, digits or '-', starting with a letter)"
                ))
            }
        };
        if !tags.insert(tag.clone()) {
            return Err(format!("networks[{index}]: tag {tag} is used twice"));
        }
        let config: MeshConfig = serde_json::from_value(Value::Object(item))
            .map_err(|error| format!("networks[{index}] ({tag}): {}", describe(&error)))?;
        let settings = config
            .validate()
            .map_err(|reason| format!("networks[{index}] ({tag}): {reason}"))?;
        if !names.insert(settings.network_name.clone()) {
            return Err(format!(
                "networks[{index}] ({tag}): network.name is used by another network"
            ));
        }
        networks.push(ManagedNetwork { tag, settings });
    }
    let backbone = match body.backbone {
        None | Some(Value::Null) => None,
        Some(value) => Some(parse_backbone(value, &tags)?),
    };
    Ok(MeshRequest { networks, backbone })
}

/// The `backbone` section: its own rules (appendix B) and a network tagged
/// `mesh-<region>` in the same body.
fn parse_backbone(value: Value, tags: &BTreeSet<String>) -> Result<ManagedBackbone, String> {
    let config: BackboneConfig =
        serde_json::from_value(value).map_err(|error| format!("backbone: {}", describe(&error)))?;
    let settings = config.validate().map_err(|error| error.to_string())?;
    if !tags.contains(&format!("{TAG_PREFIX}{}", settings.region)) {
        return Err(
            "backbone.region: networks must hold the region network, tagged mesh-<region>".into(),
        );
    }
    Ok(ManagedBackbone {
        links: config.links(),
        settings,
    })
}

/// A JSON error without the offending value: a mistyped secret must not be
/// echoed. Field names and syntax positions are safe; everything else gets
/// a fixed text.
fn describe(error: &serde_json::Error) -> String {
    let text = error.to_string();
    // Not "unknown variant": it repeats the value, which may be a secret
    // written into the wrong field.
    let names_only = ["unknown field", "missing field", "duplicate field"]
        .iter()
        .any(|prefix| text.starts_with(prefix));
    if names_only || error.is_syntax() || error.is_eof() {
        text
    } else if error.line() > 0 {
        format!(
            "a value has the wrong type or is out of range at line {} column {}",
            error.line(),
            error.column()
        )
    } else {
        "a value has the wrong type or is out of range".to_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const SECRET: &str = "s3cret-value-never-echoed";

    fn network(tag: &str, name: &str) -> Value {
        json!({
            "tag": tag,
            "config_version": 1,
            "network": {"name": name, "secret": SECRET},
            "node": {"address": "10.150.0.5/16", "role": "full", "listen": [{"transport": "tcp", "port": 11010}]},
            "peers": [{"server": "203.0.113.10", "port": 11010, "transport": "tcp"}]
        })
    }

    fn put(networks: Vec<Value>) -> Result<Vec<ManagedNetwork>, String> {
        parse(&serde_json::to_vec(&json!({ "networks": networks })).unwrap())
            .map(|request| request.networks)
    }

    fn backbone() -> Value {
        json!({
            "id": 11,
            "region": "eu",
            "members": [
                { "id": 11, "region": "eu", "link": { "kind": "k" } },
                { "id": 21, "region": "ap", "link": { "kind": "k", "params": { "key": SECRET } } }
            ]
        })
    }

    fn put_with(networks: Vec<Value>, backbone: Value) -> Result<MeshRequest, String> {
        parse(&serde_json::to_vec(&json!({ "networks": networks, "backbone": backbone })).unwrap())
    }

    /// The refusal of a body that must be refused. (`ManagedNetwork` has
    /// no `Debug`: it holds the secret, so `unwrap_err` is not available.)
    fn refused(networks: Vec<Value>) -> String {
        match put(networks) {
            Ok(_) => panic!("the body was accepted"),
            Err(error) => error,
        }
    }

    #[test]
    fn takes_several_networks_in_order() {
        let networks = put(vec![
            network("mesh-cn", "mesh-cn"),
            network("mesh-eu", "mesh-eu"),
        ])
        .unwrap();
        let tags: Vec<_> = networks.iter().map(|n| n.tag.as_str()).collect();
        assert_eq!(tags, ["mesh-cn", "mesh-eu"]);
        assert_eq!(networks[1].settings.network_name, "mesh-eu");
    }

    #[test]
    fn an_empty_list_stops_everything() {
        assert!(put(Vec::new()).unwrap().is_empty());
    }

    #[test]
    fn refuses_a_missing_or_malformed_tag() {
        let mut untagged = network("mesh-cn", "a");
        untagged.as_object_mut().unwrap().remove("tag");
        assert!(refused(vec![untagged]).contains("networks[0]: tag"));
        for tag in [json!("cn"), json!("mesh-CN"), json!(7), json!("")] {
            let mut item = network("mesh-cn", "a");
            item["tag"] = tag;
            assert!(put(vec![item]).is_err());
        }
    }

    #[test]
    fn refuses_duplicate_tags_and_names() {
        let error = refused(vec![network("mesh-cn", "a"), network("mesh-cn", "b")]);
        assert!(error.starts_with("networks[1]"), "{error}");
        let error = refused(vec![network("mesh-cn", "a"), network("mesh-eu", "a")]);
        assert!(error.contains("network.name"), "{error}");
    }

    #[test]
    fn refuses_unknown_fields_and_invalid_configs() {
        let mut item = network("mesh-cn", "a");
        item["dns"] = json!({"enabled": true});
        assert!(refused(vec![item]).contains("unknown field"));
        let mut item = network("mesh-cn", "a");
        item["config_version"] = json!(2);
        assert!(put(vec![item]).is_err());
        assert!(parse(br#"{"networks": [], "extra": 1}"#).is_err());
        assert!(parse(b"{}").is_err());
        assert!(parse(b"not json").is_err());
    }

    #[test]
    fn refuses_too_many_networks() {
        let networks = (0..=MAX_MANAGED_NETWORKS)
            .map(|i| network(&format!("mesh-r{i}"), &format!("n{i}")))
            .collect();
        assert!(refused(networks).contains("at most"));
    }

    #[test]
    fn refusals_never_echo_the_secret() {
        // A secret of the wrong type, a secret next to an invalid field, and
        // an empty network name: none of the answers may carry the value.
        let mut wrong_type = network("mesh-cn", "a");
        wrong_type["network"]["secret"] = json!([SECRET]);
        let mut bad_cipher = network("mesh-cn", "a");
        bad_cipher["network"]["cipher"] = json!(SECRET);
        let empty_name = network("mesh-cn", "");
        for item in [wrong_type, bad_cipher, empty_name] {
            let error = refused(vec![item]);
            assert!(!error.contains(SECRET), "{error}");
        }
        let mut tag_as_secret = network("mesh-cn", "a");
        tag_as_secret["tag"] = json!(SECRET);
        assert!(!refused(vec![tag_as_secret]).contains(SECRET));
    }

    #[test]
    fn takes_a_backbone_with_its_region_network() {
        let request = put_with(vec![network("mesh-eu", "eu")], backbone()).unwrap();
        let backbone = request.backbone.expect("backbone");
        assert_eq!(backbone.settings.id, 11);
        assert_eq!(backbone.links[1].0, 21);
        assert_eq!(backbone.links[1].1.params["key"], SECRET);
        assert!(put_with(vec![network("mesh-eu", "eu")], Value::Null)
            .unwrap()
            .backbone
            .is_none());
        assert!(put(vec![network("mesh-eu", "eu")]).is_ok());
    }

    #[test]
    fn refuses_a_backbone_without_its_region_network_or_with_bad_fields() {
        let error = match put_with(vec![network("mesh-ap", "ap")], backbone()) {
            Ok(_) => panic!("accepted"),
            Err(error) => error,
        };
        assert!(error.starts_with("backbone.region"), "{error}");

        let mut extra = backbone();
        extra["members"][1]["link"]["secret"] = json!(SECRET);
        let mut wrong_type = backbone();
        wrong_type["members"][1]["link"]["kind"] = json!([SECRET]);
        let mut bad_region = backbone();
        bad_region["region"] = json!("EU");
        for (body, path) in [
            (extra, "backbone"),
            (wrong_type, "backbone"),
            (bad_region, "backbone.region"),
        ] {
            let error = match put_with(vec![network("mesh-eu", "eu")], body) {
                Ok(_) => panic!("accepted"),
                Err(error) => error,
            };
            assert!(error.starts_with(path), "{error}");
            assert!(!error.contains(SECRET), "{error}");
        }
    }
}
