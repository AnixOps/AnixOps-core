//! The border node's `backbone` section (appendix B) and its validation.
//!
//! `members[].link` is handed to the caller ([`BackboneConfig::links`]):
//! its `params` are opaque to the mesh module and may hold secrets, so
//! [`LinkConfig`] has no `Debug` and nothing here prints or echoes them.
//! Errors name a field path and a rule, never a value.

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;

use serde::Deserialize;
use serde_json::Value;

use super::region::{parse_summary_prefix, RegionId};
use super::BackboneId;
use crate::net::IpNet;
use crate::scope;

/// Most members (appendix B.1).
pub const MAX_MEMBERS: usize = 256;
/// Most extra prefixes (appendix B.2).
pub const MAX_EXTRA_PREFIXES: usize = 256;
/// Longest `members[].link.kind`.
pub const MAX_KIND_LEN: usize = 32;
/// Most `deny_link` pairs (appendix B.3).
pub const MAX_DENY_LINK: usize = 256;
/// Most access rules, and most prefixes on either side of one (B.4).
pub const MAX_ACCESS_RULES: usize = 1024;
pub const MAX_ACCESS_PREFIXES: usize = 64;

/// The section as written. Unknown fields are refused.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackboneConfig {
    pub id: BackboneId,
    pub region: String,
    pub members: Vec<MemberConfig>,
    #[serde(default)]
    pub extra_prefixes: Vec<String>,
    #[serde(default)]
    pub policy: PolicyConfig,
    #[serde(default)]
    pub access: Vec<AccessConfig>,
    #[serde(default)]
    pub limits: LimitsConfig,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemberConfig {
    pub id: BackboneId,
    pub region: String,
    /// Read by the caller ([`BackboneConfig::links`]).
    pub link: LinkConfig,
}

/// `members[].link`: a registered link kind and its opaque parameters. No
/// `Debug`: `params` may hold keys.
#[derive(Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LinkConfig {
    pub kind: String,
    #[serde(default)]
    pub params: Value,
}

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyConfig {
    #[serde(default)]
    pub deny_link: Vec<[String; 2]>,
    #[serde(default)]
    pub preferred_transit: BTreeMap<String, Vec<String>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccessConfig {
    pub from: Vec<String>,
    pub to: Vec<String>,
}

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LimitsConfig {
    #[serde(default)]
    pub ip_pps: u32,
    #[serde(default)]
    pub ip_bps: u64,
}

/// One directional cross-region access rule (appendix B.4).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccessRule {
    pub from: Vec<IpNet>,
    pub to: Vec<IpNet>,
}

/// A validated `backbone` section.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BackboneSettings {
    pub id: BackboneId,
    pub region: RegionId,
    /// Every member's region, this node included.
    pub members: BTreeMap<BackboneId, RegionId>,
    pub extra_prefixes: Vec<IpNet>,
    /// Region pairs, each stored with the smaller ID first.
    pub deny_link: BTreeSet<(RegionId, RegionId)>,
    pub preferred_transit: BTreeMap<RegionId, BTreeSet<RegionId>>,
    pub access: Vec<AccessRule>,
    pub ip_pps: u32,
    pub ip_bps: u64,
}

/// A validation failure: the field path and the rule, never the value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConfigError {
    pub path: String,
    pub rule: &'static str,
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.path, self.rule)
    }
}

impl std::error::Error for ConfigError {}

fn err(path: impl Into<String>, rule: &'static str) -> ConfigError {
    ConfigError {
        path: path.into(),
        rule,
    }
}

fn region_at(text: &str, path: impl Into<String>) -> Result<RegionId, ConfigError> {
    RegionId::parse(text).ok_or_else(|| err(path, "not a valid region code"))
}

fn ordered(a: RegionId, b: RegionId) -> (RegionId, RegionId) {
    if a <= b {
        (a, b)
    } else {
        (b, a)
    }
}

fn access_prefix(text: &str, path: String) -> Result<IpNet, ConfigError> {
    if !text.contains('/') {
        return Err(err(path, "must be a prefix with an explicit length"));
    }
    let net = IpNet::parse(text).ok_or_else(|| err(path.clone(), "not a valid prefix"))?;
    if !scope::is_intranet_network(&net) {
        return Err(err(path, "must be inside the intranet ranges"));
    }
    Ok(net.trunc())
}

impl BackboneConfig {
    /// Every member's link in the order of `members`, this node's own
    /// entry included, so that errors can name `members[i]`.
    pub fn links(&self) -> Vec<(BackboneId, LinkConfig)> {
        self.members
            .iter()
            .map(|member| (member.id, member.link.clone()))
            .collect()
    }

    pub fn validate(&self) -> Result<BackboneSettings, ConfigError> {
        if self.id == 0 {
            return Err(err("backbone.id", "must not be 0"));
        }
        let region = region_at(&self.region, "backbone.region")?;
        if !(2..=MAX_MEMBERS).contains(&self.members.len()) {
            return Err(err("backbone.members", "must have 2 to 256 entries"));
        }
        let mut members = BTreeMap::new();
        for (i, member) in self.members.iter().enumerate() {
            if member.id == 0 {
                return Err(err(format!("backbone.members[{i}].id"), "must not be 0"));
            }
            let member_region = region_at(&member.region, format!("backbone.members[{i}].region"))?;
            let kind = &member.link.kind;
            if kind.is_empty()
                || kind.len() > MAX_KIND_LEN
                || !kind
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
            {
                return Err(err(
                    format!("backbone.members[{i}].link.kind"),
                    "must be 1 to 32 lowercase letters, digits or '-'",
                ));
            }
            if members.insert(member.id, member_region).is_some() {
                return Err(err(format!("backbone.members[{i}].id"), "is duplicated"));
            }
        }
        match members.get(&self.id) {
            None => return Err(err("backbone.id", "must be one of backbone.members")),
            Some(own) if *own != region => {
                return Err(err(
                    "backbone.region",
                    "must equal this node's region in backbone.members",
                ))
            }
            Some(_) => {}
        }
        if self.extra_prefixes.len() > MAX_EXTRA_PREFIXES {
            return Err(err("backbone.extra_prefixes", "has more than 256 entries"));
        }
        let mut extra_prefixes = Vec::new();
        for (i, text) in self.extra_prefixes.iter().enumerate() {
            let net = parse_summary_prefix(text).ok_or_else(|| {
                err(
                    format!("backbone.extra_prefixes[{i}]"),
                    "must be a canonical intranet prefix, /8 or longer (IPv6 /16 or longer)",
                )
            })?;
            extra_prefixes.push(net);
        }
        if self.policy.deny_link.len() > MAX_DENY_LINK {
            return Err(err(
                "backbone.policy.deny_link",
                "has more than 256 entries",
            ));
        }
        let mut deny_link = BTreeSet::new();
        for (i, [a, b]) in self.policy.deny_link.iter().enumerate() {
            let a = region_at(a, format!("backbone.policy.deny_link[{i}][0]"))?;
            let b = region_at(b, format!("backbone.policy.deny_link[{i}][1]"))?;
            if a == b {
                return Err(err(
                    format!("backbone.policy.deny_link[{i}]"),
                    "must name two different regions",
                ));
            }
            deny_link.insert(ordered(a, b));
        }
        let mut preferred_transit = BTreeMap::new();
        for (source, transits) in &self.policy.preferred_transit {
            let path = "backbone.policy.preferred_transit";
            let source = region_at(source, path)?;
            let mut set = BTreeSet::new();
            for (i, transit) in transits.iter().enumerate() {
                set.insert(region_at(transit, format!("{path}.{source}[{i}]"))?);
            }
            preferred_transit.insert(source, set);
        }
        if self.access.len() > MAX_ACCESS_RULES {
            return Err(err("backbone.access", "has more than 1024 entries"));
        }
        let mut access = Vec::new();
        for (i, rule) in self.access.iter().enumerate() {
            let side = |name: &str, list: &[String]| -> Result<Vec<IpNet>, ConfigError> {
                if list.is_empty() || list.len() > MAX_ACCESS_PREFIXES {
                    return Err(err(
                        format!("backbone.access[{i}].{name}"),
                        "must have 1 to 64 entries",
                    ));
                }
                list.iter()
                    .enumerate()
                    .map(|(j, text)| {
                        access_prefix(text, format!("backbone.access[{i}].{name}[{j}]"))
                    })
                    .collect()
            };
            access.push(AccessRule {
                from: side("from", &rule.from)?,
                to: side("to", &rule.to)?,
            });
        }
        Ok(BackboneSettings {
            id: self.id,
            region,
            members,
            extra_prefixes,
            deny_link,
            preferred_transit,
            access,
            ip_pps: self.limits.ip_pps,
            ip_bps: self.limits.ip_bps,
        })
    }
}

impl BackboneSettings {
    /// The region of a member.
    pub fn region_of(&self, id: BackboneId) -> Option<&RegionId> {
        self.members.get(&id)
    }

    /// Whether links between these two regions are forbidden (appendix A.6
    /// item 3). Links inside one region are never forbidden.
    pub fn link_denied(&self, a: &RegionId, b: &RegionId) -> bool {
        a != b && self.deny_link.contains(&ordered(a.clone(), b.clone()))
    }

    /// Whether a transit through `transit` gets the preference factor for
    /// traffic entering at `source` (spec §17.3.5 step 3).
    pub fn transit_preferred(&self, source: &RegionId, transit: &RegionId) -> bool {
        self.preferred_transit
            .get(source)
            .is_some_and(|set| set.contains(transit))
    }

    /// Whether cross-region traffic from `src` to `dst` is allowed at this
    /// ingress (appendix B.4). No rules: nothing is allowed.
    pub fn access_allows(&self, src: IpAddr, dst: IpAddr) -> bool {
        self.access.iter().any(|rule| {
            rule.from.iter().any(|net| net.contains(src))
                && rule.to.iter().any(|net| net.contains(dst))
        })
    }

    /// Regions with fewer than two border nodes (a deployment warning, spec
    /// §15.6, not an error).
    pub fn regions_without_redundancy(&self) -> Vec<RegionId> {
        let mut count: BTreeMap<&RegionId, usize> = BTreeMap::new();
        for region in self.members.values() {
            *count.entry(region).or_default() += 1;
        }
        count
            .into_iter()
            .filter(|(_, n)| *n < 2)
            .map(|(region, _)| region.clone())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn parse(value: serde_json::Value) -> Result<BackboneSettings, ConfigError> {
        let config: BackboneConfig = serde_json::from_value(value).expect("shape");
        config.validate()
    }

    fn base() -> serde_json::Value {
        json!({
            "id": 11,
            "region": "eu",
            "members": [
                { "id": 11, "region": "eu", "link": { "kind": "k", "params": { "key": "SECRET-VALUE" } } },
                { "id": 12, "region": "eu", "link": { "kind": "k" } },
                { "id": 21, "region": "ap", "link": { "kind": "k" } },
                { "id": 31, "region": "cn", "link": { "kind": "k" } }
            ],
            "extra_prefixes": ["10.200.0.0/16"],
            "policy": {
                "deny_link": [["cn", "eu"], ["na", "cn"]],
                "preferred_transit": { "cn": ["ap"] }
            },
            "access": [ { "from": ["10.10.0.0/16"], "to": ["10.20.0.0/16"] } ],
            "limits": { "ip_pps": 1000 }
        })
    }

    #[test]
    fn valid_section() {
        let s = parse(base()).unwrap();
        assert_eq!(s.id, 11);
        assert_eq!(s.region.as_str(), "eu");
        assert_eq!(s.members.len(), 4);
        let r = |x: &str| RegionId::parse(x).unwrap();
        assert!(s.link_denied(&r("eu"), &r("cn")));
        assert!(s.link_denied(&r("cn"), &r("na")));
        assert!(!s.link_denied(&r("cn"), &r("ap")));
        assert!(!s.link_denied(&r("cn"), &r("cn")));
        assert!(s.transit_preferred(&r("cn"), &r("ap")));
        assert!(!s.transit_preferred(&r("eu"), &r("ap")));
        assert!(s.access_allows("10.10.1.1".parse().unwrap(), "10.20.1.1".parse().unwrap()));
        assert!(!s.access_allows("10.20.1.1".parse().unwrap(), "10.10.1.1".parse().unwrap()));
        assert_eq!(s.ip_pps, 1000);
        assert_eq!(s.regions_without_redundancy(), vec![r("ap"), r("cn")]);
    }

    #[test]
    fn empty_access_denies_everything() {
        let mut v = base();
        v["access"] = json!([]);
        let s = parse(v).unwrap();
        assert!(!s.access_allows("10.10.1.1".parse().unwrap(), "10.20.1.1".parse().unwrap()));
    }

    #[test]
    fn errors_name_the_path_and_never_the_value() {
        type Mutation = Box<dyn Fn(&mut serde_json::Value)>;
        let cases: Vec<(Mutation, &str)> = vec![
            (Box::new(|v| v["id"] = json!(0)), "backbone.id"),
            (Box::new(|v| v["id"] = json!(99)), "backbone.id"),
            (Box::new(|v| v["region"] = json!("ap")), "backbone.region"),
            (Box::new(|v| v["region"] = json!("EU")), "backbone.region"),
            (
                Box::new(|v| v["members"][1]["id"] = json!(11)),
                "backbone.members[1].id",
            ),
            (
                Box::new(|v| v["members"][2]["region"] = json!("x")),
                "backbone.members[2].region",
            ),
            (
                Box::new(|v| v["extra_prefixes"] = json!(["8.8.8.0/24"])),
                "backbone.extra_prefixes[0]",
            ),
            (
                Box::new(|v| v["policy"]["deny_link"] = json!([["cn", "cn"]])),
                "backbone.policy.deny_link[0]",
            ),
            (
                Box::new(|v| v["access"][0]["from"] = json!([])),
                "backbone.access[0].from",
            ),
            (
                Box::new(|v| v["access"][0]["to"] = json!(["1.1.1.0/24"])),
                "backbone.access[0].to[0]",
            ),
            (
                Box::new(|v| v["access"][0]["to"] = json!(["10.1.1.1"])),
                "backbone.access[0].to[0]",
            ),
        ];
        for (mutate, path) in cases {
            let mut v = base();
            mutate(&mut v);
            let e = parse(v).unwrap_err();
            assert_eq!(e.path, path);
            assert!(!e.to_string().contains("SECRET-VALUE"));
        }
    }

    #[test]
    fn unknown_fields_are_refused() {
        let mut v = base();
        v["extra"] = json!(1);
        assert!(serde_json::from_value::<BackboneConfig>(v).is_err());
        let mut v = base();
        v["members"][0]["secret"] = json!("x");
        assert!(serde_json::from_value::<BackboneConfig>(v).is_err());
    }

    #[test]
    fn member_count_bounds() {
        let mut v = base();
        v["members"] = json!([{ "id": 11, "region": "eu", "link": { "kind": "k" } }]);
        assert_eq!(parse(v).unwrap_err().path, "backbone.members");
    }

    #[test]
    fn links_keep_kind_and_params() {
        let config: BackboneConfig = serde_json::from_value(base()).unwrap();
        config.validate().unwrap();
        let links = config.links();
        let ids: Vec<BackboneId> = links.iter().map(|(id, _)| *id).collect();
        assert_eq!(ids, [11, 12, 21, 31]);
        assert_eq!(links[0].1.kind, "k");
        assert_eq!(links[0].1.params["key"], "SECRET-VALUE");
        assert!(links[1].1.params.is_null());
    }

    #[test]
    fn link_kind_is_checked_without_echo() {
        for kind in [json!(""), json!("Bad Kind"), json!("x".repeat(33))] {
            let mut v = base();
            v["members"][1]["link"]["kind"] = kind;
            let error = parse(v).unwrap_err();
            assert_eq!(error.path, "backbone.members[1].link.kind");
        }
        let mut v = base();
        v["members"][1]["link"] = json!({ "params": {} });
        assert!(serde_json::from_value::<BackboneConfig>(v).is_err());
        let mut v = base();
        v["members"][1]["link"]["extra"] = json!(1);
        assert!(serde_json::from_value::<BackboneConfig>(v).is_err());
    }
}
