//! What a device without an Agent exchanges with Control
//! (`docs/deploy/mesh-device.md`, anix-control `agent-contract.md` §4).
//!
//! The device only reads its own membership and only reports state and
//! latency (requirement R31): an answer with any field beyond the fixed
//! set is refused as a whole, so Control can never send an instruction
//! through it. The networks it accepts are turned into the same
//! `PUT /v1/mesh` body an Agent sends to the kernel, and its report is the
//! Agent's `mesh.status` payload, so admission (`native_keys`), held
//! networks and failure codes behave the same on both paths.
//!
//! Everything here is pure: the transport and the service loop use it.
//! A [`Rejection`] names the field and the rule, never a value, because a
//! value may be a network secret or a token.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::time::Duration;

use serde_json::{json, Map, Value};

/// Fields a network may have in a device answer (contract §4 item 3).
pub const NETWORK_FIELDS: &[&str] = &[
    "id",
    "name",
    "kind",
    "native_keys",
    "secret",
    "secure_mode",
    "cipher",
    "address",
    "role",
    "listen",
    "peers",
    "subnets",
    "routing",
    "dns",
];

/// Most networks in one answer, as for `PUT /v1/mesh`.
pub const MAX_NETWORKS: usize = 64;

/// Largest answer the device reads.
pub const MAX_ANSWER: usize = 1 << 20;

/// Longest enrolment or device token accepted.
pub const MAX_TOKEN: usize = 256;

/// Most region latencies sent on enrolment (contract §4 item 2).
pub const MAX_LATENCIES: usize = 64;

/// Highest latency in milliseconds Control accepts.
pub const MAX_LATENCY_MS: f64 = 600_000.0;

/// Tag prefix of a mesh network in the kernel.
pub const TAG_PREFIX: &str = "mesh-";

/// Interval between two reads of the configuration and two reports.
pub const INTERVAL: Duration = Duration::from_secs(60);

/// Longest wait after failures or a `Retry-After`.
pub const MAX_WAIT: Duration = Duration::from_secs(600);

/// Why an answer or an argument was refused: the field and the rule, never
/// the value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rejection {
    pub field: String,
    pub rule: &'static str,
}

impl Rejection {
    fn new(field: impl Into<String>, rule: &'static str) -> Self {
        Self {
            field: field.into(),
            rule,
        }
    }
}

impl fmt::Display for Rejection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.field, self.rule)
    }
}

impl std::error::Error for Rejection {}

/// A region code: 2-16 lowercase letters, digits or '-', starting with a
/// letter and not ending with '-' (the same rule as the kernel tag).
pub fn valid_region_code(code: &str) -> bool {
    let bytes = code.as_bytes();
    (2..=16).contains(&bytes.len())
        && bytes[0].is_ascii_lowercase()
        && bytes[bytes.len() - 1] != b'-'
        && bytes
            .iter()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'-')
}

/// A kernel instance id: 1-64 ASCII letters, digits or '-', starting with a
/// letter or digit.
pub fn valid_instance_id(id: &str) -> bool {
    let bytes = id.as_bytes();
    (1..=64).contains(&bytes.len())
        && bytes[0].is_ascii_alphanumeric()
        && bytes
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || *b == b'-')
}

/// A static public key: 32 bytes in standard base64 with padding.
pub fn valid_static_key(key: &str) -> bool {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let bytes = key.as_bytes();
    if bytes.len() != 44 || bytes[43] != b'=' {
        return false;
    }
    if !bytes[..43].iter().all(|b| ALPHABET.contains(b)) {
        return false;
    }
    // 32 bytes leave two unused bits in the last character.
    let last = ALPHABET.iter().position(|b| *b == bytes[42]).unwrap_or(1);
    last & 0b11 == 0
}

fn valid_token(token: &str, prefix: &str) -> bool {
    token.len() > prefix.len()
        && token.len() <= MAX_TOKEN
        && token.starts_with(prefix)
        && token.bytes().all(|b| b.is_ascii_graphic())
}

/// The enrolment token from its file: surrounding whitespace is dropped.
pub fn enroll_token(text: &str) -> Result<String, Rejection> {
    let token = text.trim();
    if valid_token(token, "mse_") {
        Ok(token.to_owned())
    } else {
        Err(Rejection::new(
            "token",
            "must be one mse_ token of printable ASCII, at most 256 bytes",
        ))
    }
}

/// The device token as saved in the state directory.
pub fn device_token(text: &str) -> Result<String, Rejection> {
    let token = text.trim();
    if valid_token(token, "msd_") {
        Ok(token.to_owned())
    } else {
        Err(Rejection::new(
            "device_token",
            "must be one msd_ token of printable ASCII, at most 256 bytes",
        ))
    }
}

/// `--control`: `https://host[:port]`, nothing else. A trailing '/' is
/// dropped; the answer has none.
pub fn control_url(text: &str) -> Result<String, Rejection> {
    let refuse = |rule| Err(Rejection::new("control", rule));
    let Some(rest) = text.strip_prefix("https://") else {
        return refuse("must start with https://");
    };
    let authority = rest.strip_suffix('/').unwrap_or(rest);
    if authority.is_empty() {
        return refuse("needs a host");
    }
    if authority
        .bytes()
        .any(|b| matches!(b, b'/' | b'?' | b'#' | b'@' | b'\\') || !b.is_ascii_graphic())
    {
        return refuse("must be https://host[:port] without path, query or user");
    }
    let (host, port) = if let Some(inner) = authority.strip_prefix('[') {
        let Some((address, after)) = inner.split_once(']') else {
            return refuse("an IPv6 host needs a closing ]");
        };
        if address.parse::<std::net::Ipv6Addr>().is_err() {
            return refuse("the bracketed host must be an IPv6 address");
        }
        match after {
            "" => (address, None),
            _ => match after.strip_prefix(':') {
                Some(port) => (address, Some(port)),
                None => return refuse("only :port may follow the host"),
            },
        }
    } else {
        match authority.split_once(':') {
            Some((host, port)) => (host, Some(port)),
            None => (authority, None),
        }
    };
    if host.is_empty() {
        return refuse("needs a host");
    }
    if let Some(port) = port {
        let valid = !port.is_empty()
            && port.bytes().all(|b| b.is_ascii_digit())
            && matches!(port.parse::<u32>(), Ok(1..=65535));
        if !valid {
            return refuse("the port must be 1-65535");
        }
    }
    Ok(format!("https://{authority}"))
}

/// `--latency CODE=MS`.
pub fn latency(text: &str) -> Result<(String, f64), Rejection> {
    let Some((code, ms)) = text.split_once('=') else {
        return Err(Rejection::new("latency", "must be CODE=MS"));
    };
    if !valid_region_code(code) {
        return Err(Rejection::new("latency", "the region code is invalid"));
    }
    match ms.parse::<f64>() {
        Ok(ms) if ms.is_finite() && (0.0..=MAX_LATENCY_MS).contains(&ms) => {
            Ok((code.to_owned(), ms))
        }
        _ => Err(Rejection::new(
            "latency",
            "milliseconds must be a number from 0 to 600000",
        )),
    }
}

/// The enrolment request body. `static_key` is left out: the device has
/// its network keys only once it has the configuration, and the first
/// report gives them.
pub fn enroll_request(
    token: &str,
    device_key: &str,
    latencies: &BTreeMap<String, f64>,
    features: &[&str],
) -> Result<Value, Rejection> {
    if latencies.len() > MAX_LATENCIES {
        return Err(Rejection::new("latency", "at most 64 regions"));
    }
    Ok(json!({
        "token": token,
        "device_key": device_key,
        "latencies": latencies,
        "features": features,
    }))
}

/// One network of a device answer, checked against the fixed field set.
#[derive(Debug, Clone, PartialEq)]
pub struct Network {
    /// The region code.
    pub id: String,
    fields: Map<String, Value>,
}

impl Network {
    fn get(&self, key: &str) -> Option<&Value> {
        self.fields.get(key).filter(|value| !value.is_null())
    }
}

/// An accepted enrolment answer.
#[derive(Debug, Clone, PartialEq)]
pub struct Enrolled {
    pub device_id: u64,
    pub device_token: String,
    pub networks: Vec<Network>,
}

fn parse_json(body: &[u8]) -> Result<Value, Rejection> {
    if body.len() > MAX_ANSWER {
        return Err(Rejection::new("answer", "larger than 1 MiB"));
    }
    serde_json::from_slice(body).map_err(|_| Rejection::new("answer", "is not JSON"))
}

/// The object at `path` with exactly the keys `required` (plus any of
/// `optional`).
fn object<'a>(
    value: &'a Value,
    path: &str,
    required: &[&str],
    optional: &[&str],
) -> Result<&'a Map<String, Value>, Rejection> {
    let Value::Object(map) = value else {
        return Err(Rejection::new(path, "must be an object"));
    };
    for key in map.keys() {
        if !required.contains(&key.as_str()) && !optional.contains(&key.as_str()) {
            return Err(Rejection::new(format!("{path}.{key}"), "is not allowed"));
        }
    }
    for key in required {
        if !map.contains_key(*key) {
            return Err(Rejection::new(format!("{path}.{key}"), "is missing"));
        }
    }
    Ok(map)
}

/// `GET /api/v5/mesh/device/config`: `{"data":{"networks":[…]}}`.
pub fn parse_config(body: &[u8]) -> Result<Vec<Network>, Rejection> {
    let answer = parse_json(body)?;
    let top = object(&answer, "answer", &["data"], &[])?;
    let data = object(&top["data"], "data", &["networks"], &[])?;
    networks(&data["networks"], "data.networks")
}

/// `POST /api/v5/mesh/device/enroll` (201):
/// `{"data":{"device_id","device_token","config":{"networks":[…]}}}`.
pub fn parse_enrolled(body: &[u8]) -> Result<Enrolled, Rejection> {
    let answer = parse_json(body)?;
    let top = object(&answer, "answer", &["data"], &[])?;
    let data = object(
        &top["data"],
        "data",
        &["device_id", "device_token", "config"],
        &[],
    )?;
    let device_id = data["device_id"]
        .as_u64()
        .filter(|id| *id > 0)
        .ok_or_else(|| Rejection::new("data.device_id", "must be a positive integer"))?;
    let device_token = data["device_token"]
        .as_str()
        .ok_or_else(|| Rejection::new("data.device_token", "must be a string"))
        .and_then(device_token)?;
    let config = object(&data["config"], "data.config", &["networks"], &[])?;
    let networks = networks(&config["networks"], "data.config.networks")?;
    Ok(Enrolled {
        device_id,
        device_token,
        networks,
    })
}

fn networks(value: &Value, path: &str) -> Result<Vec<Network>, Rejection> {
    let Value::Array(items) = value else {
        return Err(Rejection::new(path, "must be a list"));
    };
    if items.len() > MAX_NETWORKS {
        return Err(Rejection::new(path, "at most 64 networks"));
    }
    let mut ids = BTreeSet::new();
    let mut out = Vec::with_capacity(items.len());
    for (index, item) in items.iter().enumerate() {
        let at = format!("{path}[{index}]");
        let fields = object(
            item,
            &at,
            &["id", "name", "kind", "secret", "secure_mode", "address"],
            NETWORK_FIELDS,
        )?;
        let id = match fields["id"].as_str() {
            Some(id) if valid_region_code(id) => id.to_owned(),
            _ => return Err(Rejection::new(format!("{at}.id"), "must be a region code")),
        };
        if !ids.insert(id.clone()) {
            return Err(Rejection::new(format!("{at}.id"), "is used twice"));
        }
        if fields["name"].as_str() != Some(format!("{TAG_PREFIX}{id}").as_str()) {
            return Err(Rejection::new(format!("{at}.name"), "must be mesh-<id>"));
        }
        // Only managed region networks: a device never joins a legacy one.
        if fields["kind"].as_str() != Some("managed") {
            return Err(Rejection::new(format!("{at}.kind"), "must be managed"));
        }
        if !matches!(fields["secret"].as_str(), Some(secret) if !secret.is_empty()) {
            return Err(Rejection::new(
                format!("{at}.secret"),
                "must be a non-empty string",
            ));
        }
        if !fields["secure_mode"].is_boolean() {
            return Err(Rejection::new(
                format!("{at}.secure_mode"),
                "must be true or false",
            ));
        }
        if !fields["address"].is_string() {
            return Err(Rejection::new(format!("{at}.address"), "must be a string"));
        }
        if let Some(keys) = fields.get("native_keys").filter(|v| !v.is_null()) {
            let valid = keys.as_array().is_some_and(|keys| {
                keys.iter()
                    .all(|k| k.as_str().is_some_and(valid_static_key))
            });
            if !valid {
                return Err(Rejection::new(
                    format!("{at}.native_keys"),
                    "must be a list of static public keys",
                ));
            }
        }
        out.push(Network {
            id,
            fields: fields.clone(),
        });
    }
    Ok(out)
}

/// Optional sections the local kernel takes (its own features).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Sections {
    /// `mesh_dns`: the `dns` section.
    pub dns: bool,
    /// `mesh_resolver_address`: `dns.resolver_address`.
    pub resolver_address: bool,
}

/// The `PUT /v1/mesh` body for accepted networks: each flat network in the
/// kernel's layered `config_version` 1 form, tagged `mesh-<id>`, as the
/// Agent builds it. Every network is managed and keeps its `native_keys`
/// (an empty or missing list holds the network until Control lists this
/// device's key).
pub fn kernel_body(networks: &[Network], sections: Sections) -> Value {
    let out: Vec<Value> = networks
        .iter()
        .map(|n| {
            let mut network = Map::new();
            for key in ["name", "secret", "secure_mode", "kind"] {
                if let Some(value) = n.get(key) {
                    network.insert(key.to_owned(), value.clone());
                }
            }
            if let Some(cipher) = n.get("cipher").filter(|c| c.as_str() != Some("")) {
                network.insert("cipher".to_owned(), cipher.clone());
            }
            if let Some(keys) = n.get("native_keys") {
                network.insert("native_keys".to_owned(), keys.clone());
            }
            let mut node = Map::new();
            if let Some(address) = n.get("address") {
                node.insert("address".to_owned(), address.clone());
            }
            if let Some(role) = n.get("role").filter(|r| r.as_str() != Some("")) {
                node.insert("role".to_owned(), role.clone());
            }
            if let Some(listen) = n.get("listen").filter(|l| !is_empty_list(l)) {
                node.insert("listen".to_owned(), listen.clone());
            }
            let mut config = Map::new();
            config.insert("tag".to_owned(), json!(format!("{TAG_PREFIX}{}", n.id)));
            config.insert("type".to_owned(), json!("mesh"));
            config.insert("config_version".to_owned(), json!(1));
            config.insert("network".to_owned(), Value::Object(network));
            config.insert("node".to_owned(), Value::Object(node));
            config.insert(
                "peers".to_owned(),
                n.get("peers").cloned().unwrap_or_else(|| json!([])),
            );
            for key in ["subnets", "routing"] {
                if let Some(value) = n.get(key) {
                    config.insert(key.to_owned(), value.clone());
                }
            }
            if sections.dns {
                if let Some(dns) = n.get("dns") {
                    config.insert(
                        "dns".to_owned(),
                        dns_section(dns, sections.resolver_address),
                    );
                }
            }
            Value::Object(config)
        })
        .collect();
    json!({ "networks": out })
}

fn is_empty_list(value: &Value) -> bool {
    value.as_array().is_some_and(Vec::is_empty)
}

/// Without `mesh_resolver_address` the kernel refuses the field, and with
/// it the whole configuration, so it is dropped.
fn dns_section(dns: &Value, resolver_address: bool) -> Value {
    match dns {
        Value::Object(fields) if !resolver_address && fields.contains_key("resolver_address") => {
            let mut fields = fields.clone();
            fields.remove("resolver_address");
            Value::Object(fields)
        }
        _ => dns.clone(),
    }
}

/// The report body from the local managed mesh's state (the `GET /v1/mesh`
/// answer): each network's `tag` becomes its region `id`, its static key is
/// attached by network name, and the kernel's `features` go on top.
/// Region requests are not reported: a device asks through its own
/// endpoint. A network whose tag is not `mesh-<region code>` is left out.
pub fn report_body(status: &Value, features: &[&str], takeover: Option<&Value>) -> Value {
    let mut keys = BTreeMap::new();
    if let Some(list) = status.get("static_keys").and_then(Value::as_array) {
        for item in list {
            if let (Some(network), Some(key)) = (
                item.get("network").and_then(Value::as_str),
                item.get("static_key").and_then(Value::as_str),
            ) {
                if valid_static_key(key) {
                    keys.insert(network.to_owned(), key.to_owned());
                }
            }
        }
    }
    let mut networks = Vec::new();
    if let Some(list) = status.get("networks").and_then(Value::as_array) {
        for item in list {
            let Value::Object(fields) = item else {
                continue;
            };
            let Some(tag) = fields.get("tag").and_then(Value::as_str) else {
                continue;
            };
            let Some(id) = tag
                .strip_prefix(TAG_PREFIX)
                .filter(|id| valid_region_code(id))
            else {
                continue;
            };
            let mut out = fields.clone();
            out.remove("tag");
            out.insert("id".to_owned(), json!(id));
            if let Some(key) = keys.get(tag) {
                out.insert("static_key".to_owned(), json!(key));
            }
            networks.push(Value::Object(out));
        }
    }
    let mut body = Map::new();
    if let Some(id) = status
        .get("instance_id")
        .and_then(Value::as_str)
        .filter(|id| valid_instance_id(id))
    {
        body.insert("instance_id".to_owned(), json!(id));
    }
    body.insert("networks".to_owned(), Value::Array(networks));
    body.insert("features".to_owned(), json!(features));
    if let Some(takeover) = takeover {
        body.insert("takeover".to_owned(), takeover.clone());
    }
    Value::Object(body)
}

/// Waits between reads and reports: [`INTERVAL`] while Control answers,
/// doubling after each failure up to [`MAX_WAIT`].
#[derive(Debug, Clone, Default)]
pub struct Backoff {
    failures: u32,
}

impl Backoff {
    pub fn succeeded(&mut self) {
        self.failures = 0;
    }

    /// Records a failure and returns the wait before the next attempt:
    /// 60, 120, 240, 480 seconds, then 10 minutes.
    pub fn failed(&mut self) -> Duration {
        self.failures = self.failures.saturating_add(1);
        self.wait()
    }

    /// The wait before the next attempt.
    pub fn wait(&self) -> Duration {
        let shift = self.failures.saturating_sub(1).min(4);
        INTERVAL.saturating_mul(1 << shift).min(MAX_WAIT)
    }
}

/// `Retry-After` of a 429, in seconds only (a date is ignored), at most
/// [`MAX_WAIT`].
pub fn retry_after(header: Option<&str>) -> Option<Duration> {
    let seconds: u64 = header?.trim().parse().ok()?;
    Some(Duration::from_secs(seconds).min(MAX_WAIT))
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

    fn network(id: &str) -> Value {
        json!({
            "id": id,
            "name": format!("mesh-{id}"),
            "kind": "managed",
            "native_keys": [KEY],
            "secret": "s3cret-value",
            "secure_mode": true,
            "cipher": "aes-gcm",
            "address": "10.150.128.9/16",
            "role": "access",
            "listen": [],
            "peers": [{ "server": "edge-1.example.com", "port": 11010, "transport": "tcp" }],
            "subnets": { "accept": [], "advertise": [] },
            "routing": { "policy": "latency", "paths": [] },
            "dns": { "enabled": true, "suffix": "mesh.internal", "names": [], "resolver_address": "10.150.255.254" }
        })
    }

    fn config(networks: Vec<Value>) -> Vec<u8> {
        serde_json::to_vec(&json!({ "data": { "networks": networks } })).expect("json")
    }

    #[test]
    fn a_config_with_the_fixed_fields_is_accepted() {
        let networks = parse_config(&config(vec![network("cn"), network("eu")])).expect("valid");
        let ids: Vec<_> = networks.iter().map(|n| n.id.as_str()).collect();
        assert_eq!(ids, ["cn", "eu"]);
        assert!(parse_config(&config(vec![])).expect("empty").is_empty());
    }

    #[test]
    fn any_other_field_refuses_the_whole_answer() {
        let mut extra = network("cn");
        extra["host_groups"] = json!([]);
        let rejection = parse_config(&config(vec![extra])).expect_err("refused");
        assert_eq!(rejection.field, "data.networks[0].host_groups");

        let mut command = network("cn");
        command["exec"] = json!("rm -rf /");
        assert!(parse_config(&config(vec![command])).is_err());

        let top = serde_json::to_vec(&json!({ "data": { "networks": [] }, "takeover": {} }))
            .expect("json");
        assert_eq!(
            parse_config(&top).expect_err("refused").field,
            "answer.takeover"
        );
        let data =
            serde_json::to_vec(&json!({ "data": { "networks": [], "run": true } })).expect("json");
        assert_eq!(parse_config(&data).expect_err("refused").field, "data.run");
    }

    #[test]
    fn a_rejection_never_repeats_a_value() {
        let mut wrong = network("cn");
        wrong["secret"] = json!(42);
        let mut unknown = network("cn");
        unknown["s3cret-value"] = json!(1);
        for item in [wrong, network("CN")] {
            let rejection = parse_config(&config(vec![item])).expect_err("refused");
            assert!(!rejection.to_string().contains("s3cret-value"));
            assert!(!rejection.to_string().contains("42"));
        }
        // A field name is shown; the secret itself is never a key Control sends.
        assert!(parse_config(&config(vec![unknown])).is_err());
    }

    #[test]
    fn networks_must_be_managed_region_networks() {
        let mut legacy = network("cn");
        legacy["kind"] = json!("legacy");
        let mut renamed = network("cn");
        renamed["name"] = json!("other");
        let mut missing = network("cn");
        missing.as_object_mut().expect("object").remove("secret");
        let mut bad_key = network("cn");
        bad_key["native_keys"] = json!(["short"]);
        for (item, field) in [
            (legacy, "data.networks[0].kind"),
            (renamed, "data.networks[0].name"),
            (missing, "data.networks[0].secret"),
            (bad_key, "data.networks[0].native_keys"),
            (network("-cn"), "data.networks[0].id"),
        ] {
            assert_eq!(
                parse_config(&config(vec![item]))
                    .expect_err("refused")
                    .field,
                field
            );
        }
        let twice = parse_config(&config(vec![network("cn"), network("cn")])).expect_err("refused");
        assert_eq!(twice.field, "data.networks[1].id");
        let many: Vec<Value> = (0..65).map(|i| network(&format!("r{i}"))).collect();
        assert!(parse_config(&config(many)).is_err());
    }

    #[test]
    fn answers_that_are_too_large_or_not_json_are_refused() {
        assert!(parse_config(b"not json").is_err());
        let mut large = config(vec![network("cn")]);
        large.resize(MAX_ANSWER + 1, b' ');
        assert_eq!(
            parse_config(&large).expect_err("refused").rule,
            "larger than 1 MiB"
        );
    }

    #[test]
    fn an_enrolment_answer_gives_the_device_and_its_networks() {
        let body = serde_json::to_vec(&json!({ "data": {
            "device_id": 5,
            "device_token": "msd_abc",
            "config": { "networks": [network("cn")] }
        }}))
        .expect("json");
        let enrolled = parse_enrolled(&body).expect("valid");
        assert_eq!(enrolled.device_id, 5);
        assert_eq!(enrolled.device_token, "msd_abc");
        assert_eq!(enrolled.networks.len(), 1);

        for data in [
            json!({ "device_id": 0, "device_token": "msd_abc", "config": { "networks": [] } }),
            json!({ "device_id": 5, "device_token": "mse_abc", "config": { "networks": [] } }),
            json!({ "device_id": 5, "device_token": "msd_abc", "config": { "networks": [], "x": 1 } }),
            json!({ "device_id": 5, "device_token": "msd_abc", "config": { "networks": [] }, "x": 1 }),
        ] {
            let body = serde_json::to_vec(&json!({ "data": data })).expect("json");
            assert!(parse_enrolled(&body).is_err());
        }
    }

    #[test]
    fn the_kernel_body_is_the_agents_layered_form() {
        let networks = parse_config(&config(vec![network("cn")])).expect("valid");
        let body = kernel_body(
            &networks,
            Sections {
                dns: true,
                resolver_address: false,
            },
        );
        let item = &body["networks"][0];
        assert_eq!(item["tag"], "mesh-cn");
        assert_eq!(item["type"], "mesh");
        assert_eq!(item["config_version"], 1);
        assert_eq!(item["network"]["name"], "mesh-cn");
        assert_eq!(item["network"]["kind"], "managed");
        assert_eq!(item["network"]["native_keys"], json!([KEY]));
        assert_eq!(item["network"]["cipher"], "aes-gcm");
        assert_eq!(item["node"]["address"], "10.150.128.9/16");
        assert_eq!(item["node"]["role"], "access");
        assert!(
            item["node"].get("listen").is_none(),
            "an empty listen list is left out"
        );
        assert_eq!(item["peers"][0]["port"], 11010);
        assert!(item.get("id").is_none());
        assert!(item["dns"].get("resolver_address").is_none());
        assert_eq!(item["dns"]["suffix"], "mesh.internal");

        let with_resolver = kernel_body(
            &networks,
            Sections {
                dns: true,
                resolver_address: true,
            },
        );
        assert_eq!(
            with_resolver["networks"][0]["dns"]["resolver_address"],
            "10.150.255.254"
        );
        let without_dns = kernel_body(&networks, Sections::default());
        assert!(without_dns["networks"][0].get("dns").is_none());
        assert_eq!(
            kernel_body(&[], Sections::default()),
            json!({ "networks": [] })
        );
    }

    #[test]
    fn the_report_maps_tags_back_to_regions_with_their_keys() {
        let status = json!({
            "instance_id": "2f6d7c1e-0b8a",
            "networks": [
                { "tag": "mesh-cn", "running": true, "error": "", "address": "10.150.128.9/16", "peers": [] },
                { "tag": "other", "running": true }
            ],
            "static_keys": [{ "network": "mesh-cn", "static_key": KEY }, { "network": "mesh-eu", "static_key": "bad" }],
            "region_requests": [{ "id": "r1", "network": "mesh-cn", "region": "eu", "reason": "" }]
        });
        let takeover = json!({ "found": true, "stopped": ["svc"], "error": "" });
        let body = report_body(&status, &["mesh", "mesh_native_keys"], Some(&takeover));
        assert_eq!(body["instance_id"], "2f6d7c1e-0b8a");
        assert_eq!(body["networks"].as_array().expect("list").len(), 1);
        assert_eq!(body["networks"][0]["id"], "cn");
        assert!(body["networks"][0].get("tag").is_none());
        assert_eq!(body["networks"][0]["static_key"], KEY);
        assert_eq!(body["features"], json!(["mesh", "mesh_native_keys"]));
        assert_eq!(body["takeover"], takeover);
        assert!(body.get("region_requests").is_none());

        let anonymous = report_body(&json!({ "instance_id": "-bad", "networks": [] }), &[], None);
        assert!(anonymous.get("instance_id").is_none());
        assert!(anonymous.get("takeover").is_none());
    }

    #[test]
    fn static_keys_are_32_bytes_of_padded_base64() {
        assert!(valid_static_key(KEY));
        assert!(valid_static_key(
            "q83vEjRWeJCrze8SNFZ4kKvN7xI0VniQq83vEjRWeJA="
        ));
        assert!(
            !valid_static_key("q83vEjRWeJCrze8SNFZ4kKvN7xI0VniQq83vEjRWeJB="),
            "unused bits set"
        );
        assert!(!valid_static_key(
            "q83vEjRWeJCrze8SNFZ4kKvN7xI0VniQq83vEjRWeJA"
        ));
        assert!(!valid_static_key(
            "q83vEjRWeJCrze8SNFZ4kKvN7xI0VniQq83vEjRW-JA="
        ));
    }

    #[test]
    fn the_control_address_is_https_host_and_port_only() {
        assert_eq!(
            control_url("https://panel.example.com").expect("ok"),
            "https://panel.example.com"
        );
        assert_eq!(
            control_url("https://panel.example.com/").expect("ok"),
            "https://panel.example.com"
        );
        assert_eq!(
            control_url("https://10.0.0.1:8443").expect("ok"),
            "https://10.0.0.1:8443"
        );
        assert_eq!(
            control_url("https://[2001:db8::1]:443").expect("ok"),
            "https://[2001:db8::1]:443"
        );
        for bad in [
            "http://panel.example.com",
            "https://",
            "https://panel.example.com/api",
            "https://user@panel.example.com",
            "https://panel.example.com?x=1",
            "https://panel.example.com:0",
            "https://panel.example.com:70000",
            "https://panel.example.com:",
            "https://:443",
            "https://[not-v6]:443",
            "https://panel example.com",
        ] {
            assert!(control_url(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn tokens_and_latencies_are_checked() {
        assert_eq!(enroll_token("  mse_abc\n").expect("ok"), "mse_abc");
        let long = format!("mse_{}", "a".repeat(253));
        for bad in ["", "mse_", "msd_abc", "mse_a b", long.as_str()] {
            assert!(enroll_token(bad).is_err(), "{bad}");
        }
        assert_eq!(device_token("msd_x\n").expect("ok"), "msd_x");
        assert!(device_token("mse_x").is_err());

        assert_eq!(latency("cn=35.2").expect("ok"), ("cn".to_owned(), 35.2));
        for bad in [
            "cn",
            "CN=1",
            "cn=-1",
            "cn=600001",
            "cn=NaN",
            "cn=inf",
            "c=1",
        ] {
            assert!(latency(bad).is_err(), "{bad}");
        }
        let many: BTreeMap<String, f64> = (0..65).map(|i| (format!("r{i}"), 1.0)).collect();
        assert!(enroll_request("mse_a", "k", &many, &[]).is_err());
        let body = enroll_request("mse_a", "k", &BTreeMap::new(), &["mesh"]).expect("ok");
        assert!(body.get("static_key").is_none());
        assert_eq!(body["latencies"], json!({}));
    }

    #[test]
    fn failures_back_off_to_ten_minutes_and_success_resets() {
        let mut backoff = Backoff::default();
        assert_eq!(backoff.wait(), INTERVAL);
        let waits: Vec<u64> = (0..6).map(|_| backoff.failed().as_secs()).collect();
        assert_eq!(waits, [60, 120, 240, 480, 600, 600]);
        backoff.succeeded();
        assert_eq!(backoff.wait(), INTERVAL);
        assert_eq!(retry_after(Some(" 30 ")), Some(Duration::from_secs(30)));
        assert_eq!(retry_after(Some("99999")), Some(MAX_WAIT));
        assert_eq!(retry_after(Some("Wed, 21 Oct 2026 07:28:00 GMT")), None);
        assert_eq!(retry_after(None), None);
    }
}
