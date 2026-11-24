//! Pure configuration service for NetworkCore.
//!
//! This crate parses and normalizes the first minimal TOML configuration shape.
//! It performs no file I/O, network access, platform probing, or engine work.

pub mod certificate_pin;
pub mod node_id;
pub mod redirect;
pub mod routing;
pub mod routing_import;
pub mod rule_set;
pub mod sdwan_delivery;

use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
use base64::Engine as _;
use control_domain::{
    ConfigSnapshot, ConfigurationService, Diagnostic, DiagnosticSeverity, DomainError,
    DomainResult, Endpoint, ListenerBind, ListenerDescriptor, ListenerKind, ListenerNetwork,
    ListenerRoute, Metadata, MetadataEntry, NodeCatalog, NodeDescriptor, PlatformCapabilities,
    Protocol, RawSubscription, RouteAction, RuleSet, SchemaVersion, SubscriptionDocument,
    SubscriptionService, SubscriptionSource, NODE_METADATA_ANX_ALPN, NODE_METADATA_ANX_BARE_PORT,
    NODE_METADATA_ANX_FINGERPRINT, NODE_METADATA_ANX_JACKET, NODE_METADATA_ANX_PUBLIC_KEY,
    NODE_METADATA_ANX_SERVER_NAME, NODE_METADATA_ANX_USER_KEY, NODE_METADATA_ANX_WG_PORT,
    NODE_METADATA_HYSTERIA2_OBFS_MAX_PACKET_SIZE, NODE_METADATA_HYSTERIA2_OBFS_MIN_PACKET_SIZE,
    NODE_METADATA_HYSTERIA2_OBFS_PASSWORD, NODE_METADATA_HYSTERIA2_OBFS_TYPE,
    NODE_METADATA_HYSTERIA2_PASSWORD, NODE_METADATA_HYSTERIA2_SERVER_PORTS,
    NODE_METADATA_IWAN_ENCRYPT, NODE_METADATA_IWAN_MTU, NODE_METADATA_IWAN_PASSWORD,
    NODE_METADATA_IWAN_USERNAME, NODE_METADATA_MIERU_HANDSHAKE_MODE, NODE_METADATA_MIERU_MTU,
    NODE_METADATA_MIERU_MULTIPLEXING, NODE_METADATA_MIERU_PASSWORD, NODE_METADATA_MIERU_PORT_RANGE,
    NODE_METADATA_MIERU_TRAFFIC_PATTERN, NODE_METADATA_MIERU_TRANSPORT,
    NODE_METADATA_MIERU_USERNAME, NODE_METADATA_MULTIPLEX, NODE_METADATA_PATH,
    NODE_METADATA_PROXY_PASSWORD, NODE_METADATA_PROXY_USERNAME, NODE_METADATA_SHADOWSOCKS_METHOD,
    NODE_METADATA_SHADOWSOCKS_PASSWORD, NODE_METADATA_SHADOWSOCKS_PLUGIN, NODE_METADATA_SNELL_MODE,
    NODE_METADATA_SNELL_OBFS, NODE_METADATA_SNELL_OBFS_HOST, NODE_METADATA_SNELL_OBFS_URI,
    NODE_METADATA_SNELL_PSK, NODE_METADATA_SNELL_REUSE, NODE_METADATA_SNELL_USER_KEY,
    NODE_METADATA_SNELL_VERSION, NODE_METADATA_SOURCE_FORMAT, NODE_METADATA_TLS_ALPN,
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
use routing::{NetworkRuleSpec, PolicyGroupSpec, RoutingModel, RoutingSpec};
use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};

mod clash_yaml;
mod config_document;
mod loon_lines;
mod proxy_line_options;
mod quantumult_x_lines;
mod raw_documents;
mod share_links;
mod sing_box_json;
mod surge_lines;

pub use clash_yaml::*;
pub use config_document::*;
pub use loon_lines::*;
pub use proxy_line_options::*;
pub use quantumult_x_lines::*;
pub use raw_documents::*;
pub use share_links::*;
pub use sing_box_json::*;
pub use surge_lines::*;

pub const CURRENT_SCHEMA_VERSION: u32 = 1;

pub const SOURCE_CONFIG_CORE: &str = "config.core";
pub const SOURCE_SUBSCRIPTION_CORE: &str = "subscription.core";

pub const CONFIG_PARSE_FAILED_CODE: &str = "config.core.parse_failed";
pub const CONFIG_SCHEMA_UNSUPPORTED_CODE: &str = "config.core.schema_unsupported";
pub const CONFIG_PROFILE_MISSING_CODE: &str = "config.core.profile_missing";
pub const CONFIG_PROFILE_EMPTY_CODE: &str = "config.core.profile_empty";
pub const CONFIG_PROFILE_CONFLICT_CODE: &str = "config.core.profile_conflict";
pub const CONFIG_LISTENER_ID_EMPTY_CODE: &str = "config.core.listener_id_empty";
pub const CONFIG_LISTENER_KIND_EMPTY_CODE: &str = "config.core.listener_kind_empty";
pub const CONFIG_LISTENER_BIND_HOST_EMPTY_CODE: &str = "config.core.listener_bind_host_empty";
pub const CONFIG_LISTENER_BIND_PORT_INVALID_CODE: &str = "config.core.listener_bind_port_invalid";
pub const CONFIG_LISTENER_NETWORK_UNSUPPORTED_CODE: &str =
    "config.core.listener_network_unsupported";
pub const CONFIG_LISTENER_ROUTE_MISSING_CODE: &str = "config.core.listener_route_missing";
pub const CONFIG_LISTENER_ROUTE_CONFLICT_CODE: &str = "config.core.listener_route_conflict";
pub const CONFIG_NODE_ID_EMPTY_CODE: &str = "config.core.node_id_empty";
pub const CONFIG_NODE_NAME_EMPTY_CODE: &str = "config.core.node_name_empty";
pub const CONFIG_NODE_PROTOCOL_EMPTY_CODE: &str = "config.core.node_protocol_empty";
pub const CONFIG_NODE_HOST_EMPTY_CODE: &str = "config.core.node_host_empty";
pub const CONFIG_NODE_PORT_INVALID_CODE: &str = "config.core.node_port_invalid";
pub const CONFIG_ROUTE_ID_EMPTY_CODE: &str = "config.core.route_id_empty";
pub const CONFIG_ROUTE_ACTION_UNSUPPORTED_CODE: &str = "config.core.route_action_unsupported";
pub const CONFIG_ROUTE_PROXY_NODE_MISSING_CODE: &str = "config.core.route_proxy_node_missing";
pub const CONFIG_MIGRATION_UNSUPPORTED_CODE: &str = "config.core.migration_unsupported";
pub const SUBSCRIPTION_SOURCE_ID_EMPTY_CODE: &str = "subscription.core.source_id_empty";
pub const SUBSCRIPTION_LOCATION_EMPTY_CODE: &str = "subscription.core.location_empty";
pub const SUBSCRIPTION_FETCH_UNSUPPORTED_CODE: &str = "subscription.core.fetch_unsupported";
pub const SUBSCRIPTION_INLINE_PAYLOAD_EMPTY_CODE: &str = "subscription.core.inline_payload_empty";
pub const SUBSCRIPTION_PARSE_FAILED_CODE: &str = "subscription.core.parse_failed";
pub const SUBSCRIPTION_LINK_UNSUPPORTED_CODE: &str = "subscription.core.link_unsupported";
pub const SUBSCRIPTION_SHADOWSOCKS_LINK_INVALID_CODE: &str =
    "subscription.core.shadowsocks_link_invalid";
pub const SUBSCRIPTION_TROJAN_LINK_INVALID_CODE: &str = "subscription.core.trojan_link_invalid";
pub const SUBSCRIPTION_VLESS_LINK_INVALID_CODE: &str = "subscription.core.vless_link_invalid";
pub const SUBSCRIPTION_VMESS_LINK_INVALID_CODE: &str = "subscription.core.vmess_link_invalid";
pub const SUBSCRIPTION_HYSTERIA2_LINK_INVALID_CODE: &str =
    "subscription.core.hysteria2_link_invalid";
pub const SUBSCRIPTION_TUIC_LINK_INVALID_CODE: &str = "subscription.core.tuic_link_invalid";
pub const SUBSCRIPTION_IWAN_LINK_INVALID_CODE: &str = "subscription.core.iwan_link_invalid";
pub const SUBSCRIPTION_ANX_LINK_INVALID_CODE: &str = "subscription.core.anx_link_invalid";
pub const SUBSCRIPTION_WIREGUARD_LINK_INVALID_CODE: &str =
    "subscription.core.wireguard_link_invalid";
pub const SUBSCRIPTION_MIERU_LINK_INVALID_CODE: &str = "subscription.core.mieru_link_invalid";
pub const SUBSCRIPTION_HTTP_LINK_INVALID_CODE: &str = "subscription.core.http_link_invalid";
pub const SUBSCRIPTION_SOCKS_LINK_INVALID_CODE: &str = "subscription.core.socks_link_invalid";
pub const SUBSCRIPTION_CLASH_YAML_INVALID_CODE: &str = "subscription.core.clash_yaml_invalid";
pub const SUBSCRIPTION_CLASH_YAML_UNSUPPORTED_CODE: &str =
    "subscription.core.clash_yaml_unsupported";
pub const SUBSCRIPTION_SING_BOX_JSON_INVALID_CODE: &str = "subscription.core.sing_box_json_invalid";
pub const SUBSCRIPTION_SING_BOX_JSON_UNSUPPORTED_CODE: &str =
    "subscription.core.sing_box_json_unsupported";
pub const SUBSCRIPTION_QUANTUMULT_X_PROXY_LINE_INVALID_CODE: &str =
    "subscription.core.quantumult_x_proxy_line_invalid";
pub const SUBSCRIPTION_QUANTUMULT_X_PROXY_LINE_UNSUPPORTED_CODE: &str =
    "subscription.core.quantumult_x_proxy_line_unsupported";
pub const SUBSCRIPTION_LOON_PROXY_LINE_INVALID_CODE: &str =
    "subscription.core.loon_proxy_line_invalid";
pub const SUBSCRIPTION_LOON_PROXY_LINE_UNSUPPORTED_CODE: &str =
    "subscription.core.loon_proxy_line_unsupported";
pub const SUBSCRIPTION_SURGE_PROXY_LINE_INVALID_CODE: &str =
    "subscription.core.surge_proxy_line_invalid";
pub const SUBSCRIPTION_SURGE_PROXY_LINE_UNSUPPORTED_CODE: &str =
    "subscription.core.surge_proxy_line_unsupported";

#[derive(Debug, Clone, Copy, Default)]
pub struct CoreConfigurationService;

impl CoreConfigurationService {
    pub const fn new() -> Self {
        Self
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct CoreSubscriptionService;

impl CoreSubscriptionService {
    pub const fn new() -> Self {
        Self
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedConfigDocument {
    pub schema_version: SchemaVersion,
    pub profiles: Vec<String>,
    pub listeners: Vec<ListenerDescriptor>,
    pub nodes: Vec<NodeDescriptor>,
    pub routes: Vec<RuleSet>,
    /// First-class rules and policy groups, present when `rules` is set.
    pub routing: Option<RoutingModel>,
}

impl ConfigurationService for CoreConfigurationService {
    fn validate(&self, raw_config: &str, _capabilities: &PlatformCapabilities) -> Vec<Diagnostic> {
        parse_config_document(raw_config)
            .err()
            .map(domain_error_to_diagnostic)
            .into_iter()
            .collect()
    }

    fn normalize(
        &self,
        raw_config: &str,
        _capabilities: &PlatformCapabilities,
    ) -> DomainResult<ConfigSnapshot> {
        let document = parse_config_document(raw_config)?;

        Ok(ConfigSnapshot {
            version: document.schema_version,
            profiles: document.profiles,
            listeners: document.listeners,
            nodes: document.nodes,
            policies: document.routes,
            dns: Vec::new(),
            plugins: Vec::new(),
        })
    }

    fn migrate(
        &self,
        raw_config: &str,
        from_version: SchemaVersion,
        to_version: SchemaVersion,
    ) -> DomainResult<String> {
        if from_version == to_version {
            return Ok(raw_config.to_string());
        }

        Err(domain_error(
            CONFIG_MIGRATION_UNSUPPORTED_CODE,
            "configuration migration is not supported by the minimal config service",
        ))
    }
}

impl SubscriptionService for CoreSubscriptionService {
    fn fetch(&self, source: &SubscriptionSource) -> DomainResult<RawSubscription> {
        let source_id = required_trimmed(
            source.id.clone(),
            SUBSCRIPTION_SOURCE_ID_EMPTY_CODE,
            "subscription source id cannot be empty",
        )?;
        let location = required_trimmed(
            source.location.clone(),
            SUBSCRIPTION_LOCATION_EMPTY_CODE,
            "subscription source location cannot be empty",
        )?;

        let Some(content) = location.strip_prefix("inline:") else {
            return Err(domain_error(
                SUBSCRIPTION_FETCH_UNSUPPORTED_CODE,
                "subscription source location is unsupported by the pure subscription service",
            ));
        };

        if content.trim().is_empty() {
            return Err(domain_error(
                SUBSCRIPTION_INLINE_PAYLOAD_EMPTY_CODE,
                "inline subscription payload cannot be empty",
            ));
        }

        Ok(RawSubscription {
            source_id,
            content: content.to_string(),
        })
    }

    fn parse(&self, raw_subscription: &RawSubscription) -> DomainResult<SubscriptionDocument> {
        let source_id = required_trimmed(
            raw_subscription.source_id.clone(),
            SUBSCRIPTION_SOURCE_ID_EMPTY_CODE,
            "subscription source id cannot be empty",
        )?;

        if let Ok(raw) = toml::from_str::<RawSubscriptionDocument>(&raw_subscription.content) {
            return Ok(SubscriptionDocument {
                nodes: collect_nodes(raw.nodes.unwrap_or_default())?,
                rules: collect_routes(raw.routes.unwrap_or_default())?,
                diagnostics: Vec::new(),
            });
        }

        if let Some(document) =
            parse_sing_box_json_subscription(&source_id, &raw_subscription.content)?
        {
            return Ok(document);
        }

        if let Some(document) =
            parse_clash_yaml_subscription(&source_id, &raw_subscription.content)?
        {
            return Ok(document);
        }

        if let Some(document) =
            parse_quantumult_x_proxy_line_subscription(&source_id, &raw_subscription.content)?
        {
            return Ok(document);
        }

        if let Some(document) =
            parse_loon_proxy_line_subscription(&source_id, &raw_subscription.content)?
        {
            return Ok(document);
        }

        if let Some(document) =
            parse_surge_proxy_line_subscription(&source_id, &raw_subscription.content)?
        {
            return Ok(document);
        }

        if let Some(document) = parse_link_subscription(&source_id, &raw_subscription.content)? {
            return Ok(document);
        }

        Err(domain_error(
            SUBSCRIPTION_PARSE_FAILED_CODE,
            "subscription payload could not be parsed as NetworkCore TOML, Clash YAML, sing-box JSON, Quantumult X proxy lines, Loon proxy lines, Surge proxy lines, or supported proxy links",
        ))
    }

    fn normalize(&self, document: &SubscriptionDocument) -> DomainResult<NodeCatalog> {
        Ok(NodeCatalog {
            nodes: document.nodes.clone(),
            rules: document.rules.clone(),
        })
    }
}

/// The built-in policy a proxy entry of type `kind` stands for: `DIRECT`,
/// or `REJECT` and its variants (as [`routing::RejectKind`] names them).
/// Surge, Loon, Quantumult X and Clash list these beside their nodes (Surge's
/// `DIRECT = direct`, an alias such as `Home = direct, interface=en0`, a
/// Clash `type: direct` proxy); they are policies, not nodes, so importing
/// skips them without a warning and rules may still name them.
pub(crate) fn builtin_policy(kind: &str) -> Option<&'static str> {
    let kind = kind.trim();
    if kind.eq_ignore_ascii_case("direct") {
        return Some("DIRECT");
    }
    let upper = kind.to_ascii_uppercase();
    if upper == "REJECT" || upper.starts_with("REJECT-") {
        return Some(routing::RejectKind::parse(kind).unwrap_or_default().name());
    }
    None
}

/// A Surge or Loon `[Proxy]` line that declares a built-in policy
/// (`Name = direct`, `Name = reject-drop`, ...): its name, the policy, and
/// whether the line sets options (such as `interface=`) beyond the type.
pub(crate) fn proxy_line_builtin_policy(line: &str) -> Option<(&str, &'static str, bool)> {
    let (name, definition) = line.split_once('=')?;
    let name = name.trim();
    if name.is_empty() {
        return None;
    }
    let mut parts = definition.split(',');
    let policy = builtin_policy(parts.next()?)?;
    let has_options = parts.any(|part| !part.trim().is_empty());
    Some((name, policy, has_options))
}

fn parse_link_subscription(
    source_id: &str,
    content: &str,
) -> DomainResult<Option<SubscriptionDocument>> {
    let content = content.trim();
    if content.is_empty() {
        return Ok(None);
    }

    if content.starts_with("ss://") || content.lines().any(|line| line.trim().contains("://")) {
        return parse_proxy_link_lines(source_id, content).map(Some);
    }

    if let Some(decoded) = decode_base64_text(content) {
        let decoded = decoded.trim();
        if decoded.lines().any(|line| line.trim().contains("://")) {
            return parse_proxy_link_lines(source_id, decoded).map(Some);
        }
    }

    Ok(None)
}

fn decode_base64_text(value: &str) -> Option<String> {
    let compact = value.split_whitespace().collect::<String>();
    let bytes = STANDARD
        .decode(compact.as_bytes())
        .or_else(|_| STANDARD_NO_PAD.decode(compact.as_bytes()))
        .or_else(|_| URL_SAFE.decode(compact.as_bytes()))
        .or_else(|_| URL_SAFE_NO_PAD.decode(compact.as_bytes()))
        .ok()?;

    String::from_utf8(bytes).ok()
}

fn percent_decode(value: &str) -> Result<String, ()> {
    let bytes = value.as_bytes();
    let mut output = Vec::with_capacity(bytes.len());
    let mut index = 0;

    while index < bytes.len() {
        if bytes[index] == b'%' {
            let hi = bytes.get(index + 1).and_then(|byte| hex_value(*byte));
            let lo = bytes.get(index + 2).and_then(|byte| hex_value(*byte));
            match (hi, lo) {
                (Some(hi), Some(lo)) => {
                    output.push((hi << 4) | lo);
                    index += 3;
                    continue;
                }
                _ => return Err(()),
            }
        }

        output.push(bytes[index]);
        index += 1;
    }

    String::from_utf8(output).map_err(|_| ())
}

fn required_json_text_field(
    value: &serde_json::Value,
    field: &'static str,
    code: &'static str,
    message: &'static str,
) -> DomainResult<String> {
    let Some(raw) = value.get(field) else {
        return Err(domain_error(code, message));
    };
    let text = match raw {
        serde_json::Value::String(value) => value.clone(),
        serde_json::Value::Number(value) => value.to_string(),
        _ => return Err(domain_error(code, message)),
    };

    required_trimmed(text, code, message)
}

fn optional_json_text_field(value: &serde_json::Value, field: &'static str) -> Option<String> {
    let text = match value.get(field)? {
        serde_json::Value::String(value) => value.clone(),
        serde_json::Value::Number(value) => value.to_string(),
        _ => return None,
    };
    let text = text.trim().to_string();
    if text.is_empty() {
        None
    } else {
        Some(text)
    }
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn split_once_optional(value: &str, separator: char) -> (&str, Option<&str>) {
    value
        .split_once(separator)
        .map(|(left, right)| (left, Some(right)))
        .unwrap_or((value, None))
}

fn sanitize_identifier(value: &str) -> String {
    let sanitized = value
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() {
                character.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect::<String>();
    sanitized.trim_matches('-').to_string()
}

fn parse_protocol(raw: String) -> DomainResult<Protocol> {
    let protocol = required_trimmed(
        raw,
        CONFIG_NODE_PROTOCOL_EMPTY_CODE,
        "node protocol cannot be empty",
    )?;

    Ok(match normalized_token(&protocol).as_str() {
        "http" => Protocol::Http,
        "socks" => Protocol::Socks,
        "shadowsocks" => Protocol::Shadowsocks,
        "vmess" => Protocol::Vmess,
        "vless" => Protocol::Vless,
        "trojan" => Protocol::Trojan,
        "hysteria" => Protocol::Hysteria,
        "hysteria2" | "hy2" => Protocol::Hysteria2,
        "tuic" => Protocol::Tuic,
        "wireguard" => Protocol::WireGuard,
        "snell" => Protocol::Snell,
        "iwan" => Protocol::Iwan,
        "anx" => Protocol::Anx,
        _ => Protocol::Other(protocol),
    })
}

fn domain_error(code: impl Into<String>, message: impl Into<String>) -> DomainError {
    DomainError::new(code, message)
}

fn domain_error_to_diagnostic(error: DomainError) -> Diagnostic {
    Diagnostic::new(
        DiagnosticSeverity::Error,
        error.code,
        error.message,
        Some(SOURCE_CONFIG_CORE.to_string()),
    )
}
