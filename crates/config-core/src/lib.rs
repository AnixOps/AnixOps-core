//! Pure configuration service for NetworkCore.
//!
//! This crate parses and normalizes the first minimal TOML configuration shape.
//! It performs no file I/O, network access, platform probing, or engine work.

pub mod certificate_pin;
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
    NODE_METADATA_SHADOWSOCKS_METHOD, NODE_METADATA_SHADOWSOCKS_PASSWORD,
    NODE_METADATA_SHADOWSOCKS_PLUGIN, NODE_METADATA_SNELL_MODE, NODE_METADATA_SNELL_OBFS,
    NODE_METADATA_SNELL_OBFS_HOST, NODE_METADATA_SNELL_OBFS_URI, NODE_METADATA_SNELL_PSK,
    NODE_METADATA_SNELL_REUSE, NODE_METADATA_SNELL_USER_KEY, NODE_METADATA_SNELL_VERSION,
    NODE_METADATA_SOURCE_FORMAT, NODE_METADATA_TLS_ALPN,
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
    NODE_UNSUPPORTED_OPTION_HTTP_OBFS, NODE_UNSUPPORTED_OPTION_TRANSPORT,
    NODE_UNSUPPORTED_OPTION_XHTTP,
};
use routing::{NetworkRuleSpec, PolicyGroupSpec, RoutingModel, RoutingSpec};
use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};

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

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawConfigDocument {
    schema_version: Option<u32>,
    profile: Option<String>,
    profiles: Option<Vec<String>>,
    listeners: Option<Vec<RawListener>>,
    nodes: Option<Vec<RawNode>>,
    routes: Option<Vec<RawRoute>>,
    rules: Option<Vec<String>>,
    policy_groups: Option<Vec<RawPolicyGroup>>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawPolicyGroup {
    id: String,
    #[serde(rename = "type")]
    kind: String,
    /// Absent for a subnet group.
    #[serde(default)]
    members: Vec<String>,
    default: Option<String>,
    url: Option<String>,
    interval_secs: Option<u32>,
    tolerance_ms: Option<u16>,
    evaluate_before_use: Option<bool>,
    network_rules: Option<Vec<RawNetworkRule>>,
}

/// One subnet group rule: `{"when": "SSID:Home", "target": "DIRECT"}`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawNetworkRule {
    when: String,
    target: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawSubscriptionDocument {
    nodes: Option<Vec<RawNode>>,
    routes: Option<Vec<RawRoute>>,
}

#[derive(Debug, Deserialize)]
struct RawClashDocument {
    /// Each entry is read into [`RawClashProxy`] on its own, so one entry
    /// with a field of an unexpected type is skipped instead of hiding the
    /// whole list.
    proxies: Option<Vec<serde_json::Value>>,
}

#[derive(Debug, Deserialize)]
struct RawClashProxy {
    name: Option<RawClashScalar>,
    #[serde(rename = "type")]
    protocol: Option<RawClashScalar>,
    server: Option<RawClashScalar>,
    port: Option<RawClashScalar>,
    cipher: Option<RawClashScalar>,
    password: Option<RawClashScalar>,
    uuid: Option<RawClashScalar>,
    encryption: Option<RawClashScalar>,
    psk: Option<RawClashScalar>,
    version: Option<RawClashScalar>,
    #[serde(rename = "obfs-opts")]
    obfs_opts: Option<RawClashSnellObfs>,
    username: Option<RawClashScalar>,
    transport: Option<RawClashScalar>,
    multiplexing: Option<RawClashScalar>,
    #[serde(rename = "port-range")]
    port_range: Option<RawClashScalar>,
    /// sing-mux client multiplexing (mihomo).
    smux: Option<serde_json::Value>,
    /// Certificate pin (mihomo): SHA-256 of the server's certificate in hex.
    /// The uTLS fingerprint is `client-fingerprint`.
    fingerprint: Option<RawClashScalar>,
    /// TLS, REALITY and transport options of vmess, vless and trojan.
    #[serde(flatten)]
    stream: RawClashStreamOptions,
    /// VLESS flow (`xtls-rprx-vision`).
    flow: Option<serde_json::Value>,
    #[serde(rename = "alterId", alias = "alter-id")]
    alter_id: Option<serde_json::Value>,
    /// Shadowsocks SIP003 plugin (`obfs`, `v2ray-plugin`, `shadow-tls`, ...);
    /// its `plugin-opts` are not read, they can hold passwords.
    plugin: Option<serde_json::Value>,
}

/// TLS, REALITY and transport options of a Clash vmess, vless or trojan
/// proxy. YAML gives booleans, lists and maps here, so they are kept as JSON
/// values (see [`clash_stream_options`]) and a value of an unexpected shape
/// is reported for this proxy instead of failing the entry's whole read.
#[derive(Debug, Default, Deserialize)]
struct RawClashStreamOptions {
    tls: Option<serde_json::Value>,
    servername: Option<serde_json::Value>,
    sni: Option<serde_json::Value>,
    #[serde(rename = "skip-cert-verify")]
    skip_cert_verify: Option<serde_json::Value>,
    alpn: Option<serde_json::Value>,
    /// uTLS fingerprint name (`chrome`, `safari`, ...).
    #[serde(rename = "client-fingerprint")]
    client_fingerprint: Option<serde_json::Value>,
    network: Option<serde_json::Value>,
    #[serde(rename = "ws-opts")]
    ws_opts: Option<serde_json::Value>,
    #[serde(rename = "grpc-opts")]
    grpc_opts: Option<serde_json::Value>,
    #[serde(rename = "h2-opts")]
    h2_opts: Option<serde_json::Value>,
    #[serde(rename = "xhttp-opts")]
    xhttp_opts: Option<serde_json::Value>,
    #[serde(rename = "reality-opts")]
    reality_opts: Option<serde_json::Value>,
    #[serde(rename = "ech-opts")]
    ech_opts: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
struct RawClashSnellObfs {
    mode: Option<RawClashScalar>,
    host: Option<RawClashScalar>,
}

#[derive(Debug, Deserialize)]
struct RawSingBoxDocument {
    /// Each entry is read into [`RawSingBoxOutbound`] on its own, so one
    /// outbound with a field of an unexpected type is skipped instead of
    /// hiding the whole list.
    outbounds: Option<Vec<serde_json::Value>>,
}

#[derive(Debug, Deserialize)]
struct RawSingBoxOutbound {
    #[serde(rename = "type")]
    protocol: Option<RawSingBoxScalar>,
    tag: Option<RawSingBoxScalar>,
    server: Option<RawSingBoxScalar>,
    server_port: Option<RawSingBoxScalar>,
    server_ports: Option<RawSingBoxStringList>,
    method: Option<RawSingBoxScalar>,
    password: Option<RawSingBoxScalar>,
    uuid: Option<RawSingBoxScalar>,
    flow: Option<RawSingBoxScalar>,
    security: Option<RawSingBoxScalar>,
    alter_id: Option<RawSingBoxScalar>,
    congestion_control: Option<RawSingBoxScalar>,
    obfs: Option<RawSingBoxHysteria2Obfs>,
    tls: Option<RawSingBoxTls>,
    transport: Option<RawSingBoxTransport>,
    /// The tag of the outbound this one dials through (a proxy chain).
    detour: Option<RawSingBoxScalar>,
    /// sing-mux client multiplexing.
    multiplex: Option<serde_json::Value>,
    /// iWAN (an AnixOps extension; sing-box has no such type).
    username: Option<RawSingBoxScalar>,
    mtu: Option<RawSingBoxScalar>,
    encrypt: Option<bool>,
    /// Shadowsocks SIP003 plugin (`obfs-local`, `v2ray-plugin`); its
    /// `plugin_opts` are not read, they can hold passwords.
    plugin: Option<RawSingBoxScalar>,
}

#[derive(Debug, Deserialize)]
struct RawSingBoxHysteria2Obfs {
    #[serde(rename = "type")]
    kind: Option<RawSingBoxScalar>,
    password: Option<RawSingBoxScalar>,
    min_packet_size: Option<RawSingBoxScalar>,
    max_packet_size: Option<RawSingBoxScalar>,
}

#[derive(Debug, Deserialize)]
struct RawSingBoxTls {
    enabled: Option<bool>,
    server_name: Option<RawSingBoxScalar>,
    insecure: Option<bool>,
    alpn: Option<RawSingBoxStringList>,
    /// SHA-256 of the whole leaf certificate, base64 (sing-box 1.15).
    certificate_sha256: Option<RawSingBoxStringList>,
    /// SHA-256 of the leaf certificate's SubjectPublicKeyInfo, base64.
    certificate_public_key_sha256: Option<RawSingBoxStringList>,
    utls: Option<RawSingBoxUtls>,
    reality: Option<RawSingBoxReality>,
}

#[derive(Debug, Deserialize)]
struct RawSingBoxUtls {
    enabled: Option<bool>,
    fingerprint: Option<RawSingBoxScalar>,
}

#[derive(Debug, Deserialize)]
struct RawSingBoxReality {
    enabled: Option<bool>,
    public_key: Option<RawSingBoxScalar>,
    short_id: Option<RawSingBoxScalar>,
}

#[derive(Debug, Deserialize)]
struct RawSingBoxTransport {
    #[serde(rename = "type")]
    kind: Option<RawSingBoxScalar>,
    host: Option<RawSingBoxStringList>,
    path: Option<RawSingBoxScalar>,
    service_name: Option<RawSingBoxScalar>,
    headers: Option<RawSingBoxTransportHeaders>,
}

#[derive(Debug, Deserialize)]
struct RawSingBoxTransportHeaders {
    #[serde(rename = "Host")]
    host: Option<RawSingBoxStringList>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum RawClashScalar {
    Text(String),
    Integer(i64),
}

impl RawClashScalar {
    fn into_text(self) -> String {
        match self {
            Self::Text(value) => value,
            Self::Integer(value) => value.to_string(),
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum RawSingBoxScalar {
    Text(String),
    Integer(i64),
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum RawSingBoxStringList {
    Text(String),
    Values(Vec<String>),
}

impl RawSingBoxScalar {
    fn into_text(self) -> String {
        match self {
            Self::Text(value) => value,
            Self::Integer(value) => value.to_string(),
        }
    }
}

impl RawSingBoxStringList {
    fn into_values(self) -> Vec<String> {
        match self {
            Self::Text(value) => vec![value],
            Self::Values(values) => values,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawListener {
    id: String,
    enabled: Option<bool>,
    kind: String,
    bind_host: String,
    bind_port: i64,
    network: String,
    route: Option<String>,
    route_action: Option<String>,
    route_node: Option<String>,
    tags: Option<Vec<String>>,
    metadata: Option<BTreeMap<String, String>>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawNode {
    id: String,
    name: Option<String>,
    protocol: String,
    host: String,
    port: i64,
    tags: Option<Vec<String>>,
    metadata: Option<BTreeMap<String, String>>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRoute {
    id: String,
    default_action: String,
    default_node: Option<String>,
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

pub fn parse_config_document(raw_config: &str) -> DomainResult<ParsedConfigDocument> {
    let raw = toml::from_str::<RawConfigDocument>(raw_config).map_err(|_| {
        domain_error(
            CONFIG_PARSE_FAILED_CODE,
            "configuration could not be parsed as NetworkCore TOML",
        )
    })?;

    let schema_version = raw.schema_version.unwrap_or(CURRENT_SCHEMA_VERSION);
    if schema_version != CURRENT_SCHEMA_VERSION {
        return Err(domain_error(
            CONFIG_SCHEMA_UNSUPPORTED_CODE,
            "configuration schema version is unsupported",
        ));
    }

    let profiles = collect_profiles(raw.profile, raw.profiles)?;
    let listeners = collect_listeners(raw.listeners.unwrap_or_default())?;
    let nodes = collect_nodes(raw.nodes.unwrap_or_default())?;
    let routes = collect_routes(raw.routes.unwrap_or_default())?;
    let routing = collect_routing(raw.rules, raw.policy_groups, &nodes)?;

    Ok(ParsedConfigDocument {
        schema_version: SchemaVersion::new(schema_version),
        profiles,
        listeners,
        nodes,
        routes,
        routing,
    })
}

fn collect_routing(
    rules: Option<Vec<String>>,
    policy_groups: Option<Vec<RawPolicyGroup>>,
    nodes: &[NodeDescriptor],
) -> DomainResult<Option<RoutingModel>> {
    if rules.is_none() && policy_groups.is_none() {
        return Ok(None);
    }
    let spec = RoutingSpec {
        rules: rules.unwrap_or_default(),
        groups: policy_groups
            .unwrap_or_default()
            .into_iter()
            .map(|group| PolicyGroupSpec {
                id: group.id,
                kind: group.kind,
                members: group.members,
                default: group.default,
                url: group.url,
                interval_secs: group.interval_secs,
                tolerance_ms: group.tolerance_ms,
                evaluate_before_use: group.evaluate_before_use.unwrap_or(false),
                network_rules: group
                    .network_rules
                    .unwrap_or_default()
                    .into_iter()
                    .map(|rule| NetworkRuleSpec {
                        when: rule.when,
                        target: rule.target,
                    })
                    .collect(),
            })
            .collect(),
    };
    let node_ids = nodes
        .iter()
        .map(|node| node.id.clone())
        .collect::<BTreeSet<_>>();
    RoutingModel::from_spec(&spec, &node_ids).map(Some)
}

fn collect_profiles(
    profile: Option<String>,
    profiles: Option<Vec<String>>,
) -> DomainResult<Vec<String>> {
    let profiles = match (profile, profiles) {
        (Some(_), Some(_)) => {
            return Err(domain_error(
                CONFIG_PROFILE_CONFLICT_CODE,
                "configuration must use either profile or profiles",
            ));
        }
        (Some(profile), None) => vec![profile],
        (None, Some(profiles)) => profiles,
        (None, None) => {
            return Err(domain_error(
                CONFIG_PROFILE_MISSING_CODE,
                "configuration must define at least one profile",
            ));
        }
    };

    if profiles.is_empty() {
        return Err(domain_error(
            CONFIG_PROFILE_MISSING_CODE,
            "configuration must define at least one profile",
        ));
    }

    let profiles = profiles
        .into_iter()
        .map(|profile| profile.trim().to_string())
        .collect::<Vec<_>>();

    if profiles.iter().any(String::is_empty) {
        return Err(domain_error(
            CONFIG_PROFILE_EMPTY_CODE,
            "configuration profiles cannot be empty",
        ));
    }

    Ok(profiles)
}

fn collect_listeners(raw_listeners: Vec<RawListener>) -> DomainResult<Vec<ListenerDescriptor>> {
    raw_listeners
        .into_iter()
        .map(normalize_listener)
        .collect::<DomainResult<Vec<_>>>()
}

fn normalize_listener(raw: RawListener) -> DomainResult<ListenerDescriptor> {
    let id = required_trimmed(
        raw.id,
        CONFIG_LISTENER_ID_EMPTY_CODE,
        "listener id cannot be empty",
    )?;
    let kind = parse_listener_kind(raw.kind)?;
    let bind_host = required_trimmed(
        raw.bind_host,
        CONFIG_LISTENER_BIND_HOST_EMPTY_CODE,
        "listener bind host cannot be empty",
    )?;
    let bind_port = parse_port(
        raw.bind_port,
        CONFIG_LISTENER_BIND_PORT_INVALID_CODE,
        "listener bind port must be between 1 and 65535",
    )?;

    Ok(ListenerDescriptor {
        id,
        enabled: raw.enabled.unwrap_or(true),
        kind,
        bind: ListenerBind {
            host: bind_host,
            port: bind_port,
        },
        network: parse_listener_network(raw.network)?,
        route: parse_listener_route(raw.route, raw.route_action, raw.route_node)?,
        tags: collect_tags(raw.tags),
        metadata: collect_metadata(raw.metadata),
    })
}

fn parse_listener_kind(raw: String) -> DomainResult<ListenerKind> {
    let kind = required_trimmed(
        raw,
        CONFIG_LISTENER_KIND_EMPTY_CODE,
        "listener kind cannot be empty",
    )?;

    Ok(match normalized_token(&kind).as_str() {
        "local_tcp" => ListenerKind::LocalTcp,
        "socks" => ListenerKind::Socks,
        "http" => ListenerKind::Http,
        "tun" => ListenerKind::Tun,
        _ => ListenerKind::Other(kind),
    })
}

fn parse_listener_network(raw: String) -> DomainResult<ListenerNetwork> {
    match normalized_token(&raw).as_str() {
        "tcp" => Ok(ListenerNetwork::Tcp),
        "udp" => Ok(ListenerNetwork::Udp),
        "tcp_udp" => Ok(ListenerNetwork::TcpUdp),
        _ => Err(domain_error(
            CONFIG_LISTENER_NETWORK_UNSUPPORTED_CODE,
            "listener network must be tcp, udp, or tcp_udp",
        )),
    }
}

fn parse_listener_route(
    route: Option<String>,
    route_action: Option<String>,
    route_node: Option<String>,
) -> DomainResult<ListenerRoute> {
    match (route, route_action) {
        (Some(route), None) => Ok(ListenerRoute::RuleSet {
            rule_set_id: required_trimmed(
                route,
                CONFIG_LISTENER_ROUTE_MISSING_CODE,
                "listener route cannot be empty",
            )?,
        }),
        (None, Some(action)) => Ok(ListenerRoute::DefaultAction(parse_route_action(
            action, route_node,
        )?)),
        (Some(_), Some(_)) => Err(domain_error(
            CONFIG_LISTENER_ROUTE_CONFLICT_CODE,
            "listener must use either route or route_action",
        )),
        (None, None) => Err(domain_error(
            CONFIG_LISTENER_ROUTE_MISSING_CODE,
            "listener must define route or route_action",
        )),
    }
}

fn collect_nodes(raw_nodes: Vec<RawNode>) -> DomainResult<Vec<NodeDescriptor>> {
    raw_nodes
        .into_iter()
        .map(normalize_node)
        .collect::<DomainResult<Vec<_>>>()
}

fn normalize_node(raw: RawNode) -> DomainResult<NodeDescriptor> {
    let id = required_trimmed(raw.id, CONFIG_NODE_ID_EMPTY_CODE, "node id cannot be empty")?;
    let name = match raw.name {
        Some(name) => required_trimmed(
            name,
            CONFIG_NODE_NAME_EMPTY_CODE,
            "node name cannot be empty",
        )?,
        None => id.clone(),
    };
    let host = required_trimmed(
        raw.host,
        CONFIG_NODE_HOST_EMPTY_CODE,
        "node host cannot be empty",
    )?;
    let port = parse_port(
        raw.port,
        CONFIG_NODE_PORT_INVALID_CODE,
        "node port must be between 1 and 65535",
    )?;

    Ok(NodeDescriptor {
        id,
        name,
        protocol: parse_protocol(raw.protocol)?,
        endpoint: Endpoint { host, port },
        tags: collect_tags(raw.tags),
        metadata: collect_metadata(raw.metadata),
    })
}

/// Bad entries one subscription format left out, so the entries around them
/// still import. Each becomes a warning [`Diagnostic`] with the entry's own
/// error code; the first error is what [`SkippedEntries::finish`] returns
/// when no entry could be imported at all.
struct SkippedEntries {
    /// How the format calls one entry (`clash proxy`, `share link`, ...).
    entry: &'static str,
    diagnostics: Vec<Diagnostic>,
    first_error: Option<DomainError>,
}

/// Longest entry name a skip warning repeats.
const MAX_SKIPPED_ENTRY_NAME_CHARS: usize = 64;
/// Longest entry type a skip warning repeats.
const MAX_SKIPPED_ENTRY_KIND_LEN: usize = 32;

impl SkippedEntries {
    fn new(entry: &'static str) -> Self {
        Self {
            entry,
            diagnostics: Vec::new(),
            first_error: None,
        }
    }

    /// Records that entry `index` (counted from 0) was left out. The warning
    /// names the entry by its position, and by its declared name and type
    /// when they look like labels, with the error's fixed reason; never by
    /// the entry's text, which holds its credentials.
    fn skip(&mut self, index: usize, name: Option<&str>, kind: Option<&str>, error: DomainError) {
        let position = index + 1;
        let name = name.map(str::trim).filter(|name| is_entry_label(name));
        let kind = kind.map(str::trim).filter(|kind| is_entry_kind(kind));
        let entry = match (name, kind) {
            (Some(name), Some(kind)) => format!("{} {position} ({name}, type {kind})", self.entry),
            (Some(name), None) => format!("{} {position} ({name})", self.entry),
            (None, Some(kind)) => format!("{} {position} (type {kind})", self.entry),
            (None, None) => format!("{} {position}", self.entry),
        };
        self.diagnostics.push(Diagnostic::new(
            DiagnosticSeverity::Warning,
            error.code.clone(),
            format!("{entry} was skipped: {}", error.message),
            Some(SOURCE_SUBSCRIPTION_CORE.to_string()),
        ));
        if self.first_error.is_none() {
            self.first_error = Some(error);
        }
    }

    /// The document of the imported `nodes` with a warning per skipped
    /// entry, or, when there are none, the first skipped entry's error
    /// (`none_imported` when no entry failed, as when every entry was a
    /// built-in policy).
    fn finish(
        self,
        nodes: Vec<NodeDescriptor>,
        none_imported: impl FnOnce() -> DomainError,
    ) -> DomainResult<SubscriptionDocument> {
        if nodes.is_empty() {
            return Err(self.first_error.unwrap_or_else(none_imported));
        }
        Ok(SubscriptionDocument {
            nodes,
            rules: Vec::new(),
            diagnostics: self.diagnostics,
        })
    }
}

/// Whether an entry's declared name can be repeated in a warning: short,
/// one line, and not shaped like a link or credentials.
fn is_entry_label(name: &str) -> bool {
    !name.is_empty()
        && name.chars().count() <= MAX_SKIPPED_ENTRY_NAME_CHARS
        && !name.contains("://")
        && !name.contains('@')
        && !name.chars().any(char::is_control)
}

/// Whether an entry's type can be repeated in a warning: one short word.
fn is_entry_kind(kind: &str) -> bool {
    !kind.is_empty()
        && kind.len() <= MAX_SKIPPED_ENTRY_KIND_LEN
        && kind
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

/// Adds `node` to `nodes`, renaming its id with a `-<n>` suffix when an
/// earlier node took it.
fn push_unique_node(
    nodes: &mut Vec<NodeDescriptor>,
    seen_ids: &mut BTreeSet<String>,
    mut node: NodeDescriptor,
) {
    if !seen_ids.insert(node.id.clone()) {
        let base_id = node.id.clone();
        let mut suffix = seen_ids.len() + 1;
        loop {
            node.id = format!("{base_id}-{suffix}");
            if seen_ids.insert(node.id.clone()) {
                break;
            }
            suffix += 1;
        }
    }
    nodes.push(node);
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

fn parse_clash_yaml_subscription(
    source_id: &str,
    content: &str,
) -> DomainResult<Option<SubscriptionDocument>> {
    let content = content.trim();
    if content.is_empty() {
        return Ok(None);
    }

    let raw = match serde_saphyr::from_str::<RawClashDocument>(content) {
        Ok(raw) => raw,
        Err(_) => return Ok(None),
    };
    let Some(proxies) = raw.proxies else {
        return Ok(None);
    };
    if proxies.is_empty() {
        return Err(domain_error(
            SUBSCRIPTION_CLASH_YAML_INVALID_CODE,
            "clash yaml proxies cannot be empty",
        ));
    }

    let mut nodes = Vec::new();
    let mut seen_ids = BTreeSet::new();
    let mut skipped = SkippedEntries::new("clash proxy");
    // Whether any entry reads as a Clash proxy; when none does, the text is
    // not a Clash document and the next format gets it.
    let mut readable = false;
    for (index, value) in proxies.into_iter().enumerate() {
        let name = value
            .get("name")
            .and_then(serde_json::Value::as_str)
            .map(str::to_string);
        let kind = value
            .get("type")
            .and_then(serde_json::Value::as_str)
            .map(str::to_string);
        if kind.as_deref().is_some_and(is_clash_builtin_proxy_type) {
            readable = true;
            continue;
        }
        let raw = match serde_json::from_value::<RawClashProxy>(value) {
            Ok(raw) => raw,
            Err(_) => {
                skipped.skip(
                    index,
                    name.as_deref(),
                    kind.as_deref(),
                    domain_error(
                        SUBSCRIPTION_CLASH_YAML_INVALID_CODE,
                        "clash proxy fields have unexpected types",
                    ),
                );
                continue;
            }
        };
        readable = true;
        match parse_clash_proxy(raw, source_id) {
            Ok(node) => push_unique_node(&mut nodes, &mut seen_ids, node),
            Err(error) => skipped.skip(index, name.as_deref(), kind.as_deref(), error),
        }
    }
    if !readable {
        return Ok(None);
    }

    skipped
        .finish(nodes, || {
            domain_error(
                SUBSCRIPTION_CLASH_YAML_UNSUPPORTED_CODE,
                "clash yaml proxies must contain at least one supported proxy",
            )
        })
        .map(Some)
}

/// Clash proxy types that are policies rather than nodes (mihomo's
/// `direct`, `reject`, `reject-drop`, `dns`).
fn is_clash_builtin_proxy_type(kind: &str) -> bool {
    builtin_policy(kind).is_some() || kind.trim().eq_ignore_ascii_case("dns")
}

fn parse_clash_proxy(mut raw: RawClashProxy, source_id: &str) -> DomainResult<NodeDescriptor> {
    let text = |value: Option<RawClashScalar>| {
        value
            .map(RawClashScalar::into_text)
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
    };
    let name = required_clash_scalar_field(raw.name, "clash proxy name cannot be empty")?;
    let protocol = required_clash_scalar_field(raw.protocol, "clash proxy type cannot be empty")?;
    let host = required_clash_scalar_field(raw.server, "clash proxy server cannot be empty")?;
    // Mieru entries may give only `port-range`; its first port is the endpoint.
    let port_range = text(raw.port_range.take());
    let port = match (
        raw.port,
        port_range
            .as_deref()
            .and_then(|range| range.split_once('-')),
    ) {
        (None, Some((low, _))) => low.trim().to_string(),
        (port, _) => required_clash_scalar_field(port, "clash proxy port cannot be empty")?,
    };
    let port = port.parse::<i64>().map_err(|_| {
        domain_error(
            SUBSCRIPTION_CLASH_YAML_INVALID_CODE,
            "clash proxy port must be a number",
        )
    })?;
    let port = parse_port(
        port,
        SUBSCRIPTION_CLASH_YAML_INVALID_CODE,
        "clash proxy port must be between 1 and 65535",
    )?;

    let protocol_token = normalized_token(&protocol);
    let (protocol, protocol_tag, mut metadata) = match protocol_token.as_str() {
        "ss" | "shadowsocks" => {
            let method = required_clash_scalar_field(
                raw.cipher,
                "clash shadowsocks cipher cannot be empty",
            )?;
            let password = required_clash_scalar_field(
                raw.password,
                "clash shadowsocks password cannot be empty",
            )?;
            let mut metadata = vec![
                MetadataEntry {
                    key: NODE_METADATA_SHADOWSOCKS_METHOD.to_string(),
                    value: method,
                },
                MetadataEntry {
                    key: NODE_METADATA_SHADOWSOCKS_PASSWORD.to_string(),
                    value: password,
                },
            ];
            metadata.extend(shadowsocks_plugin_entry(clash_option_text(
                raw.plugin.as_ref(),
            )));
            (Protocol::Shadowsocks, "ss", metadata)
        }
        "trojan" => {
            let password =
                required_clash_scalar_field(raw.password, "clash trojan password cannot be empty")?;
            (
                Protocol::Trojan,
                "trojan",
                vec![MetadataEntry {
                    key: NODE_METADATA_TROJAN_PASSWORD.to_string(),
                    value: password,
                }],
            )
        }
        "vless" => {
            let uuid = required_clash_scalar_field(raw.uuid, "clash vless uuid cannot be empty")?;
            let mut metadata = vec![MetadataEntry {
                key: NODE_METADATA_VLESS_UUID.to_string(),
                value: uuid,
            }];
            if let Some(encryption) = raw
                .encryption
                .map(|raw| raw.into_text().trim().to_string())
                .filter(|value| !value.is_empty() && value != "none")
            {
                metadata.push(MetadataEntry {
                    key: NODE_METADATA_VLESS_ENCRYPTION.to_string(),
                    value: encryption,
                });
            }
            if let Some(flow) = clash_option_text(raw.flow.as_ref()) {
                metadata.push(MetadataEntry {
                    key: NODE_METADATA_VLESS_FLOW.to_string(),
                    value: flow,
                });
            }
            (Protocol::Vless, "vless", metadata)
        }
        "vmess" => {
            let uuid = required_clash_scalar_field(raw.uuid, "clash vmess uuid cannot be empty")?;
            let mut metadata = vec![MetadataEntry {
                key: NODE_METADATA_VMESS_UUID.to_string(),
                value: uuid,
            }];
            metadata.extend(proxy_vmess_security(text(raw.cipher)));
            if let Some(alter_id) = clash_option_text(raw.alter_id.as_ref()) {
                metadata.push(MetadataEntry {
                    key: NODE_METADATA_VMESS_ALTER_ID.to_string(),
                    value: alter_id,
                });
            }
            (Protocol::Vmess, "vmess", metadata)
        }
        "snell" => {
            let psk = required_clash_scalar_field(raw.psk, "clash snell psk cannot be empty")?;
            let obfs = raw.obfs_opts.unwrap_or(RawClashSnellObfs {
                mode: None,
                host: None,
            });
            (
                Protocol::Snell,
                "snell",
                snell_metadata(SnellFields {
                    psk,
                    version: text(raw.version),
                    mode: None,
                    obfs: text(obfs.mode),
                    obfs_host: text(obfs.host),
                    obfs_uri: None,
                    reuse: None,
                    user_key: None,
                }),
            )
        }
        "mieru" => {
            let username =
                required_clash_scalar_field(raw.username, "clash mieru username cannot be empty")?;
            let password =
                required_clash_scalar_field(raw.password, "clash mieru password cannot be empty")?;
            let mut metadata = vec![
                MetadataEntry {
                    key: NODE_METADATA_MIERU_USERNAME.to_string(),
                    value: username,
                },
                MetadataEntry {
                    key: NODE_METADATA_MIERU_PASSWORD.to_string(),
                    value: password,
                },
                MetadataEntry {
                    key: NODE_METADATA_MIERU_TRANSPORT.to_string(),
                    value: text(raw.transport)
                        .unwrap_or_else(|| "TCP".to_string())
                        .to_ascii_uppercase(),
                },
            ];
            if let Some(range) = port_range {
                metadata.push(MetadataEntry {
                    key: NODE_METADATA_MIERU_PORT_RANGE.to_string(),
                    value: range,
                });
            }
            if let Some(level) = text(raw.multiplexing) {
                if let Ok(enabled) = parse_mieru_multiplexing(&level) {
                    metadata.push(MetadataEntry {
                        key: NODE_METADATA_MIERU_MULTIPLEXING.to_string(),
                        value: enabled.to_string(),
                    });
                }
            }
            (Protocol::Mieru, "mieru", metadata)
        }
        _ => {
            return Err(domain_error(
                SUBSCRIPTION_CLASH_YAML_UNSUPPORTED_CODE,
                "clash proxy type must be ss, trojan, vless, vmess, snell, or mieru",
            ));
        }
    };

    if matches!(
        protocol,
        Protocol::Trojan | Protocol::Vless | Protocol::Vmess
    ) {
        metadata.extend(proxy_line_pin_metadata(text(raw.fingerprint.take()), None));
        clash_stream_options(&raw.stream)?.append_to(
            &mut metadata,
            &host,
            protocol == Protocol::Trojan,
            SUBSCRIPTION_CLASH_YAML_INVALID_CODE,
            "clash proxy",
        )?;
    }
    metadata.extend(multiplex_metadata(raw.smux.as_ref()));
    let name_id = sanitize_identifier(&name);
    let name_id = if name_id.is_empty() {
        "node".to_string()
    } else {
        name_id
    };
    let id = format!("clash-{protocol_tag}-{name_id}");
    metadata.push(MetadataEntry {
        key: NODE_METADATA_SOURCE_FORMAT.to_string(),
        value: "clash-yaml".to_string(),
    });
    metadata.push(MetadataEntry {
        key: "subscription.source_id".to_string(),
        value: source_id.to_string(),
    });

    Ok(NodeDescriptor {
        id,
        name,
        protocol,
        endpoint: Endpoint { host, port },
        tags: vec![
            "subscription".to_string(),
            "clash-yaml".to_string(),
            protocol_tag.to_string(),
        ],
        metadata,
    })
}

/// The engine's `multiplex` object for a Clash `smux` or sing-box
/// `multiplex` that is turned on: the protocol and pool sizes, in either
/// spelling (`max-connections`, `max_connections`). `None` when it is off
/// or not an object. Values that make no sense are dropped, not rejected,
/// so a node still imports.
fn multiplex_metadata(raw: Option<&serde_json::Value>) -> Option<MetadataEntry> {
    use serde_json::Value;
    let object = raw?.as_object()?;
    let enabled = match object.get("enabled") {
        Some(Value::Bool(enabled)) => *enabled,
        Some(Value::String(text)) => matches!(text.trim(), "true" | "1"),
        Some(Value::Number(number)) => number.as_u64() == Some(1),
        _ => false,
    };
    if !enabled {
        return None;
    }
    let count = |names: [&str; 2]| {
        names.iter().find_map(|name| match object.get(*name)? {
            Value::Number(number) => number.as_u64(),
            Value::String(text) => text.trim().parse::<u64>().ok(),
            _ => None,
        })
    };
    let mut settings = serde_json::Map::new();
    if let Some(protocol) = object.get("protocol").and_then(Value::as_str) {
        if matches!(protocol, "smux" | "yamux" | "h2mux") {
            settings.insert("protocol".into(), protocol.into());
        }
    }
    match count(["max_streams", "max-streams"]).filter(|n| *n > 0) {
        Some(streams) => {
            settings.insert("max_streams".into(), streams.into());
        }
        None => {
            if let Some(n) = count(["max_connections", "max-connections"]).filter(|n| *n > 0) {
                settings.insert("max_connections".into(), n.into());
            }
            if let Some(n) = count(["min_streams", "min-streams"]).filter(|n| *n > 0) {
                settings.insert("min_streams".into(), n.into());
            }
        }
    }
    if object.get("padding").and_then(Value::as_bool) == Some(true) {
        settings.insert("padding".into(), true.into());
    }
    Some(MetadataEntry {
        key: NODE_METADATA_MULTIPLEX.to_string(),
        value: Value::Object(settings).to_string(),
    })
}

fn required_clash_scalar_field(
    raw: Option<RawClashScalar>,
    message: &'static str,
) -> DomainResult<String> {
    let Some(raw) = raw else {
        return Err(domain_error(SUBSCRIPTION_CLASH_YAML_INVALID_CODE, message));
    };

    required_trimmed(
        raw.into_text(),
        SUBSCRIPTION_CLASH_YAML_INVALID_CODE,
        message,
    )
}

fn parse_sing_box_json_subscription(
    source_id: &str,
    content: &str,
) -> DomainResult<Option<SubscriptionDocument>> {
    let content = content.trim();
    if content.is_empty() {
        return Ok(None);
    }

    let raw = match serde_json::from_str::<RawSingBoxDocument>(content) {
        Ok(raw) => raw,
        Err(_) => return Ok(None),
    };
    let Some(outbounds) = raw.outbounds else {
        return Ok(None);
    };
    if outbounds.is_empty() {
        return Err(domain_error(
            SUBSCRIPTION_SING_BOX_JSON_INVALID_CODE,
            "sing-box json outbounds cannot be empty",
        ));
    }

    let mut nodes = Vec::new();
    let mut seen_ids = BTreeSet::new();
    let mut skipped = SkippedEntries::new("sing-box outbound");
    // Whether any entry reads as an outbound; when none does, the text is
    // not a sing-box document and the next format gets it.
    let mut readable = false;
    for (index, value) in outbounds.into_iter().enumerate() {
        let tag = value
            .get("tag")
            .and_then(serde_json::Value::as_str)
            .map(str::to_string);
        let kind = value
            .get("type")
            .and_then(serde_json::Value::as_str)
            .map(str::to_string);
        if kind
            .as_deref()
            .is_some_and(|kind| is_ignored_sing_box_outbound(&normalized_token(kind)))
        {
            readable = true;
            continue;
        }
        let outbound = match serde_json::from_value::<RawSingBoxOutbound>(value) {
            Ok(outbound) => outbound,
            Err(_) => {
                skipped.skip(
                    index,
                    tag.as_deref(),
                    kind.as_deref(),
                    domain_error(
                        SUBSCRIPTION_SING_BOX_JSON_INVALID_CODE,
                        "sing-box outbound fields have unexpected types",
                    ),
                );
                continue;
            }
        };
        readable = true;
        match parse_sing_box_outbound(outbound, source_id) {
            Ok(Some(node)) => push_unique_node(&mut nodes, &mut seen_ids, node),
            Ok(None) => {}
            Err(error) => skipped.skip(index, tag.as_deref(), kind.as_deref(), error),
        }
    }
    if !readable {
        return Ok(None);
    }
    resolve_vias(&mut nodes);

    skipped
        .finish(nodes, || {
            domain_error(
                SUBSCRIPTION_SING_BOX_JSON_UNSUPPORTED_CODE,
                "sing-box json outbounds must contain at least one supported proxy outbound",
            )
        })
        .map(Some)
}

/// Turns each node's `detour` tag into the id of the imported node with that
/// name. A tag that names no imported node stays unresolved, and the node
/// cannot run (the importer reports it), rather than leaving beside its chain.
fn resolve_vias(nodes: &mut [NodeDescriptor]) {
    let mut ids = BTreeMap::new();
    for node in nodes.iter() {
        ids.entry(node.name.clone())
            .or_insert_with(|| node.id.clone());
    }
    for node in nodes.iter_mut() {
        let Some(index) = node
            .metadata
            .iter()
            .position(|entry| entry.key == NODE_METADATA_VIA_UNRESOLVED)
        else {
            continue;
        };
        if let Some(id) = ids.get(&node.metadata[index].value) {
            node.metadata[index] = MetadataEntry {
                key: NODE_METADATA_VIA.to_string(),
                value: id.clone(),
            };
        }
    }
}

fn parse_sing_box_outbound(
    raw: RawSingBoxOutbound,
    source_id: &str,
) -> DomainResult<Option<NodeDescriptor>> {
    let RawSingBoxOutbound {
        protocol,
        tag,
        server,
        server_port,
        server_ports,
        method,
        password,
        uuid,
        flow,
        security,
        alter_id,
        congestion_control,
        obfs,
        tls,
        transport,
        detour,
        multiplex,
        username,
        mtu,
        encrypt,
        plugin,
    } = raw;
    let protocol =
        required_sing_box_scalar_field(protocol, "sing-box outbound type cannot be empty")?;
    let protocol_token = normalized_token(&protocol);
    if is_ignored_sing_box_outbound(&protocol_token) {
        return Ok(None);
    }

    let host = required_sing_box_scalar_field(server, "sing-box outbound server cannot be empty")?;
    let (port, server_ports) = parse_sing_box_outbound_port(
        server_port,
        server_ports.map(RawSingBoxStringList::into_values),
        matches!(protocol_token.as_str(), "hysteria2" | "hy2"),
    )?;

    let (protocol, protocol_tag, mut metadata) = match protocol_token.as_str() {
        "ss" | "shadowsocks" => {
            let method = required_sing_box_scalar_field(
                method,
                "sing-box shadowsocks method cannot be empty",
            )?;
            let password = required_sing_box_scalar_field(
                password,
                "sing-box shadowsocks password cannot be empty",
            )?;
            let mut metadata = vec![
                MetadataEntry {
                    key: NODE_METADATA_SHADOWSOCKS_METHOD.to_string(),
                    value: method,
                },
                MetadataEntry {
                    key: NODE_METADATA_SHADOWSOCKS_PASSWORD.to_string(),
                    value: password,
                },
            ];
            metadata.extend(shadowsocks_plugin_entry(optional_sing_box_scalar_field(
                plugin,
            )));
            (Protocol::Shadowsocks, "ss", metadata)
        }
        "trojan" => {
            let password = required_sing_box_scalar_field(
                password,
                "sing-box trojan password cannot be empty",
            )?;
            let mut metadata = vec![MetadataEntry {
                key: NODE_METADATA_TROJAN_PASSWORD.to_string(),
                value: password,
            }];
            metadata.extend(sing_box_v2ray_tls_metadata(tls, &host, false)?);
            append_sing_box_v2ray_transport_metadata(&mut metadata, transport)?;
            (Protocol::Trojan, "trojan", metadata)
        }
        "vless" => {
            let uuid = required_sing_box_scalar_field(uuid, "sing-box vless uuid cannot be empty")?;
            let mut metadata = vec![MetadataEntry {
                key: NODE_METADATA_VLESS_UUID.to_string(),
                value: uuid,
            }];
            if let Some(flow) = optional_sing_box_scalar_field(flow) {
                metadata.push(MetadataEntry {
                    key: NODE_METADATA_VLESS_FLOW.to_string(),
                    value: flow,
                });
            }
            metadata.extend(sing_box_v2ray_tls_metadata(tls, &host, false)?);
            append_sing_box_v2ray_transport_metadata(&mut metadata, transport)?;
            (Protocol::Vless, "vless", metadata)
        }
        "vmess" => {
            let uuid = required_sing_box_scalar_field(uuid, "sing-box vmess uuid cannot be empty")?;
            let mut metadata = vec![MetadataEntry {
                key: NODE_METADATA_VMESS_UUID.to_string(),
                value: uuid,
            }];
            if let Some(security) = optional_sing_box_scalar_field(security) {
                metadata.push(MetadataEntry {
                    key: NODE_METADATA_VMESS_SECURITY.to_string(),
                    value: security,
                });
            }
            if let Some(alter_id) = optional_sing_box_scalar_field(alter_id) {
                metadata.push(MetadataEntry {
                    key: NODE_METADATA_VMESS_ALTER_ID.to_string(),
                    value: alter_id,
                });
            }
            metadata.extend(sing_box_v2ray_tls_metadata(tls, &host, false)?);
            append_sing_box_v2ray_transport_metadata(&mut metadata, transport)?;
            (Protocol::Vmess, "vmess", metadata)
        }
        "hysteria2" | "hy2" => {
            let password = required_sing_box_scalar_field(
                password,
                "sing-box hysteria2 password cannot be empty",
            )?;
            let mut metadata = vec![MetadataEntry {
                key: NODE_METADATA_HYSTERIA2_PASSWORD.to_string(),
                value: password,
            }];
            if let Some(server_ports) = server_ports {
                metadata.push(MetadataEntry {
                    key: NODE_METADATA_HYSTERIA2_SERVER_PORTS.to_string(),
                    value: server_ports,
                });
            }
            metadata.extend(sing_box_tls_metadata(tls, &host)?);
            append_sing_box_hysteria2_obfs_metadata(&mut metadata, obfs)?;
            (Protocol::Hysteria2, "hysteria2", metadata)
        }
        "tuic" => {
            let uuid = required_sing_box_scalar_field(uuid, "sing-box tuic uuid cannot be empty")?;
            let mut metadata = vec![MetadataEntry {
                key: NODE_METADATA_TUIC_UUID.to_string(),
                value: uuid,
            }];
            if let Some(password) = optional_sing_box_scalar_field(password) {
                metadata.push(MetadataEntry {
                    key: NODE_METADATA_TUIC_PASSWORD.to_string(),
                    value: password,
                });
            }
            if let Some(congestion_control) = optional_sing_box_scalar_field(congestion_control) {
                metadata.push(MetadataEntry {
                    key: NODE_METADATA_TUIC_CONGESTION_CONTROL.to_string(),
                    value: congestion_control,
                });
            }
            metadata.extend(sing_box_tls_metadata(tls, &host)?);
            (Protocol::Tuic, "tuic", metadata)
        }
        "iwan" => {
            let username =
                required_sing_box_scalar_field(username, "sing-box iwan username cannot be empty")?;
            let password =
                required_sing_box_scalar_field(password, "sing-box iwan password cannot be empty")?;
            let mut metadata = vec![
                MetadataEntry {
                    key: NODE_METADATA_IWAN_USERNAME.to_string(),
                    value: username,
                },
                MetadataEntry {
                    key: NODE_METADATA_IWAN_PASSWORD.to_string(),
                    value: password,
                },
            ];
            if let Some(mtu) = optional_sing_box_scalar_field(mtu) {
                metadata.push(MetadataEntry {
                    key: NODE_METADATA_IWAN_MTU.to_string(),
                    value: mtu,
                });
            }
            if let Some(encrypt) = encrypt {
                metadata.push(MetadataEntry {
                    key: NODE_METADATA_IWAN_ENCRYPT.to_string(),
                    value: encrypt.to_string(),
                });
            }
            (Protocol::Iwan, "iwan", metadata)
        }
        _ => {
            return Err(domain_error(
                SUBSCRIPTION_SING_BOX_JSON_UNSUPPORTED_CODE,
                "sing-box outbound type must be shadowsocks, trojan, vless, vmess, hysteria2, tuic, or iwan for catalog import",
            ));
        }
    };
    if let Some(detour) = optional_sing_box_scalar_field(detour) {
        metadata.push(MetadataEntry {
            key: NODE_METADATA_VIA_UNRESOLVED.to_string(),
            value: detour,
        });
    }
    metadata.extend(multiplex_metadata(multiplex.as_ref()));

    let tag = optional_sing_box_scalar_field(tag);
    let host_id = sanitize_identifier(&host);
    let host_id = if host_id.is_empty() {
        "host".to_string()
    } else {
        host_id
    };
    let fallback_id = format!("{host_id}-{port}");
    let name = tag
        .clone()
        .unwrap_or_else(|| format!("sing-box-{protocol_tag}-{fallback_id}"));
    let name_id = tag.as_deref().unwrap_or(&fallback_id);
    let name_id = sanitize_identifier(name_id);
    let name_id = if name_id.is_empty() {
        "node".to_string()
    } else {
        name_id
    };
    let id = format!("sing-box-{protocol_tag}-{name_id}");
    metadata.push(MetadataEntry {
        key: NODE_METADATA_SOURCE_FORMAT.to_string(),
        value: "sing-box-json".to_string(),
    });
    metadata.push(MetadataEntry {
        key: "subscription.source_id".to_string(),
        value: source_id.to_string(),
    });

    Ok(Some(NodeDescriptor {
        id,
        name,
        protocol,
        endpoint: Endpoint { host, port },
        tags: vec![
            "subscription".to_string(),
            "sing-box-json".to_string(),
            protocol_tag.to_string(),
        ],
        metadata,
    }))
}

fn parse_sing_box_outbound_port(
    server_port: Option<RawSingBoxScalar>,
    server_ports: Option<Vec<String>>,
    supports_port_ranges: bool,
) -> DomainResult<(u16, Option<String>)> {
    if supports_port_ranges {
        if let Some(server_ports) = server_ports {
            let normalized = normalize_hysteria2_server_port_ranges(
                server_ports,
                SUBSCRIPTION_SING_BOX_JSON_INVALID_CODE,
            )?;
            let first_port = normalized.first().ok_or_else(|| {
                domain_error(
                    SUBSCRIPTION_SING_BOX_JSON_INVALID_CODE,
                    "sing-box hysteria2 server_ports cannot be empty",
                )
            })?;
            let first_port = hysteria2_server_port_range_start(
                first_port,
                SUBSCRIPTION_SING_BOX_JSON_INVALID_CODE,
            )?;
            return Ok((first_port, Some(normalized.join(","))));
        }
    }

    let port = required_sing_box_scalar_field(
        server_port,
        "sing-box outbound server_port cannot be empty",
    )?;
    let port = port.parse::<i64>().map_err(|_| {
        domain_error(
            SUBSCRIPTION_SING_BOX_JSON_INVALID_CODE,
            "sing-box outbound server_port must be a number",
        )
    })?;
    let port = parse_port(
        port,
        SUBSCRIPTION_SING_BOX_JSON_INVALID_CODE,
        "sing-box outbound server_port must be between 1 and 65535",
    )?;

    Ok((port, None))
}

fn sing_box_v2ray_tls_metadata(
    raw: Option<RawSingBoxTls>,
    host: &str,
    default_enabled: bool,
) -> DomainResult<Metadata> {
    let Some(raw) = raw else {
        return Ok(vec![MetadataEntry {
            key: NODE_METADATA_TLS_ENABLED.to_string(),
            value: default_enabled.to_string(),
        }]);
    };
    let RawSingBoxTls {
        enabled,
        server_name,
        insecure,
        alpn,
        certificate_sha256,
        certificate_public_key_sha256,
        utls,
        reality,
    } = raw;
    let reality_enabled = reality
        .as_ref()
        .and_then(|reality| reality.enabled)
        .unwrap_or(false);
    let enabled = enabled.unwrap_or(default_enabled) || reality_enabled;
    let mut metadata = vec![
        MetadataEntry {
            key: NODE_METADATA_TLS_ENABLED.to_string(),
            value: enabled.to_string(),
        },
        MetadataEntry {
            key: NODE_METADATA_TLS_SERVER_NAME.to_string(),
            value: optional_sing_box_scalar_field(server_name).unwrap_or_else(|| host.to_string()),
        },
        MetadataEntry {
            key: NODE_METADATA_TLS_INSECURE.to_string(),
            value: insecure.unwrap_or(false).to_string(),
        },
    ];
    if let Some(alpn) = normalize_non_empty_metadata_values(
        alpn.map(RawSingBoxStringList::into_values),
        "sing-box tls alpn values cannot be empty",
    )? {
        metadata.push(MetadataEntry {
            key: NODE_METADATA_TLS_ALPN.to_string(),
            value: alpn.join(","),
        });
    }
    metadata.extend(sing_box_pin_metadata(
        certificate_sha256,
        certificate_public_key_sha256,
    )?);
    if let Some(utls) = utls.filter(|utls| utls.enabled.unwrap_or(false)) {
        let fingerprint = required_sing_box_scalar_field(
            utls.fingerprint,
            "sing-box tls utls fingerprint cannot be empty when utls is enabled",
        )?;
        metadata.push(MetadataEntry {
            key: NODE_METADATA_TLS_UTLS_FINGERPRINT.to_string(),
            value: fingerprint,
        });
    }
    if let Some(reality) = reality.filter(|reality| reality.enabled.unwrap_or(false)) {
        let public_key = required_sing_box_scalar_field(
            reality.public_key,
            "sing-box tls reality public_key cannot be empty when reality is enabled",
        )?;
        metadata.push(MetadataEntry {
            key: NODE_METADATA_TLS_REALITY_PUBLIC_KEY.to_string(),
            value: public_key,
        });
        if let Some(short_id) = optional_sing_box_scalar_field(reality.short_id) {
            metadata.push(MetadataEntry {
                key: NODE_METADATA_TLS_REALITY_SHORT_ID.to_string(),
                value: short_id,
            });
        }
    }
    Ok(metadata)
}

fn append_sing_box_v2ray_transport_metadata(
    metadata: &mut Metadata,
    raw: Option<RawSingBoxTransport>,
) -> DomainResult<()> {
    let Some(raw) = raw else {
        return Ok(());
    };
    let RawSingBoxTransport {
        kind,
        host,
        path,
        service_name,
        headers,
    } = raw;
    let kind = required_sing_box_scalar_field(kind, "sing-box transport type cannot be empty")?;
    let kind = match normalized_token(&kind).as_str() {
        "ws" | "websocket" => "ws",
        "grpc" => "grpc",
        "http" | "h2" => "http",
        "httpupgrade" | "http_upgrade" => "httpupgrade",
        "quic" => "quic",
        "tcp" | "raw" | "none" => return Ok(()),
        _ => {
            return Err(domain_error(
                SUBSCRIPTION_SING_BOX_JSON_UNSUPPORTED_CODE,
                "sing-box outbound transport must be ws, grpc, http, httpupgrade, or quic for catalog import",
            ));
        }
    };
    metadata.push(MetadataEntry {
        key: NODE_METADATA_V2RAY_TRANSPORT_TYPE.to_string(),
        value: kind.to_string(),
    });
    let host = host.or_else(|| headers.and_then(|headers| headers.host));
    if let Some(host) = normalize_non_empty_metadata_values(
        host.map(RawSingBoxStringList::into_values),
        "sing-box transport host values cannot be empty",
    )? {
        metadata.push(MetadataEntry {
            key: NODE_METADATA_V2RAY_TRANSPORT_HOST.to_string(),
            value: host.join(","),
        });
    }
    if let Some(path) = optional_sing_box_scalar_field(path) {
        metadata.push(MetadataEntry {
            key: NODE_METADATA_V2RAY_TRANSPORT_PATH.to_string(),
            value: path,
        });
    }
    if let Some(service_name) = optional_sing_box_scalar_field(service_name) {
        metadata.push(MetadataEntry {
            key: NODE_METADATA_V2RAY_TRANSPORT_SERVICE_NAME.to_string(),
            value: service_name,
        });
    }
    Ok(())
}

fn sing_box_tls_metadata(raw: Option<RawSingBoxTls>, host: &str) -> DomainResult<Metadata> {
    let (server_name, insecure, alpn, certificate_sha256, certificate_public_key_sha256) = match raw
    {
        Some(raw) => (
            optional_sing_box_scalar_field(raw.server_name).unwrap_or_else(|| host.to_string()),
            raw.insecure.unwrap_or(false),
            raw.alpn.map(RawSingBoxStringList::into_values),
            raw.certificate_sha256,
            raw.certificate_public_key_sha256,
        ),
        None => (host.to_string(), false, None, None, None),
    };
    let mut metadata = vec![
        MetadataEntry {
            key: NODE_METADATA_TLS_SERVER_NAME.to_string(),
            value: server_name,
        },
        MetadataEntry {
            key: NODE_METADATA_TLS_INSECURE.to_string(),
            value: insecure.to_string(),
        },
    ];
    if let Some(alpn) =
        normalize_non_empty_metadata_values(alpn, "sing-box tls alpn values cannot be empty")?
    {
        metadata.push(MetadataEntry {
            key: NODE_METADATA_TLS_ALPN.to_string(),
            value: alpn.join(","),
        });
    }
    metadata.extend(sing_box_pin_metadata(
        certificate_sha256,
        certificate_public_key_sha256,
    )?);
    Ok(metadata)
}

/// The pin entries of a sing-box `tls` object (both lists base64; see
/// [`certificate_pin_metadata`]).
fn sing_box_pin_metadata(
    certificate_sha256: Option<RawSingBoxStringList>,
    certificate_public_key_sha256: Option<RawSingBoxStringList>,
) -> DomainResult<Metadata> {
    let certificate = normalize_non_empty_metadata_values(
        certificate_sha256.map(RawSingBoxStringList::into_values),
        "sing-box tls certificate_sha256 values cannot be empty",
    )?
    .unwrap_or_default();
    let public_key = normalize_non_empty_metadata_values(
        certificate_public_key_sha256.map(RawSingBoxStringList::into_values),
        "sing-box tls certificate_public_key_sha256 values cannot be empty",
    )?
    .unwrap_or_default();
    Ok(certificate_pin_metadata(&certificate, &public_key))
}

fn append_sing_box_hysteria2_obfs_metadata(
    metadata: &mut Metadata,
    obfs: Option<RawSingBoxHysteria2Obfs>,
) -> DomainResult<()> {
    let Some(obfs) = obfs else {
        return Ok(());
    };
    let kind =
        required_sing_box_scalar_field(obfs.kind, "sing-box hysteria2 obfs type cannot be empty")?;
    let kind = normalized_token(&kind);
    if !matches!(kind.as_str(), "salamander" | "gecko") {
        return Err(domain_error(
            SUBSCRIPTION_SING_BOX_JSON_INVALID_CODE,
            "sing-box hysteria2 obfs type must be salamander or gecko",
        ));
    }
    let password = required_sing_box_scalar_field(
        obfs.password,
        "sing-box hysteria2 obfs password cannot be empty",
    )?;
    metadata.push(MetadataEntry {
        key: NODE_METADATA_HYSTERIA2_OBFS_TYPE.to_string(),
        value: kind.clone(),
    });
    metadata.push(MetadataEntry {
        key: NODE_METADATA_HYSTERIA2_OBFS_PASSWORD.to_string(),
        value: password,
    });
    if kind == "gecko" {
        if let Some(value) = obfs.min_packet_size {
            metadata.push(MetadataEntry {
                key: NODE_METADATA_HYSTERIA2_OBFS_MIN_PACKET_SIZE.to_string(),
                value: normalize_hysteria2_packet_size(
                    value.into_text(),
                    SUBSCRIPTION_SING_BOX_JSON_INVALID_CODE,
                )?,
            });
        }
        if let Some(value) = obfs.max_packet_size {
            metadata.push(MetadataEntry {
                key: NODE_METADATA_HYSTERIA2_OBFS_MAX_PACKET_SIZE.to_string(),
                value: normalize_hysteria2_packet_size(
                    value.into_text(),
                    SUBSCRIPTION_SING_BOX_JSON_INVALID_CODE,
                )?,
            });
        }
    }
    Ok(())
}

fn normalize_non_empty_metadata_values(
    values: Option<Vec<String>>,
    message: &'static str,
) -> DomainResult<Option<Vec<String>>> {
    values
        .map(|values| {
            values
                .into_iter()
                .map(|value| {
                    required_trimmed(value, SUBSCRIPTION_SING_BOX_JSON_INVALID_CODE, message)
                })
                .collect::<DomainResult<Vec<_>>>()
        })
        .transpose()
}

fn is_ignored_sing_box_outbound(protocol_token: &str) -> bool {
    matches!(
        protocol_token,
        "direct" | "block" | "dns" | "selector" | "urltest" | "bridge"
    )
}

fn required_sing_box_scalar_field(
    raw: Option<RawSingBoxScalar>,
    message: &'static str,
) -> DomainResult<String> {
    let Some(raw) = raw else {
        return Err(domain_error(
            SUBSCRIPTION_SING_BOX_JSON_INVALID_CODE,
            message,
        ));
    };

    required_trimmed(
        raw.into_text(),
        SUBSCRIPTION_SING_BOX_JSON_INVALID_CODE,
        message,
    )
}

fn optional_sing_box_scalar_field(raw: Option<RawSingBoxScalar>) -> Option<String> {
    let text = raw?.into_text().trim().to_string();
    if text.is_empty() {
        None
    } else {
        Some(text)
    }
}

fn parse_quantumult_x_proxy_line_subscription(
    source_id: &str,
    content: &str,
) -> DomainResult<Option<SubscriptionDocument>> {
    let content = content.trim();
    if content.is_empty() {
        return Ok(None);
    }

    let mut saw_server_local_section = false;
    let mut in_server_local_section = false;
    let mut proxy_lines = Vec::new();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty()
            || line.starts_with('#')
            || line.starts_with("//")
            || line.starts_with(';')
        {
            continue;
        }

        if let Some(section) = parse_surge_section_header(line) {
            in_server_local_section = normalized_token(section).as_str() == "server_local";
            saw_server_local_section |= in_server_local_section;
            continue;
        }

        if in_server_local_section {
            proxy_lines.push(line.to_string());
        }
    }

    if !saw_server_local_section {
        return Ok(None);
    }
    if proxy_lines.is_empty() {
        return Err(domain_error(
            SUBSCRIPTION_QUANTUMULT_X_PROXY_LINE_INVALID_CODE,
            "quantumult x server_local section cannot be empty",
        ));
    }

    let mut nodes = Vec::new();
    let mut seen_ids = BTreeSet::new();
    let mut skipped = SkippedEntries::new("quantumult x server_local line");
    for (index, line) in proxy_lines.iter().enumerate() {
        let kind = line.split_once('=').map(|(kind, _)| kind.trim());
        if kind.and_then(builtin_policy).is_some() {
            continue;
        }
        match parse_quantumult_x_proxy_line(line, source_id) {
            Ok(node) => push_unique_node(&mut nodes, &mut seen_ids, node),
            Err(error) => {
                let tag = quantumult_x_proxy_line_tag(line);
                skipped.skip(index, tag.as_deref(), kind, error);
            }
        }
    }

    skipped
        .finish(nodes, || {
            domain_error(
                SUBSCRIPTION_QUANTUMULT_X_PROXY_LINE_UNSUPPORTED_CODE,
                "quantumult x server_local section must contain at least one supported proxy",
            )
        })
        .map(Some)
}

/// The `tag=` of a Quantumult X server line, for naming it in a warning.
fn quantumult_x_proxy_line_tag(line: &str) -> Option<String> {
    let (_, definition) = line.split_once('=')?;
    definition.split(',').find_map(|part| {
        let (key, value) = part.split_once('=')?;
        (normalized_token(key) == "tag").then(|| strip_quantumult_x_quotes(value.to_string()))
    })
}

fn parse_quantumult_x_proxy_line(line: &str, source_id: &str) -> DomainResult<NodeDescriptor> {
    let (protocol, definition) = line.split_once('=').ok_or_else(|| {
        domain_error(
            SUBSCRIPTION_QUANTUMULT_X_PROXY_LINE_INVALID_CODE,
            "quantumult x proxy line must contain protocol and definition",
        )
    })?;
    let protocol_token = normalized_token(protocol);
    let parts = definition
        .split(',')
        .map(|part| part.trim().to_string())
        .collect::<Vec<_>>();
    let endpoint = parts.first().cloned().unwrap_or_default();
    let endpoint = required_trimmed(
        endpoint,
        SUBSCRIPTION_QUANTUMULT_X_PROXY_LINE_INVALID_CODE,
        "quantumult x proxy endpoint cannot be empty",
    )?;
    let (host, port) = parse_host_port_for(
        &endpoint,
        SUBSCRIPTION_QUANTUMULT_X_PROXY_LINE_INVALID_CODE,
        "quantumult x proxy",
    )?;
    let options = collect_quantumult_x_proxy_options(&parts[1..])?;

    let (protocol, protocol_tag, mut metadata) = match protocol_token.as_str() {
        "ss" | "shadowsocks" => {
            let method = required_quantumult_x_proxy_option(
                &options,
                &["method"],
                "quantumult x shadowsocks method cannot be empty",
            )?;
            let password = required_quantumult_x_proxy_option(
                &options,
                &["password"],
                "quantumult x shadowsocks password cannot be empty",
            )?;
            let mut metadata = vec![
                MetadataEntry {
                    key: NODE_METADATA_SHADOWSOCKS_METHOD.to_string(),
                    value: method,
                },
                MetadataEntry {
                    key: NODE_METADATA_SHADOWSOCKS_PASSWORD.to_string(),
                    value: password,
                },
            ];
            metadata.extend(shadowsocks_plugin_entry(
                options
                    .get("obfs")
                    .map(String::as_str)
                    .map(obfs_plugin_name),
            ));
            (Protocol::Shadowsocks, "ss", metadata)
        }
        "trojan" => {
            let password = required_quantumult_x_proxy_option(
                &options,
                &["password"],
                "quantumult x trojan password cannot be empty",
            )?;
            (
                Protocol::Trojan,
                "trojan",
                vec![MetadataEntry {
                    key: NODE_METADATA_TROJAN_PASSWORD.to_string(),
                    value: password,
                }],
            )
        }
        "vless" => {
            let uuid = required_quantumult_x_proxy_option(
                &options,
                &["password", "uuid"],
                "quantumult x vless uuid cannot be empty",
            )?;
            let mut metadata = vec![MetadataEntry {
                key: NODE_METADATA_VLESS_UUID.to_string(),
                value: uuid,
            }];
            if let Some(flow) = optional_quantumult_x_proxy_option(&options, &["vless_flow"]) {
                metadata.push(MetadataEntry {
                    key: NODE_METADATA_VLESS_FLOW.to_string(),
                    value: flow,
                });
            }
            (Protocol::Vless, "vless", metadata)
        }
        "vmess" => {
            let uuid = required_quantumult_x_proxy_option(
                &options,
                &["password", "uuid", "username"],
                "quantumult x vmess uuid cannot be empty",
            )?;
            let mut metadata = vec![MetadataEntry {
                key: NODE_METADATA_VMESS_UUID.to_string(),
                value: uuid,
            }];
            metadata.extend(proxy_vmess_security(optional_quantumult_x_proxy_option(
                &options,
                &["method"],
            )));
            (Protocol::Vmess, "vmess", metadata)
        }
        "direct" | "reject" | "http" | "https" | "socks" | "socks5" | "ssr" | "shadowsocksr"
        | "hysteria" | "hysteria2" | "tuic" | "wireguard" => {
            return Err(domain_error(
                SUBSCRIPTION_QUANTUMULT_X_PROXY_LINE_UNSUPPORTED_CODE,
                "quantumult x proxy type must be shadowsocks, trojan, vless, or vmess for catalog import",
            ));
        }
        _ => {
            return Err(domain_error(
                SUBSCRIPTION_QUANTUMULT_X_PROXY_LINE_UNSUPPORTED_CODE,
                "quantumult x proxy type must be shadowsocks, trojan, vless, or vmess for catalog import",
            ));
        }
    };
    if matches!(
        protocol,
        Protocol::Trojan | Protocol::Vless | Protocol::Vmess
    ) {
        metadata.extend(proxy_line_pin_metadata(
            optional_quantumult_x_proxy_option(&options, &["tls_cert_sha256"]),
            optional_quantumult_x_proxy_option(&options, &["tls_pubkey_sha256"]),
        ));
        quantumult_x_stream_options(&options)?.append_to(
            &mut metadata,
            &host,
            protocol == Protocol::Trojan,
            SUBSCRIPTION_QUANTUMULT_X_PROXY_LINE_INVALID_CODE,
            "quantumult x proxy",
        )?;
    }

    let name = optional_quantumult_x_proxy_option(&options, &["tag"]).unwrap_or_else(|| {
        let host_id = sanitize_identifier(&host);
        let host_id = if host_id.is_empty() {
            "host".to_string()
        } else {
            host_id
        };
        format!("quantumult-x-{protocol_tag}-{host_id}-{port}")
    });
    let name_id = sanitize_identifier(&name);
    let name_id = if name_id.is_empty() {
        "node".to_string()
    } else {
        name_id
    };
    let id = format!("quantumult-x-{protocol_tag}-{name_id}");
    metadata.push(MetadataEntry {
        key: NODE_METADATA_SOURCE_FORMAT.to_string(),
        value: "quantumult-x-proxy-line".to_string(),
    });
    metadata.push(MetadataEntry {
        key: "subscription.source_id".to_string(),
        value: source_id.to_string(),
    });

    Ok(NodeDescriptor {
        id,
        name,
        protocol,
        endpoint: Endpoint { host, port },
        tags: vec![
            "subscription".to_string(),
            "quantumult-x-proxy-line".to_string(),
            protocol_tag.to_string(),
        ],
        metadata,
    })
}

/// The share-link settings of a Quantumult X vmess, vless or trojan line:
/// `obfs=over-tls|wss|ws` with `obfs-host` and `obfs-uri`, `over-tls`,
/// `tls-host`, `tls-verification`, `reality-base64-pubkey` and
/// `reality-hex-shortid`. `obfs=http` (HTTP/1.1 header obfuscation) and
/// other `obfs` values make the node unsupported.
fn quantumult_x_stream_options(
    options: &BTreeMap<String, String>,
) -> DomainResult<ProxyStreamOptions> {
    let code = SUBSCRIPTION_QUANTUMULT_X_PROXY_LINE_INVALID_CODE;
    let mut stream = ProxyStreamOptions::default();
    let mut tls = proxy_line_boolean(options.get("over_tls"), code, "quantumult x over-tls")?;
    match options
        .get("obfs")
        .map(String::as_str)
        .map(normalized_token)
        .as_deref()
    {
        None | Some("" | "none") => {}
        Some("over_tls") => tls = Some(true),
        Some("wss") => {
            tls = Some(true);
            stream.set_transport("ws");
        }
        Some(other) => stream.set_transport(other),
    }
    let obfs_host = options.get("obfs_host").cloned();
    if stream.query.get("type").map(String::as_str) == Some("ws") {
        stream.set("path", options.get("obfs_uri").cloned());
        stream.set("host", obfs_host.clone());
    }
    let reality = options.get("reality_base64_pubkey").cloned();
    if reality.is_some() {
        stream.set("security", Some("reality".to_string()));
        stream.set("pbk", reality);
        stream.set("sid", options.get("reality_hex_shortid").cloned());
    } else if let Some(tls) = tls {
        let security = if tls { "tls" } else { "none" };
        stream.set("security", Some(security.to_string()));
    }
    // `tls-host` names the server; without it the `obfs-host` of a TLS
    // `obfs` does.
    stream.set("sni", options.get("tls_host").cloned());
    if matches!(
        stream.query.get("security").map(String::as_str),
        Some("tls" | "reality")
    ) {
        stream.set_default("sni", obfs_host);
    }
    if let Some(verify) = proxy_line_boolean(
        options.get("tls_verification"),
        code,
        "quantumult x tls-verification",
    )? {
        stream.set("insecure", Some((!verify).to_string()));
    }
    Ok(stream)
}

/// The SIP003 plugin a Shadowsocks `obfs=` option stands for: simple-obfs
/// for `http` and `tls`, v2ray-plugin for `ws` and `wss`. `none` is no
/// plugin.
fn obfs_plugin_name(obfs: &str) -> String {
    match normalized_token(obfs).as_str() {
        "" | "none" => String::new(),
        "http" | "tls" => "obfs-local".to_string(),
        "ws" | "wss" | "websocket" => "v2ray-plugin".to_string(),
        other => other.to_string(),
    }
}

fn collect_quantumult_x_proxy_options(parts: &[String]) -> DomainResult<BTreeMap<String, String>> {
    let mut options = BTreeMap::new();
    for part in parts {
        if part.is_empty() {
            continue;
        }
        let Some((key, value)) = part.split_once('=') else {
            return Err(domain_error(
                SUBSCRIPTION_QUANTUMULT_X_PROXY_LINE_INVALID_CODE,
                "quantumult x proxy option must use key=value",
            ));
        };
        let key = normalized_token(key);
        let value = strip_quantumult_x_quotes(value.to_string());
        let value = required_trimmed(
            value,
            SUBSCRIPTION_QUANTUMULT_X_PROXY_LINE_INVALID_CODE,
            "quantumult x proxy option value cannot be empty",
        )?;
        if !key.is_empty() {
            options.insert(key, value);
        }
    }
    Ok(options)
}

fn optional_quantumult_x_proxy_option(
    options: &BTreeMap<String, String>,
    keys: &[&str],
) -> Option<String> {
    for key in keys {
        if let Some(value) = options.get(*key) {
            return Some(value.clone());
        }
    }
    None
}

fn required_quantumult_x_proxy_option(
    options: &BTreeMap<String, String>,
    keys: &[&str],
    message: &'static str,
) -> DomainResult<String> {
    optional_quantumult_x_proxy_option(options, keys)
        .ok_or_else(|| domain_error(SUBSCRIPTION_QUANTUMULT_X_PROXY_LINE_INVALID_CODE, message))
}

fn strip_quantumult_x_quotes(value: String) -> String {
    let value = value.trim();
    if value.len() >= 2 && value.starts_with('"') && value.ends_with('"') {
        value[1..value.len() - 1].to_string()
    } else {
        value.to_string()
    }
}

fn parse_loon_proxy_line_subscription(
    source_id: &str,
    content: &str,
) -> DomainResult<Option<SubscriptionDocument>> {
    let content = content.trim();
    if content.is_empty() {
        return Ok(None);
    }

    let mut saw_proxy_section = false;
    let mut in_proxy_section = false;
    let mut proxy_lines = Vec::new();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with("//") {
            continue;
        }

        if let Some(section) = parse_surge_section_header(line) {
            in_proxy_section = normalized_token(section).as_str() == "proxy";
            saw_proxy_section |= in_proxy_section;
            continue;
        }

        if in_proxy_section {
            proxy_lines.push(line.to_string());
        }
    }

    if !saw_proxy_section {
        return Ok(None);
    }
    if proxy_lines.is_empty() {
        return Err(domain_error(
            SUBSCRIPTION_LOON_PROXY_LINE_INVALID_CODE,
            "loon proxy section cannot be empty",
        ));
    }

    let mut nodes = Vec::new();
    let mut seen_ids = BTreeSet::new();
    let mut skipped = SkippedEntries::new("loon proxy line");
    // Lines in another style (Surge's `key=value` options) or of a type the
    // Loon reader does not know: when no line reads as a Loon node, the
    // section is not Loon's and the Surge reader gets it.
    let mut other_style = Vec::new();
    for (index, line) in proxy_lines.iter().enumerate() {
        if proxy_line_builtin_policy(line).is_some() {
            continue;
        }
        match parse_loon_proxy_line(line, source_id) {
            Ok(Some(node)) => push_unique_node(&mut nodes, &mut seen_ids, node),
            Ok(None) => other_style.push(index),
            Err(error) => {
                let (name, kind) = proxy_line_name_and_kind(line);
                skipped.skip(index, name, kind, error);
            }
        }
    }

    if nodes.is_empty() {
        // Every line was in Loon's positional style yet none could be
        // imported: report the first one's error rather than letting the
        // Surge reader misread the section.
        if other_style.is_empty() {
            if let Some(error) = skipped.first_error {
                return Err(error);
            }
        }
        return Ok(None);
    }
    for index in other_style {
        let (name, kind) = proxy_line_name_and_kind(&proxy_lines[index]);
        skipped.skip(
            index,
            name,
            kind,
            domain_error(
                SUBSCRIPTION_LOON_PROXY_LINE_UNSUPPORTED_CODE,
                "loon proxy line type or option style is not supported for catalog import",
            ),
        );
    }

    skipped
        .finish(nodes, || {
            domain_error(
                SUBSCRIPTION_LOON_PROXY_LINE_UNSUPPORTED_CODE,
                "loon proxy section must contain at least one supported proxy",
            )
        })
        .map(Some)
}

/// The name and type of a Surge or Loon `Name = type, server, port, ...`
/// line, for naming it in a warning.
fn proxy_line_name_and_kind(line: &str) -> (Option<&str>, Option<&str>) {
    match line.split_once('=') {
        Some((name, definition)) => (
            Some(name.trim()),
            definition.split(',').next().map(str::trim),
        ),
        None => (None, None),
    }
}

fn parse_loon_proxy_line(line: &str, source_id: &str) -> DomainResult<Option<NodeDescriptor>> {
    let Some((name, definition)) = line.split_once('=') else {
        return Ok(None);
    };
    let name = required_trimmed(
        name.to_string(),
        SUBSCRIPTION_LOON_PROXY_LINE_INVALID_CODE,
        "loon proxy name cannot be empty",
    )?;
    let parts = definition
        .split(',')
        .map(|part| part.trim().to_string())
        .collect::<Vec<_>>();
    if parts.len() < 3 || parts.iter().take(3).any(String::is_empty) {
        return Err(domain_error(
            SUBSCRIPTION_LOON_PROXY_LINE_INVALID_CODE,
            "loon proxy line must contain type, server, and port",
        ));
    }

    let protocol_token = normalized_token(&parts[0]);
    let host = required_trimmed(
        parts[1].clone(),
        SUBSCRIPTION_LOON_PROXY_LINE_INVALID_CODE,
        "loon proxy server cannot be empty",
    )?;
    let port = parts[2].parse::<i64>().map_err(|_| {
        domain_error(
            SUBSCRIPTION_LOON_PROXY_LINE_INVALID_CODE,
            "loon proxy port must be a number",
        )
    })?;
    let port = parse_port(
        port,
        SUBSCRIPTION_LOON_PROXY_LINE_INVALID_CODE,
        "loon proxy port must be between 1 and 65535",
    )?;

    let (protocol, protocol_tag, mut metadata) = match protocol_token.as_str() {
        "ss" | "shadowsocks" => {
            if is_surge_style_proxy_definition(&parts) {
                return Ok(None);
            }
            let method =
                required_loon_proxy_part(&parts, 3, "loon shadowsocks method cannot be empty")?;
            let password =
                required_loon_proxy_part(&parts, 4, "loon shadowsocks password cannot be empty")?;
            let mut metadata = vec![
                MetadataEntry {
                    key: NODE_METADATA_SHADOWSOCKS_METHOD.to_string(),
                    value: method,
                },
                MetadataEntry {
                    key: NODE_METADATA_SHADOWSOCKS_PASSWORD.to_string(),
                    value: password,
                },
            ];
            metadata.extend(shadowsocks_plugin_entry(loon_shadowsocks_plugin(
                parts.get(5..).unwrap_or_default(),
            )));
            (Protocol::Shadowsocks, "ss", metadata)
        }
        "trojan" => {
            if is_surge_style_proxy_definition(&parts) {
                return Ok(None);
            }
            let password =
                required_loon_proxy_part(&parts, 3, "loon trojan password cannot be empty")?;
            (
                Protocol::Trojan,
                "trojan",
                vec![MetadataEntry {
                    key: NODE_METADATA_TROJAN_PASSWORD.to_string(),
                    value: password,
                }],
            )
        }
        "vless" => {
            if is_surge_style_proxy_definition(&parts) {
                return Ok(None);
            }
            let uuid = required_loon_proxy_part(&parts, 3, "loon vless uuid cannot be empty")?;
            let mut metadata = vec![MetadataEntry {
                key: NODE_METADATA_VLESS_UUID.to_string(),
                value: uuid,
            }];
            if let Some(flow) = loon_proxy_option(parts.get(4..).unwrap_or_default(), "flow") {
                metadata.push(MetadataEntry {
                    key: NODE_METADATA_VLESS_FLOW.to_string(),
                    value: flow,
                });
            }
            (Protocol::Vless, "vless", metadata)
        }
        "vmess" => {
            if is_surge_style_proxy_definition(&parts) {
                return Ok(None);
            }
            let uuid = required_loon_proxy_part(&parts, 4, "loon vmess uuid cannot be empty")?;
            let mut metadata = vec![MetadataEntry {
                key: NODE_METADATA_VMESS_UUID.to_string(),
                value: uuid,
            }];
            // The cipher comes before the uuid.
            metadata.extend(proxy_vmess_security(
                parts.get(3).cloned().map(strip_loon_quotes),
            ));
            if let Some(alter_id) = loon_proxy_option(parts.get(5..).unwrap_or_default(), "alterid")
            {
                metadata.push(MetadataEntry {
                    key: NODE_METADATA_VMESS_ALTER_ID.to_string(),
                    value: alter_id,
                });
            }
            (Protocol::Vmess, "vmess", metadata)
        }
        "direct" | "reject" | "http" | "https" | "socks" | "socks5" | "ssr" | "shadowsocksr"
        | "hysteria" | "hysteria2" | "tuic" | "wireguard" => {
            return Err(domain_error(
                SUBSCRIPTION_LOON_PROXY_LINE_UNSUPPORTED_CODE,
                "loon proxy type must be shadowsocks, trojan, vless, or vmess for catalog import",
            ));
        }
        _ => return Ok(None),
    };
    // Options follow the credentials: the password or uuid, and for vmess
    // the cipher before the uuid.
    let first_option = match protocol {
        Protocol::Trojan | Protocol::Vless => Some(4),
        Protocol::Vmess => Some(5),
        _ => None,
    };
    if let Some(options) = first_option.and_then(|index| parts.get(index..)) {
        metadata.extend(proxy_line_pin_metadata(
            loon_proxy_option(options, "tls_cert_sha256"),
            loon_proxy_option(options, "tls_pubkey_sha256"),
        ));
        loon_stream_options(options)?.append_to(
            &mut metadata,
            &host,
            protocol == Protocol::Trojan,
            SUBSCRIPTION_LOON_PROXY_LINE_INVALID_CODE,
            "loon proxy",
        )?;
    }

    let name_id = sanitize_identifier(&name);
    let name_id = if name_id.is_empty() {
        "node".to_string()
    } else {
        name_id
    };
    let id = format!("loon-{protocol_tag}-{name_id}");
    metadata.push(MetadataEntry {
        key: NODE_METADATA_SOURCE_FORMAT.to_string(),
        value: "loon-proxy-line".to_string(),
    });
    metadata.push(MetadataEntry {
        key: "subscription.source_id".to_string(),
        value: source_id.to_string(),
    });

    Ok(Some(NodeDescriptor {
        id,
        name,
        protocol,
        endpoint: Endpoint { host, port },
        tags: vec![
            "subscription".to_string(),
            "loon-proxy-line".to_string(),
            protocol_tag.to_string(),
        ],
        metadata,
    }))
}

/// The value of the `key=value` option named `key` (normalized, as
/// [`normalized_token`] spells it) among a Loon proxy line's options.
fn loon_proxy_option(options: &[String], key: &str) -> Option<String> {
    options.iter().find_map(|option| {
        let (name, value) = option.split_once('=')?;
        (normalized_token(name) == key)
            .then(|| strip_loon_quotes(value.to_string()))
            .filter(|value| !value.is_empty())
    })
}

/// The share-link settings of a Loon vmess, vless or trojan line from its
/// options: `over-tls`, `tls-name`/`sni`, `skip-cert-verify`, `alpn`,
/// `transport` with `path` and `host` (ws) or `grpc-service-name` (grpc),
/// and REALITY's `public-key` and `short-id`. `transport=http` (HTTP/1.1
/// header obfuscation) and unknown transports make the node unsupported.
fn loon_stream_options(options: &[String]) -> DomainResult<ProxyStreamOptions> {
    let code = SUBSCRIPTION_LOON_PROXY_LINE_INVALID_CODE;
    let option = |key: &str| loon_proxy_option(options, key);
    let mut stream = ProxyStreamOptions::default();
    let public_key = option("public_key");
    if public_key.is_some() {
        stream.set("security", Some("reality".to_string()));
        stream.set("pbk", public_key);
        stream.set("sid", option("short_id"));
    } else if let Some(tls) =
        proxy_line_boolean(option("over_tls").as_ref(), code, "loon over-tls")?
    {
        let security = if tls { "tls" } else { "none" };
        stream.set("security", Some(security.to_string()));
    }
    stream.set("sni", option("sni").or_else(|| option("tls_name")));
    if let Some(insecure) = proxy_line_boolean(
        option("skip_cert_verify").as_ref(),
        code,
        "loon skip-cert-verify",
    )? {
        stream.set("insecure", Some(insecure.to_string()));
    }
    stream.set("alpn", option("alpn"));
    if let Some(transport) = option("transport") {
        stream.set_transport(&transport);
        match stream.query.get("type").map(String::as_str) {
            Some("ws") => {
                stream.set("path", option("path"));
                stream.set("host", option("host"));
            }
            Some("grpc") => stream.set(
                "servicename",
                option("grpc_service_name").or_else(|| option("service_name")),
            ),
            _ => {}
        }
    }
    Ok(stream)
}

/// The SIP003 plugin of a Loon Shadowsocks line from the fields after its
/// password: `obfs-name=http|tls` (or `obfs=`), a positional `http`/`tls`
/// as older lines write it, or ShadowTLS (`shadow-tls-password=`).
fn loon_shadowsocks_plugin(options: &[String]) -> Option<String> {
    if let Some(obfs) =
        loon_proxy_option(options, "obfs_name").or_else(|| loon_proxy_option(options, "obfs"))
    {
        return Some(obfs_plugin_name(&obfs));
    }
    if loon_proxy_option(options, "shadow_tls_password").is_some() {
        return Some("shadow-tls".to_string());
    }
    options
        .iter()
        .map(|field| field.trim())
        .find(|field| !field.is_empty() && !is_proxy_line_option(field))
        .filter(|field| matches!(normalized_token(field).as_str(), "http" | "tls"))
        .map(obfs_plugin_name)
}

/// Whether a `type, server, port, ...` definition is in Surge's style, where
/// the fields after the port are `key=value` options, rather than Loon's,
/// where the credentials follow the port as positional fields (the cipher
/// and password of shadowsocks, the password of trojan, the UUID of vless,
/// the cipher and UUID of vmess).
///
/// Only the first field after the port decides. A positional password or
/// SS-2022 key may itself contain `=` (base64 padding), so containing `=`
/// alone does not make a field an option; see [`is_proxy_line_option`].
fn is_surge_style_proxy_definition(parts: &[String]) -> bool {
    parts
        .get(3..)
        .unwrap_or_default()
        .iter()
        .find(|field| !field.is_empty())
        .is_some_and(|field| is_proxy_line_option(field))
}

/// Whether a proxy line field is a `key=value` option: not quoted, a key
/// that is a word (a letter, then letters, digits, `-` or `_`), and a value
/// that is more than `=` padding. A base64 value such as `aGVsbG8=` or
/// `AAAAAAAAAAAAAAAAAAAAAA==` splits into a word and padding only, so it
/// stays a positional value.
fn is_proxy_line_option(field: &str) -> bool {
    if field.starts_with('"') {
        return false;
    }
    let Some((key, value)) = field.split_once('=') else {
        return false;
    };
    let mut key = key.trim().chars();
    key.next().is_some_and(|first| first.is_ascii_alphabetic())
        && key.all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        && !value.trim().trim_matches('=').is_empty()
}

fn required_loon_proxy_part(
    parts: &[String],
    index: usize,
    message: &'static str,
) -> DomainResult<String> {
    let value = parts.get(index).cloned().unwrap_or_default();
    let value = strip_loon_quotes(value);
    required_trimmed(value, SUBSCRIPTION_LOON_PROXY_LINE_INVALID_CODE, message)
}

fn strip_loon_quotes(value: String) -> String {
    let value = value.trim();
    if value.len() >= 2 && value.starts_with('"') && value.ends_with('"') {
        value[1..value.len() - 1].to_string()
    } else {
        value.to_string()
    }
}

fn parse_surge_proxy_line_subscription(
    source_id: &str,
    content: &str,
) -> DomainResult<Option<SubscriptionDocument>> {
    let content = content.trim();
    if content.is_empty() {
        return Ok(None);
    }

    let mut saw_proxy_section = false;
    let mut in_proxy_section = false;
    let mut proxy_lines = Vec::new();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with("//") {
            continue;
        }

        if let Some(section) = parse_surge_section_header(line) {
            in_proxy_section = normalized_token(section).as_str() == "proxy";
            saw_proxy_section |= in_proxy_section;
            continue;
        }

        if in_proxy_section {
            proxy_lines.push(line.to_string());
        }
    }

    if !saw_proxy_section {
        return Ok(None);
    }
    if proxy_lines.is_empty() {
        return Err(domain_error(
            SUBSCRIPTION_SURGE_PROXY_LINE_INVALID_CODE,
            "surge proxy section cannot be empty",
        ));
    }

    let mut nodes = Vec::new();
    let mut seen_ids = BTreeSet::new();
    let mut skipped = SkippedEntries::new("surge proxy line");
    for (index, line) in proxy_lines.iter().enumerate() {
        if proxy_line_builtin_policy(line).is_some() {
            continue;
        }
        match parse_surge_proxy_line(line, source_id) {
            Ok(node) => push_unique_node(&mut nodes, &mut seen_ids, node),
            Err(error) => {
                let (name, kind) = proxy_line_name_and_kind(line);
                skipped.skip(index, name, kind, error);
            }
        }
    }

    skipped
        .finish(nodes, || {
            domain_error(
                SUBSCRIPTION_SURGE_PROXY_LINE_UNSUPPORTED_CODE,
                "surge proxy section must contain at least one supported proxy",
            )
        })
        .map(Some)
}

fn parse_surge_proxy_line(line: &str, source_id: &str) -> DomainResult<NodeDescriptor> {
    let (name, definition) = line.split_once('=').ok_or_else(|| {
        domain_error(
            SUBSCRIPTION_SURGE_PROXY_LINE_INVALID_CODE,
            "surge proxy line must contain name and definition",
        )
    })?;
    let name = required_trimmed(
        name.to_string(),
        SUBSCRIPTION_SURGE_PROXY_LINE_INVALID_CODE,
        "surge proxy name cannot be empty",
    )?;
    let parts = definition
        .split(',')
        .map(|part| part.trim().to_string())
        .collect::<Vec<_>>();
    if parts.len() < 3 || parts.iter().take(3).any(String::is_empty) {
        return Err(domain_error(
            SUBSCRIPTION_SURGE_PROXY_LINE_INVALID_CODE,
            "surge proxy line must contain type, server, and port",
        ));
    }

    let protocol_token = normalized_token(&parts[0]);
    let host = required_trimmed(
        parts[1].clone(),
        SUBSCRIPTION_SURGE_PROXY_LINE_INVALID_CODE,
        "surge proxy server cannot be empty",
    )?;
    let port = parts[2].parse::<i64>().map_err(|_| {
        domain_error(
            SUBSCRIPTION_SURGE_PROXY_LINE_INVALID_CODE,
            "surge proxy port must be a number",
        )
    })?;
    let port = parse_port(
        port,
        SUBSCRIPTION_SURGE_PROXY_LINE_INVALID_CODE,
        "surge proxy port must be between 1 and 65535",
    )?;
    let options = collect_surge_proxy_options(&parts[3..])?;

    let (protocol, protocol_tag, mut metadata) = match protocol_token.as_str() {
        "ss" | "shadowsocks" => {
            let method = required_surge_proxy_option(
                &options,
                &["encrypt_method", "method"],
                "surge shadowsocks encrypt-method cannot be empty",
            )?;
            let password = required_surge_proxy_option(
                &options,
                &["password"],
                "surge shadowsocks password cannot be empty",
            )?;
            let mut metadata = vec![
                MetadataEntry {
                    key: NODE_METADATA_SHADOWSOCKS_METHOD.to_string(),
                    value: method,
                },
                MetadataEntry {
                    key: NODE_METADATA_SHADOWSOCKS_PASSWORD.to_string(),
                    value: password,
                },
            ];
            // simple-obfs (`obfs=http|tls`) or ShadowTLS
            // (`shadow-tls-password=`).
            let plugin = match options
                .get("obfs")
                .map(String::as_str)
                .map(obfs_plugin_name)
            {
                Some(name) if !name.is_empty() => Some(name),
                _ => options
                    .contains_key("shadow_tls_password")
                    .then(|| "shadow-tls".to_string()),
            };
            metadata.extend(shadowsocks_plugin_entry(plugin));
            (Protocol::Shadowsocks, "ss", metadata)
        }
        "trojan" => {
            let password = required_surge_proxy_option(
                &options,
                &["password"],
                "surge trojan password cannot be empty",
            )?;
            (
                Protocol::Trojan,
                "trojan",
                vec![MetadataEntry {
                    key: NODE_METADATA_TROJAN_PASSWORD.to_string(),
                    value: password,
                }],
            )
        }
        "vmess" => {
            let uuid = required_surge_proxy_option(
                &options,
                &["username", "uuid"],
                "surge vmess username cannot be empty",
            )?;
            let mut metadata = vec![MetadataEntry {
                key: NODE_METADATA_VMESS_UUID.to_string(),
                value: uuid,
            }];
            metadata.extend(proxy_vmess_security(options.get("encrypt_method").cloned()));
            (Protocol::Vmess, "vmess", metadata)
        }
        "snell" => {
            let psk =
                required_surge_proxy_option(&options, &["psk"], "surge snell psk cannot be empty")?;
            let option = |key: &str| options.get(key).cloned();
            (
                Protocol::Snell,
                "snell",
                snell_metadata(SnellFields {
                    psk,
                    version: option("version"),
                    mode: option("mode"),
                    obfs: option("obfs"),
                    obfs_host: option("obfs_host"),
                    obfs_uri: option("obfs_uri"),
                    reuse: option("reuse"),
                    user_key: option("userkey"),
                }),
            )
        }
        _ => {
            return Err(domain_error(
                SUBSCRIPTION_SURGE_PROXY_LINE_UNSUPPORTED_CODE,
                "surge proxy type must be ss, trojan, vmess, or snell for catalog import",
            ));
        }
    };
    if matches!(protocol, Protocol::Trojan | Protocol::Vmess) {
        metadata.extend(proxy_line_pin_metadata(
            options.get("server_cert_fingerprint_sha256").cloned(),
            None,
        ));
        surge_stream_options(&options)?.append_to(
            &mut metadata,
            &host,
            protocol == Protocol::Trojan,
            SUBSCRIPTION_SURGE_PROXY_LINE_INVALID_CODE,
            "surge proxy",
        )?;
    }

    let name_id = sanitize_identifier(&name);
    let name_id = if name_id.is_empty() {
        "node".to_string()
    } else {
        name_id
    };
    let id = format!("surge-{protocol_tag}-{name_id}");
    metadata.push(MetadataEntry {
        key: NODE_METADATA_SOURCE_FORMAT.to_string(),
        value: "surge-proxy-line".to_string(),
    });
    metadata.push(MetadataEntry {
        key: "subscription.source_id".to_string(),
        value: source_id.to_string(),
    });

    Ok(NodeDescriptor {
        id,
        name,
        protocol,
        endpoint: Endpoint { host, port },
        tags: vec![
            "subscription".to_string(),
            "surge-proxy-line".to_string(),
            protocol_tag.to_string(),
        ],
        metadata,
    })
}

/// The share-link settings of a Surge vmess or trojan line: `tls`, `sni`,
/// `skip-cert-verify`, and `ws` with `ws-path` and the `Host` of
/// `ws-headers`. `sni=off` (no SNI) is not carried; the node then sends the
/// server name.
fn surge_stream_options(options: &BTreeMap<String, String>) -> DomainResult<ProxyStreamOptions> {
    let code = SUBSCRIPTION_SURGE_PROXY_LINE_INVALID_CODE;
    let mut stream = ProxyStreamOptions::default();
    if let Some(tls) = proxy_line_boolean(options.get("tls"), code, "surge tls")? {
        let security = if tls { "tls" } else { "none" };
        stream.set("security", Some(security.to_string()));
    }
    stream.set(
        "sni",
        options
            .get("sni")
            .filter(|sni| !sni.trim().eq_ignore_ascii_case("off"))
            .cloned(),
    );
    if let Some(insecure) = proxy_line_boolean(
        options.get("skip_cert_verify"),
        code,
        "surge skip-cert-verify",
    )? {
        stream.set("insecure", Some(insecure.to_string()));
    }
    if proxy_line_boolean(options.get("ws"), code, "surge ws")? == Some(true) {
        stream.set_transport("ws");
        stream.set("path", options.get("ws_path").cloned());
        stream.set(
            "host",
            options
                .get("ws_headers")
                .map(String::as_str)
                .and_then(surge_ws_host_header),
        );
    }
    Ok(stream)
}

/// Snell node options shared by the Surge and Clash parsers.
struct SnellFields {
    psk: String,
    version: Option<String>,
    mode: Option<String>,
    obfs: Option<String>,
    obfs_host: Option<String>,
    obfs_uri: Option<String>,
    reuse: Option<String>,
    user_key: Option<String>,
}

fn snell_metadata(fields: SnellFields) -> Metadata {
    let mut metadata = vec![MetadataEntry {
        key: NODE_METADATA_SNELL_PSK.to_string(),
        value: fields.psk,
    }];
    for (key, value) in [
        (NODE_METADATA_SNELL_VERSION, fields.version),
        (
            NODE_METADATA_SNELL_MODE,
            fields.mode.map(|v| v.to_ascii_lowercase()),
        ),
        (
            NODE_METADATA_SNELL_OBFS,
            fields.obfs.map(|v| v.to_ascii_lowercase()),
        ),
        (NODE_METADATA_SNELL_OBFS_HOST, fields.obfs_host),
        (NODE_METADATA_SNELL_OBFS_URI, fields.obfs_uri),
        (
            NODE_METADATA_SNELL_REUSE,
            fields.reuse.map(|v| v.to_ascii_lowercase()),
        ),
        (NODE_METADATA_SNELL_USER_KEY, fields.user_key),
    ] {
        if let Some(value) = value {
            metadata.push(MetadataEntry {
                key: key.to_string(),
                value,
            });
        }
    }
    metadata
}

fn parse_surge_section_header(line: &str) -> Option<&str> {
    line.strip_prefix('[')?.strip_suffix(']')
}

fn collect_surge_proxy_options(parts: &[String]) -> DomainResult<BTreeMap<String, String>> {
    let mut options = BTreeMap::new();
    for part in parts {
        if part.is_empty() {
            continue;
        }
        let Some((key, value)) = part.split_once('=') else {
            return Err(domain_error(
                SUBSCRIPTION_SURGE_PROXY_LINE_INVALID_CODE,
                "surge proxy option must use key=value",
            ));
        };
        let key = normalized_token(key);
        let value = required_trimmed(
            value.to_string(),
            SUBSCRIPTION_SURGE_PROXY_LINE_INVALID_CODE,
            "surge proxy option value cannot be empty",
        )?;
        if !key.is_empty() {
            options.insert(key, value);
        }
    }
    Ok(options)
}

fn required_surge_proxy_option(
    options: &BTreeMap<String, String>,
    keys: &[&str],
    message: &'static str,
) -> DomainResult<String> {
    for key in keys {
        if let Some(value) = options.get(*key) {
            return required_trimmed(
                value.clone(),
                SUBSCRIPTION_SURGE_PROXY_LINE_INVALID_CODE,
                message,
            );
        }
    }

    Err(domain_error(
        SUBSCRIPTION_SURGE_PROXY_LINE_INVALID_CODE,
        message,
    ))
}

fn parse_proxy_link_lines(source_id: &str, content: &str) -> DomainResult<SubscriptionDocument> {
    let mut nodes = Vec::new();
    let mut seen_ids = BTreeSet::new();
    let mut skipped = SkippedEntries::new("share link");
    // An AnixOps `#anixops:path=<kind>` line describes the link after it.
    let mut path: Option<String> = None;

    for (index, line) in content
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .enumerate()
    {
        if let Some(comment) = line.strip_prefix('#') {
            if let Some(kind) = comment.trim().strip_prefix(ANIXOPS_PATH_MARK) {
                path = Some(kind.trim().to_string()).filter(|kind| is_path_kind(kind));
            }
            continue;
        }
        let path = path.take();
        let Some(parser) = share_link_parser(line) else {
            continue;
        };
        let scheme = line.split_once("://").map(|(scheme, _)| scheme);
        let parsed =
            take_link_via(line).and_then(|(link, via)| parser(&link).map(|node| (node, via)));
        let (mut node, via) = match parsed {
            Ok(parsed) => parsed,
            Err(error) => {
                skipped.skip(index, None, scheme, error);
                continue;
            }
        };
        if let Some(via) = via {
            node.metadata.push(MetadataEntry {
                key: NODE_METADATA_VIA_UNRESOLVED.to_string(),
                value: via,
            });
        }
        if let Some(path) = path {
            node.metadata.push(MetadataEntry {
                key: NODE_METADATA_PATH.to_string(),
                value: path,
            });
        }
        node.metadata.push(MetadataEntry {
            key: "subscription.source_id".to_string(),
            value: source_id.to_string(),
        });
        push_unique_node(&mut nodes, &mut seen_ids, node);
    }
    resolve_vias(&mut nodes);

    skipped.finish(nodes, || {
        domain_error(
            SUBSCRIPTION_LINK_UNSUPPORTED_CODE,
            "subscription link list did not contain supported proxy links",
        )
    })
}

/// The parser for a share link's scheme; `None` for lines of other schemes,
/// which a link list skips silently.
fn share_link_parser(line: &str) -> Option<fn(&str) -> DomainResult<NodeDescriptor>> {
    let parser: fn(&str) -> DomainResult<NodeDescriptor> = if line.starts_with("ss://") {
        parse_shadowsocks_link
    } else if line.starts_with("trojan://") {
        parse_trojan_link
    } else if line.starts_with("vless://") {
        parse_vless_link
    } else if line.starts_with("vmess://") {
        parse_vmess_link
    } else if line.starts_with("hysteria2://") || line.starts_with("hy2://") {
        parse_hysteria2_link
    } else if line.starts_with("tuic://") {
        parse_tuic_link
    } else if line.starts_with("wireguard://") {
        parse_wireguard_link
    } else if line.starts_with("mierus://") {
        parse_mieru_link
    } else if line.starts_with("iwan://") {
        parse_iwan_link
    } else if line.starts_with("anx://") {
        parse_anx_link
    } else {
        return None;
    };
    Some(parser)
}

/// The AnixOps subscription line that marks the next link's path
/// (`#anixops:path=trunk`); other `#` lines stay comments.
const ANIXOPS_PATH_MARK: &str = "anixops:path=";

/// Path kinds a mark may carry: 1-32 of `[a-z0-9_-]`, so a later kind
/// passes through to clients that know it.
fn is_path_kind(kind: &str) -> bool {
    (1..=32).contains(&kind.len())
        && kind.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'_' | b'-')
        })
}

/// Takes the AnixOps `via` query field (the name of the node a link connects
/// through, like a sing-box `detour`) off a share link, so the protocol's own
/// parser never sees it. A `vmess://` link carries it after its base64 body.
fn take_link_via(line: &str) -> DomainResult<(String, Option<String>)> {
    let (without_fragment, fragment) = split_once_optional(line, '#');
    let (main, query) = split_once_optional(without_fragment, '?');
    let Some(query) = query else {
        return Ok((line.to_string(), None));
    };
    let mut via = None;
    let mut kept = Vec::new();
    for entry in query.split('&') {
        let key = entry.split_once('=').map_or(entry, |(key, _)| key);
        if key.eq_ignore_ascii_case("via") {
            let value = entry.split_once('=').map_or("", |(_, value)| value);
            let value = percent_decode(value).map_err(|_| {
                domain_error(
                    SUBSCRIPTION_LINK_UNSUPPORTED_CODE,
                    "share link via is not valid percent encoding",
                )
            })?;
            via = Some(value.trim().to_string()).filter(|value| !value.is_empty());
        } else {
            kept.push(entry);
        }
    }
    if via.is_none() {
        return Ok((line.to_string(), None));
    }
    let mut rebuilt = main.to_string();
    if !kept.is_empty() {
        rebuilt.push('?');
        rebuilt.push_str(&kept.join("&"));
    }
    if let Some(fragment) = fragment {
        rebuilt.push('#');
        rebuilt.push_str(fragment);
    }
    Ok((rebuilt, via))
}

/// Parses an AnixOps Panabit iWAN link:
/// `iwan://user:password@host:port?mtu=1400&encrypt=1#name`.
fn parse_iwan_link(link: &str) -> DomainResult<NodeDescriptor> {
    let invalid = |message: &str| domain_error(SUBSCRIPTION_IWAN_LINK_INVALID_CODE, message);
    let payload = link
        .strip_prefix("iwan://")
        .ok_or_else(|| invalid("iwan link must start with iwan://"))?;
    let (without_fragment, fragment) = split_once_optional(payload, '#');
    let name = fragment
        .and_then(|fragment| percent_decode(fragment).ok())
        .filter(|name| !name.trim().is_empty());
    let (main_without_query, query) = split_once_optional(without_fragment, '?');
    let (userinfo, host_port) = main_without_query
        .rsplit_once('@')
        .ok_or_else(|| invalid("iwan link must contain a login and an endpoint"))?;
    let (username, password) = userinfo
        .split_once(':')
        .ok_or_else(|| invalid("iwan link login must be username:password"))?;
    let decode = |value: &str| percent_decode(value).unwrap_or_else(|_| value.to_string());
    let username = required_trimmed(
        decode(username),
        SUBSCRIPTION_IWAN_LINK_INVALID_CODE,
        "iwan username cannot be empty",
    )?;
    let password = required_trimmed(
        decode(password),
        SUBSCRIPTION_IWAN_LINK_INVALID_CODE,
        "iwan password cannot be empty",
    )?;
    let (host, port) = parse_host_port_for(host_port, SUBSCRIPTION_IWAN_LINK_INVALID_CODE, "iwan")?;
    let query = parse_share_link_query(query, SUBSCRIPTION_IWAN_LINK_INVALID_CODE, "iwan")?;
    let host_id = sanitize_identifier(&host);
    let host_id = if host_id.is_empty() {
        "host".to_string()
    } else {
        host_id
    };
    let id = format!("iwan-{host_id}-{port}");
    let name = name.unwrap_or_else(|| id.clone());

    let mut metadata = vec![
        MetadataEntry {
            key: NODE_METADATA_IWAN_USERNAME.to_string(),
            value: username,
        },
        MetadataEntry {
            key: NODE_METADATA_IWAN_PASSWORD.to_string(),
            value: password,
        },
    ];
    if let Some(mtu) = query.get("mtu").filter(|mtu| !mtu.trim().is_empty()) {
        metadata.push(MetadataEntry {
            key: NODE_METADATA_IWAN_MTU.to_string(),
            value: mtu.trim().to_string(),
        });
    }
    if let Some(encrypt) = query.get("encrypt") {
        metadata.push(MetadataEntry {
            key: NODE_METADATA_IWAN_ENCRYPT.to_string(),
            value: parse_share_link_boolean(
                encrypt,
                SUBSCRIPTION_IWAN_LINK_INVALID_CODE,
                "iwan encrypt",
            )?
            .to_string(),
        });
    }
    metadata.push(MetadataEntry {
        key: NODE_METADATA_SOURCE_FORMAT.to_string(),
        value: "iwan-url".to_string(),
    });

    Ok(NodeDescriptor {
        id,
        name,
        protocol: Protocol::Iwan,
        endpoint: Endpoint { host, port },
        tags: vec!["subscription".to_string(), "iwan".to_string()],
        metadata,
    })
}

/// Parses an AnixOps ANX-A link:
/// `anx://<user key>@host:port?sni=<name>&pk=<server public key>&alpn=h2,http/1.1&fp=chrome#name`.
/// The user key is 64 hex digits; `pk` is the server's public key text. `sni` is
/// optional: leave it out and the client sends no SNI.
fn parse_anx_link(link: &str) -> DomainResult<NodeDescriptor> {
    let invalid = |message: &str| domain_error(SUBSCRIPTION_ANX_LINK_INVALID_CODE, message);
    let payload = link
        .strip_prefix("anx://")
        .ok_or_else(|| invalid("anx link must start with anx://"))?;
    let (without_fragment, fragment) = split_once_optional(payload, '#');
    let name = fragment
        .and_then(|fragment| percent_decode(fragment).ok())
        .filter(|name| !name.trim().is_empty());
    let (main_without_query, query) = split_once_optional(without_fragment, '?');
    let (user_key, host_port) = main_without_query
        .rsplit_once('@')
        .ok_or_else(|| invalid("anx link must contain a user key and an endpoint"))?;
    let user_key = required_trimmed(
        user_key.to_string(),
        SUBSCRIPTION_ANX_LINK_INVALID_CODE,
        "anx user key cannot be empty",
    )?;
    if user_key.len() != 64 || !user_key.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(invalid("anx user key must be 64 hex digits"));
    }
    let (host, port) = parse_host_port_for(host_port, SUBSCRIPTION_ANX_LINK_INVALID_CODE, "anx")?;
    let query = parse_share_link_query(query, SUBSCRIPTION_ANX_LINK_INVALID_CODE, "anx")?;
    let public_key = required_trimmed(
        query.get("pk").cloned().unwrap_or_default(),
        SUBSCRIPTION_ANX_LINK_INVALID_CODE,
        "anx link needs pk, the server public key",
    )?;
    // `sni` is optional: without it the client sends no SNI, for servers that
    // accept connections to their IP address directly.
    let server_name = query
        .get("sni")
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty());
    let host_id = sanitize_identifier(&host);
    let host_id = if host_id.is_empty() {
        "host".to_string()
    } else {
        host_id
    };
    let id = format!("anx-{host_id}-{port}");
    let name = name.unwrap_or_else(|| id.clone());

    let mut metadata = vec![
        MetadataEntry {
            key: NODE_METADATA_ANX_USER_KEY.to_string(),
            value: user_key,
        },
        MetadataEntry {
            key: NODE_METADATA_ANX_PUBLIC_KEY.to_string(),
            value: public_key,
        },
    ];
    if let Some(server_name) = server_name {
        metadata.push(MetadataEntry {
            key: NODE_METADATA_ANX_SERVER_NAME.to_string(),
            value: server_name,
        });
    }
    for (query_key, metadata_key) in [
        ("alpn", NODE_METADATA_ANX_ALPN),
        ("fp", NODE_METADATA_ANX_FINGERPRINT),
    ] {
        if let Some(value) = query
            .get(query_key)
            .filter(|value| !value.trim().is_empty())
        {
            metadata.push(MetadataEntry {
                key: metadata_key.to_string(),
                value: value.trim().to_string(),
            });
        }
    }
    // `jacket` picks the outer shape (auto, wg, bare or a2); `wg_port` is the
    // UDP port of the wg jacket, which `jacket=wg` needs; `bare_port` is the
    // TCP port of the bare jacket, which `jacket=bare` needs.
    let jacket = query
        .get("jacket")
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty());
    if let Some(jacket) = &jacket {
        if !matches!(jacket.as_str(), "auto" | "wg" | "bare" | "a2") {
            return Err(invalid("anx jacket must be auto, wg, bare or a2"));
        }
    }
    let wg_port = match query.get("wg_port").map(|value| value.trim()) {
        None | Some("") => None,
        Some(value) => match value.parse::<u16>() {
            Ok(port) if port > 0 => Some(port),
            _ => return Err(invalid("anx wg_port must be a port number")),
        },
    };
    if jacket.as_deref() == Some("wg") && wg_port.is_none() {
        return Err(invalid("anx jacket wg needs wg_port"));
    }
    let bare_port = match query.get("bare_port").map(|value| value.trim()) {
        None | Some("") => None,
        Some(value) => match value.parse::<u16>() {
            Ok(port) if port > 0 => Some(port),
            _ => return Err(invalid("anx bare_port must be a port number")),
        },
    };
    if jacket.as_deref() == Some("bare") && bare_port.is_none() {
        return Err(invalid("anx jacket bare needs bare_port"));
    }
    if let Some(jacket) = jacket {
        metadata.push(MetadataEntry {
            key: NODE_METADATA_ANX_JACKET.to_string(),
            value: jacket,
        });
    }
    if let Some(port) = wg_port {
        metadata.push(MetadataEntry {
            key: NODE_METADATA_ANX_WG_PORT.to_string(),
            value: port.to_string(),
        });
    }
    if let Some(port) = bare_port {
        metadata.push(MetadataEntry {
            key: NODE_METADATA_ANX_BARE_PORT.to_string(),
            value: port.to_string(),
        });
    }
    metadata.push(MetadataEntry {
        key: NODE_METADATA_SOURCE_FORMAT.to_string(),
        value: "anx-url".to_string(),
    });

    Ok(NodeDescriptor {
        id,
        name,
        protocol: Protocol::Anx,
        endpoint: Endpoint { host, port },
        tags: vec!["subscription".to_string(), "anx".to_string()],
        metadata,
    })
}

/// A `port=` / `protocol=` pair of a simple share link.
struct MieruBinding {
    port: String,
    protocol: String,
}

/// `P` or `A-B` as (first port, range text when it is a range).
fn parse_mieru_port_binding(value: &str) -> DomainResult<(u16, Option<String>)> {
    let invalid = || {
        domain_error(
            SUBSCRIPTION_MIERU_LINK_INVALID_CODE,
            "Mieru port must be a port or a port range",
        )
    };
    let value = value.trim();
    let parse = |text: &str| {
        text.trim()
            .parse::<u16>()
            .ok()
            .filter(|port| *port != 0)
            .ok_or_else(invalid)
    };
    match value.split_once('-') {
        None => Ok((parse(value)?, None)),
        Some((low, high)) => {
            let (low, high) = (parse(low)?, parse(high)?);
            if low > high {
                return Err(invalid());
            }
            Ok((low, Some(format!("{low}-{high}"))))
        }
    }
}

/// Parses the official simple share link
/// (`mierus://user:pass@host?port=P&protocol=TCP&...`, `port`/`protocol`
/// repeating in pairs) and the older `mierus://user:pass@host:port?...` form.
fn parse_mieru_link(link: &str) -> DomainResult<NodeDescriptor> {
    let payload = link.strip_prefix("mierus://").ok_or_else(|| {
        domain_error(
            SUBSCRIPTION_MIERU_LINK_INVALID_CODE,
            "Mieru link must start with mierus://",
        )
    })?;
    let (without_fragment, fragment) = split_once_optional(payload, '#');
    let name = fragment
        .map(percent_decode)
        .transpose()
        .map_err(|_| {
            domain_error(
                SUBSCRIPTION_MIERU_LINK_INVALID_CODE,
                "Mieru link name is not valid percent encoding",
            )
        })?
        .filter(|value| !value.trim().is_empty());
    let (authority, query) = split_once_optional(without_fragment, '?');
    let (userinfo, host_port) = authority.rsplit_once('@').ok_or_else(|| {
        domain_error(
            SUBSCRIPTION_MIERU_LINK_INVALID_CODE,
            "Mieru link must contain credentials and endpoint",
        )
    })?;
    let (username, password) = userinfo.split_once(':').ok_or_else(|| {
        domain_error(
            SUBSCRIPTION_MIERU_LINK_INVALID_CODE,
            "Mieru link credentials must contain username and password",
        )
    })?;
    let username = required_trimmed(
        percent_decode(username).map_err(|_| {
            domain_error(
                SUBSCRIPTION_MIERU_LINK_INVALID_CODE,
                "Mieru username is not valid percent encoding",
            )
        })?,
        SUBSCRIPTION_MIERU_LINK_INVALID_CODE,
        "Mieru username cannot be empty",
    )?;
    let password = required_trimmed(
        percent_decode(password).map_err(|_| {
            domain_error(
                SUBSCRIPTION_MIERU_LINK_INVALID_CODE,
                "Mieru password is not valid percent encoding",
            )
        })?,
        SUBSCRIPTION_MIERU_LINK_INVALID_CODE,
        "Mieru password cannot be empty",
    )?;
    let fields = parse_share_link_query(query, SUBSCRIPTION_MIERU_LINK_INVALID_CODE, "Mieru")?;
    // `port` and `protocol` repeat, so read them in order from the raw query.
    let mut ports = Vec::new();
    let mut protocols = Vec::new();
    for entry in query.unwrap_or_default().split('&') {
        let Some((key, value)) = entry.split_once('=') else {
            continue;
        };
        let value = percent_decode(value).unwrap_or_default();
        match key.trim().to_ascii_lowercase().as_str() {
            "port" => ports.push(value),
            "protocol" => protocols.push(value),
            _ => {}
        }
    }
    let mut transport = "TCP".to_string();
    let mut port_range = fields
        .get("port_range")
        .or_else(|| fields.get("ports"))
        .map(|value| {
            required_trimmed(
                value.clone(),
                SUBSCRIPTION_MIERU_LINK_INVALID_CODE,
                "Mieru port range cannot be empty",
            )
        })
        .transpose()?;
    let (host, port) = if ports.is_empty() {
        parse_host_port_for(host_port, SUBSCRIPTION_MIERU_LINK_INVALID_CODE, "Mieru")?
    } else {
        if ports.len() != protocols.len() {
            return Err(domain_error(
                SUBSCRIPTION_MIERU_LINK_INVALID_CODE,
                "Mieru port and protocol must appear in pairs",
            ));
        }
        let bindings: Vec<MieruBinding> = ports
            .into_iter()
            .zip(protocols)
            .map(|(port, protocol)| MieruBinding {
                port,
                protocol: protocol.trim().to_ascii_uppercase(),
            })
            .collect();
        let binding = bindings
            .iter()
            .find(|binding| binding.protocol == "TCP")
            .unwrap_or(&bindings[0]);
        if binding.protocol != "TCP" && binding.protocol != "UDP" {
            return Err(domain_error(
                SUBSCRIPTION_MIERU_LINK_INVALID_CODE,
                "Mieru protocol must be TCP or UDP",
            ));
        }
        transport = binding.protocol.clone();
        let (port, range) = parse_mieru_port_binding(&binding.port)?;
        if range.is_some() {
            port_range = range;
        }
        let host = host_port
            .strip_prefix('[')
            .and_then(|rest| rest.strip_suffix(']'))
            .unwrap_or(host_port);
        let host = required_trimmed(
            host.to_string(),
            SUBSCRIPTION_MIERU_LINK_INVALID_CODE,
            "Mieru host cannot be empty",
        )?;
        (host, port)
    };
    let host_id = sanitize_identifier(&host);
    let host_id = if host_id.is_empty() { "host" } else { &host_id };
    let id = format!("mieru-{host_id}-{port}");
    let mut metadata = vec![
        MetadataEntry {
            key: NODE_METADATA_MIERU_USERNAME.to_string(),
            value: username,
        },
        MetadataEntry {
            key: NODE_METADATA_MIERU_PASSWORD.to_string(),
            value: password,
        },
        MetadataEntry {
            key: NODE_METADATA_MIERU_TRANSPORT.to_string(),
            value: transport,
        },
    ];
    if let Some(value) = port_range {
        metadata.push(MetadataEntry {
            key: NODE_METADATA_MIERU_PORT_RANGE.to_string(),
            value,
        });
    }
    if let Some(value) = fields.get("mtu") {
        let value = value.parse::<u16>().map_err(|_| {
            domain_error(
                SUBSCRIPTION_MIERU_LINK_INVALID_CODE,
                "Mieru mtu must be an unsigned 16-bit integer",
            )
        })?;
        metadata.push(MetadataEntry {
            key: NODE_METADATA_MIERU_MTU.to_string(),
            value: value.to_string(),
        });
    }
    if let Some(value) = fields
        .get("multiplexing")
        .or_else(|| fields.get("multiplex"))
    {
        metadata.push(MetadataEntry {
            key: NODE_METADATA_MIERU_MULTIPLEXING.to_string(),
            value: parse_mieru_multiplexing(value)?.to_string(),
        });
    }
    for (keys, metadata_key) in [
        (
            ["handshake_mode", "handshake-mode", "handshake"],
            NODE_METADATA_MIERU_HANDSHAKE_MODE,
        ),
        (
            ["traffic_pattern", "traffic-pattern", "traffic"],
            NODE_METADATA_MIERU_TRAFFIC_PATTERN,
        ),
    ] {
        if let Some(value) = keys.iter().find_map(|key| fields.get(*key)) {
            metadata.push(MetadataEntry {
                key: metadata_key.to_string(),
                value: required_trimmed(
                    value.clone(),
                    SUBSCRIPTION_MIERU_LINK_INVALID_CODE,
                    "Mieru option cannot be empty",
                )?,
            });
        }
    }
    metadata.push(MetadataEntry {
        key: NODE_METADATA_SOURCE_FORMAT.to_string(),
        value: "mierus-url".to_string(),
    });
    Ok(NodeDescriptor {
        id,
        name: name.unwrap_or_else(|| format!("Mieru {host}")),
        protocol: Protocol::Mieru,
        endpoint: Endpoint { host, port },
        tags: vec!["subscription".to_string(), "mieru".to_string()],
        metadata,
    })
}

/// A boolean, or a `MULTIPLEXING_*` level (anything but `OFF` is on).
fn parse_mieru_multiplexing(value: &str) -> DomainResult<bool> {
    match normalized_token(value).as_str() {
        "1" | "true" | "yes" => Ok(true),
        "0" | "false" | "no" | "multiplexing_off" => Ok(false),
        "multiplexing_low" | "multiplexing_middle" | "multiplexing_high" => Ok(true),
        _ => Err(domain_error(
            SUBSCRIPTION_MIERU_LINK_INVALID_CODE,
            "Mieru multiplexing must be a boolean or a MULTIPLEXING_ level",
        )),
    }
}

fn parse_shadowsocks_link(link: &str) -> DomainResult<NodeDescriptor> {
    let payload = link.strip_prefix("ss://").ok_or_else(|| {
        domain_error(
            SUBSCRIPTION_SHADOWSOCKS_LINK_INVALID_CODE,
            "shadowsocks link must start with ss://",
        )
    })?;
    let (without_fragment, fragment) = split_once_optional(payload, '#');
    let name = fragment
        .and_then(|fragment| percent_decode(fragment).ok())
        .filter(|name| !name.trim().is_empty());
    let (main_without_query, query) = split_once_optional(without_fragment, '?');
    // SIP003 `plugin=<name>;<options>`; only the name is kept, the options
    // can hold passwords. Other query fields (`outline=1`, ...) do not
    // change the connection and are not read.
    let plugin = shadowsocks_plugin_entry(
        query
            .into_iter()
            .flat_map(|query| query.split('&'))
            .find_map(|entry| {
                let (key, value) = entry.split_once('=')?;
                key.trim().eq_ignore_ascii_case("plugin").then(|| {
                    let value = percent_decode(value).unwrap_or_else(|_| value.to_string());
                    let (name, _) = split_once_optional(&value, ';');
                    name.to_string()
                })
            }),
    );

    let decoded_main = if main_without_query.contains('@') {
        main_without_query.to_string()
    } else {
        decode_base64_text(main_without_query).ok_or_else(|| {
            domain_error(
                SUBSCRIPTION_SHADOWSOCKS_LINK_INVALID_CODE,
                "shadowsocks link payload is not valid base64",
            )
        })?
    };

    let (userinfo, host_port) = decoded_main.rsplit_once('@').ok_or_else(|| {
        domain_error(
            SUBSCRIPTION_SHADOWSOCKS_LINK_INVALID_CODE,
            "shadowsocks link must contain credentials and endpoint",
        )
    })?;
    let credentials = decode_base64_text(userinfo).unwrap_or_else(|| userinfo.to_string());
    let (method, password) = credentials.split_once(':').ok_or_else(|| {
        domain_error(
            SUBSCRIPTION_SHADOWSOCKS_LINK_INVALID_CODE,
            "shadowsocks credentials must contain method and password",
        )
    })?;
    let method = required_trimmed(
        method.to_string(),
        SUBSCRIPTION_SHADOWSOCKS_LINK_INVALID_CODE,
        "shadowsocks method cannot be empty",
    )?;
    let password = required_trimmed(
        password.to_string(),
        SUBSCRIPTION_SHADOWSOCKS_LINK_INVALID_CODE,
        "shadowsocks password cannot be empty",
    )?;
    // SIP002 puts a `/` between the port and the query (`@host:8388/?plugin=`).
    let host_port = host_port.strip_suffix('/').unwrap_or(host_port);
    let (host, port) = parse_host_port_for(
        host_port,
        SUBSCRIPTION_SHADOWSOCKS_LINK_INVALID_CODE,
        "shadowsocks",
    )?;
    let host_id = sanitize_identifier(&host);
    let host_id = if host_id.is_empty() {
        "host".to_string()
    } else {
        host_id
    };
    let id = format!("ss-{}-{port}", host_id);
    let name = name.unwrap_or_else(|| id.clone());

    Ok(NodeDescriptor {
        id,
        name,
        protocol: Protocol::Shadowsocks,
        endpoint: Endpoint { host, port },
        tags: vec!["subscription".to_string(), "ss".to_string()],
        metadata: vec![
            MetadataEntry {
                key: NODE_METADATA_SHADOWSOCKS_METHOD.to_string(),
                value: method,
            },
            MetadataEntry {
                key: NODE_METADATA_SHADOWSOCKS_PASSWORD.to_string(),
                value: password,
            },
            MetadataEntry {
                key: NODE_METADATA_SOURCE_FORMAT.to_string(),
                value: "ss-url".to_string(),
            },
        ]
        .into_iter()
        .chain(plugin)
        .collect(),
    })
}

fn parse_trojan_link(link: &str) -> DomainResult<NodeDescriptor> {
    let payload = link.strip_prefix("trojan://").ok_or_else(|| {
        domain_error(
            SUBSCRIPTION_TROJAN_LINK_INVALID_CODE,
            "trojan link must start with trojan://",
        )
    })?;
    let (without_fragment, fragment) = split_once_optional(payload, '#');
    let name = fragment
        .and_then(|fragment| percent_decode(fragment).ok())
        .filter(|name| !name.trim().is_empty());
    let (main_without_query, query) = split_once_optional(without_fragment, '?');
    let (password, host_port) = main_without_query.rsplit_once('@').ok_or_else(|| {
        domain_error(
            SUBSCRIPTION_TROJAN_LINK_INVALID_CODE,
            "trojan link must contain password and endpoint",
        )
    })?;
    let password = percent_decode(password).unwrap_or_else(|_| password.to_string());
    let password = required_trimmed(
        password,
        SUBSCRIPTION_TROJAN_LINK_INVALID_CODE,
        "trojan password cannot be empty",
    )?;
    let (host, port) =
        parse_host_port_for(host_port, SUBSCRIPTION_TROJAN_LINK_INVALID_CODE, "trojan")?;
    let host_id = sanitize_identifier(&host);
    let host_id = if host_id.is_empty() {
        "host".to_string()
    } else {
        host_id
    };
    let id = format!("trojan-{}-{port}", host_id);
    let name = name.unwrap_or_else(|| id.clone());

    let query = parse_share_link_query(query, SUBSCRIPTION_TROJAN_LINK_INVALID_CODE, "trojan")?;
    let mut metadata = vec![MetadataEntry {
        key: NODE_METADATA_TROJAN_PASSWORD.to_string(),
        value: password,
    }];
    append_v2ray_share_link_metadata(
        &mut metadata,
        &query,
        &host,
        true,
        SUBSCRIPTION_TROJAN_LINK_INVALID_CODE,
        "trojan",
    )?;
    metadata.push(MetadataEntry {
        key: NODE_METADATA_SOURCE_FORMAT.to_string(),
        value: "trojan-url".to_string(),
    });

    Ok(NodeDescriptor {
        id,
        name,
        protocol: Protocol::Trojan,
        endpoint: Endpoint { host, port },
        tags: vec!["subscription".to_string(), "trojan".to_string()],
        metadata,
    })
}

fn parse_vless_link(link: &str) -> DomainResult<NodeDescriptor> {
    let payload = link.strip_prefix("vless://").ok_or_else(|| {
        domain_error(
            SUBSCRIPTION_VLESS_LINK_INVALID_CODE,
            "vless link must start with vless://",
        )
    })?;
    let (without_fragment, fragment) = split_once_optional(payload, '#');
    let name = fragment
        .and_then(|fragment| percent_decode(fragment).ok())
        .filter(|name| !name.trim().is_empty());
    let (main_without_query, query) = split_once_optional(without_fragment, '?');
    let (uuid, host_port) = main_without_query.rsplit_once('@').ok_or_else(|| {
        domain_error(
            SUBSCRIPTION_VLESS_LINK_INVALID_CODE,
            "vless link must contain uuid and endpoint",
        )
    })?;
    let uuid = percent_decode(uuid).unwrap_or_else(|_| uuid.to_string());
    let uuid = required_trimmed(
        uuid,
        SUBSCRIPTION_VLESS_LINK_INVALID_CODE,
        "vless uuid cannot be empty",
    )?;
    let (host, port) =
        parse_host_port_for(host_port, SUBSCRIPTION_VLESS_LINK_INVALID_CODE, "vless")?;
    let host_id = sanitize_identifier(&host);
    let host_id = if host_id.is_empty() {
        "host".to_string()
    } else {
        host_id
    };
    let id = format!("vless-{}-{port}", host_id);
    let name = name.unwrap_or_else(|| id.clone());

    let query = parse_share_link_query(query, SUBSCRIPTION_VLESS_LINK_INVALID_CODE, "vless")?;
    let mut metadata = vec![MetadataEntry {
        key: NODE_METADATA_VLESS_UUID.to_string(),
        value: uuid,
    }];
    if let Some(flow) = query.get("flow").filter(|value| !value.trim().is_empty()) {
        metadata.push(MetadataEntry {
            key: NODE_METADATA_VLESS_FLOW.to_string(),
            value: flow.trim().to_string(),
        });
    }
    if let Some(encryption) = query
        .get("encryption")
        .map(|value| value.trim())
        .filter(|value| !value.is_empty() && *value != "none")
    {
        metadata.push(MetadataEntry {
            key: NODE_METADATA_VLESS_ENCRYPTION.to_string(),
            value: encryption.to_string(),
        });
    }
    append_v2ray_share_link_metadata(
        &mut metadata,
        &query,
        &host,
        false,
        SUBSCRIPTION_VLESS_LINK_INVALID_CODE,
        "vless",
    )?;

    Ok(NodeDescriptor {
        id,
        name,
        protocol: Protocol::Vless,
        endpoint: Endpoint { host, port },
        tags: vec!["subscription".to_string(), "vless".to_string()],
        metadata: {
            metadata.push(MetadataEntry {
                key: NODE_METADATA_SOURCE_FORMAT.to_string(),
                value: "vless-url".to_string(),
            });
            metadata
        },
    })
}

fn parse_vmess_link(link: &str) -> DomainResult<NodeDescriptor> {
    let payload = link.strip_prefix("vmess://").ok_or_else(|| {
        domain_error(
            SUBSCRIPTION_VMESS_LINK_INVALID_CODE,
            "vmess link must start with vmess://",
        )
    })?;
    let decoded = decode_base64_text(payload).ok_or_else(|| {
        domain_error(
            SUBSCRIPTION_VMESS_LINK_INVALID_CODE,
            "vmess link payload is not valid base64",
        )
    })?;
    let value = serde_json::from_str::<serde_json::Value>(&decoded).map_err(|_| {
        domain_error(
            SUBSCRIPTION_VMESS_LINK_INVALID_CODE,
            "vmess link payload is not valid json",
        )
    })?;
    let uuid = required_json_text_field(
        &value,
        "id",
        SUBSCRIPTION_VMESS_LINK_INVALID_CODE,
        "vmess uuid cannot be empty",
    )?;
    let host = required_json_text_field(
        &value,
        "add",
        SUBSCRIPTION_VMESS_LINK_INVALID_CODE,
        "vmess host cannot be empty",
    )?;
    let port = required_json_text_field(
        &value,
        "port",
        SUBSCRIPTION_VMESS_LINK_INVALID_CODE,
        "vmess port cannot be empty",
    )?;
    let port = port.parse::<i64>().map_err(|_| {
        domain_error(
            SUBSCRIPTION_VMESS_LINK_INVALID_CODE,
            "vmess port must be a number",
        )
    })?;
    let port = parse_port(
        port,
        SUBSCRIPTION_VMESS_LINK_INVALID_CODE,
        "vmess port must be between 1 and 65535",
    )?;
    let host_id = sanitize_identifier(&host);
    let host_id = if host_id.is_empty() {
        "host".to_string()
    } else {
        host_id
    };
    let id = format!("vmess-{}-{port}", host_id);
    let name = optional_json_text_field(&value, "ps").unwrap_or_else(|| id.clone());

    let mut query = BTreeMap::new();
    for (json_key, query_key) in [
        ("tls", "tls"),
        ("sni", "sni"),
        ("alpn", "alpn"),
        ("allowInsecure", "allowinsecure"),
        ("insecure", "insecure"),
        ("pcs", "pcs"),
        ("fp", "fp"),
        ("pbk", "pbk"),
        ("sid", "sid"),
        ("net", "type"),
        ("host", "host"),
        ("path", "path"),
        ("serviceName", "servicename"),
        ("mode", "mode"),
        ("extra", "extra"),
    ] {
        if let Some(field) = optional_json_text_field(&value, json_key) {
            query.insert(query_key.to_string(), field);
        }
    }
    let mut metadata = vec![MetadataEntry {
        key: NODE_METADATA_VMESS_UUID.to_string(),
        value: uuid,
    }];
    if let Some(security) = optional_json_text_field(&value, "scy") {
        metadata.push(MetadataEntry {
            key: NODE_METADATA_VMESS_SECURITY.to_string(),
            value: security,
        });
    }
    if let Some(alter_id) = optional_json_text_field(&value, "aid") {
        metadata.push(MetadataEntry {
            key: NODE_METADATA_VMESS_ALTER_ID.to_string(),
            value: alter_id,
        });
    }
    append_v2ray_share_link_metadata(
        &mut metadata,
        &query,
        &host,
        false,
        SUBSCRIPTION_VMESS_LINK_INVALID_CODE,
        "vmess",
    )?;

    Ok(NodeDescriptor {
        id,
        name,
        protocol: Protocol::Vmess,
        endpoint: Endpoint { host, port },
        tags: vec!["subscription".to_string(), "vmess".to_string()],
        metadata: {
            metadata.push(MetadataEntry {
                key: NODE_METADATA_SOURCE_FORMAT.to_string(),
                value: "vmess-url".to_string(),
            });
            metadata
        },
    })
}

fn parse_hysteria2_link(link: &str) -> DomainResult<NodeDescriptor> {
    let payload = link
        .strip_prefix("hysteria2://")
        .or_else(|| link.strip_prefix("hy2://"))
        .ok_or_else(|| {
            domain_error(
                SUBSCRIPTION_HYSTERIA2_LINK_INVALID_CODE,
                "hysteria2 link must start with hysteria2:// or hy2://",
            )
        })?;
    let parsed = parse_quic_share_link(
        payload,
        SUBSCRIPTION_HYSTERIA2_LINK_INVALID_CODE,
        "hysteria2",
    )?;
    let password = required_trimmed(
        parsed.userinfo.clone(),
        SUBSCRIPTION_HYSTERIA2_LINK_INVALID_CODE,
        "hysteria2 password cannot be empty",
    )?;
    let mut metadata = vec![MetadataEntry {
        key: NODE_METADATA_HYSTERIA2_PASSWORD.to_string(),
        value: password,
    }];
    append_query_tls_metadata(
        &mut metadata,
        &parsed.query,
        &parsed.host,
        SUBSCRIPTION_HYSTERIA2_LINK_INVALID_CODE,
    )?;
    if let Some(server_ports) = parsed.query.get("mport") {
        let server_ports = normalize_hysteria2_server_port_ranges(
            vec![server_ports.to_string()],
            SUBSCRIPTION_HYSTERIA2_LINK_INVALID_CODE,
        )?
        .join(",");
        metadata.push(MetadataEntry {
            key: NODE_METADATA_HYSTERIA2_SERVER_PORTS.to_string(),
            value: server_ports,
        });
    }
    if let Some(kind) = parsed.query.get("obfs") {
        let kind = normalized_token(kind);
        if !matches!(kind.as_str(), "salamander" | "gecko") {
            return Err(domain_error(
                SUBSCRIPTION_HYSTERIA2_LINK_INVALID_CODE,
                "hysteria2 obfs must be salamander or gecko",
            ));
        }
        let password = required_query_value(
            &parsed.query,
            "obfs-password",
            SUBSCRIPTION_HYSTERIA2_LINK_INVALID_CODE,
            "hysteria2 obfs-password cannot be empty when obfs is configured",
        )?;
        metadata.push(MetadataEntry {
            key: NODE_METADATA_HYSTERIA2_OBFS_TYPE.to_string(),
            value: kind.clone(),
        });
        metadata.push(MetadataEntry {
            key: NODE_METADATA_HYSTERIA2_OBFS_PASSWORD.to_string(),
            value: password,
        });
        if kind == "gecko" {
            if let Some(value) = parsed.query.get("minpacketsize") {
                metadata.push(MetadataEntry {
                    key: NODE_METADATA_HYSTERIA2_OBFS_MIN_PACKET_SIZE.to_string(),
                    value: normalize_hysteria2_packet_size(
                        value.to_string(),
                        SUBSCRIPTION_HYSTERIA2_LINK_INVALID_CODE,
                    )?,
                });
            }
            if let Some(value) = parsed.query.get("maxpacketsize") {
                metadata.push(MetadataEntry {
                    key: NODE_METADATA_HYSTERIA2_OBFS_MAX_PACKET_SIZE.to_string(),
                    value: normalize_hysteria2_packet_size(
                        value.to_string(),
                        SUBSCRIPTION_HYSTERIA2_LINK_INVALID_CODE,
                    )?,
                });
            }
        }
    }

    Ok(quic_node_descriptor(
        "hysteria2",
        Protocol::Hysteria2,
        parsed,
        metadata,
    ))
}

fn parse_tuic_link(link: &str) -> DomainResult<NodeDescriptor> {
    let payload = link.strip_prefix("tuic://").ok_or_else(|| {
        domain_error(
            SUBSCRIPTION_TUIC_LINK_INVALID_CODE,
            "tuic link must start with tuic://",
        )
    })?;
    let parsed = parse_quic_share_link(payload, SUBSCRIPTION_TUIC_LINK_INVALID_CODE, "tuic")?;
    let (uuid, password) = parsed
        .userinfo
        .split_once(':')
        .map(|(uuid, password)| (uuid.to_string(), Some(password.to_string())))
        .unwrap_or_else(|| (parsed.userinfo.clone(), None));
    let uuid = required_trimmed(
        uuid,
        SUBSCRIPTION_TUIC_LINK_INVALID_CODE,
        "tuic uuid cannot be empty",
    )?;
    let mut metadata = vec![MetadataEntry {
        key: NODE_METADATA_TUIC_UUID.to_string(),
        value: uuid,
    }];
    if let Some(password) = password {
        metadata.push(MetadataEntry {
            key: NODE_METADATA_TUIC_PASSWORD.to_string(),
            value: password,
        });
    }
    if let Some(congestion_control) = parsed.query.get("congestion_control") {
        let congestion_control = required_trimmed(
            congestion_control.to_string(),
            SUBSCRIPTION_TUIC_LINK_INVALID_CODE,
            "tuic congestion_control cannot be empty",
        )?;
        if !matches!(congestion_control.as_str(), "cubic" | "new_reno" | "bbr") {
            return Err(domain_error(
                SUBSCRIPTION_TUIC_LINK_INVALID_CODE,
                "tuic congestion_control must be cubic, new_reno, or bbr",
            ));
        }
        metadata.push(MetadataEntry {
            key: NODE_METADATA_TUIC_CONGESTION_CONTROL.to_string(),
            value: congestion_control,
        });
    }
    append_query_tls_metadata(
        &mut metadata,
        &parsed.query,
        &parsed.host,
        SUBSCRIPTION_TUIC_LINK_INVALID_CODE,
    )?;

    Ok(quic_node_descriptor(
        "tuic",
        Protocol::Tuic,
        parsed,
        metadata,
    ))
}

fn parse_wireguard_link(link: &str) -> DomainResult<NodeDescriptor> {
    let payload = link.strip_prefix("wireguard://").ok_or_else(|| {
        domain_error(
            SUBSCRIPTION_WIREGUARD_LINK_INVALID_CODE,
            "wireguard link must start with wireguard://",
        )
    })?;
    let parsed = parse_quic_share_link(
        payload,
        SUBSCRIPTION_WIREGUARD_LINK_INVALID_CODE,
        "wireguard",
    )?;
    let private_key = validate_wireguard_key(
        &parsed.userinfo,
        SUBSCRIPTION_WIREGUARD_LINK_INVALID_CODE,
        "private key",
    )?;
    let peer_public_key = required_query_value(
        &parsed.query,
        "publickey",
        SUBSCRIPTION_WIREGUARD_LINK_INVALID_CODE,
        "wireguard publickey is required",
    )?;
    let peer_public_key = validate_wireguard_key(
        &peer_public_key,
        SUBSCRIPTION_WIREGUARD_LINK_INVALID_CODE,
        "publickey",
    )?;
    let local_address = required_query_value(
        &parsed.query,
        "address",
        SUBSCRIPTION_WIREGUARD_LINK_INVALID_CODE,
        "wireguard address is required",
    )?;
    let local_address =
        normalize_wireguard_addresses(&local_address, SUBSCRIPTION_WIREGUARD_LINK_INVALID_CODE)?;
    let mut metadata = vec![
        MetadataEntry {
            key: NODE_METADATA_WIREGUARD_PRIVATE_KEY.to_string(),
            value: private_key,
        },
        MetadataEntry {
            key: NODE_METADATA_WIREGUARD_PEER_PUBLIC_KEY.to_string(),
            value: peer_public_key,
        },
        MetadataEntry {
            key: NODE_METADATA_WIREGUARD_LOCAL_ADDRESS.to_string(),
            value: local_address,
        },
    ];
    if let Some(value) = parsed.query.get("presharedkey") {
        metadata.push(MetadataEntry {
            key: NODE_METADATA_WIREGUARD_PRE_SHARED_KEY.to_string(),
            value: validate_wireguard_key(
                value,
                SUBSCRIPTION_WIREGUARD_LINK_INVALID_CODE,
                "presharedkey",
            )?,
        });
    }
    if let Some(value) = parsed.query.get("mtu") {
        let mtu = value.trim().parse::<u16>().map_err(|_| {
            domain_error(
                SUBSCRIPTION_WIREGUARD_LINK_INVALID_CODE,
                "wireguard mtu must be an unsigned 16-bit integer",
            )
        })?;
        if mtu == 0 {
            return Err(domain_error(
                SUBSCRIPTION_WIREGUARD_LINK_INVALID_CODE,
                "wireguard mtu must be greater than zero",
            ));
        }
        metadata.push(MetadataEntry {
            key: NODE_METADATA_WIREGUARD_MTU.to_string(),
            value: mtu.to_string(),
        });
    }
    if let Some(value) = parsed.query.get("allowedips") {
        metadata.push(MetadataEntry {
            key: NODE_METADATA_WIREGUARD_ALLOWED_IPS.to_string(),
            value: normalize_wireguard_addresses(value, SUBSCRIPTION_WIREGUARD_LINK_INVALID_CODE)?,
        });
    }
    if let Some(value) = parsed.query.get("reserved") {
        metadata.push(MetadataEntry {
            key: NODE_METADATA_WIREGUARD_RESERVED.to_string(),
            value: normalize_wireguard_reserved(value, SUBSCRIPTION_WIREGUARD_LINK_INVALID_CODE)?,
        });
    }
    Ok(quic_node_descriptor(
        "wireguard",
        Protocol::WireGuard,
        parsed,
        metadata,
    ))
}

fn validate_wireguard_key(
    value: &str,
    code: &'static str,
    field: &'static str,
) -> DomainResult<String> {
    let value = value.trim();
    if value.is_empty() {
        return Err(domain_error(
            code,
            format!("wireguard {field} cannot be empty"),
        ));
    }
    let decoded = [STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD]
        .iter()
        .find_map(|engine| engine.decode(value).ok());
    if !matches!(decoded, Some(ref bytes) if bytes.len() == 32) {
        return Err(domain_error(
            code,
            format!("wireguard {field} must be a base64-encoded 32-byte key"),
        ));
    }
    Ok(value.to_string())
}

/// Three reserved header bytes as `a,b,c` decimals (`reserved=1,2,3`).
fn normalize_wireguard_reserved(value: &str, code: &'static str) -> DomainResult<String> {
    let bytes = value
        .split(',')
        .map(|byte| byte.trim().parse::<u8>())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| domain_error(code, "wireguard reserved must be three bytes"))?;
    if bytes.len() != 3 {
        return Err(domain_error(code, "wireguard reserved must be three bytes"));
    }
    Ok(format!("{},{},{}", bytes[0], bytes[1], bytes[2]))
}

fn normalize_wireguard_addresses(value: &str, code: &'static str) -> DomainResult<String> {
    let addresses = value
        .split(',')
        .map(str::trim)
        .map(|address| {
            let (host, prefix) = address.split_once('/').ok_or_else(|| {
                domain_error(code, "wireguard address entries must use CIDR notation")
            })?;
            let host = host.parse::<std::net::IpAddr>().map_err(|_| {
                domain_error(
                    code,
                    "wireguard address entries must contain valid IP addresses",
                )
            })?;
            let prefix = prefix.parse::<u8>().map_err(|_| {
                domain_error(code, "wireguard address prefixes must be unsigned integers")
            })?;
            let maximum_prefix = match host {
                std::net::IpAddr::V4(_) => 32,
                std::net::IpAddr::V6(_) => 128,
            };
            if prefix > maximum_prefix {
                return Err(domain_error(
                    code,
                    "wireguard address prefix exceeds the address family limit",
                ));
            }
            Ok(format!("{host}/{prefix}"))
        })
        .collect::<DomainResult<Vec<_>>>()?;
    if addresses.is_empty() {
        return Err(domain_error(code, "wireguard address cannot be empty"));
    }
    Ok(addresses.join(","))
}

#[derive(Debug)]
struct ParsedQuicShareLink {
    userinfo: String,
    host: String,
    port: u16,
    name: Option<String>,
    query: BTreeMap<String, String>,
}

fn parse_quic_share_link(
    payload: &str,
    code: &'static str,
    protocol_name: &'static str,
) -> DomainResult<ParsedQuicShareLink> {
    let (without_fragment, fragment) = split_once_optional(payload, '#');
    let name = fragment
        .map(percent_decode)
        .transpose()
        .map_err(|_| {
            domain_error(
                code,
                format!("{protocol_name} link name is not valid percent encoding"),
            )
        })?
        .filter(|name| !name.trim().is_empty());
    let (authority, query) = split_once_optional(without_fragment, '?');
    let (userinfo, host_port) = authority.rsplit_once('@').ok_or_else(|| {
        domain_error(
            code,
            format!("{protocol_name} link must contain credentials and endpoint"),
        )
    })?;
    let userinfo = percent_decode(userinfo).map_err(|_| {
        domain_error(
            code,
            format!("{protocol_name} link credentials are not valid percent encoding"),
        )
    })?;
    let (host, port) = parse_host_port_for(host_port, code, protocol_name)?;
    let query = parse_share_link_query(query, code, protocol_name)?;
    Ok(ParsedQuicShareLink {
        userinfo,
        host,
        port,
        name,
        query,
    })
}

fn parse_share_link_query(
    query: Option<&str>,
    code: &'static str,
    protocol_name: &'static str,
) -> DomainResult<BTreeMap<String, String>> {
    let mut values = BTreeMap::new();
    let Some(query) = query else {
        return Ok(values);
    };
    for entry in query.split('&') {
        if entry.is_empty() {
            continue;
        }
        let (key, value) = entry.split_once('=').ok_or_else(|| {
            domain_error(
                code,
                format!("{protocol_name} query fields must use key=value"),
            )
        })?;
        let key = percent_decode(key).map_err(|_| {
            domain_error(
                code,
                format!("{protocol_name} query key is not valid percent encoding"),
            )
        })?;
        let value = percent_decode(value).map_err(|_| {
            domain_error(
                code,
                format!("{protocol_name} query value is not valid percent encoding"),
            )
        })?;
        let key = key.trim().to_ascii_lowercase();
        if key.is_empty() {
            return Err(domain_error(
                code,
                format!("{protocol_name} query key cannot be empty"),
            ));
        }
        values.insert(key, value);
    }
    Ok(values)
}

fn quic_node_descriptor(
    protocol_tag: &'static str,
    protocol: Protocol,
    parsed: ParsedQuicShareLink,
    mut metadata: Metadata,
) -> NodeDescriptor {
    let host_id = sanitize_identifier(&parsed.host);
    let host_id = if host_id.is_empty() {
        "host".to_string()
    } else {
        host_id
    };
    let id = format!("{protocol_tag}-{host_id}-{}", parsed.port);
    let name = parsed.name.unwrap_or_else(|| id.clone());
    metadata.push(MetadataEntry {
        key: NODE_METADATA_SOURCE_FORMAT.to_string(),
        value: format!("{protocol_tag}-url"),
    });
    NodeDescriptor {
        id,
        name,
        protocol,
        endpoint: Endpoint {
            host: parsed.host,
            port: parsed.port,
        },
        tags: vec!["subscription".to_string(), protocol_tag.to_string()],
        metadata,
    }
}

fn append_query_tls_metadata(
    metadata: &mut Metadata,
    query: &BTreeMap<String, String>,
    host: &str,
    code: &'static str,
) -> DomainResult<()> {
    let server_name = query
        .get("sni")
        .filter(|value| !value.trim().is_empty())
        .cloned()
        .unwrap_or_else(|| host.to_string());
    metadata.push(MetadataEntry {
        key: NODE_METADATA_TLS_SERVER_NAME.to_string(),
        value: server_name,
    });
    let insecure = query
        .get("insecure")
        .or_else(|| query.get("allowinsecure"))
        .or_else(|| query.get("allow_insecure"))
        .map(|value| parse_share_link_boolean(value, code, "TLS insecure"))
        .transpose()?
        .unwrap_or(false);
    metadata.push(MetadataEntry {
        key: NODE_METADATA_TLS_INSECURE.to_string(),
        value: insecure.to_string(),
    });
    if let Some(alpn) = query.get("alpn") {
        let alpn = split_share_link_list(alpn, code, "TLS alpn")?;
        metadata.push(MetadataEntry {
            key: NODE_METADATA_TLS_ALPN.to_string(),
            value: alpn.join(","),
        });
    }
    // Hysteria2 `pinSHA256` and Xray `pcs` both pin the whole certificate.
    let mut pins = Vec::new();
    for key in ["pinsha256", "pcs"] {
        if let Some(value) = query.get(key) {
            pins.extend(split_share_link_list(
                value,
                code,
                "TLS certificate sha256",
            )?);
        }
    }
    metadata.extend(certificate_pin_metadata(&pins, &[]));
    Ok(())
}

/// Pin entries for certificate digests (`tls.certificate_sha256`, kept in
/// lowercase hex) and public key digests (`tls.certificate_public_key_sha256`,
/// kept in base64), each written in hex or base64. A value that is not a
/// SHA-256 digest is kept as written, so the node import reports that node as
/// unsupported instead of running it without its pin, and the rest of the
/// subscription still imports.
fn certificate_pin_metadata(certificate: &[String], public_key: &[String]) -> Metadata {
    let mut metadata = Vec::new();
    metadata.extend(pin_metadata_entry(
        NODE_METADATA_TLS_CERTIFICATE_SHA256,
        certificate,
        certificate_pin::to_hex,
    ));
    metadata.extend(pin_metadata_entry(
        NODE_METADATA_TLS_CERTIFICATE_PUBLIC_KEY_SHA256,
        public_key,
        certificate_pin::to_base64,
    ));
    metadata
}

fn pin_metadata_entry(
    key: &str,
    pins: &[String],
    spell: fn(&certificate_pin::Sha256Digest) -> String,
) -> Option<MetadataEntry> {
    let mut values: Vec<String> = Vec::new();
    for pin in pins
        .iter()
        .map(|pin| pin.trim())
        .filter(|pin| !pin.is_empty())
    {
        let value =
            certificate_pin::parse(pin).map_or_else(|| pin.to_string(), |digest| spell(&digest));
        if !values.contains(&value) {
            values.push(value);
        }
    }
    (!values.is_empty()).then(|| MetadataEntry {
        key: key.to_string(),
        value: values.join(","),
    })
}

/// The pin entries of a Clash, Surge, Loon or Quantumult X proxy, whose
/// formats name one certificate digest and one public key digest at most.
fn proxy_line_pin_metadata(certificate: Option<String>, public_key: Option<String>) -> Metadata {
    certificate_pin_metadata(
        &certificate.into_iter().collect::<Vec<_>>(),
        &public_key.into_iter().collect::<Vec<_>>(),
    )
}

/// The TLS, REALITY and transport settings of a Clash, Surge, Loon or
/// Quantumult X proxy, spelled as the fields of the equivalent share link
/// (`security`, `sni`, `insecure`, `alpn`, `fp`, `pbk`, `sid`, `type`,
/// `host`, `path`, `servicename`, `mode`, `extra`), so
/// [`append_v2ray_share_link_metadata`] writes the same node metadata a share
/// link for that node would, and the node imports as the same outbound.
///
/// `unsupported` is an option the format names that no share-link field can
/// carry (one of the `NODE_UNSUPPORTED_OPTION_*` codes). It is written as
/// [`NODE_METADATA_UNSUPPORTED_OPTION`], so the importer reports the node as
/// unsupported instead of running it without that option.
#[derive(Default)]
struct ProxyStreamOptions {
    query: BTreeMap<String, String>,
    unsupported: Option<&'static str>,
}

impl ProxyStreamOptions {
    /// Sets share-link field `key` to `value` when it is not empty.
    fn set(&mut self, key: &str, value: Option<String>) {
        if let Some(value) = value
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
        {
            self.query.insert(key.to_string(), value);
        }
    }

    /// Sets share-link field `key` when it is not set yet.
    fn set_default(&mut self, key: &str, value: Option<String>) {
        if !self.query.contains_key(key) {
            self.set(key, value);
        }
    }

    /// Records the first option that cannot be carried.
    fn unsupported(&mut self, code: &'static str) {
        self.unsupported.get_or_insert(code);
    }

    /// Sets `type` from a transport name: `ws`, `grpc`, `h2` and `xhttp`
    /// as share links spell them; an HTTP/1.1 header obfuscation or a name
    /// no reader knows makes the node unsupported.
    fn set_transport(&mut self, name: &str) {
        match normalized_token(name).as_str() {
            "" | "tcp" | "none" => {}
            "ws" | "websocket" => self.set("type", Some("ws".to_string())),
            "grpc" => self.set("type", Some("grpc".to_string())),
            "h2" => self.set("type", Some("h2".to_string())),
            "httpupgrade" | "http_upgrade" => self.set("type", Some("httpupgrade".to_string())),
            "xhttp" | "splithttp" => self.set("type", Some("xhttp".to_string())),
            "http" => self.unsupported(NODE_UNSUPPORTED_OPTION_HTTP_OBFS),
            _ => self.unsupported(NODE_UNSUPPORTED_OPTION_TRANSPORT),
        }
    }

    /// Writes the settings to `metadata`. `default_tls_enabled` is whether
    /// the protocol runs TLS when the source does not say (trojan).
    fn append_to(
        self,
        metadata: &mut Metadata,
        host: &str,
        default_tls_enabled: bool,
        code: &'static str,
        protocol_name: &'static str,
    ) -> DomainResult<()> {
        append_v2ray_share_link_metadata(
            metadata,
            &self.query,
            host,
            default_tls_enabled,
            code,
            protocol_name,
        )?;
        if let Some(option) = self.unsupported {
            metadata.push(MetadataEntry {
                key: NODE_METADATA_UNSUPPORTED_OPTION.to_string(),
                value: option.to_string(),
            });
        }
        Ok(())
    }
}

/// A boolean option of a proxy line (`true`, `false`, `1`, `0`), as the
/// share-link `security`/`insecure` spelling.
fn proxy_line_boolean(
    value: Option<&String>,
    code: &'static str,
    field_name: &'static str,
) -> DomainResult<Option<bool>> {
    value
        .map(|value| parse_share_link_boolean(value, code, field_name))
        .transpose()
}

/// The `Host` header of a Surge `ws-headers` value (`Host:cdn.example|K:v`).
fn surge_ws_host_header(headers: &str) -> Option<String> {
    headers.split('|').find_map(|header| {
        let (name, value) = header.split_once(':')?;
        name.trim()
            .trim_matches('"')
            .eq_ignore_ascii_case("host")
            .then(|| value.trim().trim_matches('"').trim().to_string())
            .filter(|value| !value.is_empty())
    })
}

/// The metadata entry naming a Shadowsocks plugin, unless `name` is empty or
/// `none`.
fn shadowsocks_plugin_entry(name: Option<String>) -> Option<MetadataEntry> {
    let name = name?.trim().to_string();
    (!name.is_empty() && !name.eq_ignore_ascii_case("none")).then(|| MetadataEntry {
        key: NODE_METADATA_SHADOWSOCKS_PLUGIN.to_string(),
        value: name,
    })
}

/// The VMess security a Clash, Surge, Loon or Quantumult X proxy names, for
/// [`NODE_METADATA_VMESS_SECURITY`]. `none` and `zero` are left out: the
/// client picks the VMess security and servers take any, so such a node runs
/// with the default (`auto`) rather than being refused.
fn proxy_vmess_security(value: Option<String>) -> Option<MetadataEntry> {
    let value = value?.trim().to_ascii_lowercase();
    (!value.is_empty() && value != "none" && value != "zero").then(|| MetadataEntry {
        key: NODE_METADATA_VMESS_SECURITY.to_string(),
        value,
    })
}

/// A Clash scalar option as text: a string trimmed, a number or boolean as
/// YAML read it; `None` when empty, absent or not a scalar.
fn clash_option_text(value: Option<&serde_json::Value>) -> Option<String> {
    let text = match value? {
        serde_json::Value::String(text) => text.trim().to_string(),
        serde_json::Value::Number(number) => number.to_string(),
        serde_json::Value::Bool(flag) => flag.to_string(),
        _ => return None,
    };
    (!text.is_empty()).then_some(text)
}

/// A Clash boolean option: a YAML boolean, or `true`/`false`/`1`/`0`.
fn clash_option_bool(
    value: Option<&serde_json::Value>,
    message: &'static str,
) -> DomainResult<Option<bool>> {
    match value {
        None | Some(serde_json::Value::Null) => Ok(None),
        Some(serde_json::Value::Bool(flag)) => Ok(Some(*flag)),
        Some(serde_json::Value::Number(number)) => match number.as_u64() {
            Some(0) => Ok(Some(false)),
            Some(1) => Ok(Some(true)),
            _ => Err(domain_error(SUBSCRIPTION_CLASH_YAML_INVALID_CODE, message)),
        },
        Some(serde_json::Value::String(text)) => match text.trim().to_ascii_lowercase().as_str() {
            "" => Ok(None),
            "true" | "1" => Ok(Some(true)),
            "false" | "0" => Ok(Some(false)),
            _ => Err(domain_error(SUBSCRIPTION_CLASH_YAML_INVALID_CODE, message)),
        },
        Some(_) => Err(domain_error(SUBSCRIPTION_CLASH_YAML_INVALID_CODE, message)),
    }
}

/// A Clash list option (`alpn: [h2, http/1.1]`, `host: [a, b]`) as a
/// comma-separated list; a single string counts as a list of one.
fn clash_option_list(value: Option<&serde_json::Value>) -> Option<String> {
    let values: Vec<String> = match value? {
        serde_json::Value::Array(values) => values
            .iter()
            .filter_map(|value| clash_option_text(Some(value)))
            .collect(),
        other => clash_option_text(Some(other))
            .map(|text| {
                text.split(',')
                    .map(|value| value.trim().to_string())
                    .filter(|value| !value.is_empty())
                    .collect()
            })
            .unwrap_or_default(),
    };
    (!values.is_empty()).then(|| values.join(","))
}

/// The value of map `object`'s key `name`, ignoring ASCII case (HTTP header
/// names such as `Host`).
fn clash_map_entry<'a>(
    object: Option<&'a serde_json::Value>,
    name: &str,
) -> Option<&'a serde_json::Value> {
    object?
        .as_object()?
        .iter()
        .find(|(key, _)| key.eq_ignore_ascii_case(name))
        .map(|(_, value)| value)
}

/// The share-link settings of a Clash vmess, vless or trojan proxy:
/// `tls`, `servername`/`sni`, `skip-cert-verify`, `alpn`,
/// `client-fingerprint`, `reality-opts`, `network` with `ws-opts`,
/// `grpc-opts`, `h2-opts` or `xhttp-opts`, and `ech-opts`.
fn clash_stream_options(raw: &RawClashStreamOptions) -> DomainResult<ProxyStreamOptions> {
    let mut options = ProxyStreamOptions::default();
    let tls = clash_option_bool(raw.tls.as_ref(), "clash proxy tls must be true or false")?;
    match raw.reality_opts.as_ref().filter(|value| !value.is_null()) {
        // REALITY is TLS; mihomo also wants `tls: true` beside it.
        Some(reality) => {
            options.set("security", Some("reality".to_string()));
            options.set("pbk", clash_option_text(reality.get("public-key")));
            options.set("sid", clash_option_text(reality.get("short-id")));
        }
        None => {
            if let Some(tls) = tls {
                let security = if tls { "tls" } else { "none" };
                options.set("security", Some(security.to_string()));
            }
        }
    }
    options.set(
        "sni",
        clash_option_text(raw.servername.as_ref()).or_else(|| clash_option_text(raw.sni.as_ref())),
    );
    if let Some(insecure) = clash_option_bool(
        raw.skip_cert_verify.as_ref(),
        "clash proxy skip-cert-verify must be true or false",
    )? {
        options.set("insecure", Some(insecure.to_string()));
    }
    options.set("alpn", clash_option_list(raw.alpn.as_ref()));
    options.set("fp", clash_option_text(raw.client_fingerprint.as_ref()));
    if let Some(ech) = raw.ech_opts.as_ref().filter(|value| !value.is_null()) {
        let enabled = clash_option_bool(
            ech.get("enable"),
            "clash proxy ech-opts enable must be true or false",
        )?;
        if enabled.unwrap_or(false) {
            options.unsupported(NODE_UNSUPPORTED_OPTION_ECH);
        }
    }

    let network = clash_option_text(raw.network.as_ref()).unwrap_or_default();
    match normalized_token(&network).as_str() {
        "ws" | "websocket" => {
            let ws = raw.ws_opts.as_ref();
            let upgrade = clash_option_bool(
                ws.and_then(|ws| ws.get("v2ray-http-upgrade")),
                "clash proxy ws-opts v2ray-http-upgrade must be true or false",
            )?;
            options.set_transport(if upgrade.unwrap_or(false) {
                "httpupgrade"
            } else {
                "ws"
            });
            options.set("path", clash_option_text(ws.and_then(|ws| ws.get("path"))));
            options.set(
                "host",
                clash_option_text(clash_map_entry(ws.and_then(|ws| ws.get("headers")), "host")),
            );
        }
        "grpc" => {
            options.set_transport("grpc");
            options.set(
                "servicename",
                clash_option_text(
                    raw.grpc_opts
                        .as_ref()
                        .and_then(|grpc| grpc.get("grpc-service-name")),
                ),
            );
        }
        "h2" => {
            let h2 = raw.h2_opts.as_ref();
            options.set_transport("h2");
            options.set("host", clash_option_list(h2.and_then(|h2| h2.get("host"))));
            options.set("path", clash_option_text(h2.and_then(|h2| h2.get("path"))));
        }
        "xhttp" => {
            options.set_transport("xhttp");
            if let Some(xhttp) = raw.xhttp_opts.as_ref().and_then(|value| value.as_object()) {
                for (key, value) in xhttp {
                    match key.as_str() {
                        "path" => options.set("path", clash_option_text(Some(value))),
                        "host" => options.set("host", clash_option_text(Some(value))),
                        "mode" => options.set("mode", clash_option_text(Some(value))),
                        "headers" if value.is_object() => options.set(
                            "extra",
                            Some(serde_json::json!({ "headers": value }).to_string()),
                        ),
                        "headers" if value.is_null() => {}
                        _ => options.unsupported(NODE_UNSUPPORTED_OPTION_XHTTP),
                    }
                }
            }
        }
        // `http` is HTTP/1.1 header obfuscation in Clash, not h2.
        other => options.set_transport(other),
    }
    Ok(options)
}

fn append_v2ray_share_link_metadata(
    metadata: &mut Metadata,
    query: &BTreeMap<String, String>,
    host: &str,
    default_tls_enabled: bool,
    code: &'static str,
    protocol_name: &'static str,
) -> DomainResult<()> {
    let security = query
        .get("security")
        .or_else(|| query.get("tls"))
        .map(|value| value.trim().to_ascii_lowercase());
    let (tls_enabled, reality_enabled) = match security.as_deref() {
        None | Some("") => (default_tls_enabled, false),
        Some("tls") => (true, false),
        Some("reality") => (true, true),
        Some("none") => (false, false),
        Some(_) => {
            return Err(domain_error(
                code,
                format!("{protocol_name} security must be none, tls, or reality"),
            ));
        }
    };
    metadata.push(MetadataEntry {
        key: NODE_METADATA_TLS_ENABLED.to_string(),
        value: tls_enabled.to_string(),
    });
    if tls_enabled {
        append_query_tls_metadata(metadata, query, host, code)?;
        if let Some(fingerprint) = query.get("fp").filter(|value| !value.trim().is_empty()) {
            metadata.push(MetadataEntry {
                key: NODE_METADATA_TLS_UTLS_FINGERPRINT.to_string(),
                value: fingerprint.trim().to_string(),
            });
        }
    }
    if reality_enabled {
        let public_key = required_query_value(
            query,
            "pbk",
            code,
            "reality public key cannot be empty when security=reality",
        )?;
        metadata.push(MetadataEntry {
            key: NODE_METADATA_TLS_REALITY_PUBLIC_KEY.to_string(),
            value: public_key,
        });
        if let Some(short_id) = query.get("sid").filter(|value| !value.trim().is_empty()) {
            metadata.push(MetadataEntry {
                key: NODE_METADATA_TLS_REALITY_SHORT_ID.to_string(),
                value: short_id.trim().to_string(),
            });
        }
    }
    append_v2ray_share_link_transport_metadata(metadata, query, code, protocol_name)
}

fn append_v2ray_share_link_transport_metadata(
    metadata: &mut Metadata,
    query: &BTreeMap<String, String>,
    code: &'static str,
    protocol_name: &'static str,
) -> DomainResult<()> {
    let Some(raw_type) = query.get("type") else {
        return Ok(());
    };
    let kind = match normalized_token(raw_type).as_str() {
        "" | "tcp" | "raw" | "none" => return Ok(()),
        "ws" | "websocket" => "ws",
        "grpc" => "grpc",
        "http" | "h2" => "http",
        "httpupgrade" | "http_upgrade" => "httpupgrade",
        "quic" => "quic",
        "xhttp" | "splithttp" => "xhttp",
        _ => {
            return Err(domain_error(
                code,
                format!(
                    "{protocol_name} transport must be tcp, ws, grpc, http, httpupgrade, quic, or xhttp"
                ),
            ));
        }
    };
    metadata.push(MetadataEntry {
        key: NODE_METADATA_V2RAY_TRANSPORT_TYPE.to_string(),
        value: kind.to_string(),
    });
    if let Some(host) = query.get("host").filter(|value| !value.trim().is_empty()) {
        metadata.push(MetadataEntry {
            key: NODE_METADATA_V2RAY_TRANSPORT_HOST.to_string(),
            value: split_share_link_list(host, code, "transport host")?.join(","),
        });
    }
    if let Some(path) = query.get("path").filter(|value| !value.trim().is_empty()) {
        metadata.push(MetadataEntry {
            key: NODE_METADATA_V2RAY_TRANSPORT_PATH.to_string(),
            value: path.trim().to_string(),
        });
    }
    if let Some(service_name) = query
        .get("servicename")
        .or_else(|| query.get("service_name"))
        .filter(|value| !value.trim().is_empty())
    {
        metadata.push(MetadataEntry {
            key: NODE_METADATA_V2RAY_TRANSPORT_SERVICE_NAME.to_string(),
            value: service_name.trim().to_string(),
        });
    }
    if kind == "xhttp" {
        if let Some(mode) = query.get("mode").filter(|value| !value.trim().is_empty()) {
            metadata.push(MetadataEntry {
                key: NODE_METADATA_V2RAY_TRANSPORT_MODE.to_string(),
                value: mode.trim().to_string(),
            });
        }
        if let Some(extra) = query.get("extra").filter(|value| !value.trim().is_empty()) {
            metadata.push(MetadataEntry {
                key: NODE_METADATA_V2RAY_TRANSPORT_EXTRA.to_string(),
                value: extra.trim().to_string(),
            });
        }
    }
    Ok(())
}

fn parse_share_link_boolean(
    value: &str,
    code: &'static str,
    field_name: &'static str,
) -> DomainResult<bool> {
    match value.trim().to_ascii_lowercase().as_str() {
        "1" | "true" => Ok(true),
        "0" | "false" | "" => Ok(false),
        _ => Err(domain_error(
            code,
            format!("{field_name} must be 0, 1, false, or true"),
        )),
    }
}

fn split_share_link_list(
    value: &str,
    code: &'static str,
    field_name: &'static str,
) -> DomainResult<Vec<String>> {
    let values = value
        .split(',')
        .map(|value| {
            required_trimmed(
                value.to_string(),
                code,
                format!("{field_name} cannot be empty"),
            )
        })
        .collect::<DomainResult<Vec<_>>>()?;
    if values.is_empty() {
        return Err(domain_error(code, format!("{field_name} cannot be empty")));
    }
    Ok(values)
}

fn required_query_value(
    query: &BTreeMap<String, String>,
    key: &'static str,
    code: &'static str,
    message: &'static str,
) -> DomainResult<String> {
    query
        .get(key)
        .cloned()
        .ok_or_else(|| domain_error(code, message))
        .and_then(|value| required_trimmed(value, code, message))
}

fn normalize_hysteria2_server_port_range(
    value: String,
    code: &'static str,
) -> DomainResult<String> {
    let value = required_trimmed(value, code, "hysteria2 server port range cannot be empty")?;
    let Some((start, end)) = value.split_once(':').or_else(|| value.split_once('-')) else {
        let port = parse_hysteria2_port(&value, code)?;
        return Ok(port.to_string());
    };
    let start = parse_hysteria2_port(start, code)?;
    let end = parse_hysteria2_port(end, code)?;
    if start > end {
        return Err(domain_error(
            code,
            "hysteria2 server port range start cannot exceed end",
        ));
    }
    Ok(format!("{start}:{end}"))
}

fn normalize_hysteria2_server_port_ranges(
    values: Vec<String>,
    code: &'static str,
) -> DomainResult<Vec<String>> {
    let mut normalized = Vec::new();
    for value in values {
        for range in value.split(',') {
            normalized.push(normalize_hysteria2_server_port_range(
                range.to_string(),
                code,
            )?);
        }
    }
    if normalized.is_empty() {
        return Err(domain_error(
            code,
            "hysteria2 server port ranges cannot be empty",
        ));
    }
    Ok(normalized)
}

fn hysteria2_server_port_range_start(value: &str, code: &'static str) -> DomainResult<u16> {
    let start = value
        .split_once(':')
        .map(|(start, _)| start)
        .unwrap_or(value);
    parse_hysteria2_port(start, code)
}

fn parse_hysteria2_port(value: &str, code: &'static str) -> DomainResult<u16> {
    let value = value.trim();
    let port = value
        .parse::<i64>()
        .map_err(|_| domain_error(code, "hysteria2 server port must be a number"))?;
    parse_port(
        port,
        code,
        "hysteria2 server port must be between 1 and 65535",
    )
}

fn normalize_hysteria2_packet_size(value: String, code: &'static str) -> DomainResult<String> {
    let value = required_trimmed(value, code, "hysteria2 obfs packet size cannot be empty")?;
    let value = value.parse::<u32>().map_err(|_| {
        domain_error(
            code,
            "hysteria2 obfs packet size must be a positive integer",
        )
    })?;
    if value == 0 {
        return Err(domain_error(
            code,
            "hysteria2 obfs packet size must be a positive integer",
        ));
    }
    Ok(value.to_string())
}

fn parse_host_port_for(
    value: &str,
    error_code: &'static str,
    protocol_name: &'static str,
) -> DomainResult<(String, u16)> {
    let (host, port) = if let Some(rest) = value.strip_prefix('[') {
        let (host, rest) = rest.split_once(']').ok_or_else(|| {
            domain_error(
                error_code,
                format!("IPv6 {protocol_name} endpoint must close with ]"),
            )
        })?;
        let port = rest.strip_prefix(':').ok_or_else(|| {
            domain_error(
                error_code,
                format!("{protocol_name} endpoint must contain a port"),
            )
        })?;
        (host.to_string(), port)
    } else {
        let (host, port) = value.rsplit_once(':').ok_or_else(|| {
            domain_error(
                error_code,
                format!("{protocol_name} endpoint must contain host and port"),
            )
        })?;
        (host.to_string(), port)
    };
    let host = required_trimmed(
        host,
        error_code,
        format!("{protocol_name} host cannot be empty"),
    )?;
    let port = port
        .parse::<i64>()
        .map_err(|_| domain_error(error_code, format!("{protocol_name} port must be a number")))?;
    let port = parse_port(
        port,
        error_code,
        format!("{protocol_name} port must be between 1 and 65535"),
    )?;

    Ok((host, port))
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

fn collect_routes(raw_routes: Vec<RawRoute>) -> DomainResult<Vec<RuleSet>> {
    raw_routes
        .into_iter()
        .map(normalize_route)
        .collect::<DomainResult<Vec<_>>>()
}

fn normalize_route(raw: RawRoute) -> DomainResult<RuleSet> {
    Ok(RuleSet {
        id: required_trimmed(
            raw.id,
            CONFIG_ROUTE_ID_EMPTY_CODE,
            "route id cannot be empty",
        )?,
        rules: Vec::new(),
        default_action: parse_route_action(raw.default_action, raw.default_node)?,
    })
}

fn parse_route_action(raw_action: String, node_id: Option<String>) -> DomainResult<RouteAction> {
    match normalized_token(&raw_action).as_str() {
        "direct" => Ok(RouteAction::Direct),
        "reject" => Ok(RouteAction::Reject),
        "proxy" => Ok(RouteAction::Proxy {
            node_id: required_trimmed(
                node_id.unwrap_or_default(),
                CONFIG_ROUTE_PROXY_NODE_MISSING_CODE,
                "proxy route action requires a node id",
            )?,
        }),
        _ => Err(domain_error(
            CONFIG_ROUTE_ACTION_UNSUPPORTED_CODE,
            "route action must be direct, proxy, or reject",
        )),
    }
}

fn collect_tags(tags: Option<Vec<String>>) -> Vec<String> {
    tags.unwrap_or_default()
        .into_iter()
        .map(|tag| tag.trim().to_string())
        .filter(|tag| !tag.is_empty())
        .collect()
}

fn collect_metadata(metadata: Option<BTreeMap<String, String>>) -> Metadata {
    metadata
        .unwrap_or_default()
        .into_iter()
        .map(|(key, value)| MetadataEntry {
            key: key.trim().to_string(),
            value,
        })
        .filter(|entry| !entry.key.is_empty())
        .collect()
}

fn parse_port(value: i64, code: &'static str, message: impl Into<String>) -> DomainResult<u16> {
    if !(1..=(u16::MAX as i64)).contains(&value) {
        return Err(domain_error(code, message));
    }

    Ok(value as u16)
}

fn required_trimmed(
    value: String,
    code: &'static str,
    message: impl Into<String>,
) -> DomainResult<String> {
    let value = value.trim().to_string();
    if value.is_empty() {
        Err(domain_error(code, message))
    } else {
        Ok(value)
    }
}

fn normalized_token(value: &str) -> String {
    value.trim().to_ascii_lowercase().replace('-', "_")
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
