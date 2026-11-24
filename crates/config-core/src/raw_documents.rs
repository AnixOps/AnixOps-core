//! Serde shapes of the documents read: the config file and the subscription
//! formats (Clash YAML, sing-box JSON).

use super::*;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RawConfigDocument {
    pub(crate) schema_version: Option<u32>,
    pub(crate) profile: Option<String>,
    pub(crate) profiles: Option<Vec<String>>,
    pub(crate) listeners: Option<Vec<RawListener>>,
    pub(crate) nodes: Option<Vec<RawNode>>,
    pub(crate) routes: Option<Vec<RawRoute>>,
    pub(crate) rules: Option<Vec<String>>,
    pub(crate) policy_groups: Option<Vec<RawPolicyGroup>>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RawPolicyGroup {
    pub(crate) id: String,
    #[serde(rename = "type")]
    pub(crate) kind: String,
    /// Absent for a subnet group.
    #[serde(default)]
    pub(crate) members: Vec<String>,
    pub(crate) default: Option<String>,
    pub(crate) url: Option<String>,
    pub(crate) interval_secs: Option<u32>,
    pub(crate) tolerance_ms: Option<u16>,
    pub(crate) evaluate_before_use: Option<bool>,
    pub(crate) network_rules: Option<Vec<RawNetworkRule>>,
}

/// One subnet group rule: `{"when": "SSID:Home", "target": "DIRECT"}`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RawNetworkRule {
    pub(crate) when: String,
    pub(crate) target: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RawSubscriptionDocument {
    pub(crate) nodes: Option<Vec<RawNode>>,
    pub(crate) routes: Option<Vec<RawRoute>>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct RawClashDocument {
    /// Each entry is read into [`RawClashProxy`] on its own, so one entry
    /// with a field of an unexpected type is skipped instead of hiding the
    /// whole list.
    pub(crate) proxies: Option<Vec<serde_json::Value>>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct RawClashProxy {
    pub(crate) name: Option<RawClashScalar>,
    #[serde(rename = "type")]
    pub(crate) protocol: Option<RawClashScalar>,
    pub(crate) server: Option<RawClashScalar>,
    pub(crate) port: Option<RawClashScalar>,
    pub(crate) cipher: Option<RawClashScalar>,
    pub(crate) password: Option<RawClashScalar>,
    pub(crate) uuid: Option<RawClashScalar>,
    pub(crate) encryption: Option<RawClashScalar>,
    pub(crate) psk: Option<RawClashScalar>,
    pub(crate) version: Option<RawClashScalar>,
    #[serde(rename = "obfs-opts")]
    pub(crate) obfs_opts: Option<RawClashSnellObfs>,
    pub(crate) username: Option<RawClashScalar>,
    pub(crate) transport: Option<RawClashScalar>,
    pub(crate) multiplexing: Option<RawClashScalar>,
    #[serde(rename = "port-range")]
    pub(crate) port_range: Option<RawClashScalar>,
    /// sing-mux client multiplexing (mihomo).
    pub(crate) smux: Option<serde_json::Value>,
    /// Certificate pin (mihomo): SHA-256 of the server's certificate in hex.
    /// The uTLS fingerprint is `client-fingerprint`.
    pub(crate) fingerprint: Option<RawClashScalar>,
    /// TLS, REALITY and transport options of vmess, vless and trojan.
    #[serde(flatten)]
    pub(crate) stream: RawClashStreamOptions,
    /// VLESS flow (`xtls-rprx-vision`).
    pub(crate) flow: Option<serde_json::Value>,
    #[serde(rename = "alterId", alias = "alter-id")]
    pub(crate) alter_id: Option<serde_json::Value>,
    /// Shadowsocks SIP003 plugin (`obfs`, `v2ray-plugin`, `shadow-tls`, ...);
    /// its `plugin-opts` are not read, they can hold passwords.
    pub(crate) plugin: Option<serde_json::Value>,
    /// Extra request headers of an `http` proxy, which the engine does not
    /// send; read only to tell whether there are any.
    pub(crate) headers: Option<serde_json::Value>,
}

/// TLS, REALITY and transport options of a Clash vmess, vless or trojan
/// proxy. YAML gives booleans, lists and maps here, so they are kept as JSON
/// values (see [`clash_stream_options`]) and a value of an unexpected shape
/// is reported for this proxy instead of failing the entry's whole read.
#[derive(Debug, Default, Deserialize)]
pub(crate) struct RawClashStreamOptions {
    pub(crate) tls: Option<serde_json::Value>,
    pub(crate) servername: Option<serde_json::Value>,
    pub(crate) sni: Option<serde_json::Value>,
    #[serde(rename = "skip-cert-verify")]
    pub(crate) skip_cert_verify: Option<serde_json::Value>,
    pub(crate) alpn: Option<serde_json::Value>,
    /// uTLS fingerprint name (`chrome`, `safari`, ...).
    #[serde(rename = "client-fingerprint")]
    pub(crate) client_fingerprint: Option<serde_json::Value>,
    pub(crate) network: Option<serde_json::Value>,
    #[serde(rename = "ws-opts")]
    pub(crate) ws_opts: Option<serde_json::Value>,
    #[serde(rename = "grpc-opts")]
    pub(crate) grpc_opts: Option<serde_json::Value>,
    #[serde(rename = "h2-opts")]
    pub(crate) h2_opts: Option<serde_json::Value>,
    #[serde(rename = "xhttp-opts")]
    pub(crate) xhttp_opts: Option<serde_json::Value>,
    #[serde(rename = "reality-opts")]
    pub(crate) reality_opts: Option<serde_json::Value>,
    #[serde(rename = "ech-opts")]
    pub(crate) ech_opts: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct RawClashSnellObfs {
    pub(crate) mode: Option<RawClashScalar>,
    pub(crate) host: Option<RawClashScalar>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct RawSingBoxDocument {
    /// Each entry is read into [`RawSingBoxOutbound`] on its own, so one
    /// outbound with a field of an unexpected type is skipped instead of
    /// hiding the whole list.
    pub(crate) outbounds: Option<Vec<serde_json::Value>>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct RawSingBoxOutbound {
    #[serde(rename = "type")]
    pub(crate) protocol: Option<RawSingBoxScalar>,
    pub(crate) tag: Option<RawSingBoxScalar>,
    pub(crate) server: Option<RawSingBoxScalar>,
    pub(crate) server_port: Option<RawSingBoxScalar>,
    pub(crate) server_ports: Option<RawSingBoxStringList>,
    pub(crate) method: Option<RawSingBoxScalar>,
    pub(crate) password: Option<RawSingBoxScalar>,
    pub(crate) uuid: Option<RawSingBoxScalar>,
    pub(crate) flow: Option<RawSingBoxScalar>,
    pub(crate) security: Option<RawSingBoxScalar>,
    pub(crate) alter_id: Option<RawSingBoxScalar>,
    pub(crate) congestion_control: Option<RawSingBoxScalar>,
    pub(crate) obfs: Option<RawSingBoxHysteria2Obfs>,
    pub(crate) tls: Option<RawSingBoxTls>,
    pub(crate) transport: Option<RawSingBoxTransport>,
    /// The tag of the outbound this one dials through (a proxy chain).
    pub(crate) detour: Option<RawSingBoxScalar>,
    /// sing-mux client multiplexing.
    pub(crate) multiplex: Option<serde_json::Value>,
    /// iWAN (an AnixOps extension; sing-box has no such type).
    pub(crate) username: Option<RawSingBoxScalar>,
    pub(crate) mtu: Option<RawSingBoxScalar>,
    pub(crate) encrypt: Option<bool>,
    /// Shadowsocks SIP003 plugin (`obfs-local`, `v2ray-plugin`); its
    /// `plugin_opts` are not read, they can hold passwords.
    pub(crate) plugin: Option<RawSingBoxScalar>,
    /// SOCKS version of a `socks` outbound (`4`, `4a`, `5`).
    pub(crate) version: Option<serde_json::Value>,
    /// Request path and extra headers of an `http` outbound, which the
    /// engine does not send; read only to tell whether there are any.
    pub(crate) path: Option<serde_json::Value>,
    pub(crate) headers: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct RawSingBoxHysteria2Obfs {
    #[serde(rename = "type")]
    pub(crate) kind: Option<RawSingBoxScalar>,
    pub(crate) password: Option<RawSingBoxScalar>,
    pub(crate) min_packet_size: Option<RawSingBoxScalar>,
    pub(crate) max_packet_size: Option<RawSingBoxScalar>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct RawSingBoxTls {
    pub(crate) enabled: Option<bool>,
    pub(crate) server_name: Option<RawSingBoxScalar>,
    pub(crate) insecure: Option<bool>,
    pub(crate) alpn: Option<RawSingBoxStringList>,
    /// SHA-256 of the whole leaf certificate, base64 (sing-box 1.15).
    pub(crate) certificate_sha256: Option<RawSingBoxStringList>,
    /// SHA-256 of the leaf certificate's SubjectPublicKeyInfo, base64.
    pub(crate) certificate_public_key_sha256: Option<RawSingBoxStringList>,
    pub(crate) utls: Option<RawSingBoxUtls>,
    pub(crate) reality: Option<RawSingBoxReality>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct RawSingBoxUtls {
    pub(crate) enabled: Option<bool>,
    pub(crate) fingerprint: Option<RawSingBoxScalar>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct RawSingBoxReality {
    pub(crate) enabled: Option<bool>,
    public_key: Option<RawSingBoxScalar>,
    pub(crate) short_id: Option<RawSingBoxScalar>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct RawSingBoxTransport {
    #[serde(rename = "type")]
    pub(crate) kind: Option<RawSingBoxScalar>,
    pub(crate) host: Option<RawSingBoxStringList>,
    pub(crate) path: Option<RawSingBoxScalar>,
    pub(crate) service_name: Option<RawSingBoxScalar>,
    pub(crate) headers: Option<RawSingBoxTransportHeaders>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct RawSingBoxTransportHeaders {
    #[serde(rename = "Host")]
    pub(crate) host: Option<RawSingBoxStringList>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub(crate) enum RawClashScalar {
    Text(String),
    Integer(i64),
}

impl RawClashScalar {
    pub(crate) fn into_text(self) -> String {
        match self {
            Self::Text(value) => value,
            Self::Integer(value) => value.to_string(),
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub(crate) enum RawSingBoxScalar {
    Text(String),
    Integer(i64),
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub(crate) enum RawSingBoxStringList {
    Text(String),
    Values(Vec<String>),
}

impl RawSingBoxScalar {
    pub(crate) fn into_text(self) -> String {
        match self {
            Self::Text(value) => value,
            Self::Integer(value) => value.to_string(),
        }
    }
}

impl RawSingBoxStringList {
    pub(crate) fn into_values(self) -> Vec<String> {
        match self {
            Self::Text(value) => vec![value],
            Self::Values(values) => values,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RawListener {
    pub(crate) id: String,
    pub(crate) enabled: Option<bool>,
    pub(crate) kind: String,
    pub(crate) bind_host: String,
    pub(crate) bind_port: i64,
    pub(crate) network: String,
    pub(crate) route: Option<String>,
    pub(crate) route_action: Option<String>,
    pub(crate) route_node: Option<String>,
    pub(crate) tags: Option<Vec<String>>,
    pub(crate) metadata: Option<BTreeMap<String, String>>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RawNode {
    pub(crate) id: String,
    pub(crate) name: Option<String>,
    pub(crate) protocol: String,
    pub(crate) host: String,
    pub(crate) port: i64,
    pub(crate) tags: Option<Vec<String>>,
    pub(crate) metadata: Option<BTreeMap<String, String>>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RawRoute {
    pub(crate) id: String,
    pub(crate) default_action: String,
    pub(crate) default_node: Option<String>,
}
