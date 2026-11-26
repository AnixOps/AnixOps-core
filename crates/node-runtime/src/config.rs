//! The `anixcore` configuration file.
//!
//! ```json
//! {
//!   "management": {"listen": "127.0.0.1:10085", "token": "..."},
//!   "allow_private_targets": false,
//!   "inbounds": [
//!     {"tag": "ss", "type": "shadowsocks", "listen": "::", "listen_port": 8388,
//!      "method": "2022-blake3-aes-128-gcm", "password": "...", "users": []}
//!   ],
//!   "egress": {"routes": [], "relays": []},
//!   "network": {"generation": 1, "egresses": [], "ingresses": [], "paths": []}
//! }
//! ```
//!
//! `management` is optional. Its `listen` must be a loopback address:
//! anything else is refused unless `"insecure_public": true` accepts the
//! plaintext API there ([`ManagementSettings::check`]).
//!
//! Every inbound key other than `tag`, `type`, `listen`, `listen_port`,
//! `outbound`, `ingress` and `accept_proxy_protocol` is passed to the
//! protocol factory as its settings. `egress` is optional and has the
//! format of `PUT /v1/egress` ([`crate::egress::EgressConfig`]); `network`
//! is optional and has the format of `PUT /v1/network`
//! ([`crate::network::NetworkPlan`]).
//!
//! `outbound` (on an inbound) and `default_outbound` (for all inbounds)
//! name the base outbound traffic leaves through: `"direct"` (the default),
//! `"egress:<id>"` (an egress of the network plan) or one the binary
//! registered ([`crate::Node::with_outbound`]); plain `anixcore` registers
//! none. `ingress` (instead of `outbound`) puts the inbound in an ingress
//! of the network plan: it takes that ingress's active path.
//!
//! `"accept_proxy_protocol": true` is for an inbound behind a relay or load
//! balancer that sends the PROXY protocol: every TCP connection must then
//! start with a version 1 or 2 header, read ahead of TLS, REALITY or any
//! transport, and the address in it is the client's for device limits,
//! online IPs and what a `forward` writes on (its own `proxy_protocol`).
//! A connection without a valid header is closed, so the port must be
//! reachable by that relay only. Inbounds on a UDP socket (Hysteria2, TUIC)
//! refuse the key; UDP on a stream inbound's port is not affected.
//!
//! VLESS, Trojan and AnyTLS inbounds relay a connection that is not a known
//! user's to a fallback: `"fallback": {"server": "127.0.0.1", "server_port":
//! 8080}` for all of them, and `"fallbacks"` for a choice by connection:
//!
//! ```json
//! "fallbacks": [
//!   {"alpn": "h2", "dest": 8443, "xver": 1},
//!   {"path": "/ws", "dest": "127.0.0.1:8081"},
//!   {"name": "blog.example.com", "dest": "blog.internal:80"},
//!   {"dest": 8080}
//! ]
//! ```
//!
//! `name` is the server name of the TLS (or REALITY) handshake, `alpn` the
//! ALPN protocol it agreed on and `path` the path of the HTTP/1.x request
//! the connection starts with; `dest` is `host:port` or a port on this
//! host, and `xver` 1 or 2 sends the destination a PROXY protocol header of
//! that version with the client's address. Of the entries whose conditions
//! all hold, the one with the most conditions takes the connection (the
//! earlier one of equals); an entry without conditions is the default, as
//! `fallback` is. See [`engine_inbound::fallback`].

use std::net::{IpAddr, Ipv6Addr, SocketAddr};

use engine_inbound::registry::Settings;
use engine_inbound::{FallbackRule, FallbackSettings};
use engine_outbound::TargetAddr;
use serde::Deserialize;

use crate::egress::EgressConfig;
use crate::network::NetworkPlan;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeConfig {
    #[serde(default)]
    pub management: Option<ManagementSettings>,
    #[serde(default)]
    pub allow_private_targets: bool,
    #[serde(default)]
    pub inbounds: Vec<InboundConfig>,
    #[serde(default)]
    pub egress: Option<EgressConfig>,
    #[serde(default)]
    pub default_outbound: Option<String>,
    #[serde(default)]
    pub network: Option<NetworkPlan>,
    /// A ClientHello fingerprint bundle to install at start, as
    /// `PUT /v1/tls-fingerprints` takes it (see [`crate::apply_tls_fingerprints`]).
    #[serde(default)]
    pub tls_fingerprints: Option<serde_json::Value>,
    /// Where the managed mesh networks (`PUT /v1/mesh`) keep this device's
    /// instance ID and each network's static key; `anixcore` on Linux
    /// uses `/var/lib/anixcore/mesh` when it is absent.
    #[serde(default)]
    pub mesh_state_dir: Option<std::path::PathBuf>,
    /// Turns on the external network bridges of managed networks (spec
    /// §15.12, `docs/architecture/mesh-bridge.md`). Off by default: the
    /// node then neither lists `mesh_external_bridge` nor touches
    /// nftables or conntrack, unless its state directory says an earlier
    /// run installed a bridge, whose tables it then removes once.
    #[serde(default)]
    pub mesh_external_bridge: bool,
}

/// Has no `Debug`: `token` is a credential.
///
/// The management API is plaintext HTTP carrying a reusable bearer token
/// with full control of the node, so it listens on loopback only:
/// [`ManagementSettings::check`] refuses any other address (`0.0.0.0` and
/// `::` included) unless `insecure_public` is set. Remote management goes
/// through an authenticated, encrypted channel (SSH or a VPN) that ends on
/// this host's loopback.
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManagementSettings {
    pub listen: SocketAddr,
    /// Bearer token every request must carry.
    pub token: String,
    /// Accepts a non-loopback `listen` in plaintext. Off by default; a
    /// deployment that sets it must keep the port on a restricted network.
    #[serde(default)]
    pub insecure_public: bool,
}

/// Why a [`ManagementSettings`] is refused. The messages are static text:
/// they never quote the token.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ManagementError {
    /// `listen` is not a loopback address and `insecure_public` is off.
    PublicWithoutOptIn,
    /// `token` is empty or whitespace.
    EmptyToken,
}

impl ManagementError {
    pub fn message(self) -> &'static str {
        match self {
            Self::PublicWithoutOptIn => {
                "management api listens on loopback only: bind 127.0.0.1 or ::1 \
                 and reach it through SSH or a VPN, or set management.insecure_public \
                 to accept plaintext on this address"
            }
            Self::EmptyToken => "management api token must not be empty",
        }
    }
}

impl std::fmt::Display for ManagementError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.message())
    }
}

impl std::error::Error for ManagementError {}

/// Whether `address` is a loopback address, an IPv4-mapped IPv6 one
/// (`::ffff:127.0.0.1`) included.
pub fn is_loopback(address: IpAddr) -> bool {
    address.to_canonical().is_loopback()
}

impl ManagementSettings {
    /// Checks the settings before anything binds. `Ok(Some(warning))` is a
    /// non-loopback address accepted through `insecure_public`, which the
    /// binary prints.
    pub fn check(&self) -> Result<Option<&'static str>, ManagementError> {
        if self.token.trim().is_empty() {
            return Err(ManagementError::EmptyToken);
        }
        if is_loopback(self.listen.ip()) {
            return Ok(None);
        }
        if self.insecure_public {
            Ok(Some(
                "management api accepts plaintext on a non-loopback address \
                 (insecure_public): its bearer token can be read by anyone on the path",
            ))
        } else {
            Err(ManagementError::PublicWithoutOptIn)
        }
    }

    /// [`Self::check`]s the settings, then binds `listen`. A warning goes to
    /// stderr prefixed with `program`.
    pub async fn bind(&self, program: &str) -> Result<tokio::net::TcpListener, String> {
        if let Some(warning) = self.check().map_err(|error| error.to_string())? {
            eprintln!("{program}: WARNING: {warning}");
        }
        tokio::net::TcpListener::bind(self.listen)
            .await
            .map_err(|error| format!("management api: {error}"))
    }
}

/// One inbound. Has no `Debug`: settings carry passwords.
#[derive(Clone, Deserialize)]
pub struct InboundConfig {
    pub tag: String,
    #[serde(rename = "type")]
    pub kind: String,
    #[serde(default = "any_address")]
    pub listen: IpAddr,
    pub listen_port: u16,
    /// The base outbound's name; `None` takes the node's default.
    #[serde(default)]
    pub outbound: Option<String>,
    /// The network-model ingress; excludes `outbound`.
    #[serde(default)]
    pub ingress: Option<String>,
    /// TCP connections start with a PROXY protocol header naming the client.
    #[serde(default)]
    pub accept_proxy_protocol: bool,
    /// When the inbound ends, in Unix milliseconds: the node closes its
    /// listener and connections at that time and drops it from the list.
    /// Must be in the future when the inbound is added; required for
    /// `"type": "socks"` ([`crate::SOCKS_TYPE`]).
    #[serde(default)]
    pub expires_at_ms: Option<u64>,
    #[serde(flatten)]
    pub settings: Settings,
}

fn any_address() -> IpAddr {
    IpAddr::V6(Ipv6Addr::UNSPECIFIED)
}

impl InboundConfig {
    /// Targets this inbound relays to by design (`fallback`, the `dest` of
    /// `fallbacks`, the REALITY and ShadowTLS `handshake`, a forward's
    /// `server` or `targets`, a reverse proxy's upstreams), which the
    /// private-target filter lets through.
    pub fn allowed_targets(&self) -> Vec<(String, u16)> {
        let fallback = self.settings.get("fallback");
        let handshakes = ["reality", "shadow_tls"]
            .into_iter()
            .map(|layer| self.settings.get(layer)?.get("handshake"));
        let mut allowed: Vec<(String, u16)> = std::iter::once(fallback)
            .chain(handshakes)
            .flatten()
            .filter_map(|value| serde_json::from_value::<FallbackSettings>(value.clone()).ok())
            .map(|target| (target.server, target.server_port))
            .collect();
        let rules = self.settings.get("fallbacks").cloned();
        let rules = rules.and_then(|rules| serde_json::from_value::<Vec<FallbackRule>>(rules).ok());
        for target in rules.iter().flatten().filter_map(FallbackRule::target) {
            allowed.push((target.host(), target.port()));
        }
        if self.kind == crate::FORWARD_TYPE {
            let targets = self
                .settings
                .get("targets")
                .and_then(|value| value.as_array());
            let own = std::iter::once(&self.settings).filter_map(|settings| {
                settings
                    .get("server")
                    .map(|server| (server, settings.get("server_port")))
            });
            let listed = targets.into_iter().flatten().filter_map(|target| {
                target
                    .get("server")
                    .map(|server| (server, target.get("server_port")))
            });
            for (server, port) in own.chain(listed) {
                let server = server.as_str();
                let port = port
                    .and_then(|value| value.as_u64())
                    .and_then(|port| u16::try_from(port).ok());
                if let (Some(server), Some(port)) = (server, port) {
                    // As the forward sends it: IP literals in canonical form.
                    let target = TargetAddr::from_host(server.trim(), port);
                    allowed.push((target.host(), port));
                }
            }
        }
        if self.kind == crate::REVERSE_PROXY_TYPE {
            let upstreams = self
                .settings
                .get("sites")
                .and_then(|sites| sites.as_array())
                .into_iter()
                .flatten()
                .filter_map(|site| site.get("routes").and_then(|routes| routes.as_array()))
                .flatten()
                .filter_map(|route| route.get("upstreams").and_then(|ups| ups.as_array()))
                .flatten();
            for upstream in upstreams {
                let server = upstream.get("server").and_then(|value| value.as_str());
                let port = upstream
                    .get("server_port")
                    .and_then(|value| value.as_u64())
                    .and_then(|port| u16::try_from(port).ok());
                if let (Some(server), Some(port)) = (server, port) {
                    let target = TargetAddr::from_host(server.trim(), port);
                    allowed.push((target.host(), port));
                }
            }
        }
        allowed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn management(listen: &str, insecure_public: bool) -> ManagementSettings {
        let config: NodeConfig = serde_json::from_value(serde_json::json!({
            "management": {"listen": listen, "token": "t0ken", "insecure_public": insecure_public}
        }))
        .unwrap();
        config.management.unwrap()
    }

    #[test]
    fn management_listens_on_loopback_by_default() {
        for listen in [
            "127.0.0.1:10085",
            "127.8.9.10:1",
            "[::1]:10085",
            "[::ffff:127.0.0.1]:10085",
        ] {
            assert_eq!(management(listen, false).check(), Ok(None), "{listen}");
        }
        for listen in [
            "0.0.0.0:10085",
            "[::]:10085",
            "10.0.0.1:10085",
            "192.168.1.2:10085",
            "203.0.113.7:10085",
            "[fd00::1]:10085",
            "[2001:db8::1]:10085",
            "[::ffff:10.0.0.1]:10085",
        ] {
            assert_eq!(
                management(listen, false).check(),
                Err(ManagementError::PublicWithoutOptIn),
                "{listen}"
            );
        }
    }

    #[test]
    fn management_non_loopback_needs_the_explicit_switch() {
        let warning = management("0.0.0.0:10085", true).check().unwrap();
        assert!(warning.unwrap().contains("plaintext"));
        // Absent means off.
        let config: NodeConfig = serde_json::from_value(serde_json::json!({
            "management": {"listen": "0.0.0.0:10085", "token": "t0ken"}
        }))
        .unwrap();
        assert_eq!(
            config.management.unwrap().check(),
            Err(ManagementError::PublicWithoutOptIn)
        );
    }

    #[test]
    fn management_refuses_an_empty_token_and_never_quotes_it() {
        let config: NodeConfig = serde_json::from_value(serde_json::json!({
            "management": {"listen": "127.0.0.1:10085", "token": "  "}
        }))
        .unwrap();
        assert_eq!(
            config.management.unwrap().check(),
            Err(ManagementError::EmptyToken)
        );
        let mut settings = management("0.0.0.0:1", false);
        settings.token = "s3cret-token-value".to_owned();
        let message = settings.check().unwrap_err().to_string();
        assert!(!message.contains("s3cret"));
    }

    #[tokio::test]
    async fn management_bind_refuses_before_binding() {
        let error = management("0.0.0.0:0", false)
            .bind("test")
            .await
            .unwrap_err();
        assert!(error.contains("loopback only"), "{error}");
        let listener = management("127.0.0.1:0", false).bind("test").await.unwrap();
        assert!(listener.local_addr().unwrap().ip().is_loopback());
    }

    #[test]
    fn splits_inbound_keys_from_protocol_settings() {
        let config: NodeConfig = serde_json::from_value(serde_json::json!({
            "inbounds": [{
                "tag": "vless", "type": "vless", "listen_port": 443,
                "outbound": "direct",
                "accept_proxy_protocol": true,
                "users": [],
                "fallback": {"server": "127.0.0.1", "server_port": 8080},
                "fallbacks": [{"alpn": "h2", "dest": 8443}, {"path": "/ws", "dest": "[::1]:81"}],
                "reality": {"handshake": {"server": "www.example.com", "server_port": 443}}
            }]
        }))
        .unwrap();
        let inbound = &config.inbounds[0];
        assert_eq!(inbound.listen, any_address());
        assert!(!inbound.settings.contains_key("tag"));
        assert!(!inbound.settings.contains_key("listen_port"));
        assert_eq!(inbound.outbound.as_deref(), Some("direct"));
        assert!(!inbound.settings.contains_key("outbound"));
        assert!(inbound.accept_proxy_protocol);
        assert!(!inbound.settings.contains_key("accept_proxy_protocol"));
        assert!(inbound.settings.contains_key("users"));
        assert_eq!(
            inbound.allowed_targets(),
            vec![
                ("127.0.0.1".to_owned(), 8080),
                ("www.example.com".to_owned(), 443),
                ("127.0.0.1".to_owned(), 8443),
                ("::1".to_owned(), 81)
            ]
        );
    }

    #[test]
    fn allows_the_shadow_tls_handshake_site() {
        let config: NodeConfig = serde_json::from_value(serde_json::json!({
            "inbounds": [{
                "tag": "ss", "type": "shadowsocks", "listen_port": 443,
                "shadow_tls": {"password": "front",
                    "handshake": {"server": "10.0.0.2", "server_port": 8443}}
            }]
        }))
        .unwrap();
        assert_eq!(
            config.inbounds[0].allowed_targets(),
            vec![("10.0.0.2".to_owned(), 8443)]
        );
    }

    #[test]
    fn allows_the_forward_target() {
        let config: NodeConfig = serde_json::from_value(serde_json::json!({
            "inbounds": [
                {"tag": "f", "type": "forward", "listen_port": 10001,
                 "server": "[fd00::0:7]", "server_port": 22},
                {"tag": "ss", "type": "shadowsocks", "listen_port": 8388,
                 "server": "10.0.0.1", "server_port": 22}
            ]
        }))
        .unwrap();
        assert_eq!(
            config.inbounds[0].allowed_targets(),
            vec![("fd00::7".to_owned(), 22)]
        );
        assert!(config.inbounds[1].allowed_targets().is_empty());
        let config: NodeConfig = serde_json::from_value(serde_json::json!({
            "inbounds": [
                {"tag": "f", "type": "forward", "listen_port": 10001,
                 "targets": [{"server": "10.0.0.1", "server_port": 22},
                             {"server": "b.example", "server_port": 80}]}
            ]
        }))
        .unwrap();
        assert_eq!(
            config.inbounds[0].allowed_targets(),
            vec![("10.0.0.1".to_owned(), 22), ("b.example".to_owned(), 80)]
        );
    }

    #[test]
    fn allows_the_reverse_proxy_upstreams() {
        let config: NodeConfig = serde_json::from_value(serde_json::json!({
            "inbounds": [
                {"tag": "rp", "type": "reverse_proxy", "listen_port": 443,
                 "sites": [{"hosts": ["a.example"], "routes": [
                     {"path": "/api", "upstreams": [{"server": "10.0.0.1", "server_port": 8080}]},
                     {"upstreams": [{"server": "[fd00::0:7]", "server_port": 80}]}]},
                     {"hosts": ["b.example"], "redirect_https": true}]}
            ]
        }))
        .unwrap();
        assert_eq!(
            config.inbounds[0].allowed_targets(),
            vec![("10.0.0.1".to_owned(), 8080), ("fd00::7".to_owned(), 80)]
        );
    }
}
