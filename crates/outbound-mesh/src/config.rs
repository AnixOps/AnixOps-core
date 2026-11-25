//! Settings of a `"type": "mesh"` outbound.
//!
//! The structure is our own (requirement R13) and versioned by
//! `config_version`, so importers in the Agent or deployment layer can
//! target it. It is layered as network, this node, peers, subnets and
//! routing. Protocol meanings come from `docs/protocols/intranet-mesh.md`
//! (§2.4 defaults, §5.2 secure mode, §7.1 ciphers, §13 route policy, §17
//! custom paths).
//!
//! ```json
//! {
//!   "config_version": 1,
//!   "network": { "name": "office", "secret": "…", "secure_mode": false, "cipher": "aes-gcm" },
//!   "node": {
//!     "address": "10.144.144.5/24", "role": "full", "hostname": "build-01",
//!     "mtu": 1380, "relay": true, "listen": [{ "transport": "tcp" }]
//!   },
//!   "peers": [{ "server": "peer.example.com", "port": 11010, "transport": "tcp" }],
//!   "subnets": { "accept": ["192.168.0.0/16"], "advertise": ["192.168.10.0/24"] },
//!   "routing": {
//!     "policy": "hops",
//!     "system_routes": ["192.168.10.0/24"],
//!     "paths": [{ "to_peer": "10.144.144.7", "via": ["10.144.144.3"] }]
//!   }
//! }
//! ```
//!
//! Nested objects reject unknown fields so an importer mistake fails loudly.

use std::collections::HashSet;
use std::net::IpAddr;

use serde::Deserialize;

use crate::net::IpNet;
use crate::scope::is_intranet_network;

/// The only `config_version` this build reads.
pub const CONFIG_VERSION: u32 = 1;
/// Longest accepted network name, in bytes.
pub const MAX_NETWORK_NAME_BYTES: usize = 255;
/// Most bootstrap peers one node may list.
pub const MAX_PEERS: usize = 64;
/// Most entries in each subnet list.
pub const MAX_SUBNETS: usize = 256;
/// Most custom paths.
pub const MAX_PATHS: usize = 256;
/// Most waypoints in one path: the hop limit is 7 relays (spec §4.4).
pub const MAX_WAYPOINTS: usize = 6;
/// Default TCP and UDP port (spec §2.4).
pub const DEFAULT_PORT: u16 = 11010;
/// Default virtual interface MTU (spec §2.4).
pub const DEFAULT_MTU: u16 = 1380;
/// Smallest accepted MTU: the IPv6 minimum.
pub const MIN_MTU: u16 = 1280;
/// Largest accepted MTU.
pub const MAX_MTU: u16 = 9000;
/// Longest host name: one DNS label.
pub const MAX_HOSTNAME_BYTES: usize = 63;

/// One mesh node as it appears in the config. The secret is injected from
/// the Keychain like the other protocols' passwords. Has no `Debug`: it
/// holds the secret.
#[derive(Deserialize)]
pub struct MeshConfig {
    pub config_version: u32,
    pub network: NetworkConfig,
    pub node: NodeConfig,
    pub peers: Vec<PeerConfig>,
    #[serde(default)]
    pub subnets: SubnetsConfig,
    #[serde(default)]
    pub routing: RoutingConfig,
}

/// The virtual network; every node of it must agree on all of these.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkConfig {
    /// Used byte for byte in the network digest (spec §6.3).
    pub name: String,
    pub secret: String,
    /// `false`, the default: the default handshake, without forward secrecy.
    /// `true`: the secure mode. All nodes of a network use the same mode and
    /// there is no fallback (spec §5.2).
    #[serde(default)]
    pub secure_mode: bool,
    /// Cipher of the default handshake mode (spec §7.1). `none` turns
    /// encryption off and must be chosen explicitly.
    #[serde(default)]
    pub cipher: Cipher,
}

/// This node.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeConfig {
    /// IPv4 address with prefix, for example `10.144.144.5/24`; the prefix
    /// is the virtual subnet.
    pub address: String,
    #[serde(default)]
    pub address_v6: Option<String>,
    /// Absent: the platform's role (full on desktop and server, access on
    /// phones). Phones are always access nodes (requirement R10).
    #[serde(default)]
    pub role: Option<Role>,
    /// Listening sockets; full nodes only.
    #[serde(default)]
    pub listen: Vec<ListenConfig>,
    /// The name other nodes and the intranet DNS show (requirement R28): one
    /// DNS label. Absent: the system host name, read when the node starts.
    #[serde(default)]
    pub hostname: Option<String>,
    /// Virtual interface MTU, [`MIN_MTU`] to [`MAX_MTU`]. Absent: [`DEFAULT_MTU`].
    #[serde(default)]
    pub mtu: Option<u16>,
    /// Whether this node relays for other nodes. Absent: `true` on full
    /// nodes. Access nodes never relay, so `true` is refused there. A node
    /// that does not relay is still reachable as a destination.
    #[serde(default)]
    pub relay: Option<bool>,
}

/// What a node does for others (spec §1.3, requirement R10).
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    /// Listens, relays for other nodes and may advertise local subnets.
    Full,
    /// Connects out only; never relays and never advertises subnets.
    Access,
}

impl Role {
    /// The role of this platform when the config names none.
    pub fn platform_default() -> Self {
        if cfg!(any(target_os = "ios", target_os = "android")) {
            Role::Access
        } else {
            Role::Full
        }
    }

    /// Whether this platform may run as a full node.
    pub fn platform_allows_full() -> bool {
        Self::platform_default() == Role::Full
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ListenConfig {
    #[serde(default)]
    pub transport: Transport,
    /// Absent: [`DEFAULT_PORT`].
    #[serde(default = "default_port")]
    pub port: u16,
    /// Absent: every address.
    #[serde(default)]
    pub address: Option<IpAddr>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PeerConfig {
    /// IP address or host name.
    pub server: String,
    #[serde(default = "default_port")]
    pub port: u16,
    #[serde(default)]
    pub transport: Transport,
}

fn default_port() -> u16 {
    DEFAULT_PORT
}

/// Transports of the first version (spec §3.1, §3.2).
#[derive(Clone, Copy, Debug, Default, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum Transport {
    #[default]
    Tcp,
    Udp,
}

/// Cipher of the default handshake mode (spec §7.1). The unauthenticated
/// XOR mode is not offered: a config naming it fails to parse.
#[derive(Clone, Copy, Debug, Default, Deserialize, PartialEq, Eq)]
pub enum Cipher {
    /// No encryption at all (spec §7.1, requirement R14). Only when the
    /// config says so explicitly; such a network is shown as unencrypted and
    /// the plaintext checks of spec §7.6 cannot apply. Without it, this node
    /// drops the plaintext traffic of such a network.
    #[serde(rename = "none")]
    None,
    /// AES-128-GCM.
    #[default]
    #[serde(rename = "aes-gcm", alias = "openssl-aes-gcm")]
    Aes128Gcm,
    /// AES-256-GCM.
    #[serde(rename = "aes-256-gcm", alias = "openssl-aes-256-gcm")]
    Aes256Gcm,
    /// ChaCha20-Poly1305.
    #[serde(
        rename = "chacha20",
        alias = "chacha20-poly1305",
        alias = "openssl-chacha20",
        alias = "openssl-chacha20-poly1305"
    )]
    ChaCha20Poly1305,
}

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SubnetsConfig {
    /// Limits which advertised subnets this node uses. Empty: every
    /// intranet subnet. Never widens the intranet scope of [`crate::scope`].
    #[serde(default)]
    pub accept: Vec<String>,
    /// Local subnets this node offers to the network; full nodes only.
    #[serde(default)]
    pub advertise: Vec<String>,
}

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoutingConfig {
    #[serde(default)]
    pub policy: RoutePolicy,
    /// Limits which routes go into the operating system's routing table.
    /// Absent: every accepted route. Present: only routes inside one of
    /// these networks; the others still work inside the mesh and are shown.
    #[serde(default)]
    pub system_routes: Option<Vec<String>>,
    #[serde(default)]
    pub paths: Vec<PathConfig>,
}

/// Relay choice for this node's own packets (spec §13).
#[derive(Clone, Copy, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RoutePolicy {
    /// Fewest hops.
    #[default]
    Hops,
    /// Lowest latency.
    Latency,
}

/// One custom path (spec §17, requirements R8, R9): traffic to a node or a
/// subnet goes through the listed waypoints, identified by their virtual
/// addresses. If a waypoint is unreachable the default route is used and
/// the status names it.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PathConfig {
    /// A node's virtual address.
    #[serde(default)]
    pub to_peer: Option<IpAddr>,
    /// An advertised subnet.
    #[serde(default)]
    pub to_subnet: Option<String>,
    pub via: Vec<IpAddr>,
}

/// Where a path leads.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PathTarget {
    Peer(IpAddr),
    Subnet(IpNet),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CustomPath {
    pub target: PathTarget,
    /// Virtual addresses of the waypoints, first hop first.
    pub via: Vec<IpAddr>,
}

/// Where a bootstrap peer listens.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeerEndpoint {
    pub server: String,
    pub port: u16,
    pub transport: Transport,
}

/// The handshake mode of a network (spec §5.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SecurityMode {
    /// The default handshake, which has no forward secrecy. Sessions in this
    /// mode are reported as such so the interface can mark them.
    Default,
    /// The secure mode, with forward secrecy.
    ForwardSecrecy,
}

impl SecurityMode {
    pub fn has_forward_secrecy(self) -> bool {
        self == SecurityMode::ForwardSecrecy
    }
}

impl MeshSettings {
    /// Whether traffic is encrypted at all; `false` only with an explicit
    /// `cipher: none` (requirement R14).
    pub fn encrypted(&self) -> bool {
        self.security == SecurityMode::ForwardSecrecy || self.cipher != Cipher::None
    }
}

/// Validated settings. Has no `Debug`: it holds the secret.
#[derive(Clone)]
pub struct MeshSettings {
    pub network_name: String,
    pub network_secret: String,
    pub security: SecurityMode,
    pub cipher: Cipher,
    /// This node's IPv4 address; [`IpNet::trunc`] is the virtual subnet.
    pub address: IpNet,
    pub address_v6: Option<IpNet>,
    pub role: Role,
    /// `None`: the system host name.
    pub hostname: Option<String>,
    pub mtu: u16,
    /// Whether this node relays for others; always `false` on access nodes.
    pub relay: bool,
    pub listen: Vec<ListenConfig>,
    pub peers: Vec<PeerEndpoint>,
    /// Masked networks; empty means no extra limit.
    pub accept_subnets: Vec<IpNet>,
    /// Masked networks this node advertises.
    pub advertise_subnets: Vec<IpNet>,
    pub route_policy: RoutePolicy,
    /// `None`: every accepted route goes into the system routing table.
    pub system_routes: Option<Vec<IpNet>>,
    pub paths: Vec<CustomPath>,
}

impl MeshSettings {
    /// The virtual subnets of the network, IPv4 first.
    pub fn virtual_subnets(&self) -> Vec<IpNet> {
        let mut subnets = vec![self.address.trunc()];
        subnets.extend(self.address_v6.map(|address| address.trunc()));
        subnets
    }

    /// This node's own virtual addresses.
    pub fn local_addresses(&self) -> Vec<IpAddr> {
        let mut addresses = vec![self.address.address()];
        addresses.extend(self.address_v6.map(|address| address.address()));
        addresses
    }

    fn in_virtual_subnet(&self, address: IpAddr) -> bool {
        self.virtual_subnets()
            .iter()
            .any(|subnet| subnet.contains(address) && subnet.network() != address)
    }
}

impl MeshConfig {
    pub fn validate(self) -> Result<MeshSettings, &'static str> {
        if self.config_version != CONFIG_VERSION {
            return Err("mesh config_version is not supported by this build");
        }

        let network = self.network;
        if network.name.trim().is_empty() {
            return Err("mesh network name is empty");
        }
        if network.name.len() > MAX_NETWORK_NAME_BYTES {
            return Err("mesh network name is too long");
        }
        if network.name.chars().any(char::is_control) {
            return Err("mesh network name contains control characters");
        }
        if network.secret.is_empty() {
            return Err("mesh network secret is empty");
        }
        if network.secure_mode && network.cipher == Cipher::None {
            return Err(
                "mesh secure_mode always encrypts; cipher none applies to the default mode only",
            );
        }

        let node = self.node;
        let address =
            IpNet::parse(&node.address).ok_or("mesh node address is not address/prefix")?;
        if !address.is_ipv4() {
            return Err("mesh node address must be IPv4; use address_v6 for IPv6");
        }
        check_interface_address(&address, 8, 30)?;
        let address_v6 = match node.address_v6.as_deref() {
            None => None,
            Some(text) => {
                let address =
                    IpNet::parse(text).ok_or("mesh node address_v6 is not address/prefix")?;
                if address.is_ipv4() {
                    return Err("mesh node address_v6 must be IPv6");
                }
                check_interface_address(&address, 8, 126)?;
                Some(address)
            }
        };

        let role = node.role.unwrap_or_else(Role::platform_default);
        if role == Role::Full && !Role::platform_allows_full() {
            return Err("mesh full nodes are not available on this platform");
        }
        if role == Role::Access && !node.listen.is_empty() {
            return Err("mesh access nodes do not listen");
        }
        let relay = match (role, node.relay) {
            (Role::Access, Some(true)) => return Err("mesh access nodes do not relay"),
            (Role::Access, _) => false,
            (Role::Full, relay) => relay.unwrap_or(true),
        };
        let mtu = node.mtu.unwrap_or(DEFAULT_MTU);
        if !(MIN_MTU..=MAX_MTU).contains(&mtu) {
            return Err("mesh node mtu is out of range");
        }
        if let Some(hostname) = &node.hostname {
            if !is_dns_label(hostname) {
                return Err("mesh node hostname is not a DNS label");
            }
        }
        let mut seen = HashSet::new();
        for listen in &node.listen {
            if listen.port == 0 {
                return Err("mesh listen port is 0");
            }
            if !seen.insert((listen.transport, listen.port, listen.address)) {
                return Err("mesh listen entries repeat");
            }
        }

        if self.peers.is_empty() {
            return Err("mesh needs at least one peer");
        }
        if self.peers.len() > MAX_PEERS {
            return Err("mesh lists too many peers");
        }
        let mut peers = Vec::with_capacity(self.peers.len());
        for peer in self.peers {
            let server = peer.server.trim();
            if server.is_empty() {
                return Err("mesh peer server is empty");
            }
            if peer.port == 0 {
                return Err("mesh peer port is 0");
            }
            peers.push(PeerEndpoint {
                server: server.to_owned(),
                port: peer.port,
                transport: peer.transport,
            });
        }

        let accept_subnets = intranet_subnets(&self.subnets.accept, "mesh subnets.accept")?;
        let advertise_subnets =
            intranet_subnets(&self.subnets.advertise, "mesh subnets.advertise")?;
        if role == Role::Access && !advertise_subnets.is_empty() {
            return Err("mesh access nodes do not advertise subnets");
        }
        let system_routes = match &self.routing.system_routes {
            None => None,
            Some(texts) => Some(intranet_subnets(texts, "mesh routing.system_routes")?),
        };

        let mut settings = MeshSettings {
            network_name: network.name,
            network_secret: network.secret,
            security: if network.secure_mode {
                SecurityMode::ForwardSecrecy
            } else {
                SecurityMode::Default
            },
            cipher: network.cipher,
            address,
            address_v6,
            role,
            hostname: node.hostname,
            mtu,
            relay,
            listen: node.listen,
            peers,
            accept_subnets,
            advertise_subnets,
            route_policy: self.routing.policy,
            system_routes,
            paths: Vec::new(),
        };
        if advertise_subnets_overlap_virtual(&settings) {
            return Err("mesh subnets.advertise overlaps the virtual subnet");
        }

        if self.routing.paths.len() > MAX_PATHS {
            return Err("mesh routing lists too many paths");
        }
        let mut targets = HashSet::new();
        for path in self.routing.paths {
            let target = match (path.to_peer, path.to_subnet.as_deref()) {
                (Some(peer), None) => {
                    if !settings.in_virtual_subnet(peer)
                        || settings.local_addresses().contains(&peer)
                    {
                        return Err("mesh path to_peer is not another node's virtual address");
                    }
                    PathTarget::Peer(peer)
                }
                (None, Some(text)) => {
                    let subnet =
                        IpNet::parse(text).ok_or("mesh path to_subnet is not a network")?;
                    if !is_intranet_network(&subnet) || subnet.prefix() == 0 {
                        return Err("mesh path to_subnet is outside the intranet ranges");
                    }
                    PathTarget::Subnet(subnet.trunc())
                }
                _ => return Err("mesh path needs exactly one of to_peer and to_subnet"),
            };
            if !targets.insert(target) {
                return Err("mesh routing has two paths to the same target");
            }
            if path.via.is_empty() {
                return Err("mesh path via is empty");
            }
            if path.via.len() > MAX_WAYPOINTS {
                return Err("mesh path via has too many waypoints");
            }
            let mut waypoints = HashSet::new();
            for waypoint in &path.via {
                if !settings.in_virtual_subnet(*waypoint)
                    || settings.local_addresses().contains(waypoint)
                {
                    return Err("mesh path waypoint is not another node's virtual address");
                }
                if !waypoints.insert(*waypoint) || target == PathTarget::Peer(*waypoint) {
                    return Err("mesh path repeats a node");
                }
            }
            settings.paths.push(CustomPath {
                target,
                via: path.via,
            });
        }
        Ok(settings)
    }
}

impl std::hash::Hash for PathTarget {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        match self {
            PathTarget::Peer(address) => (0u8, address).hash(state),
            PathTarget::Subnet(subnet) => (1u8, subnet).hash(state),
        }
    }
}

fn intranet_subnets(texts: &[String], what: &'static str) -> Result<Vec<IpNet>, &'static str> {
    if texts.len() > MAX_SUBNETS {
        return Err(what);
    }
    texts
        .iter()
        .map(|text| {
            let subnet = IpNet::parse(text).ok_or(what)?;
            if !is_intranet_network(&subnet) {
                return Err(what);
            }
            Ok(subnet.trunc())
        })
        .collect()
}

/// One DNS label (RFC 1123): letters, digits and hyphens, not starting or
/// ending with a hyphen.
fn is_dns_label(text: &str) -> bool {
    !text.is_empty()
        && text.len() <= MAX_HOSTNAME_BYTES
        && text.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        && !text.starts_with('-')
        && !text.ends_with('-')
}

fn advertise_subnets_overlap_virtual(settings: &MeshSettings) -> bool {
    let virtual_subnets = settings.virtual_subnets();
    settings
        .advertise_subnets
        .iter()
        .any(|subnet| virtual_subnets.iter().any(|own| own.overlaps(subnet)))
}

/// The virtual subnet must be intranet and the address a usable host in it.
fn check_interface_address(address: &IpNet, min: u8, max: u8) -> Result<(), &'static str> {
    if address.prefix() < min || address.prefix() > max {
        return Err("mesh node address prefix is out of range");
    }
    if !is_intranet_network(&address.trunc()) {
        return Err("mesh node address is outside the intranet ranges");
    }
    if address.address() == address.network() {
        return Err("mesh node address is the subnet's network address");
    }
    if let IpAddr::V4(v4) = address.address() {
        let host_bits = 32 - u32::from(address.prefix());
        let host_mask = (1u32 << host_bits) - 1;
        if u32::from(v4) & host_mask == host_mask {
            return Err("mesh node address is the subnet's broadcast address");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use serde_json::{json, Value};

    use super::*;

    fn base() -> Value {
        json!({
            "config_version": 1,
            "network": {"name": "office", "secret": "s3cret"},
            "node": {"address": "10.144.144.5/24", "role": "access"},
            "peers": [{"server": "peer.example", "port": 40000}],
        })
    }

    fn parse(value: Value) -> Result<MeshConfig, serde_json::Error> {
        serde_json::from_value(value)
    }

    fn validate(value: Value) -> Result<MeshSettings, &'static str> {
        parse(value).unwrap().validate()
    }

    /// Sets `path` (dot-separated) in the base config.
    fn with(path: &str, value: Value) -> Value {
        let mut config = base();
        let mut target = &mut config;
        let keys: Vec<&str> = path.split('.').collect();
        for key in &keys[..keys.len() - 1] {
            target = target
                .as_object_mut()
                .unwrap()
                .entry(*key)
                .or_insert(json!({}));
        }
        target[keys[keys.len() - 1]] = value;
        config
    }

    #[test]
    fn minimal_config_has_spec_defaults() {
        let settings = validate(base()).unwrap();
        assert_eq!(settings.network_name, "office");
        assert_eq!(settings.address.to_string(), "10.144.144.0/24");
        assert_eq!(settings.security, SecurityMode::Default);
        assert!(!settings.security.has_forward_secrecy());
        assert_eq!(settings.cipher, Cipher::Aes128Gcm);
        assert!(settings.encrypted());
        assert_eq!(settings.route_policy, RoutePolicy::Hops);
        assert_eq!(settings.role, Role::Access);
        assert_eq!(settings.hostname, None);
        assert_eq!(settings.mtu, DEFAULT_MTU);
        assert!(!settings.relay);
        assert_eq!(settings.system_routes, None);
        assert!(settings.paths.is_empty());
        assert_eq!(
            settings.peers,
            vec![PeerEndpoint {
                server: "peer.example".into(),
                port: 40000,
                transport: Transport::Tcp,
            }]
        );
    }

    #[test]
    fn config_version_is_checked() {
        assert!(validate(with("config_version", json!(2))).is_err());
        let mut missing = base();
        missing.as_object_mut().unwrap().remove("config_version");
        assert!(parse(missing).is_err());
    }

    #[test]
    fn nested_unknown_fields_are_rejected() {
        for path in ["network.mode", "node.tun", "subnets.extra", "routing.exit"] {
            assert!(parse(with(path, json!(1))).is_err(), "{path}");
        }
        assert!(parse(with("peers", json!([{"server": "a", "uri": "x"}]))).is_err());
    }

    #[test]
    fn secure_mode_is_an_explicit_network_switch() {
        let settings = validate(with("network.secure_mode", json!(true))).unwrap();
        assert_eq!(settings.security, SecurityMode::ForwardSecrecy);
        assert!(parse(with("network.secure_mode", json!("yes"))).is_err());
    }

    #[test]
    fn ciphers_and_their_aliases() {
        for (name, cipher) in [
            ("aes-gcm", Cipher::Aes128Gcm),
            ("openssl-aes-gcm", Cipher::Aes128Gcm),
            ("aes-256-gcm", Cipher::Aes256Gcm),
            ("openssl-aes-256-gcm", Cipher::Aes256Gcm),
            ("chacha20", Cipher::ChaCha20Poly1305),
            ("chacha20-poly1305", Cipher::ChaCha20Poly1305),
            ("openssl-chacha20", Cipher::ChaCha20Poly1305),
        ] {
            let settings = validate(with("network.cipher", json!(name))).unwrap();
            assert_eq!(settings.cipher, cipher, "{name}");
        }
        // No encryption only when chosen, and never with the secure mode.
        let settings = validate(with("network.cipher", json!("none"))).unwrap();
        assert_eq!(settings.cipher, Cipher::None);
        assert!(!settings.encrypted());
        let mut secure_plain = with("network.cipher", json!("none"));
        secure_plain["network"]["secure_mode"] = json!(true);
        assert!(validate(secure_plain).is_err());
        // XOR has no authentication and is refused (spec §7.1).
        for name in ["xor", "openssl-xor", "AES-GCM", "", "None", "plain"] {
            assert!(
                parse(with("network.cipher", json!(name))).is_err(),
                "{name}"
            );
        }
    }

    #[test]
    fn network_name_is_kept_byte_for_byte() {
        let settings = validate(with("network.name", json!(" office "))).unwrap();
        assert_eq!(settings.network_name, " office ");
        assert!(validate(with("network.name", json!("  "))).is_err());
        assert!(validate(with("network.name", json!("a\nb"))).is_err());
        assert!(validate(with("network.name", json!("x".repeat(256)))).is_err());
        assert!(validate(with("network.secret", json!(""))).is_err());
    }

    #[test]
    fn refuses_public_or_unusable_addresses() {
        for address in [
            "8.8.8.8/24",
            "10.0.0.1",
            "10.0.0.1/31",
            "10.0.0.1/7",
            "10.144.144.0/24",
            "10.144.144.255/24",
            "fd00::5/64",
            "not an address",
        ] {
            assert!(
                validate(with("node.address", json!(address))).is_err(),
                "{address}"
            );
        }
        for address in ["2001:db8::5/64", "10.0.0.5/24", "fd00::/64"] {
            assert!(
                validate(with("node.address_v6", json!(address))).is_err(),
                "{address}"
            );
        }
        let settings = validate(with("node.address_v6", json!("fd00:aa::5/64"))).unwrap();
        assert_eq!(settings.virtual_subnets().len(), 2);
        assert_eq!(settings.local_addresses().len(), 2);
    }

    #[test]
    fn access_nodes_neither_listen_nor_advertise() {
        assert_eq!(
            validate(with("node.listen", json!([{"transport": "tcp"}]))).err(),
            Some("mesh access nodes do not listen")
        );
        assert_eq!(
            validate(with("subnets.advertise", json!(["192.168.10.0/24"]))).err(),
            Some("mesh access nodes do not advertise subnets")
        );
    }

    #[cfg(not(any(target_os = "ios", target_os = "android")))]
    #[test]
    fn full_nodes_listen_and_advertise_intranet_subnets() {
        let mut config = with("node.role", json!("full"));
        config["node"]["listen"] =
            json!([{"transport": "tcp"}, {"transport": "udp", "port": 11011}]);
        config["subnets"] = json!({"advertise": ["192.168.10.0/24"], "accept": ["192.168.0.0/16"]});
        let settings = validate(config).unwrap();
        assert_eq!(settings.role, Role::Full);
        assert_eq!(settings.listen[0].port, DEFAULT_PORT);
        assert_eq!(settings.listen[1].transport, Transport::Udp);
        assert_eq!(
            settings.advertise_subnets,
            vec![IpNet::parse("192.168.10.0/24").unwrap()]
        );

        let mut repeated = with("node.role", json!("full"));
        repeated["node"]["listen"] = json!([{"transport": "tcp"}, {"transport": "tcp"}]);
        assert!(validate(repeated).is_err());

        for subnet in ["0.0.0.0/0", "1.1.1.0/24", "10.144.0.0/16"] {
            let mut config = with("node.role", json!("full"));
            config["subnets"] = json!({"advertise": [subnet]});
            assert!(validate(config).is_err(), "{subnet}");
        }
    }

    #[cfg(any(target_os = "ios", target_os = "android"))]
    #[test]
    fn phones_cannot_be_full_nodes() {
        assert!(validate(with("node.role", json!("full"))).is_err());
    }

    #[test]
    fn hostname_and_mtu() {
        let mut config = with("node.hostname", json!("build-01"));
        config["node"]["mtu"] = json!(1420);
        let settings = validate(config).unwrap();
        assert_eq!(settings.hostname.as_deref(), Some("build-01"));
        assert_eq!(settings.mtu, 1420);
        let long = "a".repeat(64);
        for bad in ["", "-a", "a-", "a.b", "a b", "例子", long.as_str()] {
            assert!(
                validate(with("node.hostname", json!(bad))).is_err(),
                "{bad}"
            );
        }
        assert!(validate(with("node.hostname", json!("A1-b"))).is_ok());
        for mtu in [MIN_MTU, MAX_MTU] {
            assert!(validate(with("node.mtu", json!(mtu))).is_ok(), "{mtu}");
        }
        for mtu in [0, 1279, 9001] {
            assert!(validate(with("node.mtu", json!(mtu))).is_err(), "{mtu}");
        }
        assert!(parse(with("node.mtu", json!(70000))).is_err());
    }

    #[test]
    fn access_nodes_never_relay() {
        assert!(!validate(with("node.relay", json!(false))).unwrap().relay);
        assert_eq!(
            validate(with("node.relay", json!(true))).err(),
            Some("mesh access nodes do not relay")
        );
    }

    #[cfg(not(any(target_os = "ios", target_os = "android")))]
    #[test]
    fn full_nodes_relay_unless_told_not_to() {
        assert!(validate(with("node.role", json!("full"))).unwrap().relay);
        let mut config = with("node.role", json!("full"));
        config["node"]["relay"] = json!(false);
        assert!(!validate(config).unwrap().relay);
    }

    #[test]
    fn system_routes_are_intranet_networks() {
        let settings = validate(with(
            "routing.system_routes",
            json!(["192.168.10.9/24", "10.20.0.0/16"]),
        ))
        .unwrap();
        assert_eq!(
            settings.system_routes,
            Some(vec![
                IpNet::parse("192.168.10.0/24").unwrap(),
                IpNet::parse("10.20.0.0/16").unwrap(),
            ])
        );
        // Present but empty: nothing goes into the system routing table.
        let settings = validate(with("routing.system_routes", json!([]))).unwrap();
        assert_eq!(settings.system_routes, Some(Vec::new()));
        for bad in ["0.0.0.0/0", "8.8.8.0/24", "bogus"] {
            assert!(
                validate(with("routing.system_routes", json!([bad]))).is_err(),
                "{bad}"
            );
        }
    }

    #[test]
    fn accept_subnets_cannot_widen_the_intranet() {
        for subnet in ["0.0.0.0/0", "1.1.1.0/24", "::/0", "bogus"] {
            assert!(
                validate(with("subnets.accept", json!([subnet]))).is_err(),
                "{subnet}"
            );
        }
    }

    #[test]
    fn refuses_bad_peers() {
        assert!(validate(with("peers", json!([]))).is_err());
        assert!(validate(with("peers", json!([{"server": " ", "port": 1}]))).is_err());
        assert!(validate(with("peers", json!([{"server": "a", "port": 0}]))).is_err());
        assert!(parse(with("peers", json!([{"server": "a", "transport": "quic"}]))).is_err());
        let settings = validate(with(
            "peers",
            json!([{"server": "a"}, {"server": "b", "transport": "udp"}]),
        ))
        .unwrap();
        assert_eq!(settings.peers[0].port, DEFAULT_PORT);
        assert_eq!(settings.peers[1].transport, Transport::Udp);
        let many: Vec<Value> = (0..=MAX_PEERS)
            .map(|i| json!({"server": format!("p{i}")}))
            .collect();
        assert!(validate(with("peers", Value::Array(many))).is_err());
    }

    #[test]
    fn custom_paths_by_peer_and_by_subnet() {
        let config = with(
            "routing",
            json!({
                "policy": "latency",
                "paths": [
                    {"to_peer": "10.144.144.7", "via": ["10.144.144.3"]},
                    {"to_subnet": "192.168.10.9/24", "via": ["10.144.144.3", "10.144.144.4"]},
                ]
            }),
        );
        let settings = validate(config).unwrap();
        assert_eq!(settings.route_policy, RoutePolicy::Latency);
        assert_eq!(
            settings.paths,
            vec![
                CustomPath {
                    target: PathTarget::Peer("10.144.144.7".parse().unwrap()),
                    via: vec!["10.144.144.3".parse().unwrap()],
                },
                CustomPath {
                    target: PathTarget::Subnet(IpNet::parse("192.168.10.0/24").unwrap()),
                    via: vec![
                        "10.144.144.3".parse().unwrap(),
                        "10.144.144.4".parse().unwrap()
                    ],
                },
            ]
        );
    }

    #[test]
    fn refuses_bad_custom_paths() {
        let path = |value: Value| with("routing", json!({"paths": [value]}));
        for bad in [
            json!({"via": ["10.144.144.3"]}),
            json!({"to_peer": "10.144.144.7", "to_subnet": "192.168.1.0/24", "via": ["10.144.144.3"]}),
            json!({"to_peer": "10.144.144.7", "via": []}),
            json!({"to_peer": "10.144.144.5", "via": ["10.144.144.3"]}),
            json!({"to_peer": "10.9.9.9", "via": ["10.144.144.3"]}),
            json!({"to_peer": "10.144.144.7", "via": ["10.144.144.5"]}),
            json!({"to_peer": "10.144.144.7", "via": ["10.144.144.7"]}),
            json!({"to_peer": "10.144.144.7", "via": ["10.144.144.3", "10.144.144.3"]}),
            json!({"to_peer": "10.144.144.7", "via": ["192.168.1.1"]}),
            json!({"to_subnet": "0.0.0.0/0", "via": ["10.144.144.3"]}),
            json!({"to_subnet": "8.8.8.0/24", "via": ["10.144.144.3"]}),
            json!({"to_peer": "10.144.144.7", "via": ["10.144.144.1", "10.144.144.2", "10.144.144.3", "10.144.144.4", "10.144.144.6", "10.144.144.8", "10.144.144.9"]}),
        ] {
            assert!(validate(path(bad.clone())).is_err(), "{bad}");
        }
        let twice = with(
            "routing",
            json!({"paths": [
                {"to_peer": "10.144.144.7", "via": ["10.144.144.3"]},
                {"to_peer": "10.144.144.7", "via": ["10.144.144.4"]},
            ]}),
        );
        assert!(validate(twice).is_err());
    }
}
