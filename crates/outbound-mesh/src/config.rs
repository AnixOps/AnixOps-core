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
//!   "network": { "name": "office", "secret": "…", "kind": "managed", "secure_mode": true },
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
use zeroize::Zeroizing;

use crate::bridge::{ExternalBridge, ExternalBridgeConfig};
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
/// The outbound's own fields; the registration layer removes the outbound
/// `type` and `tag` before parsing, so anything else unknown is an error.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MeshConfig {
    pub config_version: u32,
    pub network: NetworkConfig,
    pub node: NodeConfig,
    pub peers: Vec<PeerConfig>,
    #[serde(default)]
    pub subnets: SubnetsConfig,
    #[serde(default)]
    pub routing: RoutingConfig,
    /// The external network bridge (spec §15.12): Linux full nodes only.
    #[serde(default)]
    pub external_bridge: Option<ExternalBridgeConfig>,
}

/// The virtual network; every node of it must agree on all of these.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkConfig {
    /// Used byte for byte in the network digest (spec §6.3).
    pub name: String,
    #[serde(deserialize_with = "secret_text")]
    pub secret: Zeroizing<String>,
    /// `managed`, the default: one of our region networks, which always use
    /// the secure mode (spec §5.2, §15.11, requirement R30). `legacy`: an
    /// existing network joined during migration, typically the old-network
    /// instance of a bridge node; only this kind may use the default mode or
    /// no encryption.
    #[serde(default)]
    pub kind: NetworkKind,
    /// The secure mode (`true`) or the default handshake without forward
    /// secrecy (`false`). All nodes of a network use the same mode and there
    /// is no fallback (spec §5.2). Absent: `true` for managed networks,
    /// `false` for legacy ones.
    #[serde(default)]
    pub secure_mode: Option<bool>,
    /// Cipher of the default handshake mode (spec §7.1). `none` turns
    /// encryption off and must be chosen explicitly.
    #[serde(default)]
    pub cipher: Cipher,
    /// Secure-mode static keys of our nodes in this network, standard
    /// Base64 of 32 bytes each (spec §8.3.1). A managed network admits only
    /// these and waits while the list is absent, empty or lacks this
    /// node's own key. Legacy networks use it only to tell implementations
    /// apart.
    #[serde(default)]
    pub native_keys: Option<Vec<String>>,
}

/// Who runs a network (spec §15.11).
#[derive(Clone, Copy, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum NetworkKind {
    /// Ours: secure mode only, never unencrypted.
    #[default]
    Managed,
    /// An existing network kept during migration.
    Legacy,
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
    /// Whether this node serves as a waypoint of other nodes' custom paths
    /// (spec §17.2.4). Absent: `false`. Needs `relay`, so `true` is refused
    /// on access nodes and with `relay: false`.
    #[serde(default)]
    pub waypoint_relay: Option<bool>,
    /// This node's secure-mode static private key for the network, standard
    /// Base64 of 32 bytes, injected from the system key store like the
    /// secret and never written out. Absent: the caller keeps one.
    #[serde(default, deserialize_with = "optional_secret_text")]
    pub private_key: Option<Zeroizing<String>>,
}

/// Secret text, wiped from memory when dropped.
fn secret_text<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Zeroizing<String>, D::Error> {
    String::deserialize(deserializer).map(Zeroizing::new)
}

fn optional_secret_text<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<Zeroizing<String>>, D::Error> {
    Option::<String>::deserialize(deserializer).map(|text| text.map(Zeroizing::new))
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

/// Whether this build runs on a phone, where nodes are access nodes only
/// (requirement R10).
pub const IS_PHONE: bool = cfg!(any(target_os = "ios", target_os = "android"));

impl Role {
    /// The role of this platform when the config names none.
    pub fn platform_default() -> Self {
        Self::default_for(IS_PHONE)
    }

    /// Whether this platform may run as a full node.
    pub fn platform_allows_full() -> bool {
        Self::allowed(Role::Full, IS_PHONE)
    }

    /// The role when the config names none, on a phone or elsewhere.
    pub fn default_for(phone: bool) -> Self {
        if phone {
            Role::Access
        } else {
            Role::Full
        }
    }

    /// Whether `role` may run on a phone or elsewhere.
    pub fn allowed(role: Role, phone: bool) -> bool {
        role == Role::Access || !phone
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
/// XOR mode is not offered: a config naming it fails validation with a
/// message saying it is insecure.
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
    #[serde(rename = "aes-gcm")]
    Aes128Gcm,
    /// AES-256-GCM.
    #[serde(rename = "aes-256-gcm")]
    Aes256Gcm,
    /// ChaCha20-Poly1305.
    #[serde(rename = "chacha20", alias = "chacha20-poly1305")]
    ChaCha20Poly1305,
    /// The unauthenticated XOR mode (spec §7.1). Recognised only so that
    /// validation can say why it is refused; never used.
    #[serde(rename = "xor")]
    Xor,
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

/// Validated settings. Has no `Debug`: it holds the secret. Equality
/// tells the management API whether a network's settings changed.
#[derive(Clone, PartialEq, Eq)]
pub struct MeshSettings {
    pub network_name: String,
    pub network_secret: Zeroizing<String>,
    pub kind: NetworkKind,
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
    /// Whether this node serves as a waypoint of custom paths (spec
    /// §17.2.4); never without `relay`.
    pub waypoint_relay: bool,
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
    /// Decoded `network.native_keys`; `None` when absent.
    pub native_keys: Option<Vec<[u8; 32]>>,
    /// Decoded `node.private_key`, wiped when dropped.
    pub private_key: Option<Zeroizing<[u8; 32]>>,
    /// The checked `external_bridge` section; its routes are also in
    /// `advertise_subnets`.
    pub external_bridge: Option<ExternalBridge>,
}

impl MeshSettings {
    /// A managed network waits, without links, interface or routes, while
    /// its native key list is absent, empty or lacks `own_public`, the
    /// node's static public key (spec §8.3.1 rule 1). Legacy networks never
    /// wait.
    pub fn waits_for_native_keys(&self, own_public: &[u8; 32]) -> bool {
        self.kind == NetworkKind::Managed
            && !self
                .native_keys
                .as_ref()
                .is_some_and(|keys| keys.contains(own_public))
    }

    /// Whether a peer with `key` is admitted (spec §8.3.1): in a managed
    /// network only keys on the list; in a legacy network every key.
    pub fn admits(&self, key: &[u8; 32]) -> bool {
        self.kind != NetworkKind::Managed
            || self
                .native_keys
                .as_ref()
                .is_some_and(|keys| keys.contains(key))
    }

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
            .any(|subnet| subnet.is_host(address))
    }
}

/// Most keys `network.native_keys` may list: one per node of the largest
/// network (spec §12.4).
pub const MAX_NATIVE_KEYS: usize = 4096;

/// Decodes standard Base64 with padding (RFC 4648 §4) of exactly 32 bytes.
fn decode_key(text: &str) -> Option<Zeroizing<[u8; 32]>> {
    use base64::Engine as _;
    let bytes = Zeroizing::new(
        base64::engine::general_purpose::STANDARD
            .decode(text)
            .ok()?,
    );
    let mut key = Zeroizing::new([0u8; 32]);
    key.copy_from_slice(bytes.get(..32).filter(|_| bytes.len() == 32)?);
    Some(key)
}

/// Encodes a static public key the way the status and `native_keys` do.
pub fn encode_key(key: &[u8; 32]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(key)
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
        if network.cipher == Cipher::Xor {
            return Err("mesh cipher xor is insecure (no authentication) and is not supported");
        }
        let secure_mode = network
            .secure_mode
            .unwrap_or(network.kind == NetworkKind::Managed);
        if network.kind == NetworkKind::Managed && !secure_mode {
            return Err("mesh managed networks always use secure_mode");
        }
        if secure_mode && network.cipher == Cipher::None {
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
        if !Role::allowed(role, IS_PHONE) {
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
        let waypoint_relay = node.waypoint_relay.unwrap_or(false);
        if waypoint_relay && !relay {
            return Err("mesh node waypoint_relay needs relay");
        }
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

        // A full node that listens may wait for others to connect (a hub);
        // every other node needs somewhere to connect to.
        if self.peers.is_empty() && (role == Role::Access || node.listen.is_empty()) {
            return Err("mesh needs at least one peer, or a full node that listens");
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
        // Spec §15.12: a Linux full node only. The routes join this node's
        // advertisement (field 5) under the checks below; the single
        // addresses inside the overlay ranges are allowed for the bridge
        // only, `subnets.advertise` itself stays as strict as before.
        let mut advertise_subnets = advertise_subnets;
        let external_bridge = match &self.external_bridge {
            None => None,
            Some(section) => {
                if role != Role::Full || !cfg!(target_os = "linux") {
                    return Err("external_bridge_not_supported");
                }
                let bridge = section.validate().map_err(|error| error.reason())?;
                for route in bridge.routes() {
                    if !advertise_subnets.contains(route) {
                        advertise_subnets.push(*route);
                    }
                }
                Some(bridge)
            }
        };
        let system_routes = match &self.routing.system_routes {
            None => None,
            Some(texts) => Some(intranet_subnets(texts, "mesh routing.system_routes")?),
        };

        let native_keys = match &network.native_keys {
            None => None,
            Some(texts) => {
                if texts.len() > MAX_NATIVE_KEYS {
                    return Err("mesh network native_keys lists too many keys");
                }
                let mut keys = Vec::with_capacity(texts.len());
                let mut seen = HashSet::with_capacity(texts.len());
                for text in texts {
                    let key = decode_key(text)
                        .ok_or("mesh network native_keys entry is not Base64 of 32 bytes")?;
                    if seen.insert(*key) {
                        keys.push(*key);
                    }
                }
                Some(keys)
            }
        };
        let private_key = match &node.private_key {
            None => None,
            Some(text) => {
                Some(decode_key(text).ok_or("mesh node private_key is not Base64 of 32 bytes")?)
            }
        };

        let mut settings = MeshSettings {
            network_name: network.name,
            network_secret: network.secret,
            kind: network.kind,
            security: if secure_mode {
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
            waypoint_relay,
            listen: node.listen,
            peers,
            accept_subnets,
            advertise_subnets,
            route_policy: self.routing.policy,
            system_routes,
            paths: Vec::new(),
            native_keys,
            private_key,
            external_bridge,
        };
        if let Some(bridge) = &settings.external_bridge {
            // The mesh interface is named at start; [`ExternalBridge`] is
            // checked against it again then.
            bridge
                .check_mesh("", &settings.virtual_subnets(), &settings.local_addresses())
                .map_err(|error| error.reason())?;
        }
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
            "network": {"name": "office", "secret": "s3cret", "kind": "legacy"},
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
    fn managed_networks_always_use_the_secure_mode() {
        let mut managed = base();
        managed["network"].as_object_mut().unwrap().remove("kind");
        let settings = validate(managed.clone()).unwrap();
        assert_eq!(settings.kind, NetworkKind::Managed);
        assert_eq!(settings.security, SecurityMode::ForwardSecrecy);
        managed["network"]["secure_mode"] = json!(false);
        assert_eq!(
            validate(managed.clone()).err(),
            Some("mesh managed networks always use secure_mode")
        );
        managed["network"]["secure_mode"] = json!(true);
        managed["network"]["cipher"] = json!("none");
        assert!(validate(managed).is_err());
        // Legacy networks default to the default mode.
        let settings = validate(base()).unwrap();
        assert_eq!(settings.kind, NetworkKind::Legacy);
        assert_eq!(settings.security, SecurityMode::Default);
        assert!(parse(with("network.kind", json!("other"))).is_err());
    }

    #[test]
    fn roles_by_platform() {
        assert_eq!(Role::default_for(true), Role::Access);
        assert_eq!(Role::default_for(false), Role::Full);
        assert!(!Role::allowed(Role::Full, true));
        assert!(Role::allowed(Role::Access, true));
        assert!(Role::allowed(Role::Full, false));
        assert!(Role::allowed(Role::Access, false));
        assert_eq!(Role::platform_default(), Role::default_for(IS_PHONE));
    }

    #[test]
    fn top_level_unknown_fields_are_rejected() {
        assert!(parse(with("exit", json!(true))).is_err());
    }

    #[test]
    fn ciphers_take_only_the_names_of_the_table() {
        // Spec §7.1: other spellings are mapped by the importer, not here.
        for (name, cipher) in [
            ("aes-gcm", Cipher::Aes128Gcm),
            ("aes-256-gcm", Cipher::Aes256Gcm),
            ("chacha20", Cipher::ChaCha20Poly1305),
            ("chacha20-poly1305", Cipher::ChaCha20Poly1305),
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
        // XOR has no authentication and is refused with that reason
        // (spec §7.1).
        assert_eq!(
            validate(with("network.cipher", json!("xor"))).err(),
            Some("mesh cipher xor is insecure (no authentication) and is not supported")
        );
        for name in [
            "AES-GCM",
            "",
            "None",
            "plain",
            "openssl-aes-gcm",
            "openssl-xor",
        ] {
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

    fn bridged(section: Value) -> Value {
        let mut config = with("node.role", json!("full"));
        config["external_bridge"] = section;
        config
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a_bridge_joins_its_routes_to_the_advertisement() {
        let mut config = bridged(json!({
            "interface": "ext0",
            "routes": ["100.100.0.5", "192.168.10.0/24"],
            "allow": ["10.144.144.7/32"],
        }));
        config["subnets"] = json!({"advertise": ["192.168.10.0/24"]});
        let settings = validate(config).unwrap();
        let bridge = settings.external_bridge.as_ref().unwrap();
        assert_eq!(bridge.interface(), "ext0");
        assert_eq!(
            settings.advertise_subnets,
            [
                IpNet::parse("192.168.10.0/24").unwrap(),
                IpNet::parse("100.100.0.5/32").unwrap(),
            ]
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a_bad_bridge_refuses_the_whole_config() {
        let section = |routes: Value| json!({"interface": "ext0", "routes": routes});
        assert_eq!(
            validate(bridged(section(json!([])))).err(),
            Some("external_bridge_no_routes")
        );
        assert_eq!(
            validate(bridged(section(json!(["100.64.0.0/10"])))).err(),
            Some("external_bridge_overlay_range")
        );
        assert_eq!(
            validate(bridged(section(json!(["10.144.144.0/25"])))).err(),
            Some("external_bridge_route_overlaps_mesh")
        );
        let mut unknown = section(json!(["100.100.0.5"]));
        unknown["extra"] = json!(1);
        assert!(parse(bridged(unknown)).is_err());
        // Access nodes do not bridge.
        let mut access = base();
        access["external_bridge"] = section(json!(["100.100.0.5"]));
        assert_eq!(
            validate(access).err(),
            Some("external_bridge_not_supported")
        );
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn only_linux_bridges() {
        let config = bridged(json!({"interface": "ext0", "routes": ["100.100.0.5"]}));
        assert!(validate(config).is_err());
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

    #[cfg(not(any(target_os = "ios", target_os = "android")))]
    #[test]
    fn waypoint_relay_is_off_unless_asked_and_needs_relay() {
        // Off by default (spec §17.2.4).
        assert!(
            !validate(with("node.role", json!("full")))
                .unwrap()
                .waypoint_relay
        );
        let mut config = with("node.role", json!("full"));
        config["node"]["waypoint_relay"] = json!(true);
        assert!(validate(config.clone()).unwrap().waypoint_relay);
        config["node"]["relay"] = json!(false);
        assert_eq!(
            validate(config).err(),
            Some("mesh node waypoint_relay needs relay")
        );
        assert_eq!(
            validate(with("node.waypoint_relay", json!(true))).err(),
            Some("mesh node waypoint_relay needs relay")
        );
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
    fn a_listening_full_node_may_have_no_peers() {
        // An access node always needs a peer.
        assert!(validate(with("peers", json!([]))).is_err());
        let mut hub = with("peers", json!([]));
        hub["node"]["role"] = json!("full");
        // A full node that does not listen cannot be reached either.
        assert!(validate(hub.clone()).is_err());
        hub["node"]["listen"] = json!([{"transport": "tcp"}]);
        if Role::platform_allows_full() {
            assert!(validate(hub).unwrap().peers.is_empty());
        }
    }

    #[test]
    fn broadcast_addresses_are_not_nodes() {
        let path = with(
            "routing",
            json!({"paths": [{"to_peer": "10.144.144.255", "via": ["10.144.144.3"]}]}),
        );
        assert!(validate(path).is_err());
        let via = with(
            "routing",
            json!({"paths": [{"to_peer": "10.144.144.7", "via": ["10.144.144.255"]}]}),
        );
        assert!(validate(via).is_err());
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

    #[test]
    fn native_keys_and_the_private_key_are_base64_of_32_bytes() {
        let key = encode_key(&[7; 32]);
        assert_eq!(key.len(), 44);
        let settings = validate(with("network.native_keys", json!([key, key]))).unwrap();
        assert_eq!(settings.native_keys, Some(vec![[7; 32]]));
        let settings = validate(with("node.private_key", json!(encode_key(&[9; 32])))).unwrap();
        assert_eq!(settings.private_key.as_deref(), Some(&[9; 32]));
        for bad in [
            json!(["not base64!"]),
            json!([&encode_key(&[1; 32])[..40]]),
            json!(["AAAA"]),
        ] {
            assert!(validate(with("network.native_keys", bad)).is_err());
        }
        assert!(validate(with("node.private_key", json!("AAAA"))).is_err());
        // Without padding is not the standard form.
        let unpadded = key.trim_end_matches('=').to_owned();
        assert!(validate(with("network.native_keys", json!([unpadded]))).is_err());
        // Non-zero bits after the last byte are not the canonical form:
        // one key has exactly one text.
        let zero = encode_key(&[0; 32]);
        assert!(zero.ends_with("A="));
        assert!(validate(with("network.native_keys", json!([zero.clone()]))).is_ok());
        let noncanonical = format!("{}B=", &zero[..42]);
        assert!(validate(with("network.native_keys", json!([noncanonical]))).is_err());
    }

    #[test]
    fn a_managed_network_waits_until_its_list_holds_this_node() {
        let mut config = with("network.kind", json!("managed"));
        config["node"]["role"] = json!("full");
        let own = [5; 32];
        let settings = validate(config.clone()).unwrap();
        assert!(settings.waits_for_native_keys(&own));
        config["network"]["native_keys"] = json!([]);
        assert!(validate(config.clone())
            .unwrap()
            .waits_for_native_keys(&own));
        config["network"]["native_keys"] = json!([encode_key(&[6; 32])]);
        let settings = validate(config.clone()).unwrap();
        assert!(settings.waits_for_native_keys(&own));
        assert!(settings.admits(&[6; 32]));
        assert!(!settings.admits(&own));
        config["network"]["native_keys"] = json!([encode_key(&[6; 32]), encode_key(&own)]);
        assert!(!validate(config).unwrap().waits_for_native_keys(&own));
        // A legacy network never waits and admits every key.
        let legacy = validate(base()).unwrap();
        assert!(!legacy.waits_for_native_keys(&own));
        assert!(legacy.admits(&own));
    }
}
