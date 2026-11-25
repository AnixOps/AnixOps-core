//! Settings of a `"type": "mesh"` outbound.
//!
//! Field meanings follow `docs/protocols/intranet-mesh.md` (§2.4 defaults,
//! §5.2 `secure_mode`, §7.1 `cipher`, §13.2 `route_policy`). Unknown fields
//! are ignored like in the other outbounds.

use std::net::IpAddr;

use serde::Deserialize;

use crate::net::IpNet;
use crate::scope::is_intranet_network;

/// Longest accepted network name, in bytes.
pub const MAX_NETWORK_NAME_BYTES: usize = 255;
/// Most bootstrap peers one node may list.
pub const MAX_PEERS: usize = 64;
/// Most entries in `allowed_subnets`.
pub const MAX_ALLOWED_SUBNETS: usize = 256;
/// Default TCP and UDP port of a peer (spec §2.4).
pub const DEFAULT_PORT: u16 = 11010;

/// One mesh node as it appears in the config. The secret is injected from
/// the Keychain like the other protocols' passwords. Has no `Debug`: it
/// holds the secret.
#[derive(Deserialize)]
pub struct MeshConfig {
    /// Name of the virtual network to join.
    pub network_name: String,
    /// Shared secret of the virtual network.
    pub network_secret: String,
    /// This node's IPv4 address in the virtual network with its prefix,
    /// for example `10.144.144.5/24`; the prefix is the virtual subnet.
    pub address: String,
    /// Optional IPv6 address in the virtual network, same form.
    #[serde(default)]
    pub address_v6: Option<String>,
    /// Peers to connect to first. More peers are learned from them.
    pub peers: Vec<PeerConfig>,
    /// Further limits which advertised subnets this node accepts. Empty:
    /// every intranet subnet a peer advertises. Never widens the intranet
    /// scope of [`crate::scope`].
    #[serde(default)]
    pub allowed_subnets: Vec<String>,
    /// The network's handshake mode (spec §5.2): `false`, the default, is
    /// the default handshake without forward secrecy; `true` is the secure
    /// mode. Every node of a network uses the same mode and there is no
    /// fallback between them.
    #[serde(default)]
    pub secure_mode: bool,
    /// Traffic cipher of the default handshake mode (spec §7.1); both ends
    /// must agree. Absent: `aes-gcm`.
    #[serde(default)]
    pub cipher: Cipher,
    /// How this node's own packets choose relays (spec §13.2). Absent:
    /// `hops`.
    #[serde(default)]
    pub route_policy: RoutePolicy,
}

/// One bootstrap peer.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub struct PeerConfig {
    /// IP address or host name.
    pub server: String,
    /// Absent: [`DEFAULT_PORT`].
    #[serde(default = "default_port")]
    pub port: u16,
    /// Absent: `tcp`.
    #[serde(default)]
    pub transport: Transport,
}

fn default_port() -> u16 {
    DEFAULT_PORT
}

/// Transports of the first version (spec §3.1, §3.2).
#[derive(Clone, Copy, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Transport {
    #[default]
    Tcp,
    Udp,
}

/// Where a bootstrap peer listens.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeerEndpoint {
    pub server: String,
    pub port: u16,
    pub transport: Transport,
}

/// Traffic cipher of the default handshake mode (spec §7.1). The unsafe XOR
/// mode is not offered: a config naming it fails to parse.
#[derive(Clone, Copy, Debug, Default, Deserialize, PartialEq, Eq)]
pub enum Cipher {
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

/// The handshake mode of a network (spec §5.2). Every node of one network
/// uses the same mode; there is no per-connection negotiation.
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

/// Validated settings. Has no `Debug`: it holds the secret.
#[derive(Clone)]
pub struct MeshSettings {
    pub network_name: String,
    pub network_secret: String,
    /// This node's IPv4 address; [`IpNet::trunc`] is the virtual subnet.
    pub address: IpNet,
    pub address_v6: Option<IpNet>,
    pub peers: Vec<PeerEndpoint>,
    /// Masked networks; empty means no extra limit.
    pub allowed_subnets: Vec<IpNet>,
    pub security: SecurityMode,
    pub cipher: Cipher,
    pub route_policy: RoutePolicy,
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
}

impl MeshConfig {
    pub fn validate(self) -> Result<MeshSettings, &'static str> {
        // The name goes into the network digest byte for byte (spec §6.3),
        // so it is used exactly as written.
        let network_name = self.network_name.as_str();
        if network_name.trim().is_empty() {
            return Err("mesh network_name is empty");
        }
        if network_name.len() > MAX_NETWORK_NAME_BYTES {
            return Err("mesh network_name is too long");
        }
        if network_name.chars().any(char::is_control) {
            return Err("mesh network_name contains control characters");
        }
        if self.network_secret.is_empty() {
            return Err("mesh network_secret is empty");
        }

        let address = IpNet::parse(&self.address).ok_or("mesh address is not address/prefix")?;
        if !address.is_ipv4() {
            return Err("mesh address must be IPv4; use address_v6 for IPv6");
        }
        check_interface_address(&address, 8, 30)?;

        let address_v6 = match self.address_v6.as_deref() {
            None => None,
            Some(text) => {
                let address = IpNet::parse(text).ok_or("mesh address_v6 is not address/prefix")?;
                if address.is_ipv4() {
                    return Err("mesh address_v6 must be IPv6");
                }
                check_interface_address(&address, 8, 126)?;
                Some(address)
            }
        };

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

        if self.allowed_subnets.len() > MAX_ALLOWED_SUBNETS {
            return Err("mesh lists too many allowed_subnets");
        }
        let mut allowed_subnets = Vec::with_capacity(self.allowed_subnets.len());
        for text in &self.allowed_subnets {
            let subnet = IpNet::parse(text).ok_or("mesh allowed_subnets entry is not a network")?;
            if !is_intranet_network(&subnet) {
                return Err("mesh allowed_subnets entry is outside the intranet ranges");
            }
            allowed_subnets.push(subnet.trunc());
        }

        Ok(MeshSettings {
            network_name: network_name.to_owned(),
            network_secret: self.network_secret,
            address,
            address_v6,
            peers,
            allowed_subnets,
            security: if self.secure_mode {
                SecurityMode::ForwardSecrecy
            } else {
                SecurityMode::Default
            },
            cipher: self.cipher,
            route_policy: self.route_policy,
        })
    }
}

/// The virtual subnet must be intranet and the address a usable host in it.
fn check_interface_address(address: &IpNet, min: u8, max: u8) -> Result<(), &'static str> {
    if address.prefix() < min || address.prefix() > max {
        return Err("mesh address prefix is out of range");
    }
    if !is_intranet_network(&address.trunc()) {
        return Err("mesh address is outside the intranet ranges");
    }
    if address.address() == address.network() {
        return Err("mesh address is the subnet's network address");
    }
    if let IpAddr::V4(v4) = address.address() {
        let host_bits = 32 - u32::from(address.prefix());
        let host_mask = (1u32 << host_bits) - 1;
        if u32::from(v4) & host_mask == host_mask {
            return Err("mesh address is the subnet's broadcast address");
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
            "network_name": "office",
            "network_secret": "s3cret",
            "address": "10.144.144.5/24",
            "peers": [{"server": "peer.example", "port": 40000}],
        })
    }

    fn validate(value: Value) -> Result<MeshSettings, &'static str> {
        serde_json::from_value::<MeshConfig>(value)
            .unwrap()
            .validate()
    }

    fn with(key: &str, value: Value) -> Value {
        let mut config = base();
        config[key] = value;
        config
    }

    #[test]
    fn minimal_config_validates() {
        let settings = validate(base()).unwrap();
        assert_eq!(settings.network_name, "office");
        assert_eq!(settings.address.to_string(), "10.144.144.0/24");
        assert_eq!(
            settings.address.address(),
            "10.144.144.5".parse::<IpAddr>().unwrap()
        );
        assert_eq!(
            settings.virtual_subnets(),
            vec![IpNet::parse("10.144.144.0/24").unwrap()]
        );
        assert_eq!(settings.security, SecurityMode::Default);
        assert!(!settings.security.has_forward_secrecy());
        assert!(settings.allowed_subnets.is_empty());
        assert_eq!(
            settings.peers,
            vec![PeerEndpoint {
                server: "peer.example".into(),
                port: 40000
            }]
        );
    }

    #[test]
    fn secure_mode_is_an_explicit_network_switch() {
        let settings = validate(with("secure_mode", json!(true))).unwrap();
        assert_eq!(settings.security, SecurityMode::ForwardSecrecy);
        assert!(settings.security.has_forward_secrecy());
        let settings = validate(with("secure_mode", json!(false))).unwrap();
        assert_eq!(settings.security, SecurityMode::Default);
        assert!(serde_json::from_value::<MeshConfig>(with("secure_mode", json!("yes"))).is_err());
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
            assert_eq!(
                validate(with("cipher", json!(name))).unwrap().cipher,
                cipher,
                "{name}"
            );
        }
        // XOR has no authentication and is refused (spec §7.1).
        for name in ["xor", "openssl-xor", "AES-GCM", ""] {
            assert!(
                serde_json::from_value::<MeshConfig>(with("cipher", json!(name))).is_err(),
                "{name}"
            );
        }
    }

    #[test]
    fn peer_defaults_and_route_policy() {
        let mut config = with(
            "peers",
            json!([{"server": "a"}, {"server": "b", "port": 1, "transport": "udp"}]),
        );
        config["route_policy"] = json!("latency");
        let settings = validate(config).unwrap();
        assert_eq!(settings.peers[0].port, DEFAULT_PORT);
        assert_eq!(settings.peers[0].transport, Transport::Tcp);
        assert_eq!(settings.peers[1].transport, Transport::Udp);
        assert_eq!(settings.route_policy, RoutePolicy::Latency);
        assert!(serde_json::from_value::<MeshConfig>(with(
            "peers",
            json!([{"server": "a", "transport": "quic"}])
        ))
        .is_err());
    }

    #[test]
    fn network_name_is_kept_byte_for_byte() {
        let settings = validate(with("network_name", json!(" office "))).unwrap();
        assert_eq!(settings.network_name, " office ");
    }

    #[test]
    fn ipv6_address_and_allowed_subnets() {
        let mut config = with("address_v6", json!("fd00:aa::5/64"));
        config["allowed_subnets"] = json!(["192.168.10.0/24", "fd12::/48"]);
        let settings = validate(config).unwrap();
        assert_eq!(settings.virtual_subnets().len(), 2);
        assert_eq!(settings.local_addresses().len(), 2);
        assert_eq!(settings.allowed_subnets.len(), 2);
    }

    #[test]
    fn refuses_bad_names_and_secrets() {
        assert!(validate(with("network_name", json!("  "))).is_err());
        assert!(validate(with("network_name", json!("a\nb"))).is_err());
        assert!(validate(with("network_name", json!("x".repeat(256)))).is_err());
        assert!(validate(with("network_secret", json!(""))).is_err());
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
                validate(with("address", json!(address))).is_err(),
                "{address}"
            );
        }
        for address in ["2001:db8::5/64", "10.0.0.5/24", "fd00::/64"] {
            assert!(
                validate(with("address_v6", json!(address))).is_err(),
                "{address}"
            );
        }
    }

    #[test]
    fn refuses_bad_peers() {
        assert!(validate(with("peers", json!([]))).is_err());
        assert!(validate(with("peers", json!([{"server": " ", "port": 1}]))).is_err());
        assert!(validate(with("peers", json!([{"server": "a", "port": 0}]))).is_err());
        let many: Vec<Value> = (0..=MAX_PEERS)
            .map(|i| json!({"server": format!("p{i}"), "port": 1}))
            .collect();
        assert!(validate(with("peers", Value::Array(many))).is_err());
    }

    #[test]
    fn allowed_subnets_cannot_widen_the_intranet() {
        for subnet in ["0.0.0.0/0", "1.1.1.0/24", "::/0", "bogus"] {
            assert!(
                validate(with("allowed_subnets", json!([subnet]))).is_err(),
                "{subnet}"
            );
        }
    }
}
