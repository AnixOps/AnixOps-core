//! Settings of a `"type": "mesh"` outbound.
//!
//! Only the fields every mesh needs regardless of wire format live here; the
//! specification adds the transport and protocol fields it defines. Unknown
//! fields are ignored like in the other outbounds.

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
    /// The network's handshake mode, the same on every node of the
    /// network; see [`SecurityMode`]. Required, so a config never falls into
    /// a mode nobody chose.
    pub security: SecurityMode,
}

/// One bootstrap peer.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub struct PeerConfig {
    /// IP address or host name.
    pub server: String,
    pub port: u16,
}

/// Where a bootstrap peer listens.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeerEndpoint {
    pub server: String,
    pub port: u16,
}

/// The handshake mode of a network. Every node of one network uses the same
/// mode; there is no per-connection negotiation.
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SecurityMode {
    /// `"default"`: the network's default handshake, which has no forward
    /// secrecy. Sessions in this mode are reported as such so the interface
    /// can mark them. Networks whose nodes do not enable forward secrecy
    /// need this mode to interoperate.
    Default,
    /// `"forward_secrecy"`: the handshake with forward secrecy.
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
        let network_name = self.network_name.trim();
        if network_name.is_empty() {
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
            security: self.security,
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
            "security": "default",
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
    fn security_mode_is_required_and_closed() {
        let settings = validate(with("security", json!("forward_secrecy"))).unwrap();
        assert_eq!(settings.security, SecurityMode::ForwardSecrecy);
        assert!(settings.security.has_forward_secrecy());
        for value in [json!("off"), json!("preferred"), json!(true), json!(null)] {
            assert!(
                serde_json::from_value::<MeshConfig>(with("security", value.clone())).is_err(),
                "{value}"
            );
        }
        let mut missing = base();
        missing.as_object_mut().unwrap().remove("security");
        assert!(serde_json::from_value::<MeshConfig>(missing).is_err());
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
