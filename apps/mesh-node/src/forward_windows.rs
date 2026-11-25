//! Host side of a Windows full node (requirement R10): what lets the node
//! accept peers and carry traffic to the subnets it advertises.
//!
//! Every change is a guard from `platform_windows::mesh_host`, held by
//! [`HostChanges`] while the node runs; what a dead process left behind is
//! put back by `recover_mesh_host` on the next start.
//!
//! - Firewall: inbound TCP/UDP to this program's listen ports, and inbound
//!   from the mesh adapter to this program, for any full node that listens.
//! - Forwarding: interface-level forwarding on the mesh adapter and on each
//!   interface with an address on an advertised subnet, for a full node with
//!   subnets to advertise. The global `IPEnableRouter` setting is not
//!   touched.
//! - Translation: one WinNAT object whose internal prefix is the IPv4
//!   virtual subnet, so hosts on an advertised subnet answer this machine's
//!   address on that subnet. WinNAT takes one internal prefix per object and
//!   some Windows versions only one object at all, so subnets routed into
//!   the mesh from other nodes and IPv6 are not translated: hosts on the
//!   advertised subnets need a route back for those. When WinNAT refuses
//!   the object, forwarding stays on and a warning says so.

use std::io;
use std::net::{IpAddr, Ipv4Addr};
use std::path::Path;

use outbound_mesh::IpNet;
use platform_windows::mesh_host::{self, FirewallGuard, ForwardingGuard, NatGuard};

/// The guards of one running node. Dropped in field order: translation
/// first, then forwarding, then the firewall rules.
#[derive(Debug, Default)]
pub struct HostChanges {
    nat: Option<NatGuard>,
    forwarding: Option<ForwardingGuard>,
    firewall: Option<FirewallGuard>,
}

impl HostChanges {
    /// Whether forwarding is held.
    pub fn forwarding(&self) -> bool {
        self.forwarding.is_some()
    }

    /// Adds the firewall rules of `network` for this program's
    /// `listen_ports`, the mesh adapter being `adapter`.
    pub fn allow_inbound(
        &mut self,
        network: &str,
        listen_ports: &[u16],
        adapter: &str,
    ) -> io::Result<()> {
        let program = std::env::current_exe()?;
        self.firewall = Some(mesh_host::add_mesh_firewall_rules(
            network,
            &program,
            listen_ports,
            adapter,
        )?);
        Ok(())
    }

    /// Switches forwarding on for `adapter` and the interfaces that carry
    /// the `advertised` subnets, then translates the IPv4 virtual subnet
    /// (`virtual_v4`, the node's address and prefix). `interfaces` are the
    /// machine's (alias, address network) pairs. Returns warnings: subnets
    /// no interface is on, and a translation WinNAT refused.
    pub fn forward(
        &mut self,
        state_dir: &Path,
        network: &str,
        adapter: &str,
        interfaces: &[(String, IpNet)],
        advertised: &[IpNet],
        virtual_v4: Option<(Ipv4Addr, u8)>,
    ) -> io::Result<Vec<String>> {
        let lan = crate::host_routes::lan_interfaces(interfaces, advertised, adapter);
        let mut warnings = missing_interfaces(&lan, advertised);
        let mut aliases: Vec<String> = lan.into_iter().map(|(alias, _)| alias).collect();
        aliases.dedup();
        self.forwarding = Some(mesh_host::enable_mesh_forwarding(
            state_dir, adapter, &aliases,
        )?);
        if let Some((address, prefix)) = virtual_v4 {
            match mesh_host::add_mesh_nat(network, address, prefix) {
                Ok(guard) => self.nat = Some(guard),
                Err(error) => warnings.push(format!(
                    "address translation is off ({error}); hosts on the advertised subnets \
                     need a route back to the virtual subnet"
                )),
            }
        }
        Ok(warnings)
    }
}

/// One warning for each advertised subnet that no interface is on.
fn missing_interfaces(lan: &[(String, IpNet)], advertised: &[IpNet]) -> Vec<String> {
    advertised
        .iter()
        .filter(|subnet| !lan.iter().any(|(_, net)| net == *subnet))
        .map(|subnet| format!("{subnet}: no interface of this machine is on it"))
        .collect()
}

/// The IPv4 address and prefix of `address`, `None` for IPv6.
pub fn ipv4(address: &IpNet) -> Option<(Ipv4Addr, u8)> {
    match address.address() {
        IpAddr::V4(v4) => Some((v4, address.prefix())),
        IpAddr::V6(_) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn net(text: &str) -> IpNet {
        IpNet::parse(text).unwrap()
    }

    #[test]
    fn subnets_without_an_interface_are_reported() {
        let lan = vec![("Ethernet".to_string(), net("192.168.1.0/24"))];
        let warnings = missing_interfaces(&lan, &[net("192.168.1.0/24"), net("172.16.0.0/16")]);
        assert_eq!(
            warnings,
            vec!["172.16.0.0/16: no interface of this machine is on it".to_string()]
        );
    }

    #[test]
    fn only_ipv4_virtual_addresses_are_translated() {
        assert_eq!(
            ipv4(&net("10.144.0.5/24")),
            Some((Ipv4Addr::new(10, 144, 0, 5), 24))
        );
        assert_eq!(ipv4(&net("fd00::5/64")), None);
    }

    #[test]
    fn nothing_held_puts_nothing_back() {
        let host = HostChanges::default();
        assert!(!host.forwarding());
        drop(host);
    }
}
