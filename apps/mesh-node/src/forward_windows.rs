//! Host side of a Windows full node (requirement R10): what lets the node
//! accept peers and carry traffic to the subnets it advertises.
//!
//! Every change is a guard from `platform_windows::mesh_host`, held by
//! [`HostChanges`] while the node runs; what a dead process left behind is
//! put back by `recover_mesh_host` on the next start. Only one process per
//! host makes these changes (the client or this node): a second one is
//! refused with `ResourceBusy` and runs without them.
//!
//! - Firewall: inbound TCP/UDP to this program's listen ports, and inbound
//!   from the mesh adapter to this program, for any full node that listens.
//! - Forwarding: interface-level forwarding on the mesh adapter and on each
//!   interface with an address on an advertised subnet, for a full node with
//!   subnets to advertise, for IPv6 too when the node has an IPv6 virtual
//!   address. The global `IPEnableRouter` setting is not touched. Other
//!   interfaces that already forward are reported, since Windows forwards
//!   between all of them.
//! - Translation: one WinNAT object whose internal prefix is the IPv4
//!   virtual subnet, so hosts on an advertised subnet answer this machine's
//!   address on that subnet. WinNAT takes one internal prefix per object and
//!   some Windows versions only one object at all, so subnets routed into
//!   the mesh from other nodes and IPv6 are not translated: hosts on the
//!   advertised subnets need a route back for those. When WinNAT refuses
//!   the object, forwarding stays on and a warning says so.

use std::io;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::mpsc;
use std::time::Duration;

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

    /// Switches forwarding on for `adapter` and the interfaces in `lan`
    /// (alias, advertised subnet it carries; IPv6 too when `ipv6`), then
    /// translates the IPv4 virtual subnet (`virtual_v4`, the node's address
    /// and prefix). Returns warnings: other interfaces that forward, and a
    /// translation WinNAT refused.
    pub fn forward(
        &mut self,
        network: &str,
        adapter: &str,
        lan: &[(String, IpNet)],
        virtual_v4: Option<(Ipv4Addr, u8)>,
        ipv6: bool,
    ) -> io::Result<Vec<String>> {
        let mut warnings = Vec::new();
        let mut aliases: Vec<String> = lan.iter().map(|(alias, _)| alias.clone()).collect();
        aliases.sort();
        aliases.dedup();
        let forwarding = mesh_host::enable_mesh_forwarding(adapter, &aliases, ipv6)?;
        match forwarding.other_forwarding_interfaces() {
            Ok(others) if !others.is_empty() => warnings.push(format!(
                "other interfaces forward too and can reach the advertised subnets: {}",
                others.join(", ")
            )),
            Ok(_) => {}
            Err(error) => warnings.push(format!("forwarding interfaces unknown: {error}")),
        }
        self.forwarding = Some(forwarding);
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

    /// Undoes everything now, in the order the fields drop, waiting for the
    /// removals so that none is left running when the service reports that
    /// it stopped (a removal still running could delete the rules of the
    /// next start), including removals of guards dropped before. Returns
    /// problems as warnings.
    pub fn shutdown(mut self) -> Vec<String> {
        let mut warnings = Vec::new();
        if let Some(nat) = self.nat.take() {
            if let Err(error) = nat.remove() {
                warnings.push(error.to_string());
            }
        }
        drop(self.forwarding.take());
        if let Some(firewall) = self.firewall.take() {
            if let Err(error) = firewall.remove() {
                warnings.push(error.to_string());
            }
        }
        // Guards dropped earlier (a start that failed half way) remove on
        // threads of their own: wait for those too, but not forever.
        if !finish_removals(REMOVAL_WAIT) {
            warnings.push(format!(
                "earlier firewall or translation removals still running after {} s; \
                 the next start or restore-host puts back what they leave",
                REMOVAL_WAIT.as_secs()
            ));
        }
        warnings
    }
}

/// How long shutdown waits for removals of guards dropped earlier.
const REMOVAL_WAIT: Duration = Duration::from_secs(10);

/// Waits up to `limit` for the removals of dropped guards. Returns whether
/// they finished; if not, the waiting thread is left to finish them.
fn finish_removals(limit: Duration) -> bool {
    let (done, finished) = mpsc::channel();
    let spawned = std::thread::Builder::new()
        .name("mesh-removals-wait".into())
        .spawn(move || {
            mesh_host::finish_mesh_firewall_removals();
            let _ = done.send(());
        });
    match spawned {
        Ok(_) => finished.recv_timeout(limit).is_ok(),
        Err(_) => {
            mesh_host::finish_mesh_firewall_removals();
            true
        }
    }
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

    #[test]
    fn shutdown_with_nothing_pending_returns_at_once() {
        assert!(finish_removals(Duration::from_secs(10)));
        assert!(HostChanges::default().shutdown().is_empty());
    }
}
