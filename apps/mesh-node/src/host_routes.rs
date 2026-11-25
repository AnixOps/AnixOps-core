//! What the host already reaches without the mesh, for the overlap rule of
//! spec §15.4 (Linux).
//!
//! An accepted subnet is kept out of the system routes and out of the mesh's
//! destination lookup when it overlaps one of the networks returned here:
//!
//! - the address networks of every interface but loopback and our own mesh
//!   interfaces (a physical LAN, or an address on another mesh program's
//!   virtual interface);
//! - routes carried by another program's virtual interface (point-to-point
//!   or without a link layer, as TUN devices are), from every routing table,
//!   so that policy routing tables other programs install are seen too.
//!   Routes wider than /8 (IPv4) or /7 (IPv6) are left out: they are default
//!   routes or their splits (0.0.0.0/1 + 128.0.0.0/1 and finer), and would
//!   otherwise turn every advertisement local while that program carries the
//!   default route.
//!
//! Our own mesh interfaces never count, whichever network they belong to:
//! otherwise a route we install would be found on the next scan, withdrawn as
//! an overlap, and installed again once gone.

use std::collections::HashMap;
use std::net::IpAddr;

use outbound_mesh::IpNet;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub use linux::{host_links, host_routes};
#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "macos")]
pub use macos::{host_links, host_routes};
#[cfg(windows)]
mod windows;
#[cfg(windows)]
pub use windows::{host_links, host_routes, local_interfaces, local_networks};

/// Names our mesh interfaces start with: `anixmesh0` for `run`,
/// `anixmesh-<n>` for the managed networks.
pub const OWN_INTERFACE_PREFIX: &str = "anixmesh";

/// Narrowest prefix that still counts as a default-route split.
const WIDEST_V4: u8 = 8;
const WIDEST_V6: u8 = 7;

/// Whether `name` is one of our mesh interfaces: it starts with
/// [`OWN_INTERFACE_PREFIX`] or is in `extra` (a name given with
/// `run --interface`).
pub fn is_own_interface(name: &str, extra: &[&str]) -> bool {
    name.starts_with(OWN_INTERFACE_PREFIX) || extra.contains(&name)
}

/// One unicast route: destination and the interfaces it leaves through.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostRoute {
    pub destination: IpNet,
    pub interfaces: Vec<u32>,
}

/// One interface: name and whether it is virtual (point-to-point or without
/// a link layer).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostLink {
    pub name: String,
    pub is_virtual: bool,
}

/// Routes whose prefix is at least /8 (IPv4) or /7 (IPv6) and that leave
/// through another program's virtual interface.
pub fn foreign_virtual_routes(
    routes: &[HostRoute],
    links: &HashMap<u32, HostLink>,
    own: &[&str],
) -> Vec<IpNet> {
    let mut found: Vec<IpNet> = routes
        .iter()
        .filter(|route| {
            let widest = match route.destination.network() {
                IpAddr::V4(_) => WIDEST_V4,
                IpAddr::V6(_) => WIDEST_V6,
            };
            route.destination.prefix() >= widest
        })
        .filter(|route| {
            route.interfaces.iter().any(|index| {
                links
                    .get(index)
                    .is_some_and(|link| link.is_virtual && !is_own_interface(&link.name, own))
            })
        })
        .map(|route| route.destination)
        .collect();
    found.sort_by_key(|net| net.to_string());
    found.dedup();
    found
}

/// The LAN interfaces that carry each advertised subnet: those with an
/// address whose network overlaps it. `interfaces` lists (name, address
/// network) pairs; `own` is the mesh interface.
pub fn lan_interfaces(
    interfaces: &[(String, IpNet)],
    advertised: &[IpNet],
    own: &str,
) -> Vec<(String, IpNet)> {
    let mut found = Vec::new();
    for subnet in advertised {
        for (name, network) in interfaces {
            if name != own && network.overlaps(subnet) {
                found.push((name.clone(), *subnet));
            }
        }
    }
    found.sort_by_key(|(name, net)| (name.clone(), net.to_string()));
    found.dedup();
    found
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn advertised_subnets_find_their_interfaces() {
        let interfaces = vec![
            ("en0".to_string(), net("192.168.1.10/24")),
            ("utun4".to_string(), net("10.144.0.5/24")),
            ("en1".to_string(), net("172.16.5.2/24")),
        ];
        let found = lan_interfaces(
            &interfaces,
            &[
                net("192.168.1.0/24"),
                net("10.144.0.0/24"),
                net("172.16.0.0/16"),
            ],
            "utun4",
        );
        assert_eq!(
            found,
            vec![
                ("en0".to_string(), net("192.168.1.0/24")),
                ("en1".to_string(), net("172.16.0.0/16")),
            ]
        );
    }

    fn net(text: &str) -> IpNet {
        IpNet::parse(text).unwrap()
    }

    fn links() -> HashMap<u32, HostLink> {
        let link = |name: &str, is_virtual| HostLink {
            name: name.into(),
            is_virtual,
        };
        HashMap::from([
            (1, link("lo", false)),
            (2, link("eth0", false)),
            (3, link("vpn0", true)),
            (4, link("anixmesh-0", true)),
            (5, link("anixmesh0", true)),
            (6, link("custom9", true)),
        ])
    }

    fn route(text: &str, interfaces: &[u32]) -> HostRoute {
        HostRoute {
            destination: net(text),
            interfaces: interfaces.to_vec(),
        }
    }

    #[test]
    fn only_routes_of_other_virtual_interfaces_count() {
        let routes = [
            route("100.64.0.0/10", &[3]),
            route("192.168.1.0/24", &[2]),
            route("10.20.0.0/16", &[4]),
            route("10.21.0.0/16", &[5]),
            route("10.22.0.0/16", &[6]),
            route("10.23.0.0/16", &[9]),
            route("fd7a:115c:a1e0::/48", &[3]),
        ];
        assert_eq!(
            foreign_virtual_routes(&routes, &links(), &["custom9"]),
            vec![net("100.64.0.0/10"), net("fd7a:115c:a1e0::/48")]
        );
        // Without `custom9` as ours, its route counts.
        assert!(foreign_virtual_routes(&routes, &links(), &[]).contains(&net("10.22.0.0/16")));
    }

    #[test]
    fn default_routes_and_their_splits_do_not_count() {
        let routes = [
            route("0.0.0.0/0", &[3]),
            route("0.0.0.0/1", &[3]),
            route("128.0.0.0/1", &[3]),
            route("64.0.0.0/2", &[3]),
            route("8.0.0.0/7", &[3]),
            route("10.0.0.0/8", &[3]),
            route("::/0", &[3]),
            route("::/1", &[3]),
            route("8000::/1", &[3]),
            route("fe00::/6", &[3]),
            route("fc00::/7", &[3]),
        ];
        assert_eq!(
            foreign_virtual_routes(&routes, &links(), &[]),
            vec![net("10.0.0.0/8"), net("fc00::/7")]
        );
    }

    #[test]
    fn a_multipath_route_counts_when_any_hop_is_foreign() {
        let routes = [
            route("10.30.0.0/16", &[2, 3]),
            route("10.31.0.0/16", &[2, 4]),
        ];
        assert_eq!(
            foreign_virtual_routes(&routes, &links(), &[]),
            vec![net("10.30.0.0/16")]
        );
    }

    #[test]
    fn own_interfaces_are_recognised_by_prefix_or_name() {
        assert!(is_own_interface("anixmesh0", &[]));
        assert!(is_own_interface("anixmesh-3", &[]));
        assert!(is_own_interface("custom9", &["custom9"]));
        assert!(!is_own_interface("vpn0", &["custom9"]));
    }
}
