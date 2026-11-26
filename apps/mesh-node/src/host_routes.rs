//! What the host already reaches without the mesh, for the overlap rule of
//! spec §15.4.
//!
//! An accepted subnet is kept out of the system routes and out of the mesh's
//! destination lookup when it overlaps one of:
//!
//! - the address networks of every interface but loopback and our own mesh
//!   interfaces (a physical LAN, or an address on another mesh program's
//!   virtual interface), read by the caller;
//! - the routes of [`foreign_routes`]: routes that leave through another
//!   program's virtual interface (point-to-point, without a link layer, or a
//!   TUN/TAP device), and refusing (blackhole, unreachable, prohibit)
//!   routes, each kept only when the system selects it for its own
//!   destination. On Linux that is a lookup through the policy rules
//!   (`RTM_F_FIB_MATCH`, so `throw` routes apply); elsewhere the most
//!   specific route of the table read. Routes wider than /8 (IPv4) or /7
//!   (IPv6) are left out: they are default routes or their splits
//!   (0.0.0.0/1 + 128.0.0.0/1 and finer), and would otherwise turn every
//!   advertisement local while that program carries the default route.
//!
//! Our own mesh interfaces never count, whichever network they belong to:
//! otherwise a route we install would be found on the next scan, withdrawn as
//! an overlap, and installed again once gone. They are recognised by the
//! record this process keeps of the interfaces it serves
//! ([`claim_own_interface`]), not by their name alone.

use std::collections::HashMap;
#[cfg(not(target_os = "linux"))]
use std::io;
use std::net::IpAddr;
use std::sync::Mutex;

use outbound_mesh::IpNet;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub use linux::{foreign_routes, host_links, host_routes};
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
/// Route selections checked per scan at most.
const MAX_LOOKUPS: usize = 1024;

/// Names of the mesh interfaces this process serves.
static OWN_NAMES: Mutex<Vec<String>> = Mutex::new(Vec::new());

/// Records one of our mesh interfaces for as long as it is held.
#[derive(Debug)]
pub struct OwnInterface(String);

impl Drop for OwnInterface {
    fn drop(&mut self) {
        let mut own = OWN_NAMES.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(at) = own.iter().position(|name| *name == self.0) {
            own.swap_remove(at);
        }
    }
}

/// Records `name` as one of our mesh interfaces until the result is
/// dropped: every network of this process then leaves it out.
pub fn claim_own_interface(name: &str) -> OwnInterface {
    OWN_NAMES
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .push(name.to_owned());
    OwnInterface(name.to_owned())
}

/// Whether `name` is one of our mesh interfaces: recorded by
/// [`claim_own_interface`], or in `extra` (the interface being served).
pub fn is_own_interface(name: &str, extra: &[&str]) -> bool {
    extra.contains(&name)
        || OWN_NAMES
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .any(|own| own == name)
}

/// What a route does with the traffic it matches.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteKind {
    /// Sends it out through its interfaces.
    Unicast,
    /// Drops or refuses it (blackhole, unreachable, prohibit).
    Refusing,
}

/// One route: destination, kind and the interfaces it leaves through.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostRoute {
    pub destination: IpNet,
    pub kind: RouteKind,
    pub interfaces: Vec<u32>,
}

/// One interface: name and whether it is virtual (point-to-point, without
/// a link layer, or a TUN/TAP device).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostLink {
    pub name: String,
    pub is_virtual: bool,
}

/// What the route selection for one address found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Lookup {
    /// A route, with the interfaces it leaves through.
    Route(Vec<u32>),
    /// A refusing route.
    Refused,
    /// No route, or nothing known.
    Unknown,
}

fn wide_enough(net: &IpNet) -> bool {
    let widest = match net.network() {
        IpAddr::V4(_) => WIDEST_V4,
        IpAddr::V6(_) => WIDEST_V6,
    };
    net.prefix() >= widest
}

/// The routes, at least /8 (IPv4) or /7 (IPv6), that another program's
/// virtual interface carries or that refuse traffic, kept only when
/// `lookup` of their destination shows the system selects them. `own` tells
/// our mesh interfaces by index.
pub fn select_foreign(
    routes: &[HostRoute],
    links: &HashMap<u32, HostLink>,
    own: &dyn Fn(u32) -> bool,
    lookup: &mut dyn FnMut(IpAddr) -> Lookup,
) -> Vec<IpNet> {
    let foreign =
        |index: &u32| !own(*index) && links.get(index).is_some_and(|link| link.is_virtual);
    let mut found: Vec<IpNet> = Vec::new();
    let mut lookups = 0;
    for route in routes
        .iter()
        .filter(|route| wide_enough(&route.destination))
    {
        let candidate = match route.kind {
            RouteKind::Unicast => route.interfaces.iter().any(foreign),
            RouteKind::Refusing => true,
        };
        if !candidate || found.contains(&route.destination) {
            continue;
        }
        if lookups == MAX_LOOKUPS {
            break;
        }
        lookups += 1;
        let selected = match (lookup(route.destination.network()), route.kind) {
            (Lookup::Route(interfaces), RouteKind::Unicast) => interfaces.iter().any(foreign),
            (Lookup::Refused, RouteKind::Refusing) => true,
            _ => false,
        };
        if selected {
            found.push(route.destination);
        }
    }
    found.sort_by_key(|net| net.to_string());
    found
}

/// The most specific of `routes` that holds `address`, as a selection:
/// where no lookup through the system is available, the table read stands
/// for it.
pub fn most_specific(routes: &[HostRoute], address: IpAddr) -> Lookup {
    routes
        .iter()
        .filter(|route| route.destination.contains(address))
        .max_by_key(|route| route.destination.prefix())
        .map_or(Lookup::Unknown, |route| match route.kind {
            RouteKind::Unicast => Lookup::Route(route.interfaces.clone()),
            RouteKind::Refusing => Lookup::Refused,
        })
}

/// The routes of other programs' virtual interfaces and the refusing
/// routes that the system selects (see the module documentation). `own`
/// names the interface being served, in addition to those recorded.
#[cfg(not(target_os = "linux"))]
pub fn foreign_routes(own: &str) -> io::Result<Vec<IpNet>> {
    let links = host_links()?;
    let routes = host_routes()?;
    let is_own = |index: u32| {
        links
            .get(&index)
            .is_some_and(|link| is_own_interface(&link.name, &[own]))
    };
    Ok(select_foreign(&routes, &links, &is_own, &mut |address| {
        most_specific(&routes, address)
    }))
}

/// The LAN interfaces that carry each advertised subnet: those with an
/// address network inside it (or equal to it). `interfaces` lists (name,
/// address network) pairs, other programs' virtual interfaces already left
/// out; `own` is the mesh interface. An interface on a wider network that
/// merely overlaps the subnet is not chosen: it may be a VPN covering it.
pub fn lan_interfaces(
    interfaces: &[(String, IpNet)],
    advertised: &[IpNet],
    own: &str,
) -> Vec<(String, IpNet)> {
    let mut found = Vec::new();
    for subnet in advertised {
        for (name, network) in interfaces {
            if name != own && inside(network, subnet) {
                found.push((name.clone(), *subnet));
            }
        }
    }
    found.sort_by_key(|(name, net)| (name.clone(), net.to_string()));
    found.dedup();
    found
}

/// Whether `network` lies inside `subnet`.
fn inside(network: &IpNet, subnet: &IpNet) -> bool {
    network.is_ipv4() == subnet.is_ipv4()
        && network.prefix() >= subnet.prefix()
        && subnet.contains(network.network())
}

/// One warning for each advertised subnet that no interface in `lan` is on.
pub fn missing_interfaces(lan: &[(String, IpNet)], advertised: &[IpNet]) -> Vec<String> {
    advertised
        .iter()
        .filter(|subnet| !lan.iter().any(|(_, net)| net == *subnet))
        .map(|subnet| format!("{subnet}: no interface of this machine is on it"))
        .collect()
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
        // A wider network that only overlaps the subnet (a VPN on 10/8) is
        // not chosen for 10.20.0.0/16.
        let vpn = vec![("utun3".to_string(), net("10.0.0.2/8"))];
        assert!(lan_interfaces(&vpn, &[net("10.20.0.0/16")], "utun4").is_empty());
        assert_eq!(
            missing_interfaces(&found, &[net("192.168.1.0/24"), net("10.30.0.0/16")]),
            vec!["10.30.0.0/16: no interface of this machine is on it".to_string()]
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
            kind: RouteKind::Unicast,
            interfaces: interfaces.to_vec(),
        }
    }

    fn refusing(text: &str) -> HostRoute {
        HostRoute {
            destination: net(text),
            kind: RouteKind::Refusing,
            interfaces: Vec::new(),
        }
    }

    /// Ours: the interfaces at 4 and 5, and `extra`.
    fn ours(extra: &'static [u32]) -> impl Fn(u32) -> bool {
        move |index| index == 4 || index == 5 || extra.contains(&index)
    }

    /// Every selection finds the most specific route of the table.
    fn foreign(routes: &[HostRoute], own: &dyn Fn(u32) -> bool) -> Vec<IpNet> {
        select_foreign(routes, &links(), own, &mut |address| {
            most_specific(routes, address)
        })
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
            foreign(&routes, &ours(&[6])),
            vec![net("100.64.0.0/10"), net("fd7a:115c:a1e0::/48")]
        );
        // Without `custom9` as ours, its route counts.
        assert!(foreign(&routes, &ours(&[])).contains(&net("10.22.0.0/16")));
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
        let found = select_foreign(&routes, &links(), &ours(&[]), &mut |_| {
            Lookup::Route(vec![3])
        });
        assert_eq!(found, vec![net("10.0.0.0/8"), net("fc00::/7")]);
    }

    #[test]
    fn a_multipath_route_counts_when_any_hop_is_foreign() {
        let routes = [
            route("10.30.0.0/16", &[2, 3]),
            route("10.31.0.0/16", &[2, 4]),
        ];
        assert_eq!(foreign(&routes, &ours(&[])), vec![net("10.30.0.0/16")]);
    }

    #[test]
    fn only_routes_the_system_selects_count() {
        let routes = [
            route("100.64.0.0/10", &[3]),
            route("10.40.0.0/16", &[3]),
            refusing("10.50.0.0/16"),
            refusing("10.51.0.0/16"),
            refusing("10.0.0.0/7"),
        ];
        // The policy rules send 10.40.0.0/16 out through eth0 (a table of
        // another program is not consulted), and 10.51.0.0/16 is reached
        // through another, preferred table.
        let found = select_foreign(&routes, &links(), &ours(&[]), &mut |address| match address
            .to_string()
            .as_str()
        {
            "10.40.0.0" | "10.51.0.0" => Lookup::Route(vec![2]),
            "100.64.0.0" => Lookup::Route(vec![3]),
            _ => Lookup::Refused,
        });
        assert_eq!(found, vec![net("10.50.0.0/16"), net("100.64.0.0/10")]);
        // A route that leaves through our own interface in the end is ours.
        let found = select_foreign(&routes[..1], &links(), &ours(&[]), &mut |_| {
            Lookup::Route(vec![4])
        });
        assert!(found.is_empty());
        // Nothing known: nothing counts.
        let found = select_foreign(&routes, &links(), &ours(&[]), &mut |_| Lookup::Unknown);
        assert!(found.is_empty());
    }

    #[test]
    fn the_most_specific_route_stands_for_the_selection() {
        let routes = [
            route("10.0.0.0/8", &[3]),
            route("10.60.0.0/16", &[2]),
            refusing("10.61.0.0/16"),
        ];
        let address = |text: &str| text.parse::<IpAddr>().unwrap();
        assert_eq!(
            most_specific(&routes, address("10.60.1.1")),
            Lookup::Route(vec![2])
        );
        assert_eq!(
            most_specific(&routes, address("10.61.0.0")),
            Lookup::Refused
        );
        assert_eq!(
            most_specific(&routes, address("10.1.0.0")),
            Lookup::Route(vec![3])
        );
        assert_eq!(
            most_specific(&routes, address("192.168.0.1")),
            Lookup::Unknown
        );
    }

    #[test]
    fn own_interfaces_are_the_recorded_ones() {
        assert!(is_own_interface("custom9", &["custom9"]));
        assert!(!is_own_interface("vpn0", &["custom9"]));
        // A name like ours is not enough.
        assert!(!is_own_interface("anixmesh-recorded-test", &[]));
        let claim = claim_own_interface("anixmesh-recorded-test");
        assert!(is_own_interface("anixmesh-recorded-test", &[]));
        drop(claim);
        assert!(!is_own_interface("anixmesh-recorded-test", &[]));
    }
}
