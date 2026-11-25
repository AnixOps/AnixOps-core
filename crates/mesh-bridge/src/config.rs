//! The `external_bridge` section of one network's mesh config and its checks
//! (spec §15.12 items 1, 2, 4 and 8; `docs/architecture/mesh-module.md`).
//!
//! Anything the checks refuse refuses the whole network config with
//! `invalid_argument`; the [`BridgeError::reason`] says why.

use std::fmt;
use std::net::IpAddr;

use outbound_mesh::scope::is_intranet_network;
use outbound_mesh::IpNet;
use serde::Deserialize;

/// Most `routes` entries. The panel allows 64; the kernel keeps the same
/// limit so a bridge never advertises more than the panel can show.
pub const MAX_ROUTES: usize = 64;

/// Most `allow` entries. The panel allows 256 sources and expands each to
/// one prefix; the kernel keeps headroom.
pub const MAX_ALLOW: usize = 1024;

/// Longest Linux interface name (`IFNAMSIZ` - 1).
pub const MAX_INTERFACE_BYTES: usize = 15;

/// The ranges other overlay programs commonly take whole (spec §15.4,
/// §15.12 item 1). Inside them only single addresses may be advertised.
pub const OVERLAY_RANGES: [&str; 2] = ["100.64.0.0/10", "fd7a:115c:a1e0::/48"];

/// The section as the panel sends it. It sits next to `subnets` and
/// `routing` at the top level of each network's config (spec #332 V4).
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ExternalBridgeConfig {
    /// The node's interface in the external network.
    pub interface: String,
    /// External addresses to advertise: single addresses (`/32`, `/128`,
    /// or no prefix) and whitelisted subnets.
    pub routes: Vec<String>,
    /// Sources allowed through the bridge: members' virtual addresses and
    /// host group segments, already expanded by the panel.
    #[serde(default)]
    pub allow: Vec<String>,
}

/// A checked bridge. `routes` and `allow` are normalised (host bits zero,
/// single addresses with their prefix), without duplicates and sorted by
/// their CIDR text, the order the digests use.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExternalBridge {
    interface: String,
    routes: Vec<IpNet>,
    allow: Vec<IpNet>,
}

/// Why a section is refused. All map to `invalid_argument`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BridgeError {
    /// Empty, longer than 15 bytes, `.`/`..`, or a byte other than ASCII
    /// letters, digits, `-`, `_` and `.`.
    Interface,
    /// No routes: a bridge that advertises nothing is a mistake.
    NoRoutes,
    TooManyRoutes,
    TooManyAllow,
    /// Not an address or `address/prefix`, or an IPv4-mapped IPv6 address.
    Syntax(String),
    /// Host bits set below the prefix, such as `192.168.1.5/24`.
    HostBits(String),
    /// A default route (`/0`).
    Default(String),
    /// Outside the intranet whitelist (spec §15.4).
    NotIntranet(String),
    /// A subnet that overlaps 100.64.0.0/10 or fd7a:115c:a1e0::/48, or
    /// covers one of them; only single addresses may lie there.
    OverlayRange(String),
    /// An `allow` entry that overlaps a route: a source cannot also be an
    /// external destination.
    AllowOverlapsRoute(String),
    /// The external interface is the mesh's own interface.
    SameInterface,
    /// A route overlaps the network's own virtual subnet or address.
    RouteOverlapsMesh(String),
}

impl BridgeError {
    /// A stable reason code, shown after `invalid_argument`.
    pub fn reason(&self) -> &'static str {
        match self {
            Self::Interface => "external_bridge_interface",
            Self::NoRoutes => "external_bridge_no_routes",
            Self::TooManyRoutes => "external_bridge_too_many_routes",
            Self::TooManyAllow => "external_bridge_too_many_allow",
            Self::Syntax(_) => "external_bridge_syntax",
            Self::HostBits(_) => "external_bridge_host_bits",
            Self::Default(_) => "external_bridge_default_route",
            Self::NotIntranet(_) => "external_bridge_not_intranet",
            Self::OverlayRange(_) => "external_bridge_overlay_range",
            Self::AllowOverlapsRoute(_) => "external_bridge_allow_overlaps_route",
            Self::SameInterface => "external_bridge_same_interface",
            Self::RouteOverlapsMesh(_) => "external_bridge_route_overlaps_mesh",
        }
    }
}

impl fmt::Display for BridgeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Interface => write!(f, "external_bridge.interface is not a valid interface name"),
            Self::NoRoutes => write!(f, "external_bridge.routes is empty"),
            Self::TooManyRoutes => {
                write!(f, "external_bridge.routes has more than {MAX_ROUTES} entries")
            }
            Self::TooManyAllow => {
                write!(f, "external_bridge.allow has more than {MAX_ALLOW} entries")
            }
            Self::Syntax(entry) => write!(f, "external_bridge: {entry:?} is not a network"),
            Self::HostBits(entry) => {
                write!(f, "external_bridge: {entry:?} has host bits set")
            }
            Self::Default(entry) => {
                write!(f, "external_bridge: {entry:?} is a default route")
            }
            Self::NotIntranet(entry) => write!(
                f,
                "external_bridge: {entry:?} is outside the intranet ranges"
            ),
            Self::OverlayRange(entry) => write!(
                f,
                "external_bridge.routes: {entry:?} is a subnet overlapping 100.64.0.0/10 or fd7a:115c:a1e0::/48; only single addresses may lie there"
            ),
            Self::AllowOverlapsRoute(entry) => write!(
                f,
                "external_bridge.allow: {entry:?} overlaps a route"
            ),
            Self::SameInterface => write!(
                f,
                "external_bridge.interface is the mesh's own interface"
            ),
            Self::RouteOverlapsMesh(entry) => write!(
                f,
                "external_bridge.routes: {entry:?} overlaps the network's virtual subnet"
            ),
        }
    }
}

impl std::error::Error for BridgeError {}

/// Whether `name` can be a Linux interface name and is safe to place in an
/// nftables string.
pub fn valid_interface(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_INTERFACE_BYTES
        && name != "."
        && name != ".."
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
}

fn overlay_ranges() -> impl Iterator<Item = IpNet> {
    OVERLAY_RANGES
        .iter()
        .map(|range| IpNet::parse(range).expect("overlay range table is valid"))
}

fn max_prefix(net: &IpNet) -> u8 {
    if net.is_ipv4() {
        32
    } else {
        128
    }
}

/// Parses one entry: `address` or `address/prefix`, host bits zero, not a
/// default route, inside the intranet whitelist.
fn parse_entry(text: &str) -> Result<IpNet, BridgeError> {
    let net = IpNet::parse(text).ok_or_else(|| BridgeError::Syntax(text.to_owned()))?;
    if net.address() != net.network() {
        return Err(BridgeError::HostBits(text.to_owned()));
    }
    if net.prefix() == 0 {
        return Err(BridgeError::Default(text.to_owned()));
    }
    if !is_intranet_network(&net) {
        return Err(BridgeError::NotIntranet(text.to_owned()));
    }
    Ok(net.trunc())
}

/// Sorted by CIDR text and without duplicates.
fn canonical(mut nets: Vec<IpNet>) -> Vec<IpNet> {
    nets.sort_by_key(|net| net.to_string());
    nets.dedup();
    nets
}

impl ExternalBridgeConfig {
    /// Checks the section on its own. [`ExternalBridge::check_mesh`] adds
    /// the checks that need the network's own interface and subnets.
    pub fn validate(&self) -> Result<ExternalBridge, BridgeError> {
        if !valid_interface(&self.interface) {
            return Err(BridgeError::Interface);
        }
        if self.routes.is_empty() {
            return Err(BridgeError::NoRoutes);
        }
        if self.routes.len() > MAX_ROUTES {
            return Err(BridgeError::TooManyRoutes);
        }
        if self.allow.len() > MAX_ALLOW {
            return Err(BridgeError::TooManyAllow);
        }
        let mut routes = Vec::with_capacity(self.routes.len());
        for text in &self.routes {
            let net = parse_entry(text)?;
            // Spec §15.12 item 1: inside the overlay ranges only single
            // addresses; a subnet that overlaps them, or covers them, is
            // refused.
            let single = net.prefix() == max_prefix(&net);
            if !single && overlay_ranges().any(|range| range.overlaps(&net)) {
                return Err(BridgeError::OverlayRange(text.clone()));
            }
            routes.push(net);
        }
        let mut allow = Vec::with_capacity(self.allow.len());
        for text in &self.allow {
            let net = parse_entry(text)?;
            if routes.iter().any(|route| route.overlaps(&net)) {
                return Err(BridgeError::AllowOverlapsRoute(text.clone()));
            }
            allow.push(net);
        }
        Ok(ExternalBridge {
            interface: self.interface.clone(),
            routes: canonical(routes),
            allow: canonical(allow),
        })
    }
}

impl ExternalBridge {
    pub fn interface(&self) -> &str {
        &self.interface
    }

    /// The external addresses, in digest order.
    pub fn routes(&self) -> &[IpNet] {
        &self.routes
    }

    /// The allowed sources, in digest order.
    pub fn allow(&self) -> &[IpNet] {
        &self.allow
    }

    /// Checks against the network the section belongs to: the external
    /// interface is not the mesh interface, and no route overlaps the
    /// network's virtual subnets or its own addresses (the advertisement
    /// would otherwise compete with the members themselves).
    pub fn check_mesh(
        &self,
        mesh_interface: &str,
        virtual_subnets: &[IpNet],
        local_addresses: &[IpAddr],
    ) -> Result<(), BridgeError> {
        if self.interface == mesh_interface {
            return Err(BridgeError::SameInterface);
        }
        for route in &self.routes {
            let overlaps = virtual_subnets.iter().any(|subnet| subnet.overlaps(route))
                || local_addresses
                    .iter()
                    .any(|address| route.contains(*address));
            if overlaps {
                return Err(BridgeError::RouteOverlapsMesh(route.to_string()));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(interface: &str, routes: &[&str], allow: &[&str]) -> ExternalBridgeConfig {
        ExternalBridgeConfig {
            interface: interface.into(),
            routes: routes.iter().map(|s| s.to_string()).collect(),
            allow: allow.iter().map(|s| s.to_string()).collect(),
        }
    }

    fn reason(routes: &[&str], allow: &[&str]) -> &'static str {
        config("ext0", routes, allow)
            .validate()
            .unwrap_err()
            .reason()
    }

    #[test]
    fn the_panel_example_is_accepted_and_normalised() {
        let bridge = config(
            "ext0",
            &[
                "192.168.50.0/24",
                "100.100.1.2",
                "FD7A:115C:A1E0::9",
                "100.100.1.2/32",
            ],
            &["10.150.128.7/32", "10.127.0.0/24"],
        )
        .validate()
        .unwrap();
        let routes: Vec<String> = bridge.routes().iter().map(|n| n.to_string()).collect();
        assert_eq!(
            routes,
            ["100.100.1.2/32", "192.168.50.0/24", "fd7a:115c:a1e0::9/128"]
        );
        let allow: Vec<String> = bridge.allow().iter().map(|n| n.to_string()).collect();
        assert_eq!(allow, ["10.127.0.0/24", "10.150.128.7/32"]);
    }

    #[test]
    fn the_section_refuses_unknown_fields() {
        let error = serde_json::from_str::<ExternalBridgeConfig>(
            r#"{"interface":"ext0","routes":["100.64.0.1"],"allow":[],"exit":true}"#,
        )
        .unwrap_err();
        assert!(error.to_string().contains("unknown field"), "{error}");
        let parsed: ExternalBridgeConfig =
            serde_json::from_str(r#"{"interface":"ext0","routes":["100.64.0.1"]}"#).unwrap();
        assert!(parsed.allow.is_empty());
    }

    #[test]
    fn single_addresses_may_lie_in_the_overlay_ranges() {
        for route in ["100.64.0.1", "100.127.255.254/32", "fd7a:115c:a1e0::1/128"] {
            config("ext0", &[route], &[]).validate().unwrap();
        }
    }

    #[test]
    fn subnets_may_not_touch_the_overlay_ranges() {
        for route in [
            "100.64.0.0/10",
            "100.64.0.0/31",
            "100.100.0.0/16",
            "fd7a:115c:a1e0::/48",
            "fd7a:115c:a1e0:1::/64",
            "fd7a:115c:a1e0::/127",
            "fd7a::/16",
            "fc00::/7",
        ] {
            assert_eq!(
                reason(&[route], &[]),
                "external_bridge_overlay_range",
                "{route}"
            );
        }
    }

    #[test]
    fn subnets_must_be_whitelisted() {
        assert_eq!(reason(&["8.8.8.0/24"], &[]), "external_bridge_not_intranet");
        assert_eq!(reason(&["8.8.8.8"], &[]), "external_bridge_not_intranet");
        assert_eq!(reason(&["10.0.0.0/7"], &[]), "external_bridge_not_intranet");
        assert_eq!(
            reason(&["2001:db8::/32"], &[]),
            "external_bridge_not_intranet"
        );
        assert_eq!(reason(&["127.0.0.1"], &[]), "external_bridge_not_intranet");
        config("ext0", &["172.16.0.0/12", "fd00:aa::/64"], &[])
            .validate()
            .unwrap();
    }

    #[test]
    fn default_routes_are_refused() {
        assert_eq!(reason(&["0.0.0.0/0"], &[]), "external_bridge_default_route");
        assert_eq!(reason(&["::/0"], &[]), "external_bridge_default_route");
        assert_eq!(
            reason(&["100.64.0.1"], &["0.0.0.0/0"]),
            "external_bridge_default_route"
        );
    }

    #[test]
    fn host_bits_and_bad_syntax_are_refused() {
        assert_eq!(
            reason(&["192.168.1.5/24"], &[]),
            "external_bridge_host_bits"
        );
        assert_eq!(
            reason(&["100.64.0.1"], &["10.127.0.1/24"]),
            "external_bridge_host_bits"
        );
        for bad in [
            "",
            "ext",
            "10.0.0.1/33",
            "10.0.0.1/",
            "::ffff:10.0.0.1",
            "10.0.0.1/+8",
        ] {
            assert_eq!(reason(&[bad], &[]), "external_bridge_syntax", "{bad:?}");
        }
    }

    #[test]
    fn allow_may_not_overlap_routes() {
        assert_eq!(
            reason(&["192.168.50.0/24"], &["192.168.50.7/32"]),
            "external_bridge_allow_overlaps_route"
        );
        assert_eq!(
            reason(&["100.64.0.9"], &["100.64.0.0/24"]),
            "external_bridge_allow_overlaps_route"
        );
    }

    #[test]
    fn interface_names_are_checked() {
        for bad in [
            "",
            ".",
            "..",
            "a b",
            "ext0;",
            "eth0\"",
            "a23456789012345x",
            "é",
        ] {
            assert_eq!(
                config(bad, &["100.64.0.1"], &[]).validate().unwrap_err(),
                BridgeError::Interface,
                "{bad:?}"
            );
        }
        for good in ["ext0", "overlay0", "wg-ext.1", "a23456789012345"] {
            config(good, &["100.64.0.1"], &[]).validate().unwrap();
        }
    }

    #[test]
    fn limits_hold() {
        assert_eq!(reason(&[], &[]), "external_bridge_no_routes");
        let many: Vec<String> = (1..=MAX_ROUTES + 1)
            .map(|i| format!("100.64.1.{i}"))
            .collect();
        let many: Vec<&str> = many.iter().map(String::as_str).collect();
        assert_eq!(reason(&many, &[]), "external_bridge_too_many_routes");
        let allow: Vec<String> = (0..=MAX_ALLOW)
            .map(|i| format!("10.150.{}.{}/32", i / 256, i % 256))
            .collect();
        let allow: Vec<&str> = allow.iter().map(String::as_str).collect();
        assert_eq!(
            reason(&["100.64.0.1"], &allow),
            "external_bridge_too_many_allow"
        );
    }

    #[test]
    fn the_mesh_checks_see_the_network() {
        let bridge = config(
            "ext0",
            &["192.168.50.0/24", "100.64.0.1"],
            &["10.150.0.2/32"],
        )
        .validate()
        .unwrap();
        let subnet = [IpNet::parse("10.150.0.0/16").unwrap()];
        let local = ["10.150.0.1".parse().unwrap()];
        bridge.check_mesh("anixmesh-0", &subnet, &local).unwrap();
        assert_eq!(
            bridge.check_mesh("ext0", &subnet, &local).unwrap_err(),
            BridgeError::SameInterface
        );
        let wide = [IpNet::parse("192.168.0.0/16").unwrap()];
        assert_eq!(
            bridge
                .check_mesh("anixmesh-0", &wide, &local)
                .unwrap_err()
                .reason(),
            "external_bridge_route_overlaps_mesh"
        );
        let own = ["100.64.0.1".parse().unwrap()];
        assert_eq!(
            bridge
                .check_mesh("anixmesh-0", &subnet, &own)
                .unwrap_err()
                .reason(),
            "external_bridge_route_overlaps_mesh"
        );
    }
}
