//! The nftables rules of one bridge (spec §15.12 items 2–4).
//!
//! Each mesh interface with a bridge gets its own `inet` table, replaced as
//! a whole in one `nft -f` transaction, so a new allow list takes effect
//! all at once or not at all, and the old rules stay when loading fails:
//!
//! - `forward`: from the mesh interface to the external interface only
//!   sources in `allow` towards addresses in `routes` pass; everything else
//!   from the mesh to the external interface is dropped and counted
//!   (`source_denied`). This check runs before the source is rewritten.
//!   From the external interface to the mesh only replies of connections our
//!   side opened pass; new connections are dropped and counted
//!   (`inbound_denied`).
//! - `input`: new connections arriving on the external interface for this
//!   node's own mesh addresses are dropped and counted (`inbound_denied`),
//!   so the external network cannot reach into the mesh through the node
//!   itself either.
//! - `postrouting`: the allowed traffic leaves the external interface with
//!   the node's external address (masquerade); connection tracking restores
//!   the replies.
//!
//! The tables never touch other tables or chains. An accept here does not
//! override a drop in another program's table; see
//! `docs/architecture/mesh-bridge.md` for hosts with their own forward
//! policy.

use std::fmt::Write as _;
use std::net::IpAddr;

use outbound_mesh::IpNet;

use crate::config::ExternalBridge;

/// Counter of packets from the mesh refused by source or destination.
pub const COUNTER_SOURCE_DENIED: &str = "source_denied";
/// Counter of new connections from the external network refused.
pub const COUNTER_INBOUND_DENIED: &str = "inbound_denied";

/// Prefix of every table this crate creates.
pub const TABLE_PREFIX: &str = "anixops_bridge_";

/// The table of one mesh interface: the prefix and the name's bytes in hex,
/// so distinct interface names never share a table.
pub fn table_name(mesh_interface: &str) -> String {
    let mut name = String::from(TABLE_PREFIX);
    for byte in mesh_interface.bytes() {
        let _ = write!(name, "{byte:02x}");
    }
    name
}

/// Removes entries covered by another entry: an nftables interval set
/// refuses overlapping elements, and a covered entry adds nothing.
fn without_covered(nets: &[IpNet]) -> Vec<IpNet> {
    let mut kept: Vec<IpNet> = Vec::with_capacity(nets.len());
    for (index, net) in nets.iter().enumerate() {
        let covered = nets.iter().enumerate().any(|(other_index, other)| {
            other_index != index
                && other.covers(net)
                && (other.prefix() < net.prefix() || other_index < index)
        });
        if !covered {
            kept.push(*net);
        }
    }
    kept
}

fn set(out: &mut String, name: &str, v4: bool, interval: bool, elements: &[String]) {
    let kind = if v4 { "ipv4_addr" } else { "ipv6_addr" };
    let _ = write!(out, "\tset {name} {{\n\t\ttype {kind}\n");
    if interval {
        out.push_str("\t\tflags interval\n");
    }
    if !elements.is_empty() {
        let _ = writeln!(out, "\t\telements = {{ {} }}", elements.join(", "));
    }
    out.push_str("\t}\n");
}

fn split(nets: &[IpNet]) -> (Vec<String>, Vec<String>) {
    let nets = without_covered(nets);
    let v4 = nets
        .iter()
        .filter(|net| net.is_ipv4())
        .map(|net| net.trunc().to_string())
        .collect();
    let v6 = nets
        .iter()
        .filter(|net| !net.is_ipv4())
        .map(|net| net.trunc().to_string())
        .collect();
    (v4, v6)
}

/// The script that installs or replaces the table of `mesh_interface`.
/// Both interface names must have passed
/// [`crate::config::valid_interface`]; `local_addresses` are the node's own
/// addresses in this network.
pub fn render(bridge: &ExternalBridge, mesh_interface: &str, local_addresses: &[IpAddr]) -> String {
    let table = table_name(mesh_interface);
    let mesh = mesh_interface;
    let ext = bridge.interface();
    let (allow_v4, allow_v6) = split(bridge.allow());
    let (routes_v4, routes_v6) = split(bridge.routes());
    let mut local_v4: Vec<String> = Vec::new();
    let mut local_v6: Vec<String> = Vec::new();
    for address in local_addresses {
        match address {
            IpAddr::V4(v4) => local_v4.push(v4.to_string()),
            IpAddr::V6(v6) => local_v6.push(v6.to_string()),
        }
    }
    local_v4.sort();
    local_v4.dedup();
    local_v6.sort();
    local_v6.dedup();

    // Creating the table first makes the delete succeed when it does not
    // exist yet; all three statements are one transaction.
    let mut out = format!("table inet {table}\ndelete table inet {table}\ntable inet {table} {{\n");
    set(&mut out, "allow_v4", true, true, &allow_v4);
    set(&mut out, "allow_v6", false, true, &allow_v6);
    set(&mut out, "routes_v4", true, true, &routes_v4);
    set(&mut out, "routes_v6", false, true, &routes_v6);
    set(&mut out, "local_v4", true, false, &local_v4);
    set(&mut out, "local_v6", false, false, &local_v6);
    let _ = writeln!(out, "\tcounter {COUNTER_SOURCE_DENIED} {{\n\t}}");
    let _ = writeln!(out, "\tcounter {COUNTER_INBOUND_DENIED} {{\n\t}}");

    let out_dir = format!("iifname \"{mesh}\" oifname \"{ext}\"");
    let in_dir = format!("iifname \"{ext}\" oifname \"{mesh}\"");
    let _ = write!(
        out,
        "\tchain forward {{\n\
         \t\ttype filter hook forward priority filter; policy accept;\n\
         \t\t{out_dir} ip saddr @allow_v4 ip daddr @routes_v4 accept\n\
         \t\t{out_dir} ip6 saddr @allow_v6 ip6 daddr @routes_v6 accept\n\
         \t\t{out_dir} counter name \"{COUNTER_SOURCE_DENIED}\" drop\n\
         \t\t{in_dir} ct state established,related accept\n\
         \t\t{in_dir} counter name \"{COUNTER_INBOUND_DENIED}\" drop\n\
         \t}}\n"
    );
    let _ = write!(
        out,
        "\tchain input {{\n\
         \t\ttype filter hook input priority filter; policy accept;\n\
         \t\tiifname \"{ext}\" ip daddr @local_v4 ct state established,related accept\n\
         \t\tiifname \"{ext}\" ip daddr @local_v4 counter name \"{COUNTER_INBOUND_DENIED}\" drop\n\
         \t\tiifname \"{ext}\" ip6 daddr @local_v6 ct state established,related accept\n\
         \t\tiifname \"{ext}\" ip6 daddr @local_v6 counter name \"{COUNTER_INBOUND_DENIED}\" drop\n\
         \t}}\n"
    );
    let _ = write!(
        out,
        "\tchain postrouting {{\n\
         \t\ttype nat hook postrouting priority srcnat; policy accept;\n\
         \t\t{out_dir} ip saddr @allow_v4 ip daddr @routes_v4 masquerade\n\
         \t\t{out_dir} ip6 saddr @allow_v6 ip6 daddr @routes_v6 masquerade\n\
         \t}}\n"
    );
    out.push_str("}\n");
    out
}

/// The script that removes the table of `mesh_interface`; succeeds when
/// it does not exist.
pub fn render_removal(mesh_interface: &str) -> String {
    let table = table_name(mesh_interface);
    format!("table inet {table}\ndelete table inet {table}\n")
}

/// The table the capability probe uses. It is not a bridge table
/// ([`is_own_table`] is false): the probe creates and deletes it in one
/// transaction, so it is never left behind.
pub const PROBE_TABLE: &str = "anixops_bridge_probe";

/// One transaction that sets up what a bridge needs (an `inet` table, a
/// filter chain with `ct state`, a NAT chain with `masquerade`, an interval
/// set) and deletes it again. It loads only where the kernel supports all
/// of it; older kernels (e.g. before 5.2, no `inet` NAT) refuse it.
pub fn render_probe() -> String {
    format!(
        "table inet {PROBE_TABLE}\n\
         delete table inet {PROBE_TABLE}\n\
         table inet {PROBE_TABLE} {{\n\
         \tset probe_v4 {{\n\t\ttype ipv4_addr\n\t\tflags interval\n\t\telements = {{ 10.0.0.0/8 }}\n\t}}\n\
         \tchain forward {{\n\
         \t\ttype filter hook forward priority filter; policy accept;\n\
         \t\tiifname \"lo\" ip saddr @probe_v4 ct state established,related accept\n\
         \t}}\n\
         \tchain postrouting {{\n\
         \t\ttype nat hook postrouting priority srcnat; policy accept;\n\
         \t\toifname \"lo\" ip saddr @probe_v4 masquerade\n\
         \t}}\n\
         }}\n\
         delete table inet {PROBE_TABLE}\n"
    )
}

/// Whether `name` is one of our tables: the prefix, then the hex of a
/// non-empty interface name as [`table_name`] writes it. This prefix is the
/// mark spec §15.12 item 9 cleans up by; nothing else is touched.
pub fn is_own_table(name: &str) -> bool {
    let Some(hex) = name.strip_prefix(TABLE_PREFIX) else {
        return false;
    };
    !hex.is_empty()
        && hex.len().is_multiple_of(2)
        && hex.len() <= 2 * crate::config::MAX_INTERFACE_BYTES
        && hex
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// The script that removes every table in `tables` (family, name) that is
/// ours, in one transaction; `None` when none is.
pub fn render_cleanup<'a>(tables: impl IntoIterator<Item = (&'a str, &'a str)>) -> Option<String> {
    let mut out = String::new();
    for (family, name) in tables {
        if family == "inet" && is_own_table(name) {
            let _ = writeln!(out, "delete table inet {name}");
        }
    }
    (!out.is_empty()).then_some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ExternalBridgeConfig;

    #[test]
    fn the_probe_leaves_nothing_and_is_not_a_bridge_table() {
        let script = render_probe();
        assert!(!is_own_table(PROBE_TABLE));
        assert!(script.contains("masquerade"));
        assert!(script.contains("ct state established,related"));
        assert!(script.ends_with(&format!("delete table inet {PROBE_TABLE}\n")));
        let creates = script
            .matches(&format!("table inet {PROBE_TABLE} {{"))
            .count();
        assert_eq!(creates, 1);
    }

    fn bridge(routes: &[&str], allow: &[&str]) -> ExternalBridge {
        ExternalBridgeConfig {
            interface: "ext0".into(),
            routes: routes.iter().map(|s| s.to_string()).collect(),
            allow: allow.iter().map(|s| s.to_string()).collect(),
        }
        .validate()
        .unwrap()
    }

    #[test]
    fn table_names_are_unique_per_interface() {
        assert_eq!(
            table_name("anixmesh-0"),
            "anixops_bridge_616e69786d6573682d30"
        );
        assert_ne!(table_name("a-b"), table_name("a_b"));
        // nftables names may be 255 bytes; 15 interface bytes give 45.
        assert!(table_name("a23456789012345").len() < 64);
    }

    #[test]
    fn covered_entries_are_left_out_of_sets() {
        let nets: Vec<IpNet> = [
            "10.127.0.0/24",
            "10.127.0.9/32",
            "10.127.0.0/24",
            "10.150.0.2/32",
        ]
        .iter()
        .map(|s| IpNet::parse(s).unwrap())
        .collect();
        let kept: Vec<String> = without_covered(&nets)
            .iter()
            .map(|n| n.to_string())
            .collect();
        assert_eq!(kept, ["10.127.0.0/24", "10.150.0.2/32"]);
    }

    #[test]
    fn the_script_replaces_one_table_atomically() {
        let script = render(
            &bridge(
                &["100.100.1.2", "192.168.50.0/24", "fd7a:115c:a1e0::9"],
                &["10.127.0.0/24", "10.127.0.4/32", "10.150.128.7/32"],
            ),
            "anixmesh-0",
            &[
                "10.150.0.1".parse().unwrap(),
                "fd00:150::1".parse().unwrap(),
            ],
        );
        let table = table_name("anixmesh-0");
        assert!(script.starts_with(&format!(
            "table inet {table}\ndelete table inet {table}\ntable inet {table} {{\n"
        )));
        assert_eq!(script.matches("table inet").count(), 3, "{script}");
        assert!(
            script.contains("elements = { 10.127.0.0/24, 10.150.128.7/32 }"),
            "{script}"
        );
        assert!(
            script.contains("elements = { 100.100.1.2/32, 192.168.50.0/24 }"),
            "{script}"
        );
        assert!(
            script.contains("elements = { fd7a:115c:a1e0::9/128 }"),
            "{script}"
        );
        assert!(script.contains("elements = { 10.150.0.1 }"), "{script}");
        assert!(script.contains("elements = { fd00:150::1 }"), "{script}");
        // allow_v6 is empty: declared without elements.
        assert!(script.contains("\tset allow_v6 {\n\t\ttype ipv6_addr\n\t\tflags interval\n\t}\n"));
    }

    #[test]
    fn only_allowed_sources_to_routes_pass_and_are_translated() {
        let script = render(
            &bridge(&["100.64.0.1"], &["10.150.0.2/32"]),
            "anixmesh-0",
            &[],
        );
        let forward = script.split("chain forward").nth(1).unwrap();
        let forward = forward.split("chain input").next().unwrap();
        let lines: Vec<&str> = forward
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty())
            .collect();
        assert_eq!(
            lines,
            [
                "{",
                "type filter hook forward priority filter; policy accept;",
                "iifname \"anixmesh-0\" oifname \"ext0\" ip saddr @allow_v4 ip daddr @routes_v4 accept",
                "iifname \"anixmesh-0\" oifname \"ext0\" ip6 saddr @allow_v6 ip6 daddr @routes_v6 accept",
                "iifname \"anixmesh-0\" oifname \"ext0\" counter name \"source_denied\" drop",
                "iifname \"ext0\" oifname \"anixmesh-0\" ct state established,related accept",
                "iifname \"ext0\" oifname \"anixmesh-0\" counter name \"inbound_denied\" drop",
                "}",
            ]
        );
        let nat = script.split("chain postrouting").nth(1).unwrap();
        assert!(nat.contains("type nat hook postrouting priority srcnat; policy accept;"));
        assert!(nat.contains(
            "iifname \"anixmesh-0\" oifname \"ext0\" ip saddr @allow_v4 ip daddr @routes_v4 masquerade"
        ));
        assert!(!script.contains("0.0.0.0/0"));
        assert!(!script.contains("::/0"));
    }

    #[test]
    fn only_our_tables_are_cleaned_up() {
        let own = table_name("anixmesh-0");
        let other = table_name("anixmesh-1");
        assert!(is_own_table(&own));
        for foreign in [
            "anixops_bridge_",
            "anixops_bridge_6",
            "anixops_bridge_ZZ",
            "anixops_bridge_616E",
            "anixops_bridge_616e_x",
            "filter",
            "nat",
            "anixops_other",
        ] {
            assert!(!is_own_table(foreign), "{foreign}");
        }
        let script = render_cleanup([
            ("inet", own.as_str()),
            ("ip", own.as_str()),
            ("inet", "filter"),
            ("inet", other.as_str()),
            ("ip", "nat"),
        ])
        .unwrap();
        assert_eq!(
            script,
            format!("delete table inet {own}\ndelete table inet {other}\n")
        );
        assert!(render_cleanup([("inet", "filter"), ("ip", "nat")]).is_none());
    }

    #[test]
    fn removal_is_idempotent() {
        let table = table_name("anixmesh-0");
        assert_eq!(
            render_removal("anixmesh-0"),
            format!("table inet {table}\ndelete table inet {table}\n")
        );
    }
}
