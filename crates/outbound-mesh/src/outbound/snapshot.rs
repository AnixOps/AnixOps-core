//! The `mesh_status` snapshot (`docs/architecture/mesh-status.md`
//! «快照»): one network's view for the clients of the embedded engine,
//! built from the network's settings and its driver's [`Snapshot`].
//!
//! Only kernel 0.3 fields are given. A field this kernel cannot fill yet is
//! left out rather than guessed, as the snapshot contract allows.

use std::collections::BTreeSet;
use std::net::IpAddr;

use serde_json::{json, Map, Value};

use crate::config::{encode_key, Cipher, MeshSettings, NetworkKind, Role, SecurityMode};
use crate::dns::Names;
use crate::driver::{Member, Snapshot};
use crate::net::IpNet;

use super::Failure;

/// The snapshot format this module writes (`statusVersion`).
pub const STATUS_VERSION: u32 = 1;

/// Where a saved network stands, as the engine sees it.
pub struct NetworkView<'a> {
    pub settings: &'a MeshSettings,
    /// `None` when the network is not joined.
    pub joined: Option<Joined<'a>>,
    /// The node's static public key in the network; `None` in the default
    /// mode.
    pub static_key: Option<[u8; 32]>,
}

/// A joined network: whether its driver runs, why it stopped, and its
/// latest snapshot.
pub struct Joined<'a> {
    pub running: bool,
    pub failure: Option<Failure>,
    pub snapshot: &'a Snapshot,
}

/// The engine-wide `tunnel` object: shared by every network's snapshot.
pub struct Tunnel<'a> {
    pub routes: &'a [IpNet],
    pub routes_version: u64,
    /// `tunnel.dns.matchDomains`; `tunnel.dns` is `null` when empty.
    pub dns_domains: &'a [String],
}

/// `tunnel.dns.servers`: the DNS addresses inside the tunnel that the
/// embedded engine answers itself (the client's tunnel DNS, IPv4 first):
/// never a member's address or a public resolver, so that a query for an
/// intranet name never leaves the tunnel.
pub const TUNNEL_DNS_SERVERS: [&str; 2] = ["198.18.0.2", "fd00::53"];

/// `tunnel.dns`: `null` while no network answers names.
fn tunnel_dns(domains: &[String]) -> Value {
    if domains.is_empty() {
        return Value::Null;
    }
    json!({"servers": TUNNEL_DNS_SERVERS, "matchDomains": domains})
}

/// The name list `view` answers from: its driver runs and its names are
/// on.
fn running_names<'a>(view: &NetworkView<'a>) -> Option<&'a Names> {
    let joined = view.joined.as_ref().filter(|joined| joined.running)?;
    let snapshot: &'a Snapshot = joined.snapshot;
    snapshot.names.as_deref().filter(|names| names.enabled())
}

/// `names[]` and `refusedNames[]` of `view` (requirement R28): empty while
/// its names are off. A network that does not run lists only the entries
/// its config skipped. A name is a duplicate too when a query that reaches
/// it is also answered with addresses by another running network whose
/// names are on, whatever its suffix: the tunnel merges the addresses of
/// all of them (`mesh-status.md`). `duplicateNetworks` lists those
/// networks, sorted by id.
fn names(view: &NetworkView<'_>, networks: &[NetworkView<'_>]) -> (Value, Value) {
    if !view.settings.dns.enabled {
        return (json!([]), json!([]));
    }
    let Some(own) = running_names(view) else {
        return (json!([]), json!(view.settings.dns.refused));
    };
    // Each other network's query names, once per snapshot.
    let mut others: Vec<(&str, BTreeSet<String>)> = networks
        .iter()
        .filter(|other| other.settings.network_name != view.settings.network_name)
        .filter_map(|other| {
            running_names(other)
                .map(|names| (other.settings.network_name.as_str(), names.queries()))
        })
        .collect();
    others.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));
    let entries = own
        .entries()
        .iter()
        .enumerate()
        .map(|(index, entry)| {
            let queries = own.queries_of(index);
            let elsewhere: Vec<&str> = others
                .iter()
                .filter(|(_, answered)| queries.iter().any(|query| answered.contains(query)))
                .map(|(network, _)| *network)
                .collect();
            let mut value = json!(entry);
            if !elsewhere.is_empty() {
                value["duplicate"] = Value::Bool(true);
                value["duplicateNetworks"] = json!(elsewhere);
            }
            value
        })
        .collect();
    (Value::Array(entries), json!(own.refused()))
}

/// `network.state` (snapshot «取值»).
pub fn state(view: &NetworkView<'_>) -> &'static str {
    let Some(joined) = &view.joined else {
        return "not_joined";
    };
    match joined.failure {
        // A managed network waiting for its key list is not joined yet;
        // nor is a saved network of another device ID than the profile's.
        Some(Failure::NativeKeysPending | Failure::InstanceIdChanged) => "not_joined",
        Some(_) => "failed",
        None if !joined.running => "joining",
        None if joined.snapshot.neighbours.is_empty() => "joining",
        None => "joined",
    }
}

/// The whole snapshot for `view`, listing every saved network in
/// `networks`.
pub fn snapshot(
    view: &NetworkView<'_>,
    networks: &[NetworkView<'_>],
    tunnel: &Tunnel<'_>,
) -> Value {
    let empty = Snapshot::default();
    let current = view
        .joined
        .as_ref()
        .map_or(&empty, |joined| joined.snapshot);
    let (names, refused_names) = names(view, networks);
    json!({
        "statusVersion": STATUS_VERSION,
        "networks": networks
            .iter()
            .map(|other| json!({
                "id": other.settings.network_name,
                "name": other.settings.network_name,
                "state": state(other),
            }))
            .collect::<Vec<_>>(),
        "network": network(view),
        "self": own(view),
        "members": known(current)
            .map(|member| member_value(member, current))
            .collect::<Vec<_>>(),
        "subnets": subnets(current),
        "refusedAdvertisements": current.rejected_advertisements,
        "names": names,
        "refusedNames": refused_names,
        "tunnel": {
            "routes": tunnel.routes.iter().map(ToString::to_string).collect::<Vec<_>>(),
            "routesVersion": tunnel.routes_version,
            "dns": tunnel_dns(tunnel.dns_domains),
        },
    })
}

fn network(view: &NetworkView<'_>) -> Value {
    let settings = view.settings;
    let security = match (settings.security, settings.cipher) {
        (SecurityMode::ForwardSecrecy, _) => "forward_secrecy",
        (_, Cipher::None) => "none",
        _ => "standard",
    };
    let kind = match settings.kind {
        NetworkKind::Managed => "managed",
        NetworkKind::Legacy => "legacy",
    };
    // A legacy network in the secure mode is made of reference nodes; a
    // managed one admits only listed keys (spec §8.3.1, §19.2 rule 5).
    let limitations: Vec<&str> = if settings.kind == NetworkKind::Legacy
        && settings.security == SecurityMode::ForwardSecrecy
    {
        vec!["reference_peers"]
    } else {
        Vec::new()
    };
    json!({
        "id": settings.network_name,
        "name": settings.network_name,
        "state": state(view),
        "security": security,
        "kind": kind,
        "limitations": limitations,
        "failure": failure(view),
        "joining": joining(view),
        "routingPolicy": match settings.route_policy {
            crate::config::RoutePolicy::Hops => "hops",
            crate::config::RoutePolicy::Latency => "latency",
        },
        // The names this device uses: the network's `dns` section, with
        // the local `mesh_set_dns` override applied.
        "dnsSuffix": settings.dns.suffix,
        "dnsEnabled": settings.dns.enabled,
    })
}

/// `network.failure`: what keeps the network from running first, then a
/// refused peer (snapshot «取值», `network.failure`).
fn failure(view: &NetworkView<'_>) -> Value {
    let Some(joined) = &view.joined else {
        return Value::Null;
    };
    match joined.failure {
        Some(Failure::NativeKeysPending) => {
            let detail = match &view.settings.native_keys {
                Some(keys) if !keys.is_empty() => "self_missing",
                _ => "empty",
            };
            json!({"code": "native_keys_pending", "detail": detail})
        }
        Some(Failure::PortInUse) => json!({
            "code": "port_in_use",
            "detail": listen_text(view.settings),
        }),
        Some(failure) => json!({"code": failure.code(), "detail": ""}),
        None => match joined.snapshot.not_native {
            Some(peer) => json!({"code": "peer_not_native", "detail": peer.to_string()}),
            None => Value::Null,
        },
    }
}

fn listen_text(settings: &MeshSettings) -> String {
    settings
        .listen
        .iter()
        .map(|listen| format!("{:?} {}", listen.transport, listen.port).to_lowercase())
        .collect::<Vec<_>>()
        .join(", ")
}

/// `network.joining` while the network is joined but has no neighbour.
fn joining(view: &NetworkView<'_>) -> Value {
    match &view.joined {
        Some(joined) if state(view) == "joining" => json!({
            "stage": "connecting",
            "peersConnected": joined.snapshot.neighbours.len(),
        }),
        _ => Value::Null,
    }
}

fn own(view: &NetworkView<'_>) -> Value {
    let settings = view.settings;
    let mut own = Map::new();
    // The device's instance ID (`node.instance_id`) of the chosen
    // network, the same in every network that has one; `null` for a
    // network configured without it. The instance ID on the wire changes
    // at every start.
    own.insert("id".into(), json!(settings.instance_id));
    own.insert("name".into(), json!(settings.hostname));
    own.insert(
        "role".into(),
        json!(match settings.role {
            Role::Full => "server",
            Role::Access => "client",
        }),
    );
    own.insert(
        "address".into(),
        json!(settings.address.address().to_string()),
    );
    own.insert(
        "addressV6".into(),
        json!(settings.address_v6.map(|net| net.address().to_string())),
    );
    own.insert("relay".into(), json!(settings.relay));
    own.insert(
        "advertised".into(),
        json!(settings
            .advertise_subnets
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()),
    );
    own.insert(
        "staticKey".into(),
        json!(view.static_key.as_ref().map(encode_key)),
    );
    Value::Object(own)
}

/// The members whose route information arrived: only they have an `id`
/// that stays the same for the rest of their run, so the others are left
/// out until it arrives.
fn known(current: &Snapshot) -> impl Iterator<Item = &Member> {
    current
        .members
        .iter()
        .filter(|member| !member.instance.is_empty())
}

/// A member's `id`: its instance ID on the wire, the same for one run of
/// that member. A relay not (yet) known by it is named by its node ID.
fn member_id(member: &Member) -> String {
    if member.instance.is_empty() {
        format!("node-{}", member.peer_id)
    } else {
        member.instance.clone()
    }
}

fn member_value(member: &Member, current: &Snapshot) -> Value {
    let id_of = |peer: u32| {
        current
            .members
            .iter()
            .find(|other| other.peer_id == peer)
            .map_or_else(|| format!("node-{peer}"), member_id)
    };
    let mut path: Vec<String> = member.via.iter().map(|peer| id_of(*peer)).collect();
    path.push(member_id(member));
    json!({
        "id": member_id(member),
        "name": member.hostname,
        "state": "online",
        "address": member.addresses.first().map(IpAddr::to_string),
        "connection": if member.via.is_empty() { "direct" } else { "relay" },
        "hops": member.via.len(),
        "latencyMs": member.latency_ms,
        "path": path,
        "pathState": "auto",
        "unreachable": Value::Null,
        "subnets": member.subnets.iter().map(ToString::to_string).collect::<Vec<_>>(),
    })
}

/// Every subnet a member advertises, with its advertisers. The one in use
/// is the one the driver sends to (spec §15.2, `RouteTable::lookup_by`):
/// among the peers advertising the same subnet, the fewest hops away
/// whatever the path policy (`Member::fewest_hops`), then
/// the smallest node ID. `route` is `mesh` only for a subnet the driver
/// routes into the mesh now, the ones `tunnel.routes` lists; every other
/// subnet stays on this machine's own networks.
fn subnets(current: &Snapshot) -> Vec<Value> {
    let mut cidrs: Vec<IpNet> = known(current)
        .flat_map(|member| member.subnets.iter().copied())
        .collect();
    cidrs.sort();
    cidrs.dedup();
    cidrs
        .into_iter()
        .map(|cidr| {
            let mut advertisers: Vec<&Member> = known(current)
                .filter(|member| member.subnets.contains(&cidr))
                .collect();
            advertisers.sort_by_key(|member| (member.fewest_hops, member.peer_id));
            let routed = current.local_networks_read && current.system_routes.contains(&cidr);
            let overlaps = current.overlaps.contains(&cidr);
            json!({
                "cidr": cidr.to_string(),
                "advertisers": advertisers
                    .iter()
                    .enumerate()
                    .map(|(index, member)| json!({
                        "member": member_id(member),
                        "inUse": index == 0,
                    }))
                    .collect::<Vec<_>>(),
                "latencyMs": advertisers.first().and_then(|member| member.latency_ms),
                "path": advertisers.first().map(|member| {
                    let mut path: Vec<String> = member
                        .via
                        .iter()
                        .map(|peer| {
                            current
                                .members
                                .iter()
                                .find(|other| other.peer_id == *peer)
                                .map_or_else(|| format!("node-{peer}"), member_id)
                        })
                        .collect();
                    path.push(member_id(member));
                    path
                }),
                "state": "ok",
                "overlaps": overlaps,
                "localOverlap": overlaps && !current.foreign_overlaps.contains(&cidr),
                "route": if routed { "mesh" } else { "local" },
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::MeshConfig;

    fn settings(kind: &str, secure: bool) -> MeshSettings {
        let config: MeshConfig = serde_json::from_value(json!({
            "config_version": 1,
            "network": {"name": "office", "secret": "s3cr3t", "kind": kind, "secure_mode": secure},
            "node": {"address": "10.144.0.2/24", "role": "access", "hostname": "laptop"},
            "peers": [{"server": "127.0.0.1", "port": 1}],
        }))
        .unwrap();
        config.validate().unwrap()
    }

    fn net(text: &str) -> IpNet {
        IpNet::parse(text).unwrap()
    }

    fn member(peer_id: u32, address: &str, subnets: &[&str], via: Vec<u32>) -> Member {
        Member {
            peer_id,
            instance: format!("00000000-0000-0000-0000-{peer_id:012}"),
            hostname: Some(format!("host-{peer_id}")),
            addresses: vec![address.parse().unwrap()],
            subnets: subnets.iter().map(|s| net(s)).collect(),
            hops: via.len() as u32 + 1,
            fewest_hops: via.len() as u32 + 1,
            latency_ms: via.is_empty().then_some(12),
            via,
            path_state: "auto",
            unreachable: None,
        }
    }

    #[test]
    fn names_are_listed_with_their_duplicates_in_other_networks() {
        use std::sync::Arc;

        use crate::dns::{ConfiguredName, DnsSettings, MemberNames, RefusedName, RefusedReason};

        fn dns(suffix: &str, region: &str, panel: &[(&str, &str, &str)]) -> DnsSettings {
            DnsSettings {
                enabled: true,
                suffix: suffix.to_owned(),
                region: Some(region.to_owned()),
                names: panel
                    .iter()
                    .map(|(label, region, address)| ConfiguredName {
                        label: (*label).to_owned(),
                        region: (*region).to_owned(),
                        address: address.parse().unwrap(),
                    })
                    .collect(),
                ..DnsSettings::default()
            }
        }
        fn names(settings: &DnsSettings, subnet: &str, members: &[(&str, &str)]) -> Arc<Names> {
            let subnets = [net(subnet)];
            let members: Vec<MemberNames> = members
                .iter()
                .map(|(hostname, address)| MemberNames {
                    hostname: Some((*hostname).to_owned()),
                    addresses: vec![address.parse().unwrap()],
                    subnets: Vec::new(),
                })
                .collect();
            Arc::new(Names::build(
                settings,
                &crate::dns::NetworkView {
                    virtual_subnets: &subnets,
                    host_groups: &[],
                    local_addresses: &[],
                    own_hostname: None,
                    members: &members,
                },
            ))
        }
        fn snapshot_of(names: Arc<Names>) -> Snapshot {
            Snapshot {
                names: Some(names),
                ..Snapshot::default()
            }
        }
        fn view<'a>(
            settings: &'a MeshSettings,
            snapshot: &'a Snapshot,
            running: bool,
        ) -> NetworkView<'a> {
            NetworkView {
                settings,
                joined: Some(Joined {
                    running,
                    failure: None,
                    snapshot,
                }),
                static_key: None,
            }
        }
        let named = |name: &str, dns: &DnsSettings| {
            let mut settings = settings("legacy", false);
            settings.network_name = name.to_owned();
            settings.dns = dns.clone();
            settings
        };

        // office: region lon. `cam.lon` has one address inside the network
        // and one outside it, so it is not answerable as a whole but its
        // first address is answered.
        let mut office_dns = dns(
            "mesh.internal",
            "lon",
            &[("cam", "lon", "10.144.0.41"), ("cam", "lon", "10.147.0.5")],
        );
        let refused = RefusedName {
            name: "bad.lon".to_owned(),
            address: "8.8.8.8".to_owned(),
            reason: RefusedReason::NotIntranet,
        };
        office_dns.refused.push(refused.clone());
        let office = named("office", &office_dns);
        let office_now = snapshot_of(names(
            &office_dns,
            "10.144.0.0/24",
            &[
                ("printer", "10.144.0.9"),
                ("nas", "10.144.0.20"),
                ("solo", "10.144.0.30"),
                ("router", "10.144.0.1"),
            ],
        ));
        // lab: same suffix and region, so `printer.lon` and `cam.lon` are
        // the same full names.
        let lab_dns = dns("mesh.internal", "lon", &[]);
        let lab = named("lab", &lab_dns);
        let lab_now = snapshot_of(names(
            &lab_dns,
            "10.145.0.0/24",
            &[("printer", "10.145.0.9"), ("cam", "10.145.0.41")],
        ));
        // paris: same suffix, region par. Its `printer.par` shares the
        // short name and the bare name with office's `printer.lon`; its
        // `solo.ber` (no `solo` in par) only the short name `solo.<suffix>`.
        let paris_dns = dns("mesh.internal", "par", &[("solo", "ber", "10.148.0.30")]);
        let paris = named("paris", &paris_dns);
        let paris_now = snapshot_of(names(
            &paris_dns,
            "10.148.0.0/24",
            &[("printer", "10.148.0.9")],
        ));
        // home: another suffix, region lon. Only the bare name `nas` is
        // shared, since a bare name is answered under every suffix.
        let home_dns = dns("home.internal", "lon", &[]);
        let home = named("home", &home_dns);
        let home_now = snapshot_of(names(&home_dns, "10.146.0.0/24", &[("nas", "10.146.0.20")]));
        // attic: names off, so it answers nothing.
        let mut attic_dns = dns("mesh.internal", "lon", &[]);
        attic_dns.enabled = false;
        let attic = named("attic", &attic_dns);
        let attic_now = snapshot_of(names(
            &attic_dns,
            "10.149.0.0/24",
            &[("router", "10.149.0.1")],
        ));

        let tunnel = Tunnel {
            routes: &[],
            routes_version: 1,
            dns_domains: &[],
        };
        let entry = |value: &Value, name: &str| {
            value["names"]
                .as_array()
                .unwrap()
                .iter()
                .find(|entry| entry["name"] == name)
                .cloned()
                .unwrap()
        };
        // Not sorted by id: `duplicateNetworks` is.
        let views = [
            view(&office, &office_now, true),
            view(&paris, &paris_now, true),
            view(&lab, &lab_now, true),
            view(&home, &home_now, true),
            view(&attic, &attic_now, true),
        ];
        let value = snapshot(&views[0], &views, &tunnel);
        let printer = entry(&value, "printer.lon");
        assert_eq!(printer["source"], "member");
        assert_eq!(printer["addresses"], json!(["10.144.0.9"]));
        assert_eq!(printer["duplicate"], true);
        assert_eq!(printer["duplicateNetworks"], json!(["lab", "paris"]));
        let cam = entry(&value, "cam.lon");
        assert_eq!(cam["source"], "panel");
        assert_eq!(cam["answerable"], false);
        assert_eq!(cam["duplicate"], true);
        assert_eq!(cam["duplicateNetworks"], json!(["lab"]));
        assert_eq!(
            entry(&value, "nas.lon")["duplicateNetworks"],
            json!(["home"])
        );
        assert_eq!(
            entry(&value, "solo.lon")["duplicateNetworks"],
            json!(["paris"])
        );
        let router = entry(&value, "router.lon");
        assert_eq!(router["duplicate"], false);
        assert!(router.get("duplicateNetworks").is_none());
        assert_eq!(value["refusedNames"], json!([refused]));
        // From the other side alike.
        let value = snapshot(&views[1], &views, &tunnel);
        assert_eq!(
            entry(&value, "printer.par")["duplicateNetworks"],
            json!(["lab", "office"])
        );
        assert_eq!(
            entry(&value, "solo.ber")["duplicateNetworks"],
            json!(["office"])
        );
        let value = snapshot(&views[3], &views, &tunnel);
        assert_eq!(
            entry(&value, "nas.lon")["duplicateNetworks"],
            json!(["office"])
        );
        // A network that does not run answers nothing: no duplicate.
        let views = [
            view(&office, &office_now, true),
            view(&lab, &lab_now, false),
        ];
        let value = snapshot(&views[0], &views, &tunnel);
        assert_eq!(entry(&value, "printer.lon")["duplicate"], false);
        assert_eq!(entry(&value, "cam.lon")["duplicate"], false);
        // Not running itself: no names, only what its config skipped.
        let views = [
            view(&office, &office_now, false),
            view(&lab, &lab_now, true),
        ];
        let value = snapshot(&views[0], &views, &tunnel);
        assert_eq!(value["names"], json!([]));
        assert_eq!(value["refusedNames"], json!([refused]));
        // Names off: both lists empty.
        let mut quiet = office.clone();
        quiet.dns.enabled = false;
        let views = [view(&quiet, &office_now, true)];
        let value = snapshot(&views[0], &views, &tunnel);
        assert_eq!(value["names"], json!([]));
        assert_eq!(value["refusedNames"], json!([]));
    }

    #[test]
    fn a_saved_network_not_joined() {
        let settings = settings("legacy", false);
        let view = NetworkView {
            settings: &settings,
            joined: None,
            static_key: None,
        };
        let tunnel = Tunnel {
            routes: &[],
            routes_version: 1,
            dns_domains: &[],
        };
        let value = snapshot(&view, std::slice::from_ref(&view), &tunnel);
        assert_eq!(value["statusVersion"], 1);
        assert_eq!(
            value["networks"],
            json!([{"id": "office", "name": "office", "state": "not_joined"}])
        );
        assert_eq!(value["network"]["state"], "not_joined");
        assert_eq!(value["network"]["security"], "standard");
        assert_eq!(value["network"]["kind"], "legacy");
        assert_eq!(value["network"]["limitations"], json!([]));
        assert_eq!(value["network"]["failure"], Value::Null);
        assert_eq!(value["self"]["role"], "client");
        assert_eq!(value["self"]["address"], "10.144.0.2");
        assert_eq!(value["self"]["staticKey"], Value::Null);
        assert_eq!(value["self"]["id"], Value::Null);
        assert_eq!(value["members"], json!([]));
        assert_eq!(value["tunnel"]["dns"], Value::Null);
    }

    #[test]
    fn the_advertiser_in_use_is_the_fewest_hops_away_whatever_the_policy() {
        let settings = settings("legacy", false);
        // By the latency policy node 9 is reached in three hops, but it is
        // one hop away at the fewest; node 3 is two hops away either way.
        let current = Snapshot {
            members: vec![
                member(3, "10.144.0.3", &["192.168.10.0/24"], vec![5]),
                Member {
                    fewest_hops: 1,
                    ..member(9, "10.144.0.9", &["192.168.10.0/24"], vec![3, 5])
                },
            ],
            ..Snapshot::default()
        };
        let view = NetworkView {
            settings: &settings,
            joined: Some(Joined {
                running: true,
                failure: None,
                snapshot: &current,
            }),
            static_key: None,
        };
        let tunnel = Tunnel {
            routes: &[],
            routes_version: 1,
            dns_domains: &[],
        };
        let value = snapshot(&view, std::slice::from_ref(&view), &tunnel);
        let advertisers = &value["subnets"][0]["advertisers"];
        assert_eq!(
            advertisers[0]["member"],
            "00000000-0000-0000-0000-000000000009"
        );
        assert_eq!(advertisers[0]["inUse"], true);
        assert_eq!(advertisers[1]["inUse"], false);
    }

    #[test]
    fn a_joined_network_lists_members_paths_and_subnets() {
        let mut settings = settings("legacy", true);
        settings.instance_id = Some("device-1".into());
        let unknown = Member {
            instance: String::new(),
            ..member(12, "10.144.0.12", &["172.16.0.0/16"], Vec::new())
        };
        let current = Snapshot {
            neighbours: vec![3],
            instance: "11111111-2222-3333-4444-555555555555".into(),
            members: vec![
                member(
                    3,
                    "10.144.0.3",
                    &["192.168.10.0/24", "10.30.0.0/16"],
                    Vec::new(),
                ),
                member(
                    9,
                    "10.144.0.9",
                    &["192.168.10.0/24", "192.168.1.0/24"],
                    vec![3],
                ),
                unknown,
            ],
            system_routes: vec![net("192.168.10.0/24")],
            local_networks_read: true,
            overlaps: vec![net("192.168.1.0/24")],
            not_native: None,
            rejected_advertisements: 2,
            ..Snapshot::default()
        };
        let view = NetworkView {
            settings: &settings,
            joined: Some(Joined {
                running: true,
                failure: None,
                snapshot: &current,
            }),
            static_key: Some([1; 32]),
        };
        // `Registry::tunnel_routes` gives them.
        let routes = [net("10.144.0.0/24"), net("192.168.10.0/24")];
        let domains = ["mesh.internal".to_owned(), "144.10.in-addr.arpa".to_owned()];
        let tunnel = Tunnel {
            routes: &routes,
            routes_version: 4,
            dns_domains: &domains,
        };
        let value = snapshot(&view, std::slice::from_ref(&view), &tunnel);
        assert_eq!(
            value["tunnel"]["dns"],
            json!({
                "servers": ["198.18.0.2", "fd00::53"],
                "matchDomains": ["mesh.internal", "144.10.in-addr.arpa"],
            })
        );
        assert_eq!(value["network"]["state"], "joined");
        assert_eq!(value["network"]["security"], "forward_secrecy");
        assert_eq!(value["network"]["limitations"], json!(["reference_peers"]));
        assert_eq!(value["network"]["joining"], Value::Null);
        assert_eq!(value["self"]["id"], "device-1");
        // A member whose route information has not arrived is left out.
        assert_eq!(value["members"].as_array().unwrap().len(), 2);
        assert_eq!(value["self"]["name"], "laptop");
        assert_eq!(
            value["self"]["staticKey"],
            "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="
        );
        let far = &value["members"][1];
        assert_eq!(far["connection"], "relay");
        assert_eq!(far["hops"], 1);
        assert_eq!(far["latencyMs"], Value::Null);
        assert_eq!(
            far["path"],
            json!([
                "00000000-0000-0000-0000-000000000003",
                "00000000-0000-0000-0000-000000000009"
            ])
        );
        assert_eq!(value["members"][0]["connection"], "direct");
        assert_eq!(value["members"][0]["name"], "host-3");
        let subnets = value["subnets"].as_array().unwrap();
        let lan = subnets
            .iter()
            .find(|s| s["cidr"] == "192.168.10.0/24")
            .unwrap();
        assert_eq!(lan["route"], "mesh");
        assert_eq!(lan["advertisers"][0]["inUse"], true);
        assert_eq!(
            lan["advertisers"][0]["member"],
            "00000000-0000-0000-0000-000000000003"
        );
        assert_eq!(lan["advertisers"][1]["inUse"], false);
        let home = subnets
            .iter()
            .find(|s| s["cidr"] == "192.168.1.0/24")
            .unwrap();
        assert_eq!(home["route"], "local");
        assert_eq!(home["localOverlap"], true);
        // Not overlapping, but not routed either (for instance beyond
        // `routing.system_routes`): it is not in the tunnel, so not `mesh`.
        let beyond = subnets
            .iter()
            .find(|s| s["cidr"] == "10.30.0.0/16")
            .unwrap();
        assert_eq!(beyond["route"], "local");
        assert_eq!(beyond["localOverlap"], false);
        assert!(!subnets.iter().any(|s| s["cidr"] == "172.16.0.0/16"));
        assert_eq!(value["refusedAdvertisements"], 2);
        assert_eq!(
            value["tunnel"]["routes"],
            json!(["10.144.0.0/24", "192.168.10.0/24"])
        );
        assert_eq!(value["tunnel"]["routesVersion"], 4);
    }

    #[test]
    fn failures_follow_the_snapshot_contract() {
        let settings = settings("managed", true);
        let current = Snapshot {
            not_native: Some(44),
            neighbours: vec![3],
            ..Snapshot::default()
        };
        let view = |failure, running| NetworkView {
            settings: &settings,
            joined: Some(Joined {
                running,
                failure,
                snapshot: &current,
            }),
            static_key: Some([2; 32]),
        };
        let waiting = view(Some(Failure::NativeKeysPending), false);
        assert_eq!(state(&waiting), "not_joined");
        assert_eq!(
            failure(&waiting),
            json!({"code": "native_keys_pending", "detail": "empty"})
        );
        let refused = view(None, true);
        assert_eq!(state(&refused), "joined");
        assert_eq!(
            failure(&refused),
            json!({"code": "peer_not_native", "detail": "44"})
        );
        assert_eq!(state(&view(Some(Failure::Stopped), false)), "failed");
        assert_eq!(state(&view(None, false)), "joining");
    }

    #[test]
    fn no_secret_is_in_the_snapshot() {
        let mut settings = settings("managed", true);
        settings.private_key = Some(Box::new(zeroize::Zeroizing::new([7; 32])));
        let view = NetworkView {
            settings: &settings,
            joined: None,
            static_key: Some([2; 32]),
        };
        let tunnel = Tunnel {
            routes: &[],
            routes_version: 1,
            dns_domains: &[],
        };
        let text = snapshot(&view, std::slice::from_ref(&view), &tunnel).to_string();
        assert!(!text.contains("s3cr3t"));
        assert!(!text.contains(&encode_key(&[7; 32])));
    }
}
