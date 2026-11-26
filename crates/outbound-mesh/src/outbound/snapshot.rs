//! The `mesh_status` snapshot (`docs/architecture/mesh-status.md`
//! «快照»): one network's view for the clients of the embedded engine,
//! built from the network's settings and its driver's [`Snapshot`].
//!
//! Only kernel 0.3 fields are given. A field this kernel cannot fill yet is
//! left out rather than guessed, as the snapshot contract allows.

use std::net::IpAddr;

use serde_json::{json, Map, Value};

use crate::config::{encode_key, Cipher, MeshSettings, NetworkKind, Role, SecurityMode};
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
}

/// `network.state` (snapshot «取值»).
pub fn state(view: &NetworkView<'_>) -> &'static str {
    let Some(joined) = &view.joined else {
        return "not_joined";
    };
    match joined.failure {
        // A managed network waiting for its key list is not joined yet.
        Some(Failure::NativeKeysPending) => "not_joined",
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
        "self": own(view, current),
        "members": current
            .members
            .iter()
            .map(|member| member_value(member, current))
            .collect::<Vec<_>>(),
        "subnets": subnets(current),
        "refusedAdvertisements": current.rejected_advertisements,
        "tunnel": {
            "routes": tunnel.routes.iter().map(ToString::to_string).collect::<Vec<_>>(),
            "routesVersion": tunnel.routes_version,
            // Intranet names are answered once the engine serves them.
            "dns": Value::Null,
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
        "dnsSuffix": Value::Null,
        "dnsEnabled": false,
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

fn own(view: &NetworkView<'_>, current: &Snapshot) -> Value {
    let settings = view.settings;
    let mut own = Map::new();
    own.insert("id".into(), json!(current.instance));
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

/// A member's `id`: its instance ID, or its node ID until its route
/// information arrived.
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

/// Every subnet a member advertises, with its advertisers; the one in use
/// is the nearest (fewest hops, then lowest node ID).
fn subnets(current: &Snapshot) -> Vec<Value> {
    let mut cidrs: Vec<IpNet> = current
        .members
        .iter()
        .flat_map(|member| member.subnets.iter().copied())
        .collect();
    cidrs.sort();
    cidrs.dedup();
    cidrs
        .into_iter()
        .map(|cidr| {
            let mut advertisers: Vec<&Member> = current
                .members
                .iter()
                .filter(|member| member.subnets.contains(&cidr))
                .collect();
            advertisers.sort_by_key(|member| (member.hops, member.peer_id));
            let routed = current.system_routes.contains(&cidr);
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
                "route": if routed || !overlaps { "mesh" } else { "local" },
            })
        })
        .collect()
}

/// `tunnel.routes` (snapshot «取值»): the virtual subnets of every joined
/// network and the subnets its driver routes into the mesh, once this
/// machine's networks were read; deduplicated, in a stable order.
pub fn tunnel_routes<'a>(
    joined: impl IntoIterator<Item = (&'a MeshSettings, &'a Snapshot)>,
) -> Vec<IpNet> {
    let mut routes = Vec::new();
    for (settings, snapshot) in joined {
        for net in settings.virtual_subnets() {
            if !routes.contains(&net) {
                routes.push(net);
            }
        }
        if snapshot.local_networks_read {
            for net in &snapshot.system_routes {
                if !routes.contains(net) {
                    routes.push(*net);
                }
            }
        }
    }
    routes
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
            latency_ms: via.is_empty().then_some(12),
            via,
        }
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
        assert_eq!(value["members"], json!([]));
        assert_eq!(value["tunnel"]["dns"], Value::Null);
    }

    #[test]
    fn a_joined_network_lists_members_paths_and_subnets() {
        let settings = settings("legacy", true);
        let current = Snapshot {
            neighbours: vec![3],
            instance: "11111111-2222-3333-4444-555555555555".into(),
            members: vec![
                member(3, "10.144.0.3", &["192.168.10.0/24"], Vec::new()),
                member(
                    9,
                    "10.144.0.9",
                    &["192.168.10.0/24", "192.168.1.0/24"],
                    vec![3],
                ),
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
        let routes = tunnel_routes([(&settings, &current)]);
        assert_eq!(routes, [net("10.144.0.0/24"), net("192.168.10.0/24")]);
        let tunnel = Tunnel {
            routes: &routes,
            routes_version: 4,
        };
        let value = snapshot(&view, std::slice::from_ref(&view), &tunnel);
        assert_eq!(value["network"]["state"], "joined");
        assert_eq!(value["network"]["security"], "forward_secrecy");
        assert_eq!(value["network"]["limitations"], json!(["reference_peers"]));
        assert_eq!(value["network"]["joining"], Value::Null);
        assert_eq!(value["self"]["id"], "11111111-2222-3333-4444-555555555555");
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
        assert_eq!(value["refusedAdvertisements"], 2);
        assert_eq!(
            value["tunnel"]["routes"],
            json!(["10.144.0.0/24", "192.168.10.0/24"])
        );
        assert_eq!(value["tunnel"]["routesVersion"], 4);
    }

    #[test]
    fn no_subnet_enters_the_tunnel_before_local_networks_are_read() {
        let settings = settings("legacy", false);
        let current = Snapshot {
            system_routes: vec![net("192.168.10.0/24")],
            local_networks_read: false,
            ..Snapshot::default()
        };
        assert_eq!(
            tunnel_routes([(&settings, &current)]),
            [net("10.144.0.0/24")]
        );
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
}
