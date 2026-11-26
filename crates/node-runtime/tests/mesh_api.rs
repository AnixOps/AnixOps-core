//! `GET` / `PUT /v1/mesh` the way a node agent uses them (networkcore issue
//! #300), against a stand-in for the mesh: the feature flag, whole-body
//! replacement, refusal of invalid bodies without applying anything, and no
//! secret in any answer. Peer addresses are documentation addresses only.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use node_runtime::{api, default_registry, Node};
use outbound_mesh::status::{
    Alert, AlertCode, ApplyError, BoxFuture, ManagedBackbone, ManagedNetwork, ManagedNetworkStatus,
    ManagedPeer, ManagedStatus, MeshControl,
};
use outbound_mesh::IpNet;
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const TIMEOUT: Duration = Duration::from_secs(10);
const TOKEN: &str = "test-token";
const SECRET: &str = "region-secret-never-answered";
const INSTANCE_ID: &str = "2f6d7c1e-0b8a-4c55-9e0e-6a1f3b9d2c10";

/// Runs what it is given: every network starts, except one whose network
/// name is `refuse`, which is reported as refused to start. Records every
/// applied list (tags and secrets) so tests can tell what reached the mesh.
#[derive(Default)]
struct FakeMesh {
    running: Mutex<ManagedStatus>,
    applied: Mutex<Vec<Vec<(String, String)>>>,
    /// The backbone ID of every applied request, `None` without one.
    backbones: Mutex<Vec<Option<u32>>>,
    /// Does not list `mesh_backbone`, as a node with the backbone off.
    no_backbone: bool,
}

impl MeshControl for FakeMesh {
    fn features(&self) -> Vec<&'static str> {
        if self.no_backbone {
            vec!["mesh", "mesh_dns"]
        } else {
            vec!["mesh", "mesh_dns", "mesh_backbone"]
        }
    }

    fn status(&self) -> ManagedStatus {
        self.running.lock().unwrap().clone()
    }

    fn apply(
        &self,
        networks: Vec<ManagedNetwork>,
        backbone: Option<ManagedBackbone>,
    ) -> BoxFuture<'_, Result<ManagedStatus, ApplyError>> {
        Box::pin(async move {
            self.backbones
                .lock()
                .unwrap()
                .push(backbone.as_ref().map(|backbone| backbone.settings.id));
            self.applied.lock().unwrap().push(
                networks
                    .iter()
                    .map(|n| (n.tag.clone(), (*n.settings.network_secret).clone()))
                    .collect(),
            );
            let status = ManagedStatus {
                instance_id: INSTANCE_ID.into(),
                networks: networks.iter().map(network_status).collect(),
                static_keys: Vec::new(),
                backbone: None,
                alerts: Vec::new(),
                region_probe: None,
            };
            *self.running.lock().unwrap() = status.clone();
            Ok(status)
        })
    }
}

fn network_status(network: &ManagedNetwork) -> ManagedNetworkStatus {
    if network.settings.network_name == "refuse" {
        let mut status = ManagedNetworkStatus::stopped(&network.tag, "tcp port 11010 in use");
        status.alerts.push(Alert {
            code: AlertCode::StartRefused,
            address: None,
            peer: String::new(),
            detail: "tcp port 11010 in use".into(),
        });
        return status;
    }
    ManagedNetworkStatus {
        tag: network.tag.clone(),
        running: true,
        error: String::new(),
        address: Some(network.settings.address),
        forward_secrecy: network.settings.security.has_forward_secrecy(),
        failure: None,
        peers: vec![ManagedPeer {
            address: "10.150.0.1".parse().unwrap(),
            subnets: vec![IpNet::parse("192.168.10.0/24").unwrap()],
            via: Vec::new(),
            hops: 1,
            latency_ms: Some(12),
            forward_secrecy: true,
            path_state: "auto",
            unreachable: None,
        }],
        rejected_advertisements: 0,
        overlaps: Vec::new(),
        alerts: Vec::new(),
        names: Vec::new(),
        refused_names: Vec::new(),
        paths: Vec::new(),
        external_bridge: None,
    }
}

async fn start_api(mesh: Option<Arc<FakeMesh>>) -> SocketAddr {
    let mut node = Node::new(default_registry(), false);
    if let Some(mesh) = mesh {
        node = node.with_mesh(mesh);
    }
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(api::serve(listener, Arc::new(node), TOKEN.to_owned()));
    addr
}

/// One HTTP request; returns the status, the raw body and the JSON body.
async fn call(
    api: SocketAddr,
    method: &str,
    path: &str,
    body: Option<Value>,
) -> (u16, String, Value) {
    let body = body.map(|body| body.to_string()).unwrap_or_default();
    let mut stream = TcpStream::connect(api).await.unwrap();
    let request = format!(
        "{method} {path} HTTP/1.1\r\nHost: node\r\nAuthorization: Bearer {TOKEN}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(request.as_bytes()).await.unwrap();
    let mut response = Vec::new();
    tokio::time::timeout(TIMEOUT, stream.read_to_end(&mut response))
        .await
        .expect("api timed out")
        .unwrap();
    let response = String::from_utf8(response).unwrap();
    let (head, body) = response.split_once("\r\n\r\n").unwrap();
    let status = head.split(' ').nth(1).unwrap().parse().unwrap();
    (status, body.to_owned(), serde_json::from_str(body).unwrap())
}

fn network(tag: &str, name: &str, address: &str) -> Value {
    json!({
        "tag": tag,
        "config_version": 1,
        "network": {"name": name, "secret": SECRET, "secure_mode": true, "cipher": "aes-gcm"},
        "node": {
            "address": address,
            "role": "full",
            "listen": [{"transport": "tcp", "port": 11010}, {"transport": "udp", "port": 11010}]
        },
        "peers": [{"server": "203.0.113.10", "port": 11010, "transport": "tcp"}],
        "subnets": {"accept": [], "advertise": []},
        "routing": {"policy": "latency", "paths": []}
    })
}

fn features(status: &Value) -> Vec<String> {
    status["features"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f.as_str().unwrap().to_owned())
        .collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn without_a_mesh_the_kernel_does_not_offer_it() {
    let api = start_api(None).await;
    let (status, _, body) = call(api, "GET", "/v1/status", None).await;
    assert_eq!(status, 200);
    assert!(!features(&body).contains(&"mesh".to_owned()));
    let (status, _, _) = call(api, "GET", "/v1/mesh", None).await;
    assert_eq!(status, 404);
    let put = json!({"networks": [network("mesh-cn", "mesh-cn", "10.150.0.5/16")]});
    let (status, raw, _) = call(api, "PUT", "/v1/mesh", Some(put)).await;
    assert_eq!(status, 404);
    assert!(!raw.contains(SECRET));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_agent_replaces_and_reads_its_networks() {
    let mesh = Arc::new(FakeMesh::default());
    let api = start_api(Some(mesh.clone())).await;

    let (status, _, body) = call(api, "GET", "/v1/status", None).await;
    assert_eq!(status, 200);
    let listed = features(&body);
    assert!(listed.contains(&"mesh".to_owned()));
    assert!(listed.contains(&"mesh_dns".to_owned()));
    assert!(listed.contains(&"qos".to_owned()), "base features stay");

    // A border node: two regions at once, one of which cannot start.
    let put = json!({"networks": [
        network("mesh-cn", "mesh-cn", "10.150.0.5/16"),
        network("mesh-eu", "refuse", "10.151.0.5/16"),
    ]});
    let (status, raw, body) = call(api, "PUT", "/v1/mesh", Some(put)).await;
    assert_eq!(status, 200, "{body}");
    assert!(!raw.contains(SECRET), "the answer carries the secret");
    assert_eq!(body["instance_id"], json!(INSTANCE_ID));
    let cn = &body["networks"][0];
    assert_eq!(cn["tag"], json!("mesh-cn"));
    assert_eq!(cn["running"], json!(true));
    assert_eq!(cn["error"], json!(""));
    assert_eq!(cn["address"], json!("10.150.0.5/16"));
    assert_eq!(cn["forward_secrecy"], json!(true));
    assert_eq!(
        cn["peers"],
        json!([{"address": "10.150.0.1", "subnets": ["192.168.10.0/24"], "via": [], "hops": 1, "latency_ms": 12, "forward_secrecy": true, "path_state": "auto", "unreachable": null}])
    );
    assert_eq!(cn["paths"], json!([]));
    assert_eq!(cn["rejected_advertisements"], json!(0));
    assert_eq!(cn["overlaps"], json!([]));
    let eu = &body["networks"][1];
    assert_eq!(eu["running"], json!(false));
    assert_eq!(eu["alerts"][0]["code"], json!("start_refused"));

    // The secret reached the mesh, and only the mesh.
    assert_eq!(
        mesh.applied.lock().unwrap().last().unwrap(),
        &vec![
            ("mesh-cn".to_owned(), SECRET.to_owned()),
            ("mesh-eu".to_owned(), SECRET.to_owned())
        ]
    );

    // GET answers the same as the PUT did.
    let (status, raw, got) = call(api, "GET", "/v1/mesh", None).await;
    assert_eq!(status, 200);
    assert!(!raw.contains(SECRET));
    assert_eq!(got, body);

    // An empty list stops everything.
    let (status, _, body) = call(api, "PUT", "/v1/mesh", Some(json!({"networks": []}))).await;
    assert_eq!(status, 200);
    assert_eq!(body["networks"], json!([]));
    assert_eq!(body["instance_id"], json!(INSTANCE_ID));
    assert_eq!(mesh.applied.lock().unwrap().len(), 2);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_invalid_network_refuses_the_whole_body() {
    let mesh = Arc::new(FakeMesh::default());
    let api = start_api(Some(mesh.clone())).await;

    let mut bad_address = network("mesh-eu", "mesh-eu", "10.151.0.5/16");
    bad_address["node"]["address"] = json!("not an address");
    let mut bad_cipher = network("mesh-eu", "mesh-eu", "10.151.0.5/16");
    bad_cipher["network"]["cipher"] = json!(SECRET);
    let mut untagged = network("mesh-eu", "mesh-eu", "10.151.0.5/16");
    untagged.as_object_mut().unwrap().remove("tag");
    let bodies = [
        json!({"networks": [network("mesh-cn", "mesh-cn", "10.150.0.5/16"), bad_address]}),
        json!({"networks": [network("mesh-cn", "mesh-cn", "10.150.0.5/16"), bad_cipher]}),
        json!({"networks": [network("mesh-cn", "mesh-cn", "10.150.0.5/16"), untagged]}),
        json!({"networks": [
            network("mesh-cn", "mesh-cn", "10.150.0.5/16"),
            network("mesh-cn", "mesh-eu", "10.151.0.5/16")
        ]}),
        json!({"networks": [network("mesh-cn", "mesh-cn", "10.150.0.5/16")], "takeover": {}}),
        json!({}),
    ];
    for body in bodies {
        let (status, raw, answer) = call(api, "PUT", "/v1/mesh", Some(body)).await;
        assert_eq!(status, 400, "{answer}");
        assert!(answer["error"].is_string());
        assert!(!raw.contains(SECRET), "{raw}");
    }
    assert!(
        mesh.applied.lock().unwrap().is_empty(),
        "a refused body reached the mesh"
    );
}

fn backbone(region: &str) -> Value {
    json!({
        "id": 11,
        "region": region,
        "members": [
            {"id": 11, "region": region, "link": {"kind": "line"}},
            {"id": 21, "region": "ap", "link": {"kind": "line", "params": {"key": SECRET}}}
        ],
        "policy": {"deny_link": [["cn", "eu"]]}
    })
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_border_node_takes_its_backbone_with_the_region_network() {
    let mesh = Arc::new(FakeMesh::default());
    let api = start_api(Some(mesh.clone())).await;

    // Refused as a whole, without echoing a link parameter: no region
    // network for the backbone, an unknown field, a bad region.
    let mut unknown = backbone("cn");
    unknown["members"][1]["link"]["extra"] = json!(SECRET);
    let mut bad_region = backbone("cn");
    bad_region["region"] = json!("CN");
    for (networks, section) in [
        (
            vec![network("mesh-eu", "mesh-eu", "10.151.0.5/16")],
            backbone("cn"),
        ),
        (
            vec![network("mesh-cn", "mesh-cn", "10.150.0.5/16")],
            unknown,
        ),
        (
            vec![network("mesh-cn", "mesh-cn", "10.150.0.5/16")],
            bad_region,
        ),
    ] {
        let body = json!({"networks": networks, "backbone": section});
        let (status, raw, answer) = call(api, "PUT", "/v1/mesh", Some(body)).await;
        assert_eq!(status, 400, "{answer}");
        assert!(answer["error"].as_str().unwrap().starts_with("backbone"));
        assert!(!raw.contains(SECRET), "{raw}");
    }
    assert!(mesh.backbones.lock().unwrap().is_empty());

    let body = json!({
        "networks": [network("mesh-cn", "mesh-cn", "10.150.0.5/16")],
        "backbone": backbone("cn")
    });
    let (status, raw, answer) = call(api, "PUT", "/v1/mesh", Some(body)).await;
    assert_eq!(status, 200, "{answer}");
    assert!(!raw.contains(SECRET), "{raw}");
    assert_eq!(answer["backbone"], Value::Null);
    let body = json!({"networks": [network("mesh-cn", "mesh-cn", "10.150.0.5/16")]});
    let (status, _, _) = call(api, "PUT", "/v1/mesh", Some(body)).await;
    assert_eq!(status, 200);
    assert_eq!(*mesh.backbones.lock().unwrap(), [Some(11), None]);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_region_object_needs_the_region_probe_feature() {
    let mesh = Arc::new(FakeMesh::default());
    let api = start_api(Some(mesh.clone())).await;
    let body = json!({
        "networks": [network("mesh-cn", "mesh-cn", "10.150.0.5/16")],
        "region": { "current": "cn", "basis": "admin", "directory": null }
    });
    let (status, raw, answer) = call(api, "PUT", "/v1/mesh", Some(body)).await;
    assert_eq!(status, 400, "{answer}");
    assert!(answer["error"].as_str().unwrap().starts_with("region"));
    assert!(!raw.contains(SECRET), "{raw}");
    assert!(mesh.applied.lock().unwrap().is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_node_with_the_backbone_off_refuses_the_section_and_keeps_its_networks() {
    let mesh = Arc::new(FakeMesh {
        no_backbone: true,
        ..FakeMesh::default()
    });
    let api = start_api(Some(mesh.clone())).await;
    let (_, _, status) = call(api, "GET", "/v1/status", None).await;
    assert!(features(&status).contains(&"mesh".to_owned()));
    assert!(!features(&status).contains(&"mesh_backbone".to_owned()));

    let body = json!({"networks": [network("mesh-cn", "mesh-cn", "10.150.0.5/16")]});
    let (status, _, before) = call(api, "PUT", "/v1/mesh", Some(body)).await;
    assert_eq!(status, 200, "{before}");

    // A valid body with a backbone: refused as a whole with its own code,
    // nothing reaches the mesh, the running network stays.
    let body = json!({
        "networks": [network("mesh-cn", "mesh-cn", "10.150.0.5/16")],
        "backbone": backbone("cn")
    });
    let (status, raw, answer) = call(api, "PUT", "/v1/mesh", Some(body)).await;
    assert_eq!(status, 400, "{answer}");
    assert!(
        answer["error"]
            .as_str()
            .unwrap()
            .starts_with("backbone_disabled"),
        "{answer}"
    );
    assert!(!raw.contains(SECRET), "{raw}");
    assert_eq!(*mesh.backbones.lock().unwrap(), [None]);
    assert_eq!(mesh.applied.lock().unwrap().len(), 1);
    let (status, _, after) = call(api, "GET", "/v1/mesh", None).await;
    assert_eq!(status, 200);
    assert_eq!(after, before);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_node_with_custom_paths_off_refuses_them_and_keeps_its_networks() {
    // FakeMesh does not list mesh_paths, as a node with the switch off.
    let mesh = Arc::new(FakeMesh::default());
    let api = start_api(Some(mesh.clone())).await;
    let (_, _, status) = call(api, "GET", "/v1/status", None).await;
    assert!(!features(&status).contains(&"mesh_paths".to_owned()));

    let body = json!({"networks": [network("mesh-cn", "mesh-cn", "10.150.0.5/16")]});
    let (status, _, before) = call(api, "PUT", "/v1/mesh", Some(body)).await;
    assert_eq!(status, 200, "{before}");

    // A valid body whose network carries a path: refused as a whole,
    // nothing reaches the mesh, the running network stays.
    let mut routed = network("mesh-cn", "mesh-cn", "10.150.0.5/16");
    routed["routing"]["paths"] = json!([{"to_peer": "10.150.0.7", "via": ["10.150.0.3"]}]);
    let (status, raw, answer) =
        call(api, "PUT", "/v1/mesh", Some(json!({"networks": [routed]}))).await;
    assert_eq!(status, 400, "{answer}");
    assert!(
        answer["error"]
            .as_str()
            .unwrap()
            .starts_with("paths_disabled"),
        "{answer}"
    );
    assert!(!raw.contains(SECRET), "{raw}");
    // Relaying as a waypoint for others opens the same code: refused too.
    let mut relaying = network("mesh-cn", "mesh-cn", "10.150.0.5/16");
    relaying["node"]["waypoint_relay"] = json!(true);
    let (status, _, answer) = call(
        api,
        "PUT",
        "/v1/mesh",
        Some(json!({"networks": [relaying]})),
    )
    .await;
    assert_eq!(status, 400, "{answer}");
    assert!(
        answer["error"]
            .as_str()
            .unwrap()
            .starts_with("paths_disabled: node.waypoint_relay"),
        "{answer}"
    );
    assert_eq!(mesh.applied.lock().unwrap().len(), 1);
    let (status, _, after) = call(api, "GET", "/v1/mesh", None).await;
    assert_eq!(status, 200);
    assert_eq!(after, before);
}
