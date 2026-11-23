//! Node ids keep naming the same server across subscription refreshes:
//! reordering, inserting or renaming entries never moves an id to another
//! node (docs/architecture/subscription-node-ids.md).

use base64::Engine as _;
use config_core::{node_id, CoreSubscriptionService};
use control_domain::{
    NodeDescriptor, RawSubscription, SubscriptionDocument, SubscriptionService, NODE_METADATA_VIA,
};

/// One Shadowsocks entry: name, server, password.
type Entry<'a> = (&'a str, &'a str, &'a str);

fn parse(content: &str) -> SubscriptionDocument {
    CoreSubscriptionService::new()
        .parse(&RawSubscription {
            source_id: "node-ids".to_string(),
            content: content.to_string(),
        })
        .unwrap_or_else(|error| panic!("should parse: {error:?}\n{content}"))
}

fn clash(entries: &[Entry]) -> String {
    let mut text = String::from("proxies:\n");
    for (name, host, password) in entries {
        text.push_str(&format!(
            "  - name: \"{name}\"\n    type: ss\n    server: {host}\n    port: 8388\n    cipher: aes-256-gcm\n    password: \"{password}\"\n"
        ));
    }
    text
}

fn surge(entries: &[Entry]) -> String {
    let mut text = String::from("[Proxy]\n");
    for (name, host, password) in entries {
        text.push_str(&format!(
            "{name} = ss, {host}, 8388, encrypt-method=aes-256-gcm, password={password}\n"
        ));
    }
    text
}

fn loon(entries: &[Entry]) -> String {
    let mut text = String::from("[Proxy]\n");
    for (name, host, password) in entries {
        text.push_str(&format!(
            "{name} = Shadowsocks, {host}, 8388, aes-256-gcm, \"{password}\"\n"
        ));
    }
    text
}

fn quantumult_x(entries: &[Entry]) -> String {
    let mut text = String::from("[server_local]\n");
    for (name, host, password) in entries {
        text.push_str(&format!(
            "shadowsocks={host}:8388, method=aes-256-gcm, password=\"{password}\", tag={name}\n"
        ));
    }
    text
}

fn sing_box(entries: &[Entry]) -> String {
    let outbounds = entries
        .iter()
        .map(|(name, host, password)| {
            serde_json::json!({
                "type": "shadowsocks",
                "tag": name,
                "server": host,
                "server_port": 8388,
                "method": "aes-256-gcm",
                "password": password,
            })
        })
        .collect::<Vec<_>>();
    serde_json::json!({ "outbounds": outbounds }).to_string()
}

fn share_links(entries: &[Entry]) -> String {
    entries
        .iter()
        .map(|(name, host, password)| {
            let userinfo = base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(format!("aes-256-gcm:{password}"));
            format!("ss://{userinfo}@{host}:8388#{}", percent_encode(name))
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn percent_encode(value: &str) -> String {
    value
        .bytes()
        .map(|byte| {
            if byte.is_ascii_alphanumeric() {
                (byte as char).to_string()
            } else {
                format!("%{byte:02X}")
            }
        })
        .collect()
}

const FORMATS: &[(&str, fn(&[Entry]) -> String)] = &[
    ("clash", clash),
    ("surge", surge),
    ("loon", loon),
    ("quantumult x", quantumult_x),
    ("sing-box", sing_box),
    ("share links", share_links),
];

fn id_for_host<'a>(document: &'a SubscriptionDocument, host: &str) -> &'a str {
    let nodes = document
        .nodes
        .iter()
        .filter(|node| node.endpoint.host == host)
        .collect::<Vec<_>>();
    assert_eq!(nodes.len(), 1, "{host}: {:?}", document.nodes);
    &nodes[0].id
}

fn assert_outbound_id(id: &str) {
    assert!((1..=128).contains(&id.len()), "{id}");
    assert!(
        id.bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-')),
        "{id}"
    );
}

#[test]
fn reordering_inserting_and_renaming_keep_ids_in_every_format() {
    let first: &[Entry] = &[
        ("🇭🇰 香港 01", "hk.example.test", "hk-secret"),
        ("🇯🇵 日本 01", "jp.example.test", "jp-secret"),
    ];
    // A node inserted at the top, and the others swapped.
    let reordered: &[Entry] = &[
        ("🇸🇬 新加坡 01", "sg.example.test", "sg-secret"),
        ("🇯🇵 日本 01", "jp.example.test", "jp-secret"),
        ("🇭🇰 香港 01", "hk.example.test", "hk-secret"),
    ];
    let renamed: &[Entry] = &[
        ("HK Premium", "hk.example.test", "hk-secret"),
        ("JP Premium", "jp.example.test", "jp-secret"),
    ];
    for (format, render) in FORMATS {
        let first = parse(&render(first));
        let reordered = parse(&render(reordered));
        let renamed = parse(&render(renamed));
        assert_eq!(first.nodes.len(), 2, "{format}");
        assert_eq!(reordered.nodes.len(), 3, "{format}");

        let hk = id_for_host(&first, "hk.example.test");
        let jp = id_for_host(&first, "jp.example.test");
        assert_ne!(hk, jp, "{format}");
        for document in [&reordered, &renamed] {
            assert_eq!(id_for_host(document, "hk.example.test"), hk, "{format}");
            assert_eq!(id_for_host(document, "jp.example.test"), jp, "{format}");
        }
        assert_ne!(id_for_host(&reordered, "sg.example.test"), hk, "{format}");
        for node in first.nodes.iter().chain(&reordered.nodes) {
            assert_outbound_id(&node.id);
            assert!(!node.id.contains("secret"), "{format}: {}", node.id);
            assert!(node_id::legacy_node_id(node).is_some(), "{format}");
        }
    }
}

#[test]
fn the_same_server_gets_the_same_id_from_every_format() {
    let entries: &[Entry] = &[("HK", "hk.example.test", "hk-secret")];
    let ids = FORMATS
        .iter()
        .map(|(_, render)| parse(&render(entries)).nodes[0].id.clone())
        .collect::<Vec<_>>();
    assert!(ids.iter().all(|id| *id == ids[0]), "{ids:?}");
    assert!(ids[0].starts_with("ss-hk-example-test-8388-"), "{ids:?}");
}

#[test]
fn different_nodes_with_the_same_name_get_different_ids() {
    // Names that only differ outside ASCII used to collapse into one id.
    let document = parse(&clash(&[
        ("🇭🇰 香港 01", "hk.example.test", "hk-secret"),
        ("🇯🇵 日本 01", "jp.example.test", "jp-secret"),
        ("香港", "hk2.example.test", "hk2-secret"),
        ("香港", "hk3.example.test", "hk3-secret"),
    ]));
    let ids = document
        .nodes
        .iter()
        .map(|node| node.id.as_str())
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(ids.len(), 4, "{:?}", document.nodes);
}

#[test]
fn nodes_on_one_server_differ_by_credential_hash_and_duplicates_by_count() {
    let entries: &[Entry] = &[
        ("A", "shared.example.test", "a-secret"),
        ("B", "shared.example.test", "b-secret"),
        ("A copy", "shared.example.test", "a-secret"),
    ];
    let document = parse(&clash(entries));
    let ids = document
        .nodes
        .iter()
        .map(|node| node.id.clone())
        .collect::<Vec<_>>();
    assert_ne!(ids[0], ids[1]);
    assert_eq!(ids[2], format!("{}-2", ids[0]));
    let base = ids[0].rsplit_once('-').unwrap().0;
    assert!(ids[1].starts_with(&format!("{base}-")), "{ids:?}");
    let credential = ids[0].rsplit_once('-').unwrap().1;
    assert_eq!(credential.len(), node_id::CREDENTIAL_HASH_HEX, "{ids:?}");
    for id in &ids {
        assert!(!id.contains("secret"), "{id}");
        assert_outbound_id(id);
    }

    // Swapping the two servers keeps both ids.
    let swapped = parse(&clash(&[entries[1], entries[0]]));
    let by_name = |name: &str| {
        swapped
            .nodes
            .iter()
            .find(|node| node.name == name)
            .unwrap()
            .id
            .clone()
    };
    assert_eq!(by_name("A"), ids[0]);
    assert_eq!(by_name("B"), ids[1]);

    // A server alone on its host and port keeps its id when the provider
    // rotates its password.
    let rotated = parse(&clash(&[("A", "shared.example.test", "rotated")]));
    let alone = parse(&clash(&[("A", "shared.example.test", "a-secret")]));
    assert_eq!(rotated.nodes[0].id, alone.nodes[0].id);
}

#[test]
fn previous_ids_are_kept_for_migrating_saved_selections() {
    let document = parse(&clash(&[
        ("🇭🇰 香港 01", "hk.example.test", "hk-secret"),
        ("🇯🇵 日本 01", "jp.example.test", "jp-secret"),
        ("日本标准", "jp2.example.test", "jp2-secret"),
    ]));
    let legacy = document
        .nodes
        .iter()
        .map(|node| node_id::legacy_node_id(node).unwrap())
        .collect::<Vec<_>>();
    assert_eq!(legacy, ["clash-ss-01", "clash-ss-01-2", "clash-ss-node"]);

    let japan = node_id::find_node(&document.nodes, "clash-ss-01-2").unwrap();
    assert_eq!(japan.name, "🇯🇵 日本 01");
    let current = japan.id.clone();
    assert_eq!(
        node_id::find_node(&document.nodes, &current).map(|node| node.name.as_str()),
        Some("🇯🇵 日本 01")
    );
    assert!(node_id::find_node(&document.nodes, "clash-ss-missing").is_none());
    assert!(node_id::find_node(&document.nodes, "").is_none());
}

#[test]
fn current_ids_win_over_previous_ones() {
    let mut nodes: Vec<NodeDescriptor> =
        parse(&clash(&[("HK", "hk.example.test", "hk-secret")])).nodes;
    let mut other = nodes[0].clone();
    other.name = "Other".to_string();
    other.id = node_id::legacy_node_id(&nodes[0]).unwrap().to_string();
    nodes.insert(0, other);
    // `nodes[1]` still carries that id as its previous one; the node whose
    // current id it is wins.
    let found = node_id::find_node(&nodes, "clash-ss-hk").unwrap();
    assert_eq!(found.name, "Other");
}

#[test]
fn long_hosts_still_give_valid_outbound_ids() {
    let host = format!("{}.example.test", "a".repeat(200));
    let document = parse(&clash(&[("Long", &host, "secret")]));
    let id = &document.nodes[0].id;
    assert_outbound_id(id);
    assert!(id.len() <= 80, "{id}");
}

#[test]
fn chained_node_ids_survive_renaming_the_node_they_connect_through() {
    let render = |upstream: &str| {
        serde_json::json!({ "outbounds": [
            {
                "type": "shadowsocks", "tag": upstream, "server": "line.example.test",
                "server_port": 8388, "method": "aes-256-gcm", "password": "line-secret",
            },
            {
                "type": "shadowsocks", "tag": "Land", "server": "land.example.test",
                "server_port": 8388, "method": "aes-256-gcm", "password": "land-secret",
                "detour": upstream,
            },
            {
                "type": "shadowsocks", "tag": "Land direct", "server": "land.example.test",
                "server_port": 8388, "method": "aes-256-gcm", "password": "land-secret",
            },
        ]})
        .to_string()
    };
    let first = parse(&render("Line"));
    let renamed = parse(&render("Line 2"));
    let land = |document: &SubscriptionDocument, name: &str| {
        document
            .nodes
            .iter()
            .find(|node| node.name == name)
            .unwrap()
            .clone()
    };
    assert_eq!(land(&first, "Land").id, land(&renamed, "Land").id);
    // Going through another node is another path, not a duplicate.
    assert_ne!(land(&first, "Land").id, land(&first, "Land direct").id);
    assert!(!land(&first, "Land direct").id.ends_with("-2"));
    // The chain points at the upstream node's final id.
    let via = land(&first, "Land")
        .metadata
        .iter()
        .find(|entry| entry.key == NODE_METADATA_VIA)
        .map(|entry| entry.value.clone());
    assert_eq!(via, Some(land(&first, "Line").id));
}
