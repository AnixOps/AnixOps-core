//! Subscription nodes to config envelope: supported protocols produce entries
//! the registry accepts, unsupported ones are named without their secrets.

#![cfg(all(feature = "shadowsocks", feature = "trojan", feature = "vless"))]

use std::sync::Arc;

use config_core::routing::{PolicyGroupSpec, RoutingSpec};
use config_core::routing_import::ImportedRuleSet;
use control_domain::{Endpoint, MetadataEntry, NodeDescriptor, Protocol, NODE_METADATA_LEGACY_ID};
use engine_embedded::config::RuntimeConfig;
use engine_embedded::nodes::{
    outbound_for_node, routing_envelope, routing_envelope_with_sets, single_node_envelope,
};
use engine_embedded::protocols::default_registry;
use engine_outbound::TcpDialer;

fn node(id: &str, protocol: Protocol, metadata: &[(&str, &str)]) -> NodeDescriptor {
    NodeDescriptor {
        id: id.to_string(),
        name: id.to_string(),
        protocol,
        endpoint: Endpoint {
            host: "192.0.2.1".to_string(),
            port: 443,
        },
        tags: Vec::new(),
        metadata: metadata
            .iter()
            .map(|(key, value)| MetadataEntry {
                key: key.to_string(),
                value: value.to_string(),
            })
            .collect(),
    }
}

fn ss2022() -> NodeDescriptor {
    node(
        "ss",
        Protocol::Shadowsocks,
        &[
            ("shadowsocks.method", "2022-blake3-aes-128-gcm"),
            ("shadowsocks.password", "AAECAwQFBgcICQoLDA0ODw=="),
        ],
    )
}

fn ss_aead() -> NodeDescriptor {
    node(
        "ss-aead",
        Protocol::Shadowsocks,
        &[
            ("shadowsocks.method", "chacha20-ietf-poly1305"),
            ("shadowsocks.password", "plain-password"),
        ],
    )
}

fn vless_reality() -> NodeDescriptor {
    node(
        "vless",
        Protocol::Vless,
        &[
            ("vless.uuid", "b831381d-6324-4d53-ad4f-8cda48b30811"),
            ("vless.flow", "xtls-rprx-vision"),
            ("tls.server_name", "www.example.com"),
            (
                "tls.reality.public_key",
                "Z84J2IelR9ch3k8VtlVhhs5ycBUlXA7wHBWcBrjqnAw",
            ),
            ("tls.reality.short_id", "6ba85179e30d4fc2"),
            ("tls.utls.fingerprint", "firefox"),
        ],
    )
}

fn trojan() -> NodeDescriptor {
    node(
        "trojan",
        Protocol::Trojan,
        &[
            ("trojan.password", "trojan-secret"),
            ("tls.server_name", "edge.example.com"),
            ("tls.insecure", "true"),
            ("tls.alpn", "h2, http/1.1"),
        ],
    )
}

fn builds(envelope: &str) -> &'static str {
    let config = RuntimeConfig::from_json(envelope.as_bytes()).expect("envelope is valid");
    config
        .build_outbound(&default_registry(), Arc::new(TcpDialer))
        .expect("registry accepts the outbound")
        .protocol()
}

#[test]
fn supported_nodes_become_registry_outbounds() {
    for (node, protocol) in [
        (ss2022(), "shadowsocks-2022"),
        (ss_aead(), "shadowsocks"),
        (vless_reality(), "vless"),
        (trojan(), "trojan"),
    ] {
        let (envelope, chosen) =
            single_node_envelope("p", std::slice::from_ref(&node), None).unwrap();
        assert_eq!(chosen.id, node.id);
        assert_eq!(builds(&envelope), protocol);
    }
    let trojan = outbound_for_node(&trojan()).unwrap();
    assert_eq!(trojan["alpn"], serde_json::json!(["h2", "http/1.1"]));
    assert_eq!(trojan["insecure"], true);
}

#[test]
fn trojan_websocket_nodes_carry_path_and_host() {
    let trojan_ws = node(
        "trojan-ws",
        Protocol::Trojan,
        &[
            ("trojan.password", "secret"),
            ("tls.server_name", "cdn.example"),
            ("v2ray.transport.type", "ws"),
            ("v2ray.transport.path", "/ws"),
            ("v2ray.transport.host", "front.example"),
        ],
    );
    let outbound = outbound_for_node(&trojan_ws).unwrap();
    assert_eq!(
        outbound["transport"],
        serde_json::json!({"type": "ws", "path": "/ws", "host": "front.example"})
    );
    let (envelope, _) = single_node_envelope("p", &[trojan_ws], None).unwrap();
    assert_eq!(builds(&envelope), "trojan");

    let trojan_grpc = node(
        "trojan-grpc",
        Protocol::Trojan,
        &[
            ("trojan.password", "secret"),
            ("v2ray.transport.type", "grpc"),
            ("v2ray.transport.service_name", "TunService"),
        ],
    );
    let outbound = outbound_for_node(&trojan_grpc).unwrap();
    assert_eq!(
        outbound["transport"],
        serde_json::json!({"type": "grpc", "service_name": "TunService"})
    );
    let (envelope, _) = single_node_envelope("p", &[trojan_grpc], None).unwrap();
    assert_eq!(builds(&envelope), "trojan");

    for transport in [
        &[("v2ray.transport.type", "grpc")][..],
        &[("v2ray.transport.type", "h2")],
    ] {
        let mut metadata = vec![("trojan.password", "secret")];
        metadata.extend_from_slice(transport);
        let unsupported = node("trojan-unsupported", Protocol::Trojan, &metadata);
        assert!(outbound_for_node(&unsupported).is_err());
    }
}

#[test]
fn vless_tls_and_websocket_nodes_map_to_the_standard_outbound() {
    let vless_ws_tls = node(
        "vless-ws",
        Protocol::Vless,
        &[
            ("vless.uuid", "b831381d-6324-4d53-ad4f-8cda48b30811"),
            ("tls.enabled", "true"),
            ("tls.server_name", "cdn.example"),
            ("tls.alpn", "http/1.1"),
            ("v2ray.transport.type", "ws"),
            ("v2ray.transport.path", "/vl"),
        ],
    );
    let outbound = outbound_for_node(&vless_ws_tls).unwrap();
    assert_eq!(outbound["tls"]["server_name"], "cdn.example");
    assert_eq!(outbound["tls"]["alpn"], serde_json::json!(["http/1.1"]));
    assert_eq!(outbound["transport"]["path"], "/vl");
    assert!(outbound.get("reality").is_none());
    let (envelope, _) = single_node_envelope("p", &[vless_ws_tls], None).unwrap();
    assert_eq!(builds(&envelope), "vless");

    let vless_plain = node(
        "vless-plain",
        Protocol::Vless,
        &[
            ("vless.uuid", "b831381d-6324-4d53-ad4f-8cda48b30811"),
            ("tls.enabled", "false"),
        ],
    );
    let outbound = outbound_for_node(&vless_plain).unwrap();
    assert!(outbound["tls"].is_null());
    let (envelope, _) = single_node_envelope("p", &[vless_plain], None).unwrap();
    assert_eq!(builds(&envelope), "vless");

    let vision_tls = node(
        "vision-tls",
        Protocol::Vless,
        &[
            ("vless.uuid", "b831381d-6324-4d53-ad4f-8cda48b30811"),
            ("vless.flow", "xtls-rprx-vision"),
            ("tls.enabled", "true"),
        ],
    );
    assert!(outbound_for_node(&vision_tls).is_err());
}

#[cfg(feature = "vmess")]
#[test]
fn vmess_nodes_map_security_tls_and_websocket() {
    let vmess_ws_tls = node(
        "vmess-ws",
        Protocol::Vmess,
        &[
            ("vmess.uuid", "b831381d-6324-4d53-ad4f-8cda48b30811"),
            ("vmess.security", "chacha20-poly1305"),
            ("vmess.alter_id", "0"),
            ("tls.enabled", "true"),
            ("tls.server_name", "cdn.example"),
            ("v2ray.transport.type", "ws"),
            ("v2ray.transport.path", "/vm"),
        ],
    );
    let outbound = outbound_for_node(&vmess_ws_tls).unwrap();
    assert_eq!(outbound["security"], "chacha20-poly1305");
    assert_eq!(outbound["tls"]["server_name"], "cdn.example");
    assert_eq!(outbound["transport"]["path"], "/vm");
    let (envelope, _) = single_node_envelope("p", &[vmess_ws_tls], None).unwrap();
    assert_eq!(builds(&envelope), "vmess");

    let vmess_plain = node(
        "vmess-plain",
        Protocol::Vmess,
        &[("vmess.uuid", "b831381d-6324-4d53-ad4f-8cda48b30811")],
    );
    let outbound = outbound_for_node(&vmess_plain).unwrap();
    assert_eq!(outbound["security"], "auto");
    assert!(outbound["tls"].is_null());
    let (envelope, _) = single_node_envelope("p", &[vmess_plain], None).unwrap();
    assert_eq!(builds(&envelope), "vmess");

    for (key, value) in [("vmess.alter_id", "64"), ("vmess.security", "none")] {
        let unsupported = node(
            "vmess-legacy",
            Protocol::Vmess,
            &[
                ("vmess.uuid", "b831381d-6324-4d53-ad4f-8cda48b30811"),
                (key, value),
            ],
        );
        assert!(outbound_for_node(&unsupported).is_err(), "{key}={value}");
    }
}

#[cfg(feature = "hysteria2")]
#[test]
fn hysteria2_nodes_map_password_and_tls() {
    let hy2 = node(
        "hy2",
        Protocol::Hysteria2,
        &[
            ("hysteria2.password", "hy2-secret"),
            ("hysteria2.server_ports", "20000-30000"),
            ("tls.server_name", "hy2.example"),
            ("tls.insecure", "true"),
        ],
    );
    let outbound = outbound_for_node(&hy2).unwrap();
    assert_eq!(
        outbound,
        serde_json::json!({
            "type": "hysteria2",
            "server": "192.0.2.1",
            "port": 443,
            "password": "hy2-secret",
            "server_name": "hy2.example",
            "alpn": [],
            "insecure": true,
            "obfs": null,
        })
    );
    let (envelope, _) = single_node_envelope("p", &[hy2], None).unwrap();
    assert_eq!(builds(&envelope), "hysteria2");

    let missing = node("hy2-missing", Protocol::Hysteria2, &[]);
    assert!(outbound_for_node(&missing).is_err());
}

#[cfg(feature = "mieru")]
#[test]
fn mieru_nodes_map_credentials_and_port_range() {
    let mieru = node(
        "mieru",
        Protocol::Mieru,
        &[
            ("mieru.username", "alice"),
            ("mieru.password", "mieru-secret"),
            ("mieru.transport", "TCP"),
            ("mieru.port_range", "443-445"),
            ("mieru.multiplexing", "true"),
        ],
    );
    let outbound = outbound_for_node(&mieru).unwrap();
    assert_eq!(
        outbound,
        serde_json::json!({
            "type": "mieru",
            "server": "192.0.2.1",
            "port": 443,
            "username": "alice",
            "password": "mieru-secret",
            "port_range": "443-445",
            "transport": "TCP",
        })
    );
    let (envelope, _) = single_node_envelope("p", &[mieru], None).unwrap();
    assert_eq!(builds(&envelope), "mieru");

    let udp = node(
        "mieru-udp",
        Protocol::Mieru,
        &[
            ("mieru.username", "alice"),
            ("mieru.password", "mieru-secret"),
            ("mieru.transport", "UDP"),
        ],
    );
    assert_eq!(
        outbound_for_node(&udp).unwrap_err(),
        "mieru udp transport is not implemented yet"
    );
    let missing = node(
        "mieru-missing",
        Protocol::Mieru,
        &[("mieru.username", "alice")],
    );
    assert!(outbound_for_node(&missing).is_err());
}

#[cfg(feature = "snell")]
#[test]
fn snell_nodes_map_psk_version_and_obfs() {
    let snell = node(
        "snell",
        Protocol::Snell,
        &[
            ("snell.psk", "snell-secret"),
            ("snell.version", "4"),
            ("snell.obfs", "http"),
            ("snell.obfs_host", "cdn.example"),
            ("snell.reuse", "true"),
        ],
    );
    let outbound = outbound_for_node(&snell).unwrap();
    assert_eq!(
        outbound,
        serde_json::json!({
            "type": "snell",
            "server": "192.0.2.1",
            "port": 443,
            "psk": "snell-secret",
            "version": 4,
            "mode": "default",
            "obfs": "http",
            "obfs_host": "cdn.example",
            "obfs_uri": null,
            "reuse": true,
            "userkey": null,
        })
    );
    let (envelope, _) = single_node_envelope("p", &[snell], None).unwrap();
    assert_eq!(builds(&envelope), "snell");

    let v6_obfs = node(
        "snell-v6",
        Protocol::Snell,
        &[
            ("snell.psk", "snell-secret"),
            ("snell.version", "6"),
            ("snell.obfs", "http"),
        ],
    );
    assert!(outbound_for_node(&v6_obfs).is_err());
}

#[cfg(feature = "tuic")]
#[test]
fn tuic_nodes_map_uuid_password_and_congestion() {
    let tuic = node(
        "tuic",
        Protocol::Tuic,
        &[
            ("tuic.uuid", "b831381d-6324-4d53-ad4f-8cda48b30811"),
            ("tuic.password", "tuic-secret"),
            ("tuic.congestion_control", "bbr"),
            ("tls.server_name", "tuic.example"),
            ("tls.alpn", "h3"),
        ],
    );
    let outbound = outbound_for_node(&tuic).unwrap();
    assert_eq!(
        outbound,
        serde_json::json!({
            "type": "tuic",
            "server": "192.0.2.1",
            "port": 443,
            "uuid": "b831381d-6324-4d53-ad4f-8cda48b30811",
            "password": "tuic-secret",
            "server_name": "tuic.example",
            "alpn": ["h3"],
            "insecure": false,
            "congestion_control": "bbr",
        })
    );
    let (envelope, _) = single_node_envelope("p", &[tuic], None).unwrap();
    assert_eq!(builds(&envelope), "tuic");

    let v4 = node(
        "tuic-v4",
        Protocol::Tuic,
        &[("tuic.uuid", "b831381d-6324-4d53-ad4f-8cda48b30811")],
    );
    assert!(outbound_for_node(&v4).is_err());
}

#[test]
fn unsupported_nodes_are_reported_without_secrets() {
    let legacy_ss = node(
        "legacy",
        Protocol::Shadowsocks,
        &[
            ("shadowsocks.method", "aes-256-cfb"),
            ("shadowsocks.password", "legacy-secret"),
        ],
    );
    let vless_h2 = node(
        "h2",
        Protocol::Vless,
        &[
            ("vless.uuid", "b831381d-6324-4d53-ad4f-8cda48b30811"),
            ("v2ray.transport.type", "h2"),
        ],
    );
    let hysteria2 = node(
        "hy2",
        Protocol::Hysteria2,
        &[
            ("hysteria2.password", "hy2-secret"),
            ("hysteria2.obfs.type", "gecko"),
            ("hysteria2.obfs.password", "obfs-secret"),
        ],
    );
    for node in [legacy_ss, vless_h2, hysteria2] {
        let reason = outbound_for_node(&node).unwrap_err();
        assert!(!reason.contains("secret"), "{reason}");
    }
}

fn ss_with_plugin() -> NodeDescriptor {
    node(
        "ss-obfs",
        Protocol::Shadowsocks,
        &[
            ("shadowsocks.method", "chacha20-ietf-poly1305"),
            ("shadowsocks.password", "plain-password"),
            ("shadowsocks.plugin", "obfs-local"),
        ],
    )
}

/// Without a selection the first node this build can run is used, so an
/// unsupported node at the top of a subscription does not fail the profile.
#[test]
fn unselected_envelope_skips_nodes_that_cannot_run() {
    let unsupported = ss_with_plugin();
    let reason = outbound_for_node(&unsupported).unwrap_err();

    let (envelope, chosen) =
        single_node_envelope("p", &[unsupported.clone(), trojan()], None).unwrap();
    assert_eq!(chosen.id, "trojan");
    assert_eq!(builds(&envelope), "trojan");

    // When nothing can run, the first node's reason is reported.
    assert_eq!(
        single_node_envelope("p", std::slice::from_ref(&unsupported), None).unwrap_err(),
        reason
    );
    assert!(single_node_envelope("p", &[], None).is_err());

    // An explicit selection is honoured even when it cannot run.
    assert_eq!(
        single_node_envelope("p", &[unsupported, trojan()], Some("ss-obfs")).unwrap_err(),
        reason
    );
}

/// A selection saved before stable node ids names the node by its previous
/// id; it still finds the node, which carries its current id to save.
#[test]
fn selection_saved_under_the_previous_id_finds_its_node() {
    let mut chosen_before = trojan();
    chosen_before.id = "trojan-edge-example-com-443-0123456789".to_string();
    chosen_before.metadata.push(MetadataEntry {
        key: NODE_METADATA_LEGACY_ID.to_string(),
        value: "clash-trojan-01-2".to_string(),
    });
    let mut other = ss2022();
    other.metadata.push(MetadataEntry {
        key: NODE_METADATA_LEGACY_ID.to_string(),
        value: "clash-ss-01".to_string(),
    });
    let nodes = [other, chosen_before];
    let (envelope, chosen) = single_node_envelope("p", &nodes, Some("clash-trojan-01-2")).unwrap();
    assert_eq!(chosen.id, "trojan-edge-example-com-443-0123456789");
    assert_eq!(builds(&envelope), "trojan");
    let (_, chosen) =
        single_node_envelope("p", &nodes, Some("trojan-edge-example-com-443-0123456789")).unwrap();
    assert_eq!(chosen.name, "trojan");
    assert!(single_node_envelope("p", &nodes, Some("clash-trojan-01-3")).is_err());
}

#[test]
fn selected_node_and_routing_envelopes() {
    let nodes = [ss2022(), vless_reality(), trojan()];
    let (_, chosen) = single_node_envelope("p", &nodes, Some("trojan")).unwrap();
    assert_eq!(chosen.id, "trojan");
    assert!(single_node_envelope("p", &nodes, Some("missing")).is_err());

    let spec = RoutingSpec {
        rules: vec![
            "DOMAIN-SUFFIX,example.org,trojan".to_string(),
            "FINAL,Proxy".to_string(),
        ],
        groups: vec![PolicyGroupSpec {
            id: "Proxy".to_string(),
            kind: "select".to_string(),
            members: vec!["ss".to_string(), "vless".to_string()],
            default: Some("vless".to_string()),
            url: None,
            interval_secs: None,
            tolerance_ms: None,
            ..PolicyGroupSpec::default()
        }],
    };
    let envelope = routing_envelope("p", &nodes, &spec).unwrap();
    assert_eq!(builds(&envelope), "routed");

    let with_unsupported = [
        ss2022(),
        node("hy1", Protocol::Hysteria, &[("hysteria.auth", "x")]),
    ];
    assert!(routing_envelope("p", &with_unsupported, &spec).is_err());
}

#[test]
fn routing_envelopes_carry_the_subscriptions_rule_sets() {
    let nodes = [ss2022(), trojan()];
    let spec = RoutingSpec {
        rules: vec![
            "RULE-SET,ads,REJECT".to_string(),
            "RULE-SET,LAN,DIRECT".to_string(),
            "FINAL,trojan".to_string(),
        ],
        groups: Vec::new(),
    };
    let sets = [ImportedRuleSet {
        id: "ads".to_string(),
        url: "https://lists.example/ads.list".to_string(),
        format: Some("domain"),
        interval_secs: Some(3600),
        via: None,
    }];
    let envelope: serde_json::Value =
        serde_json::from_str(&routing_envelope_with_sets("p", &nodes, &spec, &sets).unwrap())
            .unwrap();
    assert_eq!(
        envelope["routing"]["rule_sets"],
        serde_json::json!({"ads": {"url": "https://lists.example/ads.list", "format": "domain", "interval_secs": 3600}})
    );
    // Without sets the key is left out, as before.
    let plain: serde_json::Value =
        serde_json::from_str(&routing_envelope("p", &nodes, &spec).unwrap()).unwrap();
    assert!(plain["routing"].get("rule_sets").is_none());
    // The engine needs the set a rule names; LAN is built in.
    assert!(RuntimeConfig::from_json(plain.to_string().as_bytes())
        .and_then(|config| config
            .build_routed(&default_registry(), Arc::new(TcpDialer))
            .map(|_| ()))
        .is_err());
    #[cfg(feature = "local-proxy")]
    assert_eq!(
        builds(&routing_envelope_with_sets("p", &nodes, &spec, &sets).unwrap()),
        "routed"
    );
}

#[test]
fn vless_xhttp_nodes_build_with_their_extra_settings() {
    let vless_xhttp = node(
        "vless-xhttp",
        Protocol::Vless,
        &[
            ("vless.uuid", "b831381d-6324-4d53-ad4f-8cda48b30811"),
            ("tls.enabled", "true"),
            ("tls.server_name", "cdn.example"),
            ("v2ray.transport.type", "xhttp"),
            ("v2ray.transport.path", "/xh"),
            ("v2ray.transport.mode", "stream-up"),
            (
                "v2ray.transport.extra",
                r#"{"headers":{"X-Edge":"1"},"xPaddingBytes":"200-400","xmux":{"maxConcurrency":"16-32"}}"#,
            ),
        ],
    );
    let outbound = outbound_for_node(&vless_xhttp).unwrap();
    assert_eq!(
        outbound["transport"],
        serde_json::json!({
            "type": "xhttp", "path": "/xh", "host": "", "mode": "stream-up",
            "headers": {"X-Edge": "1"}, "x_padding_bytes": "200-400",
        })
    );
    let (envelope, _) = single_node_envelope("p", &[vless_xhttp], None).unwrap();
    assert_eq!(builds(&envelope), "vless");
}

/// Subscription pins reach every TLS and QUIC outbound the registry builds,
/// and a pin the engine cannot read fails the build instead of being
/// dropped.
#[test]
fn certificate_pins_reach_the_built_outbounds() {
    // A certificate digest in hex and a public key digest in base64, of the
    // same 32 bytes, so both lists show the same hex.
    const CERTIFICATE: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const PUBLIC_KEY: &str = "ASNFZ4mrze8BI0VniavN7wEjRWeJq83vASNFZ4mrze8=";
    const UUID: &str = "b831381d-6324-4d53-ad4f-8cda48b30811";
    let pinned = |id: &str, protocol: Protocol, own: &[(&str, &str)]| {
        let mut metadata = own.to_vec();
        metadata.extend([
            ("tls.insecure", "true"),
            ("tls.certificate_sha256", CERTIFICATE),
            ("tls.certificate_public_key_sha256", PUBLIC_KEY),
        ]);
        node(id, protocol, &metadata)
    };
    #[allow(unused_mut)]
    let mut nodes = vec![
        (
            "trojan",
            pinned("trojan", Protocol::Trojan, &[("trojan.password", "secret")]),
        ),
        (
            "vless",
            pinned(
                "vless",
                Protocol::Vless,
                &[("vless.uuid", UUID), ("tls.enabled", "true")],
            ),
        ),
    ];
    #[cfg(feature = "vmess")]
    nodes.push((
        "vmess",
        pinned(
            "vmess",
            Protocol::Vmess,
            &[("vmess.uuid", UUID), ("tls.enabled", "true")],
        ),
    ));
    #[cfg(feature = "hysteria2")]
    nodes.push((
        "hysteria2",
        pinned(
            "hysteria2",
            Protocol::Hysteria2,
            &[("hysteria2.password", "secret")],
        ),
    ));
    #[cfg(feature = "tuic")]
    nodes.push((
        "tuic",
        pinned(
            "tuic",
            Protocol::Tuic,
            &[("tuic.uuid", UUID), ("tuic.password", "secret")],
        ),
    ));

    for (protocol, node) in nodes {
        let outbound = outbound_for_node(&node).unwrap();
        // VLESS and VMess keep their TLS settings in `tls`, the others at
        // the top level.
        let tls = if outbound["tls"].is_object() {
            &outbound["tls"]
        } else {
            &outbound
        };
        assert_eq!(tls["insecure"], true, "{protocol}");
        assert_eq!(
            tls["pinned_certificate_sha256"],
            serde_json::json!([CERTIFICATE]),
            "{protocol}"
        );
        assert_eq!(
            tls["pinned_public_key_sha256"],
            serde_json::json!([CERTIFICATE]),
            "{protocol}"
        );
        let (envelope, _) = single_node_envelope("p", std::slice::from_ref(&node), None).unwrap();
        assert_eq!(builds(&envelope), protocol);

        let mut envelope: serde_json::Value = serde_json::from_str(&envelope).unwrap();
        let entry = if envelope["outbound"]["tls"].is_object() {
            &mut envelope["outbound"]["tls"]
        } else {
            &mut envelope["outbound"]
        };
        entry["pinned_certificate_sha256"] = serde_json::json!(["not a sha-256 digest"]);
        let config = RuntimeConfig::from_json(envelope.to_string().as_bytes()).unwrap();
        let message = match config.build_outbound(&default_registry(), Arc::new(TcpDialer)) {
            Ok(_) => panic!("{protocol} built with an unreadable pin"),
            Err(error) => error.message,
        };
        assert_eq!(message, format!("{protocol} certificate pins are invalid"));
    }
}

/// The nodes of subscription `text` as the client keeps them.
fn subscription_nodes(text: &str) -> Vec<NodeDescriptor> {
    use control_domain::{SubscriptionService, SubscriptionSource};
    let service = config_core::CoreSubscriptionService::new();
    let source = SubscriptionSource {
        id: "p".to_string(),
        location: format!("inline:{text}"),
    };
    let document = service
        .fetch(&source)
        .and_then(|raw| service.parse(&raw))
        .unwrap();
    service.normalize(&document).unwrap().nodes
}

const SUBSCRIPTION: &str = r#"
proxies:
  - { name: HK, type: ss, server: 192.0.2.1, port: 8388, cipher: rc4-md5, password: hk-secret }
  - { name: JP, type: trojan, server: jp.example.test, port: 443, password: jp-secret, sni: jp.example.test }
  - { name: Web, type: http, server: proxy.example.test, port: 8443, username: user, password: http-secret, tls: true }
  - { name: Socks, type: socks5, server: socks.example.test, port: 1080, username: user, password: socks-secret }
proxy-groups:
  - { name: Proxy, type: select, proxies: [HK, JP, Web, DIRECT] }
rules:
  - DOMAIN,hk.example.org,HK
  - DOMAIN,socks.example.org,Socks
  - MATCH,Proxy
"#;

#[cfg(all(feature = "http", feature = "socks"))]
#[test]
fn http_and_socks_nodes_become_registry_outbounds() {
    let nodes = subscription_nodes(SUBSCRIPTION);
    for (name, protocol) in [("Web", "http"), ("Socks", "socks")] {
        let node = nodes.iter().find(|node| node.name == name).unwrap();
        let (envelope, chosen) =
            single_node_envelope("p", std::slice::from_ref(node), None).unwrap();
        assert_eq!(chosen.id, node.id);
        assert_eq!(builds(&envelope), protocol, "{name}");
    }
}

#[cfg(all(feature = "http", feature = "socks"))]
#[test]
fn subscription_routing_leaves_out_only_the_nodes_that_cannot_run() {
    use engine_embedded::nodes::subscription_routing_envelope;

    let nodes = subscription_nodes(SUBSCRIPTION);
    let id = |name: &str| {
        nodes
            .iter()
            .find(|node| node.name == name)
            .unwrap()
            .id
            .clone()
    };
    let routing = subscription_routing_envelope("p", SUBSCRIPTION, &nodes, &nodes, None);
    let envelope = routing
        .envelope
        .clone()
        .expect("the nodes that run keep the rules");
    assert_eq!(builds(&envelope), "routed");
    let json: serde_json::Value = serde_json::from_str(&envelope).unwrap();
    let mut outbounds = json["routing"]["outbounds"]
        .as_object()
        .unwrap()
        .keys()
        .cloned()
        .collect::<Vec<_>>();
    outbounds.sort();
    let mut expected = vec![id("JP"), id("Web"), id("Socks")];
    expected.sort();
    assert_eq!(outbounds, expected);
    assert_eq!(
        json["routing"]["groups"][0]["members"],
        serde_json::json!([id("JP"), id("Web"), "DIRECT"])
    );
    assert_eq!(
        json["routing"]["rules"],
        serde_json::json!([
            format!("DOMAIN,socks.example.org,{}", id("Socks")),
            "FINAL,Proxy,dns-continue"
        ])
    );
    assert_eq!(
        routing.warnings[0],
        "1 node that cannot run was left out of the subscription's rules and policy groups"
    );
    let warnings = routing.warnings.join("\n");
    assert!(
        warnings.contains("policy group Proxy member HK was skipped"),
        "{warnings}"
    );
    assert!(
        warnings.contains("rule 0 was skipped: target HK was not imported"),
        "{warnings}"
    );
    assert!(!warnings.contains("secret"), "{warnings}");

    // The user's edits decide what runs: a node edited into one that cannot
    // run is left out too.
    let mut edited = nodes.clone();
    let socks = edited.iter_mut().find(|node| node.name == "Socks").unwrap();
    socks.metadata.retain(|entry| entry.key != "proxy.username");
    let routing = subscription_routing_envelope("p", SUBSCRIPTION, &nodes, &edited, None);
    let json: serde_json::Value =
        serde_json::from_str(routing.envelope.as_deref().unwrap()).unwrap();
    assert!(json["routing"]["outbounds"]
        .get(id("Socks").as_str())
        .is_none());
    assert_eq!(
        routing.warnings[0],
        "2 nodes that cannot run were left out of the subscription's rules and policy groups"
    );
}

#[test]
fn subscription_routing_beyond_the_outbound_limit_carries_the_named_and_selected_nodes() {
    use engine_embedded::nodes::subscription_routing_envelope;

    let mut text = String::from("proxies:\n");
    for index in 0..100 {
        text.push_str(&format!(
            "  - {{ name: N{index}, type: ss, server: 192.0.2.1, port: {}, cipher: aes-256-gcm, password: pw-{index} }}\n",
            10_000 + index
        ));
    }
    text.push_str("proxy-groups:\n  - { name: Proxy, type: select, proxies: [N0, N1, DIRECT] }\n");
    text.push_str("rules:\n  - DOMAIN,last.example.org,N99\n  - MATCH,Proxy\n");
    let nodes = subscription_nodes(&text);
    assert_eq!(nodes.len(), 100);
    let id = |name: &str| {
        nodes
            .iter()
            .find(|node| node.name == name)
            .unwrap()
            .id
            .clone()
    };

    let routing =
        subscription_routing_envelope("p", &text, &nodes, &nodes, Some(id("N50").as_str()));
    let envelope = routing.envelope.expect("the named nodes fit");
    assert_eq!(builds(&envelope), "routed");
    let json: serde_json::Value = serde_json::from_str(&envelope).unwrap();
    let mut outbounds = json["routing"]["outbounds"]
        .as_object()
        .unwrap()
        .keys()
        .cloned()
        .collect::<Vec<_>>();
    outbounds.sort();
    let mut expected = vec![id("N0"), id("N1"), id("N99"), id("N50")];
    expected.sort();
    assert_eq!(outbounds, expected);
    assert!(routing.warnings.is_empty(), "{:?}", routing.warnings);

    // A subscription without rules has no routing and nothing to say.
    let plain = "ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ@82.47.34.99:11111#HK\n";
    let plain_nodes = subscription_nodes(plain);
    let routing = subscription_routing_envelope("p", plain, &plain_nodes, &plain_nodes, None);
    assert!(routing.envelope.is_none());
    assert!(routing.warnings.is_empty());
}
