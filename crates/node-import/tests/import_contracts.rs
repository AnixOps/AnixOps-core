//! Subscription text to node list, through the Rust API and the C ABI the
//! iOS app calls.

use control_domain::{Endpoint, MetadataEntry, NodeDescriptor, Protocol};
use node_import::ffi::{
    networkcore_import_abi_version, networkcore_import_free_buffer, networkcore_import_nodes,
    NetworkCoreImportBuffer, NETWORKCORE_IMPORT_ABI_VERSION, NETWORKCORE_IMPORT_ERR_EMPTY,
    NETWORKCORE_IMPORT_ERR_INVALID_ARGUMENT, NETWORKCORE_IMPORT_ERR_UNRECOGNIZED,
    NETWORKCORE_IMPORT_OK,
};
use node_import::ffi::{networkcore_import_share_link, NETWORKCORE_IMPORT_ERR_UNSUPPORTED};
use node_import::{import_text, outbound_json, share_link, ImportError};

const LINKS: &str = "\
ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ@82.47.34.99:11111#HK
trojan://trojan-secret@example.com:443?sni=edge.example.com#HK%20Trojan
tuic://00000000-0000-0000-0000-000000000001:tuic%2Dpassword@tuic.example.test:443?sni=cdn.tuic.example.test&alpn=h3&congestion_control=bbr#TUIC%20Node
hysteria2://hy2-secret@edge.example.test:443?sni=cdn.example.test&obfs=gecko&obfs-password=mask-secret#Gecko
";

#[test]
fn links_become_outbounds_and_unsupported_nodes_keep_their_secrets() {
    let report = import_text(LINKS).unwrap();
    let protocols: Vec<_> = report
        .nodes
        .iter()
        .map(|node| node.protocol.as_str())
        .collect();
    assert_eq!(protocols, ["shadowsocks", "trojan", "tuic"]);
    let trojan = &report.nodes[1];
    assert_eq!(trojan.server, "example.com");
    assert_eq!(trojan.port, 443);
    assert_eq!(trojan.outbound["password"], "trojan-secret");
    assert_eq!(trojan.outbound["server_name"], "edge.example.com");

    assert_eq!(report.unsupported.len(), 1);
    assert_eq!(report.unsupported[0].protocol, "hysteria2");
    let unsupported = serde_json::to_string(&report.unsupported).unwrap();
    assert!(!unsupported.contains("secret"), "{unsupported}");
}

const CLASH: &str = r#"
proxies:
  - name: HK
    type: ss
    server: 82.47.34.99
    port: 11111
    cipher: aes-256-gcm
    password: hk-secret
  - name: JP
    type: trojan
    server: jp.example.com
    port: 443
    password: jp-secret
proxy-groups:
  - name: Proxy
    type: select
    proxies:
      - Auto
      - HK
      - DIRECT
  - name: Auto
    type: url-test
    proxies:
      - HK
      - JP
    url: http://www.gstatic.com/generate_204
    interval: 300
rules:
  - DOMAIN-SUFFIX,google.com,Proxy
  - DOMAIN,jp.example.org,JP
  - MATCH,Proxy
"#;

#[test]
fn clash_rules_and_groups_come_with_the_nodes() {
    let report = import_text(CLASH).unwrap();
    let ids: Vec<_> = report.nodes.iter().map(|node| node.id.as_str()).collect();
    assert_eq!(ids.len(), 2);
    let routing = report
        .routing
        .expect("every node runs, so routing is offered");
    let groups = routing["groups"].as_array().unwrap();
    let names: Vec<_> = groups
        .iter()
        .map(|group| group["id"].as_str().unwrap())
        .collect();
    assert_eq!(names, ["Proxy", "Auto"]);
    assert_eq!(groups[0]["type"], "select");
    assert_eq!(groups[1]["members"], serde_json::json!([ids[0], ids[1]]));
    let rules: Vec<_> = routing["rules"]
        .as_array()
        .unwrap()
        .iter()
        .map(|rule| rule.as_str().unwrap().to_string())
        .collect();
    assert!(
        rules
            .iter()
            .any(|rule| rule.ends_with(&format!(",{}", ids[1]))),
        "{rules:?}"
    );
    let text = serde_json::to_string(&routing).unwrap();
    assert!(!text.contains("secret"), "{text}");

    // Links carry no rules, and a subscription with an unsupported node offers none.
    assert!(import_text(LINKS).unwrap().routing.is_none());
    let with_unsupported = CLASH.replace("cipher: aes-256-gcm", "cipher: rc4-md5");
    let report = import_text(&with_unsupported).unwrap();
    assert!(report.routing.is_none());
}

#[test]
fn rules_left_out_of_the_import_are_reported() {
    let report = import_text(CLASH).unwrap();
    assert!(report.routing_warnings.is_empty());
    let json = serde_json::to_value(&report).unwrap();
    assert!(json.get("routing_warnings").is_none());

    let text = CLASH.replace(
        "  - MATCH,Proxy",
        "  - UID,501,Proxy\n  - UID,502,Proxy\n  - RULE-SET,SYSTEM,DIRECT\n  - MATCH,Proxy",
    );
    let report = import_text(&text).unwrap();
    assert!(report.routing.is_some());
    let warnings = report.routing_warnings.join("\n");
    assert!(warnings.contains("UID x2"), "{warnings}");
    assert!(warnings.contains("rule set SYSTEM"), "{warnings}");
    let json = serde_json::to_value(&report).unwrap();
    assert_eq!(
        json["routing_warnings"].as_array().map(Vec::len),
        Some(report.routing_warnings.len())
    );
}

#[test]
fn empty_and_unknown_text_are_rejected() {
    assert_eq!(import_text("  \n"), Err(ImportError::Empty));
    assert_eq!(
        import_text("this is not a subscription"),
        Err(ImportError::Unrecognized)
    );
}

fn call(text: &[u8]) -> (i32, Option<serde_json::Value>) {
    let mut out = NetworkCoreImportBuffer {
        ptr: std::ptr::null_mut(),
        len: 0,
        cap: 0,
    };
    // SAFETY: `text` is a live slice and `out` is writable.
    let code = unsafe { networkcore_import_nodes(text.as_ptr(), text.len(), &mut out) };
    let json = (code == NETWORKCORE_IMPORT_OK).then(|| {
        // SAFETY: on success the buffer holds `len` bytes of JSON.
        let bytes = unsafe { std::slice::from_raw_parts(out.ptr, out.len) };
        serde_json::from_slice(bytes).unwrap()
    });
    // SAFETY: released once, as returned.
    unsafe { networkcore_import_free_buffer(out) };
    (code, json)
}

#[test]
fn c_abi_returns_the_report_as_json_and_stable_codes() {
    assert_eq!(
        networkcore_import_abi_version(),
        NETWORKCORE_IMPORT_ABI_VERSION
    );
    let (code, json) = call(LINKS.as_bytes());
    assert_eq!(code, NETWORKCORE_IMPORT_OK);
    let json = json.unwrap();
    assert_eq!(json["nodes"].as_array().unwrap().len(), 3);
    assert_eq!(json["nodes"][0]["outbound"]["type"], "shadowsocks");
    assert_eq!(json["unsupported"][0]["protocol"], "hysteria2");

    assert_eq!(call(b"").0, NETWORKCORE_IMPORT_ERR_EMPTY);
    assert_eq!(
        call(&[0xff, 0xfe]).0,
        NETWORKCORE_IMPORT_ERR_INVALID_ARGUMENT
    );
    assert_eq!(call(b"garbage").0, NETWORKCORE_IMPORT_ERR_UNRECOGNIZED);
    // SAFETY: null output is rejected before anything is read or written.
    let code =
        unsafe { networkcore_import_nodes(LINKS.as_ptr(), LINKS.len(), std::ptr::null_mut()) };
    assert_eq!(code, NETWORKCORE_IMPORT_ERR_INVALID_ARGUMENT);
}

#[test]
fn header_declares_every_symbol_and_code() {
    let header = include_str!("../include/networkcore_import.h");
    for symbol in [
        "networkcore_import_abi_version",
        "networkcore_import_nodes",
        "networkcore_import_share_link",
        "networkcore_import_free_buffer",
    ] {
        assert!(header.contains(&format!("{symbol}(")), "{symbol}");
    }
    for (name, value) in [
        ("NETWORKCORE_IMPORT_OK", 0),
        ("NETWORKCORE_IMPORT_ERR_INVALID_ARGUMENT", 1),
        ("NETWORKCORE_IMPORT_ERR_EMPTY", 2),
        ("NETWORKCORE_IMPORT_ERR_TOO_LARGE", 3),
        ("NETWORKCORE_IMPORT_ERR_UNRECOGNIZED", 4),
        ("NETWORKCORE_IMPORT_ERR_PANIC_CAUGHT", 5),
        ("NETWORKCORE_IMPORT_ERR_INTERNAL_ERROR", 6),
        ("NETWORKCORE_IMPORT_ERR_UNSUPPORTED", 7),
    ] {
        let define = format!("#define {name} {value}");
        assert!(
            header.lines().any(|line| line.trim_end() == define),
            "{name}"
        );
    }
    assert!(header.contains(&format!(
        "#define NETWORKCORE_IMPORT_ABI_VERSION {NETWORKCORE_IMPORT_ABI_VERSION}u"
    )));
}

#[test]
fn surge_and_clash_snell_nodes_become_snell_outbounds() {
    let surge = "\
[Proxy]
Snell v4 = snell, snell.example.test, 8443, psk=snell-secret, version=4, obfs=http, obfs-host=cdn.example.test, reuse=true
Snell v6 = snell, 192.0.2.6, 9443, psk=snell-secret-6, version=6, mode=unshaped
Snell v1 = snell, 192.0.2.1, 1443, psk=snell-secret-1
Snell tls = snell, 192.0.2.3, 3443, psk=snell-secret-3, version=3, obfs=tls
";
    let report = import_text(surge).unwrap();
    assert_eq!(report.nodes.len(), 3);
    let v4 = &report.nodes[0].outbound;
    assert_eq!(v4["type"], "snell");
    assert_eq!(v4["server"], "snell.example.test");
    assert_eq!(v4["port"], 8443);
    assert_eq!(v4["psk"], "snell-secret");
    assert_eq!(v4["version"], 4);
    assert_eq!(v4["obfs"], "http");
    assert_eq!(v4["obfs_host"], "cdn.example.test");
    assert_eq!(v4["reuse"], true);
    let v6 = &report.nodes[1].outbound;
    assert_eq!(
        (v6["version"].as_u64(), v6["mode"].as_str()),
        (Some(6), Some("unshaped"))
    );
    assert!(v6["obfs"].is_null());
    // A missing version means 1.
    assert_eq!(report.nodes[2].outbound["version"], 1);
    assert_eq!(report.unsupported.len(), 1);
    assert_eq!(report.unsupported[0].protocol, "snell");
    assert_eq!(
        report.unsupported[0].reason,
        "snell tls obfs is not implemented yet"
    );
    let unsupported = serde_json::to_string(&report.unsupported).unwrap();
    assert!(!unsupported.contains("secret"), "{unsupported}");

    let clash = r#"
proxies:
  - name: Snell
    type: snell
    server: snell.example.test
    port: 8443
    psk: clash-snell-secret
    version: 3
    obfs-opts:
      mode: http
      host: bing.com
"#;
    let report = import_text(clash).unwrap();
    assert_eq!(report.nodes.len(), 1);
    let outbound = &report.nodes[0].outbound;
    assert_eq!(report.nodes[0].protocol, "snell");
    assert_eq!(outbound["psk"], "clash-snell-secret");
    assert_eq!(outbound["version"], 3);
    assert_eq!(outbound["obfs"], "http");
    assert_eq!(outbound["obfs_host"], "bing.com");
}

/// Imports `text`, exports every node and imports the links again: the
/// outbounds and names must come back unchanged.
fn assert_round_trip(text: &str) {
    let first = import_text(text).unwrap();
    assert!(!first.nodes.is_empty(), "{text}");
    for node in &first.nodes {
        let link = share_link(&node.name, &node.outbound).unwrap();
        let link_text = if node.protocol == "snell" {
            format!("[Proxy]\n{link}\n")
        } else {
            link.clone()
        };
        let again = import_text(&link_text).unwrap_or_else(|_| panic!("{link}"));
        assert_eq!(again.nodes.len(), 1, "{link}");
        assert_eq!(again.nodes[0].outbound, node.outbound, "{link}");
        assert_eq!(again.nodes[0].name, node.name, "{link}");
    }
}

#[test]
fn share_links_import_back_to_the_same_outbound() {
    assert_round_trip(
        "\
ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ@82.47.34.99:11111#HK%20%E9%A6%99%E6%B8%AF
ss://MjAyMi1ibGFrZTMtYWVzLTEyOC1nY206QUFBQUFBQUFBQUFBQUFBQUFBQUFBQT09@[2001:db8::7]:8388#SS%202022
trojan://trojan%2Fsecret@example.com:443?sni=edge.example.com&alpn=h2,http/1.1&allowInsecure=1&type=ws&path=%2Fws%3Fed%3D2048&host=cdn.example.com#Trojan%20WS
trojan://trojan-secret@example.com:443?sni=edge.example.com&type=xhttp&path=%2Fxh&mode=stream-up#Trojan%20XHTTP
vless://00000000-0000-0000-0000-000000000002@vless.example.test:443?encryption=none&security=reality&sni=www.example.com&pbk=PUBLICKEY&sid=ab12&fp=chrome&flow=xtls-rprx-vision&type=tcp#Reality
vless://00000000-0000-0000-0000-000000000003@vless.example.test:8443?encryption=none&security=tls&sni=grpc.example.test&type=grpc&serviceName=tunnel#VLESS%20gRPC
vless://00000000-0000-0000-0000-000000000004@192.0.2.4:80?encryption=none&security=none&type=tcp#Plain
vless://00000000-0000-0000-0000-000000000006@xh.example.test:443?encryption=none&security=tls&sni=cdn.example.test&alpn=h2&type=xhttp&path=%2Fxh&host=cdn.example.test&mode=stream-one&extra=%7B%22headers%22%3A%7B%22X-Edge%22%3A%221%22%7D%2C%22xPaddingBytes%22%3A%22200-400%22%2C%22noGRPCHeader%22%3Atrue%7D#VLESS%20XHTTP
tuic://00000000-0000-0000-0000-000000000001:tuic%2Dpassword@tuic.example.test:443?sni=cdn.tuic.example.test&alpn=h3&congestion_control=bbr#TUIC%20Node
hysteria2://hy2-secret@edge.example.test:443?sni=cdn.example.test&insecure=1&obfs=salamander&obfs-password=mask-secret#Hy2
",
    );
    // VMess over TLS with WebSocket, as a v2rayN link.
    let vmess = serde_json::json!({
        "v": "2", "ps": "VMess WS", "add": "vmess.example.test", "port": "443",
        "id": "00000000-0000-0000-0000-000000000005", "aid": "0", "scy": "aes-128-gcm",
        "net": "ws", "type": "none", "host": "cdn.example.test", "path": "/v",
        "tls": "tls", "sni": "cdn.example.test", "alpn": "h2"
    });
    let encoded = base64_standard(vmess.to_string().as_bytes());
    assert_round_trip(&format!("vmess://{encoded}"));
    // VMess over XHTTP with v2rayN-style `mode` and `extra`.
    let vmess = serde_json::json!({
        "v": "2", "ps": "VMess XHTTP", "add": "vmess.example.test", "port": "443",
        "id": "00000000-0000-0000-0000-000000000005", "aid": "0", "scy": "auto",
        "net": "xhttp", "type": "none", "host": "cdn.example.test", "path": "/xh",
        "mode": "packet-up", "extra": "{\"xPaddingBytes\":\"200-400\"}",
        "tls": "tls", "sni": "cdn.example.test"
    });
    let encoded = base64_standard(vmess.to_string().as_bytes());
    assert_round_trip(&format!("vmess://{encoded}"));
    assert_round_trip(
        "[Proxy]\nSnell v4 = snell, snell.example.test, 8443, psk=snell-secret, version=4, obfs=http, obfs-host=cdn.example.test, reuse=true\n",
    );
}

/// Test-side base64, independent of the exporter's.
fn base64_standard(bytes: &[u8]) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(char::from(ALPHABET[((n >> (18 - 6 * i)) & 63) as usize]));
            } else {
                out.push('=');
            }
        }
    }
    out
}

#[test]
fn share_links_are_refused_for_protocols_without_a_format() {
    let mieru = serde_json::json!({
        "type": "mieru", "server": "example.com", "port": 443,
        "username": "user", "password": "secret-pass", "transport": "TCP"
    });
    let error = share_link("M", &mieru).unwrap_err();
    assert!(!error.contains("secret"));
    assert!(share_link("X", &serde_json::json!({"type": "shadowsocks"})).is_err());
}

fn call_share_link(input: &[u8]) -> (i32, Option<String>) {
    let mut out = NetworkCoreImportBuffer {
        ptr: std::ptr::null_mut(),
        len: 0,
        cap: 0,
    };
    // SAFETY: valid input slice and output pointer.
    let code = unsafe { networkcore_import_share_link(input.as_ptr(), input.len(), &mut out) };
    let text = (code == NETWORKCORE_IMPORT_OK).then(|| {
        // SAFETY: the library returned `len` initialized bytes.
        let bytes = unsafe { std::slice::from_raw_parts(out.ptr, out.len) };
        String::from_utf8(bytes.to_vec()).unwrap()
    });
    // SAFETY: released once, as returned.
    unsafe { networkcore_import_free_buffer(out) };
    (code, text)
}

#[test]
fn c_abi_exports_share_links() {
    let report = import_text(LINKS).unwrap();
    let entry = serde_json::json!({
        "name": report.nodes[0].name,
        "outbound": report.nodes[0].outbound,
    });
    let (code, link) = call_share_link(entry.to_string().as_bytes());
    assert_eq!(code, NETWORKCORE_IMPORT_OK);
    let link = link.unwrap();
    assert!(link.starts_with("ss://"), "{link}");
    assert!(link.ends_with("#HK"), "{link}");

    assert_eq!(call_share_link(b"").0, NETWORKCORE_IMPORT_ERR_EMPTY);
    assert_eq!(
        call_share_link(b"not json").0,
        NETWORKCORE_IMPORT_ERR_INVALID_ARGUMENT
    );
    assert_eq!(
        call_share_link(br#"{"name":"x"}"#).0,
        NETWORKCORE_IMPORT_ERR_INVALID_ARGUMENT
    );
    assert_eq!(
        call_share_link(br#"{"name":"x","outbound":{"type":"mieru","server":"a","port":1}}"#).0,
        NETWORKCORE_IMPORT_ERR_UNSUPPORTED
    );
}

#[test]
fn clash_rule_providers_come_with_the_routing() {
    let text = r#"
proxies:
  - { name: HK 01, type: ss, server: 82.47.34.99, port: 11111, cipher: aes-256-gcm, password: f43c0eee-13b9-4f07-bec9-d4b744141503 }
proxy-groups:
  - { name: Proxy, type: select, proxies: [HK 01, DIRECT] }
rule-providers:
  listed:
    type: http
    behavior: domain
    url: https://rules.example/listed.txt
    interval: 86400
    proxy: Proxy
rules:
  - RULE-SET,listed,Proxy
  - GEOSITE,cn,DIRECT
  - MATCH,DIRECT
"#;
    let routing = import_text(text).unwrap().routing.unwrap();
    assert_eq!(
        routing["rules"],
        serde_json::json!(["RULE-SET,listed,Proxy", "GEOSITE,cn,DIRECT", "FINAL,DIRECT"])
    );
    assert_eq!(
        routing["rule_sets"],
        serde_json::json!({
            "listed": {
                "url": "https://rules.example/listed.txt",
                "format": "domain",
                "interval_secs": 86400,
                "via": "Proxy"
            }
        })
    );
    // Without remote sets the key is left out.
    let plain = text.replace(
        "RULE-SET,listed,Proxy",
        "DOMAIN-SUFFIX,listed.example,Proxy",
    );
    assert!(import_text(&plain).unwrap().routing.unwrap()["rule_sets"].is_null());
}

/// A `#anixops:pubkey=` mark on a list URL becomes the set's signing key and
/// leaves the URL the engine downloads.
#[test]
fn rule_set_public_key_mark_becomes_public_key() {
    let key = "11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=";
    let text = format!(
        r#"
proxies:
  - {{ name: HK 01, type: ss, server: 82.47.34.99, port: 11111, cipher: aes-256-gcm, password: f43c0eee-13b9-4f07-bec9-d4b744141503 }}
rule-providers:
  listed:
    type: http
    behavior: domain
    url: "https://rules.example/listed.txt#anixops:pubkey={key}"
rules:
  - RULE-SET,listed,HK 01
  - MATCH,DIRECT
"#
    );
    let routing = import_text(&text).unwrap().routing.unwrap();
    assert_eq!(
        routing["rule_sets"]["listed"]["url"],
        "https://rules.example/listed.txt"
    );
    assert_eq!(routing["rule_sets"]["listed"]["public_key"], key);
}

/// A land node behind a Panabit iWAN line, as the panel sends it to the App:
/// sing-box JSON with `detour`, and `iwan` as an AnixOps extension type.
const IWAN_LINE: &str = r#"{
  "outbounds": [
    {"type": "iwan", "tag": "HK line", "server": "203.0.113.10", "server_port": 4567,
     "username": "1001", "password": "iwan-secret", "mtu": 1400, "encrypt": true},
    {"type": "shadowsocks", "tag": "US land", "server": "198.51.100.20", "server_port": 8388,
     "method": "2022-blake3-aes-128-gcm", "password": "AAAAAAAAAAAAAAAAAAAAAA==", "detour": "HK line"},
    {"type": "shadowsocks", "tag": "JP land", "server": "198.51.100.30", "server_port": 8388,
     "method": "2022-blake3-aes-128-gcm", "password": "AAAAAAAAAAAAAAAAAAAAAA==", "detour": "missing"},
    {"type": "direct", "tag": "direct"}
  ]
}"#;

#[test]
fn sing_box_detour_becomes_via_and_iwan_nodes_import() {
    let report = import_text(IWAN_LINE).unwrap();
    let line = report
        .nodes
        .iter()
        .find(|node| node.name == "HK line")
        .expect("the iWAN line imports");
    assert_eq!(line.protocol, "iwan");
    assert_eq!(line.outbound["username"], "1001");
    assert_eq!(line.outbound["password"], "iwan-secret");
    assert_eq!(line.outbound["mtu"], 1400);
    assert_eq!(line.outbound["encrypt"], true);
    assert!(line.outbound.get("via").is_none());

    let land = report
        .nodes
        .iter()
        .find(|node| node.name == "US land")
        .expect("the land node imports");
    assert_eq!(land.outbound["via"], line.id.as_str());

    // A detour that names no imported node must not silently go direct.
    assert_eq!(report.unsupported.len(), 1);
    assert_eq!(report.unsupported[0].name, "JP land");
    let unsupported = serde_json::to_string(&report.unsupported).unwrap();
    assert!(!unsupported.contains("AAAA"), "{unsupported}");
}

#[test]
fn share_link_via_and_iwan_links_import() {
    let text = "iwan://shared%20user:p%40ss@203.0.113.10:4567?mtu=1400&encrypt=0#HK%20line\n\
        trojan://pw@198.51.100.20:443?security=tls&sni=land.example&via=HK%20line#US%20land\n\
        vmess://eyJ2IjoiMiIsInBzIjoiSlAgdm1lc3MiLCJhZGQiOiIxOTguNTEuMTAwLjQwIiwicG9ydCI6IjQ0MyIsImlkIjoiMDAwMDAwMDAtMDAwMC0wMDAwLTAwMDAtMDAwMDAwMDAwMDAxIiwiYWlkIjoiMCIsInNjeSI6ImF1dG8iLCJuZXQiOiJ0Y3AiLCJ0eXBlIjoibm9uZSIsInRscyI6IiJ9?via=HK%20line\n\
        trojan://pw@198.51.100.30:443?security=tls&via=missing#Lost\n\
        hysteria2://pw@198.51.100.50:443?sni=land.example&via=HK%20line#UDP%20land";
    let report = import_text(text).unwrap();
    let line = report
        .nodes
        .iter()
        .find(|node| node.name == "HK line")
        .expect("the iWAN link imports");
    assert_eq!(line.protocol, "iwan");
    assert_eq!(line.outbound["username"], "shared user");
    assert_eq!(line.outbound["password"], "p@ss");
    assert_eq!(line.outbound["mtu"], 1400);
    assert_eq!(line.outbound["encrypt"], false);

    let land = report
        .nodes
        .iter()
        .find(|node| node.name == "US land")
        .expect("the trojan link imports");
    assert_eq!(land.outbound["via"], line.id.as_str());
    // The via field is the importer's, not the protocol's.
    assert_eq!(land.outbound["server_name"], "land.example");
    let vmess = report
        .nodes
        .iter()
        .find(|node| node.name == "JP vmess")
        .expect("the vmess link imports");
    assert_eq!(vmess.outbound["via"], line.id.as_str());

    // Lost names no imported node; hysteria2 cannot ride another node.
    let names: Vec<_> = report
        .unsupported
        .iter()
        .map(|node| node.name.as_str())
        .collect();
    assert_eq!(names, ["Lost", "UDP land"]);
}

#[test]
fn a_node_behind_a_node_that_cannot_run_cannot_run_either() {
    let text = r#"{
  "outbounds": [
    {"type": "shadowsocks", "tag": "old", "server": "192.0.2.1", "server_port": 8388,
     "method": "rc4-md5", "password": "pw"},
    {"type": "shadowsocks", "tag": "behind", "server": "192.0.2.2", "server_port": 8388,
     "method": "aes-128-gcm", "password": "pw", "detour": "old"}
  ]
}"#;
    let report = import_text(text).unwrap();
    assert!(report.nodes.is_empty());
    let names: Vec<_> = report
        .unsupported
        .iter()
        .map(|node| node.name.as_str())
        .collect();
    assert_eq!(names, ["old", "behind"]);
}

#[test]
fn xhttp_links_keep_mode_and_client_extra_settings() {
    let report = import_text(
        "vless://00000000-0000-0000-0000-000000000006@xh.example.test:443?encryption=none&security=none&type=splithttp&path=%2Fxh&extra=%7B%22scMaxEachPostBytes%22%3A500000%2C%22xmux%22%3A%7B%22maxConcurrency%22%3A%2216-32%22%7D%7D#XH",
    )
    .unwrap();
    assert_eq!(
        report.nodes[0].outbound["transport"],
        serde_json::json!({
            "type": "xhttp", "path": "/xh", "host": "", "mode": "auto",
            "sc_max_each_post_bytes": 500000,
        })
    );
    let link = share_link("XH", &report.nodes[0].outbound).unwrap();
    assert!(link.contains("type=xhttp"), "{link}");
    assert!(!link.contains("xmux"), "{link}");

    // Split download servers and unknown modes are not carried.
    let report = import_text(
        "\
vless://00000000-0000-0000-0000-000000000006@a.example.test:443?security=tls&type=xhttp&extra=%7B%22downloadSettings%22%3A%7B%7D%7D#Split
vless://00000000-0000-0000-0000-000000000006@d.example.test:443?security=tls&type=xhttp&mode=stream-two#Mode
",
    )
    .unwrap();
    assert!(report.nodes.is_empty(), "{:?}", report.nodes);
    assert_eq!(report.unsupported.len(), 2);

    // XHTTP over REALITY; Vision does not run over XHTTP.
    let report = import_text(
        "\
vless://00000000-0000-0000-0000-000000000006@c.example.test:443?security=reality&sni=www.example.com&pbk=KEY&sid=ab12&type=xhttp&path=%2Fxh#Reality
vless://00000000-0000-0000-0000-000000000006@c.example.test:443?security=reality&sni=www.example.com&pbk=KEY&flow=xtls-rprx-vision&type=xhttp#Vision
",
    )
    .unwrap();
    assert_eq!(report.nodes.len(), 1);
    assert_eq!(report.unsupported.len(), 1);
    let outbound = &report.nodes[0].outbound;
    assert_eq!(outbound["reality"]["public_key"], "KEY");
    assert_eq!(outbound["transport"]["type"], "xhttp");
    // No `fp` in the link: the platform's own fingerprint, and none exported.
    assert_eq!(outbound["reality"]["fingerprint"], "auto");
    let link = share_link("Reality", outbound).unwrap();
    assert!(
        link.contains("security=reality") && link.contains("type=xhttp") && !link.contains("fp="),
        "{link}"
    );
    let again = import_text(&link).unwrap();
    assert_eq!(&again.nodes[0].outbound, outbound);

    // uTLS names: Safari and iOS map to the Safari fingerprint, Firefox and
    // Edge to their own, the rest to Chrome.
    for (fp, expected) in [
        ("ios", "safari"),
        ("Safari", "safari"),
        ("firefox", "firefox"),
        ("Edge", "edge"),
        ("android", "chrome"),
        ("randomized", "chrome"),
    ] {
        let report = import_text(&format!(
            "vless://00000000-0000-0000-0000-000000000006@c.example.test:443?security=reality&sni=www.example.com&pbk=KEY&sid=ab12&fp={fp}&flow=xtls-rprx-vision&type=tcp#R"
        ))
        .unwrap();
        assert_eq!(
            report.nodes[0].outbound["reality"]["fingerprint"], expected,
            "{fp}"
        );
    }
}

#[test]
fn anx_links_import_as_anx_outbounds() {
    let key = "ab".repeat(32);
    let text = format!(
        "anx://{key}@203.0.113.7:8443?sni=www.apple.com&pk=aa%3Abb&alpn=h2%2Chttp%2F1.1&fp=chrome#JP%20ANX"
    );
    let report = import_text(&text).unwrap();
    let node = report
        .nodes
        .iter()
        .find(|node| node.name == "JP ANX")
        .expect("the anx link imports");
    assert_eq!(node.protocol, "anx");
    assert_eq!(node.outbound["type"], "anx");
    assert_eq!(node.outbound["server"], "203.0.113.7");
    assert_eq!(node.outbound["port"], 8443);
    assert_eq!(node.outbound["server_name"], "www.apple.com");
    assert_eq!(node.outbound["public_key"], "aa:bb");
    assert_eq!(node.outbound["user_key"], key.as_str());
    assert_eq!(node.outbound["alpn"], serde_json::json!(["h2", "http/1.1"]));
    assert_eq!(node.outbound["fingerprint"], "chrome");
}

#[test]
fn anx_links_without_sni_import_without_server_name() {
    let key = "cd".repeat(32);
    let text = format!("anx://{key}@203.0.113.8:443?pk=aa%3Abb#No%20SNI");
    let report = import_text(&text).unwrap();
    let node = report
        .nodes
        .iter()
        .find(|node| node.name == "No SNI")
        .expect("an anx link without sni imports");
    assert_eq!(node.outbound["type"], "anx");
    assert_eq!(node.outbound["server"], "203.0.113.8");
    assert!(node.outbound.get("server_name").is_none());
}

#[test]
fn anx_links_carry_jacket_and_wg_port() {
    let key = "cd".repeat(32);
    let text = format!("anx://{key}@203.0.113.8:443?pk=aa%3Abb&jacket=wg&wg_port=51820#W1");
    let report = import_text(&text).unwrap();
    let node = report
        .nodes
        .iter()
        .find(|node| node.name == "W1")
        .expect("an anx link with jacket=wg imports");
    assert_eq!(node.outbound["jacket"], "wg");
    assert_eq!(node.outbound["wg_port"], 51820);

    let auto = format!("anx://{key}@203.0.113.8:443?pk=aa%3Abb&wg_port=51820#Auto");
    let report = import_text(&auto).unwrap();
    let node = report
        .nodes
        .iter()
        .find(|node| node.name == "Auto")
        .unwrap();
    assert!(node.outbound.get("jacket").is_none());
    assert_eq!(node.outbound["wg_port"], 51820);

    for bad in [
        "jacket=wg",
        "jacket=xx&wg_port=1",
        "wg_port=0",
        "wg_port=abc",
        "jacket=bare",
        "jacket=bare&wg_port=1",
        "bare_port=0",
        "bare_port=99999",
    ] {
        let text = format!("anx://{key}@203.0.113.8:443?pk=aa%3Abb&{bad}#Bad");
        let imported = import_text(&text)
            .map(|report| report.nodes.iter().any(|node| node.name == "Bad"))
            .unwrap_or(false);
        assert!(!imported, "{bad} must not import");
    }
}

#[test]
fn anx_links_carry_bare_port() {
    let key = "cd".repeat(32);
    let text = format!("anx://{key}@203.0.113.8:443?pk=aa%3Abb&jacket=bare&bare_port=8443#Bare");
    let report = import_text(&text).unwrap();
    let node = report
        .nodes
        .iter()
        .find(|node| node.name == "Bare")
        .expect("an anx link with jacket=bare imports");
    assert_eq!(node.outbound["jacket"], "bare");
    assert_eq!(node.outbound["bare_port"], 8443);

    let auto = format!("anx://{key}@203.0.113.8:443?pk=aa%3Abb&wg_port=51820&bare_port=8443#Both");
    let report = import_text(&auto).unwrap();
    let node = report
        .nodes
        .iter()
        .find(|node| node.name == "Both")
        .unwrap();
    assert!(node.outbound.get("jacket").is_none());
    assert_eq!(node.outbound["wg_port"], 51820);
    assert_eq!(node.outbound["bare_port"], 8443);
}

#[test]
fn vless_encryption_nodes_are_reported_unsupported_not_imported_as_plain() {
    // Xray VLESS Encryption (XTLS/Xray-core#5067): dialing it as plain VLESS
    // would only read the server's random stream, so say it is unsupported.
    let links = "\
vless://00000000-0000-0000-0000-000000000007@enc.example.test:443?encryption=mlkem768x25519plus.native.0rtt.enc-secret&security=none&type=tcp#Enc
vless://00000000-0000-0000-0000-000000000008@plain.example.test:443?encryption=none&security=none&type=tcp#Plain
";
    let report = import_text(links).unwrap();
    assert_eq!(report.nodes.len(), 1);
    assert_eq!(report.nodes[0].server, "plain.example.test");
    assert_eq!(report.unsupported.len(), 1);
    assert_eq!(report.unsupported[0].protocol, "vless");
    assert_eq!(
        report.unsupported[0].reason,
        "vless encryption (VLESS Encryption) is not implemented yet"
    );
    let unsupported = serde_json::to_string(&report.unsupported).unwrap();
    assert!(!unsupported.contains("enc-secret"), "{unsupported}");

    let clash = r#"
proxies:
  - name: Enc
    type: vless
    server: enc.example.test
    port: 443
    uuid: 00000000-0000-0000-0000-000000000007
    encryption: mlkem768x25519plus.native.1rtt.enc-secret
  - name: Plain
    type: vless
    server: plain.example.test
    port: 443
    uuid: 00000000-0000-0000-0000-000000000008
    encryption: ""
"#;
    let report = import_text(clash).unwrap();
    assert_eq!(report.nodes.len(), 1);
    assert_eq!(report.nodes[0].server, "plain.example.test");
    assert_eq!(report.unsupported.len(), 1);
    assert_eq!(
        report.unsupported[0].reason,
        "vless encryption (VLESS Encryption) is not implemented yet"
    );
}

/// An AnixOps subscription marks trunk nodes (a domestic ingress on a shared
/// link) with a `#anixops:path=trunk` line before the link; only that link
/// gets `path`, the report JSON leaves it out elsewhere, and other `#` lines
/// stay comments (anx FUTURE-IMPROVEMENTS F-51).
#[test]
fn anixops_path_mark_tags_the_next_link() {
    let plain = "#anixops:path=trunk\n\
        trojan://pw@sh.example.com:443?security=tls&sni=land.example#SH%20CN2\n\
        # a comment\n\
        trojan://pw@198.51.100.40:443?security=tls&sni=land.example#JP%20direct\n\
        #anixops:path=Bad Kind\n\
        trojan://pw@198.51.100.41:443?security=tls&sni=land.example#JP%20two";
    for text in [plain.to_string(), base64_standard(plain.as_bytes())] {
        let report = import_text(&text).unwrap();
        let paths: Vec<_> = report
            .nodes
            .iter()
            .map(|node| (node.name.as_str(), node.path.as_deref()))
            .collect();
        assert_eq!(
            paths,
            [
                ("SH CN2", Some("trunk")),
                ("JP direct", None),
                ("JP two", None)
            ]
        );
        let json = serde_json::to_value(&report).unwrap();
        assert_eq!(json["nodes"][0]["path"], "trunk");
        assert!(json["nodes"][1].get("path").is_none());
    }
}

/// sing-box `multiplex` and Clash `smux` become the engine's `multiplex`
/// for stream protocols; a vless flow and disabled settings run without.
#[test]
fn subscription_multiplexing_becomes_multiplex() {
    let sing_box = r#"{
  "outbounds": [
    {"type": "trojan", "tag": "Muxed trojan", "server": "198.51.100.20", "server_port": 443,
     "password": "pw", "tls": {"enabled": true, "server_name": "land.example"},
     "multiplex": {"enabled": true, "protocol": "h2mux", "max_connections": 2, "min_streams": 8, "padding": true}},
    {"type": "shadowsocks", "tag": "Streams ss", "server": "198.51.100.21", "server_port": 8388,
     "method": "aes-128-gcm", "password": "pw",
     "multiplex": {"enabled": true, "max_streams": 16, "max_connections": 4}},
    {"type": "shadowsocks", "tag": "Off ss", "server": "198.51.100.22", "server_port": 8388,
     "method": "aes-128-gcm", "password": "pw", "multiplex": {"enabled": false, "protocol": "smux"}}
  ]
}"#;
    let report = import_text(sing_box).unwrap();
    let node = |name: &str| {
        report
            .nodes
            .iter()
            .find(|node| node.name == name)
            .unwrap_or_else(|| panic!("{name} imports"))
            .outbound
            .clone()
    };
    assert_eq!(
        node("Muxed trojan")["multiplex"],
        serde_json::json!({"protocol": "h2mux", "max_connections": 2, "min_streams": 8, "padding": true})
    );
    // max_streams wins over the settings it cannot be used with.
    assert_eq!(
        node("Streams ss")["multiplex"],
        serde_json::json!({"max_streams": 16})
    );
    assert!(node("Off ss").get("multiplex").is_none());

    let clash = r#"
proxies:
  - name: Clash ss
    type: ss
    server: 198.51.100.23
    port: 8388
    cipher: aes-128-gcm
    password: pw
    smux:
      enabled: true
      protocol: smux
      max-connections: 4
      min-streams: "4"
"#;
    let report = import_text(clash).unwrap();
    assert_eq!(
        report.nodes[0].outbound["multiplex"],
        serde_json::json!({"protocol": "smux", "max_connections": 4, "min_streams": 4})
    );
}

#[test]
fn wireguard_links_import_with_allowed_ips_and_reserved() {
    let key = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";
    let peer = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=";
    let text = format!(
        "wireguard://{key}@wg.example.test:51820?publickey={peer}&address=10.7.0.2%2F32%2Cfd00%3A7%3A%3A2%2F128&allowedips=10.0.0.0%2F8%2Cfd00%3A%3A%2F8&reserved=1%2C2%2C3&mtu=1380#Office%20WG"
    );
    let report = import_text(&text).unwrap();
    assert!(report.unsupported.is_empty());
    let node = &report.nodes[0];
    assert_eq!(node.protocol, "wireguard");
    assert_eq!(node.name, "Office WG");
    let outbound = &node.outbound;
    assert_eq!(outbound["type"], "wireguard");
    assert_eq!(outbound["server"], "wg.example.test");
    assert_eq!(outbound["port"], 51820);
    assert_eq!(outbound["private_key"], key);
    assert_eq!(outbound["peer_public_key"], peer);
    assert_eq!(
        outbound["local_address"],
        serde_json::json!(["10.7.0.2/32", "fd00:7::2/128"])
    );
    assert_eq!(
        outbound["allowed_ips"],
        serde_json::json!(["10.0.0.0/8", "fd00::/8"])
    );
    assert_eq!(outbound["reserved"], serde_json::json!([1, 2, 3]));
    assert_eq!(outbound["mtu"], 1380);
}

/// One SHA-256 digest in lowercase hex and as OpenSSL prints fingerprints,
/// and another one.
const PIN: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const PIN_COLONS: &str =
    "01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF";
const OTHER_PIN: &str = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";

/// Certificate pins reach every TLS and QUIC outbound, in lowercase hex,
/// next to `insecure`; nodes without pins keep their entries as before.
#[test]
fn certificate_pins_reach_the_outbound_entries() {
    let vmess = base64_standard(
        serde_json::json!({
            "v": "2", "ps": "VMess", "add": "vmess.example.test", "port": "443",
            "id": "00000000-0000-0000-0000-000000000005", "aid": "0", "net": "tcp",
            "tls": "tls", "allowInsecure": "1", "pcs": PIN
        })
        .to_string()
        .as_bytes(),
    );
    let text = format!(
        "\
hysteria2://hy2-secret@hy2.example.test:443?insecure=1&pinSHA256={PIN_COLONS}#Hy2
tuic://00000000-0000-0000-0000-000000000001:tuic-secret@tuic.example.test:443?allow_insecure=1&pinSHA256={PIN}#TUIC
trojan://trojan-secret@trojan.example.test:443?allowInsecure=1&pcs={PIN}#Trojan
vless://00000000-0000-0000-0000-000000000002@vless.example.test:443?encryption=none&security=tls&allowInsecure=1&pcs={PIN}%2C{OTHER_PIN}#VLESS
vmess://{vmess}
hysteria2://hy2-secret@plain.example.test:443?insecure=1#Unpinned
"
    );
    let report = import_text(&text).unwrap();
    assert!(report.unsupported.is_empty(), "{:?}", report.unsupported);
    let outbound = |name: &str| {
        report
            .nodes
            .iter()
            .find(|node| node.name == name)
            .unwrap_or_else(|| panic!("{name} imports"))
            .outbound
            .clone()
    };
    for name in ["Hy2", "TUIC", "Trojan"] {
        let outbound = outbound(name);
        assert_eq!(outbound["insecure"], true, "{name}");
        assert_eq!(
            outbound["pinned_certificate_sha256"],
            serde_json::json!([PIN]),
            "{name}"
        );
        assert!(outbound.get("pinned_public_key_sha256").is_none(), "{name}");
    }
    let vless = outbound("VLESS");
    assert_eq!(vless["tls"]["insecure"], true);
    assert_eq!(
        vless["tls"]["pinned_certificate_sha256"],
        serde_json::json!([PIN, OTHER_PIN])
    );
    let vmess = outbound("VMess");
    assert_eq!(
        vmess["tls"]["pinned_certificate_sha256"],
        serde_json::json!([PIN])
    );
    let unpinned = outbound("Unpinned");
    assert!(unpinned.get("pinned_certificate_sha256").is_none());
    assert!(unpinned.get("pinned_public_key_sha256").is_none());
}

/// sing-box keeps both kinds of pin in base64; the engine gets both in hex.
#[test]
fn sing_box_certificate_and_public_key_pins_reach_the_outbound() {
    let pin_base64 = base64_standard(&hex_bytes(PIN));
    let other_base64 = base64_standard(&hex_bytes(OTHER_PIN));
    let sing_box = format!(
        r#"{{
  "outbounds": [
    {{"type": "hysteria2", "tag": "Hy2", "server": "hy2.example.test", "server_port": 443,
      "password": "hy2-secret",
      "tls": {{"enabled": true, "insecure": true, "certificate_public_key_sha256": ["{pin_base64}"]}}}},
    {{"type": "vless", "tag": "VLESS", "server": "vless.example.test", "server_port": 443,
      "uuid": "00000000-0000-0000-0000-000000000002",
      "tls": {{"enabled": true, "certificate_sha256": ["{other_base64}"],
               "certificate_public_key_sha256": "{pin_base64}"}}}}
  ]
}}"#
    );
    let report = import_text(&sing_box).unwrap();
    assert!(report.unsupported.is_empty(), "{:?}", report.unsupported);
    let hy2 = &report.nodes[0].outbound;
    assert_eq!(hy2["pinned_public_key_sha256"], serde_json::json!([PIN]));
    assert!(hy2.get("pinned_certificate_sha256").is_none());
    let vless = &report.nodes[1].outbound["tls"];
    assert_eq!(vless["insecure"], false);
    assert_eq!(
        vless["pinned_certificate_sha256"],
        serde_json::json!([OTHER_PIN])
    );
    assert_eq!(vless["pinned_public_key_sha256"], serde_json::json!([PIN]));
}

/// A pin that cannot be read never turns into a node without it: such a
/// node is unsupported, with a fixed reason and without its secrets.
#[test]
fn nodes_with_unreadable_pins_are_unsupported_not_unpinned() {
    let text = "\
hysteria2://hy2-secret@hy2.example.test:443?insecure=1&pinSHA256=pin-secret#Hy2
trojan://trojan-secret@trojan.example.test:443?allowInsecure=1&pcs=ABCD#Trojan
trojan://trojan-secret@ok.example.test:443?allowInsecure=1#Unpinned
";
    let report = import_text(text).unwrap();
    assert_eq!(report.nodes.len(), 1);
    assert_eq!(report.nodes[0].name, "Unpinned");
    let reasons: Vec<_> = report
        .unsupported
        .iter()
        .map(|node| (node.name.as_str(), node.reason))
        .collect();
    assert_eq!(
        reasons,
        [
            ("Hy2", "tls certificate pin is not a sha-256 digest"),
            ("Trojan", "tls certificate pin is not a sha-256 digest"),
        ]
    );
    let unsupported = serde_json::to_string(&report.unsupported).unwrap();
    assert!(!unsupported.contains("secret"), "{unsupported}");
}

fn pinned_node(protocol: Protocol, metadata: &[(&str, &str)]) -> NodeDescriptor {
    NodeDescriptor {
        id: "pinned".to_string(),
        name: "Pinned".to_string(),
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

/// Nodes imported before certificate pins had their own key kept Hysteria2
/// `pinSHA256` and Xray `pcs` values (hex certificate digests) under the
/// public key key; they still pin the certificate.
#[test]
fn hex_values_under_the_public_key_key_are_certificate_pins() {
    let node = pinned_node(
        Protocol::Hysteria2,
        &[
            ("hysteria2.password", "hy2-secret"),
            ("tls.insecure", "true"),
            ("tls.certificate_public_key_sha256", PIN_COLONS),
        ],
    );
    let outbound = outbound_json(&node).unwrap();
    assert_eq!(
        outbound["pinned_certificate_sha256"],
        serde_json::json!([PIN])
    );
    assert!(outbound.get("pinned_public_key_sha256").is_none());

    let node = pinned_node(
        Protocol::Hysteria2,
        &[
            ("hysteria2.password", "hy2-secret"),
            ("tls.certificate_public_key_sha256", "not-a-digest"),
        ],
    );
    assert_eq!(
        outbound_json(&node).unwrap_err(),
        "tls public key pin is not a sha-256 digest"
    );
}

/// Pins without TLS have no certificate to check: the node is unsupported
/// rather than run in the clear with its pins ignored. REALITY checks the
/// server by its own key and keeps no pins.
#[test]
fn pins_need_tls_and_reality_ignores_them() {
    let plain = pinned_node(
        Protocol::Vless,
        &[
            ("vless.uuid", "00000000-0000-0000-0000-000000000002"),
            ("tls.enabled", "false"),
            ("tls.certificate_sha256", PIN),
        ],
    );
    assert_eq!(
        outbound_json(&plain).unwrap_err(),
        "certificate pins are set on a node without tls"
    );

    let reality = pinned_node(
        Protocol::Vless,
        &[
            ("vless.uuid", "00000000-0000-0000-0000-000000000002"),
            ("tls.enabled", "true"),
            ("tls.server_name", "www.example.com"),
            (
                "tls.reality.public_key",
                "Z84J2IelR9ch3k8VtlVhhs5ycBUlXA7wHBWcBrjqnAw",
            ),
            ("tls.certificate_sha256", PIN),
        ],
    );
    let outbound = outbound_json(&reality).unwrap();
    assert!(outbound["reality"].is_object());
    assert!(!outbound.to_string().contains("pinned"));
}

#[test]
fn pinned_share_links_import_back_with_their_pins() {
    assert_round_trip(&format!(
        "\
hysteria2://hy2-secret@hy2.example.test:443?sni=cdn.example.test&insecure=1&pinSHA256={PIN}#Hy2
tuic://00000000-0000-0000-0000-000000000001:tuic-secret@tuic.example.test:443?allow_insecure=1&pinSHA256={PIN_COLONS}#TUIC
trojan://trojan-secret@trojan.example.test:443?allowInsecure=1&pcs={PIN}#Trojan
vless://00000000-0000-0000-0000-000000000002@vless.example.test:443?encryption=none&security=tls&allowInsecure=1&pcs={PIN}%2C{OTHER_PIN}&type=ws&path=%2Fws#VLESS
"
    ));
    let vmess = base64_standard(
        serde_json::json!({
            "v": "2", "ps": "VMess", "add": "vmess.example.test", "port": "443",
            "id": "00000000-0000-0000-0000-000000000005", "aid": "0", "net": "tcp",
            "tls": "tls", "allowInsecure": "1", "pcs": OTHER_PIN
        })
        .to_string()
        .as_bytes(),
    );
    assert_round_trip(&format!("vmess://{vmess}"));
}

/// No link format carries public key pins; a link without them would check
/// less than the node does, so there is none.
#[test]
fn share_links_are_refused_for_public_key_pins() {
    let hysteria2 = serde_json::json!({
        "type": "hysteria2", "server": "hy2.example.test", "port": 443,
        "password": "hy2-secret", "insecure": true,
        "pinned_public_key_sha256": [PIN]
    });
    let vless = serde_json::json!({
        "type": "vless", "server": "vless.example.test", "port": 443,
        "uuid": "00000000-0000-0000-0000-000000000002",
        "tls": {"server_name": "vless.example.test", "insecure": true,
                "pinned_public_key_sha256": [PIN]}
    });
    for outbound in [hysteria2, vless] {
        let error = share_link("Pinned", &outbound).unwrap_err();
        assert_eq!(error, "certificate public key pins have no share link form");
    }
}

fn hex_bytes(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&hex[index..index + 2], 16).unwrap())
        .collect()
}
