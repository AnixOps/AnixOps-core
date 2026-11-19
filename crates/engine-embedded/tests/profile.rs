//! Routing modes and policy group choices over imported profiles.

use engine_embedded::profile::{
    envelope_for_mode, groups, selected_node, set_group_default, switch_group_for_node,
    RoutingMode, PROXY_OUTBOUND,
};
use serde_json::{json, Value};

fn ss(server: &str) -> Value {
    json!({
        "type": "shadowsocks",
        "server": server,
        "port": 443,
        "method": "2022-blake3-aes-128-gcm",
        "password": "AAECAwQFBgcICQoLDA0ODw==",
    })
}

fn single() -> Value {
    json!({ "schema_version": 1, "profile_id": "p", "outbound": ss("192.0.2.1") })
}

fn routed() -> Value {
    json!({
        "schema_version": 1,
        "profile_id": "p",
        "routing": {
            "outbounds": { "hk": ss("192.0.2.1"), "jp": ss("192.0.2.2") },
            "rules": ["DOMAIN-SUFFIX,example.org,DIRECT", "FINAL,Proxy"],
            "groups": [
                { "id": "Proxy", "type": "select", "members": ["Auto", "hk", "DIRECT"] },
                { "id": "Auto", "type": "url-test", "members": ["jp", "hk"],
                  "url": "http://www.gstatic.com/generate_204", "interval_secs": 300 },
            ],
        },
    })
}

fn render(profile: &Value, mode: RoutingMode) -> Value {
    serde_json::from_str(&envelope_for_mode(&profile.to_string(), mode).unwrap()).unwrap()
}

#[test]
fn only_rule_and_direct_modes_exist() {
    for mode in [RoutingMode::Direct, RoutingMode::Rule] {
        assert_eq!(RoutingMode::parse(mode.as_str()), Some(mode));
        assert_eq!(
            serde_json::to_value(mode).unwrap(),
            Value::String(mode.as_str().to_string())
        );
    }
    // No preset list modes (docs/no-presets.md).
    for removed in ["bypass_china", "gfw_list", "return_china", "global"] { // neutral-terms: allow (values saved by earlier versions)
        assert_eq!(RoutingMode::parse(removed), None, "{removed}");
    }
    assert_eq!(RoutingMode::default(), RoutingMode::Rule);
}

#[test]
fn rule_mode_keeps_the_profile_and_direct_mode_replaces_its_rules() {
    let profile = routed();
    assert_eq!(render(&profile, RoutingMode::Rule), profile);

    let direct = render(&profile, RoutingMode::Direct);
    assert_eq!(direct["routing"]["rules"], json!(["FINAL,DIRECT"]));
    assert_eq!(direct["routing"]["rule_sets"], json!({}));
    assert_eq!(direct["routing"]["groups"], profile["routing"]["groups"]);

    let single_direct = render(&single(), RoutingMode::Direct);
    assert!(single_direct.get("outbound").is_none());
    assert_eq!(single_direct["routing"]["rules"], json!(["FINAL,DIRECT"]));
    assert!(single_direct["routing"]["outbounds"][PROXY_OUTBOUND].is_object());

    assert!(envelope_for_mode("[]", RoutingMode::Direct).is_err());
}

#[test]
fn groups_report_their_choice_and_select_groups_switch() {
    let mut profile = routed();
    let listed = groups(&profile);
    assert_eq!(listed.len(), 2);
    assert_eq!(listed[0].id, "Proxy");
    assert_eq!(listed[0].choice.as_deref(), Some("Auto"));
    assert_eq!(listed[1].kind, "url-test");
    assert!(groups(&single()).is_empty());

    // FINAL → Proxy → Auto → jp before any health check.
    assert_eq!(selected_node(&profile).as_deref(), Some("jp"));
    assert_eq!(
        switch_group_for_node(&profile, "hk").as_deref(),
        Some("Proxy")
    );
    assert_eq!(switch_group_for_node(&profile, "missing"), None);

    set_group_default(&mut profile, "Proxy", "hk").unwrap();
    assert_eq!(selected_node(&profile).as_deref(), Some("hk"));
    assert!(set_group_default(&mut profile, "Auto", "hk").is_err());
    assert!(set_group_default(&mut profile, "Proxy", "nope").is_err());
    assert!(set_group_default(&mut profile, "Missing", "hk").is_err());

    set_group_default(&mut profile, "Proxy", "DIRECT").unwrap();
    assert_eq!(selected_node(&profile), None);
}
