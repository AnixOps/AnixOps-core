//! Routing modes and policy group choices over imported profiles.

use engine_embedded::config::RuntimeConfig;
use engine_embedded::connections::Mode;
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
fn the_rule_global_and_direct_modes_exist() {
    // All three stay offered on every desktop and Android client
    // (docs/platform-parity.md, 分流模式); losing one fails here.
    assert_eq!(
        RoutingMode::ALL,
        [RoutingMode::Rule, RoutingMode::Global, RoutingMode::Direct]
    );
    for (mode, name) in RoutingMode::ALL
        .into_iter()
        .zip(["rule", "global", "direct"])
    {
        assert_eq!(mode.as_str(), name);
        assert_eq!(RoutingMode::parse(name), Some(mode));
        assert_eq!(
            serde_json::to_value(mode).unwrap(),
            Value::String(name.to_string())
        );
    }
    // No preset list modes (docs/no-presets.md).
    assert_eq!(RoutingMode::parse("preset_list"), None);
    assert_eq!(RoutingMode::default(), RoutingMode::Rule);
}

#[test]
fn the_global_envelope_starts_the_engine_in_its_global_mode_on_final_s_group() {
    let profile = routed();
    let global = render(&profile, RoutingMode::Global);
    assert_eq!(global["mode"], "global");
    // FINAL,Proxy: the global mode follows the Proxy group, so choosing
    // another node in it keeps working.
    assert_eq!(global["routing"]["global"], "Proxy");
    // The rules are kept for switching back in place; the engine ignores them.
    assert_eq!(global["routing"]["rules"], profile["routing"]["rules"]);
    let config = RuntimeConfig::from_json(global.to_string().as_bytes()).unwrap();
    assert_eq!(config.mode, Mode::Global);

    // FINAL straight at a node.
    let mut to_node = routed();
    to_node["routing"]["rules"] = json!(["FINAL,hk"]);
    assert_eq!(
        render(&to_node, RoutingMode::Global)["routing"]["global"],
        "hk"
    );

    // FINAL,DIRECT does not make the global mode direct: the engine's own
    // default (the first group) is used.
    let mut to_direct = routed();
    to_direct["routing"]["rules"] = json!(["FINAL,DIRECT"]);
    let rendered = render(&to_direct, RoutingMode::Global);
    assert_eq!(rendered["mode"], "global");
    assert!(rendered["routing"].get("global").is_none());

    // A global target the profile names is kept.
    let mut named = routed();
    named["routing"]["global"] = json!("Auto");
    assert_eq!(
        render(&named, RoutingMode::Global)["routing"]["global"],
        "Auto"
    );

    // A single-node profile keeps its one outbound.
    let single_global = render(&single(), RoutingMode::Global);
    assert_eq!(single_global["mode"], "global");
    assert_eq!(single_global["outbound"], single()["outbound"]);
    assert!(single_global.get("routing").is_none());
    let config = RuntimeConfig::from_json(single_global.to_string().as_bytes()).unwrap();
    assert_eq!(config.mode, Mode::Global);

    assert!(envelope_for_mode("[]", RoutingMode::Global).is_err());
}

#[test]
fn rule_mode_keeps_the_profile_and_direct_mode_replaces_its_rules() {
    let profile = routed();
    assert_eq!(render(&profile, RoutingMode::Rule), profile);

    let direct = render(&profile, RoutingMode::Direct);
    assert_eq!(direct["mode"], "direct");
    assert_eq!(direct["routing"]["rules"], json!(["FINAL,DIRECT"]));
    assert_eq!(direct["routing"]["rule_sets"], json!({}));
    assert_eq!(direct["routing"]["groups"], profile["routing"]["groups"]);

    let single_direct = render(&single(), RoutingMode::Direct);
    assert!(single_direct.get("outbound").is_none());
    assert_eq!(single_direct["mode"], "direct");
    assert_eq!(single_direct["routing"]["rules"], json!(["FINAL,DIRECT"]));
    assert!(single_direct["routing"]["outbounds"][PROXY_OUTBOUND].is_object());

    assert!(envelope_for_mode("[]", RoutingMode::Direct).is_err());
}

#[test]
fn the_direct_envelope_starts_the_engine_in_its_direct_mode() {
    // `FINAL,DIRECT` alone runs in the rule mode, where a `proxy` DNS server
    // still goes through a node; the direct mode sends nothing through one.
    let engine_mode = |profile: &Value, mode: RoutingMode| -> Mode {
        let envelope = envelope_for_mode(&profile.to_string(), mode).unwrap();
        RuntimeConfig::from_json(envelope.as_bytes()).unwrap().mode
    };
    for profile in [routed(), single()] {
        assert_eq!(engine_mode(&profile, RoutingMode::Direct), Mode::Direct);
        assert_eq!(engine_mode(&profile, RoutingMode::Rule), Mode::Rule);
        assert_eq!(engine_mode(&profile, RoutingMode::Global), Mode::Global);
    }

    // A mode the profile carries gives way to the direct one.
    let mut global = routed();
    global["mode"] = json!("global");
    assert_eq!(engine_mode(&global, RoutingMode::Direct), Mode::Direct);
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

#[test]
fn a_final_rule_with_dns_failed_still_names_its_group() {
    // Surge's `FINAL,<target>,dns-failed` keeps its option after import; the
    // option is not part of the group name.
    let mut profile = routed();
    profile["routing"]["rules"] =
        json!(["DOMAIN-SUFFIX,example.org,DIRECT", "FINAL,Proxy,dns-failed"]);
    assert_eq!(selected_node(&profile).as_deref(), Some("jp"));
    assert_eq!(
        switch_group_for_node(&profile, "hk").as_deref(),
        Some("Proxy")
    );
    set_group_default(&mut profile, "Proxy", "hk").unwrap();
    assert_eq!(selected_node(&profile).as_deref(), Some("hk"));

    // The rule mode hands the option to the engine unchanged.
    let rendered = render(&profile, RoutingMode::Rule);
    assert_eq!(
        rendered["routing"]["rules"],
        json!(["DOMAIN-SUFFIX,example.org,DIRECT", "FINAL,Proxy,dns-failed"])
    );
    RuntimeConfig::from_json(rendered.to_string().as_bytes()).unwrap();
}
