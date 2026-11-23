//! mitm-scripts-07 / mitm-scripts-11: a loaded policy is compiled once per
//! revision. Hostname decisions, Map Local, header-block and jq rules reuse
//! the compiled forms instead of loading the policy or compiling a filter
//! again for every host or message, and give the same answers as a freshly
//! loaded engine. Releasing a revision frees its compiled forms.
//!
//! One test in its own binary: the load counter is per thread and the caches
//! are per process, so no other test may run beside it.

use control_domain::{
    CertificateTrustState, GrantedPermissions, HttpMitmAction, HttpMitmEvent, HttpMitmPhase,
    MetadataEntry, MitmHostnameDecision, MitmPluginService, PluginInstance,
};
use mitm_policy::loon_jq::jq_compilations_on_this_thread;
use mitm_policy::loon_plugin::{import_loon_plugin, merged_plugin_source};
use mitm_policy::{
    idle_policy_engines, policy_loads_on_this_thread, release_compiled_policy, user_plugin_package,
    AnixOpsMitmPluginService, AnixOpsMitmPolicyEngine, CompiledPolicyRelease,
    MitmPolicyMitmDecisionType,
};

fn load(service: &AnixOpsMitmPluginService, source: &str) -> PluginInstance {
    let package = user_plugin_package(source);
    service
        .load(
            &package,
            &GrantedPermissions {
                permissions: package.manifest.permissions.clone(),
            },
        )
        .expect("policy should load")
}

/// The decision a freshly loaded engine gives, as the service used to.
fn fresh_decision(source: &str, host: &str, is_quic: bool) -> MitmHostnameDecision {
    let mut engine = AnixOpsMitmPolicyEngine::new().expect("engine allocates");
    engine.load_config(source).expect("policy loads");
    engine.set_certificate_trust_state(CertificateTrustState::Trusted);
    match engine
        .evaluate_mitm(host, is_quic)
        .expect("decision evaluates")
        .decision
    {
        MitmPolicyMitmDecisionType::Bypass => MitmHostnameDecision::Bypass,
        MitmPolicyMitmDecisionType::Intercept => MitmHostnameDecision::Intercept,
        MitmPolicyMitmDecisionType::RejectQuic => MitmHostnameDecision::RejectQuic,
    }
}

fn request(url: &str) -> HttpMitmEvent {
    HttpMitmEvent {
        request_id: "cache".to_string(),
        url: url.to_string(),
        method: Some("GET".to_string()),
        phase: HttpMitmPhase::Request,
        status_code: None,
        headers: vec![
            MetadataEntry {
                key: "Host".to_string(),
                value: "a.example.test".to_string(),
            },
            MetadataEntry {
                key: "User-Agent".to_string(),
                value: "App/1.0".to_string(),
            },
        ],
        body: Vec::new(),
    }
}

fn response(url: &str, body: &str) -> HttpMitmEvent {
    HttpMitmEvent {
        request_id: "cache".to_string(),
        url: url.to_string(),
        method: Some("GET".to_string()),
        phase: HttpMitmPhase::Response,
        status_code: Some(200),
        headers: Vec::new(),
        body: body.as_bytes().to_vec(),
    }
}

#[test]
fn a_policy_is_compiled_once_per_revision() {
    let plugin = import_loon_plugin(concat!(
        "#!name = Cached\n",
        "[Rewrite]\n",
        "^https://a\\.example\\.test/ads reject\n",
        "^https://a\\.example\\.test/ua url request-header (\\r\\n)User-Agent:.+(\\r\\n) request-header $1User-Agent: Cached$2\n",
        "[Body Rewrite]\n",
        "http-response-jq ^https://a\\.example\\.test/jq 'del(.ad)'\n",
        "[Map Local]\n",
        "^https://a\\.example\\.test/local data=\"local\"\n",
        "[MITM]\n",
        "hostname = a.example.test, *.b.example.test, -skip.b.example.test\n",
    ))
    .expect("plugin should import");
    let source = merged_plugin_source("Cached", &[&plugin]);
    let service = AnixOpsMitmPluginService::new();
    let instance = load(&service, &source);

    // Same decisions as a freshly loaded engine.
    for host in [
        "a.example.test",
        "A.EXAMPLE.TEST",
        "x.b.example.test",
        "skip.b.example.test",
        "other.example.test",
    ] {
        for is_quic in [false, true] {
            assert_eq!(
                service
                    .evaluate_mitm_hostname(&instance, host, is_quic)
                    .expect("decision evaluates"),
                fresh_decision(&source, host, is_quic),
                "{host} quic={is_quic}"
            );
        }
    }
    assert_eq!(
        service
            .evaluate_mitm_hostname(&instance, "a.example.test", false)
            .unwrap(),
        MitmHostnameDecision::Intercept
    );
    assert_eq!(
        service
            .evaluate_mitm_hostname(&instance, "other.example.test", false)
            .unwrap(),
        MitmHostnameDecision::Bypass
    );

    let plan = |url: &str| {
        service
            .handle_http_mitm_event(&instance, &request(url))
            .expect("event plans")
    };
    let check_plans = || {
        assert_eq!(
            plan("https://a.example.test/ads").action,
            HttpMitmAction::Reject { status_code: 403 }
        );
        match plan("https://a.example.test/local").action {
            HttpMitmAction::Respond { body, .. } => assert_eq!(body, b"local"),
            other => panic!("Map Local should answer: {other:?}"),
        }
        let ua = plan("https://a.example.test/ua");
        assert!(
            ua.header_mutations.iter().any(|mutation| {
                mutation.name.eq_ignore_ascii_case("User-Agent")
                    && mutation.value.as_deref() == Some("Cached")
            }),
            "{:?}",
            ua.header_mutations
        );
        let other = plan("https://a.example.test/other");
        assert_eq!(other.action, HttpMitmAction::Continue);
        assert!(other.header_mutations.is_empty());
        let jq = service
            .handle_http_mitm_event(
                &instance,
                &response("https://a.example.test/jq", r#"{"ad":1,"ok":true}"#),
            )
            .expect("response plans");
        assert_eq!(
            jq.body_mutation
                .expect("the jq rule rewrites the body")
                .body,
            br#"{"ok":true}"#
        );
    };
    check_plans();

    // Warm: every compiled form exists. Many more hosts and messages load
    // nothing and compile no jq filter.
    let loads = policy_loads_on_this_thread();
    let jq_compilations = jq_compilations_on_this_thread();
    for index in 0..300 {
        let host = format!("host-{index}.b.example.test");
        assert_eq!(
            service
                .evaluate_mitm_hostname(&instance, &host, false)
                .unwrap(),
            MitmHostnameDecision::Intercept,
            "{host}"
        );
    }
    for _ in 0..20 {
        check_plans();
    }
    assert_eq!(
        policy_loads_on_this_thread(),
        loads,
        "the warm policy was loaded again"
    );
    assert_eq!(
        jq_compilations_on_this_thread(),
        jq_compilations,
        "the warm jq rule was compiled again"
    );

    // A new revision is compiled for itself and answers by its own rules.
    let changed = source.replace("b.example.test", "c.example.test");
    assert_ne!(changed, source);
    let changed_instance = load(&service, &changed);
    let before = policy_loads_on_this_thread();
    assert_eq!(
        service
            .evaluate_mitm_hostname(&changed_instance, "x.b.example.test", false)
            .unwrap(),
        MitmHostnameDecision::Bypass
    );
    assert_eq!(
        service
            .evaluate_mitm_hostname(&changed_instance, "x.c.example.test", false)
            .unwrap(),
        MitmHostnameDecision::Intercept
    );
    assert!(policy_loads_on_this_thread() > before);
    // The first revision still answers by its rules.
    assert_eq!(
        service
            .evaluate_mitm_hostname(&instance, "x.b.example.test", false)
            .unwrap(),
        MitmHostnameDecision::Intercept
    );

    // Released when its owner stops using it: no idle engine of it stays,
    // and its hostname engine, Map Local and jq rules are compiled again if
    // it is ever used again. The other revision keeps its compiled forms.
    assert!(idle_policy_engines() > 0);
    drop(CompiledPolicyRelease::new(&source));
    let before = policy_loads_on_this_thread();
    service
        .evaluate_mitm_hostname(&changed_instance, "x.c.example.test", false)
        .unwrap();
    assert_eq!(
        policy_loads_on_this_thread(),
        before,
        "releasing one revision kept the other"
    );
    assert_eq!(
        idle_policy_engines(),
        0,
        "every idle engine was of the released revision"
    );
    let jq_compilations = jq_compilations_on_this_thread();
    check_plans();
    assert!(
        policy_loads_on_this_thread() > before,
        "the released revision's engines were freed"
    );
    assert!(
        jq_compilations_on_this_thread() > jq_compilations,
        "the released revision's jq filters were freed"
    );
    let before = policy_loads_on_this_thread();
    service
        .evaluate_mitm_hostname(&instance, "x.b.example.test", false)
        .unwrap();
    assert!(
        policy_loads_on_this_thread() > before,
        "the released revision's hostname engine was freed"
    );

    release_compiled_policy(&source);
    release_compiled_policy(&changed);
    assert_eq!(idle_policy_engines(), 0);
}
