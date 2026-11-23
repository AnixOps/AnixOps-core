//! Contracts for `AnixOpsMitmPluginService::handle_http_mitm_event` and
//! `needs_body`, the path every data plane plans decrypted messages through:
//! rewrite actions the adapter does not apply, regex header rewrites, binary
//! bodies, header-only scripts and body rewrite chains that outgrow the core's
//! buffers.

use control_domain::{
    GrantedPermissions, HttpHeaderMutation, HttpHeaderMutationOperation, HttpMitmAction,
    HttpMitmEvent, HttpMitmOutcome, HttpMitmPhase, MetadataEntry, MitmPluginService,
    PluginInstance,
};
use mitm_policy::loon_plugin::{import_loon_plugin, merged_plugin_source};
use mitm_policy::{
    user_plugin_package, AnixOpsMitmPluginService, AnixOpsMitmPolicyEngine,
    MitmPolicyBodyChainOutcome, MitmPolicyPhase, MitmPolicyRewriteAction,
    MITM_POLICY_HTTP_EVENT_BINARY_BODY_SKIPPED_CODE,
    MITM_POLICY_HTTP_EVENT_BODY_REWRITE_RECORDS_CAPPED_CODE,
    MITM_POLICY_HTTP_EVENT_BODY_REWRITE_SKIPPED_CODE,
    MITM_POLICY_HTTP_EVENT_HEADER_REGEX_SKIPPED_CODE,
};

fn load(source: &str) -> (AnixOpsMitmPluginService, PluginInstance) {
    let service = AnixOpsMitmPluginService::new();
    let package = user_plugin_package(source);
    let instance = service
        .load(
            &package,
            &GrantedPermissions {
                permissions: package.manifest.permissions.clone(),
            },
        )
        .expect("the plugin should load");
    (service, instance)
}

fn event(url: &str, phase: HttpMitmPhase, headers: &[(&str, &str)], body: &[u8]) -> HttpMitmEvent {
    HttpMitmEvent {
        request_id: "contract".to_string(),
        url: url.to_string(),
        method: Some("GET".to_string()),
        phase,
        status_code: (phase == HttpMitmPhase::Response).then_some(200),
        headers: headers
            .iter()
            .map(|(key, value)| MetadataEntry {
                key: key.to_string(),
                value: value.to_string(),
            })
            .collect(),
        body: body.to_vec(),
    }
}

fn plan(
    service: &AnixOpsMitmPluginService,
    instance: &PluginInstance,
    event: &HttpMitmEvent,
) -> HttpMitmOutcome {
    service
        .handle_http_mitm_event(instance, event)
        .expect("the message should be planned")
}

/// `headers` after `mutations`, applied the way engine-native applies them.
fn applied(headers: &[(&str, &str)], mutations: &[HttpHeaderMutation]) -> Vec<(String, String)> {
    let mut headers = headers
        .iter()
        .map(|(key, value)| (key.to_string(), value.to_string()))
        .collect::<Vec<_>>();
    for mutation in mutations {
        let named = |key: &str| key.eq_ignore_ascii_case(&mutation.name);
        let value = mutation.value.clone().unwrap_or_default();
        match mutation.operation {
            HttpHeaderMutationOperation::Add => headers.push((mutation.name.clone(), value)),
            HttpHeaderMutationOperation::Replace => {
                for header in headers.iter_mut().filter(|(key, _)| named(key)) {
                    header.1 = value.clone();
                }
            }
            HttpHeaderMutationOperation::Delete => headers.retain(|(key, _)| !named(key)),
            HttpHeaderMutationOperation::Set => {
                headers.retain(|(key, _)| !named(key));
                headers.push((mutation.name.clone(), value));
            }
        }
    }
    headers
}

fn has_diagnostic(outcome: &HttpMitmOutcome, code: &str) -> bool {
    outcome
        .diagnostics
        .iter()
        .any(|diagnostic| diagnostic.code == code)
}

/// mitm-scripts-02: the core's `200` action (a transparent URL rewrite) used
/// to reach Rust as an enum value it did not declare. It now continues the
/// message unchanged in all three spellings the core accepts.
#[test]
fn url_rewrite_200_rules_continue_the_message_unchanged() {
    let source = concat!(
        "[Rewrite]\n",
        "^https://a\\.example\\.test/(.*) https://new.example.test/$1 200\n",
        "^https://b\\.example\\.test/ 200 https://new.example.test/\n",
        "^https://c\\.example\\.test/ url 200 https://new.example.test/\n",
        "\n[MITM]\nhostname = a.example.test, b.example.test, c.example.test\n",
    );
    let mut engine = AnixOpsMitmPolicyEngine::new().expect("policy engine should allocate");
    engine.load_config(source).expect("200 rules should load");
    let (service, instance) = load(source);
    for url in [
        "https://a.example.test/page",
        "https://b.example.test/page",
        "https://c.example.test/page",
    ] {
        let rewrite = engine
            .evaluate_url_rewrite(url, MitmPolicyPhase::Request)
            .expect("rewrite should evaluate");
        assert_eq!(rewrite.action, MitmPolicyRewriteAction::Other, "{url}");
        let (plan, _) = engine
            .build_rewrite_plan(url, MitmPolicyPhase::Request, "")
            .expect("plan should build");
        assert_eq!(plan.rewrite.action, MitmPolicyRewriteAction::Other, "{url}");

        let outcome = plan_request(&service, &instance, url);
        assert_eq!(outcome.action, HttpMitmAction::Continue, "{url}");
        assert!(outcome.body_mutation.is_none(), "{url}");
        assert!(!service
            .needs_body(&instance, url, HttpMitmPhase::Request)
            .expect("needs_body should evaluate"));
    }
}

fn plan_request(
    service: &AnixOpsMitmPluginService,
    instance: &PluginInstance,
    url: &str,
) -> HttpMitmOutcome {
    plan(
        service,
        instance,
        &event(url, HttpMitmPhase::Request, &[], b""),
    )
}

const HEADER_REGEX_PLUGIN: &str = concat!(
    "[Rewrite]\n",
    "^https://m\\.example\\.test/ua header-replace-regex User-Agent iPhone iPad\n",
    "^https://m\\.example\\.test/lang header-replace-regex Accept-Language ^([a-z]+)-[A-Z]+ $1\n",
    "^https://m\\.example\\.test/long header-replace-regex X-Long a b\n",
    "^https://m\\.example\\.test/order header-add X-Mode alpha\n",
    "^https://m\\.example\\.test/order header-replace-regex X-Mode alpha beta\n",
    "^https://m\\.example\\.test/cookie response-header-replace-regex Set-Cookie SameSite=None SameSite=Lax\n",
    "\n[MITM]\nhostname = m.example.test\n",
);

/// mitm-scripts-03: a regex header rule rewrites only the matched part of
/// the header's current value, not the whole header to its template.
#[test]
fn header_replace_regex_rewrites_the_matched_part_of_each_value() {
    let (service, instance) = load(HEADER_REGEX_PLUGIN);

    let headers = [
        ("Host", "m.example.test"),
        (
            "User-Agent",
            "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X)",
        ),
    ];
    let outcome = plan(
        &service,
        &instance,
        &event(
            "https://m.example.test/ua",
            HttpMitmPhase::Request,
            &headers,
            b"",
        ),
    );
    assert_eq!(
        applied(&headers, &outcome.header_mutations),
        vec![
            ("Host".to_string(), "m.example.test".to_string()),
            (
                "User-Agent".to_string(),
                "Mozilla/5.0 (iPad; CPU iPad OS 17_0 like Mac OS X)".to_string()
            ),
        ]
    );

    // No match: the header is left alone, not replaced by the template.
    let android = [("User-Agent", "Mozilla/5.0 (Linux; Android 14)")];
    let outcome = plan(
        &service,
        &instance,
        &event(
            "https://m.example.test/ua",
            HttpMitmPhase::Request,
            &android,
            b"",
        ),
    );
    assert!(
        outcome.header_mutations.is_empty(),
        "{:?}",
        outcome.header_mutations
    );

    // No such header: nothing is added.
    let outcome = plan(
        &service,
        &instance,
        &event(
            "https://m.example.test/ua",
            HttpMitmPhase::Request,
            &[],
            b"",
        ),
    );
    assert!(outcome.header_mutations.is_empty());

    // Capture groups expand.
    let language = [("Accept-Language", "zh-CN")];
    let outcome = plan(
        &service,
        &instance,
        &event(
            "https://m.example.test/lang",
            HttpMitmPhase::Request,
            &language,
            b"",
        ),
    );
    assert_eq!(
        applied(&language, &outcome.header_mutations),
        vec![("Accept-Language".to_string(), "zh".to_string())]
    );
}

#[test]
fn header_replace_regex_changes_only_the_matching_set_cookie() {
    let (service, instance) = load(HEADER_REGEX_PLUGIN);
    let headers = [
        ("Content-Type", "text/html"),
        ("Set-Cookie", "session=1; SameSite=None; Secure"),
        ("set-cookie", "theme=dark; Path=/"),
    ];
    let outcome = plan(
        &service,
        &instance,
        &event(
            "https://m.example.test/cookie",
            HttpMitmPhase::Response,
            &headers,
            b"",
        ),
    );
    assert_eq!(
        applied(&headers, &outcome.header_mutations),
        vec![
            ("Content-Type".to_string(), "text/html".to_string()),
            (
                "Set-Cookie".to_string(),
                "session=1; SameSite=Lax; Secure".to_string()
            ),
            ("set-cookie".to_string(), "theme=dark; Path=/".to_string()),
        ]
    );
}

#[test]
fn header_replace_regex_sees_earlier_rules_and_skips_values_it_cannot_rewrite() {
    let (service, instance) = load(HEADER_REGEX_PLUGIN);

    // The regex rule runs on the value the earlier `header-add` left.
    let outcome = plan(
        &service,
        &instance,
        &event(
            "https://m.example.test/order",
            HttpMitmPhase::Request,
            &[],
            b"",
        ),
    );
    assert_eq!(
        applied(&[], &outcome.header_mutations),
        vec![("X-Mode".to_string(), "beta".to_string())]
    );

    // A result longer than the core's value capacity is never written cut
    // short: the value stays and a warning says why.
    let long = "a".repeat(3000);
    let headers = [("X-Long", long.as_str())];
    let outcome = plan(
        &service,
        &instance,
        &event(
            "https://m.example.test/long",
            HttpMitmPhase::Request,
            &headers,
            b"",
        ),
    );
    assert!(outcome.header_mutations.is_empty());
    assert!(has_diagnostic(
        &outcome,
        MITM_POLICY_HTTP_EVENT_HEADER_REGEX_SKIPPED_CODE
    ));
}

#[test]
fn imported_surge_header_rewrite_regex_rewrites_the_matched_part() {
    let plugin = import_loon_plugin(concat!(
        "#!name = UA\n",
        "[Header Rewrite]\n",
        "http-request ^https://m\\.example\\.test/ header-replace-regex User-Agent iPhone iPad\n",
        "http-response ^https://m\\.example\\.test/ header-replace-regex Set-Cookie SameSite=None SameSite=Lax\n",
        "[MITM]\n",
        "hostname = m.example.test\n",
    ))
    .expect("module should import");
    let (service, instance) = load(&merged_plugin_source("UA", &[&plugin]));

    let request = [("User-Agent", "App/1.0 (iPhone)")];
    let outcome = plan(
        &service,
        &instance,
        &event(
            "https://m.example.test/home",
            HttpMitmPhase::Request,
            &request,
            b"",
        ),
    );
    assert_eq!(
        applied(&request, &outcome.header_mutations),
        vec![("User-Agent".to_string(), "App/1.0 (iPad)".to_string())]
    );

    let response = [("Set-Cookie", "a=1; SameSite=None"), ("Set-Cookie", "b=2")];
    let outcome = plan(
        &service,
        &instance,
        &event(
            "https://m.example.test/home",
            HttpMitmPhase::Response,
            &response,
            b"",
        ),
    );
    assert_eq!(
        applied(&response, &outcome.header_mutations),
        vec![
            ("Set-Cookie".to_string(), "a=1; SameSite=Lax".to_string()),
            ("Set-Cookie".to_string(), "b=2".to_string()),
        ]
    );
}

const BINARY_PLUGIN: &str = concat!(
    "[Rewrite]\n",
    "^https://api\\.example\\.test/feed response-header-add X-Seen 1\n",
    "^https://api\\.example\\.test/feed response-body-replace-regex ads none\n",
    "^https://api\\.example\\.test/blocked reject\n",
    "\n[Script]\n",
    "http-response ^https://api\\.example\\.test/feed script-path=https://scripts.example.test/pb.js, requires-body=true, binary-body-mode=true, tag=pb\n",
    "\n[MITM]\nhostname = api.example.test\n",
);

/// mitm-scripts-05: a body with NUL bytes (protobuf, gRPC) used to fail the
/// whole plan, so the message passed untouched and the binary-body-mode
/// script never ran.
#[test]
fn binary_bodies_keep_the_plan_and_dispatch_binary_scripts() {
    let (service, instance) = load(BINARY_PLUGIN);
    let protobuf = [0x08, 0x00, 0x10, 0x01, 0xff, 0x00];
    let outcome = plan(
        &service,
        &instance,
        &event(
            "https://api.example.test/feed",
            HttpMitmPhase::Response,
            &[("Content-Type", "application/x-protobuf")],
            &protobuf,
        ),
    );

    assert_eq!(outcome.action, HttpMitmAction::Continue);
    let script = outcome
        .script_dispatch
        .as_ref()
        .expect("the binary-body-mode script should be dispatched");
    assert!(script.binary_body_mode);
    assert!(script.requires_body);
    assert_eq!(script.tag, "pb");
    assert_eq!(
        outcome.header_mutations,
        vec![HttpHeaderMutation {
            operation: HttpHeaderMutationOperation::Add,
            name: "X-Seen".to_string(),
            value: Some("1".to_string()),
        }]
    );
    // Text rules never see the bytes, and the bytes are never rewritten as
    // lossy text.
    assert!(outcome.body_mutation.is_none());
    assert!(has_diagnostic(
        &outcome,
        MITM_POLICY_HTTP_EVENT_BINARY_BODY_SKIPPED_CODE
    ));

    // Not UTF-8 but without NUL: still skipped, never rewritten with U+FFFD.
    let outcome = plan(
        &service,
        &instance,
        &event(
            "https://api.example.test/feed",
            HttpMitmPhase::Response,
            &[],
            b"ads \xff\xfe ads",
        ),
    );
    assert!(outcome.body_mutation.is_none());
    assert!(outcome.script_dispatch.is_some());

    // Text bodies are still rewritten.
    let outcome = plan(
        &service,
        &instance,
        &event(
            "https://api.example.test/feed",
            HttpMitmPhase::Response,
            &[],
            b"{\"ads\":1}",
        ),
    );
    assert_eq!(
        outcome
            .body_mutation
            .expect("text body should be rewritten")
            .body,
        b"{\"none\":1}".to_vec()
    );
}

#[test]
fn a_binary_request_body_does_not_stop_a_url_reject() {
    let (service, instance) = load(BINARY_PLUGIN);
    let outcome = plan(
        &service,
        &instance,
        &event(
            "https://api.example.test/blocked",
            HttpMitmPhase::Request,
            &[("Content-Type", "application/octet-stream")],
            &[0x00, 0x01, 0x02, 0x00],
        ),
    );
    assert_eq!(outcome.action, HttpMitmAction::Reject { status_code: 403 });
}

/// mitm-scripts-12: only a body rule or a script with `requires-body=true`
/// holds the body back; a header-only script lets it stream.
#[test]
fn only_body_readers_hold_the_body_back() {
    let (service, instance) = load(concat!(
        "[Script]\n",
        "http-response ^https://h\\.example\\.test/head script-path=https://scripts.example.test/head.js, tag=head\n",
        "http-request ^https://h\\.example\\.test/head script-path=https://scripts.example.test/req.js, requires-body=false, tag=req\n",
        "http-response ^https://h\\.example\\.test/body script-path=https://scripts.example.test/body.js, requires-body=true, tag=body\n",
        "\n[Rewrite]\n",
        "^https://h\\.example\\.test/rule response-body-replace-regex a b\n",
        "\n[MITM]\nhostname = h.example.test\n",
    ));
    let needs_body = |url: &str, phase: HttpMitmPhase| {
        service
            .needs_body(&instance, url, phase)
            .expect("needs_body should evaluate")
    };
    assert!(!needs_body(
        "https://h.example.test/head",
        HttpMitmPhase::Response
    ));
    assert!(!needs_body(
        "https://h.example.test/head",
        HttpMitmPhase::Request
    ));
    assert!(needs_body(
        "https://h.example.test/body",
        HttpMitmPhase::Response
    ));
    assert!(needs_body(
        "https://h.example.test/rule",
        HttpMitmPhase::Response
    ));
    assert!(!needs_body(
        "https://h.example.test/other",
        HttpMitmPhase::Response
    ));

    // The header-only script is still dispatched for the streamed message.
    let outcome = plan(
        &service,
        &instance,
        &event(
            "https://h.example.test/head",
            HttpMitmPhase::Response,
            &[],
            b"",
        ),
    );
    let script = outcome
        .script_dispatch
        .expect("the header script should be dispatched");
    assert!(!script.requires_body);
}

/// mitm-scripts-14: more matching body rules than the core records.
#[test]
fn a_body_chain_past_the_record_cap_still_applies_every_rule() {
    let mut source = String::from("[Rewrite]\n");
    let mut body = Vec::new();
    let mut expected = Vec::new();
    for index in 0..20 {
        source.push_str(&format!(
            "^https://api\\.example\\.test/many response-body-replace-regex t{index:02} u{index:02}\n"
        ));
        body.push(format!("t{index:02}"));
        expected.push(format!("u{index:02}"));
    }
    source.push_str("\n[MITM]\nhostname = api.example.test\n");
    let (service, instance) = load(&source);

    let outcome = plan(
        &service,
        &instance,
        &event(
            "https://api.example.test/many",
            HttpMitmPhase::Response,
            &[],
            body.join(" ").as_bytes(),
        ),
    );
    assert_eq!(
        String::from_utf8(
            outcome
                .body_mutation
                .as_ref()
                .expect("every rule should apply")
                .body
                .clone()
        )
        .unwrap(),
        expected.join(" ")
    );
    assert!(has_diagnostic(
        &outcome,
        MITM_POLICY_HTTP_EVENT_BODY_REWRITE_RECORDS_CAPPED_CODE
    ));
}

/// mitm-scripts-14: a rewrite that grows the body past the first buffer.
#[test]
fn a_body_chain_that_grows_the_body_gets_a_larger_buffer() {
    let (service, instance) = load(concat!(
        "[Rewrite]\n",
        "^https://api\\.example\\.test/grow response-body-replace-regex x yyyyyyyyyy\n",
        "^https://api\\.example\\.test/huge response-header-add X-Seen 1\n",
        "^https://api\\.example\\.test/huge response-body-replace-regex x yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy\n",
        "\n[MITM]\nhostname = api.example.test\n",
    ));

    let outcome = plan(
        &service,
        &instance,
        &event(
            "https://api.example.test/grow",
            HttpMitmPhase::Response,
            &[],
            "x".repeat(1000).as_bytes(),
        ),
    );
    assert_eq!(
        outcome
            .body_mutation
            .expect("the grown body should apply")
            .body,
        "y".repeat(10_000).into_bytes()
    );

    // Past the output limit the body rewrite is skipped with a warning; the
    // rest of the plan stands and the message is never dropped.
    let outcome = plan(
        &service,
        &instance,
        &event(
            "https://api.example.test/huge",
            HttpMitmPhase::Response,
            &[],
            "x".repeat(100_000).as_bytes(),
        ),
    );
    assert_eq!(outcome.action, HttpMitmAction::Continue);
    assert!(outcome.body_mutation.is_none());
    assert_eq!(outcome.header_mutations.len(), 1);
    assert!(has_diagnostic(
        &outcome,
        MITM_POLICY_HTTP_EVENT_BODY_REWRITE_SKIPPED_CODE
    ));
}

#[test]
fn the_engine_reports_whole_and_skipped_body_chains() {
    let mut engine = AnixOpsMitmPolicyEngine::new().expect("policy engine should allocate");
    engine
        .load_config(concat!(
            "[Rewrite]\n",
            "^https://api\\.example\\.test/grow response-body-replace-regex x yyyyyyyyyy\n",
        ))
        .expect("body rule should load");
    let body = "x".repeat(1000);

    // The plain chain still reports the cut, as the core does.
    let (_, chain) = engine
        .apply_body_chain(
            "https://api.example.test/grow",
            MitmPolicyPhase::Response,
            &body,
        )
        .expect("chain should run");
    assert!(chain.truncated);

    match engine
        .apply_body_chain_whole(
            "https://api.example.test/grow",
            MitmPolicyPhase::Response,
            &body,
        )
        .expect("chain should run")
    {
        MitmPolicyBodyChainOutcome::Applied {
            body,
            chain,
            records_capped,
        } => {
            assert_eq!(body, "y".repeat(10_000));
            assert!(!chain.truncated);
            assert!(!records_capped);
        }
        other => panic!("the chain should apply whole: {other:?}"),
    }
}
