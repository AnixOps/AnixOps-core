//! mitm-scripts-11: planning engines are bounded per policy revision.
//! Scripted messages are planned in parallel on the data plane's blocking
//! pool ([`plan_waiting_for_engines`]); when every engine of the revision is
//! leased, planning waits for one instead of loading the whole policy again,
//! so a multi-megabyte policy is loaded once however many requests a page
//! makes at the same time.
//!
//! One test in its own binary: the load counter and the pool are per
//! process, so no other test may run beside it.

use std::sync::Barrier;

use control_domain::{
    GrantedPermissions, HttpMitmAction, HttpMitmEvent, HttpMitmPhase, MetadataEntry,
    MitmPluginService, PluginInstance,
};
use mitm_policy::loon_plugin::{import_loon_plugin, merged_plugin_source};
use mitm_policy::{
    idle_policy_engines, plan_waiting_for_engines, planning_engine_loads, release_compiled_policy,
    user_plugin_package, AnixOpsMitmPluginService,
};

/// Parallel planners per policy.
const THREADS: usize = 16;
/// Messages each planner plans.
const ROUNDS: usize = 4;

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

fn request(url: &str) -> HttpMitmEvent {
    HttpMitmEvent {
        request_id: "pool".to_string(),
        url: url.to_string(),
        method: Some("GET".to_string()),
        phase: HttpMitmPhase::Request,
        status_code: None,
        headers: vec![MetadataEntry {
            key: "Host".to_string(),
            value: "a.example.test".to_string(),
        }],
        body: Vec::new(),
    }
}

/// A policy rejecting `/ads`, padded with comment lines to at least
/// `min_bytes`.
fn policy(min_bytes: usize) -> String {
    let plugin = import_loon_plugin(concat!(
        "#!name = Pool\n",
        "[Rewrite]\n",
        "^https://a\\.example\\.test/ads reject\n",
    ))
    .expect("plugin should import");
    let mut source = merged_plugin_source("Pool", &[&plugin]);
    let mut line = 0usize;
    while source.len() < min_bytes {
        source.push_str(&format!(
            "\n# padding line {line:08} keeps the policy large without adding rules"
        ));
        line += 1;
    }
    source.push('\n');
    source
}

/// Plans `THREADS * ROUNDS` messages of `source` from `THREADS` threads at
/// once, the way the data plane plans scripted messages, and answers how
/// many planning engines were loaded meanwhile.
fn plan_in_parallel(service: &AnixOpsMitmPluginService, source: &str) -> u64 {
    let instance = load(service, source);
    let before = planning_engine_loads();
    let barrier = Barrier::new(THREADS);
    std::thread::scope(|scope| {
        for index in 0..THREADS {
            let barrier = &barrier;
            let instance = &instance;
            scope.spawn(move || {
                plan_waiting_for_engines(|| {
                    barrier.wait();
                    for round in 0..ROUNDS {
                        let (url, expected) = if (index + round) % 2 == 0 {
                            (
                                "https://a.example.test/ads",
                                HttpMitmAction::Reject { status_code: 403 },
                            )
                        } else {
                            ("https://a.example.test/other", HttpMitmAction::Continue)
                        };
                        let outcome = service
                            .handle_http_mitm_event(instance, &request(url))
                            .expect("event plans");
                        assert_eq!(outcome.action, expected, "{url}");
                    }
                });
            });
        }
    });
    planning_engine_loads() - before
}

#[test]
fn parallel_planning_loads_a_revision_at_most_its_engine_limit() {
    let service = AnixOpsMitmPluginService::new();

    // Over the 2 MiB budget: one planning engine, loaded once.
    let large = policy(3 * 1024 * 1024);
    assert_eq!(
        plan_in_parallel(&service, &large),
        1,
        "parallel planning of a 3 MiB policy loaded it more than once"
    );
    assert_eq!(idle_policy_engines(), 1);

    // Outside `plan_waiting_for_engines` (an async thread) nothing waits:
    // `needs_body` takes the idle engine, and loads nothing.
    let before = planning_engine_loads();
    let instance = load(&service, &large);
    assert!(!service
        .needs_body(
            &instance,
            "https://a.example.test/other",
            HttpMitmPhase::Request
        )
        .expect("needs_body answers"));
    assert_eq!(planning_engine_loads(), before);
    release_compiled_policy(&large);
    assert_eq!(idle_policy_engines(), 0);

    // A small policy: up to four planning engines, however many threads.
    let small = policy(0);
    let loads = plan_in_parallel(&service, &small);
    assert!(
        (1..=4).contains(&loads),
        "parallel planning of a small policy loaded it {loads} times"
    );
    assert!(idle_policy_engines() <= 4);
    release_compiled_policy(&small);
    assert_eq!(idle_policy_engines(), 0);
}
