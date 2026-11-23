//! Shared `$`-API conformance suite. Each `fixtures/conformance/<case>.json`
//! describes one dispatch of `<case>.js` and its expected outcome. The fixture
//! format is engine-neutral: QuickJS and JavaScriptCore run the same files. A
//! fixture's `requires` list names engine capabilities (`heap-limit`); an
//! engine without one skips that fixture.
#![cfg(feature = "quickjs")]

use script_runtime::{
    binary_body_string, MemoryScriptStore, QuickJsScriptRuntime, ScriptFailure, ScriptHttpClient,
    ScriptHttpClientRequest, ScriptInvocation, ScriptLimits, ScriptMutation, ScriptOutcome,
    ScriptPhase, ScriptRequest, ScriptResponse, ScriptRuleRequest, ScriptRunStatus, ScriptStore,
    SCRIPT_HTTP_CLIENT_DISABLED_MESSAGE,
};
use serde_json::{Map, Value};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

/// `$httpClient` for the fixtures: `https://stub.example.test/bytes`
/// answers four bytes that are not UTF-8, `/echo` describes the request it
/// got; every other URL fails as a disabled client does.
struct StubHttpClient;

const STUB_BYTES: [u8; 4] = [0x00, 0x01, 0x80, 0xff];

impl ScriptHttpClient for StubHttpClient {
    fn execute(&self, request: &ScriptHttpClientRequest) -> Result<ScriptResponse, String> {
        let body = match request.url.as_str() {
            "https://stub.example.test/bytes" => STUB_BYTES.to_vec(),
            "https://stub.example.test/echo" => format!(
                "{}|follow={}|binary={}|body={}",
                request.method,
                request.follow_redirects,
                request.binary_response,
                request
                    .body_bytes()
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect::<String>()
            )
            .into_bytes(),
            _ => return Err(SCRIPT_HTTP_CLIENT_DISABLED_MESSAGE.to_string()),
        };
        Ok(ScriptResponse {
            status: 200,
            headers: vec![(
                "Content-Type".to_string(),
                "application/octet-stream".to_string(),
            )],
            body: Some(if request.binary_response {
                binary_body_string(&body)
            } else {
                String::from_utf8_lossy(&body).into_owned()
            }),
        })
    }
}

fn fixture_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/conformance")
}

fn headers(value: Option<&Value>) -> Vec<(String, String)> {
    value
        .and_then(Value::as_object)
        .map(|object| {
            object
                .iter()
                .map(|(name, value)| (name.clone(), value.as_str().unwrap().to_string()))
                .collect()
        })
        .unwrap_or_default()
}

fn header_map(headers: &[(String, String)]) -> BTreeMap<String, String> {
    headers.iter().cloned().collect()
}

fn text(value: Option<&Value>) -> Option<String> {
    value.and_then(Value::as_str).map(str::to_string)
}

fn response(value: &Value) -> ScriptResponse {
    ScriptResponse {
        status: value.get("status").and_then(Value::as_u64).unwrap_or(200) as u16,
        headers: headers(value.get("headers")),
        body: text(value.get("body")),
    }
}

fn invocation(value: &Value) -> ScriptInvocation {
    let request = &value["request"];
    ScriptInvocation {
        phase: match value["phase"].as_str() {
            Some("request") => ScriptPhase::Request,
            Some("response") => ScriptPhase::Response,
            Some("cron") => ScriptPhase::Cron,
            Some("event") => ScriptPhase::Event,
            Some("generic") => ScriptPhase::Generic,
            Some("rule") => ScriptPhase::Rule,
            other => panic!("unknown phase {other:?}"),
        },
        script_name: text(value.get("scriptName")).unwrap_or_else(|| "fixture".to_string()),
        argument: text(value.get("argument")).unwrap_or_default(),
        request: ScriptRequest {
            url: text(request.get("url")).unwrap_or_default(),
            method: text(request.get("method")).unwrap_or_else(|| "GET".to_string()),
            headers: headers(request.get("headers")),
            body: text(request.get("body")),
        },
        response: value.get("response").map(response),
        binary_body: value
            .get("binaryBody")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        body_is_bytes: value
            .get("bodyIsBytes")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        event: text(value.get("event")),
        rule: value.get("rule").map(|rule| ScriptRuleRequest {
            hostname: text(rule.get("hostname")),
            dest_ip: text(rule.get("destIP")).map(|ip| ip.parse().unwrap()),
            dest_port: rule
                .get("destPort")
                .and_then(Value::as_u64)
                .map(|port| port as u16),
            source_ip: text(rule.get("sourceIP")).map(|ip| ip.parse().unwrap()),
            in_port: rule
                .get("inPort")
                .and_then(Value::as_u64)
                .map(|port| port as u16),
            process_name: text(rule.get("processName")),
            protocol: text(rule.get("protocol")),
            user_agent: text(rule.get("userAgent")),
            url: text(rule.get("url")),
        }),
    }
}

fn limits(value: Option<&Value>) -> ScriptLimits {
    let mut limits = ScriptLimits {
        timeout: Duration::from_secs(5),
        ..ScriptLimits::default()
    };
    let Some(value) = value else {
        return limits;
    };
    if let Some(timeout) = value.get("timeoutMs").and_then(Value::as_u64) {
        limits.timeout = Duration::from_millis(timeout);
    }
    if let Some(memory) = value.get("memoryBytes").and_then(Value::as_u64) {
        limits.memory_limit_bytes = memory as usize;
    }
    if let Some(max_body) = value.get("maxBodyBytes").and_then(Value::as_u64) {
        limits.max_body_bytes = max_body as usize;
    }
    limits
}

fn expected_mutation(value: Option<&Value>) -> ScriptMutation {
    let empty = Map::new();
    let object = value.and_then(Value::as_object).unwrap_or(&empty);
    ScriptMutation {
        url: text(object.get("url")),
        status: object
            .get("status")
            .and_then(Value::as_u64)
            .map(|status| status as u16),
        headers: object.get("headers").map(|value| headers(Some(value))),
        body: text(object.get("body")),
        response: object.get("response").map(response),
        matched: object.get("matched").and_then(Value::as_bool),
        binary_bodies: object
            .get("binaryBodies")
            .and_then(Value::as_bool)
            .unwrap_or(false),
    }
}

fn assert_mutation_eq(case: &str, actual: &ScriptMutation, expected: &ScriptMutation) {
    let normalize = |mutation: &ScriptMutation| {
        (
            mutation.url.clone(),
            mutation.status,
            mutation.headers.as_deref().map(header_map),
            mutation.body.clone(),
            mutation.response.as_ref().map(|response| {
                (
                    response.status,
                    header_map(&response.headers),
                    response.body.clone(),
                )
            }),
            mutation.matched,
            mutation.binary_bodies,
        )
    };
    assert_eq!(normalize(actual), normalize(expected), "{case}: mutation");
}

fn status_name(status: &ScriptRunStatus) -> &'static str {
    match status {
        ScriptRunStatus::Done => "done",
        ScriptRunStatus::FinishedWithoutDone => "finished_without_done",
        ScriptRunStatus::Failed(_) => "failed",
    }
}

/// One engine under test: builds a runtime over `store` and runs a dispatch.
type EngineRunner =
    dyn Fn(Arc<dyn ScriptStore>, &str, &ScriptInvocation, &ScriptLimits) -> ScriptOutcome;

fn check_case(case: &str, fixture: &Value, script: &str, run: &EngineRunner) {
    let store = Arc::new(MemoryScriptStore::with_entries(
        fixture
            .get("store")
            .and_then(Value::as_object)
            .map(|object| {
                object
                    .iter()
                    .map(|(key, value)| (key.clone(), value.as_str().unwrap().to_string()))
                    .collect()
            })
            .unwrap_or_default(),
    ));
    let outcome: ScriptOutcome = run(
        Arc::clone(&store) as Arc<dyn ScriptStore>,
        script,
        &invocation(&fixture["invocation"]),
        &limits(fixture.get("limits")),
    );

    let expect = &fixture["expect"];
    assert_eq!(
        status_name(&outcome.status),
        expect["status"].as_str().unwrap(),
        "{case}: status {:?}",
        outcome.status
    );
    if let Some(failure) = expect.get("failure").and_then(Value::as_str) {
        let ScriptRunStatus::Failed(actual) = &outcome.status else {
            unreachable!();
        };
        assert_eq!(actual.code(), failure, "{case}: failure {actual:?}");
    }
    assert_mutation_eq(
        case,
        &outcome.mutation,
        &expected_mutation(expect.get("mutation")),
    );
    if let Some(expected_store) = expect.get("store").and_then(Value::as_object) {
        let expected_store = expected_store
            .iter()
            .map(|(key, value)| (key.clone(), value.as_str().unwrap().to_string()))
            .collect::<BTreeMap<_, _>>();
        assert_eq!(store.snapshot(), expected_store, "{case}: store");
    }
    if let Some(expected) = expect.get("notifications").and_then(Value::as_array) {
        let actual = outcome
            .notifications
            .iter()
            .map(|notification| {
                (
                    notification.title.clone(),
                    notification.subtitle.clone(),
                    notification.content.clone(),
                    notification.open_url.clone(),
                )
            })
            .collect::<Vec<_>>();
        let expected = expected
            .iter()
            .map(|notification| {
                (
                    text(notification.get("title")).unwrap_or_default(),
                    text(notification.get("subtitle")).unwrap_or_default(),
                    text(notification.get("content")).unwrap_or_default(),
                    text(notification.get("openUrl")),
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(actual, expected, "{case}: notifications");
    }
    if let Some(expected) = expect.get("logs").and_then(Value::as_array) {
        let expected = expected
            .iter()
            .map(|line| line.as_str().unwrap().to_string())
            .collect::<Vec<_>>();
        assert_eq!(outcome.logs, expected, "{case}: logs");
    }
}

/// Runs every fixture whose `requires` list `capabilities` covers; returns the
/// names of the skipped ones.
fn run_suite(capabilities: &[&str], run: &EngineRunner) -> Vec<String> {
    let mut cases = std::fs::read_dir(fixture_dir())
        .expect("conformance fixture directory should exist")
        .map(|entry| entry.unwrap().path())
        .filter(|path| {
            path.extension()
                .is_some_and(|extension| extension == "json")
        })
        .collect::<Vec<_>>();
    cases.sort();
    assert!(cases.len() >= 15, "conformance suite lost fixtures");

    let mut skipped = Vec::new();
    for case_path in cases {
        let case = case_path.file_stem().unwrap().to_string_lossy().to_string();
        let fixture: Value =
            serde_json::from_slice(&std::fs::read(&case_path).unwrap()).expect("fixture JSON");
        let supported = fixture
            .get("requires")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .all(|capability| capabilities.contains(&capability.as_str().unwrap()));
        if !supported {
            skipped.push(case);
            continue;
        }
        let script = std::fs::read_to_string(case_path.with_extension("js"))
            .unwrap_or_else(|_| panic!("{case}: missing script"));
        check_case(&case, &fixture, &script, run);
    }
    skipped
}

#[test]
fn quickjs_passes_shared_conformance_fixtures() {
    let skipped = run_suite(&["heap-limit"], &|store, script, invocation, limits| {
        QuickJsScriptRuntime::new(store, Arc::new(StubHttpClient)).run(script, invocation, limits)
    });
    assert!(skipped.is_empty(), "QuickJS skipped {skipped:?}");
}

#[cfg(all(feature = "javascriptcore", target_vendor = "apple"))]
mod javascriptcore {
    use super::*;
    use script_runtime::{JscScriptRuntime, MAX_STUCK_WORKERS};

    #[test]
    fn javascriptcore_passes_shared_conformance_fixtures() {
        let skipped = run_suite(&[], &|store, script, invocation, limits| {
            JscScriptRuntime::new(store, Arc::new(StubHttpClient)).run(script, invocation, limits)
        });
        assert_eq!(
            skipped,
            ["memory-limit"],
            "only the heap limit may be skipped"
        );
    }

    #[test]
    fn stuck_busy_loops_are_abandoned_then_refused() {
        let runtime = JscScriptRuntime::default();
        let invocation = ScriptInvocation {
            phase: ScriptPhase::Request,
            script_name: "busy".to_string(),
            argument: String::new(),
            request: ScriptRequest {
                url: "https://api.example.test/".to_string(),
                method: "GET".to_string(),
                headers: Vec::new(),
                body: None,
            },
            response: None,
            binary_body: false,
            body_is_bytes: false,
            event: None,
            rule: None,
        };
        let limits = ScriptLimits {
            timeout: Duration::from_millis(100),
            ..ScriptLimits::default()
        };
        for stuck in 1..=MAX_STUCK_WORKERS {
            let outcome = runtime.run("for (;;) {}", &invocation, &limits);
            assert_eq!(
                outcome.status,
                ScriptRunStatus::Failed(ScriptFailure::Timeout)
            );
            assert_eq!(runtime.stuck_workers(), stuck);
        }
        let refused = runtime.run("$done({});", &invocation, &limits);
        let ScriptRunStatus::Failed(failure) = &refused.status else {
            panic!("expected a refusal, got {:?}", refused.status);
        };
        assert_eq!(failure.code(), "script.engine");

        // A finite script that overruns is no longer counted once it ends.
        let other = JscScriptRuntime::default();
        let outcome = other.run(
            "var end = Date.now() + 800; while (Date.now() < end) {}",
            &invocation,
            &limits,
        );
        assert_eq!(
            outcome.status,
            ScriptRunStatus::Failed(ScriptFailure::Timeout)
        );
        assert_eq!(other.stuck_workers(), 1);
        std::thread::sleep(Duration::from_millis(1500));
        assert_eq!(other.stuck_workers(), 0);
        assert_eq!(
            other.run("$done({});", &invocation, &limits).status,
            ScriptRunStatus::Done
        );
    }
}

#[test]
fn failure_codes_are_stable() {
    assert_eq!(ScriptFailure::Timeout.code(), "script.timeout");
    assert_eq!(ScriptFailure::MemoryLimit.code(), "script.memory_limit");
    assert_eq!(
        ScriptFailure::Exception(String::new()).code(),
        "script.exception"
    );
}

#[test]
fn json_file_store_persists_and_refuses_oversized_values() {
    let dir = std::env::temp_dir().join(format!(
        "networkcore-script-store-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("store.json");

    let store = script_runtime::JsonFileScriptStore::open(&path).expect("missing file is empty");
    assert!(store.write("token", "abc"));
    assert!(!store.write(
        "big",
        &"x".repeat(script_runtime::SCRIPT_STORE_MAX_VALUE_BYTES + 1)
    ));
    assert!(!store.write("", "empty key"));
    drop(store);

    let reopened = script_runtime::JsonFileScriptStore::open(&path).expect("store reopens");
    assert_eq!(reopened.read("token").as_deref(), Some("abc"));
    assert_eq!(reopened.read("big"), None);
    assert!(reopened.remove("token"));
    assert_eq!(reopened.read("token"), None);

    std::fs::write(&path, b"[1,2]").unwrap();
    assert!(script_runtime::JsonFileScriptStore::open(&path).is_err());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_corrupt_store_file_is_set_aside_and_the_store_starts_empty() {
    let dir = std::env::temp_dir().join(format!(
        "networkcore-script-store-recover-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("store.json");
    let backup = dir.join(format!(
        "store.json{}",
        script_runtime::SCRIPT_STORE_QUARANTINE_SUFFIX
    ));

    // A healthy file opens as it is.
    std::fs::write(&path, br#"{"token":"abc"}"#).unwrap();
    let (store, recovery) = script_runtime::open_script_store(&path);
    assert_eq!(recovery, script_runtime::ScriptStoreRecovery::Opened);
    assert_eq!(store.read("token").as_deref(), Some("abc"));
    drop(store);

    // Truncated JSON and a non-string value are both set aside; only the
    // latest copy is kept.
    for broken in [&br#"{"token":"ab"#[..], &br#"{"count":1}"#[..], &b""[..]] {
        std::fs::write(&path, broken).unwrap();
        let (store, recovery) = script_runtime::open_script_store(&path);
        assert_eq!(
            recovery,
            script_runtime::ScriptStoreRecovery::Quarantined {
                backup: backup.clone()
            }
        );
        assert_eq!(std::fs::read(&backup).unwrap(), broken);
        assert_eq!(store.read("token"), None);
        assert!(store.write("token", "fresh"));
        drop(store);
        let reopened = script_runtime::JsonFileScriptStore::open(&path).expect("fresh store");
        assert_eq!(reopened.read("token").as_deref(), Some("fresh"));
    }
    let names = std::fs::read_dir(&dir)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(
        names,
        ["store.json", "store.json.corrupt"]
            .into_iter()
            .map(String::from)
            .collect(),
        "no temporary file or older copy is left behind"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn json_file_store_skips_writes_that_change_nothing() {
    let dir = std::env::temp_dir().join(format!(
        "networkcore-script-store-same-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("store.json");
    let store = script_runtime::JsonFileScriptStore::open(&path).expect("missing file is empty");
    assert!(store.write("token", "abc"));
    // Replace the file behind the store's back: an unchanged write must not
    // rewrite it.
    std::fs::write(&path, br#"{"token":"abc","marker":"kept"}"#).unwrap();
    assert!(store.write("token", "abc"));
    assert_eq!(
        std::fs::read(&path).unwrap(),
        br#"{"token":"abc","marker":"kept"}"#.to_vec()
    );
    assert!(store.write("token", "def"));
    let reopened = script_runtime::JsonFileScriptStore::open(&path).expect("store reopens");
    assert_eq!(reopened.read("token").as_deref(), Some("def"));
    assert_eq!(reopened.read("marker"), None);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn concurrent_dispatches_share_only_the_store() {
    let store = Arc::new(MemoryScriptStore::new());
    let runtime = QuickJsScriptRuntime::new(
        Arc::clone(&store) as Arc<dyn ScriptStore>,
        Arc::new(script_runtime::DisabledScriptHttpClient),
    );
    let threads = (0..4)
        .map(|index| {
            let runtime = runtime.clone();
            std::thread::spawn(move || {
                let invocation = ScriptInvocation {
                    phase: ScriptPhase::Request,
                    script_name: format!("worker{index}"),
                    argument: index.to_string(),
                    request: ScriptRequest {
                        url: "https://api.example.test/".to_string(),
                        method: "GET".to_string(),
                        headers: Vec::new(),
                        body: None,
                    },
                    response: None,
                    binary_body: false,
                    body_is_bytes: false,
                    event: None,
                    rule: None,
                };
                runtime.run(
                    "leaked = (typeof leaked === 'undefined') ? $argument : 'shared';\
                     $persistentStore.write(leaked);\
                     $done({ url: $request.url + leaked });",
                    &invocation,
                    &ScriptLimits::default(),
                )
            })
        })
        .collect::<Vec<_>>();
    for (index, thread) in threads.into_iter().enumerate() {
        let outcome = thread.join().unwrap();
        assert_eq!(outcome.status, ScriptRunStatus::Done);
        assert_eq!(
            outcome.mutation.url.as_deref(),
            Some(format!("https://api.example.test/{index}").as_str())
        );
    }
    assert_eq!(store.snapshot().len(), 4);
}
