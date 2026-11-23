//! Contracts for the in-process QuickJS `[Script]` executor on the MITM hook.

use control_domain::{
    AuditEvent, Diagnostic, DomainResult, GrantedPermissions, HookPoint, HttpEvent, HttpMitmAction,
    HttpMitmEvent, HttpMitmOutcome, HttpMitmPhase, HttpMitmScriptDispatch, HttpMitmScriptKind,
    MetadataEntry, MitmPluginService, PluginInstance, PluginManifest, PluginPackage,
    PluginPermission, PluginResult,
};
use engine_native::{
    scaled_memory_limit, NativeHttpMitmPluginHook, NativePlainHttpMessage,
    NativeQuickJsScriptExecutor, NativeQuickJsScriptRuntimeConfig, ScriptStoreRecovery,
    ENGINE_NATIVE_QUICKJS_SCRIPT_CONFIG_INVALID_CODE,
    ENGINE_NATIVE_RUNTIME_HTTP_SCRIPT_BODY_IGNORED_CODE,
    ENGINE_NATIVE_RUNTIME_HTTP_SCRIPT_FAILED_CODE, QUICKJS_MAX_SCALED_MEMORY_LIMIT_BYTES,
};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

const SCRIPT_URL: &str = "https://scripts.networkcore.test/contract.js";

struct ScriptDispatchingService {
    timeout_ms: usize,
    binary_body_mode: bool,
    requires_body: bool,
}

impl MitmPluginService for ScriptDispatchingService {
    fn validate_manifest(&self, _plugin_manifest: &PluginManifest) -> Vec<Diagnostic> {
        Vec::new()
    }

    fn load(
        &self,
        plugin_package: &PluginPackage,
        _granted_permissions: &GrantedPermissions,
    ) -> DomainResult<PluginInstance> {
        Ok(PluginInstance {
            manifest: plugin_package.manifest.clone(),
            loaded_source: None,
        })
    }

    fn handle_http_event(
        &self,
        _plugin_instance: &PluginInstance,
        _http_event: &HttpEvent,
    ) -> DomainResult<PluginResult> {
        Ok(PluginResult {
            audits: Vec::new(),
            diagnostics: Vec::new(),
        })
    }

    fn handle_http_mitm_event(
        &self,
        _plugin_instance: &PluginInstance,
        http_event: &HttpMitmEvent,
    ) -> DomainResult<HttpMitmOutcome> {
        let kind = match http_event.phase {
            HttpMitmPhase::Request => HttpMitmScriptKind::Request,
            HttpMitmPhase::Response => HttpMitmScriptKind::Response,
        };
        Ok(HttpMitmOutcome {
            action: HttpMitmAction::Continue,
            header_mutations: Vec::new(),
            body_mutation: None,
            script_dispatch: Some(HttpMitmScriptDispatch {
                kind,
                phase: http_event.phase,
                requires_body: self.requires_body,
                timeout_ms: self.timeout_ms,
                max_size: 4096,
                script_path: SCRIPT_URL.to_string(),
                tag: "contract".to_string(),
                argument: "mode=contract".to_string(),
                binary_body_mode: self.binary_body_mode,
            }),
            audits: Vec::new(),
            diagnostics: Vec::new(),
        })
    }

    fn audit(&self, plugin_result: &PluginResult) -> Vec<AuditEvent> {
        plugin_result.audits.clone()
    }
}

fn temp_dir(name: &str) -> PathBuf {
    let dir =
        std::env::temp_dir().join(format!("networkcore-quickjs-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("temp dir should be created");
    dir
}

fn executor(script: &Path, store: Option<&Path>) -> NativeQuickJsScriptExecutor {
    let mut script_assets = BTreeMap::new();
    script_assets.insert(SCRIPT_URL.to_string(), script.display().to_string());
    NativeQuickJsScriptExecutor::new(NativeQuickJsScriptRuntimeConfig {
        script_assets,
        persistent_store_path: store.map(|path| path.display().to_string()),
        max_timeout_ms: 5000,
        max_body_bytes: 4096,
        memory_limit_bytes: 0,
    })
    .expect("mapped script should configure the QuickJS executor")
}

fn hook(executor: NativeQuickJsScriptExecutor, timeout_ms: usize) -> NativeHttpMitmPluginHook {
    hook_with(executor, timeout_ms, false)
}

fn hook_with(
    executor: NativeQuickJsScriptExecutor,
    timeout_ms: usize,
    binary_body_mode: bool,
) -> NativeHttpMitmPluginHook {
    hook_for(
        executor,
        ScriptDispatchingService {
            timeout_ms,
            binary_body_mode,
            requires_body: true,
        },
    )
}

fn hook_for(
    executor: NativeQuickJsScriptExecutor,
    service: ScriptDispatchingService,
) -> NativeHttpMitmPluginHook {
    NativeHttpMitmPluginHook::new(
        PluginInstance {
            manifest: PluginManifest {
                id: "networkcore.quickjs-contract".to_string(),
                version: "0.1.0".to_string(),
                permissions: vec![
                    PluginPermission::ReadRequest,
                    PluginPermission::ModifyRequest,
                    PluginPermission::ReadResponse,
                    PluginPermission::ModifyResponse,
                ],
                hooks: vec![HookPoint::Request, HookPoint::Response],
            },
            loaded_source: None,
        },
        Arc::new(service),
    )
    .with_quickjs_script_executor(executor)
}

fn message(phase: HttpMitmPhase, body: &str) -> NativePlainHttpMessage {
    NativePlainHttpMessage {
        request_id: "quickjs-contract".to_string(),
        url: "https://api.networkcore.test/v1/feed".to_string(),
        method: Some("GET".to_string()),
        phase,
        status_code: (phase == HttpMitmPhase::Response).then_some(200),
        headers: vec![MetadataEntry {
            key: "Content-Type".to_string(),
            value: "application/json".to_string(),
        }],
        body: body.as_bytes().to_vec(),
        request_headers: Vec::new(),
        request_body: None,
    }
}

#[test]
fn quickjs_response_script_rewrites_body_and_persists_store() {
    let dir = temp_dir("response");
    let script = dir.join("response.js");
    std::fs::write(
        &script,
        "var body = JSON.parse($response.body); delete body.ad; body.mode = $argument;\
         $persistentStore.write('seen', 'last');\
         $done({ body: JSON.stringify(body), headers: { 'Content-Type': 'application/json', 'X-Script': '1' } });",
    )
    .unwrap();
    let store = dir.join("store.json");
    let hook = hook(executor(&script, Some(store.as_path())), 1000);
    assert_eq!(hook.script_engine(), Some("quickjs-ng"));
    assert_eq!(hook.script_sandbox(), None);

    let report = hook.plan_plain_http(&message(HttpMitmPhase::Response, "{\"ad\":1,\"items\":[]}"));

    assert!(report.script_dispatch_executed, "{:?}", report.diagnostics);
    assert!(report.applied);
    assert_eq!(
        String::from_utf8(report.body).unwrap(),
        "{\"items\":[],\"mode\":\"mode=contract\"}"
    );
    assert!(report
        .headers
        .iter()
        .any(|header| header.key == "X-Script" && header.value == "1"));
    let stored = std::fs::read_to_string(&store).expect("store file should be written");
    assert!(stored.contains("\"last\":\"seen\""), "{stored}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn quickjs_response_script_reads_the_request_it_answers() {
    let dir = temp_dir("response-request");
    let script = dir.join("request-in-response.js");
    std::fs::write(
        &script,
        "$done({ body: [$request.method, $request.headers['Cookie'], $request.headers['Content-Type'],\
         String($request.body), $response.headers['Content-Type'], $response.body].join('|') });",
    )
    .unwrap();
    let hook = hook(executor(&script, None), 1000);
    let mut response = message(HttpMitmPhase::Response, "{\"ok\":true}");
    response.method = Some("POST".to_string());
    response.request_headers = vec![
        MetadataEntry {
            key: "Cookie".to_string(),
            value: "session=abc; theme=dark".to_string(),
        },
        MetadataEntry {
            key: "Content-Type".to_string(),
            value: "application/x-www-form-urlencoded".to_string(),
        },
    ];
    response.request_body = Some(b"user=1".to_vec());

    let report = hook.plan_plain_http(&response);

    assert!(report.script_dispatch_executed, "{:?}", report.diagnostics);
    assert_eq!(
        String::from_utf8(report.body).unwrap(),
        "POST|session=abc; theme=dark|application/x-www-form-urlencoded|user=1|application/json|{\"ok\":true}"
    );

    // A request body text mode cannot carry, or one past the limit, is left
    // out; the response script still runs.
    for body in [vec![0xff, 0xfe], vec![b'a'; 4097]] {
        response.request_body = Some(body);
        let report = hook.plan_plain_http(&response);
        assert!(report.script_dispatch_executed, "{:?}", report.diagnostics);
        assert!(String::from_utf8(report.body)
            .unwrap()
            .contains("|application/x-www-form-urlencoded|undefined|"),);
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn quickjs_binary_body_mode_passes_bytes_both_ways() {
    let dir = temp_dir("binary");
    let script = dir.join("binary.js");
    std::fs::write(
        &script,
        "var bytes = $response.body;\
         if (!(bytes instanceof Uint8Array)) { throw new Error('not bytes'); }\
         var out = new Uint8Array(bytes.length + 1);\
         out.set(bytes); out[bytes.length] = 0xff;\
         $done({ body: out });",
    )
    .unwrap();
    let hook = hook_with(executor(&script, None), 1000, true);
    let mut response = message(HttpMitmPhase::Response, "");
    // Not UTF-8: a binary body the text mode would defer.
    response.body = vec![0x08, 0x96, 0x01, 0x00, 0xc3];

    let report = hook.plan_plain_http(&response);

    assert!(report.script_dispatch_executed, "{:?}", report.diagnostics);
    assert_eq!(report.body, vec![0x08, 0x96, 0x01, 0x00, 0xc3, 0xff]);
    let _ = std::fs::remove_dir_all(&dir);
}

/// Quantumult X scripts read `bodyBytes` without binary-body-mode: a body
/// that is not UTF-8 reaches them as bytes, and `$done({bodyBytes})` writes
/// bytes back. A text script that never reads `bodyBytes` is still deferred
/// on such a body.
#[test]
fn quickjs_quantumult_body_bytes_work_without_binary_mode() {
    let dir = temp_dir("quantumult-bytes");
    let script = dir.join("protobuf.js");
    std::fs::write(
        &script,
        "var view = new Uint8Array($response.bodyBytes);\
         var out = new Uint8Array(view.length + 1); out.set(view); out[view.length] = 0x00;\
         $done({ bodyBytes: out.buffer });",
    )
    .unwrap();
    let hook = hook_with(executor(&script, None), 1000, false);
    let mut response = message(HttpMitmPhase::Response, "");
    response.body = vec![0x08, 0x96, 0x01, 0xc3];

    let report = hook.plan_plain_http(&response);

    assert!(report.script_dispatch_executed, "{:?}", report.diagnostics);
    assert_eq!(report.body, vec![0x08, 0x96, 0x01, 0xc3, 0x00]);

    // Text bodies keep their text view and gain the bytes.
    let text = hook.plan_plain_http(&message(HttpMitmPhase::Response, "é"));
    assert!(text.script_dispatch_executed, "{:?}", text.diagnostics);
    assert_eq!(text.body, vec![0xc3, 0xa9, 0x00]);

    let plain = dir.join("text.js");
    std::fs::write(&plain, "$done({ body: $response.body + '!' });").unwrap();
    let hook = hook_with(executor(&plain, None), 1000, false);
    let report = hook.plan_plain_http(&response);
    assert!(!report.script_dispatch_executed);
    assert!(report.script_dispatch_deferred, "{:?}", report.diagnostics);
    assert_eq!(report.body, vec![0x08, 0x96, 0x01, 0xc3]);
    let _ = std::fs::remove_dir_all(&dir);
}

/// A script without `requires-body` never read the body, and the data plane
/// streams such bodies, so a body it returns is not applied.
#[test]
fn quickjs_script_without_requires_body_cannot_replace_the_body() {
    let dir = temp_dir("header-only");
    let script = dir.join("header-only.js");
    std::fs::write(
        &script,
        "$done({ body: 'replaced', headers: { 'Content-Type': 'application/json', 'X-Script': '1' } });",
    )
    .unwrap();
    let hook = hook_for(
        executor(&script, None),
        ScriptDispatchingService {
            timeout_ms: 1000,
            binary_body_mode: false,
            requires_body: false,
        },
    );

    let report = hook.plan_plain_http(&message(HttpMitmPhase::Response, "{\"items\":[]}"));

    assert!(report.script_dispatch_executed, "{:?}", report.diagnostics);
    assert_eq!(String::from_utf8(report.body).unwrap(), "{\"items\":[]}");
    assert!(report
        .headers
        .iter()
        .any(|header| header.key == "X-Script" && header.value == "1"));
    assert!(report
        .diagnostics
        .iter()
        .any(|diagnostic| diagnostic.code == ENGINE_NATIVE_RUNTIME_HTTP_SCRIPT_BODY_IGNORED_CODE));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn quickjs_request_script_can_answer_without_the_origin() {
    let dir = temp_dir("mock");
    let script = dir.join("mock.js");
    std::fs::write(
        &script,
        "$done({ response: { status: 403, headers: { 'Content-Type': 'text/plain' }, body: 'blocked ' + $request.method } });",
    )
    .unwrap();
    let hook = hook(executor(&script, None), 1000);

    let report = hook.plan_plain_http(&message(HttpMitmPhase::Request, ""));

    assert_eq!(report.terminal_action.as_deref(), Some("script-response"));
    assert_eq!(report.final_status_code, Some(403));
    assert_eq!(String::from_utf8(report.body).unwrap(), "blocked GET");
    assert_eq!(report.headers.len(), 1);
    let _ = std::fs::remove_dir_all(&dir);
}

const MIB: usize = 1024 * 1024;

#[test]
fn large_scripts_get_a_heap_that_fits_their_source() {
    assert_eq!(scaled_memory_limit(8 * MIB, 100 * 1024), 8 * MIB);
    assert_eq!(scaled_memory_limit(8 * MIB, MIB), 10 * MIB);
    assert_eq!(scaled_memory_limit(8 * MIB, 3 * MIB), 22 * MIB);
    assert_eq!(
        scaled_memory_limit(8 * MIB, 64 * MIB),
        QUICKJS_MAX_SCALED_MEMORY_LIMIT_BYTES
    );
    assert_eq!(scaled_memory_limit(48 * MIB, 3 * MIB), 48 * MIB);
}

#[test]
fn a_script_of_a_few_mib_runs_under_a_small_configured_heap() {
    let dir = temp_dir("large");
    let script = dir.join("large.js");
    let filler = "x".repeat(3 * MIB);
    std::fs::write(
        &script,
        format!("var s = \"{filler}\";\n$done({{ body: String(s.length) }});"),
    )
    .unwrap();
    let mut script_assets = BTreeMap::new();
    script_assets.insert(SCRIPT_URL.to_string(), script.display().to_string());
    let executor = NativeQuickJsScriptExecutor::new(NativeQuickJsScriptRuntimeConfig {
        script_assets,
        persistent_store_path: None,
        max_timeout_ms: 5000,
        max_body_bytes: 4096,
        memory_limit_bytes: 8 * MIB,
    })
    .unwrap()
    // Smaller than the dispatch's limit: it still runs, alone.
    .with_memory_budget(MIB);
    let hook = hook(executor, 5000);

    let report = hook.plan_plain_http(&message(HttpMitmPhase::Response, "{}"));

    assert!(report.script_dispatch_executed, "{:?}", report.diagnostics);
    assert_eq!(
        String::from_utf8(report.body).unwrap(),
        (3 * MIB).to_string()
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn quickjs_script_timeout_leaves_the_message_unchanged() {
    let dir = temp_dir("timeout");
    let script = dir.join("loop.js");
    std::fs::write(&script, "for (;;) {}").unwrap();
    let hook = hook(executor(&script, None), 100);

    let report = hook.plan_plain_http(&message(HttpMitmPhase::Response, "{\"a\":1}"));

    assert!(report.script_dispatch_failed);
    assert!(!report.script_dispatch_executed);
    assert_eq!(String::from_utf8(report.body).unwrap(), "{\"a\":1}");
    assert!(report.diagnostics.iter().any(|diagnostic| {
        diagnostic.code == ENGINE_NATIVE_RUNTIME_HTTP_SCRIPT_FAILED_CODE
            && diagnostic.message.contains("script.timeout")
    }));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn quickjs_script_defers_when_the_authorized_asset_changes() {
    let dir = temp_dir("hash");
    let script = dir.join("asset.js");
    std::fs::write(&script, "$done({ body: 'authorized' });").unwrap();
    let hook = hook(executor(&script, None), 1000);
    std::fs::write(&script, "$done({ body: 'replaced' });").unwrap();

    let report = hook.plan_plain_http(&message(HttpMitmPhase::Response, "original"));

    assert!(report.script_dispatch_deferred);
    assert_eq!(String::from_utf8(report.body).unwrap(), "original");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn quickjs_script_source_is_read_and_hashed_once_while_the_file_is_unchanged() {
    let dir = temp_dir("source-cache");
    let script = dir.join("asset.js");
    std::fs::write(&script, "$done({ body: 'authorized' });").unwrap();
    let modified = std::fs::metadata(&script).unwrap().modified().unwrap();
    let hook = hook(executor(&script, None), 1000);

    let first = hook.plan_plain_http(&message(HttpMitmPhase::Response, "original"));
    assert_eq!(String::from_utf8(first.body).unwrap(), "authorized");

    // Same size and modification time: the verified copy in memory runs and
    // the file is not read again, so these bytes never execute.
    std::fs::write(&script, "$done({ body: 'xxxxxxxxxx' });").unwrap();
    std::fs::File::options()
        .write(true)
        .open(&script)
        .unwrap()
        .set_modified(modified)
        .unwrap();
    let cached = hook.plan_plain_http(&message(HttpMitmPhase::Response, "original"));
    assert!(!cached.script_dispatch_deferred);
    assert_eq!(String::from_utf8(cached.body).unwrap(), "authorized");

    // A real change (new size) is read, hashed and refused as before.
    std::fs::write(&script, "$done({ body: 'replaced' });").unwrap();
    let changed = hook.plan_plain_http(&message(HttpMitmPhase::Response, "original"));
    assert!(changed.script_dispatch_deferred);
    assert_eq!(String::from_utf8(changed.body).unwrap(), "original");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn quickjs_executor_rejects_missing_assets() {
    let dir = temp_dir("config");
    let mut script_assets = BTreeMap::new();
    script_assets.insert(
        SCRIPT_URL.to_string(),
        dir.join("missing.js").display().to_string(),
    );
    let missing = NativeQuickJsScriptExecutor::new(NativeQuickJsScriptRuntimeConfig {
        script_assets,
        persistent_store_path: None,
        max_timeout_ms: 1000,
        max_body_bytes: 1024,
        memory_limit_bytes: 0,
    })
    .expect_err("missing script asset must be rejected");
    assert_eq!(
        missing.code,
        ENGINE_NATIVE_QUICKJS_SCRIPT_CONFIG_INVALID_CODE
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn quickjs_executor_sets_a_corrupt_store_aside_and_starts() {
    let dir = temp_dir("corrupt-store");
    let store = dir.join("store.json");
    // A truncated write and a hand edit with a number value.
    for broken in ["{\"token\":\"ab", "{\"count\":1}"] {
        std::fs::write(&store, broken).unwrap();
        let executor = NativeQuickJsScriptExecutor::new(NativeQuickJsScriptRuntimeConfig {
            script_assets: BTreeMap::new(),
            persistent_store_path: Some(store.display().to_string()),
            max_timeout_ms: 1000,
            max_body_bytes: 1024,
            memory_limit_bytes: 0,
        })
        .expect("a corrupt store must not stop the script runtime");
        let backup = dir.join("store.json.corrupt");
        assert_eq!(
            executor.persistent_store_recovery(),
            &ScriptStoreRecovery::Quarantined {
                backup: backup.clone()
            }
        );
        // The broken file is kept aside, not overwritten.
        assert_eq!(std::fs::read_to_string(&backup).unwrap(), broken);
        assert!(!store.exists());
    }
    assert_eq!(
        std::fs::read_dir(&dir).unwrap().count(),
        1,
        "only the latest broken copy is kept"
    );

    // The runtime keeps working on a fresh store at the original path.
    let script = dir.join("store.js");
    std::fs::write(&script, "$persistentStore.write('fresh', 'k'); $done({});").unwrap();
    let executor = executor(&script, Some(&store));
    assert_eq!(
        executor.persistent_store_recovery(),
        &ScriptStoreRecovery::Opened
    );
    let report = hook(executor, 1000).plan_plain_http(&message(HttpMitmPhase::Request, "x"));
    assert!(report.script_dispatch_executed);
    let saved: BTreeMap<String, String> =
        serde_json::from_slice(&std::fs::read(&store).unwrap()).unwrap();
    assert_eq!(saved.get("k").map(String::as_str), Some("fresh"));
    let _ = std::fs::remove_dir_all(&dir);
}
