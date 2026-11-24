use super::*;
use std::os::unix::fs::PermissionsExt;

#[test]
fn script_runtime_body_staging_uses_owner_only_permissions() {
    let path = write_script_runtime_body(b"sensitive script body")
        .expect("script runtime body should stage securely");
    let mode = std::fs::metadata(&path)
        .expect("script runtime body metadata should be readable")
        .permissions()
        .mode()
        & 0o777;
    let _ = std::fs::remove_file(&path);

    assert_eq!(mode, 0o600);
}

#[test]
fn script_runtime_defers_when_an_authorized_asset_changes() {
    let path = std::env::temp_dir().join(format!(
        "networkcore-script-asset-hash-contract-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&path);
    std::fs::write(&path, "authorized local script")
        .expect("script asset fixture should be written");
    let script_url = "https://scripts.networkcore.test/authorized.js".to_string();
    let mut script_assets = BTreeMap::new();
    script_assets.insert(script_url.clone(), path.display().to_string());
    let executor = NativeNodeScriptExecutor::new(NativeNodeScriptRuntimeConfig {
        node_binary: "node".to_string(),
        runner_path: path.display().to_string(),
        script_assets,
        persistent_store_path: None,
        sandbox: NativeNodeScriptSandbox::Unrestricted,
        max_timeout_ms: 1000,
        max_body_bytes: 1024,
    });
    assert!(executor.script_asset_hashes().contains_key(&script_url));
    std::fs::write(&path, "replacement local script")
        .expect("script asset fixture should be replaceable for the contract");

    let report = executor.execute(
        &HttpMitmScriptDispatch {
            kind: HttpMitmScriptKind::Request,
            phase: HttpMitmPhase::Request,
            requires_body: false,
            timeout_ms: 1000,
            max_size: 1024,
            script_path: script_url,
            tag: "asset-hash-contract".to_string(),
            argument: String::new(),
            binary_body_mode: false,
        },
        &NativePlainHttpMessage {
            request_id: "asset-hash-contract".to_string(),
            url: "https://api.networkcore.test/v1".to_string(),
            method: Some("GET".to_string()),
            phase: HttpMitmPhase::Request,
            status_code: None,
            headers: Vec::new(),
            body: Vec::new(),
            request_headers: Vec::new(),
            request_body: None,
        },
    );
    let _ = std::fs::remove_file(&path);

    assert!(!report.executed);
    assert!(report
        .diagnostics
        .iter()
        .any(|diagnostic| { diagnostic.code == ENGINE_NATIVE_RUNTIME_HTTP_SCRIPT_DEFERRED_CODE }));
}

#[test]
fn script_runtime_timeout_fails_open() {
    let root =
        std::env::temp_dir().join(format!("networkcore-script-timeout-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).expect("timeout fixture directory should be created");
    let runner = root.join("runner.sh");
    let asset = root.join("asset.js");
    std::fs::write(&runner, "sleep 1").expect("timeout runner should be written");
    std::fs::write(&asset, "module.exports = {};").expect("timeout asset should be written");
    let script_url = "https://scripts.networkcore.test/timeout.js".to_string();
    let mut script_assets = BTreeMap::new();
    script_assets.insert(script_url.clone(), asset.display().to_string());
    let executor = NativeNodeScriptExecutor::new(NativeNodeScriptRuntimeConfig {
        node_binary: "sh".to_string(),
        runner_path: runner.display().to_string(),
        script_assets,
        persistent_store_path: None,
        sandbox: NativeNodeScriptSandbox::Unrestricted,
        max_timeout_ms: 10,
        max_body_bytes: 1024,
    });
    let report = executor.execute(
        &HttpMitmScriptDispatch {
            kind: HttpMitmScriptKind::Request,
            phase: HttpMitmPhase::Request,
            requires_body: false,
            timeout_ms: 10,
            max_size: 1024,
            script_path: script_url,
            tag: "timeout".to_string(),
            argument: String::new(),
            binary_body_mode: false,
        },
        &NativePlainHttpMessage {
            request_id: "timeout".to_string(),
            url: "https://api.networkcore.test/".to_string(),
            method: Some("GET".to_string()),
            phase: HttpMitmPhase::Request,
            status_code: None,
            headers: Vec::new(),
            body: Vec::new(),
            request_headers: Vec::new(),
            request_body: None,
        },
    );
    let _ = std::fs::remove_dir_all(&root);
    assert!(!report.executed);
    assert!(report
        .diagnostics
        .iter()
        .any(|diagnostic| diagnostic.code == ENGINE_NATIVE_RUNTIME_HTTP_SCRIPT_FAILED_CODE));
}

#[cfg(target_os = "linux")]
#[test]
fn linux_script_runtime_command_denies_network_and_unlisted_permissions() {
    let root = std::env::temp_dir().join(format!(
        "networkcore-script-sandbox-contract-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).expect("script sandbox fixture directory should be created");
    let runner_path = root.join("runner.js");
    let asset_path = root.join("asset.js");
    let body_path = root.join("body.txt");
    std::fs::write(&runner_path, "process.exit(0)").expect("runner fixture should be written");
    std::fs::write(&asset_path, "module.exports = {}").expect("asset fixture should be written");
    std::fs::write(&body_path, "bounded body").expect("body fixture should be written");

    let script_url = "https://scripts.networkcore.test/sandbox.js".to_string();
    let mut script_assets = BTreeMap::new();
    script_assets.insert(script_url, asset_path.display().to_string());
    let executor = NativeNodeScriptExecutor::new(NativeNodeScriptRuntimeConfig {
        node_binary: "node".to_string(),
        runner_path: runner_path.display().to_string(),
        script_assets,
        persistent_store_path: None,
        sandbox: NativeNodeScriptSandbox::LinuxNoNetwork,
        max_timeout_ms: 1000,
        max_body_bytes: 1024,
    });

    let command = executor
        .node_command(&asset_path.display().to_string(), &body_path)
        .expect("Linux sandbox command should be constructible for local files");
    let arguments = command
        .get_args()
        .map(|argument| argument.to_string_lossy().into_owned())
        .collect::<Vec<_>>();
    let _ = std::fs::remove_dir_all(&root);

    assert_eq!(command.get_program().to_string_lossy(), "unshare");
    assert!(arguments.iter().any(|argument| argument == "--net"));
    assert!(arguments.iter().any(|argument| argument == "--kill-child"));
    assert!(arguments
        .iter()
        .any(|argument| argument == "--experimental-permission"));
    let expected_heap_limit = format!("--max-old-space-size={SCRIPT_RUNTIME_V8_MAX_OLD_SPACE_MIB}");
    assert!(arguments
        .iter()
        .any(|argument| argument == expected_heap_limit.as_str()));
    assert!(arguments
        .iter()
        .any(|argument| argument.starts_with("--allow-fs-read=")));
    assert!(!arguments
        .iter()
        .any(|argument| argument.starts_with("--allow-child-process")));
    assert!(!arguments
        .iter()
        .any(|argument| argument.starts_with("--allow-fs-write")));
    assert!(!arguments
        .iter()
        .any(|argument| argument.starts_with("--allow-net")));
}
