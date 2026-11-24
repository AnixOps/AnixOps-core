//! HTTP scripts and MITM plugin hooks: script runtimes, executors and the
//! helpers that apply a script's result to a message.

use super::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NativeNodeScriptSandbox {
    Disabled,
    LinuxNoNetwork,
    /// Reserved for isolated test fixtures; product entrypoints must not select it.
    Unrestricted,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeNodeScriptRuntimeConfig {
    pub node_binary: String,
    pub runner_path: String,
    pub script_assets: BTreeMap<String, String>,
    pub persistent_store_path: Option<String>,
    pub sandbox: NativeNodeScriptSandbox,
    pub max_timeout_ms: usize,
    pub max_body_bytes: usize,
}

/// Response a request-phase script returned instead of forwarding the request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeHttpScriptResponse {
    pub status_code: u16,
    pub headers: Vec<MetadataEntry>,
    pub body: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeHttpScriptExecutionReport {
    pub executed: bool,
    pub applied: bool,
    pub url: Option<String>,
    pub headers: Option<Vec<MetadataEntry>>,
    pub body: Option<Vec<u8>>,
    pub status_code: Option<u16>,
    pub response: Option<NativeHttpScriptResponse>,
    pub diagnostics: Vec<Diagnostic>,
}

#[derive(Debug, Clone)]
pub struct NativeNodeScriptExecutor {
    pub(crate) config: NativeNodeScriptRuntimeConfig,
    pub(crate) script_asset_hashes: BTreeMap<String, String>,
}

impl NativeNodeScriptExecutor {
    pub fn new(config: NativeNodeScriptRuntimeConfig) -> Self {
        let script_asset_hashes = config
            .script_assets
            .iter()
            .filter_map(|(url, path)| {
                script_asset_sha256(std::path::Path::new(path)).map(|hash| (url.clone(), hash))
            })
            .collect();
        Self {
            config,
            script_asset_hashes,
        }
    }

    pub fn config(&self) -> &NativeNodeScriptRuntimeConfig {
        &self.config
    }

    pub fn script_asset_hashes(&self) -> &BTreeMap<String, String> {
        &self.script_asset_hashes
    }

    pub fn sandbox(&self) -> &NativeNodeScriptSandbox {
        &self.config.sandbox
    }

    pub fn execute(
        &self,
        dispatch: &HttpMitmScriptDispatch,
        message: &NativePlainHttpMessage,
    ) -> NativeHttpScriptExecutionReport {
        if !script_dispatch_matches_message(dispatch, message) {
            return script_execution_deferred(
                "native HTTP script dispatch phase does not match the intercepted message",
            );
        }
        if dispatch.max_size > 0 && message.body.len() > dispatch.max_size {
            return script_execution_deferred(
                "native HTTP script dispatch body exceeds the rule max-size limit",
            );
        }
        if self.config.max_body_bytes > 0 && message.body.len() > self.config.max_body_bytes {
            return script_execution_deferred(
                "native HTTP script dispatch body exceeds the runtime max-size limit",
            );
        }
        if std::str::from_utf8(&message.body).is_err() {
            return script_execution_deferred(
                "native HTTP script dispatch requires a UTF-8 buffered body",
            );
        }
        let Some(script_asset_path) = self.config.script_assets.get(&dispatch.script_path) else {
            return script_execution_deferred(
                "native HTTP script dispatch has no explicitly configured local script asset",
            );
        };
        let Some(expected_hash) = self.script_asset_hashes.get(&dispatch.script_path) else {
            return script_execution_deferred(
                "native HTTP script runtime could not record the mapped local script asset hash",
            );
        };
        let asset_path = std::path::Path::new(script_asset_path);
        let Some(actual_hash) = script_asset_sha256(asset_path) else {
            return script_execution_deferred(
                "native HTTP script runtime mapped local script asset is unavailable or unsafe",
            );
        };
        if actual_hash != *expected_hash {
            return script_execution_deferred(
                "native HTTP script runtime mapped local script asset changed after authorization",
            );
        }
        if self.config.node_binary.trim().is_empty()
            || self.config.runner_path.trim().is_empty()
            || script_asset_path.trim().is_empty()
        {
            return script_execution_deferred(
                "native HTTP script runtime requires explicit node, runner, and local asset paths",
            );
        }
        if !std::path::Path::new(&self.config.runner_path).is_file()
            || !std::path::Path::new(script_asset_path).is_file()
        {
            return script_execution_deferred(
                "native HTTP script runtime runner or mapped local asset is unavailable",
            );
        }

        let body_path = match write_script_runtime_body(&message.body) {
            Ok(body_path) => body_path,
            Err(()) => {
                return script_execution_failed(
                    "native HTTP script runtime could not securely stage a buffered body",
                )
            }
        };
        let execution = self.execute_staged(dispatch, message, script_asset_path, &body_path);
        let _ = std::fs::remove_file(&body_path);
        execution
    }

    pub(crate) fn execute_staged(
        &self,
        dispatch: &HttpMitmScriptDispatch,
        message: &NativePlainHttpMessage,
        script_asset_path: &str,
        body_path: &std::path::Path,
    ) -> NativeHttpScriptExecutionReport {
        // A response script's `$request` is the request the response
        // answers, not the response's own head.
        let request_headers = match message.phase {
            HttpMitmPhase::Request => &message.headers,
            HttpMitmPhase::Response => &message.request_headers,
        };
        let request_headers = match serde_json::to_string(&script_headers_to_map(request_headers)) {
            Ok(headers) => headers,
            Err(_) => {
                return script_execution_failed(
                    "native HTTP script runtime could not encode request headers",
                )
            }
        };
        let timeout_ms = bounded_script_timeout(dispatch.timeout_ms, self.config.max_timeout_ms);
        let execution_timeout = Duration::from_millis(timeout_ms as u64);
        let Some(mut command) = self.node_command(script_asset_path, body_path) else {
            return script_execution_deferred(
                "native HTTP script runtime is disabled or its sandbox could not be configured",
            );
        };
        command
            .arg(&self.config.runner_path)
            .arg("--script")
            .arg(script_asset_path)
            .arg("--url")
            .arg(&message.url)
            .arg("--argument")
            .arg(&dispatch.argument)
            .arg("--body")
            .arg(body_path)
            .arg("--phase")
            .arg(script_phase_name(message.phase))
            .arg("--method")
            .arg(message.method.as_deref().unwrap_or("GET"))
            .arg("--timeoutMs")
            .arg(timeout_ms.to_string())
            .arg("--requestHeaders")
            .arg(request_headers)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        if let HttpMitmPhase::Response = message.phase {
            let response_headers =
                match serde_json::to_string(&script_headers_to_map(&message.headers)) {
                    Ok(headers) => headers,
                    Err(_) => {
                        return script_execution_failed(
                            "native HTTP script runtime could not encode response headers",
                        )
                    }
                };
            command
                .arg("--status")
                .arg(message.status_code.unwrap_or(200).to_string())
                .arg("--responseHeaders")
                .arg(response_headers);
        }
        if let Some(store_path) = self.config.persistent_store_path.as_deref() {
            command.arg("--store").arg(store_path);
        }

        let mut child = match command.spawn() {
            Ok(child) => child,
            Err(_) => {
                return script_execution_failed(
                    "native HTTP script runtime could not start the configured node runner",
                )
            }
        };
        let started_at = Instant::now();
        let output = loop {
            match child.try_wait() {
                Ok(Some(_)) => match child.wait_with_output() {
                    Ok(output) => break output,
                    Err(_) => {
                        return script_execution_failed(
                            "native HTTP script runtime could not collect runner output",
                        )
                    }
                },
                Ok(None) if started_at.elapsed() >= execution_timeout => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return script_execution_failed("native HTTP script runtime timed out");
                }
                Ok(None) => thread::sleep(Duration::from_millis(5)),
                Err(_) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return script_execution_failed(
                        "native HTTP script runtime could not monitor the runner process",
                    );
                }
            }
        };
        if !output.status.success() {
            return script_execution_failed(
                "native HTTP script runtime runner exited unsuccessfully",
            );
        }
        let output = match String::from_utf8(output.stdout) {
            Ok(output) => output,
            Err(_) => {
                return script_execution_failed(
                    "native HTTP script runtime returned non-UTF-8 output",
                )
            }
        };
        let result = match serde_json::from_str::<NativeNodeScriptDone>(&output) {
            Ok(result) => result,
            Err(_) => {
                return script_execution_failed("native HTTP script runtime returned invalid JSON")
            }
        };
        let headers = match result.headers {
            Some(headers) => match script_headers_from_map(headers) {
                Some(headers) => Some(restore_joined_script_headers(&message.headers, headers)),
                None => {
                    return script_execution_failed(
                        "native HTTP script runtime returned invalid headers",
                    )
                }
            },
            None => None,
        };
        let status_code = match result.status {
            Some(status_code)
                if message.phase == HttpMitmPhase::Response
                    && (100..=599).contains(&status_code) =>
            {
                Some(status_code)
            }
            Some(_) => {
                return script_execution_failed(
                    "native HTTP script runtime returned an unsupported status mutation",
                )
            }
            None => None,
        };
        let body = result.body.map(String::into_bytes);
        let applied =
            result.url.is_some() || headers.is_some() || body.is_some() || status_code.is_some();

        NativeHttpScriptExecutionReport {
            executed: true,
            applied,
            url: result.url,
            headers,
            body,
            status_code,
            response: None,
            diagnostics: vec![engine_diagnostic(
                DiagnosticSeverity::Info,
                ENGINE_NATIVE_RUNTIME_HTTP_SCRIPT_EXECUTED_CODE,
                "native HTTP script runtime completed a locally mapped script dispatch",
                SOURCE_ENGINE_NATIVE_MITM,
            )],
        }
    }

    pub(crate) fn node_command(
        &self,
        script_asset_path: &str,
        body_path: &std::path::Path,
    ) -> Option<Command> {
        match self.config.sandbox {
            NativeNodeScriptSandbox::Disabled => None,
            NativeNodeScriptSandbox::Unrestricted => Some(Command::new(&self.config.node_binary)),
            NativeNodeScriptSandbox::LinuxNoNetwork => {
                #[cfg(target_os = "linux")]
                {
                    let body_path = body_path.to_str()?;
                    let read_paths = [
                        self.config.runner_path.as_str(),
                        script_asset_path,
                        body_path,
                    ]
                    .iter()
                    .map(|path| std::fs::canonicalize(path).ok())
                    .collect::<Option<Vec<_>>>()?;
                    let read_paths = read_paths
                        .iter()
                        .map(|path| path.to_str())
                        .collect::<Option<Vec<_>>>()?;
                    if read_paths.iter().any(|path| path.contains(',')) {
                        return None;
                    }
                    let mut command = Command::new("unshare");
                    command
                        .arg("--user")
                        .arg("--map-root-user")
                        .arg("--net")
                        .arg("--mount-proc")
                        .arg("--kill-child")
                        .arg("--")
                        .arg(&self.config.node_binary)
                        .arg("--experimental-permission")
                        .arg(format!(
                            "--max-old-space-size={SCRIPT_RUNTIME_V8_MAX_OLD_SPACE_MIB}"
                        ))
                        .arg(format!("--allow-fs-read={}", read_paths.join(",")));
                    Some(command)
                }
                #[cfg(not(target_os = "linux"))]
                {
                    let _ = (script_asset_path, body_path);
                    None
                }
            }
        }
    }
}

pub(crate) fn script_asset_sha256(path: &std::path::Path) -> Option<String> {
    let metadata = std::fs::symlink_metadata(path).ok()?;
    if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
        return None;
    }
    let mut file = std::fs::File::open(path).ok()?;
    let mut hash = Sha256::new();
    let mut buffer = [0_u8; 8192];
    loop {
        let count = file.read(&mut buffer).ok()?;
        if count == 0 {
            break;
        }
        hash.update(&buffer[..count]);
    }
    Some(format!("{:x}", hash.finalize()))
}

#[derive(Debug, Deserialize)]
pub(crate) struct NativeNodeScriptDone {
    pub(crate) url: Option<String>,
    pub(crate) headers: Option<BTreeMap<String, String>>,
    pub(crate) body: Option<String>,
    pub(crate) status: Option<u16>,
}

/// Runtime that executes `[Script]` dispatches for the MITM hook.
#[derive(Debug, Clone)]
pub enum NativeHttpScriptExecutor {
    /// External Node.js runner inside an OS sandbox.
    Node(NativeNodeScriptExecutor),
    /// In-process QuickJS with the host-mediated `$`-API.
    #[cfg(feature = "quickjs")]
    QuickJs(NativeQuickJsScriptExecutor),
}

impl NativeHttpScriptExecutor {
    pub fn engine_name(&self) -> &'static str {
        match self {
            Self::Node(_) => "node",
            #[cfg(feature = "quickjs")]
            Self::QuickJs(_) => script_runtime::QuickJsScriptRuntime::ENGINE_NAME,
        }
    }

    pub fn execute(
        &self,
        dispatch: &HttpMitmScriptDispatch,
        message: &NativePlainHttpMessage,
    ) -> NativeHttpScriptExecutionReport {
        match self {
            Self::Node(executor) => executor.execute(dispatch, message),
            #[cfg(feature = "quickjs")]
            Self::QuickJs(executor) => executor.execute(dispatch, message),
        }
    }
}

#[derive(Clone)]
pub struct NativeHttpMitmPluginHook {
    pub(crate) plugin_instance: PluginInstance,
    pub(crate) plugin_service: Arc<dyn MitmPluginService + Send + Sync>,
    pub(crate) script_executor: Option<NativeHttpScriptExecutor>,
}

impl NativeHttpMitmPluginHook {
    pub fn new(
        plugin_instance: PluginInstance,
        plugin_service: Arc<dyn MitmPluginService + Send + Sync>,
    ) -> Self {
        Self {
            plugin_instance,
            plugin_service,
            script_executor: None,
        }
    }

    pub fn with_node_script_executor(mut self, executor: NativeNodeScriptExecutor) -> Self {
        self.script_executor = Some(NativeHttpScriptExecutor::Node(executor));
        self
    }

    #[cfg(feature = "quickjs")]
    pub fn with_quickjs_script_executor(mut self, executor: NativeQuickJsScriptExecutor) -> Self {
        self.script_executor = Some(NativeHttpScriptExecutor::QuickJs(executor));
        self
    }

    pub fn script_executor_enabled(&self) -> bool {
        self.script_executor.is_some()
    }

    /// Whether TLS to `host` is decrypted: the plugin's `[MITM]` hostname
    /// list (wildcards and `-` exclusions included) intercepts it. A host
    /// outside the list, and a list that cannot be evaluated, is not
    /// decrypted.
    pub fn intercepts_tls_host(&self, host: &str) -> bool {
        let hostname = host
            .trim_start_matches('[')
            .trim_end_matches(']')
            .trim_end_matches('.')
            .to_ascii_lowercase();
        matches!(
            self.plugin_service
                .evaluate_mitm_hostname(&self.plugin_instance, &hostname, false),
            Ok(MitmHostnameDecision::Intercept)
        )
    }

    /// `node` or `quickjs-ng` when a script executor is configured.
    pub fn script_engine(&self) -> Option<&'static str> {
        self.script_executor
            .as_ref()
            .map(NativeHttpScriptExecutor::engine_name)
    }

    /// OS sandbox of the Node executor; QuickJS needs none.
    pub fn script_sandbox(&self) -> Option<NativeNodeScriptSandbox> {
        match self.script_executor.as_ref()? {
            NativeHttpScriptExecutor::Node(executor) => Some(*executor.sandbox()),
            #[cfg(feature = "quickjs")]
            NativeHttpScriptExecutor::QuickJs(_) => None,
        }
    }

    pub fn plugin_instance(&self) -> &PluginInstance {
        &self.plugin_instance
    }

    pub fn plan_socks5_connect(
        &self,
        request_id: impl Into<String>,
        target: &NativeSocks5ConnectTarget,
    ) -> NativeSocks5ConnectHttpMitmPlanReport {
        plan_socks5_connect_http_mitm(
            request_id,
            target,
            &self.plugin_instance,
            self.plugin_service.as_ref(),
        )
    }

    pub fn plan_plain_http(
        &self,
        message: &NativePlainHttpMessage,
    ) -> NativePlainHttpRewriteReport {
        let mut report = plan_and_apply_plain_http_mitm(
            message,
            &self.plugin_instance,
            self.plugin_service.as_ref(),
        );
        if let Some(script_executor) = self.script_executor.as_ref() {
            apply_script_dispatch_to_plain_http_rewrite_report(
                &mut report,
                message,
                script_executor,
            );
        }
        report
    }
}

impl NativeHttpMitmPluginHook {
    /// Decides whether one UDP datagram flow may leave the data plane. QUIC to
    /// a MITM hostname is refused so the client falls back to TCP TLS, where
    /// the controlled TLS session can intercept it.
    pub fn plan_udp_datagram(
        &self,
        target_host: &str,
        target_port: u16,
    ) -> NativeUdpMitmDecisionReport {
        plan_native_udp_mitm_decision(
            target_host,
            target_port,
            &self.plugin_instance,
            self.plugin_service.as_ref(),
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NativeUdpMitmDecision {
    Allow,
    RejectQuic,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeUdpMitmDecisionReport {
    pub decision: NativeUdpMitmDecision,
    pub diagnostics: Vec<Diagnostic>,
}

/// Applies the plugin's MITM hostname list to a UDP flow. Only UDP/443 is
/// treated as QUIC; other ports and hosts outside the list are allowed. A
/// policy evaluation error allows the flow, because refusing it would not
/// make the TCP fallback interceptable either.
pub fn plan_native_udp_mitm_decision(
    target_host: &str,
    target_port: u16,
    plugin_instance: &PluginInstance,
    plugin_service: &dyn MitmPluginService,
) -> NativeUdpMitmDecisionReport {
    if target_port != QUIC_HTTPS_UDP_PORT {
        return NativeUdpMitmDecisionReport {
            decision: NativeUdpMitmDecision::Allow,
            diagnostics: Vec::new(),
        };
    }

    let hostname = target_host
        .trim_start_matches('[')
        .trim_end_matches(']')
        .trim_end_matches('.')
        .to_ascii_lowercase();
    match plugin_service.evaluate_mitm_hostname(plugin_instance, &hostname, true) {
        Ok(MitmHostnameDecision::RejectQuic) => NativeUdpMitmDecisionReport {
            decision: NativeUdpMitmDecision::RejectQuic,
            diagnostics: vec![engine_diagnostic(
                DiagnosticSeverity::Info,
                ENGINE_NATIVE_RUNTIME_UDP_MITM_QUIC_REJECTED_CODE,
                "native data plane refused QUIC to a MITM hostname so the client falls back to TCP TLS",
                SOURCE_ENGINE_NATIVE_MITM,
            )],
        },
        Ok(MitmHostnameDecision::Bypass | MitmHostnameDecision::Intercept) => {
            NativeUdpMitmDecisionReport {
                decision: NativeUdpMitmDecision::Allow,
                diagnostics: vec![engine_diagnostic(
                    DiagnosticSeverity::Info,
                    ENGINE_NATIVE_RUNTIME_UDP_MITM_ALLOWED_CODE,
                    "native data plane allowed UDP/443 to a host outside the QUIC rejection policy",
                    SOURCE_ENGINE_NATIVE_MITM,
                )],
            }
        }
        Err(error) => NativeUdpMitmDecisionReport {
            decision: NativeUdpMitmDecision::Allow,
            diagnostics: vec![engine_diagnostic(
                DiagnosticSeverity::Warning,
                ENGINE_NATIVE_RUNTIME_UDP_MITM_POLICY_FAILED_CODE,
                format!(
                    "native data plane could not evaluate the MITM hostname list for UDP/443: {}",
                    error.code
                ),
                SOURCE_ENGINE_NATIVE_MITM,
            )],
        },
    }
}

impl fmt::Debug for NativeHttpMitmPluginHook {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NativeHttpMitmPluginHook")
            .field("plugin_id", &self.plugin_instance.manifest.id)
            .field("plugin_version", &self.plugin_instance.manifest.version)
            .field(
                "script_executor",
                &self.script_executor.as_ref().map(|_| "[configured]"),
            )
            .finish_non_exhaustive()
    }
}

pub(crate) fn apply_script_dispatch_to_plain_http_rewrite_report(
    report: &mut NativePlainHttpRewriteReport,
    original_message: &NativePlainHttpMessage,
    script_executor: &NativeHttpScriptExecutor,
) {
    let Some(dispatch) = report
        .outcome
        .as_ref()
        .and_then(|outcome| outcome.script_dispatch.as_ref())
    else {
        return;
    };
    if report.terminal_action.is_some() {
        return;
    }

    let script_message = NativePlainHttpMessage {
        request_id: original_message.request_id.clone(),
        url: report.url.clone(),
        method: original_message.method.clone(),
        phase: original_message.phase,
        status_code: report.final_status_code,
        headers: report.headers.clone(),
        body: report.body.clone(),
        request_headers: original_message.request_headers.clone(),
        request_body: original_message.request_body.clone(),
    };
    let requires_body = dispatch.requires_body;
    let execution = script_executor.execute(dispatch, &script_message);
    report.diagnostics.extend(execution.diagnostics.clone());
    if !execution.executed {
        report.script_dispatch_deferred = execution
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == ENGINE_NATIVE_RUNTIME_HTTP_SCRIPT_DEFERRED_CODE);
        report.script_dispatch_failed = execution
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == ENGINE_NATIVE_RUNTIME_HTTP_SCRIPT_FAILED_CODE);
        return;
    }

    report.script_dispatch_executed = true;
    report.script_dispatch_deferred = false;
    report.script_dispatch_failed = false;
    if let Some(response) = execution.response {
        if original_message.phase == HttpMitmPhase::Request {
            report.terminal_action = Some("script-response".to_string());
            report.final_status_code = Some(response.status_code);
            report.redirect_location = None;
            report.headers = response.headers;
            report.body = response.body;
            report.applied = true;
            return;
        }
    }
    if let Some(url) = execution.url {
        if script_url_mutation_preserves_authority(&report.url, &url) {
            report.url = url;
            report.applied = true;
        } else {
            report.diagnostics.push(engine_diagnostic(
                DiagnosticSeverity::Warning,
                ENGINE_NATIVE_RUNTIME_HTTP_SCRIPT_URL_MUTATION_BLOCKED_CODE,
                "native HTTP script runtime ignored a cross-authority or scheme-changing URL mutation",
                SOURCE_ENGINE_NATIVE_MITM,
            ));
        }
    }
    if let Some(headers) = execution.headers {
        report.headers = headers;
        report.applied = true;
    }
    if let Some(body) = execution.body {
        if requires_body {
            report.body = body;
            report.applied = true;
        } else {
            report.diagnostics.push(engine_diagnostic(
                DiagnosticSeverity::Warning,
                ENGINE_NATIVE_RUNTIME_HTTP_SCRIPT_BODY_IGNORED_CODE,
                "native HTTP script runtime ignored a body returned by a script without requires-body",
                SOURCE_ENGINE_NATIVE_MITM,
            ));
        }
    }
    if let Some(status_code) = execution.status_code {
        report.final_status_code = Some(status_code);
        report.applied = true;
    }
}

pub(crate) fn script_dispatch_matches_message(
    dispatch: &HttpMitmScriptDispatch,
    message: &NativePlainHttpMessage,
) -> bool {
    matches!(
        (dispatch.kind, dispatch.phase, message.phase),
        (
            HttpMitmScriptKind::Request,
            HttpMitmPhase::Request,
            HttpMitmPhase::Request
        ) | (
            HttpMitmScriptKind::Response,
            HttpMitmPhase::Response,
            HttpMitmPhase::Response
        )
    )
}

pub(crate) fn script_execution_deferred(message: &'static str) -> NativeHttpScriptExecutionReport {
    NativeHttpScriptExecutionReport {
        executed: false,
        applied: false,
        url: None,
        headers: None,
        body: None,
        status_code: None,
        response: None,
        diagnostics: vec![engine_diagnostic(
            DiagnosticSeverity::Warning,
            ENGINE_NATIVE_RUNTIME_HTTP_SCRIPT_DEFERRED_CODE,
            message,
            SOURCE_ENGINE_NATIVE_MITM,
        )],
    }
}

pub(crate) fn script_execution_failed(message: &'static str) -> NativeHttpScriptExecutionReport {
    NativeHttpScriptExecutionReport {
        executed: false,
        applied: false,
        url: None,
        headers: None,
        body: None,
        status_code: None,
        response: None,
        diagnostics: vec![engine_diagnostic(
            DiagnosticSeverity::Warning,
            ENGINE_NATIVE_RUNTIME_HTTP_SCRIPT_FAILED_CODE,
            message,
            SOURCE_ENGINE_NATIVE_MITM,
        )],
    }
}

/// Repeated names are joined as `script-runtime` joins them: `Cookie` with
/// "; ", the rest with ", ", so no field is lost.
pub(crate) fn script_headers_to_map(headers: &[MetadataEntry]) -> BTreeMap<String, String> {
    let mut values = BTreeMap::<String, String>::new();
    for header in headers {
        match values.get_mut(&header.key) {
            Some(existing) => {
                existing.push_str(if header.key.eq_ignore_ascii_case("cookie") {
                    "; "
                } else {
                    ", "
                });
                existing.push_str(&header.value);
            }
            None => {
                values.insert(header.key.clone(), header.value.clone());
            }
        }
    }
    values
}

/// The fields [`script_headers_to_map`] joined, given back where the
/// script returned them unchanged (see
/// [`script_runtime::restore_joined_headers`]), so several `Set-Cookie`
/// fields are not merged into one.
pub(crate) fn restore_joined_script_headers(
    original: &[MetadataEntry],
    returned: Vec<MetadataEntry>,
) -> Vec<MetadataEntry> {
    let pairs = |entries: Vec<MetadataEntry>| {
        entries
            .into_iter()
            .map(|entry| (entry.key, entry.value))
            .collect::<Vec<_>>()
    };
    script_runtime::restore_joined_headers(&pairs(original.to_vec()), pairs(returned))
        .into_iter()
        .map(|(key, value)| MetadataEntry { key, value })
        .collect()
}

pub(crate) fn script_headers_from_map(
    headers: BTreeMap<String, String>,
) -> Option<Vec<MetadataEntry>> {
    let mut values = Vec::with_capacity(headers.len());
    for (key, value) in headers {
        if key.trim().is_empty()
            || key.contains('\r')
            || key.contains('\n')
            || value.contains('\r')
            || value.contains('\n')
        {
            return None;
        }
        values.push(MetadataEntry { key, value });
    }
    Some(values)
}

pub(crate) fn script_phase_name(phase: HttpMitmPhase) -> &'static str {
    match phase {
        HttpMitmPhase::Request => "request",
        HttpMitmPhase::Response => "response",
    }
}

pub(crate) fn bounded_script_timeout(
    rule_timeout_ms: usize,
    runtime_max_timeout_ms: usize,
) -> usize {
    let requested = if rule_timeout_ms == 0 {
        SCRIPT_RUNTIME_DEFAULT_TIMEOUT_MS
    } else {
        rule_timeout_ms
    };
    let runtime_max_timeout_ms = if runtime_max_timeout_ms == 0 {
        SCRIPT_RUNTIME_HARD_MAX_TIMEOUT_MS
    } else {
        runtime_max_timeout_ms.min(SCRIPT_RUNTIME_HARD_MAX_TIMEOUT_MS)
    };
    requested.min(runtime_max_timeout_ms).max(1)
}

pub(crate) fn write_script_runtime_body(body: &[u8]) -> Result<std::path::PathBuf, ()> {
    for _ in 0..16 {
        let sequence = SCRIPT_RUNTIME_TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "networkcore-script-body-{}-{sequence}.tmp",
            std::process::id()
        ));
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        options.mode(0o600);
        let file = options.open(&path);
        let Ok(mut file) = file else {
            continue;
        };
        if file.write_all(body).is_ok() && file.flush().is_ok() {
            return Ok(path);
        }
        let _ = std::fs::remove_file(&path);
        return Err(());
    }
    Err(())
}

pub(crate) fn script_url_mutation_preserves_authority(
    current_url: &str,
    updated_url: &str,
) -> bool {
    let Some((current_scheme, current_target)) = parse_script_absolute_url(current_url) else {
        return false;
    };
    let Some((updated_scheme, updated_target)) = parse_script_absolute_url(updated_url) else {
        return false;
    };
    current_scheme == updated_scheme
        && current_target
            .target_host
            .eq_ignore_ascii_case(&updated_target.target_host)
        && current_target.target_port == updated_target.target_port
}

pub(crate) fn parse_script_absolute_url(
    url: &str,
) -> Option<(&'static str, ParsedExplicitHttpProxyTarget)> {
    if let Some(rest) = url.strip_prefix("https://") {
        return parse_absolute_http_proxy_target("https", rest, 443)
            .map(|target| ("https", target));
    }
    if let Some(rest) = url.strip_prefix("http://") {
        return parse_absolute_http_proxy_target("http", rest, 80).map(|target| ("http", target));
    }
    None
}
