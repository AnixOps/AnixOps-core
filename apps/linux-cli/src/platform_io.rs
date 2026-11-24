//! Platform operations behind traits: the unavailable engine, foreground
//! lifecycle hosts and signals, browser capture processes and probes, PAC
//! files and MITM certificate artifacts.

use super::*;

#[derive(Debug, Clone, Copy, Default)]
pub struct UnavailableProxyEngineService;

impl UnavailableProxyEngineService {
    pub const fn new() -> Self {
        Self
    }
}

impl ProxyEngineService for UnavailableProxyEngineService {
    fn list_engines(&self) -> Vec<ProxyEngineDescriptor> {
        Vec::new()
    }

    fn validate_config(&self, _engine_config: &ProxyEngineConfig) -> Vec<Diagnostic> {
        vec![cli_diagnostic(
            DiagnosticSeverity::Error,
            CLI_RUNTIME_UNWIRED_CODE,
            "linux proxy engine adapter is not wired",
            SOURCE_CLI_RUNTIME,
        )]
    }

    fn start(&self, _engine_config: &ProxyEngineConfig) -> DomainResult<ProxyEngineStatus> {
        Err(unavailable_engine_error())
    }

    fn reload(&self, _engine_config: &ProxyEngineConfig) -> DomainResult<ProxyEngineStatus> {
        Err(unavailable_engine_error())
    }

    fn stop(&self, _engine_id: &str) -> DomainResult<ProxyEngineStatus> {
        Err(unavailable_engine_error())
    }

    fn status(&self, _engine_id: &str) -> DomainResult<ProxyEngineStatus> {
        Err(unavailable_engine_error())
    }

    fn events(&self, _engine_id: &str) -> DomainResult<Vec<ProxyEngineEvent>> {
        Err(unavailable_engine_error())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForegroundLifecycleRequest {
    pub engine_status: ProxyEngineStatus,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForegroundLifecycleOutcome {
    pub exit_code: LinuxCliExitCode,
    pub diagnostics: Vec<Diagnostic>,
}

impl ForegroundLifecycleOutcome {
    pub fn success(diagnostics: Vec<Diagnostic>) -> Self {
        Self {
            exit_code: LinuxCliExitCode::Success,
            diagnostics,
        }
    }

    pub fn failure(exit_code: LinuxCliExitCode, diagnostic: Diagnostic) -> Self {
        Self {
            exit_code,
            diagnostics: vec![diagnostic],
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForegroundLifecycleInterruption {
    pub reason: String,
    pub diagnostics: Vec<Diagnostic>,
}

impl ForegroundLifecycleInterruption {
    pub fn new(reason: impl Into<String>) -> Self {
        Self {
            reason: reason.into(),
            diagnostics: Vec::new(),
        }
    }

    pub fn with_diagnostics(mut self, diagnostics: Vec<Diagnostic>) -> Self {
        self.diagnostics = diagnostics;
        self
    }
}

pub trait ForegroundLifecycleHost {
    fn run_foreground(&self, request: &ForegroundLifecycleRequest) -> ForegroundLifecycleOutcome;
}

pub trait ForegroundLifecycleInterruptionSource {
    fn wait_for_interruption(
        &self,
        request: &ForegroundLifecycleRequest,
    ) -> ForegroundLifecycleInterruption;
}

pub trait BrowserCaptureProcessRunner {
    fn launch(
        &self,
        request: &LinuxBrowserCaptureLaunchRequest,
    ) -> DomainResult<LinuxBrowserCaptureLaunchOutcome>;
}

pub trait BrowserCaptureEndpointProbe {
    fn verify_proxy_endpoint(
        &self,
        request: &LinuxBrowserCaptureVerifyRequest,
    ) -> DomainResult<LinuxBrowserCaptureVerifyOutcome>;
}

pub trait BrowserCaptureTrafficProofProbe {
    fn verify_traffic_proof(
        &self,
        request: &LinuxBrowserCaptureTrafficProofRequest,
    ) -> DomainResult<LinuxBrowserCaptureTrafficProofOutcome>;
}

pub trait BrowserCapturePacFileStore {
    fn apply_pac_file(
        &self,
        request: &LinuxBrowserCapturePacRequest,
    ) -> DomainResult<LinuxBrowserCapturePacApplyOutcome>;

    fn rollback_pac_file(
        &self,
        snapshot: &BrowserCaptureRollbackSnapshot,
    ) -> DomainResult<LinuxBrowserCapturePacRollbackOutcome>;
}

pub trait MitmCertificateArtifactStore {
    fn apply_certificate_artifact(
        &self,
        request: &LinuxMitmCertificateArtifactRequest,
    ) -> DomainResult<LinuxMitmCertificateArtifactApplyOutcome>;

    fn rollback_certificate_artifact(
        &self,
        snapshot: &MitmCertificateRollbackSnapshot,
    ) -> DomainResult<LinuxMitmCertificateArtifactRollbackOutcome>;
}

#[derive(Debug, Clone, Copy, Default)]
pub struct CommandBrowserCaptureProcessRunner;

impl CommandBrowserCaptureProcessRunner {
    pub const fn new() -> Self {
        Self
    }
}

impl BrowserCaptureProcessRunner for CommandBrowserCaptureProcessRunner {
    fn launch(
        &self,
        request: &LinuxBrowserCaptureLaunchRequest,
    ) -> DomainResult<LinuxBrowserCaptureLaunchOutcome> {
        let child = std::process::Command::new(&request.command.executable)
            .args(&request.command.args)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::inherit())
            .stderr(std::process::Stdio::inherit())
            .spawn()
            .map_err(|error| {
                DomainError::new(
                    CLI_MITM_BROWSER_CAPTURE_LAUNCH_FAILED_CODE,
                    format!(
                        "failed to launch browser capture profile with {}: {error}",
                        request.command.executable
                    ),
                )
            })?;

        Ok(LinuxBrowserCaptureLaunchOutcome {
            pid: child.id(),
            diagnostics: vec![cli_diagnostic(
                DiagnosticSeverity::Info,
                CLI_MITM_BROWSER_CAPTURE_LAUNCH_STARTED_CODE,
                "browser capture dedicated profile process was started with an explicit proxy argument",
                SOURCE_CLI_MITM,
            )],
        })
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct CommandBrowserCaptureEndpointProbe;

impl CommandBrowserCaptureEndpointProbe {
    pub const fn new() -> Self {
        Self
    }
}

impl BrowserCaptureEndpointProbe for CommandBrowserCaptureEndpointProbe {
    fn verify_proxy_endpoint(
        &self,
        request: &LinuxBrowserCaptureVerifyRequest,
    ) -> DomainResult<LinuxBrowserCaptureVerifyOutcome> {
        let target = request
            .target_url
            .as_deref()
            .map(parse_browser_capture_target_endpoint)
            .transpose()?;
        let address = format!("{}:{}", request.proxy_host, request.proxy_port);
        let mut addrs = address.as_str().to_socket_addrs().map_err(|error| {
            DomainError::new(
                CLI_MITM_BROWSER_CAPTURE_VERIFY_PROXY_UNREACHABLE_CODE,
                format!("failed to resolve browser capture proxy endpoint {address}: {error}"),
            )
        })?;
        let socket_addr = addrs.next().ok_or_else(|| {
            DomainError::new(
                CLI_MITM_BROWSER_CAPTURE_VERIFY_PROXY_UNREACHABLE_CODE,
                format!("browser capture proxy endpoint {address} did not resolve"),
            )
        })?;

        let mut stream =
            TcpStream::connect_timeout(&socket_addr, Duration::from_secs(2)).map_err(|error| {
                DomainError::new(
                    CLI_MITM_BROWSER_CAPTURE_VERIFY_PROXY_UNREACHABLE_CODE,
                    format!(
                        "browser capture planned proxy endpoint {} is not reachable: {error}",
                        request.proxy_url
                    ),
                )
            })?;
        stream
            .set_read_timeout(Some(Duration::from_secs(3)))
            .map_err(|error| {
                DomainError::new(
                    CLI_MITM_BROWSER_CAPTURE_VERIFY_PROXY_UNREACHABLE_CODE,
                    format!(
                        "failed to set browser capture proxy read timeout for {}: {error}",
                        request.proxy_url
                    ),
                )
            })?;
        stream
            .set_write_timeout(Some(Duration::from_secs(3)))
            .map_err(|error| {
                DomainError::new(
                    CLI_MITM_BROWSER_CAPTURE_VERIFY_PROXY_UNREACHABLE_CODE,
                    format!(
                        "failed to set browser capture proxy write timeout for {}: {error}",
                        request.proxy_url
                    ),
                )
            })?;

        if let (Some(target_url), Some(target)) = (&request.target_url, target) {
            let authority = target.authority();
            let connect_request = format!(
                "CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\nUser-Agent: networkcore-linux-browser-capture-verify\r\nProxy-Connection: close\r\n\r\n"
            );
            stream
                .write_all(connect_request.as_bytes())
                .map_err(|error| {
                    DomainError::new(
                        CLI_MITM_BROWSER_CAPTURE_VERIFY_PROXY_UNREACHABLE_CODE,
                        format!(
                            "failed to write browser capture target probe through {} for {target_url}: {error}",
                            request.proxy_url
                        ),
                    )
                })?;
            let mut buffer = [0_u8; 512];
            let byte_count = stream.read(&mut buffer).map_err(|error| {
                DomainError::new(
                    CLI_MITM_BROWSER_CAPTURE_VERIFY_PROXY_UNREACHABLE_CODE,
                    format!(
                        "failed to read browser capture target probe response through {} for {target_url}: {error}",
                        request.proxy_url
                    ),
                )
            })?;
            let response = String::from_utf8_lossy(&buffer[..byte_count]);
            let status_line = response.lines().next().unwrap_or_default();
            if !status_line.contains(" 200 ") && !status_line.ends_with(" 200") {
                return Err(DomainError::new(
                    CLI_MITM_BROWSER_CAPTURE_VERIFY_PROXY_UNREACHABLE_CODE,
                    format!(
                        "browser capture proxy {} did not open a CONNECT tunnel to {target_url}: {status_line}",
                        request.proxy_url
                    ),
                ));
            }

            return Ok(LinuxBrowserCaptureVerifyOutcome {
                diagnostics: vec![cli_diagnostic(
                    DiagnosticSeverity::Info,
                    CLI_MITM_BROWSER_CAPTURE_VERIFY_TARGET_REACHABLE_CODE,
                    format!(
                        "browser capture planned proxy endpoint {} can open a target tunnel to {target_url}",
                        request.proxy_url
                    ),
                    SOURCE_CLI_MITM,
                )],
            });
        }

        Ok(LinuxBrowserCaptureVerifyOutcome {
            diagnostics: vec![cli_diagnostic(
                DiagnosticSeverity::Info,
                CLI_MITM_BROWSER_CAPTURE_VERIFY_PROXY_REACHABLE_CODE,
                format!(
                    "browser capture planned proxy endpoint {} is reachable",
                    request.proxy_url
                ),
                SOURCE_CLI_MITM,
            )],
        })
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct CommandBrowserCaptureTrafficProofProbe;

impl CommandBrowserCaptureTrafficProofProbe {
    pub const fn new() -> Self {
        Self
    }
}

impl BrowserCaptureTrafficProofProbe for CommandBrowserCaptureTrafficProofProbe {
    fn verify_traffic_proof(
        &self,
        request: &LinuxBrowserCaptureTrafficProofRequest,
    ) -> DomainResult<LinuxBrowserCaptureTrafficProofOutcome> {
        let proof_log = std::fs::read_to_string(&request.proof_log_path).map_err(|error| {
            DomainError::new(
                CLI_MITM_BROWSER_CAPTURE_TRAFFIC_PROOF_LOG_UNREADABLE_CODE,
                format!(
                    "failed to read browser capture traffic proof log {}: {error}",
                    request.proof_log_path
                ),
            )
        })?;

        let token_observed = proof_log.contains(&request.proof_token);
        if !token_observed {
            return Err(DomainError::new(
                CLI_MITM_BROWSER_CAPTURE_TRAFFIC_PROOF_MISSING_CODE,
                "browser capture traffic proof token was not observed in the proof log",
            ));
        }
        if let Some(authority) = &request.proof_connect_authority {
            let bound_line_observed = proof_log.lines().any(|line| {
                line.contains(&request.proof_token)
                    && line.contains(&request.proxy_url)
                    && line.contains(authority)
            });
            if !bound_line_observed {
                return Err(DomainError::new(
                    CLI_MITM_BROWSER_CAPTURE_TRAFFIC_PROOF_BINDING_MISMATCH_CODE,
                    format!(
                        "browser capture proof token was observed, but no proof log line bound it to proxy {} and CONNECT authority {authority}",
                        request.proxy_url
                    ),
                ));
            }
        }

        let observed_message = if request.proof_connect_authority.is_some() {
            "browser capture proof token was observed in the proof log with the expected proxy and CONNECT authority binding"
        } else {
            "browser capture proof token was observed in the proof log"
        };

        Ok(LinuxBrowserCaptureTrafficProofOutcome {
            diagnostics: vec![cli_diagnostic(
                DiagnosticSeverity::Info,
                CLI_MITM_BROWSER_CAPTURE_TRAFFIC_PROOF_OBSERVED_CODE,
                observed_message,
                SOURCE_CLI_MITM,
            )],
        })
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct CommandBrowserCapturePacFileStore;

impl CommandBrowserCapturePacFileStore {
    pub const fn new() -> Self {
        Self
    }
}

impl BrowserCapturePacFileStore for CommandBrowserCapturePacFileStore {
    fn apply_pac_file(
        &self,
        request: &LinuxBrowserCapturePacRequest,
    ) -> DomainResult<LinuxBrowserCapturePacApplyOutcome> {
        if std::path::Path::new(&request.pac_file_path).exists() {
            return Err(DomainError::new(
                CLI_MITM_BROWSER_CAPTURE_PAC_WRITE_FAILED_CODE,
                format!(
                    "refusing to overwrite existing browser capture PAC file {}",
                    request.pac_file_path
                ),
            ));
        }
        if std::path::Path::new(&request.snapshot_path).exists() {
            return Err(DomainError::new(
                CLI_MITM_BROWSER_CAPTURE_SNAPSHOT_WRITE_FAILED_CODE,
                format!(
                    "refusing to overwrite existing browser capture rollback snapshot {}",
                    request.snapshot_path
                ),
            ));
        }
        if let Some(policy_file_path) = &request.policy_file_path {
            if std::path::Path::new(policy_file_path).exists() {
                return Err(DomainError::new(
                    CLI_MITM_BROWSER_CAPTURE_POLICY_WRITE_FAILED_CODE,
                    format!(
                        "refusing to overwrite existing browser capture policy file {policy_file_path}"
                    ),
                ));
            }
        }
        let profile_prefs_previous_content = request
            .profile_prefs_file_path
            .as_ref()
            .map(|path| match std::fs::read_to_string(path) {
                Ok(contents) => Ok(Some(contents)),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
                Err(error) => Err(DomainError::new(
                    CLI_MITM_BROWSER_CAPTURE_PROFILE_PREFS_WRITE_FAILED_CODE,
                    format!("failed to read browser capture profile prefs file {path}: {error}"),
                )),
            })
            .transpose()?
            .flatten();

        let snapshot = BrowserCapturePacSnapshotFile {
            version: 1,
            kind: BROWSER_CAPTURE_PAC_SNAPSHOT_KIND.to_string(),
            pac_file_path: request.pac_file_path.clone(),
            pac_url: request.pac_url.clone(),
            created_file: true,
            policy_file_path: request.policy_file_path.clone(),
            policy_url: request.policy_url.clone(),
            created_policy_file: request.policy_file_path.is_some(),
            profile_prefs_file_path: request.profile_prefs_file_path.clone(),
            created_profile_prefs_file: request.profile_prefs_file_path.is_some()
                && profile_prefs_previous_content.is_none(),
            previous_profile_prefs_content: profile_prefs_previous_content,
            applied_profile_prefs_content: request.profile_prefs_content.clone(),
        };

        let snapshot_json = serde_json::to_string_pretty(&snapshot).map_err(|error| {
            DomainError::new(
                CLI_MITM_BROWSER_CAPTURE_SNAPSHOT_WRITE_FAILED_CODE,
                format!(
                    "failed to render browser capture PAC snapshot {}: {error}",
                    request.snapshot_path
                ),
            )
        })?;
        write_new_file(
            &request.snapshot_path,
            snapshot_json.as_bytes(),
            CLI_MITM_BROWSER_CAPTURE_SNAPSHOT_WRITE_FAILED_CODE,
            "browser capture PAC snapshot",
        )?;

        write_new_file(
            &request.pac_file_path,
            request.pac_content.as_bytes(),
            CLI_MITM_BROWSER_CAPTURE_PAC_WRITE_FAILED_CODE,
            "browser capture PAC file",
        )?;
        if let (Some(policy_file_path), Some(policy_content)) =
            (&request.policy_file_path, &request.policy_content)
        {
            write_new_file(
                policy_file_path,
                policy_content.as_bytes(),
                CLI_MITM_BROWSER_CAPTURE_POLICY_WRITE_FAILED_CODE,
                "browser capture browser policy file",
            )?;
        }
        if let (Some(profile_prefs_file_path), Some(profile_prefs_content)) = (
            &request.profile_prefs_file_path,
            &request.profile_prefs_content,
        ) {
            write_replace_file(
                profile_prefs_file_path,
                profile_prefs_content.as_bytes(),
                CLI_MITM_BROWSER_CAPTURE_PROFILE_PREFS_WRITE_FAILED_CODE,
                "browser capture Firefox profile prefs file",
            )?;
        }

        let policy_message = request
            .policy_file_path
            .as_ref()
            .map(|path| format!(" and browser policy file {path}"))
            .unwrap_or_default();
        let profile_prefs_message = request
            .profile_prefs_file_path
            .as_ref()
            .map(|path| format!(" and Firefox profile prefs file {path}"))
            .unwrap_or_default();
        Ok(LinuxBrowserCapturePacApplyOutcome {
            rollback_snapshot: BrowserCaptureRollbackSnapshot {
                path: request.snapshot_path.clone(),
                status: "networkcore-created".to_string(),
            },
            diagnostics: vec![cli_diagnostic(
                DiagnosticSeverity::Info,
                CLI_MITM_BROWSER_CAPTURE_APPLY_READY_CODE,
                format!(
                    "browser capture PAC file {}{}{} was written with planned proxy {}",
                    request.pac_file_path, policy_message, profile_prefs_message, request.proxy_url
                ),
                SOURCE_CLI_MITM,
            )],
        })
    }

    fn rollback_pac_file(
        &self,
        snapshot: &BrowserCaptureRollbackSnapshot,
    ) -> DomainResult<LinuxBrowserCapturePacRollbackOutcome> {
        let snapshot_json = std::fs::read_to_string(&snapshot.path).map_err(|error| {
            DomainError::new(
                CLI_MITM_BROWSER_CAPTURE_SNAPSHOT_READ_FAILED_CODE,
                format!(
                    "failed to read browser capture PAC snapshot {}: {error}",
                    snapshot.path
                ),
            )
        })?;
        let snapshot_file: BrowserCapturePacSnapshotFile = serde_json::from_str(&snapshot_json)
            .map_err(|error| {
                DomainError::new(
                    CLI_MITM_BROWSER_CAPTURE_SNAPSHOT_READ_FAILED_CODE,
                    format!(
                        "failed to parse browser capture PAC snapshot {}: {error}",
                        snapshot.path
                    ),
                )
            })?;
        if snapshot_file.kind != BROWSER_CAPTURE_PAC_SNAPSHOT_KIND || !snapshot_file.created_file {
            return Err(DomainError::new(
                CLI_MITM_BROWSER_CAPTURE_SNAPSHOT_READ_FAILED_CODE,
                "browser capture rollback snapshot is not a NetworkCore PAC snapshot",
            ));
        }

        match std::fs::remove_file(&snapshot_file.pac_file_path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(DomainError::new(
                    CLI_MITM_BROWSER_CAPTURE_ROLLBACK_FAILED_CODE,
                    format!(
                        "failed to remove browser capture PAC file {}: {error}",
                        snapshot_file.pac_file_path
                    ),
                ));
            }
        }
        if snapshot_file.created_policy_file {
            let Some(policy_file_path) = snapshot_file.policy_file_path.as_ref() else {
                return Err(DomainError::new(
                    CLI_MITM_BROWSER_CAPTURE_SNAPSHOT_READ_FAILED_CODE,
                    "browser capture rollback snapshot is missing the policy file path",
                ));
            };
            match std::fs::remove_file(policy_file_path) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => {
                    return Err(DomainError::new(
                        CLI_MITM_BROWSER_CAPTURE_ROLLBACK_FAILED_CODE,
                        format!(
                            "failed to remove browser capture policy file {policy_file_path}: {error}"
                        ),
                    ));
                }
            }
        }
        if let Some(profile_prefs_file_path) = snapshot_file.profile_prefs_file_path.as_ref() {
            let Some(applied_content) = snapshot_file.applied_profile_prefs_content.as_ref() else {
                return Err(DomainError::new(
                    CLI_MITM_BROWSER_CAPTURE_SNAPSHOT_READ_FAILED_CODE,
                    "browser capture rollback snapshot is missing applied profile prefs content",
                ));
            };
            match std::fs::read_to_string(profile_prefs_file_path) {
                Ok(current_content) if current_content != *applied_content => {
                    return Err(DomainError::new(
                        CLI_MITM_BROWSER_CAPTURE_ROLLBACK_FAILED_CODE,
                        format!(
                            "refusing to rollback browser capture profile prefs file {profile_prefs_file_path} because it changed after apply"
                        ),
                    ));
                }
                Ok(_) => {
                    rollback_profile_prefs_file(
                        profile_prefs_file_path,
                        snapshot_file.created_profile_prefs_file,
                        snapshot_file.previous_profile_prefs_content.as_deref(),
                    )?;
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    if !snapshot_file.created_profile_prefs_file {
                        rollback_profile_prefs_file(
                            profile_prefs_file_path,
                            false,
                            snapshot_file.previous_profile_prefs_content.as_deref(),
                        )?;
                    }
                }
                Err(error) => {
                    return Err(DomainError::new(
                        CLI_MITM_BROWSER_CAPTURE_ROLLBACK_FAILED_CODE,
                        format!(
                            "failed to read browser capture profile prefs file {profile_prefs_file_path}: {error}"
                        ),
                    ));
                }
            }
        }

        Ok(LinuxBrowserCapturePacRollbackOutcome {
            pac_file_path: snapshot_file.pac_file_path.clone(),
            policy_file_path: snapshot_file.policy_file_path.clone(),
            profile_prefs_file_path: snapshot_file.profile_prefs_file_path.clone(),
            diagnostics: vec![cli_diagnostic(
                DiagnosticSeverity::Info,
                CLI_MITM_BROWSER_CAPTURE_ROLLBACK_READY_CODE,
                format!(
                    "browser capture PAC file {}, optional policy artifact, and optional profile prefs were restored from snapshot {}",
                    snapshot_file.pac_file_path, snapshot.path
                ),
                SOURCE_CLI_MITM,
            )],
        })
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct UnavailableBrowserCapturePacFileStore;

impl UnavailableBrowserCapturePacFileStore {
    pub const fn new() -> Self {
        Self
    }
}

impl BrowserCapturePacFileStore for UnavailableBrowserCapturePacFileStore {
    fn apply_pac_file(
        &self,
        _request: &LinuxBrowserCapturePacRequest,
    ) -> DomainResult<LinuxBrowserCapturePacApplyOutcome> {
        Err(DomainError::new(
            CLI_MITM_BROWSER_CAPTURE_APPLY_BLOCKED_CODE,
            "browser capture PAC file store is not wired",
        ))
    }

    fn rollback_pac_file(
        &self,
        _snapshot: &BrowserCaptureRollbackSnapshot,
    ) -> DomainResult<LinuxBrowserCapturePacRollbackOutcome> {
        Err(DomainError::new(
            CLI_MITM_BROWSER_CAPTURE_ROLLBACK_BLOCKED_CODE,
            "browser capture PAC file store is not wired",
        ))
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct CommandMitmCertificateArtifactStore;

impl CommandMitmCertificateArtifactStore {
    pub const fn new() -> Self {
        Self
    }
}

impl MitmCertificateArtifactStore for CommandMitmCertificateArtifactStore {
    fn apply_certificate_artifact(
        &self,
        request: &LinuxMitmCertificateArtifactRequest,
    ) -> DomainResult<LinuxMitmCertificateArtifactApplyOutcome> {
        validate_mitm_certificate_artifact_request(request)?;

        if std::path::Path::new(&request.cert_file_path).exists() {
            return Err(DomainError::new(
                CLI_MITM_CERTIFICATE_ARTIFACT_WRITE_FAILED_CODE,
                format!(
                    "refusing to overwrite existing MITM certificate artifact {}",
                    request.cert_file_path
                ),
            ));
        }
        if std::path::Path::new(&request.key_file_path).exists() {
            return Err(DomainError::new(
                CLI_MITM_CERTIFICATE_ARTIFACT_WRITE_FAILED_CODE,
                format!(
                    "refusing to overwrite existing MITM private key artifact {}",
                    request.key_file_path
                ),
            ));
        }
        if let Some(profile_trust_file_path) = &request.profile_trust_file_path {
            if std::path::Path::new(profile_trust_file_path).exists() {
                return Err(DomainError::new(
                    CLI_MITM_CERTIFICATE_ARTIFACT_WRITE_FAILED_CODE,
                    format!(
                        "refusing to overwrite existing MITM dedicated profile trust artifact {}",
                        profile_trust_file_path
                    ),
                ));
            }
        }
        if std::path::Path::new(&request.snapshot_path).exists() {
            return Err(DomainError::new(
                CLI_MITM_CERTIFICATE_SNAPSHOT_WRITE_FAILED_CODE,
                format!(
                    "refusing to overwrite existing MITM certificate rollback snapshot {}",
                    request.snapshot_path
                ),
            ));
        }

        let snapshot = MitmCertificateArtifactSnapshotFile {
            version: 1,
            kind: MITM_CERTIFICATE_ARTIFACT_SNAPSHOT_KIND.to_string(),
            cert_file_path: request.cert_file_path.clone(),
            key_file_path: request.key_file_path.clone(),
            profile_trust_file_path: request.profile_trust_file_path.clone(),
            subject: request.subject.clone(),
            created_cert_file: true,
            created_key_file: true,
            created_profile_trust_file: request.profile_trust_file_path.is_some(),
            applied_cert_fingerprint: request.cert_fingerprint.clone(),
            applied_key_fingerprint: request.key_fingerprint.clone(),
            applied_profile_trust_fingerprint: request.profile_trust_fingerprint.clone(),
        };
        let snapshot_json = serde_json::to_string_pretty(&snapshot).map_err(|error| {
            DomainError::new(
                CLI_MITM_CERTIFICATE_SNAPSHOT_WRITE_FAILED_CODE,
                format!(
                    "failed to render MITM certificate artifact snapshot {}: {error}",
                    request.snapshot_path
                ),
            )
        })?;

        write_new_file(
            &request.snapshot_path,
            snapshot_json.as_bytes(),
            CLI_MITM_CERTIFICATE_SNAPSHOT_WRITE_FAILED_CODE,
            "MITM certificate artifact snapshot",
        )?;
        if let Err(error) = write_new_file(
            &request.cert_file_path,
            request.cert_content.as_bytes(),
            CLI_MITM_CERTIFICATE_ARTIFACT_WRITE_FAILED_CODE,
            "MITM certificate artifact",
        ) {
            let _ = std::fs::remove_file(&request.snapshot_path);
            return Err(error);
        }
        if let Err(error) = write_new_private_key_file(
            &request.key_file_path,
            request.key_content.as_bytes(),
            CLI_MITM_CERTIFICATE_ARTIFACT_WRITE_FAILED_CODE,
            "MITM private key artifact",
        ) {
            let _ = std::fs::remove_file(&request.cert_file_path);
            let _ = std::fs::remove_file(&request.snapshot_path);
            return Err(error);
        }
        if let (Some(profile_trust_file_path), Some(profile_trust_content)) = (
            &request.profile_trust_file_path,
            &request.profile_trust_content,
        ) {
            if let Err(error) = write_new_file(
                profile_trust_file_path,
                profile_trust_content.as_bytes(),
                CLI_MITM_CERTIFICATE_ARTIFACT_WRITE_FAILED_CODE,
                "MITM dedicated profile trust artifact",
            ) {
                let _ = std::fs::remove_file(&request.key_file_path);
                let _ = std::fs::remove_file(&request.cert_file_path);
                let _ = std::fs::remove_file(&request.snapshot_path);
                return Err(error);
            }
        }

        Ok(LinuxMitmCertificateArtifactApplyOutcome {
            rollback_snapshot: MitmCertificateRollbackSnapshot {
                path: request.snapshot_path.clone(),
                status: "networkcore-created".to_string(),
            },
            diagnostics: vec![cli_diagnostic(
                DiagnosticSeverity::Info,
                CLI_MITM_CERTIFICATE_APPLY_READY_CODE,
                format!(
                    "MITM certificate artifact {} and private key artifact {} were written with profile trust artifact {} and system trust-store mutation blocked",
                    request.cert_file_path,
                    request.key_file_path,
                    request
                        .profile_trust_file_path
                        .as_deref()
                        .unwrap_or("not-requested")
                ),
                SOURCE_CLI_MITM,
            )],
        })
    }

    fn rollback_certificate_artifact(
        &self,
        snapshot: &MitmCertificateRollbackSnapshot,
    ) -> DomainResult<LinuxMitmCertificateArtifactRollbackOutcome> {
        let snapshot_json = std::fs::read_to_string(&snapshot.path).map_err(|error| {
            DomainError::new(
                CLI_MITM_CERTIFICATE_SNAPSHOT_READ_FAILED_CODE,
                format!(
                    "failed to read MITM certificate artifact snapshot {}: {error}",
                    snapshot.path
                ),
            )
        })?;
        let snapshot_file: MitmCertificateArtifactSnapshotFile =
            serde_json::from_str(&snapshot_json).map_err(|error| {
                DomainError::new(
                    CLI_MITM_CERTIFICATE_SNAPSHOT_READ_FAILED_CODE,
                    format!(
                        "failed to parse MITM certificate artifact snapshot {}: {error}",
                        snapshot.path
                    ),
                )
            })?;
        if snapshot_file.kind != MITM_CERTIFICATE_ARTIFACT_SNAPSHOT_KIND
            || !snapshot_file.created_cert_file
            || !snapshot_file.created_key_file
        {
            return Err(DomainError::new(
                CLI_MITM_CERTIFICATE_SNAPSHOT_READ_FAILED_CODE,
                "MITM certificate rollback snapshot is not a NetworkCore certificate artifact snapshot",
            ));
        }

        rollback_mitm_certificate_artifact_file(
            &snapshot_file.cert_file_path,
            &snapshot_file.applied_cert_fingerprint,
            "MITM certificate artifact",
        )?;
        rollback_mitm_certificate_artifact_file(
            &snapshot_file.key_file_path,
            &snapshot_file.applied_key_fingerprint,
            "MITM private key artifact",
        )?;
        if snapshot_file.created_profile_trust_file {
            let (Some(profile_trust_file_path), Some(applied_profile_trust_fingerprint)) = (
                snapshot_file.profile_trust_file_path.as_deref(),
                snapshot_file.applied_profile_trust_fingerprint.as_deref(),
            ) else {
                return Err(DomainError::new(
                    CLI_MITM_CERTIFICATE_SNAPSHOT_READ_FAILED_CODE,
                    "MITM certificate rollback snapshot is missing dedicated profile trust artifact fields",
                ));
            };
            rollback_mitm_certificate_artifact_file(
                profile_trust_file_path,
                applied_profile_trust_fingerprint,
                "MITM dedicated profile trust artifact",
            )?;
        }

        Ok(LinuxMitmCertificateArtifactRollbackOutcome {
            cert_file_path: snapshot_file.cert_file_path.clone(),
            key_file_path: snapshot_file.key_file_path.clone(),
            profile_trust_file_path: snapshot_file.profile_trust_file_path.clone(),
            diagnostics: vec![cli_diagnostic(
                DiagnosticSeverity::Info,
                CLI_MITM_CERTIFICATE_ROLLBACK_READY_CODE,
                format!(
                    "MITM certificate artifact {} and private key artifact {} were removed from NetworkCore snapshot {}; profile trust artifact {}",
                    snapshot_file.cert_file_path,
                    snapshot_file.key_file_path,
                    snapshot.path,
                    snapshot_file
                        .profile_trust_file_path
                        .as_deref()
                        .unwrap_or("not-requested")
                ),
                SOURCE_CLI_MITM,
            )],
        })
    }
}

pub(crate) fn validate_mitm_certificate_artifact_request(
    request: &LinuxMitmCertificateArtifactRequest,
) -> DomainResult<()> {
    if request.artifact_version != 2 {
        return Err(DomainError::new(
            CLI_MITM_CERTIFICATE_ARTIFACT_WRITE_FAILED_CODE,
            "MITM certificate artifact request must use artifact version 2",
        ));
    }
    if !request.cert_content.contains("-----BEGIN CERTIFICATE-----")
        || !request.cert_content.contains("-----END CERTIFICATE-----")
    {
        return Err(DomainError::new(
            CLI_MITM_CERTIFICATE_ARTIFACT_WRITE_FAILED_CODE,
            "MITM certificate artifact request must contain CA certificate PEM content",
        ));
    }
    if request.cert_content.contains("-----BEGIN PRIVATE KEY-----") {
        return Err(DomainError::new(
            CLI_MITM_CERTIFICATE_ARTIFACT_WRITE_FAILED_CODE,
            "MITM certificate artifact request must not contain private key material",
        ));
    }
    if !request.key_content.contains("-----BEGIN PRIVATE KEY-----")
        || !request.key_content.contains("-----END PRIVATE KEY-----")
    {
        return Err(DomainError::new(
            CLI_MITM_CERTIFICATE_ARTIFACT_WRITE_FAILED_CODE,
            "MITM certificate artifact request must contain private key PEM content",
        ));
    }
    let Some(profile_trust_file_path) = &request.profile_trust_file_path else {
        return Ok(());
    };
    let Some(profile_trust_content) = &request.profile_trust_content else {
        return Err(DomainError::new(
            CLI_MITM_CERTIFICATE_ARTIFACT_WRITE_FAILED_CODE,
            format!(
                "MITM dedicated profile CA PEM copy request is missing content for {}",
                profile_trust_file_path
            ),
        ));
    };
    let Some(profile_trust_fingerprint) = &request.profile_trust_fingerprint else {
        return Err(DomainError::new(
            CLI_MITM_CERTIFICATE_ARTIFACT_WRITE_FAILED_CODE,
            format!(
                "MITM dedicated profile CA PEM copy request is missing fingerprint for {}",
                profile_trust_file_path
            ),
        ));
    };
    if profile_trust_content.contains("-----BEGIN PRIVATE KEY-----")
        || profile_trust_content == &request.key_content
    {
        return Err(DomainError::new(
            CLI_MITM_CERTIFICATE_ARTIFACT_WRITE_FAILED_CODE,
            "MITM dedicated profile CA PEM copy must not contain private key material",
        ));
    }
    if profile_trust_content != &request.cert_content {
        return Err(DomainError::new(
            CLI_MITM_CERTIFICATE_ARTIFACT_WRITE_FAILED_CODE,
            "MITM dedicated profile CA PEM copy must match certificate PEM content",
        ));
    }
    if profile_trust_fingerprint != &request.cert_fingerprint {
        return Err(DomainError::new(
            CLI_MITM_CERTIFICATE_ARTIFACT_WRITE_FAILED_CODE,
            "MITM dedicated profile CA PEM copy fingerprint must match certificate fingerprint",
        ));
    }

    Ok(())
}

#[derive(Debug, Clone, Copy, Default)]
pub struct UnavailableMitmCertificateArtifactStore;

impl UnavailableMitmCertificateArtifactStore {
    pub const fn new() -> Self {
        Self
    }
}

impl MitmCertificateArtifactStore for UnavailableMitmCertificateArtifactStore {
    fn apply_certificate_artifact(
        &self,
        _request: &LinuxMitmCertificateArtifactRequest,
    ) -> DomainResult<LinuxMitmCertificateArtifactApplyOutcome> {
        Err(DomainError::new(
            CLI_MITM_CERTIFICATE_APPLY_BLOCKED_CODE,
            "MITM certificate artifact store is not wired",
        ))
    }

    fn rollback_certificate_artifact(
        &self,
        _snapshot: &MitmCertificateRollbackSnapshot,
    ) -> DomainResult<LinuxMitmCertificateArtifactRollbackOutcome> {
        Err(DomainError::new(
            CLI_MITM_CERTIFICATE_ROLLBACK_BLOCKED_CODE,
            "MITM certificate artifact store is not wired",
        ))
    }
}

pub(crate) const BROWSER_CAPTURE_PAC_SNAPSHOT_KIND: &str = "networkcore-linux-browser-capture-pac";
pub(crate) const MITM_CERTIFICATE_ARTIFACT_SNAPSHOT_KIND: &str =
    "networkcore-linux-mitm-certificate-artifact";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct BrowserCapturePacSnapshotFile {
    pub(crate) version: u8,
    pub(crate) kind: String,
    pub(crate) pac_file_path: String,
    pub(crate) pac_url: String,
    pub(crate) created_file: bool,
    #[serde(default)]
    pub(crate) policy_file_path: Option<String>,
    #[serde(default)]
    pub(crate) policy_url: Option<String>,
    #[serde(default)]
    pub(crate) created_policy_file: bool,
    #[serde(default)]
    pub(crate) profile_prefs_file_path: Option<String>,
    #[serde(default)]
    pub(crate) created_profile_prefs_file: bool,
    #[serde(default)]
    pub(crate) previous_profile_prefs_content: Option<String>,
    #[serde(default)]
    pub(crate) applied_profile_prefs_content: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct MitmCertificateArtifactSnapshotFile {
    pub(crate) version: u8,
    pub(crate) kind: String,
    pub(crate) cert_file_path: String,
    pub(crate) key_file_path: String,
    #[serde(default)]
    pub(crate) profile_trust_file_path: Option<String>,
    pub(crate) subject: String,
    pub(crate) created_cert_file: bool,
    pub(crate) created_key_file: bool,
    #[serde(default)]
    pub(crate) created_profile_trust_file: bool,
    pub(crate) applied_cert_fingerprint: String,
    pub(crate) applied_key_fingerprint: String,
    #[serde(default)]
    pub(crate) applied_profile_trust_fingerprint: Option<String>,
}

pub(crate) fn rollback_mitm_certificate_artifact_file(
    path: &str,
    expected_fingerprint: &str,
    description: &str,
) -> DomainResult<()> {
    match std::fs::read_to_string(path) {
        Ok(current_content)
            if stable_content_fingerprint(&current_content) != expected_fingerprint =>
        {
            Err(DomainError::new(
                CLI_MITM_CERTIFICATE_ROLLBACK_FAILED_CODE,
                format!("refusing to rollback {description} {path} because it changed after apply"),
            ))
        }
        Ok(_) => match std::fs::remove_file(path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(DomainError::new(
                CLI_MITM_CERTIFICATE_ROLLBACK_FAILED_CODE,
                format!("failed to remove {description} {path}: {error}"),
            )),
        },
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(DomainError::new(
            CLI_MITM_CERTIFICATE_ROLLBACK_FAILED_CODE,
            format!("failed to read {description} {path}: {error}"),
        )),
    }
}

pub(crate) fn write_parent_dir(path: &str, error_code: &'static str) -> DomainResult<()> {
    let parent = std::path::Path::new(path)
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty());
    if let Some(parent) = parent {
        std::fs::create_dir_all(parent).map_err(|error| {
            DomainError::new(
                error_code,
                format!("failed to create parent directory for {path}: {error}"),
            )
        })?;
    }
    Ok(())
}

pub(crate) fn write_new_file(
    path: &str,
    contents: &[u8],
    error_code: &'static str,
    description: &str,
) -> DomainResult<()> {
    write_parent_dir(path, error_code)?;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|error| {
            DomainError::new(
                error_code,
                format!("failed to create {description} {path}: {error}"),
            )
        })?;
    file.write_all(contents).map_err(|error| {
        DomainError::new(
            error_code,
            format!("failed to write {description} {path}: {error}"),
        )
    })
}

/// Writes a NetworkCore-generated MITM private key with no group or world
/// access. The mode is supplied at creation time and read back before the
/// caller can use the key, avoiding a permissive-umask window.
#[cfg(unix)]
pub(crate) fn write_new_private_key_file(
    path: &str,
    contents: &[u8],
    error_code: &'static str,
    description: &str,
) -> DomainResult<()> {
    write_parent_dir(path, error_code)?;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|error| {
            DomainError::new(
                error_code,
                format!("failed to create {description} {path}: {error}"),
            )
        })?;
    if let Err(error) = file.write_all(contents).and_then(|_| file.sync_all()) {
        let _ = std::fs::remove_file(path);
        return Err(DomainError::new(
            error_code,
            format!("failed to write {description} {path}: {error}"),
        ));
    }
    let mode = std::fs::metadata(path)
        .map_err(|error| {
            DomainError::new(
                error_code,
                format!("failed to verify {description} {path}: {error}"),
            )
        })?
        .permissions()
        .mode()
        & 0o777;
    if mode != 0o600 {
        let _ = std::fs::remove_file(path);
        return Err(DomainError::new(
            error_code,
            format!("{description} {path} did not retain owner-only permissions"),
        ));
    }
    Ok(())
}

#[cfg(not(unix))]
pub(crate) fn write_new_private_key_file(
    path: &str,
    contents: &[u8],
    error_code: &'static str,
    description: &str,
) -> DomainResult<()> {
    write_new_file(path, contents, error_code, description)
}

pub(crate) fn write_replace_file(
    path: &str,
    contents: &[u8],
    error_code: &'static str,
    description: &str,
) -> DomainResult<()> {
    write_parent_dir(path, error_code)?;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(path)
        .map_err(|error| {
            DomainError::new(
                error_code,
                format!("failed to open {description} {path}: {error}"),
            )
        })?;
    file.write_all(contents).map_err(|error| {
        DomainError::new(
            error_code,
            format!("failed to write {description} {path}: {error}"),
        )
    })
}

pub(crate) fn rollback_profile_prefs_file(
    path: &str,
    created_by_networkcore: bool,
    previous_content: Option<&str>,
) -> DomainResult<()> {
    if created_by_networkcore {
        match std::fs::remove_file(path) {
            Ok(()) => return Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(error) => {
                return Err(DomainError::new(
                    CLI_MITM_BROWSER_CAPTURE_ROLLBACK_FAILED_CODE,
                    format!("failed to remove browser capture profile prefs file {path}: {error}"),
                ));
            }
        }
    }

    let Some(previous_content) = previous_content else {
        return Err(DomainError::new(
            CLI_MITM_BROWSER_CAPTURE_SNAPSHOT_READ_FAILED_CODE,
            "browser capture rollback snapshot is missing previous profile prefs content",
        ));
    };
    write_replace_file(
        path,
        previous_content.as_bytes(),
        CLI_MITM_BROWSER_CAPTURE_ROLLBACK_FAILED_CODE,
        "browser capture Firefox profile prefs file",
    )
}

#[derive(Debug, Clone, Copy, Default)]
pub struct UnavailableBrowserCaptureTrafficProofProbe;

impl UnavailableBrowserCaptureTrafficProofProbe {
    pub const fn new() -> Self {
        Self
    }
}

impl BrowserCaptureTrafficProofProbe for UnavailableBrowserCaptureTrafficProofProbe {
    fn verify_traffic_proof(
        &self,
        _request: &LinuxBrowserCaptureTrafficProofRequest,
    ) -> DomainResult<LinuxBrowserCaptureTrafficProofOutcome> {
        Err(DomainError::new(
            CLI_MITM_BROWSER_CAPTURE_TRAFFIC_PROOF_BLOCKED_CODE,
            "browser capture traffic proof probe is not wired",
        ))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct BrowserCaptureTargetEndpoint {
    pub(crate) host: String,
    pub(crate) port: u16,
    pub(crate) bracketed: bool,
}

impl BrowserCaptureTargetEndpoint {
    pub(crate) fn authority(&self) -> String {
        if self.bracketed {
            format!("[{}]:{}", self.host, self.port)
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }
}

pub(crate) fn parse_browser_capture_target_endpoint(
    target_url: &str,
) -> DomainResult<BrowserCaptureTargetEndpoint> {
    let Some((scheme, remainder)) = target_url.split_once("://") else {
        return Err(DomainError::new(
            CLI_MITM_BROWSER_CAPTURE_VERIFY_TARGET_INVALID_CODE,
            "browser capture target URL must include http:// or https://",
        ));
    };
    let default_port = match scheme {
        "http" => 80,
        "https" => 443,
        _ => {
            return Err(DomainError::new(
                CLI_MITM_BROWSER_CAPTURE_VERIFY_TARGET_INVALID_CODE,
                "browser capture target URL scheme must be http or https",
            ));
        }
    };
    let authority = remainder
        .split(['/', '?', '#'])
        .next()
        .unwrap_or_default()
        .rsplit('@')
        .next()
        .unwrap_or_default();
    if authority.is_empty() {
        return Err(DomainError::new(
            CLI_MITM_BROWSER_CAPTURE_VERIFY_TARGET_INVALID_CODE,
            "browser capture target URL is missing a host",
        ));
    }

    let (host, port, bracketed) = if let Some(rest) = authority.strip_prefix('[') {
        let Some((host, after_host)) = rest.split_once(']') else {
            return Err(DomainError::new(
                CLI_MITM_BROWSER_CAPTURE_VERIFY_TARGET_INVALID_CODE,
                "browser capture target IPv6 host is missing a closing bracket",
            ));
        };
        let port = if let Some(port) = after_host.strip_prefix(':') {
            parse_browser_capture_target_port(port)?
        } else if after_host.is_empty() {
            default_port
        } else {
            return Err(DomainError::new(
                CLI_MITM_BROWSER_CAPTURE_VERIFY_TARGET_INVALID_CODE,
                "browser capture target IPv6 host has an invalid suffix",
            ));
        };
        (host.to_string(), port, true)
    } else {
        let mut parts = authority.split(':');
        let host = parts.next().unwrap_or_default();
        let port = match (parts.next(), parts.next()) {
            (None, None) => default_port,
            (Some(port), None) => parse_browser_capture_target_port(port)?,
            _ => {
                return Err(DomainError::new(
                    CLI_MITM_BROWSER_CAPTURE_VERIFY_TARGET_INVALID_CODE,
                    "browser capture target URL host with multiple colons must use IPv6 brackets",
                ));
            }
        };
        (host.to_string(), port, false)
    };

    if host.is_empty() {
        return Err(DomainError::new(
            CLI_MITM_BROWSER_CAPTURE_VERIFY_TARGET_INVALID_CODE,
            "browser capture target URL is missing a host",
        ));
    }

    Ok(BrowserCaptureTargetEndpoint {
        host,
        port,
        bracketed,
    })
}

pub(crate) fn parse_browser_capture_target_port(port: &str) -> DomainResult<u16> {
    port.parse::<u16>().map_err(|_| {
        DomainError::new(
            CLI_MITM_BROWSER_CAPTURE_VERIFY_TARGET_INVALID_CODE,
            "browser capture target URL port must be a valid TCP port",
        )
    })
}

#[derive(Debug, Clone, Copy, Default)]
pub struct UnavailableForegroundLifecycleHost;

impl UnavailableForegroundLifecycleHost {
    pub const fn new() -> Self {
        Self
    }
}

impl ForegroundLifecycleHost for UnavailableForegroundLifecycleHost {
    fn run_foreground(&self, _request: &ForegroundLifecycleRequest) -> ForegroundLifecycleOutcome {
        ForegroundLifecycleOutcome::failure(
            LinuxCliExitCode::Unavailable,
            cli_diagnostic(
                DiagnosticSeverity::Error,
                CLI_START_LIFECYCLE_HOST_MISSING_CODE,
                "linux foreground lifecycle host is not wired",
                SOURCE_CLI_START,
            ),
        )
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct ParkingForegroundLifecycleInterruptionSource;

impl ParkingForegroundLifecycleInterruptionSource {
    pub const fn new() -> Self {
        Self
    }
}

impl ForegroundLifecycleInterruptionSource for ParkingForegroundLifecycleInterruptionSource {
    fn wait_for_interruption(
        &self,
        _request: &ForegroundLifecycleRequest,
    ) -> ForegroundLifecycleInterruption {
        loop {
            thread::park();
        }
    }
}

#[cfg(unix)]
#[derive(Debug, Clone, Copy, Default)]
pub struct OsSignalForegroundLifecycleInterruptionSource;

#[cfg(unix)]
impl OsSignalForegroundLifecycleInterruptionSource {
    pub const fn new() -> Self {
        Self
    }

    pub fn interruption_for_signal(signal: i32) -> ForegroundLifecycleInterruption {
        foreground_os_signal_interruption(signal)
    }

    pub fn interruption_for_managed_control_stop() -> ForegroundLifecycleInterruption {
        ForegroundLifecycleInterruption::new("managed-control-stop").with_diagnostics(vec![
            cli_diagnostic(
                DiagnosticSeverity::Warning,
                CLI_START_MANAGED_CONTROL_STOP_REQUESTED_CODE,
                "managed foreground control socket requested runtime stop",
                SOURCE_CLI_MANAGED_CONTROL,
            ),
        ])
    }

    pub fn interruption_for_managed_control_reload() -> ForegroundLifecycleInterruption {
        ForegroundLifecycleInterruption::new("managed-control-reload").with_diagnostics(vec![
            cli_diagnostic(
                DiagnosticSeverity::Info,
                CLI_START_MANAGED_CONTROL_RELOAD_REQUESTED_CODE,
                "managed foreground control socket requested runtime reload",
                SOURCE_CLI_MANAGED_CONTROL,
            ),
        ])
    }

    pub fn interruption_for_managed_control_rollback() -> ForegroundLifecycleInterruption {
        ForegroundLifecycleInterruption::new("managed-control-rollback").with_diagnostics(vec![
            cli_diagnostic(
                DiagnosticSeverity::Warning,
                CLI_START_MANAGED_CONTROL_ROLLBACK_REQUESTED_CODE,
                "managed foreground control socket requested runtime rollback",
                SOURCE_CLI_MANAGED_CONTROL,
            ),
        ])
    }
}

#[cfg(unix)]
impl ForegroundLifecycleInterruptionSource for OsSignalForegroundLifecycleInterruptionSource {
    fn wait_for_interruption(
        &self,
        _request: &ForegroundLifecycleRequest,
    ) -> ForegroundLifecycleInterruption {
        let mut signals = match Signals::new([SIGINT, SIGTERM]) {
            Ok(signals) => signals,
            Err(error) => {
                return ForegroundLifecycleInterruption::new("os-signal-source-failed")
                    .with_diagnostics(vec![cli_diagnostic(
                        DiagnosticSeverity::Error,
                        CLI_START_SIGNAL_SOURCE_FAILED_CODE,
                        format!("failed to register foreground OS signal source: {error}"),
                        SOURCE_CLI_START,
                    )]);
            }
        };

        loop {
            match MANAGED_CONTROL_REQUEST.swap(MANAGED_CONTROL_NONE, Ordering::SeqCst) {
                MANAGED_CONTROL_STOP => return Self::interruption_for_managed_control_stop(),
                MANAGED_CONTROL_RELOAD => return Self::interruption_for_managed_control_reload(),
                MANAGED_CONTROL_ROLLBACK => {
                    return Self::interruption_for_managed_control_rollback()
                }
                _ => {}
            }
            if let Some(signal) = signals.pending().next() {
                return Self::interruption_for_signal(signal);
            }
            thread::sleep(Duration::from_millis(20));
        }
    }
}

#[cfg(unix)]
pub type DefaultForegroundLifecycleInterruptionSource =
    OsSignalForegroundLifecycleInterruptionSource;

#[cfg(not(unix))]
pub type DefaultForegroundLifecycleInterruptionSource =
    ParkingForegroundLifecycleInterruptionSource;

#[derive(Debug, Clone, Copy, Default)]
pub struct CurrentProcessForegroundLifecycleHost<I = DefaultForegroundLifecycleInterruptionSource> {
    pub(crate) interruption_source: I,
}

impl CurrentProcessForegroundLifecycleHost<DefaultForegroundLifecycleInterruptionSource> {
    pub const fn new() -> Self {
        Self {
            interruption_source: DefaultForegroundLifecycleInterruptionSource::new(),
        }
    }
}

impl<I> CurrentProcessForegroundLifecycleHost<I> {
    pub const fn with_interruption_source(interruption_source: I) -> Self {
        Self {
            interruption_source,
        }
    }
}

impl<I> ForegroundLifecycleHost for CurrentProcessForegroundLifecycleHost<I>
where
    I: ForegroundLifecycleInterruptionSource,
{
    fn run_foreground(&self, request: &ForegroundLifecycleRequest) -> ForegroundLifecycleOutcome {
        let interruption = self.interruption_source.wait_for_interruption(request);
        let mut diagnostics = interruption.diagnostics;
        diagnostics.push(cli_diagnostic(
            DiagnosticSeverity::Warning,
            CLI_START_LIFECYCLE_INTERRUPTED_CODE,
            format!(
                "linux foreground runtime was interrupted: {}",
                interruption.reason
            ),
            SOURCE_CLI_START,
        ));

        ForegroundLifecycleOutcome {
            exit_code: LinuxCliExitCode::Interrupted,
            diagnostics,
        }
    }
}

#[cfg(unix)]
pub(crate) fn foreground_os_signal_interruption(signal: i32) -> ForegroundLifecycleInterruption {
    let signal_name = foreground_os_signal_name(signal);

    ForegroundLifecycleInterruption::new(signal_name.clone()).with_diagnostics(vec![
        cli_diagnostic(
            DiagnosticSeverity::Warning,
            CLI_START_SIGNAL_RECEIVED_CODE,
            format!("foreground OS signal {signal_name} interrupted linux runtime"),
            SOURCE_CLI_START,
        ),
    ])
}

#[cfg(unix)]
pub(crate) fn foreground_os_signal_name(signal: i32) -> String {
    match signal {
        SIGINT => "SIGINT".to_string(),
        SIGTERM => "SIGTERM".to_string(),
        _ => format!("signal-{signal}"),
    }
}
