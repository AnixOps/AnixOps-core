//! Handlers for MITM: status, certificate lifecycle and trust, browser
//! capture and HTTP rewrite previews.

use super::*;

pub fn handle_mitm_status<P>(platform: &P) -> LinuxCliResponse
where
    P: PlatformCapabilityService,
{
    handle_mitm_status_inner("mitm status", platform)
}

pub fn handle_mitm_diagnostics<P>(platform: &P) -> LinuxCliResponse
where
    P: PlatformCapabilityService,
{
    handle_mitm_status_inner("mitm diagnostics", platform)
}

pub fn handle_mitm_certificate_plan<P>(platform: &P) -> LinuxCliResponse
where
    P: PlatformCapabilityService,
{
    handle_mitm_status_inner("mitm certificate-plan", platform)
}

pub fn handle_mitm_certificate_trust_apply(
    certificate_path: Option<&str>,
    trust_file_path: Option<&str>,
    snapshot_path: Option<&str>,
    confirm: bool,
) -> LinuxCliResponse {
    let command = "mitm certificate trust-apply";
    let (Some(certificate_path), Some(trust_file_path), Some(snapshot_path)) =
        (certificate_path, trust_file_path, snapshot_path)
    else {
        return LinuxCliResponse::failure(
            command,
            LinuxCliExitCode::ArgumentOrConfig,
            cli_diagnostic(
                DiagnosticSeverity::Error,
                CLI_MITM_CERTIFICATE_TRUST_CONFIG_MISSING_CODE,
                "MITM trust apply requires --cert-file <path>, --trust-file <path>, and --snapshot <path>",
                SOURCE_CLI_MITM,
            ),
        );
    };

    let runner = CommandLinuxTrustRefreshRunner::new();
    match apply_linux_trust(
        &runner,
        &LinuxTrustApplyRequest {
            certificate_path: PathBuf::from(certificate_path),
            trust_file_path: PathBuf::from(trust_file_path),
            snapshot_path: PathBuf::from(snapshot_path),
            confirmed: confirm,
        },
    ) {
        Ok(report) => LinuxCliResponse::success(command).with_diagnostics(vec![cli_diagnostic(
            DiagnosticSeverity::Info,
            CLI_MITM_CERTIFICATE_TRUST_APPLIED_CODE,
            format!(
                "Linux trust file applied and refreshed: {} (snapshot: {})",
                report.trust_file_path.display(),
                report.snapshot_path.display()
            ),
            SOURCE_CLI_MITM,
        )]),
        Err(error) => domain_error_response(
            command,
            LinuxCliExitCode::PlatformDenied,
            error,
            SOURCE_CLI_MITM,
        ),
    }
}

pub fn handle_mitm_certificate_trust_rollback(
    trust_file_path: Option<&str>,
    snapshot_path: Option<&str>,
    confirm: bool,
) -> LinuxCliResponse {
    let command = "mitm certificate trust-rollback";
    let (Some(trust_file_path), Some(snapshot_path)) = (trust_file_path, snapshot_path) else {
        return LinuxCliResponse::failure(
            command,
            LinuxCliExitCode::ArgumentOrConfig,
            cli_diagnostic(
                DiagnosticSeverity::Error,
                CLI_MITM_CERTIFICATE_TRUST_CONFIG_MISSING_CODE,
                "MITM trust rollback requires --trust-file <path> and --snapshot <path>",
                SOURCE_CLI_MITM,
            ),
        );
    };

    let runner = CommandLinuxTrustRefreshRunner::new();
    match rollback_linux_trust(
        &runner,
        &LinuxTrustRollbackRequest {
            trust_file_path: PathBuf::from(trust_file_path),
            snapshot_path: PathBuf::from(snapshot_path),
            confirmed: confirm,
        },
    ) {
        Ok(report) => LinuxCliResponse::success(command).with_diagnostics(vec![cli_diagnostic(
            DiagnosticSeverity::Info,
            CLI_MITM_CERTIFICATE_TRUST_ROLLED_BACK_CODE,
            format!(
                "Linux trust file rolled back and refreshed: {} (snapshot retained: {})",
                report.trust_file_path.display(),
                report.snapshot_retained
            ),
            SOURCE_CLI_MITM,
        )]),
        Err(error) => domain_error_response(
            command,
            LinuxCliExitCode::PlatformDenied,
            error,
            SOURCE_CLI_MITM,
        ),
    }
}

pub fn handle_mitm_certificate_apply<P>(platform: &P, confirm: bool) -> LinuxCliResponse
where
    P: PlatformCapabilityService,
{
    let store = UnavailableMitmCertificateArtifactStore::new();
    handle_mitm_certificate_apply_with_store(platform, &store, None, None, None, None, confirm)
}

pub fn handle_mitm_certificate_apply_with_store<P, S>(
    platform: &P,
    certificate_store: &S,
    cert_file_path: Option<&str>,
    key_file_path: Option<&str>,
    profile_trust_file_path: Option<&str>,
    snapshot_path: Option<&str>,
    confirm: bool,
) -> LinuxCliResponse
where
    P: PlatformCapabilityService,
    S: MitmCertificateArtifactStore,
{
    let command = "mitm certificate apply";
    let platform_status = match platform.status() {
        Ok(status) => status,
        Err(error) => {
            return domain_error_response(
                command,
                LinuxCliExitCode::GeneralFailure,
                error,
                SOURCE_CLI_MITM,
            );
        }
    };

    let (mitm_status, mut diagnostics) = match build_linux_mitm_status(&platform_status) {
        Ok(status) => status,
        Err(error) => {
            return domain_error_response(
                command,
                LinuxCliExitCode::GeneralFailure,
                error,
                SOURCE_CLI_MITM,
            );
        }
    };

    let authorization = MitmCertificateAuthorization {
        confirmed: confirm,
        source: if confirm {
            "cli --confirm".to_string()
        } else {
            "missing --confirm".to_string()
        },
        scope:
            "linux MITM certificate, private key, and optional dedicated profile trust artifacts"
                .to_string(),
        gate: MITM_CERTIFICATE_LIFECYCLE_GATE.to_string(),
    };
    let mut report = build_linux_mitm_certificate_lifecycle_report(
        LinuxMitmCertificateLifecycleAction::Apply,
        &platform_status,
        Some(authorization.clone()),
        None,
    );

    if !confirm {
        diagnostics.push(cli_diagnostic(
            DiagnosticSeverity::Error,
            CLI_MITM_CERTIFICATE_AUTHORIZATION_REQUIRED_CODE,
            "MITM certificate artifact apply requires --confirm; no certificate or private key artifact was written",
            SOURCE_CLI_MITM,
        ));
        report.apply_report = Some(LinuxMitmCertificateApplyReport {
            status: "authorization_required".to_string(),
            applied: false,
            authorization,
            cert_file_path: cert_file_path.map(ToString::to_string),
            key_file_path: key_file_path.map(ToString::to_string),
            profile_trust_file_path: profile_trust_file_path.map(ToString::to_string),
            rollback_snapshot: snapshot_path.map(|path| MitmCertificateRollbackSnapshot {
                path: path.to_string(),
                status: "operator-provided".to_string(),
            }),
            blocked_operations: report.trust_plan.blocked_operations.clone(),
        });
        return LinuxCliResponse {
            ok: false,
            exit_code: LinuxCliExitCode::Unavailable,
            ..LinuxCliResponse::success(command)
                .with_platform(platform_status)
                .with_mitm_status(mitm_status)
                .with_certificate_lifecycle(report)
                .with_diagnostics(diagnostics)
        };
    }

    let (Some(cert_file_path), Some(key_file_path), Some(snapshot_path)) =
        (cert_file_path, key_file_path, snapshot_path)
    else {
        diagnostics.push(cli_diagnostic(
            DiagnosticSeverity::Error,
            CLI_MITM_CERTIFICATE_APPLY_CONFIG_MISSING_CODE,
            "MITM certificate artifact apply requires --cert-file <path>, --key-file <path>, and --snapshot <path>",
            SOURCE_CLI_MITM,
        ));
        report.apply_report = Some(LinuxMitmCertificateApplyReport {
            status: "config_missing".to_string(),
            applied: false,
            authorization,
            cert_file_path: cert_file_path.map(ToString::to_string),
            key_file_path: key_file_path.map(ToString::to_string),
            profile_trust_file_path: profile_trust_file_path.map(ToString::to_string),
            rollback_snapshot: snapshot_path.map(|path| MitmCertificateRollbackSnapshot {
                path: path.to_string(),
                status: "operator-provided".to_string(),
            }),
            blocked_operations: report.trust_plan.blocked_operations.clone(),
        });
        return LinuxCliResponse {
            ok: false,
            exit_code: LinuxCliExitCode::ArgumentOrConfig,
            ..LinuxCliResponse::success(command)
                .with_platform(platform_status)
                .with_mitm_status(mitm_status)
                .with_certificate_lifecycle(report)
                .with_diagnostics(diagnostics)
        };
    };

    let artifact_request = match build_linux_mitm_certificate_artifact_request(
        cert_file_path,
        key_file_path,
        profile_trust_file_path,
        snapshot_path,
    ) {
        Ok(artifact_request) => artifact_request,
        Err(error) => {
            diagnostics.push(cli_diagnostic(
                DiagnosticSeverity::Error,
                error.code,
                error.message,
                SOURCE_CLI_MITM,
            ));
            report.apply_report = Some(LinuxMitmCertificateApplyReport {
                status: "failed".to_string(),
                applied: false,
                authorization,
                cert_file_path: Some(cert_file_path.to_string()),
                key_file_path: Some(key_file_path.to_string()),
                profile_trust_file_path: profile_trust_file_path.map(ToString::to_string),
                rollback_snapshot: Some(MitmCertificateRollbackSnapshot {
                    path: snapshot_path.to_string(),
                    status: "operator-provided".to_string(),
                }),
                blocked_operations: report.trust_plan.blocked_operations.clone(),
            });
            return LinuxCliResponse {
                ok: false,
                exit_code: LinuxCliExitCode::Unavailable,
                ..LinuxCliResponse::success(command)
                    .with_platform(platform_status)
                    .with_mitm_status(mitm_status)
                    .with_certificate_lifecycle(report)
                    .with_diagnostics(diagnostics)
            };
        }
    };
    report.request.artifact = Some(artifact_request.clone());

    match certificate_store.apply_certificate_artifact(&artifact_request) {
        Ok(outcome) => {
            diagnostics.extend(outcome.diagnostics);
            report.apply_report = Some(LinuxMitmCertificateApplyReport {
                status: "applied".to_string(),
                applied: true,
                authorization,
                cert_file_path: Some(artifact_request.cert_file_path.clone()),
                key_file_path: Some(artifact_request.key_file_path.clone()),
                profile_trust_file_path: artifact_request.profile_trust_file_path.clone(),
                rollback_snapshot: Some(outcome.rollback_snapshot),
                blocked_operations: report.trust_plan.blocked_operations.clone(),
            });
            LinuxCliResponse::success(command)
                .with_platform(platform_status)
                .with_mitm_status(mitm_status)
                .with_certificate_lifecycle(report)
                .with_diagnostics(diagnostics)
        }
        Err(error) => {
            diagnostics.push(cli_diagnostic(
                DiagnosticSeverity::Error,
                error.code,
                error.message,
                SOURCE_CLI_MITM,
            ));
            report.apply_report = Some(LinuxMitmCertificateApplyReport {
                status: "failed".to_string(),
                applied: false,
                authorization,
                cert_file_path: Some(artifact_request.cert_file_path.clone()),
                key_file_path: Some(artifact_request.key_file_path.clone()),
                profile_trust_file_path: artifact_request.profile_trust_file_path.clone(),
                rollback_snapshot: Some(MitmCertificateRollbackSnapshot {
                    path: artifact_request.snapshot_path,
                    status: "operator-provided".to_string(),
                }),
                blocked_operations: report.trust_plan.blocked_operations.clone(),
            });
            LinuxCliResponse {
                ok: false,
                exit_code: LinuxCliExitCode::Unavailable,
                ..LinuxCliResponse::success(command)
                    .with_platform(platform_status)
                    .with_mitm_status(mitm_status)
                    .with_certificate_lifecycle(report)
                    .with_diagnostics(diagnostics)
            }
        }
    }
}

pub fn handle_mitm_certificate_rollback<P>(
    platform: &P,
    snapshot_path: Option<String>,
) -> LinuxCliResponse
where
    P: PlatformCapabilityService,
{
    let store = UnavailableMitmCertificateArtifactStore::new();
    handle_mitm_certificate_rollback_with_store(platform, &store, snapshot_path)
}

pub fn handle_mitm_certificate_rollback_with_store<P, S>(
    platform: &P,
    certificate_store: &S,
    snapshot_path: Option<String>,
) -> LinuxCliResponse
where
    P: PlatformCapabilityService,
    S: MitmCertificateArtifactStore,
{
    let command = "mitm certificate rollback";
    let platform_status = match platform.status() {
        Ok(status) => status,
        Err(error) => {
            return domain_error_response(
                command,
                LinuxCliExitCode::GeneralFailure,
                error,
                SOURCE_CLI_MITM,
            );
        }
    };

    let (mitm_status, mut diagnostics) = match build_linux_mitm_status(&platform_status) {
        Ok(status) => status,
        Err(error) => {
            return domain_error_response(
                command,
                LinuxCliExitCode::GeneralFailure,
                error,
                SOURCE_CLI_MITM,
            );
        }
    };

    let Some(snapshot_path) = snapshot_path else {
        diagnostics.push(cli_diagnostic(
            DiagnosticSeverity::Error,
            CLI_MITM_CERTIFICATE_ROLLBACK_BLOCKED_CODE,
            "MITM certificate artifact rollback requires --snapshot <path>",
            SOURCE_CLI_MITM,
        ));
        let report = build_linux_mitm_certificate_lifecycle_report(
            LinuxMitmCertificateLifecycleAction::Rollback,
            &platform_status,
            None,
            None,
        );
        return LinuxCliResponse {
            ok: false,
            exit_code: LinuxCliExitCode::ArgumentOrConfig,
            ..LinuxCliResponse::success(command)
                .with_platform(platform_status)
                .with_mitm_status(mitm_status)
                .with_certificate_lifecycle(report)
                .with_diagnostics(diagnostics)
        };
    };

    let rollback_snapshot = MitmCertificateRollbackSnapshot {
        path: snapshot_path,
        status: "operator-provided".to_string(),
    };
    let mut report = build_linux_mitm_certificate_lifecycle_report(
        LinuxMitmCertificateLifecycleAction::Rollback,
        &platform_status,
        None,
        Some(rollback_snapshot.clone()),
    );

    match certificate_store.rollback_certificate_artifact(&rollback_snapshot) {
        Ok(outcome) => {
            diagnostics.extend(outcome.diagnostics);
            report.rollback_report = Some(LinuxMitmCertificateRollbackReport {
                status: "rolled_back".to_string(),
                rolled_back: true,
                cert_file_path: Some(outcome.cert_file_path),
                key_file_path: Some(outcome.key_file_path),
                profile_trust_file_path: outcome.profile_trust_file_path,
                rollback_snapshot: Some(MitmCertificateRollbackSnapshot {
                    status: "networkcore-restored".to_string(),
                    ..rollback_snapshot
                }),
                blocked_operations: report.trust_plan.blocked_operations.clone(),
            });
            LinuxCliResponse::success(command)
                .with_platform(platform_status)
                .with_mitm_status(mitm_status)
                .with_certificate_lifecycle(report)
                .with_diagnostics(diagnostics)
        }
        Err(error) => {
            diagnostics.push(cli_diagnostic(
                DiagnosticSeverity::Error,
                error.code,
                error.message,
                SOURCE_CLI_MITM,
            ));
            report.rollback_report = Some(LinuxMitmCertificateRollbackReport {
                status: "failed".to_string(),
                rolled_back: false,
                cert_file_path: None,
                key_file_path: None,
                profile_trust_file_path: None,
                rollback_snapshot: Some(rollback_snapshot),
                blocked_operations: report.trust_plan.blocked_operations.clone(),
            });
            LinuxCliResponse {
                ok: false,
                exit_code: LinuxCliExitCode::Unavailable,
                ..LinuxCliResponse::success(command)
                    .with_platform(platform_status)
                    .with_mitm_status(mitm_status)
                    .with_certificate_lifecycle(report)
                    .with_diagnostics(diagnostics)
            }
        }
    }
}

pub fn handle_mitm_browser_plan<P>(platform: &P) -> LinuxCliResponse
where
    P: PlatformCapabilityService,
{
    handle_mitm_status_inner("mitm browser-plan", platform)
}

pub fn handle_mitm_browser_capture_plan<P>(platform: &P) -> LinuxCliResponse
where
    P: PlatformCapabilityService,
{
    handle_mitm_browser_capture_plan_with_proxy_scheme(
        platform,
        MITM_BROWSER_CAPTURE_DEFAULT_PROXY_SCHEME,
    )
}

pub fn handle_mitm_browser_capture_plan_with_proxy_scheme<P>(
    platform: &P,
    proxy_scheme: &str,
) -> LinuxCliResponse
where
    P: PlatformCapabilityService,
{
    handle_mitm_browser_capture_inner(
        "mitm browser-capture plan",
        platform,
        LinuxBrowserCaptureAction::Plan,
        false,
        None,
        None,
        None,
        None,
        Some(proxy_scheme),
    )
}

pub fn handle_mitm_browser_capture_launch_plan<P>(platform: &P) -> LinuxCliResponse
where
    P: PlatformCapabilityService,
{
    handle_mitm_browser_capture_launch_plan_with_proxy_scheme(
        platform,
        MITM_BROWSER_CAPTURE_DEFAULT_PROXY_SCHEME,
    )
}

pub fn handle_mitm_browser_capture_launch_plan_with_proxy_scheme<P>(
    platform: &P,
    proxy_scheme: &str,
) -> LinuxCliResponse
where
    P: PlatformCapabilityService,
{
    handle_mitm_browser_capture_inner(
        "mitm browser-capture launch-plan",
        platform,
        LinuxBrowserCaptureAction::LaunchPlan,
        false,
        None,
        None,
        None,
        None,
        Some(proxy_scheme),
    )
}

#[allow(clippy::too_many_arguments)]
pub fn handle_mitm_browser_capture_session_plan<P>(
    platform: &P,
    url: &str,
    browser: &str,
    profile_dir: &str,
    target_url: Option<&str>,
    proof_token: Option<&str>,
    proof_log_path: Option<&str>,
    listen_host: &str,
    listen_port: u16,
) -> LinuxCliResponse
where
    P: PlatformCapabilityService,
{
    handle_mitm_browser_capture_session_plan_with_proxy_scheme(
        platform,
        url,
        browser,
        profile_dir,
        target_url,
        proof_token,
        proof_log_path,
        MITM_BROWSER_CAPTURE_DEFAULT_PROXY_SCHEME,
        listen_host,
        listen_port,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn handle_mitm_browser_capture_session_plan_with_proxy_scheme<P>(
    platform: &P,
    url: &str,
    browser: &str,
    profile_dir: &str,
    target_url: Option<&str>,
    proof_token: Option<&str>,
    proof_log_path: Option<&str>,
    proxy_scheme: &str,
    listen_host: &str,
    listen_port: u16,
) -> LinuxCliResponse
where
    P: PlatformCapabilityService,
{
    let command = "mitm browser-capture session-plan";
    let platform_status = match platform.status() {
        Ok(status) => status,
        Err(error) => {
            return domain_error_response(
                command,
                LinuxCliExitCode::GeneralFailure,
                error,
                SOURCE_CLI_MITM,
            );
        }
    };

    let (mitm_status, mut diagnostics) = match build_linux_mitm_status(&platform_status) {
        Ok(status) => status,
        Err(error) => {
            return domain_error_response(
                command,
                LinuxCliExitCode::GeneralFailure,
                error,
                SOURCE_CLI_MITM,
            );
        }
    };

    let subscription = CoreSubscriptionService::new();
    let raw_subscription = RawSubscription {
        source_id: "cli-browser-capture-session-plan".to_string(),
        content: url.to_string(),
    };
    let document = match subscription.parse(&raw_subscription) {
        Ok(document) => document,
        Err(error) => {
            return domain_error_response(
                command,
                LinuxCliExitCode::ArgumentOrConfig,
                DomainError::new(
                    CLI_MITM_BROWSER_CAPTURE_SESSION_PLAN_URL_PARSE_FAILED_CODE,
                    error.message,
                ),
                SOURCE_CLI_MITM,
            );
        }
    };
    let catalog = match subscription.normalize(&document) {
        Ok(catalog) => catalog,
        Err(error) => {
            return domain_error_response(
                command,
                LinuxCliExitCode::ArgumentOrConfig,
                DomainError::new(
                    CLI_MITM_BROWSER_CAPTURE_SESSION_PLAN_URL_PARSE_FAILED_CODE,
                    error.message,
                ),
                SOURCE_CLI_MITM,
            );
        }
    };
    let Some(selected_node) = catalog.nodes.first() else {
        return domain_error_response(
            command,
            LinuxCliExitCode::ArgumentOrConfig,
            DomainError::new(
                CLI_MITM_BROWSER_CAPTURE_SESSION_PLAN_CONFIG_FAILED_CODE,
                "subscription contains no usable node for the browser capture session",
            ),
            SOURCE_CLI_MITM,
        );
    };
    let selected_node_id = selected_node.id.clone();
    let selected_node_name = selected_node.name.clone();

    diagnostics.extend(document.diagnostics.clone());
    diagnostics.push(cli_diagnostic(
        DiagnosticSeverity::Info,
        CLI_MITM_BROWSER_CAPTURE_SESSION_PLAN_READY_CODE,
        "browser capture session plan is ready; no proxy process, browser process, or system state was changed",
        SOURCE_CLI_MITM,
    ));

    let plan = build_linux_browser_capture_plan_with_proxy_scheme(
        &platform_status,
        &mitm_status.policy,
        listen_host,
        listen_port,
        proxy_scheme,
    );
    let launch_request = build_linux_browser_capture_launch_request(
        browser,
        profile_dir,
        target_url,
        proof_token,
        proof_log_path,
        &plan,
    );
    let verify_request = build_linux_browser_capture_verify_request(&plan, target_url);
    let traffic_proof_request = build_linux_browser_capture_traffic_proof_request(
        &plan,
        target_url,
        Some(&launch_request.proof_token),
        Some(&launch_request.proof_log_path),
    );
    let session_request = LinuxBrowserCaptureSessionPlanRequest {
        url_source: "cli-argument-redacted".to_string(),
        browser: browser.to_string(),
        profile_dir: profile_dir.to_string(),
        target_url: target_url.map(ToString::to_string),
        proof_target_url: launch_request.proof_target_url.clone(),
        proof_token: launch_request.proof_token.clone(),
        proof_log_path: launch_request.proof_log_path.clone(),
        proxy_scheme: plan.planned_proxy_scheme.clone(),
        listen_host: listen_host.to_string(),
        listen_port,
    };
    let session_plan = build_linux_browser_capture_session_plan_report(
        session_request.clone(),
        selected_node_id,
        selected_node_name,
        launch_request.command.clone(),
        verify_request.proxy_url.clone(),
        traffic_proof_request.clone(),
        &mitm_status.policy,
        plan.blocked_operations.clone(),
    );
    let request = LinuxBrowserCaptureRequest {
        action: LinuxBrowserCaptureAction::SessionPlan,
        session: Some(session_request),
        launch: Some(launch_request),
        pac: None,
        verify: Some(verify_request),
        traffic_proof: Some(traffic_proof_request),
        authorization: None,
        rollback_snapshot: None,
    };
    let mut report = build_linux_browser_capture_report(
        LinuxBrowserCaptureAction::SessionPlan,
        &platform_status,
        &mitm_status.policy,
        None,
        None,
        None,
        None,
        None,
    );
    report.request = request;
    report.plan = plan;
    report.session_plan = Some(session_plan);

    LinuxCliResponse::success(command)
        .with_platform(platform_status)
        .with_mitm_status(mitm_status)
        .with_browser_capture(report)
        .with_diagnostics(diagnostics)
}

#[allow(clippy::too_many_arguments)]
pub fn handle_mitm_browser_capture_launch<P, B>(
    platform: &P,
    browser_runner: &B,
    browser: &str,
    profile_dir: &str,
    target_url: Option<&str>,
    proof_token: Option<&str>,
    proof_log_path: Option<&str>,
    confirm: bool,
) -> LinuxCliResponse
where
    P: PlatformCapabilityService,
    B: BrowserCaptureProcessRunner,
{
    handle_mitm_browser_capture_launch_with_proxy_scheme(
        platform,
        browser_runner,
        browser,
        profile_dir,
        target_url,
        proof_token,
        proof_log_path,
        MITM_BROWSER_CAPTURE_DEFAULT_PROXY_SCHEME,
        confirm,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn handle_mitm_browser_capture_launch_with_proxy_scheme<P, B>(
    platform: &P,
    browser_runner: &B,
    browser: &str,
    profile_dir: &str,
    target_url: Option<&str>,
    proof_token: Option<&str>,
    proof_log_path: Option<&str>,
    proxy_scheme: &str,
    confirm: bool,
) -> LinuxCliResponse
where
    P: PlatformCapabilityService,
    B: BrowserCaptureProcessRunner,
{
    let command = "mitm browser-capture launch";
    let platform_status = match platform.status() {
        Ok(status) => status,
        Err(error) => {
            return domain_error_response(
                command,
                LinuxCliExitCode::GeneralFailure,
                error,
                SOURCE_CLI_MITM,
            );
        }
    };

    let (mitm_status, mut diagnostics) = match build_linux_mitm_status(&platform_status) {
        Ok(status) => status,
        Err(error) => {
            return domain_error_response(
                command,
                LinuxCliExitCode::GeneralFailure,
                error,
                SOURCE_CLI_MITM,
            );
        }
    };

    let authorization = BrowserCaptureAuthorization {
        confirmed: confirm,
        source: if confirm {
            "cli --confirm".to_string()
        } else {
            "missing --confirm".to_string()
        },
        scope: "linux dedicated browser profile launch".to_string(),
        gate: MITM_BROWSER_CAPTURE_GATE.to_string(),
    };
    let mut report = build_linux_browser_capture_report_with_proxy_scheme(
        LinuxBrowserCaptureAction::Launch,
        &platform_status,
        &mitm_status.policy,
        Some(authorization),
        None,
        None,
        None,
        None,
        proxy_scheme,
    );
    let launch_request = build_linux_browser_capture_launch_request(
        browser,
        profile_dir,
        target_url,
        proof_token,
        proof_log_path,
        &report.plan,
    );
    let traffic_proof_request = build_linux_browser_capture_traffic_proof_request(
        &report.plan,
        target_url,
        Some(&launch_request.proof_token),
        Some(&launch_request.proof_log_path),
    );
    report.request.launch = Some(launch_request.clone());
    report.request.traffic_proof = Some(traffic_proof_request);

    if !confirm {
        diagnostics.push(cli_diagnostic(
            DiagnosticSeverity::Error,
            CLI_MITM_BROWSER_CAPTURE_LAUNCH_AUTHORIZATION_REQUIRED_CODE,
            "browser capture launch requires --confirm before starting a dedicated browser profile",
            SOURCE_CLI_MITM,
        ));
        report.launch_report = Some(build_linux_browser_capture_launch_report(
            "authorization_required",
            false,
            None,
            launch_request,
            &mitm_status.policy,
        ));
        return LinuxCliResponse {
            ok: false,
            exit_code: LinuxCliExitCode::Unavailable,
            ..LinuxCliResponse::success(command)
                .with_platform(platform_status)
                .with_mitm_status(mitm_status)
                .with_browser_capture(report)
                .with_diagnostics(diagnostics)
        };
    }

    match browser_runner.launch(&launch_request) {
        Ok(outcome) => {
            let LinuxBrowserCaptureLaunchOutcome {
                pid,
                diagnostics: runner_diagnostics,
            } = outcome;
            diagnostics.extend(runner_diagnostics);
            report.launch_report = Some(build_linux_browser_capture_launch_report(
                "started",
                true,
                Some(pid),
                launch_request,
                &mitm_status.policy,
            ));
            LinuxCliResponse::success(command)
                .with_platform(platform_status)
                .with_mitm_status(mitm_status)
                .with_browser_capture(report)
                .with_diagnostics(diagnostics)
        }
        Err(error) => {
            diagnostics.push(cli_diagnostic(
                DiagnosticSeverity::Error,
                CLI_MITM_BROWSER_CAPTURE_LAUNCH_FAILED_CODE,
                error.message,
                SOURCE_CLI_MITM,
            ));
            report.launch_report = Some(build_linux_browser_capture_launch_report(
                "failed",
                false,
                None,
                launch_request,
                &mitm_status.policy,
            ));
            LinuxCliResponse {
                ok: false,
                exit_code: LinuxCliExitCode::GeneralFailure,
                ..LinuxCliResponse::success(command)
                    .with_platform(platform_status)
                    .with_mitm_status(mitm_status)
                    .with_browser_capture(report)
                    .with_diagnostics(diagnostics)
            }
        }
    }
}

pub(crate) fn handle_mitm_browser_capture_launch_unwired() -> LinuxCliResponse {
    LinuxCliResponse::failure(
        "mitm browser-capture launch",
        LinuxCliExitCode::Unavailable,
        cli_diagnostic(
            DiagnosticSeverity::Error,
            CLI_MITM_BROWSER_CAPTURE_LAUNCH_FAILED_CODE,
            "browser capture process runner is not wired",
            SOURCE_CLI_MITM,
        ),
    )
}

pub fn handle_mitm_browser_capture_apply<P>(platform: &P, confirm: bool) -> LinuxCliResponse
where
    P: PlatformCapabilityService,
{
    handle_mitm_browser_capture_apply_with_proxy_scheme(
        platform,
        MITM_BROWSER_CAPTURE_DEFAULT_PROXY_SCHEME,
        confirm,
    )
}

pub fn handle_mitm_browser_capture_apply_with_proxy_scheme<P>(
    platform: &P,
    proxy_scheme: &str,
    confirm: bool,
) -> LinuxCliResponse
where
    P: PlatformCapabilityService,
{
    handle_mitm_browser_capture_inner(
        "mitm browser-capture apply",
        platform,
        LinuxBrowserCaptureAction::Apply,
        confirm,
        None,
        None,
        None,
        None,
        Some(proxy_scheme),
    )
}

pub fn handle_mitm_browser_capture_apply_with_store<P, S>(
    platform: &P,
    pac_store: &S,
    pac_file_path: Option<&str>,
    policy_file_path: Option<&str>,
    snapshot_path: Option<&str>,
    confirm: bool,
) -> LinuxCliResponse
where
    P: PlatformCapabilityService,
    S: BrowserCapturePacFileStore,
{
    handle_mitm_browser_capture_apply_with_store_and_profile_prefs_and_proxy_scheme(
        platform,
        pac_store,
        pac_file_path,
        policy_file_path,
        None,
        snapshot_path,
        MITM_BROWSER_CAPTURE_DEFAULT_PROXY_SCHEME,
        confirm,
    )
}

pub fn handle_mitm_browser_capture_apply_with_store_and_proxy_scheme<P, S>(
    platform: &P,
    pac_store: &S,
    pac_file_path: Option<&str>,
    policy_file_path: Option<&str>,
    snapshot_path: Option<&str>,
    proxy_scheme: &str,
    confirm: bool,
) -> LinuxCliResponse
where
    P: PlatformCapabilityService,
    S: BrowserCapturePacFileStore,
{
    handle_mitm_browser_capture_apply_with_store_and_profile_prefs_and_proxy_scheme(
        platform,
        pac_store,
        pac_file_path,
        policy_file_path,
        None,
        snapshot_path,
        proxy_scheme,
        confirm,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn handle_mitm_browser_capture_apply_with_store_and_profile_prefs_and_proxy_scheme<P, S>(
    platform: &P,
    pac_store: &S,
    pac_file_path: Option<&str>,
    policy_file_path: Option<&str>,
    profile_prefs_file_path: Option<&str>,
    snapshot_path: Option<&str>,
    proxy_scheme: &str,
    confirm: bool,
) -> LinuxCliResponse
where
    P: PlatformCapabilityService,
    S: BrowserCapturePacFileStore,
{
    let command = "mitm browser-capture apply";
    let platform_status = match platform.status() {
        Ok(status) => status,
        Err(error) => {
            return domain_error_response(
                command,
                LinuxCliExitCode::GeneralFailure,
                error,
                SOURCE_CLI_MITM,
            );
        }
    };

    let (mitm_status, mut diagnostics) = match build_linux_mitm_status(&platform_status) {
        Ok(status) => status,
        Err(error) => {
            return domain_error_response(
                command,
                LinuxCliExitCode::GeneralFailure,
                error,
                SOURCE_CLI_MITM,
            );
        }
    };

    let authorization = BrowserCaptureAuthorization {
        confirmed: confirm,
        source: if confirm {
            "cli --confirm".to_string()
        } else {
            "missing --confirm".to_string()
        },
        scope: "linux browser capture PAC/browser policy artifacts".to_string(),
        gate: MITM_BROWSER_CAPTURE_GATE.to_string(),
    };
    let mut report = build_linux_browser_capture_report_with_proxy_scheme(
        LinuxBrowserCaptureAction::Apply,
        &platform_status,
        &mitm_status.policy,
        Some(authorization.clone()),
        None,
        None,
        None,
        None,
        proxy_scheme,
    );

    if !confirm {
        diagnostics.push(cli_diagnostic(
            DiagnosticSeverity::Error,
            CLI_MITM_BROWSER_CAPTURE_AUTHORIZATION_REQUIRED_CODE,
            "browser capture apply requires --confirm; no browser capture PAC or policy artifact was written",
            SOURCE_CLI_MITM,
        ));
        report.apply_report = Some(LinuxBrowserCaptureApplyReport {
            status: "authorization_required".to_string(),
            applied: false,
            authorization,
            pac_file_path: pac_file_path.map(ToString::to_string),
            pac_url: pac_file_path.map(browser_capture_pac_file_url),
            policy_file_path: policy_file_path.map(ToString::to_string),
            policy_url: policy_file_path.map(browser_capture_pac_file_url),
            profile_prefs_file_path: profile_prefs_file_path.map(ToString::to_string),
            rollback_snapshot: snapshot_path.map(|path| BrowserCaptureRollbackSnapshot {
                path: path.to_string(),
                status: "operator-provided".to_string(),
            }),
            blocked_operations: report.plan.blocked_operations.clone(),
        });
        return LinuxCliResponse {
            ok: false,
            exit_code: LinuxCliExitCode::Unavailable,
            ..LinuxCliResponse::success(command)
                .with_platform(platform_status)
                .with_mitm_status(mitm_status)
                .with_browser_capture(report)
                .with_diagnostics(diagnostics)
        };
    }

    let (Some(pac_file_path), Some(snapshot_path)) = (pac_file_path, snapshot_path) else {
        diagnostics.push(cli_diagnostic(
            DiagnosticSeverity::Error,
            CLI_MITM_BROWSER_CAPTURE_APPLY_CONFIG_MISSING_CODE,
            "browser capture apply requires --pac-file <path> and --snapshot <path>",
            SOURCE_CLI_MITM,
        ));
        report.apply_report = Some(LinuxBrowserCaptureApplyReport {
            status: "config_missing".to_string(),
            applied: false,
            authorization,
            pac_file_path: pac_file_path.map(ToString::to_string),
            pac_url: pac_file_path.map(browser_capture_pac_file_url),
            policy_file_path: policy_file_path.map(ToString::to_string),
            policy_url: policy_file_path.map(browser_capture_pac_file_url),
            profile_prefs_file_path: profile_prefs_file_path.map(ToString::to_string),
            rollback_snapshot: snapshot_path.map(|path| BrowserCaptureRollbackSnapshot {
                path: path.to_string(),
                status: "operator-provided".to_string(),
            }),
            blocked_operations: report.plan.blocked_operations.clone(),
        });
        return LinuxCliResponse {
            ok: false,
            exit_code: LinuxCliExitCode::ArgumentOrConfig,
            ..LinuxCliResponse::success(command)
                .with_platform(platform_status)
                .with_mitm_status(mitm_status)
                .with_browser_capture(report)
                .with_diagnostics(diagnostics)
        };
    };

    let pac_request = build_linux_browser_capture_pac_request(
        &report.plan,
        pac_file_path,
        policy_file_path,
        profile_prefs_file_path,
        snapshot_path,
    );
    report.request.pac = Some(pac_request.clone());

    match pac_store.apply_pac_file(&pac_request) {
        Ok(outcome) => {
            diagnostics.extend(outcome.diagnostics);
            report.apply_report = Some(LinuxBrowserCaptureApplyReport {
                status: "applied".to_string(),
                applied: true,
                authorization,
                pac_file_path: Some(pac_request.pac_file_path.clone()),
                pac_url: Some(pac_request.pac_url.clone()),
                policy_file_path: pac_request.policy_file_path.clone(),
                policy_url: pac_request.policy_url.clone(),
                profile_prefs_file_path: pac_request.profile_prefs_file_path.clone(),
                rollback_snapshot: Some(outcome.rollback_snapshot),
                blocked_operations: report.plan.blocked_operations.clone(),
            });
            LinuxCliResponse::success(command)
                .with_platform(platform_status)
                .with_mitm_status(mitm_status)
                .with_browser_capture(report)
                .with_diagnostics(diagnostics)
        }
        Err(error) => {
            diagnostics.push(cli_diagnostic(
                DiagnosticSeverity::Error,
                error.code,
                error.message,
                SOURCE_CLI_MITM,
            ));
            report.apply_report = Some(LinuxBrowserCaptureApplyReport {
                status: "failed".to_string(),
                applied: false,
                authorization,
                pac_file_path: Some(pac_request.pac_file_path.clone()),
                pac_url: Some(pac_request.pac_url.clone()),
                policy_file_path: pac_request.policy_file_path.clone(),
                policy_url: pac_request.policy_url.clone(),
                profile_prefs_file_path: pac_request.profile_prefs_file_path.clone(),
                rollback_snapshot: Some(BrowserCaptureRollbackSnapshot {
                    path: pac_request.snapshot_path,
                    status: "operator-provided".to_string(),
                }),
                blocked_operations: report.plan.blocked_operations.clone(),
            });
            LinuxCliResponse {
                ok: false,
                exit_code: LinuxCliExitCode::Unavailable,
                ..LinuxCliResponse::success(command)
                    .with_platform(platform_status)
                    .with_mitm_status(mitm_status)
                    .with_browser_capture(report)
                    .with_diagnostics(diagnostics)
            }
        }
    }
}

pub fn handle_mitm_browser_capture_rollback<P>(
    platform: &P,
    snapshot_path: Option<String>,
) -> LinuxCliResponse
where
    P: PlatformCapabilityService,
{
    handle_mitm_browser_capture_inner(
        "mitm browser-capture rollback",
        platform,
        LinuxBrowserCaptureAction::Rollback,
        false,
        snapshot_path,
        None,
        None,
        None,
        None,
    )
}

pub fn handle_mitm_browser_capture_rollback_with_store<P, S>(
    platform: &P,
    pac_store: &S,
    snapshot_path: Option<String>,
) -> LinuxCliResponse
where
    P: PlatformCapabilityService,
    S: BrowserCapturePacFileStore,
{
    let command = "mitm browser-capture rollback";
    let platform_status = match platform.status() {
        Ok(status) => status,
        Err(error) => {
            return domain_error_response(
                command,
                LinuxCliExitCode::GeneralFailure,
                error,
                SOURCE_CLI_MITM,
            );
        }
    };

    let (mitm_status, mut diagnostics) = match build_linux_mitm_status(&platform_status) {
        Ok(status) => status,
        Err(error) => {
            return domain_error_response(
                command,
                LinuxCliExitCode::GeneralFailure,
                error,
                SOURCE_CLI_MITM,
            );
        }
    };

    let Some(snapshot_path) = snapshot_path else {
        diagnostics.push(cli_diagnostic(
            DiagnosticSeverity::Error,
            CLI_MITM_BROWSER_CAPTURE_ROLLBACK_BLOCKED_CODE,
            "browser capture rollback requires --snapshot <path>",
            SOURCE_CLI_MITM,
        ));
        let report = build_linux_browser_capture_report(
            LinuxBrowserCaptureAction::Rollback,
            &platform_status,
            &mitm_status.policy,
            None,
            None,
            None,
            None,
            None,
        );
        return LinuxCliResponse {
            ok: false,
            exit_code: LinuxCliExitCode::ArgumentOrConfig,
            ..LinuxCliResponse::success(command)
                .with_platform(platform_status)
                .with_mitm_status(mitm_status)
                .with_browser_capture(report)
                .with_diagnostics(diagnostics)
        };
    };

    let rollback_snapshot = BrowserCaptureRollbackSnapshot {
        path: snapshot_path,
        status: "operator-provided".to_string(),
    };
    let mut report = build_linux_browser_capture_report(
        LinuxBrowserCaptureAction::Rollback,
        &platform_status,
        &mitm_status.policy,
        None,
        Some(rollback_snapshot.clone()),
        None,
        None,
        None,
    );

    match pac_store.rollback_pac_file(&rollback_snapshot) {
        Ok(outcome) => {
            diagnostics.extend(outcome.diagnostics);
            report.rollback_report = Some(LinuxBrowserCaptureRollbackReport {
                status: "rolled_back".to_string(),
                rolled_back: true,
                pac_file_path: Some(outcome.pac_file_path),
                policy_file_path: outcome.policy_file_path,
                profile_prefs_file_path: outcome.profile_prefs_file_path,
                rollback_snapshot: Some(BrowserCaptureRollbackSnapshot {
                    status: "networkcore-restored".to_string(),
                    ..rollback_snapshot
                }),
                blocked_operations: report.plan.blocked_operations.clone(),
            });
            LinuxCliResponse::success(command)
                .with_platform(platform_status)
                .with_mitm_status(mitm_status)
                .with_browser_capture(report)
                .with_diagnostics(diagnostics)
        }
        Err(error) => {
            diagnostics.push(cli_diagnostic(
                DiagnosticSeverity::Error,
                error.code,
                error.message,
                SOURCE_CLI_MITM,
            ));
            report.rollback_report = Some(LinuxBrowserCaptureRollbackReport {
                status: "failed".to_string(),
                rolled_back: false,
                pac_file_path: None,
                policy_file_path: None,
                profile_prefs_file_path: None,
                rollback_snapshot: Some(rollback_snapshot),
                blocked_operations: report.plan.blocked_operations.clone(),
            });
            LinuxCliResponse {
                ok: false,
                exit_code: LinuxCliExitCode::Unavailable,
                ..LinuxCliResponse::success(command)
                    .with_platform(platform_status)
                    .with_mitm_status(mitm_status)
                    .with_browser_capture(report)
                    .with_diagnostics(diagnostics)
            }
        }
    }
}

pub fn handle_mitm_browser_capture_verify<P>(
    platform: &P,
    target_url: Option<&str>,
    confirm: bool,
) -> LinuxCliResponse
where
    P: PlatformCapabilityService,
{
    handle_mitm_browser_capture_verify_with_proxy_scheme(
        platform,
        target_url,
        MITM_BROWSER_CAPTURE_DEFAULT_PROXY_SCHEME,
        confirm,
    )
}

pub fn handle_mitm_browser_capture_verify_with_proxy_scheme<P>(
    platform: &P,
    target_url: Option<&str>,
    proxy_scheme: &str,
    confirm: bool,
) -> LinuxCliResponse
where
    P: PlatformCapabilityService,
{
    handle_mitm_browser_capture_inner(
        "mitm browser-capture verify",
        platform,
        LinuxBrowserCaptureAction::Verify,
        confirm,
        None,
        target_url,
        None,
        None,
        Some(proxy_scheme),
    )
}

pub fn handle_mitm_browser_capture_verify_with_probe<P, V>(
    platform: &P,
    endpoint_probe: &V,
    target_url: Option<&str>,
    confirm: bool,
) -> LinuxCliResponse
where
    P: PlatformCapabilityService,
    V: BrowserCaptureEndpointProbe,
{
    handle_mitm_browser_capture_verify_with_probe_and_proxy_scheme(
        platform,
        endpoint_probe,
        target_url,
        MITM_BROWSER_CAPTURE_DEFAULT_PROXY_SCHEME,
        confirm,
    )
}

pub fn handle_mitm_browser_capture_verify_with_probe_and_proxy_scheme<P, V>(
    platform: &P,
    endpoint_probe: &V,
    target_url: Option<&str>,
    proxy_scheme: &str,
    confirm: bool,
) -> LinuxCliResponse
where
    P: PlatformCapabilityService,
    V: BrowserCaptureEndpointProbe,
{
    let command = "mitm browser-capture verify";
    let platform_status = match platform.status() {
        Ok(status) => status,
        Err(error) => {
            return domain_error_response(
                command,
                LinuxCliExitCode::GeneralFailure,
                error,
                SOURCE_CLI_MITM,
            );
        }
    };

    let (mitm_status, mut diagnostics) = match build_linux_mitm_status(&platform_status) {
        Ok(status) => status,
        Err(error) => {
            return domain_error_response(
                command,
                LinuxCliExitCode::GeneralFailure,
                error,
                SOURCE_CLI_MITM,
            );
        }
    };

    let authorization = BrowserCaptureAuthorization {
        confirmed: confirm,
        source: if confirm {
            "cli --confirm".to_string()
        } else {
            "missing --confirm".to_string()
        },
        scope: "linux browser capture local proxy endpoint verify".to_string(),
        gate: MITM_BROWSER_CAPTURE_GATE.to_string(),
    };
    let mut report = build_linux_browser_capture_report_with_proxy_scheme(
        LinuxBrowserCaptureAction::Verify,
        &platform_status,
        &mitm_status.policy,
        Some(authorization),
        None,
        target_url,
        None,
        None,
        proxy_scheme,
    );
    let verify_request = report
        .request
        .verify
        .clone()
        .expect("verify action should build a verify request");

    if !confirm {
        diagnostics.push(cli_diagnostic(
            DiagnosticSeverity::Error,
            CLI_MITM_BROWSER_CAPTURE_VERIFY_AUTHORIZATION_REQUIRED_CODE,
            "browser capture verify requires --confirm before probing the planned local proxy endpoint",
            SOURCE_CLI_MITM,
        ));
        report.verify_report = Some(build_linux_browser_capture_verify_report(
            "authorization_required",
            false,
            verify_request,
            &mitm_status.policy,
            report.plan.blocked_operations.clone(),
        ));
        return LinuxCliResponse {
            ok: false,
            exit_code: LinuxCliExitCode::Unavailable,
            ..LinuxCliResponse::success(command)
                .with_platform(platform_status)
                .with_mitm_status(mitm_status)
                .with_browser_capture(report)
                .with_diagnostics(diagnostics)
        };
    }

    match endpoint_probe.verify_proxy_endpoint(&verify_request) {
        Ok(outcome) => {
            diagnostics.extend(outcome.diagnostics);
            let status = if verify_request.target_url.is_some() {
                "target_reachable"
            } else {
                "proxy_reachable"
            };
            report.verify_report = Some(build_linux_browser_capture_verify_report(
                status,
                true,
                verify_request,
                &mitm_status.policy,
                report.plan.blocked_operations.clone(),
            ));
            LinuxCliResponse::success(command)
                .with_platform(platform_status)
                .with_mitm_status(mitm_status)
                .with_browser_capture(report)
                .with_diagnostics(diagnostics)
        }
        Err(error) => {
            let status = if error.code == CLI_MITM_BROWSER_CAPTURE_VERIFY_TARGET_INVALID_CODE {
                "target_invalid"
            } else {
                "proxy_unreachable"
            };
            diagnostics.push(cli_diagnostic(
                DiagnosticSeverity::Error,
                error.code,
                error.message,
                SOURCE_CLI_MITM,
            ));
            report.verify_report = Some(build_linux_browser_capture_verify_report(
                status,
                false,
                verify_request,
                &mitm_status.policy,
                report.plan.blocked_operations.clone(),
            ));
            LinuxCliResponse {
                ok: false,
                exit_code: LinuxCliExitCode::Unavailable,
                ..LinuxCliResponse::success(command)
                    .with_platform(platform_status)
                    .with_mitm_status(mitm_status)
                    .with_browser_capture(report)
                    .with_diagnostics(diagnostics)
            }
        }
    }
}

pub fn handle_mitm_browser_capture_traffic_proof<P>(
    platform: &P,
    target_url: Option<&str>,
    proof_token: Option<&str>,
    proof_log_path: Option<&str>,
    confirm: bool,
) -> LinuxCliResponse
where
    P: PlatformCapabilityService,
{
    handle_mitm_browser_capture_traffic_proof_with_proxy_scheme(
        platform,
        target_url,
        proof_token,
        proof_log_path,
        MITM_BROWSER_CAPTURE_DEFAULT_PROXY_SCHEME,
        confirm,
    )
}

pub fn handle_mitm_browser_capture_traffic_proof_with_proxy_scheme<P>(
    platform: &P,
    target_url: Option<&str>,
    proof_token: Option<&str>,
    proof_log_path: Option<&str>,
    proxy_scheme: &str,
    confirm: bool,
) -> LinuxCliResponse
where
    P: PlatformCapabilityService,
{
    handle_mitm_browser_capture_inner(
        "mitm browser-capture traffic-proof",
        platform,
        LinuxBrowserCaptureAction::TrafficProof,
        confirm,
        None,
        target_url,
        proof_token,
        proof_log_path,
        Some(proxy_scheme),
    )
}

pub fn handle_mitm_browser_capture_traffic_proof_with_probe<P, T>(
    platform: &P,
    traffic_proof_probe: &T,
    target_url: Option<&str>,
    proof_token: Option<&str>,
    proof_log_path: Option<&str>,
    confirm: bool,
) -> LinuxCliResponse
where
    P: PlatformCapabilityService,
    T: BrowserCaptureTrafficProofProbe,
{
    handle_mitm_browser_capture_traffic_proof_with_probe_and_proxy_scheme(
        platform,
        traffic_proof_probe,
        target_url,
        proof_token,
        proof_log_path,
        MITM_BROWSER_CAPTURE_DEFAULT_PROXY_SCHEME,
        confirm,
    )
}

pub fn handle_mitm_browser_capture_traffic_proof_with_probe_and_proxy_scheme<P, T>(
    platform: &P,
    traffic_proof_probe: &T,
    target_url: Option<&str>,
    proof_token: Option<&str>,
    proof_log_path: Option<&str>,
    proxy_scheme: &str,
    confirm: bool,
) -> LinuxCliResponse
where
    P: PlatformCapabilityService,
    T: BrowserCaptureTrafficProofProbe,
{
    let command = "mitm browser-capture traffic-proof";
    let platform_status = match platform.status() {
        Ok(status) => status,
        Err(error) => {
            return domain_error_response(
                command,
                LinuxCliExitCode::GeneralFailure,
                error,
                SOURCE_CLI_MITM,
            );
        }
    };

    let (mitm_status, mut diagnostics) = match build_linux_mitm_status(&platform_status) {
        Ok(status) => status,
        Err(error) => {
            return domain_error_response(
                command,
                LinuxCliExitCode::GeneralFailure,
                error,
                SOURCE_CLI_MITM,
            );
        }
    };

    let authorization = BrowserCaptureAuthorization {
        confirmed: confirm,
        source: if confirm {
            "cli --confirm".to_string()
        } else {
            "missing --confirm".to_string()
        },
        scope: "linux browser capture traffic proof".to_string(),
        gate: MITM_BROWSER_CAPTURE_GATE.to_string(),
    };
    let mut report = build_linux_browser_capture_report_with_proxy_scheme(
        LinuxBrowserCaptureAction::TrafficProof,
        &platform_status,
        &mitm_status.policy,
        Some(authorization),
        None,
        target_url,
        proof_token,
        proof_log_path,
        proxy_scheme,
    );
    let proof_request = report
        .request
        .traffic_proof
        .clone()
        .expect("traffic-proof action should build a traffic proof request");

    if !confirm {
        diagnostics.push(cli_diagnostic(
            DiagnosticSeverity::Error,
            CLI_MITM_BROWSER_CAPTURE_TRAFFIC_PROOF_AUTHORIZATION_REQUIRED_CODE,
            "browser capture traffic proof requires --confirm before reading proof evidence",
            SOURCE_CLI_MITM,
        ));
        report.traffic_proof_report = Some(build_linux_browser_capture_traffic_proof_report(
            "authorization_required",
            false,
            proof_request,
            &mitm_status.policy,
            report.plan.blocked_operations.clone(),
        ));
        return LinuxCliResponse {
            ok: false,
            exit_code: LinuxCliExitCode::Unavailable,
            ..LinuxCliResponse::success(command)
                .with_platform(platform_status)
                .with_mitm_status(mitm_status)
                .with_browser_capture(report)
                .with_diagnostics(diagnostics)
        };
    }

    match traffic_proof_probe.verify_traffic_proof(&proof_request) {
        Ok(outcome) => {
            diagnostics.extend(outcome.diagnostics);
            report.traffic_proof_report = Some(build_linux_browser_capture_traffic_proof_report(
                "observed",
                true,
                proof_request,
                &mitm_status.policy,
                report.plan.blocked_operations.clone(),
            ));
            LinuxCliResponse::success(command)
                .with_platform(platform_status)
                .with_mitm_status(mitm_status)
                .with_browser_capture(report)
                .with_diagnostics(diagnostics)
        }
        Err(error) => {
            let status = if error.code == CLI_MITM_BROWSER_CAPTURE_TRAFFIC_PROOF_MISSING_CODE {
                "missing"
            } else if error.code == CLI_MITM_BROWSER_CAPTURE_TRAFFIC_PROOF_LOG_UNREADABLE_CODE {
                "log_unreadable"
            } else if error.code == CLI_MITM_BROWSER_CAPTURE_TRAFFIC_PROOF_BINDING_MISMATCH_CODE {
                "binding_mismatch"
            } else {
                "blocked"
            };
            diagnostics.push(cli_diagnostic(
                DiagnosticSeverity::Error,
                error.code,
                error.message,
                SOURCE_CLI_MITM,
            ));
            report.traffic_proof_report = Some(build_linux_browser_capture_traffic_proof_report(
                status,
                false,
                proof_request,
                &mitm_status.policy,
                report.plan.blocked_operations.clone(),
            ));
            LinuxCliResponse {
                ok: false,
                exit_code: LinuxCliExitCode::Unavailable,
                ..LinuxCliResponse::success(command)
                    .with_platform(platform_status)
                    .with_mitm_status(mitm_status)
                    .with_browser_capture(report)
                    .with_diagnostics(diagnostics)
            }
        }
    }
}

pub fn handle_mitm_http_rewrite_plan<P>(platform: &P) -> LinuxCliResponse
where
    P: PlatformCapabilityService,
{
    let command = "mitm http-rewrite plan";
    let platform_status = match platform.status() {
        Ok(status) => status,
        Err(error) => {
            return domain_error_response(
                command,
                LinuxCliExitCode::GeneralFailure,
                error,
                SOURCE_CLI_MITM,
            );
        }
    };

    let (mitm_status, mut diagnostics) = match build_linux_mitm_status(&platform_status) {
        Ok(status) => status,
        Err(error) => {
            return domain_error_response(
                command,
                LinuxCliExitCode::GeneralFailure,
                error,
                SOURCE_CLI_MITM,
            );
        }
    };

    diagnostics.push(cli_diagnostic(
        DiagnosticSeverity::Info,
        CLI_MITM_HTTP_REWRITE_PLAN_READY_CODE,
        "plain HTTP rewrite data-plane is active for explicit HTTP proxy requests and explicit preview inputs",
        SOURCE_CLI_MITM,
    ));
    diagnostics.push(cli_diagnostic(
        DiagnosticSeverity::Warning,
        CLI_MITM_HTTP_REWRITE_TLS_BLOCKED_CODE,
        "TLS decryption and live HTTPS rewrite remain blocked until CA trust and TLS interception are active",
        SOURCE_CLI_MITM,
    ));
    let report = build_linux_mitm_http_rewrite_report("plan", None, None);

    LinuxCliResponse::success(command)
        .with_platform(platform_status)
        .with_mitm_status(mitm_status)
        .with_http_rewrite(report)
        .with_diagnostics(diagnostics)
}

#[allow(clippy::too_many_arguments)]
pub fn handle_mitm_http_rewrite_preview<P>(
    platform: &P,
    plugin_path: Option<&str>,
    url: Option<&str>,
    method: &str,
    phase: &str,
    status_code: Option<u16>,
    raw_headers: &[String],
    body: Option<&str>,
    confirm: bool,
) -> LinuxCliResponse
where
    P: PlatformCapabilityService,
{
    let command = "mitm http-rewrite preview";
    let platform_status = match platform.status() {
        Ok(status) => status,
        Err(error) => {
            return domain_error_response(
                command,
                LinuxCliExitCode::GeneralFailure,
                error,
                SOURCE_CLI_MITM,
            );
        }
    };
    let plugin = match plugin_path.map(read_user_mitm_plugin).transpose() {
        Ok(plugin) => plugin,
        Err(error) => {
            return domain_error_response(
                command,
                LinuxCliExitCode::ArgumentOrConfig,
                error,
                SOURCE_CLI_MITM,
            );
        }
    };

    let (mitm_status, mut diagnostics) =
        match build_linux_mitm_status_with_plugin(&platform_status, plugin.as_ref()) {
            Ok(status) => status,
            Err(error) => {
                return domain_error_response(
                    command,
                    LinuxCliExitCode::GeneralFailure,
                    error,
                    SOURCE_CLI_MITM,
                );
            }
        };

    let authorization = LinuxMitmHttpRewriteAuthorization {
        confirmed: confirm,
        source: if confirm {
            "cli --confirm".to_string()
        } else {
            "missing --confirm".to_string()
        },
        scope: "linux plain HTTP rewrite preview".to_string(),
        gate: MITM_HTTP_TLS_DATA_PLANE_GATE.to_string(),
    };
    let parsed_headers = match parse_http_rewrite_header_values(raw_headers) {
        Ok(headers) => headers,
        Err(diagnostic) => {
            diagnostics.push(diagnostic);
            let report = build_linux_mitm_http_rewrite_report(
                "preview",
                Some(build_linux_mitm_http_rewrite_request(
                    url,
                    method,
                    phase,
                    status_code,
                    Vec::new(),
                    body,
                    Some(authorization),
                )),
                None,
            );
            return LinuxCliResponse {
                ok: false,
                exit_code: LinuxCliExitCode::ArgumentOrConfig,
                ..LinuxCliResponse::success(command)
                    .with_platform(platform_status)
                    .with_mitm_status(mitm_status)
                    .with_http_rewrite(report)
                    .with_diagnostics(diagnostics)
            };
        }
    };
    let request = build_linux_mitm_http_rewrite_request(
        url,
        method,
        phase,
        status_code,
        parsed_headers.clone(),
        body,
        Some(authorization.clone()),
    );

    if !confirm {
        diagnostics.push(cli_diagnostic(
            DiagnosticSeverity::Error,
            CLI_MITM_HTTP_REWRITE_AUTHORIZATION_REQUIRED_CODE,
            "plain HTTP rewrite preview requires --confirm before applying a plugin outcome to caller-provided input",
            SOURCE_CLI_MITM,
        ));
        let report = build_linux_mitm_http_rewrite_report("preview", Some(request), None);
        return LinuxCliResponse {
            ok: false,
            exit_code: LinuxCliExitCode::Unavailable,
            ..LinuxCliResponse::success(command)
                .with_platform(platform_status)
                .with_mitm_status(mitm_status)
                .with_http_rewrite(report)
                .with_diagnostics(diagnostics)
        };
    }

    let Some(url) = url else {
        diagnostics.push(cli_diagnostic(
            DiagnosticSeverity::Error,
            CLI_MITM_HTTP_REWRITE_CONFIG_MISSING_CODE,
            "plain HTTP rewrite preview requires --url <url>",
            SOURCE_CLI_MITM,
        ));
        let report = build_linux_mitm_http_rewrite_report("preview", Some(request), None);
        return LinuxCliResponse {
            ok: false,
            exit_code: LinuxCliExitCode::ArgumentOrConfig,
            ..LinuxCliResponse::success(command)
                .with_platform(platform_status)
                .with_mitm_status(mitm_status)
                .with_http_rewrite(report)
                .with_diagnostics(diagnostics)
        };
    };

    let Some(package) = plugin else {
        diagnostics.push(cli_diagnostic(
            DiagnosticSeverity::Error,
            CLI_MITM_HTTP_REWRITE_PLUGIN_MISSING_CODE,
            "plain HTTP rewrite preview requires --mitm-plugin <path>: NetworkCore ships no MITM plugin of its own",
            SOURCE_CLI_MITM,
        ));
        let report = build_linux_mitm_http_rewrite_report("preview", Some(request), None);
        return LinuxCliResponse {
            ok: false,
            exit_code: LinuxCliExitCode::ArgumentOrConfig,
            ..LinuxCliResponse::success(command)
                .with_platform(platform_status)
                .with_mitm_status(mitm_status)
                .with_http_rewrite(report)
                .with_diagnostics(diagnostics)
        };
    };
    let service = AnixOpsMitmPluginService::new();
    let instance = match service.load(
        &package,
        &GrantedPermissions {
            permissions: package.manifest.permissions.clone(),
        },
    ) {
        Ok(instance) => instance,
        Err(error) => {
            return domain_error_response(
                command,
                LinuxCliExitCode::GeneralFailure,
                error,
                SOURCE_CLI_MITM,
            );
        }
    };
    let message = engine_native::NativePlainHttpMessage {
        request_id: "linux-cli-http-rewrite-preview".to_string(),
        url: url.to_string(),
        method: Some(method.to_string()),
        phase: http_rewrite_phase_from_name(phase),
        status_code,
        headers: parsed_headers,
        body: body.unwrap_or_default().as_bytes().to_vec(),
        request_headers: Vec::new(),
        request_body: None,
    };
    let native_report =
        engine_native::plan_and_apply_plain_http_mitm(&message, &instance, &service);
    diagnostics.extend(native_report.diagnostics.clone());
    diagnostics.push(cli_diagnostic(
        DiagnosticSeverity::Info,
        CLI_MITM_HTTP_REWRITE_APPLY_READY_CODE,
        "plain HTTP rewrite preview applied the plugin outcome to caller-provided input; explicit HTTP proxy live traffic uses the native plain HTTP data plane",
        SOURCE_CLI_MITM,
    ));
    diagnostics.push(cli_diagnostic(
        DiagnosticSeverity::Warning,
        CLI_MITM_HTTP_REWRITE_TLS_BLOCKED_CODE,
        "TLS decryption and live HTTPS rewrite remain blocked until CA trust and TLS interception are active",
        SOURCE_CLI_MITM,
    ));
    let outcome = build_linux_mitm_http_rewrite_outcome_report(&native_report);
    let report = build_linux_mitm_http_rewrite_report("preview", Some(request), Some(outcome));

    LinuxCliResponse::success(command)
        .with_platform(platform_status)
        .with_mitm_status(mitm_status)
        .with_http_rewrite(report)
        .with_diagnostics(diagnostics)
}

pub(crate) fn build_linux_mitm_http_rewrite_report(
    action: &str,
    request: Option<LinuxMitmHttpRewriteRequest>,
    outcome: Option<LinuxMitmHttpRewriteOutcomeReport>,
) -> LinuxMitmHttpRewriteReport {
    LinuxMitmHttpRewriteReport {
        action: action.to_string(),
        source_contract_status: MITM_HTTP_REWRITE_SOURCE_CONTRACT_STATUS.to_string(),
        gate: MITM_HTTP_TLS_DATA_PLANE_GATE.to_string(),
        gate_status: MITM_HTTP_TLS_DATA_PLANE_GATE_STATUS.to_string(),
        mutation_ready: MITM_HTTP_REWRITE_MUTATION_READY,
        live_traffic_ready: MITM_HTTP_REWRITE_LIVE_TRAFFIC_READY,
        tls_decryption_ready: MITM_HTTP_REWRITE_TLS_DECRYPTION_READY,
        controlled_tls_termination_plan_ready:
            MITM_HTTP_REWRITE_CONTROLLED_TLS_TERMINATION_PLAN_READY,
        downstream_tls_termination_plan_ready:
            MITM_HTTP_REWRITE_DOWNSTREAM_TLS_TERMINATION_PLAN_READY,
        upstream_tls_forwarding_ready: MITM_HTTP_REWRITE_UPSTREAM_TLS_FORWARDING_READY,
        https_request_rewrite_preview_ready: MITM_HTTP_REWRITE_HTTPS_REQUEST_REWRITE_PREVIEW_READY,
        https_response_rewrite_preview_ready:
            MITM_HTTP_REWRITE_HTTPS_RESPONSE_REWRITE_PREVIEW_READY,
        https_response_rewrite_ready: MITM_HTTP_REWRITE_HTTPS_RESPONSE_REWRITE_READY,
        script_dispatch_ready: MITM_HTTP_REWRITE_SCRIPT_DISPATCH_READY,
        certificate_pinning_bypass_supported:
            MITM_HTTP_REWRITE_CERTIFICATE_PINNING_BYPASS_SUPPORTED,
        http2_mitm_supported: MITM_HTTP_REWRITE_HTTP2_MITM_SUPPORTED,
        http3_quic_mitm_supported: MITM_HTTP_REWRITE_HTTP3_QUIC_MITM_SUPPORTED,
        request: request.unwrap_or_else(|| {
            build_linux_mitm_http_rewrite_request(
                None,
                MITM_HTTP_REWRITE_DEFAULT_METHOD,
                MITM_HTTP_REWRITE_DEFAULT_PHASE,
                None,
                Vec::new(),
                None,
                None,
            )
        }),
        outcome,
        blocked_operations: linux_mitm_http_rewrite_blocked_operations(),
    }
}

pub(crate) fn build_linux_mitm_http_rewrite_request(
    url: Option<&str>,
    method: &str,
    phase: &str,
    status_code: Option<u16>,
    headers: Vec<MetadataEntry>,
    body: Option<&str>,
    authorization: Option<LinuxMitmHttpRewriteAuthorization>,
) -> LinuxMitmHttpRewriteRequest {
    LinuxMitmHttpRewriteRequest {
        url: url.map(ToString::to_string),
        method: method.to_string(),
        phase: phase.to_string(),
        status_code,
        headers: headers
            .iter()
            .map(linux_mitm_http_header_from_metadata)
            .collect(),
        body: body.map(ToString::to_string),
        authorization,
    }
}

pub(crate) fn build_linux_mitm_http_rewrite_outcome_report(
    report: &engine_native::NativePlainHttpRewriteReport,
) -> LinuxMitmHttpRewriteOutcomeReport {
    let outcome = report.outcome.as_ref();
    LinuxMitmHttpRewriteOutcomeReport {
        planned: outcome.is_some(),
        applied: report.applied,
        action: outcome
            .map(|outcome| http_mitm_action_name(&outcome.action))
            .unwrap_or_else(|| "failed".to_string()),
        terminal_action: report.terminal_action.clone(),
        final_status_code: report.final_status_code,
        redirect_location: report.redirect_location.clone(),
        header_mutation_count: outcome
            .map(|outcome| outcome.header_mutations.len())
            .unwrap_or_default(),
        body_mutated: outcome
            .and_then(|outcome| outcome.body_mutation.as_ref())
            .is_some(),
        script_dispatch_deferred: report.script_dispatch_deferred,
        script_dispatch_failed: report.script_dispatch_failed,
        output_headers: report
            .headers
            .iter()
            .map(linux_mitm_http_header_from_metadata)
            .collect(),
        output_body: Some(String::from_utf8_lossy(&report.body).to_string()),
    }
}

pub(crate) fn parse_http_rewrite_header_values(
    values: &[String],
) -> Result<Vec<MetadataEntry>, Diagnostic> {
    values
        .iter()
        .map(|value| {
            let Some((name, header_value)) = value.split_once(':') else {
                return Err(cli_diagnostic(
                    DiagnosticSeverity::Error,
                    CLI_ARGUMENT_VALUE_MISSING_CODE,
                    "--header must use Name: Value format",
                    SOURCE_CLI_ARGUMENT,
                ));
            };
            let name = name.trim();
            if name.is_empty() {
                return Err(cli_diagnostic(
                    DiagnosticSeverity::Error,
                    CLI_ARGUMENT_VALUE_MISSING_CODE,
                    "--header name must not be empty",
                    SOURCE_CLI_ARGUMENT,
                ));
            }
            Ok(MetadataEntry {
                key: name.to_string(),
                value: header_value.trim().to_string(),
            })
        })
        .collect()
}

pub(crate) fn linux_mitm_http_header_from_metadata(header: &MetadataEntry) -> LinuxMitmHttpHeader {
    LinuxMitmHttpHeader {
        name: header.key.clone(),
        value: header.value.clone(),
    }
}

pub(crate) fn http_rewrite_phase_from_name(phase: &str) -> HttpMitmPhase {
    if phase.eq_ignore_ascii_case("response") {
        HttpMitmPhase::Response
    } else {
        HttpMitmPhase::Request
    }
}

pub(crate) fn http_mitm_action_name(action: &HttpMitmAction) -> String {
    match action {
        HttpMitmAction::Continue => "continue",
        HttpMitmAction::Redirect { .. } => "redirect",
        HttpMitmAction::Reject { .. } => "reject",
        HttpMitmAction::Respond { .. } => "respond",
    }
    .to_string()
}

pub(crate) fn linux_mitm_http_rewrite_blocked_operations() -> Vec<String> {
    [
        "decrypt-https",
        "terminate-tls",
        "install-ca",
        "trust-ca",
        "mutate-live-https-traffic",
        "bypass-certificate-pinning",
        "intercept-http2",
        "intercept-http3-quic",
        "mutate-browser-or-system-capture",
        "mutate-system-proxy",
        "mutate-system-pac",
        "mutate-tun",
        "mutate-dns",
        "mutate-firewall",
    ]
    .iter()
    .map(|operation| (*operation).to_string())
    .collect()
}

pub(crate) fn handle_mitm_status_inner<P>(command: &'static str, platform: &P) -> LinuxCliResponse
where
    P: PlatformCapabilityService,
{
    let platform_status = match platform.status() {
        Ok(status) => status,
        Err(error) => {
            return domain_error_response(
                command,
                LinuxCliExitCode::GeneralFailure,
                error,
                SOURCE_CLI_MITM,
            );
        }
    };

    match build_linux_mitm_status(&platform_status) {
        Ok((status, diagnostics)) => LinuxCliResponse::success(command)
            .with_platform(platform_status)
            .with_mitm_status(status)
            .with_diagnostics(diagnostics),
        Err(error) => domain_error_response(
            command,
            LinuxCliExitCode::GeneralFailure,
            error,
            SOURCE_CLI_MITM,
        ),
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn handle_mitm_browser_capture_inner<P>(
    command: &'static str,
    platform: &P,
    action: LinuxBrowserCaptureAction,
    confirm: bool,
    snapshot_path: Option<String>,
    target_url: Option<&str>,
    traffic_proof_token: Option<&str>,
    traffic_proof_log_path: Option<&str>,
    proxy_scheme: Option<&str>,
) -> LinuxCliResponse
where
    P: PlatformCapabilityService,
{
    let platform_status = match platform.status() {
        Ok(status) => status,
        Err(error) => {
            return domain_error_response(
                command,
                LinuxCliExitCode::GeneralFailure,
                error,
                SOURCE_CLI_MITM,
            );
        }
    };

    let (mitm_status, mut diagnostics) = match build_linux_mitm_status(&platform_status) {
        Ok(status) => status,
        Err(error) => {
            return domain_error_response(
                command,
                LinuxCliExitCode::GeneralFailure,
                error,
                SOURCE_CLI_MITM,
            );
        }
    };

    let authorization = match action {
        LinuxBrowserCaptureAction::Apply => Some(BrowserCaptureAuthorization {
            confirmed: confirm,
            source: if confirm {
                "cli --confirm".to_string()
            } else {
                "missing --confirm".to_string()
            },
            scope: "linux explicit browser proxy capture".to_string(),
            gate: MITM_BROWSER_CAPTURE_GATE.to_string(),
        }),
        LinuxBrowserCaptureAction::Verify => Some(BrowserCaptureAuthorization {
            confirmed: confirm,
            source: if confirm {
                "cli --confirm".to_string()
            } else {
                "missing --confirm".to_string()
            },
            scope: "linux browser capture local proxy endpoint verify".to_string(),
            gate: MITM_BROWSER_CAPTURE_GATE.to_string(),
        }),
        LinuxBrowserCaptureAction::TrafficProof => Some(BrowserCaptureAuthorization {
            confirmed: confirm,
            source: if confirm {
                "cli --confirm".to_string()
            } else {
                "missing --confirm".to_string()
            },
            scope: "linux browser capture traffic proof".to_string(),
            gate: MITM_BROWSER_CAPTURE_GATE.to_string(),
        }),
        _ => None,
    };
    let rollback_snapshot = snapshot_path.map(|path| BrowserCaptureRollbackSnapshot {
        path,
        status: "operator-provided".to_string(),
    });

    match action {
        LinuxBrowserCaptureAction::Plan => {}
        LinuxBrowserCaptureAction::LaunchPlan => {
            diagnostics.push(cli_diagnostic(
                DiagnosticSeverity::Info,
                CLI_MITM_BROWSER_CAPTURE_LAUNCH_PLAN_READY_CODE,
                "browser capture manual launch plan is available; no browser or system state was changed",
                SOURCE_CLI_MITM,
            ));
        }
        LinuxBrowserCaptureAction::SessionPlan => {
            diagnostics.push(cli_diagnostic(
                DiagnosticSeverity::Error,
                CLI_MITM_BROWSER_CAPTURE_SESSION_PLAN_CONFIG_FAILED_CODE,
                "browser capture session-plan requires a subscription URL and the dedicated session-plan handler",
                SOURCE_CLI_MITM,
            ));
        }
        LinuxBrowserCaptureAction::Launch => {}
        LinuxBrowserCaptureAction::Apply => {
            if !confirm {
                diagnostics.push(cli_diagnostic(
                    DiagnosticSeverity::Error,
                    CLI_MITM_BROWSER_CAPTURE_AUTHORIZATION_REQUIRED_CODE,
                    "browser capture apply requires --confirm; no browser or system state was changed",
                    SOURCE_CLI_MITM,
                ));
            }
            diagnostics.push(cli_diagnostic(
                DiagnosticSeverity::Error,
                CLI_MITM_BROWSER_CAPTURE_APPLY_BLOCKED_CODE,
                "browser capture apply is blocked until certificate lifecycle, HTTP/TLS data plane, and rollback snapshot support are active",
                SOURCE_CLI_MITM,
            ));
        }
        LinuxBrowserCaptureAction::Rollback => {
            diagnostics.push(cli_diagnostic(
                DiagnosticSeverity::Error,
                CLI_MITM_BROWSER_CAPTURE_ROLLBACK_BLOCKED_CODE,
                "browser capture rollback is blocked until a NetworkCore-created rollback snapshot exists",
                SOURCE_CLI_MITM,
            ));
        }
        LinuxBrowserCaptureAction::Verify => {
            if !confirm {
                diagnostics.push(cli_diagnostic(
                    DiagnosticSeverity::Error,
                    CLI_MITM_BROWSER_CAPTURE_VERIFY_AUTHORIZATION_REQUIRED_CODE,
                    "browser capture verify requires --confirm before probing the planned local proxy endpoint",
                    SOURCE_CLI_MITM,
                ));
            }
            diagnostics.push(cli_diagnostic(
                DiagnosticSeverity::Error,
                CLI_MITM_BROWSER_CAPTURE_VERIFY_BLOCKED_CODE,
                "browser capture verify endpoint probing is blocked because no BrowserCaptureEndpointProbe is wired",
                SOURCE_CLI_MITM,
            ));
        }
        LinuxBrowserCaptureAction::TrafficProof => {
            if !confirm {
                diagnostics.push(cli_diagnostic(
                    DiagnosticSeverity::Error,
                    CLI_MITM_BROWSER_CAPTURE_TRAFFIC_PROOF_AUTHORIZATION_REQUIRED_CODE,
                    "browser capture traffic proof requires --confirm before reading proof evidence",
                    SOURCE_CLI_MITM,
                ));
            }
            diagnostics.push(cli_diagnostic(
                DiagnosticSeverity::Error,
                CLI_MITM_BROWSER_CAPTURE_TRAFFIC_PROOF_BLOCKED_CODE,
                "browser capture traffic proof is blocked because no BrowserCaptureTrafficProofProbe is wired",
                SOURCE_CLI_MITM,
            ));
        }
    }

    let report = build_linux_browser_capture_report_with_proxy_scheme(
        action,
        &platform_status,
        &mitm_status.policy,
        authorization,
        rollback_snapshot,
        target_url,
        traffic_proof_token,
        traffic_proof_log_path,
        proxy_scheme.unwrap_or(MITM_BROWSER_CAPTURE_DEFAULT_PROXY_SCHEME),
    );
    let mut response = LinuxCliResponse::success(command)
        .with_platform(platform_status)
        .with_mitm_status(mitm_status)
        .with_browser_capture(report)
        .with_diagnostics(diagnostics);

    if !matches!(
        action,
        LinuxBrowserCaptureAction::Plan | LinuxBrowserCaptureAction::LaunchPlan
    ) {
        response.ok = false;
        response.exit_code = LinuxCliExitCode::Unavailable;
    }

    response
}

/// MITM status for the commands that take no plugin: the policy engine with
/// nothing loaded, since NetworkCore ships no plugin (docs/no-presets.md).
pub(crate) fn build_linux_mitm_status(
    platform_status: &PlatformCapabilityStatus,
) -> DomainResult<(LinuxMitmStatus, Vec<Diagnostic>)> {
    build_linux_mitm_status_with_plugin(platform_status, None)
}

pub(crate) fn build_linux_mitm_status_with_plugin(
    platform_status: &PlatformCapabilityStatus,
    plugin: Option<&PluginPackage>,
) -> DomainResult<(LinuxMitmStatus, Vec<Diagnostic>)> {
    let mut diagnostics = platform_diagnostics(platform_status);
    let policy = match plugin {
        Some(package) => {
            let mut engine = AnixOpsMitmPolicyEngine::new()?;
            let report = engine.load_config(&package.source)?;
            let service = AnixOpsMitmPluginService::new();
            let instance = service.load(
                package,
                &GrantedPermissions {
                    permissions: package.manifest.permissions.clone(),
                },
            )?;
            diagnostics.extend(report.diagnostics.clone());
            diagnostics.push(cli_diagnostic(
                DiagnosticSeverity::Info,
                CLI_MITM_POLICY_READY_CODE,
                "mitm policy engine loaded your MITM plugin",
                SOURCE_CLI_MITM,
            ));
            LinuxMitmPolicyStatus {
                engine: "mitm_anixops".to_string(),
                engine_version: report.version,
                plugin_id: instance.manifest.id,
                plugin_version: instance.manifest.version,
                plugin_loaded: true,
                mitm_pattern_count: report.mitm_pattern_count,
                rewrite_rule_count: report.rewrite_rule_count,
                script_rule_count: report.script_rule_count,
                argument_count: report.argument_count,
            }
        }
        None => {
            diagnostics.push(cli_diagnostic(
                DiagnosticSeverity::Info,
                CLI_MITM_POLICY_READY_CODE,
                "mitm policy engine is ready with no plugin loaded: NetworkCore ships none; load your own with --mitm-plugin <path>",
                SOURCE_CLI_MITM,
            ));
            LinuxMitmPolicyStatus {
                engine: "mitm_anixops".to_string(),
                engine_version: mitm_policy::engine_version().to_string(),
                plugin_id: String::new(),
                plugin_version: String::new(),
                plugin_loaded: false,
                mitm_pattern_count: 0,
                rewrite_rule_count: 0,
                script_rule_count: 0,
                argument_count: 0,
            }
        }
    };
    diagnostics.push(cli_diagnostic(
        DiagnosticSeverity::Info,
        CLI_MITM_CLI_GATE_PARTIAL_CODE,
        "MITM_CLI_COMMAND_GATE is partially active for status, diagnostics, certificate plan, browser plan, and browser capture reports",
        SOURCE_CLI_MITM,
    ));
    diagnostics.push(cli_diagnostic(
        DiagnosticSeverity::Info,
        CLI_MITM_CERTIFICATE_PLAN_READY_CODE,
        "MITM certificate lifecycle plan is available for artifact apply and rollback inspection",
        SOURCE_CLI_MITM,
    ));
    diagnostics.push(cli_diagnostic(
        DiagnosticSeverity::Warning,
        CLI_MITM_CERTIFICATE_GATE_DEFERRED_CODE,
        "MITM_CERTIFICATE_LIFECYCLE_GATE allows NetworkCore-owned artifact apply/rollback, while system trust-store mutation remains blocked",
        SOURCE_CLI_MITM,
    ));
    diagnostics.push(cli_diagnostic(
        DiagnosticSeverity::Warning,
        CLI_MITM_CERTIFICATE_MUTATION_BLOCKED_CODE,
        "MITM certificate trust mutation is blocked; the CLI does not install, trust, revoke, or mutate system trust store state",
        SOURCE_CLI_MITM,
    ));
    diagnostics.push(cli_diagnostic(
        DiagnosticSeverity::Warning,
        CLI_MITM_DATA_PLANE_GATE_DEFERRED_CODE,
        "MITM_HTTP_TLS_DATA_PLANE_GATE allows explicit plain HTTP live data-plane rewrite, while TLS decryption and live HTTPS mutation remain blocked",
        SOURCE_CLI_MITM,
    ));
    diagnostics.push(cli_diagnostic(
        DiagnosticSeverity::Info,
        CLI_MITM_BROWSER_PLAN_READY_CODE,
        "MITM browser capture plan is available for CLI inspection",
        SOURCE_CLI_MITM,
    ));
    diagnostics.push(cli_diagnostic(
        DiagnosticSeverity::Warning,
        CLI_MITM_BROWSER_CAPTURE_MUTATION_BLOCKED_CODE,
        "MITM browser capture system mutation is blocked; the CLI only writes operator-provided NetworkCore PAC and browser policy artifacts and does not install browser policy, system proxy, system PAC, TUN, DNS, or firewall state",
        SOURCE_CLI_MITM,
    ));
    diagnostics.push(cli_diagnostic(
        DiagnosticSeverity::Warning,
        CLI_MITM_BROWSER_HIJACK_DEFERRED_CODE,
        "browser hijack is deferred until certificate lifecycle, HTTP/TLS data plane, and browser capture gates are active",
        SOURCE_CLI_MITM,
    ));

    let status = LinuxMitmStatus {
        stage: MITM_USER_FACING_STAGE.to_string(),
        user_facing_ready: MITM_USER_FACING_READY,
        browser_hijack: MITM_BROWSER_HIJACK_STATUS.to_string(),
        platform_mitm_available: platform_status.mitm_available(),
        certificate_state: certificate_state_name(platform_status.mitm_certificate.state)
            .to_string(),
        certificate_plan: build_linux_mitm_certificate_plan(platform_status),
        browser_plan: build_linux_mitm_browser_plan(platform_status),
        policy,
        gates: vec![
            LinuxMitmGateStatus {
                gate: MITM_CLI_COMMAND_GATE.to_string(),
                status: MITM_CLI_COMMAND_GATE_STATUS.to_string(),
                reason: "MITM planning command surface is active".to_string(),
            },
            LinuxMitmGateStatus {
                gate: MITM_CERTIFICATE_LIFECYCLE_GATE.to_string(),
                status: MITM_CERTIFICATE_LIFECYCLE_GATE_STATUS.to_string(),
                reason: "certificate artifact apply and rollback are available; system trust-store mutation remains blocked".to_string(),
            },
            LinuxMitmGateStatus {
                gate: MITM_HTTP_TLS_DATA_PLANE_GATE.to_string(),
                status: MITM_HTTP_TLS_DATA_PLANE_GATE_STATUS.to_string(),
                reason: "explicit plain HTTP proxy live data plane and caller-provided preview are available; TLS decryption and live HTTPS mutation remain blocked".to_string(),
            },
            LinuxMitmGateStatus {
                gate: MITM_BROWSER_CAPTURE_GATE.to_string(),
                status: MITM_BROWSER_CAPTURE_GATE_STATUS.to_string(),
                reason: "browser capture PAC and browser policy artifact apply is available; proxy/browser/system mutation remains blocked".to_string(),
            },
        ],
    };

    Ok((status, diagnostics))
}

pub(crate) fn build_linux_mitm_browser_plan(
    platform_status: &PlatformCapabilityStatus,
) -> LinuxMitmBrowserPlan {
    let trust_satisfied = platform_status.mitm_certificate.is_trusted();

    LinuxMitmBrowserPlan {
        status: MITM_BROWSER_PLAN_STATUS.to_string(),
        mutation_ready: MITM_BROWSER_CAPTURE_MUTATION_READY,
        current_capture: "not_configured".to_string(),
        planned_capture_mode: MITM_BROWSER_CAPTURE_MODE.to_string(),
        planned_proxy_host: MITM_BROWSER_CAPTURE_PROXY_HOST.to_string(),
        planned_proxy_port: MITM_BROWSER_CAPTURE_PROXY_PORT,
        required_steps: vec![
            LinuxMitmBrowserPlanStep {
                id: "load-mitm-policy".to_string(),
                status: "active".to_string(),
                reason: "your own MITM plugin can be loaded with --mitm-plugin; none is built in".to_string(),
            },
            LinuxMitmBrowserPlanStep {
                id: "verify-certificate-trust".to_string(),
                status: certificate_trust_step_status(trust_satisfied).to_string(),
                reason: certificate_verify_step_reason(platform_status.mitm_certificate.state)
                    .to_string(),
            },
            LinuxMitmBrowserPlanStep {
                id: "start-http-tls-mitm-proxy".to_string(),
                status: "blocked".to_string(),
                reason: "HTTP/TLS MITM proxy data plane is not wired".to_string(),
            },
            LinuxMitmBrowserPlanStep {
                id: "write-networkcore-pac-artifact".to_string(),
                status: "active".to_string(),
                reason: "browser-capture apply can write an operator-provided NetworkCore PAC file and rollback snapshot".to_string(),
            },
            LinuxMitmBrowserPlanStep {
                id: "write-browser-policy-artifact".to_string(),
                status: "active".to_string(),
                reason: "browser-capture apply can write an operator-provided Chromium/Chrome managed proxy policy artifact and rollback snapshot".to_string(),
            },
            LinuxMitmBrowserPlanStep {
                id: "configure-browser-explicit-proxy".to_string(),
                status: "blocked".to_string(),
                reason: "browser policy installation and browser proxy configuration mutation are not implemented".to_string(),
            },
            LinuxMitmBrowserPlanStep {
                id: "verify-browser-traffic-capture".to_string(),
                status: "blocked".to_string(),
                reason: "no live browser traffic capture probe is available".to_string(),
            },
            LinuxMitmBrowserPlanStep {
                id: "rollback-browser-capture".to_string(),
                status: "blocked".to_string(),
                reason: "browser/system proxy mutation rollback is not implemented".to_string(),
            },
        ],
        blocked_operations: vec![
            "start-mitm-proxy".to_string(),
            "write-system-proxy".to_string(),
            "install-browser-policy".to_string(),
            "install-system-pac".to_string(),
            "configure-tun-capture".to_string(),
            "configure-dns-capture".to_string(),
            "configure-firewall-capture".to_string(),
            "verify-live-browser-capture".to_string(),
            "rollback-browser-capture".to_string(),
        ],
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn build_linux_browser_capture_report(
    action: LinuxBrowserCaptureAction,
    platform_status: &PlatformCapabilityStatus,
    policy: &LinuxMitmPolicyStatus,
    authorization: Option<BrowserCaptureAuthorization>,
    rollback_snapshot: Option<BrowserCaptureRollbackSnapshot>,
    target_url: Option<&str>,
    traffic_proof_token: Option<&str>,
    traffic_proof_log_path: Option<&str>,
) -> LinuxBrowserCaptureReport {
    build_linux_browser_capture_report_with_proxy_scheme(
        action,
        platform_status,
        policy,
        authorization,
        rollback_snapshot,
        target_url,
        traffic_proof_token,
        traffic_proof_log_path,
        MITM_BROWSER_CAPTURE_DEFAULT_PROXY_SCHEME,
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn build_linux_browser_capture_report_with_proxy_scheme(
    action: LinuxBrowserCaptureAction,
    platform_status: &PlatformCapabilityStatus,
    policy: &LinuxMitmPolicyStatus,
    authorization: Option<BrowserCaptureAuthorization>,
    rollback_snapshot: Option<BrowserCaptureRollbackSnapshot>,
    target_url: Option<&str>,
    traffic_proof_token: Option<&str>,
    traffic_proof_log_path: Option<&str>,
    proxy_scheme: &str,
) -> LinuxBrowserCaptureReport {
    let plan = build_linux_browser_capture_plan_with_proxy_scheme(
        platform_status,
        policy,
        MITM_BROWSER_CAPTURE_PROXY_HOST,
        MITM_BROWSER_CAPTURE_PROXY_PORT,
        proxy_scheme,
    );
    let verify_request = if action == LinuxBrowserCaptureAction::Verify {
        Some(build_linux_browser_capture_verify_request(
            &plan, target_url,
        ))
    } else {
        None
    };
    let traffic_proof_request = if action == LinuxBrowserCaptureAction::TrafficProof {
        Some(build_linux_browser_capture_traffic_proof_request(
            &plan,
            target_url,
            traffic_proof_token,
            traffic_proof_log_path,
        ))
    } else {
        None
    };
    let request = LinuxBrowserCaptureRequest {
        action,
        session: None,
        launch: None,
        pac: None,
        verify: verify_request.clone(),
        traffic_proof: traffic_proof_request.clone(),
        authorization: authorization.clone(),
        rollback_snapshot: rollback_snapshot.clone(),
    };
    let blocked_operations = plan.blocked_operations.clone();
    let apply_report = if action == LinuxBrowserCaptureAction::Apply {
        authorization.clone().map(|authorization| {
            let status = if authorization.confirmed {
                "blocked"
            } else {
                "authorization_required"
            };
            LinuxBrowserCaptureApplyReport {
                status: status.to_string(),
                applied: false,
                authorization,
                pac_file_path: None,
                pac_url: None,
                policy_file_path: None,
                policy_url: None,
                profile_prefs_file_path: None,
                rollback_snapshot: None,
                blocked_operations: blocked_operations.clone(),
            }
        })
    } else {
        None
    };
    let rollback_report = if action == LinuxBrowserCaptureAction::Rollback {
        Some(LinuxBrowserCaptureRollbackReport {
            status: "blocked".to_string(),
            rolled_back: false,
            pac_file_path: None,
            policy_file_path: None,
            profile_prefs_file_path: None,
            rollback_snapshot: rollback_snapshot.clone(),
            blocked_operations: blocked_operations.clone(),
        })
    } else {
        None
    };
    let verify_report = if action == LinuxBrowserCaptureAction::Verify {
        verify_request.map(|request| {
            build_linux_browser_capture_verify_report(
                "blocked",
                false,
                request,
                policy,
                blocked_operations.clone(),
            )
        })
    } else {
        None
    };
    let traffic_proof_report = if action == LinuxBrowserCaptureAction::TrafficProof {
        traffic_proof_request.map(|request| {
            build_linux_browser_capture_traffic_proof_report(
                "blocked",
                false,
                request,
                policy,
                blocked_operations.clone(),
            )
        })
    } else {
        None
    };

    LinuxBrowserCaptureReport {
        action: action.as_str().to_string(),
        source_contract_status: MITM_BROWSER_CAPTURE_SOURCE_CONTRACT_STATUS.to_string(),
        gate: MITM_BROWSER_CAPTURE_GATE.to_string(),
        gate_status: MITM_BROWSER_CAPTURE_GATE_STATUS.to_string(),
        mutation_ready: MITM_BROWSER_CAPTURE_MUTATION_READY,
        request,
        plan,
        session_plan: None,
        launch_report: None,
        apply_report,
        rollback_report,
        verify_report,
        traffic_proof_report,
    }
}

pub(crate) fn build_linux_browser_capture_plan_with_proxy_scheme(
    platform_status: &PlatformCapabilityStatus,
    policy: &LinuxMitmPolicyStatus,
    proxy_host: &str,
    proxy_port: u16,
    proxy_scheme: &str,
) -> LinuxBrowserCapturePlan {
    let mitm_plan = build_linux_mitm_browser_plan(platform_status);
    let mitm_plan = LinuxMitmBrowserPlan {
        planned_proxy_host: proxy_host.to_string(),
        planned_proxy_port: proxy_port,
        ..mitm_plan
    };
    let manual_launch = build_linux_browser_capture_manual_launch(&mitm_plan, policy, proxy_scheme);
    LinuxBrowserCapturePlan {
        status: mitm_plan.status,
        mutation_ready: mitm_plan.mutation_ready,
        current_capture: mitm_plan.current_capture,
        planned_capture_mode: mitm_plan.planned_capture_mode,
        planned_proxy_scheme: proxy_scheme.to_string(),
        planned_proxy_host: mitm_plan.planned_proxy_host,
        planned_proxy_port: mitm_plan.planned_proxy_port,
        manual_launch,
        required_steps: mitm_plan.required_steps,
        blocked_operations: mitm_plan.blocked_operations,
    }
}

pub(crate) fn build_linux_browser_capture_manual_launch(
    mitm_plan: &LinuxMitmBrowserPlan,
    policy: &LinuxMitmPolicyStatus,
    proxy_scheme: &str,
) -> LinuxBrowserCaptureManualLaunch {
    let proxy_url = browser_capture_proxy_url(
        proxy_scheme,
        &mitm_plan.planned_proxy_host,
        mitm_plan.planned_proxy_port,
    );

    LinuxBrowserCaptureManualLaunch {
        status: "manual-launch-plan-ready".to_string(),
        proxy_scheme: proxy_scheme.to_string(),
        proxy_url: proxy_url.clone(),
        profile_strategy: "dedicated-temporary-profile".to_string(),
        plugin_engine: policy.engine.clone(),
        plugin_id: policy.plugin_id.clone(),
        plugin_version: policy.plugin_version.clone(),
        browser_commands: default_linux_browser_capture_launch_commands(&proxy_url),
        manual_steps: vec![
            "start the planned local MITM proxy endpoint before launching the browser".to_string(),
            "launch a dedicated browser profile with an explicit proxy argument".to_string(),
            "close the dedicated browser profile to leave the manual capture session".to_string(),
        ],
    }
}

pub(crate) fn default_linux_browser_capture_launch_commands(
    proxy_url: &str,
) -> Vec<LinuxBrowserCaptureLaunchCommand> {
    ["chromium", "google-chrome", "microsoft-edge"]
        .into_iter()
        .map(|browser| {
            build_linux_browser_capture_launch_command(
                browser,
                browser,
                MITM_BROWSER_CAPTURE_DEFAULT_PROFILE_DIR,
                proxy_url,
                None,
            )
        })
        .collect()
}

pub(crate) fn browser_capture_proxy_url(
    proxy_scheme: &str,
    proxy_host: &str,
    proxy_port: u16,
) -> String {
    format!("{proxy_scheme}://{proxy_host}:{proxy_port}")
}

pub(crate) fn build_linux_browser_capture_launch_request(
    browser: &str,
    profile_dir: &str,
    target_url: Option<&str>,
    proof_token: Option<&str>,
    proof_log_path: Option<&str>,
    plan: &LinuxBrowserCapturePlan,
) -> LinuxBrowserCaptureLaunchRequest {
    let proxy_url = browser_capture_proxy_url(
        &plan.planned_proxy_scheme,
        &plan.planned_proxy_host,
        plan.planned_proxy_port,
    );
    let resolved_proof_token =
        resolve_browser_capture_proof_token(proof_token, target_url, &proxy_url);
    let resolved_proof_log_path = proof_log_path
        .unwrap_or(MITM_BROWSER_CAPTURE_DEFAULT_PROOF_LOG_PATH)
        .to_string();
    let proof_target_url = target_url
        .map(|target_url| browser_capture_proof_target_url(target_url, &resolved_proof_token));
    let browser_target_url = proof_target_url.as_deref().or(target_url);
    let command = build_linux_browser_capture_launch_command(
        browser,
        browser,
        profile_dir,
        &proxy_url,
        browser_target_url,
    );

    LinuxBrowserCaptureLaunchRequest {
        browser: browser.to_string(),
        profile_dir: profile_dir.to_string(),
        target_url: target_url.map(ToString::to_string),
        proof_target_url,
        proof_token: resolved_proof_token.clone(),
        proof_log_path: resolved_proof_log_path.clone(),
        traffic_proof_command: build_linux_browser_capture_traffic_proof_command(
            target_url,
            &resolved_proof_token,
            &resolved_proof_log_path,
            &plan.planned_proxy_scheme,
        ),
        proxy_scheme: plan.planned_proxy_scheme.clone(),
        proxy_url,
        command,
    }
}

pub(crate) fn build_linux_browser_capture_verify_request(
    plan: &LinuxBrowserCapturePlan,
    target_url: Option<&str>,
) -> LinuxBrowserCaptureVerifyRequest {
    LinuxBrowserCaptureVerifyRequest {
        proxy_host: plan.planned_proxy_host.clone(),
        proxy_port: plan.planned_proxy_port,
        proxy_scheme: plan.planned_proxy_scheme.clone(),
        proxy_url: browser_capture_proxy_url(
            &plan.planned_proxy_scheme,
            &plan.planned_proxy_host,
            plan.planned_proxy_port,
        ),
        target_url: target_url.map(ToString::to_string),
        probe: if target_url.is_some() {
            "http-connect-target"
        } else {
            "tcp-connect-timeout"
        }
        .to_string(),
    }
}

pub(crate) fn build_linux_browser_capture_pac_request(
    plan: &LinuxBrowserCapturePlan,
    pac_file_path: &str,
    policy_file_path: Option<&str>,
    profile_prefs_file_path: Option<&str>,
    snapshot_path: &str,
) -> LinuxBrowserCapturePacRequest {
    let proxy_url = browser_capture_proxy_url(
        &plan.planned_proxy_scheme,
        &plan.planned_proxy_host,
        plan.planned_proxy_port,
    );
    let policy_url = policy_file_path.map(browser_capture_pac_file_url);
    let policy_content = policy_file_path.map(|_| {
        browser_capture_chromium_policy_content(
            &plan.planned_proxy_scheme,
            &plan.planned_proxy_host,
            plan.planned_proxy_port,
        )
    });
    let profile_prefs_content = profile_prefs_file_path.map(|_| {
        browser_capture_firefox_user_js_content(
            &plan.planned_proxy_scheme,
            &plan.planned_proxy_host,
            plan.planned_proxy_port,
        )
    });
    LinuxBrowserCapturePacRequest {
        proxy_host: plan.planned_proxy_host.clone(),
        proxy_port: plan.planned_proxy_port,
        proxy_scheme: plan.planned_proxy_scheme.clone(),
        proxy_url,
        pac_file_path: pac_file_path.to_string(),
        snapshot_path: snapshot_path.to_string(),
        pac_url: browser_capture_pac_file_url(pac_file_path),
        pac_content: browser_capture_pac_content(
            &plan.planned_proxy_scheme,
            &plan.planned_proxy_host,
            plan.planned_proxy_port,
        ),
        policy_file_path: policy_file_path.map(ToString::to_string),
        policy_url,
        policy_content,
        profile_prefs_file_path: profile_prefs_file_path.map(ToString::to_string),
        profile_prefs_content,
    }
}

pub(crate) fn browser_capture_pac_file_url(path: &str) -> String {
    format!("file://{path}")
}

pub(crate) fn browser_capture_pac_content(
    proxy_scheme: &str,
    proxy_host: &str,
    proxy_port: u16,
) -> String {
    let pac_proxy_type = if proxy_scheme == MITM_BROWSER_CAPTURE_NATIVE_PLUGIN_PROXY_SCHEME {
        "SOCKS5"
    } else {
        "PROXY"
    };
    format!(
        "function FindProxyForURL(url, host) {{\n  return \"{pac_proxy_type} {proxy_host}:{proxy_port}; DIRECT\";\n}}\n"
    )
}

#[derive(Serialize)]
pub(crate) struct BrowserCaptureChromiumPolicyFile<'a> {
    #[serde(rename = "ProxyMode")]
    pub(crate) proxy_mode: &'a str,
    #[serde(rename = "ProxyServer")]
    pub(crate) proxy_server: String,
    #[serde(rename = "ProxyBypassList")]
    pub(crate) proxy_bypass_list: &'a str,
}

pub(crate) fn browser_capture_chromium_policy_content(
    proxy_scheme: &str,
    proxy_host: &str,
    proxy_port: u16,
) -> String {
    let policy = BrowserCaptureChromiumPolicyFile {
        proxy_mode: "fixed_servers",
        proxy_server: browser_capture_proxy_url(proxy_scheme, proxy_host, proxy_port),
        proxy_bypass_list: "<-loopback>",
    };
    let mut json = serde_json::to_string_pretty(&policy)
        .expect("browser capture chromium policy serialization should be infallible");
    json.push('\n');
    json
}

pub(crate) fn browser_capture_firefox_user_js_content(
    proxy_scheme: &str,
    proxy_host: &str,
    proxy_port: u16,
) -> String {
    if proxy_scheme == MITM_BROWSER_CAPTURE_NATIVE_PLUGIN_PROXY_SCHEME {
        return format!(
            "// NetworkCore browser capture managed proxy settings.\n\
             user_pref(\"network.proxy.type\", 1);\n\
             user_pref(\"network.proxy.socks\", \"{proxy_host}\");\n\
             user_pref(\"network.proxy.socks_port\", {proxy_port});\n\
             user_pref(\"network.proxy.socks_version\", 5);\n\
             user_pref(\"network.proxy.socks_remote_dns\", true);\n\
             user_pref(\"network.proxy.http\", \"\");\n\
             user_pref(\"network.proxy.http_port\", 0);\n\
             user_pref(\"network.proxy.ssl\", \"\");\n\
             user_pref(\"network.proxy.ssl_port\", 0);\n"
        );
    }

    format!(
        "// NetworkCore browser capture managed proxy settings.\n\
         user_pref(\"network.proxy.type\", 1);\n\
         user_pref(\"network.proxy.http\", \"{proxy_host}\");\n\
         user_pref(\"network.proxy.http_port\", {proxy_port});\n\
         user_pref(\"network.proxy.ssl\", \"{proxy_host}\");\n\
         user_pref(\"network.proxy.ssl_port\", {proxy_port});\n\
         user_pref(\"network.proxy.share_proxy_settings\", true);\n\
         user_pref(\"network.proxy.no_proxies_on\", \"\");\n"
    )
}

pub(crate) fn build_linux_browser_capture_verify_command(
    target_url: Option<&str>,
    proxy_scheme: &str,
) -> String {
    let mut args = vec![
        "networkcore-linux".to_string(),
        "mitm".to_string(),
        "browser-capture".to_string(),
        "verify".to_string(),
        "--confirm".to_string(),
    ];
    if proxy_scheme != MITM_BROWSER_CAPTURE_DEFAULT_PROXY_SCHEME {
        args.push("--proxy-scheme".to_string());
        args.push(proxy_scheme.to_string());
    }
    if let Some(target_url) = target_url {
        args.push("--target-url".to_string());
        args.push(target_url.to_string());
    }

    args.into_iter()
        .map(|arg| shell_display_arg(&arg))
        .collect::<Vec<_>>()
        .join(" ")
}

pub(crate) fn build_linux_browser_capture_traffic_proof_command(
    target_url: Option<&str>,
    proof_token: &str,
    proof_log_path: &str,
    proxy_scheme: &str,
) -> String {
    let mut args = vec![
        "networkcore-linux".to_string(),
        "mitm".to_string(),
        "browser-capture".to_string(),
        "traffic-proof".to_string(),
        "--confirm".to_string(),
    ];
    if proxy_scheme != MITM_BROWSER_CAPTURE_DEFAULT_PROXY_SCHEME {
        args.push("--proxy-scheme".to_string());
        args.push(proxy_scheme.to_string());
    }
    if let Some(target_url) = target_url {
        args.push("--target-url".to_string());
        args.push(target_url.to_string());
    }
    args.extend([
        "--proof-token".to_string(),
        proof_token.to_string(),
        "--proof-log".to_string(),
        proof_log_path.to_string(),
    ]);
    args.into_iter()
        .map(|arg| shell_display_arg(&arg))
        .collect::<Vec<_>>()
        .join(" ")
}

pub(crate) fn resolve_browser_capture_proof_token(
    proof_token: Option<&str>,
    target_url: Option<&str>,
    proxy_url: &str,
) -> String {
    if let Some(proof_token) = proof_token {
        return proof_token.to_string();
    }

    let proof_source = target_url
        .and_then(|target_url| {
            parse_browser_capture_target_endpoint(target_url)
                .ok()
                .map(|endpoint| format!("connect:{}|proxy:{proxy_url}", endpoint.authority()))
        })
        .unwrap_or_else(|| format!("target:no-target|proxy:{proxy_url}"));
    browser_capture_proof_token_from_source(&proof_source)
}

pub(crate) fn browser_capture_proof_token_from_source(source: &str) -> String {
    let mut hash = 0xcbf29ce484222325_u64;
    for byte in source.bytes() {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    format!("networkcore-browser-proof-{hash:016x}")
}

pub(crate) fn browser_capture_proof_target_url(target_url: &str, proof_token: &str) -> String {
    let (base, fragment) = match target_url.split_once('#') {
        Some((base, fragment)) => (base, Some(fragment)),
        None => (target_url, None),
    };
    let separator = if base.ends_with('?') || base.ends_with('&') {
        ""
    } else if base.contains('?') {
        "&"
    } else {
        "?"
    };
    let mut proof_url = format!(
        "{base}{separator}{MITM_BROWSER_CAPTURE_PROOF_QUERY_PARAM}={}",
        browser_capture_url_query_encode(proof_token)
    );
    if let Some(fragment) = fragment {
        proof_url.push('#');
        proof_url.push_str(fragment);
    }
    proof_url
}

pub(crate) fn browser_capture_url_query_encode(value: &str) -> String {
    let mut encoded = String::new();
    for byte in value.bytes() {
        let ch = byte as char;
        if ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.' | '~') {
            encoded.push(ch);
        } else {
            encoded.push_str(&format!("%{byte:02X}"));
        }
    }
    encoded
}

pub(crate) fn build_linux_browser_capture_launch_command(
    browser: &str,
    executable: &str,
    profile_dir: &str,
    proxy_url: &str,
    target_url: Option<&str>,
) -> LinuxBrowserCaptureLaunchCommand {
    let mut args = vec![
        format!("--user-data-dir={profile_dir}"),
        format!("--proxy-server={proxy_url}"),
    ];
    if let Some(target_url) = target_url {
        args.push(target_url.to_string());
    }
    let command = std::iter::once(executable.to_string())
        .chain(args.iter().cloned())
        .map(|arg| shell_display_arg(&arg))
        .collect::<Vec<_>>()
        .join(" ");

    LinuxBrowserCaptureLaunchCommand {
        browser: browser.to_string(),
        executable: executable.to_string(),
        args,
        command,
    }
}

pub(crate) fn shell_display_arg(arg: &str) -> String {
    if arg
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.' | '/' | ':' | '='))
    {
        return arg.to_string();
    }

    format!("'{}'", arg.replace('\'', "'\\''"))
}

pub(crate) fn build_linux_browser_capture_launch_report(
    status: &str,
    launched: bool,
    pid: Option<u32>,
    request: LinuxBrowserCaptureLaunchRequest,
    policy: &LinuxMitmPolicyStatus,
) -> LinuxBrowserCaptureLaunchReport {
    LinuxBrowserCaptureLaunchReport {
        status: status.to_string(),
        launched,
        pid,
        request,
        plugin_engine: policy.engine.clone(),
        plugin_id: policy.plugin_id.clone(),
        plugin_version: policy.plugin_version.clone(),
    }
}

pub(crate) fn build_linux_browser_capture_verify_report(
    status: &str,
    verified: bool,
    request: LinuxBrowserCaptureVerifyRequest,
    policy: &LinuxMitmPolicyStatus,
    blocked_operations: Vec<String>,
) -> LinuxBrowserCaptureVerifyReport {
    LinuxBrowserCaptureVerifyReport {
        status: status.to_string(),
        verified,
        request,
        plugin_engine: policy.engine.clone(),
        plugin_id: policy.plugin_id.clone(),
        plugin_version: policy.plugin_version.clone(),
        blocked_operations,
    }
}

pub(crate) fn build_linux_browser_capture_traffic_proof_request(
    plan: &LinuxBrowserCapturePlan,
    target_url: Option<&str>,
    proof_token: Option<&str>,
    proof_log_path: Option<&str>,
) -> LinuxBrowserCaptureTrafficProofRequest {
    let proxy_url = browser_capture_proxy_url(
        &plan.planned_proxy_scheme,
        &plan.planned_proxy_host,
        plan.planned_proxy_port,
    );
    let resolved_proof_token =
        resolve_browser_capture_proof_token(proof_token, target_url, &proxy_url);
    let resolved_proof_log_path = proof_log_path
        .unwrap_or(MITM_BROWSER_CAPTURE_DEFAULT_PROOF_LOG_PATH)
        .to_string();
    let proof_target_url = target_url
        .map(|target_url| browser_capture_proof_target_url(target_url, &resolved_proof_token));
    let proof_connect_authority = target_url.and_then(|target_url| {
        parse_browser_capture_target_endpoint(target_url)
            .ok()
            .map(|endpoint| endpoint.authority())
    });

    LinuxBrowserCaptureTrafficProofRequest {
        proxy_host: plan.planned_proxy_host.clone(),
        proxy_port: plan.planned_proxy_port,
        proxy_scheme: plan.planned_proxy_scheme.clone(),
        proxy_url,
        target_url: target_url.map(ToString::to_string),
        proof_connect_authority,
        proof_target_url,
        proof_token: resolved_proof_token,
        proof_log_path: resolved_proof_log_path,
        probe: "proof-log-token".to_string(),
    }
}

pub(crate) fn build_linux_browser_capture_traffic_proof_report(
    status: &str,
    proven: bool,
    request: LinuxBrowserCaptureTrafficProofRequest,
    policy: &LinuxMitmPolicyStatus,
    blocked_operations: Vec<String>,
) -> LinuxBrowserCaptureTrafficProofReport {
    LinuxBrowserCaptureTrafficProofReport {
        status: status.to_string(),
        proven,
        request,
        plugin_engine: policy.engine.clone(),
        plugin_id: policy.plugin_id.clone(),
        plugin_version: policy.plugin_version.clone(),
        blocked_operations,
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn build_linux_browser_capture_session_plan_report(
    request: LinuxBrowserCaptureSessionPlanRequest,
    node_id: String,
    node_name: String,
    browser_command: LinuxBrowserCaptureLaunchCommand,
    proxy_url: String,
    traffic_proof_request: LinuxBrowserCaptureTrafficProofRequest,
    policy: &LinuxMitmPolicyStatus,
    blocked_operations: Vec<String>,
) -> LinuxBrowserCaptureSessionPlanReport {
    let target_url = request.target_url;
    let proof_target_url = request.proof_target_url;
    let verify_command =
        build_linux_browser_capture_verify_command(target_url.as_deref(), &request.proxy_scheme);
    let traffic_proof_command = build_linux_browser_capture_traffic_proof_command(
        target_url.as_deref(),
        &traffic_proof_request.proof_token,
        &traffic_proof_request.proof_log_path,
        &request.proxy_scheme,
    );

    LinuxBrowserCaptureSessionPlanReport {
        status: "ready".to_string(),
        url_source: request.url_source,
        node_id,
        node_name,
        target_url,
        proof_target_url,
        proof_token: traffic_proof_request.proof_token,
        proof_log_path: traffic_proof_request.proof_log_path,
        listen_host: request.listen_host.clone(),
        listen_port: request.listen_port,
        proxy_scheme: request.proxy_scheme,
        proxy_url,
        run_command: format!(
            "networkcore-linux run-url <subscription-url> --listen-host {} --listen-port {}",
            request.listen_host, request.listen_port
        ),
        browser_command,
        verify_command,
        traffic_proof_command,
        plugin_engine: policy.engine.clone(),
        plugin_id: policy.plugin_id.clone(),
        plugin_version: policy.plugin_version.clone(),
        required_steps: vec![
            "start the local proxy with run-url using the same subscription URL".to_string(),
            "launch the dedicated browser profile with the planned explicit proxy".to_string(),
            "verify the local proxy endpoint before relying on browser traffic capture".to_string(),
            "inspect the proxy proof log with the generated traffic-proof command".to_string(),
            "close the dedicated browser profile and stop the foreground proxy to leave the session"
                .to_string(),
        ],
        blocked_operations,
    }
}

pub(crate) fn build_linux_mitm_certificate_plan(
    platform_status: &PlatformCapabilityStatus,
) -> LinuxMitmCertificatePlan {
    let current_state = certificate_state_name(platform_status.mitm_certificate.state);
    let trust_satisfied = platform_status.mitm_certificate.is_trusted();

    LinuxMitmCertificatePlan {
        status: MITM_CERTIFICATE_PLAN_STATUS.to_string(),
        mutation_ready: MITM_CERTIFICATE_MUTATION_READY,
        current_state: current_state.to_string(),
        subject: platform_status.mitm_certificate.subject.clone(),
        fingerprint_sha256: platform_status.mitm_certificate.fingerprint_sha256.clone(),
        required_steps: vec![
            LinuxMitmCertificatePlanStep {
                id: "probe-certificate-state".to_string(),
                status: "active".to_string(),
                reason: "read-only platform certificate state is available".to_string(),
            },
            LinuxMitmCertificatePlanStep {
                id: "write-local-ca-artifact".to_string(),
                status: "active".to_string(),
                reason: "certificate apply can write operator-provided NetworkCore cert/key artifact paths with rollback snapshot".to_string(),
            },
            LinuxMitmCertificatePlanStep {
                id: "snapshot-ca-artifact".to_string(),
                status: "active".to_string(),
                reason: "certificate apply records NetworkCore ownership and content fingerprints before artifact rollback".to_string(),
            },
            LinuxMitmCertificatePlanStep {
                id: "write-dedicated-profile-trust-artifact".to_string(),
                status: "active".to_string(),
                reason: "certificate apply can optionally copy the generated CA artifact to an operator-provided dedicated profile trust artifact path with rollback snapshot".to_string(),
            },
            LinuxMitmCertificatePlanStep {
                id: "install-user-trust".to_string(),
                status: certificate_trust_step_status(trust_satisfied).to_string(),
                reason: certificate_trust_step_reason(platform_status.mitm_certificate.state)
                    .to_string(),
            },
            LinuxMitmCertificatePlanStep {
                id: "verify-trust".to_string(),
                status: certificate_trust_step_status(trust_satisfied).to_string(),
                reason: certificate_verify_step_reason(platform_status.mitm_certificate.state)
                    .to_string(),
            },
            LinuxMitmCertificatePlanStep {
                id: "rollback-ca-artifact".to_string(),
                status: "active".to_string(),
                reason: "certificate rollback can remove NetworkCore-created cert/key artifacts when the snapshot fingerprint still matches".to_string(),
            },
            LinuxMitmCertificatePlanStep {
                id: "rollback-trust".to_string(),
                status: "blocked".to_string(),
                reason: "certificate trust store rollback command is not implemented".to_string(),
            },
            LinuxMitmCertificatePlanStep {
                id: "connect-http-tls-data-plane".to_string(),
                status: "blocked".to_string(),
                reason: "HTTP/TLS interception data plane is not wired to the MITM policy engine"
                    .to_string(),
            },
        ],
        blocked_operations: vec![
            "install-ca".to_string(),
            "trust-ca".to_string(),
            "update-ca-certificates".to_string(),
            "mutate-nss-db".to_string(),
            "mutate-p11-kit".to_string(),
            "mutate-firefox-trust-store".to_string(),
            "revoke-ca".to_string(),
            "rollback-trust-store".to_string(),
            "decrypt-https".to_string(),
            "mutate-live-http".to_string(),
            "configure-browser-proxy".to_string(),
        ],
    }
}

pub(crate) fn build_linux_mitm_certificate_lifecycle_report(
    action: LinuxMitmCertificateLifecycleAction,
    platform_status: &PlatformCapabilityStatus,
    authorization: Option<MitmCertificateAuthorization>,
    rollback_snapshot: Option<MitmCertificateRollbackSnapshot>,
) -> LinuxMitmCertificateLifecycleReport {
    let plan = build_linux_mitm_certificate_plan(platform_status);
    let trust_plan = build_linux_mitm_certificate_trust_plan(platform_status);
    let request = LinuxMitmCertificateLifecycleRequest {
        action,
        artifact: None,
        authorization: authorization.clone(),
        rollback_snapshot: rollback_snapshot.clone(),
    };
    let apply_report = if action == LinuxMitmCertificateLifecycleAction::Apply {
        authorization.clone().map(|authorization| {
            let status = if authorization.confirmed {
                "blocked"
            } else {
                "authorization_required"
            };
            LinuxMitmCertificateApplyReport {
                status: status.to_string(),
                applied: false,
                authorization,
                cert_file_path: None,
                key_file_path: None,
                profile_trust_file_path: None,
                rollback_snapshot: None,
                blocked_operations: trust_plan.blocked_operations.clone(),
            }
        })
    } else {
        None
    };
    let rollback_report = if action == LinuxMitmCertificateLifecycleAction::Rollback {
        Some(LinuxMitmCertificateRollbackReport {
            status: "blocked".to_string(),
            rolled_back: false,
            cert_file_path: None,
            key_file_path: None,
            profile_trust_file_path: None,
            rollback_snapshot: rollback_snapshot.clone(),
            blocked_operations: trust_plan.blocked_operations.clone(),
        })
    } else {
        None
    };

    LinuxMitmCertificateLifecycleReport {
        action: action.as_str().to_string(),
        source_contract_status: MITM_CERTIFICATE_LIFECYCLE_SOURCE_CONTRACT_STATUS.to_string(),
        gate: MITM_CERTIFICATE_LIFECYCLE_GATE.to_string(),
        gate_status: MITM_CERTIFICATE_LIFECYCLE_GATE_STATUS.to_string(),
        mutation_ready: MITM_CERTIFICATE_MUTATION_READY,
        request,
        plan,
        trust_plan,
        apply_report,
        rollback_report,
    }
}

pub(crate) fn build_linux_mitm_certificate_trust_plan(
    platform_status: &PlatformCapabilityStatus,
) -> LinuxMitmCertificateTrustPlan {
    let trust_satisfied = platform_status.mitm_certificate.is_trusted();

    LinuxMitmCertificateTrustPlan {
        status: "trust-mutation-blocked".to_string(),
        mutation_ready: MITM_CERTIFICATE_MUTATION_READY,
        required_steps: vec![
            LinuxMitmCertificatePlanStep {
                id: "detect-platform-trust".to_string(),
                status: certificate_trust_step_status(trust_satisfied).to_string(),
                reason: certificate_verify_step_reason(platform_status.mitm_certificate.state)
                    .to_string(),
            },
            LinuxMitmCertificatePlanStep {
                id: "prepare-system-trust-store-mutation".to_string(),
                status: "blocked".to_string(),
                reason: "system trust-store mutation is intentionally excluded from this alpha slice".to_string(),
            },
            LinuxMitmCertificatePlanStep {
                id: "prepare-dedicated-profile-trust-artifact".to_string(),
                status: "active".to_string(),
                reason: "profile-local CA trust artifact generation is available for caller-selected dedicated profile paths without mutating trust stores".to_string(),
            },
            LinuxMitmCertificatePlanStep {
                id: "prepare-browser-trust-store-mutation".to_string(),
                status: "blocked".to_string(),
                reason: "NSS DB, p11-kit, Firefox trust store, and browser-specific trust mutation are blocked".to_string(),
            },
        ],
        blocked_operations: vec![
            "install-ca".to_string(),
            "trust-ca".to_string(),
            "update-ca-certificates".to_string(),
            "mutate-nss-db".to_string(),
            "mutate-p11-kit".to_string(),
            "mutate-firefox-trust-store".to_string(),
            "revoke-ca".to_string(),
            "rollback-trust-store".to_string(),
        ],
    }
}

pub(crate) fn build_linux_mitm_certificate_artifact_request(
    cert_file_path: &str,
    key_file_path: &str,
    profile_trust_file_path: Option<&str>,
    snapshot_path: &str,
) -> DomainResult<LinuxMitmCertificateArtifactRequest> {
    let subject = MITM_CERTIFICATE_ARTIFACT_SUBJECT.to_string();
    let ca_material = generate_mitm_certificate_ca_pem_material(&subject)?;
    let cert_content = ca_material.cert_pem;
    let key_content = ca_material.key_pem;
    let profile_trust_content = profile_trust_file_path.map(|_| cert_content.clone());

    Ok(LinuxMitmCertificateArtifactRequest {
        cert_file_path: cert_file_path.to_string(),
        key_file_path: key_file_path.to_string(),
        profile_trust_file_path: profile_trust_file_path.map(ToString::to_string),
        snapshot_path: snapshot_path.to_string(),
        subject,
        artifact_version: 2,
        cert_fingerprint: stable_content_fingerprint(&cert_content),
        key_fingerprint: stable_content_fingerprint(&key_content),
        profile_trust_fingerprint: profile_trust_content
            .as_deref()
            .map(stable_content_fingerprint),
        cert_content,
        key_content,
        profile_trust_content,
    })
}

pub(crate) struct MitmCertificateCaPemMaterial {
    pub(crate) cert_pem: String,
    pub(crate) key_pem: String,
}

pub(crate) fn generate_mitm_certificate_ca_pem_material(
    subject: &str,
) -> DomainResult<MitmCertificateCaPemMaterial> {
    let mut distinguished_name = DistinguishedName::new();
    distinguished_name.push(DnType::CommonName, subject);
    distinguished_name.push(DnType::OrganizationName, "AnixOps NetworkCore");

    let mut params = CertificateParams::default();
    params.distinguished_name = distinguished_name;
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
        KeyUsagePurpose::DigitalSignature,
    ];

    let key_pair = KeyPair::generate().map_err(|error| {
        DomainError::new(
            CLI_MITM_CERTIFICATE_MATERIAL_FAILED_CODE,
            format!("failed to generate MITM CA private key material: {error}"),
        )
    })?;
    let certificate = params.self_signed(&key_pair).map_err(|error| {
        DomainError::new(
            CLI_MITM_CERTIFICATE_MATERIAL_FAILED_CODE,
            format!("failed to generate self-signed MITM CA certificate material: {error}"),
        )
    })?;

    Ok(MitmCertificateCaPemMaterial {
        cert_pem: certificate.pem(),
        key_pem: key_pair.serialize_pem(),
    })
}

pub(crate) fn stable_content_fingerprint(source: &str) -> String {
    let mut hash = 0xcbf29ce484222325_u64;
    for byte in source.bytes() {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    format!("{hash:016x}")
}

pub(crate) fn certificate_trust_step_status(trust_satisfied: bool) -> &'static str {
    if trust_satisfied {
        "satisfied"
    } else {
        "blocked"
    }
}

pub(crate) fn certificate_trust_step_reason(state: CertificateTrustState) -> &'static str {
    match state {
        CertificateTrustState::Trusted => "platform reports a trusted MITM certificate",
        CertificateTrustState::InstalledUntrusted => {
            "certificate is installed but the Linux trust path is not active"
        }
        CertificateTrustState::NotInstalled => "certificate is not installed",
        CertificateTrustState::Revoked => "certificate is revoked",
        CertificateTrustState::Unknown => "certificate trust state is unknown",
    }
}

pub(crate) fn certificate_verify_step_reason(state: CertificateTrustState) -> &'static str {
    match state {
        CertificateTrustState::Trusted => "read-only platform probe reports trusted state",
        CertificateTrustState::InstalledUntrusted => "trusted state cannot be verified yet",
        CertificateTrustState::NotInstalled => "no installed certificate is available to verify",
        CertificateTrustState::Revoked => "revoked certificate cannot be verified for MITM use",
        CertificateTrustState::Unknown => "certificate trust state probe is inconclusive",
    }
}
