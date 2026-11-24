//! The entrypoint: maps a parsed command to its handler.

use super::*;

pub fn handle_parse_error(diagnostic: Diagnostic) -> LinuxCliResponse {
    let show_help = diagnostic.code == CLI_COMMAND_MISSING_CODE
        || diagnostic.code == CLI_ARGUMENT_UNKNOWN_CODE
        || diagnostic.code == CLI_OUTPUT_FORMAT_UNSUPPORTED_CODE;
    let response =
        LinuxCliResponse::failure("parse", LinuxCliExitCode::ArgumentOrConfig, diagnostic);
    if show_help {
        response.with_help(cli_help_text())
    } else {
        response
    }
}

pub fn handle_entrypoint_skeleton(command: LinuxCliCommand) -> LinuxCliResponse {
    match command {
        LinuxCliCommand::Help { .. } => handle_help(),
        LinuxCliCommand::Version { .. } => handle_version(),
        LinuxCliCommand::Stop { .. } => handle_stop(),
        LinuxCliCommand::ManagedControlStop {
            socket_path,
            confirm,
            ..
        } => handle_managed_control_stop(&socket_path, confirm),
        LinuxCliCommand::ManagedControlReload {
            socket_path,
            confirm,
            ..
        } => handle_managed_control_reload(&socket_path, confirm),
        LinuxCliCommand::ManagedControlRollback {
            socket_path,
            expected_config_version,
            confirm,
            ..
        } => handle_managed_control_rollback(&socket_path, expected_config_version, confirm),
        LinuxCliCommand::ManagedControlStatus { socket_path, .. } => {
            handle_managed_control_status(&socket_path)
        }
        LinuxCliCommand::Restart { .. } => handle_restart_unavailable(),
        LinuxCliCommand::InstallService { .. } => handle_unwired_command("install-service"),
        LinuxCliCommand::UninstallService { .. } => handle_unwired_command("uninstall-service"),
        LinuxCliCommand::ServiceControl { .. } => handle_unwired_command("service"),
        LinuxCliCommand::NodeList { .. } => handle_unwired_command("node list"),
        LinuxCliCommand::NodeSelect { .. } => handle_unwired_command("node select"),
        LinuxCliCommand::NodeRollback { .. } => handle_unwired_command("node rollback"),
        LinuxCliCommand::ProxyApply { .. }
        | LinuxCliCommand::ProxyStatus { .. }
        | LinuxCliCommand::ProxyRollback { .. } => handle_unwired_command("proxy"),
        LinuxCliCommand::MitmCertificateTrustApply { .. }
        | LinuxCliCommand::MitmCertificateTrustRollback { .. } => {
            handle_unwired_command("mitm certificate trust")
        }
        LinuxCliCommand::CoreList { .. } => handle_unwired_command("core"),
        other => handle_unwired_command(other.name()),
    }
}

pub fn handle_entrypoint<P>(command: LinuxCliCommand, platform: &P) -> LinuxCliResponse
where
    P: PlatformCapabilityService,
{
    match command {
        LinuxCliCommand::Help { .. } => handle_help(),
        LinuxCliCommand::Version { .. } => handle_version(),
        LinuxCliCommand::Capabilities { .. } => handle_capabilities(platform),
        LinuxCliCommand::Status { .. } => handle_status(platform),
        LinuxCliCommand::InstallService {
            unit_name,
            description,
            executable_path,
            arguments,
            service_user,
            service_group,
            state_directory,
            confirm,
            ..
        } => handle_install_service_plan(
            &unit_name,
            &description,
            &executable_path,
            &arguments,
            &service_user,
            &service_group,
            &state_directory,
            confirm,
        ),
        LinuxCliCommand::UninstallService {
            unit_name,
            state_directory,
            confirm,
            ..
        } => handle_uninstall_service_apply_with_runner(
            &platform_linux::systemd::CommandLinuxSystemdCommandRunner::new(),
            &unit_name,
            &state_directory,
            confirm,
        ),
        LinuxCliCommand::ServiceControl {
            action,
            unit_name,
            confirm,
            ..
        } => handle_systemd_service_control(
            &platform_linux::systemd::CommandLinuxSystemdCommandRunner::new(),
            action,
            &unit_name,
            confirm,
        ),
        LinuxCliCommand::NodeList { config_path, .. } => handle_node_list(&config_path),
        LinuxCliCommand::NodeSelect {
            config_path,
            node_id,
            selection_path,
            snapshot_path,
            confirm,
            ..
        } => handle_node_select(
            &config_path,
            &node_id,
            &selection_path,
            &snapshot_path,
            confirm,
        ),
        LinuxCliCommand::NodeRollback {
            selection_path,
            snapshot_path,
            confirm,
            ..
        } => handle_node_rollback(&selection_path, &snapshot_path, confirm),
        LinuxCliCommand::ProxyApply {
            file_path,
            snapshot_path,
            proxy_url,
            confirm,
            ..
        } => handle_proxy_apply(&file_path, &snapshot_path, &proxy_url, confirm),
        LinuxCliCommand::ProxyStatus { file_path, .. } => handle_proxy_status(&file_path),
        LinuxCliCommand::ProxyRollback {
            file_path,
            snapshot_path,
            confirm,
            ..
        } => handle_proxy_rollback(&file_path, &snapshot_path, confirm),
        LinuxCliCommand::CoreList { .. } => handle_unwired_command("core"),
        LinuxCliCommand::Restart { .. } => handle_restart_unavailable(),
        LinuxCliCommand::ManagedStatus { status_path, .. } => {
            handle_managed_foreground_status(&status_path)
        }
        LinuxCliCommand::ManagedStatusInit {
            status_path,
            session_id,
            engine_id,
            state,
            ..
        } => handle_managed_foreground_status_init(&status_path, &session_id, &engine_id, &state),
        LinuxCliCommand::ManagedStatusTransition {
            status_path,
            snapshot_path,
            expected_state,
            next_state,
            ..
        } => handle_managed_foreground_status_transition(
            &status_path,
            &snapshot_path,
            &expected_state,
            &next_state,
        ),
        LinuxCliCommand::ManagedStatusRollback {
            status_path,
            snapshot_path,
            expected_state,
            ..
        } => {
            handle_managed_foreground_status_rollback(&status_path, &snapshot_path, &expected_state)
        }
        LinuxCliCommand::ManagedEvent { event_path, .. } => {
            handle_managed_foreground_event(&event_path)
        }
        LinuxCliCommand::ManagedEventList {
            event_directory,
            session_id,
            event_kind,
            state,
            cursor,
            limit,
            ..
        } => handle_managed_foreground_event_history(
            &event_directory,
            session_id.as_deref(),
            event_kind.as_deref(),
            state.as_deref(),
            cursor,
            limit,
        ),
        LinuxCliCommand::ManagedEventInit {
            event_path,
            session_id,
            engine_id,
            event_id,
            event_kind,
            state,
            recorded_at,
            ..
        } => handle_managed_foreground_event_init(
            &event_path,
            &session_id,
            &engine_id,
            &event_id,
            &event_kind,
            &state,
            &recorded_at,
        ),
        LinuxCliCommand::ManagedLog {
            log_path,
            line_limit,
            ..
        } => handle_managed_foreground_log_tail(&log_path, line_limit),
        LinuxCliCommand::Diagnostics { .. } => handle_diagnostics(platform),
        LinuxCliCommand::MitmStatus { .. } => handle_mitm_status(platform),
        LinuxCliCommand::MitmDiagnostics { .. } => handle_mitm_diagnostics(platform),
        LinuxCliCommand::MitmCertificatePlan { .. } => handle_mitm_certificate_plan(platform),
        LinuxCliCommand::MitmCertificateApply {
            cert_file_path,
            key_file_path,
            profile_trust_file_path,
            snapshot_path,
            confirm,
            ..
        } => {
            let store = UnavailableMitmCertificateArtifactStore::new();
            handle_mitm_certificate_apply_with_store(
                platform,
                &store,
                cert_file_path.as_deref(),
                key_file_path.as_deref(),
                profile_trust_file_path.as_deref(),
                snapshot_path.as_deref(),
                confirm,
            )
        }
        LinuxCliCommand::MitmCertificateRollback { snapshot_path, .. } => {
            let store = UnavailableMitmCertificateArtifactStore::new();
            handle_mitm_certificate_rollback_with_store(platform, &store, snapshot_path)
        }
        LinuxCliCommand::MitmCertificateTrustApply {
            certificate_path,
            trust_file_path,
            snapshot_path,
            confirm,
            ..
        } => handle_mitm_certificate_trust_apply(
            certificate_path.as_deref(),
            trust_file_path.as_deref(),
            snapshot_path.as_deref(),
            confirm,
        ),
        LinuxCliCommand::MitmCertificateTrustRollback {
            trust_file_path,
            snapshot_path,
            confirm,
            ..
        } => handle_mitm_certificate_trust_rollback(
            trust_file_path.as_deref(),
            snapshot_path.as_deref(),
            confirm,
        ),
        LinuxCliCommand::MitmBrowserPlan { .. } => handle_mitm_browser_plan(platform),
        LinuxCliCommand::MitmBrowserCapturePlan { proxy_scheme, .. } => {
            handle_mitm_browser_capture_plan_with_proxy_scheme(platform, &proxy_scheme)
        }
        LinuxCliCommand::MitmBrowserCaptureLaunchPlan { proxy_scheme, .. } => {
            handle_mitm_browser_capture_launch_plan_with_proxy_scheme(platform, &proxy_scheme)
        }
        LinuxCliCommand::MitmBrowserCaptureSessionPlan {
            url,
            browser,
            profile_dir,
            target_url,
            proof_token,
            proof_log_path,
            proxy_scheme,
            listen_host,
            listen_port,
            ..
        } => handle_mitm_browser_capture_session_plan_with_proxy_scheme(
            platform,
            &url,
            &browser,
            &profile_dir,
            target_url.as_deref(),
            proof_token.as_deref(),
            proof_log_path.as_deref(),
            &proxy_scheme,
            &listen_host,
            listen_port,
        ),
        LinuxCliCommand::MitmBrowserCaptureLaunch { .. } => {
            handle_mitm_browser_capture_launch_unwired()
        }
        LinuxCliCommand::MitmBrowserCaptureApply {
            proxy_scheme,
            confirm,
            ..
        } => handle_mitm_browser_capture_apply_with_proxy_scheme(platform, &proxy_scheme, confirm),
        LinuxCliCommand::MitmBrowserCaptureRollback { snapshot_path, .. } => {
            handle_mitm_browser_capture_rollback(platform, snapshot_path)
        }
        LinuxCliCommand::MitmBrowserCaptureVerify {
            target_url,
            proxy_scheme,
            confirm,
            ..
        } => handle_mitm_browser_capture_verify_with_proxy_scheme(
            platform,
            target_url.as_deref(),
            &proxy_scheme,
            confirm,
        ),
        LinuxCliCommand::MitmBrowserCaptureTrafficProof {
            target_url,
            proof_token,
            proof_log_path,
            proxy_scheme,
            confirm,
            ..
        } => handle_mitm_browser_capture_traffic_proof_with_proxy_scheme(
            platform,
            target_url.as_deref(),
            proof_token.as_deref(),
            proof_log_path.as_deref(),
            &proxy_scheme,
            confirm,
        ),
        LinuxCliCommand::MitmHttpRewritePlan { .. } => handle_mitm_http_rewrite_plan(platform),
        LinuxCliCommand::MitmHttpRewritePreview {
            mitm_plugin_path,
            url,
            method,
            phase,
            status_code,
            headers,
            body,
            confirm,
            ..
        } => handle_mitm_http_rewrite_preview(
            platform,
            mitm_plugin_path.as_deref(),
            url.as_deref(),
            &method,
            &phase,
            status_code,
            &headers,
            body.as_deref(),
            confirm,
        ),
        LinuxCliCommand::Stop { .. } => handle_stop(),
        LinuxCliCommand::ManagedControlStop {
            socket_path,
            confirm,
            ..
        } => handle_managed_control_stop(&socket_path, confirm),
        LinuxCliCommand::ManagedControlReload {
            socket_path,
            confirm,
            ..
        } => handle_managed_control_reload(&socket_path, confirm),
        LinuxCliCommand::ManagedControlRollback {
            socket_path,
            expected_config_version,
            confirm,
            ..
        } => handle_managed_control_rollback(&socket_path, expected_config_version, confirm),
        LinuxCliCommand::ManagedControlStatus { socket_path, .. } => {
            handle_managed_control_status(&socket_path)
        }
        other => handle_unwired_command(other.name()),
    }
}

pub fn handle_entrypoint_with_browser_capture_runner<P, B>(
    command: LinuxCliCommand,
    platform: &P,
    browser_runner: &B,
) -> LinuxCliResponse
where
    P: PlatformCapabilityService,
    B: BrowserCaptureProcessRunner,
{
    match command {
        LinuxCliCommand::MitmBrowserCaptureLaunch {
            browser,
            profile_dir,
            target_url,
            proof_token,
            proof_log_path,
            proxy_scheme,
            confirm,
            ..
        } => handle_mitm_browser_capture_launch_with_proxy_scheme(
            platform,
            browser_runner,
            &browser,
            &profile_dir,
            target_url.as_deref(),
            proof_token.as_deref(),
            proof_log_path.as_deref(),
            &proxy_scheme,
            confirm,
        ),
        other => handle_entrypoint(other, platform),
    }
}

pub fn handle_entrypoint_with_browser_capture_io<P, B, V>(
    command: LinuxCliCommand,
    platform: &P,
    browser_runner: &B,
    endpoint_probe: &V,
) -> LinuxCliResponse
where
    P: PlatformCapabilityService,
    B: BrowserCaptureProcessRunner,
    V: BrowserCaptureEndpointProbe,
{
    let traffic_proof_probe = UnavailableBrowserCaptureTrafficProofProbe::new();
    let pac_store = UnavailableBrowserCapturePacFileStore::new();
    handle_entrypoint_with_browser_capture_all_io(
        command,
        platform,
        browser_runner,
        endpoint_probe,
        &traffic_proof_probe,
        &pac_store,
    )
}

pub fn handle_entrypoint_with_certificate_lifecycle_io<P, S>(
    command: LinuxCliCommand,
    platform: &P,
    certificate_store: &S,
) -> LinuxCliResponse
where
    P: PlatformCapabilityService,
    S: MitmCertificateArtifactStore,
{
    match command {
        LinuxCliCommand::MitmCertificateApply {
            cert_file_path,
            key_file_path,
            profile_trust_file_path,
            snapshot_path,
            confirm,
            ..
        } => handle_mitm_certificate_apply_with_store(
            platform,
            certificate_store,
            cert_file_path.as_deref(),
            key_file_path.as_deref(),
            profile_trust_file_path.as_deref(),
            snapshot_path.as_deref(),
            confirm,
        ),
        LinuxCliCommand::MitmCertificateRollback { snapshot_path, .. } => {
            handle_mitm_certificate_rollback_with_store(platform, certificate_store, snapshot_path)
        }
        other => handle_entrypoint(other, platform),
    }
}

pub fn handle_entrypoint_with_browser_capture_all_io<P, B, V, T, S>(
    command: LinuxCliCommand,
    platform: &P,
    browser_runner: &B,
    endpoint_probe: &V,
    traffic_proof_probe: &T,
    pac_store: &S,
) -> LinuxCliResponse
where
    P: PlatformCapabilityService,
    B: BrowserCaptureProcessRunner,
    V: BrowserCaptureEndpointProbe,
    T: BrowserCaptureTrafficProofProbe,
    S: BrowserCapturePacFileStore,
{
    match command {
        LinuxCliCommand::MitmBrowserCaptureLaunch {
            browser,
            profile_dir,
            target_url,
            proof_token,
            proof_log_path,
            proxy_scheme,
            confirm,
            ..
        } => handle_mitm_browser_capture_launch_with_proxy_scheme(
            platform,
            browser_runner,
            &browser,
            &profile_dir,
            target_url.as_deref(),
            proof_token.as_deref(),
            proof_log_path.as_deref(),
            &proxy_scheme,
            confirm,
        ),
        LinuxCliCommand::MitmBrowserCaptureVerify {
            target_url,
            proxy_scheme,
            confirm,
            ..
        } => handle_mitm_browser_capture_verify_with_probe_and_proxy_scheme(
            platform,
            endpoint_probe,
            target_url.as_deref(),
            &proxy_scheme,
            confirm,
        ),
        LinuxCliCommand::MitmBrowserCaptureTrafficProof {
            target_url,
            proof_token,
            proof_log_path,
            proxy_scheme,
            confirm,
            ..
        } => handle_mitm_browser_capture_traffic_proof_with_probe_and_proxy_scheme(
            platform,
            traffic_proof_probe,
            target_url.as_deref(),
            proof_token.as_deref(),
            proof_log_path.as_deref(),
            &proxy_scheme,
            confirm,
        ),
        LinuxCliCommand::MitmBrowserCaptureApply {
            pac_file_path,
            policy_file_path,
            profile_prefs_file_path,
            snapshot_path,
            proxy_scheme,
            confirm,
            ..
        } => handle_mitm_browser_capture_apply_with_store_and_profile_prefs_and_proxy_scheme(
            platform,
            pac_store,
            pac_file_path.as_deref(),
            policy_file_path.as_deref(),
            profile_prefs_file_path.as_deref(),
            snapshot_path.as_deref(),
            &proxy_scheme,
            confirm,
        ),
        LinuxCliCommand::MitmBrowserCaptureRollback { snapshot_path, .. } => {
            handle_mitm_browser_capture_rollback_with_store(platform, pac_store, snapshot_path)
        }
        other => handle_entrypoint(other, platform),
    }
}

pub fn handle_entrypoint_with_runtime<C, P, E, R>(
    command: LinuxCliCommand,
    platform: &P,
    orchestrator: &RuntimeOrchestrator<C, P, E>,
    reader: &R,
) -> LinuxCliResponse
where
    C: ConfigurationService,
    P: PlatformCapabilityService,
    E: ProxyEngineService,
    R: ConfigReader,
{
    match command {
        LinuxCliCommand::CoreList { .. } => handle_core_list(orchestrator.list_engines()),
        LinuxCliCommand::PrepareConfig { config_path, .. } => {
            handle_prepare_config(orchestrator, reader, config_path.as_deref())
        }
        other => handle_entrypoint(other, platform),
    }
}

pub fn handle_entrypoint_with_runtime_and_lifecycle<C, P, E, R, H>(
    command: LinuxCliCommand,
    platform: &P,
    orchestrator: &RuntimeOrchestrator<C, P, E>,
    reader: &R,
    lifecycle_host: &H,
) -> LinuxCliResponse
where
    C: ConfigurationService,
    P: PlatformCapabilityService,
    E: ProxyEngineService,
    R: ConfigReader,
    H: ForegroundLifecycleHost,
{
    match command {
        LinuxCliCommand::CoreList { .. } => handle_core_list(orchestrator.list_engines()),
        LinuxCliCommand::PrepareConfig { config_path, .. } => {
            handle_prepare_config(orchestrator, reader, config_path.as_deref())
        }
        LinuxCliCommand::Start {
            config_path,
            managed_lifecycle,
            ..
        } => handle_start_foreground(
            orchestrator,
            reader,
            config_path.as_deref(),
            lifecycle_host,
            managed_lifecycle.as_ref(),
        ),
        other => handle_entrypoint(other, platform),
    }
}

pub fn handle_help() -> LinuxCliResponse {
    LinuxCliResponse::success("help").with_help(cli_help_text())
}
