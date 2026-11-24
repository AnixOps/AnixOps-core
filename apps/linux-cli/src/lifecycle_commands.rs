//! Handlers for starting the engine in the foreground, managed control,
//! diagnostics and the managed session's status and logs.

use super::*;

pub fn handle_start<C, P, E, R>(
    orchestrator: &RuntimeOrchestrator<C, P, E>,
    reader: &R,
    config_path: Option<&str>,
) -> LinuxCliResponse
where
    C: ConfigurationService,
    P: PlatformCapabilityService,
    E: ProxyEngineService,
    R: ConfigReader,
{
    let raw_config = match read_required_config("start", reader, config_path) {
        Ok(raw_config) => raw_config,
        Err(response) => return *response,
    };

    let request = RuntimeConfigRequest::new(DEFAULT_ENGINE_ID, raw_config);
    match orchestrator.start_runtime(request) {
        Ok(result) => LinuxCliResponse::success("start")
            .with_diagnostics(result.diagnostics)
            .with_platform(result.platform),
        Err(error) => start_error_response(error),
    }
}

pub fn handle_start_foreground<C, P, E, R, H>(
    orchestrator: &RuntimeOrchestrator<C, P, E>,
    reader: &R,
    config_path: Option<&str>,
    lifecycle_host: &H,
    managed_paths: Option<&ManagedForegroundLifecyclePaths>,
) -> LinuxCliResponse
where
    C: ConfigurationService,
    P: PlatformCapabilityService,
    E: ProxyEngineService,
    R: ConfigReader,
    H: ForegroundLifecycleHost,
{
    let raw_config = match read_required_config("start", reader, config_path) {
        Ok(raw_config) => raw_config,
        Err(response) => return *response,
    };

    let managed_recorder = match managed_paths
        .cloned()
        .map(ManagedForegroundLifecycleRecorder::new)
        .transpose()
    {
        Ok(recorder) => recorder,
        Err(error) => {
            return LinuxCliResponse::failure(
                "start",
                LinuxCliExitCode::ArgumentOrConfig,
                cli_diagnostic(
                    DiagnosticSeverity::Error,
                    error.code,
                    error.message,
                    SOURCE_CLI_START,
                ),
            )
        }
    };
    if let Some(recorder) = managed_recorder.as_ref() {
        if let Err(error) = recorder.initialize() {
            return LinuxCliResponse::failure(
                "start",
                LinuxCliExitCode::GeneralFailure,
                cli_diagnostic(
                    DiagnosticSeverity::Error,
                    CLI_START_MANAGED_LIFECYCLE_RECORD_FAILED_CODE,
                    error.message,
                    SOURCE_CLI_START,
                ),
            );
        }
    }
    let runtime_health_snapshot = Arc::new(Mutex::new(ManagedRuntimeHealthSnapshot::default()));
    let managed_control_socket = match managed_recorder
        .as_ref()
        .and_then(|recorder| recorder.paths.control_socket_path.as_deref())
        .map(|path| {
            start_managed_control_socket_with_runtime_snapshot(
                path,
                Arc::new(OsSignalManagedControlInterrupter),
                Some(runtime_health_snapshot.clone()),
            )
        })
        .transpose()
    {
        Ok(socket) => socket,
        Err(error) => {
            if let Some(recorder) = managed_recorder.as_ref() {
                let _ = recorder.transition(
                    "starting",
                    "failed",
                    format!("{}.failed", recorder.paths.snapshot_path),
                );
            }
            return LinuxCliResponse::failure(
                "start",
                LinuxCliExitCode::GeneralFailure,
                cli_diagnostic(
                    DiagnosticSeverity::Error,
                    CLI_MANAGED_CONTROL_SOCKET_START_FAILED_CODE,
                    error.message,
                    SOURCE_CLI_MANAGED_CONTROL,
                ),
            );
        }
    };
    let control_socket_path = managed_recorder
        .as_ref()
        .and_then(|recorder| recorder.paths.control_socket_path.clone());

    let config_digest = redacted_config_digest(&raw_config);
    let request = RuntimeConfigRequest::new(DEFAULT_ENGINE_ID, raw_config);
    let mut response = match orchestrator.start_runtime(request.clone()) {
        Ok(result) => {
            if let Ok(health) = orchestrator.runtime_health(DEFAULT_ENGINE_ID) {
                record_managed_runtime_health(&runtime_health_snapshot, &health, &config_digest, 1);
            }
            if let Some(recorder) = managed_recorder.as_ref() {
                if let Err(error) =
                    recorder.transition("starting", "running", recorder.paths.snapshot_path.clone())
                {
                    let mut response = handle_foreground_lifecycle_with_runtime_reload(
                        result,
                        orchestrator,
                        lifecycle_host,
                        request,
                        runtime_health_snapshot.clone(),
                        config_digest.clone(),
                    );
                    response.ok = false;
                    response.exit_code = LinuxCliExitCode::GeneralFailure;
                    response.diagnostics.push(cli_diagnostic(
                        DiagnosticSeverity::Error,
                        CLI_START_MANAGED_LIFECYCLE_RECORD_FAILED_CODE,
                        error.message,
                        SOURCE_CLI_START,
                    ));
                    return response;
                }
            }
            let mut response = handle_foreground_lifecycle_with_runtime_reload(
                result,
                orchestrator,
                lifecycle_host,
                request,
                runtime_health_snapshot.clone(),
                config_digest.clone(),
            );
            if let Some(recorder) = managed_recorder.as_ref() {
                let terminal_state = if response.exit_code == LinuxCliExitCode::Interrupted {
                    Some((
                        "stopped",
                        format!("{}.stopped", recorder.paths.snapshot_path),
                    ))
                } else if !response.ok {
                    Some(("failed", format!("{}.failed", recorder.paths.snapshot_path)))
                } else {
                    None
                };
                if let Some((next_state, snapshot_path)) = terminal_state {
                    if let Err(error) = recorder.transition("running", next_state, snapshot_path) {
                        response.ok = false;
                        response.diagnostics.push(cli_diagnostic(
                            DiagnosticSeverity::Error,
                            CLI_START_MANAGED_LIFECYCLE_RECORD_FAILED_CODE,
                            error.message,
                            SOURCE_CLI_START,
                        ));
                    }
                }
            }
            response
        }
        Err(error) => {
            let mut response = start_error_response(error);
            if let Some(recorder) = managed_recorder.as_ref() {
                if let Err(record_error) = recorder.transition(
                    "starting",
                    "failed",
                    format!("{}.failed", recorder.paths.snapshot_path),
                ) {
                    response.diagnostics.push(cli_diagnostic(
                        DiagnosticSeverity::Error,
                        CLI_START_MANAGED_LIFECYCLE_RECORD_FAILED_CODE,
                        record_error.message,
                        SOURCE_CLI_START,
                    ));
                }
            }
            response
        }
    };
    if let Some(socket_path) = control_socket_path {
        response.diagnostics.push(cli_diagnostic(
            DiagnosticSeverity::Info,
            CLI_MANAGED_CONTROL_SOCKET_START_READY_CODE,
            format!("managed foreground control socket was active at {socket_path}"),
            SOURCE_CLI_MANAGED_CONTROL,
        ));
    }
    drop(managed_control_socket);
    response
}

pub fn handle_foreground_lifecycle<H>(
    operation: RuntimeOperationResult,
    host: &H,
) -> LinuxCliResponse
where
    H: ForegroundLifecycleHost,
{
    let RuntimeOperationResult {
        platform,
        engine_status,
        mut diagnostics,
        ..
    } = operation;

    diagnostics.push(cli_diagnostic(
        DiagnosticSeverity::Info,
        CLI_START_FOREGROUND_ONLY_CODE,
        "linux start is limited to the current foreground process",
        SOURCE_CLI_START,
    ));

    if engine_status.state != ProxyEngineLifecycleState::Running {
        diagnostics.push(cli_diagnostic(
            DiagnosticSeverity::Error,
            CLI_START_LIFECYCLE_FAILED_CODE,
            "linux runtime did not enter running state before foreground hosting",
            SOURCE_CLI_START,
        ));

        return LinuxCliResponse {
            ok: false,
            command: "start".to_string(),
            exit_code: LinuxCliExitCode::GeneralFailure,
            diagnostics,
            platform: Some(platform),
            config_profiles: Vec::new(),
            version: None,
            help: None,
            managed_foreground_status: None,
            managed_foreground_status_write: None,
            managed_foreground_status_transition: None,
            managed_foreground_status_rollback: None,
            managed_foreground_event: None,
            managed_foreground_event_history: None,
            managed_foreground_event_write: None,
            managed_foreground_log_tail: None,
            mitm_status: None,
            certificate_lifecycle: None,
            browser_capture: None,
            http_rewrite: None,
            service_install: None,
            service_removal: None,
            core_engines: Vec::new(),
            node_catalog: None,
        };
    }

    let request = ForegroundLifecycleRequest { engine_status };
    let outcome = host.run_foreground(&request);
    let ok = outcome.exit_code == LinuxCliExitCode::Success;
    diagnostics.extend(outcome.diagnostics);

    LinuxCliResponse {
        ok,
        command: "start".to_string(),
        exit_code: outcome.exit_code,
        diagnostics,
        platform: Some(platform),
        config_profiles: Vec::new(),
        version: None,
        help: None,
        managed_foreground_status: None,
        managed_foreground_status_write: None,
        managed_foreground_status_transition: None,
        managed_foreground_status_rollback: None,
        managed_foreground_event: None,
        managed_foreground_event_history: None,
        managed_foreground_event_write: None,
        managed_foreground_log_tail: None,
        mitm_status: None,
        certificate_lifecycle: None,
        browser_capture: None,
        http_rewrite: None,
        service_install: None,
        service_removal: None,
        core_engines: Vec::new(),
        node_catalog: None,
    }
}

pub fn handle_foreground_lifecycle_with_runtime_stop<C, P, E, H>(
    operation: RuntimeOperationResult,
    orchestrator: &RuntimeOrchestrator<C, P, E>,
    host: &H,
) -> LinuxCliResponse
where
    C: ConfigurationService,
    P: PlatformCapabilityService,
    E: ProxyEngineService,
    H: ForegroundLifecycleHost,
{
    let engine_id = operation.engine_status.engine_id.clone();
    let mut response = handle_foreground_lifecycle(operation, host);
    if response.exit_code != LinuxCliExitCode::Interrupted {
        return response;
    }

    match orchestrator.stop_runtime(&engine_id) {
        Ok(stop_status) => response.diagnostics.extend(stop_status.diagnostics),
        Err(error) => response.diagnostics.push(cli_diagnostic(
            DiagnosticSeverity::Error,
            CLI_START_RUNTIME_STOP_FAILED_CODE,
            format!(
                "failed to stop linux runtime after foreground interruption: {}",
                error.message
            ),
            SOURCE_CLI_START,
        )),
    }

    response
}

pub(crate) fn handle_foreground_lifecycle_with_runtime_reload<C, P, E, H>(
    mut operation: RuntimeOperationResult,
    orchestrator: &RuntimeOrchestrator<C, P, E>,
    host: &H,
    request: RuntimeConfigRequest,
    runtime_health_snapshot: Arc<Mutex<ManagedRuntimeHealthSnapshot>>,
    config_digest: String,
) -> LinuxCliResponse
where
    C: ConfigurationService,
    P: PlatformCapabilityService,
    E: ProxyEngineService,
    H: ForegroundLifecycleHost,
{
    let mut previous_diagnostics = Vec::new();
    let mut config_version = 1;
    let mut rollback_snapshot = orchestrator
        .prepare_runtime_engine(request.clone())
        .ok()
        .map(|prepared| (prepared.snapshot, config_version));
    loop {
        let engine_id = operation.engine_status.engine_id.clone();
        let mut response = handle_foreground_lifecycle(operation.clone(), host);
        let reload_requested = response
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == CLI_START_MANAGED_CONTROL_RELOAD_REQUESTED_CODE);
        let rollback_requested = response
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == CLI_START_MANAGED_CONTROL_ROLLBACK_REQUESTED_CODE);
        if reload_requested || rollback_requested {
            response
                .diagnostics
                .retain(|diagnostic| diagnostic.code != CLI_START_LIFECYCLE_INTERRUPTED_CODE);
        }
        previous_diagnostics.append(&mut response.diagnostics);
        if !reload_requested && !rollback_requested {
            response.diagnostics = previous_diagnostics;
            if response.exit_code == LinuxCliExitCode::Interrupted {
                match orchestrator.stop_runtime(&engine_id) {
                    Ok(stop_status) => response.diagnostics.extend(stop_status.diagnostics),
                    Err(error) => response.diagnostics.push(cli_diagnostic(
                        DiagnosticSeverity::Error,
                        CLI_START_RUNTIME_STOP_FAILED_CODE,
                        format!(
                            "failed to stop linux runtime after foreground interruption: {}",
                            error.message
                        ),
                        SOURCE_CLI_START,
                    )),
                }
            }
            return response;
        }

        if rollback_requested {
            let expected_config_version =
                MANAGED_CONTROL_EXPECTED_CONFIG_VERSION.swap(0, Ordering::SeqCst);
            if expected_config_version != config_version {
                response.ok = false;
                response.exit_code = LinuxCliExitCode::GeneralFailure;
                response.diagnostics = previous_diagnostics;
                response.diagnostics.push(cli_diagnostic(
                    DiagnosticSeverity::Error,
                    CLI_MANAGED_CONTROL_SOCKET_ROLLBACK_FAILED_CODE,
                    format!(
                        "managed runtime rollback rejected because expected configuration version {expected_config_version} does not match active version {config_version}"
                    ),
                    SOURCE_CLI_MANAGED_CONTROL,
                ));
                return response;
            }
            let Some((snapshot, snapshot_version)) = rollback_snapshot.take() else {
                response.ok = false;
                response.exit_code = LinuxCliExitCode::GeneralFailure;
                response.diagnostics = previous_diagnostics;
                response.diagnostics.push(cli_diagnostic(
                    DiagnosticSeverity::Error,
                    CLI_MANAGED_CONTROL_SOCKET_ROLLBACK_FAILED_CODE,
                    "managed runtime rollback is unavailable because no prior successful configuration snapshot is retained",
                    SOURCE_CLI_MANAGED_CONTROL,
                ));
                return response;
            };
            if snapshot_version >= config_version {
                response.ok = false;
                response.exit_code = LinuxCliExitCode::GeneralFailure;
                response.diagnostics = previous_diagnostics;
                response.diagnostics.push(cli_diagnostic(
                    DiagnosticSeverity::Error,
                    CLI_MANAGED_CONTROL_SOCKET_ROLLBACK_FAILED_CODE,
                    "managed runtime rollback rejected because the retained snapshot version is not older than the active version",
                    SOURCE_CLI_MANAGED_CONTROL,
                ));
                return response;
            }
            match orchestrator.rollback_runtime_engine(ProxyEngineRollbackRequest {
                snapshot,
                expected_state: ProxyEngineLifecycleState::Running,
            }) {
                Ok(restored) => {
                    previous_diagnostics.extend(restored.diagnostics);
                    match orchestrator.runtime_health(&engine_id) {
                        Ok(health) => {
                            config_version = snapshot_version;
                            record_managed_runtime_health(
                                &runtime_health_snapshot,
                                &health,
                                &config_digest,
                                config_version,
                            );
                            previous_diagnostics.push(cli_diagnostic(
                                DiagnosticSeverity::Info,
                                CLI_MANAGED_CONTROL_SOCKET_ROLLBACK_READY_CODE,
                                format!(
                                    "managed runtime rollback restored configuration version {config_version} with runtime health readback"
                                ),
                                SOURCE_CLI_MANAGED_CONTROL,
                            ));
                            continue;
                        }
                        Err(error) => {
                            response.ok = false;
                            response.exit_code = LinuxCliExitCode::GeneralFailure;
                            response.diagnostics = previous_diagnostics;
                            response.diagnostics.push(cli_diagnostic(
                                DiagnosticSeverity::Error,
                                CLI_MANAGED_CONTROL_SOCKET_ROLLBACK_FAILED_CODE,
                                format!(
                                    "managed runtime rollback health readback failed: {}",
                                    error.message
                                ),
                                SOURCE_CLI_MANAGED_CONTROL,
                            ));
                            return response;
                        }
                    }
                }
                Err(error) => {
                    response.ok = false;
                    response.exit_code = LinuxCliExitCode::GeneralFailure;
                    response.diagnostics = previous_diagnostics;
                    response.diagnostics.push(cli_diagnostic(
                        DiagnosticSeverity::Error,
                        CLI_MANAGED_CONTROL_SOCKET_ROLLBACK_FAILED_CODE,
                        format!("managed runtime rollback failed: {}", error.message),
                        SOURCE_CLI_MANAGED_CONTROL,
                    ));
                    return response;
                }
            }
        }

        let prepared_snapshot = orchestrator.prepare_runtime_engine(request.clone());
        let snapshot_failed = prepared_snapshot.is_err();
        match orchestrator.reload_runtime(request.clone()) {
            Ok(reloaded) => {
                operation = reloaded;
                if let Ok(prepared) = prepared_snapshot {
                    rollback_snapshot = Some((prepared.snapshot, config_version));
                }
                config_version += 1;
                match orchestrator.runtime_health(&engine_id) {
                    Ok(health) => record_managed_runtime_health(
                        &runtime_health_snapshot,
                        &health,
                        &config_digest,
                        config_version,
                    ),
                    Err(error) => {
                        response.ok = false;
                        response.exit_code = LinuxCliExitCode::GeneralFailure;
                        response.diagnostics = previous_diagnostics;
                        response.diagnostics.push(cli_diagnostic(
                            DiagnosticSeverity::Error,
                            CLI_START_RUNTIME_RELOAD_FAILED_CODE,
                            format!(
                                "managed runtime reload health readback failed: {}",
                                error.message
                            ),
                            SOURCE_CLI_START,
                        ));
                        return response;
                    }
                }
            }
            Err(error) => {
                response.ok = false;
                response.exit_code = LinuxCliExitCode::GeneralFailure;
                response.diagnostics = previous_diagnostics;
                response.diagnostics.push(cli_diagnostic(
                    DiagnosticSeverity::Error,
                    CLI_START_RUNTIME_RELOAD_FAILED_CODE,
                    format!(
                        "failed to reload linux runtime after managed control request: {}",
                        error.message
                    ),
                    SOURCE_CLI_START,
                ));
                let rollback = prepared_snapshot.clone().and_then(|prepared| {
                    orchestrator.rollback_runtime_engine(ProxyEngineRollbackRequest {
                        snapshot: prepared.snapshot,
                        expected_state: ProxyEngineLifecycleState::Running,
                    })
                });
                let rollback_failed = rollback.is_err();
                match rollback {
                    Ok(restored) => response.diagnostics.extend(restored.diagnostics),
                    Err(rollback_error) => response.diagnostics.push(cli_diagnostic(
                        DiagnosticSeverity::Error,
                        CLI_START_RUNTIME_RELOAD_FAILED_CODE,
                        format!(
                            "managed reload rollback/readback failed: {}",
                            rollback_error.message
                        ),
                        SOURCE_CLI_START,
                    )),
                }
                if snapshot_failed {
                    response.diagnostics.push(cli_diagnostic(
                        DiagnosticSeverity::Error,
                        CLI_START_RUNTIME_RELOAD_FAILED_CODE,
                        "managed reload snapshot could not be captured before mutation",
                        SOURCE_CLI_START,
                    ));
                }
                if rollback_failed {
                    if let Err(stop_error) = orchestrator.stop_runtime(&engine_id) {
                        response.diagnostics.push(cli_diagnostic(
                            DiagnosticSeverity::Error,
                            CLI_START_RUNTIME_STOP_FAILED_CODE,
                            format!(
                                "failed to stop linux runtime after managed reload failure: {}",
                                stop_error.message
                            ),
                            SOURCE_CLI_START,
                        ));
                    }
                }
                return response;
            }
        }
    }
}

pub fn handle_stop() -> LinuxCliResponse {
    LinuxCliResponse::failure(
        "stop",
        LinuxCliExitCode::Unavailable,
        cli_diagnostic(
            DiagnosticSeverity::Error,
            CLI_STOP_UNAVAILABLE_WITHOUT_DAEMON_CODE,
            "linux stop is unavailable without a daemon or control socket",
            SOURCE_CLI_STOP,
        ),
    )
}

pub fn handle_managed_control_stop(socket_path: &str, confirm: bool) -> LinuxCliResponse {
    handle_managed_control_request(socket_path, confirm, ManagedControlRequest::Stop)
}

pub fn handle_managed_control_reload(socket_path: &str, confirm: bool) -> LinuxCliResponse {
    handle_managed_control_request(socket_path, confirm, ManagedControlRequest::Reload)
}

pub fn handle_managed_control_rollback(
    socket_path: &str,
    expected_config_version: u64,
    confirm: bool,
) -> LinuxCliResponse {
    handle_managed_control_request(
        socket_path,
        confirm,
        ManagedControlRequest::Rollback {
            expected_config_version,
        },
    )
}

pub fn handle_managed_control_status(socket_path: &str) -> LinuxCliResponse {
    let socket_path = socket_path.trim();
    if socket_path.is_empty() || !std::path::Path::new(socket_path).is_absolute() {
        return LinuxCliResponse::failure(
            "managed-control status",
            LinuxCliExitCode::ArgumentOrConfig,
            cli_diagnostic(
                DiagnosticSeverity::Error,
                CLI_MANAGED_CONTROL_SOCKET_STATUS_FAILED_CODE,
                "managed foreground control socket path must be absolute",
                SOURCE_CLI_MANAGED_CONTROL,
            ),
        );
    }
    #[cfg(unix)]
    {
        let result = (|| -> std::io::Result<String> {
            let mut stream = UnixStream::connect(socket_path)?;
            stream.set_read_timeout(Some(Duration::from_secs(
                MANAGED_CONTROL_SOCKET_IO_TIMEOUT_SECONDS,
            )))?;
            stream.set_write_timeout(Some(Duration::from_secs(
                MANAGED_CONTROL_SOCKET_IO_TIMEOUT_SECONDS,
            )))?;
            stream.write_all(b"status\n")?;
            stream.shutdown(std::net::Shutdown::Write)?;
            let mut response = String::new();
            (&mut stream).take(1024).read_to_string(&mut response)?;
            Ok(response)
        })();
        match result {
            Ok(response)
                if response.trim()
                    == "status state=unavailable error_code=runtime_status_unavailable" =>
            {
                LinuxCliResponse::failure(
                    "managed-control status",
                    LinuxCliExitCode::Unavailable,
                    cli_diagnostic(
                        DiagnosticSeverity::Error,
                        CLI_MANAGED_CONTROL_SOCKET_STATUS_FAILED_CODE,
                        "managed foreground runtime status is unavailable",
                        SOURCE_CLI_MANAGED_CONTROL,
                    ),
                )
            }
            Ok(response) if response.starts_with("status ") => {
                LinuxCliResponse::success("managed-control status").with_diagnostics(vec![
                    cli_diagnostic(
                        DiagnosticSeverity::Info,
                        CLI_MANAGED_CONTROL_SOCKET_STATUS_READY_CODE,
                        response.trim().to_string(),
                        SOURCE_CLI_MANAGED_CONTROL,
                    ),
                ])
            }
            Ok(_) => LinuxCliResponse::failure(
                "managed-control status",
                LinuxCliExitCode::GeneralFailure,
                cli_diagnostic(
                    DiagnosticSeverity::Error,
                    CLI_MANAGED_CONTROL_SOCKET_STATUS_FAILED_CODE,
                    "managed foreground control socket returned an invalid runtime status response",
                    SOURCE_CLI_MANAGED_CONTROL,
                ),
            ),
            Err(error) => LinuxCliResponse::failure(
                "managed-control status",
                LinuxCliExitCode::GeneralFailure,
                cli_diagnostic(
                    DiagnosticSeverity::Error,
                    CLI_MANAGED_CONTROL_SOCKET_STATUS_FAILED_CODE,
                    format!("managed foreground runtime status failed: {error}"),
                    SOURCE_CLI_MANAGED_CONTROL,
                ),
            ),
        }
    }
    #[cfg(not(unix))]
    LinuxCliResponse::failure(
        "managed-control status",
        LinuxCliExitCode::Unavailable,
        cli_diagnostic(
            DiagnosticSeverity::Error,
            CLI_MANAGED_CONTROL_SOCKET_STATUS_FAILED_CODE,
            "managed foreground control sockets require Unix",
            SOURCE_CLI_MANAGED_CONTROL,
        ),
    )
}

pub(crate) fn handle_managed_control_request(
    socket_path: &str,
    confirm: bool,
    request: ManagedControlRequest,
) -> LinuxCliResponse {
    let operation = request.wire_command();
    let command = format!("managed-control {operation}");
    #[cfg(unix)]
    let ready_code = match request {
        ManagedControlRequest::Stop => CLI_MANAGED_CONTROL_SOCKET_STOP_READY_CODE,
        ManagedControlRequest::Reload => CLI_MANAGED_CONTROL_SOCKET_RELOAD_READY_CODE,
        ManagedControlRequest::Rollback { .. } => CLI_MANAGED_CONTROL_SOCKET_ROLLBACK_READY_CODE,
    };
    let failed_code = match request {
        ManagedControlRequest::Stop => CLI_MANAGED_CONTROL_SOCKET_STOP_FAILED_CODE,
        ManagedControlRequest::Reload => CLI_MANAGED_CONTROL_SOCKET_RELOAD_FAILED_CODE,
        ManagedControlRequest::Rollback { .. } => CLI_MANAGED_CONTROL_SOCKET_ROLLBACK_FAILED_CODE,
    };
    if !confirm {
        return LinuxCliResponse::failure(
            command,
            LinuxCliExitCode::PlatformDenied,
            cli_diagnostic(
                DiagnosticSeverity::Error,
                CLI_MANAGED_CONTROL_SOCKET_AUTHORIZATION_REQUIRED_CODE,
                format!("managed foreground control {operation} requires --confirm"),
                SOURCE_CLI_MANAGED_CONTROL,
            ),
        );
    }
    let socket_path = socket_path.trim();
    if socket_path.is_empty() || !std::path::Path::new(socket_path).is_absolute() {
        return LinuxCliResponse::failure(
            command,
            LinuxCliExitCode::ArgumentOrConfig,
            cli_diagnostic(
                DiagnosticSeverity::Error,
                failed_code,
                "managed foreground control socket path must be absolute",
                SOURCE_CLI_MANAGED_CONTROL,
            ),
        );
    }
    #[cfg(unix)]
    {
        let result = (|| -> std::io::Result<String> {
            let mut stream = UnixStream::connect(socket_path)?;
            stream.set_read_timeout(Some(Duration::from_secs(
                MANAGED_CONTROL_SOCKET_IO_TIMEOUT_SECONDS,
            )))?;
            stream.set_write_timeout(Some(Duration::from_secs(
                MANAGED_CONTROL_SOCKET_IO_TIMEOUT_SECONDS,
            )))?;
            let wire_request = match request {
                ManagedControlRequest::Rollback {
                    expected_config_version,
                } => format!("{operation} {expected_config_version}\n"),
                _ => format!("{operation}\n"),
            };
            stream.write_all(wire_request.as_bytes())?;
            stream.shutdown(std::net::Shutdown::Write)?;
            let mut response = String::new();
            (&mut stream).take(64).read_to_string(&mut response)?;
            Ok(response)
        })();
        match result {
            Ok(response) if response.trim() == "accepted" => LinuxCliResponse::success(command)
                .with_diagnostics(vec![cli_diagnostic(
                    DiagnosticSeverity::Info,
                    ready_code,
                    format!("managed foreground {operation} was accepted by {socket_path}"),
                    SOURCE_CLI_MANAGED_CONTROL,
                )]),
            Ok(response) if response.trim() == "rejected request_pending" => {
                LinuxCliResponse::failure(
                    command,
                    LinuxCliExitCode::GeneralFailure,
                    cli_diagnostic(
                        DiagnosticSeverity::Error,
                        CLI_MANAGED_CONTROL_SOCKET_REQUEST_PENDING_CODE,
                        format!("managed foreground control {operation} is already pending"),
                        SOURCE_CLI_MANAGED_CONTROL,
                    ),
                )
            }
            Ok(_) => LinuxCliResponse::failure(
                command,
                LinuxCliExitCode::GeneralFailure,
                cli_diagnostic(
                    DiagnosticSeverity::Error,
                    failed_code,
                    format!("managed foreground control socket rejected the {operation} request"),
                    SOURCE_CLI_MANAGED_CONTROL,
                ),
            ),
            Err(error) => LinuxCliResponse::failure(
                command,
                LinuxCliExitCode::GeneralFailure,
                cli_diagnostic(
                    DiagnosticSeverity::Error,
                    failed_code,
                    format!("managed foreground control {operation} failed: {error}"),
                    SOURCE_CLI_MANAGED_CONTROL,
                ),
            ),
        }
    }
    #[cfg(not(unix))]
    {
        LinuxCliResponse::failure(
            command,
            LinuxCliExitCode::Unavailable,
            cli_diagnostic(
                DiagnosticSeverity::Error,
                failed_code,
                "managed foreground control sockets require Unix",
                SOURCE_CLI_MANAGED_CONTROL,
            ),
        )
    }
}

pub fn handle_status<P>(platform: &P) -> LinuxCliResponse
where
    P: PlatformCapabilityService,
{
    match platform.status() {
        Ok(status) => {
            let mut diagnostics = platform_diagnostics(&status);
            diagnostics.push(cli_diagnostic(
                DiagnosticSeverity::Warning,
                CLI_STATUS_NO_RUNTIME_CONTEXT_CODE,
                "no runtime context is available for linux status",
                SOURCE_CLI_STATUS,
            ));
            diagnostics.push(cli_diagnostic(
                DiagnosticSeverity::Info,
                CLI_STATUS_PLATFORM_ONLY_CODE,
                "linux status output is limited to platform capability context",
                SOURCE_CLI_STATUS,
            ));

            LinuxCliResponse::success("status")
                .with_diagnostics(diagnostics)
                .with_platform(status)
        }
        Err(error) => domain_error_response(
            "status",
            LinuxCliExitCode::GeneralFailure,
            error,
            SOURCE_CLI_STATUS,
        ),
    }
}

pub fn handle_diagnostics<P>(platform: &P) -> LinuxCliResponse
where
    P: PlatformCapabilityService,
{
    match platform.status() {
        Ok(status) => LinuxCliResponse::success("diagnostics")
            .with_diagnostics(platform_diagnostics(&status))
            .with_platform(status),
        Err(error) => domain_error_response(
            "diagnostics",
            LinuxCliExitCode::GeneralFailure,
            error,
            SOURCE_CLI_RUNTIME,
        ),
    }
}

pub fn handle_managed_foreground_status(status_path: &str) -> LinuxCliResponse {
    let store = CommandManagedForegroundSessionStore::new();
    match store.read_status(&ManagedForegroundSessionStatusRequest {
        status_path: status_path.to_string(),
    }) {
        Ok(report) => {
            LinuxCliResponse::success("managed-status").with_managed_foreground_status(report)
        }
        Err(error) => {
            let exit_code = if error.code == CLI_MANAGED_FOREGROUND_STATUS_PATH_MISSING_CODE {
                LinuxCliExitCode::ArgumentOrConfig
            } else if error.code == CLI_MANAGED_FOREGROUND_STATUS_SCHEMA_UNSUPPORTED_CODE
                || error.code == CLI_MANAGED_FOREGROUND_STATUS_RECORD_INVALID_CODE
            {
                LinuxCliExitCode::ConfigValidation
            } else {
                LinuxCliExitCode::GeneralFailure
            };
            domain_error_response(
                "managed-status",
                exit_code,
                error,
                SOURCE_CLI_MANAGED_FOREGROUND_STATUS,
            )
        }
    }
}

pub fn handle_managed_foreground_status_init(
    status_path: &str,
    session_id: &str,
    engine_id: &str,
    state: &str,
) -> LinuxCliResponse {
    let store = CommandManagedForegroundSessionStore::new();
    match store.write_status(&ManagedForegroundSessionStatusWriteRequest {
        status_path: status_path.to_string(),
        session_id: session_id.to_string(),
        engine_id: engine_id.to_string(),
        state: state.to_string(),
    }) {
        Ok(report) => LinuxCliResponse::success("managed-status init")
            .with_managed_foreground_status_write(report),
        Err(error) => {
            let exit_code = if error.code == CLI_MANAGED_FOREGROUND_STATUS_PATH_MISSING_CODE {
                LinuxCliExitCode::ArgumentOrConfig
            } else if error.code == CLI_MANAGED_FOREGROUND_STATUS_RECORD_INVALID_CODE {
                LinuxCliExitCode::ConfigValidation
            } else {
                LinuxCliExitCode::GeneralFailure
            };
            domain_error_response(
                "managed-status init",
                exit_code,
                error,
                SOURCE_CLI_MANAGED_FOREGROUND_STATUS,
            )
        }
    }
}

pub fn handle_managed_foreground_status_transition(
    status_path: &str,
    snapshot_path: &str,
    expected_state: &str,
    next_state: &str,
) -> LinuxCliResponse {
    let store = CommandManagedForegroundSessionStore::new();
    match store.transition_status(&ManagedForegroundSessionStatusTransitionRequest {
        status_path: status_path.to_string(),
        snapshot_path: snapshot_path.to_string(),
        expected_state: expected_state.to_string(),
        next_state: next_state.to_string(),
    }) {
        Ok(report) => LinuxCliResponse::success("managed-status transition")
            .with_managed_foreground_status_transition(report),
        Err(error) => {
            let exit_code = if error.code == CLI_MANAGED_FOREGROUND_STATUS_PATH_MISSING_CODE
                || error.code == CLI_MANAGED_FOREGROUND_STATUS_SNAPSHOT_PATH_MISSING_CODE
                || error.code == CLI_MANAGED_FOREGROUND_STATUS_TRANSITION_INVALID_CODE
            {
                LinuxCliExitCode::ArgumentOrConfig
            } else if error.code == CLI_MANAGED_FOREGROUND_STATUS_SCHEMA_UNSUPPORTED_CODE
                || error.code == CLI_MANAGED_FOREGROUND_STATUS_RECORD_INVALID_CODE
                || error.code == CLI_MANAGED_FOREGROUND_STATUS_STATE_CONFLICT_CODE
            {
                LinuxCliExitCode::ConfigValidation
            } else {
                LinuxCliExitCode::GeneralFailure
            };
            domain_error_response(
                "managed-status transition",
                exit_code,
                error,
                SOURCE_CLI_MANAGED_FOREGROUND_STATUS,
            )
        }
    }
}

pub fn handle_managed_foreground_status_rollback(
    status_path: &str,
    snapshot_path: &str,
    expected_state: &str,
) -> LinuxCliResponse {
    let store = CommandManagedForegroundSessionStore::new();
    match store.rollback_status(&ManagedForegroundSessionStatusRollbackRequest {
        status_path: status_path.to_string(),
        snapshot_path: snapshot_path.to_string(),
        expected_state: expected_state.to_string(),
    }) {
        Ok(report) => LinuxCliResponse::success("managed-status rollback")
            .with_managed_foreground_status_rollback(report),
        Err(error) => {
            let exit_code = if error.code == CLI_MANAGED_FOREGROUND_STATUS_PATH_MISSING_CODE
                || error.code == CLI_MANAGED_FOREGROUND_STATUS_SNAPSHOT_PATH_MISSING_CODE
                || error.code == CLI_MANAGED_FOREGROUND_STATUS_PATH_CONFLICT_CODE
                || error.code == CLI_MANAGED_FOREGROUND_STATUS_ROLLBACK_INVALID_CODE
            {
                LinuxCliExitCode::ArgumentOrConfig
            } else if error.code == CLI_MANAGED_FOREGROUND_STATUS_SCHEMA_UNSUPPORTED_CODE
                || error.code == CLI_MANAGED_FOREGROUND_STATUS_RECORD_INVALID_CODE
                || error.code == CLI_MANAGED_FOREGROUND_STATUS_STATE_CONFLICT_CODE
            {
                LinuxCliExitCode::ConfigValidation
            } else {
                LinuxCliExitCode::GeneralFailure
            };
            domain_error_response(
                "managed-status rollback",
                exit_code,
                error,
                SOURCE_CLI_MANAGED_FOREGROUND_STATUS,
            )
        }
    }
}

pub fn handle_managed_foreground_event(event_path: &str) -> LinuxCliResponse {
    let store = CommandManagedForegroundSessionEventStore::new();
    match store.read_event(&ManagedForegroundSessionEventRequest {
        event_path: event_path.to_string(),
    }) {
        Ok(report) => {
            LinuxCliResponse::success("managed-event").with_managed_foreground_event(report)
        }
        Err(error) => {
            let exit_code = if error.code == CLI_MANAGED_FOREGROUND_EVENT_PATH_MISSING_CODE {
                LinuxCliExitCode::ArgumentOrConfig
            } else if error.code == CLI_MANAGED_FOREGROUND_EVENT_SCHEMA_UNSUPPORTED_CODE
                || error.code == CLI_MANAGED_FOREGROUND_EVENT_RECORD_INVALID_CODE
            {
                LinuxCliExitCode::ConfigValidation
            } else {
                LinuxCliExitCode::GeneralFailure
            };
            domain_error_response(
                "managed-event",
                exit_code,
                error,
                SOURCE_CLI_MANAGED_FOREGROUND_EVENT,
            )
        }
    }
}

pub fn handle_managed_foreground_event_history(
    event_directory: &str,
    session_id: Option<&str>,
    event_kind: Option<&str>,
    state: Option<&str>,
    cursor: usize,
    limit: usize,
) -> LinuxCliResponse {
    let store = CommandManagedForegroundSessionEventStore::new();
    match store.list_event_history(&ManagedForegroundSessionEventHistoryRequest {
        event_directory: event_directory.to_string(),
        session_id: session_id.map(str::to_string),
        event_kind: event_kind.map(str::to_string),
        state: state.map(str::to_string),
        cursor,
        limit,
    }) {
        Ok(report) => LinuxCliResponse::success("managed-event list")
            .with_managed_foreground_event_history(report),
        Err(error) => {
            let exit_code = if error.code == CLI_MANAGED_FOREGROUND_EVENT_DIRECTORY_MISSING_CODE {
                LinuxCliExitCode::ArgumentOrConfig
            } else if error.code == CLI_MANAGED_FOREGROUND_EVENT_HISTORY_QUERY_INVALID_CODE
                || error.code == CLI_MANAGED_FOREGROUND_EVENT_SCHEMA_UNSUPPORTED_CODE
                || error.code == CLI_MANAGED_FOREGROUND_EVENT_RECORD_INVALID_CODE
            {
                LinuxCliExitCode::ConfigValidation
            } else {
                LinuxCliExitCode::GeneralFailure
            };
            domain_error_response(
                "managed-event list",
                exit_code,
                error,
                SOURCE_CLI_MANAGED_FOREGROUND_EVENT,
            )
        }
    }
}

pub fn handle_managed_foreground_event_init(
    event_path: &str,
    session_id: &str,
    engine_id: &str,
    event_id: &str,
    event_kind: &str,
    state: &str,
    recorded_at: &str,
) -> LinuxCliResponse {
    let store = CommandManagedForegroundSessionEventStore::new();
    match store.write_event(&ManagedForegroundSessionEventWriteRequest {
        event_path: event_path.to_string(),
        session_id: session_id.to_string(),
        engine_id: engine_id.to_string(),
        event_id: event_id.to_string(),
        event_kind: event_kind.to_string(),
        state: state.to_string(),
        recorded_at: recorded_at.to_string(),
    }) {
        Ok(report) => LinuxCliResponse::success("managed-event init")
            .with_managed_foreground_event_write(report),
        Err(error) => {
            let exit_code = if error.code == CLI_MANAGED_FOREGROUND_EVENT_PATH_MISSING_CODE {
                LinuxCliExitCode::ArgumentOrConfig
            } else if error.code == CLI_MANAGED_FOREGROUND_EVENT_RECORD_INVALID_CODE {
                LinuxCliExitCode::ConfigValidation
            } else {
                LinuxCliExitCode::GeneralFailure
            };
            domain_error_response(
                "managed-event init",
                exit_code,
                error,
                SOURCE_CLI_MANAGED_FOREGROUND_EVENT,
            )
        }
    }
}

pub fn handle_managed_foreground_log_tail(log_path: &str, line_limit: usize) -> LinuxCliResponse {
    let store = CommandManagedForegroundSessionLogStore::new();
    match store.read_tail(&ManagedForegroundSessionLogTailRequest {
        log_path: log_path.to_string(),
        line_limit,
    }) {
        Ok(report) => {
            LinuxCliResponse::success("managed-log").with_managed_foreground_log_tail(report)
        }
        Err(error) => {
            let exit_code = if error.code == CLI_MANAGED_FOREGROUND_LOG_PATH_MISSING_CODE
                || error.code == CLI_MANAGED_FOREGROUND_LOG_QUERY_INVALID_CODE
            {
                LinuxCliExitCode::ArgumentOrConfig
            } else if error.code == CLI_MANAGED_FOREGROUND_LOG_LIMIT_EXCEEDED_CODE {
                LinuxCliExitCode::ConfigValidation
            } else {
                LinuxCliExitCode::GeneralFailure
            };
            domain_error_response(
                "managed-log",
                exit_code,
                error,
                SOURCE_CLI_MANAGED_FOREGROUND_LOG,
            )
        }
    }
}
