//! Handlers for engines, proxies, subscriptions and the systemd service,
//! and the remote subscription fetcher they use.

use super::*;

pub fn handle_core_list(descriptors: Vec<ProxyEngineDescriptor>) -> LinuxCliResponse {
    let engines = descriptors
        .into_iter()
        .map(|descriptor| LinuxCoreEngineSummary {
            id: descriptor.id,
            kind: format!("{:?}", descriptor.kind),
            version: descriptor.version,
            capabilities: descriptor
                .capabilities
                .into_iter()
                .map(|capability| format!("{capability:?}"))
                .collect(),
        })
        .collect();
    LinuxCliResponse::success("core list").with_core_engines(engines)
}

pub fn handle_node_list(config_path: &str) -> LinuxCliResponse {
    let raw = match std::fs::read_to_string(config_path) {
        Ok(raw) => raw,
        Err(error) => {
            return LinuxCliResponse::failure(
                "node list",
                LinuxCliExitCode::ArgumentOrConfig,
                cli_diagnostic(
                    DiagnosticSeverity::Error,
                    CLI_CONFIG_READ_FAILED_CODE,
                    format!("node list config could not be read: {error}"),
                    SOURCE_CLI_RUNTIME,
                ),
            )
        }
    };
    let document = match config_core::parse_config_document(&raw) {
        Ok(document) => document,
        Err(error) => {
            return domain_error_response(
                "node list",
                LinuxCliExitCode::ArgumentOrConfig,
                error,
                SOURCE_CLI_RUNTIME,
            )
        }
    };
    let mut diagnostics = vec![cli_diagnostic(
        DiagnosticSeverity::Info,
        "cli.node.catalog_listed",
        format!(
            "node catalog contains {} node(s); runtime selection unchanged",
            document.nodes.len()
        ),
        SOURCE_CLI_RUNTIME,
    )];
    let nodes: Vec<LinuxNodeCatalogEntry> = document
        .nodes
        .into_iter()
        .map(|node| LinuxNodeCatalogEntry {
            id: node.id,
            name: node.name,
            protocol: format!("{:?}", node.protocol),
            tags: node.tags,
        })
        .collect();
    diagnostics.extend(nodes.iter().map(|node| {
        cli_diagnostic(
            DiagnosticSeverity::Info,
            "cli.node.entry",
            format!(
                "node_id={} name={} protocol={:?} tags={}",
                node.id,
                node.name,
                node.protocol,
                node.tags.join(",")
            ),
            SOURCE_CLI_RUNTIME,
        )
    }));
    LinuxCliResponse::success("node list")
        .with_diagnostics(diagnostics)
        .with_node_catalog(LinuxNodeCatalogReport {
            schema_version: 1,
            source: "explicit-config".to_string(),
            selection_mutated: false,
            nodes,
        })
}

pub fn handle_node_select(
    config_path: &str,
    node_id: &str,
    selection_path: &str,
    snapshot_path: &str,
    confirm: bool,
) -> LinuxCliResponse {
    if !confirm {
        return LinuxCliResponse::failure(
            "node select",
            LinuxCliExitCode::PlatformDenied,
            cli_diagnostic(
                DiagnosticSeverity::Error,
                "cli.node.selection_confirmation_required",
                "node select requires explicit --confirm",
                SOURCE_CLI_RUNTIME,
            ),
        );
    }
    let selection_path = std::path::Path::new(selection_path);
    let snapshot_path = std::path::Path::new(snapshot_path);
    if !selection_path.is_absolute()
        || !snapshot_path.is_absolute()
        || selection_path == snapshot_path
    {
        return LinuxCliResponse::failure(
            "node select",
            LinuxCliExitCode::ArgumentOrConfig,
            cli_diagnostic(
                DiagnosticSeverity::Error,
                "cli.node.selection_path_invalid",
                "node selection and snapshot paths must be distinct absolute paths",
                SOURCE_CLI_RUNTIME,
            ),
        );
    }
    let raw_config = match std::fs::read_to_string(config_path) {
        Ok(raw) => raw,
        Err(error) => {
            return LinuxCliResponse::failure(
                "node select",
                LinuxCliExitCode::ArgumentOrConfig,
                cli_diagnostic(
                    DiagnosticSeverity::Error,
                    CLI_CONFIG_READ_FAILED_CODE,
                    format!("node selection config could not be read: {error}"),
                    SOURCE_CLI_RUNTIME,
                ),
            )
        }
    };
    let document = match config_core::parse_config_document(&raw_config) {
        Ok(document) => document,
        Err(error) => {
            return domain_error_response(
                "node select",
                LinuxCliExitCode::ArgumentOrConfig,
                error,
                SOURCE_CLI_RUNTIME,
            )
        }
    };
    if !document.nodes.iter().any(|node| node.id == node_id.trim()) {
        return LinuxCliResponse::failure(
            "node select",
            LinuxCliExitCode::ArgumentOrConfig,
            cli_diagnostic(
                DiagnosticSeverity::Error,
                "cli.node.not_found",
                format!("node id was not found in the explicit config: {node_id}"),
                SOURCE_CLI_RUNTIME,
            ),
        );
    }
    if snapshot_path.exists() {
        return LinuxCliResponse::failure(
            "node select",
            LinuxCliExitCode::PlatformDenied,
            cli_diagnostic(
                DiagnosticSeverity::Error,
                "cli.node.snapshot_exists",
                "refusing to overwrite an existing node selection snapshot",
                SOURCE_CLI_RUNTIME,
            ),
        );
    }
    let previous = match std::fs::read_to_string(selection_path) {
        Ok(contents) => contents,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            serde_json::to_string_pretty(&NodeSelectionFile {
                schema_version: NODE_SELECTION_SCHEMA_VERSION,
                node_id: None,
            })
            .expect("node selection empty snapshot serialization should not fail")
        }
        Err(error) => {
            return LinuxCliResponse::failure(
                "node select",
                LinuxCliExitCode::PlatformDenied,
                cli_diagnostic(
                    DiagnosticSeverity::Error,
                    "cli.node.selection_read_failed",
                    format!("node selection could not be read: {error}"),
                    SOURCE_CLI_RUNTIME,
                ),
            )
        }
    };
    if let Err(error) = write_new_file(
        snapshot_path.to_string_lossy().as_ref(),
        previous.as_bytes(),
        "cli.node.snapshot_write_failed",
        "node selection snapshot",
    ) {
        return domain_error_response(
            "node select",
            LinuxCliExitCode::PlatformDenied,
            error,
            SOURCE_CLI_RUNTIME,
        );
    }
    let selected = serde_json::to_string_pretty(&NodeSelectionFile {
        schema_version: NODE_SELECTION_SCHEMA_VERSION,
        node_id: Some(node_id.trim().to_string()),
    })
    .expect("node selection serialization should not fail");
    if let Err(error) = write_replace_file(
        selection_path.to_string_lossy().as_ref(),
        selected.as_bytes(),
        "cli.node.selection_write_failed",
        "node selection",
    ) {
        return domain_error_response(
            "node select",
            LinuxCliExitCode::PlatformDenied,
            error,
            SOURCE_CLI_RUNTIME,
        );
    }
    LinuxCliResponse::success("node select").with_diagnostics(vec![cli_diagnostic(
        DiagnosticSeverity::Info,
        "cli.node.selected",
        format!(
            "node {} selected in {}; snapshot_written=true; runtime selection unchanged",
            node_id.trim(),
            selection_path.display()
        ),
        SOURCE_CLI_RUNTIME,
    )])
}

pub fn handle_node_rollback(
    selection_path: &str,
    snapshot_path: &str,
    confirm: bool,
) -> LinuxCliResponse {
    if !confirm {
        return LinuxCliResponse::failure(
            "node rollback",
            LinuxCliExitCode::PlatformDenied,
            cli_diagnostic(
                DiagnosticSeverity::Error,
                "cli.node.rollback_confirmation_required",
                "node rollback requires explicit --confirm",
                SOURCE_CLI_RUNTIME,
            ),
        );
    }
    let selection = std::path::Path::new(selection_path);
    let snapshot = std::path::Path::new(snapshot_path);
    if !selection.is_absolute() || !snapshot.is_absolute() || selection == snapshot {
        return LinuxCliResponse::failure(
            "node rollback",
            LinuxCliExitCode::ArgumentOrConfig,
            cli_diagnostic(
                DiagnosticSeverity::Error,
                "cli.node.rollback_path_invalid",
                "node selection and snapshot paths must be distinct absolute paths",
                SOURCE_CLI_RUNTIME,
            ),
        );
    }
    let contents = match std::fs::read_to_string(snapshot) {
        Ok(contents) => contents,
        Err(error) => {
            return LinuxCliResponse::failure(
                "node rollback",
                LinuxCliExitCode::ArgumentOrConfig,
                cli_diagnostic(
                    DiagnosticSeverity::Error,
                    "cli.node.rollback_snapshot_read_failed",
                    format!("node selection snapshot could not be read: {error}"),
                    SOURCE_CLI_RUNTIME,
                ),
            )
        }
    };
    let record = match serde_json::from_str::<NodeSelectionFile>(&contents) {
        Ok(record) if record.schema_version == NODE_SELECTION_SCHEMA_VERSION => record,
        Ok(_) => {
            return LinuxCliResponse::failure(
                "node rollback",
                LinuxCliExitCode::ArgumentOrConfig,
                cli_diagnostic(
                    DiagnosticSeverity::Error,
                    "cli.node.rollback_snapshot_schema_unsupported",
                    "node selection snapshot schema version is unsupported",
                    SOURCE_CLI_RUNTIME,
                ),
            )
        }
        Err(error) => {
            return LinuxCliResponse::failure(
                "node rollback",
                LinuxCliExitCode::ArgumentOrConfig,
                cli_diagnostic(
                    DiagnosticSeverity::Error,
                    "cli.node.rollback_snapshot_invalid",
                    format!("node selection snapshot is invalid: {error}"),
                    SOURCE_CLI_RUNTIME,
                ),
            )
        }
    };
    if let Err(error) = write_replace_file(
        selection.to_string_lossy().as_ref(),
        contents.as_bytes(),
        "cli.node.rollback_write_failed",
        "node selection rollback",
    ) {
        return domain_error_response(
            "node rollback",
            LinuxCliExitCode::PlatformDenied,
            error,
            SOURCE_CLI_RUNTIME,
        );
    }
    LinuxCliResponse::success("node rollback").with_diagnostics(vec![cli_diagnostic(
        DiagnosticSeverity::Info,
        "cli.node.rolled_back",
        format!(
            "node selection restored to {}; snapshot_retained=true; selected_node={}",
            selection.display(),
            record.node_id.as_deref().unwrap_or("none")
        ),
        SOURCE_CLI_RUNTIME,
    )])
}

pub fn handle_proxy_apply(
    file_path: &str,
    snapshot_path: &str,
    proxy_url: &str,
    confirm: bool,
) -> LinuxCliResponse {
    match apply_environment_proxy(&LinuxEnvironmentProxyApplyRequest {
        file_path: PathBuf::from(file_path),
        snapshot_path: PathBuf::from(snapshot_path),
        proxy_url: proxy_url.to_string(),
        confirmed: confirm,
    }) {
        Ok(report) => {
            LinuxCliResponse::success("proxy apply").with_diagnostics(vec![cli_diagnostic(
                DiagnosticSeverity::Info,
                "cli.proxy.applied",
                format!(
                    "environment proxy file applied at {}; snapshot_written=true; verified={}",
                    report.file_path.display(),
                    report.verified
                ),
                SOURCE_CLI_RUNTIME,
            )])
        }
        Err(error) => domain_error_response(
            "proxy apply",
            LinuxCliExitCode::PlatformDenied,
            error,
            SOURCE_CLI_RUNTIME,
        ),
    }
}

pub fn handle_proxy_status(file_path: &str) -> LinuxCliResponse {
    match status_environment_proxy(std::path::Path::new(file_path)) {
        Ok(report) => {
            LinuxCliResponse::success("proxy status").with_diagnostics(vec![cli_diagnostic(
                DiagnosticSeverity::Info,
                "cli.proxy.status",
                format!(
                    "environment proxy file exists={} managed_schema_version={:?}",
                    report.exists, report.managed_schema_version
                ),
                SOURCE_CLI_RUNTIME,
            )])
        }
        Err(error) => domain_error_response(
            "proxy status",
            LinuxCliExitCode::ArgumentOrConfig,
            error,
            SOURCE_CLI_RUNTIME,
        ),
    }
}

pub fn handle_proxy_rollback(
    file_path: &str,
    snapshot_path: &str,
    confirm: bool,
) -> LinuxCliResponse {
    match rollback_environment_proxy(&LinuxEnvironmentProxyRollbackRequest {
        file_path: PathBuf::from(file_path),
        snapshot_path: PathBuf::from(snapshot_path),
        confirmed: confirm,
    }) {
        Ok(report) => {
            LinuxCliResponse::success("proxy rollback").with_diagnostics(vec![cli_diagnostic(
                DiagnosticSeverity::Info,
                "cli.proxy.rolled_back",
                format!(
                    "environment proxy rollback restored_previous_file={}; snapshot_retained={}",
                    report.restored_previous_file, report.snapshot_retained
                ),
                SOURCE_CLI_RUNTIME,
            )])
        }
        Err(error) => domain_error_response(
            "proxy rollback",
            LinuxCliExitCode::PlatformDenied,
            error,
            SOURCE_CLI_RUNTIME,
        ),
    }
}

pub fn handle_subscription_command(command: LinuxCliCommand) -> LinuxCliResponse {
    handle_subscription_command_with_fetcher(command, &CommandRemoteSubscriptionFetcher::new())
}

pub fn handle_subscription_command_with_fetcher<F>(
    command: LinuxCliCommand,
    fetcher: &F,
) -> LinuxCliResponse
where
    F: RemoteSubscriptionFetcher,
{
    let store = CommandSubscriptionCatalogStore::new();
    match command {
        LinuxCliCommand::SubscriptionAdd {
            catalog_path,
            snapshot_path,
            source_id,
            location,
            ..
        } => match store.add_source(&SubscriptionCatalogAddRequest {
            catalog_path,
            snapshot_path,
            source: SubscriptionSource {
                id: source_id,
                location,
            },
        }) {
            Ok(report) => LinuxCliResponse::success("subscription add").with_diagnostics(vec![
                cli_diagnostic(
                    DiagnosticSeverity::Info,
                    "cli.subscription.source_added",
                    format!(
                        "subscription source {} added; catalog sources={}",
                        report.source_id, report.source_count
                    ),
                    SOURCE_CLI_RUNTIME,
                ),
            ]),
            Err(error) => subscription_error("subscription add", error),
        },
        LinuxCliCommand::SubscriptionList { catalog_path, .. } => {
            match store.list_sources(&SubscriptionCatalogListRequest { catalog_path }) {
                Ok(report) => {
                    let mut diagnostics = vec![cli_diagnostic(
                        DiagnosticSeverity::Info,
                        "cli.subscription.catalog_listed",
                        format!(
                            "subscription catalog contains {} source(s)",
                            report.source_count
                        ),
                        SOURCE_CLI_RUNTIME,
                    )];
                    diagnostics.extend(report.sources.into_iter().map(|source| {
                        cli_diagnostic(
                            DiagnosticSeverity::Info,
                            "cli.subscription.source",
                            format!(
                                "source_id={} location_kind={}",
                                source.source_id, source.location_kind
                            ),
                            SOURCE_CLI_RUNTIME,
                        )
                    }));
                    LinuxCliResponse::success("subscription list").with_diagnostics(diagnostics)
                }
                Err(error) => subscription_error("subscription list", error),
            }
        }
        LinuxCliCommand::SubscriptionUpdate {
            catalog_path,
            snapshot_path,
            source_id,
            location,
            ..
        } => match store.update_source_with_fetcher(
            &SubscriptionCatalogUpdateRequest {
                catalog_path,
                snapshot_path,
                source_id,
                location,
            },
            fetcher,
        ) {
            Ok(report) => LinuxCliResponse::success("subscription update").with_diagnostics(vec![
                cli_diagnostic(
                    DiagnosticSeverity::Info,
                    "cli.subscription.source_updated",
                    format!(
                        "subscription source {} updated; catalog sources={}; validated nodes={}; added={}; removed={}; changed={}",
                        report.source_id,
                        report.source_count,
                        report.validated_node_count,
                        report.added_node_count,
                        report.removed_node_count,
                        report.changed_node_count
                    ),
                    SOURCE_CLI_RUNTIME,
                ),
            ]),
            Err(error) => subscription_error("subscription update", error),
        },
        LinuxCliCommand::SubscriptionRemove {
            catalog_path,
            snapshot_path,
            source_id,
            ..
        } => match store.remove_source(&SubscriptionCatalogRemoveRequest {
            catalog_path,
            snapshot_path,
            source_id,
        }) {
            Ok(report) => LinuxCliResponse::success("subscription remove").with_diagnostics(vec![
                cli_diagnostic(
                    DiagnosticSeverity::Info,
                    "cli.subscription.source_removed",
                    format!(
                        "subscription source {} removed; catalog sources={}",
                        report.source_id, report.source_count
                    ),
                    SOURCE_CLI_RUNTIME,
                ),
            ]),
            Err(error) => subscription_error("subscription remove", error),
        },
        LinuxCliCommand::SubscriptionSelect {
            catalog_path,
            source_id,
            ..
        } => match store.select_source(&SubscriptionCatalogSelectRequest {
            catalog_path,
            source_id,
        }) {
            Ok(report) => LinuxCliResponse::success("subscription select").with_diagnostics(vec![
                cli_diagnostic(
                    DiagnosticSeverity::Info,
                    "cli.subscription.source_selected",
                    format!("subscription source {} selected", report.source_id),
                    SOURCE_CLI_RUNTIME,
                ),
            ]),
            Err(error) => subscription_error("subscription select", error),
        },
        LinuxCliCommand::SubscriptionRollback {
            catalog_path,
            snapshot_path,
            ..
        } => match store.rollback_catalog(&SubscriptionCatalogRollbackRequest {
            catalog_path,
            snapshot_path,
        }) {
            Ok(report) => {
                LinuxCliResponse::success("subscription rollback").with_diagnostics(vec![
                    cli_diagnostic(
                        DiagnosticSeverity::Info,
                        "cli.subscription.rolled_back",
                        format!(
                            "subscription catalog rolled back; catalog sources={}",
                            report.source_count
                        ),
                        SOURCE_CLI_RUNTIME,
                    ),
                ])
            }
            Err(error) => subscription_error("subscription rollback", error),
        },
        LinuxCliCommand::SubscriptionRefreshStart { catalog_path, status_path, snapshot_path, source_id, interval_seconds, confirm, .. } => match store.refresh_http_source_with_fetcher(&SubscriptionRefreshStartRequest { catalog_path, status_path, snapshot_path, source_id, interval_seconds, confirmed: confirm }, fetcher) {
            Ok(report) => LinuxCliResponse::success("subscription refresh start").with_diagnostics(vec![cli_diagnostic(DiagnosticSeverity::Info, "cli.subscription.refresh_started", format!("subscription refresh enabled=true source_id={} last_attempt={} last_success={} next_attempt={} result={} added={} removed={} changed={}", report.source_id, report.last_attempt, report.last_success.as_deref().unwrap_or("none"), report.next_attempt, report.result, report.added_node_count, report.removed_node_count, report.changed_node_count), SOURCE_CLI_RUNTIME)]),
            Err(error) => subscription_error("subscription refresh start", error),
        },
        LinuxCliCommand::SubscriptionRefreshStatus { status_path, .. } => match store.read_refresh_status(&status_path) {
            Ok(report) => LinuxCliResponse::success("subscription refresh status").with_diagnostics(vec![cli_diagnostic(DiagnosticSeverity::Info, "cli.subscription.refresh_status", format!("subscription refresh enabled={} source_id={} last_attempt={} last_success={} next_attempt={} result={} error_redacted={} error_code={} added={} removed={} changed={}", report.enabled, report.source_id, report.last_attempt, report.last_success.as_deref().unwrap_or("none"), report.next_attempt, report.result, report.error_redacted, report.error_code.as_deref().unwrap_or("none"), report.added_node_count, report.removed_node_count, report.changed_node_count), SOURCE_CLI_RUNTIME)]),
            Err(error) => subscription_error("subscription refresh status", error),
        },
        LinuxCliCommand::SubscriptionRefreshStop { status_path, source_id, confirm, .. } => match store.stop_refresh(&status_path, &source_id, confirm) {
            Ok(report) => LinuxCliResponse::success("subscription refresh stop").with_diagnostics(vec![cli_diagnostic(DiagnosticSeverity::Info, "cli.subscription.refresh_stopped", format!("subscription refresh enabled={} source_id={} result={}", report.enabled, report.source_id, report.result), SOURCE_CLI_RUNTIME)]),
            Err(error) => subscription_error("subscription refresh stop", error),
        },
        LinuxCliCommand::SubscriptionRefreshScheduleInstall { catalog_path, status_path, snapshot_path, source_id, interval_seconds, unit_name, confirm, .. } => {
            if !confirm { return subscription_error("subscription refresh schedule install", DomainError::new(CLI_SUBSCRIPTION_REFRESH_SCHEDULE_CONFIRMATION_REQUIRED_CODE, "subscription refresh schedule installation requires explicit --confirm")); }
            let executable_path = match std::env::current_exe() { Ok(path) => path, Err(_) => return subscription_error("subscription refresh schedule install", DomainError::new(CLI_SUBSCRIPTION_REFRESH_STATUS_WRITE_FAILED_CODE, "current networkcore-linux executable path could not be resolved")) };
            let request = LinuxSubscriptionRefreshScheduleRequest { unit_name, executable_path, catalog_path: std::path::PathBuf::from(catalog_path), status_path: std::path::PathBuf::from(status_path), snapshot_path: std::path::PathBuf::from(snapshot_path), source_id, interval_seconds };
            match render_subscription_refresh_schedule(&request).and_then(|plan| install_subscription_refresh_schedule(&platform_linux::systemd::CommandLinuxSystemdCommandRunner::new(), &request).map(|report| (plan, report))) {
                Ok((plan, report)) => LinuxCliResponse::success("subscription refresh schedule install").with_diagnostics(vec![cli_diagnostic(DiagnosticSeverity::Info, "cli.subscription.refresh_schedule_installed", format!("subscription refresh schedule installed service={} timer={} timer_active={} plan_snapshot={} service_plan_bytes={} timer_plan_bytes={}", report.service_name, report.timer_name, report.timer_active, report.plan_snapshot_path.display(), plan.service_content.len(), plan.timer_content.len()), SOURCE_CLI_RUNTIME)]),
                Err(error) => subscription_error("subscription refresh schedule install", error),
            }
        }
        LinuxCliCommand::SubscriptionRefreshScheduleStatus { unit_name, snapshot_path, .. } => match subscription_refresh_schedule_status(&platform_linux::systemd::CommandLinuxSystemdCommandRunner::new(), &unit_name, std::path::Path::new(&snapshot_path)) {
            Ok(report) => LinuxCliResponse::success("subscription refresh schedule status").with_diagnostics(vec![cli_diagnostic(DiagnosticSeverity::Info, "cli.subscription.refresh_schedule_status", format!("subscription refresh schedule installed={} timer_active={} service={} timer={}", report.installed, report.timer_active, report.service_name, report.timer_name), SOURCE_CLI_RUNTIME)]),
            Err(error) => subscription_error("subscription refresh schedule status", error),
        },
        LinuxCliCommand::SubscriptionRefreshScheduleStop { unit_name, snapshot_path, confirm, .. } => {
            if !confirm { return subscription_error("subscription refresh schedule stop", DomainError::new(CLI_SUBSCRIPTION_REFRESH_SCHEDULE_CONFIRMATION_REQUIRED_CODE, "subscription refresh schedule stop requires explicit --confirm")); }
            match stop_subscription_refresh_schedule(&platform_linux::systemd::CommandLinuxSystemdCommandRunner::new(), &unit_name, std::path::Path::new(&snapshot_path)) {
                Ok(report) => LinuxCliResponse::success("subscription refresh schedule stop").with_diagnostics(vec![cli_diagnostic(DiagnosticSeverity::Info, "cli.subscription.refresh_schedule_stopped", format!("subscription refresh schedule timer stopped service={} timer={}; refresh status was retained", report.service_name, report.timer_name), SOURCE_CLI_RUNTIME)]),
                Err(error) => subscription_error("subscription refresh schedule stop", error),
            }
        }
        LinuxCliCommand::SubscriptionRefreshScheduleUninstall { unit_name, snapshot_path, confirm, .. } => {
            if !confirm { return subscription_error("subscription refresh schedule uninstall", DomainError::new(CLI_SUBSCRIPTION_REFRESH_SCHEDULE_CONFIRMATION_REQUIRED_CODE, "subscription refresh schedule uninstall requires explicit --confirm")); }
            match uninstall_subscription_refresh_schedule(&platform_linux::systemd::CommandLinuxSystemdCommandRunner::new(), &unit_name, std::path::Path::new(&snapshot_path)) {
                Ok(report) => LinuxCliResponse::success("subscription refresh schedule uninstall").with_diagnostics(vec![cli_diagnostic(DiagnosticSeverity::Info, "cli.subscription.refresh_schedule_uninstalled", format!("subscription refresh schedule removed={} service={} timer={}; refresh status was retained", !report.installed, report.service_name, report.timer_name), SOURCE_CLI_RUNTIME)]),
                Err(error) => subscription_error("subscription refresh schedule uninstall", error),
            }
        }
        other => handle_unwired_command(other.name()),
    }
}

pub(crate) fn subscription_error(command: &'static str, error: DomainError) -> LinuxCliResponse {
    domain_error_response(
        command,
        LinuxCliExitCode::ArgumentOrConfig,
        error,
        SOURCE_CLI_RUNTIME,
    )
}

pub fn registered_core_engine_descriptors() -> Vec<ProxyEngineDescriptor> {
    engine_native::NativeProxyEngineService::new().list_engines()
}

#[allow(clippy::too_many_arguments)]
pub fn handle_install_service_plan(
    unit_name: &str,
    description: &str,
    executable_path: &str,
    arguments: &[String],
    service_user: &str,
    service_group: &str,
    state_directory: &str,
    confirm: bool,
) -> LinuxCliResponse {
    if !confirm {
        return LinuxCliResponse::failure(
            "install-service",
            LinuxCliExitCode::PlatformDenied,
            cli_diagnostic(
                DiagnosticSeverity::Error,
                CLI_INSTALL_SERVICE_CONFIRMATION_REQUIRED_CODE,
                "install-service requires explicit --confirm before producing an installation plan",
                SOURCE_CLI_RUNTIME,
            ),
        );
    }
    let request = LinuxManagedServiceUnitRequest {
        unit_name: unit_name.to_string(),
        description: description.to_string(),
        executable_path: PathBuf::from(executable_path),
        arguments: arguments.to_vec(),
        service_user: service_user.to_string(),
        service_group: service_group.to_string(),
        state_directory: PathBuf::from(state_directory),
    };
    match render_systemd_unit(&request) {
        Ok(plan) => LinuxCliResponse::success("install-service")
            .with_service_install(plan)
            .with_diagnostics(vec![cli_diagnostic(
                DiagnosticSeverity::Info,
                "cli.linux.install_service.plan_ready",
                "systemd unit plan rendered; no system files or service state were changed",
                SOURCE_CLI_RUNTIME,
            )]),
        Err(error) => domain_error_response(
            "install-service",
            LinuxCliExitCode::ArgumentOrConfig,
            DomainError::new(CLI_INSTALL_SERVICE_PLAN_INVALID_CODE, error.message),
            SOURCE_CLI_RUNTIME,
        ),
    }
}

pub fn handle_systemd_service_control<R: LinuxSystemdCommandRunner>(
    runner: &R,
    action: LinuxSystemdServiceAction,
    unit_name: &str,
    confirm: bool,
) -> LinuxCliResponse {
    let command = match action {
        LinuxSystemdServiceAction::Start => "service start",
        LinuxSystemdServiceAction::Stop => "service stop",
        LinuxSystemdServiceAction::Restart => "service restart",
        LinuxSystemdServiceAction::Status => "service status",
        LinuxSystemdServiceAction::Reload => "service reload",
        LinuxSystemdServiceAction::DaemonReload => "service daemon-reload",
        LinuxSystemdServiceAction::Enable => "service enable",
    };
    match control_systemd_service(
        runner,
        &LinuxSystemdServiceControlRequest {
            unit_name: unit_name.to_string(),
            action,
            confirmed: confirm,
        },
    ) {
        Ok(report) if report.succeeded => {
            LinuxCliResponse::success(command).with_diagnostics(report.diagnostics)
        }
        Ok(report) => LinuxCliResponse::failure(
            command,
            LinuxCliExitCode::PlatformDenied,
            report.diagnostics.into_iter().next().unwrap_or_else(|| {
                cli_diagnostic(
                    DiagnosticSeverity::Error,
                    "cli.linux.service.control_failed",
                    "systemd service control failed",
                    SOURCE_CLI_RUNTIME,
                )
            }),
        ),
        Err(error) => domain_error_response(
            command,
            LinuxCliExitCode::PlatformDenied,
            error,
            SOURCE_CLI_RUNTIME,
        ),
    }
}

#[allow(clippy::too_many_arguments)]
pub fn handle_install_service_apply(
    unit_name: &str,
    description: &str,
    executable_path: &str,
    arguments: &[String],
    service_user: &str,
    service_group: &str,
    state_directory: &str,
    confirm: bool,
) -> LinuxCliResponse {
    let unit_path = PathBuf::from("/etc/systemd/system").join(unit_name);
    let snapshot_path = PathBuf::from(state_directory)
        .join(".systemd-snapshots")
        .join(format!("{unit_name}.unit"));
    handle_install_service_apply_at(
        unit_name,
        description,
        executable_path,
        arguments,
        service_user,
        service_group,
        state_directory,
        &unit_path,
        &snapshot_path,
        confirm,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn handle_install_service_apply_with_runner<R: LinuxSystemdCommandRunner>(
    runner: &R,
    unit_name: &str,
    description: &str,
    executable_path: &str,
    arguments: &[String],
    service_user: &str,
    service_group: &str,
    state_directory: &str,
    confirm: bool,
) -> LinuxCliResponse {
    let response = handle_install_service_apply(
        unit_name,
        description,
        executable_path,
        arguments,
        service_user,
        service_group,
        state_directory,
        confirm,
    );
    if !response.ok {
        return response;
    }
    let reload = handle_systemd_service_control(
        runner,
        LinuxSystemdServiceAction::DaemonReload,
        unit_name,
        confirm,
    );
    if !reload.ok {
        return LinuxCliResponse::failure(
            "install-service",
            reload.exit_code,
            reload.diagnostics.into_iter().next().unwrap_or_else(|| {
                cli_diagnostic(
                    DiagnosticSeverity::Error,
                    "cli.linux.install_service.reload_failed",
                    "systemd manager reload failed after unit installation",
                    SOURCE_CLI_RUNTIME,
                )
            }),
        );
    }
    response
}

#[allow(clippy::too_many_arguments)]
pub fn handle_install_service_apply_at(
    unit_name: &str,
    description: &str,
    executable_path: &str,
    arguments: &[String],
    service_user: &str,
    service_group: &str,
    state_directory: &str,
    unit_path: &std::path::Path,
    snapshot_path: &std::path::Path,
    confirm: bool,
) -> LinuxCliResponse {
    if !confirm {
        return LinuxCliResponse::failure(
            "install-service",
            LinuxCliExitCode::PlatformDenied,
            cli_diagnostic(
                DiagnosticSeverity::Error,
                CLI_INSTALL_SERVICE_CONFIRMATION_REQUIRED_CODE,
                "install-service requires explicit --confirm before writing a systemd unit",
                SOURCE_CLI_RUNTIME,
            ),
        );
    }
    let request = LinuxManagedServiceUnitRequest {
        unit_name: unit_name.to_string(),
        description: description.to_string(),
        executable_path: PathBuf::from(executable_path),
        arguments: arguments.to_vec(),
        service_user: service_user.to_string(),
        service_group: service_group.to_string(),
        state_directory: PathBuf::from(state_directory),
    };
    let plan = match render_systemd_unit(&request) {
        Ok(plan) => plan,
        Err(error) => {
            return domain_error_response(
                "install-service",
                LinuxCliExitCode::ArgumentOrConfig,
                DomainError::new(CLI_INSTALL_SERVICE_PLAN_INVALID_CODE, error.message),
                SOURCE_CLI_RUNTIME,
            )
        }
    };
    let report = match install_systemd_unit(&LinuxManagedServiceUnitInstallRequest {
        unit_path: unit_path.to_path_buf(),
        snapshot_path: snapshot_path.to_path_buf(),
        content: plan.content.clone(),
    }) {
        Ok(report) => report,
        Err(error) => {
            return domain_error_response(
                "install-service",
                LinuxCliExitCode::PlatformDenied,
                DomainError::new(CLI_INSTALL_SERVICE_WRITE_FAILED_CODE, error.message),
                SOURCE_CLI_RUNTIME,
            )
        }
    };
    LinuxCliResponse::success("install-service")
        .with_service_install(plan)
        .with_diagnostics(vec![cli_diagnostic(
            DiagnosticSeverity::Info,
            "cli.linux.install_service.written",
            format!(
                "systemd unit written and verified at {}; snapshot_written={} snapshot_path={}",
                report.unit_path.display(),
                report.snapshot_written,
                report
                    .snapshot_path
                    .as_deref()
                    .map_or_else(|| "none".to_string(), |path| path.display().to_string())
            ),
            SOURCE_CLI_RUNTIME,
        )])
}

pub fn handle_uninstall_service_plan(
    unit_name: &str,
    state_directory: &str,
    confirm: bool,
) -> LinuxCliResponse {
    if !confirm {
        return LinuxCliResponse::failure(
            "uninstall-service",
            LinuxCliExitCode::PlatformDenied,
            cli_diagnostic(
                DiagnosticSeverity::Error,
                CLI_INSTALL_SERVICE_CONFIRMATION_REQUIRED_CODE,
                "uninstall-service requires explicit --confirm before producing a removal plan",
                SOURCE_CLI_RUNTIME,
            ),
        );
    }
    match plan_systemd_unit_removal(unit_name, PathBuf::from(state_directory).as_path()) {
        Ok(plan) => LinuxCliResponse::success("uninstall-service")
            .with_service_removal(plan)
            .with_diagnostics(vec![cli_diagnostic(
                DiagnosticSeverity::Info,
                "cli.linux.uninstall_service.plan_ready",
                "systemd removal plan rendered; no files or service state were changed",
                SOURCE_CLI_RUNTIME,
            )]),
        Err(error) => domain_error_response(
            "uninstall-service",
            LinuxCliExitCode::ArgumentOrConfig,
            DomainError::new(CLI_INSTALL_SERVICE_PLAN_INVALID_CODE, error.message),
            SOURCE_CLI_RUNTIME,
        ),
    }
}

pub fn handle_uninstall_service_apply(
    unit_name: &str,
    state_directory: &str,
    confirm: bool,
) -> LinuxCliResponse {
    handle_uninstall_service_apply_with_runner(
        &platform_linux::systemd::CommandLinuxSystemdCommandRunner::new(),
        unit_name,
        state_directory,
        confirm,
    )
}

pub fn handle_uninstall_service_apply_with_runner<R: LinuxSystemdCommandRunner>(
    runner: &R,
    unit_name: &str,
    state_directory: &str,
    confirm: bool,
) -> LinuxCliResponse {
    if let Err(error) =
        plan_systemd_unit_removal(unit_name, PathBuf::from(state_directory).as_path())
    {
        return domain_error_response(
            "uninstall-service",
            LinuxCliExitCode::ArgumentOrConfig,
            DomainError::new(CLI_INSTALL_SERVICE_PLAN_INVALID_CODE, error.message),
            SOURCE_CLI_RUNTIME,
        );
    }
    let unit_path = PathBuf::from("/etc/systemd/system").join(unit_name);
    let snapshot_path = PathBuf::from(state_directory)
        .join(".systemd-snapshots")
        .join(format!("{unit_name}.removed.unit"));
    if unit_path.exists() {
        let stop = handle_systemd_service_control(
            runner,
            LinuxSystemdServiceAction::Stop,
            unit_name,
            confirm,
        );
        if !stop.ok {
            return LinuxCliResponse::failure(
                "uninstall-service",
                stop.exit_code,
                stop.diagnostics.into_iter().next().unwrap_or_else(|| {
                    cli_diagnostic(
                        DiagnosticSeverity::Error,
                        "cli.linux.uninstall_service.stop_failed",
                        "systemd service could not be stopped before removal",
                        SOURCE_CLI_RUNTIME,
                    )
                }),
            );
        }
    }
    handle_uninstall_service_apply_at(&unit_path, &snapshot_path, confirm)
}

pub fn handle_uninstall_service_apply_at(
    unit_path: &std::path::Path,
    snapshot_path: &std::path::Path,
    confirm: bool,
) -> LinuxCliResponse {
    match remove_systemd_unit(&LinuxManagedServiceUnitRemovalRequest {
        unit_path: unit_path.to_path_buf(),
        snapshot_path: snapshot_path.to_path_buf(),
        confirmed: confirm,
    }) {
        Ok(report) => {
            LinuxCliResponse::success("uninstall-service").with_diagnostics(vec![cli_diagnostic(
                DiagnosticSeverity::Info,
                "cli.linux.uninstall_service.removed",
                format!(
                    "systemd unit removed={} at {}; snapshot_written={} snapshot_path={}",
                    report.removed,
                    report.unit_path.display(),
                    report.snapshot_written,
                    report
                        .snapshot_path
                        .as_deref()
                        .map_or_else(|| "none".to_string(), |path| path.display().to_string())
                ),
                SOURCE_CLI_RUNTIME,
            )])
        }
        Err(error) => domain_error_response(
            "uninstall-service",
            LinuxCliExitCode::PlatformDenied,
            error,
            SOURCE_CLI_RUNTIME,
        ),
    }
}

pub fn handle_restart_unavailable() -> LinuxCliResponse {
    LinuxCliResponse::failure(
        "restart",
        LinuxCliExitCode::Unavailable,
        cli_diagnostic(
            DiagnosticSeverity::Error,
            CLI_RUNTIME_UNWIRED_CODE,
            "linux managed restart is unavailable until the explicit service control boundary is wired",
            SOURCE_CLI_RUNTIME,
        ),
    )
}

pub fn handle_version() -> LinuxCliResponse {
    LinuxCliResponse::success("version").with_version(env!("CARGO_PKG_VERSION"))
}

pub fn handle_capabilities<P>(platform: &P) -> LinuxCliResponse
where
    P: PlatformCapabilityService,
{
    match platform.status() {
        Ok(status) => {
            let diagnostics = platform_diagnostics(&status);
            LinuxCliResponse::success("capabilities")
                .with_diagnostics(diagnostics)
                .with_platform(status)
        }
        Err(error) => domain_error_response(
            "capabilities",
            LinuxCliExitCode::GeneralFailure,
            error,
            SOURCE_CLI_RUNTIME,
        ),
    }
}

pub fn handle_prepare_config<C, P, E, R>(
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
    let raw_config = match read_required_config("prepare-config", reader, config_path) {
        Ok(raw_config) => raw_config,
        Err(response) => return *response,
    };

    match orchestrator.prepare_config(&raw_config) {
        Ok(prepared) => LinuxCliResponse::success("prepare-config")
            .with_diagnostics(prepared.diagnostics)
            .with_platform(prepared.platform)
            .with_config_profiles(prepared.config.profiles),
        Err(error) => domain_error_response(
            "prepare-config",
            LinuxCliExitCode::ConfigValidation,
            error,
            SOURCE_CLI_CONFIG,
        ),
    }
}

pub trait RemoteSubscriptionFetcher {
    fn fetch_subscription(&self, location: &str) -> DomainResult<String>;
}

#[derive(Debug, Clone, Copy, Default)]
pub struct CommandRemoteSubscriptionFetcher;

impl CommandRemoteSubscriptionFetcher {
    pub const fn new() -> Self {
        Self
    }
}

impl RemoteSubscriptionFetcher for CommandRemoteSubscriptionFetcher {
    fn fetch_subscription(&self, location: &str) -> DomainResult<String> {
        let mut client_builder = reqwest::blocking::Client::builder()
            .redirect(reqwest::redirect::Policy::limited(
                RUN_URL_REMOTE_SUBSCRIPTION_MAX_REDIRECTS,
            ))
            .timeout(Duration::from_secs(
                RUN_URL_REMOTE_SUBSCRIPTION_TIMEOUT_SECONDS,
            ));
        if remote_subscription_location_is_loopback(location) {
            client_builder = client_builder.no_proxy();
        }
        let client = client_builder.build().map_err(|_| {
            DomainError::new(
                CLI_RUN_URL_REMOTE_FETCH_FAILED_CODE,
                "run-url remote subscription client could not be configured",
            )
        })?;
        let response = client
            .get(location)
            .send()
            .and_then(reqwest::blocking::Response::error_for_status)
            .map_err(|_| {
                DomainError::new(
                    CLI_RUN_URL_REMOTE_FETCH_FAILED_CODE,
                    "run-url remote subscription request failed",
                )
            })?;
        if response
            .content_length()
            .is_some_and(|length| length > RUN_URL_REMOTE_SUBSCRIPTION_MAX_BYTES)
        {
            return Err(DomainError::new(
                CLI_RUN_URL_REMOTE_FETCH_LIMIT_EXCEEDED_CODE,
                "run-url remote subscription exceeds the allowed response size",
            ));
        }

        let mut content = Vec::new();
        response
            .take(RUN_URL_REMOTE_SUBSCRIPTION_MAX_BYTES + 1)
            .read_to_end(&mut content)
            .map_err(|_| {
                DomainError::new(
                    CLI_RUN_URL_REMOTE_FETCH_FAILED_CODE,
                    "run-url remote subscription response could not be read",
                )
            })?;
        if content.len() as u64 > RUN_URL_REMOTE_SUBSCRIPTION_MAX_BYTES {
            return Err(DomainError::new(
                CLI_RUN_URL_REMOTE_FETCH_LIMIT_EXCEEDED_CODE,
                "run-url remote subscription exceeds the allowed response size",
            ));
        }

        String::from_utf8(content).map_err(|_| {
            DomainError::new(
                CLI_RUN_URL_REMOTE_FETCH_FAILED_CODE,
                "run-url remote subscription response is not valid UTF-8 text",
            )
        })
    }
}

pub(crate) fn remote_subscription_location_is_loopback(location: &str) -> bool {
    let Ok(url) = reqwest::Url::parse(location) else {
        return false;
    };
    let Some(host) = url.host_str() else {
        return false;
    };
    host == "localhost"
        || host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|address| address.is_loopback())
}

pub(crate) fn read_run_url_subscription_content<F>(input: &str, fetcher: &F) -> DomainResult<String>
where
    F: RemoteSubscriptionFetcher,
{
    if input.starts_with("http://") || input.starts_with("https://") {
        return fetcher.fetch_subscription(input);
    }

    let Some(path) = input.strip_prefix("file://") else {
        if input.starts_with("file:") {
            return Err(DomainError::new(
                CLI_RUN_URL_FILE_URI_INVALID_CODE,
                "run-url file source must use an absolute file:// URI",
            ));
        }
        return Ok(input.to_string());
    };

    if path.is_empty() || !path.starts_with('/') {
        return Err(DomainError::new(
            CLI_RUN_URL_FILE_URI_INVALID_CODE,
            "run-url file source must use an absolute file:// URI",
        ));
    }

    std::fs::read_to_string(path).map_err(|_| {
        DomainError::new(
            CLI_RUN_URL_FILE_READ_FAILED_CODE,
            "run-url subscription file could not be read as UTF-8 text",
        )
    })
}

pub(crate) fn read_subscription_catalog_update_content<F>(
    location: &str,
    fetcher: &F,
) -> DomainResult<String>
where
    F: RemoteSubscriptionFetcher,
{
    let location = location.trim();
    if let Some(content) = location.strip_prefix("inline:") {
        return Ok(content.to_string());
    }
    read_run_url_subscription_content(location, fetcher)
}

pub(crate) fn parse_subscription_catalog_update_nodes<F>(
    source_id: &str,
    location: &str,
    fetcher: &F,
) -> DomainResult<Vec<control_domain::NodeDescriptor>>
where
    F: RemoteSubscriptionFetcher,
{
    let content = read_subscription_catalog_update_content(location, fetcher).map_err(|error| {
        DomainError::new(
            CLI_SUBSCRIPTION_CATALOG_UPDATE_VALIDATION_FAILED_CODE,
            format!(
                "previous subscription source could not be fetched: {}",
                error.code
            ),
        )
    })?;
    let subscription = CoreSubscriptionService::new();
    let document = subscription
        .parse(&RawSubscription {
            source_id: source_id.to_string(),
            content,
        })
        .map_err(|error| {
            DomainError::new(
                CLI_SUBSCRIPTION_CATALOG_UPDATE_VALIDATION_FAILED_CODE,
                format!(
                    "previous subscription source could not be parsed: {}",
                    error.code
                ),
            )
        })?;
    let catalog = subscription.normalize(&document).map_err(|error| {
        DomainError::new(
            CLI_SUBSCRIPTION_CATALOG_UPDATE_VALIDATION_FAILED_CODE,
            format!(
                "previous subscription source could not be normalized: {}",
                error.code
            ),
        )
    })?;
    Ok(catalog.nodes)
}

pub(crate) fn subscription_node_index(
    nodes: &[control_domain::NodeDescriptor],
) -> BTreeMap<String, u64> {
    nodes
        .iter()
        .map(|node| {
            let mut hasher = std::collections::hash_map::DefaultHasher::new();
            format!("{node:?}").hash(&mut hasher);
            (node.id.trim().to_string(), hasher.finish())
        })
        .collect()
}
