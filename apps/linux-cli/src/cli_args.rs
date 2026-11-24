//! Command-line parsing: options, subcommands and their values.

use super::*;

#[derive(Debug, Default)]
pub(crate) struct ParsedOptions {
    pub(crate) browser: Option<String>,
    pub(crate) config_path: Option<String>,
    pub(crate) profile_dir: Option<String>,
    pub(crate) profile_prefs_file_path: Option<String>,
    pub(crate) url: Option<String>,
    pub(crate) method: Option<String>,
    pub(crate) phase: Option<String>,
    pub(crate) status_code: Option<u16>,
    pub(crate) headers: Vec<String>,
    pub(crate) body: Option<String>,
    pub(crate) target_url: Option<String>,
    pub(crate) cert_file_path: Option<String>,
    pub(crate) key_file_path: Option<String>,
    pub(crate) trust_file_path: Option<String>,
    pub(crate) mitm_plugin_path: Option<String>,
    pub(crate) mitm_ca_certificate_path: Option<String>,
    pub(crate) mitm_ca_private_key_path: Option<String>,
    pub(crate) script_runner_path: Option<String>,
    pub(crate) script_maps: Vec<String>,
    pub(crate) script_store_path: Option<String>,
    pub(crate) node_binary: Option<String>,
    pub(crate) managed_status_path: Option<String>,
    pub(crate) managed_snapshot_path: Option<String>,
    pub(crate) managed_event_directory: Option<String>,
    pub(crate) managed_control_socket_path: Option<String>,
    pub(crate) profile_trust_file_path: Option<String>,
    pub(crate) pac_file_path: Option<String>,
    pub(crate) policy_file_path: Option<String>,
    pub(crate) proof_token: Option<String>,
    pub(crate) proof_log_path: Option<String>,
    pub(crate) proxy_scheme: Option<String>,
    pub(crate) managed_event_session_id: Option<String>,
    pub(crate) managed_event_kind: Option<String>,
    pub(crate) managed_event_state: Option<String>,
    pub(crate) managed_event_cursor: Option<usize>,
    pub(crate) managed_event_limit: Option<usize>,
    pub(crate) managed_log_line_limit: Option<usize>,
    pub(crate) file_path: Option<String>,
    pub(crate) catalog_path: Option<String>,
    pub(crate) refresh_status_path: Option<String>,
    pub(crate) refresh_interval_seconds: Option<u64>,
    pub(crate) refresh_schedule_unit_name: Option<String>,
    pub(crate) selection_path: Option<String>,
    pub(crate) source_id: Option<String>,
    pub(crate) selected_node_id: Option<String>,
    pub(crate) listen_host: Option<String>,
    pub(crate) listen_port: Option<u16>,
    pub(crate) snapshot_path: Option<String>,
    pub(crate) confirm: bool,
    pub(crate) enable_https_mitm: bool,
    pub(crate) enable_script_runtime: bool,
    pub(crate) service_unit_name: Option<String>,
    pub(crate) service_description: Option<String>,
    pub(crate) service_executable_path: Option<String>,
    pub(crate) service_arguments: Vec<String>,
    pub(crate) service_user: Option<String>,
    pub(crate) service_group: Option<String>,
    pub(crate) service_state_directory: Option<String>,
    pub(crate) format: OutputFormat,
}

pub fn parse_args<I, S>(args: I) -> Result<LinuxCliCommand, LinuxCliParseError>
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    let mut args = args.into_iter().map(Into::into);
    let Some(command) = args.next() else {
        return Err(parse_error(
            CLI_COMMAND_MISSING_CODE,
            "missing linux CLI command; run networkcore-linux help",
        ));
    };
    let rest = args.collect::<Vec<_>>();

    match command.as_str() {
        "help" | "--help" | "-h" => {
            let options = parse_options(&rest)?;
            Ok(LinuxCliCommand::Help {
                format: options.format,
            })
        }
        "version" => {
            let options = parse_options(&rest)?;
            Ok(LinuxCliCommand::Version {
                format: options.format,
            })
        }
        "capabilities" => {
            let options = parse_options(&rest)?;
            Ok(LinuxCliCommand::Capabilities {
                format: options.format,
            })
        }
        "prepare-config" => {
            let options = parse_options(&rest)?;
            Ok(LinuxCliCommand::PrepareConfig {
                config_path: options.config_path,
                format: options.format,
            })
        }
        "validate" => parse_validate_command(&rest),
        "core" => parse_core_command(&rest),
        "subscription" => parse_subscription_command(&rest),
        "node" => parse_node_command(&rest),
        "proxy" => parse_proxy_command(&rest),
        "service" => parse_service_command(&rest),
        "connect" | "start" => {
            let options = parse_options(&rest)?;
            if command == "connect" && (options.confirm || options.service_unit_name.is_some()) {
                return Ok(LinuxCliCommand::ServiceControl {
                    action: LinuxSystemdServiceAction::Start,
                    unit_name: options
                        .service_unit_name
                        .unwrap_or_else(|| "networkcore.service".to_string()),
                    confirm: options.confirm,
                    format: options.format,
                });
            }
            let managed_lifecycle = match (
                options.managed_status_path,
                options.managed_snapshot_path,
                options.managed_event_directory,
            ) {
                (Some(status_path), Some(snapshot_path), Some(event_directory)) => {
                    Some(ManagedForegroundLifecyclePaths {
                        status_path,
                        snapshot_path,
                        event_directory,
                        control_socket_path: options.managed_control_socket_path,
                    })
                }
                (None, None, None) if options.managed_control_socket_path.is_none() => None,
                _ => {
                    return Err(parse_error(
                        CLI_ARGUMENT_VALUE_MISSING_CODE,
                        "managed start requires --managed-status, --managed-snapshot, and --managed-events together",
                    ))
                }
            };
            Ok(LinuxCliCommand::Start {
                config_path: options.config_path,
                mitm_plugin_path: options.mitm_plugin_path,
                mitm_ca_certificate_path: options.mitm_ca_certificate_path,
                mitm_ca_private_key_path: options.mitm_ca_private_key_path,
                enable_https_mitm: options.enable_https_mitm,
                enable_script_runtime: options.enable_script_runtime,
                script_runner_path: options.script_runner_path,
                script_maps: options.script_maps,
                script_store_path: options.script_store_path,
                node_binary: options.node_binary,
                managed_lifecycle,
                confirm: options.confirm,
                format: options.format,
            })
        }
        "disconnect" | "stop" => {
            if command == "stop"
                && rest
                    .iter()
                    .any(|argument| argument == "--managed-control-socket")
            {
                let (socket_path, confirm, format) = parse_managed_control_options(&rest, "stop")?;
                return Ok(LinuxCliCommand::ManagedControlStop {
                    socket_path,
                    confirm,
                    format,
                });
            }
            let options = parse_options(&rest)?;
            if command == "disconnect" && (options.confirm || options.service_unit_name.is_some()) {
                return Ok(LinuxCliCommand::ServiceControl {
                    action: LinuxSystemdServiceAction::Stop,
                    unit_name: options
                        .service_unit_name
                        .unwrap_or_else(|| "networkcore.service".to_string()),
                    confirm: options.confirm,
                    format: options.format,
                });
            }
            Ok(LinuxCliCommand::Stop {
                format: options.format,
            })
        }
        "reload"
            if rest
                .iter()
                .any(|argument| argument == "--managed-control-socket") =>
        {
            let (socket_path, confirm, format) = parse_managed_control_options(&rest, "reload")?;
            Ok(LinuxCliCommand::ManagedControlReload {
                socket_path,
                confirm,
                format,
            })
        }
        "rollback"
            if rest
                .iter()
                .any(|argument| argument == "--managed-control-socket") =>
        {
            let (socket_path, expected_config_version, confirm, format) =
                parse_managed_control_rollback_options(&rest)?;
            Ok(LinuxCliCommand::ManagedControlRollback {
                socket_path,
                expected_config_version,
                confirm,
                format,
            })
        }
        "restart" => {
            let options = parse_options(&rest)?;
            if options.confirm || options.service_unit_name.is_some() {
                return Ok(LinuxCliCommand::ServiceControl {
                    action: LinuxSystemdServiceAction::Restart,
                    unit_name: options
                        .service_unit_name
                        .unwrap_or_else(|| "networkcore.service".to_string()),
                    confirm: options.confirm,
                    format: options.format,
                });
            }
            Ok(LinuxCliCommand::Restart {
                config_path: options.config_path,
                format: options.format,
            })
        }
        "reload" => {
            let options = parse_options(&rest)?;
            Ok(LinuxCliCommand::ServiceControl {
                action: LinuxSystemdServiceAction::Reload,
                unit_name: options
                    .service_unit_name
                    .unwrap_or_else(|| "networkcore.service".to_string()),
                confirm: options.confirm,
                format: options.format,
            })
        }
        "status" => {
            let options = parse_options(&rest)?;
            if let Some(socket_path) = options.managed_control_socket_path {
                return Ok(LinuxCliCommand::ManagedControlStatus {
                    socket_path,
                    format: options.format,
                });
            }
            if let Some(unit_name) = options.service_unit_name {
                return Ok(LinuxCliCommand::ServiceControl {
                    action: LinuxSystemdServiceAction::Status,
                    unit_name,
                    confirm: false,
                    format: options.format,
                });
            }
            Ok(LinuxCliCommand::Status {
                format: options.format,
            })
        }
        "managed-status" => parse_managed_status_command(&rest),
        "managed-event" => parse_managed_event_command(&rest),
        "managed-log" | "logs" => parse_managed_log_command(&rest),
        "diagnostics" => {
            let options = parse_options(&rest)?;
            Ok(LinuxCliCommand::Diagnostics {
                format: options.format,
            })
        }
        "mitm" => parse_mitm_command(&rest),
        "install-service" => {
            let options = parse_options(&rest)?;
            Ok(LinuxCliCommand::InstallService {
                unit_name: options
                    .service_unit_name
                    .unwrap_or_else(|| "networkcore.service".to_string()),
                description: options
                    .service_description
                    .unwrap_or_else(|| "NetworkCore managed proxy".to_string()),
                executable_path: options.service_executable_path.ok_or_else(|| {
                    parse_error(
                        CLI_ARGUMENT_VALUE_MISSING_CODE,
                        "install-service requires --service-executable <absolute-path>",
                    )
                })?,
                arguments: options.service_arguments,
                service_user: options
                    .service_user
                    .unwrap_or_else(|| "networkcore".to_string()),
                service_group: options
                    .service_group
                    .unwrap_or_else(|| "networkcore".to_string()),
                state_directory: options
                    .service_state_directory
                    .unwrap_or_else(|| "/var/lib/networkcore".to_string()),
                confirm: options.confirm,
                format: options.format,
            })
        }
        "uninstall-service" => {
            let options = parse_options(&rest)?;
            Ok(LinuxCliCommand::UninstallService {
                unit_name: options
                    .service_unit_name
                    .unwrap_or_else(|| "networkcore.service".to_string()),
                state_directory: options
                    .service_state_directory
                    .unwrap_or_else(|| "/var/lib/networkcore".to_string()),
                confirm: options.confirm,
                format: options.format,
            })
        }
        "run-url" => parse_run_url_command(&rest),
        "run-catalog" => parse_run_catalog_command(&rest),
        _ => Err(parse_error(
            CLI_ARGUMENT_UNKNOWN_CODE,
            format!("unknown linux CLI command: {command}; run networkcore-linux help"),
        )),
    }
}

pub(crate) fn parse_service_command(
    args: &[String],
) -> Result<LinuxCliCommand, LinuxCliParseError> {
    let Some(action) = args.first().map(String::as_str) else {
        return Err(parse_error(
            CLI_ARGUMENT_VALUE_MISSING_CODE,
            "service requires start, stop, restart, reload, or status",
        ));
    };
    let action = match action {
        "start" => LinuxSystemdServiceAction::Start,
        "stop" => LinuxSystemdServiceAction::Stop,
        "restart" => LinuxSystemdServiceAction::Restart,
        "reload" => LinuxSystemdServiceAction::Reload,
        "status" => LinuxSystemdServiceAction::Status,
        _ => {
            return Err(parse_error(
                CLI_ARGUMENT_UNKNOWN_CODE,
                format!("unknown service action: {action}"),
            ))
        }
    };
    let options = parse_options(&args[1..])?;
    Ok(LinuxCliCommand::ServiceControl {
        action,
        unit_name: options
            .service_unit_name
            .unwrap_or_else(|| "networkcore.service".to_string()),
        confirm: options.confirm,
        format: options.format,
    })
}

pub(crate) fn parse_node_command(args: &[String]) -> Result<LinuxCliCommand, LinuxCliParseError> {
    let Some(subcommand) = args.first().map(String::as_str) else {
        return Err(parse_error(
            CLI_ARGUMENT_VALUE_MISSING_CODE,
            "node requires list, select, or rollback",
        ));
    };
    if subcommand != "list" && subcommand != "select" && subcommand != "rollback" {
        return Err(parse_error(
            CLI_ARGUMENT_UNKNOWN_CODE,
            format!("unknown node subcommand: {subcommand}"),
        ));
    }
    let options = parse_options(&args[1..])?;
    if subcommand == "list" {
        let config_path = options.config_path.ok_or_else(|| {
            parse_error(
                CLI_ARGUMENT_VALUE_MISSING_CODE,
                "node list requires --config <absolute-path>",
            )
        })?;
        return Ok(LinuxCliCommand::NodeList {
            config_path,
            format: options.format,
        });
    }
    if subcommand == "rollback" {
        let selection_path = options.selection_path.ok_or_else(|| {
            parse_error(
                CLI_ARGUMENT_VALUE_MISSING_CODE,
                "node rollback requires --selection <absolute-path>",
            )
        })?;
        let snapshot_path = options.snapshot_path.ok_or_else(|| {
            parse_error(
                CLI_ARGUMENT_VALUE_MISSING_CODE,
                "node rollback requires --snapshot <absolute-path>",
            )
        })?;
        return Ok(LinuxCliCommand::NodeRollback {
            selection_path,
            snapshot_path,
            confirm: options.confirm,
            format: options.format,
        });
    }
    let config_path = options.config_path.ok_or_else(|| {
        parse_error(
            CLI_ARGUMENT_VALUE_MISSING_CODE,
            "node select requires --config <absolute-path>",
        )
    })?;
    let node_id = options.source_id.ok_or_else(|| {
        parse_error(
            CLI_ARGUMENT_VALUE_MISSING_CODE,
            "node select requires --source-id <node-id>",
        )
    })?;
    let selection_path = options.selection_path.ok_or_else(|| {
        parse_error(
            CLI_ARGUMENT_VALUE_MISSING_CODE,
            "node select requires --selection <absolute-path>",
        )
    })?;
    let snapshot_path = options.snapshot_path.ok_or_else(|| {
        parse_error(
            CLI_ARGUMENT_VALUE_MISSING_CODE,
            "node select requires --snapshot <absolute-path>",
        )
    })?;
    Ok(LinuxCliCommand::NodeSelect {
        config_path,
        node_id,
        selection_path,
        snapshot_path,
        confirm: options.confirm,
        format: options.format,
    })
}

pub(crate) fn parse_proxy_command(args: &[String]) -> Result<LinuxCliCommand, LinuxCliParseError> {
    let Some(subcommand) = args.first().map(String::as_str) else {
        return Err(parse_error(
            CLI_ARGUMENT_VALUE_MISSING_CODE,
            "proxy requires apply, status, or rollback",
        ));
    };
    let options = parse_options(&args[1..])?;
    let file_path = options.file_path.ok_or_else(|| {
        parse_error(
            CLI_ARGUMENT_VALUE_MISSING_CODE,
            "proxy commands require --file <absolute-path>",
        )
    })?;
    match subcommand {
        "apply" => Ok(LinuxCliCommand::ProxyApply {
            file_path,
            snapshot_path: options.snapshot_path.ok_or_else(|| {
                parse_error(
                    CLI_ARGUMENT_VALUE_MISSING_CODE,
                    "proxy apply requires --snapshot <absolute-path>",
                )
            })?,
            proxy_url: options.url.ok_or_else(|| {
                parse_error(
                    CLI_ARGUMENT_VALUE_MISSING_CODE,
                    "proxy apply requires --url <proxy-url>",
                )
            })?,
            confirm: options.confirm,
            format: options.format,
        }),
        "status" => Ok(LinuxCliCommand::ProxyStatus {
            file_path,
            format: options.format,
        }),
        "rollback" => Ok(LinuxCliCommand::ProxyRollback {
            file_path,
            snapshot_path: options.snapshot_path.ok_or_else(|| {
                parse_error(
                    CLI_ARGUMENT_VALUE_MISSING_CODE,
                    "proxy rollback requires --snapshot <absolute-path>",
                )
            })?,
            confirm: options.confirm,
            format: options.format,
        }),
        _ => Err(parse_error(
            CLI_ARGUMENT_UNKNOWN_CODE,
            format!("unknown proxy subcommand: {subcommand}"),
        )),
    }
}

pub(crate) fn parse_options(args: &[String]) -> Result<ParsedOptions, LinuxCliParseError> {
    let mut options = ParsedOptions::default();
    let mut index = 0;

    while index < args.len() {
        match args[index].as_str() {
            "--config" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    return Err(parse_error(
                        CLI_ARGUMENT_VALUE_MISSING_CODE,
                        "--config requires a path value",
                    ));
                };
                options.config_path = Some(value.clone());
            }
            "--catalog" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    return Err(parse_error(
                        CLI_ARGUMENT_VALUE_MISSING_CODE,
                        "--catalog requires a subscription catalog path",
                    ));
                };
                options.catalog_path = Some(value.clone());
            }
            "--refresh-status" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    return Err(parse_error(
                        CLI_ARGUMENT_VALUE_MISSING_CODE,
                        "--refresh-status requires an explicit status path",
                    ));
                };
                options.refresh_status_path = Some(value.clone());
            }
            "--interval-seconds" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    return Err(parse_error(
                        CLI_ARGUMENT_VALUE_MISSING_CODE,
                        "--interval-seconds requires an integer",
                    ));
                };
                options.refresh_interval_seconds = Some(value.parse::<u64>().map_err(|_| {
                    parse_error(
                        CLI_ARGUMENT_VALUE_MISSING_CODE,
                        "--interval-seconds requires an integer",
                    )
                })?);
            }
            "--unit-name" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    return Err(parse_error(
                        CLI_ARGUMENT_VALUE_MISSING_CODE,
                        "--unit-name requires a systemd unit base name",
                    ));
                };
                options.refresh_schedule_unit_name = Some(value.clone());
            }
            "--file" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    return Err(parse_error(
                        CLI_ARGUMENT_VALUE_MISSING_CODE,
                        "--file requires an absolute file path",
                    ));
                };
                options.file_path = Some(value.clone());
            }
            "--selection" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    return Err(parse_error(
                        CLI_ARGUMENT_VALUE_MISSING_CODE,
                        "--selection requires an absolute selection path",
                    ));
                };
                options.selection_path = Some(value.clone());
            }
            "--source-id" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    return Err(parse_error(
                        CLI_ARGUMENT_VALUE_MISSING_CODE,
                        "--source-id requires a subscription source id",
                    ));
                };
                options.source_id = Some(value.clone());
            }
            "--browser" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    return Err(parse_error(
                        CLI_ARGUMENT_VALUE_MISSING_CODE,
                        "--browser requires a browser executable value",
                    ));
                };
                options.browser = Some(value.clone());
            }
            "--profile-dir" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    return Err(parse_error(
                        CLI_ARGUMENT_VALUE_MISSING_CODE,
                        "--profile-dir requires a dedicated profile directory path value",
                    ));
                };
                options.profile_dir = Some(value.clone());
            }
            "--url" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    return Err(parse_error(
                        CLI_ARGUMENT_VALUE_MISSING_CODE,
                        "--url requires an HTTP/TLS rewrite target URL",
                    ));
                };
                options.url = Some(value.clone());
            }
            "--method" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    return Err(parse_error(
                        CLI_ARGUMENT_VALUE_MISSING_CODE,
                        "--method requires an HTTP method value",
                    ));
                };
                options.method = Some(value.to_ascii_uppercase());
            }
            "--phase" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    return Err(parse_error(
                        CLI_ARGUMENT_VALUE_MISSING_CODE,
                        "--phase requires request or response",
                    ));
                };
                options.phase = Some(parse_http_rewrite_phase_name(value)?);
            }
            "--status-code" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    return Err(parse_error(
                        CLI_ARGUMENT_VALUE_MISSING_CODE,
                        "--status-code requires a numeric HTTP status code",
                    ));
                };
                options.status_code = Some(parse_http_status_code(value)?);
            }
            "--header" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    return Err(parse_error(
                        CLI_ARGUMENT_VALUE_MISSING_CODE,
                        "--header requires a Name: Value header",
                    ));
                };
                options.headers.push(value.clone());
            }
            "--body" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    return Err(parse_error(
                        CLI_ARGUMENT_VALUE_MISSING_CODE,
                        "--body requires a plain HTTP body value",
                    ));
                };
                options.body = Some(value.clone());
            }
            "--target-url" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    return Err(parse_error(
                        CLI_ARGUMENT_VALUE_MISSING_CODE,
                        "--target-url requires a browser target URL value",
                    ));
                };
                options.target_url = Some(value.clone());
            }
            "--cert-file" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    return Err(parse_error(
                        CLI_ARGUMENT_VALUE_MISSING_CODE,
                        "--cert-file requires a MITM certificate artifact path",
                    ));
                };
                options.cert_file_path = Some(value.clone());
            }
            "--key-file" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    return Err(parse_error(
                        CLI_ARGUMENT_VALUE_MISSING_CODE,
                        "--key-file requires a MITM private key artifact path",
                    ));
                };
                options.key_file_path = Some(value.clone());
            }
            "--trust-file" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    return Err(parse_error(
                        CLI_ARGUMENT_VALUE_MISSING_CODE,
                        "--trust-file requires a Linux trust file path",
                    ));
                };
                options.trust_file_path = Some(value.clone());
            }
            "--mitm-plugin" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    return Err(parse_error(
                        CLI_ARGUMENT_VALUE_MISSING_CODE,
                        "--mitm-plugin requires the path of your own MITM plugin",
                    ));
                };
                options.mitm_plugin_path = Some(value.clone());
            }
            "--mitm-ca-cert" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    return Err(parse_error(
                        CLI_ARGUMENT_VALUE_MISSING_CODE,
                        "--mitm-ca-cert requires a CA certificate PEM path",
                    ));
                };
                options.mitm_ca_certificate_path = Some(value.clone());
            }
            "--mitm-ca-key" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    return Err(parse_error(
                        CLI_ARGUMENT_VALUE_MISSING_CODE,
                        "--mitm-ca-key requires a CA private key PEM path",
                    ));
                };
                options.mitm_ca_private_key_path = Some(value.clone());
            }
            "--enable-https-mitm" => {
                options.enable_https_mitm = true;
            }
            "--enable-script-runtime" => {
                options.enable_script_runtime = true;
            }
            "--script-runner" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    return Err(parse_error(
                        CLI_ARGUMENT_VALUE_MISSING_CODE,
                        "--script-runner requires a local Node contract runner path",
                    ));
                };
                options.script_runner_path = Some(value.clone());
            }
            "--script-map" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    return Err(parse_error(
                        CLI_ARGUMENT_VALUE_MISSING_CODE,
                        "--script-map requires script-url=local-file mapping",
                    ));
                };
                options.script_maps.push(value.clone());
            }
            "--script-store" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    return Err(parse_error(
                        CLI_ARGUMENT_VALUE_MISSING_CODE,
                        "--script-store requires a persistent-store JSON path",
                    ));
                };
                options.script_store_path = Some(value.clone());
            }
            "--node-binary" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    return Err(parse_error(
                        CLI_ARGUMENT_VALUE_MISSING_CODE,
                        "--node-binary requires a Node executable path or command",
                    ));
                };
                options.node_binary = Some(value.clone());
            }
            "--managed-status" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    return Err(parse_error(
                        CLI_ARGUMENT_VALUE_MISSING_CODE,
                        "--managed-status requires a managed foreground status record path",
                    ));
                };
                options.managed_status_path = Some(value.clone());
            }
            "--managed-snapshot" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    return Err(parse_error(
                        CLI_ARGUMENT_VALUE_MISSING_CODE,
                        "--managed-snapshot requires a managed foreground status snapshot path",
                    ));
                };
                options.managed_snapshot_path = Some(value.clone());
            }
            "--managed-events" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    return Err(parse_error(
                        CLI_ARGUMENT_VALUE_MISSING_CODE,
                        "--managed-events requires a managed foreground event directory",
                    ));
                };
                options.managed_event_directory = Some(value.clone());
            }
            "--managed-control-socket" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    return Err(parse_error(
                        CLI_ARGUMENT_VALUE_MISSING_CODE,
                        "--managed-control-socket requires an absolute Unix socket path",
                    ));
                };
                options.managed_control_socket_path = Some(value.clone());
            }
            "--profile-trust-file" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    return Err(parse_error(
                        CLI_ARGUMENT_VALUE_MISSING_CODE,
                        "--profile-trust-file requires a dedicated profile trust artifact path",
                    ));
                };
                options.profile_trust_file_path = Some(value.clone());
            }
            "--pac-file" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    return Err(parse_error(
                        CLI_ARGUMENT_VALUE_MISSING_CODE,
                        "--pac-file requires a browser capture PAC file path",
                    ));
                };
                options.pac_file_path = Some(value.clone());
            }
            "--policy-file" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    return Err(parse_error(
                        CLI_ARGUMENT_VALUE_MISSING_CODE,
                        "--policy-file requires a browser policy file path",
                    ));
                };
                options.policy_file_path = Some(value.clone());
            }
            "--profile-prefs-file" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    return Err(parse_error(
                        CLI_ARGUMENT_VALUE_MISSING_CODE,
                        "--profile-prefs-file requires a Firefox dedicated profile user.js path",
                    ));
                };
                options.profile_prefs_file_path = Some(value.clone());
            }
            "--proof-token" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    return Err(parse_error(
                        CLI_ARGUMENT_VALUE_MISSING_CODE,
                        "--proof-token requires a browser traffic proof token value",
                    ));
                };
                options.proof_token = Some(value.clone());
            }
            "--proof-log" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    return Err(parse_error(
                        CLI_ARGUMENT_VALUE_MISSING_CODE,
                        "--proof-log requires a browser traffic proof log path",
                    ));
                };
                options.proof_log_path = Some(value.clone());
            }
            "--proxy-scheme" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    return Err(parse_error(
                        CLI_ARGUMENT_VALUE_MISSING_CODE,
                        "--proxy-scheme requires http or socks5",
                    ));
                };
                options.proxy_scheme = Some(parse_browser_capture_proxy_scheme(value)?);
            }
            "--session-id" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    return Err(parse_error(
                        CLI_ARGUMENT_VALUE_MISSING_CODE,
                        "--session-id requires a managed event session id",
                    ));
                };
                options.managed_event_session_id = Some(value.clone());
            }
            "--event-kind" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    return Err(parse_error(
                        CLI_ARGUMENT_VALUE_MISSING_CODE,
                        "--event-kind requires a managed event kind",
                    ));
                };
                options.managed_event_kind = Some(value.clone());
            }
            "--state" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    return Err(parse_error(
                        CLI_ARGUMENT_VALUE_MISSING_CODE,
                        "--state requires a managed event state",
                    ));
                };
                options.managed_event_state = Some(value.clone());
            }
            "--cursor" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    return Err(parse_error(
                        CLI_ARGUMENT_VALUE_MISSING_CODE,
                        "--cursor requires a non-negative managed event history offset",
                    ));
                };
                options.managed_event_cursor = Some(parse_managed_event_history_cursor(value)?);
            }
            "--limit" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    return Err(parse_error(
                        CLI_ARGUMENT_VALUE_MISSING_CODE,
                        "--limit requires a managed event history page size",
                    ));
                };
                options.managed_event_limit = Some(parse_managed_event_history_limit(value)?);
            }
            "--tail-lines" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    return Err(parse_error(
                        CLI_ARGUMENT_VALUE_MISSING_CODE,
                        "--tail-lines requires a managed log line count",
                    ));
                };
                options.managed_log_line_limit = Some(parse_managed_log_tail_limit(value)?);
            }
            "--service-unit" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    return Err(parse_error(
                        CLI_ARGUMENT_VALUE_MISSING_CODE,
                        "--service-unit requires a systemd unit name",
                    ));
                };
                options.service_unit_name = Some(value.clone());
            }
            "--service-description" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    return Err(parse_error(
                        CLI_ARGUMENT_VALUE_MISSING_CODE,
                        "--service-description requires a service description",
                    ));
                };
                options.service_description = Some(value.clone());
            }
            "--service-executable" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    return Err(parse_error(
                        CLI_ARGUMENT_VALUE_MISSING_CODE,
                        "--service-executable requires an absolute executable path",
                    ));
                };
                options.service_executable_path = Some(value.clone());
            }
            "--service-arg" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    return Err(parse_error(
                        CLI_ARGUMENT_VALUE_MISSING_CODE,
                        "--service-arg requires one service argument",
                    ));
                };
                options.service_arguments.push(value.clone());
            }
            "--service-user" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    return Err(parse_error(
                        CLI_ARGUMENT_VALUE_MISSING_CODE,
                        "--service-user requires a non-root account name",
                    ));
                };
                options.service_user = Some(value.clone());
            }
            "--service-group" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    return Err(parse_error(
                        CLI_ARGUMENT_VALUE_MISSING_CODE,
                        "--service-group requires a non-root group name",
                    ));
                };
                options.service_group = Some(value.clone());
            }
            "--service-state-dir" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    return Err(parse_error(
                        CLI_ARGUMENT_VALUE_MISSING_CODE,
                        "--service-state-dir requires an absolute state directory path",
                    ));
                };
                options.service_state_directory = Some(value.clone());
            }
            "--node-id" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    return Err(parse_error(
                        CLI_ARGUMENT_VALUE_MISSING_CODE,
                        "--node-id requires a node id from the subscription catalog",
                    ));
                };
                options.selected_node_id = Some(value.clone());
            }
            "--confirm" => {
                options.confirm = true;
            }
            "--snapshot" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    return Err(parse_error(
                        CLI_ARGUMENT_VALUE_MISSING_CODE,
                        "--snapshot requires a rollback snapshot path value",
                    ));
                };
                options.snapshot_path = Some(value.clone());
            }
            "--listen-host" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    return Err(parse_error(
                        CLI_ARGUMENT_VALUE_MISSING_CODE,
                        "--listen-host requires an address value",
                    ));
                };
                options.listen_host = Some(value.clone());
            }
            "--listen-port" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    return Err(parse_error(
                        CLI_ARGUMENT_VALUE_MISSING_CODE,
                        "--listen-port requires a port value",
                    ));
                };
                options.listen_port = Some(parse_listen_port(value)?);
            }
            "--format" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    return Err(parse_error(
                        CLI_ARGUMENT_VALUE_MISSING_CODE,
                        "--format requires text or json",
                    ));
                };
                options.format = parse_output_format(value)?;
            }
            unknown => {
                return Err(parse_error(
                    CLI_ARGUMENT_UNKNOWN_CODE,
                    format!("unknown linux CLI argument: {unknown}"),
                ));
            }
        }

        index += 1;
    }

    Ok(options)
}

pub(crate) fn parse_managed_control_options(
    args: &[String],
    operation: &str,
) -> Result<(String, bool, OutputFormat), LinuxCliParseError> {
    let mut socket_path = None;
    let mut confirm = false;
    let mut format = OutputFormat::Text;
    let mut index = 0;

    while index < args.len() {
        match args[index].as_str() {
            "--managed-control-socket" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    return Err(parse_error(
                        CLI_ARGUMENT_VALUE_MISSING_CODE,
                        "--managed-control-socket requires an absolute Unix socket path",
                    ));
                };
                if value.starts_with("--") {
                    return Err(parse_error(
                        CLI_ARGUMENT_VALUE_MISSING_CODE,
                        "--managed-control-socket requires an absolute Unix socket path",
                    ));
                }
                if socket_path.replace(value.clone()).is_some() {
                    return Err(parse_error(
                        CLI_ARGUMENT_UNKNOWN_CODE,
                        format!("managed control {operation} accepts exactly one --managed-control-socket path"),
                    ));
                }
            }
            "--confirm" => confirm = true,
            "--format" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    return Err(parse_error(
                        CLI_ARGUMENT_VALUE_MISSING_CODE,
                        "--format requires text or json",
                    ));
                };
                format = parse_output_format(value)?;
            }
            argument => {
                return Err(parse_error(
                    CLI_ARGUMENT_UNKNOWN_CODE,
                    format!(
                        "managed control {operation} only accepts --managed-control-socket, --confirm, and --format; received {argument}"
                    ),
                ));
            }
        }
        index += 1;
    }

    socket_path
        .ok_or_else(|| {
            parse_error(
                CLI_ARGUMENT_VALUE_MISSING_CODE,
                format!(
                    "managed control {operation} requires --managed-control-socket <absolute-path>"
                ),
            )
        })
        .map(|socket_path| (socket_path, confirm, format))
}

pub(crate) fn parse_managed_control_rollback_options(
    args: &[String],
) -> Result<(String, u64, bool, OutputFormat), LinuxCliParseError> {
    let mut socket_path = None;
    let mut expected_config_version = None;
    let mut confirm = false;
    let mut format = OutputFormat::Text;
    let mut index = 0;

    while index < args.len() {
        match args[index].as_str() {
            "--managed-control-socket" => {
                index += 1;
                let Some(value) = args.get(index).filter(|value| !value.starts_with("--")) else {
                    return Err(parse_error(
                        CLI_ARGUMENT_VALUE_MISSING_CODE,
                        "--managed-control-socket requires an absolute Unix socket path",
                    ));
                };
                if socket_path.replace(value.clone()).is_some() {
                    return Err(parse_error(
                        CLI_ARGUMENT_UNKNOWN_CODE,
                        "managed control rollback accepts exactly one --managed-control-socket path",
                    ));
                }
            }
            "--expected-config-version" => {
                index += 1;
                let Some(value) = args.get(index).filter(|value| !value.starts_with("--")) else {
                    return Err(parse_error(
                        CLI_ARGUMENT_VALUE_MISSING_CODE,
                        "--expected-config-version requires a positive configuration version",
                    ));
                };
                let parsed = value
                    .parse::<u64>()
                    .ok()
                    .filter(|value| *value > 0)
                    .ok_or_else(|| {
                        parse_error(
                            CLI_ARGUMENT_VALUE_MISSING_CODE,
                            "--expected-config-version requires a positive configuration version",
                        )
                    })?;
                if expected_config_version.replace(parsed).is_some() {
                    return Err(parse_error(
                        CLI_ARGUMENT_UNKNOWN_CODE,
                        "managed control rollback accepts exactly one --expected-config-version value",
                    ));
                }
            }
            "--confirm" => confirm = true,
            "--format" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    return Err(parse_error(
                        CLI_ARGUMENT_VALUE_MISSING_CODE,
                        "--format requires text or json",
                    ));
                };
                format = parse_output_format(value)?;
            }
            argument => {
                return Err(parse_error(
                    CLI_ARGUMENT_UNKNOWN_CODE,
                    format!(
                        "managed control rollback only accepts --managed-control-socket, --expected-config-version, --confirm, and --format; received {argument}"
                    ),
                ));
            }
        }
        index += 1;
    }

    let socket_path = socket_path.ok_or_else(|| {
        parse_error(
            CLI_ARGUMENT_VALUE_MISSING_CODE,
            "managed control rollback requires --managed-control-socket <absolute-path>",
        )
    })?;
    let expected_config_version = expected_config_version.ok_or_else(|| {
        parse_error(
            CLI_ARGUMENT_VALUE_MISSING_CODE,
            "managed control rollback requires --expected-config-version <positive-integer>",
        )
    })?;
    Ok((socket_path, expected_config_version, confirm, format))
}

pub(crate) fn parse_run_url_command(
    args: &[String],
) -> Result<LinuxCliCommand, LinuxCliParseError> {
    let Some(url) = args.first() else {
        return Err(parse_error(
            CLI_ARGUMENT_VALUE_MISSING_CODE,
            "run-url requires a proxy URL argument",
        ));
    };
    if url.starts_with("--") {
        return Err(parse_error(
            CLI_ARGUMENT_VALUE_MISSING_CODE,
            "run-url requires a proxy URL before options",
        ));
    }
    let options = parse_options(&args[1..])?;

    Ok(LinuxCliCommand::RunUrl {
        url: url.clone(),
        selected_node_id: options.selected_node_id,
        listen_host: options
            .listen_host
            .unwrap_or_else(|| "127.0.0.1".to_string()),
        listen_port: options.listen_port.unwrap_or(7890),
        format: options.format,
    })
}

pub(crate) fn parse_validate_command(
    args: &[String],
) -> Result<LinuxCliCommand, LinuxCliParseError> {
    let Some(config_path) = args.first() else {
        return Err(parse_error(
            CLI_ARGUMENT_VALUE_MISSING_CODE,
            "validate requires an explicit config path",
        ));
    };
    if config_path.starts_with("--") {
        return Err(parse_error(
            CLI_ARGUMENT_VALUE_MISSING_CODE,
            "validate requires a config path before options",
        ));
    }
    let options = parse_options(&args[1..])?;
    Ok(LinuxCliCommand::PrepareConfig {
        config_path: Some(config_path.clone()),
        format: options.format,
    })
}

pub(crate) fn parse_subscription_command(
    args: &[String],
) -> Result<LinuxCliCommand, LinuxCliParseError> {
    let Some(subcommand) = args.first() else {
        return Err(parse_error(
            CLI_ARGUMENT_VALUE_MISSING_CODE,
            "subscription requires add, list, update, remove, select, rollback, or refresh",
        ));
    };
    if subcommand == "refresh" {
        return parse_subscription_refresh_command(&args[1..]);
    }
    let options = parse_options(&args[1..])?;
    let catalog_path = options.catalog_path.clone().ok_or_else(|| {
        parse_error(
            CLI_ARGUMENT_VALUE_MISSING_CODE,
            "subscription commands require --catalog <absolute-path>",
        )
    })?;
    let snapshot_path = || {
        options.snapshot_path.clone().ok_or_else(|| {
            parse_error(
                CLI_ARGUMENT_VALUE_MISSING_CODE,
                "subscription mutation requires --snapshot <absolute-path>",
            )
        })
    };
    let source_id = || {
        options.source_id.clone().ok_or_else(|| {
            parse_error(
                CLI_ARGUMENT_VALUE_MISSING_CODE,
                "subscription source command requires --source-id <id>",
            )
        })
    };
    let location = || {
        options.url.clone().ok_or_else(|| {
            parse_error(
                CLI_ARGUMENT_VALUE_MISSING_CODE,
                "subscription source mutation requires --url <location>",
            )
        })
    };
    match subcommand.as_str() {
        "add" => Ok(LinuxCliCommand::SubscriptionAdd {
            catalog_path,
            snapshot_path: snapshot_path()?,
            source_id: source_id()?,
            location: location()?,
            format: options.format,
        }),
        "list" => Ok(LinuxCliCommand::SubscriptionList {
            catalog_path,
            format: options.format,
        }),
        "update" => Ok(LinuxCliCommand::SubscriptionUpdate {
            catalog_path,
            snapshot_path: snapshot_path()?,
            source_id: source_id()?,
            location: location()?,
            format: options.format,
        }),
        "remove" => Ok(LinuxCliCommand::SubscriptionRemove {
            catalog_path,
            snapshot_path: snapshot_path()?,
            source_id: source_id()?,
            format: options.format,
        }),
        "select" => Ok(LinuxCliCommand::SubscriptionSelect {
            catalog_path,
            source_id: source_id()?,
            format: options.format,
        }),
        "rollback" => Ok(LinuxCliCommand::SubscriptionRollback {
            catalog_path,
            snapshot_path: snapshot_path()?,
            format: options.format,
        }),
        _ => Err(parse_error(
            CLI_ARGUMENT_UNKNOWN_CODE,
            format!("unknown subscription subcommand: {subcommand}"),
        )),
    }
}

pub(crate) fn parse_subscription_refresh_command(
    args: &[String],
) -> Result<LinuxCliCommand, LinuxCliParseError> {
    let Some(operation) = args.first() else {
        return Err(parse_error(
            CLI_ARGUMENT_VALUE_MISSING_CODE,
            "subscription refresh requires start, status, stop, or schedule",
        ));
    };
    if operation == "schedule" {
        return parse_subscription_refresh_schedule_command(&args[1..]);
    }
    let options = parse_options(&args[1..])?;
    let status_path = options.refresh_status_path.ok_or_else(|| {
        parse_error(
            CLI_ARGUMENT_VALUE_MISSING_CODE,
            "subscription refresh requires --refresh-status <path>",
        )
    })?;
    match operation.as_str() {
        "status" => Ok(LinuxCliCommand::SubscriptionRefreshStatus {
            status_path,
            format: options.format,
        }),
        "stop" => Ok(LinuxCliCommand::SubscriptionRefreshStop {
            status_path,
            source_id: options.source_id.ok_or_else(|| {
                parse_error(
                    CLI_ARGUMENT_VALUE_MISSING_CODE,
                    "subscription refresh stop requires --source-id <id>",
                )
            })?,
            confirm: options.confirm,
            format: options.format,
        }),
        "start" => Ok(LinuxCliCommand::SubscriptionRefreshStart {
            catalog_path: options.catalog_path.ok_or_else(|| {
                parse_error(
                    CLI_ARGUMENT_VALUE_MISSING_CODE,
                    "subscription refresh start requires --catalog <path>",
                )
            })?,
            status_path,
            snapshot_path: options.snapshot_path.ok_or_else(|| {
                parse_error(
                    CLI_ARGUMENT_VALUE_MISSING_CODE,
                    "subscription refresh start requires --snapshot <path>",
                )
            })?,
            source_id: options.source_id.ok_or_else(|| {
                parse_error(
                    CLI_ARGUMENT_VALUE_MISSING_CODE,
                    "subscription refresh start requires --source-id <id>",
                )
            })?,
            interval_seconds: options
                .refresh_interval_seconds
                .unwrap_or(SUBSCRIPTION_REFRESH_MIN_INTERVAL_SECONDS),
            confirm: options.confirm,
            format: options.format,
        }),
        _ => Err(parse_error(
            CLI_ARGUMENT_UNKNOWN_CODE,
            "subscription refresh accepts start, status, stop, or schedule",
        )),
    }
}

pub(crate) fn parse_subscription_refresh_schedule_command(
    args: &[String],
) -> Result<LinuxCliCommand, LinuxCliParseError> {
    let Some(operation) = args.first() else {
        return Err(parse_error(
            CLI_ARGUMENT_VALUE_MISSING_CODE,
            "subscription refresh schedule requires install, status, stop, or uninstall",
        ));
    };
    let options = parse_options(&args[1..])?;
    let unit_name = || {
        options.refresh_schedule_unit_name.clone().ok_or_else(|| {
            parse_error(
                CLI_ARGUMENT_VALUE_MISSING_CODE,
                "subscription refresh schedule requires --unit-name <base-name>",
            )
        })
    };
    match operation.as_str() {
        "install" => Ok(LinuxCliCommand::SubscriptionRefreshScheduleInstall {
            catalog_path: options.catalog_path.ok_or_else(|| {
                parse_error(
                    CLI_ARGUMENT_VALUE_MISSING_CODE,
                    "subscription refresh schedule install requires --catalog <path>",
                )
            })?,
            status_path: options.refresh_status_path.ok_or_else(|| {
                parse_error(
                    CLI_ARGUMENT_VALUE_MISSING_CODE,
                    "subscription refresh schedule install requires --refresh-status <path>",
                )
            })?,
            snapshot_path: options.snapshot_path.ok_or_else(|| {
                parse_error(
                    CLI_ARGUMENT_VALUE_MISSING_CODE,
                    "subscription refresh schedule install requires --snapshot <path>",
                )
            })?,
            source_id: options.source_id.ok_or_else(|| {
                parse_error(
                    CLI_ARGUMENT_VALUE_MISSING_CODE,
                    "subscription refresh schedule install requires --source-id <id>",
                )
            })?,
            interval_seconds: options.refresh_interval_seconds.ok_or_else(|| {
                parse_error(
                    CLI_ARGUMENT_VALUE_MISSING_CODE,
                    "subscription refresh schedule install requires --interval-seconds <>=300>",
                )
            })?,
            unit_name: unit_name()?,
            confirm: options.confirm,
            format: options.format,
        }),
        "status" => Ok(LinuxCliCommand::SubscriptionRefreshScheduleStatus {
            unit_name: unit_name()?,
            snapshot_path: options.snapshot_path.ok_or_else(|| {
                parse_error(
                    CLI_ARGUMENT_VALUE_MISSING_CODE,
                    "subscription refresh schedule status requires --snapshot <path>",
                )
            })?,
            format: options.format,
        }),
        "stop" => Ok(LinuxCliCommand::SubscriptionRefreshScheduleStop {
            unit_name: unit_name()?,
            snapshot_path: options.snapshot_path.ok_or_else(|| {
                parse_error(
                    CLI_ARGUMENT_VALUE_MISSING_CODE,
                    "subscription refresh schedule stop requires --snapshot <path>",
                )
            })?,
            confirm: options.confirm,
            format: options.format,
        }),
        "uninstall" => Ok(LinuxCliCommand::SubscriptionRefreshScheduleUninstall {
            unit_name: unit_name()?,
            snapshot_path: options.snapshot_path.ok_or_else(|| {
                parse_error(
                    CLI_ARGUMENT_VALUE_MISSING_CODE,
                    "subscription refresh schedule uninstall requires --snapshot <path>",
                )
            })?,
            confirm: options.confirm,
            format: options.format,
        }),
        _ => Err(parse_error(
            CLI_ARGUMENT_UNKNOWN_CODE,
            "subscription refresh schedule accepts install, status, stop, or uninstall",
        )),
    }
}

pub(crate) fn parse_core_command(args: &[String]) -> Result<LinuxCliCommand, LinuxCliParseError> {
    let Some(subcommand) = args.first() else {
        return Err(parse_error(
            CLI_ARGUMENT_VALUE_MISSING_CODE,
            "core requires list",
        ));
    };
    match subcommand.as_str() {
        "list" => {
            let options = parse_options(&args[1..])?;
            Ok(LinuxCliCommand::CoreList {
                format: options.format,
            })
        }
        _ => Err(parse_error(
            CLI_ARGUMENT_UNKNOWN_CODE,
            format!("unknown core subcommand: {subcommand}"),
        )),
    }
}

pub(crate) fn parse_run_catalog_command(
    args: &[String],
) -> Result<LinuxCliCommand, LinuxCliParseError> {
    let Some(catalog_path) = args.first() else {
        return Err(parse_error(
            CLI_ARGUMENT_VALUE_MISSING_CODE,
            "run-catalog requires an explicit catalog path and source id",
        ));
    };
    let Some(source_id) = args.get(1) else {
        return Err(parse_error(
            CLI_ARGUMENT_VALUE_MISSING_CODE,
            "run-catalog requires a source id after the catalog path",
        ));
    };
    if catalog_path.starts_with("--") || source_id.starts_with("--") {
        return Err(parse_error(
            CLI_ARGUMENT_VALUE_MISSING_CODE,
            "run-catalog requires a catalog path and source id before options",
        ));
    }
    let options = parse_options(&args[2..])?;

    Ok(LinuxCliCommand::RunCatalog {
        catalog_path: catalog_path.clone(),
        source_id: source_id.clone(),
        selected_node_id: options.selected_node_id,
        listen_host: options
            .listen_host
            .unwrap_or_else(|| "127.0.0.1".to_string()),
        listen_port: options.listen_port.unwrap_or(7890),
        format: options.format,
    })
}

pub(crate) fn parse_managed_status_command(
    args: &[String],
) -> Result<LinuxCliCommand, LinuxCliParseError> {
    if let Some(subcommand) = args.first() {
        if subcommand == "init" {
            return parse_managed_status_init_command(&args[1..]);
        }
        if subcommand == "transition" {
            return parse_managed_status_transition_command(&args[1..]);
        }
        if subcommand == "rollback" {
            return parse_managed_status_rollback_command(&args[1..]);
        }
    }

    let Some(status_path) = args.first() else {
        return Err(parse_error(
            CLI_ARGUMENT_VALUE_MISSING_CODE,
            "managed-status requires an explicit status record path",
        ));
    };
    if status_path.starts_with("--") {
        return Err(parse_error(
            CLI_ARGUMENT_VALUE_MISSING_CODE,
            "managed-status requires a status record path before options",
        ));
    }
    let options = parse_options(&args[1..])?;

    Ok(LinuxCliCommand::ManagedStatus {
        status_path: status_path.clone(),
        format: options.format,
    })
}

pub(crate) fn parse_managed_status_init_command(
    args: &[String],
) -> Result<LinuxCliCommand, LinuxCliParseError> {
    let Some(status_path) = args.first() else {
        return Err(parse_error(
            CLI_ARGUMENT_VALUE_MISSING_CODE,
            "managed-status init requires <status-record-path> <session-id> <engine-id> <state>",
        ));
    };
    let Some(session_id) = args.get(1) else {
        return Err(parse_error(
            CLI_ARGUMENT_VALUE_MISSING_CODE,
            "managed-status init requires <session-id> <engine-id> <state> after the status record path",
        ));
    };
    let Some(engine_id) = args.get(2) else {
        return Err(parse_error(
            CLI_ARGUMENT_VALUE_MISSING_CODE,
            "managed-status init requires <engine-id> <state> after the session id",
        ));
    };
    let Some(state) = args.get(3) else {
        return Err(parse_error(
            CLI_ARGUMENT_VALUE_MISSING_CODE,
            "managed-status init requires <state> after the engine id",
        ));
    };
    if status_path.starts_with("--")
        || session_id.starts_with("--")
        || engine_id.starts_with("--")
        || state.starts_with("--")
    {
        return Err(parse_error(
            CLI_ARGUMENT_VALUE_MISSING_CODE,
            "managed-status init requires record values before options",
        ));
    }
    let options = parse_options(&args[4..])?;

    Ok(LinuxCliCommand::ManagedStatusInit {
        status_path: status_path.clone(),
        session_id: session_id.clone(),
        engine_id: engine_id.clone(),
        state: state.clone(),
        format: options.format,
    })
}

pub(crate) fn parse_managed_status_transition_command(
    args: &[String],
) -> Result<LinuxCliCommand, LinuxCliParseError> {
    let Some(status_path) = args.first() else {
        return Err(parse_error(
            CLI_ARGUMENT_VALUE_MISSING_CODE,
            "managed-status transition requires <status-record-path> <snapshot-path> <expected-state> <next-state>",
        ));
    };
    let Some(snapshot_path) = args.get(1) else {
        return Err(parse_error(
            CLI_ARGUMENT_VALUE_MISSING_CODE,
            "managed-status transition requires <snapshot-path> <expected-state> <next-state> after the status record path",
        ));
    };
    let Some(expected_state) = args.get(2) else {
        return Err(parse_error(
            CLI_ARGUMENT_VALUE_MISSING_CODE,
            "managed-status transition requires <expected-state> <next-state> after the snapshot path",
        ));
    };
    let Some(next_state) = args.get(3) else {
        return Err(parse_error(
            CLI_ARGUMENT_VALUE_MISSING_CODE,
            "managed-status transition requires <next-state> after the expected state",
        ));
    };
    if status_path.starts_with("--")
        || snapshot_path.starts_with("--")
        || expected_state.starts_with("--")
        || next_state.starts_with("--")
    {
        return Err(parse_error(
            CLI_ARGUMENT_VALUE_MISSING_CODE,
            "managed-status transition requires record values before options",
        ));
    }
    let options = parse_options(&args[4..])?;

    Ok(LinuxCliCommand::ManagedStatusTransition {
        status_path: status_path.clone(),
        snapshot_path: snapshot_path.clone(),
        expected_state: expected_state.clone(),
        next_state: next_state.clone(),
        format: options.format,
    })
}

pub(crate) fn parse_managed_status_rollback_command(
    args: &[String],
) -> Result<LinuxCliCommand, LinuxCliParseError> {
    let Some(status_path) = args.first() else {
        return Err(parse_error(
            CLI_ARGUMENT_VALUE_MISSING_CODE,
            "managed-status rollback requires <status-record-path> <snapshot-path> <expected-state>",
        ));
    };
    let Some(snapshot_path) = args.get(1) else {
        return Err(parse_error(
            CLI_ARGUMENT_VALUE_MISSING_CODE,
            "managed-status rollback requires <snapshot-path> <expected-state> after the status record path",
        ));
    };
    let Some(expected_state) = args.get(2) else {
        return Err(parse_error(
            CLI_ARGUMENT_VALUE_MISSING_CODE,
            "managed-status rollback requires <expected-state> after the snapshot path",
        ));
    };
    if status_path.starts_with("--")
        || snapshot_path.starts_with("--")
        || expected_state.starts_with("--")
    {
        return Err(parse_error(
            CLI_ARGUMENT_VALUE_MISSING_CODE,
            "managed-status rollback requires record values before options",
        ));
    }
    let options = parse_options(&args[3..])?;

    Ok(LinuxCliCommand::ManagedStatusRollback {
        status_path: status_path.clone(),
        snapshot_path: snapshot_path.clone(),
        expected_state: expected_state.clone(),
        format: options.format,
    })
}

pub(crate) fn parse_managed_event_command(
    args: &[String],
) -> Result<LinuxCliCommand, LinuxCliParseError> {
    if let Some(subcommand) = args.first() {
        if subcommand == "init" {
            return parse_managed_event_init_command(&args[1..]);
        }
        if subcommand == "list" {
            return parse_managed_event_list_command(&args[1..]);
        }
    }

    let Some(event_path) = args.first() else {
        return Err(parse_error(
            CLI_ARGUMENT_VALUE_MISSING_CODE,
            "managed-event requires an explicit event record path",
        ));
    };
    if event_path.starts_with("--") {
        return Err(parse_error(
            CLI_ARGUMENT_VALUE_MISSING_CODE,
            "managed-event requires an event record path before options",
        ));
    }
    let options = parse_options(&args[1..])?;

    Ok(LinuxCliCommand::ManagedEvent {
        event_path: event_path.clone(),
        format: options.format,
    })
}

pub(crate) fn parse_managed_log_command(
    args: &[String],
) -> Result<LinuxCliCommand, LinuxCliParseError> {
    let Some(log_path) = args.first() else {
        return Err(parse_error(
            CLI_ARGUMENT_VALUE_MISSING_CODE,
            "managed-log requires an explicit log file path",
        ));
    };
    if log_path.starts_with("--") {
        return Err(parse_error(
            CLI_ARGUMENT_VALUE_MISSING_CODE,
            "managed-log requires a log file path before options",
        ));
    }
    let options = parse_options(&args[1..])?;

    Ok(LinuxCliCommand::ManagedLog {
        log_path: log_path.clone(),
        line_limit: options
            .managed_log_line_limit
            .unwrap_or(MANAGED_FOREGROUND_LOG_TAIL_DEFAULT_LIMIT),
        format: options.format,
    })
}

pub(crate) fn parse_managed_event_list_command(
    args: &[String],
) -> Result<LinuxCliCommand, LinuxCliParseError> {
    let Some(event_directory) = args.first() else {
        return Err(parse_error(
            CLI_ARGUMENT_VALUE_MISSING_CODE,
            "managed-event list requires an explicit event directory path",
        ));
    };
    if event_directory.starts_with("--") {
        return Err(parse_error(
            CLI_ARGUMENT_VALUE_MISSING_CODE,
            "managed-event list requires an event directory path before options",
        ));
    }
    let options = parse_options(&args[1..])?;

    Ok(LinuxCliCommand::ManagedEventList {
        event_directory: event_directory.clone(),
        session_id: options.managed_event_session_id,
        event_kind: options.managed_event_kind,
        state: options.managed_event_state,
        cursor: options.managed_event_cursor.unwrap_or(0),
        limit: options
            .managed_event_limit
            .unwrap_or(MANAGED_FOREGROUND_EVENT_HISTORY_DEFAULT_LIMIT),
        format: options.format,
    })
}

pub(crate) fn parse_managed_event_init_command(
    args: &[String],
) -> Result<LinuxCliCommand, LinuxCliParseError> {
    let Some(event_path) = args.first() else {
        return Err(parse_error(
            CLI_ARGUMENT_VALUE_MISSING_CODE,
            "managed-event init requires <event-record-path> <session-id> <engine-id> <event-id> <event-kind> <state> <recorded-at>",
        ));
    };
    let Some(session_id) = args.get(1) else {
        return Err(parse_error(
            CLI_ARGUMENT_VALUE_MISSING_CODE,
            "managed-event init requires <session-id> <engine-id> <event-id> <event-kind> <state> <recorded-at> after the event record path",
        ));
    };
    let Some(engine_id) = args.get(2) else {
        return Err(parse_error(
            CLI_ARGUMENT_VALUE_MISSING_CODE,
            "managed-event init requires <engine-id> <event-id> <event-kind> <state> <recorded-at> after the session id",
        ));
    };
    let Some(event_id) = args.get(3) else {
        return Err(parse_error(
            CLI_ARGUMENT_VALUE_MISSING_CODE,
            "managed-event init requires <event-id> <event-kind> <state> <recorded-at> after the engine id",
        ));
    };
    let Some(event_kind) = args.get(4) else {
        return Err(parse_error(
            CLI_ARGUMENT_VALUE_MISSING_CODE,
            "managed-event init requires <event-kind> <state> <recorded-at> after the event id",
        ));
    };
    let Some(state) = args.get(5) else {
        return Err(parse_error(
            CLI_ARGUMENT_VALUE_MISSING_CODE,
            "managed-event init requires <state> <recorded-at> after the event kind",
        ));
    };
    let Some(recorded_at) = args.get(6) else {
        return Err(parse_error(
            CLI_ARGUMENT_VALUE_MISSING_CODE,
            "managed-event init requires <recorded-at> after the state",
        ));
    };
    if event_path.starts_with("--")
        || session_id.starts_with("--")
        || engine_id.starts_with("--")
        || event_id.starts_with("--")
        || event_kind.starts_with("--")
        || state.starts_with("--")
        || recorded_at.starts_with("--")
    {
        return Err(parse_error(
            CLI_ARGUMENT_VALUE_MISSING_CODE,
            "managed-event init requires record values before options",
        ));
    }
    let options = parse_options(&args[7..])?;

    Ok(LinuxCliCommand::ManagedEventInit {
        event_path: event_path.clone(),
        session_id: session_id.clone(),
        engine_id: engine_id.clone(),
        event_id: event_id.clone(),
        event_kind: event_kind.clone(),
        state: state.clone(),
        recorded_at: recorded_at.clone(),
        format: options.format,
    })
}

pub(crate) fn parse_mitm_command(args: &[String]) -> Result<LinuxCliCommand, LinuxCliParseError> {
    let Some(subcommand) = args.first() else {
        let options = parse_options(args)?;
        return Ok(LinuxCliCommand::MitmStatus {
            format: options.format,
        });
    };

    if subcommand.starts_with("--") {
        let options = parse_options(args)?;
        return Ok(LinuxCliCommand::MitmStatus {
            format: options.format,
        });
    }

    match subcommand.as_str() {
        "status" => {
            let options = parse_options(&args[1..])?;
            Ok(LinuxCliCommand::MitmStatus {
                format: options.format,
            })
        }
        "diagnostics" => {
            let options = parse_options(&args[1..])?;
            Ok(LinuxCliCommand::MitmDiagnostics {
                format: options.format,
            })
        }
        "certificate-plan" | "cert-plan" => {
            let options = parse_options(&args[1..])?;
            Ok(LinuxCliCommand::MitmCertificatePlan {
                format: options.format,
            })
        }
        "certificate" | "cert" => parse_mitm_certificate_command(&args[1..]),
        "browser-plan" | "browser-capture-plan" | "hijack-plan" => {
            let options = parse_options(&args[1..])?;
            Ok(LinuxCliCommand::MitmBrowserPlan {
                format: options.format,
            })
        }
        "browser-capture" => parse_mitm_browser_capture_command(&args[1..]),
        "http-rewrite" | "https-rewrite" | "tls-rewrite" => {
            parse_mitm_http_rewrite_command(&args[1..])
        }
        unknown => Err(parse_error(
            CLI_ARGUMENT_UNKNOWN_CODE,
            format!("unknown mitm subcommand: {unknown}; run networkcore-linux help"),
        )),
    }
}

pub(crate) fn parse_mitm_certificate_command(
    args: &[String],
) -> Result<LinuxCliCommand, LinuxCliParseError> {
    let Some(subcommand) = args.first() else {
        let options = parse_options(args)?;
        return Ok(LinuxCliCommand::MitmCertificatePlan {
            format: options.format,
        });
    };

    if subcommand.starts_with("--") {
        let options = parse_options(args)?;
        return Ok(LinuxCliCommand::MitmCertificatePlan {
            format: options.format,
        });
    }

    match subcommand.as_str() {
        "plan" | "certificate-plan" | "cert-plan" => {
            let options = parse_options(&args[1..])?;
            Ok(LinuxCliCommand::MitmCertificatePlan {
                format: options.format,
            })
        }
        "apply" | "generate" => {
            let options = parse_options(&args[1..])?;
            Ok(LinuxCliCommand::MitmCertificateApply {
                cert_file_path: options.cert_file_path,
                key_file_path: options.key_file_path,
                profile_trust_file_path: options.profile_trust_file_path,
                snapshot_path: options.snapshot_path,
                confirm: options.confirm,
                format: options.format,
            })
        }
        "rollback" => {
            let options = parse_options(&args[1..])?;
            Ok(LinuxCliCommand::MitmCertificateRollback {
                snapshot_path: options.snapshot_path,
                format: options.format,
            })
        }
        "trust-apply" | "trust" => {
            let options = parse_options(&args[1..])?;
            Ok(LinuxCliCommand::MitmCertificateTrustApply {
                certificate_path: options.cert_file_path,
                trust_file_path: options.trust_file_path,
                snapshot_path: options.snapshot_path,
                confirm: options.confirm,
                format: options.format,
            })
        }
        "trust-rollback" => {
            let options = parse_options(&args[1..])?;
            Ok(LinuxCliCommand::MitmCertificateTrustRollback {
                trust_file_path: options.trust_file_path,
                snapshot_path: options.snapshot_path,
                confirm: options.confirm,
                format: options.format,
            })
        }
        unknown => Err(parse_error(
            CLI_ARGUMENT_UNKNOWN_CODE,
            format!("unknown mitm certificate subcommand: {unknown}; run networkcore-linux help"),
        )),
    }
}

pub(crate) fn parse_mitm_browser_capture_command(
    args: &[String],
) -> Result<LinuxCliCommand, LinuxCliParseError> {
    let Some(subcommand) = args.first() else {
        let options = parse_options(args)?;
        return Ok(LinuxCliCommand::MitmBrowserCapturePlan {
            proxy_scheme: options
                .proxy_scheme
                .unwrap_or_else(default_browser_capture_proxy_scheme),
            format: options.format,
        });
    };

    if subcommand.starts_with("--") {
        let options = parse_options(args)?;
        return Ok(LinuxCliCommand::MitmBrowserCapturePlan {
            proxy_scheme: options
                .proxy_scheme
                .unwrap_or_else(default_browser_capture_proxy_scheme),
            format: options.format,
        });
    }

    match subcommand.as_str() {
        "plan" => {
            let options = parse_options(&args[1..])?;
            Ok(LinuxCliCommand::MitmBrowserCapturePlan {
                proxy_scheme: options
                    .proxy_scheme
                    .unwrap_or_else(default_browser_capture_proxy_scheme),
                format: options.format,
            })
        }
        "launch-plan" | "manual-launch" | "hijack-launch-plan" => {
            let options = parse_options(&args[1..])?;
            Ok(LinuxCliCommand::MitmBrowserCaptureLaunchPlan {
                proxy_scheme: options
                    .proxy_scheme
                    .unwrap_or_else(default_browser_capture_proxy_scheme),
                format: options.format,
            })
        }
        "session-plan" | "capture-session-plan" => {
            let Some(url) = args.get(1) else {
                return Err(parse_error(
                    CLI_ARGUMENT_VALUE_MISSING_CODE,
                    "mitm browser-capture session-plan requires a proxy URL argument",
                ));
            };
            if url.starts_with("--") {
                return Err(parse_error(
                    CLI_ARGUMENT_VALUE_MISSING_CODE,
                    "mitm browser-capture session-plan requires a proxy URL before options",
                ));
            }
            let options = parse_options(&args[2..])?;
            Ok(LinuxCliCommand::MitmBrowserCaptureSessionPlan {
                url: url.clone(),
                browser: options
                    .browser
                    .unwrap_or_else(|| MITM_BROWSER_CAPTURE_DEFAULT_BROWSER.to_string()),
                profile_dir: options
                    .profile_dir
                    .unwrap_or_else(|| MITM_BROWSER_CAPTURE_DEFAULT_PROFILE_DIR.to_string()),
                target_url: options.target_url,
                proof_token: options.proof_token,
                proof_log_path: options.proof_log_path,
                proxy_scheme: options
                    .proxy_scheme
                    .unwrap_or_else(default_browser_capture_proxy_scheme),
                listen_host: options
                    .listen_host
                    .unwrap_or_else(|| MITM_BROWSER_CAPTURE_PROXY_HOST.to_string()),
                listen_port: options
                    .listen_port
                    .unwrap_or(MITM_BROWSER_CAPTURE_PROXY_PORT),
                format: options.format,
            })
        }
        "launch" | "hijack" => {
            let options = parse_options(&args[1..])?;
            Ok(LinuxCliCommand::MitmBrowserCaptureLaunch {
                browser: options
                    .browser
                    .unwrap_or_else(|| MITM_BROWSER_CAPTURE_DEFAULT_BROWSER.to_string()),
                profile_dir: options
                    .profile_dir
                    .unwrap_or_else(|| MITM_BROWSER_CAPTURE_DEFAULT_PROFILE_DIR.to_string()),
                target_url: options.target_url,
                proof_token: options.proof_token,
                proof_log_path: options.proof_log_path,
                proxy_scheme: options
                    .proxy_scheme
                    .unwrap_or_else(default_browser_capture_proxy_scheme),
                confirm: options.confirm,
                format: options.format,
            })
        }
        "apply" => {
            let options = parse_options(&args[1..])?;
            Ok(LinuxCliCommand::MitmBrowserCaptureApply {
                pac_file_path: options.pac_file_path,
                policy_file_path: options.policy_file_path,
                profile_prefs_file_path: options.profile_prefs_file_path,
                snapshot_path: options.snapshot_path,
                proxy_scheme: options
                    .proxy_scheme
                    .unwrap_or_else(default_browser_capture_proxy_scheme),
                confirm: options.confirm,
                format: options.format,
            })
        }
        "rollback" => {
            let options = parse_options(&args[1..])?;
            Ok(LinuxCliCommand::MitmBrowserCaptureRollback {
                snapshot_path: options.snapshot_path,
                format: options.format,
            })
        }
        "verify" => {
            let options = parse_options(&args[1..])?;
            Ok(LinuxCliCommand::MitmBrowserCaptureVerify {
                target_url: options.target_url,
                proxy_scheme: options
                    .proxy_scheme
                    .unwrap_or_else(default_browser_capture_proxy_scheme),
                confirm: options.confirm,
                format: options.format,
            })
        }
        "traffic-proof" | "proof" | "verify-traffic" => {
            let options = parse_options(&args[1..])?;
            Ok(LinuxCliCommand::MitmBrowserCaptureTrafficProof {
                target_url: options.target_url,
                proof_token: options.proof_token,
                proof_log_path: options.proof_log_path,
                proxy_scheme: options
                    .proxy_scheme
                    .unwrap_or_else(default_browser_capture_proxy_scheme),
                confirm: options.confirm,
                format: options.format,
            })
        }
        unknown => Err(parse_error(
            CLI_ARGUMENT_UNKNOWN_CODE,
            format!(
                "unknown mitm browser-capture subcommand: {unknown}; run networkcore-linux help"
            ),
        )),
    }
}

pub(crate) fn parse_mitm_http_rewrite_command(
    args: &[String],
) -> Result<LinuxCliCommand, LinuxCliParseError> {
    let Some(subcommand) = args.first() else {
        let options = parse_options(args)?;
        return Ok(LinuxCliCommand::MitmHttpRewritePlan {
            format: options.format,
        });
    };

    if subcommand.starts_with("--") {
        let options = parse_options(args)?;
        return Ok(LinuxCliCommand::MitmHttpRewritePlan {
            format: options.format,
        });
    }

    match subcommand.as_str() {
        "plan" | "status" => {
            let options = parse_options(&args[1..])?;
            Ok(LinuxCliCommand::MitmHttpRewritePlan {
                format: options.format,
            })
        }
        "preview" | "apply" | "dry-run" => {
            let options = parse_options(&args[1..])?;
            Ok(LinuxCliCommand::MitmHttpRewritePreview {
                mitm_plugin_path: options.mitm_plugin_path,
                url: options.url,
                method: options
                    .method
                    .unwrap_or_else(|| MITM_HTTP_REWRITE_DEFAULT_METHOD.to_string()),
                phase: options
                    .phase
                    .unwrap_or_else(|| MITM_HTTP_REWRITE_DEFAULT_PHASE.to_string()),
                status_code: options.status_code,
                headers: options.headers,
                body: options.body,
                confirm: options.confirm,
                format: options.format,
            })
        }
        unknown => Err(parse_error(
            CLI_ARGUMENT_UNKNOWN_CODE,
            format!("unknown mitm http-rewrite subcommand: {unknown}; run networkcore-linux help"),
        )),
    }
}

pub(crate) fn parse_listen_port(value: &str) -> Result<u16, LinuxCliParseError> {
    let parsed = value.parse::<u16>().map_err(|_| {
        parse_error(
            CLI_ARGUMENT_VALUE_MISSING_CODE,
            "--listen-port must be between 1 and 65535",
        )
    })?;
    if parsed == 0 {
        return Err(parse_error(
            CLI_ARGUMENT_VALUE_MISSING_CODE,
            "--listen-port must be between 1 and 65535",
        ));
    }

    Ok(parsed)
}

pub(crate) fn parse_http_status_code(value: &str) -> Result<u16, LinuxCliParseError> {
    let parsed = value.parse::<u16>().map_err(|_| {
        parse_error(
            CLI_ARGUMENT_VALUE_MISSING_CODE,
            "--status-code must be between 100 and 599",
        )
    })?;
    if !(100..=599).contains(&parsed) {
        return Err(parse_error(
            CLI_ARGUMENT_VALUE_MISSING_CODE,
            "--status-code must be between 100 and 599",
        ));
    }

    Ok(parsed)
}

pub(crate) fn parse_managed_event_history_cursor(value: &str) -> Result<usize, LinuxCliParseError> {
    value.parse::<usize>().map_err(|_| {
        parse_error(
            CLI_ARGUMENT_VALUE_MISSING_CODE,
            "--cursor requires a non-negative managed event history offset",
        )
    })
}

pub(crate) fn parse_managed_event_history_limit(value: &str) -> Result<usize, LinuxCliParseError> {
    let limit = value.parse::<usize>().map_err(|_| {
        parse_error(
            CLI_ARGUMENT_VALUE_MISSING_CODE,
            format!("--limit must be between 1 and {MANAGED_FOREGROUND_EVENT_HISTORY_MAX_LIMIT}"),
        )
    })?;
    if !(1..=MANAGED_FOREGROUND_EVENT_HISTORY_MAX_LIMIT).contains(&limit) {
        return Err(parse_error(
            CLI_ARGUMENT_VALUE_MISSING_CODE,
            format!("--limit must be between 1 and {MANAGED_FOREGROUND_EVENT_HISTORY_MAX_LIMIT}"),
        ));
    }
    Ok(limit)
}

pub(crate) fn parse_managed_log_tail_limit(value: &str) -> Result<usize, LinuxCliParseError> {
    let limit = value.parse::<usize>().map_err(|_| {
        parse_error(
            CLI_ARGUMENT_VALUE_MISSING_CODE,
            format!("--tail-lines must be between 1 and {MANAGED_FOREGROUND_LOG_TAIL_MAX_LIMIT}"),
        )
    })?;
    if !(1..=MANAGED_FOREGROUND_LOG_TAIL_MAX_LIMIT).contains(&limit) {
        return Err(parse_error(
            CLI_ARGUMENT_VALUE_MISSING_CODE,
            format!("--tail-lines must be between 1 and {MANAGED_FOREGROUND_LOG_TAIL_MAX_LIMIT}"),
        ));
    }
    Ok(limit)
}

pub(crate) fn parse_http_rewrite_phase_name(value: &str) -> Result<String, LinuxCliParseError> {
    let normalized = value.to_ascii_lowercase();
    match normalized.as_str() {
        "request" | "response" => Ok(normalized),
        _ => Err(parse_error(
            CLI_ARGUMENT_VALUE_MISSING_CODE,
            "--phase must be request or response",
        )),
    }
}

pub(crate) fn default_browser_capture_proxy_scheme() -> String {
    MITM_BROWSER_CAPTURE_DEFAULT_PROXY_SCHEME.to_string()
}

pub(crate) fn parse_browser_capture_proxy_scheme(
    value: &str,
) -> Result<String, LinuxCliParseError> {
    let normalized = value.to_ascii_lowercase();
    match normalized.as_str() {
        MITM_BROWSER_CAPTURE_DEFAULT_PROXY_SCHEME
        | MITM_BROWSER_CAPTURE_NATIVE_PLUGIN_PROXY_SCHEME => Ok(normalized),
        _ => Err(parse_error(
            CLI_ARGUMENT_VALUE_MISSING_CODE,
            format!(
                "--proxy-scheme must be {} or {}",
                MITM_BROWSER_CAPTURE_DEFAULT_PROXY_SCHEME,
                MITM_BROWSER_CAPTURE_NATIVE_PLUGIN_PROXY_SCHEME
            ),
        )),
    }
}

pub const fn cli_help_text() -> &'static str {
    concat!(
        "NetworkCore Linux CLI\n",
        "\n",
        "Usage:\n",
        "  networkcore-linux help [--format text|json]\n",
        "  networkcore-linux version [--format text|json]\n",
        "  networkcore-linux capabilities [--format text|json]\n",
        "  networkcore-linux prepare-config --config <path> [--format text|json]\n",
        "  networkcore-linux validate <config-path> [--format text|json]\n",
        "  networkcore-linux core list [--format text|json]\n",
        "  networkcore-linux subscription add --catalog <path> --snapshot <path> --source-id <id> --url <location> [--format text|json]\n",
        "  networkcore-linux subscription list --catalog <path> [--format text|json]\n",
        "  networkcore-linux subscription update --catalog <path> --snapshot <path> --source-id <id> --url <location> [--format text|json]\n",
        "  networkcore-linux subscription remove --catalog <path> --snapshot <path> --source-id <id> [--format text|json]\n",
        "  networkcore-linux subscription select --catalog <path> --source-id <id> [--format text|json]\n",
        "  networkcore-linux subscription rollback --catalog <path> --snapshot <path> [--format text|json]\n",
        "  networkcore-linux subscription refresh start --catalog <path> --refresh-status <path> --snapshot <path> --source-id <id> [--interval-seconds <>=300>] --confirm [--format text|json]\n",
        "  networkcore-linux subscription refresh status --refresh-status <path> [--format text|json]\n",
        "  networkcore-linux subscription refresh stop --refresh-status <path> --source-id <id> --confirm [--format text|json]\n",
        "  networkcore-linux subscription refresh schedule install --catalog <path> --refresh-status <path> --snapshot <path> --source-id <id> --interval-seconds <>=300> --unit-name <base-name> --confirm [--format text|json]\n",
        "  networkcore-linux subscription refresh schedule status --unit-name <base-name> --snapshot <path> [--format text|json]\n",
        "  networkcore-linux subscription refresh schedule stop --unit-name <base-name> --snapshot <path> --confirm [--format text|json]\n",
        "  networkcore-linux subscription refresh schedule uninstall --unit-name <base-name> --snapshot <path> --confirm [--format text|json]\n",
        "  networkcore-linux start --config <path> [--managed-status <path> --managed-snapshot <path> --managed-events <dir> [--managed-control-socket <absolute-path>]] [--mitm-plugin <path>] [--enable-https-mitm --mitm-ca-cert <path> --mitm-ca-key <path>] [--enable-script-runtime [--script-runner <path>] --script-map <url=file> ... [--script-store <path>]] --confirm [--format text|json]\n",
        "  networkcore-linux connect --config <path> [same explicit foreground options as start]\n",
        "  networkcore-linux stop [--managed-control-socket <absolute-path> --confirm] [--format text|json]\n",
        "  networkcore-linux reload --managed-control-socket <absolute-path> --confirm [--format text|json]\n",
        "  networkcore-linux rollback --managed-control-socket <absolute-path> --expected-config-version <positive-integer> --confirm [--format text|json]\n",
        "  networkcore-linux status --managed-control-socket <absolute-path> [--format text|json]\n",
        "  networkcore-linux disconnect [--format text|json]\n",
        "  networkcore-linux restart [--config <path>] [--format text|json]\n",
        "  networkcore-linux status [--service-unit <name>] [--format text|json]\n",
        "  networkcore-linux managed-status <status-record-path> [--format text|json]\n",
        "  networkcore-linux managed-status init <status-record-path> <session-id> <engine-id> <state> [--format text|json]\n",
        "  networkcore-linux managed-status transition <status-record-path> <snapshot-path> <expected-state> <next-state> [--format text|json]\n",
        "  networkcore-linux managed-status rollback <status-record-path> <snapshot-path> <expected-state> [--format text|json]\n",
        "  networkcore-linux managed-event <event-record-path> [--format text|json]\n",
        "  networkcore-linux managed-event list <event-directory> [--session-id <id>] [--event-kind <kind>] [--state <state>] [--cursor <offset>] [--limit <1-100>] [--format text|json]\n",
        "  networkcore-linux managed-event init <event-record-path> <session-id> <engine-id> <event-id> <event-kind> <state> <recorded-at> [--format text|json]\n",
        "  networkcore-linux managed-log <log-file-path> [--tail-lines <1-1000>] [--format text|json]\n",
        "  networkcore-linux diagnostics [--format text|json]\n",
        "  networkcore-linux mitm [status|diagnostics|certificate-plan|browser-plan] [--format text|json]\n",
        "  networkcore-linux mitm certificate [plan|apply|rollback] [--cert-file <path>] [--key-file <path>] [--profile-trust-file <path>] [--confirm] [--snapshot <path>] [--format text|json]\n",
        "  networkcore-linux mitm certificate trust-apply --cert-file <path> --trust-file <path> --snapshot <path> --confirm\n",
        "  networkcore-linux mitm certificate trust-rollback --trust-file <path> --snapshot <path> --confirm\n",
        "  networkcore-linux mitm browser-capture [plan|launch-plan|session-plan|launch|apply|rollback|verify|traffic-proof] [<ss://url>] [--browser <executable>] [--profile-dir <dir>] [--target-url <url>] [--proxy-scheme http|socks5] [--listen-host <host>] [--listen-port <port>] [--pac-file <path>] [--policy-file <path>] [--profile-prefs-file <path>] [--proof-token <token>] [--proof-log <path>] [--confirm] [--snapshot <path>] [--format text|json]\n",
        "  networkcore-linux mitm http-rewrite [plan|preview] [--mitm-plugin <path>] [--url <url>] [--method <method>] [--phase request|response] [--status-code <code>] [--header <name:value>] [--body <text>] [--confirm] [--format text|json]\n",
        "  networkcore-linux install-service --service-executable <absolute-path> [--service-unit <name>] [--service-description <text>] [--service-arg <arg>] [--service-user <user>] [--service-group <group>] [--service-state-dir <absolute-path>] --confirm [--format text|json]\n",
        "  networkcore-linux service <start|stop|restart|reload> [--service-unit <name>] --confirm [--format text|json]\n",
        "  networkcore-linux service status [--service-unit <name>] [--format text|json]\n",
        "  networkcore-linux node list --config <absolute-path> [--format text|json]\n",
        "  networkcore-linux node select --config <absolute-path> --source-id <node-id> --selection <absolute-path> --snapshot <absolute-path> --confirm [--format text|json]\n",
        "  networkcore-linux node rollback --selection <absolute-path> --snapshot <absolute-path> --confirm [--format text|json]\n",
        "  networkcore-linux proxy apply --file <absolute-path> --snapshot <absolute-path> --url <proxy-url> --confirm [--format text|json]\n",
        "  networkcore-linux proxy status --file <absolute-path> [--format text|json]\n",
        "  networkcore-linux proxy rollback --file <absolute-path> --snapshot <absolute-path> --confirm [--format text|json]\n",
        "  networkcore-linux restart --confirm [--service-unit <name>] [--format text|json]  # managed systemd restart\n",
        "  networkcore-linux reload --confirm [--service-unit <name>] [--format text|json]  # managed systemd reload\n",
        "  networkcore-linux connect|disconnect --confirm [--service-unit <name>] [--format text|json]  # managed systemd start/stop\n",
        "  networkcore-linux uninstall-service [--service-unit <name>] [--service-state-dir <absolute-path>] --confirm [--format text|json]\n",
        "  networkcore-linux logs <explicit-log-path> [--tail-lines <1-1000>] [--format text|json]\n",
        "  networkcore-linux run-url <subscription-source> [--node-id <id>] [--listen-host <host>] [--listen-port <port>] [--format text|json]\n",
        "  networkcore-linux run-catalog <catalog-path> <source-id> [--node-id <id>] [--listen-host <host>] [--listen-port <port>] [--format text|json]\n",
        "\n",
        "Commands:\n",
        "  help              Show this command table.\n",
        "  version           Print the networkcore-linux version.\n",
        "  capabilities      Report read-only Linux platform capabilities.\n",
        "  prepare-config    Read and normalize a NetworkCore TOML config.\n",
        "  validate          Validate one explicit config path (alias of prepare-config).\n",
        "  core list         List adapter descriptors without starting a core.\n",
        "  start             Start the current foreground runtime; HTTPS MITM requires explicit CA paths and confirmation.\n",
        "  connect           Starts the foreground runtime, or starts an explicit managed systemd unit with --confirm or --service-unit.\n",
        "  stop              Stop an explicitly managed foreground runtime through its Unix control socket; otherwise report unavailable.\n",
        "  disconnect        Stops an explicit managed systemd unit with --confirm or --service-unit; otherwise reports foreground stop availability.\n",
        "  restart           Restarts an explicit managed systemd unit with --confirm or --service-unit; otherwise reports unavailable.\n",
        "  status            Reads an explicit systemd unit with --service-unit; otherwise reports platform-only status.\n",
        "  managed-status    Read one explicit managed foreground status record.\n",
        "  managed-status init Create one explicit managed foreground status record without overwriting it.\n",
        "  managed-status transition Move one explicit record through an expected-state transition.\n",
        "  managed-status rollback Restore one explicit record from a matching expected-state snapshot.\n",
        "  managed-event     Read one explicit managed foreground event record.\n",
        "  managed-event list Query bounded, filtered event history from one explicit directory.\n",
        "  managed-event init Create one explicit managed foreground event record without overwriting it.\n",
        "  managed-log       Read a bounded tail from one explicit managed foreground log file.\n",
        "  diagnostics       Print platform diagnostics.\n",
        "  mitm              Report MITM plugin policy status, certificate/browser plans, and deferred browser hijack gates.\n",
        "  install-service   Write an explicit confirmed systemd unit with snapshot/verification; never calls systemctl.\n",
        "  service           Control one explicitly named systemd unit; mutations require --confirm and status uses is-active.\n",
        "  node              List nodes from one explicit config; selection and runtime state are unchanged.\n",
        "  proxy             Manage one explicit environment proxy file with snapshot and rollback.\n",
        "  restart           Without --confirm remains foreground-unavailable; with --confirm restarts the managed unit.\n",
        "  uninstall-service Render an explicit removal plan; user configuration/state is preserved and no files are deleted.\n",
        "  logs              Read a bounded tail from one explicit log path; no default path scanning.\n",
        "  run-url           Parse a subscription or share link and run it on the embedded engine as a local SOCKS5/HTTP proxy.\n",
        "  run-catalog       Resolve one saved source and run it on the embedded engine.\n",
        "\n",
        "Options:\n",
        "  --config <path>       Config file for prepare-config and start.\n",
        "  --enable-https-mitm   Explicitly enable the controlled HTTPS MITM engine path for start; requires --confirm and both CA paths.\n",
        "  --mitm-plugin <path>  Your own MITM plugin for start and mitm http-rewrite preview; none is built in. HTTPS MITM and the script runtime need one.\n",
        "  --mitm-ca-cert <path> CA certificate PEM path for explicitly enabled HTTPS MITM start.\n",
        "  --mitm-ca-key <path>  CA private key PEM path for explicitly enabled HTTPS MITM start.\n",
        "  --enable-script-runtime Explicitly enable mapped local [Script] execution in in-process QuickJS; requires --confirm and maps.\n",
        "  --script-runner <path> Optional local Node contract runner; selects Node execution in a no-network sandbox instead of QuickJS.\n",
        "  --script-map <url=file> Explicit remote script URL to a local regular asset; repeat for each permitted script.\n",
        "  --script-store <path> QuickJS $persistentStore JSON path; rejected with --script-runner.\n",
        "  --node-binary <path> Node executable for --script-runner. Defaults to node.\n",
        "  --managed-status <path> Explicit managed foreground status record path for lifecycle recording.\n",
        "  --managed-snapshot <path> Explicit initial managed foreground status snapshot path.\n",
        "  --managed-events <dir> Explicit managed foreground event directory for lifecycle recording.\n",
        "  --managed-control-socket <path> Absolute owner-only Unix socket path for managed foreground stop.\n",
        "  --browser <exe>       Browser executable for mitm browser-capture session-plan/launch. Defaults to chromium.\n",
        "  --profile-dir <dir>   Dedicated browser profile directory for mitm browser-capture session-plan/launch.\n",
        "  --target-url <url>    Optional page URL to open in the dedicated browser capture profile.\n",
        "  --url <url>           HTTP/TLS rewrite preview target URL for mitm http-rewrite preview.\n",
        "  --method <method>     HTTP method for mitm http-rewrite preview. Defaults to GET.\n",
        "  --phase <phase>       HTTP MITM phase for mitm http-rewrite preview: request or response.\n",
        "  --status-code <code>  HTTP response status code for response-phase rewrite preview.\n",
        "  --header <name:value> Plain HTTP header input for rewrite preview; repeat for multiple headers.\n",
        "  --body <text>         Plain HTTP body input for rewrite preview.\n",
        "  --proxy-scheme <mode> Browser explicit proxy scheme for browser-capture. Defaults to http; socks5 targets the native SOCKS5 CONNECT MITM hook.\n",
        "  --cert-file <path>    Certificate artifact path for mitm certificate apply.\n",
        "  --key-file <path>     Private key artifact path for mitm certificate apply.\n",
        "  --trust-file <path>   Explicit Linux trust-file path for mitm certificate trust mutation.\n",
        "  --profile-trust-file <path> Dedicated profile CA trust artifact path for mitm certificate apply.\n",
        "  --pac-file <path>     PAC file path for mitm browser-capture apply.\n",
        "  --policy-file <path>  Chromium/Chrome managed proxy policy file artifact for mitm browser-capture apply.\n",
        "  --profile-prefs-file <path> Firefox dedicated profile user.js path for reversible browser-capture apply.\n",
        "  --proof-token <token> Browser traffic proof token expected in a proof log.\n",
        "  --proof-log <path>    Browser traffic proof log path to inspect after an operator-driven visit.\n",
        "  --service-unit <name> Systemd unit name. Defaults to networkcore.service.\n",
        "  --service-description <text> Systemd service description.\n",
        "  --service-executable <path> Absolute executable path for the managed service.\n",
        "  --service-arg <arg>   One argument passed to the managed executable; repeat as needed.\n",
        "  --service-user <user> Non-root service account. Defaults to networkcore.\n",
        "  --service-group <group> Non-root service group. Defaults to networkcore.\n",
        "  --service-state-dir <path> Absolute writable state directory. Defaults to /var/lib/networkcore.\n",
        "  --node-id <id>        Catalog node id for run-url. Defaults to the first supported node.\n",
        "  --listen-host <host>  Local proxy listen address for run-url. Defaults to 127.0.0.1.\n",
        "  --listen-port <port>  Local proxy listen port for run-url. Defaults to 7890.\n",
        "  --format text|json    Output format. Defaults to text.\n",
    )
}

pub(crate) fn parse_output_format(value: &str) -> Result<OutputFormat, LinuxCliParseError> {
    match value {
        "text" => Ok(OutputFormat::Text),
        "json" => Ok(OutputFormat::Json),
        _ => Err(parse_error(
            CLI_OUTPUT_FORMAT_UNSUPPORTED_CODE,
            format!("unsupported linux CLI output format: {value}"),
        )),
    }
}

pub(crate) fn parse_error(
    code: impl Into<String>,
    message: impl Into<String>,
) -> LinuxCliParseError {
    LinuxCliParseError::new(cli_diagnostic(
        DiagnosticSeverity::Error,
        code,
        message,
        SOURCE_CLI_ARGUMENT,
    ))
}
