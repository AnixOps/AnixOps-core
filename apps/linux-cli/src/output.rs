//! Response mapping: errors to responses, redaction and the text output.

use super::*;

pub fn render_response(response: &LinuxCliResponse, format: OutputFormat) -> String {
    match format {
        OutputFormat::Text => render_text_response(response),
        OutputFormat::Json => render_json_response(response),
    }
}

pub(crate) fn redact_cli_output_text(value: &str) -> String {
    let mut redacted = value.to_string();
    for scheme in [
        "https://",
        "http://",
        "ss://",
        "trojan://",
        "vless://",
        "vmess://",
        "hysteria2://",
        "hy2://",
        "tuic://",
        "mierus://",
    ] {
        redacted = redact_cli_output_url(&redacted, scheme);
    }
    for marker in [
        "password=",
        "password:",
        "token=",
        "token:",
        "access_token=",
        "access_token:",
        "refresh_token=",
        "refresh_token:",
        "secret=",
        "secret:",
        "credential=",
        "credential:",
        "authorization:",
        "api_key=",
        "api_key:",
        "private_key=",
        "private_key:",
        "uuid=",
        "uuid:",
        "\"password\":",
        "\"token\":",
        "\"access_token\":",
        "\"refresh_token\":",
        "\"secret\":",
        "\"credential\":",
        "\"authorization\":",
        "\"api_key\":",
        "\"private_key\":",
        "\"uuid\":",
    ] {
        redacted = redact_cli_output_line_value(&redacted, marker);
    }
    redacted
}

pub(crate) fn redact_cli_output_url(value: &str, scheme: &str) -> String {
    let mut redacted = String::new();
    let mut remaining = value;
    loop {
        let lowered = remaining.to_ascii_lowercase();
        let Some(offset) = lowered.find(scheme) else {
            redacted.push_str(remaining);
            return redacted;
        };
        redacted.push_str(&remaining[..offset]);
        redacted.push_str("[redacted-url]");
        let url_end = remaining[offset..]
            .find(|character: char| {
                character.is_ascii_whitespace() || matches!(character, '"' | '\'' | '<' | '>')
            })
            .unwrap_or(remaining[offset..].len());
        remaining = &remaining[offset + url_end..];
    }
}

pub(crate) fn redact_cli_output_line_value(value: &str, marker: &str) -> String {
    let mut redacted = String::new();
    let mut remaining = value;
    loop {
        let lowered = remaining.to_ascii_lowercase();
        let Some(offset) = lowered.find(marker) else {
            redacted.push_str(remaining);
            return redacted;
        };
        redacted.push_str(&remaining[..offset]);
        redacted.push_str(&remaining[offset..offset + marker.len()]);
        redacted.push_str("[redacted]");
        let line_end = remaining[offset + marker.len()..]
            .find('\n')
            .map(|index| offset + marker.len() + index)
            .unwrap_or(remaining.len());
        remaining = &remaining[line_end..];
    }
}

pub fn cli_diagnostic(
    severity: DiagnosticSeverity,
    code: impl Into<String>,
    message: impl Into<String>,
    source: impl Into<String>,
) -> Diagnostic {
    Diagnostic::new(severity, code, message, Some(source.into()))
}

pub(crate) fn read_required_config<R>(
    command: &'static str,
    reader: &R,
    config_path: Option<&str>,
) -> Result<String, Box<LinuxCliResponse>>
where
    R: ConfigReader,
{
    let Some(path) = config_path else {
        return Err(Box::new(LinuxCliResponse::failure(
            command,
            LinuxCliExitCode::ArgumentOrConfig,
            cli_diagnostic(
                DiagnosticSeverity::Error,
                CLI_CONFIG_PATH_MISSING_CODE,
                "linux CLI command requires --config <path>",
                SOURCE_CLI_CONFIG,
            ),
        )));
    };

    let raw_config = match reader.read_config(path) {
        Ok(raw_config) => raw_config,
        Err(error) => {
            return Err(Box::new(LinuxCliResponse::failure(
                command,
                LinuxCliExitCode::ArgumentOrConfig,
                cli_diagnostic(
                    DiagnosticSeverity::Error,
                    CLI_CONFIG_READ_FAILED_CODE,
                    format!("failed to read linux config {path}: {}", error.message),
                    SOURCE_CLI_CONFIG,
                ),
            )));
        }
    };

    if raw_config.trim().is_empty() {
        return Err(Box::new(LinuxCliResponse::failure(
            command,
            LinuxCliExitCode::ArgumentOrConfig,
            cli_diagnostic(
                DiagnosticSeverity::Error,
                CLI_CONFIG_EMPTY_CODE,
                "linux CLI config is empty",
                SOURCE_CLI_CONFIG,
            ),
        )));
    }

    Ok(raw_config)
}

pub(crate) fn start_error_response(error: DomainError) -> LinuxCliResponse {
    if error.code.starts_with("runtime.platform.") {
        return LinuxCliResponse::failure(
            "start",
            LinuxCliExitCode::PlatformDenied,
            cli_diagnostic(
                DiagnosticSeverity::Error,
                CLI_START_PLATFORM_DENIED_CODE,
                error.message,
                SOURCE_CLI_START,
            ),
        );
    }

    if error.code.starts_with("runtime.config.") {
        return LinuxCliResponse::failure(
            "start",
            LinuxCliExitCode::ConfigValidation,
            cli_diagnostic(
                DiagnosticSeverity::Error,
                CLI_START_CONFIG_DENIED_CODE,
                error.message,
                SOURCE_CLI_START,
            ),
        );
    }

    if error.code.starts_with("runtime.engine") || error.code.starts_with("engine.") {
        return LinuxCliResponse::failure(
            "start",
            LinuxCliExitCode::EngineDenied,
            cli_diagnostic(
                DiagnosticSeverity::Error,
                CLI_START_ENGINE_DENIED_CODE,
                error.message,
                SOURCE_CLI_START,
            ),
        );
    }

    domain_error_response(
        "start",
        LinuxCliExitCode::GeneralFailure,
        error,
        SOURCE_CLI_START,
    )
}

pub(crate) fn domain_error_response(
    command: &'static str,
    exit_code: LinuxCliExitCode,
    error: DomainError,
    source: &'static str,
) -> LinuxCliResponse {
    LinuxCliResponse::failure(
        command,
        exit_code,
        cli_diagnostic(DiagnosticSeverity::Error, error.code, error.message, source),
    )
}

pub(crate) fn handle_unwired_command(command: &'static str) -> LinuxCliResponse {
    LinuxCliResponse::failure(
        command,
        LinuxCliExitCode::Unavailable,
        cli_diagnostic(
            DiagnosticSeverity::Error,
            CLI_RUNTIME_UNWIRED_CODE,
            "linux CLI runtime wiring is not available for this command",
            SOURCE_CLI_RUNTIME,
        ),
    )
}

pub(crate) fn unavailable_engine_error() -> DomainError {
    DomainError::new(
        CLI_RUNTIME_UNWIRED_CODE,
        "linux proxy engine adapter is not wired",
    )
}

pub(crate) fn platform_diagnostics(status: &PlatformCapabilityStatus) -> Vec<Diagnostic> {
    let mut diagnostics = status.diagnostics.clone();
    diagnostics.extend(status.mitm_certificate.diagnostics.clone());
    diagnostics
}

pub(crate) fn render_text_response(response: &LinuxCliResponse) -> String {
    if response.ok && response.command == "help" {
        return response
            .help
            .clone()
            .unwrap_or_else(|| cli_help_text().to_string());
    }

    let state = if response.ok { "ok" } else { "error" };
    let mut lines = vec![format!("{}: {state}", response.command)];

    if let Some(plan) = &response.service_install {
        lines.push(format!("systemd unit: {}", plan.unit_name));
        lines.push(format!(
            "install confirmation required: {}",
            plan.install_confirmation_required
        ));
        lines.push(format!("restart policy: {}", plan.restart_policy));
        lines.push("unit content:".to_string());
        lines.push(plan.content.clone());
    }
    if let Some(plan) = &response.service_removal {
        lines.push(format!("systemd unit: {}", plan.unit_name));
        lines.push(format!("unit path: {}", plan.unit_path.display()));
        lines.push(format!(
            "preserved state directory: {}",
            plan.preserved_state_directory.display()
        ));
        lines.push(format!(
            "purge confirmation required: {}",
            plan.purge_confirmation_required
        ));
    }
    if !response.core_engines.is_empty() {
        for engine in &response.core_engines {
            lines.push(format!(
                "core: {} ({}) version={} capabilities={}",
                engine.id,
                engine.kind,
                engine.version.as_deref().unwrap_or("unknown"),
                engine.capabilities.join(",")
            ));
        }
    }
    if let Some(catalog) = &response.node_catalog {
        lines.push(format!(
            "node catalog: source={} schema_version={} selection_mutated={} nodes={}",
            catalog.source,
            catalog.schema_version,
            catalog.selection_mutated,
            catalog.nodes.len()
        ));
        for node in &catalog.nodes {
            lines.push(format!(
                "node: id={} name={} protocol={} tags={}",
                node.id,
                node.name,
                node.protocol,
                node.tags.join(",")
            ));
        }
    }
    if let Some(status) = &response.managed_foreground_status {
        lines.push(format!(
            "managed foreground status record: {}",
            status.status_path
        ));
        lines.push(format!("managed foreground session: {}", status.session_id));
        lines.push(format!("managed foreground engine: {}", status.engine_id));
        lines.push(format!(
            "managed foreground recorded state: {}",
            status.state
        ));
        lines.push(format!(
            "managed foreground liveness verified: {}",
            status.liveness_verified
        ));
    }

    if let Some(status_write) = &response.managed_foreground_status_write {
        lines.push(format!(
            "managed foreground status record: {}",
            status_write.status_path
        ));
        lines.push(format!(
            "managed foreground session: {}",
            status_write.session_id
        ));
        lines.push(format!(
            "managed foreground engine: {}",
            status_write.engine_id
        ));
        lines.push(format!(
            "managed foreground recorded state: {}",
            status_write.state
        ));
        lines.push(format!(
            "managed foreground status record written: {}",
            status_write.record_written
        ));
        lines.push(format!(
            "managed foreground liveness verified: {}",
            status_write.liveness_verified
        ));
    }

    if let Some(status_transition) = &response.managed_foreground_status_transition {
        lines.push(format!(
            "managed foreground status record: {}",
            status_transition.status_path
        ));
        lines.push(format!(
            "managed foreground status snapshot: {}",
            status_transition.snapshot_path
        ));
        lines.push(format!(
            "managed foreground session: {}",
            status_transition.session_id
        ));
        lines.push(format!(
            "managed foreground engine: {}",
            status_transition.engine_id
        ));
        lines.push(format!(
            "managed foreground previous recorded state: {}",
            status_transition.previous_state
        ));
        lines.push(format!(
            "managed foreground recorded state: {}",
            status_transition.state
        ));
        lines.push(format!(
            "managed foreground status snapshot written: {}",
            status_transition.snapshot_written
        ));
        lines.push(format!(
            "managed foreground liveness verified: {}",
            status_transition.liveness_verified
        ));
    }

    if let Some(status_rollback) = &response.managed_foreground_status_rollback {
        lines.push(format!(
            "managed foreground status record: {}",
            status_rollback.status_path
        ));
        lines.push(format!(
            "managed foreground status snapshot: {}",
            status_rollback.snapshot_path
        ));
        lines.push(format!(
            "managed foreground session: {}",
            status_rollback.session_id
        ));
        lines.push(format!(
            "managed foreground engine: {}",
            status_rollback.engine_id
        ));
        lines.push(format!(
            "managed foreground previous recorded state: {}",
            status_rollback.previous_state
        ));
        lines.push(format!(
            "managed foreground recorded state: {}",
            status_rollback.state
        ));
        lines.push(format!(
            "managed foreground status snapshot retained: {}",
            status_rollback.snapshot_retained
        ));
        lines.push(format!(
            "managed foreground liveness verified: {}",
            status_rollback.liveness_verified
        ));
    }

    if let Some(event) = &response.managed_foreground_event {
        lines.push(format!(
            "managed foreground event record: {}",
            event.event_path
        ));
        lines.push(format!("managed foreground session: {}", event.session_id));
        lines.push(format!("managed foreground engine: {}", event.engine_id));
        lines.push(format!("managed foreground event id: {}", event.event_id));
        lines.push(format!(
            "managed foreground event kind: {}",
            event.event_kind
        ));
        lines.push(format!(
            "managed foreground recorded state: {}",
            event.state
        ));
        lines.push(format!(
            "managed foreground recorded at: {}",
            event.recorded_at
        ));
        lines.push(format!(
            "managed foreground liveness verified: {}",
            event.liveness_verified
        ));
    }

    if let Some(history) = &response.managed_foreground_event_history {
        lines.push(format!(
            "managed foreground event history directory: {}",
            history.event_directory
        ));
        lines.push(format!(
            "managed foreground event history session filter: {}",
            history.session_id.as_deref().unwrap_or("none")
        ));
        lines.push(format!(
            "managed foreground event history kind filter: {}",
            history.event_kind.as_deref().unwrap_or("none")
        ));
        lines.push(format!(
            "managed foreground event history state filter: {}",
            history.state.as_deref().unwrap_or("none")
        ));
        lines.push(format!(
            "managed foreground event history cursor: {}",
            history.cursor
        ));
        lines.push(format!(
            "managed foreground event history next cursor: {}",
            history
                .next_cursor
                .map(|cursor| cursor.to_string())
                .as_deref()
                .unwrap_or("none")
        ));
        lines.push(format!(
            "managed foreground event history matching count: {}",
            history.matching_event_count
        ));
        lines.push(format!(
            "managed foreground event history returned count: {}",
            history.events.len()
        ));
        for (offset, event) in history.events.iter().enumerate() {
            let index = history.cursor + offset;
            lines.push(format!(
                "managed foreground event history entry {index}: id={} kind={} state={} recorded_at={} session={} engine={} path={}",
                event.event_id,
                event.event_kind,
                event.state,
                event.recorded_at,
                event.session_id,
                event.engine_id,
                event.event_path
            ));
        }
        lines.push(format!(
            "managed foreground liveness verified: {}",
            history.liveness_verified
        ));
    }

    if let Some(event_write) = &response.managed_foreground_event_write {
        lines.push(format!(
            "managed foreground event record: {}",
            event_write.event_path
        ));
        lines.push(format!(
            "managed foreground session: {}",
            event_write.session_id
        ));
        lines.push(format!(
            "managed foreground engine: {}",
            event_write.engine_id
        ));
        lines.push(format!(
            "managed foreground event id: {}",
            event_write.event_id
        ));
        lines.push(format!(
            "managed foreground event kind: {}",
            event_write.event_kind
        ));
        lines.push(format!(
            "managed foreground recorded state: {}",
            event_write.state
        ));
        lines.push(format!(
            "managed foreground recorded at: {}",
            event_write.recorded_at
        ));
        lines.push(format!(
            "managed foreground event record written: {}",
            event_write.record_written
        ));
        lines.push(format!(
            "managed foreground liveness verified: {}",
            event_write.liveness_verified
        ));
    }

    if let Some(log_tail) = &response.managed_foreground_log_tail {
        lines.push(format!("managed foreground log: {}", log_tail.log_path));
        lines.push(format!(
            "managed foreground log line limit: {}",
            log_tail.line_limit
        ));
        lines.push(format!(
            "managed foreground log total lines: {}",
            log_tail.total_line_count
        ));
        lines.push(format!(
            "managed foreground log returned lines: {}",
            log_tail.lines.len()
        ));
        lines.push(format!(
            "managed foreground log returned bytes: {}",
            log_tail.returned_byte_count
        ));
        for (index, line) in log_tail.lines.iter().enumerate() {
            lines.push(format!(
                "managed foreground log line {index}: {}",
                redact_cli_output_text(line)
            ));
        }
        lines.push(format!(
            "managed foreground liveness verified: {}",
            log_tail.liveness_verified
        ));
    }

    if let Some(mitm) = &response.mitm_status {
        lines.push(format!("mitm stage: {}", mitm.stage));
        lines.push(format!(
            "user-facing mitm ready: {}",
            mitm.user_facing_ready
        ));
        lines.push(format!("browser hijack: {}", mitm.browser_hijack));
        lines.push(format!(
            "platform mitm available: {}",
            mitm.platform_mitm_available
        ));
        lines.push(format!("certificate state: {}", mitm.certificate_state));
        lines.push(format!(
            "certificate plan: {} mutation_ready={}",
            mitm.certificate_plan.status, mitm.certificate_plan.mutation_ready
        ));
        lines.push(format!(
            "certificate plan current state: {}",
            mitm.certificate_plan.current_state
        ));
        if let Some(subject) = &mitm.certificate_plan.subject {
            lines.push(format!("certificate subject: {subject}"));
        }
        if let Some(fingerprint_sha256) = &mitm.certificate_plan.fingerprint_sha256 {
            lines.push(format!(
                "certificate fingerprint sha256: {fingerprint_sha256}"
            ));
        }
        for step in &mitm.certificate_plan.required_steps {
            lines.push(format!(
                "certificate step {}: {} ({})",
                step.id, step.status, step.reason
            ));
        }
        for operation in &mitm.certificate_plan.blocked_operations {
            lines.push(format!("certificate blocked operation: {operation}"));
        }
        lines.push(format!(
            "browser plan: {} mutation_ready={}",
            mitm.browser_plan.status, mitm.browser_plan.mutation_ready
        ));
        lines.push(format!(
            "browser capture: {}",
            mitm.browser_plan.current_capture
        ));
        lines.push(format!(
            "browser planned mode: {}",
            mitm.browser_plan.planned_capture_mode
        ));
        lines.push(format!(
            "browser planned proxy: {}:{}",
            mitm.browser_plan.planned_proxy_host, mitm.browser_plan.planned_proxy_port
        ));
        for step in &mitm.browser_plan.required_steps {
            lines.push(format!(
                "browser step {}: {} ({})",
                step.id, step.status, step.reason
            ));
        }
        for operation in &mitm.browser_plan.blocked_operations {
            lines.push(format!("browser blocked operation: {operation}"));
        }
        lines.push(format!(
            "policy engine: {} {}",
            mitm.policy.engine, mitm.policy.engine_version
        ));
        lines.push(format!(
            "plugin: {} {} loaded={}",
            mitm.policy.plugin_id, mitm.policy.plugin_version, mitm.policy.plugin_loaded
        ));
        lines.push(format!(
            "rules: mitm={} rewrite={} script={} arguments={}",
            mitm.policy.mitm_pattern_count,
            mitm.policy.rewrite_rule_count,
            mitm.policy.script_rule_count,
            mitm.policy.argument_count
        ));
        for gate in &mitm.gates {
            lines.push(format!(
                "gate {}: {} ({})",
                gate.gate, gate.status, gate.reason
            ));
        }
    }

    if let Some(certificate) = &response.certificate_lifecycle {
        lines.push(format!(
            "certificate lifecycle {}: {} mutation_ready={}",
            certificate.action, certificate.gate_status, certificate.mutation_ready
        ));
        lines.push(format!(
            "certificate lifecycle source contract: {}",
            certificate.source_contract_status
        ));
        lines.push(format!(
            "certificate lifecycle plan: {}",
            certificate.plan.status
        ));
        lines.push(format!(
            "certificate trust plan: {} mutation_ready={}",
            certificate.trust_plan.status, certificate.trust_plan.mutation_ready
        ));
        if let Some(authorization) = &certificate.request.authorization {
            lines.push(format!(
                "certificate authorization: confirmed={} source={} scope={}",
                authorization.confirmed, authorization.source, authorization.scope
            ));
        }
        if let Some(artifact) = &certificate.request.artifact {
            lines.push(format!(
                "certificate artifact request: cert={} key={} profile_trust={} snapshot={} subject={}",
                artifact.cert_file_path,
                artifact.key_file_path,
                artifact
                    .profile_trust_file_path
                    .as_deref()
                    .unwrap_or("not-requested"),
                artifact.snapshot_path,
                artifact.subject
            ));
            lines.push(format!(
                "certificate artifact fingerprints: cert={} key={} profile_trust={}",
                artifact.cert_fingerprint,
                artifact.key_fingerprint,
                artifact
                    .profile_trust_fingerprint
                    .as_deref()
                    .unwrap_or("not-requested")
            ));
        }
        if let Some(snapshot) = &certificate.request.rollback_snapshot {
            lines.push(format!(
                "certificate rollback snapshot: {} ({})",
                snapshot.path, snapshot.status
            ));
        }
        if let Some(report) = &certificate.apply_report {
            lines.push(format!(
                "certificate apply: {} applied={}",
                report.status, report.applied
            ));
            if let Some(cert_file_path) = &report.cert_file_path {
                lines.push(format!("certificate artifact file: {cert_file_path}"));
            }
            if let Some(key_file_path) = &report.key_file_path {
                lines.push(format!("certificate key artifact file: {key_file_path}"));
            }
            if let Some(profile_trust_file_path) = &report.profile_trust_file_path {
                lines.push(format!(
                    "certificate dedicated profile trust artifact file: {profile_trust_file_path}"
                ));
            }
            if let Some(snapshot) = &report.rollback_snapshot {
                lines.push(format!(
                    "certificate apply rollback snapshot: {} ({})",
                    snapshot.path, snapshot.status
                ));
            }
        }
        if let Some(report) = &certificate.rollback_report {
            lines.push(format!(
                "certificate rollback: {} rolled_back={}",
                report.status, report.rolled_back
            ));
            if let Some(cert_file_path) = &report.cert_file_path {
                lines.push(format!(
                    "certificate rollback artifact file: {cert_file_path}"
                ));
            }
            if let Some(key_file_path) = &report.key_file_path {
                lines.push(format!(
                    "certificate rollback key artifact file: {key_file_path}"
                ));
            }
            if let Some(profile_trust_file_path) = &report.profile_trust_file_path {
                lines.push(format!(
                    "certificate rollback dedicated profile trust artifact file: {profile_trust_file_path}"
                ));
            }
            if let Some(snapshot) = &report.rollback_snapshot {
                lines.push(format!(
                    "certificate rollback snapshot: {} ({})",
                    snapshot.path, snapshot.status
                ));
            }
        }
        for operation in &certificate.trust_plan.blocked_operations {
            lines.push(format!("certificate trust blocked operation: {operation}"));
        }
    }

    if let Some(capture) = &response.browser_capture {
        lines.push(format!(
            "browser capture {}: {} mutation_ready={}",
            capture.action, capture.gate_status, capture.mutation_ready
        ));
        lines.push(format!(
            "browser capture source contract: {}",
            capture.source_contract_status
        ));
        lines.push(format!(
            "browser capture planned proxy: {}:{}",
            capture.plan.planned_proxy_host, capture.plan.planned_proxy_port
        ));
        lines.push(format!(
            "browser capture planned proxy scheme: {}",
            capture.plan.planned_proxy_scheme
        ));
        lines.push(format!(
            "browser capture manual launch: {} proxy={}",
            capture.plan.manual_launch.status, capture.plan.manual_launch.proxy_url
        ));
        lines.push(format!(
            "browser capture plugin: {} {} via {}",
            capture.plan.manual_launch.plugin_id,
            capture.plan.manual_launch.plugin_version,
            capture.plan.manual_launch.plugin_engine
        ));
        for command in &capture.plan.manual_launch.browser_commands {
            lines.push(format!(
                "browser launch command {}: {}",
                command.browser, command.command
            ));
        }
        for step in &capture.plan.manual_launch.manual_steps {
            lines.push(format!("browser launch step: {step}"));
        }
        if let Some(session) = &capture.session_plan {
            lines.push(format!(
                "browser capture session plan: {} node={} proxy={}",
                session.status, session.node_name, session.proxy_url
            ));
            lines.push(format!(
                "browser capture session local proxy: {}:{}",
                session.listen_host, session.listen_port
            ));
            lines.push(format!(
                "browser capture session proxy scheme: {}",
                session.proxy_scheme
            ));
            if let Some(target_url) = &session.target_url {
                lines.push(format!("browser capture session target URL: {target_url}"));
            }
            if let Some(proof_target_url) = &session.proof_target_url {
                lines.push(format!(
                    "browser capture session proof target URL: {proof_target_url}"
                ));
            }
            lines.push(format!(
                "browser capture session proof token: {}",
                session.proof_token
            ));
            lines.push(format!(
                "browser capture session proof log: {}",
                session.proof_log_path
            ));
            lines.push(format!(
                "browser capture session run command: {}",
                session.run_command
            ));
            lines.push(format!(
                "browser capture session browser command: {}",
                session.browser_command.command
            ));
            lines.push(format!(
                "browser capture session verify command: {}",
                session.verify_command
            ));
            lines.push(format!(
                "browser capture session traffic-proof command: {}",
                session.traffic_proof_command
            ));
            for step in &session.required_steps {
                lines.push(format!("browser capture session step: {step}"));
            }
        }
        if let Some(authorization) = &capture.request.authorization {
            lines.push(format!(
                "browser capture authorization: confirmed={} source={} scope={}",
                authorization.confirmed, authorization.source, authorization.scope
            ));
        }
        if let Some(snapshot) = &capture.request.rollback_snapshot {
            lines.push(format!(
                "browser capture rollback snapshot: {} ({})",
                snapshot.path, snapshot.status
            ));
        }
        if let Some(report) = &capture.launch_report {
            lines.push(format!(
                "browser capture launch: {} launched={} pid={}",
                report.status,
                report.launched,
                report
                    .pid
                    .map(|pid| pid.to_string())
                    .unwrap_or_else(|| "none".to_string())
            ));
            lines.push(format!(
                "browser capture launch command: {}",
                report.request.command.command
            ));
            if let Some(target_url) = &report.request.target_url {
                lines.push(format!("browser capture launch target URL: {target_url}"));
            }
            if let Some(proof_target_url) = &report.request.proof_target_url {
                lines.push(format!(
                    "browser capture launch proof target URL: {proof_target_url}"
                ));
            }
            lines.push(format!(
                "browser capture launch proof token: {}",
                report.request.proof_token
            ));
            lines.push(format!(
                "browser capture launch proof log: {}",
                report.request.proof_log_path
            ));
            lines.push(format!(
                "browser capture launch traffic-proof command: {}",
                report.request.traffic_proof_command
            ));
            lines.push(format!(
                "browser capture launch profile: {} proxy={}",
                report.request.profile_dir, report.request.proxy_url
            ));
        }
        if let Some(report) = &capture.apply_report {
            lines.push(format!(
                "browser capture apply: {} applied={}",
                report.status, report.applied
            ));
            if let Some(pac_file_path) = &report.pac_file_path {
                lines.push(format!("browser capture PAC file: {pac_file_path}"));
            }
            if let Some(pac_url) = &report.pac_url {
                lines.push(format!("browser capture PAC URL: {pac_url}"));
            }
            if let Some(policy_file_path) = &report.policy_file_path {
                lines.push(format!(
                    "browser capture browser policy file: {policy_file_path}"
                ));
            }
            if let Some(policy_url) = &report.policy_url {
                lines.push(format!("browser capture browser policy URL: {policy_url}"));
            }
            if let Some(profile_prefs_file_path) = &report.profile_prefs_file_path {
                lines.push(format!(
                    "browser capture Firefox profile prefs file: {profile_prefs_file_path}"
                ));
            }
            if let Some(snapshot) = &report.rollback_snapshot {
                lines.push(format!(
                    "browser capture apply rollback snapshot: {} ({})",
                    snapshot.path, snapshot.status
                ));
            }
        }
        if let Some(report) = &capture.rollback_report {
            lines.push(format!(
                "browser capture rollback: {} rolled_back={}",
                report.status, report.rolled_back
            ));
            if let Some(pac_file_path) = &report.pac_file_path {
                lines.push(format!(
                    "browser capture rollback PAC file: {pac_file_path}"
                ));
            }
            if let Some(policy_file_path) = &report.policy_file_path {
                lines.push(format!(
                    "browser capture rollback browser policy file: {policy_file_path}"
                ));
            }
            if let Some(profile_prefs_file_path) = &report.profile_prefs_file_path {
                lines.push(format!(
                    "browser capture rollback Firefox profile prefs file: {profile_prefs_file_path}"
                ));
            }
            if let Some(snapshot) = &report.rollback_snapshot {
                lines.push(format!(
                    "browser capture rollback snapshot: {} ({})",
                    snapshot.path, snapshot.status
                ));
            }
        }
        if let Some(report) = &capture.verify_report {
            lines.push(format!(
                "browser capture verify: {} verified={} proxy={} probe={}",
                report.status, report.verified, report.request.proxy_url, report.request.probe
            ));
            if let Some(target_url) = &report.request.target_url {
                lines.push(format!("browser capture verify target URL: {target_url}"));
            }
        }
        if let Some(report) = &capture.traffic_proof_report {
            lines.push(format!(
                "browser capture traffic proof: {} proven={} proxy={} proof_log={} probe={}",
                report.status,
                report.proven,
                report.request.proxy_url,
                report.request.proof_log_path,
                report.request.probe
            ));
            if let Some(target_url) = &report.request.target_url {
                lines.push(format!(
                    "browser capture traffic proof target URL: {target_url}"
                ));
            }
            if let Some(proof_target_url) = &report.request.proof_target_url {
                lines.push(format!(
                    "browser capture traffic proof target proof URL: {proof_target_url}"
                ));
            }
            if let Some(proof_connect_authority) = &report.request.proof_connect_authority {
                lines.push(format!(
                    "browser capture traffic proof CONNECT authority: {proof_connect_authority}"
                ));
            }
            lines.push(format!(
                "browser capture traffic proof token: {}",
                report.request.proof_token
            ));
        }
    }

    if let Some(rewrite) = &response.http_rewrite {
        lines.push(format!(
            "http rewrite {}: {} mutation_ready={} live_traffic_ready={} tls_decryption_ready={} controlled_tls_termination_plan_ready={} downstream_tls_termination_plan_ready={} upstream_tls_forwarding_ready={} https_request_rewrite_preview_ready={} https_response_rewrite_preview_ready={} https_response_rewrite_ready={} script_dispatch_ready={} certificate_pinning_bypass_supported={} http2_mitm_supported={} http3_quic_mitm_supported={}",
            rewrite.action,
            rewrite.gate_status,
            rewrite.mutation_ready,
            rewrite.live_traffic_ready,
            rewrite.tls_decryption_ready,
            rewrite.controlled_tls_termination_plan_ready,
            rewrite.downstream_tls_termination_plan_ready,
            rewrite.upstream_tls_forwarding_ready,
            rewrite.https_request_rewrite_preview_ready,
            rewrite.https_response_rewrite_preview_ready,
            rewrite.https_response_rewrite_ready,
            rewrite.script_dispatch_ready,
            rewrite.certificate_pinning_bypass_supported,
            rewrite.http2_mitm_supported,
            rewrite.http3_quic_mitm_supported
        ));
        lines.push(format!(
            "http rewrite source contract: {}",
            rewrite.source_contract_status
        ));
        if let Some(url) = &rewrite.request.url {
            lines.push(format!("http rewrite request URL: {url}"));
        }
        lines.push(format!(
            "http rewrite request: method={} phase={} status_code={}",
            rewrite.request.method,
            rewrite.request.phase,
            rewrite
                .request
                .status_code
                .map(|status| status.to_string())
                .unwrap_or_else(|| "none".to_string())
        ));
        if let Some(authorization) = &rewrite.request.authorization {
            lines.push(format!(
                "http rewrite authorization: confirmed={} source={} scope={}",
                authorization.confirmed, authorization.source, authorization.scope
            ));
        }
        if let Some(outcome) = &rewrite.outcome {
            lines.push(format!(
                "http rewrite outcome: planned={} applied={} action={} terminal={} final_status={}",
                outcome.planned,
                outcome.applied,
                outcome.action,
                outcome
                    .terminal_action
                    .clone()
                    .unwrap_or_else(|| "none".to_string()),
                outcome
                    .final_status_code
                    .map(|status| status.to_string())
                    .unwrap_or_else(|| "none".to_string())
            ));
            if let Some(location) = &outcome.redirect_location {
                lines.push(format!("http rewrite redirect location: {location}"));
            }
            lines.push(format!(
                "http rewrite mutations: headers={} body_mutated={} script_dispatch_deferred={} script_dispatch_failed={}",
                outcome.header_mutation_count,
                outcome.body_mutated,
                outcome.script_dispatch_deferred,
                outcome.script_dispatch_failed
            ));
            for header in &outcome.output_headers {
                lines.push(format!(
                    "http rewrite output header: {}: {}",
                    header.name, header.value
                ));
            }
            if let Some(body) = &outcome.output_body {
                lines.push(format!("http rewrite output body: {body}"));
            }
        }
        for operation in &rewrite.blocked_operations {
            lines.push(format!("http rewrite blocked operation: {operation}"));
        }
    }

    for diagnostic in &response.diagnostics {
        lines.push(format!(
            "{} {}: {}",
            severity_name(diagnostic.severity),
            diagnostic.code,
            redact_cli_output_text(&diagnostic.message)
        ));
    }

    if let Some(help) = &response.help {
        lines.push(String::new());
        lines.push(help.clone());
    }

    lines.join("\n")
}

pub(crate) fn render_json_response(response: &LinuxCliResponse) -> String {
    let dto = JsonCliResponse::from(response);
    serde_json::to_string(&dto).expect("CLI response serialization should not fail")
}

pub(crate) fn severity_name(severity: DiagnosticSeverity) -> &'static str {
    match severity {
        DiagnosticSeverity::Info => "info",
        DiagnosticSeverity::Warning => "warning",
        DiagnosticSeverity::Error => "error",
    }
}

pub(crate) fn os_name(os: OperatingSystem) -> &'static str {
    match os {
        OperatingSystem::Linux => "linux",
        OperatingSystem::Macos => "macos",
        OperatingSystem::Windows => "windows",
        OperatingSystem::Ios => "ios",
        OperatingSystem::Unknown => "unknown",
    }
}

pub(crate) fn certificate_state_name(state: CertificateTrustState) -> &'static str {
    match state {
        CertificateTrustState::NotInstalled => "not_installed",
        CertificateTrustState::InstalledUntrusted => "installed_untrusted",
        CertificateTrustState::Trusted => "trusted",
        CertificateTrustState::Revoked => "revoked",
        CertificateTrustState::Unknown => "unknown",
    }
}
