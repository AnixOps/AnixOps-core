//! The JSON output: serializable mirrors of the responses.

use super::*;

#[derive(Serialize)]
pub(crate) struct JsonCliResponse {
    pub(crate) ok: bool,
    pub(crate) command: String,
    pub(crate) exit_code: i32,
    pub(crate) diagnostics: Vec<JsonDiagnostic>,
    pub(crate) platform: Option<JsonPlatform>,
    pub(crate) config_profiles: Vec<String>,
    pub(crate) version: Option<String>,
    pub(crate) help: Option<String>,
    pub(crate) managed_foreground_status: Option<JsonManagedForegroundSessionStatusReport>,
    pub(crate) managed_foreground_status_write:
        Option<JsonManagedForegroundSessionStatusWriteReport>,
    pub(crate) managed_foreground_status_transition:
        Option<JsonManagedForegroundSessionStatusTransitionReport>,
    pub(crate) managed_foreground_status_rollback:
        Option<JsonManagedForegroundSessionStatusRollbackReport>,
    pub(crate) managed_foreground_event: Option<JsonManagedForegroundSessionEventReport>,
    pub(crate) managed_foreground_event_history:
        Option<JsonManagedForegroundSessionEventHistoryReport>,
    pub(crate) managed_foreground_event_write: Option<JsonManagedForegroundSessionEventWriteReport>,
    pub(crate) managed_foreground_log_tail: Option<JsonManagedForegroundSessionLogTailReport>,
    pub(crate) mitm_status: Option<JsonMitmStatus>,
    pub(crate) certificate_lifecycle: Option<JsonMitmCertificateLifecycleReport>,
    pub(crate) browser_capture: Option<JsonBrowserCaptureReport>,
    pub(crate) http_rewrite: Option<JsonMitmHttpRewriteReport>,
    pub(crate) service_install: Option<JsonLinuxManagedServiceUnitPlan>,
    pub(crate) service_removal: Option<JsonLinuxManagedServiceUnitRemovalPlan>,
    pub(crate) core_engines: Vec<JsonLinuxCoreEngineSummary>,
    pub(crate) node_catalog: Option<JsonLinuxNodeCatalogReport>,
}

impl From<&LinuxCliResponse> for JsonCliResponse {
    fn from(response: &LinuxCliResponse) -> Self {
        Self {
            ok: response.ok,
            command: response.command.clone(),
            exit_code: response.exit_code.code(),
            diagnostics: response
                .diagnostics
                .iter()
                .map(JsonDiagnostic::from)
                .collect(),
            platform: response.platform.as_ref().map(JsonPlatform::from),
            config_profiles: response.config_profiles.clone(),
            version: response.version.clone(),
            help: response.help.clone(),
            managed_foreground_status: response
                .managed_foreground_status
                .as_ref()
                .map(JsonManagedForegroundSessionStatusReport::from),
            managed_foreground_status_write: response
                .managed_foreground_status_write
                .as_ref()
                .map(JsonManagedForegroundSessionStatusWriteReport::from),
            managed_foreground_status_transition: response
                .managed_foreground_status_transition
                .as_ref()
                .map(JsonManagedForegroundSessionStatusTransitionReport::from),
            managed_foreground_status_rollback: response
                .managed_foreground_status_rollback
                .as_ref()
                .map(JsonManagedForegroundSessionStatusRollbackReport::from),
            managed_foreground_event: response
                .managed_foreground_event
                .as_ref()
                .map(JsonManagedForegroundSessionEventReport::from),
            managed_foreground_event_history: response
                .managed_foreground_event_history
                .as_ref()
                .map(JsonManagedForegroundSessionEventHistoryReport::from),
            managed_foreground_event_write: response
                .managed_foreground_event_write
                .as_ref()
                .map(JsonManagedForegroundSessionEventWriteReport::from),
            managed_foreground_log_tail: response
                .managed_foreground_log_tail
                .as_ref()
                .map(JsonManagedForegroundSessionLogTailReport::from),
            mitm_status: response.mitm_status.as_ref().map(JsonMitmStatus::from),
            certificate_lifecycle: response
                .certificate_lifecycle
                .as_ref()
                .map(JsonMitmCertificateLifecycleReport::from),
            browser_capture: response
                .browser_capture
                .as_ref()
                .map(JsonBrowserCaptureReport::from),
            http_rewrite: response
                .http_rewrite
                .as_ref()
                .map(JsonMitmHttpRewriteReport::from),
            service_install: response
                .service_install
                .as_ref()
                .map(JsonLinuxManagedServiceUnitPlan::from),
            service_removal: response
                .service_removal
                .as_ref()
                .map(JsonLinuxManagedServiceUnitRemovalPlan::from),
            core_engines: response
                .core_engines
                .iter()
                .map(JsonLinuxCoreEngineSummary::from)
                .collect(),
            node_catalog: response
                .node_catalog
                .as_ref()
                .map(JsonLinuxNodeCatalogReport::from),
        }
    }
}

#[derive(Serialize)]
pub(crate) struct JsonLinuxNodeCatalogReport {
    pub(crate) schema_version: u32,
    pub(crate) source: String,
    pub(crate) selection_mutated: bool,
    pub(crate) nodes: Vec<JsonLinuxNodeCatalogEntry>,
}

impl From<&LinuxNodeCatalogReport> for JsonLinuxNodeCatalogReport {
    fn from(report: &LinuxNodeCatalogReport) -> Self {
        Self {
            schema_version: report.schema_version,
            source: report.source.clone(),
            selection_mutated: report.selection_mutated,
            nodes: report
                .nodes
                .iter()
                .map(JsonLinuxNodeCatalogEntry::from)
                .collect(),
        }
    }
}

#[derive(Serialize)]
pub(crate) struct JsonLinuxNodeCatalogEntry {
    pub(crate) id: String,
    pub(crate) name: String,
    pub(crate) protocol: String,
    pub(crate) tags: Vec<String>,
}

impl From<&LinuxNodeCatalogEntry> for JsonLinuxNodeCatalogEntry {
    fn from(entry: &LinuxNodeCatalogEntry) -> Self {
        Self {
            id: entry.id.clone(),
            name: entry.name.clone(),
            protocol: entry.protocol.clone(),
            tags: entry.tags.clone(),
        }
    }
}

#[derive(Serialize)]
pub(crate) struct JsonLinuxManagedServiceUnitPlan {
    pub(crate) schema_version: u32,
    pub(crate) unit_name: String,
    pub(crate) content: String,
    pub(crate) install_confirmation_required: bool,
    pub(crate) restart_policy: String,
    pub(crate) start_limit_burst: u32,
    pub(crate) start_limit_interval_seconds: u32,
}

impl From<&LinuxManagedServiceUnitPlan> for JsonLinuxManagedServiceUnitPlan {
    fn from(plan: &LinuxManagedServiceUnitPlan) -> Self {
        Self {
            schema_version: plan.schema_version,
            unit_name: plan.unit_name.clone(),
            content: plan.content.clone(),
            install_confirmation_required: plan.install_confirmation_required,
            restart_policy: plan.restart_policy.clone(),
            start_limit_burst: plan.start_limit_burst,
            start_limit_interval_seconds: plan.start_limit_interval_seconds,
        }
    }
}

#[derive(Serialize)]
pub(crate) struct JsonLinuxManagedServiceUnitRemovalPlan {
    pub(crate) schema_version: u32,
    pub(crate) unit_name: String,
    pub(crate) unit_path: String,
    pub(crate) confirmation_required: bool,
    pub(crate) purge_confirmation_required: bool,
    pub(crate) preserved_state_directory: String,
}

impl From<&LinuxManagedServiceUnitRemovalPlan> for JsonLinuxManagedServiceUnitRemovalPlan {
    fn from(plan: &LinuxManagedServiceUnitRemovalPlan) -> Self {
        Self {
            schema_version: plan.schema_version,
            unit_name: plan.unit_name.clone(),
            unit_path: plan.unit_path.display().to_string(),
            confirmation_required: plan.confirmation_required,
            purge_confirmation_required: plan.purge_confirmation_required,
            preserved_state_directory: plan.preserved_state_directory.display().to_string(),
        }
    }
}

#[derive(Serialize)]
pub(crate) struct JsonLinuxCoreEngineSummary {
    pub(crate) id: String,
    pub(crate) kind: String,
    pub(crate) version: Option<String>,
    pub(crate) capabilities: Vec<String>,
}

impl From<&LinuxCoreEngineSummary> for JsonLinuxCoreEngineSummary {
    fn from(summary: &LinuxCoreEngineSummary) -> Self {
        Self {
            id: summary.id.clone(),
            kind: summary.kind.clone(),
            version: summary.version.clone(),
            capabilities: summary.capabilities.clone(),
        }
    }
}

#[derive(Serialize)]
pub(crate) struct JsonManagedForegroundSessionStatusReport {
    pub(crate) status_path: String,
    pub(crate) session_id: String,
    pub(crate) engine_id: String,
    pub(crate) state: String,
    pub(crate) liveness_verified: bool,
}

impl From<&ManagedForegroundSessionStatusReport> for JsonManagedForegroundSessionStatusReport {
    fn from(report: &ManagedForegroundSessionStatusReport) -> Self {
        Self {
            status_path: report.status_path.clone(),
            session_id: report.session_id.clone(),
            engine_id: report.engine_id.clone(),
            state: report.state.clone(),
            liveness_verified: report.liveness_verified,
        }
    }
}

#[derive(Serialize)]
pub(crate) struct JsonManagedForegroundSessionStatusWriteReport {
    pub(crate) status_path: String,
    pub(crate) session_id: String,
    pub(crate) engine_id: String,
    pub(crate) state: String,
    pub(crate) record_written: bool,
    pub(crate) liveness_verified: bool,
}

impl From<&ManagedForegroundSessionStatusWriteReport>
    for JsonManagedForegroundSessionStatusWriteReport
{
    fn from(report: &ManagedForegroundSessionStatusWriteReport) -> Self {
        Self {
            status_path: report.status_path.clone(),
            session_id: report.session_id.clone(),
            engine_id: report.engine_id.clone(),
            state: report.state.clone(),
            record_written: report.record_written,
            liveness_verified: report.liveness_verified,
        }
    }
}

#[derive(Serialize)]
pub(crate) struct JsonManagedForegroundSessionStatusTransitionReport {
    pub(crate) status_path: String,
    pub(crate) snapshot_path: String,
    pub(crate) session_id: String,
    pub(crate) engine_id: String,
    pub(crate) previous_state: String,
    pub(crate) state: String,
    pub(crate) snapshot_written: bool,
    pub(crate) liveness_verified: bool,
}

impl From<&ManagedForegroundSessionStatusTransitionReport>
    for JsonManagedForegroundSessionStatusTransitionReport
{
    fn from(report: &ManagedForegroundSessionStatusTransitionReport) -> Self {
        Self {
            status_path: report.status_path.clone(),
            snapshot_path: report.snapshot_path.clone(),
            session_id: report.session_id.clone(),
            engine_id: report.engine_id.clone(),
            previous_state: report.previous_state.clone(),
            state: report.state.clone(),
            snapshot_written: report.snapshot_written,
            liveness_verified: report.liveness_verified,
        }
    }
}

#[derive(Serialize)]
pub(crate) struct JsonManagedForegroundSessionStatusRollbackReport {
    pub(crate) status_path: String,
    pub(crate) snapshot_path: String,
    pub(crate) session_id: String,
    pub(crate) engine_id: String,
    pub(crate) previous_state: String,
    pub(crate) state: String,
    pub(crate) snapshot_retained: bool,
    pub(crate) liveness_verified: bool,
}

impl From<&ManagedForegroundSessionStatusRollbackReport>
    for JsonManagedForegroundSessionStatusRollbackReport
{
    fn from(report: &ManagedForegroundSessionStatusRollbackReport) -> Self {
        Self {
            status_path: report.status_path.clone(),
            snapshot_path: report.snapshot_path.clone(),
            session_id: report.session_id.clone(),
            engine_id: report.engine_id.clone(),
            previous_state: report.previous_state.clone(),
            state: report.state.clone(),
            snapshot_retained: report.snapshot_retained,
            liveness_verified: report.liveness_verified,
        }
    }
}

#[derive(Serialize)]
pub(crate) struct JsonManagedForegroundSessionEventReport {
    pub(crate) event_path: String,
    pub(crate) session_id: String,
    pub(crate) engine_id: String,
    pub(crate) event_id: String,
    pub(crate) event_kind: String,
    pub(crate) state: String,
    pub(crate) recorded_at: String,
    pub(crate) liveness_verified: bool,
}

impl From<&ManagedForegroundSessionEventReport> for JsonManagedForegroundSessionEventReport {
    fn from(report: &ManagedForegroundSessionEventReport) -> Self {
        Self {
            event_path: report.event_path.clone(),
            session_id: report.session_id.clone(),
            engine_id: report.engine_id.clone(),
            event_id: report.event_id.clone(),
            event_kind: report.event_kind.clone(),
            state: report.state.clone(),
            recorded_at: report.recorded_at.clone(),
            liveness_verified: report.liveness_verified,
        }
    }
}

#[derive(Serialize)]
pub(crate) struct JsonManagedForegroundSessionEventHistoryEntry {
    pub(crate) event_path: String,
    pub(crate) session_id: String,
    pub(crate) engine_id: String,
    pub(crate) event_id: String,
    pub(crate) event_kind: String,
    pub(crate) state: String,
    pub(crate) recorded_at: String,
}

impl From<&ManagedForegroundSessionEventHistoryEntry>
    for JsonManagedForegroundSessionEventHistoryEntry
{
    fn from(entry: &ManagedForegroundSessionEventHistoryEntry) -> Self {
        Self {
            event_path: entry.event_path.clone(),
            session_id: entry.session_id.clone(),
            engine_id: entry.engine_id.clone(),
            event_id: entry.event_id.clone(),
            event_kind: entry.event_kind.clone(),
            state: entry.state.clone(),
            recorded_at: entry.recorded_at.clone(),
        }
    }
}

#[derive(Serialize)]
pub(crate) struct JsonManagedForegroundSessionEventHistoryReport {
    pub(crate) event_directory: String,
    pub(crate) session_id: Option<String>,
    pub(crate) event_kind: Option<String>,
    pub(crate) state: Option<String>,
    pub(crate) cursor: usize,
    pub(crate) next_cursor: Option<usize>,
    pub(crate) matching_event_count: usize,
    pub(crate) events: Vec<JsonManagedForegroundSessionEventHistoryEntry>,
    pub(crate) liveness_verified: bool,
}

impl From<&ManagedForegroundSessionEventHistoryReport>
    for JsonManagedForegroundSessionEventHistoryReport
{
    fn from(report: &ManagedForegroundSessionEventHistoryReport) -> Self {
        Self {
            event_directory: report.event_directory.clone(),
            session_id: report.session_id.clone(),
            event_kind: report.event_kind.clone(),
            state: report.state.clone(),
            cursor: report.cursor,
            next_cursor: report.next_cursor,
            matching_event_count: report.matching_event_count,
            events: report
                .events
                .iter()
                .map(JsonManagedForegroundSessionEventHistoryEntry::from)
                .collect(),
            liveness_verified: report.liveness_verified,
        }
    }
}

#[derive(Serialize)]
pub(crate) struct JsonManagedForegroundSessionLogTailReport {
    pub(crate) log_path: String,
    pub(crate) line_limit: usize,
    pub(crate) total_line_count: usize,
    pub(crate) lines: Vec<String>,
    pub(crate) returned_byte_count: usize,
    pub(crate) liveness_verified: bool,
}

impl From<&ManagedForegroundSessionLogTailReport> for JsonManagedForegroundSessionLogTailReport {
    fn from(report: &ManagedForegroundSessionLogTailReport) -> Self {
        Self {
            log_path: report.log_path.clone(),
            line_limit: report.line_limit,
            total_line_count: report.total_line_count,
            lines: report
                .lines
                .iter()
                .map(|line| redact_cli_output_text(line))
                .collect(),
            returned_byte_count: report.returned_byte_count,
            liveness_verified: report.liveness_verified,
        }
    }
}

#[derive(Serialize)]
pub(crate) struct JsonManagedForegroundSessionEventWriteReport {
    pub(crate) event_path: String,
    pub(crate) session_id: String,
    pub(crate) engine_id: String,
    pub(crate) event_id: String,
    pub(crate) event_kind: String,
    pub(crate) state: String,
    pub(crate) recorded_at: String,
    pub(crate) record_written: bool,
    pub(crate) liveness_verified: bool,
}

impl From<&ManagedForegroundSessionEventWriteReport>
    for JsonManagedForegroundSessionEventWriteReport
{
    fn from(report: &ManagedForegroundSessionEventWriteReport) -> Self {
        Self {
            event_path: report.event_path.clone(),
            session_id: report.session_id.clone(),
            engine_id: report.engine_id.clone(),
            event_id: report.event_id.clone(),
            event_kind: report.event_kind.clone(),
            state: report.state.clone(),
            recorded_at: report.recorded_at.clone(),
            record_written: report.record_written,
            liveness_verified: report.liveness_verified,
        }
    }
}

#[derive(Serialize)]
pub(crate) struct JsonMitmStatus {
    pub(crate) stage: String,
    pub(crate) user_facing_ready: bool,
    pub(crate) browser_hijack: String,
    pub(crate) platform_mitm_available: bool,
    pub(crate) certificate_state: String,
    pub(crate) certificate_plan: JsonMitmCertificatePlan,
    pub(crate) browser_plan: JsonMitmBrowserPlan,
    pub(crate) policy: JsonMitmPolicyStatus,
    pub(crate) gates: Vec<JsonMitmGateStatus>,
}

impl From<&LinuxMitmStatus> for JsonMitmStatus {
    fn from(status: &LinuxMitmStatus) -> Self {
        Self {
            stage: status.stage.clone(),
            user_facing_ready: status.user_facing_ready,
            browser_hijack: status.browser_hijack.clone(),
            platform_mitm_available: status.platform_mitm_available,
            certificate_state: status.certificate_state.clone(),
            certificate_plan: JsonMitmCertificatePlan::from(&status.certificate_plan),
            browser_plan: JsonMitmBrowserPlan::from(&status.browser_plan),
            policy: JsonMitmPolicyStatus::from(&status.policy),
            gates: status.gates.iter().map(JsonMitmGateStatus::from).collect(),
        }
    }
}

#[derive(Serialize)]
pub(crate) struct JsonMitmBrowserPlan {
    pub(crate) status: String,
    pub(crate) mutation_ready: bool,
    pub(crate) current_capture: String,
    pub(crate) planned_capture_mode: String,
    pub(crate) planned_proxy_host: String,
    pub(crate) planned_proxy_port: u16,
    pub(crate) required_steps: Vec<JsonMitmBrowserPlanStep>,
    pub(crate) blocked_operations: Vec<String>,
}

impl From<&LinuxMitmBrowserPlan> for JsonMitmBrowserPlan {
    fn from(plan: &LinuxMitmBrowserPlan) -> Self {
        Self {
            status: plan.status.clone(),
            mutation_ready: plan.mutation_ready,
            current_capture: plan.current_capture.clone(),
            planned_capture_mode: plan.planned_capture_mode.clone(),
            planned_proxy_host: plan.planned_proxy_host.clone(),
            planned_proxy_port: plan.planned_proxy_port,
            required_steps: plan
                .required_steps
                .iter()
                .map(JsonMitmBrowserPlanStep::from)
                .collect(),
            blocked_operations: plan.blocked_operations.clone(),
        }
    }
}

#[derive(Serialize)]
pub(crate) struct JsonMitmBrowserPlanStep {
    pub(crate) id: String,
    pub(crate) status: String,
    pub(crate) reason: String,
}

impl From<&LinuxMitmBrowserPlanStep> for JsonMitmBrowserPlanStep {
    fn from(step: &LinuxMitmBrowserPlanStep) -> Self {
        Self {
            id: step.id.clone(),
            status: step.status.clone(),
            reason: step.reason.clone(),
        }
    }
}

#[derive(Serialize)]
pub(crate) struct JsonMitmCertificateLifecycleReport {
    pub(crate) action: String,
    pub(crate) source_contract_status: String,
    pub(crate) gate: String,
    pub(crate) gate_status: String,
    pub(crate) mutation_ready: bool,
    pub(crate) request: JsonMitmCertificateLifecycleRequest,
    pub(crate) plan: JsonMitmCertificatePlan,
    pub(crate) trust_plan: JsonMitmCertificateTrustPlan,
    pub(crate) apply_report: Option<JsonMitmCertificateApplyReport>,
    pub(crate) rollback_report: Option<JsonMitmCertificateRollbackReport>,
}

impl From<&LinuxMitmCertificateLifecycleReport> for JsonMitmCertificateLifecycleReport {
    fn from(report: &LinuxMitmCertificateLifecycleReport) -> Self {
        Self {
            action: report.action.clone(),
            source_contract_status: report.source_contract_status.clone(),
            gate: report.gate.clone(),
            gate_status: report.gate_status.clone(),
            mutation_ready: report.mutation_ready,
            request: JsonMitmCertificateLifecycleRequest::from(&report.request),
            plan: JsonMitmCertificatePlan::from(&report.plan),
            trust_plan: JsonMitmCertificateTrustPlan::from(&report.trust_plan),
            apply_report: report
                .apply_report
                .as_ref()
                .map(JsonMitmCertificateApplyReport::from),
            rollback_report: report
                .rollback_report
                .as_ref()
                .map(JsonMitmCertificateRollbackReport::from),
        }
    }
}

#[derive(Serialize)]
pub(crate) struct JsonMitmCertificateLifecycleRequest {
    pub(crate) action: String,
    pub(crate) artifact: Option<JsonMitmCertificateArtifactRequest>,
    pub(crate) authorization: Option<JsonMitmCertificateAuthorization>,
    pub(crate) rollback_snapshot: Option<JsonMitmCertificateRollbackSnapshot>,
}

impl From<&LinuxMitmCertificateLifecycleRequest> for JsonMitmCertificateLifecycleRequest {
    fn from(request: &LinuxMitmCertificateLifecycleRequest) -> Self {
        Self {
            action: request.action.as_str().to_string(),
            artifact: request
                .artifact
                .as_ref()
                .map(JsonMitmCertificateArtifactRequest::from),
            authorization: request
                .authorization
                .as_ref()
                .map(JsonMitmCertificateAuthorization::from),
            rollback_snapshot: request
                .rollback_snapshot
                .as_ref()
                .map(JsonMitmCertificateRollbackSnapshot::from),
        }
    }
}

#[derive(Serialize)]
pub(crate) struct JsonMitmCertificateArtifactRequest {
    pub(crate) cert_file_path: String,
    pub(crate) key_file_path: String,
    pub(crate) profile_trust_file_path: Option<String>,
    pub(crate) snapshot_path: String,
    pub(crate) subject: String,
    pub(crate) artifact_version: u8,
    pub(crate) cert_content: String,
    pub(crate) key_content: String,
    pub(crate) profile_trust_content: Option<String>,
    pub(crate) cert_fingerprint: String,
    pub(crate) key_fingerprint: String,
    pub(crate) profile_trust_fingerprint: Option<String>,
}

impl From<&LinuxMitmCertificateArtifactRequest> for JsonMitmCertificateArtifactRequest {
    fn from(request: &LinuxMitmCertificateArtifactRequest) -> Self {
        Self {
            cert_file_path: request.cert_file_path.clone(),
            key_file_path: request.key_file_path.clone(),
            profile_trust_file_path: request.profile_trust_file_path.clone(),
            snapshot_path: request.snapshot_path.clone(),
            subject: request.subject.clone(),
            artifact_version: request.artifact_version,
            cert_content: request.cert_content.clone(),
            key_content: request.key_content.clone(),
            profile_trust_content: request.profile_trust_content.clone(),
            cert_fingerprint: request.cert_fingerprint.clone(),
            key_fingerprint: request.key_fingerprint.clone(),
            profile_trust_fingerprint: request.profile_trust_fingerprint.clone(),
        }
    }
}

#[derive(Serialize)]
pub(crate) struct JsonMitmCertificateAuthorization {
    pub(crate) confirmed: bool,
    pub(crate) source: String,
    pub(crate) scope: String,
    pub(crate) gate: String,
}

impl From<&MitmCertificateAuthorization> for JsonMitmCertificateAuthorization {
    fn from(authorization: &MitmCertificateAuthorization) -> Self {
        Self {
            confirmed: authorization.confirmed,
            source: authorization.source.clone(),
            scope: authorization.scope.clone(),
            gate: authorization.gate.clone(),
        }
    }
}

#[derive(Serialize)]
pub(crate) struct JsonMitmCertificateRollbackSnapshot {
    pub(crate) path: String,
    pub(crate) status: String,
}

impl From<&MitmCertificateRollbackSnapshot> for JsonMitmCertificateRollbackSnapshot {
    fn from(snapshot: &MitmCertificateRollbackSnapshot) -> Self {
        Self {
            path: snapshot.path.clone(),
            status: snapshot.status.clone(),
        }
    }
}

#[derive(Serialize)]
pub(crate) struct JsonMitmCertificateTrustPlan {
    pub(crate) status: String,
    pub(crate) mutation_ready: bool,
    pub(crate) required_steps: Vec<JsonMitmCertificatePlanStep>,
    pub(crate) blocked_operations: Vec<String>,
}

impl From<&LinuxMitmCertificateTrustPlan> for JsonMitmCertificateTrustPlan {
    fn from(plan: &LinuxMitmCertificateTrustPlan) -> Self {
        Self {
            status: plan.status.clone(),
            mutation_ready: plan.mutation_ready,
            required_steps: plan
                .required_steps
                .iter()
                .map(JsonMitmCertificatePlanStep::from)
                .collect(),
            blocked_operations: plan.blocked_operations.clone(),
        }
    }
}

#[derive(Serialize)]
pub(crate) struct JsonMitmCertificateApplyReport {
    pub(crate) status: String,
    pub(crate) applied: bool,
    pub(crate) authorization: JsonMitmCertificateAuthorization,
    pub(crate) cert_file_path: Option<String>,
    pub(crate) key_file_path: Option<String>,
    pub(crate) profile_trust_file_path: Option<String>,
    pub(crate) rollback_snapshot: Option<JsonMitmCertificateRollbackSnapshot>,
    pub(crate) blocked_operations: Vec<String>,
}

impl From<&LinuxMitmCertificateApplyReport> for JsonMitmCertificateApplyReport {
    fn from(report: &LinuxMitmCertificateApplyReport) -> Self {
        Self {
            status: report.status.clone(),
            applied: report.applied,
            authorization: JsonMitmCertificateAuthorization::from(&report.authorization),
            cert_file_path: report.cert_file_path.clone(),
            key_file_path: report.key_file_path.clone(),
            profile_trust_file_path: report.profile_trust_file_path.clone(),
            rollback_snapshot: report
                .rollback_snapshot
                .as_ref()
                .map(JsonMitmCertificateRollbackSnapshot::from),
            blocked_operations: report.blocked_operations.clone(),
        }
    }
}

#[derive(Serialize)]
pub(crate) struct JsonMitmCertificateRollbackReport {
    pub(crate) status: String,
    pub(crate) rolled_back: bool,
    pub(crate) cert_file_path: Option<String>,
    pub(crate) key_file_path: Option<String>,
    pub(crate) profile_trust_file_path: Option<String>,
    pub(crate) rollback_snapshot: Option<JsonMitmCertificateRollbackSnapshot>,
    pub(crate) blocked_operations: Vec<String>,
}

impl From<&LinuxMitmCertificateRollbackReport> for JsonMitmCertificateRollbackReport {
    fn from(report: &LinuxMitmCertificateRollbackReport) -> Self {
        Self {
            status: report.status.clone(),
            rolled_back: report.rolled_back,
            cert_file_path: report.cert_file_path.clone(),
            key_file_path: report.key_file_path.clone(),
            profile_trust_file_path: report.profile_trust_file_path.clone(),
            rollback_snapshot: report
                .rollback_snapshot
                .as_ref()
                .map(JsonMitmCertificateRollbackSnapshot::from),
            blocked_operations: report.blocked_operations.clone(),
        }
    }
}

#[derive(Serialize)]
pub(crate) struct JsonBrowserCaptureReport {
    pub(crate) action: String,
    pub(crate) source_contract_status: String,
    pub(crate) gate: String,
    pub(crate) gate_status: String,
    pub(crate) mutation_ready: bool,
    pub(crate) request: JsonBrowserCaptureRequest,
    pub(crate) plan: JsonBrowserCapturePlan,
    pub(crate) session_plan: Option<JsonBrowserCaptureSessionPlanReport>,
    pub(crate) launch_report: Option<JsonBrowserCaptureLaunchReport>,
    pub(crate) apply_report: Option<JsonBrowserCaptureApplyReport>,
    pub(crate) rollback_report: Option<JsonBrowserCaptureRollbackReport>,
    pub(crate) verify_report: Option<JsonBrowserCaptureVerifyReport>,
    pub(crate) traffic_proof_report: Option<JsonBrowserCaptureTrafficProofReport>,
}

impl From<&LinuxBrowserCaptureReport> for JsonBrowserCaptureReport {
    fn from(report: &LinuxBrowserCaptureReport) -> Self {
        Self {
            action: report.action.clone(),
            source_contract_status: report.source_contract_status.clone(),
            gate: report.gate.clone(),
            gate_status: report.gate_status.clone(),
            mutation_ready: report.mutation_ready,
            request: JsonBrowserCaptureRequest::from(&report.request),
            plan: JsonBrowserCapturePlan::from(&report.plan),
            session_plan: report
                .session_plan
                .as_ref()
                .map(JsonBrowserCaptureSessionPlanReport::from),
            launch_report: report
                .launch_report
                .as_ref()
                .map(JsonBrowserCaptureLaunchReport::from),
            apply_report: report
                .apply_report
                .as_ref()
                .map(JsonBrowserCaptureApplyReport::from),
            rollback_report: report
                .rollback_report
                .as_ref()
                .map(JsonBrowserCaptureRollbackReport::from),
            verify_report: report
                .verify_report
                .as_ref()
                .map(JsonBrowserCaptureVerifyReport::from),
            traffic_proof_report: report
                .traffic_proof_report
                .as_ref()
                .map(JsonBrowserCaptureTrafficProofReport::from),
        }
    }
}

#[derive(Serialize)]
pub(crate) struct JsonBrowserCaptureRequest {
    pub(crate) action: String,
    pub(crate) session: Option<JsonBrowserCaptureSessionPlanRequest>,
    pub(crate) launch: Option<JsonBrowserCaptureLaunchRequest>,
    pub(crate) pac: Option<JsonBrowserCapturePacRequest>,
    pub(crate) verify: Option<JsonBrowserCaptureVerifyRequest>,
    pub(crate) traffic_proof: Option<JsonBrowserCaptureTrafficProofRequest>,
    pub(crate) authorization: Option<JsonBrowserCaptureAuthorization>,
    pub(crate) rollback_snapshot: Option<JsonBrowserCaptureRollbackSnapshot>,
}

impl From<&LinuxBrowserCaptureRequest> for JsonBrowserCaptureRequest {
    fn from(request: &LinuxBrowserCaptureRequest) -> Self {
        Self {
            action: request.action.as_str().to_string(),
            session: request
                .session
                .as_ref()
                .map(JsonBrowserCaptureSessionPlanRequest::from),
            launch: request
                .launch
                .as_ref()
                .map(JsonBrowserCaptureLaunchRequest::from),
            pac: request.pac.as_ref().map(JsonBrowserCapturePacRequest::from),
            verify: request
                .verify
                .as_ref()
                .map(JsonBrowserCaptureVerifyRequest::from),
            traffic_proof: request
                .traffic_proof
                .as_ref()
                .map(JsonBrowserCaptureTrafficProofRequest::from),
            authorization: request
                .authorization
                .as_ref()
                .map(JsonBrowserCaptureAuthorization::from),
            rollback_snapshot: request
                .rollback_snapshot
                .as_ref()
                .map(JsonBrowserCaptureRollbackSnapshot::from),
        }
    }
}

#[derive(Serialize)]
pub(crate) struct JsonBrowserCapturePacRequest {
    pub(crate) proxy_host: String,
    pub(crate) proxy_port: u16,
    pub(crate) proxy_scheme: String,
    pub(crate) proxy_url: String,
    pub(crate) pac_file_path: String,
    pub(crate) snapshot_path: String,
    pub(crate) pac_url: String,
    pub(crate) pac_content: String,
    pub(crate) policy_file_path: Option<String>,
    pub(crate) policy_url: Option<String>,
    pub(crate) policy_content: Option<String>,
    pub(crate) profile_prefs_file_path: Option<String>,
    pub(crate) profile_prefs_content: Option<String>,
}

impl From<&LinuxBrowserCapturePacRequest> for JsonBrowserCapturePacRequest {
    fn from(request: &LinuxBrowserCapturePacRequest) -> Self {
        Self {
            proxy_host: request.proxy_host.clone(),
            proxy_port: request.proxy_port,
            proxy_scheme: request.proxy_scheme.clone(),
            proxy_url: request.proxy_url.clone(),
            pac_file_path: request.pac_file_path.clone(),
            snapshot_path: request.snapshot_path.clone(),
            pac_url: request.pac_url.clone(),
            pac_content: request.pac_content.clone(),
            policy_file_path: request.policy_file_path.clone(),
            policy_url: request.policy_url.clone(),
            policy_content: request.policy_content.clone(),
            profile_prefs_file_path: request.profile_prefs_file_path.clone(),
            profile_prefs_content: request.profile_prefs_content.clone(),
        }
    }
}

#[derive(Serialize)]
pub(crate) struct JsonBrowserCaptureSessionPlanRequest {
    pub(crate) url_source: String,
    pub(crate) browser: String,
    pub(crate) profile_dir: String,
    pub(crate) target_url: Option<String>,
    pub(crate) proof_target_url: Option<String>,
    pub(crate) proof_token: String,
    pub(crate) proof_log_path: String,
    pub(crate) proxy_scheme: String,
    pub(crate) listen_host: String,
    pub(crate) listen_port: u16,
}

impl From<&LinuxBrowserCaptureSessionPlanRequest> for JsonBrowserCaptureSessionPlanRequest {
    fn from(request: &LinuxBrowserCaptureSessionPlanRequest) -> Self {
        Self {
            url_source: request.url_source.clone(),
            browser: request.browser.clone(),
            profile_dir: request.profile_dir.clone(),
            target_url: request.target_url.clone(),
            proof_target_url: request.proof_target_url.clone(),
            proof_token: request.proof_token.clone(),
            proof_log_path: request.proof_log_path.clone(),
            proxy_scheme: request.proxy_scheme.clone(),
            listen_host: request.listen_host.clone(),
            listen_port: request.listen_port,
        }
    }
}

#[derive(Serialize)]
pub(crate) struct JsonBrowserCaptureSessionPlanReport {
    pub(crate) status: String,
    pub(crate) url_source: String,
    pub(crate) node_id: String,
    pub(crate) node_name: String,
    pub(crate) target_url: Option<String>,
    pub(crate) proof_target_url: Option<String>,
    pub(crate) proof_token: String,
    pub(crate) proof_log_path: String,
    pub(crate) listen_host: String,
    pub(crate) listen_port: u16,
    pub(crate) proxy_scheme: String,
    pub(crate) proxy_url: String,
    pub(crate) run_command: String,
    pub(crate) browser_command: JsonBrowserCaptureLaunchCommand,
    pub(crate) verify_command: String,
    pub(crate) traffic_proof_command: String,
    pub(crate) plugin_engine: String,
    pub(crate) plugin_id: String,
    pub(crate) plugin_version: String,
    pub(crate) required_steps: Vec<String>,
    pub(crate) blocked_operations: Vec<String>,
}

impl From<&LinuxBrowserCaptureSessionPlanReport> for JsonBrowserCaptureSessionPlanReport {
    fn from(report: &LinuxBrowserCaptureSessionPlanReport) -> Self {
        Self {
            status: report.status.clone(),
            url_source: report.url_source.clone(),
            node_id: report.node_id.clone(),
            node_name: report.node_name.clone(),
            target_url: report.target_url.clone(),
            proof_target_url: report.proof_target_url.clone(),
            proof_token: report.proof_token.clone(),
            proof_log_path: report.proof_log_path.clone(),
            listen_host: report.listen_host.clone(),
            listen_port: report.listen_port,
            proxy_scheme: report.proxy_scheme.clone(),
            proxy_url: report.proxy_url.clone(),
            run_command: report.run_command.clone(),
            browser_command: JsonBrowserCaptureLaunchCommand::from(&report.browser_command),
            verify_command: report.verify_command.clone(),
            traffic_proof_command: report.traffic_proof_command.clone(),
            plugin_engine: report.plugin_engine.clone(),
            plugin_id: report.plugin_id.clone(),
            plugin_version: report.plugin_version.clone(),
            required_steps: report.required_steps.clone(),
            blocked_operations: report.blocked_operations.clone(),
        }
    }
}

#[derive(Serialize)]
pub(crate) struct JsonBrowserCaptureVerifyRequest {
    pub(crate) proxy_host: String,
    pub(crate) proxy_port: u16,
    pub(crate) proxy_scheme: String,
    pub(crate) proxy_url: String,
    pub(crate) target_url: Option<String>,
    pub(crate) probe: String,
}

impl From<&LinuxBrowserCaptureVerifyRequest> for JsonBrowserCaptureVerifyRequest {
    fn from(request: &LinuxBrowserCaptureVerifyRequest) -> Self {
        Self {
            proxy_host: request.proxy_host.clone(),
            proxy_port: request.proxy_port,
            proxy_scheme: request.proxy_scheme.clone(),
            proxy_url: request.proxy_url.clone(),
            target_url: request.target_url.clone(),
            probe: request.probe.clone(),
        }
    }
}

#[derive(Serialize)]
pub(crate) struct JsonBrowserCaptureTrafficProofRequest {
    pub(crate) proxy_host: String,
    pub(crate) proxy_port: u16,
    pub(crate) proxy_scheme: String,
    pub(crate) proxy_url: String,
    pub(crate) target_url: Option<String>,
    pub(crate) proof_connect_authority: Option<String>,
    pub(crate) proof_target_url: Option<String>,
    pub(crate) proof_token: String,
    pub(crate) proof_log_path: String,
    pub(crate) probe: String,
}

impl From<&LinuxBrowserCaptureTrafficProofRequest> for JsonBrowserCaptureTrafficProofRequest {
    fn from(request: &LinuxBrowserCaptureTrafficProofRequest) -> Self {
        Self {
            proxy_host: request.proxy_host.clone(),
            proxy_port: request.proxy_port,
            proxy_scheme: request.proxy_scheme.clone(),
            proxy_url: request.proxy_url.clone(),
            target_url: request.target_url.clone(),
            proof_connect_authority: request.proof_connect_authority.clone(),
            proof_target_url: request.proof_target_url.clone(),
            proof_token: request.proof_token.clone(),
            proof_log_path: request.proof_log_path.clone(),
            probe: request.probe.clone(),
        }
    }
}

#[derive(Serialize)]
pub(crate) struct JsonBrowserCaptureAuthorization {
    pub(crate) confirmed: bool,
    pub(crate) source: String,
    pub(crate) scope: String,
    pub(crate) gate: String,
}

impl From<&BrowserCaptureAuthorization> for JsonBrowserCaptureAuthorization {
    fn from(authorization: &BrowserCaptureAuthorization) -> Self {
        Self {
            confirmed: authorization.confirmed,
            source: authorization.source.clone(),
            scope: authorization.scope.clone(),
            gate: authorization.gate.clone(),
        }
    }
}

#[derive(Serialize)]
pub(crate) struct JsonBrowserCaptureRollbackSnapshot {
    pub(crate) path: String,
    pub(crate) status: String,
}

impl From<&BrowserCaptureRollbackSnapshot> for JsonBrowserCaptureRollbackSnapshot {
    fn from(snapshot: &BrowserCaptureRollbackSnapshot) -> Self {
        Self {
            path: snapshot.path.clone(),
            status: snapshot.status.clone(),
        }
    }
}

#[derive(Serialize)]
pub(crate) struct JsonBrowserCapturePlan {
    pub(crate) status: String,
    pub(crate) mutation_ready: bool,
    pub(crate) current_capture: String,
    pub(crate) planned_capture_mode: String,
    pub(crate) planned_proxy_scheme: String,
    pub(crate) planned_proxy_host: String,
    pub(crate) planned_proxy_port: u16,
    pub(crate) manual_launch: JsonBrowserCaptureManualLaunch,
    pub(crate) required_steps: Vec<JsonMitmBrowserPlanStep>,
    pub(crate) blocked_operations: Vec<String>,
}

impl From<&LinuxBrowserCapturePlan> for JsonBrowserCapturePlan {
    fn from(plan: &LinuxBrowserCapturePlan) -> Self {
        Self {
            status: plan.status.clone(),
            mutation_ready: plan.mutation_ready,
            current_capture: plan.current_capture.clone(),
            planned_capture_mode: plan.planned_capture_mode.clone(),
            planned_proxy_scheme: plan.planned_proxy_scheme.clone(),
            planned_proxy_host: plan.planned_proxy_host.clone(),
            planned_proxy_port: plan.planned_proxy_port,
            manual_launch: JsonBrowserCaptureManualLaunch::from(&plan.manual_launch),
            required_steps: plan
                .required_steps
                .iter()
                .map(JsonMitmBrowserPlanStep::from)
                .collect(),
            blocked_operations: plan.blocked_operations.clone(),
        }
    }
}

#[derive(Serialize)]
pub(crate) struct JsonBrowserCaptureManualLaunch {
    pub(crate) status: String,
    pub(crate) proxy_scheme: String,
    pub(crate) proxy_url: String,
    pub(crate) profile_strategy: String,
    pub(crate) plugin_engine: String,
    pub(crate) plugin_id: String,
    pub(crate) plugin_version: String,
    pub(crate) browser_commands: Vec<JsonBrowserCaptureLaunchCommand>,
    pub(crate) manual_steps: Vec<String>,
}

impl From<&LinuxBrowserCaptureManualLaunch> for JsonBrowserCaptureManualLaunch {
    fn from(plan: &LinuxBrowserCaptureManualLaunch) -> Self {
        Self {
            status: plan.status.clone(),
            proxy_scheme: plan.proxy_scheme.clone(),
            proxy_url: plan.proxy_url.clone(),
            profile_strategy: plan.profile_strategy.clone(),
            plugin_engine: plan.plugin_engine.clone(),
            plugin_id: plan.plugin_id.clone(),
            plugin_version: plan.plugin_version.clone(),
            browser_commands: plan
                .browser_commands
                .iter()
                .map(JsonBrowserCaptureLaunchCommand::from)
                .collect(),
            manual_steps: plan.manual_steps.clone(),
        }
    }
}

#[derive(Serialize)]
pub(crate) struct JsonBrowserCaptureLaunchCommand {
    pub(crate) browser: String,
    pub(crate) executable: String,
    pub(crate) args: Vec<String>,
    pub(crate) command: String,
}

impl From<&LinuxBrowserCaptureLaunchCommand> for JsonBrowserCaptureLaunchCommand {
    fn from(command: &LinuxBrowserCaptureLaunchCommand) -> Self {
        Self {
            browser: command.browser.clone(),
            executable: command.executable.clone(),
            args: command.args.clone(),
            command: command.command.clone(),
        }
    }
}

#[derive(Serialize)]
pub(crate) struct JsonBrowserCaptureLaunchRequest {
    pub(crate) browser: String,
    pub(crate) profile_dir: String,
    pub(crate) target_url: Option<String>,
    pub(crate) proof_target_url: Option<String>,
    pub(crate) proof_token: String,
    pub(crate) proof_log_path: String,
    pub(crate) traffic_proof_command: String,
    pub(crate) proxy_scheme: String,
    pub(crate) proxy_url: String,
    pub(crate) command: JsonBrowserCaptureLaunchCommand,
}

impl From<&LinuxBrowserCaptureLaunchRequest> for JsonBrowserCaptureLaunchRequest {
    fn from(request: &LinuxBrowserCaptureLaunchRequest) -> Self {
        Self {
            browser: request.browser.clone(),
            profile_dir: request.profile_dir.clone(),
            target_url: request.target_url.clone(),
            proof_target_url: request.proof_target_url.clone(),
            proof_token: request.proof_token.clone(),
            proof_log_path: request.proof_log_path.clone(),
            traffic_proof_command: request.traffic_proof_command.clone(),
            proxy_scheme: request.proxy_scheme.clone(),
            proxy_url: request.proxy_url.clone(),
            command: JsonBrowserCaptureLaunchCommand::from(&request.command),
        }
    }
}

#[derive(Serialize)]
pub(crate) struct JsonBrowserCaptureLaunchReport {
    pub(crate) status: String,
    pub(crate) launched: bool,
    pub(crate) pid: Option<u32>,
    pub(crate) request: JsonBrowserCaptureLaunchRequest,
    pub(crate) plugin_engine: String,
    pub(crate) plugin_id: String,
    pub(crate) plugin_version: String,
}

impl From<&LinuxBrowserCaptureLaunchReport> for JsonBrowserCaptureLaunchReport {
    fn from(report: &LinuxBrowserCaptureLaunchReport) -> Self {
        Self {
            status: report.status.clone(),
            launched: report.launched,
            pid: report.pid,
            request: JsonBrowserCaptureLaunchRequest::from(&report.request),
            plugin_engine: report.plugin_engine.clone(),
            plugin_id: report.plugin_id.clone(),
            plugin_version: report.plugin_version.clone(),
        }
    }
}

#[derive(Serialize)]
pub(crate) struct JsonBrowserCaptureApplyReport {
    pub(crate) status: String,
    pub(crate) applied: bool,
    pub(crate) authorization: JsonBrowserCaptureAuthorization,
    pub(crate) pac_file_path: Option<String>,
    pub(crate) pac_url: Option<String>,
    pub(crate) policy_file_path: Option<String>,
    pub(crate) policy_url: Option<String>,
    pub(crate) profile_prefs_file_path: Option<String>,
    pub(crate) rollback_snapshot: Option<JsonBrowserCaptureRollbackSnapshot>,
    pub(crate) blocked_operations: Vec<String>,
}

impl From<&LinuxBrowserCaptureApplyReport> for JsonBrowserCaptureApplyReport {
    fn from(report: &LinuxBrowserCaptureApplyReport) -> Self {
        Self {
            status: report.status.clone(),
            applied: report.applied,
            authorization: JsonBrowserCaptureAuthorization::from(&report.authorization),
            pac_file_path: report.pac_file_path.clone(),
            pac_url: report.pac_url.clone(),
            policy_file_path: report.policy_file_path.clone(),
            policy_url: report.policy_url.clone(),
            profile_prefs_file_path: report.profile_prefs_file_path.clone(),
            rollback_snapshot: report
                .rollback_snapshot
                .as_ref()
                .map(JsonBrowserCaptureRollbackSnapshot::from),
            blocked_operations: report.blocked_operations.clone(),
        }
    }
}

#[derive(Serialize)]
pub(crate) struct JsonBrowserCaptureRollbackReport {
    pub(crate) status: String,
    pub(crate) rolled_back: bool,
    pub(crate) pac_file_path: Option<String>,
    pub(crate) policy_file_path: Option<String>,
    pub(crate) profile_prefs_file_path: Option<String>,
    pub(crate) rollback_snapshot: Option<JsonBrowserCaptureRollbackSnapshot>,
    pub(crate) blocked_operations: Vec<String>,
}

impl From<&LinuxBrowserCaptureRollbackReport> for JsonBrowserCaptureRollbackReport {
    fn from(report: &LinuxBrowserCaptureRollbackReport) -> Self {
        Self {
            status: report.status.clone(),
            rolled_back: report.rolled_back,
            pac_file_path: report.pac_file_path.clone(),
            policy_file_path: report.policy_file_path.clone(),
            profile_prefs_file_path: report.profile_prefs_file_path.clone(),
            rollback_snapshot: report
                .rollback_snapshot
                .as_ref()
                .map(JsonBrowserCaptureRollbackSnapshot::from),
            blocked_operations: report.blocked_operations.clone(),
        }
    }
}

#[derive(Serialize)]
pub(crate) struct JsonBrowserCaptureVerifyReport {
    pub(crate) status: String,
    pub(crate) verified: bool,
    pub(crate) request: JsonBrowserCaptureVerifyRequest,
    pub(crate) plugin_engine: String,
    pub(crate) plugin_id: String,
    pub(crate) plugin_version: String,
    pub(crate) blocked_operations: Vec<String>,
}

impl From<&LinuxBrowserCaptureVerifyReport> for JsonBrowserCaptureVerifyReport {
    fn from(report: &LinuxBrowserCaptureVerifyReport) -> Self {
        Self {
            status: report.status.clone(),
            verified: report.verified,
            request: JsonBrowserCaptureVerifyRequest::from(&report.request),
            plugin_engine: report.plugin_engine.clone(),
            plugin_id: report.plugin_id.clone(),
            plugin_version: report.plugin_version.clone(),
            blocked_operations: report.blocked_operations.clone(),
        }
    }
}

#[derive(Serialize)]
pub(crate) struct JsonBrowserCaptureTrafficProofReport {
    pub(crate) status: String,
    pub(crate) proven: bool,
    pub(crate) request: JsonBrowserCaptureTrafficProofRequest,
    pub(crate) plugin_engine: String,
    pub(crate) plugin_id: String,
    pub(crate) plugin_version: String,
    pub(crate) blocked_operations: Vec<String>,
}

impl From<&LinuxBrowserCaptureTrafficProofReport> for JsonBrowserCaptureTrafficProofReport {
    fn from(report: &LinuxBrowserCaptureTrafficProofReport) -> Self {
        Self {
            status: report.status.clone(),
            proven: report.proven,
            request: JsonBrowserCaptureTrafficProofRequest::from(&report.request),
            plugin_engine: report.plugin_engine.clone(),
            plugin_id: report.plugin_id.clone(),
            plugin_version: report.plugin_version.clone(),
            blocked_operations: report.blocked_operations.clone(),
        }
    }
}

#[derive(Serialize)]
pub(crate) struct JsonMitmHttpRewriteReport {
    pub(crate) action: String,
    pub(crate) source_contract_status: String,
    pub(crate) gate: String,
    pub(crate) gate_status: String,
    pub(crate) mutation_ready: bool,
    pub(crate) live_traffic_ready: bool,
    pub(crate) tls_decryption_ready: bool,
    pub(crate) controlled_tls_termination_plan_ready: bool,
    pub(crate) downstream_tls_termination_plan_ready: bool,
    pub(crate) upstream_tls_forwarding_ready: bool,
    pub(crate) https_request_rewrite_preview_ready: bool,
    pub(crate) https_response_rewrite_preview_ready: bool,
    pub(crate) https_response_rewrite_ready: bool,
    pub(crate) script_dispatch_ready: bool,
    pub(crate) certificate_pinning_bypass_supported: bool,
    pub(crate) http2_mitm_supported: bool,
    pub(crate) http3_quic_mitm_supported: bool,
    pub(crate) request: JsonMitmHttpRewriteRequest,
    pub(crate) outcome: Option<JsonMitmHttpRewriteOutcomeReport>,
    pub(crate) blocked_operations: Vec<String>,
}

impl From<&LinuxMitmHttpRewriteReport> for JsonMitmHttpRewriteReport {
    fn from(report: &LinuxMitmHttpRewriteReport) -> Self {
        Self {
            action: report.action.clone(),
            source_contract_status: report.source_contract_status.clone(),
            gate: report.gate.clone(),
            gate_status: report.gate_status.clone(),
            mutation_ready: report.mutation_ready,
            live_traffic_ready: report.live_traffic_ready,
            tls_decryption_ready: report.tls_decryption_ready,
            controlled_tls_termination_plan_ready: report.controlled_tls_termination_plan_ready,
            downstream_tls_termination_plan_ready: report.downstream_tls_termination_plan_ready,
            upstream_tls_forwarding_ready: report.upstream_tls_forwarding_ready,
            https_request_rewrite_preview_ready: report.https_request_rewrite_preview_ready,
            https_response_rewrite_preview_ready: report.https_response_rewrite_preview_ready,
            https_response_rewrite_ready: report.https_response_rewrite_ready,
            script_dispatch_ready: report.script_dispatch_ready,
            certificate_pinning_bypass_supported: report.certificate_pinning_bypass_supported,
            http2_mitm_supported: report.http2_mitm_supported,
            http3_quic_mitm_supported: report.http3_quic_mitm_supported,
            request: JsonMitmHttpRewriteRequest::from(&report.request),
            outcome: report
                .outcome
                .as_ref()
                .map(JsonMitmHttpRewriteOutcomeReport::from),
            blocked_operations: report.blocked_operations.clone(),
        }
    }
}

#[derive(Serialize)]
pub(crate) struct JsonMitmHttpRewriteRequest {
    pub(crate) url: Option<String>,
    pub(crate) method: String,
    pub(crate) phase: String,
    pub(crate) status_code: Option<u16>,
    pub(crate) headers: Vec<JsonMitmHttpHeader>,
    pub(crate) body: Option<String>,
    pub(crate) authorization: Option<JsonMitmHttpRewriteAuthorization>,
}

impl From<&LinuxMitmHttpRewriteRequest> for JsonMitmHttpRewriteRequest {
    fn from(request: &LinuxMitmHttpRewriteRequest) -> Self {
        Self {
            url: request.url.clone(),
            method: request.method.clone(),
            phase: request.phase.clone(),
            status_code: request.status_code,
            headers: request
                .headers
                .iter()
                .map(JsonMitmHttpHeader::from)
                .collect(),
            body: request.body.clone(),
            authorization: request
                .authorization
                .as_ref()
                .map(JsonMitmHttpRewriteAuthorization::from),
        }
    }
}

#[derive(Serialize)]
pub(crate) struct JsonMitmHttpRewriteAuthorization {
    pub(crate) confirmed: bool,
    pub(crate) source: String,
    pub(crate) scope: String,
    pub(crate) gate: String,
}

impl From<&LinuxMitmHttpRewriteAuthorization> for JsonMitmHttpRewriteAuthorization {
    fn from(authorization: &LinuxMitmHttpRewriteAuthorization) -> Self {
        Self {
            confirmed: authorization.confirmed,
            source: authorization.source.clone(),
            scope: authorization.scope.clone(),
            gate: authorization.gate.clone(),
        }
    }
}

#[derive(Serialize)]
pub(crate) struct JsonMitmHttpHeader {
    pub(crate) name: String,
    pub(crate) value: String,
}

impl From<&LinuxMitmHttpHeader> for JsonMitmHttpHeader {
    fn from(header: &LinuxMitmHttpHeader) -> Self {
        Self {
            name: header.name.clone(),
            value: header.value.clone(),
        }
    }
}

#[derive(Serialize)]
pub(crate) struct JsonMitmHttpRewriteOutcomeReport {
    pub(crate) planned: bool,
    pub(crate) applied: bool,
    pub(crate) action: String,
    pub(crate) terminal_action: Option<String>,
    pub(crate) final_status_code: Option<u16>,
    pub(crate) redirect_location: Option<String>,
    pub(crate) header_mutation_count: usize,
    pub(crate) body_mutated: bool,
    pub(crate) script_dispatch_deferred: bool,
    pub(crate) script_dispatch_failed: bool,
    pub(crate) output_headers: Vec<JsonMitmHttpHeader>,
    pub(crate) output_body: Option<String>,
}

impl From<&LinuxMitmHttpRewriteOutcomeReport> for JsonMitmHttpRewriteOutcomeReport {
    fn from(outcome: &LinuxMitmHttpRewriteOutcomeReport) -> Self {
        Self {
            planned: outcome.planned,
            applied: outcome.applied,
            action: outcome.action.clone(),
            terminal_action: outcome.terminal_action.clone(),
            final_status_code: outcome.final_status_code,
            redirect_location: outcome.redirect_location.clone(),
            header_mutation_count: outcome.header_mutation_count,
            body_mutated: outcome.body_mutated,
            script_dispatch_deferred: outcome.script_dispatch_deferred,
            script_dispatch_failed: outcome.script_dispatch_failed,
            output_headers: outcome
                .output_headers
                .iter()
                .map(JsonMitmHttpHeader::from)
                .collect(),
            output_body: outcome.output_body.clone(),
        }
    }
}

#[derive(Serialize)]
pub(crate) struct JsonMitmCertificatePlan {
    pub(crate) status: String,
    pub(crate) mutation_ready: bool,
    pub(crate) current_state: String,
    pub(crate) subject: Option<String>,
    pub(crate) fingerprint_sha256: Option<String>,
    pub(crate) required_steps: Vec<JsonMitmCertificatePlanStep>,
    pub(crate) blocked_operations: Vec<String>,
}

impl From<&LinuxMitmCertificatePlan> for JsonMitmCertificatePlan {
    fn from(plan: &LinuxMitmCertificatePlan) -> Self {
        Self {
            status: plan.status.clone(),
            mutation_ready: plan.mutation_ready,
            current_state: plan.current_state.clone(),
            subject: plan.subject.clone(),
            fingerprint_sha256: plan.fingerprint_sha256.clone(),
            required_steps: plan
                .required_steps
                .iter()
                .map(JsonMitmCertificatePlanStep::from)
                .collect(),
            blocked_operations: plan.blocked_operations.clone(),
        }
    }
}

#[derive(Serialize)]
pub(crate) struct JsonMitmCertificatePlanStep {
    pub(crate) id: String,
    pub(crate) status: String,
    pub(crate) reason: String,
}

impl From<&LinuxMitmCertificatePlanStep> for JsonMitmCertificatePlanStep {
    fn from(step: &LinuxMitmCertificatePlanStep) -> Self {
        Self {
            id: step.id.clone(),
            status: step.status.clone(),
            reason: step.reason.clone(),
        }
    }
}

#[derive(Serialize)]
pub(crate) struct JsonMitmPolicyStatus {
    pub(crate) engine: String,
    pub(crate) engine_version: String,
    pub(crate) plugin_id: String,
    pub(crate) plugin_version: String,
    pub(crate) plugin_loaded: bool,
    pub(crate) mitm_pattern_count: usize,
    pub(crate) rewrite_rule_count: usize,
    pub(crate) script_rule_count: usize,
    pub(crate) argument_count: usize,
}

impl From<&LinuxMitmPolicyStatus> for JsonMitmPolicyStatus {
    fn from(status: &LinuxMitmPolicyStatus) -> Self {
        Self {
            engine: status.engine.clone(),
            engine_version: status.engine_version.clone(),
            plugin_id: status.plugin_id.clone(),
            plugin_version: status.plugin_version.clone(),
            plugin_loaded: status.plugin_loaded,
            mitm_pattern_count: status.mitm_pattern_count,
            rewrite_rule_count: status.rewrite_rule_count,
            script_rule_count: status.script_rule_count,
            argument_count: status.argument_count,
        }
    }
}

#[derive(Serialize)]
pub(crate) struct JsonMitmGateStatus {
    pub(crate) gate: String,
    pub(crate) status: String,
    pub(crate) reason: String,
}

impl From<&LinuxMitmGateStatus> for JsonMitmGateStatus {
    fn from(status: &LinuxMitmGateStatus) -> Self {
        Self {
            gate: status.gate.clone(),
            status: status.status.clone(),
            reason: status.reason.clone(),
        }
    }
}

#[derive(Serialize)]
pub(crate) struct JsonDiagnostic {
    pub(crate) severity: &'static str,
    pub(crate) code: String,
    pub(crate) message: String,
    pub(crate) source: Option<String>,
}

impl From<&Diagnostic> for JsonDiagnostic {
    fn from(diagnostic: &Diagnostic) -> Self {
        Self {
            severity: severity_name(diagnostic.severity),
            code: diagnostic.code.clone(),
            message: redact_cli_output_text(&diagnostic.message),
            source: diagnostic.source.clone(),
        }
    }
}

#[derive(Serialize)]
pub(crate) struct JsonPlatform {
    pub(crate) os: &'static str,
    pub(crate) tunnel: JsonFeatureState,
    pub(crate) mitm: JsonFeatureState,
    pub(crate) embedded_runtime: JsonFeatureState,
    pub(crate) remote_script_execution: JsonFeatureState,
    pub(crate) mitm_certificate: JsonCertificateStatus,
}

impl From<&PlatformCapabilityStatus> for JsonPlatform {
    fn from(status: &PlatformCapabilityStatus) -> Self {
        Self {
            os: os_name(status.os),
            tunnel: JsonFeatureState::from(&status.tunnel),
            mitm: JsonFeatureState::from(&status.mitm),
            embedded_runtime: JsonFeatureState::from(&status.embedded_runtime),
            remote_script_execution: JsonFeatureState::from(&status.remote_script_execution),
            mitm_certificate: JsonCertificateStatus::from(status),
        }
    }
}

#[derive(Serialize)]
pub(crate) struct JsonFeatureState {
    pub(crate) state: &'static str,
    pub(crate) reason: Option<String>,
}

impl From<&PlatformFeatureState> for JsonFeatureState {
    fn from(state: &PlatformFeatureState) -> Self {
        match state {
            PlatformFeatureState::Available => Self {
                state: "available",
                reason: None,
            },
            PlatformFeatureState::Unavailable { reason } => Self {
                state: "unavailable",
                reason: Some(reason.clone()),
            },
            PlatformFeatureState::Unknown => Self {
                state: "unknown",
                reason: state.denial_reason().map(ToString::to_string),
            },
        }
    }
}

#[derive(Serialize)]
pub(crate) struct JsonCertificateStatus {
    pub(crate) state: &'static str,
    pub(crate) subject: Option<String>,
    pub(crate) fingerprint_sha256: Option<String>,
}

impl From<&PlatformCapabilityStatus> for JsonCertificateStatus {
    fn from(status: &PlatformCapabilityStatus) -> Self {
        Self {
            state: certificate_state_name(status.mitm_certificate.state),
            subject: status.mitm_certificate.subject.clone(),
            fingerprint_sha256: status.mitm_certificate.fingerprint_sha256.clone(),
        }
    }
}
