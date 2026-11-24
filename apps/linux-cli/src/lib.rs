//! Linux CLI entrypoint contracts for NetworkCore.
//!
//! The crate contains command parsing, response mapping, config I/O boundaries,
//! and foreground runtime handoff. Service installation/control and release
//! packaging remain explicit platform boundaries.

mod embedded_run;

pub use embedded_run::*;
mod cli_args;
mod dispatch;
mod engine_setup;
mod lifecycle_commands;
mod managed_session;
mod mitm_commands;
mod output;
mod output_json;
mod persistence;
mod platform_io;
mod service_commands;

pub use cli_args::*;
pub use dispatch::*;
pub use engine_setup::*;
pub use lifecycle_commands::*;
pub use managed_session::*;
pub use mitm_commands::*;
pub use output::*;
pub use output_json::*;
pub use persistence::*;
pub use platform_io::*;
pub use service_commands::*;

use config_core::CoreSubscriptionService;
use control_domain::{
    CertificateTrustState, ConfigurationService, Diagnostic, DiagnosticSeverity, DomainError,
    DomainResult, GrantedPermissions, HttpMitmAction, HttpMitmPhase, MetadataEntry,
    MitmPluginService, OperatingSystem, PlatformCapabilityService, PlatformCapabilityStatus,
    PlatformFeatureState, PluginPackage, ProxyEngineConfig, ProxyEngineDescriptor,
    ProxyEngineEvent, ProxyEngineHealthReport, ProxyEngineLifecycleState,
    ProxyEngineRollbackRequest, ProxyEngineService, ProxyEngineStatus, RawSubscription,
    SubscriptionService, SubscriptionSource,
};
use control_runtime::{RuntimeConfigRequest, RuntimeOperationResult, RuntimeOrchestrator};
use mitm_policy::{user_plugin_package, AnixOpsMitmPluginService, AnixOpsMitmPolicyEngine};
use platform_linux::proxy::{
    apply_environment_proxy, rollback_environment_proxy, status_environment_proxy,
    LinuxEnvironmentProxyApplyRequest, LinuxEnvironmentProxyRollbackRequest,
};
use platform_linux::systemd::{
    control_systemd_service, install_subscription_refresh_schedule, install_systemd_unit,
    plan_systemd_unit_removal, remove_systemd_unit, render_subscription_refresh_schedule,
    render_systemd_unit, stop_subscription_refresh_schedule, subscription_refresh_schedule_status,
    uninstall_subscription_refresh_schedule, LinuxManagedServiceUnitInstallRequest,
    LinuxManagedServiceUnitPlan, LinuxManagedServiceUnitRemovalPlan,
    LinuxManagedServiceUnitRemovalRequest, LinuxManagedServiceUnitRequest,
    LinuxSubscriptionRefreshScheduleRequest, LinuxSystemdCommandRunner, LinuxSystemdServiceAction,
    LinuxSystemdServiceControlRequest,
};
use platform_linux::trust::{
    apply_linux_trust, rollback_linux_trust, CommandLinuxTrustRefreshRunner,
    LinuxTrustApplyRequest, LinuxTrustRollbackRequest,
};
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, KeyPair, KeyUsagePurpose,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
#[cfg(unix)]
use signal_hook::{
    consts::signal::{SIGINT, SIGTERM},
    iterator::Signals,
};
use std::collections::BTreeMap;
use std::hash::{Hash, Hasher};
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
#[cfg(unix)]
use std::os::unix::net::{UnixListener, UnixStream};
#[cfg(unix)]
use std::os::unix::{fs::FileTypeExt, fs::OpenOptionsExt, fs::PermissionsExt};
use std::path::PathBuf;
#[cfg(unix)]
use std::sync::atomic::AtomicU8;
use std::sync::atomic::{AtomicU64, Ordering};
#[cfg(unix)]
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub const COMMAND_NAME: &str = "networkcore-linux";

fn redacted_config_digest(raw_config: &str) -> String {
    format!("{:x}", Sha256::digest(raw_config.as_bytes()))
}
pub const DEFAULT_ENGINE_ID: &str = "native";

pub const CLI_COMMAND_MISSING_CODE: &str = "cli.linux.command.missing";
pub const CLI_ARGUMENT_UNKNOWN_CODE: &str = "cli.linux.argument.unknown";
pub const CLI_ARGUMENT_VALUE_MISSING_CODE: &str = "cli.linux.argument.value_missing";
pub const CLI_OUTPUT_FORMAT_UNSUPPORTED_CODE: &str = "cli.linux.output.format_unsupported";
pub const CLI_CONFIG_PATH_MISSING_CODE: &str = "cli.linux.config.path_missing";
pub const CLI_CONFIG_READ_FAILED_CODE: &str = "cli.linux.config.read_failed";
pub const CLI_CONFIG_EMPTY_CODE: &str = "cli.linux.config.empty";
pub const CLI_START_PLATFORM_DENIED_CODE: &str = "cli.linux.start.platform_denied";
pub const CLI_START_CONFIG_DENIED_CODE: &str = "cli.linux.start.config_denied";
pub const CLI_START_ENGINE_DENIED_CODE: &str = "cli.linux.start.engine_denied";
pub const CLI_START_FOREGROUND_ONLY_CODE: &str = "cli.linux.start.foreground_only";
pub const CLI_START_LIFECYCLE_HOST_MISSING_CODE: &str = "cli.linux.start.lifecycle_host_missing";
pub const CLI_START_LIFECYCLE_INTERRUPTED_CODE: &str = "cli.linux.start.lifecycle_interrupted";
pub const CLI_START_LIFECYCLE_FAILED_CODE: &str = "cli.linux.start.lifecycle_failed";
pub const CLI_START_RUNTIME_STOP_FAILED_CODE: &str = "cli.linux.start.runtime_stop_failed";
pub const CLI_START_MANAGED_LIFECYCLE_CONFIG_INVALID_CODE: &str =
    "cli.linux.start.managed_lifecycle_config_invalid";
pub const CLI_START_MANAGED_LIFECYCLE_RECORD_FAILED_CODE: &str =
    "cli.linux.start.managed_lifecycle_record_failed";
pub const CLI_MANAGED_CONTROL_SOCKET_AUTHORIZATION_REQUIRED_CODE: &str =
    "cli.linux.managed_control_socket.authorization_required";
pub const CLI_MANAGED_CONTROL_SOCKET_START_FAILED_CODE: &str =
    "cli.linux.managed_control_socket.start_failed";
pub const CLI_MANAGED_CONTROL_SOCKET_START_READY_CODE: &str =
    "cli.linux.managed_control_socket.start_ready";
pub const CLI_MANAGED_CONTROL_SOCKET_STOP_READY_CODE: &str =
    "cli.linux.managed_control_socket.stop_ready";
pub const CLI_MANAGED_CONTROL_SOCKET_STOP_FAILED_CODE: &str =
    "cli.linux.managed_control_socket.stop_failed";
pub const CLI_MANAGED_CONTROL_SOCKET_RELOAD_READY_CODE: &str =
    "cli.linux.managed_control_socket.reload_ready";
pub const CLI_MANAGED_CONTROL_SOCKET_RELOAD_FAILED_CODE: &str =
    "cli.linux.managed_control_socket.reload_failed";
pub const CLI_MANAGED_CONTROL_SOCKET_STATUS_READY_CODE: &str =
    "cli.linux.managed_control_socket.status_ready";
pub const CLI_MANAGED_CONTROL_SOCKET_STATUS_FAILED_CODE: &str =
    "cli.linux.managed_control_socket.status_failed";
pub const CLI_MANAGED_CONTROL_SOCKET_ROLLBACK_READY_CODE: &str =
    "cli.linux.managed_control_socket.rollback_ready";
pub const CLI_MANAGED_CONTROL_SOCKET_ROLLBACK_FAILED_CODE: &str =
    "cli.linux.managed_control_socket.rollback_failed";
pub const CLI_MANAGED_CONTROL_SOCKET_REQUEST_PENDING_CODE: &str =
    "cli.linux.managed_control_socket.request_pending";
pub const CLI_START_SIGNAL_RECEIVED_CODE: &str = "cli.linux.start.signal_received";
pub const CLI_START_SIGNAL_SOURCE_FAILED_CODE: &str = "cli.linux.start.signal_source_failed";
pub const CLI_START_MANAGED_CONTROL_STOP_REQUESTED_CODE: &str =
    "cli.linux.start.managed_control_stop_requested";
pub const CLI_START_MANAGED_CONTROL_RELOAD_REQUESTED_CODE: &str =
    "cli.linux.start.managed_control_reload_requested";
pub const CLI_START_MANAGED_CONTROL_ROLLBACK_REQUESTED_CODE: &str =
    "cli.linux.start.managed_control_rollback_requested";
pub const CLI_START_RUNTIME_RELOAD_FAILED_CODE: &str = "cli.linux.start.runtime_reload_failed";
pub const CLI_START_TLS_MITM_AUTHORIZATION_REQUIRED_CODE: &str =
    "cli.linux.start.tls_mitm_authorization_required";
pub const CLI_START_TLS_MITM_MATERIAL_REQUIRED_CODE: &str =
    "cli.linux.start.tls_mitm_material_required";
pub const CLI_START_TLS_MITM_MATERIAL_READ_FAILED_CODE: &str =
    "cli.linux.start.tls_mitm_material_read_failed";
pub const CLI_START_TLS_MITM_PRIVATE_KEY_PROTECTION_FAILED_CODE: &str =
    "cli.linux.start.tls_mitm_private_key_protection_failed";
pub const CLI_START_MITM_PLUGIN_REQUIRED_CODE: &str = "cli.linux.start.mitm_plugin_required";
pub const CLI_MITM_PLUGIN_READ_FAILED_CODE: &str = "cli.linux.mitm.plugin_read_failed";
pub const CLI_START_SCRIPT_RUNTIME_AUTHORIZATION_REQUIRED_CODE: &str =
    "cli.linux.start.script_runtime_authorization_required";
pub const CLI_START_SCRIPT_RUNTIME_CONFIG_REQUIRED_CODE: &str =
    "cli.linux.start.script_runtime_config_required";
pub const CLI_START_SCRIPT_RUNTIME_CONFIG_INVALID_CODE: &str =
    "cli.linux.start.script_runtime_config_invalid";
pub const CLI_SUBSCRIPTION_CATALOG_PATH_MISSING_CODE: &str =
    "cli.linux.subscription_catalog.path_missing";
pub const CLI_SUBSCRIPTION_CATALOG_SNAPSHOT_PATH_MISSING_CODE: &str =
    "cli.linux.subscription_catalog.snapshot_path_missing";
pub const CLI_SUBSCRIPTION_CATALOG_SNAPSHOT_READ_FAILED_CODE: &str =
    "cli.linux.subscription_catalog.snapshot_read_failed";
pub const CLI_SUBSCRIPTION_CATALOG_PATH_CONFLICT_CODE: &str =
    "cli.linux.subscription_catalog.path_conflict";
pub const CLI_SUBSCRIPTION_CATALOG_SOURCE_ID_EMPTY_CODE: &str =
    "cli.linux.subscription_catalog.source_id_empty";
pub const CLI_SUBSCRIPTION_CATALOG_SOURCE_LOCATION_EMPTY_CODE: &str =
    "cli.linux.subscription_catalog.source_location_empty";
pub const CLI_SUBSCRIPTION_CATALOG_READ_FAILED_CODE: &str =
    "cli.linux.subscription_catalog.read_failed";
pub const CLI_SUBSCRIPTION_CATALOG_SCHEMA_UNSUPPORTED_CODE: &str =
    "cli.linux.subscription_catalog.schema_unsupported";
pub const CLI_SUBSCRIPTION_CATALOG_SOURCE_INVALID_CODE: &str =
    "cli.linux.subscription_catalog.source_invalid";
pub const CLI_SUBSCRIPTION_CATALOG_DUPLICATE_SOURCE_ID_CODE: &str =
    "cli.linux.subscription_catalog.duplicate_source_id";
pub const CLI_SUBSCRIPTION_CATALOG_SOURCE_NOT_FOUND_CODE: &str =
    "cli.linux.subscription_catalog.source_not_found";
pub const CLI_SUBSCRIPTION_CATALOG_SNAPSHOT_WRITE_FAILED_CODE: &str =
    "cli.linux.subscription_catalog.snapshot_write_failed";
pub const CLI_SUBSCRIPTION_CATALOG_WRITE_FAILED_CODE: &str =
    "cli.linux.subscription_catalog.write_failed";
pub const CLI_SUBSCRIPTION_CATALOG_UPDATE_VALIDATION_FAILED_CODE: &str =
    "cli.linux.subscription_catalog.update_validation_failed";
pub const CLI_SUBSCRIPTION_REFRESH_AUTHORIZATION_REQUIRED_CODE: &str =
    "cli.linux.subscription_refresh.authorization_required";
pub const CLI_SUBSCRIPTION_REFRESH_SOURCE_UNSUPPORTED_CODE: &str =
    "cli.linux.subscription_refresh.source_unsupported";
pub const CLI_SUBSCRIPTION_REFRESH_STATUS_READ_FAILED_CODE: &str =
    "cli.linux.subscription_refresh.status_read_failed";
pub const CLI_SUBSCRIPTION_REFRESH_STATUS_WRITE_FAILED_CODE: &str =
    "cli.linux.subscription_refresh.status_write_failed";
pub const CLI_SUBSCRIPTION_REFRESH_ALREADY_ACTIVE_CODE: &str =
    "cli.linux.subscription_refresh.already_active";
pub const CLI_SUBSCRIPTION_REFRESH_INTERVAL_TOO_SHORT_CODE: &str =
    "cli.linux.subscription_refresh.interval_too_short";
pub const CLI_SUBSCRIPTION_REFRESH_SCHEDULE_CONFIRMATION_REQUIRED_CODE: &str =
    "cli.linux.subscription_refresh.schedule_confirmation_required";
pub const CLI_MANAGED_FOREGROUND_STATUS_PATH_MISSING_CODE: &str =
    "cli.linux.managed_foreground_status.path_missing";
pub const CLI_MANAGED_FOREGROUND_STATUS_READ_FAILED_CODE: &str =
    "cli.linux.managed_foreground_status.read_failed";
pub const CLI_MANAGED_FOREGROUND_STATUS_WRITE_FAILED_CODE: &str =
    "cli.linux.managed_foreground_status.write_failed";
pub const CLI_MANAGED_FOREGROUND_STATUS_SNAPSHOT_PATH_MISSING_CODE: &str =
    "cli.linux.managed_foreground_status.snapshot_path_missing";
pub const CLI_MANAGED_FOREGROUND_STATUS_PATH_CONFLICT_CODE: &str =
    "cli.linux.managed_foreground_status.path_conflict";
pub const CLI_MANAGED_FOREGROUND_STATUS_SNAPSHOT_READ_FAILED_CODE: &str =
    "cli.linux.managed_foreground_status.snapshot_read_failed";
pub const CLI_MANAGED_FOREGROUND_STATUS_SNAPSHOT_WRITE_FAILED_CODE: &str =
    "cli.linux.managed_foreground_status.snapshot_write_failed";
pub const CLI_MANAGED_FOREGROUND_STATUS_STATE_CONFLICT_CODE: &str =
    "cli.linux.managed_foreground_status.state_conflict";
pub const CLI_MANAGED_FOREGROUND_STATUS_TRANSITION_INVALID_CODE: &str =
    "cli.linux.managed_foreground_status.transition_invalid";
pub const CLI_MANAGED_FOREGROUND_STATUS_ROLLBACK_INVALID_CODE: &str =
    "cli.linux.managed_foreground_status.rollback_invalid";
pub const CLI_MANAGED_FOREGROUND_STATUS_SCHEMA_UNSUPPORTED_CODE: &str =
    "cli.linux.managed_foreground_status.schema_unsupported";
pub const CLI_MANAGED_FOREGROUND_STATUS_RECORD_INVALID_CODE: &str =
    "cli.linux.managed_foreground_status.record_invalid";
pub const CLI_MANAGED_FOREGROUND_EVENT_PATH_MISSING_CODE: &str =
    "cli.linux.managed_foreground_event.path_missing";
pub const CLI_MANAGED_FOREGROUND_EVENT_DIRECTORY_MISSING_CODE: &str =
    "cli.linux.managed_foreground_event.directory_missing";
pub const CLI_MANAGED_FOREGROUND_EVENT_READ_FAILED_CODE: &str =
    "cli.linux.managed_foreground_event.read_failed";
pub const CLI_MANAGED_FOREGROUND_EVENT_WRITE_FAILED_CODE: &str =
    "cli.linux.managed_foreground_event.write_failed";
pub const CLI_MANAGED_FOREGROUND_EVENT_SCHEMA_UNSUPPORTED_CODE: &str =
    "cli.linux.managed_foreground_event.schema_unsupported";
pub const CLI_MANAGED_FOREGROUND_EVENT_RECORD_INVALID_CODE: &str =
    "cli.linux.managed_foreground_event.record_invalid";
pub const CLI_MANAGED_FOREGROUND_EVENT_HISTORY_QUERY_INVALID_CODE: &str =
    "cli.linux.managed_foreground_event.history_query_invalid";
pub const CLI_MANAGED_FOREGROUND_EVENT_HISTORY_LIMIT_EXCEEDED_CODE: &str =
    "cli.linux.managed_foreground_event.history_limit_exceeded";
pub const CLI_MANAGED_FOREGROUND_LOG_PATH_MISSING_CODE: &str =
    "cli.linux.managed_foreground_log.path_missing";
pub const CLI_MANAGED_FOREGROUND_LOG_READ_FAILED_CODE: &str =
    "cli.linux.managed_foreground_log.read_failed";
pub const CLI_MANAGED_FOREGROUND_LOG_QUERY_INVALID_CODE: &str =
    "cli.linux.managed_foreground_log.query_invalid";
pub const CLI_MANAGED_FOREGROUND_LOG_LIMIT_EXCEEDED_CODE: &str =
    "cli.linux.managed_foreground_log.limit_exceeded";
pub const CLI_STOP_UNAVAILABLE_WITHOUT_DAEMON_CODE: &str =
    "cli.linux.stop.unavailable_without_daemon";
pub const CLI_STATUS_NO_RUNTIME_CONTEXT_CODE: &str = "cli.linux.status.no_runtime_context";
pub const CLI_STATUS_PLATFORM_ONLY_CODE: &str = "cli.linux.status.platform_only";
pub const CLI_RUNTIME_UNWIRED_CODE: &str = "cli.linux.runtime.unwired";
pub const CLI_INSTALL_SERVICE_CONFIRMATION_REQUIRED_CODE: &str =
    "cli.linux.install_service.confirmation_required";
pub const CLI_INSTALL_SERVICE_PLAN_INVALID_CODE: &str = "cli.linux.install_service.plan_invalid";
pub const CLI_INSTALL_SERVICE_WRITE_FAILED_CODE: &str = "cli.linux.install_service.write_failed";
pub const CLI_RUN_URL_PARSE_FAILED_CODE: &str = "cli.linux.run_url.parse_failed";
pub const CLI_RUN_URL_FILE_URI_INVALID_CODE: &str = "cli.linux.run_url.file_uri_invalid";
pub const CLI_RUN_URL_FILE_READ_FAILED_CODE: &str = "cli.linux.run_url.file_read_failed";
pub const CLI_RUN_URL_REMOTE_FETCH_FAILED_CODE: &str = "cli.linux.run_url.remote_fetch_failed";
pub const CLI_RUN_URL_REMOTE_FETCH_LIMIT_EXCEEDED_CODE: &str =
    "cli.linux.run_url.remote_fetch_limit_exceeded";
pub const CLI_MITM_POLICY_READY_CODE: &str = "cli.linux.mitm.policy_ready";
pub const CLI_MITM_CLI_GATE_PARTIAL_CODE: &str = "cli.linux.mitm.cli_gate.partial";
pub const CLI_MITM_CERTIFICATE_PLAN_READY_CODE: &str = "cli.linux.mitm.certificate_plan.ready";
pub const CLI_MITM_CERTIFICATE_GATE_DEFERRED_CODE: &str =
    "cli.linux.mitm.certificate_gate.deferred";
pub const CLI_MITM_CERTIFICATE_MUTATION_BLOCKED_CODE: &str =
    "cli.linux.mitm.certificate_mutation.blocked";
pub const CLI_MITM_CERTIFICATE_AUTHORIZATION_REQUIRED_CODE: &str =
    "cli.linux.mitm.certificate.authorization_required";
pub const CLI_MITM_CERTIFICATE_APPLY_BLOCKED_CODE: &str =
    "cli.linux.mitm.certificate.apply.blocked";
pub const CLI_MITM_CERTIFICATE_APPLY_READY_CODE: &str = "cli.linux.mitm.certificate.apply.ready";
pub const CLI_MITM_CERTIFICATE_APPLY_CONFIG_MISSING_CODE: &str =
    "cli.linux.mitm.certificate.apply.config_missing";
pub const CLI_MITM_CERTIFICATE_MATERIAL_FAILED_CODE: &str =
    "cli.linux.mitm.certificate.material.failed";
pub const CLI_MITM_CERTIFICATE_ARTIFACT_WRITE_FAILED_CODE: &str =
    "cli.linux.mitm.certificate.artifact.write_failed";
pub const CLI_MITM_CERTIFICATE_SNAPSHOT_WRITE_FAILED_CODE: &str =
    "cli.linux.mitm.certificate.snapshot.write_failed";
pub const CLI_MITM_CERTIFICATE_SNAPSHOT_READ_FAILED_CODE: &str =
    "cli.linux.mitm.certificate.snapshot.read_failed";
pub const CLI_MITM_CERTIFICATE_ROLLBACK_BLOCKED_CODE: &str =
    "cli.linux.mitm.certificate.rollback.blocked";
pub const CLI_MITM_CERTIFICATE_ROLLBACK_READY_CODE: &str =
    "cli.linux.mitm.certificate.rollback.ready";
pub const CLI_MITM_CERTIFICATE_ROLLBACK_FAILED_CODE: &str =
    "cli.linux.mitm.certificate.rollback.failed";
pub const CLI_MITM_CERTIFICATE_TRUST_CONFIG_MISSING_CODE: &str =
    "cli.linux.mitm.certificate.trust.config_missing";
pub const CLI_MITM_CERTIFICATE_TRUST_APPLIED_CODE: &str =
    "cli.linux.mitm.certificate.trust.applied";
pub const CLI_MITM_CERTIFICATE_TRUST_ROLLED_BACK_CODE: &str =
    "cli.linux.mitm.certificate.trust.rolled_back";
pub const CLI_MITM_DATA_PLANE_GATE_DEFERRED_CODE: &str = "cli.linux.mitm.data_plane_gate.deferred";
pub const CLI_MITM_BROWSER_PLAN_READY_CODE: &str = "cli.linux.mitm.browser_plan.ready";
pub const CLI_MITM_BROWSER_CAPTURE_MUTATION_BLOCKED_CODE: &str =
    "cli.linux.mitm.browser_capture_mutation.blocked";
pub const CLI_MITM_BROWSER_CAPTURE_AUTHORIZATION_REQUIRED_CODE: &str =
    "cli.linux.mitm.browser_capture.authorization_required";
pub const CLI_MITM_BROWSER_CAPTURE_LAUNCH_PLAN_READY_CODE: &str =
    "cli.linux.mitm.browser_capture.launch_plan.ready";
pub const CLI_MITM_BROWSER_CAPTURE_LAUNCH_AUTHORIZATION_REQUIRED_CODE: &str =
    "cli.linux.mitm.browser_capture.launch.authorization_required";
pub const CLI_MITM_BROWSER_CAPTURE_LAUNCH_STARTED_CODE: &str =
    "cli.linux.mitm.browser_capture.launch.started";
pub const CLI_MITM_BROWSER_CAPTURE_LAUNCH_FAILED_CODE: &str =
    "cli.linux.mitm.browser_capture.launch.failed";
pub const CLI_MITM_BROWSER_CAPTURE_SESSION_PLAN_READY_CODE: &str =
    "cli.linux.mitm.browser_capture.session_plan.ready";
pub const CLI_MITM_BROWSER_CAPTURE_SESSION_PLAN_URL_PARSE_FAILED_CODE: &str =
    "cli.linux.mitm.browser_capture.session_plan.url_parse_failed";
pub const CLI_MITM_BROWSER_CAPTURE_SESSION_PLAN_CONFIG_FAILED_CODE: &str =
    "cli.linux.mitm.browser_capture.session_plan.config_failed";
pub const CLI_MITM_BROWSER_CAPTURE_APPLY_BLOCKED_CODE: &str =
    "cli.linux.mitm.browser_capture.apply.blocked";
pub const CLI_MITM_BROWSER_CAPTURE_APPLY_READY_CODE: &str =
    "cli.linux.mitm.browser_capture.apply.ready";
pub const CLI_MITM_BROWSER_CAPTURE_APPLY_CONFIG_MISSING_CODE: &str =
    "cli.linux.mitm.browser_capture.apply.config_missing";
pub const CLI_MITM_BROWSER_CAPTURE_PAC_WRITE_FAILED_CODE: &str =
    "cli.linux.mitm.browser_capture.pac.write_failed";
pub const CLI_MITM_BROWSER_CAPTURE_POLICY_WRITE_FAILED_CODE: &str =
    "cli.linux.mitm.browser_capture.policy.write_failed";
pub const CLI_MITM_BROWSER_CAPTURE_PROFILE_PREFS_WRITE_FAILED_CODE: &str =
    "cli.linux.mitm.browser_capture.profile_prefs.write_failed";
pub const CLI_MITM_BROWSER_CAPTURE_SNAPSHOT_WRITE_FAILED_CODE: &str =
    "cli.linux.mitm.browser_capture.snapshot.write_failed";
pub const CLI_MITM_BROWSER_CAPTURE_SNAPSHOT_READ_FAILED_CODE: &str =
    "cli.linux.mitm.browser_capture.snapshot.read_failed";
pub const CLI_MITM_BROWSER_CAPTURE_ROLLBACK_BLOCKED_CODE: &str =
    "cli.linux.mitm.browser_capture.rollback.blocked";
pub const CLI_MITM_BROWSER_CAPTURE_ROLLBACK_READY_CODE: &str =
    "cli.linux.mitm.browser_capture.rollback.ready";
pub const CLI_MITM_BROWSER_CAPTURE_ROLLBACK_FAILED_CODE: &str =
    "cli.linux.mitm.browser_capture.rollback.failed";
pub const CLI_MITM_BROWSER_CAPTURE_VERIFY_BLOCKED_CODE: &str =
    "cli.linux.mitm.browser_capture.verify.blocked";
pub const CLI_MITM_BROWSER_CAPTURE_VERIFY_AUTHORIZATION_REQUIRED_CODE: &str =
    "cli.linux.mitm.browser_capture.verify.authorization_required";
pub const CLI_MITM_BROWSER_CAPTURE_VERIFY_PROXY_REACHABLE_CODE: &str =
    "cli.linux.mitm.browser_capture.verify.proxy_reachable";
pub const CLI_MITM_BROWSER_CAPTURE_VERIFY_PROXY_UNREACHABLE_CODE: &str =
    "cli.linux.mitm.browser_capture.verify.proxy_unreachable";
pub const CLI_MITM_BROWSER_CAPTURE_VERIFY_TARGET_REACHABLE_CODE: &str =
    "cli.linux.mitm.browser_capture.verify.target_reachable";
pub const CLI_MITM_BROWSER_CAPTURE_VERIFY_TARGET_INVALID_CODE: &str =
    "cli.linux.mitm.browser_capture.verify.target_invalid";
pub const CLI_MITM_BROWSER_CAPTURE_TRAFFIC_PROOF_BLOCKED_CODE: &str =
    "cli.linux.mitm.browser_capture.traffic_proof.blocked";
pub const CLI_MITM_BROWSER_CAPTURE_TRAFFIC_PROOF_AUTHORIZATION_REQUIRED_CODE: &str =
    "cli.linux.mitm.browser_capture.traffic_proof.authorization_required";
pub const CLI_MITM_BROWSER_CAPTURE_TRAFFIC_PROOF_OBSERVED_CODE: &str =
    "cli.linux.mitm.browser_capture.traffic_proof.observed";
pub const CLI_MITM_BROWSER_CAPTURE_TRAFFIC_PROOF_MISSING_CODE: &str =
    "cli.linux.mitm.browser_capture.traffic_proof.missing";
pub const CLI_MITM_BROWSER_CAPTURE_TRAFFIC_PROOF_LOG_UNREADABLE_CODE: &str =
    "cli.linux.mitm.browser_capture.traffic_proof.log_unreadable";
pub const CLI_MITM_BROWSER_CAPTURE_TRAFFIC_PROOF_BINDING_MISMATCH_CODE: &str =
    "cli.linux.mitm.browser_capture.traffic_proof.binding_mismatch";
pub const CLI_MITM_HTTP_REWRITE_AUTHORIZATION_REQUIRED_CODE: &str =
    "cli.linux.mitm.http_rewrite.authorization_required";
pub const CLI_MITM_HTTP_REWRITE_PLAN_READY_CODE: &str = "cli.linux.mitm.http_rewrite.plan.ready";
pub const CLI_MITM_HTTP_REWRITE_APPLY_READY_CODE: &str = "cli.linux.mitm.http_rewrite.apply.ready";
pub const CLI_MITM_HTTP_REWRITE_CONFIG_MISSING_CODE: &str =
    "cli.linux.mitm.http_rewrite.config_missing";
pub const CLI_MITM_HTTP_REWRITE_PLUGIN_MISSING_CODE: &str =
    "cli.linux.mitm.http_rewrite.plugin_missing";
pub const CLI_MITM_HTTP_REWRITE_TLS_BLOCKED_CODE: &str = "cli.linux.mitm.http_rewrite.tls_blocked";
pub const CLI_MITM_BROWSER_HIJACK_DEFERRED_CODE: &str = "cli.linux.mitm.browser_hijack.deferred";

pub const MITM_CLI_COMMAND_GATE: &str = "MITM_CLI_COMMAND_GATE";
pub const MITM_CERTIFICATE_LIFECYCLE_GATE: &str = "MITM_CERTIFICATE_LIFECYCLE_GATE";
pub const MITM_HTTP_TLS_DATA_PLANE_GATE: &str = "MITM_HTTP_TLS_DATA_PLANE_GATE";
pub const MITM_BROWSER_CAPTURE_GATE: &str = "MITM_BROWSER_CAPTURE_GATE";
pub const MITM_CLI_COMMAND_GATE_STATUS: &str = "partial-active";
pub const MITM_CERTIFICATE_LIFECYCLE_GATE_STATUS: &str =
    "artifact-lifecycle-active/profile-trust-artifact-active/trust-mutation-blocked";
pub const MITM_HTTP_TLS_DATA_PLANE_GATE_STATUS: &str =
    "plain-http-live-data-plane-active/tls-decryption-blocked";
pub const MITM_BROWSER_CAPTURE_GATE_STATUS: &str =
    "pac-policy-profile-prefs-active/system-mutation-blocked";
pub const MITM_BROWSER_HIJACK_STATUS: &str = "deferred";
pub const MITM_CERTIFICATE_PLAN_STATUS: &str = "artifact-lifecycle-active";
pub const MITM_CERTIFICATE_MUTATION_READY: bool = false;
pub const MITM_CERTIFICATE_LIFECYCLE_SOURCE_CONTRACT_STATUS: &str = "active";
pub const MITM_CERTIFICATE_ARTIFACT_SUBJECT: &str = "NetworkCore Local MITM CA";
pub const MITM_BROWSER_PLAN_STATUS: &str = "plan-only";
pub const MITM_BROWSER_CAPTURE_MUTATION_READY: bool = false;
pub const MITM_BROWSER_CAPTURE_PROXY_HOST: &str = "127.0.0.1";
pub const MITM_BROWSER_CAPTURE_PROXY_PORT: u16 = 7890;
pub const MITM_BROWSER_CAPTURE_DEFAULT_PROXY_SCHEME: &str = "http";
pub const MITM_BROWSER_CAPTURE_NATIVE_PLUGIN_PROXY_SCHEME: &str = "socks5";
pub const MITM_BROWSER_CAPTURE_MODE: &str = "explicit-proxy";
pub const MITM_BROWSER_CAPTURE_SOURCE_CONTRACT_STATUS: &str = "active";
pub const MITM_BROWSER_CAPTURE_DEFAULT_BROWSER: &str = "chromium";
pub const MITM_BROWSER_CAPTURE_DEFAULT_PROFILE_DIR: &str =
    "/tmp/networkcore-browser-capture-profile";
pub const MITM_BROWSER_CAPTURE_DEFAULT_PROOF_LOG_PATH: &str =
    "/tmp/networkcore-browser-capture-proof.log";
pub const MITM_BROWSER_CAPTURE_PROOF_QUERY_PARAM: &str = "networkcore_proof_token";
pub const MITM_HTTP_REWRITE_SOURCE_CONTRACT_STATUS: &str = "active";
pub const MITM_HTTP_REWRITE_MUTATION_READY: bool = true;
pub const MITM_HTTP_REWRITE_LIVE_TRAFFIC_READY: bool = true;
pub const MITM_HTTP_REWRITE_TLS_DECRYPTION_READY: bool = false;
pub const MITM_HTTP_REWRITE_CONTROLLED_TLS_TERMINATION_PLAN_READY: bool = true;
pub const MITM_HTTP_REWRITE_DOWNSTREAM_TLS_TERMINATION_PLAN_READY: bool = true;
pub const MITM_HTTP_REWRITE_UPSTREAM_TLS_FORWARDING_READY: bool = true;
pub const MITM_HTTP_REWRITE_HTTPS_REQUEST_REWRITE_PREVIEW_READY: bool = true;
pub const MITM_HTTP_REWRITE_HTTPS_RESPONSE_REWRITE_PREVIEW_READY: bool = true;
pub const MITM_HTTP_REWRITE_HTTPS_RESPONSE_REWRITE_READY: bool = false;
pub const MITM_HTTP_REWRITE_SCRIPT_DISPATCH_READY: bool = false;
pub const MITM_HTTP_REWRITE_CERTIFICATE_PINNING_BYPASS_SUPPORTED: bool = false;
pub const MITM_HTTP_REWRITE_HTTP2_MITM_SUPPORTED: bool = false;
pub const MITM_HTTP_REWRITE_HTTP3_QUIC_MITM_SUPPORTED: bool = false;
pub const MITM_HTTP_REWRITE_DEFAULT_METHOD: &str = "GET";
pub const MITM_HTTP_REWRITE_DEFAULT_PHASE: &str = "request";
pub const MITM_USER_FACING_STAGE: &str = "policy-only";
pub const MITM_USER_FACING_READY: bool = false;

pub const SOURCE_CLI_ARGUMENT: &str = "cli.argument";
pub const SOURCE_CLI_CONFIG: &str = "cli.config";
pub const SOURCE_CLI_HELP: &str = "cli.help";
pub const SOURCE_CLI_MITM: &str = "cli.mitm";
pub const SOURCE_CLI_MANAGED_FOREGROUND_EVENT: &str = "cli.managed_foreground_event";
pub const SOURCE_CLI_MANAGED_FOREGROUND_LOG: &str = "cli.managed_foreground_log";
pub const SOURCE_CLI_MANAGED_FOREGROUND_STATUS: &str = "cli.managed_foreground_status";
pub const SOURCE_CLI_MANAGED_CONTROL: &str = "cli.managed_control";
pub const SOURCE_CLI_START: &str = "cli.start";
pub const SOURCE_CLI_STOP: &str = "cli.stop";
pub const SOURCE_CLI_STATUS: &str = "cli.status";
pub const SOURCE_CLI_RUNTIME: &str = "cli.runtime";
pub const SUBSCRIPTION_CATALOG_SCHEMA_VERSION: u32 = 1;
pub const MANAGED_FOREGROUND_SESSION_STATUS_SCHEMA_VERSION: u32 = 1;
pub const MANAGED_FOREGROUND_SESSION_EVENT_SCHEMA_VERSION: u32 = 1;
pub const MANAGED_FOREGROUND_EVENT_HISTORY_DEFAULT_LIMIT: usize = 50;
pub const MANAGED_FOREGROUND_EVENT_HISTORY_MAX_LIMIT: usize = 100;
pub const MANAGED_FOREGROUND_EVENT_HISTORY_MAX_RECORDS: usize = 256;
pub const MANAGED_FOREGROUND_EVENT_HISTORY_MAX_RECORD_BYTES: u64 = 64 * 1024;
pub const MANAGED_FOREGROUND_LOG_TAIL_DEFAULT_LIMIT: usize = 100;
pub const MANAGED_FOREGROUND_LOG_TAIL_MAX_LIMIT: usize = 1_000;
pub const MANAGED_FOREGROUND_LOG_TAIL_MAX_BYTES: u64 = 64 * 1024;
pub const MANAGED_CONTROL_SOCKET_IO_TIMEOUT_SECONDS: u64 = 2;
#[cfg(unix)]
const MANAGED_CONTROL_NONE: u8 = 0;
#[cfg(unix)]
const MANAGED_CONTROL_STOP: u8 = 1;
#[cfg(unix)]
const MANAGED_CONTROL_RELOAD: u8 = 2;
#[cfg(unix)]
const MANAGED_CONTROL_ROLLBACK: u8 = 3;
#[cfg(unix)]
const MANAGED_CONTROL_PENDING: u8 = 4;
#[cfg(unix)]
static MANAGED_CONTROL_REQUEST: AtomicU8 = AtomicU8::new(MANAGED_CONTROL_NONE);
static MANAGED_CONTROL_EXPECTED_CONFIG_VERSION: AtomicU64 = AtomicU64::new(0);
pub const RUN_URL_REMOTE_SUBSCRIPTION_MAX_BYTES: u64 = 1024 * 1024;
pub const RUN_URL_REMOTE_SUBSCRIPTION_TIMEOUT_SECONDS: u64 = 15;
pub const RUN_URL_REMOTE_SUBSCRIPTION_MAX_REDIRECTS: usize = 5;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum OutputFormat {
    #[default]
    Text,
    Json,
}

impl OutputFormat {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Text => "text",
            Self::Json => "json",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinuxCliExitCode {
    Success,
    GeneralFailure,
    ArgumentOrConfig,
    ConfigValidation,
    PlatformDenied,
    EngineDenied,
    Unavailable,
    Interrupted,
}

impl LinuxCliExitCode {
    pub const fn code(self) -> i32 {
        match self {
            Self::Success => 0,
            Self::GeneralFailure => 1,
            Self::ArgumentOrConfig => 2,
            Self::ConfigValidation => 3,
            Self::PlatformDenied => 4,
            Self::EngineDenied => 5,
            Self::Unavailable => 6,
            Self::Interrupted => 130,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LinuxCliCommand {
    Help {
        format: OutputFormat,
    },
    Version {
        format: OutputFormat,
    },
    Capabilities {
        format: OutputFormat,
    },
    PrepareConfig {
        config_path: Option<String>,
        format: OutputFormat,
    },
    Start {
        config_path: Option<String>,
        /// The user's own MITM plugin; NetworkCore ships none.
        mitm_plugin_path: Option<String>,
        mitm_ca_certificate_path: Option<String>,
        mitm_ca_private_key_path: Option<String>,
        enable_https_mitm: bool,
        enable_script_runtime: bool,
        script_runner_path: Option<String>,
        script_maps: Vec<String>,
        script_store_path: Option<String>,
        node_binary: Option<String>,
        managed_lifecycle: Option<ManagedForegroundLifecyclePaths>,
        confirm: bool,
        format: OutputFormat,
    },
    Stop {
        format: OutputFormat,
    },
    ManagedControlStop {
        socket_path: String,
        confirm: bool,
        format: OutputFormat,
    },
    ManagedControlReload {
        socket_path: String,
        confirm: bool,
        format: OutputFormat,
    },
    ManagedControlRollback {
        socket_path: String,
        expected_config_version: u64,
        confirm: bool,
        format: OutputFormat,
    },
    ManagedControlStatus {
        socket_path: String,
        format: OutputFormat,
    },
    CoreList {
        format: OutputFormat,
    },
    SubscriptionAdd {
        catalog_path: String,
        snapshot_path: String,
        source_id: String,
        location: String,
        format: OutputFormat,
    },
    SubscriptionList {
        catalog_path: String,
        format: OutputFormat,
    },
    SubscriptionUpdate {
        catalog_path: String,
        snapshot_path: String,
        source_id: String,
        location: String,
        format: OutputFormat,
    },
    SubscriptionRemove {
        catalog_path: String,
        snapshot_path: String,
        source_id: String,
        format: OutputFormat,
    },
    SubscriptionSelect {
        catalog_path: String,
        source_id: String,
        format: OutputFormat,
    },
    SubscriptionRollback {
        catalog_path: String,
        snapshot_path: String,
        format: OutputFormat,
    },
    SubscriptionRefreshStart {
        catalog_path: String,
        status_path: String,
        snapshot_path: String,
        source_id: String,
        interval_seconds: u64,
        confirm: bool,
        format: OutputFormat,
    },
    SubscriptionRefreshStatus {
        status_path: String,
        format: OutputFormat,
    },
    SubscriptionRefreshStop {
        status_path: String,
        source_id: String,
        confirm: bool,
        format: OutputFormat,
    },
    SubscriptionRefreshScheduleInstall {
        catalog_path: String,
        status_path: String,
        snapshot_path: String,
        source_id: String,
        interval_seconds: u64,
        unit_name: String,
        confirm: bool,
        format: OutputFormat,
    },
    SubscriptionRefreshScheduleStatus {
        unit_name: String,
        snapshot_path: String,
        format: OutputFormat,
    },
    SubscriptionRefreshScheduleStop {
        unit_name: String,
        snapshot_path: String,
        confirm: bool,
        format: OutputFormat,
    },
    SubscriptionRefreshScheduleUninstall {
        unit_name: String,
        snapshot_path: String,
        confirm: bool,
        format: OutputFormat,
    },
    NodeList {
        config_path: String,
        format: OutputFormat,
    },
    NodeSelect {
        config_path: String,
        node_id: String,
        selection_path: String,
        snapshot_path: String,
        confirm: bool,
        format: OutputFormat,
    },
    NodeRollback {
        selection_path: String,
        snapshot_path: String,
        confirm: bool,
        format: OutputFormat,
    },
    ProxyApply {
        file_path: String,
        snapshot_path: String,
        proxy_url: String,
        confirm: bool,
        format: OutputFormat,
    },
    ProxyStatus {
        file_path: String,
        format: OutputFormat,
    },
    ProxyRollback {
        file_path: String,
        snapshot_path: String,
        confirm: bool,
        format: OutputFormat,
    },
    ServiceControl {
        action: LinuxSystemdServiceAction,
        unit_name: String,
        confirm: bool,
        format: OutputFormat,
    },
    Restart {
        config_path: Option<String>,
        format: OutputFormat,
    },
    Status {
        format: OutputFormat,
    },
    ManagedStatus {
        status_path: String,
        format: OutputFormat,
    },
    ManagedStatusInit {
        status_path: String,
        session_id: String,
        engine_id: String,
        state: String,
        format: OutputFormat,
    },
    ManagedStatusTransition {
        status_path: String,
        snapshot_path: String,
        expected_state: String,
        next_state: String,
        format: OutputFormat,
    },
    ManagedStatusRollback {
        status_path: String,
        snapshot_path: String,
        expected_state: String,
        format: OutputFormat,
    },
    ManagedEvent {
        event_path: String,
        format: OutputFormat,
    },
    ManagedEventList {
        event_directory: String,
        session_id: Option<String>,
        event_kind: Option<String>,
        state: Option<String>,
        cursor: usize,
        limit: usize,
        format: OutputFormat,
    },
    ManagedEventInit {
        event_path: String,
        session_id: String,
        engine_id: String,
        event_id: String,
        event_kind: String,
        state: String,
        recorded_at: String,
        format: OutputFormat,
    },
    ManagedLog {
        log_path: String,
        line_limit: usize,
        format: OutputFormat,
    },
    Diagnostics {
        format: OutputFormat,
    },
    MitmStatus {
        format: OutputFormat,
    },
    MitmDiagnostics {
        format: OutputFormat,
    },
    MitmCertificatePlan {
        format: OutputFormat,
    },
    MitmCertificateApply {
        cert_file_path: Option<String>,
        key_file_path: Option<String>,
        profile_trust_file_path: Option<String>,
        snapshot_path: Option<String>,
        confirm: bool,
        format: OutputFormat,
    },
    MitmCertificateRollback {
        snapshot_path: Option<String>,
        format: OutputFormat,
    },
    MitmCertificateTrustApply {
        certificate_path: Option<String>,
        trust_file_path: Option<String>,
        snapshot_path: Option<String>,
        confirm: bool,
        format: OutputFormat,
    },
    MitmCertificateTrustRollback {
        trust_file_path: Option<String>,
        snapshot_path: Option<String>,
        confirm: bool,
        format: OutputFormat,
    },
    MitmBrowserPlan {
        format: OutputFormat,
    },
    MitmBrowserCapturePlan {
        proxy_scheme: String,
        format: OutputFormat,
    },
    MitmBrowserCaptureLaunchPlan {
        proxy_scheme: String,
        format: OutputFormat,
    },
    MitmBrowserCaptureSessionPlan {
        url: String,
        browser: String,
        profile_dir: String,
        target_url: Option<String>,
        proof_token: Option<String>,
        proof_log_path: Option<String>,
        proxy_scheme: String,
        listen_host: String,
        listen_port: u16,
        format: OutputFormat,
    },
    MitmBrowserCaptureLaunch {
        browser: String,
        profile_dir: String,
        target_url: Option<String>,
        proof_token: Option<String>,
        proof_log_path: Option<String>,
        proxy_scheme: String,
        confirm: bool,
        format: OutputFormat,
    },
    MitmBrowserCaptureApply {
        pac_file_path: Option<String>,
        policy_file_path: Option<String>,
        profile_prefs_file_path: Option<String>,
        snapshot_path: Option<String>,
        proxy_scheme: String,
        confirm: bool,
        format: OutputFormat,
    },
    MitmBrowserCaptureRollback {
        snapshot_path: Option<String>,
        format: OutputFormat,
    },
    MitmBrowserCaptureVerify {
        target_url: Option<String>,
        proxy_scheme: String,
        confirm: bool,
        format: OutputFormat,
    },
    MitmBrowserCaptureTrafficProof {
        target_url: Option<String>,
        proof_token: Option<String>,
        proof_log_path: Option<String>,
        proxy_scheme: String,
        confirm: bool,
        format: OutputFormat,
    },
    MitmHttpRewritePlan {
        format: OutputFormat,
    },
    MitmHttpRewritePreview {
        mitm_plugin_path: Option<String>,
        url: Option<String>,
        method: String,
        phase: String,
        status_code: Option<u16>,
        headers: Vec<String>,
        body: Option<String>,
        confirm: bool,
        format: OutputFormat,
    },
    InstallService {
        unit_name: String,
        description: String,
        executable_path: String,
        arguments: Vec<String>,
        service_user: String,
        service_group: String,
        state_directory: String,
        confirm: bool,
        format: OutputFormat,
    },
    UninstallService {
        unit_name: String,
        state_directory: String,
        confirm: bool,
        format: OutputFormat,
    },
    RunUrl {
        url: String,
        selected_node_id: Option<String>,
        listen_host: String,
        listen_port: u16,
        format: OutputFormat,
    },
    RunCatalog {
        catalog_path: String,
        source_id: String,
        selected_node_id: Option<String>,
        listen_host: String,
        listen_port: u16,
        format: OutputFormat,
    },
}

impl LinuxCliCommand {
    pub const fn name(&self) -> &'static str {
        match self {
            Self::Help { .. } => "help",
            Self::Version { .. } => "version",
            Self::Capabilities { .. } => "capabilities",
            Self::PrepareConfig { .. } => "prepare-config",
            Self::Start { .. } => "start",
            Self::Stop { .. } => "stop",
            Self::ManagedControlStop { .. } => "managed-control stop",
            Self::ManagedControlReload { .. } => "managed-control reload",
            Self::ManagedControlRollback { .. } => "managed-control rollback",
            Self::ManagedControlStatus { .. } => "managed-control status",
            Self::CoreList { .. } => "core list",
            Self::SubscriptionAdd { .. } => "subscription add",
            Self::SubscriptionList { .. } => "subscription list",
            Self::SubscriptionUpdate { .. } => "subscription update",
            Self::SubscriptionRemove { .. } => "subscription remove",
            Self::SubscriptionSelect { .. } => "subscription select",
            Self::SubscriptionRollback { .. } => "subscription rollback",
            Self::SubscriptionRefreshStart { .. } => "subscription refresh start",
            Self::SubscriptionRefreshStatus { .. } => "subscription refresh status",
            Self::SubscriptionRefreshStop { .. } => "subscription refresh stop",
            Self::SubscriptionRefreshScheduleInstall { .. } => {
                "subscription refresh schedule install"
            }
            Self::SubscriptionRefreshScheduleStatus { .. } => {
                "subscription refresh schedule status"
            }
            Self::SubscriptionRefreshScheduleStop { .. } => "subscription refresh schedule stop",
            Self::SubscriptionRefreshScheduleUninstall { .. } => {
                "subscription refresh schedule uninstall"
            }
            Self::NodeList { .. } => "node list",
            Self::NodeSelect { .. } => "node select",
            Self::NodeRollback { .. } => "node rollback",
            Self::ProxyApply { .. } => "proxy apply",
            Self::ProxyStatus { .. } => "proxy status",
            Self::ProxyRollback { .. } => "proxy rollback",
            Self::ServiceControl { action, .. } => match action {
                LinuxSystemdServiceAction::Start => "service start",
                LinuxSystemdServiceAction::Stop => "service stop",
                LinuxSystemdServiceAction::Restart => "service restart",
                LinuxSystemdServiceAction::Status => "service status",
                LinuxSystemdServiceAction::Reload => "service reload",
                LinuxSystemdServiceAction::DaemonReload => "service daemon-reload",
                LinuxSystemdServiceAction::Enable => "service enable",
            },
            Self::Restart { .. } => "restart",
            Self::Status { .. } => "status",
            Self::ManagedStatus { .. } => "managed-status",
            Self::ManagedStatusInit { .. } => "managed-status init",
            Self::ManagedStatusTransition { .. } => "managed-status transition",
            Self::ManagedStatusRollback { .. } => "managed-status rollback",
            Self::ManagedEvent { .. } => "managed-event",
            Self::ManagedEventList { .. } => "managed-event list",
            Self::ManagedEventInit { .. } => "managed-event init",
            Self::ManagedLog { .. } => "managed-log",
            Self::Diagnostics { .. } => "diagnostics",
            Self::MitmStatus { .. } => "mitm status",
            Self::MitmDiagnostics { .. } => "mitm diagnostics",
            Self::MitmCertificatePlan { .. } => "mitm certificate-plan",
            Self::MitmCertificateApply { .. } => "mitm certificate apply",
            Self::MitmCertificateRollback { .. } => "mitm certificate rollback",
            Self::MitmCertificateTrustApply { .. } => "mitm certificate trust-apply",
            Self::MitmCertificateTrustRollback { .. } => "mitm certificate trust-rollback",
            Self::MitmBrowserPlan { .. } => "mitm browser-plan",
            Self::MitmBrowserCapturePlan { .. } => "mitm browser-capture plan",
            Self::MitmBrowserCaptureLaunchPlan { .. } => "mitm browser-capture launch-plan",
            Self::MitmBrowserCaptureSessionPlan { .. } => "mitm browser-capture session-plan",
            Self::MitmBrowserCaptureLaunch { .. } => "mitm browser-capture launch",
            Self::MitmBrowserCaptureApply { .. } => "mitm browser-capture apply",
            Self::MitmBrowserCaptureRollback { .. } => "mitm browser-capture rollback",
            Self::MitmBrowserCaptureVerify { .. } => "mitm browser-capture verify",
            Self::MitmBrowserCaptureTrafficProof { .. } => "mitm browser-capture traffic-proof",
            Self::MitmHttpRewritePlan { .. } => "mitm http-rewrite plan",
            Self::MitmHttpRewritePreview { .. } => "mitm http-rewrite preview",
            Self::InstallService { .. } => "install-service",
            Self::UninstallService { .. } => "uninstall-service",
            Self::RunUrl { .. } => "run-url",
            Self::RunCatalog { .. } => "run-catalog",
        }
    }

    pub const fn format(&self) -> OutputFormat {
        match self {
            Self::Help { format }
            | Self::Version { format }
            | Self::Capabilities { format }
            | Self::PrepareConfig { format, .. }
            | Self::Start { format, .. }
            | Self::Stop { format }
            | Self::ManagedControlStop { format, .. }
            | Self::ManagedControlReload { format, .. }
            | Self::ManagedControlRollback { format, .. }
            | Self::ManagedControlStatus { format, .. }
            | Self::CoreList { format }
            | Self::SubscriptionAdd { format, .. }
            | Self::SubscriptionList { format, .. }
            | Self::SubscriptionUpdate { format, .. }
            | Self::SubscriptionRemove { format, .. }
            | Self::SubscriptionSelect { format, .. }
            | Self::SubscriptionRollback { format, .. }
            | Self::SubscriptionRefreshStart { format, .. }
            | Self::SubscriptionRefreshStatus { format, .. }
            | Self::SubscriptionRefreshStop { format, .. }
            | Self::SubscriptionRefreshScheduleInstall { format, .. }
            | Self::SubscriptionRefreshScheduleStatus { format, .. }
            | Self::SubscriptionRefreshScheduleStop { format, .. }
            | Self::SubscriptionRefreshScheduleUninstall { format, .. }
            | Self::NodeList { format, .. }
            | Self::NodeSelect { format, .. }
            | Self::NodeRollback { format, .. }
            | Self::ProxyApply { format, .. }
            | Self::ProxyStatus { format, .. }
            | Self::ProxyRollback { format, .. }
            | Self::ServiceControl { format, .. }
            | Self::Restart { format, .. }
            | Self::Status { format }
            | Self::ManagedStatus { format, .. }
            | Self::ManagedStatusInit { format, .. }
            | Self::ManagedStatusTransition { format, .. }
            | Self::ManagedStatusRollback { format, .. }
            | Self::ManagedEvent { format, .. }
            | Self::ManagedEventList { format, .. }
            | Self::ManagedEventInit { format, .. }
            | Self::ManagedLog { format, .. }
            | Self::Diagnostics { format }
            | Self::MitmStatus { format }
            | Self::MitmDiagnostics { format }
            | Self::MitmCertificatePlan { format }
            | Self::MitmCertificateApply { format, .. }
            | Self::MitmCertificateRollback { format, .. }
            | Self::MitmCertificateTrustApply { format, .. }
            | Self::MitmCertificateTrustRollback { format, .. }
            | Self::MitmBrowserPlan { format, .. }
            | Self::MitmBrowserCapturePlan { format, .. }
            | Self::MitmBrowserCaptureLaunchPlan { format, .. }
            | Self::MitmBrowserCaptureSessionPlan { format, .. }
            | Self::MitmBrowserCaptureLaunch { format, .. }
            | Self::MitmBrowserCaptureApply { format, .. }
            | Self::MitmBrowserCaptureRollback { format, .. }
            | Self::MitmBrowserCaptureVerify { format, .. }
            | Self::MitmBrowserCaptureTrafficProof { format, .. }
            | Self::MitmHttpRewritePlan { format }
            | Self::MitmHttpRewritePreview { format, .. }
            | Self::InstallService { format, .. }
            | Self::UninstallService { format, .. }
            | Self::RunUrl { format, .. }
            | Self::RunCatalog { format, .. } => *format,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxCliParseError {
    diagnostic: Box<Diagnostic>,
}

impl LinuxCliParseError {
    pub fn new(diagnostic: Diagnostic) -> Self {
        Self {
            diagnostic: Box::new(diagnostic),
        }
    }

    pub fn diagnostic(&self) -> &Diagnostic {
        self.diagnostic.as_ref()
    }

    pub fn into_diagnostic(self) -> Diagnostic {
        *self.diagnostic
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxCliResponse {
    pub ok: bool,
    pub command: String,
    pub exit_code: LinuxCliExitCode,
    pub diagnostics: Vec<Diagnostic>,
    pub platform: Option<PlatformCapabilityStatus>,
    pub config_profiles: Vec<String>,
    pub version: Option<String>,
    pub help: Option<String>,
    pub managed_foreground_status: Option<ManagedForegroundSessionStatusReport>,
    pub managed_foreground_status_write: Option<ManagedForegroundSessionStatusWriteReport>,
    pub managed_foreground_status_transition:
        Option<ManagedForegroundSessionStatusTransitionReport>,
    pub managed_foreground_status_rollback: Option<ManagedForegroundSessionStatusRollbackReport>,
    pub managed_foreground_event: Option<ManagedForegroundSessionEventReport>,
    pub managed_foreground_event_history: Option<ManagedForegroundSessionEventHistoryReport>,
    pub managed_foreground_event_write: Option<ManagedForegroundSessionEventWriteReport>,
    pub managed_foreground_log_tail: Option<ManagedForegroundSessionLogTailReport>,
    pub mitm_status: Option<LinuxMitmStatus>,
    pub certificate_lifecycle: Option<LinuxMitmCertificateLifecycleReport>,
    pub browser_capture: Option<LinuxBrowserCaptureReport>,
    pub http_rewrite: Option<LinuxMitmHttpRewriteReport>,
    pub service_install: Option<LinuxManagedServiceUnitPlan>,
    pub service_removal: Option<LinuxManagedServiceUnitRemovalPlan>,
    pub core_engines: Vec<LinuxCoreEngineSummary>,
    pub node_catalog: Option<LinuxNodeCatalogReport>,
}

impl LinuxCliResponse {
    pub fn success(command: impl Into<String>) -> Self {
        Self {
            ok: true,
            command: command.into(),
            exit_code: LinuxCliExitCode::Success,
            diagnostics: Vec::new(),
            platform: None,
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

    pub fn failure(
        command: impl Into<String>,
        exit_code: LinuxCliExitCode,
        diagnostic: Diagnostic,
    ) -> Self {
        Self {
            ok: false,
            command: command.into(),
            exit_code,
            diagnostics: vec![diagnostic],
            platform: None,
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

    pub fn with_platform(mut self, platform: PlatformCapabilityStatus) -> Self {
        self.platform = Some(platform);
        self
    }

    pub fn with_config_profiles(mut self, profiles: Vec<String>) -> Self {
        self.config_profiles = profiles;
        self
    }

    pub fn with_version(mut self, version: impl Into<String>) -> Self {
        self.version = Some(version.into());
        self
    }

    pub fn with_help(mut self, help: impl Into<String>) -> Self {
        self.help = Some(help.into());
        self
    }

    pub fn with_managed_foreground_status(
        mut self,
        report: ManagedForegroundSessionStatusReport,
    ) -> Self {
        self.managed_foreground_status = Some(report);
        self
    }

    pub fn with_managed_foreground_status_write(
        mut self,
        report: ManagedForegroundSessionStatusWriteReport,
    ) -> Self {
        self.managed_foreground_status_write = Some(report);
        self
    }

    pub fn with_managed_foreground_status_transition(
        mut self,
        report: ManagedForegroundSessionStatusTransitionReport,
    ) -> Self {
        self.managed_foreground_status_transition = Some(report);
        self
    }

    pub fn with_managed_foreground_status_rollback(
        mut self,
        report: ManagedForegroundSessionStatusRollbackReport,
    ) -> Self {
        self.managed_foreground_status_rollback = Some(report);
        self
    }

    pub fn with_managed_foreground_event(
        mut self,
        report: ManagedForegroundSessionEventReport,
    ) -> Self {
        self.managed_foreground_event = Some(report);
        self
    }

    pub fn with_managed_foreground_event_history(
        mut self,
        report: ManagedForegroundSessionEventHistoryReport,
    ) -> Self {
        self.managed_foreground_event_history = Some(report);
        self
    }

    pub fn with_managed_foreground_event_write(
        mut self,
        report: ManagedForegroundSessionEventWriteReport,
    ) -> Self {
        self.managed_foreground_event_write = Some(report);
        self
    }

    pub fn with_managed_foreground_log_tail(
        mut self,
        report: ManagedForegroundSessionLogTailReport,
    ) -> Self {
        self.managed_foreground_log_tail = Some(report);
        self
    }

    pub fn with_mitm_status(mut self, status: LinuxMitmStatus) -> Self {
        self.mitm_status = Some(status);
        self
    }

    pub fn with_certificate_lifecycle(
        mut self,
        report: LinuxMitmCertificateLifecycleReport,
    ) -> Self {
        self.certificate_lifecycle = Some(report);
        self
    }

    pub fn with_browser_capture(mut self, report: LinuxBrowserCaptureReport) -> Self {
        self.browser_capture = Some(report);
        self
    }

    pub fn with_http_rewrite(mut self, report: LinuxMitmHttpRewriteReport) -> Self {
        self.http_rewrite = Some(report);
        self
    }

    pub fn with_service_install(mut self, plan: LinuxManagedServiceUnitPlan) -> Self {
        self.service_install = Some(plan);
        self
    }

    pub fn with_service_removal(mut self, plan: LinuxManagedServiceUnitRemovalPlan) -> Self {
        self.service_removal = Some(plan);
        self
    }

    pub fn with_diagnostics(mut self, diagnostics: Vec<Diagnostic>) -> Self {
        self.diagnostics = diagnostics;
        self
    }

    pub fn with_core_engines(mut self, engines: Vec<LinuxCoreEngineSummary>) -> Self {
        self.core_engines = engines;
        self
    }

    pub fn with_node_catalog(mut self, catalog: LinuxNodeCatalogReport) -> Self {
        self.node_catalog = Some(catalog);
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxCoreEngineSummary {
    pub id: String,
    pub kind: String,
    pub version: Option<String>,
    pub capabilities: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxNodeCatalogReport {
    pub schema_version: u32,
    pub source: String,
    pub selection_mutated: bool,
    pub nodes: Vec<LinuxNodeCatalogEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxNodeCatalogEntry {
    pub id: String,
    pub name: String,
    pub protocol: String,
    pub tags: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxMitmStatus {
    pub stage: String,
    pub user_facing_ready: bool,
    pub browser_hijack: String,
    pub platform_mitm_available: bool,
    pub certificate_state: String,
    pub certificate_plan: LinuxMitmCertificatePlan,
    pub browser_plan: LinuxMitmBrowserPlan,
    pub policy: LinuxMitmPolicyStatus,
    pub gates: Vec<LinuxMitmGateStatus>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxMitmCertificatePlan {
    pub status: String,
    pub mutation_ready: bool,
    pub current_state: String,
    pub subject: Option<String>,
    pub fingerprint_sha256: Option<String>,
    pub required_steps: Vec<LinuxMitmCertificatePlanStep>,
    pub blocked_operations: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxMitmCertificatePlanStep {
    pub id: String,
    pub status: String,
    pub reason: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinuxMitmCertificateLifecycleAction {
    Apply,
    Rollback,
}

impl LinuxMitmCertificateLifecycleAction {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Apply => "apply",
            Self::Rollback => "rollback",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MitmCertificateAuthorization {
    pub confirmed: bool,
    pub source: String,
    pub scope: String,
    pub gate: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MitmCertificateRollbackSnapshot {
    pub path: String,
    pub status: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxMitmCertificateTrustPlan {
    pub status: String,
    pub mutation_ready: bool,
    pub required_steps: Vec<LinuxMitmCertificatePlanStep>,
    pub blocked_operations: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxMitmCertificateArtifactRequest {
    pub cert_file_path: String,
    pub key_file_path: String,
    pub profile_trust_file_path: Option<String>,
    pub snapshot_path: String,
    pub subject: String,
    pub artifact_version: u8,
    pub cert_content: String,
    pub key_content: String,
    pub profile_trust_content: Option<String>,
    pub cert_fingerprint: String,
    pub key_fingerprint: String,
    pub profile_trust_fingerprint: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxMitmCertificateArtifactApplyOutcome {
    pub rollback_snapshot: MitmCertificateRollbackSnapshot,
    pub diagnostics: Vec<Diagnostic>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxMitmCertificateArtifactRollbackOutcome {
    pub cert_file_path: String,
    pub key_file_path: String,
    pub profile_trust_file_path: Option<String>,
    pub diagnostics: Vec<Diagnostic>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxMitmCertificateLifecycleRequest {
    pub action: LinuxMitmCertificateLifecycleAction,
    pub artifact: Option<LinuxMitmCertificateArtifactRequest>,
    pub authorization: Option<MitmCertificateAuthorization>,
    pub rollback_snapshot: Option<MitmCertificateRollbackSnapshot>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxMitmCertificateApplyReport {
    pub status: String,
    pub applied: bool,
    pub authorization: MitmCertificateAuthorization,
    pub cert_file_path: Option<String>,
    pub key_file_path: Option<String>,
    pub profile_trust_file_path: Option<String>,
    pub rollback_snapshot: Option<MitmCertificateRollbackSnapshot>,
    pub blocked_operations: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxMitmCertificateRollbackReport {
    pub status: String,
    pub rolled_back: bool,
    pub cert_file_path: Option<String>,
    pub key_file_path: Option<String>,
    pub profile_trust_file_path: Option<String>,
    pub rollback_snapshot: Option<MitmCertificateRollbackSnapshot>,
    pub blocked_operations: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxMitmCertificateLifecycleReport {
    pub action: String,
    pub source_contract_status: String,
    pub gate: String,
    pub gate_status: String,
    pub mutation_ready: bool,
    pub request: LinuxMitmCertificateLifecycleRequest,
    pub plan: LinuxMitmCertificatePlan,
    pub trust_plan: LinuxMitmCertificateTrustPlan,
    pub apply_report: Option<LinuxMitmCertificateApplyReport>,
    pub rollback_report: Option<LinuxMitmCertificateRollbackReport>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxMitmBrowserPlan {
    pub status: String,
    pub mutation_ready: bool,
    pub current_capture: String,
    pub planned_capture_mode: String,
    pub planned_proxy_host: String,
    pub planned_proxy_port: u16,
    pub required_steps: Vec<LinuxMitmBrowserPlanStep>,
    pub blocked_operations: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxMitmBrowserPlanStep {
    pub id: String,
    pub status: String,
    pub reason: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinuxBrowserCaptureAction {
    Plan,
    LaunchPlan,
    SessionPlan,
    Launch,
    Apply,
    Rollback,
    Verify,
    TrafficProof,
}

impl LinuxBrowserCaptureAction {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Plan => "plan",
            Self::LaunchPlan => "launch-plan",
            Self::SessionPlan => "session-plan",
            Self::Launch => "launch",
            Self::Apply => "apply",
            Self::Rollback => "rollback",
            Self::Verify => "verify",
            Self::TrafficProof => "traffic-proof",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxBrowserCaptureRequest {
    pub action: LinuxBrowserCaptureAction,
    pub session: Option<LinuxBrowserCaptureSessionPlanRequest>,
    pub launch: Option<LinuxBrowserCaptureLaunchRequest>,
    pub pac: Option<LinuxBrowserCapturePacRequest>,
    pub verify: Option<LinuxBrowserCaptureVerifyRequest>,
    pub traffic_proof: Option<LinuxBrowserCaptureTrafficProofRequest>,
    pub authorization: Option<BrowserCaptureAuthorization>,
    pub rollback_snapshot: Option<BrowserCaptureRollbackSnapshot>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxBrowserCaptureSessionPlanRequest {
    pub url_source: String,
    pub browser: String,
    pub profile_dir: String,
    pub target_url: Option<String>,
    pub proof_target_url: Option<String>,
    pub proof_token: String,
    pub proof_log_path: String,
    pub proxy_scheme: String,
    pub listen_host: String,
    pub listen_port: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrowserCaptureAuthorization {
    pub confirmed: bool,
    pub source: String,
    pub scope: String,
    pub gate: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrowserCaptureRollbackSnapshot {
    pub path: String,
    pub status: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxBrowserCapturePlan {
    pub status: String,
    pub mutation_ready: bool,
    pub current_capture: String,
    pub planned_capture_mode: String,
    pub planned_proxy_scheme: String,
    pub planned_proxy_host: String,
    pub planned_proxy_port: u16,
    pub manual_launch: LinuxBrowserCaptureManualLaunch,
    pub required_steps: Vec<LinuxMitmBrowserPlanStep>,
    pub blocked_operations: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxBrowserCaptureManualLaunch {
    pub status: String,
    pub proxy_scheme: String,
    pub proxy_url: String,
    pub profile_strategy: String,
    pub plugin_engine: String,
    pub plugin_id: String,
    pub plugin_version: String,
    pub browser_commands: Vec<LinuxBrowserCaptureLaunchCommand>,
    pub manual_steps: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxBrowserCaptureLaunchCommand {
    pub browser: String,
    pub executable: String,
    pub args: Vec<String>,
    pub command: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxBrowserCaptureLaunchRequest {
    pub browser: String,
    pub profile_dir: String,
    pub target_url: Option<String>,
    pub proof_target_url: Option<String>,
    pub proof_token: String,
    pub proof_log_path: String,
    pub traffic_proof_command: String,
    pub proxy_scheme: String,
    pub proxy_url: String,
    pub command: LinuxBrowserCaptureLaunchCommand,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxBrowserCaptureLaunchOutcome {
    pub pid: u32,
    pub diagnostics: Vec<Diagnostic>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxBrowserCapturePacRequest {
    pub proxy_host: String,
    pub proxy_port: u16,
    pub proxy_scheme: String,
    pub proxy_url: String,
    pub pac_file_path: String,
    pub snapshot_path: String,
    pub pac_url: String,
    pub pac_content: String,
    pub policy_file_path: Option<String>,
    pub policy_url: Option<String>,
    pub policy_content: Option<String>,
    pub profile_prefs_file_path: Option<String>,
    pub profile_prefs_content: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxBrowserCapturePacApplyOutcome {
    pub rollback_snapshot: BrowserCaptureRollbackSnapshot,
    pub diagnostics: Vec<Diagnostic>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxBrowserCapturePacRollbackOutcome {
    pub pac_file_path: String,
    pub policy_file_path: Option<String>,
    pub profile_prefs_file_path: Option<String>,
    pub diagnostics: Vec<Diagnostic>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxBrowserCaptureVerifyRequest {
    pub proxy_host: String,
    pub proxy_port: u16,
    pub proxy_scheme: String,
    pub proxy_url: String,
    pub target_url: Option<String>,
    pub probe: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxBrowserCaptureVerifyOutcome {
    pub diagnostics: Vec<Diagnostic>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxBrowserCaptureTrafficProofRequest {
    pub proxy_host: String,
    pub proxy_port: u16,
    pub proxy_scheme: String,
    pub proxy_url: String,
    pub target_url: Option<String>,
    pub proof_connect_authority: Option<String>,
    pub proof_target_url: Option<String>,
    pub proof_token: String,
    pub proof_log_path: String,
    pub probe: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxBrowserCaptureTrafficProofOutcome {
    pub diagnostics: Vec<Diagnostic>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxBrowserCaptureLaunchReport {
    pub status: String,
    pub launched: bool,
    pub pid: Option<u32>,
    pub request: LinuxBrowserCaptureLaunchRequest,
    pub plugin_engine: String,
    pub plugin_id: String,
    pub plugin_version: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxBrowserCaptureApplyReport {
    pub status: String,
    pub applied: bool,
    pub authorization: BrowserCaptureAuthorization,
    pub pac_file_path: Option<String>,
    pub pac_url: Option<String>,
    pub policy_file_path: Option<String>,
    pub policy_url: Option<String>,
    pub profile_prefs_file_path: Option<String>,
    pub rollback_snapshot: Option<BrowserCaptureRollbackSnapshot>,
    pub blocked_operations: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxBrowserCaptureRollbackReport {
    pub status: String,
    pub rolled_back: bool,
    pub pac_file_path: Option<String>,
    pub policy_file_path: Option<String>,
    pub profile_prefs_file_path: Option<String>,
    pub rollback_snapshot: Option<BrowserCaptureRollbackSnapshot>,
    pub blocked_operations: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxBrowserCaptureVerifyReport {
    pub status: String,
    pub verified: bool,
    pub request: LinuxBrowserCaptureVerifyRequest,
    pub plugin_engine: String,
    pub plugin_id: String,
    pub plugin_version: String,
    pub blocked_operations: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxBrowserCaptureTrafficProofReport {
    pub status: String,
    pub proven: bool,
    pub request: LinuxBrowserCaptureTrafficProofRequest,
    pub plugin_engine: String,
    pub plugin_id: String,
    pub plugin_version: String,
    pub blocked_operations: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxBrowserCaptureSessionPlanReport {
    pub status: String,
    pub url_source: String,
    pub node_id: String,
    pub node_name: String,
    pub target_url: Option<String>,
    pub proof_target_url: Option<String>,
    pub proof_token: String,
    pub proof_log_path: String,
    pub listen_host: String,
    pub listen_port: u16,
    pub proxy_scheme: String,
    pub proxy_url: String,
    pub run_command: String,
    pub browser_command: LinuxBrowserCaptureLaunchCommand,
    pub verify_command: String,
    pub traffic_proof_command: String,
    pub plugin_engine: String,
    pub plugin_id: String,
    pub plugin_version: String,
    pub required_steps: Vec<String>,
    pub blocked_operations: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxBrowserCaptureReport {
    pub action: String,
    pub source_contract_status: String,
    pub gate: String,
    pub gate_status: String,
    pub mutation_ready: bool,
    pub request: LinuxBrowserCaptureRequest,
    pub plan: LinuxBrowserCapturePlan,
    pub session_plan: Option<LinuxBrowserCaptureSessionPlanReport>,
    pub launch_report: Option<LinuxBrowserCaptureLaunchReport>,
    pub apply_report: Option<LinuxBrowserCaptureApplyReport>,
    pub rollback_report: Option<LinuxBrowserCaptureRollbackReport>,
    pub verify_report: Option<LinuxBrowserCaptureVerifyReport>,
    pub traffic_proof_report: Option<LinuxBrowserCaptureTrafficProofReport>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxMitmHttpRewriteAuthorization {
    pub confirmed: bool,
    pub source: String,
    pub scope: String,
    pub gate: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxMitmHttpHeader {
    pub name: String,
    pub value: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxMitmHttpRewriteRequest {
    pub url: Option<String>,
    pub method: String,
    pub phase: String,
    pub status_code: Option<u16>,
    pub headers: Vec<LinuxMitmHttpHeader>,
    pub body: Option<String>,
    pub authorization: Option<LinuxMitmHttpRewriteAuthorization>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxMitmHttpRewriteOutcomeReport {
    pub planned: bool,
    pub applied: bool,
    pub action: String,
    pub terminal_action: Option<String>,
    pub final_status_code: Option<u16>,
    pub redirect_location: Option<String>,
    pub header_mutation_count: usize,
    pub body_mutated: bool,
    pub script_dispatch_deferred: bool,
    pub script_dispatch_failed: bool,
    pub output_headers: Vec<LinuxMitmHttpHeader>,
    pub output_body: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxMitmHttpRewriteReport {
    pub action: String,
    pub source_contract_status: String,
    pub gate: String,
    pub gate_status: String,
    pub mutation_ready: bool,
    pub live_traffic_ready: bool,
    pub tls_decryption_ready: bool,
    pub controlled_tls_termination_plan_ready: bool,
    pub downstream_tls_termination_plan_ready: bool,
    pub upstream_tls_forwarding_ready: bool,
    pub https_request_rewrite_preview_ready: bool,
    pub https_response_rewrite_preview_ready: bool,
    pub https_response_rewrite_ready: bool,
    pub script_dispatch_ready: bool,
    pub certificate_pinning_bypass_supported: bool,
    pub http2_mitm_supported: bool,
    pub http3_quic_mitm_supported: bool,
    pub request: LinuxMitmHttpRewriteRequest,
    pub outcome: Option<LinuxMitmHttpRewriteOutcomeReport>,
    pub blocked_operations: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxMitmPolicyStatus {
    pub engine: String,
    pub engine_version: String,
    pub plugin_id: String,
    pub plugin_version: String,
    pub plugin_loaded: bool,
    pub mitm_pattern_count: usize,
    pub rewrite_rule_count: usize,
    pub script_rule_count: usize,
    pub argument_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxMitmGateStatus {
    pub gate: String,
    pub status: String,
    pub reason: String,
}

#[derive(Debug, Clone, Copy)]
pub struct LinuxNativeMitmRuntimeFileConfig<'a> {
    /// The user's own MITM plugin file; NetworkCore ships none.
    pub plugin_path: Option<&'a str>,
    pub certificate_path: Option<&'a str>,
    pub private_key_path: Option<&'a str>,
    pub enable_https_mitm: bool,
    pub enable_script_runtime: bool,
    pub script_runner_path: Option<&'a str>,
    pub node_binary: Option<&'a str>,
    pub script_maps: &'a [String],
    pub script_store_path: Option<&'a str>,
    pub confirm: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigReadError {
    pub message: String,
}

impl ConfigReadError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

pub trait ConfigReader {
    fn read_config(&self, path: &str) -> Result<String, ConfigReadError>;
}

#[derive(Debug, Clone, Copy, Default)]
pub struct FsConfigReader;

impl ConfigReader for FsConfigReader {
    fn read_config(&self, path: &str) -> Result<String, ConfigReadError> {
        std::fs::read_to_string(path).map_err(|error| ConfigReadError::new(error.to_string()))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubscriptionCatalogAddRequest {
    pub catalog_path: String,
    pub snapshot_path: String,
    pub source: SubscriptionSource,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubscriptionCatalogAddReport {
    pub catalog_path: String,
    pub snapshot_path: String,
    pub source_id: String,
    pub source_count: usize,
    pub location_kind: String,
    pub location_redacted: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubscriptionCatalogListRequest {
    pub catalog_path: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubscriptionCatalogListEntry {
    pub source_id: String,
    pub location_kind: String,
    pub location_redacted: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubscriptionCatalogListReport {
    pub catalog_path: String,
    pub source_count: usize,
    pub sources: Vec<SubscriptionCatalogListEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubscriptionCatalogSelectRequest {
    pub catalog_path: String,
    pub source_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubscriptionCatalogSelectReport {
    pub catalog_path: String,
    pub source_id: String,
    pub location_kind: String,
    pub location_redacted: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubscriptionCatalogUpdateRequest {
    pub catalog_path: String,
    pub snapshot_path: String,
    pub source_id: String,
    pub location: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubscriptionCatalogUpdateReport {
    pub catalog_path: String,
    pub snapshot_path: String,
    pub source_id: String,
    pub source_count: usize,
    pub location_kind: String,
    pub location_redacted: bool,
    pub validated_node_count: usize,
    pub added_node_count: usize,
    pub removed_node_count: usize,
    pub changed_node_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubscriptionCatalogRollbackRequest {
    pub catalog_path: String,
    pub snapshot_path: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubscriptionCatalogRollbackReport {
    pub catalog_path: String,
    pub snapshot_path: String,
    pub source_count: usize,
    pub snapshot_retained: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubscriptionCatalogRemoveRequest {
    pub catalog_path: String,
    pub snapshot_path: String,
    pub source_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubscriptionCatalogRemoveReport {
    pub catalog_path: String,
    pub snapshot_path: String,
    pub source_id: String,
    pub source_count: usize,
}

pub const SUBSCRIPTION_REFRESH_MIN_INTERVAL_SECONDS: u64 = 300;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubscriptionRefreshStartRequest {
    pub catalog_path: String,
    pub status_path: String,
    pub snapshot_path: String,
    pub source_id: String,
    pub interval_seconds: u64,
    pub confirmed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubscriptionRefreshStatusReport {
    pub status_path: String,
    pub source_id: String,
    pub enabled: bool,
    pub last_attempt: String,
    pub last_success: Option<String>,
    pub next_attempt: String,
    pub result: String,
    pub error_redacted: bool,
    pub error_code: Option<String>,
    pub added_node_count: usize,
    pub removed_node_count: usize,
    pub changed_node_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagedForegroundSessionStatusRequest {
    pub status_path: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagedForegroundLifecyclePaths {
    pub status_path: String,
    pub snapshot_path: String,
    pub event_directory: String,
    pub control_socket_path: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagedForegroundSessionStatusWriteRequest {
    pub status_path: String,
    pub session_id: String,
    pub engine_id: String,
    pub state: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagedForegroundSessionStatusTransitionRequest {
    pub status_path: String,
    pub snapshot_path: String,
    pub expected_state: String,
    pub next_state: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagedForegroundSessionStatusRollbackRequest {
    pub status_path: String,
    pub snapshot_path: String,
    pub expected_state: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagedForegroundSessionStatusReport {
    pub status_path: String,
    pub session_id: String,
    pub engine_id: String,
    pub state: String,
    pub liveness_verified: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagedForegroundSessionStatusWriteReport {
    pub status_path: String,
    pub session_id: String,
    pub engine_id: String,
    pub state: String,
    pub record_written: bool,
    pub liveness_verified: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagedForegroundSessionStatusTransitionReport {
    pub status_path: String,
    pub snapshot_path: String,
    pub session_id: String,
    pub engine_id: String,
    pub previous_state: String,
    pub state: String,
    pub snapshot_written: bool,
    pub liveness_verified: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagedForegroundSessionStatusRollbackReport {
    pub status_path: String,
    pub snapshot_path: String,
    pub session_id: String,
    pub engine_id: String,
    pub previous_state: String,
    pub state: String,
    pub snapshot_retained: bool,
    pub liveness_verified: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagedForegroundSessionEventRequest {
    pub event_path: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagedForegroundSessionEventHistoryRequest {
    pub event_directory: String,
    pub session_id: Option<String>,
    pub event_kind: Option<String>,
    pub state: Option<String>,
    pub cursor: usize,
    pub limit: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagedForegroundSessionEventWriteRequest {
    pub event_path: String,
    pub session_id: String,
    pub engine_id: String,
    pub event_id: String,
    pub event_kind: String,
    pub state: String,
    pub recorded_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagedForegroundSessionEventReport {
    pub event_path: String,
    pub session_id: String,
    pub engine_id: String,
    pub event_id: String,
    pub event_kind: String,
    pub state: String,
    pub recorded_at: String,
    pub liveness_verified: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagedForegroundSessionEventHistoryEntry {
    pub event_path: String,
    pub session_id: String,
    pub engine_id: String,
    pub event_id: String,
    pub event_kind: String,
    pub state: String,
    pub recorded_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagedForegroundSessionEventHistoryReport {
    pub event_directory: String,
    pub session_id: Option<String>,
    pub event_kind: Option<String>,
    pub state: Option<String>,
    pub cursor: usize,
    pub next_cursor: Option<usize>,
    pub matching_event_count: usize,
    pub events: Vec<ManagedForegroundSessionEventHistoryEntry>,
    pub liveness_verified: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagedForegroundSessionEventWriteReport {
    pub event_path: String,
    pub session_id: String,
    pub engine_id: String,
    pub event_id: String,
    pub event_kind: String,
    pub state: String,
    pub recorded_at: String,
    pub record_written: bool,
    pub liveness_verified: bool,
}

/// Reads a bounded tail from one caller-selected managed runtime log file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagedForegroundSessionLogTailRequest {
    pub log_path: String,
    pub line_limit: usize,
}

/// A read-only bounded managed runtime log tail.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagedForegroundSessionLogTailReport {
    pub log_path: String,
    pub line_limit: usize,
    pub total_line_count: usize,
    pub lines: Vec<String>,
    pub returned_byte_count: usize,
    pub liveness_verified: bool,
}
