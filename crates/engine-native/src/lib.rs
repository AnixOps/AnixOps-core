//! Native proxy engine adapter contracts for NetworkCore.
//!
//! This crate intentionally exposes descriptor, validation, lifecycle
//! diagnostics, and resource-backed runtime handle contracts for the
//! current-process foreground runtime path.

use control_domain::{
    AuditEvent, Diagnostic, DiagnosticSeverity, DomainError, DomainResult, Endpoint,
    HttpHeaderMutation, HttpHeaderMutationOperation, HttpMitmAction, HttpMitmEvent,
    HttpMitmOutcome, HttpMitmPhase, HttpMitmScriptDispatch, HttpMitmScriptKind, ListenerDescriptor,
    ListenerKind, ListenerNetwork, ListenerRoute, MetadataEntry, MitmHostnameDecision,
    MitmPluginService, NodeDescriptor, PluginInstance, Protocol, ProxyEngineConfig,
    ProxyEngineDescriptor, ProxyEngineEvent, ProxyEngineEventKind, ProxyEngineHealthReport,
    ProxyEngineKind, ProxyEngineLifecycleState, ProxyEngineRollbackRequest, ProxyEngineService,
    ProxyEngineStatus, RouteAction, RuleSet,
};
use rcgen::{
    CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, Issuer, KeyPair,
};
use rustls::{
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName},
    ClientConfig, ClientConnection, RootCertStore, ServerConfig, ServerConnection, StreamOwned,
};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::io::{ErrorKind, Read, Write};
use std::net::{IpAddr, Ipv6Addr, Shutdown, SocketAddr, TcpListener, TcpStream};
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

mod h2_mitm;
#[cfg(feature = "quickjs")]
mod quickjs_script;

#[cfg(feature = "quickjs")]
pub use quickjs_script::scaled_memory_limit;
#[cfg(feature = "quickjs")]
pub use quickjs_script::{
    NativeQuickJsScriptExecutor, NativeQuickJsScriptRuntimeConfig, NativeScheduledScriptKind,
    NativeScheduledScriptReport, NativeScheduledScriptRun, ScriptMemoryPressure,
    ENGINE_NATIVE_QUICKJS_SCRIPT_CONFIG_INVALID_CODE, QUICKJS_BODY_COPIES_PER_DISPATCH,
    QUICKJS_MAX_PENDING_NOTIFICATIONS, QUICKJS_MAX_SCALED_MEMORY_LIMIT_BYTES,
    QUICKJS_MAX_SCHEDULED_TIMEOUT_SECS,
};
/// Types an embedder needs to give scripts network access
/// ([`NativeQuickJsScriptExecutor::with_http_client`]).
#[cfg(feature = "quickjs")]
pub use script_runtime::{
    ScriptHttpClient, ScriptHttpClientRequest, ScriptNotification, ScriptResponse,
    ScriptStoreRecovery,
};

pub use h2_mitm::{
    run_native_h2_mitm_session, NativeH2MitmSessionConfig, NativeH2MitmSessionReport,
    CONTROLLED_H2_MAX_CONCURRENT_STREAMS, CONTROLLED_H2_MAX_STREAMS_PER_SESSION,
    CONTROLLED_H2_STREAM_TIMEOUT_MS,
};

mod accept_loop;
mod http_proxy;
mod listeners;
mod scripts;
mod service;
mod socks5;
mod tls_mitm;
mod validation;
mod wire;

pub(crate) use accept_loop::*;
pub use http_proxy::*;
pub use listeners::*;
pub use scripts::*;
pub use service::*;
pub use socks5::*;
pub use tls_mitm::*;
pub(crate) use validation::*;
pub use wire::*;

pub const DEFAULT_NATIVE_ENGINE_ID: &str = "native";

pub const SOURCE_ENGINE_NATIVE_CONFIG: &str = "engine.native.config";
pub const SOURCE_ENGINE_NATIVE_LIFECYCLE: &str = "engine.native.lifecycle";
pub const SOURCE_ENGINE_NATIVE_MITM: &str = "engine.native.mitm";
pub const SOURCE_ENGINE_NATIVE_RUNTIME: &str = "engine.native.runtime";

pub const ENGINE_NATIVE_CONFIG_ENGINE_ID_UNSUPPORTED_CODE: &str =
    "engine.native.config.engine_id_unsupported";
pub const ENGINE_NATIVE_CONFIG_LISTENER_MISSING_CODE: &str =
    "engine.native.config.listener_missing";
pub const ENGINE_NATIVE_CONFIG_LISTENER_ID_DUPLICATE_CODE: &str =
    "engine.native.config.listener_id_duplicate";
pub const ENGINE_NATIVE_CONFIG_LISTENER_BIND_INVALID_CODE: &str =
    "engine.native.config.listener_bind_invalid";
pub const ENGINE_NATIVE_CONFIG_LISTENER_KIND_UNSUPPORTED_CODE: &str =
    "engine.native.config.listener_kind_unsupported";
pub const ENGINE_NATIVE_CONFIG_NODE_MISSING_CODE: &str = "engine.native.config.node_missing";
pub const ENGINE_NATIVE_CONFIG_NODE_ID_DUPLICATE_CODE: &str =
    "engine.native.config.node_id_duplicate";
pub const ENGINE_NATIVE_CONFIG_NODE_PROTOCOL_UNSUPPORTED_CODE: &str =
    "engine.native.config.node_protocol_unsupported";
pub const ENGINE_NATIVE_CONFIG_ROUTE_ID_DUPLICATE_CODE: &str =
    "engine.native.config.route_id_duplicate";
pub const ENGINE_NATIVE_CONFIG_ROUTE_TARGET_MISSING_CODE: &str =
    "engine.native.config.route_target_missing";
pub const ENGINE_NATIVE_CONFIG_ROUTE_EMPTY_CODE: &str = "engine.native.config.route_empty";
pub const ENGINE_NATIVE_START_RUNTIME_UNAVAILABLE_CODE: &str =
    "engine.native.start.runtime_unavailable";
pub const ENGINE_NATIVE_START_RUNTIME_ASSEMBLY_READY_CODE: &str =
    "engine.native.start.runtime_assembly_ready";
pub const ENGINE_NATIVE_START_SERVICE_RUNTIME_OWNER_MISSING_CODE: &str =
    "engine.native.start.service_runtime_owner_missing";
pub const ENGINE_NATIVE_START_RUNNING_CODE: &str = "engine.native.start.running";
pub const ENGINE_NATIVE_START_BIND_FAILED_CODE: &str = "engine.native.start.bind_failed";
pub const ENGINE_NATIVE_START_LIFECYCLE_FAILED_CODE: &str = "engine.native.start.lifecycle_failed";
pub const ENGINE_NATIVE_RELOAD_RUNTIME_MISSING_CODE: &str = "engine.native.reload.runtime_missing";
pub const ENGINE_NATIVE_RELOAD_RUNNING_CODE: &str = "engine.native.reload.running";
pub const ENGINE_NATIVE_RELOAD_FAILED_CODE: &str = "engine.native.reload.failed";
pub const ENGINE_NATIVE_RELOAD_ROLLBACK_FAILED_CODE: &str = "engine.native.reload.rollback_failed";
pub const ENGINE_NATIVE_RUNTIME_LISTENER_DISABLED_CODE: &str =
    "engine.native.runtime.listener_disabled";
pub const ENGINE_NATIVE_RUNTIME_LISTENER_NON_LOOPBACK_CODE: &str =
    "engine.native.runtime.listener_non_loopback";
pub const ENGINE_NATIVE_RUNTIME_LISTENER_UNSUPPORTED_CODE: &str =
    "engine.native.runtime.listener_unsupported";
pub const ENGINE_NATIVE_RUNTIME_OUTBOUND_ENDPOINT_INVALID_CODE: &str =
    "engine.native.runtime.outbound_endpoint_invalid";
pub const ENGINE_NATIVE_RUNTIME_OUTBOUND_UNSUPPORTED_CODE: &str =
    "engine.native.runtime.outbound_unsupported";
pub const ENGINE_NATIVE_RUNTIME_RESOURCE_MISSING_CODE: &str =
    "engine.native.runtime.resource_missing";
pub const ENGINE_NATIVE_RUNTIME_RELEASED_CODE: &str = "engine.native.runtime.released";
pub const ENGINE_NATIVE_RUNTIME_FOREGROUND_HANDOFF_READY_CODE: &str =
    "engine.native.runtime.foreground_handoff_ready";
pub const ENGINE_NATIVE_RUNTIME_ACCEPT_LOOP_READY_CODE: &str =
    "engine.native.runtime.accept_loop_ready";
pub const ENGINE_NATIVE_RUNTIME_ACCEPT_LOOP_STOPPED_CODE: &str =
    "engine.native.runtime.accept_loop_stopped";
/// The accept loop is short of file descriptors or buffers and keeps
/// retrying; reported once per loop.
pub const ENGINE_NATIVE_RUNTIME_ACCEPT_LOOP_RETRYING_CODE: &str =
    "engine.native.runtime.accept_loop_retrying";
pub const ENGINE_NATIVE_RUNTIME_CONNECTION_PRE_PROTOCOL_CLOSED_CODE: &str =
    "engine.native.runtime.connection_pre_protocol_closed";
pub const ENGINE_NATIVE_RUNTIME_SOCKS5_GREETING_READ_CODE: &str =
    "engine.native.runtime.socks5_greeting_read";
pub const ENGINE_NATIVE_RUNTIME_SOCKS5_GREETING_INVALID_CODE: &str =
    "engine.native.runtime.socks5_greeting_invalid";
pub const ENGINE_NATIVE_RUNTIME_SOCKS5_GREETING_READ_FAILED_CODE: &str =
    "engine.native.runtime.socks5_greeting_read_failed";
pub const ENGINE_NATIVE_RUNTIME_SOCKS5_AUTH_METHOD_SELECTED_CODE: &str =
    "engine.native.runtime.socks5_auth_method_selected";
pub const ENGINE_NATIVE_RUNTIME_SOCKS5_AUTH_METHOD_UNSUPPORTED_CODE: &str =
    "engine.native.runtime.socks5_auth_method_unsupported";
pub const ENGINE_NATIVE_RUNTIME_SOCKS5_AUTH_METHOD_RESPONSE_WRITTEN_CODE: &str =
    "engine.native.runtime.socks5_auth_method_response_written";
pub const ENGINE_NATIVE_RUNTIME_SOCKS5_AUTH_METHOD_RESPONSE_WRITE_FAILED_CODE: &str =
    "engine.native.runtime.socks5_auth_method_response_write_failed";
pub const ENGINE_NATIVE_RUNTIME_SOCKS5_COMMAND_HEADER_READ_CODE: &str =
    "engine.native.runtime.socks5_command_header_read";
pub const ENGINE_NATIVE_RUNTIME_SOCKS5_COMMAND_HEADER_INVALID_CODE: &str =
    "engine.native.runtime.socks5_command_header_invalid";
pub const ENGINE_NATIVE_RUNTIME_SOCKS5_COMMAND_HEADER_READ_FAILED_CODE: &str =
    "engine.native.runtime.socks5_command_header_read_failed";
pub const ENGINE_NATIVE_RUNTIME_SOCKS5_COMMAND_UNSUPPORTED_CODE: &str =
    "engine.native.runtime.socks5_command_unsupported";
pub const ENGINE_NATIVE_RUNTIME_SOCKS5_CONNECT_TARGET_READ_CODE: &str =
    "engine.native.runtime.socks5_connect_target_read";
pub const ENGINE_NATIVE_RUNTIME_SOCKS5_CONNECT_TARGET_INVALID_CODE: &str =
    "engine.native.runtime.socks5_connect_target_invalid";
pub const ENGINE_NATIVE_RUNTIME_SOCKS5_CONNECT_TARGET_READ_FAILED_CODE: &str =
    "engine.native.runtime.socks5_connect_target_read_failed";
pub const ENGINE_NATIVE_RUNTIME_SOCKS5_ROUTE_OUTBOUND_SELECTED_CODE: &str =
    "engine.native.runtime.socks5_route_outbound_selected";
pub const ENGINE_NATIVE_RUNTIME_SOCKS5_OUTBOUND_CONNECT_REQUEST_FRAME_GENERATED_CODE: &str =
    "engine.native.runtime.socks5_outbound_connect_request_frame_generated";
pub const ENGINE_NATIVE_RUNTIME_SOCKS5_OUTBOUND_CONNECT_REQUEST_FRAME_INVALID_CODE: &str =
    "engine.native.runtime.socks5_outbound_connect_request_frame_invalid";
pub const ENGINE_NATIVE_RUNTIME_SOCKS5_OUTBOUND_TCP_CONNECTION_PLANNED_CODE: &str =
    "engine.native.runtime.socks5_outbound_tcp_connection_planned";
pub const ENGINE_NATIVE_RUNTIME_SOCKS5_OUTBOUND_TCP_CONNECTION_PLAN_INVALID_CODE: &str =
    "engine.native.runtime.socks5_outbound_tcp_connection_plan_invalid";
pub const ENGINE_NATIVE_RUNTIME_SOCKS5_OUTBOUND_TCP_CONNECTION_ATTEMPT_SUCCEEDED_CODE: &str =
    "engine.native.runtime.socks5_outbound_tcp_connection_attempt_succeeded";
pub const ENGINE_NATIVE_RUNTIME_SOCKS5_OUTBOUND_TCP_CONNECTION_ATTEMPT_FAILED_CODE: &str =
    "engine.native.runtime.socks5_outbound_tcp_connection_attempt_failed";
pub const ENGINE_NATIVE_RUNTIME_SOCKS5_OUTBOUND_CONNECT_REQUEST_WRITTEN_CODE: &str =
    "engine.native.runtime.socks5_outbound_connect_request_written";
pub const ENGINE_NATIVE_RUNTIME_SOCKS5_OUTBOUND_CONNECT_REQUEST_WRITE_FAILED_CODE: &str =
    "engine.native.runtime.socks5_outbound_connect_request_write_failed";
pub const ENGINE_NATIVE_RUNTIME_SOCKS5_OUTBOUND_CONNECT_RESPONSE_READ_CODE: &str =
    "engine.native.runtime.socks5_outbound_connect_response_read";
pub const ENGINE_NATIVE_RUNTIME_SOCKS5_OUTBOUND_CONNECT_RESPONSE_INVALID_CODE: &str =
    "engine.native.runtime.socks5_outbound_connect_response_invalid";
pub const ENGINE_NATIVE_RUNTIME_SOCKS5_OUTBOUND_CONNECT_RESPONSE_READ_FAILED_CODE: &str =
    "engine.native.runtime.socks5_outbound_connect_response_read_failed";
pub const ENGINE_NATIVE_RUNTIME_SOCKS5_OUTBOUND_CONNECT_RESPONSE_ACCEPTED_CODE: &str =
    "engine.native.runtime.socks5_outbound_connect_response_accepted";
pub const ENGINE_NATIVE_RUNTIME_SOCKS5_OUTBOUND_CONNECT_RESPONSE_REJECTED_CODE: &str =
    "engine.native.runtime.socks5_outbound_connect_response_rejected";
pub const ENGINE_NATIVE_RUNTIME_SOCKS5_OUTBOUND_CONNECT_RELAY_READY_CODE: &str =
    "engine.native.runtime.socks5_outbound_connect_relay_ready";
pub const ENGINE_NATIVE_RUNTIME_SOCKS5_OUTBOUND_CONNECT_RELAY_UNWIRED_CODE: &str =
    "engine.native.runtime.socks5_outbound_connect_relay_unwired";
pub const ENGINE_NATIVE_RUNTIME_SOCKS5_OUTBOUND_CONNECT_RELAY_REJECTED_CODE: &str =
    "engine.native.runtime.socks5_outbound_connect_relay_rejected";
pub const ENGINE_NATIVE_RUNTIME_SOCKS5_OUTBOUND_CONNECT_DATA_RELAY_PLAN_READY_CODE: &str =
    "engine.native.runtime.socks5_outbound_connect_data_relay_plan_ready";
pub const ENGINE_NATIVE_RUNTIME_SOCKS5_OUTBOUND_CONNECT_DATA_RELAY_PLAN_UNWIRED_CODE: &str =
    "engine.native.runtime.socks5_outbound_connect_data_relay_plan_unwired";
pub const ENGINE_NATIVE_RUNTIME_SOCKS5_OUTBOUND_CONNECT_DATA_RELAY_PLAN_REJECTED_CODE: &str =
    "engine.native.runtime.socks5_outbound_connect_data_relay_plan_rejected";
pub const ENGINE_NATIVE_RUNTIME_SOCKS5_OUTBOUND_CONNECT_DATA_RELAY_COMPLETED_CODE: &str =
    "engine.native.runtime.socks5_outbound_connect_data_relay_completed";
pub const ENGINE_NATIVE_RUNTIME_SOCKS5_OUTBOUND_CONNECT_DATA_RELAY_FAILED_CODE: &str =
    "engine.native.runtime.socks5_outbound_connect_data_relay_failed";
pub const ENGINE_NATIVE_RUNTIME_SOCKS5_OUTBOUND_CONNECT_CLIENT_SUCCESS_RESPONSE_READY_CODE: &str =
    "engine.native.runtime.socks5_outbound_connect_client_success_response_ready";
pub const ENGINE_NATIVE_RUNTIME_SOCKS5_OUTBOUND_CONNECT_CLIENT_SUCCESS_RESPONSE_UNWIRED_CODE: &str =
    "engine.native.runtime.socks5_outbound_connect_client_success_response_unwired";
pub const ENGINE_NATIVE_RUNTIME_SOCKS5_OUTBOUND_CONNECT_CLIENT_SUCCESS_RESPONSE_REJECTED_CODE:
    &str = "engine.native.runtime.socks5_outbound_connect_client_success_response_rejected";
pub const ENGINE_NATIVE_RUNTIME_SOCKS5_OUTBOUND_CONNECT_CLIENT_SUCCESS_RESPONSE_WRITE_PLAN_READY_CODE:
    &str = "engine.native.runtime.socks5_outbound_connect_client_success_response_write_plan_ready";
pub const ENGINE_NATIVE_RUNTIME_SOCKS5_OUTBOUND_CONNECT_CLIENT_SUCCESS_RESPONSE_WRITE_PLAN_UNWIRED_CODE:
    &str = "engine.native.runtime.socks5_outbound_connect_client_success_response_write_plan_unwired";
pub const ENGINE_NATIVE_RUNTIME_SOCKS5_OUTBOUND_CONNECT_CLIENT_SUCCESS_RESPONSE_WRITE_PLAN_REJECTED_CODE:
    &str = "engine.native.runtime.socks5_outbound_connect_client_success_response_write_plan_rejected";
pub const ENGINE_NATIVE_RUNTIME_SOCKS5_OUTBOUND_CONNECT_CLIENT_SUCCESS_RESPONSE_WRITTEN_CODE: &str =
    "engine.native.runtime.socks5_outbound_connect_client_success_response_written";
pub const ENGINE_NATIVE_RUNTIME_SOCKS5_OUTBOUND_CONNECT_CLIENT_SUCCESS_RESPONSE_WRITE_FAILED_CODE:
    &str = "engine.native.runtime.socks5_outbound_connect_client_success_response_write_failed";
pub const ENGINE_NATIVE_RUNTIME_SOCKS5_ROUTE_OUTBOUND_UNWIRED_CODE: &str =
    "engine.native.runtime.socks5_route_outbound_unwired";
pub const ENGINE_NATIVE_RUNTIME_SOCKS5_CONNECT_FAILURE_RESPONSE_WRITTEN_CODE: &str =
    "engine.native.runtime.socks5_connect_failure_response_written";
pub const ENGINE_NATIVE_RUNTIME_SOCKS5_CONNECT_FAILURE_RESPONSE_WRITE_FAILED_CODE: &str =
    "engine.native.runtime.socks5_connect_failure_response_write_failed";
pub const ENGINE_NATIVE_RUNTIME_HTTP_MITM_CONNECT_EVENT_PLANNED_CODE: &str =
    "engine.native.runtime.http_mitm_connect_event_planned";
pub const ENGINE_NATIVE_RUNTIME_HTTP_MITM_CONNECT_PLAN_READY_CODE: &str =
    "engine.native.runtime.http_mitm_connect_plan_ready";
pub const ENGINE_NATIVE_RUNTIME_HTTP_MITM_CONNECT_PLAN_FAILED_CODE: &str =
    "engine.native.runtime.http_mitm_connect_plan_failed";
pub const ENGINE_NATIVE_RUNTIME_HTTP_MITM_CONNECT_PLAN_NOT_APPLIED_CODE: &str =
    "engine.native.runtime.http_mitm_connect_plan_not_applied";
pub const ENGINE_NATIVE_RUNTIME_HTTP_MITM_CONNECT_REJECT_APPLIED_CODE: &str =
    "engine.native.runtime.http_mitm_connect_reject_applied";
pub const ENGINE_NATIVE_RUNTIME_HTTP_MITM_CONNECT_REJECT_RESPONSE_WRITTEN_CODE: &str =
    "engine.native.runtime.http_mitm_connect_reject_response_written";
pub const ENGINE_NATIVE_RUNTIME_HTTP_MITM_CONNECT_REJECT_RESPONSE_WRITE_FAILED_CODE: &str =
    "engine.native.runtime.http_mitm_connect_reject_response_write_failed";
pub const ENGINE_NATIVE_RUNTIME_HTTP_MITM_CONNECT_BROWSER_PROOF_OBSERVED_CODE: &str =
    "engine.native.runtime.http_mitm_connect_browser_proof_observed";
pub const ENGINE_NATIVE_RUNTIME_HTTP_MITM_PLAIN_EVENT_PLANNED_CODE: &str =
    "engine.native.runtime.http_mitm_plain_event_planned";
pub const ENGINE_NATIVE_RUNTIME_HTTP_MITM_PLAIN_PLAN_READY_CODE: &str =
    "engine.native.runtime.http_mitm_plain_plan_ready";
pub const ENGINE_NATIVE_RUNTIME_HTTP_MITM_PLAIN_PLAN_FAILED_CODE: &str =
    "engine.native.runtime.http_mitm_plain_plan_failed";
pub const ENGINE_NATIVE_RUNTIME_HTTP_MITM_PLAIN_TERMINAL_ACTION_APPLIED_CODE: &str =
    "engine.native.runtime.http_mitm_plain_terminal_action_applied";
pub const ENGINE_NATIVE_RUNTIME_HTTP_MITM_PLAIN_HEADER_MUTATION_APPLIED_CODE: &str =
    "engine.native.runtime.http_mitm_plain_header_mutation_applied";
pub const ENGINE_NATIVE_RUNTIME_HTTP_MITM_PLAIN_BODY_MUTATION_APPLIED_CODE: &str =
    "engine.native.runtime.http_mitm_plain_body_mutation_applied";
pub const ENGINE_NATIVE_RUNTIME_HTTP_MITM_PLAIN_SCRIPT_DISPATCH_DEFERRED_CODE: &str =
    "engine.native.runtime.http_mitm_plain_script_dispatch_deferred";
pub const ENGINE_NATIVE_RUNTIME_HTTP_MITM_PLAIN_REWRITE_NOOP_CODE: &str =
    "engine.native.runtime.http_mitm_plain_rewrite_noop";
pub const ENGINE_NATIVE_RUNTIME_HTTP_PROXY_PLAIN_REQUEST_READ_CODE: &str =
    "engine.native.runtime.http_proxy_plain_request_read";
pub const ENGINE_NATIVE_RUNTIME_HTTP_PROXY_PLAIN_REQUEST_INVALID_CODE: &str =
    "engine.native.runtime.http_proxy_plain_request_invalid";
pub const ENGINE_NATIVE_RUNTIME_HTTP_PROXY_PLAIN_HTTP_VERSION_UNSUPPORTED_CODE: &str =
    "engine.native.runtime.http_proxy_plain_http_version_unsupported";
pub const ENGINE_NATIVE_RUNTIME_HTTP_PROXY_PLAIN_REQUEST_READ_FAILED_CODE: &str =
    "engine.native.runtime.http_proxy_plain_request_read_failed";
pub const ENGINE_NATIVE_RUNTIME_HTTP_PROXY_PLAIN_CONNECT_TLS_BLOCKED_CODE: &str =
    "engine.native.runtime.http_proxy_plain_connect_tls_blocked";
pub const ENGINE_NATIVE_RUNTIME_HTTP_PROXY_TLS_FOUNDATION_READY_CODE: &str =
    "engine.native.runtime.http_proxy_tls_foundation_ready";
pub const ENGINE_NATIVE_RUNTIME_HTTP_PROXY_TLS_CONNECT_TUNNEL_ESTABLISHED_CODE: &str =
    "engine.native.runtime.http_proxy_tls_connect_tunnel_established";
pub const ENGINE_NATIVE_RUNTIME_HTTP_PROXY_TLS_CONNECT_TUNNEL_FAILED_CODE: &str =
    "engine.native.runtime.http_proxy_tls_connect_tunnel_failed";
pub const ENGINE_NATIVE_RUNTIME_HTTP_PROXY_TLS_CLIENT_HELLO_OBSERVED_CODE: &str =
    "engine.native.runtime.http_proxy_tls_client_hello_observed";
pub const ENGINE_NATIVE_RUNTIME_HTTP_PROXY_TLS_CLIENT_HELLO_DEFERRED_CODE: &str =
    "engine.native.runtime.http_proxy_tls_client_hello_deferred";
pub const ENGINE_NATIVE_RUNTIME_HTTP_PROXY_TLS_SNI_AUTHORITY_MATCHED_CODE: &str =
    "engine.native.runtime.http_proxy_tls_sni_authority_matched";
pub const ENGINE_NATIVE_RUNTIME_HTTP_PROXY_TLS_SNI_AUTHORITY_MISMATCH_CODE: &str =
    "engine.native.runtime.http_proxy_tls_sni_authority_mismatch";
pub const ENGINE_NATIVE_RUNTIME_HTTP_PROXY_TLS_TERMINATION_PLAN_READY_CODE: &str =
    "engine.native.runtime.http_proxy_tls_termination_plan_ready";
pub const ENGINE_NATIVE_RUNTIME_HTTP_PROXY_TLS_TERMINATION_DEFERRED_CODE: &str =
    "engine.native.runtime.http_proxy_tls_termination_deferred";
pub const ENGINE_NATIVE_RUNTIME_HTTP_PROXY_TLS_LEAF_CERTIFICATE_ISSUED_CODE: &str =
    "engine.native.runtime.http_proxy_tls_leaf_certificate_issued";
pub const ENGINE_NATIVE_RUNTIME_HTTP_PROXY_TLS_LEAF_CERTIFICATE_DEFERRED_CODE: &str =
    "engine.native.runtime.http_proxy_tls_leaf_certificate_deferred";
pub const ENGINE_NATIVE_RUNTIME_HTTP_PROXY_TLS_LEAF_CERTIFICATE_FAILED_CODE: &str =
    "engine.native.runtime.http_proxy_tls_leaf_certificate_failed";
pub const ENGINE_NATIVE_RUNTIME_HTTP_PROXY_TLS_SERVER_CONFIG_READY_CODE: &str =
    "engine.native.runtime.http_proxy_tls_server_config_ready";
pub const ENGINE_NATIVE_RUNTIME_HTTP_PROXY_TLS_SERVER_CONFIG_FAILED_CODE: &str =
    "engine.native.runtime.http_proxy_tls_server_config_failed";
pub const ENGINE_NATIVE_RUNTIME_HTTP_PROXY_TLS_UPSTREAM_CONFIG_READY_CODE: &str =
    "engine.native.runtime.http_proxy_tls_upstream_config_ready";
pub const ENGINE_NATIVE_RUNTIME_HTTP_PROXY_TLS_UPSTREAM_CONFIG_FAILED_CODE: &str =
    "engine.native.runtime.http_proxy_tls_upstream_config_failed";
pub const ENGINE_NATIVE_RUNTIME_HTTP_PROXY_TLS_SESSION_DECRYPTION_READY_CODE: &str =
    "engine.native.runtime.http_proxy_tls_session_decryption_ready";
pub const ENGINE_NATIVE_RUNTIME_HTTP_PROXY_TLS_SESSION_DECRYPTION_FAILED_CODE: &str =
    "engine.native.runtime.http_proxy_tls_session_decryption_failed";
pub const ENGINE_NATIVE_RUNTIME_HTTP_SCRIPT_EXECUTED_CODE: &str =
    "engine.native.runtime.http_script_executed";
pub const ENGINE_NATIVE_RUNTIME_HTTP_SCRIPT_DEFERRED_CODE: &str =
    "engine.native.runtime.http_script_deferred";
pub const ENGINE_NATIVE_RUNTIME_HTTP_SCRIPT_FAILED_CODE: &str =
    "engine.native.runtime.http_script_failed";
pub const ENGINE_NATIVE_RUNTIME_HTTP_SCRIPT_URL_MUTATION_BLOCKED_CODE: &str =
    "engine.native.runtime.http_script_url_mutation_blocked";
/// A script without `requires-body=true` returned a body. It never read the
/// body, and the data plane may already be streaming it, so the body it
/// returned is ignored.
pub const ENGINE_NATIVE_RUNTIME_HTTP_SCRIPT_BODY_IGNORED_CODE: &str =
    "engine.native.runtime.http_script_body_ignored";
pub const ENGINE_NATIVE_RUNTIME_HTTP_PROXY_HTTPS_REQUEST_REWRITE_PREVIEW_READY_CODE: &str =
    "engine.native.runtime.http_proxy_https_request_rewrite_preview_ready";
pub const ENGINE_NATIVE_RUNTIME_HTTP_PROXY_HTTPS_REQUEST_REWRITE_PREVIEW_DEFERRED_CODE: &str =
    "engine.native.runtime.http_proxy_https_request_rewrite_preview_deferred";
pub const ENGINE_NATIVE_RUNTIME_HTTP_PROXY_HTTPS_REQUEST_REWRITE_SCRIPT_DEFERRED_CODE: &str =
    "engine.native.runtime.http_proxy_https_request_rewrite_script_deferred";
pub const ENGINE_NATIVE_RUNTIME_HTTP_PROXY_HTTPS_RESPONSE_REWRITE_PREVIEW_READY_CODE: &str =
    "engine.native.runtime.http_proxy_https_response_rewrite_preview_ready";
pub const ENGINE_NATIVE_RUNTIME_HTTP_PROXY_HTTPS_RESPONSE_REWRITE_PREVIEW_DEFERRED_CODE: &str =
    "engine.native.runtime.http_proxy_https_response_rewrite_preview_deferred";
pub const ENGINE_NATIVE_RUNTIME_HTTP_PROXY_HTTPS_RESPONSE_REWRITE_SCRIPT_DEFERRED_CODE: &str =
    "engine.native.runtime.http_proxy_https_response_rewrite_script_deferred";
pub const ENGINE_NATIVE_RUNTIME_HTTP_PROXY_PLAIN_REWRITE_APPLIED_CODE: &str =
    "engine.native.runtime.http_proxy_plain_rewrite_applied";
pub const ENGINE_NATIVE_RUNTIME_HTTP_PROXY_PLAIN_UPSTREAM_REQUEST_WRITTEN_CODE: &str =
    "engine.native.runtime.http_proxy_plain_upstream_request_written";
pub const ENGINE_NATIVE_RUNTIME_HTTP_PROXY_PLAIN_UPSTREAM_REQUEST_WRITE_FAILED_CODE: &str =
    "engine.native.runtime.http_proxy_plain_upstream_request_write_failed";
pub const ENGINE_NATIVE_RUNTIME_HTTP_PROXY_PLAIN_UPSTREAM_RESPONSE_READ_CODE: &str =
    "engine.native.runtime.http_proxy_plain_upstream_response_read";
pub const ENGINE_NATIVE_RUNTIME_HTTP_PROXY_PLAIN_UPSTREAM_RESPONSE_READ_FAILED_CODE: &str =
    "engine.native.runtime.http_proxy_plain_upstream_response_read_failed";
pub const ENGINE_NATIVE_RUNTIME_HTTP_PROXY_PLAIN_CLIENT_RESPONSE_WRITTEN_CODE: &str =
    "engine.native.runtime.http_proxy_plain_client_response_written";
pub const ENGINE_NATIVE_RUNTIME_HTTP_PROXY_PLAIN_CLIENT_RESPONSE_WRITE_FAILED_CODE: &str =
    "engine.native.runtime.http_proxy_plain_client_response_write_failed";
pub const ENGINE_NATIVE_RUNTIME_HTTP_PROXY_TLS_ALPN_NEGOTIATED_CODE: &str =
    "engine.native.runtime.http_proxy_tls_alpn_negotiated";
pub const ENGINE_NATIVE_RUNTIME_HTTP_PROXY_H2_SESSION_READY_CODE: &str =
    "engine.native.runtime.http_proxy_h2_session_ready";
pub const ENGINE_NATIVE_RUNTIME_HTTP_PROXY_H2_SESSION_FAILED_CODE: &str =
    "engine.native.runtime.http_proxy_h2_session_failed";
pub const ENGINE_NATIVE_RUNTIME_HTTP_PROXY_H2_STREAM_COMPLETED_CODE: &str =
    "engine.native.runtime.http_proxy_h2_stream_completed";
pub const ENGINE_NATIVE_RUNTIME_HTTP_PROXY_H2_STREAM_FAILED_CODE: &str =
    "engine.native.runtime.http_proxy_h2_stream_failed";
pub const ENGINE_NATIVE_RUNTIME_HTTP_PROXY_H2_STREAM_PASSTHROUGH_CODE: &str =
    "engine.native.runtime.http_proxy_h2_stream_passthrough";
pub const ENGINE_NATIVE_RUNTIME_HTTP_PROXY_H2_STREAM_AUTHORITY_MISMATCH_CODE: &str =
    "engine.native.runtime.http_proxy_h2_stream_authority_mismatch";
pub const ENGINE_NATIVE_RUNTIME_HTTP_PROXY_H2_STREAM_LIMIT_REACHED_CODE: &str =
    "engine.native.runtime.http_proxy_h2_stream_limit_reached";
pub const ENGINE_NATIVE_RUNTIME_UDP_MITM_QUIC_REJECTED_CODE: &str =
    "engine.native.runtime.udp_mitm_quic_rejected";
pub const ENGINE_NATIVE_RUNTIME_UDP_MITM_ALLOWED_CODE: &str =
    "engine.native.runtime.udp_mitm_allowed";
pub const ENGINE_NATIVE_RUNTIME_UDP_MITM_POLICY_FAILED_CODE: &str =
    "engine.native.runtime.udp_mitm_policy_failed";
/// An explicit proxy CONNECT to a host outside the plugin's `[MITM]`
/// hostname list was relayed without decryption.
pub const ENGINE_NATIVE_RUNTIME_HTTP_PROXY_TLS_MITM_HOSTNAME_BYPASSED_CODE: &str =
    "engine.native.runtime.http_proxy_tls_mitm_hostname_bypassed";
/// An explicit proxy CONNECT to a `[MITM]` host could not be terminated
/// (no or another SNI, not TLS, no leaf certificate) and was relayed
/// without decryption instead of being closed.
pub const ENGINE_NATIVE_RUNTIME_HTTP_PROXY_TLS_MITM_PASSTHROUGH_CODE: &str =
    "engine.native.runtime.http_proxy_tls_mitm_passthrough";

/// UDP port that carries HTTP/3 over QUIC.
pub const QUIC_HTTPS_UDP_PORT: u16 = 443;

const SOCKS5_VERSION: u8 = 0x05;
const SOCKS5_AUTH_METHOD_NO_AUTHENTICATION_REQUIRED: u8 = 0x00;
const SOCKS5_AUTH_METHOD_NO_ACCEPTABLE_METHODS: u8 = 0xff;
const SOCKS5_COMMAND_CONNECT: u8 = 0x01;
const SOCKS5_REPLY_SUCCEEDED: u8 = 0x00;
const SOCKS5_REPLY_GENERAL_FAILURE: u8 = 0x01;
const SOCKS5_RESERVED: u8 = 0x00;
const SOCKS5_ADDRESS_TYPE_IPV4: u8 = 0x01;
const SOCKS5_ADDRESS_TYPE_DOMAIN_NAME: u8 = 0x03;
const SOCKS5_ADDRESS_TYPE_IPV6: u8 = 0x04;
const SOCKS5_CONNECT_FAILURE_RESPONSE: [u8; 10] = [
    SOCKS5_VERSION,
    SOCKS5_REPLY_GENERAL_FAILURE,
    SOCKS5_RESERVED,
    SOCKS5_ADDRESS_TYPE_IPV4,
    0,
    0,
    0,
    0,
    0,
    0,
];
const ACCEPTED_CONNECTION_READ_TIMEOUT_MS: u64 = 1000;
const OUTBOUND_CONNECTION_ATTEMPT_TIMEOUT_MS: u64 = 100;
const OUTBOUND_CONNECT_REQUEST_WRITE_TIMEOUT_MS: u64 = 100;
const OUTBOUND_CONNECT_RESPONSE_READ_TIMEOUT_MS: u64 = 100;
const TLS_CLIENT_HELLO_PEEK_MAX_BYTES: usize = 16 * 1024 + 5;
const TLS_CLIENT_HELLO_OBSERVATION_TIMEOUT_MS: u64 = 1000;
const TLS_CLIENT_HELLO_OBSERVATION_POLL_MS: u64 = 5;
const CONTROLLED_TLS_SESSION_TIMEOUT_MS: u64 = 15_000;
const CONTROLLED_TLS_SOCKET_READ_TIMEOUT_MS: u64 = 1000;
const CONTROLLED_TLS_MAX_HTTP_EXCHANGES: usize = 4;
const MAX_CONCURRENT_ACCEPTED_CONNECTIONS: usize = 64;
const HTTP_PROXY_MAX_HEADER_BYTES: usize = 16 * 1024;
const HTTP_PROXY_MAX_BODY_BYTES: usize = 64 * 1024;
const SCRIPT_RUNTIME_DEFAULT_TIMEOUT_MS: usize = 5000;
const SCRIPT_RUNTIME_HARD_MAX_TIMEOUT_MS: usize = 30_000;
#[cfg(target_os = "linux")]
const SCRIPT_RUNTIME_V8_MAX_OLD_SPACE_MIB: usize = 64;
static SCRIPT_RUNTIME_TEMP_SEQUENCE: AtomicUsize = AtomicUsize::new(0);

#[derive(Clone, PartialEq, Eq)]
pub struct NativeTlsMitmCaMaterial {
    certificate_pem: String,
    private_key_pem: String,
}

impl NativeTlsMitmCaMaterial {
    pub fn new(certificate_pem: impl Into<String>, private_key_pem: impl Into<String>) -> Self {
        Self {
            certificate_pem: certificate_pem.into(),
            private_key_pem: private_key_pem.into(),
        }
    }

    fn certificate_pem(&self) -> &str {
        &self.certificate_pem
    }

    fn private_key_pem(&self) -> &str {
        &self.private_key_pem
    }

    fn certificate_pem_ready(&self) -> bool {
        !self.certificate_pem.trim().is_empty()
    }

    fn private_key_pem_ready(&self) -> bool {
        !self.private_key_pem.trim().is_empty()
    }
}

impl fmt::Debug for NativeTlsMitmCaMaterial {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NativeTlsMitmCaMaterial")
            .field("certificate_pem", &"[redacted]")
            .field("private_key_pem", &"[redacted]")
            .finish()
    }
}

#[derive(Debug, Clone)]
struct NativeLoopbackTcpAcceptLoopIdentity {
    listener_id: String,
    listener_kind: ListenerKind,
    outbound_handler_id: String,
    outbound_handler: NativeOutboundHandlerHandle,
    http_mitm_hook: Option<NativeHttpMitmPluginHook>,
    tls_mitm_ca_material: Option<NativeTlsMitmCaMaterial>,
    local_host: String,
    local_port: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeSocks5Greeting {
    pub version: u8,
    pub auth_methods: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeSocks5GreetingReadReport {
    pub greeting: Option<NativeSocks5Greeting>,
    pub diagnostics: Vec<Diagnostic>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NativeSocks5AuthMethodDecision {
    NoAuthenticationRequired,
    NoAcceptableMethods,
}

impl NativeSocks5AuthMethodDecision {
    pub const fn method_code(self) -> u8 {
        match self {
            Self::NoAuthenticationRequired => SOCKS5_AUTH_METHOD_NO_AUTHENTICATION_REQUIRED,
            Self::NoAcceptableMethods => SOCKS5_AUTH_METHOD_NO_ACCEPTABLE_METHODS,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeSocks5AuthMethodSelectionReport {
    pub decision: NativeSocks5AuthMethodDecision,
    pub diagnostics: Vec<Diagnostic>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeSocks5AuthMethodResponseWriteReport {
    pub response: [u8; 2],
    pub diagnostics: Vec<Diagnostic>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeSocks5CommandHeader {
    pub version: u8,
    pub command: u8,
    pub reserved: u8,
    pub address_type: u8,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeSocks5CommandHeaderReadReport {
    pub command_header: Option<NativeSocks5CommandHeader>,
    pub diagnostics: Vec<Diagnostic>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NativeSocks5CommandDecision {
    Connect,
    UnsupportedCommand,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeSocks5CommandSupportReport {
    pub decision: NativeSocks5CommandDecision,
    pub diagnostics: Vec<Diagnostic>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NativeSocks5Address {
    Ipv4([u8; 4]),
    DomainName(String),
    Ipv6([u8; 16]),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeSocks5ConnectTarget {
    pub address: NativeSocks5Address,
    pub port: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeSocks5ConnectTargetReadReport {
    pub target: Option<NativeSocks5ConnectTarget>,
    pub diagnostics: Vec<Diagnostic>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeSocks5ConnectHttpMitmPlanReport {
    pub request_id: String,
    pub target_host: String,
    pub target_port: u16,
    pub url: String,
    pub event: HttpMitmEvent,
    pub outcome: Option<HttpMitmOutcome>,
    pub applied: bool,
    pub audits: Vec<AuditEvent>,
    pub diagnostics: Vec<Diagnostic>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeTlsMitmFoundationReport {
    pub request_id: String,
    pub target_host: String,
    pub target_port: u16,
    pub target_url: String,
    pub connect_tunnel_ready: bool,
    pub downstream_tls_termination_ready: bool,
    pub upstream_tls_forwarding_ready: bool,
    pub https_request_rewrite_ready: bool,
    pub https_response_rewrite_ready: bool,
    pub script_dispatch_ready: bool,
    pub diagnostics: Vec<Diagnostic>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeTlsClientHelloObservationReport {
    pub request_id: String,
    pub target_host: String,
    pub target_port: u16,
    pub client_hello_observed: bool,
    pub sni_hostname: Option<String>,
    pub tls_record_version: Option<String>,
    pub tls_handshake_version: Option<String>,
    pub downstream_tls_termination_ready: bool,
    pub https_request_rewrite_ready: bool,
    pub https_response_rewrite_ready: bool,
    pub diagnostics: Vec<Diagnostic>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeControlledTlsTerminationPlanReport {
    pub request_id: String,
    pub target_host: String,
    pub target_port: u16,
    pub target_url: String,
    pub connect_tunnel_ready: bool,
    pub client_hello_observed: bool,
    pub sni_hostname: Option<String>,
    pub tls_record_version: Option<String>,
    pub tls_handshake_version: Option<String>,
    pub ca_certificate_pem_ready: bool,
    pub ca_private_key_pem_ready: bool,
    pub downstream_tls_termination_plan_ready: bool,
    pub upstream_tls_forwarding_ready: bool,
    pub live_https_decryption_ready: bool,
    pub https_request_rewrite_ready: bool,
    pub https_response_rewrite_ready: bool,
    pub script_dispatch_ready: bool,
    pub diagnostics: Vec<Diagnostic>,
}

#[derive(Clone, PartialEq, Eq)]
pub struct NativeTlsLeafCertificateMaterial {
    pub authority: String,
    pub certificate_pem: String,
    pub private_key_pem: String,
    pub certificate_der: Vec<u8>,
    pub private_key_der: Vec<u8>,
}

impl fmt::Debug for NativeTlsLeafCertificateMaterial {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NativeTlsLeafCertificateMaterial")
            .field("authority", &self.authority)
            .field("certificate_pem", &"[redacted]")
            .field("private_key_pem", &"[redacted]")
            .field("certificate_der", &"[redacted]")
            .field("private_key_der", &"[redacted]")
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeTlsLeafCertificateIssueReport {
    pub authority: String,
    pub issued: bool,
    pub material: Option<NativeTlsLeafCertificateMaterial>,
    pub diagnostics: Vec<Diagnostic>,
}

#[derive(Clone)]
pub struct NativeTlsServerConfigBuildReport {
    pub authority: String,
    pub server_config_ready: bool,
    pub server_config: Option<Arc<ServerConfig>>,
    pub diagnostics: Vec<Diagnostic>,
}

impl fmt::Debug for NativeTlsServerConfigBuildReport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NativeTlsServerConfigBuildReport")
            .field("authority", &self.authority)
            .field("server_config_ready", &self.server_config_ready)
            .field(
                "server_config",
                &self.server_config.as_ref().map(|_| "[configured]"),
            )
            .field("diagnostics", &self.diagnostics)
            .finish()
    }
}

#[derive(Clone)]
pub struct NativeTlsUpstreamClientConfigBuildReport {
    pub client_config_ready: bool,
    pub client_config: Option<Arc<ClientConfig>>,
    pub diagnostics: Vec<Diagnostic>,
}

impl fmt::Debug for NativeTlsUpstreamClientConfigBuildReport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NativeTlsUpstreamClientConfigBuildReport")
            .field("client_config_ready", &self.client_config_ready)
            .field(
                "client_config",
                &self.client_config.as_ref().map(|_| "[configured]"),
            )
            .field("diagnostics", &self.diagnostics)
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeHttpsRequestRewritePreviewReport {
    pub request_id: String,
    pub target_host: String,
    pub target_port: u16,
    pub target_url: String,
    pub controlled_tls_termination_plan_ready: bool,
    pub https_request_rewrite_preview_ready: bool,
    pub applied: bool,
    pub terminal_action: Option<String>,
    pub final_status_code: Option<u16>,
    pub redirect_location: Option<String>,
    pub header_mutation_count: usize,
    pub body_mutation_deferred: bool,
    pub https_response_rewrite_preview_ready: bool,
    pub https_response_rewrite_ready: bool,
    pub script_dispatch_ready: bool,
    pub script_dispatch_deferred: bool,
    pub headers: Vec<MetadataEntry>,
    pub body: Vec<u8>,
    pub diagnostics: Vec<Diagnostic>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeHttpsResponseRewritePreviewReport {
    pub request_id: String,
    pub target_host: String,
    pub target_port: u16,
    pub target_url: String,
    pub controlled_tls_termination_plan_ready: bool,
    pub https_response_rewrite_preview_ready: bool,
    pub applied: bool,
    pub terminal_action: Option<String>,
    pub final_status_code: Option<u16>,
    pub redirect_location: Option<String>,
    pub header_mutation_count: usize,
    pub content_type: Option<String>,
    pub content_type_guard_ready: bool,
    pub body_size_bytes: usize,
    pub body_size_limit_bytes: usize,
    pub body_buffering_guard_ready: bool,
    pub body_mutated: bool,
    pub body_mutation_deferred: bool,
    pub https_request_rewrite_preview_ready: bool,
    pub https_response_rewrite_ready: bool,
    pub script_dispatch_ready: bool,
    pub script_dispatch_deferred: bool,
    pub headers: Vec<MetadataEntry>,
    pub body: Vec<u8>,
    pub diagnostics: Vec<Diagnostic>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativePlainHttpMessage {
    pub request_id: String,
    pub url: String,
    pub method: Option<String>,
    pub phase: HttpMitmPhase,
    pub status_code: Option<u16>,
    pub headers: Vec<MetadataEntry>,
    pub body: Vec<u8>,
    /// Response phase: the headers of the request this response answers, as
    /// the request rules and scripts left them. Response scripts read them
    /// as `$request.headers`; rules never see them. Empty in the request
    /// phase.
    pub request_headers: Vec<MetadataEntry>,
    /// Response phase: the request body, when the data plane held it whole
    /// (a request rule or script read it), for a response script with
    /// `requires-body` (`$request.body`). `None` when the body was streamed
    /// to the origin, and in the request phase.
    pub request_body: Option<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativePlainHttpRewriteApplication {
    pub applied: bool,
    pub terminal_action: Option<String>,
    pub final_status_code: Option<u16>,
    pub redirect_location: Option<String>,
    pub headers: Vec<MetadataEntry>,
    pub body: Vec<u8>,
    pub script_dispatch_deferred: bool,
    pub diagnostics: Vec<Diagnostic>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativePlainHttpRewriteReport {
    pub request_id: String,
    pub url: String,
    pub event: HttpMitmEvent,
    pub outcome: Option<HttpMitmOutcome>,
    pub applied: bool,
    pub terminal_action: Option<String>,
    pub final_status_code: Option<u16>,
    pub redirect_location: Option<String>,
    pub headers: Vec<MetadataEntry>,
    pub body: Vec<u8>,
    pub script_dispatch_deferred: bool,
    pub script_dispatch_executed: bool,
    pub script_dispatch_failed: bool,
    pub audits: Vec<AuditEvent>,
    pub diagnostics: Vec<Diagnostic>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeExplicitHttpProxyRequest {
    pub request_id: String,
    pub method: String,
    pub target_url: String,
    pub target_host: String,
    pub target_port: u16,
    pub origin_path: String,
    pub version: String,
    pub headers: Vec<MetadataEntry>,
    pub body: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeExplicitHttpProxyRequestReadReport {
    pub request: Option<NativeExplicitHttpProxyRequest>,
    pub diagnostics: Vec<Diagnostic>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativePlainHttpProxyResponse {
    pub version: String,
    pub status_code: u16,
    pub reason_phrase: String,
    pub headers: Vec<MetadataEntry>,
    pub body: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativePlainHttpProxyResponseReadReport {
    pub response: Option<NativePlainHttpProxyResponse>,
    pub diagnostics: Vec<Diagnostic>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativePlainHttpProxyWriteReport {
    pub bytes: Vec<u8>,
    pub diagnostics: Vec<Diagnostic>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NativeSocks5RouteOutboundDecision {
    Unwired,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NativeSocks5RouteOutboundBehavior {
    ProxyViaSocksOutbound {
        target: NativeSocks5ConnectTarget,
        outbound_handler: NativeOutboundHandlerHandle,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeSocks5RouteOutboundSelectionReport {
    pub behavior: NativeSocks5RouteOutboundBehavior,
    pub diagnostics: Vec<Diagnostic>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeSocks5OutboundConnectRequestFrameReport {
    pub frame: Vec<u8>,
    pub diagnostics: Vec<Diagnostic>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeSocks5OutboundTcpConnectionPlan {
    pub outbound_handler_id: String,
    pub outbound_endpoint: Endpoint,
    pub target: NativeSocks5ConnectTarget,
    pub request_frame: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeSocks5OutboundTcpConnectionPlanReport {
    pub plan: Option<NativeSocks5OutboundTcpConnectionPlan>,
    pub diagnostics: Vec<Diagnostic>,
}

#[derive(Debug)]
pub struct NativeSocks5OutboundTcpConnectionAttemptReport {
    pub stream: Option<TcpStream>,
    pub diagnostics: Vec<Diagnostic>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeSocks5OutboundConnectRequestWriteReport {
    pub request_frame: Vec<u8>,
    pub diagnostics: Vec<Diagnostic>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeSocks5OutboundConnectResponse {
    pub version: u8,
    pub reply: u8,
    pub reserved: u8,
    pub address_type: u8,
    pub bound_address: NativeSocks5Address,
    pub bound_port: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeSocks5OutboundConnectResponseReadReport {
    pub response: Option<NativeSocks5OutboundConnectResponse>,
    pub diagnostics: Vec<Diagnostic>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NativeSocks5OutboundConnectResponseDecision {
    Accepted,
    Rejected,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeSocks5OutboundConnectResponseDecisionReport {
    pub decision: NativeSocks5OutboundConnectResponseDecision,
    pub diagnostics: Vec<Diagnostic>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NativeSocks5OutboundConnectRelayReadiness {
    Ready,
    Blocked,
    Rejected,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeSocks5OutboundConnectRelayReadinessReport {
    pub readiness: NativeSocks5OutboundConnectRelayReadiness,
    pub diagnostics: Vec<Diagnostic>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NativeSocks5OutboundConnectDataRelayPlanDecision {
    Ready,
    Blocked,
    Rejected,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeSocks5OutboundConnectDataRelayPlanReport {
    pub decision: NativeSocks5OutboundConnectDataRelayPlanDecision,
    pub diagnostics: Vec<Diagnostic>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeSocks5OutboundConnectDataRelayReport {
    pub client_to_outbound_bytes: u64,
    pub outbound_to_client_bytes: u64,
    pub diagnostics: Vec<Diagnostic>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NativeSocks5OutboundConnectClientSuccessResponseReadiness {
    Ready,
    Blocked,
    Rejected,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeSocks5OutboundConnectClientSuccessResponseReadinessReport {
    pub readiness: NativeSocks5OutboundConnectClientSuccessResponseReadiness,
    pub diagnostics: Vec<Diagnostic>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NativeSocks5OutboundConnectClientSuccessResponseWritePlanDecision {
    Ready,
    Blocked,
    Rejected,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeSocks5OutboundConnectClientSuccessResponseWritePlanReport {
    pub decision: NativeSocks5OutboundConnectClientSuccessResponseWritePlanDecision,
    pub diagnostics: Vec<Diagnostic>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeSocks5OutboundConnectClientSuccessResponseWriteReport {
    pub response_frame: Vec<u8>,
    pub diagnostics: Vec<Diagnostic>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeSocks5RouteOutboundReport {
    pub decision: NativeSocks5RouteOutboundDecision,
    pub diagnostics: Vec<Diagnostic>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeSocks5ConnectFailureResponseWriteReport {
    pub response: [u8; 10],
    pub diagnostics: Vec<Diagnostic>,
}

#[derive(Debug)]
struct NativeRuntimeReleaseResources {
    engine_id: String,
    listeners: Vec<LoopbackListenerHandle>,
    bound_listeners: Vec<BoundLoopbackTcpListenerHandle>,
    accept_loops: Vec<NativeLoopbackTcpAcceptLoopHandle>,
    outbound_handlers: Vec<NativeOutboundHandlerHandle>,
    events: Vec<ProxyEngineEvent>,
}

fn release_report(
    resources: NativeRuntimeReleaseResources,
    event_kind: ProxyEngineEventKind,
    mut diagnostics: Vec<Diagnostic>,
) -> NativeRuntimeReleaseReport {
    let NativeRuntimeReleaseResources {
        engine_id,
        listeners,
        bound_listeners,
        accept_loops,
        outbound_handlers,
        mut events,
    } = resources;
    let mut listener_ids = listeners
        .into_iter()
        .map(|listener| listener.listener_id)
        .collect::<Vec<_>>();
    listener_ids.extend(
        bound_listeners
            .into_iter()
            .map(|listener| listener.release().listener_id),
    );
    let mut outbound_handler_ids = outbound_handlers
        .into_iter()
        .map(|outbound_handler| outbound_handler.node_id)
        .collect::<Vec<_>>();
    for accept_loop in accept_loops {
        let report = accept_loop.shutdown();
        listener_ids.push(report.listener_id);
        outbound_handler_ids.push(report.outbound_handler_id);
        diagnostics.extend(report.diagnostics);
    }

    diagnostics.push(runtime_info(
        ENGINE_NATIVE_RUNTIME_RELEASED_CODE,
        "native runtime handles were released",
    ));
    events.push(runtime_event(&engine_id, event_kind, diagnostics.clone()));

    NativeRuntimeReleaseReport {
        engine_id,
        listener_ids,
        outbound_handler_ids,
        diagnostics,
        events,
    }
}

fn runtime_error(code: impl Into<String>, message: impl Into<String>) -> DomainError {
    DomainError::new(code, message)
}

fn runtime_info(code: impl Into<String>, message: impl Into<String>) -> Diagnostic {
    engine_diagnostic(
        DiagnosticSeverity::Info,
        code,
        message,
        SOURCE_ENGINE_NATIVE_RUNTIME,
    )
}

fn runtime_warning(code: impl Into<String>, message: impl Into<String>) -> Diagnostic {
    engine_diagnostic(
        DiagnosticSeverity::Warning,
        code,
        message,
        SOURCE_ENGINE_NATIVE_RUNTIME,
    )
}

fn runtime_event(
    engine_id: &str,
    kind: ProxyEngineEventKind,
    diagnostics: Vec<Diagnostic>,
) -> ProxyEngineEvent {
    ProxyEngineEvent {
        engine_id: engine_id.to_string(),
        kind,
        diagnostics,
    }
}

fn domain_error(code: impl Into<String>, message: impl Into<String>) -> DomainError {
    DomainError::new(code, message)
}

fn config_error(code: impl Into<String>, message: impl Into<String>) -> Diagnostic {
    engine_diagnostic(
        DiagnosticSeverity::Error,
        code,
        message,
        SOURCE_ENGINE_NATIVE_CONFIG,
    )
}

fn engine_diagnostic(
    severity: DiagnosticSeverity,
    code: impl Into<String>,
    message: impl Into<String>,
    source: impl Into<String>,
) -> Diagnostic {
    Diagnostic::new(severity, code, message, Some(source.into()))
}

#[cfg(all(test, unix))]
mod script_runtime_security_tests;

#[cfg(test)]
mod controlled_tls_session_tests;

#[cfg(test)]
mod http1_response_framing_tests;
