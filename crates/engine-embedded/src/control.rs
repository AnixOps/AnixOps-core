//! Runtime control: JSON requests from the client while the engine runs.
//!
//! One request is a JSON object naming its command in `cmd`; the answer is a
//! JSON object. The same requests reach the iOS tunnel through
//! `networkcore_ios_runtime_control` and the desktop local proxy through
//! `LocalProxy::control_json`.
//!
//! | `cmd` | Request fields | Answer |
//! | --- | --- | --- |
//! | `traffic` | | [`crate::connections::TrafficSnapshot`] |
//! | `connections` | | [`crate::connections::ConnectionsSnapshot`] |
//! | `close_connection` | `id` | `{"closed": bool}` |
//! | `close_all` | | `{"closed": count}` |
//! | `mode` | | `{"mode": "rule" \| "global" \| "direct"}` |
//! | `set_mode` | `mode` | `{"mode": ...}` |
//! | `block_quic` | | `{"block_quic": bool}` |
//! | `set_block_quic` | `enabled` | `{"block_quic": bool}`: refuse UDP to port 443 so apps fall back to TCP |
//! | `groups` | | `{"groups": [`[`crate::routing::GroupView`]`]}` |
//! | `select` | `group`, `member` | `{"now": member}` |
//! | `rule_sets` | | `{"rule_sets": [`[`crate::rule_sets::RuleSetStatus`]`]}` |
//! | `update_rule_sets` | | `{"scheduled": remote set count}` |
//! | `scripts` | | `{"scripts": [`[`ScheduledScriptView`]`]}` |
//! | `script_notifications` | | `{"notifications": [`[`ScriptNotificationView`]`]}`, each returned once |
//! | `network_changed` | | `{"scheduled": network-change script count}` |
//! | `reset_network` | `close_connections` (default `true`) | `{"reset": dropped sessions, "closed": closed connections}` |
//! | `run_script` | `tag` | `{"scheduled": bool}` |
//! | `outbound_health` | | `{"outbounds": [{"node", "protocol", "health"}]}`, only outbounds that report health |
//! | `resume_outbound` | `node` | `{"resumed": bool}` |
//! | `metrics` | `anonymous` (optional bool) | `{"content_type", "text"}`: [`crate::metrics`] in the Prometheus text format |
//! | `reload_rules` | `rules`, optional `dry_run` | `{"reloaded": bool, "rules", "generation"}` or `{"reloaded": false, "error": {"line", "code"}}` |
//! | `outbound_reuse` | | `{"outbounds": [{"node", "protocol", "reuse"}]}`: connection pool (`mux`) and TLS resumption counters, only outbounds that keep them |
//! | `capture` | | [`crate::capture::CaptureStatus`] |
//! | `set_capture` | `enabled`, optional `max_total_bytes` | [`crate::capture::CaptureStatus`]: keep the bytes of new connections |
//! | `clear_capture` | | [`crate::capture::CaptureStatus`] |
//! | `capture_connection` | `id` | `{"capture": {...} \| null}`: kept bytes and decrypted HTTP messages of one connection |
//! | `export_capture` | `format` (`pcapng` \| `har` \| `curl` \| `code` \| `postman` \| `insomnia`), optional `id`, `exchange` (index in that connection's `http`), `language` (`code`: `python` \| `javascript` \| `swift` \| `kotlin` \| `go`), `redact` (default `true`) | `{"format", "file_name", "content_type", "size", "redacted", "data_base64"}` |
//! | `set_capture_storage` | `dir`, `key_base64` (32 bytes the client keeps), optional `retention_days` (default 7, 1–365) | `{"retention_days", "purged"}`: where `save_capture` writes; old sessions are deleted |
//! | `save_capture` | optional `name` | `{"session": {"session", "name", "saved_at_ms", "expires_at_ms", "size", "connections", "requests"}}`: seals what capture holds |
//! | `capture_sessions` | | `{"sessions": [...]}`, newest first; a session this key cannot open has `"unreadable": true` |
//! | `load_capture` | `session` | [`crate::capture::CaptureStatus`]: the session replaces what capture holds, live capture turns off |
//! | `delete_capture` | `session` | `{"deleted": bool}` |
//! | `capture_requests` | optional `since_seq`, `since_rev`, `limit`, `filter` | `{"requests": [...], "last_seq", "last_rev", "dropped_before_seq"}` or `{"error": {"code": "invalid_filter", "at"}}`: one row per decrypted HTTP exchange, once finished (by `since_seq`), or at each change, still in progress included (by `since_rev`; rows carry `state`, `rev`, `message_count`, `rules_skipped`) |
//! | `capture_exchange` | `id`, `index`, optional `since_message` | `{"exchange": {...} \| null}`: one decrypted exchange with the kept stream messages (server-sent events, WebSocket messages) from `since_message` on |
//! | `capture_h2_frames` | `id`, optional `since` | `{"h2_frames": {"seen", "dropped", "frames": [...]} \| null}`: the HTTP/2 frame headers of a decrypted `h2` connection on both links (`link`: `app` \| `origin`, `dir`, `type`, `flags`, `stream`, `length`, `error`, `value`), the last 512 |
//! | `pro_status` | | [`crate::pro::ProStatus`] |
//! | `set_pro_license` | `license` (string or `null`) | [`crate::pro::ProStatus`]: the client's stored license, `null` removes it |
//!
//! The desktop local proxy and the packet tunnel runtime also answer
//! `lan_share`, `start_lan_share` and `stop_lan_share` before this module
//! sees them (feature `local-proxy`): sharing the engine with phones on the
//! local network, see [`crate::lan_share`]; and `replay_proxy`,
//! `start_replay_proxy` and `stop_replay_proxy`: a `127.0.0.1` listener
//! for the client's own requests, see [`crate::replay_proxy`]. The packet
//! tunnel runtime alone answers `system_proxy`, `start_system_proxy` and
//! `stop_system_proxy`: the `127.0.0.1` listener that iOS and macOS register
//! as the system proxy, see [`crate::system_proxy`].
//!
//! Capture is off until `set_capture` turns it on and lasts until the engine
//! stops; see [`crate::capture`] for what is kept and its memory budget,
//! [`crate::capture::redact`] for what an export masks and
//! [`crate::capture::filter`] for the `capture_requests` filter syntax.
//!
//! `reload_rules` swaps the rule lines of a routing config while the engine
//! runs ([`crate::routing::RoutedOutbound::reload_rules`]): `rules` is the
//! whole new list ending with `FINAL`, naming only the configured nodes,
//! groups and rule sets. Open connections and their packets are untouched.
//! A refused list leaves the running rules in force; `error.line` is the
//! 0-based index of the first bad line and `error.code` one of
//! [`crate::routing::reject_code`]. With `dry_run` the list is only checked,
//! which the client's rule editor uses to mark lines. It is the only command
//! that may be longer than [`MAX_REQUEST_LEN`], up to
//! [`MAX_RELOAD_REQUEST_LEN`].
//!
//! `reset_network` is what the client sends when the network under the
//! engine changed (another Wi-Fi, Wi-Fi to cellular, the default interface
//! moved) or the device woke from a long sleep: every outbound drops the
//! sessions it keeps between flows (see
//! [`engine_outbound::TcpOutbound::reset_sessions`]) and, unless
//! `close_connections` is `false`, the open connections are closed so the
//! apps behind them reconnect at once instead of waiting for a dead path to
//! time out. It works with or without plugin scripts.
//!
//! The script commands need a MITM config with plugin scripts; the client
//! sends `network_changed` when the device's network changes and polls
//! `script_notifications` to show what scripts posted.
//!
//! Mode, `block_quic` and group choices last until the engine stops; the
//! client keeps them in its profile (`mode`, `block_quic`, a select group's
//! `default`) for the next start.

use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::capture::filter::Filter;
use crate::capture::{self, ExportFormat, ExportRequest, Language, Selection};
use crate::connections::{Dispatcher, Mode};
use crate::metrics;
use crate::pro;
use crate::tunnel::FlowInterceptor;
use crate::{RuntimeError, RuntimeErrorCode};

/// The node name `outbound_health` gives the only outbound of a config
/// without policy groups.
pub const SINGLE_NODE: &str = "proxy";

/// Largest request accepted, except `reload_rules`.
pub const MAX_REQUEST_LEN: usize = 4096;

/// Largest `reload_rules` request accepted: 4096 rules of a typical length.
pub const MAX_RELOAD_REQUEST_LEN: usize = 1024 * 1024;

#[derive(Debug, Deserialize)]
#[serde(tag = "cmd", rename_all = "snake_case")]
enum ControlRequest {
    Traffic,
    Connections,
    CloseConnection {
        id: u64,
    },
    CloseAll,
    Mode,
    SetMode {
        mode: Mode,
    },
    BlockQuic,
    SetBlockQuic {
        enabled: bool,
    },
    Groups,
    Select {
        group: String,
        member: String,
    },
    RuleSets,
    UpdateRuleSets,
    Scripts,
    ScriptNotifications,
    NetworkChanged,
    ResetNetwork {
        #[serde(default = "default_true")]
        close_connections: bool,
    },
    RunScript {
        tag: String,
    },
    OutboundHealth,
    ResumeOutbound {
        node: String,
    },
    Metrics {
        #[serde(default)]
        anonymous: bool,
    },
    ReloadRules {
        rules: Vec<String>,
        #[serde(default)]
        dry_run: bool,
    },
    OutboundReuse,
    Capture,
    SetCapture {
        enabled: bool,
        #[serde(default)]
        max_total_bytes: Option<usize>,
    },
    ClearCapture,
    CaptureConnection {
        id: u64,
    },
    CaptureExchange {
        id: u64,
        index: usize,
        #[serde(default)]
        since_message: u64,
    },
    CaptureH2Frames {
        id: u64,
        #[serde(default)]
        since: u64,
    },
    ExportCapture {
        format: ExportFormat,
        #[serde(default)]
        id: Option<u64>,
        #[serde(default)]
        exchange: Option<usize>,
        #[serde(default)]
        language: Language,
        #[serde(default = "default_true")]
        redact: bool,
    },
    SetCaptureStorage {
        dir: String,
        key_base64: String,
        #[serde(default)]
        retention_days: Option<u32>,
    },
    SaveCapture {
        #[serde(default)]
        name: Option<String>,
    },
    CaptureSessions,
    LoadCapture {
        session: String,
    },
    DeleteCapture {
        session: String,
    },
    CaptureRequests {
        #[serde(default)]
        since_seq: u64,
        #[serde(default)]
        since_rev: Option<u64>,
        #[serde(default)]
        limit: Option<usize>,
        #[serde(default)]
        filter: String,
    },
    ProStatus,
    SetProLicense {
        #[serde(default)]
        license: Option<String>,
    },
}

/// Script commands, answered by the flow interceptor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScriptControl {
    Scripts,
    Notifications,
    NetworkChanged,
    Run { tag: String },
}

/// A cron, network-change or generic plugin script.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ScheduledScriptView {
    pub tag: String,
    /// `cron`, `network-changed` or `generic`.
    pub trigger: &'static str,
    /// Cron expression of a `cron` script.
    pub cron: Option<String>,
    /// Local time of the next cron run, RFC 9557 (`2026-11-09T09:00:00+08:00[Asia/Shanghai]`).
    pub next_run: Option<String>,
    /// Result of the last run since the engine started: `done`,
    /// `finished_without_done`, or a failure code.
    pub last_status: Option<String>,
}

/// A notification a script posted (`$notification.post`, `$notify`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ScriptNotificationView {
    pub title: String,
    pub subtitle: String,
    pub content: String,
    pub open_url: Option<String>,
}

/// Runs one JSON request against the flows of `dispatcher`.
pub fn handle(dispatcher: &Dispatcher, request: &[u8]) -> Result<Vec<u8>, RuntimeError> {
    handle_with_interceptor(dispatcher, None, request)
}

/// [`handle`], with the script commands going to `interceptor`.
pub fn handle_with_interceptor(
    dispatcher: &Dispatcher,
    interceptor: Option<&dyn FlowInterceptor>,
    request: &[u8],
) -> Result<Vec<u8>, RuntimeError> {
    if request.is_empty() || request.len() > MAX_RELOAD_REQUEST_LEN {
        return Err(invalid("control request size is out of range"));
    }
    let long = request.len() > MAX_REQUEST_LEN;
    let request: ControlRequest = serde_json::from_slice(request)
        .map_err(|_| invalid("control request is not a known command"))?;
    if long && !matches!(request, ControlRequest::ReloadRules { .. }) {
        return Err(invalid("control request size is out of range"));
    }
    let tracker = dispatcher.tracker();
    let answer = match request {
        ControlRequest::Traffic => serde_json::to_value(tracker.traffic()),
        ControlRequest::Connections => serde_json::to_value(tracker.connections()),
        ControlRequest::CloseConnection { id } => Ok(json!({ "closed": tracker.close(id) })),
        ControlRequest::CloseAll => Ok(json!({ "closed": tracker.close_all() })),
        ControlRequest::Mode => Ok(json!({ "mode": dispatcher.mode() })),
        ControlRequest::SetMode { mode } => {
            dispatcher.set_mode(mode);
            Ok(json!({ "mode": dispatcher.mode() }))
        }
        ControlRequest::BlockQuic => Ok(json!({ "block_quic": dispatcher.block_quic() })),
        ControlRequest::SetBlockQuic { enabled } => {
            dispatcher.set_block_quic(enabled);
            Ok(json!({ "block_quic": dispatcher.block_quic() }))
        }
        ControlRequest::Groups => {
            let groups = dispatcher
                .routed_outbound()
                .map(|routed| routed.groups())
                .unwrap_or_default();
            Ok(json!({ "groups": groups }))
        }
        ControlRequest::Select { group, member } => {
            let routed = dispatcher
                .routed_outbound()
                .ok_or_else(|| invalid("this config has no policy groups"))?;
            Ok(json!({ "now": routed.select(&group, &member)? }))
        }
        ControlRequest::RuleSets => {
            let sets = dispatcher
                .routed_outbound()
                .map(|routed| routed.rule_sets().status())
                .unwrap_or_default();
            Ok(json!({ "rule_sets": sets }))
        }
        ControlRequest::UpdateRuleSets => {
            let scheduled = dispatcher
                .routed_outbound()
                .map_or(0, |routed| routed.rule_sets().refresh_now());
            Ok(json!({ "scheduled": scheduled }))
        }
        ControlRequest::Scripts => Ok(script(interceptor, ScriptControl::Scripts)?),
        ControlRequest::ScriptNotifications => {
            Ok(script(interceptor, ScriptControl::Notifications)?)
        }
        ControlRequest::NetworkChanged => Ok(script(interceptor, ScriptControl::NetworkChanged)?),
        ControlRequest::ResetNetwork { close_connections } => {
            let reset = dispatcher.reset_sessions();
            let closed = if close_connections {
                tracker.close_all()
            } else {
                0
            };
            Ok(json!({ "reset": reset, "closed": closed }))
        }
        ControlRequest::RunScript { tag } => Ok(script(interceptor, ScriptControl::Run { tag })?),
        ControlRequest::OutboundHealth => {
            let outbounds: Vec<_> = match dispatcher.routed_outbound() {
                Some(routed) => routed
                    .node_health()
                    .into_iter()
                    .map(|(node, protocol, health)| {
                        json!({ "node": node, "protocol": protocol, "health": health })
                    })
                    .collect(),
                None => {
                    let outbound = dispatcher.outbound();
                    outbound
                        .health()
                        .map(|health| {
                            json!({
                                "node": SINGLE_NODE,
                                "protocol": outbound.protocol(),
                                "health": health,
                            })
                        })
                        .into_iter()
                        .collect()
                }
            };
            Ok(json!({ "outbounds": outbounds }))
        }
        ControlRequest::OutboundReuse => {
            let outbounds: Vec<_> = match dispatcher.routed_outbound() {
                Some(routed) => routed
                    .node_reuse_stats()
                    .into_iter()
                    .map(|(node, protocol, reuse)| {
                        json!({ "node": node, "protocol": protocol, "reuse": reuse })
                    })
                    .collect(),
                None => {
                    let outbound = dispatcher.outbound();
                    outbound
                        .reuse_stats()
                        .map(|reuse| {
                            json!({
                                "node": SINGLE_NODE,
                                "protocol": outbound.protocol(),
                                "reuse": reuse,
                            })
                        })
                        .into_iter()
                        .collect()
                }
            };
            Ok(json!({ "outbounds": outbounds }))
        }
        ControlRequest::ResumeOutbound { node } => {
            let resumed = match dispatcher.routed_outbound() {
                Some(routed) => routed
                    .resume_node(&node)
                    .ok_or_else(|| invalid("no such node"))?,
                None if node == SINGLE_NODE => dispatcher.outbound().resume(),
                None => return Err(invalid("no such node")),
            };
            Ok(json!({ "resumed": resumed }))
        }
        ControlRequest::Metrics { anonymous } => {
            let labels = if anonymous {
                metrics::Labels::Anonymous
            } else {
                metrics::Labels::Named
            };
            Ok(json!({
                "content_type": metrics::CONTENT_TYPE,
                "text": metrics::render(dispatcher, labels),
            }))
        }
        ControlRequest::Capture => serde_json::to_value(tracker.capture().status()),
        ControlRequest::SetCapture {
            enabled,
            max_total_bytes,
        } => {
            tracker.capture().set(enabled, max_total_bytes);
            serde_json::to_value(tracker.capture().status())
        }
        ControlRequest::ClearCapture => {
            tracker.capture().clear();
            serde_json::to_value(tracker.capture().status())
        }
        ControlRequest::CaptureConnection { id } => {
            Ok(json!({ "capture": tracker.capture().connection_json(id) }))
        }
        ControlRequest::CaptureExchange {
            id,
            index,
            since_message,
        } => Ok(json!({
            "exchange": tracker.capture().exchange_json(id, index, since_message),
        })),
        ControlRequest::CaptureH2Frames { id, since } => Ok(json!({
            "h2_frames": tracker.capture().h2_frames_json(id, since),
        })),
        ControlRequest::ExportCapture {
            format,
            id,
            exchange,
            language,
            redact,
        } => {
            if exchange.is_some() && id.is_none() {
                return Err(invalid("exchange needs the connection id"));
            }
            let request = ExportRequest {
                format,
                selection: Selection { id, exchange },
                language,
                redact,
            };
            // The file goes out as written, without a JSON value in between.
            return Ok(capture::export_answer(tracker.capture(), &request));
        }
        ControlRequest::SetCaptureStorage {
            dir,
            key_base64,
            retention_days,
        } => {
            use base64::Engine as _;
            let key = base64::engine::general_purpose::STANDARD
                .decode(key_base64.trim())
                .map_err(|_| storage_error(capture::storage::StorageError::InvalidKey))?;
            let set = tracker.capture().set_storage(&dir, &key, retention_days);
            Ok(set.map_err(storage_error)?)
        }
        ControlRequest::SaveCapture { name } => {
            let saved = tracker.capture().save_session(name.as_deref());
            Ok(saved.map_err(storage_error)?)
        }
        ControlRequest::CaptureSessions => {
            let sessions = tracker.capture().sessions();
            Ok(sessions.map_err(storage_error)?)
        }
        ControlRequest::LoadCapture { session } => {
            let status = tracker.capture().load_session(&session);
            serde_json::to_value(status.map_err(storage_error)?)
        }
        ControlRequest::DeleteCapture { session } => {
            let deleted = tracker.capture().delete_session(&session);
            Ok(deleted.map_err(storage_error)?)
        }
        ControlRequest::CaptureRequests {
            since_seq,
            since_rev,
            limit,
            filter,
        } => match Filter::parse(&filter) {
            Ok(filter) => Ok(tracker
                .capture()
                .requests_json(since_seq, since_rev, limit, &filter)),
            Err(error) => Ok(json!({
                "error": { "code": "invalid_filter", "at": error.at },
            })),
        },
        ControlRequest::ProStatus => serde_json::to_value(pro::status()),
        ControlRequest::SetProLicense { license } => {
            serde_json::to_value(pro::set_license(license.as_deref()))
        }
        ControlRequest::ReloadRules { rules, dry_run } => {
            let routed = dispatcher
                .routed_outbound()
                .ok_or_else(|| invalid("this config has no routing rules"))?;
            Ok(match routed.reload_rules(&rules, dry_run) {
                Ok(done) => json!({
                    "reloaded": done.applied,
                    "rules": done.rules,
                    "generation": done.generation,
                }),
                Err(rejection) => json!({ "reloaded": false, "error": rejection }),
            })
        }
    };
    answer
        .and_then(|answer| serde_json::to_vec(&answer))
        .map_err(|_| RuntimeError::new(RuntimeErrorCode::InternalError, "control answer failed"))
}

/// The answer for runtimes without flows to control, such as a WireGuard
/// tunnel.
#[cfg(feature = "wireguard")]
pub(crate) fn unavailable() -> RuntimeError {
    invalid("this tunnel has no runtime controls")
}

fn script(
    interceptor: Option<&dyn FlowInterceptor>,
    request: ScriptControl,
) -> Result<serde_json::Value, RuntimeError> {
    interceptor
        .and_then(|interceptor| interceptor.script_control(&request))
        .ok_or_else(|| invalid("this config runs no plugin scripts"))
}

fn storage_error(error: capture::storage::StorageError) -> RuntimeError {
    invalid(error.message())
}

fn default_true() -> bool {
    true
}

fn invalid(message: &'static str) -> RuntimeError {
    RuntimeError::new(RuntimeErrorCode::InvalidArgument, message)
}
