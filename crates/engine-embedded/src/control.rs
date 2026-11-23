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
//! | `rule_sets` | | `{"rule_sets": [`[`crate::rule_sets::RuleSetStatus`]`], "missing": [names]}`: `missing` lists the `geoip-<cc>` and `asn-<number>` sets `GEOIP` and `IP-ASN` rules use that the config lacks ([`crate::routing::RoutedOutbound::missing_data_sets`]) |
//! | `update_rule_sets` | | `{"scheduled": remote set count}` |
//! | `rule_hits` | | [`crate::routing::RuleHitsView`]: every rule in order, then FINAL, with how often it decided a flow since the rules were loaded |
//! | `clear_rule_hits` | | the `rule_hits` answer, after setting the counts to zero |
//! | `test_route` | `host` (domain or IP), optional `port` (default 443), `network` (`tcp` \| `udp`), `address` (the domain's IP, as a lookup would give it), `process`, `url`, `user_agent`, `source` (the app's IP), `source_port` | `{"mode", "test":` [`crate::routing::RouteTest`]`}`: which rule decides such a connection and where it goes, without opening or counting one |
//! | `scripts` | | `{"scripts": [`[`ScheduledScriptView`]`]}` |
//! | `script_notifications` | | `{"notifications": [`[`ScriptNotificationView`]`]}`, each returned once |
//! | `network_changed` | | `{"scheduled": network-change script count}` |
//! | `reset_network` | `close_connections` (default `true`) | `{"reset": dropped sessions, "closed": closed connections, "health_forgotten": groups whose check results were dropped}` |
//! | `set_network` | optional `type` (`wifi` \| `wired` \| `cellular`), `ssid`, `bssid`, `router`, `addresses` (IPs of the default interface), `radio` (cellular radio technology such as `LTE` or `NR`) | `{"changed": bool}`: the network subnet groups and `SUBNET` / `CELLULAR-RADIO` rules match; all fields absent means unknown |
//! | `devices` | | `{"devices": {ip: name}}` |
//! | `set_devices` | `devices` (`{ip: name}`, at most 256) | `{"changed": bool}`: the names `DEVICE-NAME` rules match, replacing the earlier ones |
//! | `run_script` | `tag` | `{"scheduled": bool}` |
//! | `outbound_health` | | `{"outbounds": [{"node", "protocol", "health"}]}`, only outbounds that report health |
//! | `resume_outbound` | `node` | `{"resumed": bool}` |
//! | `metrics` | `anonymous` (optional bool) | `{"content_type", "text"}`: [`crate::metrics`] in the Prometheus text format |
//! | `reload_rules` | `rules`, optional `dry_run` | `{"reloaded": bool, "rules", "generation"}` or `{"reloaded": false, "error": {"line", "code"}}` |
//! | `outbound_reuse` | | `{"outbounds": [{"node", "protocol", "reuse"}]}`: connection pool (`mux`) and TLS resumption counters, only outbounds that keep them |
//! | `capture` | | [`crate::capture::CaptureStatus`]: `enabled`, `max_total_bytes`, `used_bytes`, `connections`, `dropped_exchanges`, `dropped_bodies` (what the budget let go of since the last clear), `run_session` (this run's session id) |
//! | `set_capture` | `enabled`, optional `max_total_bytes` | [`crate::capture::CaptureStatus`]: keep the bytes of new connections |
//! | `clear_capture` | | [`crate::capture::CaptureStatus`]: connections still open record their later exchanges under new indexes |
//! | `capture_connection` | `id` | `{"capture": {...} \| null}`: kept bytes and decrypted HTTP messages of one connection |
//! | `export_capture` | `format` (`pcapng` \| `har` \| `zip` (both and a listing of the connections, [`crate::capture::archive`]) \| `curl` \| `code` \| `postman` \| `insomnia`), optional `id`, `exchange` (index in that connection's `http`), `language` (`code`: `python` \| `javascript` \| `swift` \| `kotlin` \| `go`), `redact` (default `true`) | `{"format", "file_name", "content_type", "size", "redacted", "data_base64"}` |
//! | `set_capture_storage` | `dir`, `key_base64` (32 bytes the client keeps), optional `retention_days` (default 7, 1–365) | `{"retention_days", "purged"}`: where `save_capture` writes; old sessions are deleted |
//! | `save_capture` | optional `name`, `run` | `{"session": {"session", "name", "saved_at_ms", "expires_at_ms", "size", "connections", "requests"}}`: seals what capture holds, as a new session or with `run` as this run's own (`run_session` of `capture`, replaced each time) |
//! | `capture_sessions` | | `{"sessions": [...]}`, newest first; a session this key cannot open has `"unreadable": true` |
//! | `load_capture` | `session` | [`crate::capture::CaptureStatus`]: the session replaces what capture holds, live capture turns off; its connections get new ids from [`crate::capture::LOADED_ID_BASE`] (2^52) up, so no live connection writes into them |
//! | `delete_capture` | `session` | `{"deleted": bool}` |
//! | `copy_capture` | `key_base64` (32 bytes), optional `session`, `name` | `{"session", "file_name", "size", "data_base64"}`: a saved session sealed again under that key, or without `session` what capture holds now sealed as this run's session named `name` (no storage needed), for the app's own store (the capture viewer's `import_capture`) |
//! | `capture_requests` | optional `since_seq`, `since_rev`, `limit`, `filter` | `{"requests": [...], "last_seq", "last_rev", "dropped_before_seq"}` or `{"error": {"code": "invalid_filter", "at"}}`: one row per decrypted HTTP exchange, once finished (by `since_seq`), or at each change, still in progress included (by `since_rev`; rows carry `state`, `rev`, `message_count`, `rules_skipped`) |
//! | `capture_exchange` | `id`, `index`, optional `since_message` | `{"exchange": {...} \| null}`: one decrypted exchange with the kept stream messages (server-sent events, WebSocket messages) from `since_message` on |
//! | `capture_h2_frames` | `id`, optional `since` | `{"h2_frames": {"seen", "dropped", "frames": [...]} \| null}`: the HTTP/2 frame headers of a decrypted `h2` connection on both links (`link`: `app` \| `origin`, `dir`, `type`, `flags`, `stream`, `length`, `error`, `value`), the last 512 |
//! | `mitm_hosts` | | `{"enabled", "hosts": [{"host", "decrypted", "failed", "last_failure", "last_failure_at_ms", "last_decrypted_at_ms", "failures"}]}`: what HTTPS decryption did per host since the engine started, the most recently seen first, at most 256; `last_failure` is `client_rejected_certificate` (certificate alert from the app: untrusted root or pinning), `client_closed` (the app hung up during the handshake, often pinning), `client_handshake_failed`, `client_timeout`, `origin_tls` or `origin_unreachable` |
//! | `clear_mitm_hosts` | | the `mitm_hosts` answer, after forgetting it |
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
//! The capture viewer ([`handle_capture_viewer`], [`crate::capture_viewer`])
//! answers the same capture commands with no engine, for saved sessions,
//! and `import_capture` (`session`, `data_base64`: a `copy_capture` file)
//! besides; a running engine refuses `import_capture`. Its `load_capture`
//! keeps the connection ids the session was saved with.
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
//! time out. It works with or without plugin scripts. It also forgets every
//! policy group health check result, which says nothing about the new
//! network: a group is checked again as soon as a connection goes through
//! it (see [`crate::routing`]). A running WireGuard node moves its session to
//! a new UDP socket and counts as one reset.
//!
//! A whole-device WireGuard tunnel (a config whose single `outbound` is
//! `wireguard`) has no flows: it answers `reset_network` by moving to a new
//! UDP socket (`reset` is 1 while the tunnel runs, `closed` is 0) and accepts
//! `set_network` without effect; every other command is refused.
//!
//! `set_network` tells subnet groups which network the device is on. The
//! client sends it whenever the network changes, before `reset_network`, so
//! the reconnecting apps already go through the new pick. The Wi-Fi name
//! and access point never leave the engine: they are not logged, listed or
//! exported.
//!
//! The script commands need a MITM config with plugin scripts; the client
//! sends `network_changed` when the device's network changes and polls
//! `script_notifications` to show what scripts posted.
//!
//! Mode, `block_quic` and group choices last until the engine stops; the
//! client keeps them in its profile (`mode`, `block_quic`, a select group's
//! `default`) for the next start.

use std::collections::BTreeMap;
use std::net::IpAddr;

use config_core::routing::{RouteNetwork, RouteQuery};
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

/// Largest request accepted, except `reload_rules` and `set_devices`.
pub const MAX_REQUEST_LEN: usize = 4096;

/// Largest `reload_rules` or `set_devices` request accepted: 4096 rules of
/// a typical length.
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
    RuleHits,
    ClearRuleHits,
    TestRoute {
        host: String,
        #[serde(default = "default_test_port")]
        port: u16,
        #[serde(default)]
        network: Option<String>,
        #[serde(default)]
        address: Option<String>,
        #[serde(default)]
        process: Option<String>,
        #[serde(default)]
        url: Option<String>,
        #[serde(default)]
        user_agent: Option<String>,
        #[serde(default)]
        source: Option<String>,
        #[serde(default)]
        source_port: Option<u16>,
    },
    Scripts,
    ScriptNotifications,
    NetworkChanged,
    ResetNetwork {
        #[serde(default = "default_true")]
        close_connections: bool,
    },
    SetNetwork {
        #[serde(default, rename = "type")]
        kind: Option<String>,
        #[serde(default)]
        ssid: Option<String>,
        #[serde(default)]
        bssid: Option<String>,
        #[serde(default)]
        router: Option<String>,
        #[serde(default)]
        addresses: Vec<String>,
        #[serde(default)]
        radio: Option<String>,
    },
    Devices,
    SetDevices {
        devices: BTreeMap<String, String>,
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
        #[serde(default)]
        run: bool,
    },
    CaptureSessions,
    LoadCapture {
        session: String,
    },
    DeleteCapture {
        session: String,
    },
    CopyCapture {
        #[serde(default)]
        session: Option<String>,
        key_base64: String,
        #[serde(default)]
        name: Option<String>,
    },
    ImportCapture {
        session: String,
        data_base64: String,
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
    MitmHosts,
    ClearMitmHosts,
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

/// Most addresses `set_network` takes.
const MAX_NETWORK_ADDRESSES: usize = 16;

/// Validates a `set_network` request; every field absent means unknown.
fn network_context(
    kind: Option<String>,
    ssid: Option<String>,
    bssid: Option<String>,
    router: Option<String>,
    addresses: Vec<String>,
    radio: Option<String>,
) -> Result<Option<config_core::routing::NetworkContext>, RuntimeError> {
    use config_core::routing::{NetworkCondition, NetworkContext, NetworkKind};

    if kind.is_none()
        && ssid.is_none()
        && bssid.is_none()
        && router.is_none()
        && addresses.is_empty()
        && radio.is_none()
    {
        return Ok(None);
    }
    let kind = kind
        .map(|kind| NetworkKind::parse(&kind).ok_or_else(|| invalid("network type is unknown")))
        .transpose()?;
    // 802.11 names are at most 32 bytes.
    if ssid
        .as_ref()
        .is_some_and(|ssid| ssid.is_empty() || ssid.len() > 32)
    {
        return Err(invalid("ssid must be 1-32 bytes"));
    }
    let bssid = bssid
        .map(
            |bssid| match NetworkCondition::parse(&format!("BSSID:{bssid}")) {
                Some(NetworkCondition::Bssid(bssid)) => Ok(bssid),
                _ => Err(invalid("bssid is not a MAC address")),
            },
        )
        .transpose()?;
    let router = router
        .map(|router| {
            router
                .trim()
                .parse()
                .map_err(|_| invalid("router is not an IP address"))
        })
        .transpose()?;
    if addresses.len() > MAX_NETWORK_ADDRESSES {
        return Err(invalid("too many network addresses"));
    }
    let addresses = addresses
        .iter()
        .map(|address| {
            address
                .trim()
                .parse()
                .map_err(|_| invalid("network address is not an IP address"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let radio = radio
        .map(|radio| {
            let radio = radio.trim().to_ascii_uppercase();
            if radio.is_empty()
                || radio.len() > 24
                || !radio.bytes().all(|byte| byte.is_ascii_alphanumeric())
            {
                return Err(invalid(
                    "radio must be a radio technology such as LTE or NR",
                ));
            }
            Ok(radio)
        })
        .transpose()?;
    Ok(Some(NetworkContext {
        kind,
        ssid,
        bssid,
        router,
        addresses,
        radio,
    }))
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
    if long
        && !matches!(
            request,
            ControlRequest::ReloadRules { .. } | ControlRequest::SetDevices { .. }
        )
    {
        return Err(invalid("control request size is out of range"));
    }
    let tracker = dispatcher.tracker();
    let request = match capture_command(tracker.capture(), request, CaptureHost::Engine) {
        Ok(answer) => return answer,
        Err(other) => other,
    };
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
            let routed = dispatcher.routed_outbound();
            let sets = routed
                .map(|routed| routed.rule_sets().status())
                .unwrap_or_default();
            let missing = routed
                .map(|routed| routed.missing_data_sets())
                .unwrap_or_default();
            Ok(json!({ "rule_sets": sets, "missing": missing }))
        }
        ControlRequest::RuleHits => {
            let routed = dispatcher
                .routed_outbound()
                .ok_or_else(|| invalid("this config has no routing rules"))?;
            serde_json::to_value(routed.rule_hits())
        }
        ControlRequest::ClearRuleHits => {
            let routed = dispatcher
                .routed_outbound()
                .ok_or_else(|| invalid("this config has no routing rules"))?;
            routed.clear_rule_hits();
            serde_json::to_value(routed.rule_hits())
        }
        ControlRequest::TestRoute {
            host,
            port,
            network,
            address,
            process,
            url,
            user_agent,
            source,
            source_port,
        } => {
            let routed = dispatcher
                .routed_outbound()
                .ok_or_else(|| invalid("this config has no routing rules"))?;
            let ip = |text: Option<String>, message: &'static str| {
                text.filter(|text| !text.trim().is_empty())
                    .map(|text| text.trim().parse::<IpAddr>().map_err(|_| invalid(message)))
                    .transpose()
            };
            let host = host.trim().trim_end_matches('.');
            if host.is_empty() || host.len() > 253 {
                return Err(invalid("test_route needs a host name or an IP address"));
            }
            let network = match network.as_deref() {
                None | Some("tcp") => RouteNetwork::Tcp,
                Some("udp") => RouteNetwork::Udp,
                Some(_) => return Err(invalid("network must be tcp or udp")),
            };
            let mut query = match host.trim_matches(['[', ']']).parse::<IpAddr>() {
                Ok(address) => RouteQuery::ip(address),
                Err(_) => RouteQuery::domain(host.to_string()),
            }
            .with_port(port)
            .with_network(network)
            .with_source(ip(source, "source is not an IP address")?, None)
            .with_source_port(source_port);
            query.process = process.filter(|name| !name.trim().is_empty());
            query.url = url.filter(|url| !url.is_empty());
            query.user_agent = user_agent.filter(|agent| !agent.is_empty());
            let test = routed.test_route(&query, ip(address, "address is not an IP address")?);
            Ok(json!({ "mode": dispatcher.mode(), "test": test }))
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
        ControlRequest::SetNetwork {
            kind,
            ssid,
            bssid,
            router,
            addresses,
            radio,
        } => {
            let network = network_context(kind, ssid, bssid, router, addresses, radio)?;
            let changed = dispatcher
                .routed_outbound()
                .is_some_and(|routed| routed.set_network(network));
            Ok(json!({ "changed": changed }))
        }
        ControlRequest::Devices => {
            let devices = dispatcher
                .routed_outbound()
                .map(|routed| routed.devices())
                .unwrap_or_default()
                .into_iter()
                .map(|(address, name)| (address.to_string(), name))
                .collect::<BTreeMap<_, _>>();
            Ok(json!({ "devices": devices }))
        }
        ControlRequest::SetDevices { devices } => {
            let routed = dispatcher
                .routed_outbound()
                .ok_or_else(|| invalid("this config has no routing rules"))?;
            let devices =
                crate::routing::RoutedOutbound::parse_devices(&devices).map_err(invalid)?;
            Ok(json!({ "changed": routed.set_devices(devices) }))
        }
        ControlRequest::ResetNetwork { close_connections } => {
            let health_forgotten = dispatcher
                .routed_outbound()
                .map_or(0, |routed| routed.forget_health());
            let reset = dispatcher.reset_sessions();
            let closed = if close_connections {
                tracker.close_all()
            } else {
                0
            };
            Ok(json!({ "reset": reset, "closed": closed, "health_forgotten": health_forgotten }))
        }
        ControlRequest::RunScript { tag } => Ok(script(interceptor, ScriptControl::Run { tag })?),
        ControlRequest::MitmHosts => Ok(mitm_hosts(interceptor, false)),
        ControlRequest::ClearMitmHosts => Ok(mitm_hosts(interceptor, true)),
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
        // Answered by `capture_command` above.
        _ => return Err(invalid("control request is not a known command")),
    };
    answer
        .and_then(|answer| serde_json::to_vec(&answer))
        .map_err(|_| RuntimeError::new(RuntimeErrorCode::InternalError, "control answer failed"))
}

/// Where a capture command is answered.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CaptureHost {
    /// A running engine, capturing live.
    Engine,
    /// The capture viewer ([`handle_capture_viewer`]): saved sessions only.
    Viewer,
}

/// Answers the capture commands, which the engine and the capture viewer
/// share; any other request comes back as `Err` for the caller to answer.
fn capture_command(
    store: &capture::CaptureStore,
    request: ControlRequest,
    host: CaptureHost,
) -> Result<Result<Vec<u8>, RuntimeError>, ControlRequest> {
    let answer = match request {
        ControlRequest::Capture => json_value(store.status()),
        ControlRequest::SetCapture {
            enabled,
            max_total_bytes,
        } => {
            if enabled && host == CaptureHost::Viewer {
                Err(invalid("the capture viewer only opens saved sessions"))
            } else {
                store.set(enabled, max_total_bytes);
                json_value(store.status())
            }
        }
        ControlRequest::ClearCapture => {
            store.clear();
            json_value(store.status())
        }
        ControlRequest::CaptureConnection { id } => {
            Ok(json!({ "capture": store.connection_json(id) }))
        }
        ControlRequest::CaptureExchange {
            id,
            index,
            since_message,
        } => Ok(json!({
            "exchange": store.exchange_json(id, index, since_message),
        })),
        ControlRequest::CaptureH2Frames { id, since } => Ok(json!({
            "h2_frames": store.h2_frames_json(id, since),
        })),
        ControlRequest::ExportCapture {
            format,
            id,
            exchange,
            language,
            redact,
        } => {
            if exchange.is_some() && id.is_none() {
                return Ok(Err(invalid("exchange needs the connection id")));
            }
            let request = ExportRequest {
                format,
                selection: Selection { id, exchange },
                language,
                redact,
            };
            // The file goes out as written, without a JSON value in between.
            return Ok(Ok(capture::export_answer(store, &request)));
        }
        ControlRequest::SetCaptureStorage {
            dir,
            key_base64,
            retention_days,
        } => decode_key(&key_base64).and_then(|key| {
            store
                .set_storage(&dir, &key, retention_days)
                .map_err(storage_error)
        }),
        ControlRequest::SaveCapture { name, run } => {
            if host == CaptureHost::Viewer {
                Err(invalid("the capture viewer only opens saved sessions"))
            } else {
                store
                    .save_session(name.as_deref(), run)
                    .map_err(storage_error)
            }
        }
        ControlRequest::CaptureSessions => store.sessions().map_err(storage_error),
        ControlRequest::LoadCapture { session } => store
            .load_session(&session, host == CaptureHost::Viewer)
            .map_err(storage_error)
            .and_then(json_value),
        ControlRequest::DeleteCapture { session } => {
            store.delete_session(&session).map_err(storage_error)
        }
        ControlRequest::CopyCapture {
            session,
            key_base64,
            name,
        } => {
            if session.is_none() && host == CaptureHost::Viewer {
                return Ok(Err(invalid("the capture viewer only opens saved sessions")));
            }
            return Ok(decode_key(&key_base64).and_then(|key| {
                store
                    .copy_session(session.as_deref(), &key, name.as_deref())
                    .map_err(storage_error)
            }));
        }
        ControlRequest::ImportCapture {
            session,
            data_base64,
        } => {
            if host == CaptureHost::Engine {
                Err(invalid("import_capture is answered by the capture viewer"))
            } else {
                use base64::Engine as _;
                base64::engine::general_purpose::STANDARD
                    .decode(data_base64.trim())
                    .map_err(|_| invalid("data_base64 is not base64"))
                    .and_then(|file| store.import_session(&session, &file).map_err(storage_error))
            }
        }
        ControlRequest::CaptureRequests {
            since_seq,
            since_rev,
            limit,
            filter,
        } => match Filter::parse(&filter) {
            Ok(filter) => Ok(store.requests_json(since_seq, since_rev, limit, &filter)),
            Err(error) => Ok(json!({
                "error": { "code": "invalid_filter", "at": error.at },
            })),
        },
        other => return Err(other),
    };
    Ok(answer.and_then(|answer| {
        serde_json::to_vec(&answer).map_err(|_| {
            RuntimeError::new(RuntimeErrorCode::InternalError, "control answer failed")
        })
    }))
}

/// Largest request the capture viewer accepts: `import_capture` with a
/// whole session file in base64.
pub const MAX_VIEWER_REQUEST_LEN: usize = 96 * 1024 * 1024;

/// Answers one request against `store` with no engine running: the capture
/// viewer a client uses to open saved sessions while its tunnel is off
/// ([`crate::capture_viewer`]). It takes the capture commands except
/// turning capture on and `save_capture`, plus `import_capture`, and
/// `connections` and `traffic` from what the store holds
/// ([`capture::CaptureStore::connections_json`]); anything else is refused.
pub fn handle_capture_viewer(
    store: &capture::CaptureStore,
    request: &[u8],
) -> Result<Vec<u8>, RuntimeError> {
    if request.is_empty() || request.len() > MAX_VIEWER_REQUEST_LEN {
        return Err(invalid("control request size is out of range"));
    }
    let request: ControlRequest = serde_json::from_slice(request)
        .map_err(|_| invalid("control request is not a known command"))?;
    let answer = match capture_command(store, request, CaptureHost::Viewer) {
        Ok(answer) => return answer,
        Err(ControlRequest::Connections) => store.connections_json(),
        Err(ControlRequest::Traffic) => store.connections_json()["traffic"].clone(),
        Err(_) => return Err(invalid("the capture viewer only answers capture commands")),
    };
    serde_json::to_vec(&answer)
        .map_err(|_| RuntimeError::new(RuntimeErrorCode::InternalError, "control answer failed"))
}

fn json_value(value: impl Serialize) -> Result<serde_json::Value, RuntimeError> {
    serde_json::to_value(value)
        .map_err(|_| RuntimeError::new(RuntimeErrorCode::InternalError, "control answer failed"))
}

/// A 32-byte session key in base64.
fn decode_key(key_base64: &str) -> Result<Vec<u8>, RuntimeError> {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD
        .decode(key_base64.trim())
        .map_err(|_| storage_error(capture::storage::StorageError::InvalidKey))
}

/// Answers a request to a whole-device WireGuard tunnel, which has no flows
/// to control. `reset_network` moves the running tunnel to a new UDP socket
/// ([`crate::wireguard::PathControl::reset`]): `reset` is 1 when a tunnel
/// runs, `closed` and `health_forgotten` are 0. `set_network` is checked and
/// changes nothing (`"changed": false`). Every other command is refused.
#[cfg(feature = "wireguard")]
pub(crate) fn handle_wireguard(
    paths: &crate::wireguard::PathControl,
    request: &[u8],
) -> Result<Vec<u8>, RuntimeError> {
    if request.is_empty() || request.len() > MAX_REQUEST_LEN {
        return Err(invalid("control request size is out of range"));
    }
    let request: ControlRequest = serde_json::from_slice(request)
        .map_err(|_| invalid("control request is not a known command"))?;
    let answer = match request {
        ControlRequest::ResetNetwork { .. } => {
            json!({ "reset": paths.reset(), "closed": 0, "health_forgotten": 0 })
        }
        ControlRequest::SetNetwork {
            kind,
            ssid,
            bssid,
            router,
            addresses,
            radio,
        } => {
            network_context(kind, ssid, bssid, router, addresses, radio)?;
            json!({ "changed": false })
        }
        _ => return Err(unavailable()),
    };
    serde_json::to_vec(&answer)
        .map_err(|_| RuntimeError::new(RuntimeErrorCode::InternalError, "control answer failed"))
}

/// The answer for runtimes without flows to control, such as a WireGuard
/// tunnel.
#[cfg(feature = "wireguard")]
fn unavailable() -> RuntimeError {
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

/// What HTTPS decryption did per host; `enabled: false` with no hosts when
/// this engine decrypts nothing.
fn mitm_hosts(interceptor: Option<&dyn FlowInterceptor>, clear: bool) -> serde_json::Value {
    interceptor
        .and_then(|interceptor| interceptor.mitm_hosts(clear))
        .unwrap_or_else(|| json!({ "enabled": false, "hosts": [] }))
}

fn storage_error(error: capture::storage::StorageError) -> RuntimeError {
    invalid(error.message())
}

fn default_true() -> bool {
    true
}

fn default_test_port() -> u16 {
    443
}

fn invalid(message: &'static str) -> RuntimeError {
    RuntimeError::new(RuntimeErrorCode::InvalidArgument, message)
}
