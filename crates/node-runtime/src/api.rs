//! Local management API: HTTP/1.1 with JSON bodies, one request per
//! connection, every request authorized by `Authorization: Bearer <token>`.
//!
//! | Method and path | Body | Answer |
//! | --- | --- | --- |
//! | `GET /v1/status` | | `{"version", "features", "types", "outbounds", "inbounds"}` |
//! | `GET /v1/inbounds` | | `{"inbounds": [InboundInfo]}` |
//! | `POST /v1/inbounds` | inbound config | `{"tag", "listen"}` (201) |
//! | `DELETE /v1/inbounds/{tag}` | | `{}` |
//! | `POST /v1/inbounds/{tag}/users` | `{"users": [User]}` | `{"users": n}` |
//! | `POST /v1/inbounds/{tag}/users/remove` | `{"names": [..]}` | `{"removed": n}` |
//! | `GET /v1/inbounds/{tag}/users` | | `{"names": [..]}` |
//! | `GET /v1/inbounds/{tag}/traffic[?reset=true]` | | `{"traffic": [UserTraffic], "inbound": InboundTraffic}` |
//! | `GET /v1/inbounds/{tag}/online` | | `{"online": [OnlineUser]}` |
//! | `GET /v1/inbounds/{tag}/destinations[?reset=true]` | | `{"destinations": [DestinationTraffic]}` |
//! | `GET /v1/inbounds/{tag}/targets` | | `{"targets": [TargetHealth]}` |
//! | `GET /v1/egress` | | `EgressStatus` |
//! | `PUT /v1/egress` | `EgressConfig` | `EgressStatus` |
//! | `GET /v1/network` | | `NetworkStatus` |
//! | `PUT /v1/network` | `NetworkPlan` | `NetworkStatus` |
//! | `GET /v1/rules` | | `RulesConfig` |
//! | `PUT /v1/rules` | `RulesConfig` | `RulesConfig` |
//! | `GET /v1/rules/counters[?reset=true]` | | `{"blocked_cidrs": n}` |
//! | `GET /v1/qos` | | `QosStatus` |
//! | `PUT /v1/qos` | `QosConfig` | `QosStatus` |
//!
//! `PUT /v1/qos` replaces the traffic priorities and per-user class caps
//! ([`engine_inbound::qos`]); `{}` turns them off. An invalid entry refuses
//! the whole body with 400. The status answers the classes' rule counts and
//! the node scheduler's capacity and current rates per priority.
//!
//! `PUT /v1/rules` replaces the block rules: `block_domains`,
//! `block_protocols` and `block_cidrs` (address ranges `a.b.c.d/n`, `x::/n`
//! or a bare address, at most 100 000). An invalid entry refuses the whole
//! body with 400. The ranges apply to every direct dial of the process once
//! a target is resolved, so also to relays served on this node and to
//! port-forward targets. `GET /v1/rules/counters` answers how many TCP
//! connections and UDP datagrams the ranges refused since the last
//! `reset=true` call.
//!
//! `PUT /v1/egress` replaces the domain egress routes and relays (the panel's
//! `egress` member, see [`crate::egress`]); `{}` removes them all. An
//! invalid entry refuses the whole body with 400; a relay port that cannot
//! be bound answers 500 after the rest was applied. Neither answer carries a
//! relay key.
//!
//! `PUT /v1/network` replaces the device's network plan (egresses, ingresses,
//! paths; see [`crate::network`]); `{}` removes it. It coexists with
//! `/v1/egress`: domain egress routes still apply on top of an ingress's
//! path. An invalid entry refuses the whole body with 400. `GET` answers the
//! plan's generation, each egress's probe state and each ingress's active
//! egress and path.
//!
//! `traffic` lists the bytes per user, `inbound` the bytes of the whole
//! inbound (users or not, so also a `forward` inbound's), both since the
//! last `reset=true` call, which starts the next interval for both.
//!
//! `targets` answers a `forward` inbound's targets in their configured order:
//! `address`, `port`, `state` (`unknown`, `healthy`, `unhealthy` or
//! `circuit_open`), `consecutive_failures`, `circuit_open_until_unix_ms`,
//! and the last active check's `rtt_us` (0 when it failed) and
//! `checked_at_unix_ms` (0 before the first). Other inbounds answer an empty
//! list.
//!
//! `features` names what this kernel takes beyond the base API, so an agent
//! can tell before sending it: `user_limits` (the user members below),
//! `block_rules` (`/v1/rules`), `qos` (`/v1/qos`), `destinations`
//! (`/v1/inbounds/{tag}/destinations`), `block_cidrs` (`block_cidrs` in
//! `/v1/rules` and `/v1/rules/counters`), `accept_proxy_protocol` (the
//! inbound key of that name), `sing_mux` (inbounds serve clients that
//! multiplex with sing-mux in smux or yamux), `sing_mux_h2mux` (and in
//! h2mux, which those clients run when no protocol is set, and with
//! padding), `fallbacks` (the `fallbacks` list of VLESS, Trojan and AnyTLS
//! inbounds), `xhttp_h3` (an XHTTP inbound with `h3` in its TLS `alpn` also
//! serves HTTP/3 on the UDP port), `shadow_tls` (a `shadowsocks` inbound
//! takes a `shadow_tls` object and is then served behind ShadowTLS v3),
//! `shadowsocks_plugins` (a `shadowsocks` inbound takes `obfs` for
//! simple-obfs clients, and `transport` `ws` with or without `tls` for
//! v2ray-plugin clients).
//!
//! A user may carry `speed_limit` (Mbit/s for each direction, shared by
//! all of its connections) and `device_limit` (most client IPs online at
//! once; a connection from one more IP is refused and counted in the
//! inbound's `device_limited`). Both default to 0, no limit.
//!
//! Adding a user that exists replaces it (and closes its connections when the
//! credentials changed). Errors answer `{"error": "..."}` with 400, 401, 404,
//! 409, 413, 500 or 503.
//!
//! Limits: a request is read in two steps. The head (at most 16 KiB, within
//! 5 s) is checked first: the bearer token (401), the endpoint (404) and the
//! endpoint's body limit (413) are all decided before a single body byte is
//! read, so an unauthorized or oversized request costs no body memory. Bodies
//! are limited per endpoint: 4 KiB for requests without one (`GET`,
//! `DELETE`), 4 MiB for `POST /v1/inbounds/{tag}/users/remove` and
//! `PUT /v1/network`, 32 MiB for the rest. All bodies in flight together
//! share a 64 MiB budget, and at most 64 connections are served at once;
//! past either limit a request answers 503 at once instead of waiting.

use std::io;
use std::sync::Arc;
use std::time::Duration;

use engine_inbound::User;
use engine_outbound::accept::{self, AcceptBackoff};
use serde::Deserialize;
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use crate::{EgressConfig, InboundConfig, NetworkPlan, Node, NodeError, QosConfig, RulesConfig};

const MAX_HEAD_BYTES: usize = 16 * 1024;
/// Body limit of a request that takes none (`GET`, `DELETE`): room for a
/// client that sends `{}` anyway.
const BODYLESS_LIMIT: usize = 4 * 1024;
/// Body limit of the endpoints with small bodies (a list of user names, the
/// network plan with its 256 items).
const SMALL_BODY_LIMIT: usize = 4 * 1024 * 1024;
/// Body limit of the endpoints that take large lists: users, block rules
/// (100 000 ranges), traffic priorities, egress routes, fingerprints.
const LARGE_BODY_LIMIT: usize = 32 * 1024 * 1024;
/// Time for the request head: an unauthenticated client holds a connection
/// slot at most this long.
const HEAD_TIMEOUT: Duration = Duration::from_secs(5);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(15);
/// How long, and how many bytes, a refused request's unread body is drained
/// after the answer, so the client reads the answer instead of a reset.
const DRAIN_TIMEOUT: Duration = Duration::from_secs(1);
const DRAIN_BYTES: usize = 256 * 1024;
const BUSY_RESPONSE: &[u8] = b"HTTP/1.1 503 Service Unavailable\r\nContent-Type: application/json\r\nContent-Length: 34\r\nConnection: close\r\n\r\n{\"error\":\"management api is busy\"}";

/// Resource limits of the management API.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ApiLimits {
    /// Connections served at once; one more answers 503 and is closed.
    pub max_connections: usize,
    /// Bytes of request bodies held at once over all connections; a request
    /// whose body does not fit answers 503 before its body is read.
    pub body_budget: usize,
}

impl Default for ApiLimits {
    fn default() -> Self {
        Self {
            max_connections: 64,
            body_budget: 2 * LARGE_BODY_LIMIT,
        }
    }
}

/// Serves the management API until the listener becomes unusable or the
/// task is dropped.
pub async fn serve(listener: TcpListener, node: Arc<Node>, token: String) -> io::Result<()> {
    serve_with_limits(listener, node, token, ApiLimits::default()).await
}

/// [`serve`] with explicit resource limits.
pub async fn serve_with_limits(
    listener: TcpListener,
    node: Arc<Node>,
    token: String,
    limits: ApiLimits,
) -> io::Result<()> {
    if token.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "management token must not be empty",
        ));
    }
    if limits.max_connections == 0 || limits.body_budget < BODYLESS_LIMIT {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "management api limits are too small",
        ));
    }
    let token: Arc<str> = token.into();
    let connections = Arc::new(Semaphore::new(limits.max_connections));
    // Semaphore permits are u32; a budget past 4 GiB is clamped.
    let budget = Arc::new(Semaphore::new(limits.body_budget.min(u32::MAX as usize)));
    let mut backoff = AcceptBackoff::default();
    loop {
        // A reset client or a moment without file descriptors must not stop
        // the management API (see [`engine_outbound::accept`]).
        let (stream, _) = accept::accept(|| listener.accept(), &mut backoff, None).await?;
        let Ok(slot) = connections.clone().try_acquire_owned() else {
            answer_busy(stream);
            continue;
        };
        let node = node.clone();
        let token = token.clone();
        let budget = budget.clone();
        tokio::spawn(async move {
            // Held until the connection is done, also when the task panics
            // or is cancelled.
            let _slot = slot;
            let _ =
                tokio::time::timeout(REQUEST_TIMEOUT, connection(stream, &node, &token, &budget))
                    .await;
        });
    }
}

/// Answers 503 on a connection past the limit and closes it, without a
/// task and without waiting: the answer is written straight to the
/// non-blocking socket, whose fresh send buffer holds it.
fn answer_busy(stream: TcpStream) {
    use std::io::Write;
    if let Ok(mut stream) = stream.into_std() {
        let _ = stream.write_all(BUSY_RESPONSE);
        let _ = stream.shutdown(std::net::Shutdown::Write);
    }
}

/// The parsed request head.
struct Head {
    method: String,
    path: String,
    query: String,
    authorization: Option<String>,
    content_length: usize,
    /// Bytes read past the head: the start of the body.
    rest: Vec<u8>,
}

/// What a request asks for, decided from the head alone.
#[derive(Debug, PartialEq, Eq)]
enum Endpoint {
    Status,
    ListInbounds,
    AddInbound,
    RemoveInbound(String),
    ListUsers(String),
    AddUsers(String),
    RemoveUsers(String),
    Traffic(String),
    Destinations(String),
    Targets(String),
    Online(String),
    GetEgress,
    PutEgress,
    GetNetwork,
    PutNetwork,
    GetRules,
    RuleCounters,
    PutRules,
    GetQos,
    PutQos,
    GetTlsFingerprints,
    PutTlsFingerprints,
}

impl Endpoint {
    fn parse(method: &str, path: &str) -> Option<Self> {
        let segments: Vec<&str> = path
            .trim_matches('/')
            .split('/')
            .filter(|segment| !segment.is_empty())
            .collect();
        let tag = |tag: &&str| (*tag).to_owned();
        Some(match (method, segments.as_slice()) {
            ("GET", ["v1", "status"]) => Self::Status,
            ("GET", ["v1", "inbounds"]) => Self::ListInbounds,
            ("POST", ["v1", "inbounds"]) => Self::AddInbound,
            ("DELETE", ["v1", "inbounds", t]) => Self::RemoveInbound(tag(t)),
            ("GET", ["v1", "inbounds", t, "users"]) => Self::ListUsers(tag(t)),
            ("POST", ["v1", "inbounds", t, "users"]) => Self::AddUsers(tag(t)),
            ("POST", ["v1", "inbounds", t, "users", "remove"]) => Self::RemoveUsers(tag(t)),
            ("GET", ["v1", "inbounds", t, "traffic"]) => Self::Traffic(tag(t)),
            ("GET", ["v1", "inbounds", t, "destinations"]) => Self::Destinations(tag(t)),
            ("GET", ["v1", "inbounds", t, "targets"]) => Self::Targets(tag(t)),
            ("GET", ["v1", "inbounds", t, "online"]) => Self::Online(tag(t)),
            ("GET", ["v1", "egress"]) => Self::GetEgress,
            ("PUT", ["v1", "egress"]) => Self::PutEgress,
            ("GET", ["v1", "network"]) => Self::GetNetwork,
            ("PUT", ["v1", "network"]) => Self::PutNetwork,
            ("GET", ["v1", "rules"]) => Self::GetRules,
            ("GET", ["v1", "rules", "counters"]) => Self::RuleCounters,
            ("PUT", ["v1", "rules"]) => Self::PutRules,
            ("GET", ["v1", "qos"]) => Self::GetQos,
            ("PUT", ["v1", "qos"]) => Self::PutQos,
            ("GET", ["v1", "tls-fingerprints"]) => Self::GetTlsFingerprints,
            ("PUT", ["v1", "tls-fingerprints"]) => Self::PutTlsFingerprints,
            _ => return None,
        })
    }

    /// The largest body this endpoint reads.
    fn body_limit(&self) -> usize {
        match self {
            Self::AddInbound
            | Self::AddUsers(_)
            | Self::PutEgress
            | Self::PutRules
            | Self::PutQos
            | Self::PutTlsFingerprints => LARGE_BODY_LIMIT,
            Self::RemoveUsers(_) | Self::PutNetwork => SMALL_BODY_LIMIT,
            Self::Status
            | Self::ListInbounds
            | Self::RemoveInbound(_)
            | Self::ListUsers(_)
            | Self::Traffic(_)
            | Self::Destinations(_)
            | Self::Targets(_)
            | Self::Online(_)
            | Self::GetEgress
            | Self::GetNetwork
            | Self::GetRules
            | Self::RuleCounters
            | Self::GetQos
            | Self::GetTlsFingerprints => BODYLESS_LIMIT,
        }
    }
}

struct Response {
    status: u16,
    body: Value,
}

impl Response {
    fn ok(body: Value) -> Self {
        Self { status: 200, body }
    }

    fn error(status: u16, message: impl Into<String>) -> Self {
        Self {
            status,
            body: json!({ "error": message.into() }),
        }
    }
}

impl From<NodeError> for Response {
    fn from(error: NodeError) -> Self {
        let status = match &error {
            NodeError::NotFound => 404,
            NodeError::Exists => 409,
            NodeError::Invalid(_)
            | NodeError::Egress(_)
            | NodeError::Network(_)
            | NodeError::Rules(_)
            | NodeError::Qos(_)
            | NodeError::TlsFingerprints(_) => 400,
            NodeError::Io(_) => 500,
        };
        Response::error(status, error.to_string())
    }
}

async fn connection(
    mut stream: TcpStream,
    node: &Node,
    token: &str,
    budget: &Arc<Semaphore>,
) -> io::Result<()> {
    let head = match tokio::time::timeout(HEAD_TIMEOUT, read_head(&mut stream)).await {
        Err(_) => return Ok(()),
        Ok(Ok(head)) => head,
        Ok(Err(error)) if error.kind() == io::ErrorKind::InvalidData => {
            return refuse(&mut stream, Response::error(400, error.to_string())).await;
        }
        Ok(Err(error)) => return Err(error),
    };
    // Everything below is decided before a body byte is read.
    if !authorized(head.authorization.as_deref(), token) {
        return refuse(&mut stream, Response::error(401, "unauthorized")).await;
    }
    let Some(endpoint) = Endpoint::parse(&head.method, &head.path) else {
        return refuse(&mut stream, Response::error(404, "no such endpoint")).await;
    };
    if head.content_length > endpoint.body_limit() {
        return refuse(&mut stream, Response::error(413, "request body too large")).await;
    }
    if head.rest.len() > head.content_length {
        return refuse(
            &mut stream,
            Response::error(400, "request body longer than content-length"),
        )
        .await;
    }
    let Some(_reservation) = reserve(budget, head.content_length) else {
        return refuse(&mut stream, Response::error(503, "management api is busy")).await;
    };
    let mut body = head.rest;
    let already = body.len();
    body.resize(head.content_length, 0);
    stream.read_exact(&mut body[already..]).await?;
    let response = route(node, endpoint, &head.query, &body).await;
    write_response(&mut stream, response).await
}

/// Reserves `bytes` of the body budget, or `None` when they do not fit now.
fn reserve(budget: &Arc<Semaphore>, bytes: usize) -> Option<Option<OwnedSemaphorePermit>> {
    if bytes == 0 {
        return Some(None);
    }
    let bytes = u32::try_from(bytes).ok()?;
    budget.clone().try_acquire_many_owned(bytes).ok().map(Some)
}

/// Answers a request whose body is not read, then drains a little of what
/// the client still sends so that it sees the answer rather than a reset.
async fn refuse(stream: &mut TcpStream, response: Response) -> io::Result<()> {
    write_response(stream, response).await?;
    let _ = tokio::time::timeout(DRAIN_TIMEOUT, async {
        let mut chunk = [0u8; 4096];
        let mut drained = 0;
        while drained < DRAIN_BYTES {
            match stream.read(&mut chunk).await {
                Ok(0) | Err(_) => break,
                Ok(n) => drained += n,
            }
        }
    })
    .await;
    Ok(())
}

async fn read_head(stream: &mut TcpStream) -> io::Result<Head> {
    let mut buffer = Vec::with_capacity(1024);
    let head_end = loop {
        if let Some(end) = find_head_end(&buffer) {
            break end;
        }
        if buffer.len() > MAX_HEAD_BYTES {
            return Err(invalid("request head too large"));
        }
        let mut chunk = [0u8; 4096];
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        buffer.extend_from_slice(&chunk[..n]);
    };
    parse_head(buffer, head_end)
}

fn parse_head(mut buffer: Vec<u8>, head_end: usize) -> io::Result<Head> {
    if head_end > MAX_HEAD_BYTES {
        return Err(invalid("request head too large"));
    }
    let head = std::str::from_utf8(&buffer[..head_end]).map_err(|_| invalid("bad request head"))?;
    let mut lines = head.split("\r\n");
    let mut request_line = lines.next().unwrap_or_default().split(' ');
    let (Some(method), Some(target), Some(_version)) = (
        request_line.next(),
        request_line.next(),
        request_line.next(),
    ) else {
        return Err(invalid("bad request line"));
    };
    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    let mut content_length: Option<usize> = None;
    let mut authorization = None;
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let value = value.trim();
        if name.eq_ignore_ascii_case("content-length") {
            let length = value.parse().map_err(|_| invalid("bad content-length"))?;
            if content_length.is_some_and(|known| known != length) {
                return Err(invalid("conflicting content-length"));
            }
            content_length = Some(length);
        } else if name.eq_ignore_ascii_case("authorization") {
            if authorization.is_some() {
                return Err(invalid("more than one authorization header"));
            }
            authorization = Some(value.to_owned());
        } else if name.eq_ignore_ascii_case("transfer-encoding") {
            return Err(invalid("chunked bodies are not supported"));
        }
    }
    let (method, path, query) = (method.to_owned(), path.to_owned(), query.to_owned());
    let rest = buffer.split_off(head_end + 4);
    Ok(Head {
        method,
        path,
        query,
        authorization,
        content_length: content_length.unwrap_or(0),
        rest,
    })
}

fn find_head_end(buffer: &[u8]) -> Option<usize> {
    buffer.windows(4).position(|window| window == b"\r\n\r\n")
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn authorized(authorization: Option<&str>, token: &str) -> bool {
    let Some(presented) = authorization.and_then(|value| value.strip_prefix("Bearer ")) else {
        return false;
    };
    let (a, b) = (presented.as_bytes(), token.as_bytes());
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AddUsers {
    users: Vec<User>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RemoveUsers {
    names: Vec<String>,
}

fn parse<T: for<'de> Deserialize<'de>>(body: &[u8]) -> Result<T, Response> {
    serde_json::from_slice(body).map_err(|error| {
        // Only an authorized caller sees this, and at most its own input.
        Response::error(400, format!("invalid request body: {error}"))
    })
}

async fn route(node: &Node, endpoint: Endpoint, query: &str, body: &[u8]) -> Response {
    let reset = wants_reset(query);
    let result = match endpoint {
        Endpoint::Status => Ok(Response::ok(json!({
            "version": env!("CARGO_PKG_VERSION"),
            "features": crate::FEATURES,
            "types": node.types(),
            "outbounds": node.outbounds(),
            "inbounds": node.list().len(),
        }))),
        Endpoint::ListInbounds => Ok(Response::ok(json!({ "inbounds": node.list() }))),
        Endpoint::GetEgress => Ok(Response::ok(json!(node.egress_state().await))),
        Endpoint::PutEgress => match parse::<EgressConfig>(body) {
            Ok(config) => node
                .apply_egress(&config)
                .await
                .map(|status| Response::ok(json!(status))),
            Err(response) => return response,
        },
        Endpoint::GetNetwork => Ok(Response::ok(json!(node.network_state()))),
        Endpoint::PutNetwork => match parse::<NetworkPlan>(body) {
            Ok(plan) => node
                .apply_network(&plan)
                .await
                .map(|status| Response::ok(json!(status))),
            Err(response) => return response,
        },
        Endpoint::GetRules => Ok(Response::ok(json!(node.rules()))),
        Endpoint::RuleCounters => Ok(Response::ok(
            json!({ "blocked_cidrs": node.blocked_cidrs(reset) }),
        )),
        Endpoint::PutRules => match parse::<RulesConfig>(body) {
            Ok(config) => node
                .apply_rules(&config)
                .map(|rules| Response::ok(json!(rules))),
            Err(response) => return response,
        },
        Endpoint::GetQos => Ok(Response::ok(json!(node.qos()))),
        Endpoint::PutQos => match parse::<QosConfig>(body) {
            Ok(config) => node
                .apply_qos(&config)
                .map(|status| Response::ok(json!(status))),
            Err(response) => return response,
        },
        Endpoint::GetTlsFingerprints => Ok(Response::ok(json!(crate::tls_fingerprints()))),
        Endpoint::PutTlsFingerprints => match parse::<serde_json::Value>(body) {
            Ok(bundle) => {
                crate::apply_tls_fingerprints(&bundle).map(|status| Response::ok(json!(status)))
            }
            Err(response) => return response,
        },
        Endpoint::AddInbound => match parse::<InboundConfig>(body) {
            Ok(config) => {
                let tag = config.tag.clone();
                node.add_inbound(config).await.map(|listen| Response {
                    status: 201,
                    body: json!({ "tag": tag, "listen": listen }),
                })
            }
            Err(response) => return response,
        },
        Endpoint::RemoveInbound(tag) => node.remove_inbound(&tag).map(|()| Response::ok(json!({}))),
        Endpoint::ListUsers(tag) => node
            .users(&tag)
            .map(|users| Response::ok(json!({ "names": users.names() }))),
        Endpoint::AddUsers(tag) => match parse::<AddUsers>(body) {
            Ok(add) => node.users(&tag).and_then(|users| {
                let count = add.users.len();
                users
                    .add_all(add.users)
                    .map(|()| Response::ok(json!({ "users": count })))
                    .map_err(NodeError::Invalid)
            }),
            Err(response) => return response,
        },
        Endpoint::RemoveUsers(tag) => match parse::<RemoveUsers>(body) {
            Ok(remove) => node.users(&tag).map(|users| {
                let removed = remove
                    .names
                    .iter()
                    .filter(|name| users.remove(name))
                    .count();
                Response::ok(json!({ "removed": removed }))
            }),
            Err(response) => return response,
        },
        Endpoint::Traffic(tag) => node.users(&tag).and_then(|users| {
            let traffic = users.traffic(reset);
            let inbound = node.inbound_traffic(&tag, reset)?;
            Ok(Response::ok(
                json!({ "traffic": traffic, "inbound": inbound }),
            ))
        }),
        Endpoint::Destinations(tag) => node
            .users(&tag)
            .map(|users| Response::ok(json!({ "destinations": users.destinations(reset) }))),
        Endpoint::Targets(tag) => node
            .target_health(&tag)
            .map(|targets| Response::ok(json!({ "targets": targets }))),
        Endpoint::Online(tag) => node
            .users(&tag)
            .map(|users| Response::ok(json!({ "online": users.online() }))),
    };
    result.unwrap_or_else(Response::from)
}

fn wants_reset(query: &str) -> bool {
    query
        .split('&')
        .any(|pair| pair == "reset=true" || pair == "reset=1")
}

async fn write_response(stream: &mut TcpStream, response: Response) -> io::Result<()> {
    let body = response.body.to_string();
    let reason = match response.status {
        200 => "OK",
        201 => "Created",
        400 => "Bad Request",
        401 => "Unauthorized",
        404 => "Not Found",
        409 => "Conflict",
        413 => "Payload Too Large",
        503 => "Service Unavailable",
        _ => "Internal Server Error",
    };
    let head = format!(
        "HTTP/1.1 {} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        response.status,
        body.len()
    );
    stream.write_all(head.as_bytes()).await?;
    stream.write_all(body.as_bytes()).await?;
    stream.shutdown().await
}
