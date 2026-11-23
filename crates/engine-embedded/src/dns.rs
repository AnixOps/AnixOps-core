//! DNS forwarding for the tunnel.
//!
//! UDP/53 queries captured from the TUN interface are answered from the
//! configured hosts or re-sent to an upstream over TCP, UDP, TLS, HTTPS or
//! QUIC through an outbound, or to the device's own resolvers;
//! [`crate::dns_policy`] picks the upstreams for each name and
//! [`crate::dns_client`] races them.

use std::future::Future;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use config_core::routing::RuleProtocol;
use engine_outbound::{BoxStream, TargetAddr, TcpOutbound, UdpFlow};
use futures::stream::{FuturesUnordered, StreamExt};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::Instant;

use crate::dns_cache::{DnsPools, PoolKey, UpstreamPool};

/// Smallest valid DNS message: the fixed header.
const DNS_HEADER_LEN: usize = 12;
/// Upper bound for a query taken from the tunnel (EDNS0 payloads stay below this).
pub const MAX_QUERY_LEN: usize = 4096;

/// Why a forwarded query or flow failed: the stage and the error kind, never
/// an address or payload.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum OutboundFailure {
    /// The query taken from the tunnel is not a usable DNS message.
    QueryInvalid = 1,
    /// Dialing the proxy server timed out.
    ConnectTimeout,
    ConnectRefused,
    ConnectUnreachable,
    ConnectFailed,
    /// The proxy accepted the connection but no reply arrived in time.
    ReplyTimeout,
    /// The proxy closed or reset the connection before replying.
    ReplyClosed,
    /// The reply failed authentication or did not parse.
    ReplyRejected,
    ReplyFailed,
}

impl OutboundFailure {
    const ALL: [Self; 9] = [
        Self::QueryInvalid,
        Self::ConnectTimeout,
        Self::ConnectRefused,
        Self::ConnectUnreachable,
        Self::ConnectFailed,
        Self::ReplyTimeout,
        Self::ReplyClosed,
        Self::ReplyRejected,
        Self::ReplyFailed,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::QueryInvalid => "query_invalid",
            Self::ConnectTimeout => "connect_timeout",
            Self::ConnectRefused => "connect_refused",
            Self::ConnectUnreachable => "connect_unreachable",
            Self::ConnectFailed => "connect_failed",
            Self::ReplyTimeout => "reply_timeout",
            Self::ReplyClosed => "reply_closed",
            Self::ReplyRejected => "reply_rejected",
            Self::ReplyFailed => "reply_failed",
        }
    }

    pub fn from_code(code: u8) -> Option<Self> {
        Self::ALL.into_iter().find(|failure| *failure as u8 == code)
    }

    /// Classifies an error from dialing the proxy server.
    pub fn connect(err: &io::Error) -> Self {
        match err.kind() {
            io::ErrorKind::TimedOut => Self::ConnectTimeout,
            io::ErrorKind::ConnectionRefused => Self::ConnectRefused,
            io::ErrorKind::NetworkUnreachable | io::ErrorKind::HostUnreachable => {
                Self::ConnectUnreachable
            }
            _ => Self::ConnectFailed,
        }
    }

    /// Classifies an error after the proxy connection was open.
    pub fn reply(err: &io::Error) -> Self {
        match err.kind() {
            io::ErrorKind::TimedOut => Self::ReplyTimeout,
            io::ErrorKind::UnexpectedEof
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::BrokenPipe => Self::ReplyClosed,
            io::ErrorKind::InvalidData => Self::ReplyRejected,
            _ => Self::ReplyFailed,
        }
    }
}

/// Where a query goes: DNS over TCP, over UDP, over TLS (RFC 7858), over
/// HTTPS (RFC 8484, HTTP/1.1 POST) or over QUIC (RFC 9250) through an
/// outbound, or the device's own resolvers. TCP, TLS and HTTPS connections
/// and QUIC connections are kept for later queries (see
/// [`crate::dns_cache::DnsPools`]).
#[derive(Clone)]
pub enum Upstream {
    Tcp(TargetAddr),
    /// Plain UDP, retried over TCP when the answer is truncated or the
    /// outbound does not relay UDP.
    Udp(TargetAddr),
    #[cfg(feature = "dns-tls")]
    Tls {
        target: TargetAddr,
        tls: transport_tls::TlsConnector,
    },
    #[cfg(feature = "dns-tls")]
    Https {
        target: TargetAddr,
        tls: transport_tls::TlsConnector,
        /// `Host` header value.
        host: String,
        path: String,
    },
    #[cfg(feature = "dns-quic")]
    Quic {
        target: TargetAddr,
        connector: Arc<transport_quic::QuicConnector>,
    },
    /// The device's resolvers: these addresses over UDP through the direct
    /// outbound, raced, or the system resolver (`getaddrinfo`, A and AAAA
    /// only) when there are none. Always direct.
    System(Arc<[SocketAddr]>),
}

/// Why an upstream URL was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UpstreamError {
    Invalid,
    /// `tls://` and `https://` need the `dns-tls` feature, `quic://` the
    /// `dns-quic` feature.
    Unsupported,
}

impl Upstream {
    /// Parses `1.1.1.1`, `1.1.1.1:53`, `tcp://host[:port]`,
    /// `udp://host[:port]`, `tls://host[:port]`, `https://host[:port][/path]`,
    /// `quic://host[:port]` or `system`. `server_name` overrides the TLS
    /// name, for servers given by IP address. `system` comes back without
    /// addresses; [`crate::dns_policy::DnsPolicy`] fills in the configured
    /// ones.
    pub fn parse(url: &str, server_name: Option<&str>) -> Result<Self, UpstreamError> {
        if url.eq_ignore_ascii_case("system") {
            return Ok(Self::System(Arc::from(Vec::new())));
        }
        let (scheme, rest) = url.split_once("://").unwrap_or(("tcp", url));
        let (authority, path) = match rest.find('/') {
            Some(slash) => (&rest[..slash], &rest[slash..]),
            None => (rest, ""),
        };
        let default_port = match scheme {
            "tcp" | "udp" => 53,
            "tls" | "quic" => 853,
            "https" => 443,
            _ => return Err(UpstreamError::Invalid),
        };
        if scheme != "https" && !path.is_empty() {
            return Err(UpstreamError::Invalid);
        }
        let (host, port) =
            split_host_port(authority, default_port).ok_or(UpstreamError::Invalid)?;
        let host = host.to_ascii_lowercase();
        let target = match host.parse::<std::net::IpAddr>() {
            Ok(ip) => TargetAddr::Ip(SocketAddr::new(ip, port)),
            Err(_) => TargetAddr::Domain(host.clone(), port),
        };
        match scheme {
            "tcp" => Ok(Self::Tcp(target)),
            "udp" => Ok(Self::Udp(target)),
            #[cfg(feature = "dns-quic")]
            "quic" => {
                let name = server_name.unwrap_or(&host).to_string();
                let connector = transport_quic::QuicConnector::new(
                    host.clone(),
                    port,
                    &transport_tls::TlsSettings {
                        server_name: name,
                        alpn: vec!["doq".to_string()],
                        insecure: false,
                        ..transport_tls::TlsSettings::default()
                    },
                    &["doq"],
                    transport_quic::Congestion::Cubic,
                )
                .and_then(transport_quic::QuicConnector::without_keep_alive)
                .map_err(|_| UpstreamError::Invalid)?;
                Ok(Self::Quic {
                    target,
                    connector: Arc::new(connector),
                })
            }
            #[cfg(not(feature = "dns-quic"))]
            "quic" => Err(UpstreamError::Unsupported),
            #[cfg(feature = "dns-tls")]
            _ => {
                let name = server_name.unwrap_or(&host).to_string();
                let alpn = if scheme == "https" { "http/1.1" } else { "dot" };
                let tls = transport_tls::TlsConnector::new(&transport_tls::TlsSettings {
                    server_name: name,
                    alpn: vec![alpn.to_string()],
                    insecure: false,
                    ..transport_tls::TlsSettings::default()
                })
                .map_err(|_| UpstreamError::Invalid)?;
                if scheme == "tls" {
                    return Ok(Self::Tls { target, tls });
                }
                let host = match port {
                    443 => bracketed(&host),
                    _ => format!("{}:{port}", bracketed(&host)),
                };
                let path = if path.is_empty() { "/dns-query" } else { path };
                if path
                    .bytes()
                    .any(|b| b.is_ascii_whitespace() || b.is_ascii_control())
                {
                    return Err(UpstreamError::Invalid);
                }
                Ok(Self::Https {
                    target,
                    tls,
                    host,
                    path: path.to_string(),
                })
            }
            #[cfg(not(feature = "dns-tls"))]
            _ => {
                let _ = server_name;
                Err(UpstreamError::Unsupported)
            }
        }
    }

    /// `tcp`, `udp`, `tls`, `https`, `quic` or `system`, for status.
    pub fn scheme(&self) -> &'static str {
        match self {
            Self::Tcp(_) => "tcp",
            Self::Udp(_) => "udp",
            #[cfg(feature = "dns-tls")]
            Self::Tls { .. } => "tls",
            #[cfg(feature = "dns-tls")]
            Self::Https { .. } => "https",
            #[cfg(feature = "dns-quic")]
            Self::Quic { .. } => "quic",
            Self::System(_) => "system",
        }
    }

    /// The server's address or name and port; `None` for `system`, which
    /// has several or none.
    pub fn target(&self) -> Option<&TargetAddr> {
        match self {
            Self::Tcp(target) | Self::Udp(target) => Some(target),
            #[cfg(feature = "dns-tls")]
            Self::Tls { target, .. } | Self::Https { target, .. } => Some(target),
            #[cfg(feature = "dns-quic")]
            Self::Quic { target, .. } => Some(target),
            Self::System(_) => None,
        }
    }

    /// What `PROTOCOL,DOH` and `PROTOCOL,DOQ` rules see a query to this
    /// server as: [`RuleProtocol::Doh`] for `https://`,
    /// [`RuleProtocol::Doq`] for `quic://`, `None` for the rest.
    // Without `dns-tls` and `dns-quic` only the catch-all arm is left.
    #[allow(clippy::match_single_binding)]
    pub fn rule_protocol(&self) -> Option<RuleProtocol> {
        match self {
            #[cfg(feature = "dns-tls")]
            Self::Https { .. } => Some(RuleProtocol::Doh),
            #[cfg(feature = "dns-quic")]
            Self::Quic { .. } => Some(RuleProtocol::Doq),
            _ => None,
        }
    }
}

/// `host` and `port` of `host`, `host:port`, `[v6]` or `[v6]:port`.
fn split_host_port(authority: &str, default_port: u16) -> Option<(String, u16)> {
    let (host, port) = if let Some(rest) = authority.strip_prefix('[') {
        let (host, after) = rest.split_once(']')?;
        host.parse::<std::net::Ipv6Addr>().ok()?;
        match after {
            "" => (host, None),
            _ => (host, Some(after.strip_prefix(':')?)),
        }
    } else if authority.matches(':').count() > 1 {
        // A bare IPv6 address without a port.
        authority.parse::<std::net::Ipv6Addr>().ok()?;
        (authority, None)
    } else {
        match authority.split_once(':') {
            Some((host, port)) => (host, Some(port)),
            None => (authority, None),
        }
    };
    if host.is_empty()
        || host.len() > 253
        || !host
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_' | b':'))
    {
        return None;
    }
    let port = match port {
        Some(port) => port.parse::<u16>().ok().filter(|port| *port != 0)?,
        None => default_port,
    };
    Some((host.to_string(), port))
}

#[cfg(feature = "dns-tls")]
fn bracketed(host: &str) -> String {
    if host.contains(':') {
        format!("[{host}]")
    } else {
        host.to_string()
    }
}

/// Sends one query to `upstream` through `outbound` (the direct outbound for
/// `system`) and returns the reply, whose id must match the query's. With
/// `pools`, connections kept there for `key` are reused (see
/// [`stream_exchange`] and [`crate::dns_quic`]) and new ones kept.
pub async fn exchange(
    upstream: &Upstream,
    outbound: &dyn TcpOutbound,
    query: &[u8],
    timeout: Duration,
    pools: Option<(&DnsPools, PoolKey)>,
) -> Result<Vec<u8>, OutboundFailure> {
    if query.len() < DNS_HEADER_LEN || query.len() > MAX_QUERY_LEN {
        return Err(OutboundFailure::QueryInvalid);
    }
    let deadline = Instant::now() + timeout;
    let tcp_pool = pools.map(|(pools, key)| (&pools.tcp, key));
    match upstream {
        Upstream::Udp(target) => udp_exchange(target, outbound, query, deadline, tcp_pool).await,
        #[cfg(feature = "dns-quic")]
        Upstream::Quic { target, connector } => {
            crate::dns_quic::exchange(
                connector,
                target,
                outbound,
                query,
                deadline,
                pools.map(|(pools, key)| (&pools.quic, key)),
            )
            .await
        }
        Upstream::System(servers) => system_exchange(servers, outbound, query, deadline).await,
        _ => stream_exchange(upstream, outbound, query, timeout, tcp_pool).await,
    }
}

/// One query over TCP, TLS or HTTPS. With a `pool`, an idle connection kept
/// there for `key` is tried first (for at most half of `timeout`, falling
/// back to a new connection), and the connection is kept there afterwards
/// when it can carry another query.
pub async fn stream_exchange(
    upstream: &Upstream,
    outbound: &dyn TcpOutbound,
    query: &[u8],
    timeout: Duration,
    pool: Option<(&Mutex<UpstreamPool>, PoolKey)>,
) -> Result<Vec<u8>, OutboundFailure> {
    let Some(target) = upstream.target() else {
        return Err(OutboundFailure::QueryInvalid);
    };
    let started = Instant::now();
    let deadline = started + timeout;
    let take = |pool: &Mutex<UpstreamPool>, key| {
        pool.lock()
            .unwrap_or_else(|e| e.into_inner())
            .take(key, std::time::Instant::now())
    };
    let put = |stream: BoxStream| {
        if let Some((pool, key)) = pool {
            pool.lock().unwrap_or_else(|e| e.into_inner()).put(
                key,
                stream,
                std::time::Instant::now(),
            );
        }
    };
    if let Some(mut stream) = pool.and_then(|(pool, key)| take(pool, key)) {
        // A kept connection the server has closed fails fast; one that went
        // silent costs at most half the budget before a new connection.
        let budget = started + timeout / 2;
        if let Ok(Ok((response, reusable))) =
            tokio::time::timeout_at(budget, exchange_on(&mut stream, upstream, query)).await
        {
            if reusable {
                put(stream);
            }
            return Ok(response);
        }
    }
    let connect = async {
        let stream = match outbound.connect(target).await {
            Ok(stream) => stream,
            Err(err) => return Err(OutboundFailure::connect(&err)),
        };
        #[cfg(feature = "dns-tls")]
        if let Upstream::Tls { tls, .. } | Upstream::Https { tls, .. } = upstream {
            return tls
                .connect(stream)
                .await
                .map_err(|err| OutboundFailure::connect(&err));
        }
        Ok(stream)
    };
    let mut stream = match tokio::time::timeout_at(deadline, connect).await {
        Ok(Ok(stream)) => stream,
        Ok(Err(failure)) => return Err(failure),
        Err(_) => return Err(OutboundFailure::ConnectTimeout),
    };
    match tokio::time::timeout_at(deadline, exchange_on(&mut stream, upstream, query)).await {
        Ok(Ok((response, reusable))) => {
            if reusable {
                put(stream);
            }
            Ok(response)
        }
        Ok(Err(err)) => Err(OutboundFailure::reply(&err)),
        Err(_) => Err(OutboundFailure::ReplyTimeout),
    }
}

/// One query on an open connection: the checked reply, and whether the
/// connection can carry another query.
async fn exchange_on(
    stream: &mut BoxStream,
    upstream: &Upstream,
    query: &[u8],
) -> io::Result<(Vec<u8>, bool)> {
    #[cfg(feature = "dns-tls")]
    let (response, reusable) = if let Upstream::Https { host, path, .. } = upstream {
        https_exchange(stream, host, path, query).await?
    } else {
        (framed_exchange(stream, query).await?, true)
    };
    #[cfg(not(feature = "dns-tls"))]
    let (response, reusable) = {
        let _ = upstream;
        (framed_exchange(stream, query).await?, true)
    };
    if response.len() < DNS_HEADER_LEN {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "DNS response is too short",
        ));
    }
    if response[..2] != query[..2] {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "DNS response id does not match the query",
        ));
    }
    Ok((response, reusable))
}

/// DNS over TCP or TLS: each message behind a two-byte length.
async fn framed_exchange(stream: &mut BoxStream, query: &[u8]) -> io::Result<Vec<u8>> {
    let mut message = Vec::with_capacity(2 + query.len());
    message.extend_from_slice(&(query.len() as u16).to_be_bytes());
    message.extend_from_slice(query);
    stream.write_all(&message).await?;
    stream.flush().await?;

    let mut length = [0u8; 2];
    stream.read_exact(&mut length).await?;
    let mut response = vec![0u8; usize::from(u16::from_be_bytes(length))];
    stream.read_exact(&mut response).await?;
    Ok(response)
}

/// Longest DNS over HTTPS answer read, head included.
#[cfg(feature = "dns-tls")]
const MAX_HTTPS_RESPONSE: usize = crate::http1::MAX_HEAD_BYTES + 65_535;

/// DNS over HTTPS: one POST of `application/dns-message` on a kept-alive
/// connection. The flag says whether the connection can carry another
/// request: the answer was framed by `Content-Length`, nothing followed it,
/// and the server did not ask to close.
#[cfg(feature = "dns-tls")]
async fn https_exchange(
    stream: &mut BoxStream,
    host: &str,
    path: &str,
    query: &[u8],
) -> io::Result<(Vec<u8>, bool)> {
    let mut request = format!(
        "POST {path} HTTP/1.1\r\nHost: {host}\r\nContent-Type: application/dns-message\r\nAccept: application/dns-message\r\nContent-Length: {}\r\n\r\n",
        query.len()
    )
    .into_bytes();
    request.extend_from_slice(query);
    stream.write_all(&request).await?;
    stream.flush().await?;

    let mut raw = Vec::new();
    let mut buf = vec![0u8; 4096];
    loop {
        let read = match stream.read(&mut buf).await {
            Ok(read) => read,
            Err(_) if !raw.is_empty() => 0,
            Err(err) => return Err(err),
        };
        if read == 0 {
            break;
        }
        raw.extend_from_slice(&buf[..read]);
        if raw.len() > MAX_HTTPS_RESPONSE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "DNS over HTTPS response is too long",
            ));
        }
        if crate::http1::response_complete(&raw) {
            break;
        }
    }
    if raw.is_empty() {
        return Err(io::ErrorKind::UnexpectedEof.into());
    }
    let reusable = keeps_alive(&raw);
    let body = crate::http1::parse_response(&raw, 65_535).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "DNS over HTTPS answer was not a 200 dns-message",
        )
    })?;
    Ok((body, reusable))
}

/// Whether the connection that carried the HTTP/1.1 response `raw` can carry
/// another request: `Content-Length` framing with nothing after the body,
/// and no `Connection: close`.
#[cfg(feature = "dns-tls")]
fn keeps_alive(raw: &[u8]) -> bool {
    let Some(head_end) = raw.windows(4).position(|window| window == b"\r\n\r\n") else {
        return false;
    };
    let Ok(head) = std::str::from_utf8(&raw[..head_end]) else {
        return false;
    };
    if !head.starts_with("HTTP/1.1 ") {
        return false;
    }
    let mut length = None;
    for line in head.split("\r\n").skip(1) {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let (name, value) = (name.trim(), value.trim());
        if name.eq_ignore_ascii_case("connection") && value.eq_ignore_ascii_case("close") {
            return false;
        }
        if name.eq_ignore_ascii_case("content-length") {
            length = value.parse::<usize>().ok();
        }
    }
    length.is_some_and(|length| raw.len() == head_end + 4 + length)
}

/// Datagrams sent for one UDP query: the first, then again after
/// [`UDP_RETRY`] each while no answer came.
const UDP_SENDS: u32 = 3;
const UDP_RETRY: Duration = Duration::from_millis(1000);

/// DNS over UDP to `target` through `outbound`, with a random id of its own
/// (the app's comes back in the answer). Datagrams that are not the answer
/// to this question are ignored. A truncated answer, or an outbound without
/// UDP, makes the query go over TCP to the same server.
async fn udp_exchange(
    target: &TargetAddr,
    outbound: &dyn TcpOutbound,
    query: &[u8],
    deadline: Instant,
    tcp_pool: Option<(&Mutex<UpstreamPool>, PoolKey)>,
) -> Result<Vec<u8>, OutboundFailure> {
    let flow = match tokio::time::timeout_at(deadline, outbound.open_udp(target)).await {
        Ok(Ok(flow)) => flow,
        Ok(Err(err)) if err.kind() == io::ErrorKind::Unsupported => {
            return over_tcp(target, outbound, query, deadline, tcp_pool).await;
        }
        Ok(Err(err)) => return Err(OutboundFailure::connect(&err)),
        Err(_) => return Err(OutboundFailure::ConnectTimeout),
    };
    let mut sent = query.to_vec();
    sent[..2].copy_from_slice(&random_id().to_be_bytes());
    let mut response = udp_ask(flow, &sent, deadline).await?;
    if response[2] & FLAG_TC != 0 {
        return over_tcp(target, outbound, query, deadline, tcp_pool).await;
    }
    response[..2].copy_from_slice(&query[..2]);
    Ok(response)
}

/// The UDP server's query over TCP, in the time left.
async fn over_tcp(
    target: &TargetAddr,
    outbound: &dyn TcpOutbound,
    query: &[u8],
    deadline: Instant,
    tcp_pool: Option<(&Mutex<UpstreamPool>, PoolKey)>,
) -> Result<Vec<u8>, OutboundFailure> {
    let left = deadline.saturating_duration_since(Instant::now());
    if left.is_zero() {
        return Err(OutboundFailure::ReplyTimeout);
    }
    let upstream = Upstream::Tcp(target.clone());
    stream_exchange(&upstream, outbound, query, left, tcp_pool).await
}

/// Sends `query` on `flow` until its answer arrives or `deadline` passes.
async fn udp_ask(
    flow: UdpFlow,
    query: &[u8],
    deadline: Instant,
) -> Result<Vec<u8>, OutboundFailure> {
    let UdpFlow { mut send, mut recv } = flow;
    let mut sends = 0;
    let mut next_send = Instant::now();
    loop {
        if sends < UDP_SENDS && Instant::now() >= next_send {
            send.send(query)
                .await
                .map_err(|err| OutboundFailure::reply(&err))?;
            sends += 1;
            next_send = Instant::now() + UDP_RETRY;
        }
        let wait = if sends < UDP_SENDS {
            next_send.min(deadline)
        } else {
            deadline
        };
        match tokio::time::timeout_at(wait, recv.recv()).await {
            Ok(Ok(datagram)) if answers(query, &datagram) => return Ok(datagram),
            Ok(Ok(_)) => {}
            Ok(Err(err)) => return Err(OutboundFailure::reply(&err)),
            Err(_) if Instant::now() >= deadline => return Err(OutboundFailure::ReplyTimeout),
            Err(_) => {}
        }
    }
}

/// Whether `response` answers `query`: same id, a response, and the same
/// question (names compared without case).
pub fn answers(query: &[u8], response: &[u8]) -> bool {
    if response.len() < DNS_HEADER_LEN
        || response[..2] != query[..2]
        || response[2] & 0x80 == 0
        || response[4..6] != query[4..6]
    {
        return false;
    }
    match question(query) {
        Some(question) => response
            .get(DNS_HEADER_LEN..question.end)
            .is_some_and(|asked| asked.eq_ignore_ascii_case(&query[DNS_HEADER_LEN..question.end])),
        None => true,
    }
}

/// TC: the answer did not fit in the datagram.
const FLAG_TC: u8 = 0x02;

pub const RCODE_NOERROR: u8 = 0;
pub const RCODE_SERVFAIL: u8 = 2;
pub const RCODE_NXDOMAIN: u8 = 3;

/// The response code of a response.
pub fn rcode(response: &[u8]) -> u8 {
    response.get(3).map_or(RCODE_SERVFAIL, |flags| flags & 0x0F)
}

fn random_id() -> u16 {
    use ring::rand::{SecureRandom, SystemRandom};
    let mut id = [0u8; 2];
    if SystemRandom::new().fill(&mut id).is_err() {
        // Only the spoofing margin of direct UDP rests on it.
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |elapsed| elapsed.subsec_nanos());
        return nanos as u16;
    }
    u16::from_be_bytes(id)
}

/// The device's resolvers: `servers` over UDP through `direct`, raced, or
/// the system resolver when there are none.
async fn system_exchange(
    servers: &[SocketAddr],
    direct: &dyn TcpOutbound,
    query: &[u8],
    deadline: Instant,
) -> Result<Vec<u8>, OutboundFailure> {
    if servers.is_empty() {
        return system_resolver_answer(query, deadline).await;
    }
    let targets: Vec<TargetAddr> = servers
        .iter()
        .map(|server| TargetAddr::Ip(*server))
        .collect();
    race(
        targets
            .iter()
            .map(|target| udp_exchange(target, direct, query, deadline, None)),
    )
    .await
    .into_result()
}

/// An answer to an A or AAAA query from the system resolver (TTL 60 s), or
/// SERVFAIL when it fails or for other types, which it cannot look up.
async fn system_resolver_answer(
    query: &[u8],
    deadline: Instant,
) -> Result<Vec<u8>, OutboundFailure> {
    let question = question(query).ok_or(OutboundFailure::QueryInvalid)?;
    if !matches!(question.qtype, TYPE_A | TYPE_AAAA) {
        return Ok(error_answer(query, &question, RCODE_SERVFAIL));
    }
    // The lookup owns its name: the match below borrows `question` while the
    // finished lookup's iterator is still alive.
    let lookup = tokio::net::lookup_host((question.name.clone(), 0));
    let looked_up = tokio::time::timeout_at(deadline, lookup).await;
    match looked_up {
        Ok(Ok(addresses)) => {
            let mut found: Vec<IpAddr> = Vec::new();
            for address in addresses {
                if !found.contains(&address.ip()) {
                    found.push(address.ip());
                }
            }
            Ok(local_answer(query, &question, &found))
        }
        Ok(Err(_)) => Ok(error_answer(query, &question, RCODE_SERVFAIL)),
        Err(_) => Err(OutboundFailure::ReplyTimeout),
    }
}

/// The outcome of [`race`]: the best response, and why the others failed.
#[derive(Debug, Default)]
pub struct Raced {
    /// The best response by [`rank`], with its rank.
    pub best: Option<(u8, Vec<u8>)>,
    /// The last failure, when an exchange failed.
    pub failure: Option<OutboundFailure>,
}

impl Raced {
    /// Whether the best response is an answer (NOERROR or NXDOMAIN), not an
    /// error or nothing.
    pub fn answered(&self) -> bool {
        self.best.as_ref().is_some_and(|(rank, _)| *rank <= 1)
    }

    /// Keeps the better of two outcomes.
    pub fn merge(mut self, other: Raced) -> Raced {
        if let Some((rank, response)) = other.best {
            if self.best.as_ref().is_none_or(|(best, _)| rank < *best) {
                self.best = Some((rank, response));
            }
        }
        self.failure = other.failure.or(self.failure);
        self
    }

    /// The best response, or the failure when no exchange got one.
    pub fn into_result(self) -> Result<Vec<u8>, OutboundFailure> {
        match self.best {
            Some((_, response)) => Ok(response),
            None => Err(self.failure.unwrap_or(OutboundFailure::ReplyFailed)),
        }
    }
}

/// How good a response is: 0 for NOERROR, 1 for NXDOMAIN, 2 for any error.
pub fn rank(response: &[u8]) -> u8 {
    match rcode(response) {
        RCODE_NOERROR => 0,
        RCODE_NXDOMAIN => 1,
        _ => 2,
    }
}

/// Runs `exchanges` at once. The first NOERROR response wins and the others
/// are dropped; otherwise, once all have finished, the best response by
/// [`rank`] (the first of equals) is kept, so a server that knows a name
/// beats one that answers NXDOMAIN faster.
pub async fn race<F>(exchanges: impl IntoIterator<Item = F>) -> Raced
where
    F: Future<Output = Result<Vec<u8>, OutboundFailure>>,
{
    let mut pending: FuturesUnordered<F> = exchanges.into_iter().collect();
    let mut raced = Raced::default();
    while let Some(result) = pending.next().await {
        match result {
            Ok(response) => {
                let rank = rank(&response);
                if rank == 0 {
                    return Raced {
                        best: Some((0, response)),
                        failure: None,
                    };
                }
                if raced.best.as_ref().is_none_or(|(best, _)| rank < *best) {
                    raced.best = Some((rank, response));
                }
            }
            Err(failure) => raced.failure = Some(failure),
        }
    }
    raced
}

/// The first question of a query: the name in lower case without the final
/// dot, its type, and where the question ends.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Question {
    pub name: String,
    pub qtype: u16,
    pub end: usize,
}

pub const TYPE_A: u16 = 1;
pub const TYPE_AAAA: u16 = 28;
const CLASS_IN: u16 = 1;

/// Reads the first question of a standard query; `None` for anything else
/// (responses, other opcodes, compressed or oversized names).
pub fn question(query: &[u8]) -> Option<Question> {
    if query.len() < DNS_HEADER_LEN || query.len() > MAX_QUERY_LEN {
        return None;
    }
    let flags = u16::from_be_bytes([query[2], query[3]]);
    // QR must be clear and the opcode QUERY.
    if flags & 0xF800 != 0 || u16::from_be_bytes([query[4], query[5]]) == 0 {
        return None;
    }
    let mut at = DNS_HEADER_LEN;
    let mut name = String::new();
    loop {
        let length = usize::from(*query.get(at)?);
        at += 1;
        if length == 0 {
            break;
        }
        if length > 63 {
            return None;
        }
        let label = query.get(at..at + length)?;
        if !name.is_empty() {
            name.push('.');
        }
        name.push_str(std::str::from_utf8(label).ok()?);
        if name.len() > 253 {
            return None;
        }
        at += length;
    }
    let fixed = query.get(at..at + 4)?;
    let qtype = u16::from_be_bytes([fixed[0], fixed[1]]);
    if u16::from_be_bytes([fixed[2], fixed[3]]) != CLASS_IN {
        return None;
    }
    Some(Question {
        name: name.to_ascii_lowercase(),
        qtype,
        end: at + 4,
    })
}

/// A standard recursive query for `name` (no final dot) of type `qtype`, or
/// `None` for a name that cannot be encoded.
pub fn query(id: u16, name: &str, qtype: u16) -> Option<Vec<u8>> {
    let name = name.strip_suffix('.').unwrap_or(name);
    if name.is_empty() || name.len() > 253 {
        return None;
    }
    let mut query = Vec::with_capacity(DNS_HEADER_LEN + name.len() + 6);
    query.extend_from_slice(&id.to_be_bytes());
    // RD set, one question.
    query.extend_from_slice(&[0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]);
    for label in name.split('.') {
        if label.is_empty() || label.len() > 63 {
            return None;
        }
        query.push(label.len() as u8);
        query.extend_from_slice(label.as_bytes());
    }
    query.push(0);
    query.extend_from_slice(&qtype.to_be_bytes());
    query.extend_from_slice(&CLASS_IN.to_be_bytes());
    Some(query)
}

/// Seconds a locally answered record may be cached.
const LOCAL_TTL_SECS: u32 = 60;

/// An authoritative answer to `query` with the addresses of the asked family
/// (none for other types, which is "no data").
pub fn local_answer(query: &[u8], question: &Question, addresses: &[IpAddr]) -> Vec<u8> {
    let records: Vec<&IpAddr> = addresses
        .iter()
        .filter(|address| match question.qtype {
            TYPE_A => address.is_ipv4(),
            TYPE_AAAA => address.is_ipv6(),
            _ => false,
        })
        .collect();
    let flags = u16::from_be_bytes([query[2], query[3]]);
    // QR, the opcode and RD copied, AA and RA set, NOERROR.
    let flags = 0x8000 | (flags & 0x7900) | 0x0400 | 0x0080;
    let mut response = Vec::with_capacity(question.end + records.len() * 28);
    response.extend_from_slice(&query[..2]);
    response.extend_from_slice(&flags.to_be_bytes());
    response.extend_from_slice(&1u16.to_be_bytes());
    response.extend_from_slice(&(records.len() as u16).to_be_bytes());
    response.extend_from_slice(&[0, 0, 0, 0]);
    response.extend_from_slice(&query[DNS_HEADER_LEN..question.end]);
    for address in records {
        // The name points back at the question.
        response.extend_from_slice(&[0xC0, 0x0C]);
        let (rtype, data) = match address {
            IpAddr::V4(v4) => (TYPE_A, v4.octets().to_vec()),
            IpAddr::V6(v6) => (TYPE_AAAA, v6.octets().to_vec()),
        };
        response.extend_from_slice(&rtype.to_be_bytes());
        response.extend_from_slice(&CLASS_IN.to_be_bytes());
        response.extend_from_slice(&LOCAL_TTL_SECS.to_be_bytes());
        response.extend_from_slice(&(data.len() as u16).to_be_bytes());
        response.extend_from_slice(&data);
    }
    response
}

/// A reply to `query` with no records and response code `rcode` (e.g.
/// SERVFAIL).
pub fn error_answer(query: &[u8], question: &Question, rcode: u8) -> Vec<u8> {
    let flags = u16::from_be_bytes([query[2], query[3]]);
    // QR, the opcode and RD copied, RA set.
    let flags = 0x8000 | (flags & 0x7900) | 0x0080 | u16::from(rcode & 0x0F);
    let mut response = Vec::with_capacity(question.end);
    response.extend_from_slice(&query[..2]);
    response.extend_from_slice(&flags.to_be_bytes());
    response.extend_from_slice(&[0, 1, 0, 0, 0, 0, 0, 0]);
    response.extend_from_slice(&query[DNS_HEADER_LEN..question.end]);
    response
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn failure_codes_round_trip() {
        for failure in OutboundFailure::ALL {
            assert_eq!(OutboundFailure::from_code(failure as u8), Some(failure));
        }
        assert_eq!(OutboundFailure::from_code(0), None);
    }

    #[test]
    fn errors_are_classified_by_stage() {
        let eof = io::Error::from(io::ErrorKind::UnexpectedEof);
        let invalid = io::Error::from(io::ErrorKind::InvalidData);
        let refused = io::Error::from(io::ErrorKind::ConnectionRefused);
        assert_eq!(OutboundFailure::reply(&eof), OutboundFailure::ReplyClosed);
        assert_eq!(
            OutboundFailure::reply(&invalid),
            OutboundFailure::ReplyRejected
        );
        assert_eq!(
            OutboundFailure::connect(&refused),
            OutboundFailure::ConnectRefused
        );
    }

    fn query(name: &[u8], qtype: u16) -> Vec<u8> {
        let mut query = vec![0xab, 0xcd, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        query.extend_from_slice(name);
        query.extend_from_slice(&qtype.to_be_bytes());
        query.extend_from_slice(&CLASS_IN.to_be_bytes());
        query
    }

    #[test]
    fn questions_are_read_in_lower_case() {
        let query = query(b"\x03WWW\x07Example\x03com\x00", TYPE_AAAA);
        let question = question(&query).unwrap();
        assert_eq!(question.name, "www.example.com");
        assert_eq!(question.qtype, TYPE_AAAA);
        assert_eq!(question.end, query.len());

        let mut response = query.clone();
        response[2] |= 0x80;
        assert_eq!(super::question(&response), None);
        let compressed = query_with_pointer();
        assert_eq!(super::question(&compressed), None);
        assert_eq!(super::question(&query[..14]), None);
    }

    fn query_with_pointer() -> Vec<u8> {
        query(b"\xc0\x0c", TYPE_A)
    }

    #[test]
    fn local_answers_hold_the_asked_family() {
        let mx = query(b"\x06router\x03lan\x00", 15);
        let query = query(b"\x06router\x03lan\x00", TYPE_A);
        let question = question(&query).unwrap();
        let addresses: Vec<IpAddr> =
            vec!["192.168.1.1".parse().unwrap(), "fd00::1".parse().unwrap()];
        let response = local_answer(&query, &question, &addresses);
        assert_eq!(&response[..2], &[0xab, 0xcd]);
        assert_eq!(response[2] & 0x80, 0x80, "QR");
        assert_eq!(response[2] & 0x01, 0x01, "RD copied");
        assert_eq!(response[3] & 0x0f, 0, "NOERROR");
        assert_eq!(&response[6..8], &[0, 1], "one answer");
        assert_eq!(&response[12..question.end], &query[12..]);
        let answer = &response[question.end..];
        assert_eq!(&answer[..4], &[0xc0, 0x0c, 0, 1]);
        assert_eq!(&answer[10..12], &[0, 4]);
        assert_eq!(&answer[12..], &[192, 168, 1, 1]);

        let question = super::question(&mx).unwrap();
        let response = local_answer(&mx, &question, &addresses);
        assert_eq!(&response[6..8], &[0, 0], "no data");
        assert_eq!(response.len(), mx.len());
    }

    fn tcp_target(url: &str) -> TargetAddr {
        let upstream = Upstream::parse(url, None).unwrap();
        assert_eq!(upstream.scheme(), "tcp", "{url}");
        upstream.target().unwrap().clone()
    }

    #[test]
    fn upstream_urls_parse() {
        assert_eq!(
            tcp_target("1.1.1.1"),
            TargetAddr::Ip("1.1.1.1:53".parse().unwrap())
        );
        assert_eq!(
            tcp_target("tcp://[2606:4700::1111]:5353"),
            TargetAddr::Ip("[2606:4700::1111]:5353".parse().unwrap())
        );
        assert_eq!(
            tcp_target("tcp://DNS.example:53"),
            TargetAddr::Domain("dns.example".into(), 53)
        );
        for url in [
            "",
            "ftp://1.1.1.1",
            "udp://1.1.1.1/x",
            "tcp://1.1.1.1/x",
            "tcp://:53",
            "tcp://a b",
            "1.1.1.1:0",
        ] {
            assert!(Upstream::parse(url, None).is_err(), "{url}");
        }
    }

    #[cfg(feature = "dns-tls")]
    #[test]
    fn encrypted_upstream_urls_parse() {
        let Upstream::Https {
            target, host, path, ..
        } = Upstream::parse("https://dns.google/dns-query", None).unwrap()
        else {
            panic!("https");
        };
        assert_eq!(target, TargetAddr::Domain("dns.google".into(), 443));
        assert_eq!((host.as_str(), path.as_str()), ("dns.google", "/dns-query"));
        let Upstream::Https { host, path, .. } =
            Upstream::parse("https://1.1.1.1:8443", Some("cloudflare-dns.com")).unwrap()
        else {
            panic!("https");
        };
        assert_eq!(
            (host.as_str(), path.as_str()),
            ("1.1.1.1:8443", "/dns-query")
        );
        let upstream = Upstream::parse("tls://dns.alidns.com", None).unwrap();
        assert_eq!(upstream.scheme(), "tls");
        assert_eq!(
            upstream.target(),
            Some(&TargetAddr::Domain("dns.alidns.com".into(), 853))
        );
    }

    #[cfg(feature = "dns-tls")]
    #[test]
    fn https_connections_are_kept_only_when_framed() {
        let ok = b"HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nContent-Length: 3\r\n\r\nabc";
        assert!(keeps_alive(ok));
        let close = b"HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 3\r\n\r\nabc";
        assert!(!keeps_alive(close));
        let chunked = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\n";
        assert!(!keeps_alive(chunked));
        let extra = b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nabcd";
        assert!(!keeps_alive(extra));
        let old = b"HTTP/1.0 200 OK\r\nContent-Length: 3\r\n\r\nabc";
        assert!(!keeps_alive(old));
    }

    #[cfg(not(feature = "dns-tls"))]
    #[test]
    fn encrypted_upstreams_need_the_feature() {
        assert_eq!(
            Upstream::parse("tls://1.1.1.1", None).err(),
            Some(UpstreamError::Unsupported)
        );
    }
}
