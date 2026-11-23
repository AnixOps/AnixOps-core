//! Local mixed inbound: SOCKS5 and HTTP proxy requests on one listening port.
//!
//! The first byte of a connection picks the protocol: `0x05` is SOCKS5,
//! anything else is parsed as an HTTP/1.x proxy request. Both end in a
//! [`TargetAddr`] that is handed to a [`TcpOutbound`]; after that the bytes are
//! relayed unchanged in both directions.
//!
//! With a [`ClientInterceptor`] ([`serve_intercepted`]) a tunnel is answered
//! before the outbound connection exists and its first bytes are offered to
//! the interceptor, which may take the connection over (HTTPS decryption).
//! Tunnels it leaves alone are relayed as usual, the first bytes included.
//!
//! Supported: SOCKS5 without authentication and with username/password
//! (RFC 1929), `CONNECT`, and `UDP ASSOCIATE` when [`MixedSettings::udp`] is
//! set (see [`ClientConnector::open_client_udp`]); HTTP `CONNECT` tunnels and
//! absolute-form plain HTTP requests, optionally with
//! `Proxy-Authorization: Basic`. SOCKS5 `BIND`, and `UDP ASSOCIATE` on a
//! listener without UDP, are answered with "command not supported".
//!
//! The listener is meant for loopback. To serve other devices on the local
//! network (a phone that sets this computer as its Wi-Fi proxy), bind it to
//! all interfaces with [`PeerFilter::PrivateNetworks`] so that only clients
//! from private and link-local addresses are answered, and give it
//! [`ClientPages`]: plain HTTP requests made to the listener itself (`GET /`
//! from a browser that has not set the proxy yet) or through it to
//! [`ClientPages::host`] are answered by those pages instead of being
//! relayed, for a setup page with the root certificate download.
//!
//! A connect the outbound refuses with a routing rejection
//! ([`engine_outbound::reject`]) is answered as the rule asks: `REJECT-DROP`
//! gets no answer at all (the connection is held open until the client
//! gives up), `REJECT-TINYGIF` answers a plain HTTP request with a 1x1 GIF,
//! and the rest get the usual failure reply.
//!
//! Errors and logs never contain credentials or request contents.

mod http;
mod socks5;
mod udp;

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use engine_outbound::accept::{self, AcceptBackoff};
use engine_outbound::reject::{self, RejectAction};
use engine_outbound::{udp_unsupported, BoxFuture, BoxStream, TargetAddr, TcpOutbound, UdpFlow};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;

/// Largest request head accepted from a client, for SOCKS5 and HTTP alike.
pub const MAX_HEAD_BYTES: usize = 16 * 1024;
const RELAY_BUFFER_BYTES: usize = 16 * 1024;
/// How long an error reply waits for the client to close before the socket
/// is dropped.
const LINGER: Duration = Duration::from_millis(500);
/// Most first bytes of a tunnel offered to a [`ClientInterceptor`].
const FIRST_BYTES_MAX: usize = 4096;
/// How long an intercepted listener waits for a tunnel's first bytes; a
/// protocol where the server speaks first is relayed after this delay.
const FIRST_BYTES_WAIT: Duration = Duration::from_millis(300);

/// Credentials a client must present. Has no `Debug` on purpose.
#[derive(Clone, PartialEq, Eq)]
pub struct Credentials {
    pub username: String,
    pub password: String,
}

#[derive(Clone)]
pub struct MixedSettings {
    pub max_connections: usize,
    /// Time allowed for the client's SOCKS5 or HTTP request head.
    pub handshake_timeout: Duration,
    pub connect_timeout: Duration,
    /// When set, both protocols require these credentials. Pages from
    /// [`Self::pages`] asked for without the proxy need none.
    pub credentials: Option<Credentials>,
    /// Which client addresses are answered; others are closed unread.
    pub peers: PeerFilter,
    /// Local pages served on this listener; see [`ClientPages`].
    pub pages: Option<Arc<dyn ClientPages>>,
    /// Answers SOCKS5 `UDP ASSOCIATE` with a relay socket on the listener's
    /// address. Off by default: a listener shared with other devices should
    /// not relay UDP unless its owner chose to.
    pub udp: bool,
}

impl Default for MixedSettings {
    fn default() -> Self {
        Self {
            max_connections: 1024,
            handshake_timeout: Duration::from_secs(10),
            connect_timeout: Duration::from_secs(10),
            credentials: None,
            peers: PeerFilter::Any,
            pages: None,
            udp: false,
        }
    }
}

/// The client addresses a listener answers.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum PeerFilter {
    /// Every client; for a loopback listener.
    #[default]
    Any,
    /// Loopback, private (RFC 1918, RFC 6598 shared, IPv6 unique local) and
    /// link-local addresses only: devices on the same network, never the
    /// internet when the computer has a public address or a forwarded port.
    PrivateNetworks,
}

impl PeerFilter {
    pub fn allows(self, peer: IpAddr) -> bool {
        match self {
            Self::Any => true,
            Self::PrivateNetworks => is_private_network(peer),
        }
    }
}

/// Whether `ip` belongs to the local network side of a typical router.
pub fn is_private_network(ip: IpAddr) -> bool {
    match ip.to_canonical() {
        IpAddr::V4(ip) => is_private_v4(ip),
        IpAddr::V6(ip) => is_private_v6(ip),
    }
}

fn is_private_v4(ip: Ipv4Addr) -> bool {
    let [a, b, ..] = ip.octets();
    ip.is_loopback()
        || ip.is_private()
        || ip.is_link_local()
        // 100.64.0.0/10, carrier-grade NAT and mesh VPNs.
        || (a == 100 && (64..128).contains(&b))
}

fn is_private_v6(ip: Ipv6Addr) -> bool {
    let first = ip.segments()[0];
    ip.is_loopback()
        // fc00::/7 unique local, fe80::/10 link-local.
        || (first & 0xfe00) == 0xfc00
        || (first & 0xffc0) == 0xfe80
}

/// A plain HTTP request for a local page, before it is answered.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PageRequest {
    /// `GET`, `HEAD`, ... as sent.
    pub method: String,
    /// Path and query, starting with `/`.
    pub path: String,
    /// The `Host` header, when sent.
    pub host: Option<String>,
    /// The `User-Agent` header, when sent.
    pub user_agent: Option<String>,
    /// Whether the request came through the proxy (absolute form for
    /// [`ClientPages::host`]) rather than straight to the listener.
    pub proxied: bool,
}

/// The answer to a [`PageRequest`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PageResponse {
    pub status: u16,
    pub content_type: String,
    pub body: Vec<u8>,
    /// Sent as an attachment with this file name when set.
    pub file_name: Option<String>,
}

impl PageResponse {
    pub fn ok(content_type: &str, body: Vec<u8>) -> Self {
        Self {
            status: 200,
            content_type: content_type.to_string(),
            body,
            file_name: None,
        }
    }

    pub fn not_found() -> Self {
        Self {
            status: 404,
            content_type: "text/plain; charset=utf-8".to_string(),
            body: b"not found\n".to_vec(),
            file_name: None,
        }
    }
}

/// Pages a listener serves itself: a request in origin form (`GET / HTTP/1.1`,
/// a browser that opened `http://<listener address>/`) or one through the
/// proxy for [`Self::host`] (`GET http://<host>/ HTTP/1.1`). Nothing is
/// relayed for them; the connection closes after the answer.
pub trait ClientPages: Send + Sync {
    /// The made-up host name the pages also answer to through the proxy,
    /// lower case, such as `cert.anixops`.
    fn host(&self) -> &str;

    fn respond(&self, client: ClientAddrs, request: &PageRequest) -> PageResponse;
}

/// Counters only; no addresses.
#[derive(Debug, Default)]
pub struct MixedStats {
    pub accepted: AtomicU64,
    pub rejected: AtomicU64,
    pub active: AtomicU64,
    pub handshake_failed: AtomicU64,
    pub connect_failed: AtomicU64,
    pub bytes_up: AtomicU64,
    pub bytes_down: AtomicU64,
    /// Local pages answered ([`ClientPages`]).
    pub pages: AtomicU64,
    /// SOCKS5 UDP associations opened.
    pub udp_associations: AtomicU64,
    /// Errors of `accept` that the listener survived: a client that reset
    /// before it was accepted, or the process out of file descriptors or
    /// buffers for a while (see [`engine_outbound::accept`]).
    pub accept_errors: AtomicU64,
}

/// What a client asked for.
pub(crate) enum Incoming {
    Proxy(Request),
    Page(PageRequest),
}

/// A parsed proxy request, before the outbound connection exists.
pub(crate) struct Request {
    pub target: TargetAddr,
    /// Bytes to send to the target first (a rewritten plain HTTP request head).
    pub initial: Vec<u8>,
    pub reply: Reply,
}

/// How to answer the client once the outbound connection succeeded or failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Reply {
    Socks5,
    /// SOCKS5 `UDP ASSOCIATE`; answered by the UDP relay, not a tunnel.
    Socks5Associate,
    HttpConnect,
    /// Plain HTTP: the target's own response is the answer.
    HttpForward,
}

/// Both ends of an accepted client connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ClientAddrs {
    /// The client's own address.
    pub peer: SocketAddr,
    /// The listener address the client connected to.
    pub local: SocketAddr,
}

/// Connects a client's request; unlike a [`TcpOutbound`] it learns which
/// client asked, for routing by the local process.
pub trait ClientConnector: Send + Sync {
    fn connect_client<'a>(
        &'a self,
        client: ClientAddrs,
        target: &'a TargetAddr,
    ) -> BoxFuture<'a, io::Result<BoxStream>>;

    /// [`Self::connect_client`] with the bytes the client sends first, known
    /// before the connection opens: the origin-form head of a plain HTTP
    /// request, or the start of a tunnel's payload (empty when the client
    /// waits for the server or the listener did not read ahead). Connectors
    /// that route by a plain HTTP request's head (`USER-AGENT`, `URL-REGEX`)
    /// override it; the default ignores `first`.
    fn connect_client_with_first<'a>(
        &'a self,
        client: ClientAddrs,
        target: &'a TargetAddr,
        first: &'a [u8],
    ) -> BoxFuture<'a, io::Result<BoxStream>> {
        let _ = first;
        self.connect_client(client, target)
    }

    /// Opens a UDP flow to `target` for a SOCKS5 `UDP ASSOCIATE`. The default
    /// fails with [`udp_unsupported`]; a datagram for such a destination is
    /// dropped.
    fn open_client_udp<'a>(
        &'a self,
        client: ClientAddrs,
        target: &'a TargetAddr,
    ) -> BoxFuture<'a, io::Result<UdpFlow>> {
        let _ = (client, target);
        Box::pin(async { Err(udp_unsupported()) })
    }
}

/// Takes tunnels over before they are relayed, judged from the first bytes
/// the client sends through them.
pub trait ClientInterceptor: Send + Sync {
    /// The host name to take the connection for. `first` is what the client
    /// sent first: the start of a tunnel's payload (empty when the client
    /// waits for the server), or the origin-form head of a plain HTTP request.
    fn claim(&self, target: &TargetAddr, first: &[u8]) -> Option<String>;

    /// Serves a claimed connection to the end. The client has already been
    /// told that the tunnel is open; `first` is not yet answered.
    fn serve<'a>(
        &'a self,
        client: ClientAddrs,
        target: &'a TargetAddr,
        host: String,
        stream: BoxStream,
        first: Vec<u8>,
    ) -> BoxFuture<'a, ()>;
}

/// Any outbound, ignoring who asked.
struct AnyClient(Arc<dyn TcpOutbound>);

impl ClientConnector for AnyClient {
    fn connect_client<'a>(
        &'a self,
        _client: ClientAddrs,
        target: &'a TargetAddr,
    ) -> BoxFuture<'a, io::Result<BoxStream>> {
        self.0.connect(target)
    }

    fn open_client_udp<'a>(
        &'a self,
        _client: ClientAddrs,
        target: &'a TargetAddr,
    ) -> BoxFuture<'a, io::Result<UdpFlow>> {
        self.0.open_udp(target)
    }
}

/// Accepts connections until the listener becomes unusable or the task is
/// dropped. Errors of one connection and running out of file descriptors
/// do not end it (see [`engine_outbound::accept`]).
pub async fn serve(
    listener: TcpListener,
    outbound: Arc<dyn TcpOutbound>,
    settings: MixedSettings,
    stats: Arc<MixedStats>,
) -> io::Result<()> {
    serve_clients(listener, Arc::new(AnyClient(outbound)), settings, stats).await
}

/// [`serve`] with a connector that is told each client's addresses.
pub async fn serve_clients(
    listener: TcpListener,
    connector: Arc<dyn ClientConnector>,
    settings: MixedSettings,
    stats: Arc<MixedStats>,
) -> io::Result<()> {
    serve_intercepted(listener, connector, None, settings, stats).await
}

/// [`serve_clients`], offering each connection to `interceptor` first.
pub async fn serve_intercepted(
    listener: TcpListener,
    connector: Arc<dyn ClientConnector>,
    interceptor: Option<Arc<dyn ClientInterceptor>>,
    settings: MixedSettings,
    stats: Arc<MixedStats>,
) -> io::Result<()> {
    let permits = Arc::new(Semaphore::new(settings.max_connections));
    let settings = Arc::new(settings);
    let mut backoff = AcceptBackoff::default();
    loop {
        let (stream, peer) = accept::accept(
            || listener.accept(),
            &mut backoff,
            Some(&stats.accept_errors),
        )
        .await?;
        if !settings.peers.allows(peer.ip()) {
            stats.rejected.fetch_add(1, Ordering::Relaxed);
            drop(stream);
            continue;
        }
        let Ok(permit) = permits.clone().try_acquire_owned() else {
            stats.rejected.fetch_add(1, Ordering::Relaxed);
            drop(stream);
            continue;
        };
        stats.accepted.fetch_add(1, Ordering::Relaxed);
        let Ok(local) = stream.local_addr() else {
            continue;
        };
        let client = ClientAddrs { peer, local };
        let connector = connector.clone();
        let interceptor = interceptor.clone();
        let settings = settings.clone();
        let stats = stats.clone();
        tokio::spawn(async move {
            let _permit = permit;
            let _ = stream.set_nodelay(true);
            stats.active.fetch_add(1, Ordering::Relaxed);
            handle(
                stream,
                client,
                &connector,
                interceptor.as_deref(),
                &settings,
                &stats,
            )
            .await;
            stats.active.fetch_sub(1, Ordering::Relaxed);
        });
    }
}

async fn handle(
    mut client: TcpStream,
    addrs: ClientAddrs,
    connector: &Arc<dyn ClientConnector>,
    interceptor: Option<&dyn ClientInterceptor>,
    settings: &MixedSettings,
    stats: &Arc<MixedStats>,
) {
    let request = tokio::time::timeout(
        settings.handshake_timeout,
        read_request(
            &mut client,
            settings.credentials.as_ref(),
            settings.pages.as_deref(),
            settings.udp,
        ),
    )
    .await;
    let request = match request {
        Ok(Ok(Incoming::Proxy(request))) => request,
        Ok(Ok(Incoming::Page(page))) => {
            if let Some(pages) = settings.pages.as_deref() {
                let response = pages.respond(addrs, &page);
                stats.pages.fetch_add(1, Ordering::Relaxed);
                let _ = http::send_page(&mut client, &page, &response).await;
            }
            close_gracefully(client).await;
            return;
        }
        Ok(Err(_)) | Err(_) => {
            stats.handshake_failed.fetch_add(1, Ordering::Relaxed);
            close_gracefully(client).await;
            return;
        }
    };
    if request.reply == Reply::Socks5Associate {
        udp::associate(
            client,
            addrs,
            connector.clone(),
            settings.connect_timeout,
            stats.clone(),
        )
        .await;
        return;
    }
    if let Some(interceptor) = interceptor {
        handle_intercepted(
            client,
            addrs,
            request,
            connector.as_ref(),
            interceptor,
            settings,
            stats,
        )
        .await;
        return;
    }

    let connected = tokio::time::timeout(
        settings.connect_timeout,
        connector.connect_client_with_first(addrs, &request.target, &request.initial),
    )
    .await;
    let mut remote = match connected {
        Ok(Ok(remote)) => remote,
        Ok(Err(error)) => {
            stats.connect_failed.fetch_add(1, Ordering::Relaxed);
            answer_failure(client, request.reply, reject::rejection(&error), false).await;
            return;
        }
        Err(_) => {
            stats.connect_failed.fetch_add(1, Ordering::Relaxed);
            answer_failure(client, request.reply, None, false).await;
            return;
        }
    };
    if send_success(&mut client, request.reply).await.is_err() {
        return;
    }
    if !request.initial.is_empty() {
        if remote.write_all(&request.initial).await.is_err() {
            return;
        }
        stats
            .bytes_up
            .fetch_add(request.initial.len() as u64, Ordering::Relaxed);
    }
    relay(client, remote, stats).await;
}

/// [`handle`] for a listener with an interceptor: a tunnel is answered first
/// so that the client sends the bytes the interceptor judges by.
async fn handle_intercepted(
    mut client: TcpStream,
    addrs: ClientAddrs,
    request: Request,
    connector: &dyn ClientConnector,
    interceptor: &dyn ClientInterceptor,
    settings: &MixedSettings,
    stats: &MixedStats,
) {
    let tunnel = request.reply != Reply::HttpForward;
    // Bytes that came with the request head: a plain HTTP request, or the
    // start of a tunnel's payload sent without waiting for the answer.
    let mut first = request.initial;
    if tunnel {
        if send_success(&mut client, request.reply).await.is_err() {
            return;
        }
        if first.is_empty() {
            first.resize(FIRST_BYTES_MAX, 0);
            let read = tokio::time::timeout(FIRST_BYTES_WAIT, client.read(&mut first)).await;
            let len = match read {
                Ok(Ok(0)) | Ok(Err(_)) => return,
                Ok(Ok(n)) => n,
                Err(_) => 0,
            };
            first.truncate(len);
        }
    }

    if let Some(host) = interceptor.claim(&request.target, &first) {
        interceptor
            .serve(addrs, &request.target, host, Box::new(client), first)
            .await;
        return;
    }

    let connected = tokio::time::timeout(
        settings.connect_timeout,
        connector.connect_client_with_first(addrs, &request.target, &first),
    )
    .await;
    let mut remote = match connected {
        Ok(Ok(remote)) => remote,
        Ok(Err(error)) => {
            stats.connect_failed.fetch_add(1, Ordering::Relaxed);
            // A tunnel was already answered; all that is left is to close it.
            answer_failure(client, request.reply, reject::rejection(&error), tunnel).await;
            return;
        }
        Err(_) => {
            stats.connect_failed.fetch_add(1, Ordering::Relaxed);
            answer_failure(client, request.reply, None, tunnel).await;
            return;
        }
    };
    if !first.is_empty() {
        if remote.write_all(&first).await.is_err() {
            return;
        }
        stats
            .bytes_up
            .fetch_add(first.len() as u64, Ordering::Relaxed);
    }
    relay(client, remote, stats).await;
}

async fn read_request(
    client: &mut TcpStream,
    credentials: Option<&Credentials>,
    pages: Option<&dyn ClientPages>,
    udp: bool,
) -> io::Result<Incoming> {
    let mut first = [0u8; 1];
    let peeked = client.peek(&mut first).await?;
    if peeked == 0 {
        return Err(io::ErrorKind::UnexpectedEof.into());
    }
    if first[0] == socks5::VERSION {
        socks5::read_request(client, credentials, udp)
            .await
            .map(Incoming::Proxy)
    } else {
        http::read_request(client, credentials, pages).await
    }
}

async fn send_success<S: AsyncWrite + Unpin>(client: &mut S, reply: Reply) -> io::Result<()> {
    match reply {
        Reply::Socks5 | Reply::Socks5Associate => {
            client
                .write_all(&socks5::reply(socks5::REP_SUCCEEDED))
                .await
        }
        Reply::HttpConnect => {
            client
                .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
                .await
        }
        Reply::HttpForward => Ok(()),
    }
}

async fn send_failure<S: AsyncWrite + Unpin>(client: &mut S, reply: Reply) -> io::Result<()> {
    match reply {
        Reply::Socks5 | Reply::Socks5Associate => {
            client
                .write_all(&socks5::reply(socks5::REP_GENERAL_FAILURE))
                .await
        }
        Reply::HttpConnect | Reply::HttpForward => {
            client
                .write_all(http::status_response(502, "Bad Gateway").as_bytes())
                .await
        }
    }
}

/// Answers a request whose outbound connect failed, then closes: with the
/// failure reply (unless the request was `answered` already), a 1x1 GIF for
/// a plain HTTP request a `REJECT-TINYGIF` rule refused, or nothing at all
/// for `REJECT-DROP` while the connection is held (see
/// [`reject::hold`]); when no hold slot is free a drop gets the failure
/// reply after all.
async fn answer_failure(
    mut client: TcpStream,
    reply: Reply,
    rejection: Option<RejectAction>,
    answered: bool,
) {
    match rejection {
        Some(RejectAction::Drop) => {
            if reject::hold(&mut client, reject::DROP_HOLD).await {
                return;
            }
        }
        Some(RejectAction::TinyGif) if reply == Reply::HttpForward && !answered => {
            let _ = client.write_all(&reject::tiny_gif_response()).await;
            close_gracefully(client).await;
            return;
        }
        _ => {}
    }
    if !answered {
        let _ = send_failure(&mut client, reply).await;
    }
    close_gracefully(client).await;
}

/// Sends FIN after an error reply and drains what the client still sends for
/// a moment. Dropping a socket with unread input makes the kernel answer with
/// a reset, and on Windows the reset discards the reply before the client
/// reads it.
async fn close_gracefully(mut client: TcpStream) {
    let _ = client.shutdown().await;
    let mut sink = [0u8; 1024];
    let mut drained = 0;
    let deadline = tokio::time::Instant::now() + LINGER;
    while drained < MAX_HEAD_BYTES {
        match tokio::time::timeout_at(deadline, client.read(&mut sink)).await {
            Ok(Ok(n)) if n > 0 => drained += n,
            _ => break,
        }
    }
}

async fn relay(mut client: TcpStream, mut remote: BoxStream, stats: &MixedStats) {
    if let Ok((up, down)) = tokio::io::copy_bidirectional_with_sizes(
        &mut client,
        &mut remote,
        RELAY_BUFFER_BYTES,
        RELAY_BUFFER_BYTES,
    )
    .await
    {
        stats.bytes_up.fetch_add(up, Ordering::Relaxed);
        stats.bytes_down.fetch_add(down, Ordering::Relaxed);
    }
}

/// Reads exactly `buf.len()` bytes; shared by both protocol parsers.
pub(crate) async fn read_exact<S: AsyncRead + Unpin>(
    stream: &mut S,
    buf: &mut [u8],
) -> io::Result<()> {
    tokio::io::AsyncReadExt::read_exact(stream, buf)
        .await
        .map(|_| ())
}

pub(crate) fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
