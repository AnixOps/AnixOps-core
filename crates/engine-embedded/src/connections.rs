//! Connection tracking: the client's connection list and live traffic.
//!
//! Every TCP connection and UDP flow the tunnel or the local proxy opens goes
//! through a [`Dispatcher`], which routes it, registers it with the
//! [`ConnectionTracker`] and wraps its stream so the bytes are counted per
//! connection. A closed connection moves to a short list of recent ones,
//! where connections that moved a lot of data outlive small ones.
//!
//! The list holds destinations (host names and addresses) and which rule and
//! node carried them: data the user asks for to see what their device does.
//! It lives in memory only, is returned only to an explicit `connections`
//! request and is never written to status, logs or errors. Payloads and
//! outbound settings never reach it.

use std::collections::{BTreeMap, VecDeque};
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, Weak};
use std::task::{Context, Poll};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use config_core::redirect::{RedirectHost, RedirectTable, RedirectTo};
use config_core::routing::{RejectKind, RouteNetwork, RouteQuery, RuleProtocol};
use engine_outbound::sniff::HttpRequestHead;
use engine_outbound::{
    BoxFuture, BoxStream, DatagramRecv, DatagramSend, RequestRouter, TargetAddr, TcpDialer,
    TcpOutbound, UdpFlow,
};
use futures::task::AtomicWaker;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::Notify;

use crate::capture::{self, CaptureStore, Direction};
use crate::config::DnsVia;
use crate::direct::{self, DirectOutbound};
use crate::dns_cache::{DnsCache, DnsPools, DnsReset};
use crate::fake_ip::FakeIpPool;
use crate::first_payload::ServerFirst;
use crate::lan_guard::{self, LanPeer};
use crate::routing::{DomainResolver, FlowSource, RouteInfo, RoutedOutbound};

/// Closed connections kept for the list, newest first.
pub const MAX_CLOSED_CONNECTIONS: usize = 128;
/// A closed connection that moved at least this many bytes is a large one:
/// it outlives the small ones in the closed list, so a download or speed test
/// stays visible while a page keeps opening small connections afterwards.
pub const LARGE_CONNECTION_BYTES: u64 = 1024 * 1024;
/// At most this many large connections are held back from eviction; past it
/// the oldest large one goes first.
pub const MAX_KEPT_LARGE_CONNECTIONS: usize = 64;
/// Shortest interval the traffic rates are measured over; calls closer
/// together report the previous rates.
const RATE_MIN_INTERVAL: Duration = Duration::from_millis(500);

/// How flows are routed, switchable while the engine runs.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    /// The config's rules and policy groups.
    #[default]
    Rule,
    /// Every flow to the global target of a routing config (its outbound for
    /// a config with one outbound).
    Global,
    /// Every flow direct, and every DNS server asked directly (the tunnel's
    /// queries and the names of Fake-IP flows alike), `proxy` ones included.
    Direct,
}

impl Mode {
    const ALL: [Self; 3] = [Self::Rule, Self::Global, Self::Direct];

    fn from_code(code: u8) -> Self {
        Self::ALL
            .into_iter()
            .find(|mode| *mode as u8 == code)
            .unwrap_or_default()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Network {
    Tcp,
    Udp,
}

impl Network {
    fn index(self) -> usize {
        match self {
            Self::Tcp => 0,
            Self::Udp => 1,
        }
    }

    /// The lower-case name, as the connection list writes it.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
        }
    }
}

/// One connection as the list shows it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ConnectionSnapshot {
    pub id: u64,
    pub network: Network,
    /// The destination's host name: the requested domain, or the TLS SNI or
    /// HTTP `Host` sniffed from an address target.
    pub host: Option<String>,
    /// The local process that opened the connection, when the desktop local
    /// proxy looked it up for `PROCESS-NAME` rules.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub process: Option<String>,
    /// The destination as requested, `address:port` or `domain:port`.
    pub destination: String,
    /// Where a `redirects` line sent the connection instead, and that line.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub redirect: Option<RedirectSnapshot>,
    pub rule: String,
    pub chain: Vec<String>,
    pub outbound: String,
    /// Unix time in milliseconds.
    pub started_at_ms: u64,
    pub ended_at_ms: Option<u64>,
    pub upload: u64,
    pub download: u64,
    /// `rejected` (a REJECT rule), `quic_blocked` (a UDP flow to port 443
    /// refused by `block_quic`), `quic_mitm_fallback` (QUIC to a decrypted
    /// host, refused so the app uses TCP), `lan_share_local_target` (a
    /// device using the LAN share asked DIRECT for this computer itself; see
    /// [`crate::lan_guard`]) or `connect_failed`.
    pub error: Option<&'static str>,
    /// Capture was on as the connection opened: `capture_connection` may
    /// have its bytes (see [`crate::capture`]).
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub captured: bool,
}

/// A rewritten destination: the new one and the `redirects` line that chose it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct RedirectSnapshot {
    pub destination: String,
    pub rule: String,
}

/// Totals since the tunnel started and the current rates in bytes per second.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct TrafficSnapshot {
    pub upload_total: u64,
    pub download_total: u64,
    pub upload_rate: u64,
    pub download_rate: u64,
    pub active: usize,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ConnectionsSnapshot {
    pub traffic: TrafficSnapshot,
    /// Oldest first.
    pub active: Vec<ConnectionSnapshot>,
    /// Newest first.
    pub closed: Vec<ConnectionSnapshot>,
}

struct Entry {
    id: u64,
    network: Network,
    host: Option<String>,
    process: Option<String>,
    destination: String,
    started_at_ms: u64,
    redirect: Mutex<Option<RedirectSnapshot>>,
    route: Mutex<RouteInfo>,
    upload: AtomicU64,
    download: AtomicU64,
    connected: AtomicBool,
    error: Mutex<Option<&'static str>>,
    /// Capture keeps this connection's bytes.
    captured: bool,
    aborted: AtomicBool,
    abort: Notify,
    read_waker: AtomicWaker,
    write_waker: AtomicWaker,
}

impl Entry {
    fn snapshot(&self, ended_at_ms: Option<u64>) -> ConnectionSnapshot {
        let route = lock(&self.route).clone();
        ConnectionSnapshot {
            id: self.id,
            network: self.network,
            host: self.host.clone(),
            process: self.process.clone(),
            destination: self.destination.clone(),
            redirect: lock(&self.redirect).clone(),
            rule: route.rule,
            chain: route.chain,
            outbound: route.outbound,
            started_at_ms: self.started_at_ms,
            ended_at_ms,
            upload: self.upload.load(Ordering::Relaxed),
            download: self.download.load(Ordering::Relaxed),
            error: *lock(&self.error),
            captured: self.captured,
        }
    }

    fn is_aborted(&self) -> bool {
        self.aborted.load(Ordering::Acquire)
    }

    fn abort(&self) {
        self.aborted.store(true, Ordering::Release);
        self.abort.notify_waiters();
        self.read_waker.wake();
        self.write_waker.wake();
    }

    /// Completes once the connection is closed from the list.
    async fn aborted(&self) {
        loop {
            let notified = self.abort.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self.is_aborted() {
                return;
            }
            notified.await;
        }
    }
}

struct RateSample {
    at: Instant,
    upload: u64,
    download: u64,
    upload_rate: u64,
    download_rate: u64,
}

/// Open and recently closed connections, with traffic totals.
pub struct ConnectionTracker {
    next_id: AtomicU64,
    active: Mutex<BTreeMap<u64, Arc<Entry>>>,
    closed: Mutex<VecDeque<ConnectionSnapshot>>,
    upload_total: AtomicU64,
    download_total: AtomicU64,
    sample: Mutex<RateSample>,
    started: Instant,
    /// Connections opened since the start, TCP then UDP.
    opened: [AtomicU64; 2],
    /// Connections closed since the start, by network and result (`ok` or the
    /// connection's error code).
    outcomes: Mutex<BTreeMap<(Network, &'static str), u64>>,
    /// The bytes of connections opened while capture is on.
    capture: Arc<CaptureStore>,
}

/// Counters since the tracker started, for the `metrics` control command.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TrackerCounters {
    pub uptime: Duration,
    pub opened_tcp: u64,
    pub opened_udp: u64,
    pub active_tcp: usize,
    pub active_udp: usize,
    /// Closed connections by network and result, sorted.
    pub closed: Vec<(Network, &'static str, u64)>,
}

impl Default for ConnectionTracker {
    fn default() -> Self {
        Self {
            next_id: AtomicU64::new(1),
            active: Mutex::default(),
            closed: Mutex::default(),
            upload_total: AtomicU64::new(0),
            download_total: AtomicU64::new(0),
            sample: Mutex::new(RateSample {
                at: Instant::now(),
                upload: 0,
                download: 0,
                upload_rate: 0,
                download_rate: 0,
            }),
            started: Instant::now(),
            opened: [AtomicU64::new(0), AtomicU64::new(0)],
            outcomes: Mutex::default(),
            capture: Arc::default(),
        }
    }
}

impl ConnectionTracker {
    /// Registers a new connection. It stays active until the returned guard
    /// and every stream holding it are dropped.
    pub(crate) fn open(
        self: &Arc<Self>,
        network: Network,
        target: &TargetAddr,
        host: Option<&str>,
        process: Option<&str>,
    ) -> Arc<ConnectionGuard> {
        let host = match target {
            TargetAddr::Domain(domain, _) => Some(domain.clone()),
            TargetAddr::Ip(_) => host.map(str::to_string),
        };
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let destination = target.to_string();
        let started_at_ms = unix_millis();
        let captured =
            self.capture
                .begin(id, network, host.as_deref(), &destination, started_at_ms);
        let entry = Arc::new(Entry {
            id,
            network,
            host,
            process: process.map(str::to_string),
            destination,
            started_at_ms,
            redirect: Mutex::default(),
            route: Mutex::default(),
            upload: AtomicU64::new(0),
            download: AtomicU64::new(0),
            connected: AtomicBool::new(false),
            error: Mutex::new(None),
            captured,
            aborted: AtomicBool::new(false),
            abort: Notify::new(),
            read_waker: AtomicWaker::new(),
            write_waker: AtomicWaker::new(),
        });
        self.opened[network.index()].fetch_add(1, Ordering::Relaxed);
        lock(&self.active).insert(entry.id, entry.clone());
        Arc::new(ConnectionGuard {
            tracker: self.clone(),
            entry,
        })
    }

    /// The capture switch and what it kept; see [`crate::capture`].
    pub fn capture(&self) -> &Arc<CaptureStore> {
        &self.capture
    }

    pub fn traffic(&self) -> TrafficSnapshot {
        let upload = self.upload_total.load(Ordering::Relaxed);
        let download = self.download_total.load(Ordering::Relaxed);
        let now = Instant::now();
        let mut sample = lock(&self.sample);
        let elapsed = now.duration_since(sample.at);
        if elapsed >= RATE_MIN_INTERVAL {
            let millis = elapsed.as_millis().max(1);
            let rate = |now: u64, then: u64| {
                u64::try_from(u128::from(now.saturating_sub(then)) * 1000 / millis)
                    .unwrap_or(u64::MAX)
            };
            sample.upload_rate = rate(upload, sample.upload);
            sample.download_rate = rate(download, sample.download);
            sample.at = now;
            sample.upload = upload;
            sample.download = download;
        }
        TrafficSnapshot {
            upload_total: upload,
            download_total: download,
            upload_rate: sample.upload_rate,
            download_rate: sample.download_rate,
            active: lock(&self.active).len(),
        }
    }

    pub fn connections(&self) -> ConnectionsSnapshot {
        let traffic = self.traffic();
        let active = lock(&self.active)
            .values()
            .map(|entry| entry.snapshot(None))
            .collect();
        let closed = lock(&self.closed).iter().cloned().collect();
        ConnectionsSnapshot {
            traffic,
            active,
            closed,
        }
    }

    /// Counters since the start: opened, active and closed connections.
    pub fn counters(&self) -> TrackerCounters {
        let (mut active_tcp, mut active_udp) = (0, 0);
        for entry in lock(&self.active).values() {
            match entry.network {
                Network::Tcp => active_tcp += 1,
                Network::Udp => active_udp += 1,
            }
        }
        TrackerCounters {
            uptime: self.started.elapsed(),
            opened_tcp: self.opened[Network::Tcp.index()].load(Ordering::Relaxed),
            opened_udp: self.opened[Network::Udp.index()].load(Ordering::Relaxed),
            active_tcp,
            active_udp,
            closed: lock(&self.outcomes)
                .iter()
                .map(|(&(network, result), &count)| (network, result, count))
                .collect(),
        }
    }

    /// Closes one active connection; `false` when it is not active.
    pub fn close(&self, id: u64) -> bool {
        let entry = lock(&self.active).get(&id).cloned();
        match entry {
            Some(entry) => {
                entry.abort();
                true
            }
            None => false,
        }
    }

    /// Closes every active connection and returns how many there were.
    pub fn close_all(&self) -> usize {
        let entries: Vec<_> = lock(&self.active).values().cloned().collect();
        for entry in &entries {
            entry.abort();
        }
        entries.len()
    }

    fn finish(&self, entry: &Entry) {
        if !entry.connected.load(Ordering::Relaxed) {
            let mut error = lock(&entry.error);
            if error.is_none() {
                *error = Some("connect_failed");
            }
        }
        let removed = lock(&self.active).remove(&entry.id);
        if removed.is_none() {
            return;
        }
        let snapshot = entry.snapshot(Some(unix_millis()));
        if entry.captured {
            self.capture
                .end(entry.id, snapshot.ended_at_ms.unwrap_or_default());
        }
        *lock(&self.outcomes)
            .entry((entry.network, snapshot.error.unwrap_or("ok")))
            .or_default() += 1;
        let mut closed = lock(&self.closed);
        closed.push_front(snapshot);
        trim_closed(&mut closed);
    }
}

fn is_large(connection: &ConnectionSnapshot) -> bool {
    connection.upload.saturating_add(connection.download) >= LARGE_CONNECTION_BYTES
}

/// Drops one closed connection once the list is over its size: the oldest
/// small one, so large connections survive a burst of small ones, or the
/// oldest large one when more than [`MAX_KEPT_LARGE_CONNECTIONS`] are kept.
/// The newest connection is never the one dropped while an older one can go.
fn trim_closed(closed: &mut VecDeque<ConnectionSnapshot>) {
    while closed.len() > MAX_CLOSED_CONNECTIONS {
        let large = closed
            .iter()
            .filter(|connection| is_large(connection))
            .count();
        let evict = if large > MAX_KEPT_LARGE_CONNECTIONS {
            (0..closed.len()).rev().find(|&i| is_large(&closed[i]))
        } else {
            (1..closed.len()).rev().find(|&i| !is_large(&closed[i]))
        };
        closed.remove(evict.unwrap_or(closed.len() - 1));
    }
}

/// Keeps a connection in the active list; dropping the last one moves it to
/// the closed list.
pub(crate) struct ConnectionGuard {
    tracker: Arc<ConnectionTracker>,
    entry: Arc<Entry>,
}

impl ConnectionGuard {
    fn set_route(&self, route: RouteInfo) {
        *lock(&self.entry.route) = route;
    }

    fn set_redirect(&self, redirect: RedirectSnapshot) {
        *lock(&self.entry.redirect) = Some(redirect);
    }

    fn fail(&self, error: &'static str) {
        *lock(&self.entry.error) = Some(error);
    }

    fn connected(&self) {
        self.entry.connected.store(true, Ordering::Relaxed);
    }

    fn count_upload(&self, bytes: usize) {
        let bytes = bytes as u64;
        self.entry.upload.fetch_add(bytes, Ordering::Relaxed);
        self.tracker
            .upload_total
            .fetch_add(bytes, Ordering::Relaxed);
    }

    /// Keeps `data` when capture keeps this connection.
    fn capture(&self, direction: Direction, data: &[u8]) {
        if self.entry.captured {
            self.tracker.capture.record(self.entry.id, direction, data);
        }
    }

    fn count_download(&self, bytes: usize) {
        let bytes = bytes as u64;
        self.entry.download.fetch_add(bytes, Ordering::Relaxed);
        self.tracker
            .download_total
            .fetch_add(bytes, Ordering::Relaxed);
    }
}

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        self.tracker.finish(&self.entry);
    }
}

fn closed_from_list() -> io::Error {
    io::Error::new(
        io::ErrorKind::ConnectionAborted,
        "connection closed from the connection list",
    )
}

/// A connected stream counted into its connection.
struct TrackedStream {
    inner: BoxStream,
    guard: Arc<ConnectionGuard>,
}

impl AsyncRead for TrackedStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let entry = &this.guard.entry;
        entry.read_waker.register(cx.waker());
        if entry.is_aborted() {
            return Poll::Ready(Err(closed_from_list()));
        }
        let before = buf.filled().len();
        let result = Pin::new(&mut this.inner).poll_read(cx, buf);
        let read = buf.filled().len() - before;
        if read > 0 {
            this.guard.count_download(read);
            this.guard.capture(Direction::Down, &buf.filled()[before..]);
        }
        result
    }
}

impl AsyncWrite for TrackedStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let entry = &this.guard.entry;
        entry.write_waker.register(cx.waker());
        if entry.is_aborted() {
            return Poll::Ready(Err(closed_from_list()));
        }
        let result = Pin::new(&mut this.inner).poll_write(cx, buf);
        if let Poll::Ready(Ok(written)) = &result {
            this.guard.count_upload(*written);
            this.guard.capture(Direction::Up, &buf[..*written]);
        }
        result
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

struct TrackedSend {
    inner: Box<dyn DatagramSend>,
    guard: Arc<ConnectionGuard>,
}

impl DatagramSend for TrackedSend {
    fn send<'a>(&'a mut self, payload: &'a [u8]) -> BoxFuture<'a, io::Result<()>> {
        Box::pin(async move {
            if self.guard.entry.is_aborted() {
                return Err(closed_from_list());
            }
            self.inner.send(payload).await?;
            self.guard.count_upload(payload.len());
            self.guard.capture(Direction::Up, payload);
            Ok(())
        })
    }
}

struct TrackedRecv {
    inner: Box<dyn DatagramRecv>,
    guard: Arc<ConnectionGuard>,
}

impl DatagramRecv for TrackedRecv {
    fn recv(&mut self) -> BoxFuture<'_, io::Result<Vec<u8>>> {
        Box::pin(async move {
            let guard = self.guard.clone();
            let datagram = tokio::select! {
                datagram = self.inner.recv() => datagram?,
                _ = guard.entry.aborted() => return Err(closed_from_list()),
            };
            guard.count_download(datagram.len());
            guard.capture(Direction::Down, &datagram);
            Ok(datagram)
        })
    }
}

/// Routes, tracks and connects every flow of a running tunnel or local proxy.
///
/// It is itself a [`TcpOutbound`], so inbounds that take one (the local
/// proxy, HTTPS decryption) need no change; the packet tunnel calls
/// [`Dispatcher::connect_flow`] to add the host it sniffed.
pub struct Dispatcher {
    outbound: Arc<dyn TcpOutbound>,
    routed: Option<Arc<RoutedOutbound>>,
    /// The outbound of the direct mode.
    direct: Arc<dyn TcpOutbound>,
    mode: AtomicU8,
    tracker: Arc<ConnectionTracker>,
    /// Destination rewrites applied before routing, in every mode.
    redirects: Arc<RedirectTable>,
    /// Fake-IP table: flows to its addresses go out by name.
    fake_ip: Option<Arc<FakeIpPool>>,
    /// Resolves the name of a Fake-IP flow that goes DIRECT (the `dns`
    /// section of a routed config); without one the direct dialer gets the
    /// name.
    resolver: Option<Arc<dyn DomainResolver>>,
    /// `block_quic`: refuse UDP flows to [`QUIC_PORT`]; see
    /// [`Dispatcher::set_block_quic`].
    block_quic: AtomicBool,
    /// Destinations whose packet tunnel flows connect without waiting for
    /// the app's first bytes; forgotten on `reset_network`.
    server_first: Arc<ServerFirst>,
    /// The DNS answers and upstream connections of the tunnels running on
    /// this dispatcher, for [`Dispatcher::reset_dns`].
    tunnel_dns: Mutex<Vec<TunnelDns>>,
}

/// A running tunnel's DNS cache and upstream connection pools.
type TunnelDns = (Weak<Mutex<DnsCache>>, Weak<DnsPools>);

/// The port QUIC (HTTP/3) runs on: `block_quic` refuses UDP flows to it.
pub const QUIC_PORT: u16 = 443;

/// The rule a flow refused by `block_quic` shows in the connection list.
pub const BLOCK_QUIC_RULE: &str = "BLOCK-QUIC";

/// The rule a QUIC flow to a decrypted host shows in the connection list:
/// refused so the app falls back to TCP, where HTTPS decryption takes it.
pub const MITM_QUIC_RULE: &str = "MITM-QUIC";

impl Dispatcher {
    /// Every flow through `outbound`, as a config with one outbound runs. The
    /// direct mode uses the system's sockets; see [`Dispatcher::with_direct`].
    pub fn single(outbound: Arc<dyn TcpOutbound>) -> Self {
        Self {
            outbound,
            routed: None,
            direct: Arc::new(DirectOutbound::new(Arc::new(TcpDialer))),
            mode: AtomicU8::new(Mode::Rule as u8),
            tracker: Arc::default(),
            redirects: Arc::default(),
            fake_ip: None,
            resolver: None,
            block_quic: AtomicBool::new(false),
            server_first: Arc::default(),
            tunnel_dns: Mutex::default(),
        }
    }

    /// Flows routed by the rules and groups of `routed`; the direct mode uses
    /// its DIRECT outbound.
    pub fn routed(routed: Arc<RoutedOutbound>) -> Self {
        Self {
            outbound: routed.clone(),
            direct: routed.direct().clone(),
            resolver: Some(routed.resolver().clone()),
            routed: Some(routed),
            mode: AtomicU8::new(Mode::Rule as u8),
            tracker: Arc::default(),
            redirects: Arc::default(),
            fake_ip: None,
            block_quic: AtomicBool::new(false),
            server_first: Arc::default(),
            tunnel_dns: Mutex::default(),
        }
    }

    /// Sends flows to the addresses of `pool` out by the name each address
    /// stands for; see [`crate::fake_ip`]. The tunnel answers DNS from the
    /// same pool.
    pub fn with_fake_ip(mut self, pool: Option<Arc<FakeIpPool>>) -> Self {
        self.fake_ip = pool;
        self
    }

    /// What the packet tunnel learned about destinations that stay silent
    /// until the server speaks; see [`crate::first_payload`].
    pub fn server_first(&self) -> &ServerFirst {
        &self.server_first
    }

    /// The Fake-IP table, when it is on.
    pub fn fake_ip(&self) -> Option<&Arc<FakeIpPool>> {
        self.fake_ip.as_ref()
    }

    /// The name target of a flow to a Fake-IP address, `Ok(None)` for any
    /// other flow, or an error when the address maps to no name and nothing
    /// was sniffed.
    fn unfake(&self, target: &TargetAddr, host: Option<&str>) -> io::Result<Option<TargetAddr>> {
        let (Some(pool), TargetAddr::Ip(address)) = (&self.fake_ip, target) else {
            return Ok(None);
        };
        if !pool.contains(address.ip()) {
            return Ok(None);
        }
        match pool.resolve_flow(address.ip(), host) {
            Some(name) => Ok(Some(TargetAddr::Domain(name, address.port()))),
            None => Err(io::Error::new(
                io::ErrorKind::AddrNotAvailable,
                "fake-ip address maps to no name",
            )),
        }
    }

    /// The target to hand `outbound` for a Fake-IP flow routed in `mode`: a
    /// DIRECT flow gets the address the `dns` section gives, so the name
    /// never goes to the system resolver (which may answer from the tunnel's
    /// own fake range). In the direct mode every DNS server is asked
    /// directly ([`DomainResolver::resolve_direct`]), so the flow does not
    /// depend on a node.
    async fn direct_target(
        &self,
        target: &TargetAddr,
        outbound: &dyn TcpOutbound,
        mode: Mode,
    ) -> io::Result<Option<TargetAddr>> {
        let (TargetAddr::Domain(name, port), Some(resolver)) = (target, &self.resolver) else {
            return Ok(None);
        };
        if outbound.protocol() != direct::PROTOCOL {
            return Ok(None);
        }
        let address = if mode == Mode::Direct {
            resolver.resolve_direct(name).await?
        } else {
            resolver.resolve(name).await?
        };
        if self
            .fake_ip
            .as_ref()
            .is_some_and(|pool| pool.contains(address))
        {
            return Err(io::Error::new(
                io::ErrorKind::AddrNotAvailable,
                "name resolved into the fake-ip range",
            ));
        }
        Ok(Some(TargetAddr::Ip(SocketAddr::new(address, *port))))
    }

    /// Rewrites the destination of every matching flow before it is routed;
    /// see [`config_core::redirect`]. The rules then route the new
    /// destination alone: the sniffed host no longer applies to it.
    pub fn with_redirects(mut self, redirects: RedirectTable) -> Self {
        self.redirects = Arc::new(redirects);
        self
    }

    /// The new destination of a flow a `redirects` line matches, with that
    /// line and whether the line named a new host, or `None`.
    fn redirect(
        &self,
        target: &TargetAddr,
        host: Option<&str>,
        origin: FlowOrigin<'_>,
        network: RouteNetwork,
        http: Option<&HttpRequestHead>,
    ) -> Option<(TargetAddr, String, bool)> {
        if self.redirects.is_empty() {
            return None;
        }
        let mut query = match target {
            TargetAddr::Ip(addr) => RouteQuery::ip(addr.ip()),
            TargetAddr::Domain(domain, _) => RouteQuery::domain(domain.clone()),
        }
        .with_port(target.port())
        .with_network(network)
        .with_source(origin.source.address, origin.source.in_port)
        .with_source_port(origin.source.port);
        if query.domain.is_none() {
            query.domain = host.map(str::to_string);
        }
        query.process = origin.process.map(str::to_string);
        if let Some(http) = http {
            query.user_agent.clone_from(&http.user_agent);
            query.url.clone_from(&http.url);
        }
        let rule = self.redirects.find(&query)?;
        let new_host = rule.to.host != RedirectHost::Keep;
        Some((
            redirected_target(target, &rule.to),
            rule.to_string(),
            new_host,
        ))
    }

    /// Replaces the outbound of the direct mode.
    pub fn with_direct(mut self, direct: Arc<dyn TcpOutbound>) -> Self {
        self.direct = direct;
        self
    }

    pub fn mode(&self) -> Mode {
        Mode::from_code(self.mode.load(Ordering::Relaxed))
    }

    /// Switches the mode for every later flow; open connections keep their
    /// route.
    pub fn set_mode(&self, mode: Mode) {
        self.mode.store(mode as u8, Ordering::Relaxed);
    }

    /// Whether UDP flows to port 443 are refused, so apps fall back from
    /// QUIC (HTTP/3) to TCP, where HTTPS decryption and domain rules see
    /// them.
    pub fn block_quic(&self) -> bool {
        self.block_quic.load(Ordering::Relaxed)
    }

    /// Turns `block_quic` on or off for every later UDP flow; open flows
    /// keep going. It holds in every mode, DIRECT included. The packet
    /// tunnel answers a refused datagram with ICMP port unreachable, so the
    /// app gives up on QUIC at once instead of waiting for a timeout.
    pub fn set_block_quic(&self, enabled: bool) {
        self.block_quic.store(enabled, Ordering::Relaxed);
    }

    /// The rule-based outbound of a routing config, for its policy groups.
    /// Whether flows should carry the name of their local process: the
    /// rule mode with a `PROCESS-NAME` rule.
    pub fn wants_process(&self) -> bool {
        self.mode() == Mode::Rule
            && self
                .routed
                .as_ref()
                .is_some_and(|routed| routed.uses_process())
    }

    pub fn routed_outbound(&self) -> Option<&Arc<RoutedOutbound>> {
        self.routed.as_ref()
    }

    /// [`TcpOutbound::reset_sessions`] on every outbound flows can take
    /// (the nodes, or the single outbound, and DIRECT), after the device
    /// changed networks or woke up. Returns the total dropped. The address
    /// family each server last connected with is forgotten too
    /// ([`engine_outbound::happy_eyeballs::forget_families`]): the new
    /// network may reach the other family better.
    pub fn reset_sessions(&self) -> usize {
        engine_outbound::happy_eyeballs::forget_families();
        let direct = if self.routed.is_some() {
            // The routed outbound resets its own DIRECT.
            0
        } else {
            self.direct.reset_sessions()
        };
        self.outbound.reset_sessions() + direct
    }

    pub fn tracker(&self) -> &Arc<ConnectionTracker> {
        &self.tracker
    }

    /// Lets [`Dispatcher::reset_dns`] reach a tunnel's DNS cache and
    /// upstream pools; they stay owned by the tunnel.
    pub fn attach_dns(&self, cache: &Arc<Mutex<DnsCache>>, pools: &Arc<DnsPools>) {
        let mut attached = self.tunnel_dns.lock().unwrap_or_else(|e| e.into_inner());
        attached.retain(|(cache, pools)| cache.strong_count() > 0 || pools.strong_count() > 0);
        attached.push((Arc::downgrade(cache), Arc::downgrade(pools)));
    }

    /// After the device changed networks: drops the answers the tunnels
    /// cached and the addresses the resolver of IP rules and Fake-IP DIRECT
    /// flows kept, and every upstream DNS connection kept for reuse. They
    /// came from (or ran over) the old network: split-horizon and carrier
    /// CDN answers no longer fit, and a kept connection would cost the next
    /// query half its budget before a new one is dialed. Exchanges in flight
    /// still answer their apps but cache nothing. Fake-IP mappings stay:
    /// apps still hold those addresses.
    pub fn reset_dns(&self) -> DnsReset {
        let mut reset = DnsReset::default();
        let attached = self
            .tunnel_dns
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        for (cache, pools) in attached {
            if let Some(cache) = cache.upgrade() {
                reset.flushed += cache.lock().unwrap_or_else(|e| e.into_inner()).clear();
            }
            if let Some(pools) = pools.upgrade() {
                reset.dropped += pools.clear();
            }
        }
        if let Some(resolver) = &self.resolver {
            reset += resolver.reset_network();
        }
        reset
    }

    /// The untracked outbound of the direct mode, for DNS servers reached
    /// directly.
    pub fn direct(&self) -> &Arc<dyn TcpOutbound> {
        &self.direct
    }

    /// The untracked outbound, for the tunnel's own DNS queries.
    pub fn outbound(&self) -> &Arc<dyn TcpOutbound> {
        &self.outbound
    }

    /// The untracked outbound for a query to the DNS server at `server`
    /// reached `via`: DIRECT for a `direct` server or in the direct mode;
    /// otherwise the global target in the global mode, and in the rule mode
    /// the node a rule picks for the server or else the global target (see
    /// [`RoutedOutbound::dns_outbound`]), so a `proxy` server is never asked
    /// in the clear because a rule said DIRECT. `None` when routing rejects.
    pub fn dns_outbound(&self, via: DnsVia, server: &TargetAddr) -> Option<Arc<dyn TcpOutbound>> {
        self.dns_outbound_as(via, server, None)
    }

    /// [`Self::dns_outbound`] for a query sent as `dns` (DoH or DoQ, see
    /// [`crate::dns::Upstream::rule_protocol`]), for `PROTOCOL,DOH` and
    /// `PROTOCOL,DOQ` rules.
    pub fn dns_outbound_as(
        &self,
        via: DnsVia,
        server: &TargetAddr,
        dns: Option<RuleProtocol>,
    ) -> Option<Arc<dyn TcpOutbound>> {
        if via == DnsVia::Direct || self.mode() == Mode::Direct {
            return Some(self.direct.clone());
        }
        match (&self.routed, self.mode()) {
            (Some(routed), Mode::Global) => routed.route_global().1,
            (Some(routed), _) => routed.dns_outbound_as(server, dns),
            (None, _) => Some(self.outbound.clone()),
        }
    }

    /// Picks the outbound for one flow in `mode` and records the decision.
    /// Returns the route too, so a failed connect can ask its groups to
    /// retest.
    #[allow(clippy::too_many_arguments)]
    async fn route(
        &self,
        mode: Mode,
        target: &TargetAddr,
        host: Option<&str>,
        origin: FlowOrigin<'_>,
        network: RouteNetwork,
        http: Option<&HttpRequestHead>,
        guard: &ConnectionGuard,
    ) -> io::Result<(Arc<dyn TcpOutbound>, RouteInfo)> {
        let (route, outbound) = match (mode, &self.routed) {
            (Mode::Direct, _) => (direct_route(), Some(self.direct.clone())),
            (Mode::Global, Some(routed)) => routed.route_global_flow().await,
            (Mode::Rule, Some(routed)) => {
                routed
                    .route_network_flow(target, host, origin.process, network, http, origin.source)
                    .await
            }
            (_, None) => (single_route(&*self.outbound), Some(self.outbound.clone())),
        };
        let reject = route.reject.unwrap_or_default();
        guard.set_route(route.clone());
        match outbound {
            Some(outbound) => Ok((outbound, route)),
            None => {
                guard.fail("rejected");
                Err(engine_outbound::reject::rejected(crate::reject::action(
                    reject,
                )))
            }
        }
    }

    /// A TCP connection routed as `route` failed to open: the health-checked
    /// groups it went through probe its member at once (see
    /// [`RoutedOutbound::report_failure`]).
    fn report_connect_failure(&self, route: &RouteInfo, error: &io::Error) {
        if error.kind() == io::ErrorKind::PermissionDenied {
            // Refused by a rule or policy inside the outbound, not a dead node.
            return;
        }
        if let Some(routed) = &self.routed {
            routed.report_failure(route);
        }
    }

    /// The outbound name (node id, `DIRECT` or `REJECT`) a request to
    /// `target` would get, the way [`Self::connect_http_flow`] routes it
    /// (Fake-IP names and redirects included), without connecting or
    /// listing anything. `None` unless the rule mode runs a rule that looks
    /// at requests (`URL-REGEX`, `USER-AGENT`): then every request of a
    /// connection goes where the connection went.
    pub async fn request_route(
        &self,
        target: &TargetAddr,
        host: Option<&str>,
        origin: FlowOrigin<'_>,
        http: Option<&HttpRequestHead>,
    ) -> Option<String> {
        if self.mode() != Mode::Rule {
            return None;
        }
        let routed = self
            .routed
            .as_ref()
            .filter(|routed| routed.uses_request())?;
        let unfaked = self.unfake(target, host).ok()?;
        let (target, host) = match &unfaked {
            Some(named) => (named, None),
            None => (target, host),
        };
        let redirected = self.redirect(target, host, origin, RouteNetwork::Tcp, http);
        let (target, host) = match &redirected {
            Some((new, _, _)) => (new, None),
            None => (target, host),
        };
        let (route, _) = routed
            .route_network_flow(
                target,
                host,
                origin.process,
                RouteNetwork::Tcp,
                http,
                origin.source,
            )
            .await;
        // Every REJECT variant refuses the request the same way.
        Some(if route.reject.is_some() {
            "REJECT".to_string()
        } else {
            route.outbound
        })
    }

    /// Opens a TCP connection to `target`. For an address target, `host` is
    /// the name sniffed from the flow, used for domain rules and the list.
    pub async fn connect_flow(
        &self,
        target: &TargetAddr,
        host: Option<&str>,
    ) -> io::Result<BoxStream> {
        self.connect_process_flow(target, host, None).await
    }

    /// Opens a TCP connection to `target` for the local process named
    /// `process`, which `PROCESS-NAME` rules match.
    pub async fn connect_process_flow(
        &self,
        target: &TargetAddr,
        host: Option<&str>,
        process: Option<&str>,
    ) -> io::Result<BoxStream> {
        let origin = FlowOrigin {
            process,
            ..FlowOrigin::default()
        };
        self.connect_tcp(target, host, origin, None).await
    }

    /// Opens a TCP connection to `target` for a flow from `origin` (the
    /// local process, the client's address and the listener port), which
    /// `PROCESS-NAME`, `SRC-IP` and `IN-PORT` rules match; `http` is the head
    /// of a plain HTTP request sniffed from the flow, if any.
    pub async fn connect_origin_flow(
        &self,
        target: &TargetAddr,
        host: Option<&str>,
        origin: FlowOrigin<'_>,
        http: Option<&HttpRequestHead>,
    ) -> io::Result<BoxStream> {
        self.connect_tcp(target, host, origin, http).await
    }

    /// Opens a TCP connection for a proxy listener's client: `process` is
    /// the local process that asked, for `PROCESS-NAME` rules, and `http` the
    /// head of its plain HTTP request, for `USER-AGENT` and `URL-REGEX` rules.
    pub async fn connect_client_flow(
        &self,
        target: &TargetAddr,
        process: Option<&str>,
        http: Option<&HttpRequestHead>,
    ) -> io::Result<BoxStream> {
        let origin = FlowOrigin {
            process,
            ..FlowOrigin::default()
        };
        self.connect_tcp(target, None, origin, http).await
    }

    /// [`Self::connect_flow`] with the head of a plain HTTP request sniffed
    /// from the flow's first bytes, for `USER-AGENT` and `URL-REGEX` rules.
    pub async fn connect_http_flow(
        &self,
        target: &TargetAddr,
        host: Option<&str>,
        http: Option<&HttpRequestHead>,
    ) -> io::Result<BoxStream> {
        self.connect_tcp(target, host, FlowOrigin::default(), http)
            .await
    }

    async fn connect_tcp(
        &self,
        target: &TargetAddr,
        host: Option<&str>,
        origin: FlowOrigin<'_>,
        http: Option<&HttpRequestHead>,
    ) -> io::Result<BoxStream> {
        let process = origin.process;
        // One mode for the whole flow: a `set_mode` meanwhile cannot route
        // it in one mode and resolve its name in another.
        let mode = self.mode();
        let unfaked = self.unfake(target, host)?;
        let (target, host) = match &unfaked {
            Some(named) => (named, None),
            None => (target, host),
        };
        let guard = self.tracker.open(Network::Tcp, target, host, process);
        if guard.entry.captured {
            // HTTPS decryption files its HTTP messages under this connection.
            capture::note_flow(&self.tracker.capture, guard.entry.id);
        }
        let redirected = self.redirect(target, host, origin, RouteNetwork::Tcp, http);
        let (target, host) = match &redirected {
            Some((new, rule, _)) => {
                guard.set_redirect(RedirectSnapshot {
                    destination: new.to_string(),
                    rule: rule.clone(),
                });
                (new, None)
            }
            None => (target, host),
        };
        let (outbound, route) = self
            .route(mode, target, host, origin, RouteNetwork::Tcp, http, &guard)
            .await?;
        // A device using the LAN share may not reach this computer itself
        // through DIRECT (see `crate::lan_guard`), unless a `redirects` line
        // the user wrote named the new host.
        let host_redirected = redirected
            .as_ref()
            .is_some_and(|(_, _, new_host)| *new_host);
        let lan_peer = origin
            .lan_peer
            .filter(|_| outbound.protocol() == direct::PROTOCOL && !host_redirected);
        if lan_peer.is_some() {
            if let TargetAddr::Domain(name, _) = target {
                if lan_guard::is_local_name(name) {
                    guard.fail(lan_guard::REFUSED);
                    return Err(lan_guard::refused());
                }
            }
        }
        // With a LAN peer the name is resolved here, the way a Fake-IP flow's
        // is, so the address checked is the address dialed.
        let resolved = if unfaked.is_some() || lan_peer.is_some() {
            self.direct_target(target, &*outbound, mode).await?
        } else {
            None
        };
        let named = resolved.or_else(|| proxied_name(target, host, &*outbound));
        let dial = named.as_ref().unwrap_or(target);
        let connected = match lan_peer {
            Some(peer) => self.connect_lan_peer(peer, &*outbound, dial, &guard).await,
            None => outbound.connect(dial).await,
        };
        let stream = match connected {
            Ok(stream) => stream,
            Err(error) => {
                self.report_connect_failure(&route, &error);
                return Err(error);
            }
        };
        guard.connected();
        Ok(Box::new(TrackedStream {
            inner: stream,
            guard,
        }))
    }

    /// Connects a DIRECT flow of a device using the LAN share to `target`,
    /// refusing it when any address of `target` is this computer itself, its
    /// loopback or link-local, or (on request) a private network; see
    /// [`crate::lan_guard`]. A name is resolved here (the way the DIRECT
    /// outbound would) and the checked addresses are dialed in turn, so a
    /// later lookup cannot answer with another address. An address in the
    /// Fake-IP range is refused too: dialing it would bring the flow back
    /// through the tunnel without its origin.
    async fn connect_lan_peer(
        &self,
        peer: LanPeer,
        outbound: &dyn TcpOutbound,
        target: &TargetAddr,
        guard: &ConnectionGuard,
    ) -> io::Result<BoxStream> {
        let addresses: Vec<SocketAddr> = match target {
            TargetAddr::Ip(address) => vec![*address],
            TargetAddr::Domain(name, port) => tokio::net::lookup_host((name.as_str(), *port))
                .await?
                .collect(),
        };
        if addresses.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "target did not resolve",
            ));
        }
        let fake = |address: IpAddr| {
            self.fake_ip
                .as_ref()
                .is_some_and(|pool| pool.contains(address))
        };
        if addresses.iter().any(|address| {
            fake(address.ip()) || lan_guard::refuses(peer, *address, lan_guard::is_own_address)
        }) {
            guard.fail(lan_guard::REFUSED);
            return Err(lan_guard::refused());
        }
        let mut last_error = None;
        for address in addresses {
            match outbound.connect(&TargetAddr::Ip(address)).await {
                Ok(stream) => return Ok(stream),
                Err(error) => last_error = Some(error),
            }
        }
        Err(last_error.unwrap_or_else(|| io::Error::from(io::ErrorKind::NotFound)))
    }

    /// The name the Fake-IP table gave `address`, if it is a fake address.
    pub fn fake_ip_name(&self, address: IpAddr) -> Option<String> {
        let pool = self.fake_ip.as_ref()?;
        if !pool.contains(address) {
            return None;
        }
        pool.lookup(address).map(|name| name.to_string())
    }

    /// Records a QUIC flow to `destination` refused because HTTPS to `host`
    /// is decrypted (see `FlowInterceptor::refuses_quic`): it shows in the
    /// connection list as rule [`MITM_QUIC_RULE`], error
    /// `quic_mitm_fallback`.
    pub fn refuse_quic_for_decryption(&self, destination: SocketAddr, host: &str) {
        let guard = self
            .tracker
            .open(Network::Udp, &TargetAddr::Ip(destination), Some(host), None);
        guard.set_route(RouteInfo {
            rule: MITM_QUIC_RULE.to_string(),
            chain: vec!["REJECT".to_string()],
            outbound: "REJECT".to_string(),
            reject: Some(RejectKind::Reject),
        });
        guard.fail("quic_mitm_fallback");
    }

    /// Opens a UDP flow to `target`.
    pub async fn open_udp_flow(
        &self,
        target: &TargetAddr,
        host: Option<&str>,
    ) -> io::Result<UdpFlow> {
        self.open_origin_udp_flow(target, host, FlowOrigin::default())
            .await
    }

    /// [`Self::open_udp_flow`] for a flow from `origin`, which `SRC-IP` and
    /// `IN-PORT` rules match.
    pub async fn open_origin_udp_flow(
        &self,
        target: &TargetAddr,
        host: Option<&str>,
        origin: FlowOrigin<'_>,
    ) -> io::Result<UdpFlow> {
        // One mode for the whole flow, as for TCP.
        let mode = self.mode();
        let unfaked = self.unfake(target, host)?;
        let (target, host) = match &unfaked {
            Some(named) => (named, None),
            None => (target, host),
        };
        let guard = self.tracker.open(Network::Udp, target, host, None);
        // The port the app asked for: a redirect does not let QUIC through.
        if target.port() == QUIC_PORT && self.block_quic() {
            guard.set_route(block_quic_route());
            guard.fail("quic_blocked");
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "QUIC blocked by block_quic",
            ));
        }
        let redirected = self.redirect(target, host, origin, RouteNetwork::Udp, None);
        let (target, host) = match &redirected {
            Some((new, rule, _)) => {
                guard.set_redirect(RedirectSnapshot {
                    destination: new.to_string(),
                    rule: rule.clone(),
                });
                (new, None)
            }
            None => (target, host),
        };
        // UDP failures do not retest: a node without UDP relay still passes
        // the (TCP) health check, so a retest would only cost a dial.
        let (outbound, _) = self
            .route(mode, target, host, origin, RouteNetwork::Udp, None, &guard)
            .await?;
        let resolved = if unfaked.is_some() {
            self.direct_target(target, &*outbound, mode).await?
        } else {
            None
        };
        let flow = outbound
            .open_udp(resolved.as_ref().unwrap_or(target))
            .await?;
        guard.connected();
        Ok(UdpFlow::new(
            Box::new(TrackedSend {
                inner: flow.send,
                guard: guard.clone(),
            }),
            Box::new(TrackedRecv {
                inner: flow.recv,
                guard,
            }),
        ))
    }

    /// A [`TcpOutbound`] view that adds `host` to every connection, for a
    /// flow handed to the HTTPS decryption interceptor.
    pub fn with_host<'a>(&'a self, host: &'a str) -> HostedDispatcher<'a> {
        self.with_request(host, None)
    }

    /// [`Dispatcher::with_host`] that also routes by `http`, the first
    /// request of a plain HTTP flow, for `USER-AGENT` and `URL-REGEX` rules.
    pub fn with_request<'a>(
        &'a self,
        host: &'a str,
        http: Option<&'a HttpRequestHead>,
    ) -> HostedDispatcher<'a> {
        self.with_origin_request(host, http, FlowSource::default())
    }

    /// [`Self::with_request`] for a flow from `source`, which `SRC-IP` and
    /// `IN-PORT` rules match.
    pub fn with_origin_request<'a>(
        &'a self,
        host: &'a str,
        http: Option<&'a HttpRequestHead>,
        source: FlowSource,
    ) -> HostedDispatcher<'a> {
        HostedDispatcher {
            dispatcher: self,
            host,
            http,
            origin: FlowOrigin {
                process: None,
                source,
                lan_peer: None,
            },
            requested: None,
        }
    }

    /// [`Self::with_origin_request`] for a flow a proxy listener's client
    /// asked for as `requested` (a name or an address), for the decrypting
    /// listeners ([`crate::local_proxy`]): the connection and every
    /// per-request route go to `requested`, not to the placeholder address
    /// the interceptor holds for a name; `host`, read from the flow, names
    /// only an address target; `origin` also carries the client's process
    /// label, for `PROCESS-NAME` rules.
    pub fn with_requested_target<'a>(
        &'a self,
        requested: &'a TargetAddr,
        host: &'a str,
        http: Option<&'a HttpRequestHead>,
        origin: FlowOrigin<'a>,
    ) -> HostedDispatcher<'a> {
        HostedDispatcher {
            dispatcher: self,
            host,
            http,
            origin,
            requested: Some(requested),
        }
    }
}

impl TcpOutbound for Dispatcher {
    fn protocol(&self) -> &'static str {
        self.outbound.protocol()
    }

    fn reset_sessions(&self) -> usize {
        Dispatcher::reset_sessions(self)
    }

    fn connect<'a>(&'a self, target: &'a TargetAddr) -> BoxFuture<'a, io::Result<BoxStream>> {
        Box::pin(self.connect_flow(target, None))
    }

    fn open_udp<'a>(&'a self, target: &'a TargetAddr) -> BoxFuture<'a, io::Result<UdpFlow>> {
        Box::pin(self.open_udp_flow(target, None))
    }
}

/// Who opened a flow: the local process (for `PROCESS-NAME`), the client's
/// address and listener port (for `SRC-IP` and `IN-PORT`), and whether it is
/// another device on the local network using the LAN share.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FlowOrigin<'a> {
    pub process: Option<&'a str>,
    pub source: FlowSource,
    /// Set for a flow of another device through the LAN share: DIRECT may
    /// not take it to this computer itself; see [`crate::lan_guard`].
    pub lan_peer: Option<LanPeer>,
}

/// See [`Dispatcher::with_host`] and [`Dispatcher::with_requested_target`].
/// The packet tunnel and the proxy listeners hand the interceptor this same
/// view, so a decrypted connection is routed request by request the same
/// way whichever way it came in.
pub struct HostedDispatcher<'a> {
    dispatcher: &'a Dispatcher,
    host: &'a str,
    http: Option<&'a HttpRequestHead>,
    origin: FlowOrigin<'a>,
    /// What a proxy listener's client asked for, which replaces the target
    /// the interceptor passes in.
    requested: Option<&'a TargetAddr>,
}

impl HostedDispatcher<'_> {
    /// The target and host a connection for the interceptor's `target` is
    /// routed and opened with. The connection, its route and every
    /// request's route must use the same pair, or a request routed like
    /// its connection would look like a switch to another outbound.
    fn flow<'b>(&'b self, target: &'b TargetAddr) -> (&'b TargetAddr, Option<&'b str>) {
        match self.requested {
            // A name the client asked for is routed by itself; an address
            // by the host the interceptor read from the flow.
            Some(requested) => (
                requested,
                matches!(requested, TargetAddr::Ip(_)).then_some(self.host),
            ),
            None => (target, Some(self.host)),
        }
    }
}

impl TcpOutbound for HostedDispatcher<'_> {
    fn protocol(&self) -> &'static str {
        self.dispatcher.protocol()
    }

    fn request_router(&self) -> Option<&dyn RequestRouter> {
        Some(self)
    }

    fn connect<'a>(&'a self, target: &'a TargetAddr) -> BoxFuture<'a, io::Result<BoxStream>> {
        let (target, host) = self.flow(target);
        Box::pin(
            self.dispatcher
                .connect_origin_flow(target, host, self.origin, self.http),
        )
    }

    fn open_udp<'a>(&'a self, target: &'a TargetAddr) -> BoxFuture<'a, io::Result<UdpFlow>> {
        // The LAN share does not answer UDP ASSOCIATE, and the UDP path
        // has no `crate::lan_guard` check: a LAN device's flow gets none.
        if self.origin.lan_peer.is_some() {
            return Box::pin(async { Err(lan_guard::refused()) });
        }
        let (target, host) = self.flow(target);
        Box::pin(
            self.dispatcher
                .open_origin_udp_flow(target, host, self.origin),
        )
    }
}

/// A decrypted connection's requests are routed with the claimed host and,
/// without a request of their own, the first plain HTTP request the flow
/// was opened with.
impl RequestRouter for HostedDispatcher<'_> {
    fn request_route<'a>(
        &'a self,
        target: &'a TargetAddr,
        request: Option<&'a HttpRequestHead>,
    ) -> BoxFuture<'a, Option<String>> {
        let (target, host) = self.flow(target);
        Box::pin(
            self.dispatcher
                .request_route(target, host, self.origin, request.or(self.http)),
        )
    }

    fn connect_request<'a>(
        &'a self,
        target: &'a TargetAddr,
        request: &'a HttpRequestHead,
    ) -> BoxFuture<'a, io::Result<BoxStream>> {
        let (target, host) = self.flow(target);
        Box::pin(
            self.dispatcher
                .connect_origin_flow(target, host, self.origin, Some(request)),
        )
    }
}

/// `target` rewritten by `to`: its host, its port, or both.
fn redirected_target(target: &TargetAddr, to: &RedirectTo) -> TargetAddr {
    let port = to.port.unwrap_or_else(|| target.port());
    match (&to.host, target) {
        (RedirectHost::Ip(ip), _) => TargetAddr::Ip(SocketAddr::new(*ip, port)),
        (RedirectHost::Domain(domain), _) => TargetAddr::Domain(domain.clone(), port),
        (RedirectHost::Keep, TargetAddr::Ip(addr)) => {
            TargetAddr::Ip(SocketAddr::new(addr.ip(), port))
        }
        (RedirectHost::Keep, TargetAddr::Domain(domain, _)) => {
            TargetAddr::Domain(domain.clone(), port)
        }
    }
}

/// The route of a config with one outbound.
fn single_route(outbound: &dyn TcpOutbound) -> RouteInfo {
    let name = match outbound.protocol() {
        crate::direct::PROTOCOL => "DIRECT".to_string(),
        protocol => protocol.to_string(),
    };
    RouteInfo {
        rule: "DEFAULT".to_string(),
        chain: vec![name.clone()],
        outbound: name,
        reject: None,
    }
}

/// Outbounds that reach an address themselves rather than through a proxy
/// that resolves names on the far side.
// "wireguard" is `crate::wireguard::PROTOCOL`, which only exists with that feature.
const ADDRESS_OUTBOUNDS: [&str; 4] = [crate::direct::PROTOCOL, "wireguard", "iwan", "mesh"];

/// The name to send a proxy instead of an IPv6 address the flow announced.
///
/// The packet tunnel installs an IPv6 default route and its DNS answers AAAA
/// records, so a browser connects to a site's IPv6 address first. Many proxy
/// servers have no IPv6 egress, so that connection is closed by the server
/// after the local stack has accepted it, and the browser shows
/// "connection closed" instead of falling back to IPv4 (curl -4 works,
/// Chrome does not). Sending the sniffed name lets the server resolve the
/// site with the address family it has. IPv4 targets and outbounds that
/// dial the address themselves keep the address.
fn proxied_name(
    target: &TargetAddr,
    host: Option<&str>,
    outbound: &dyn TcpOutbound,
) -> Option<TargetAddr> {
    let (TargetAddr::Ip(address), Some(host)) = (target, host) else {
        return None;
    };
    if !address.is_ipv6() || ADDRESS_OUTBOUNDS.contains(&outbound.protocol()) {
        return None;
    }
    if host.parse::<std::net::IpAddr>().is_ok() {
        return None;
    }
    Some(TargetAddr::Domain(host.to_string(), address.port()))
}

/// The route of the direct mode.
fn block_quic_route() -> RouteInfo {
    RouteInfo {
        rule: BLOCK_QUIC_RULE.to_string(),
        chain: vec!["REJECT".to_string()],
        outbound: "REJECT".to_string(),
        reject: Some(RejectKind::Reject),
    }
}

fn direct_route() -> RouteInfo {
    RouteInfo {
        rule: "MODE,direct".to_string(),
        chain: vec!["DIRECT".to_string()],
        outbound: "DIRECT".to_string(),
        reject: None,
    }
}

fn unix_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

/// Locks `mutex`, recovering the data when a panic poisoned it: every value
/// behind these locks stays consistent between statements.
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

#[cfg(test)]
mod lan_peer_tests {
    use super::*;

    /// Accepts every connection without dialing, recording the target.
    struct Record {
        protocol: &'static str,
        seen: Mutex<Vec<String>>,
    }

    impl Record {
        fn new(protocol: &'static str) -> Arc<Self> {
            Arc::new(Self {
                protocol,
                seen: Mutex::default(),
            })
        }

        fn seen(&self) -> Vec<String> {
            lock(&self.seen).clone()
        }
    }

    impl TcpOutbound for Record {
        fn protocol(&self) -> &'static str {
            self.protocol
        }

        fn connect<'a>(&'a self, target: &'a TargetAddr) -> BoxFuture<'a, io::Result<BoxStream>> {
            Box::pin(async move {
                lock(&self.seen).push(target.to_string());
                let (client, _server) = tokio::io::duplex(64);
                Ok(Box::new(client) as BoxStream)
            })
        }
    }

    /// A `dns` section that answers from a fixed table.
    struct Names;

    impl DomainResolver for Names {
        fn resolve<'a>(&'a self, domain: &'a str) -> BoxFuture<'a, io::Result<IpAddr>> {
            Box::pin(async move {
                match domain {
                    // DNS rebinding: a public-looking name that answers loopback.
                    "rebind.example" => Ok("127.0.0.1".parse().unwrap()),
                    "docker.example" => Ok("::ffff:127.0.0.2".parse().unwrap()),
                    "printer.example" => Ok("192.168.213.40".parse().unwrap()),
                    _ => Err(io::Error::new(io::ErrorKind::NotFound, "no such name")),
                }
            })
        }
    }

    fn runtime() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
    }

    fn ip(address: &str) -> TargetAddr {
        TargetAddr::Ip(address.parse().unwrap())
    }

    fn name(name: &str, port: u16) -> TargetAddr {
        TargetAddr::Domain(name.to_string(), port)
    }

    /// A phone at 192.168.1.23 that reached the share on 192.168.1.5.
    fn phone(block_private_networks: bool) -> FlowOrigin<'static> {
        FlowOrigin {
            process: Some("LAN 192.168.1.23"),
            source: FlowSource {
                address: Some("192.168.1.23".parse().unwrap()),
                in_port: Some(8899),
                port: Some(50000),
            },
            lan_peer: Some(LanPeer {
                via: "192.168.1.5".parse().unwrap(),
                share_port: 8899,
                block_private_networks,
            }),
        }
    }

    fn with_names(dispatcher: Dispatcher) -> Dispatcher {
        Dispatcher {
            resolver: Some(Arc::new(Names)),
            ..dispatcher
        }
    }

    async fn connect(
        dispatcher: &Dispatcher,
        target: &TargetAddr,
        origin: FlowOrigin<'_>,
    ) -> io::Result<()> {
        dispatcher
            .connect_origin_flow(target, None, origin, None)
            .await
            .map(drop)
    }

    #[test]
    fn devices_on_the_lan_never_reach_this_computer_through_direct() {
        runtime().block_on(async {
            let direct = Record::new(direct::PROTOCOL);
            let dispatcher = with_names(Dispatcher::single(direct.clone()));
            for target in [
                ip("127.0.0.1:6379"),
                ip("127.0.0.53:53"),
                ip("[::1]:2375"),
                ip("[::ffff:127.0.0.1]:8890"),
                ip("0.0.0.0:9477"),
                ip("169.254.169.254:80"),
                ip("[fe80::1]:80"),
                name("localhost", 8890),
                name("App.Localhost.", 3000),
                name("rebind.example", 6379),
                name("docker.example", 2375),
            ] {
                let error = connect(&dispatcher, &target, phone(false))
                    .await
                    .expect_err(&target.to_string());
                assert_eq!(error.kind(), io::ErrorKind::PermissionDenied, "{target}");
            }
            assert!(direct.seen().is_empty(), "{:?}", direct.seen());
            let closed = dispatcher.tracker().connections().closed;
            assert_eq!(closed.len(), 11);
            assert!(closed
                .iter()
                .all(|connection| connection.error == Some(lan_guard::REFUSED)
                    && connection.outbound == "DIRECT"));

            // Other devices on the network and the internet stay reachable;
            // a name is dialed at the address that was checked.
            connect(&dispatcher, &ip("192.168.213.40:80"), phone(false))
                .await
                .unwrap();
            connect(&dispatcher, &name("printer.example", 631), phone(false))
                .await
                .unwrap();
            connect(&dispatcher, &ip("93.184.216.34:443"), phone(false))
                .await
                .unwrap();
            assert_eq!(
                direct.seen(),
                [
                    "192.168.213.40:80",
                    "192.168.213.40:631",
                    "93.184.216.34:443"
                ]
            );
        });
    }

    #[test]
    fn names_resolved_by_the_system_are_checked_too() {
        runtime().block_on(async {
            let direct = Record::new(direct::PROTOCOL);
            // No `dns` section: the name goes to the system resolver, as the
            // DIRECT outbound would send it.
            let dispatcher = Dispatcher::single(direct.clone());
            let error = connect(&dispatcher, &name("127.0.0.1", 6379), phone(false))
                .await
                .unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
            let error = connect(&dispatcher, &name("localhost", 6379), phone(false))
                .await
                .unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
            assert!(direct.seen().is_empty(), "{:?}", direct.seen());
        });
    }

    #[test]
    fn the_direct_mode_is_checked_like_a_direct_rule() {
        runtime().block_on(async {
            let node = Record::new("vless");
            let direct = Record::new(direct::PROTOCOL);
            let dispatcher =
                with_names(Dispatcher::single(node.clone()).with_direct(direct.clone()));
            dispatcher.set_mode(Mode::Direct);
            let error = connect(&dispatcher, &ip("127.0.0.1:6379"), phone(false))
                .await
                .unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
            assert!(direct.seen().is_empty());

            // Through a node the far side resolves and dials: not this
            // computer, so nothing is refused.
            dispatcher.set_mode(Mode::Rule);
            connect(&dispatcher, &ip("127.0.0.1:6379"), phone(false))
                .await
                .unwrap();
            assert_eq!(node.seen(), ["127.0.0.1:6379"]);
        });
    }

    #[test]
    fn this_computers_own_programs_keep_reaching_loopback() {
        runtime().block_on(async {
            let direct = Record::new(direct::PROTOCOL);
            let dispatcher = with_names(Dispatcher::single(direct.clone()));
            connect(&dispatcher, &ip("127.0.0.1:6379"), FlowOrigin::default())
                .await
                .unwrap();
            connect(&dispatcher, &name("localhost", 8890), FlowOrigin::default())
                .await
                .unwrap();
            assert_eq!(direct.seen(), ["127.0.0.1:6379", "localhost:8890"]);
        });
    }

    #[test]
    fn private_networks_are_refused_when_asked() {
        runtime().block_on(async {
            let direct = Record::new(direct::PROTOCOL);
            let dispatcher = with_names(Dispatcher::single(direct.clone()));
            for target in [ip("192.168.213.40:80"), name("printer.example", 631)] {
                let error = connect(&dispatcher, &target, phone(true))
                    .await
                    .unwrap_err();
                assert_eq!(error.kind(), io::ErrorKind::PermissionDenied, "{target}");
            }
            connect(&dispatcher, &ip("93.184.216.34:443"), phone(true))
                .await
                .unwrap();
            // The share itself, where the phone reached it (the setup page),
            // but no other port of that address.
            connect(&dispatcher, &ip("192.168.1.5:8899"), phone(true))
                .await
                .unwrap();
            let error = connect(&dispatcher, &ip("192.168.1.5:3000"), phone(true))
                .await
                .unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
            assert_eq!(direct.seen(), ["93.184.216.34:443", "192.168.1.5:8899"]);
        });
    }

    #[test]
    fn a_redirect_to_a_new_host_is_the_users_choice() {
        runtime().block_on(async {
            let direct = Record::new(direct::PROTOCOL);
            let dispatcher = with_names(
                Dispatcher::single(direct.clone()).with_redirects(
                    RedirectTable::parse(&[
                        "DOMAIN,api.example.com,127.0.0.1:3000",
                        "DOMAIN,rebind.example,:8080",
                    ])
                    .unwrap(),
                ),
            );
            connect(&dispatcher, &name("api.example.com", 443), phone(false))
                .await
                .unwrap();
            assert_eq!(direct.seen(), ["127.0.0.1:3000"]);
            // A line that keeps the host only moves the port: still checked.
            let error = connect(&dispatcher, &name("rebind.example", 443), phone(false))
                .await
                .unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
            assert_eq!(direct.seen(), ["127.0.0.1:3000"]);
        });
    }
}
