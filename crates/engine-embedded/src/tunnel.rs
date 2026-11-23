//! Packet tunnel: IP packets in, IP packets out, connections through an outbound.
//!
//! The tunnel owns one tokio runtime on a dedicated thread: a current-thread
//! runtime, or on desktop a multi-thread one with
//! [`TunnelSettings::worker_threads`] workers. IP packets from the TUN side
//! enter through [`Tunnel::input_packet`]; packets produced by the userspace
//! TCP/IP stack leave through the [`PacketWriter`] on a tunnel thread, a
//! burst at a time and one call at a time. TCP flows are relayed through the
//! [`Dispatcher`], which routes and tracks them; the host name sniffed from a
//! flow's first bytes (TLS SNI or HTTP `Host`) goes along for domain rules.
//! UDP/53 is answered from the DNS hosts, from the Fake-IP table when it is on
//! (see [`crate::fake_ip`]), from the DNS cache, or forwarded to
//! the upstream the DNS policy picks (over TCP, TLS or HTTPS, on kept
//! connections; see [`crate::dns_cache`]), and other UDP goes through the
//! outbound's UDP flows, one per app socket and destination. A UDP datagram
//! the system split into IP fragments is joined before it goes on; a UDP
//! packet that does not parse, or a reply too large for one IP packet, is
//! dropped and counted while the others keep flowing. An outbound
//! without UDP drops those datagrams; QUIC (UDP 443) is also answered with
//! ICMP port unreachable so it falls back to TCP at once. A WireGuard
//! tunnel (`Tunnel::start_wireguard`) skips the stack and seals packets
//! straight to its peer, on a UDP socket that moves to a new one when the
//! network changes (see the `wireguard` module).

use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, AtomicU8, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::thread;
use std::time::Duration;

use engine_outbound::reject::{rejection, RejectAction};
use engine_outbound::{BoxFuture, BoxStream, TargetAddr, TcpOutbound, UdpFlow};
use futures::{FutureExt, SinkExt, StreamExt};
use netstack_smoltcp::udp::UdpMsg;
use netstack_smoltcp::StackBuilder;
use serde::Serialize;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::sync::mpsc::error::TrySendError;
use tokio::sync::{mpsc, oneshot, Semaphore};

use crate::config::DnsVia;
use crate::connections::{Dispatcher, FlowOrigin, Mode};
use crate::dns::{self, OutboundFailure};
use crate::dns_cache::{CacheKey, DnsCache, DnsPools, Lookup, Waiter};
use crate::dns_policy::{DnsPolicy, Plan};
use crate::fake_ip::FakeAnswer;
use crate::first_payload::{ServerFirst, Wait};
use crate::routing::FlowSource;
use crate::sniff;
#[cfg(feature = "wireguard")]
use crate::wireguard::{self, PathControl, WireGuardSettings};

/// Receives every IP packet the stack emits. Called on a tunnel thread, one
/// call at a time.
pub type PacketSink = Box<dyn Fn(&[u8]) + Send + Sync + 'static>;

/// Where the tunnel writes the IP packets it emits, on a tunnel thread. Calls
/// never overlap, even when the tunnel runs on several worker threads.
///
/// Packets that are ready together arrive in one [`PacketWriter::write_batch`]
/// call, so a host whose packet write is expensive (one
/// `NEPacketTunnelFlow.writePackets` per call on iOS) pays once per burst.
/// Every [`PacketSink`] closure is a writer that takes packets one by one.
pub trait PacketWriter: Send + Sync + 'static {
    fn write(&self, packet: &[u8]);

    /// A burst of packets in order; the default writes them one by one.
    fn write_batch(&self, packets: &[Vec<u8>]) {
        for packet in packets {
            self.write(packet);
        }
    }
}

/// Keeps a multi-thread tunnel's writes one at a time: the stack's output
/// and ICMP replies from the UDP path run as different tasks.
struct OneAtATime<W> {
    lock: std::sync::Mutex<()>,
    inner: W,
}

impl<W: PacketWriter> PacketWriter for OneAtATime<W> {
    fn write(&self, packet: &[u8]) {
        let _guard = self.lock.lock().unwrap_or_else(|e| e.into_inner());
        self.inner.write(packet);
    }

    fn write_batch(&self, packets: &[Vec<u8>]) {
        let _guard = self.lock.lock().unwrap_or_else(|e| e.into_inner());
        self.inner.write_batch(packets);
    }
}

impl<F> PacketWriter for F
where
    F: Fn(&[u8]) + Send + Sync + 'static,
{
    fn write(&self, packet: &[u8]) {
        self(packet);
    }
}

/// Most packets handed to [`PacketWriter::write_batch`] at once.
pub const MAX_WRITE_BATCH: usize = 64;

/// A TCP flow handed to a [`FlowInterceptor`]: the app's stream, the bytes it
/// sent first, the host name the interceptor claimed and the destination.
pub struct InterceptedFlow {
    pub inbound: BoxStream,
    pub first: Vec<u8>,
    pub host: String,
    pub target: SocketAddr,
}

/// Takes over TCP flows before they are relayed, e.g. HTTPS decryption.
pub trait FlowInterceptor: Send + Sync {
    /// The host name to take the flow for, judged from its first bytes.
    fn claim(&self, first: &[u8], target: SocketAddr) -> Option<String>;

    /// Gives the interceptor the tunnel's dispatcher for connections it opens
    /// on its own, e.g. script `$httpClient` requests. The default ignores it.
    fn set_script_outbound(&self, outbound: Arc<dyn TcpOutbound>) {
        let _ = outbound;
    }

    /// Routing rules the interceptor's plugins add ahead of the user's
    /// rules. The default adds none.
    fn plugin_rules(&self) -> Vec<config_core::routing::RoutingRule> {
        Vec::new()
    }

    /// Work the interceptor runs on the tunnel's runtime while it runs, such
    /// as scheduled plugin scripts. The default has none.
    fn background(self: Arc<Self>) -> Option<BoxFuture<'static, ()>> {
        None
    }

    /// Whether QUIC to `host` (the server name of a QUIC client's first
    /// packets, or the Fake-IP name of the address) is refused, so the app
    /// falls back to TCP where [`FlowInterceptor::claim`] can take it. The
    /// default refuses none.
    fn refuses_quic(&self, host: &str) -> bool {
        let _ = host;
        false
    }

    /// The `mitm_hosts` answer: what HTTPS decryption did per host, after
    /// forgetting it when `clear`. `None` when the interceptor decrypts
    /// nothing.
    fn mitm_hosts(&self, clear: bool) -> Option<serde_json::Value> {
        let _ = clear;
        None
    }

    /// Answers a script control command; `None` when the interceptor runs
    /// no scripts.
    fn script_control(&self, request: &crate::control::ScriptControl) -> Option<serde_json::Value> {
        let _ = request;
        None
    }

    /// Serves a claimed flow to the end, connecting through `outbound`.
    fn serve<'a>(
        &'a self,
        flow: InterceptedFlow,
        outbound: &'a dyn TcpOutbound,
        settings: &'a TunnelSettings,
        stats: &'a TunnelStats,
    ) -> BoxFuture<'a, ()>;
}

/// Packets queued from the TUN side before the stack drops new ones.
const INPUT_QUEUE_PACKETS: usize = 512;
/// How long a new flow waits for the application's first bytes, so they can
/// travel inside the proxy request header.
const FIRST_PAYLOAD_WAIT: Duration = Duration::from_millis(100);
/// The same for HTTP and HTTPS (client-first protocols): under load the
/// request or ClientHello can come later than [`FIRST_PAYLOAD_WAIT`], and a
/// flow without its first bytes misses HTTPS decryption and rewrites.
const FIRST_PAYLOAD_CLIENT_FIRST_WAIT: Duration = Duration::from_secs(1);
const FIRST_PAYLOAD_MAX: usize = 4096;
/// Largest TLS record that is read whole as the first payload.
const FIRST_TLS_RECORD_MAX: usize = 5 + 16 * 1024;
const RELAY_BUFFER_BYTES: usize = 8 * 1024;
const DNS_PORT: u16 = 53;
/// TCP connections relayed at once by default
/// ([`TunnelSettings::max_tcp_connections`]). Each holds two stack windows
/// and relay buffers, so iOS keeps 128 inside the ~50 MB Network Extension
/// limit; Android gets 512 and desktop (macOS, Windows, Linux TUN and the
/// system proxy) 1024, where a browser with many tabs alone opens hundreds.
#[cfg(target_os = "ios")]
pub const DEFAULT_MAX_TCP_CONNECTIONS: usize = 128;
#[cfg(target_os = "android")]
pub const DEFAULT_MAX_TCP_CONNECTIONS: usize = 512;
#[cfg(not(any(target_os = "ios", target_os = "android")))]
pub const DEFAULT_MAX_TCP_CONNECTIONS: usize = 1024;
/// UDP flows open at once by default ([`TunnelSettings::max_udp_flows`]):
/// 256 on iOS for the Network Extension memory limit, 4096 elsewhere
/// (about 2.2 KiB each). A new flow past the limit takes the place of an
/// idle one (see [`TunnelSettings::udp_evict_idle`]).
#[cfg(target_os = "ios")]
pub const DEFAULT_MAX_UDP_FLOWS: usize = 256;
#[cfg(not(target_os = "ios"))]
pub const DEFAULT_MAX_UDP_FLOWS: usize = 4096;
/// Default [`TunnelSettings::tcp_evict_idle`].
pub const DEFAULT_TCP_EVICT_IDLE: Duration = Duration::from_secs(30);
/// Default [`TunnelSettings::udp_evict_idle`].
pub const DEFAULT_UDP_EVICT_IDLE: Duration = Duration::from_secs(15);
/// A full UDP table frees up to 1/this of its slots per pass, so the next
/// new flows find room without another pass.
const UDP_EVICT_BATCH: usize = 16;
/// The share of a full UDP table one app socket may keep when another
/// needs room, as 1/this.
const UDP_SOURCE_SHARE: usize = 4;
/// After a pass over a full UDP table found nothing to close, new flows are
/// dropped without another pass for this long.
const UDP_RESCAN_AFTER: Duration = Duration::from_millis(250);
/// After no idle TCP connection was found, new ones are refused without
/// another look for this long.
const TCP_RESCAN_AFTER: Duration = Duration::from_millis(100);
/// How long a new TCP connection waits for the place of the idle one it
/// closed.
const TCP_EVICT_WAIT: Duration = Duration::from_secs(1);
/// Datagrams queued per flow while it connects or sends.
const UDP_FLOW_QUEUE: usize = 64;
/// A UDP flow without traffic in either direction for this long is closed.
const UDP_IDLE_TIMEOUT: Duration = Duration::from_secs(60);

#[derive(Clone, Debug)]
pub struct TunnelSettings {
    pub mtu: u16,
    pub tcp_window_bytes: u32,
    /// TCP connections relayed at once. When all are taken, a new one
    /// closes the connection that has been without payload longest, if that
    /// is at least [`Self::tcp_evict_idle`]; otherwise it is refused.
    pub max_tcp_connections: usize,
    /// UDP flows (app socket, destination) open at once. DNS to port 53 does
    /// not count. When all are taken, flows that ended and then those idle
    /// for at least [`Self::udp_evict_idle`] make room, longest idle first;
    /// failing that, an app socket holding more than a quarter of the table
    /// gives up its least active flow; failing that, the datagram of the new
    /// flow is dropped.
    pub max_udp_flows: usize,
    /// How long a TCP connection must have carried no payload either way
    /// before a new connection may take its place at the limit.
    pub tcp_evict_idle: Duration,
    /// The same for UDP flows (no datagram either way).
    pub udp_evict_idle: Duration,
    pub max_dns_in_flight: usize,
    pub idle_timeout: Duration,
    pub connect_timeout: Duration,
    /// Hosts, per-domain servers and upstreams for UDP/53.
    pub dns: Arc<DnsPolicy>,
    /// Threads the tunnel's runtime runs on. 1 runs everything on the tunnel
    /// thread; more spreads flows (relay, encryption, outbound I/O) over a
    /// multi-thread runtime while the userspace TCP/IP stack stays one task.
    /// iOS and Android always use 1. See [`default_worker_threads`].
    pub worker_threads: usize,
}

/// Most worker threads a tunnel runs on.
pub const MAX_WORKER_THREADS: usize = 16;
/// Worker threads a desktop tunnel uses by default, at most this many.
const DEFAULT_DESKTOP_WORKERS: usize = 4;

/// Worker threads when the config does not say: 1 on iOS and Android (the
/// iOS Network Extension has a hard memory limit, and phones gain little),
/// otherwise the CPUs available, at most 4.
pub fn default_worker_threads() -> usize {
    if cfg!(any(target_os = "ios", target_os = "android")) {
        return 1;
    }
    thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1)
        .min(DEFAULT_DESKTOP_WORKERS)
}

/// The worker threads a tunnel really uses: 1 on iOS and Android, otherwise
/// `requested` within 1..=[`MAX_WORKER_THREADS`].
fn effective_workers(requested: usize) -> usize {
    if cfg!(any(target_os = "ios", target_os = "android")) {
        1
    } else {
        requested.clamp(1, MAX_WORKER_THREADS)
    }
}

/// The tunnel runtime: one thread, or `workers` threads on desktop.
fn tunnel_runtime(workers: usize) -> io::Result<tokio::runtime::Runtime> {
    #[cfg(not(any(target_os = "ios", target_os = "android")))]
    if workers > 1 {
        return tokio::runtime::Builder::new_multi_thread()
            .worker_threads(workers)
            .thread_name("networkcore-tunnel-worker")
            .enable_all()
            .build();
    }
    let _ = workers;
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
}

/// Live counters. Snapshots are safe to expose: no addresses, no payloads.
#[derive(Default)]
pub struct TunnelStats {
    pub(crate) packets_in: AtomicU64,
    pub(crate) packets_in_dropped: AtomicU64,
    pub(crate) packets_out: AtomicU64,
    pub(crate) tcp_active: AtomicU64,
    pub(crate) tcp_total: AtomicU64,
    pub(crate) tcp_rejected: AtomicU64,
    pub(crate) tcp_evicted: AtomicU64,
    pub(crate) tcp_connect_failed: AtomicU64,
    pub(crate) udp_dropped: AtomicU64,
    pub(crate) udp_evicted: AtomicU64,
    pub(crate) udp_flows: AtomicU64,
    pub(crate) udp_failed: AtomicU64,
    pub(crate) dns_queries: AtomicU64,
    pub(crate) dns_failed: AtomicU64,
    pub(crate) dns_cached: AtomicU64,
    pub(crate) dns_fake: AtomicU64,
    pub(crate) bytes_up: AtomicU64,
    pub(crate) bytes_down: AtomicU64,
    /// Last `OutboundFailure` code, 0 for none.
    pub(crate) dns_last_failure: AtomicU8,
    pub(crate) tcp_last_failure: AtomicU8,
    pub(crate) mitm_flows: AtomicU64,
    pub(crate) mitm_failed: AtomicU64,
    pub(crate) quic_mitm_fallback: AtomicU64,
    pub(crate) tcp_first_wait_skipped: AtomicU64,
    /// What the userspace stack dropped or rebuilt.
    pub(crate) stack: Arc<netstack_smoltcp::StackStats>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct TunnelStatsSnapshot {
    pub packets_in: u64,
    pub packets_in_dropped: u64,
    pub packets_out: u64,
    pub tcp_active: u64,
    pub tcp_total: u64,
    /// New TCP connections refused because `max_tcp_connections` were open
    /// and none of them had been idle long enough to close.
    pub tcp_rejected: u64,
    /// Idle TCP connections closed to make room for a new one at
    /// `max_tcp_connections`.
    pub tcp_evicted: u64,
    pub tcp_connect_failed: u64,
    pub udp_dropped: u64,
    /// UDP flows closed to make room for a new one at `max_udp_flows`.
    pub udp_evicted: u64,
    /// UDP flows opened through the outbound.
    pub udp_flows: u64,
    /// UDP flows the outbound could not open, including outbounds without UDP.
    pub udp_failed: u64,
    pub dns_queries: u64,
    pub dns_failed: u64,
    /// Queries answered from the DNS cache (fresh or stale) or joined to an
    /// identical query in flight; counted in `dns_queries` too.
    pub dns_cached: u64,
    /// Queries answered from the Fake-IP table (a fake A record, or an empty
    /// AAAA / HTTPS answer); counted in `dns_queries` too.
    pub dns_fake: u64,
    pub bytes_up: u64,
    pub bytes_down: u64,
    pub dns_last_failure: Option<&'static str>,
    pub tcp_last_failure: Option<&'static str>,
    pub mitm_flows: u64,
    pub mitm_failed: u64,
    /// QUIC flows to a decrypted host refused so the app falls back to TCP
    /// (see [`FlowInterceptor::refuses_quic`]); counted in `udp_failed` too.
    pub quic_mitm_fallback: u64,
    /// TCP flows that connected without waiting for the application's first
    /// bytes: a server-first port, or a destination that stayed silent
    /// before (see [`crate::first_payload`]); counted in `tcp_total` too.
    pub tcp_first_wait_skipped: u64,
    /// UDP packets from the apps whose UDP header did not parse (cut short,
    /// or a length that disagrees with the packet); each one is dropped and
    /// the next one read.
    pub udp_malformed: u64,
    /// UDP replies to the apps too large for one IP packet; each one is
    /// dropped and the next one sent.
    pub udp_unsendable: u64,
    /// IP fragments dropped: fragments of other protocols than UDP,
    /// malformed or repeated ones, and those of UDP datagrams that never
    /// became whole.
    pub ip_fragments_dropped: u64,
    /// UDP datagrams that came in IP fragments and were joined.
    pub udp_reassembled: u64,
}

impl TunnelStats {
    pub fn snapshot(&self) -> TunnelStatsSnapshot {
        let get = |counter: &AtomicU64| counter.load(Ordering::Relaxed);
        TunnelStatsSnapshot {
            packets_in: get(&self.packets_in),
            packets_in_dropped: get(&self.packets_in_dropped),
            packets_out: get(&self.packets_out),
            tcp_active: get(&self.tcp_active),
            tcp_total: get(&self.tcp_total),
            tcp_rejected: get(&self.tcp_rejected),
            tcp_evicted: get(&self.tcp_evicted),
            tcp_connect_failed: get(&self.tcp_connect_failed),
            udp_dropped: get(&self.udp_dropped),
            udp_evicted: get(&self.udp_evicted),
            udp_flows: get(&self.udp_flows),
            udp_failed: get(&self.udp_failed),
            dns_queries: get(&self.dns_queries),
            dns_failed: get(&self.dns_failed),
            dns_cached: get(&self.dns_cached),
            dns_fake: get(&self.dns_fake),
            bytes_up: get(&self.bytes_up),
            bytes_down: get(&self.bytes_down),
            dns_last_failure: last_failure(&self.dns_last_failure),
            tcp_last_failure: last_failure(&self.tcp_last_failure),
            mitm_flows: get(&self.mitm_flows),
            mitm_failed: get(&self.mitm_failed),
            quic_mitm_fallback: get(&self.quic_mitm_fallback),
            tcp_first_wait_skipped: get(&self.tcp_first_wait_skipped),
            udp_malformed: self.stack.udp_malformed(),
            udp_unsendable: self.stack.udp_unsendable(),
            ip_fragments_dropped: self.stack.ip_fragments_dropped(),
            udp_reassembled: self.stack.udp_reassembled(),
        }
    }
}

fn last_failure(slot: &AtomicU8) -> Option<&'static str> {
    OutboundFailure::from_code(slot.load(Ordering::Relaxed)).map(OutboundFailure::as_str)
}

fn record(slot: &AtomicU8, failure: OutboundFailure) {
    slot.store(failure as u8, Ordering::Relaxed);
}

pub(crate) fn bump(counter: &AtomicU64) {
    counter.fetch_add(1, Ordering::Relaxed);
}

pub struct Tunnel {
    packet_tx: mpsc::Sender<Vec<u8>>,
    shutdown_tx: Option<oneshot::Sender<()>>,
    thread: Option<thread::JoinHandle<()>>,
    stats: Arc<TunnelStats>,
}

impl Tunnel {
    pub fn start(
        settings: TunnelSettings,
        outbound: Arc<dyn TcpOutbound>,
        sink: impl PacketWriter,
    ) -> io::Result<Self> {
        Self::start_with_interceptor(settings, outbound, None, sink)
    }

    /// Like [`Tunnel::start`], offering each new TCP flow to `interceptor`
    /// first.
    pub fn start_with_interceptor(
        settings: TunnelSettings,
        outbound: Arc<dyn TcpOutbound>,
        interceptor: Option<Arc<dyn FlowInterceptor>>,
        sink: impl PacketWriter,
    ) -> io::Result<Self> {
        let dispatcher = Arc::new(Dispatcher::single(outbound));
        Self::start_with_dispatcher(settings, dispatcher, interceptor, None, sink)
    }

    /// Starts the tunnel with flows through `dispatcher`, offering each new
    /// TCP flow to `interceptor` first and running `background` (such as
    /// policy group health checks) on the tunnel's runtime until it stops.
    pub fn start_with_dispatcher(
        settings: TunnelSettings,
        dispatcher: Arc<Dispatcher>,
        interceptor: Option<Arc<dyn FlowInterceptor>>,
        background: Option<BoxFuture<'static, ()>>,
        sink: impl PacketWriter,
    ) -> io::Result<Self> {
        let workers = effective_workers(settings.worker_threads);
        let sink: Arc<dyn PacketWriter> = if workers > 1 {
            Arc::new(OneAtATime {
                lock: std::sync::Mutex::new(()),
                inner: sink,
            })
        } else {
            Arc::new(sink)
        };
        let interceptor_background = interceptor
            .clone()
            .and_then(|interceptor| interceptor.background());
        Self::launch(workers, move |packet_rx, stats| {
            spawn_tasks(settings, dispatcher, interceptor, sink, packet_rx, stats)?;
            for background in [background, interceptor_background].into_iter().flatten() {
                tokio::spawn(background);
            }
            Ok(())
        })
    }

    /// Starts a WireGuard tunnel to one peer. Resolving the endpoint and
    /// binding the UDP socket happen before this returns; `paths` moves the
    /// running tunnel to a new socket after a network change.
    #[cfg(feature = "wireguard")]
    pub fn start_wireguard(
        settings: WireGuardSettings,
        paths: Arc<PathControl>,
        sink: impl PacketWriter,
    ) -> io::Result<Self> {
        let sink: PacketSink = Box::new(move |packet: &[u8]| sink.write(packet));
        Self::launch(1, move |packet_rx, stats| {
            wireguard::spawn_tasks(settings, paths, sink, packet_rx, stats)
        })
    }

    /// Runs `setup` on a new tunnel thread inside its tokio runtime (one
    /// thread, or `workers` worker threads) and waits for it to report
    /// whether the tasks started.
    fn launch<F>(workers: usize, setup: F) -> io::Result<Self>
    where
        F: FnOnce(mpsc::Receiver<Vec<u8>>, Arc<TunnelStats>) -> io::Result<()> + Send + 'static,
    {
        let runtime = tunnel_runtime(workers)?;
        let stats = Arc::new(TunnelStats::default());
        let (packet_tx, packet_rx) = mpsc::channel(INPUT_QUEUE_PACKETS);
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let (ready_tx, ready_rx) = std::sync::mpsc::sync_channel(1);

        let thread_stats = stats.clone();
        let thread = thread::Builder::new()
            .name("networkcore-tunnel".into())
            .spawn(move || {
                runtime.block_on(async move {
                    match setup(packet_rx, thread_stats) {
                        Ok(()) => {
                            let _ = ready_tx.send(Ok(()));
                            let _ = shutdown_rx.await;
                        }
                        Err(err) => {
                            let _ = ready_tx.send(Err(err));
                        }
                    }
                });
                // Dropping the runtime cancels every flow; bound the wait for
                // resolver threads so stop stays prompt.
                runtime.shutdown_timeout(Duration::from_secs(1));
            })?;

        match ready_rx.recv() {
            Ok(Ok(())) => Ok(Self {
                packet_tx,
                shutdown_tx: Some(shutdown_tx),
                thread: Some(thread),
                stats,
            }),
            Ok(Err(err)) => {
                let _ = thread.join();
                Err(err)
            }
            Err(_) => {
                let _ = thread.join();
                Err(io::Error::other("tunnel thread exited during startup"))
            }
        }
    }

    /// Queues one IP packet from the TUN side. Returns `false` when the packet
    /// was dropped because the queue is full or the tunnel stopped.
    pub fn input_packet(&self, packet: &[u8]) -> bool {
        if packet.is_empty() {
            return false;
        }
        bump(&self.stats.packets_in);
        if self.packet_tx.try_send(packet.to_vec()).is_ok() {
            true
        } else {
            bump(&self.stats.packets_in_dropped);
            false
        }
    }

    pub fn stats(&self) -> TunnelStatsSnapshot {
        self.stats.snapshot()
    }

    pub fn is_running(&self) -> bool {
        self.thread.is_some()
    }

    /// Stops the tunnel and joins its thread. After this returns the sink is
    /// never called again. Calling it twice is a no-op.
    pub fn stop(&mut self) {
        if let Some(shutdown_tx) = self.shutdown_tx.take() {
            let _ = shutdown_tx.send(());
        }
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

impl Drop for Tunnel {
    fn drop(&mut self) {
        self.stop();
    }
}

fn spawn_tasks(
    settings: TunnelSettings,
    dispatcher: Arc<Dispatcher>,
    interceptor: Option<Arc<dyn FlowInterceptor>>,
    sink: Arc<dyn PacketWriter>,
    mut packet_rx: mpsc::Receiver<Vec<u8>>,
    stats: Arc<TunnelStats>,
) -> io::Result<()> {
    let (stack, runner, udp_socket, tcp_listener) = StackBuilder::default()
        .enable_tcp(true)
        .enable_udp(true)
        .enable_icmp(false)
        .mtu(usize::from(settings.mtu))
        .tcp_recv_buffer_size(settings.tcp_window_bytes)
        .tcp_send_buffer_size(settings.tcp_window_bytes)
        .stats(stats.stack.clone())
        .build()?;
    let runner = runner.ok_or_else(|| io::Error::other("userspace TCP runner is unavailable"))?;
    let udp_socket =
        udp_socket.ok_or_else(|| io::Error::other("userspace UDP socket is unavailable"))?;
    let mut tcp_listener =
        tcp_listener.ok_or_else(|| io::Error::other("userspace TCP listener is unavailable"))?;

    tokio::spawn(runner);

    let (mut stack_sink, mut stack_stream) = stack.split();

    // Stack -> TUN. The UDP path also writes ICMP errors straight to the
    // sink (see [`crate::icmp`]); on a multi-thread tunnel the sink is
    // wrapped so those writes never overlap.
    // Packets that are already waiting go out with the first one, in one
    // batch of at most MAX_WRITE_BATCH.
    let raw_sink = sink.clone();
    let out_stats = stats.clone();
    tokio::spawn(async move {
        let mut batch = Vec::with_capacity(MAX_WRITE_BATCH);
        while let Some(first) = stack_stream.next().await {
            batch.extend(first.ok());
            while batch.len() < MAX_WRITE_BATCH {
                match stack_stream.next().now_or_never() {
                    Some(Some(packet)) => batch.extend(packet.ok()),
                    Some(None) | None => break,
                }
            }
            if batch.is_empty() {
                continue;
            }
            out_stats
                .packets_out
                .fetch_add(batch.len() as u64, Ordering::Relaxed);
            sink.write_batch(&batch);
            batch.clear();
        }
    });

    // TUN -> stack. Invalid packets are rejected by the stack and skipped;
    // the IP fragments of a UDP datagram are held there until it is whole.
    tokio::spawn(async move {
        while let Some(packet) = packet_rx.recv().await {
            let _ = stack_sink.send(packet).await;
        }
    });

    // UDP flows to QUIC's port ask the interceptor first.
    let udp_interceptor = interceptor.clone();

    // TCP flows.
    let tcp_permits = Arc::new(Semaphore::new(settings.max_tcp_connections));
    // REJECT-DROP flows held open, each still on its TCP permit (its stack
    // buffers stay allocated): an eighth of them at most, so a retry storm
    // never starves real flows; past that a dropped flow just closes.
    let tcp_shared = Arc::new(TcpShared {
        drop_holds: Semaphore::new((settings.max_tcp_connections / 8).max(1)),
        server_first: ServerFirst::default(),
        live: LiveTcp::default(),
    });
    let tcp_dispatcher = dispatcher.clone();
    let tcp_stats = stats.clone();
    let tcp_settings = settings.clone();
    tokio::spawn(async move {
        // When the last look found no idle connection to close.
        let mut none_idle_at: Option<tokio::time::Instant> = None;
        while let Some((stream, _local, remote)) = tcp_listener.next().await {
            // At the limit, the connection idle longest makes room; the new
            // one waits for its permit, which comes back as soon as the
            // closed connection's task ends.
            let permit = match tcp_permits.clone().try_acquire_owned() {
                Ok(permit) => Some(permit),
                Err(_) => {
                    let now = tokio::time::Instant::now();
                    let look = none_idle_at
                        .is_none_or(|at| now.saturating_duration_since(at) >= TCP_RESCAN_AFTER);
                    if look && tcp_shared.live.evict_idle(now, tcp_settings.tcp_evict_idle) {
                        none_idle_at = None;
                        bump(&tcp_stats.tcp_evicted);
                        None
                    } else {
                        if look {
                            none_idle_at = Some(now);
                        }
                        bump(&tcp_stats.tcp_rejected);
                        drop(stream);
                        continue;
                    }
                }
            };
            let permits = tcp_permits.clone();
            let dispatcher = tcp_dispatcher.clone();
            let stats = tcp_stats.clone();
            let settings = tcp_settings.clone();
            let interceptor = interceptor.clone();
            let shared = tcp_shared.clone();
            tokio::spawn(async move {
                let _permit = match permit {
                    Some(permit) => permit,
                    None => {
                        match tokio::time::timeout(TCP_EVICT_WAIT, permits.acquire_owned()).await {
                            Ok(Ok(permit)) => permit,
                            _ => {
                                bump(&stats.tcp_rejected);
                                return;
                            }
                        }
                    }
                };
                bump(&stats.tcp_total);
                let activity = Arc::new(LastActive::new());
                let live = shared.live.register(activity.clone());
                stats.tcp_active.fetch_add(1, Ordering::Relaxed);
                tokio::select! {
                    () = handle_tcp(
                        stream,
                        remote,
                        &dispatcher,
                        interceptor.as_deref(),
                        &stats,
                        &settings,
                        &shared,
                        &activity,
                    ) => {}
                    // Closed to make room: dropping the flow closes both sides.
                    () = live.evicted() => {}
                }
                stats.tcp_active.fetch_sub(1, Ordering::Relaxed);
            });
        }
    });

    // UDP: DNS over TCP, everything else through the outbound's UDP flows.
    // The stack's UDP socket drops (and counts) a packet it cannot read or a
    // reply it cannot send and goes on, so both loops end with the tunnel.
    let (mut udp_rx, mut udp_tx) = udp_socket.split();
    let (reply_tx, mut reply_rx) = mpsc::channel::<UdpMsg>(64);
    tokio::spawn(async move {
        while let Some(reply) = reply_rx.recv().await {
            if udp_tx.send(reply).await.is_err() {
                break;
            }
        }
    });
    let dns_permits = Arc::new(Semaphore::new(settings.max_dns_in_flight));
    let dns_state = Arc::new(std::sync::Mutex::new(DnsCache::default()));
    let upstream_pool = Arc::new(DnsPools::default());
    let mut flows = UdpFlows::default();
    tokio::spawn(async move {
        while let Some((payload, src, dst)) = udp_rx.next().await {
            if dst.port() != DNS_PORT {
                flows.forward(
                    payload,
                    src,
                    dst,
                    &dispatcher,
                    udp_interceptor.as_ref(),
                    &stats,
                    &reply_tx,
                    &raw_sink,
                    &settings,
                );
                continue;
            }
            let rule_sets = dispatcher
                .routed_outbound()
                .map(|routed| routed.rule_sets().as_ref());
            let server = match settings.dns.plan(&payload, rule_sets) {
                Plan::Local(response) => {
                    bump(&stats.dns_queries);
                    if reply_tx.try_send((response, dst, src)).is_err() {
                        bump(&stats.dns_failed);
                    }
                    continue;
                }
                Plan::Forward(server) => server,
            };
            // Fake-IP: names outside the hosts and the filter get a fake
            // address at once; the dispatcher maps it back on connect.
            if let Some(FakeAnswer::Reply(reply)) =
                dispatcher.fake_ip().map(|pool| pool.answer(&payload))
            {
                bump(&stats.dns_queries);
                bump(&stats.dns_fake);
                if reply_tx.try_send((reply, dst, src)).is_err() {
                    bump(&stats.dns_failed);
                }
                continue;
            }
            bump(&stats.dns_queries);
            let proxied = dispatcher.mode() != Mode::Direct
                && settings
                    .dns
                    .target(server)
                    .iter()
                    .any(|&index| settings.dns.servers()[index].via == DnsVia::Proxy);
            let question = dns::question(&payload);
            let key = question.as_ref().map(|question| CacheKey {
                name: question.name.clone(),
                qtype: question.qtype,
                server,
                proxied,
            });
            if let (Some(key), Some(question)) = (&key, &question) {
                let mut state = dns_state.lock().unwrap_or_else(|e| e.into_inner());
                match state.lookup(key, &payload, question.end, std::time::Instant::now()) {
                    Lookup::Fresh(reply) => {
                        drop(state);
                        bump(&stats.dns_cached);
                        if reply_tx.try_send((reply, dst, src)).is_err() {
                            bump(&stats.dns_failed);
                        }
                        continue;
                    }
                    Lookup::Stale(reply) => {
                        // Answer now; refresh unless a refresh is already running.
                        let refresh = state.begin(key, None);
                        drop(state);
                        bump(&stats.dns_cached);
                        if reply_tx.try_send((reply, dst, src)).is_err() {
                            bump(&stats.dns_failed);
                        }
                        if !refresh {
                            continue;
                        }
                        let Ok(permit) = dns_permits.clone().try_acquire_owned() else {
                            dns_state
                                .lock()
                                .unwrap_or_else(|e| e.into_inner())
                                .finish(key);
                            continue;
                        };
                        spawn_dns_exchange(DnsExchange {
                            payload,
                            app: None,
                            resolver: dst,
                            key: Some(key.clone()),
                            server,
                            proxied,
                            permit,
                            dispatcher: dispatcher.clone(),
                            policy: settings.dns.clone(),
                            stats: stats.clone(),
                            reply_tx: reply_tx.clone(),
                            state: dns_state.clone(),
                            pool: upstream_pool.clone(),
                        });
                        continue;
                    }
                    Lookup::Miss => {
                        let waiter = Waiter {
                            query: payload.clone(),
                            question_end: question.end,
                            app: src,
                            resolver: dst,
                        };
                        if !state.begin(key, Some(waiter)) {
                            bump(&stats.dns_cached);
                            continue;
                        }
                    }
                }
            }
            let Ok(permit) = dns_permits.clone().try_acquire_owned() else {
                if let Some(key) = &key {
                    dns_state
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .finish(key);
                }
                bump(&stats.dns_failed);
                continue;
            };
            spawn_dns_exchange(DnsExchange {
                payload,
                app: Some(src),
                resolver: dst,
                key,
                server,
                proxied,
                permit,
                dispatcher: dispatcher.clone(),
                policy: settings.dns.clone(),
                stats: stats.clone(),
                reply_tx: reply_tx.clone(),
                state: dns_state.clone(),
                pool: upstream_pool.clone(),
            });
        }
    });

    Ok(())
}

/// One query to send upstream and who gets the answer.
struct DnsExchange {
    payload: Vec<u8>,
    /// The app that asked, `None` for a background refresh of a stale answer.
    app: Option<SocketAddr>,
    /// The address the app queried; replies come from it.
    resolver: SocketAddr,
    /// The cache entry and in-flight slot, `None` when the question did not parse.
    key: Option<CacheKey>,
    /// The target of the policy: the servers asked together.
    server: usize,
    /// Whether the servers are reached as configured (`false` in the direct
    /// mode, where every server is direct).
    proxied: bool,
    permit: tokio::sync::OwnedSemaphorePermit,
    dispatcher: Arc<Dispatcher>,
    policy: Arc<DnsPolicy>,
    stats: Arc<TunnelStats>,
    reply_tx: mpsc::Sender<UdpMsg>,
    state: Arc<std::sync::Mutex<DnsCache>>,
    pool: Arc<DnsPools>,
}

fn spawn_dns_exchange(job: DnsExchange) {
    tokio::spawn(async move {
        let DnsExchange {
            payload,
            app,
            resolver,
            key,
            server,
            proxied,
            permit: _permit,
            dispatcher,
            policy,
            stats,
            reply_tx,
            state,
            pool,
        } = job;
        // DNS queries are the tunnel's own traffic, not listed connections.
        // Routing that rejects the proxy gives no outbound: no query rather
        // than one in the clear.
        let outbound_for = |index: usize| -> Option<Arc<dyn TcpOutbound>> {
            let server = &policy.servers()[index];
            match server.upstream.target() {
                Some(target) if proxied => {
                    dispatcher.dns_outbound_as(server.via, target, server.upstream.rule_protocol())
                }
                Some(target) => dispatcher.dns_outbound(DnsVia::Direct, target),
                // `system`: always direct.
                None => Some(dispatcher.direct().clone()),
            }
        };
        let result =
            crate::dns_client::resolve(&policy, server, &payload, &outbound_for, &pool).await;
        let waiters = match &key {
            Some(key) => {
                let mut state = state.lock().unwrap_or_else(|e| e.into_inner());
                if let (Ok(response), Some(question)) = (&result, dns::question(&payload)) {
                    state.insert(key.clone(), &question, response, std::time::Instant::now());
                }
                state.finish(key)
            }
            None => Vec::new(),
        };
        match result {
            Ok(response) => {
                // Queries that joined this exchange get the answer with their
                // own id and question.
                for waiter in waiters {
                    if let Some(reply) = crate::dns_cache::reply_from(
                        &response,
                        &waiter.query,
                        waiter.question_end,
                        None,
                    ) {
                        let _ = reply_tx.send((reply, waiter.resolver, waiter.app)).await;
                    }
                }
                // The reply goes back from the address the app queried.
                if let Some(app) = app {
                    let _ = reply_tx.send((response, resolver, app)).await;
                }
            }
            Err(failure) => {
                bump(&stats.dns_failed);
                record(&stats.dns_last_failure, failure);
            }
        }
    });
}

/// A UDP flow's key: (app socket, destination).
type FlowKey = (SocketAddr, SocketAddr);

/// Open UDP flows keyed by (app socket, destination). Owned by the task that
/// reads datagrams from the stack, so it needs no lock.
#[derive(Default)]
struct UdpFlows {
    map: HashMap<FlowKey, FlowSender>,
    /// When the last pass over the full table found nothing to close (see
    /// [`UDP_RESCAN_AFTER`]).
    no_room_at: Option<tokio::time::Instant>,
}

impl UdpFlows {
    #[allow(clippy::too_many_arguments)]
    fn forward(
        &mut self,
        payload: Vec<u8>,
        src: SocketAddr,
        dst: SocketAddr,
        dispatcher: &Arc<Dispatcher>,
        interceptor: Option<&Arc<dyn FlowInterceptor>>,
        stats: &Arc<TunnelStats>,
        replies: &mpsc::Sender<UdpMsg>,
        raw: &Arc<dyn PacketWriter>,
        settings: &TunnelSettings,
    ) {
        let key = (src, dst);
        let payload = if let Some(flow) = self.map.get(&key) {
            match flow.try_send(payload) {
                Ok(()) => return,
                Err(TrySendError::Full(_)) => {
                    bump(&stats.udp_dropped);
                    return;
                }
                // The flow ended; open a new one for this datagram.
                Err(TrySendError::Closed(payload)) => payload,
            }
        } else {
            payload
        };
        self.map.remove(&key);
        if self.map.len() >= settings.max_udp_flows
            && !self.make_room(src, tokio::time::Instant::now(), settings, stats)
        {
            bump(&stats.udp_dropped);
            return;
        }
        let (flow, packets) = flow_queue();
        let _ = flow.try_send(payload);
        self.map.insert(key, flow);
        tokio::spawn(run_udp_flow(
            packets,
            src,
            dst,
            dispatcher.clone(),
            interceptor.filter(|_| dst.port() == QUIC_PORT).cloned(),
            stats.clone(),
            replies.clone(),
            raw.clone(),
            settings.connect_timeout,
        ));
    }
}

impl UdpFlows {
    /// Frees room in the full table for a new flow from `src`, in one pass:
    /// flows that ended go; then up to a batch of those idle longest, idle
    /// for at least `udp_evict_idle`; when none is idle, the least active
    /// flows of the app socket holding the most, if that is more than its
    /// share (a quarter; the new flow counts for its own socket), so one
    /// app fanning out to many peers cannot starve the others. Closing a
    /// flow drops its sender, and its task ends once the queued datagrams
    /// are gone. Returns `false` when nothing could go; new flows are then
    /// dropped without another pass for [`UDP_RESCAN_AFTER`], so a full
    /// table costs one pass per batch of new flows, not one per datagram.
    fn make_room(
        &mut self,
        src: SocketAddr,
        now: tokio::time::Instant,
        settings: &TunnelSettings,
        stats: &TunnelStats,
    ) -> bool {
        if let Some(at) = self.no_room_at {
            if now.saturating_duration_since(at) < UDP_RESCAN_AFTER {
                return false;
            }
        }
        self.no_room_at = None;
        let max = settings.max_udp_flows;
        self.map.retain(|_, flow| !flow.is_closed());
        if self.map.len() < max {
            return true;
        }
        let batch = (max / UDP_EVICT_BATCH).max(1);
        let share = (max / UDP_SOURCE_SHARE).max(1);
        let mut idle = Vec::new();
        let mut per_source: HashMap<SocketAddr, usize> = HashMap::new();
        for (key, flow) in &self.map {
            *per_source.entry(key.0).or_default() += 1;
            let quiet = flow.idle(now);
            if quiet >= settings.udp_evict_idle {
                idle.push((quiet, *key));
            }
        }
        let mut victims = longest_idle(idle, batch);
        if victims.is_empty() {
            let hog = per_source
                .into_iter()
                .map(|(source, flows)| (source, flows + usize::from(source == src)))
                .filter(|&(_, flows)| flows > share)
                .max_by_key(|&(_, flows)| flows);
            if let Some((hog, flows)) = hog {
                let own: Vec<_> = self
                    .map
                    .iter()
                    .filter(|(key, _)| key.0 == hog)
                    .map(|(key, flow)| (flow.idle(now), *key))
                    .collect();
                victims = longest_idle(own, batch.min(flows - share));
            }
        }
        if victims.is_empty() {
            self.no_room_at = Some(now);
            return false;
        }
        for key in victims {
            if self.map.remove(&key).is_some() {
                bump(&stats.udp_evicted);
            }
        }
        true
    }
}

/// The keys of the `count` flows idle longest among `flows`.
fn longest_idle(mut flows: Vec<(Duration, FlowKey)>, count: usize) -> Vec<FlowKey> {
    if count == 0 {
        return Vec::new();
    }
    if flows.len() > count {
        flows.select_nth_unstable_by(count - 1, |a, b| b.0.cmp(&a.0));
        flows.truncate(count);
    }
    flows.into_iter().map(|(_, key)| key).collect()
}

/// The datagrams waiting for one UDP flow.
///
/// A flow holds one of these for as long as it lives, and a tunnel may hold
/// a hundred thousand flows, so it is a plain locked queue that allocates
/// only for the datagrams it holds; a `tokio::sync::mpsc` channel reserves a
/// block of slots and padded counters up front (about a kilobyte per flow).
struct FlowQueue {
    state: std::sync::Mutex<FlowQueueState>,
    /// The last datagram either way, for closing idle flows at the limit.
    activity: LastActive,
    /// Woken on every datagram and when either end leaves; `notify_one`
    /// keeps a permit, so a wake between a check and the wait is not lost.
    ready: tokio::sync::Notify,
}

#[derive(Default)]
struct FlowQueueState {
    packets: std::collections::VecDeque<Vec<u8>>,
    closed: bool,
}

fn flow_queue() -> (FlowSender, FlowReceiver) {
    let queue = Arc::new(FlowQueue {
        state: std::sync::Mutex::default(),
        activity: LastActive::new(),
        ready: tokio::sync::Notify::new(),
    });
    (FlowSender(queue.clone()), FlowReceiver(queue))
}

impl FlowQueue {
    fn state(&self) -> std::sync::MutexGuard<'_, FlowQueueState> {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn close(&self) {
        self.state().closed = true;
        self.ready.notify_one();
    }
}

/// The tunnel's end: queues datagrams for the flow's task.
struct FlowSender(Arc<FlowQueue>);

impl FlowSender {
    fn try_send(&self, packet: Vec<u8>) -> Result<(), TrySendError<Vec<u8>>> {
        let mut state = self.0.state();
        if state.closed {
            return Err(TrySendError::Closed(packet));
        }
        if state.packets.len() >= UDP_FLOW_QUEUE {
            return Err(TrySendError::Full(packet));
        }
        state.packets.push_back(packet);
        drop(state);
        self.0.activity.touch();
        self.0.ready.notify_one();
        Ok(())
    }

    fn is_closed(&self) -> bool {
        self.0.state().closed
    }

    /// How long the flow has been without a datagram either way at `now`.
    fn idle(&self, now: tokio::time::Instant) -> Duration {
        self.0.activity.idle(now)
    }
}

impl Drop for FlowSender {
    fn drop(&mut self) {
        self.0.close();
    }
}

/// The flow task's end.
struct FlowReceiver(Arc<FlowQueue>);

impl FlowReceiver {
    /// The next datagram; `None` once the tunnel dropped the flow and the
    /// queue is empty. Cancel safe: a datagram is only taken when returned.
    async fn recv(&mut self) -> Option<Vec<u8>> {
        loop {
            {
                let mut state = self.0.state();
                if let Some(packet) = state.packets.pop_front() {
                    return Some(packet);
                }
                if state.closed {
                    return None;
                }
            }
            self.0.ready.notified().await;
        }
    }
}

impl FlowReceiver {
    /// Records a reply passing to the app now.
    fn touch(&self) {
        self.0.activity.touch();
    }
}

impl Drop for FlowReceiver {
    fn drop(&mut self) {
        let mut state = self.0.state();
        state.closed = true;
        // Datagrams nobody will send go now, not with the tunnel's map entry.
        state.packets = std::collections::VecDeque::new();
    }
}

/// Waits for the next reply of a flow. The receiver moves into the future
/// and comes back with the reply, so a pending read is never cancelled
/// halfway through a datagram while the flow lives.
type PendingReply =
    BoxFuture<'static, (Box<dyn engine_outbound::DatagramRecv>, io::Result<Vec<u8>>)>;

fn next_reply(mut recv: Box<dyn engine_outbound::DatagramRecv>) -> PendingReply {
    Box::pin(async move {
        let reply = recv.recv().await;
        (recv, reply)
    })
}

// QUIC's port: a flow there that cannot be opened (no UDP on the outbound,
// or `block_quic`) is refused with ICMP so the app falls back to TCP at once.
use crate::connections::QUIC_PORT;
/// ICMP errors sent per refused flow (QUIC clients resend their first
/// packet a few times).
const MAX_ICMP_PER_FLOW: u32 = 4;
/// Longest wait for the rest of a QUIC ClientHello split over Initial
/// packets. Clients send those back to back, so this only bounds a client
/// that never sends the rest.
const QUIC_HELLO_WAIT: Duration = Duration::from_millis(200);

/// Relays one UDP flow until it idles out or either side ends. Replies go
/// back to the app from the destination it sent to.
///
/// One task per flow, sized for the relay loop: opening the flow (routing,
/// rules, the outbound's handshake) runs in a boxed future that is freed
/// once the flow is open, so it does not stay in every flow's task.
///
/// With an `interceptor` (only for QUIC's port), the QUIC client's first
/// packets are read for the server name first; QUIC to a host the
/// interceptor decrypts is refused like `block_quic`, so the app falls back
/// to TCP and its requests are decrypted instead of passing by. The packets
/// read meanwhile are relayed first once the flow opens.
#[allow(clippy::too_many_arguments)]
async fn run_udp_flow(
    mut packets: FlowReceiver,
    app: SocketAddr,
    destination: SocketAddr,
    dispatcher: Arc<Dispatcher>,
    interceptor: Option<Arc<dyn FlowInterceptor>>,
    stats: Arc<TunnelStats>,
    replies: mpsc::Sender<UdpMsg>,
    raw: Arc<dyn PacketWriter>,
    connect_timeout: Duration,
) {
    let mut held = Vec::new();
    if let Some(interceptor) = interceptor {
        // Boxed like opening below, so the sniffing state is freed after.
        let refused = {
            let sniff: BoxFuture<'_, Option<String>> = Box::pin(async {
                let sniffed = sniff_quic_name(&mut packets, &mut held).await;
                let mapped = dispatcher.fake_ip_name(destination.ip());
                [sniffed, mapped]
                    .into_iter()
                    .flatten()
                    .find(|host| interceptor.refuses_quic(host))
            });
            sniff.await
        };
        if let Some(host) = refused {
            dispatcher.refuse_quic_for_decryption(destination, &host);
            bump(&stats.udp_failed);
            bump(&stats.quic_mitm_fallback);
            refuse_udp_flow(packets, held, app, destination, &stats, Some(raw.as_ref())).await;
            return;
        }
    }
    let process = flow_process(&dispatcher, move || flow_lookup::udp(app)).await;
    let opened = {
        let open: BoxFuture<'_, io::Result<UdpFlow>> = Box::pin(async {
            let target = TargetAddr::Ip(destination);
            let origin = FlowOrigin {
                process: process.as_deref(),
                source: FlowSource {
                    address: Some(app.ip().to_canonical()),
                    in_port: None,
                    port: Some(app.port()),
                },
                lan_peer: None,
            };
            dispatcher.open_origin_udp_flow(&target, None, origin).await
        });
        tokio::time::timeout(connect_timeout, open).await
    };
    drop(dispatcher);
    let opened = match opened {
        Ok(Ok(flow)) => Ok(flow),
        Ok(Err(error)) => Err(rejection(&error)),
        Err(_) => Err(None),
    };
    let UdpFlow { mut send, recv } = match opened {
        Ok(flow) => flow,
        Err(rejected) => {
            bump(&stats.udp_failed);
            // REJECT-DROP answers nothing, not even ICMP.
            let silent = rejected == Some(RejectAction::Drop);
            let raw = (!silent).then_some(raw.as_ref());
            refuse_udp_flow(packets, held, app, destination, &stats, raw).await;
            return;
        }
    };
    drop(raw);
    bump(&stats.udp_flows);
    for packet in held {
        if send.send(&packet).await.is_err() {
            return;
        }
        stats
            .bytes_up
            .fetch_add(packet.len() as u64, Ordering::Relaxed);
    }
    let mut pending = next_reply(recv);
    // The flow ends after a whole idle period without a datagram either way.
    let idle = tokio::time::sleep(UDP_IDLE_TIMEOUT);
    tokio::pin!(idle);
    let mut active = false;
    loop {
        tokio::select! {
            packet = packets.recv() => {
                let Some(packet) = packet else { break };
                if send.send(&packet).await.is_err() {
                    break;
                }
                stats.bytes_up.fetch_add(packet.len() as u64, Ordering::Relaxed);
                active = true;
            }
            (recv, reply) = &mut pending => {
                let Ok(reply) = reply else { break };
                stats.bytes_down.fetch_add(reply.len() as u64, Ordering::Relaxed);
                if replies.send((reply, destination, app)).await.is_err() {
                    break;
                }
                packets.touch();
                active = true;
                pending = next_reply(recv);
            }
            () = &mut idle => {
                if !active {
                    break;
                }
                active = false;
                idle.as_mut().reset(tokio::time::Instant::now() + UDP_IDLE_TIMEOUT);
            }
        }
    }
}

/// Reads a QUIC client's first datagrams into `held` until the server name
/// of its ClientHello shows; `None` when they are not QUIC Initial packets,
/// carry no name, or the rest does not come within [`QUIC_HELLO_WAIT`].
async fn sniff_quic_name(packets: &mut FlowReceiver, held: &mut Vec<Vec<u8>>) -> Option<String> {
    use engine_outbound::quic_sniff::{QuicHello, Sniffed};

    let mut hello = QuicHello::default();
    let deadline = tokio::time::Instant::now() + QUIC_HELLO_WAIT;
    loop {
        let datagram = tokio::time::timeout_at(deadline, packets.recv())
            .await
            .ok()??;
        let sniffed = hello.push(&datagram);
        held.push(datagram);
        match sniffed {
            Sniffed::Name(name) => return Some(name),
            Sniffed::None => return None,
            Sniffed::Pending => {}
        }
    }
}

/// Drops a flow that could not be opened (or was refused), staying mapped
/// until it goes quiet so an outbound without UDP is not asked again for
/// every packet. QUIC is refused with ICMP port unreachable through `raw`,
/// so it falls back to TCP instead of waiting for its handshake to time
/// out; without `raw` (REJECT-DROP) nothing is answered.
async fn refuse_udp_flow(
    mut packets: FlowReceiver,
    held: Vec<Vec<u8>>,
    app: SocketAddr,
    destination: SocketAddr,
    stats: &TunnelStats,
    raw: Option<&dyn PacketWriter>,
) {
    let mut refused = 0;
    let mut refuse = |datagram: &[u8]| {
        bump(&stats.udp_dropped);
        let Some(raw) = raw else { return };
        if destination.port() == QUIC_PORT && refused < MAX_ICMP_PER_FLOW {
            if let Some(packet) = crate::icmp::port_unreachable(app, destination, datagram.len()) {
                refused += 1;
                bump(&stats.packets_out);
                raw.write(&packet);
            }
        }
    };
    for datagram in held {
        refuse(&datagram);
    }
    while let Ok(Some(datagram)) = tokio::time::timeout(UDP_IDLE_TIMEOUT, packets.recv()).await {
        refuse(&datagram);
    }
}

/// The application's first bytes, empty when it sent none in time; `None`
/// when it closed first. A TLS ClientHello larger than one segment (such as
/// one with post-quantum key shares) arrives in pieces: reading goes on until
/// its first record is whole, so the server name can be read from it.
/// With [`Wait::Skip`] nothing is read and the payload is empty at once.
async fn read_first_payload(inbound: &mut (impl AsyncRead + Unpin), wait: Wait) -> Option<Vec<u8>> {
    let wait = match wait {
        Wait::Skip => return Some(Vec::new()),
        Wait::ClientFirst => FIRST_PAYLOAD_CLIENT_FIRST_WAIT,
        Wait::Sniff => FIRST_PAYLOAD_WAIT,
    };
    let mut first = vec![0u8; FIRST_PAYLOAD_MAX];
    let mut len = match tokio::time::timeout(wait, inbound.read(&mut first)).await {
        Ok(Ok(0)) | Ok(Err(_)) => return None,
        Ok(Ok(n)) => n,
        Err(_) => 0,
    };
    if let Some(record) = tls_record_len(&first[..len]) {
        let record = record.min(FIRST_TLS_RECORD_MAX);
        if record > first.len() {
            first.resize(record, 0);
        }
        while len < record {
            match tokio::time::timeout(
                FIRST_PAYLOAD_CLIENT_FIRST_WAIT,
                inbound.read(&mut first[len..record]),
            )
            .await
            {
                Ok(Ok(n)) if n > 0 => len += n,
                _ => break,
            }
        }
    }
    first.truncate(len);
    Some(first)
}

/// What every TCP flow of one tunnel shares besides the dispatcher.
struct TcpShared {
    /// Hold slots for REJECT-DROP flows (see [`answer_rejected`]).
    drop_holds: Semaphore,
    /// Destinations that do not get the first-payload wait.
    server_first: ServerFirst,
    /// The connections that hold a permit, for closing the idle one.
    live: LiveTcp,
}

/// When a TCP connection or UDP flow last carried data: milliseconds after
/// it was opened, so one atomic store per read keeps it current and any
/// thread can read it.
struct LastActive {
    opened: tokio::time::Instant,
    millis: AtomicU64,
}

impl LastActive {
    fn new() -> Self {
        Self {
            opened: tokio::time::Instant::now(),
            millis: AtomicU64::new(0),
        }
    }

    /// Records data passing now.
    fn touch(&self) {
        let millis = u64::try_from(self.opened.elapsed().as_millis()).unwrap_or(u64::MAX);
        self.millis.store(millis, Ordering::Relaxed);
    }

    /// How long it has been without data at `now`.
    fn idle(&self, now: tokio::time::Instant) -> Duration {
        let last = self.opened + Duration::from_millis(self.millis.load(Ordering::Relaxed));
        now.saturating_duration_since(last)
    }
}

/// The live TCP connections of a tunnel and when each last carried data.
/// A connection is registered while it holds its permit; at the limit the
/// one idle longest is told to close ([`LiveTcp::evict_idle`]).
#[derive(Default)]
struct LiveTcp {
    next_id: AtomicU64,
    table: std::sync::Mutex<HashMap<u64, LiveEntry>>,
}

struct LiveEntry {
    activity: Arc<LastActive>,
    evict: Arc<tokio::sync::Notify>,
}

impl LiveTcp {
    fn table(&self) -> std::sync::MutexGuard<'_, HashMap<u64, LiveEntry>> {
        self.table
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn register(&self, activity: Arc<LastActive>) -> LiveConn<'_> {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let evict = Arc::new(tokio::sync::Notify::new());
        self.table().insert(
            id,
            LiveEntry {
                activity,
                evict: evict.clone(),
            },
        );
        LiveConn {
            live: self,
            id,
            evict,
        }
    }

    /// Tells the connection idle longest to close, if it has been idle for
    /// at least `min_idle` at `now`; `true` when one was told. One pass over
    /// the table, only when it is full. The connection leaves the table at
    /// once, so the next new connection picks another one.
    fn evict_idle(&self, now: tokio::time::Instant, min_idle: Duration) -> bool {
        let mut table = self.table();
        let victim = table
            .iter()
            .map(|(id, entry)| (entry.activity.idle(now), *id))
            .filter(|(idle, _)| *idle >= min_idle)
            .max_by_key(|(idle, _)| *idle)
            .map(|(_, id)| id);
        let Some(entry) = victim.and_then(|id| table.remove(&id)) else {
            return false;
        };
        drop(table);
        // Keeps a permit when the connection is not waiting yet.
        entry.evict.notify_one();
        true
    }
}

/// A registered connection; leaves the table when dropped.
struct LiveConn<'a> {
    live: &'a LiveTcp,
    id: u64,
    evict: Arc<tokio::sync::Notify>,
}

impl LiveConn<'_> {
    /// Completes when the connection was chosen to make room.
    async fn evicted(&self) {
        self.evict.notified().await;
    }
}

impl Drop for LiveConn<'_> {
    fn drop(&mut self) {
        self.live.table().remove(&self.id);
    }
}

/// Answers a TCP flow a routing rule rejected, once its first bytes are
/// read: `REJECT-TINYGIF` answers a plain HTTP request with a 1x1 GIF,
/// `REJECT-DROP` keeps the flow open without a word (while a hold slot is
/// free), and everything else closes.
async fn answer_rejected(
    mut inbound: netstack_smoltcp::TcpStream,
    action: RejectAction,
    plain_http: bool,
    drop_holds: &Semaphore,
) {
    match action {
        RejectAction::TinyGif if plain_http => {
            let response = engine_outbound::reject::tiny_gif_response();
            if inbound.write_all(&response).await.is_ok() {
                let _ = inbound.shutdown().await;
            }
        }
        RejectAction::Drop => {
            if let Ok(_slot) = drop_holds.try_acquire() {
                engine_outbound::reject::hold(&mut inbound, engine_outbound::reject::DROP_HOLD)
                    .await;
            }
        }
        RejectAction::TinyGif | RejectAction::Close => {}
    }
}

/// Process lookups for tunnel flows: [`crate::process`] where the build has
/// it (feature `local-proxy`), nothing otherwise.
#[cfg(feature = "local-proxy")]
mod flow_lookup {
    pub use crate::process::{
        process_name as tcp, udp_process_name as udp, TUNNEL_LOOKUP as ENABLED,
    };
}

#[cfg(not(feature = "local-proxy"))]
mod flow_lookup {
    use std::net::SocketAddr;

    pub const ENABLED: bool = false;

    pub fn tcp(_app: SocketAddr, _server: SocketAddr) -> Option<String> {
        None
    }

    pub fn udp(_app: SocketAddr) -> Option<String> {
        None
    }
}

/// The local process behind a tunnel flow, for `PROCESS-NAME` rules: looked
/// up on a blocking thread with `lookup`, only where the tunnel can see the
/// app's socket (`process::TUNNEL_LOOKUP`) and only when a rule
/// needs it.
async fn flow_process(
    dispatcher: &Dispatcher,
    lookup: impl FnOnce() -> Option<String> + Send + 'static,
) -> Option<String> {
    if !flow_lookup::ENABLED || !dispatcher.wants_process() {
        return None;
    }
    tokio::task::spawn_blocking(lookup).await.ok().flatten()
}

/// Length of the TLS handshake record `bytes` starts with, header included.
fn tls_record_len(bytes: &[u8]) -> Option<usize> {
    if bytes.len() < 5 || bytes[0] != 0x16 || bytes[1] != 0x03 {
        return None;
    }
    Some(5 + usize::from(u16::from_be_bytes([bytes[3], bytes[4]])))
}

/// Relays one TCP flow, recording in `activity` when payload passes.
#[allow(clippy::too_many_arguments)]
async fn handle_tcp(
    mut inbound: netstack_smoltcp::TcpStream,
    target: SocketAddr,
    dispatcher: &Dispatcher,
    interceptor: Option<&dyn FlowInterceptor>,
    stats: &TunnelStats,
    settings: &TunnelSettings,
    shared: &TcpShared,
    activity: &Arc<LastActive>,
) {
    // The app (or, with the tunnel as a gateway, the device) that opened
    // the flow, for SRC-IP rules; the tunnel has no listener port.
    let inbound_app = *inbound.local_addr();
    let source = FlowSource {
        address: Some(inbound_app.ip().to_canonical()),
        in_port: None,
        port: Some(inbound_app.port()),
    };
    let server_first = &shared.server_first;
    let wait = server_first.wait(target);
    if wait == Wait::Skip {
        bump(&stats.tcp_first_wait_skipped);
    }
    let Some(first) = read_first_payload(&mut inbound, wait).await else {
        return;
    };
    if first.is_empty() && wait == Wait::Sniff {
        // Silent for the whole wait: a server-first protocol, most likely.
        server_first.learn(target);
    }

    if let Some(interceptor) = interceptor {
        if let Some(host) = interceptor.claim(&first, target) {
            bump(&stats.mitm_flows);
            let http = sniff::http_request_head(&first);
            let outbound = dispatcher.with_origin_request(&host, http.as_ref(), source);
            let flow = InterceptedFlow {
                // Payload either way through the app's side keeps the flow
                // from looking idle.
                inbound: Box::new(Active {
                    inner: inbound,
                    activity: activity.clone(),
                }),
                first,
                host: host.clone(),
                target,
            };
            interceptor.serve(flow, &outbound, settings, stats).await;
            return;
        }
    }

    let host = sniff::host(&first);
    let http = sniff::http_request_head(&first);
    let process = flow_process(dispatcher, move || flow_lookup::tcp(inbound_app, target)).await;
    let target = TargetAddr::Ip(target);
    let origin = FlowOrigin {
        process: process.as_deref(),
        source,
        lan_peer: None,
    };
    let connect = dispatcher.connect_origin_flow(&target, host.as_deref(), origin, http.as_ref());
    let mut remote = match tokio::time::timeout(settings.connect_timeout, connect).await {
        Ok(Ok(remote)) => remote,
        Ok(Err(err)) => {
            bump(&stats.tcp_connect_failed);
            record(&stats.tcp_last_failure, OutboundFailure::connect(&err));
            if let Some(action) = rejection(&err) {
                answer_rejected(inbound, action, http.is_some(), &shared.drop_holds).await;
            }
            return;
        }
        Err(_) => {
            bump(&stats.tcp_connect_failed);
            record(&stats.tcp_last_failure, OutboundFailure::ConnectTimeout);
            return;
        }
    };
    if !first.is_empty() {
        let written = match remote.write_all(&first).await {
            Ok(()) => remote.flush().await,
            Err(err) => Err(err),
        };
        if let Err(err) = written {
            bump(&stats.tcp_connect_failed);
            record(&stats.tcp_last_failure, OutboundFailure::reply(&err));
            return;
        }
        stats
            .bytes_up
            .fetch_add(first.len() as u64, Ordering::Relaxed);
    }
    drop(first);

    let mut inbound = Counted::new(inbound, activity.clone(), &stats.bytes_up);
    let mut remote = Counted::new(remote, activity.clone(), &stats.bytes_down);
    let copy = tokio::io::copy_bidirectional_with_sizes(
        &mut inbound,
        &mut remote,
        RELAY_BUFFER_BYTES,
        RELAY_BUFFER_BYTES,
    );
    tokio::pin!(copy);
    // Ends once a whole `idle_timeout` passed without payload either way.
    let mut wait = settings.idle_timeout;
    loop {
        tokio::select! {
            result = &mut copy => {
                // Resets are routine; only a reply the outbound rejects is worth reporting.
                if let Err(err) = result {
                    if err.kind() == io::ErrorKind::InvalidData {
                        record(&stats.tcp_last_failure, OutboundFailure::ReplyRejected);
                    }
                }
                break;
            }
            _ = tokio::time::sleep(wait) => {
                let idle = activity.idle(tokio::time::Instant::now());
                if idle >= settings.idle_timeout {
                    break;
                }
                wait = settings.idle_timeout - idle;
            }
        }
    }
}

/// A stream that records in `activity` when payload passes either way.
struct Active<S> {
    inner: S,
    activity: Arc<LastActive>,
}

impl<S: AsyncRead + Unpin> AsyncRead for Active<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let before = buf.filled().len();
        let result = Pin::new(&mut this.inner).poll_read(cx, buf);
        if buf.filled().len() > before {
            this.activity.touch();
        }
        result
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Active<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let result = Pin::new(&mut this.inner).poll_write(cx, buf);
        if matches!(result, Poll::Ready(Ok(n)) if n > 0) {
            this.activity.touch();
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

/// Counts bytes read from the wrapped stream and records activity for the
/// idle timer and for closing idle connections at the limit.
struct Counted<'a, S> {
    inner: S,
    activity: Arc<LastActive>,
    bytes_read: &'a AtomicU64,
}

impl<'a, S> Counted<'a, S> {
    fn new(inner: S, activity: Arc<LastActive>, bytes_read: &'a AtomicU64) -> Self {
        Self {
            inner,
            activity,
            bytes_read,
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for Counted<'_, S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let before = buf.filled().len();
        let result = Pin::new(&mut this.inner).poll_read(cx, buf);
        let n = (buf.filled().len() - before) as u64;
        if n > 0 {
            this.bytes_read.fetch_add(n, Ordering::Relaxed);
            this.activity.touch();
        }
        result
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Counted<'_, S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn a_client_hello_in_pieces_is_read_whole() {
        let mut record = vec![0x16, 0x03, 0x01, 0x17, 0x00];
        record.extend((0..0x1700).map(|i| i as u8));
        let (mut app, mut tunnel_side) = tokio::io::duplex(64 * 1024);
        let sent = record.clone();
        let writer = tokio::spawn(async move {
            app.write_all(&sent[..1400]).await.unwrap();
            tokio::time::sleep(Duration::from_millis(150)).await;
            app.write_all(&sent[1400..]).await.unwrap();
            app
        });
        let first = read_first_payload(&mut tunnel_side, Wait::ClientFirst)
            .await
            .unwrap();
        assert_eq!(first, record);
        drop(writer.await.unwrap());
    }

    #[tokio::test]
    async fn http_and_https_wait_longer_than_other_ports_for_the_first_bytes() {
        let (mut app, mut tunnel_side) = tokio::io::duplex(1024);
        let writer = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(300)).await;
            app.write_all(b"GET / HTTP/1.1\r\n\r\n").await.unwrap();
            app
        });
        let first = read_first_payload(&mut tunnel_side, Wait::ClientFirst)
            .await
            .unwrap();
        assert_eq!(first, b"GET / HTTP/1.1\r\n\r\n");
        drop(writer.await.unwrap());

        let (_app, mut tunnel_side) = tokio::io::duplex(1024);
        let started = std::time::Instant::now();
        assert_eq!(
            read_first_payload(&mut tunnel_side, Wait::Sniff)
                .await
                .unwrap(),
            b""
        );
        assert!(started.elapsed() < Duration::from_millis(900));
    }

    #[test]
    fn connection_limits_stay_tight_only_on_ios() {
        #[cfg(target_os = "ios")]
        let expected = (128, 256);
        #[cfg(target_os = "android")]
        let expected = (512, 4096);
        #[cfg(not(any(target_os = "ios", target_os = "android")))]
        let expected = (1024, 4096);
        assert_eq!(
            (DEFAULT_MAX_TCP_CONNECTIONS, DEFAULT_MAX_UDP_FLOWS),
            expected
        );
        let limits = crate::config::Limits::default();
        assert_eq!(limits.max_tcp_connections, DEFAULT_MAX_TCP_CONNECTIONS);
        assert_eq!(limits.max_udp_flows, DEFAULT_MAX_UDP_FLOWS);
        let parsed: crate::config::Limits = serde_json::from_str("{}").unwrap();
        assert_eq!(parsed.max_tcp_connections, DEFAULT_MAX_TCP_CONNECTIONS);
        assert_eq!(parsed.max_udp_flows, DEFAULT_MAX_UDP_FLOWS);
    }

    /// Marks `activity` as having carried data `after` its start.
    fn active_after(activity: &LastActive, after: Duration) {
        activity
            .millis
            .store(after.as_millis() as u64, Ordering::Relaxed);
    }

    #[tokio::test]
    async fn the_tcp_connection_idle_longest_makes_room() {
        let live = LiveTcp::default();
        let quiet = Arc::new(LastActive::new());
        let busy = Arc::new(LastActive::new());
        let quiet_conn = live.register(quiet.clone());
        let busy_conn = live.register(busy.clone());
        active_after(&busy, Duration::from_secs(60));
        let now = tokio::time::Instant::now() + Duration::from_secs(60);

        // Nobody has been idle for two minutes: the new connection is refused.
        assert!(!live.evict_idle(now, Duration::from_secs(120)));
        assert!(live.evict_idle(now, DEFAULT_TCP_EVICT_IDLE));
        tokio::time::timeout(Duration::from_secs(1), quiet_conn.evicted())
            .await
            .expect("the idle connection is told to close");
        assert!(
            tokio::time::timeout(Duration::from_millis(50), busy_conn.evicted())
                .await
                .is_err(),
            "the active connection stays"
        );
        // The busy one was active just now; the quiet one already left.
        assert!(!live.evict_idle(now, DEFAULT_TCP_EVICT_IDLE));
        drop(quiet_conn);
        drop(busy_conn);
        assert!(live.table().is_empty());
    }

    fn udp_settings(max_udp_flows: usize) -> TunnelSettings {
        TunnelSettings {
            mtu: 1500,
            tcp_window_bytes: 64 * 1024,
            max_tcp_connections: 8,
            max_udp_flows,
            tcp_evict_idle: DEFAULT_TCP_EVICT_IDLE,
            udp_evict_idle: DEFAULT_UDP_EVICT_IDLE,
            max_dns_in_flight: 4,
            idle_timeout: Duration::from_secs(30),
            connect_timeout: Duration::from_secs(5),
            dns: Arc::new(DnsPolicy::tcp(
                SocketAddr::from(([1, 1, 1, 1], 53)),
                Duration::from_secs(5),
            )),
            worker_threads: 1,
        }
    }

    fn app(port: u16) -> SocketAddr {
        SocketAddr::from(([10, 0, 0, 2], port))
    }

    fn peer(port: u16) -> SocketAddr {
        SocketAddr::from(([10, 0, 0, 80], port))
    }

    /// Adds a flow as `forward` does; the flow lives while the receiver does.
    fn open(flows: &mut UdpFlows, src: SocketAddr, dst: SocketAddr) -> FlowReceiver {
        let (sender, receiver) = flow_queue();
        flows.map.insert((src, dst), sender);
        receiver
    }

    fn is_closed(flow: &FlowReceiver) -> bool {
        flow.0.state().closed
    }

    #[test]
    fn a_full_udp_table_closes_its_idle_flow_for_a_new_one() {
        let settings = udp_settings(2);
        let stats = TunnelStats::default();
        let mut flows = UdpFlows::default();
        let idle = open(&mut flows, app(5001), peer(7001));
        let busy = open(&mut flows, app(5002), peer(7002));
        active_after(&busy.0.activity, Duration::from_secs(60));
        let now = tokio::time::Instant::now() + Duration::from_secs(60);

        assert!(flows.make_room(app(5003), now, &settings, &stats));
        assert!(is_closed(&idle), "the idle flow's task ends");
        assert!(!is_closed(&busy));
        assert!(flows.map.contains_key(&(app(5002), peer(7002))));
        assert_eq!(stats.snapshot().udp_evicted, 1);
        assert_eq!(stats.snapshot().udp_dropped, 0);
    }

    #[test]
    fn one_app_fanning_out_does_not_block_another() {
        let settings = udp_settings(4);
        let stats = TunnelStats::default();
        let mut flows = UdpFlows::default();
        // One socket talks to four peers at once, all of them active.
        let fan: Vec<_> = (7001..7005)
            .map(|port| open(&mut flows, app(6881), peer(port)))
            .collect();
        for flow in &fan {
            active_after(&flow.0.activity, Duration::from_secs(60));
        }
        let now = tokio::time::Instant::now() + Duration::from_secs(60);

        assert!(flows.make_room(app(5000), now, &settings, &stats));
        assert_eq!(fan.iter().filter(|flow| is_closed(flow)).count(), 1);
        assert_eq!(flows.map.len(), 3);
        assert_eq!(stats.snapshot().udp_evicted, 1);
    }

    #[test]
    fn without_anything_to_close_the_full_table_is_not_scanned_again_at_once() {
        let settings = udp_settings(2);
        let stats = TunnelStats::default();
        let mut flows = UdpFlows::default();
        let first = open(&mut flows, app(5001), peer(7001));
        let second = open(&mut flows, app(5002), peer(7002));
        active_after(&first.0.activity, Duration::from_secs(60));
        active_after(&second.0.activity, Duration::from_secs(60));
        let now = tokio::time::Instant::now() + Duration::from_secs(60);

        // Two apps with one active flow each: nothing may go.
        assert!(!flows.make_room(app(5003), now, &settings, &stats));
        // A flow that ended is only noticed after the pause...
        drop(first);
        assert!(!flows.make_room(app(5003), now, &settings, &stats));
        assert_eq!(flows.map.len(), 2);
        // ...and then cleared without closing anything else.
        let later = now + UDP_RESCAN_AFTER;
        assert!(flows.make_room(app(5003), later, &settings, &stats));
        assert_eq!(flows.map.len(), 1);
        assert!(!is_closed(&second));
        assert_eq!(stats.snapshot().udp_evicted, 0);
    }

    #[test]
    fn a_full_table_frees_a_batch_of_idle_flows_in_one_pass() {
        let settings = udp_settings(64);
        let stats = TunnelStats::default();
        let mut flows = UdpFlows::default();
        let open_flows: Vec<_> = (0..64)
            .map(|i| open(&mut flows, app(10_000 + i), peer(7000)))
            .collect();
        let now = tokio::time::Instant::now() + Duration::from_secs(60);

        assert!(flows.make_room(app(9999), now, &settings, &stats));
        // 64 / 16: the next three new flows need no pass.
        assert_eq!(flows.map.len(), 60);
        assert_eq!(open_flows.iter().filter(|flow| is_closed(flow)).count(), 4);
        assert_eq!(stats.snapshot().udp_evicted, 4);
    }
}
