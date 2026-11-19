//! Node checkup (节点体检): a user-started measurement of one node, run
//! through the same outbound the engine would use for it.
//!
//! - **Latency**: `samples` rounds of a connect + TLS handshake to
//!   `handshake_url` (one real round trip through the node, so a node that
//!   accepts the connection locally but cannot reach anything fails) and one
//!   HTTP request to `latency_url`. The first handshake is reported apart as
//!   the cold one: it pays the protocol's own handshake, which later rounds
//!   may reuse. Medians, jitter (mean difference of consecutive samples,
//!   RFC 3550 style) and loss.
//! - **Throughput** (optional): `connections` parallel downloads of
//!   `download_url` for `duration_ms`, the per-second curve, and the latency
//!   of a fresh request to `latency_url` every `probe_interval_ms` while the
//!   download runs ("loaded latency"); `bloat_ms` is loaded minus idle.
//!
//! The defaults match AnixOps Speedtest so numbers from both compare. Every
//! address is the caller's to change; nothing here runs unless a user starts
//! it. Failures are fixed codes without node values.

use std::fmt;
use std::io;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use engine_outbound::registry::OutboundRegistry;
use engine_outbound::{BoxStream, Dialer, TcpDialer, TcpOutbound};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::Instant;
use transport_tls::TlsConnector;

use crate::config::RuntimeConfig;
use crate::delay::{self, DelayError, ProbeUrl};
use crate::{protocols, RuntimeError};

/// A connect + TLS handshake target that answers from many places.
pub const DEFAULT_HANDSHAKE_URL: &str = "https://1.1.1.1/";
/// The request used for latency, the same as delay tests.
pub const DEFAULT_LATENCY_URL: &str = "https://www.gstatic.com/generate_204";
/// A download that is large enough for one throughput chunk.
pub const DEFAULT_DOWNLOAD_URL: &str = "https://speed.cloudflare.com/__down?bytes=25000000";

const MAX_SAMPLES: u32 = 20;
const MAX_CONNECTIONS: u32 = 16;
const MAX_DURATION_MS: u64 = 30_000;
const MIN_DURATION_MS: u64 = 1_000;
const MIN_PROBE_INTERVAL_MS: u64 = 100;
const MAX_TIMEOUT_MS: u64 = 30_000;
const MAX_IDLE_SAMPLES: u32 = 10;
/// Response heads longer than this are not HTTP for our purpose.
const MAX_HEAD_BYTES: usize = 16 * 1024;
/// A download worker gives up after this many failed requests in a row.
const MAX_WORKER_FAILURES: u32 = 3;

/// What a checkup measures. Unknown fields are rejected so a client and the
/// kernel never disagree silently.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct CheckupOptions {
    /// Latency rounds, 1 to 20.
    pub samples: u32,
    /// Limit for one handshake or request, 1 ms to 30 s.
    pub timeout_ms: u64,
    pub handshake_url: String,
    pub latency_url: String,
    /// The throughput suite; off when absent.
    pub throughput: Option<ThroughputOptions>,
}

impl Default for CheckupOptions {
    fn default() -> Self {
        Self {
            samples: 5,
            timeout_ms: 5_000,
            handshake_url: DEFAULT_HANDSHAKE_URL.to_string(),
            latency_url: DEFAULT_LATENCY_URL.to_string(),
            throughput: None,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct ThroughputOptions {
    /// Parallel downloads, 1 to 16.
    pub connections: u32,
    /// How long the download runs, 1 s to 30 s.
    pub duration_ms: u64,
    pub download_url: String,
    /// Stop once this many bytes arrived (0 = no cap); bounds the traffic a
    /// checkup spends on a metered node.
    pub max_bytes: u64,
    /// Loaded-latency probe interval, at least 100 ms.
    pub probe_interval_ms: u64,
    /// Idle-latency probes before the load, 1 to 10.
    pub idle_samples: u32,
}

impl Default for ThroughputOptions {
    fn default() -> Self {
        Self {
            connections: 4,
            duration_ms: 8_000,
            download_url: DEFAULT_DOWNLOAD_URL.to_string(),
            max_bytes: 0,
            probe_interval_ms: 500,
            idle_samples: 3,
        }
    }
}

impl CheckupOptions {
    pub fn validate(&self) -> Result<(), CheckupError> {
        if !(1..=MAX_SAMPLES).contains(&self.samples) {
            return Err(CheckupError::InvalidOptions("samples must be 1 to 20"));
        }
        if !(1..=MAX_TIMEOUT_MS).contains(&self.timeout_ms) {
            return Err(CheckupError::InvalidOptions(
                "timeout_ms must be 1 to 30000",
            ));
        }
        for url in [&self.handshake_url, &self.latency_url] {
            if ProbeUrl::parse(url).is_none() {
                return Err(CheckupError::InvalidOptions(
                    "urls must be http or https URLs",
                ));
            }
        }
        if let Some(throughput) = &self.throughput {
            if !(1..=MAX_CONNECTIONS).contains(&throughput.connections) {
                return Err(CheckupError::InvalidOptions("connections must be 1 to 16"));
            }
            if !(MIN_DURATION_MS..=MAX_DURATION_MS).contains(&throughput.duration_ms) {
                return Err(CheckupError::InvalidOptions(
                    "duration_ms must be 1000 to 30000",
                ));
            }
            if throughput.probe_interval_ms < MIN_PROBE_INTERVAL_MS {
                return Err(CheckupError::InvalidOptions(
                    "probe_interval_ms must be at least 100",
                ));
            }
            if !(1..=MAX_IDLE_SAMPLES).contains(&throughput.idle_samples) {
                return Err(CheckupError::InvalidOptions("idle_samples must be 1 to 10"));
            }
            if ProbeUrl::parse(&throughput.download_url).is_none() {
                return Err(CheckupError::InvalidOptions(
                    "urls must be http or https URLs",
                ));
            }
        }
        Ok(())
    }

    fn timeout(&self) -> Duration {
        Duration::from_millis(self.timeout_ms)
    }
}

/// Why a checkup could not start. Fixed text, no node values.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CheckupError {
    Config(RuntimeError),
    InvalidOptions(&'static str),
    Runtime(io::ErrorKind),
}

impl fmt::Display for CheckupError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CheckupError::Config(error) => write!(f, "checkup config rejected: {error}"),
            CheckupError::InvalidOptions(why) => write!(f, "checkup options rejected: {why}"),
            CheckupError::Runtime(kind) => write!(f, "checkup could not start: {kind}"),
        }
    }
}

impl std::error::Error for CheckupError {}

/// Why one probe failed, as a fixed code.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProbeFailure {
    Timeout,
    ConnectFailed,
    TlsFailed,
    NotHttp,
    HttpStatus,
}

impl From<DelayError> for ProbeFailure {
    fn from(error: DelayError) -> Self {
        match error {
            DelayError::Timeout => ProbeFailure::Timeout,
            DelayError::NotHttp => ProbeFailure::NotHttp,
            DelayError::Config(_) | DelayError::InvalidUrl | DelayError::Failed(_) => {
                ProbeFailure::ConnectFailed
            }
        }
    }
}

#[derive(Clone, Debug, Default, Serialize, PartialEq)]
pub struct CheckupReport {
    pub latency: LatencyReport,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub throughput: Option<ThroughputReport>,
}

#[derive(Clone, Debug, Default, Serialize, PartialEq)]
pub struct LatencyReport {
    pub samples: u32,
    /// Median connect + handshake time of the successful rounds.
    pub handshake_ms: Option<f64>,
    /// The first round's handshake.
    pub cold_handshake_ms: Option<f64>,
    /// Median of the later rounds' handshakes (with two or more rounds).
    pub warm_handshake_ms: Option<f64>,
    pub handshake_loss_pct: f64,
    /// Median time of the HTTP request (connect, TLS, first response line).
    pub request_ms: Option<f64>,
    pub request_jitter_ms: Option<f64>,
    pub request_loss_pct: f64,
    /// The last failure, when any round failed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub failure: Option<ProbeFailure>,
}

#[derive(Clone, Debug, Default, Serialize, PartialEq)]
pub struct ThroughputReport {
    pub connections: u32,
    /// Median idle request latency before the download.
    pub idle_ms: Option<f64>,
    /// Average over the whole download.
    pub mbps: f64,
    /// Best one-second window.
    pub peak_mbps: f64,
    pub bytes: u64,
    pub seconds: f64,
    /// Throughput of each whole second, in order.
    pub per_second_mbps: Vec<f64>,
    /// Median and 90th percentile request latency during the download.
    pub loaded_ms: Option<f64>,
    pub loaded_p90_ms: Option<f64>,
    /// Loaded minus idle: the queueing the download added.
    pub bloat_ms: Option<f64>,
    pub loaded_loss_pct: f64,
    /// `max_bytes` ended the download before `duration_ms`.
    pub capped: bool,
    /// Why no data arrived, when none did.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub failure: Option<ProbeFailure>,
}

/// Runs a checkup of the outbound of `config` (an engine envelope) on its
/// own runtime, as delay tests do.
pub fn run_checkup(config: &[u8], options: &CheckupOptions) -> Result<CheckupReport, CheckupError> {
    run_checkup_with(
        config,
        options,
        &protocols::default_registry(),
        Arc::new(TcpDialer),
    )
}

pub fn run_checkup_with(
    config: &[u8],
    options: &CheckupOptions,
    registry: &OutboundRegistry,
    dialer: Arc<dyn Dialer>,
) -> Result<CheckupReport, CheckupError> {
    options.validate()?;
    let config = RuntimeConfig::from_json(config).map_err(CheckupError::Config)?;
    let outbound = config
        .build_outbound(registry, dialer)
        .map_err(CheckupError::Config)?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|error| CheckupError::Runtime(error.kind()))?;
    runtime.block_on(checkup(outbound, options))
}

/// Runs a checkup through `outbound` on the caller's runtime.
pub async fn checkup(
    outbound: Arc<dyn TcpOutbound>,
    options: &CheckupOptions,
) -> Result<CheckupReport, CheckupError> {
    options.validate()?;
    let latency = latency(&*outbound, options).await;
    let throughput = match &options.throughput {
        Some(throughput) => Some(self::throughput(outbound, options, throughput).await),
        None => None,
    };
    Ok(CheckupReport {
        latency,
        throughput,
    })
}

async fn latency(outbound: &dyn TcpOutbound, options: &CheckupOptions) -> LatencyReport {
    let timeout = options.timeout();
    let mut handshakes = Samples::default();
    let mut requests = Samples::default();
    let mut cold = None;
    let mut warm = Samples::default();
    let mut failure = None;
    for round in 0..options.samples {
        let handshake = handshake_once(outbound, &options.handshake_url, timeout).await;
        let ms = handshakes.add(handshake);
        if round == 0 {
            cold = ms;
        } else {
            warm.add(handshake);
        }
        if let Err(error) = handshake {
            failure = Some(error);
        }
        let request = delay::probe(outbound, &options.latency_url, timeout)
            .await
            .map_err(ProbeFailure::from);
        requests.add(request);
        if let Err(error) = request {
            failure = Some(error);
        }
    }
    LatencyReport {
        samples: options.samples,
        handshake_ms: handshakes.median(),
        cold_handshake_ms: cold,
        warm_handshake_ms: warm.median(),
        handshake_loss_pct: handshakes.loss_pct(),
        request_ms: requests.median(),
        request_jitter_ms: requests.jitter(),
        request_loss_pct: requests.loss_pct(),
        failure,
    }
}

/// Connect + TLS handshake to an `https` URL; an `http` URL is measured
/// like a delay test, since without TLS only a request makes a round trip.
async fn handshake_once(
    outbound: &dyn TcpOutbound,
    url: &str,
    timeout: Duration,
) -> Result<Duration, ProbeFailure> {
    let parsed = ProbeUrl::parse(url).ok_or(ProbeFailure::ConnectFailed)?;
    let Some(tls) = delay::tls_for(&parsed).map_err(ProbeFailure::from)? else {
        return delay::probe(outbound, url, timeout)
            .await
            .map_err(ProbeFailure::from);
    };
    let started = Instant::now();
    let exchange = async {
        let stream = outbound
            .connect(&parsed.target())
            .await
            .map_err(|_| ProbeFailure::ConnectFailed)?;
        tls.connect(stream)
            .await
            .map_err(|_| ProbeFailure::TlsFailed)?;
        Ok(())
    };
    match tokio::time::timeout(timeout, exchange).await {
        Ok(Ok(())) => Ok(started.elapsed()),
        Ok(Err(error)) => Err(error),
        Err(_) => Err(ProbeFailure::Timeout),
    }
}

async fn throughput(
    outbound: Arc<dyn TcpOutbound>,
    options: &CheckupOptions,
    throughput: &ThroughputOptions,
) -> ThroughputReport {
    let timeout = options.timeout();
    let mut report = ThroughputReport {
        connections: throughput.connections,
        ..ThroughputReport::default()
    };

    // One discarded request first: the first one through a fresh outbound
    // pays the protocol's cold handshake and would inflate the idle baseline.
    let _ = delay::probe(&*outbound, &options.latency_url, timeout).await;
    let mut idle = Samples::default();
    for _ in 0..throughput.idle_samples {
        idle.add(
            delay::probe(&*outbound, &options.latency_url, timeout)
                .await
                .map_err(ProbeFailure::from),
        );
    }
    report.idle_ms = idle.median();

    let Some(url) = ProbeUrl::parse(&throughput.download_url) else {
        report.failure = Some(ProbeFailure::ConnectFailed);
        return report;
    };
    let tls = match delay::tls_for(&url) {
        Ok(tls) => tls,
        Err(error) => {
            report.failure = Some(error.into());
            return report;
        }
    };

    let started = Instant::now();
    let deadline = started + Duration::from_millis(throughput.duration_ms);
    let received = Arc::new(AtomicU64::new(0));

    let workers: Vec<_> = (0..throughput.connections)
        .map(|_| {
            tokio::spawn(download_worker(
                outbound.clone(),
                url.clone(),
                tls.clone(),
                received.clone(),
                throughput.max_bytes,
                deadline,
            ))
        })
        .collect();

    // Loaded latency: a fresh request every interval while the download runs.
    let mut probes = Vec::new();
    let mut ticker = tokio::time::interval(Duration::from_millis(throughput.probe_interval_ms));
    // Per-second throughput.
    let mut per_second = Vec::new();
    let mut next_second = started + Duration::from_secs(1);
    let mut last_bytes = 0u64;
    loop {
        let done = Instant::now() >= deadline || capped(&received, throughput.max_bytes);
        if done || workers.iter().all(|worker| worker.is_finished()) {
            break;
        }
        tokio::select! {
            _ = ticker.tick() => {
                let outbound = outbound.clone();
                let url = options.latency_url.clone();
                probes.push(tokio::spawn(async move {
                    delay::probe(&*outbound, &url, timeout).await.map_err(ProbeFailure::from)
                }));
            }
            _ = tokio::time::sleep_until(next_second) => {
                let bytes = received.load(Ordering::Relaxed);
                per_second.push(mbps(bytes - last_bytes, Duration::from_secs(1)));
                last_bytes = bytes;
                next_second += Duration::from_secs(1);
            }
            _ = tokio::time::sleep_until(deadline) => {}
        }
    }
    let elapsed = started.elapsed();
    let mut failure = None;
    for worker in workers {
        // A worker stops at the deadline or the cap on its own; the abort
        // only guards against a connect that ignores both.
        let abort = worker.abort_handle();
        match tokio::time::timeout(timeout, worker).await {
            Ok(Ok(Some(error))) => failure = failure.or(Some(error)),
            Ok(Ok(None)) | Ok(Err(_)) => {}
            Err(_) => abort.abort(),
        }
    }
    let mut loaded = Samples::default();
    for probe in probes {
        match probe.await {
            Ok(result) => {
                loaded.add(result);
            }
            Err(_) => {
                loaded.add(Err(ProbeFailure::Timeout));
            }
        }
    }

    let bytes = received.load(Ordering::Relaxed);
    report.bytes = bytes;
    report.seconds = round1(elapsed.as_secs_f64());
    report.mbps = mbps(bytes, elapsed);
    report.peak_mbps = per_second.iter().copied().fold(0.0, f64::max);
    report.per_second_mbps = per_second;
    report.loaded_ms = loaded.median();
    report.loaded_p90_ms = loaded.percentile(0.9);
    report.bloat_ms = match (report.loaded_ms, report.idle_ms) {
        (Some(loaded), Some(idle)) => Some(round1(loaded - idle)),
        _ => None,
    };
    report.loaded_loss_pct = loaded.loss_pct();
    report.capped = capped(&received, throughput.max_bytes);
    if bytes == 0 {
        report.failure = Some(failure.unwrap_or(ProbeFailure::Timeout));
    }
    report
}

fn capped(received: &AtomicU64, max_bytes: u64) -> bool {
    max_bytes > 0 && received.load(Ordering::Relaxed) >= max_bytes
}

/// Downloads `url` again and again until the deadline or the cap; returns
/// the last failure when it stopped because of failures.
async fn download_worker(
    outbound: Arc<dyn TcpOutbound>,
    url: ProbeUrl,
    tls: Option<TlsConnector>,
    received: Arc<AtomicU64>,
    max_bytes: u64,
    deadline: Instant,
) -> Option<ProbeFailure> {
    let mut failures = 0;
    let mut last = None;
    while Instant::now() < deadline && !capped(&received, max_bytes) {
        let download = download_once(&*outbound, &url, tls.as_ref(), &received, max_bytes);
        match tokio::time::timeout_at(deadline, download).await {
            Ok(Ok(())) => failures = 0,
            Ok(Err(error)) => {
                failures += 1;
                last = Some(error);
                if failures >= MAX_WORKER_FAILURES {
                    return last;
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            Err(_) => break,
        }
    }
    last.filter(|_| failures > 0)
}

async fn download_once(
    outbound: &dyn TcpOutbound,
    url: &ProbeUrl,
    tls: Option<&TlsConnector>,
    received: &AtomicU64,
    max_bytes: u64,
) -> Result<(), ProbeFailure> {
    let mut stream: BoxStream = outbound
        .connect(&url.target())
        .await
        .map_err(|_| ProbeFailure::ConnectFailed)?;
    if let Some(tls) = tls {
        stream = tls
            .connect(stream)
            .await
            .map_err(|_| ProbeFailure::TlsFailed)?;
    }
    let request = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: networkcore-checkup\r\nAccept: */*\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n",
        url.path,
        url.host_header()
    );
    let failed = |_: io::Error| ProbeFailure::ConnectFailed;
    stream.write_all(request.as_bytes()).await.map_err(failed)?;
    stream.flush().await.map_err(failed)?;

    let mut buffer = vec![0u8; 64 * 1024];
    let mut head = Vec::new();
    let mut in_body = false;
    loop {
        let read = stream.read(&mut buffer).await.map_err(failed)?;
        if read == 0 {
            return if in_body {
                Ok(())
            } else {
                Err(ProbeFailure::NotHttp)
            };
        }
        if in_body {
            received.fetch_add(read as u64, Ordering::Relaxed);
        } else {
            head.extend_from_slice(&buffer[..read]);
            if let Some(end) = head.windows(4).position(|window| window == b"\r\n\r\n") {
                check_status(&head[..end])?;
                received.fetch_add((head.len() - end - 4) as u64, Ordering::Relaxed);
                head = Vec::new();
                in_body = true;
            } else if head.len() > MAX_HEAD_BYTES {
                return Err(ProbeFailure::NotHttp);
            }
        }
        if capped(received, max_bytes) {
            return Ok(());
        }
    }
}

/// Accepts only an HTTP/1.x `2xx` status line.
fn check_status(head: &[u8]) -> Result<(), ProbeFailure> {
    if head.len() < 12 || !head.starts_with(b"HTTP/1.") || head[8] != b' ' {
        return Err(ProbeFailure::NotHttp);
    }
    if !head[9..12].iter().all(u8::is_ascii_digit) {
        return Err(ProbeFailure::NotHttp);
    }
    if head[9] != b'2' {
        return Err(ProbeFailure::HttpStatus);
    }
    Ok(())
}

fn mbps(bytes: u64, elapsed: Duration) -> f64 {
    let seconds = elapsed.as_secs_f64();
    if seconds <= 0.0 {
        return 0.0;
    }
    round1(bytes as f64 * 8.0 / seconds / 1_000_000.0)
}

fn round1(value: f64) -> f64 {
    (value * 10.0).round() / 10.0
}

/// Repeated measurements of one metric, in milliseconds.
#[derive(Default)]
struct Samples {
    ok: Vec<f64>,
    total: u32,
}

impl Samples {
    /// Records one attempt and returns its time when it succeeded.
    fn add(&mut self, result: Result<Duration, ProbeFailure>) -> Option<f64> {
        self.total += 1;
        let ms = result.ok().map(|elapsed| elapsed.as_secs_f64() * 1000.0)?;
        self.ok.push(ms);
        Some(round1(ms))
    }

    fn sorted(&self) -> Option<Vec<f64>> {
        if self.ok.is_empty() {
            return None;
        }
        let mut sorted = self.ok.clone();
        sorted.sort_by(f64::total_cmp);
        Some(sorted)
    }

    /// The middle value; the mean of the two middle values for an even count.
    fn median(&self) -> Option<f64> {
        let sorted = self.sorted()?;
        let n = sorted.len();
        let value = if n % 2 == 1 {
            sorted[n / 2]
        } else {
            (sorted[n / 2 - 1] + sorted[n / 2]) / 2.0
        };
        Some(round1(value))
    }

    /// Nearest-rank percentile, `p` in (0, 1].
    fn percentile(&self, p: f64) -> Option<f64> {
        let sorted = self.sorted()?;
        let n = sorted.len();
        let rank = ((p * n as f64).ceil() as usize).clamp(1, n);
        Some(round1(sorted[rank - 1]))
    }

    fn jitter(&self) -> Option<f64> {
        if self.ok.len() < 2 {
            return None;
        }
        let sum: f64 = self
            .ok
            .windows(2)
            .map(|pair| (pair[1] - pair[0]).abs())
            .sum();
        Some(round1(sum / (self.ok.len() - 1) as f64))
    }

    fn loss_pct(&self) -> f64 {
        if self.total == 0 {
            return 0.0;
        }
        round1(f64::from(self.total - self.ok.len() as u32) / f64::from(self.total) * 100.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use engine_outbound::{BoxFuture, TargetAddr};
    use tokio::net::{TcpListener, TcpStream};

    /// Connects to IP targets directly, like DIRECT without the dialer.
    struct Loopback;

    impl TcpOutbound for Loopback {
        fn protocol(&self) -> &'static str {
            "test-loopback"
        }

        fn connect<'a>(&'a self, target: &'a TargetAddr) -> BoxFuture<'a, io::Result<BoxStream>> {
            Box::pin(async move {
                match target {
                    TargetAddr::Ip(addr) => {
                        let stream = TcpStream::connect(addr).await?;
                        Ok(Box::new(stream) as BoxStream)
                    }
                    TargetAddr::Domain(..) => Err(io::ErrorKind::Unsupported.into()),
                }
            })
        }
    }

    /// Fails every connection.
    struct Refuse;

    impl TcpOutbound for Refuse {
        fn protocol(&self) -> &'static str {
            "test-refuse"
        }

        fn connect<'a>(&'a self, _target: &'a TargetAddr) -> BoxFuture<'a, io::Result<BoxStream>> {
            Box::pin(async { Err(io::ErrorKind::ConnectionRefused.into()) })
        }
    }

    /// Answers every request on 127.0.0.1 with `status` and `body_bytes`
    /// zero bytes, then closes.
    async fn server(status: &'static str, body_bytes: usize) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let mut request = Vec::new();
                    let mut buffer = [0u8; 1024];
                    while !request.windows(4).any(|w| w == b"\r\n\r\n") {
                        match stream.read(&mut buffer).await {
                            Ok(0) | Err(_) => return,
                            Ok(n) => request.extend_from_slice(&buffer[..n]),
                        }
                    }
                    let head = format!(
                        "HTTP/1.1 {status}\r\nContent-Length: {body_bytes}\r\nConnection: close\r\n\r\n"
                    );
                    if stream.write_all(head.as_bytes()).await.is_err() {
                        return;
                    }
                    let chunk = vec![0u8; 16 * 1024];
                    let mut left = body_bytes;
                    while left > 0 {
                        let n = left.min(chunk.len());
                        if stream.write_all(&chunk[..n]).await.is_err() {
                            return;
                        }
                        left -= n;
                    }
                    let _ = stream.shutdown().await;
                });
            }
        });
        format!("http://{addr}/")
    }

    fn runtime() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
    }

    #[test]
    fn defaults_are_valid_and_unknown_fields_are_rejected() {
        CheckupOptions::default().validate().unwrap();
        let with_throughput = CheckupOptions {
            throughput: Some(ThroughputOptions::default()),
            ..CheckupOptions::default()
        };
        with_throughput.validate().unwrap();
        let parsed: CheckupOptions =
            serde_json::from_str(r#"{"samples":3,"throughput":{"connections":2}}"#).unwrap();
        assert_eq!(parsed.samples, 3);
        assert_eq!(parsed.latency_url, DEFAULT_LATENCY_URL);
        assert_eq!(parsed.throughput.as_ref().unwrap().connections, 2);
        assert_eq!(parsed.throughput.unwrap().duration_ms, 8_000);
        assert!(serde_json::from_str::<CheckupOptions>(r#"{"sample":3}"#).is_err());
    }

    #[test]
    fn out_of_range_options_are_rejected() {
        let cases = [
            CheckupOptions {
                samples: 0,
                ..CheckupOptions::default()
            },
            CheckupOptions {
                samples: 21,
                ..CheckupOptions::default()
            },
            CheckupOptions {
                timeout_ms: 0,
                ..CheckupOptions::default()
            },
            CheckupOptions {
                latency_url: "ftp://example.com/".into(),
                ..CheckupOptions::default()
            },
            CheckupOptions {
                throughput: Some(ThroughputOptions {
                    connections: 17,
                    ..ThroughputOptions::default()
                }),
                ..CheckupOptions::default()
            },
            CheckupOptions {
                throughput: Some(ThroughputOptions {
                    duration_ms: 500,
                    ..ThroughputOptions::default()
                }),
                ..CheckupOptions::default()
            },
            CheckupOptions {
                throughput: Some(ThroughputOptions {
                    probe_interval_ms: 50,
                    ..ThroughputOptions::default()
                }),
                ..CheckupOptions::default()
            },
        ];
        for options in cases {
            assert!(
                matches!(options.validate(), Err(CheckupError::InvalidOptions(_))),
                "{options:?}"
            );
        }
    }

    #[test]
    fn latency_rounds_report_medians_cold_warm_and_no_loss() {
        let runtime = runtime();
        runtime.block_on(async {
            let url = server("204 No Content", 0).await;
            let options = CheckupOptions {
                samples: 4,
                timeout_ms: 2_000,
                handshake_url: url.clone(),
                latency_url: url,
                throughput: None,
            };
            let report = checkup(Arc::new(Loopback), &options).await.unwrap();
            let latency = report.latency;
            assert_eq!(latency.samples, 4);
            assert!(latency.handshake_ms.is_some());
            assert!(latency.cold_handshake_ms.is_some());
            assert!(latency.warm_handshake_ms.is_some());
            assert!(latency.request_ms.is_some());
            assert!(latency.request_jitter_ms.is_some());
            assert_eq!(latency.handshake_loss_pct, 0.0);
            assert_eq!(latency.request_loss_pct, 0.0);
            assert_eq!(latency.failure, None);
            assert!(report.throughput.is_none());
        });
    }

    #[test]
    fn a_node_that_reaches_nothing_reports_full_loss_with_a_code() {
        let runtime = runtime();
        runtime.block_on(async {
            let options = CheckupOptions {
                samples: 2,
                timeout_ms: 1_000,
                handshake_url: "http://127.0.0.1:9/".into(),
                latency_url: "http://127.0.0.1:9/".into(),
                throughput: Some(ThroughputOptions {
                    connections: 1,
                    duration_ms: 1_000,
                    download_url: "http://127.0.0.1:9/".into(),
                    idle_samples: 1,
                    ..ThroughputOptions::default()
                }),
            };
            let report = checkup(Arc::new(Refuse), &options).await.unwrap();
            assert_eq!(report.latency.handshake_ms, None);
            assert_eq!(report.latency.handshake_loss_pct, 100.0);
            assert_eq!(report.latency.request_loss_pct, 100.0);
            assert_eq!(report.latency.failure, Some(ProbeFailure::ConnectFailed));
            let throughput = report.throughput.unwrap();
            assert_eq!(throughput.bytes, 0);
            assert_eq!(throughput.failure, Some(ProbeFailure::ConnectFailed));
        });
    }

    #[test]
    fn throughput_counts_body_bytes_and_stops_at_the_cap() {
        let runtime = runtime();
        runtime.block_on(async {
            let latency_url = server("204 No Content", 0).await;
            let download_url = server("200 OK", 512 * 1024).await;
            let options = CheckupOptions {
                samples: 1,
                timeout_ms: 2_000,
                handshake_url: latency_url.clone(),
                latency_url,
                throughput: Some(ThroughputOptions {
                    connections: 2,
                    duration_ms: 5_000,
                    download_url,
                    max_bytes: 2 * 1024 * 1024,
                    probe_interval_ms: 100,
                    idle_samples: 2,
                }),
            };
            let report = checkup(Arc::new(Loopback), &options).await.unwrap();
            let throughput = report.throughput.unwrap();
            assert!(throughput.capped);
            assert!(throughput.bytes >= 2 * 1024 * 1024);
            // Each worker stops within one read of the cap.
            assert!(throughput.bytes < 3 * 1024 * 1024, "{}", throughput.bytes);
            assert!(throughput.mbps > 0.0);
            assert!(throughput.idle_ms.is_some());
            assert_eq!(throughput.failure, None);
            assert_eq!(throughput.connections, 2);
        });
    }

    #[test]
    fn a_download_that_is_not_2xx_is_a_status_failure() {
        let runtime = runtime();
        runtime.block_on(async {
            let latency_url = server("204 No Content", 0).await;
            let download_url = server("403 Forbidden", 10).await;
            let options = CheckupOptions {
                samples: 1,
                timeout_ms: 1_000,
                handshake_url: latency_url.clone(),
                latency_url,
                throughput: Some(ThroughputOptions {
                    connections: 1,
                    duration_ms: 2_000,
                    download_url,
                    idle_samples: 1,
                    ..ThroughputOptions::default()
                }),
            };
            let report = checkup(Arc::new(Loopback), &options).await.unwrap();
            let throughput = report.throughput.unwrap();
            assert_eq!(throughput.bytes, 0);
            assert_eq!(throughput.failure, Some(ProbeFailure::HttpStatus));
        });
    }

    #[test]
    fn samples_compute_median_percentile_jitter_and_loss() {
        let mut samples = Samples::default();
        for ms in [10, 30, 20] {
            samples.add(Ok(Duration::from_millis(ms)));
        }
        samples.add(Err(ProbeFailure::Timeout));
        assert_eq!(samples.median(), Some(20.0));
        assert_eq!(samples.percentile(0.9), Some(30.0));
        // |30-10| and |20-30| over two pairs.
        assert_eq!(samples.jitter(), Some(15.0));
        assert_eq!(samples.loss_pct(), 25.0);
        let mut even = Samples::default();
        for ms in [10, 20] {
            even.add(Ok(Duration::from_millis(ms)));
        }
        assert_eq!(even.median(), Some(15.0));
        assert_eq!(Samples::default().median(), None);
        assert_eq!(Samples::default().loss_pct(), 0.0);
    }

    #[test]
    fn status_lines_are_checked() {
        assert_eq!(check_status(b"HTTP/1.1 200 OK"), Ok(()));
        assert_eq!(check_status(b"HTTP/1.0 204 No Content"), Ok(()));
        assert_eq!(
            check_status(b"HTTP/1.1 302 Found"),
            Err(ProbeFailure::HttpStatus)
        );
        assert_eq!(check_status(b"SSH-2.0-OpenSSH"), Err(ProbeFailure::NotHttp));
        assert_eq!(check_status(b"HTTP/1.1"), Err(ProbeFailure::NotHttp));
    }
}
