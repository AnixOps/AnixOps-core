//! Long-run stability of the desktop local proxy on every platform: the
//! SOCKS5/HTTP listener of macOS and Windows (and Linux) with a Shadowsocks
//! 2022 outbound, kept busy for hours. `.github/scripts/proxy_soak.py` runs
//! the two processes below, samples the proxy process (resident memory, open
//! descriptors or handles, threads) and applies the gates
//! (docs/performance-ci.md, F9).
//!
//! - `peer --minutes N`: the far side, in one process: an echo server, a
//!   Shadowsocks 2022 server in front of it, and the load. Prints
//!   `SS <port>`, then reads `PROXY <port>` from stdin and drives the proxy
//!   for N minutes: a short echo connection every 50 ms, a pool of 32 held
//!   connections of which one is replaced every second, and a 4 MiB echo
//!   burst every 30 s. Prints one JSON line per minute and a last line
//!   `DONE {...}` with the counts; exits 1 when more than 0.1% of the
//!   connections failed.
//! - `proxy --ss-port P`: the measured process: one [`LocalProxy`] whose
//!   outbound is the peer's Shadowsocks server. Prints `READY <port>`; each
//!   line on stdin is answered with one JSON line of the listener's counters
//!   (`active` connections among them), and end of input stops it.

#[cfg(all(feature = "local-proxy", feature = "shadowsocks"))]
fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = match args.first().map(String::as_str) {
        Some("peer") => soak::peer(&args[1..]),
        Some("proxy") => soak::proxy(&args[1..]),
        _ => Err(std::io::Error::other(
            "usage: proxy_soak peer --minutes N | proxy --ss-port P",
        )),
    };
    if let Err(err) = result {
        eprintln!("proxy_soak: {err}");
        std::process::exit(1);
    }
}

#[cfg(not(all(feature = "local-proxy", feature = "shadowsocks")))]
fn main() {
    eprintln!("proxy_soak needs the local-proxy and shadowsocks features");
}

#[cfg(all(feature = "local-proxy", feature = "shadowsocks"))]
mod soak {
    use std::collections::{BTreeMap, VecDeque};
    use std::io::{self, BufRead, Write};
    use std::net::{Ipv4Addr, SocketAddr};
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    use base64::Engine as _;
    use engine_embedded::local_proxy::LocalProxy;
    use engine_inbound::registry::InboundFactory;
    use engine_inbound::server::{serve, InboundStats, ServeSettings};
    use engine_outbound::{BoxFuture, BoxStream, TargetAddr, TcpOutbound};
    use inbound_mixed::MixedSettings;
    use inbound_shadowsocks::ShadowsocksInboundFactory;
    use serde_json::json;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    const SHORT_EVERY: Duration = Duration::from_millis(50);
    const POOL: usize = 32;
    const POOL_TURN_EVERY: Duration = Duration::from_secs(1);
    const BURST_EVERY: Duration = Duration::from_secs(30);
    const BURST_BYTES: usize = 4 << 20;
    const IO_TIMEOUT: Duration = Duration::from_secs(15);
    const MAX_FAILURE_RATIO: f64 = 0.001;

    fn key() -> String {
        base64::engine::general_purpose::STANDARD.encode([7u8; 16])
    }

    fn arg<'a>(args: &'a [String], name: &str) -> Option<&'a str> {
        args.windows(2)
            .find(|pair| pair[0] == format!("--{name}"))
            .map(|pair| pair[1].as_str())
    }

    fn number(args: &[String], name: &str) -> io::Result<u64> {
        arg(args, name)
            .and_then(|value| value.parse().ok())
            .ok_or_else(|| io::Error::other(format!("--{name} N is required")))
    }

    // ---- proxy process (measured) ---------------------------------------

    pub fn proxy(args: &[String]) -> io::Result<()> {
        let ss_port = number(args, "ss-port")?;
        let config = json!({
            "schema_version": 1,
            "profile_id": "soak",
            "outbound": {
                "type": "shadowsocks",
                "server": "127.0.0.1",
                "port": ss_port,
                "method": "2022-blake3-aes-128-gcm",
                "password": key(),
            },
        });
        let mut proxy = LocalProxy::start(
            config.to_string().as_bytes(),
            SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
            MixedSettings::default(),
        )
        .map_err(|err| io::Error::other(format!("local proxy: {:?}", err.code)))?;
        let mut out = io::stdout().lock();
        writeln!(out, "READY {}", proxy.local_addr().port())?;
        out.flush()?;
        for line in io::stdin().lock().lines() {
            line?;
            let stats = proxy.stats();
            let answer = json!({
                "accepted": stats.accepted.load(Ordering::Relaxed),
                "active": stats.active.load(Ordering::Relaxed),
                "rejected": stats.rejected.load(Ordering::Relaxed),
                "handshake_failed": stats.handshake_failed.load(Ordering::Relaxed),
                "connect_failed": stats.connect_failed.load(Ordering::Relaxed),
            });
            writeln!(out, "{answer}")?;
            out.flush()?;
        }
        proxy.stop();
        Ok(())
    }

    // ---- peer process -----------------------------------------------------

    /// Every flow goes to the echo server, whatever the target.
    struct ToEcho(SocketAddr);

    impl TcpOutbound for ToEcho {
        fn protocol(&self) -> &'static str {
            "soak-echo"
        }

        fn connect<'a>(&'a self, _target: &'a TargetAddr) -> BoxFuture<'a, io::Result<BoxStream>> {
            Box::pin(async move {
                let stream = TcpStream::connect(self.0).await?;
                stream.set_nodelay(true)?;
                Ok(Box::new(stream) as BoxStream)
            })
        }
    }

    #[derive(Default)]
    struct Counts {
        opened: AtomicU64,
        failed: AtomicU64,
        bytes: AtomicU64,
        /// Why connections failed, by load and reason; the first few are
        /// also written to stderr with their details.
        reasons: Mutex<BTreeMap<String, u64>>,
    }

    impl Counts {
        fn fail(&self, load: &str, error: &io::Error) {
            let failed = self.failed.fetch_add(1, Ordering::Relaxed);
            let reason = format!("{load}: {}", reason(error));
            if failed < 20 {
                eprintln!("proxy_soak: {reason}: {error}");
            }
            *self
                .reasons
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .entry(reason)
                .or_default() += 1;
        }

        fn json(&self) -> serde_json::Value {
            let reasons = self
                .reasons
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .clone();
            json!({
                "opened": self.opened.load(Ordering::Relaxed),
                "failed": self.failed.load(Ordering::Relaxed),
                "bytes": self.bytes.load(Ordering::Relaxed),
                "reasons": reasons,
            })
        }
    }

    /// A short, fixed name for what went wrong.
    fn reason(error: &io::Error) -> String {
        match error.kind() {
            io::ErrorKind::Other => error.to_string(),
            kind => format!("{kind:?}"),
        }
    }

    pub fn peer(args: &[String]) -> io::Result<()> {
        let minutes = number(args, "minutes")?;
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()?;
        runtime.block_on(async move {
            let echo = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
            let echo_addr = echo.local_addr()?;
            tokio::spawn(async move {
                while let Ok((mut stream, _)) = echo.accept().await {
                    tokio::spawn(async move {
                        let (mut reader, mut writer) = stream.split();
                        let _ = tokio::io::copy(&mut reader, &mut writer).await;
                    });
                }
            });
            let settings = json!({"method": "2022-blake3-aes-128-gcm", "password": key()});
            let inbound = ShadowsocksInboundFactory
                .build(settings.as_object().expect("object"))
                .map_err(io::Error::other)?;
            let ss = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
            println!("SS {}", ss.local_addr()?.port());
            tokio::spawn(serve(
                ss,
                inbound,
                Arc::new(ToEcho(echo_addr)),
                ServeSettings::default(),
                Arc::new(InboundStats::default()),
            ));

            let proxy_port = tokio::task::spawn_blocking(|| -> io::Result<u16> {
                let mut line = String::new();
                io::stdin().lock().read_line(&mut line)?;
                line.trim()
                    .strip_prefix("PROXY ")
                    .and_then(|port| port.parse().ok())
                    .ok_or_else(|| io::Error::other("expected PROXY <port> on stdin"))
            })
            .await
            .map_err(io::Error::other)??;
            let proxy = SocketAddr::from((Ipv4Addr::LOCALHOST, proxy_port));
            load(proxy, echo_addr, Duration::from_secs(minutes * 60)).await
        })
    }

    async fn load(proxy: SocketAddr, echo: SocketAddr, length: Duration) -> io::Result<()> {
        let counts = Arc::new(Counts::default());
        let started = Instant::now();
        let mut short = tokio::time::interval(SHORT_EVERY);
        let mut turn = tokio::time::interval(POOL_TURN_EVERY);
        let mut burst = tokio::time::interval(BURST_EVERY);
        let mut report = tokio::time::interval(Duration::from_secs(60));
        for interval in [&mut short, &mut turn, &mut burst, &mut report] {
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        }
        let mut pool: VecDeque<TcpStream> = VecDeque::new();
        let mut tasks = tokio::task::JoinSet::new();
        while started.elapsed() < length {
            tokio::select! {
                _ = short.tick() => {
                    let counts = counts.clone();
                    tasks.spawn(async move {
                        counted(&counts, "short", echo_once(proxy, echo, 64)).await
                    });
                }
                _ = turn.tick() => {
                    // Closing the oldest held connection, opening a new one.
                    if pool.len() >= POOL {
                        pool.pop_front();
                    }
                    counts.opened.fetch_add(1, Ordering::Relaxed);
                    match tokio::time::timeout(IO_TIMEOUT, open(proxy, echo)).await {
                        Ok(Ok(stream)) => pool.push_back(stream),
                        Ok(Err(error)) => counts.fail("pool", &error),
                        Err(_) => counts.fail("pool", &io::ErrorKind::TimedOut.into()),
                    }
                }
                _ = burst.tick() => {
                    let counts = counts.clone();
                    tasks.spawn(async move {
                        counted(&counts, "burst", echo_once(proxy, echo, BURST_BYTES)).await
                    });
                }
                _ = report.tick() => {
                    let mut line = counts.json();
                    line["minute"] = (started.elapsed().as_secs() / 60).into();
                    line["held"] = pool.len().into();
                    println!("{line}");
                }
                Some(_) = tasks.join_next(), if !tasks.is_empty() => {}
            }
        }
        pool.clear();
        while tasks.join_next().await.is_some() {}
        let summary = counts.json();
        println!("DONE {summary}");
        let opened = counts.opened.load(Ordering::Relaxed).max(1);
        let failed = counts.failed.load(Ordering::Relaxed);
        if failed as f64 / opened as f64 > MAX_FAILURE_RATIO {
            return Err(io::Error::other(format!(
                "{failed} of {opened} connections failed"
            )));
        }
        Ok(())
    }

    async fn counted(
        counts: &Counts,
        load: &str,
        run: impl std::future::Future<Output = io::Result<usize>>,
    ) {
        counts.opened.fetch_add(1, Ordering::Relaxed);
        match tokio::time::timeout(IO_TIMEOUT, run).await {
            Ok(Ok(bytes)) => {
                counts.bytes.fetch_add(bytes as u64, Ordering::Relaxed);
            }
            Ok(Err(error)) => counts.fail(load, &error),
            Err(_) => counts.fail(load, &io::ErrorKind::TimedOut.into()),
        }
    }

    /// A SOCKS5 CONNECT through the proxy to the echo server.
    async fn open(proxy: SocketAddr, echo: SocketAddr) -> io::Result<TcpStream> {
        let SocketAddr::V4(target) = echo else {
            return Err(io::Error::other("the echo server is on IPv4 loopback"));
        };
        let mut stream = TcpStream::connect(proxy).await?;
        stream.set_nodelay(true)?;
        stream.write_all(&[0x05, 0x01, 0x00]).await?;
        let mut method = [0u8; 2];
        stream.read_exact(&mut method).await?;
        if method != [0x05, 0x00] {
            return Err(io::Error::other("SOCKS5 method refused"));
        }
        let mut request = vec![0x05, 0x01, 0x00, 0x01];
        request.extend_from_slice(&target.ip().octets());
        request.extend_from_slice(&target.port().to_be_bytes());
        stream.write_all(&request).await?;
        let mut reply = [0u8; 10];
        stream.read_exact(&mut reply).await?;
        if reply[1] != 0x00 {
            return Err(io::Error::other("SOCKS5 connect refused"));
        }
        Ok(stream)
    }

    /// Sends `len` bytes through the proxy and reads them back.
    async fn echo_once(proxy: SocketAddr, echo: SocketAddr, len: usize) -> io::Result<usize> {
        let stream = open(proxy, echo).await?;
        let (mut reader, mut writer) = stream.into_split();
        let payload: Vec<u8> = (0..len).map(|i| i as u8).collect();
        let send = async move {
            writer.write_all(&payload).await?;
            writer.shutdown().await
        };
        let receive = async move {
            let mut received = Vec::with_capacity(len);
            reader.read_to_end(&mut received).await?;
            Ok::<_, io::Error>(received)
        };
        let (sent, received) = tokio::join!(send, receive);
        sent?;
        let received = received?;
        if received.len() != len {
            return Err(io::Error::other(format!(
                "echo returned {} of {len} bytes",
                received.len()
            )));
        }
        if !received.iter().copied().eq((0..len).map(|i| i as u8)) {
            return Err(io::Error::other("echo returned other bytes"));
        }
        Ok(len)
    }
}
