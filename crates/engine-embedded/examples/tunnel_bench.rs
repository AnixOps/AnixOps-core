//! Packet-tunnel benchmark: the same code path as the iOS Network Extension,
//! driven by the Linux kernel's TCP stack through a TUN device.
//!
//! ```text
//! client (kernel TCP) -> TUN -> Tunnel (userspace TCP/IP, relay) -> outbound -> server process
//! ```
//!
//! `tunnel_bench run` starts two child processes of itself: `server` (data
//! source/sink, plus one in-process server per protocol in front of it) and
//! `tunnel` (the TUN device and one [`Tunnel`] whose outbound is the client of
//! that protocol, built from the same JSON settings as in the product). Only
//! the tunnel process is measured for CPU, wakeups and memory, so the numbers
//! are what the extension costs.
//!
//! Outbounds (`--outbound`): `redirect` (no protocol: the tunnel's own cost),
//! `ss2022` (Shadowsocks 2022, AES-128-GCM), `trojan` (TLS), `vless` (TLS),
//! `vless-reality` (REALITY, default fingerprint), `vmess`
//! (AES-128-GCM), `socks5`, `http` (HTTP CONNECT) and `wireguard` (the
//! routable WireGuard outbound with its own userspace stack, against a
//! boringtun peer that ends the flows in a second [`Tunnel`]). TLS servers use
//! a self-signed certificate that the client pins by SHA-256.
//!
//! The TUN device must already exist and belong to the current user, e.g.
//!
//! ```text
//! sudo ip tuntap add dev ncb0 mode tun user "$(id -u)"
//! sudo ip addr add 198.18.0.1/16 dev ncb0
//! sudo ip link set ncb0 mtu 1500 up
//! cargo run --release -p engine-embedded --example tunnel_bench -- run --tun ncb0 --json out.json
//! ```
//!
//! Options of `run`: `--tun NAME`, `--outbound NAME` (see above), `--seconds N`
//! (per throughput test), `--window-kib N`, `--max-conns N`, `--conns N`
//! (memory test), `--connects N` (latency test), `--workers N` (tunnel
//! worker threads; 0 or absent is the platform default, as in the product),
//! `--json PATH`. `run`, `scale` and `soak` pass `--workers` to the tunnel.
//!
//! Two scale tests have their own commands and fail (exit 1) when a target is
//! missed:
//!
//! - `scale --tun NAME --concurrent N [--max-rss-mb M]`: N connections open
//!   at once through the tunnel (the same TUN set-up as `run`); every one must
//!   be established and echo one byte while all are open. Pass `--max-conns`
//!   above N.
//! - `udp-sessions --flows N [--max-rss-mb M]`: no TUN needed. N UDP flows,
//!   each from its own app socket, are fed to one in-process [`Tunnel`] whose
//!   outbound keeps every flow open in memory; every flow must open and the
//!   process RSS with all of them open must stay under M MiB.
//!
//! `soak --tun NAME --minutes N [--max-slope-mb-per-h F]` keeps the tunnel
//! busy for N minutes (short echo connections every second, a pool of held
//! connections that is turned over, a download burst every 30 s), samples
//! the tunnel process every `--sample-secs`, and fails when the RSS trend
//! after warm-up grows faster than F MiB per hour, when more than
//! `--max-failure-ratio` of the connections fail, or when connections or file
//! descriptors are left over at the end.
//!
//! `.github/workflows/perf.yml` runs `run` for a pull request's base and head,
//! and both scale tests on the head; `.github/workflows/soak.yml` runs `soak`.

#[cfg(target_os = "linux")]
fn main() {
    if let Err(err) = linux::main() {
        eprintln!("tunnel_bench: {err}");
        std::process::exit(1);
    }
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("tunnel_bench needs Linux (a TUN device)");
}

#[cfg(target_os = "linux")]
mod linux {
    use std::collections::HashMap;
    use std::io::{self, BufRead, BufReader, Read, Write};
    use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
    use std::os::fd::RawFd;
    use std::process::{Child, Command, Stdio};
    use std::sync::{Arc, Mutex};
    use std::thread;
    use std::time::{Duration, Instant};

    use base64::Engine as _;
    use boringtun::noise::{Tunn, TunnResult};
    use boringtun::x25519::{PublicKey, StaticSecret};
    use engine_embedded::dns_policy::DnsPolicy;
    use engine_embedded::protocols::default_registry;
    use engine_embedded::shadowsocks::{Method, Ss2022Outbound};
    use engine_embedded::tunnel::{default_worker_threads, PacketSink, Tunnel, TunnelSettings};
    use engine_inbound::registry::InboundFactory;
    use engine_inbound::server::{serve, InboundStats, ServeSettings};
    use engine_inbound::StreamInbound;
    use engine_outbound::{
        BoxFuture, BoxStream, DatagramRecv, DatagramSend, TargetAddr, TcpDialer, TcpOutbound,
        UdpFlow,
    };
    use inbound_mixed::{MixedSettings, MixedStats};
    use inbound_shadowsocks::Ss2022Inbound;
    use inbound_trojan::TrojanInboundFactory;
    use inbound_vless::VlessInboundFactory;
    use inbound_vmess::VmessInboundFactory;
    use serde_json::{json, Value};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// Where the client connects: any address routed into the TUN device.
    const TARGET: &str = "198.18.0.2:5201";
    const CHUNK: usize = 64 * 1024;
    const GIB: f64 = 1024.0 * 1024.0 * 1024.0;

    /// Every outbound `--outbound` accepts, in the order the scale job runs
    /// them.
    const OUTBOUNDS: [&str; 9] = [
        "redirect",
        "ss2022",
        "trojan",
        "vless",
        "vless-reality",
        "vmess",
        "socks5",
        "http",
        "wireguard",
    ];
    /// Name in the self-signed certificate of the TLS servers.
    const TLS_NAME: &str = "bench.test";
    const PASSWORD: &str = "tunnel-bench";
    const UUID: &str = "b831381d-6324-4d53-ad4f-8cda48b30811";
    /// REALITY: server key, short id and the server name the client sends.
    const REALITY_KEY: [u8; 32] = [0x61; 32];
    const REALITY_SHORT_ID: &str = "0123456789abcdef";
    const REALITY_NAME: &str = "www.example.com";
    /// WireGuard: client and peer keys, the client's tunnel address and the
    /// MTU on both sides.
    const WG_CLIENT_KEY: [u8; 32] = [7; 32];
    const WG_PEER_KEY: [u8; 32] = [9; 32];
    const WG_ADDRESS: &str = "10.7.0.2/32";
    const WG_MTU: u16 = 1420;

    type Args = HashMap<String, String>;

    pub fn main() -> io::Result<()> {
        let mut argv = std::env::args().skip(1);
        let command = argv.next().unwrap_or_default();
        let mut args = Args::new();
        while let Some(key) = argv.next() {
            let key = key.trim_start_matches("--").to_string();
            let value = argv.next().unwrap_or_default();
            args.insert(key, value);
        }
        match command.as_str() {
            "run" => run(&args),
            "scale" => scale(&args),
            "udp-sessions" => udp_sessions(&args),
            "soak" => soak(&args),
            "server" => server_child(),
            "tunnel" => tunnel_child(&args),
            _ => Err(io::Error::other(
                "usage: tunnel_bench run|scale --tun NAME [--outbound NAME] [--json PATH] \
                 | tunnel_bench udp-sessions --flows N [--json PATH]",
            )),
        }
    }

    fn arg<'a>(args: &'a Args, key: &str, default: &'a str) -> &'a str {
        args.get(key).map(String::as_str).unwrap_or(default)
    }

    fn num(args: &Args, key: &str, default: u64) -> io::Result<u64> {
        match args.get(key) {
            Some(value) => value
                .parse()
                .map_err(|_| io::Error::other(format!("--{key} is not a number"))),
            None => Ok(default),
        }
    }

    /// `--workers N`: tunnel worker threads; 0 or absent is the runtime's
    /// default for this platform ([`default_worker_threads`]).
    fn workers(args: &Args) -> io::Result<usize> {
        Ok(match num(args, "workers", 0)? as usize {
            0 => default_worker_threads(),
            n => n,
        })
    }

    fn fnum(args: &Args, key: &str, default: f64) -> io::Result<f64> {
        match args.get(key) {
            Some(value) => value
                .parse()
                .map_err(|_| io::Error::other(format!("--{key} is not a number"))),
            None => Ok(default),
        }
    }

    fn key() -> String {
        base64::engine::general_purpose::STANDARD.encode([7u8; 16])
    }

    /// Sends every flow to one local address, whatever the target.
    struct Redirect(SocketAddr);

    impl TcpOutbound for Redirect {
        fn protocol(&self) -> &'static str {
            "bench-redirect"
        }

        fn connect<'a>(&'a self, _target: &'a TargetAddr) -> BoxFuture<'a, io::Result<BoxStream>> {
            Box::pin(async move {
                let stream = tokio::net::TcpStream::connect(self.0).await?;
                stream.set_nodelay(true)?;
                Ok(Box::new(stream) as BoxStream)
            })
        }
    }

    // ---- server process -------------------------------------------------

    fn server_child() -> io::Result<()> {
        // Bound before the runtime: the WireGuard peer's tunnel needs the
        // sink's port and starts its own runtime.
        let sink = TcpListener::bind("127.0.0.1:0")?;
        sink.set_nonblocking(true)?;
        let sink_addr = sink.local_addr()?;
        let wireguard_port = wireguard_peer(sink_addr)?;
        let (certificate, private_key, pin) = self_signed()?;
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(4)
            .enable_all()
            .build()?;
        runtime.block_on(async {
            let sink = tokio::net::TcpListener::from_std(sink)?;
            tokio::spawn(async move {
                while let Ok((stream, _)) = sink.accept().await {
                    tokio::spawn(async move {
                        let _ = data_connection(stream).await;
                    });
                }
            });
            let redirect: Arc<dyn TcpOutbound> = Arc::new(Redirect(sink_addr));
            let tls = json!({"certificate": certificate, "key": private_key});
            let user = |key: &str, value: &str| json!([{"name": "bench", key: value}]);
            let ss: Arc<dyn StreamInbound> = Arc::new(Ss2022Inbound::new(
                inbound_shadowsocks::Method::Aes128Gcm,
                &key(),
                false,
            )?);
            let built = |factory: &dyn InboundFactory,
                         settings: Value|
             -> io::Result<Arc<dyn StreamInbound>> {
                let settings = settings
                    .as_object()
                    .cloned()
                    .ok_or_else(|| io::Error::other("inbound settings are not an object"))?;
                factory
                    .build(&settings)
                    .map_err(|err| io::Error::other(format!("{}: {err}", factory.type_name())))
            };
            let inbounds = [
                ("ss", ss),
                (
                    "trojan",
                    built(
                        &TrojanInboundFactory,
                        json!({"users": user("password", PASSWORD), "tls": tls}),
                    )?,
                ),
                (
                    "vless",
                    built(
                        &VlessInboundFactory,
                        json!({"users": user("uuid", UUID), "tls": tls}),
                    )?,
                ),
                (
                    "reality",
                    built(
                        &VlessInboundFactory,
                        json!({
                            "users": user("uuid", UUID),
                            "reality": {
                                "private_key": base64::engine::general_purpose::URL_SAFE_NO_PAD
                                    .encode(REALITY_KEY),
                                "short_ids": [REALITY_SHORT_ID],
                                "server_names": [REALITY_NAME],
                                // Only clients that fail authentication go
                                // there; the bench has none.
                                "handshake": {"server": "127.0.0.1", "server_port": sink_addr.port()},
                            }
                        }),
                    )?,
                ),
                (
                    "vmess",
                    built(&VmessInboundFactory, json!({"users": user("uuid", UUID)}))?,
                ),
            ];
            let mut ports = vec![format!("sink={}", sink_addr.port())];
            for (name, inbound) in inbounds {
                let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
                ports.push(format!("{name}={}", listener.local_addr()?.port()));
                tokio::spawn(serve(
                    listener,
                    inbound,
                    redirect.clone(),
                    // The default cap (4096) is below the scale test's count.
                    ServeSettings {
                        max_connections: 1 << 20,
                        ..ServeSettings::default()
                    },
                    Arc::new(InboundStats::default()),
                ));
            }
            // SOCKS5 and HTTP CONNECT share one listener, as in the product.
            let mixed = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
            ports.push(format!("mixed={}", mixed.local_addr()?.port()));
            tokio::spawn(inbound_mixed::serve(
                mixed,
                redirect.clone(),
                MixedSettings {
                    max_connections: 1 << 20,
                    ..MixedSettings::default()
                },
                Arc::new(MixedStats::default()),
            ));
            ports.push(format!("wireguard={wireguard_port}"));
            ports.push(format!("pin={pin}"));
            println!("READY {}", ports.join(" "));
            io::stdout().flush()?;
            std::future::pending::<()>().await;
            Ok::<(), io::Error>(())
        })
    }

    /// A self-signed certificate for [`TLS_NAME`]: PEM certificate, PEM key
    /// and the certificate's SHA-256 in hex, which the clients pin.
    fn self_signed() -> io::Result<(String, String, String)> {
        let key = rcgen::KeyPair::generate().map_err(io::Error::other)?;
        let certificate = rcgen::CertificateParams::new(vec![TLS_NAME.to_string()])
            .map_err(io::Error::other)?
            .self_signed(&key)
            .map_err(io::Error::other)?;
        let digest = ring::digest::digest(&ring::digest::SHA256, certificate.der());
        let pin = digest
            .as_ref()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        Ok((certificate.pem(), key.serialize_pem(), pin))
    }

    fn wireguard_public(private: [u8; 32]) -> [u8; 32] {
        PublicKey::from(&StaticSecret::from(private)).to_bytes()
    }

    /// The WireGuard server: a boringtun peer on a UDP port whose decrypted
    /// packets go to a second [`Tunnel`], which ends every TCP flow and
    /// relays it to `sink`. Returns the UDP port.
    fn wireguard_peer(sink: SocketAddr) -> io::Result<u16> {
        let socket = std::net::UdpSocket::bind("127.0.0.1:0")?;
        let port = socket.local_addr()?.port();
        // The noise session and the client's address, shared by the receive
        // loop, the timers and the tunnel's packet sink.
        let state = Arc::new(Mutex::new((
            Tunn::new(
                StaticSecret::from(WG_PEER_KEY),
                PublicKey::from(wireguard_public(WG_CLIENT_KEY)),
                None,
                None,
                1,
                None,
            ),
            None::<SocketAddr>,
        )));
        let sender = socket.try_clone()?;
        let sealer = state.clone();
        let sink_packets: PacketSink = Box::new(move |packet: &[u8]| {
            let mut sealed = vec![0u8; packet.len() + 148];
            let mut state = sealer
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let Some(peer) = state.1 else {
                return;
            };
            if let TunnResult::WriteToNetwork(datagram) = state.0.encapsulate(packet, &mut sealed) {
                let _ = sender.send_to(datagram, peer);
            }
        });
        let settings = tunnel_settings(WG_MTU, 64 * 1024, 1 << 16, 2);
        let tunnel = Arc::new(Tunnel::start(
            settings,
            Arc::new(Redirect(sink)),
            sink_packets,
        )?);

        let receiver = socket.try_clone()?;
        let opened = state.clone();
        thread::Builder::new()
            .name("wg-peer".into())
            .spawn(move || {
                let mut datagram = vec![0u8; 65_536];
                let mut out = vec![0u8; 65_536 + 148];
                while let Ok((len, from)) = receiver.recv_from(&mut datagram) {
                    let mut input = &datagram[..len];
                    let mut state = opened
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner());
                    state.1 = Some(from);
                    loop {
                        let packet = match state.0.decapsulate(Some(from.ip()), input, &mut out) {
                            // A handshake answer, then packets queued before
                            // it: repeat with no input until done.
                            TunnResult::WriteToNetwork(reply) => {
                                let _ = receiver.send_to(reply, from);
                                input = &[];
                                continue;
                            }
                            TunnResult::WriteToTunnelV4(packet, _)
                            | TunnResult::WriteToTunnelV6(packet, _) => packet.to_vec(),
                            _ => Vec::new(),
                        };
                        // The tunnel may answer through the sink, which
                        // takes the lock.
                        drop(state);
                        if !packet.is_empty() {
                            tunnel.input_packet(&packet);
                        }
                        break;
                    }
                }
            })?;
        let ticker = state;
        thread::Builder::new()
            .name("wg-timers".into())
            .spawn(move || {
                let mut out = vec![0u8; 65_536 + 148];
                loop {
                    thread::sleep(Duration::from_millis(250));
                    let mut state = ticker
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner());
                    let peer = state.1;
                    if let (TunnResult::WriteToNetwork(datagram), Some(peer)) =
                        (state.0.update_timers(&mut out), peer)
                    {
                        let _ = socket.send_to(datagram, peer);
                    }
                }
            })?;
        Ok(port)
    }

    /// One command byte, then: `D` streams data until the peer leaves, `U`
    /// counts what arrives and answers the total, `E` echoes, anything else
    /// holds the connection open.
    async fn data_connection(mut stream: tokio::net::TcpStream) -> io::Result<()> {
        stream.set_nodelay(true)?;
        let mut command = [0u8; 1];
        stream.read_exact(&mut command).await?;
        let mut buf = vec![0x5a; CHUNK];
        match command[0] {
            b'D' => loop {
                stream.write_all(&buf).await?;
            },
            b'U' => {
                let mut total = 0u64;
                loop {
                    let n = stream.read(&mut buf).await?;
                    if n == 0 {
                        break;
                    }
                    total += n as u64;
                }
                stream.write_all(&total.to_be_bytes()).await?;
            }
            b'E' => loop {
                let n = stream.read(&mut buf).await?;
                if n == 0 {
                    break;
                }
                stream.write_all(&buf[..n]).await?;
            },
            _ => while stream.read(&mut buf).await? > 0 {},
        }
        Ok(())
    }

    // ---- tunnel process -------------------------------------------------

    /// The tunnel settings of the product for a bench tunnel.
    fn tunnel_settings(mtu: u16, window: u32, max_conns: usize, workers: usize) -> TunnelSettings {
        TunnelSettings {
            mtu,
            tcp_window_bytes: window,
            max_tcp_connections: max_conns,
            max_udp_flows: 256,
            tcp_evict_idle: engine_embedded::tunnel::DEFAULT_TCP_EVICT_IDLE,
            udp_evict_idle: engine_embedded::tunnel::DEFAULT_UDP_EVICT_IDLE,
            max_dns_in_flight: 32,
            idle_timeout: Duration::from_secs(300),
            connect_timeout: Duration::from_secs(10),
            dns: Arc::new(DnsPolicy::tcp(
                SocketAddr::from(([127, 0, 0, 1], 53)),
                Duration::from_secs(5),
            )),
            worker_threads: workers,
        }
    }

    /// The outbound named by `--outbound`, aimed at the server process whose
    /// ports (and certificate pin) arrive as `--sink`, `--ss`, `--trojan`, ...
    fn bench_outbound(args: &Args) -> io::Result<Arc<dyn TcpOutbound>> {
        let port = |key: &str| -> io::Result<u16> {
            match num(args, key, 0)? {
                0 => Err(io::Error::other(format!(
                    "the server reported no --{key} port"
                ))),
                port => u16::try_from(port).map_err(io::Error::other),
            }
        };
        let tls = || {
            json!({
                "server_name": TLS_NAME,
                "insecure": true,
                "pinned_certificate_sha256": [arg(args, "pin", "")],
            })
        };
        let (kind, settings) = match arg(args, "outbound", "redirect") {
            "redirect" => {
                return Ok(Arc::new(Redirect(SocketAddr::from((
                    [127, 0, 0, 1],
                    port("sink")?,
                )))))
            }
            "ss2022" => {
                return Ok(Arc::new(Ss2022Outbound::new(
                    "127.0.0.1",
                    port("ss")?,
                    Method::Aes128Gcm,
                    &key(),
                    Arc::new(TcpDialer),
                )?))
            }
            // WebPKI cannot vouch for the self-signed certificate; the pin
            // checks it instead.
            "trojan" => (
                "trojan",
                json!({
                    "server": "127.0.0.1",
                    "port": port("trojan")?,
                    "password": PASSWORD,
                    "server_name": TLS_NAME,
                    "insecure": true,
                    "pinned_certificate_sha256": [arg(args, "pin", "")],
                }),
            ),
            "vless" => (
                "vless",
                json!({"server": "127.0.0.1", "port": port("vless")?, "uuid": UUID, "tls": tls()}),
            ),
            "vless-reality" => (
                "vless",
                json!({
                    "server": "127.0.0.1",
                    "port": port("reality")?,
                    "uuid": UUID,
                    "reality": {
                        "server_name": REALITY_NAME,
                        "public_key": base64::engine::general_purpose::URL_SAFE_NO_PAD
                            .encode(wireguard_public(REALITY_KEY)),
                        "short_id": REALITY_SHORT_ID,
                    },
                }),
            ),
            "vmess" => (
                "vmess",
                json!({
                    "server": "127.0.0.1",
                    "port": port("vmess")?,
                    "uuid": UUID,
                    "security": "aes-128-gcm",
                }),
            ),
            "socks5" => (
                "socks",
                json!({"server": "127.0.0.1", "port": port("mixed")?}),
            ),
            "http" => (
                "http",
                json!({"server": "127.0.0.1", "port": port("mixed")?}),
            ),
            "wireguard" => (
                "wireguard",
                json!({
                    "server": "127.0.0.1",
                    "port": port("wireguard")?,
                    "private_key": base64::engine::general_purpose::STANDARD.encode(WG_CLIENT_KEY),
                    "peer_public_key": base64::engine::general_purpose::STANDARD
                        .encode(wireguard_public(WG_PEER_KEY)),
                    "local_address": [WG_ADDRESS],
                    "mtu": WG_MTU,
                }),
            ),
            other => {
                return Err(io::Error::other(format!(
                    "unknown outbound {other}; one of {}",
                    OUTBOUNDS.join(", ")
                )))
            }
        };
        let settings = settings
            .as_object()
            .cloned()
            .ok_or_else(|| io::Error::other("outbound settings are not an object"))?;
        default_registry()
            .build(kind, &settings, Arc::new(TcpDialer))
            .map_err(|err| io::Error::other(format!("{kind} outbound: {err}")))
    }

    fn tunnel_child(args: &Args) -> io::Result<()> {
        let fd = open_tun(arg(args, "tun", "ncb0"))?;
        let outbound = bench_outbound(args)?;
        let mut settings = tunnel_settings(
            num(args, "mtu", 1500)? as u16,
            (num(args, "window-kib", 64)? * 1024) as u32,
            num(args, "max-conns", 128)? as usize,
            workers(args)?,
        );
        settings.max_udp_flows = num(args, "max-udp-flows", 256)? as usize;
        let sink: PacketSink = Box::new(move |packet: &[u8]| {
            // SAFETY: `fd` stays open for the life of the process.
            let _ = unsafe { libc::write(fd, packet.as_ptr().cast(), packet.len()) };
        });

        let started = Instant::now();
        let tunnel = Arc::new(Tunnel::start(settings, outbound, sink)?);
        let start_us = started.elapsed().as_micros();

        let reader = tunnel.clone();
        thread::Builder::new()
            .name("tun-read".into())
            .spawn(move || {
                let mut buf = vec![0u8; 65536];
                loop {
                    // SAFETY: `buf` is valid for `buf.len()` bytes.
                    let n = unsafe { libc::read(fd, buf.as_mut_ptr().cast(), buf.len()) };
                    if n > 0 {
                        reader.input_packet(&buf[..n as usize]);
                    } else if n == 0
                        || io::Error::last_os_error().kind() != io::ErrorKind::Interrupted
                    {
                        break;
                    }
                }
            })?;

        let control = TcpListener::bind("127.0.0.1:0")?;
        println!("READY {} {}", control.local_addr()?.port(), start_us);
        io::stdout().flush()?;
        for stream in control.incoming() {
            let mut stream = stream?;
            let mut line = String::new();
            BufReader::new(&stream).read_line(&mut line)?;
            let sample = sample(&tunnel);
            writeln!(stream, "{sample}")?;
        }
        Ok(())
    }

    fn open_tun(name: &str) -> io::Result<RawFd> {
        const TUNSETIFF: u64 = 0x4004_54ca;
        #[repr(C)]
        #[allow(dead_code)] // read by the kernel, not by Rust
        struct IfReq {
            name: [libc::c_char; libc::IFNAMSIZ],
            flags: libc::c_short,
            pad: [u8; 22],
        }
        if name.is_empty() || name.len() >= libc::IFNAMSIZ {
            return Err(io::Error::other("bad TUN name"));
        }
        let mut request = IfReq {
            name: [0; libc::IFNAMSIZ],
            flags: (libc::IFF_TUN | libc::IFF_NO_PI) as libc::c_short,
            pad: [0; 22],
        };
        for (slot, byte) in request.name.iter_mut().zip(name.bytes()) {
            *slot = byte as libc::c_char;
        }
        // SAFETY: a NUL-terminated path; the request outlives the call.
        unsafe {
            let fd = libc::open(c"/dev/net/tun".as_ptr(), libc::O_RDWR | libc::O_CLOEXEC);
            if fd < 0 {
                return Err(io::Error::last_os_error());
            }
            if libc::ioctl(fd, TUNSETIFF as _, &mut request as *mut IfReq) < 0 {
                let err = io::Error::last_os_error();
                libc::close(fd);
                return Err(err);
            }
            Ok(fd)
        }
    }

    /// Process memory, CPU and context switches, plus the tunnel counters.
    fn sample(tunnel: &Tunnel) -> Value {
        let status = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
        let field = |name: &str| -> u64 {
            status
                .lines()
                .find_map(|line| line.strip_prefix(name))
                .and_then(|rest| rest.split_whitespace().next())
                .and_then(|value| value.parse().ok())
                .unwrap_or(0)
        };
        // SAFETY: getrusage fills the zeroed struct.
        let usage = unsafe {
            let mut usage: libc::rusage = std::mem::zeroed();
            libc::getrusage(libc::RUSAGE_SELF, &mut usage);
            usage
        };
        let micros = |time: libc::timeval| time.tv_sec as u64 * 1_000_000 + time.tv_usec as u64;
        json!({
            "rss_kb": field("VmRSS:"),
            "hwm_kb": field("VmHWM:"),
            "threads": field("Threads:"),
            "fds": std::fs::read_dir("/proc/self/fd").map_or(0, |dir| dir.count()),
            "cpu_us": micros(usage.ru_utime) + micros(usage.ru_stime),
            "nvcsw": usage.ru_nvcsw as u64,
            "nivcsw": usage.ru_nivcsw as u64,
            "tunnel": serde_json::to_value(tunnel.stats()).unwrap_or(Value::Null),
        })
    }

    // ---- orchestration --------------------------------------------------

    struct Children {
        server: Child,
        tunnel: Child,
        control: u16,
    }

    impl Drop for Children {
        fn drop(&mut self) {
            let _ = self.tunnel.kill();
            let _ = self.server.kill();
            let _ = self.tunnel.wait();
            let _ = self.server.wait();
        }
    }

    fn spawn_child(args: &[&str]) -> io::Result<(Child, Vec<String>)> {
        let mut child = Command::new(std::env::current_exe()?)
            .args(args)
            .stdout(Stdio::piped())
            .spawn()?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| io::Error::other("no stdout"))?;
        let mut line = String::new();
        BufReader::new(stdout).read_line(&mut line)?;
        let words: Vec<String> = line.split_whitespace().map(str::to_string).collect();
        if words.first().map(String::as_str) != Some("READY") {
            let _ = child.kill();
            return Err(io::Error::other(format!("child {args:?} did not start")));
        }
        Ok((child, words[1..].to_vec()))
    }

    fn stats(children: &Children) -> io::Result<Value> {
        let mut stream = TcpStream::connect(("127.0.0.1", children.control))?;
        stream.write_all(b"stats\n")?;
        let mut line = String::new();
        BufReader::new(stream).read_line(&mut line)?;
        serde_json::from_str(&line).map_err(io::Error::other)
    }

    fn get(value: &Value, key: &str) -> f64 {
        value[key].as_f64().unwrap_or(0.0)
    }

    fn delta(before: &Value, after: &Value, key: &str) -> f64 {
        get(after, key) - get(before, key)
    }

    fn target() -> SocketAddr {
        TARGET.parse().expect("valid target")
    }

    fn connect(command: u8) -> io::Result<TcpStream> {
        let mut stream = TcpStream::connect_timeout(&target(), Duration::from_secs(10))?;
        stream.set_nodelay(true)?;
        stream.write_all(&[command])?;
        Ok(stream)
    }

    /// Starts the server and tunnel processes; returns them and the tunnel's
    /// start time in microseconds.
    fn start(args: &Args) -> io::Result<(Children, f64)> {
        let outbound = arg(args, "outbound", "redirect").to_string();
        let (server, ports) = spawn_child(&["server"])?;
        // The server reports `name=value` words: its ports and the pin.
        let reported: Vec<(String, String)> = ports
            .iter()
            .filter_map(|word| word.split_once('='))
            .map(|(key, value)| (format!("--{key}"), value.to_string()))
            .collect();
        let mut tunnel_args = vec!["tunnel", "--outbound", outbound.as_str()];
        for (key, value) in &reported {
            tunnel_args.push(key.as_str());
            tunnel_args.push(value.as_str());
        }
        let forwarded: Vec<(String, String)> = ["tun", "window-kib", "max-conns", "mtu", "workers"]
            .iter()
            .filter_map(|key| {
                args.get(*key)
                    .map(|value| (format!("--{key}"), value.clone()))
            })
            .collect();
        for (key, value) in &forwarded {
            tunnel_args.push(key.as_str());
            tunnel_args.push(value.as_str());
        }
        let (tunnel, words) = match spawn_child(&tunnel_args) {
            Ok(started) => started,
            Err(err) => {
                let mut server = server;
                let _ = server.kill();
                return Err(err);
            }
        };
        let children = Children {
            server,
            tunnel,
            control: words[0].parse().map_err(io::Error::other)?,
        };
        let start_us: f64 = words[1].parse().unwrap_or(0.0);
        Ok((children, start_us))
    }

    fn write_report(args: &Args, report: &Value) -> io::Result<()> {
        let text = serde_json::to_string_pretty(report).map_err(io::Error::other)?;
        println!("{text}");
        if let Some(path) = args.get("json") {
            std::fs::write(path, text)?;
        }
        Ok(())
    }

    fn run(args: &Args) -> io::Result<()> {
        let outbound = arg(args, "outbound", "redirect").to_string();
        let seconds = num(args, "seconds", 5)? as f64;
        let conns = num(args, "conns", 100)? as usize;
        let connects = num(args, "connects", 200)? as usize;
        let (children, start_us) = start(args)?;

        thread::sleep(Duration::from_secs(1));
        let started = stats(&children)?;
        let mut report = json!({
            "outbound": outbound,
            "window_kib": num(args, "window-kib", 64)?,
            "start_ms": start_us / 1000.0,
            "rss_after_start_kb": get(&started, "rss_kb"),
            "threads": get(&started, "threads"),
            "workers": workers(args)?,
        });

        report["idle"] = idle(&children, Duration::from_secs(10), &[])?;
        report["connect"] = connect_latency(connects)?;
        thread::sleep(Duration::from_secs(1));
        report["download_1"] = download(&children, 1, seconds)?;
        thread::sleep(Duration::from_secs(1));
        report["download_8"] = download(&children, 8, seconds)?;
        thread::sleep(Duration::from_secs(1));
        report["upload_1"] = upload(&children, seconds)?;
        thread::sleep(Duration::from_secs(1));
        report["memory"] = memory(&children, conns)?;
        thread::sleep(Duration::from_secs(1));
        let held = (0..conns)
            .map(|_| connect(b'H'))
            .collect::<io::Result<Vec<_>>>()?;
        thread::sleep(Duration::from_secs(1));
        report["idle_conns"] = idle(&children, Duration::from_secs(10), &held)?;
        drop(held);
        thread::sleep(Duration::from_secs(1));
        let last = stats(&children)?;
        report["hwm_kb"] = json!(get(&last, "hwm_kb"));
        report["tunnel"] = last["tunnel"].clone();
        write_report(args, &report)
    }

    /// CPU and wakeups of the tunnel process while nothing moves.
    fn idle(children: &Children, period: Duration, held: &[TcpStream]) -> io::Result<Value> {
        let before = stats(children)?;
        thread::sleep(period);
        let after = stats(children)?;
        let secs = period.as_secs_f64();
        Ok(json!({
            "conns": held.len(),
            "cpu_ms_per_s": delta(&before, &after, "cpu_us") / 1000.0 / secs,
            "wakeups_per_s": delta(&before, &after, "nvcsw") / secs,
            "rss_kb": get(&after, "rss_kb"),
        }))
    }

    fn percentile(sorted: &[f64], p: f64) -> f64 {
        if sorted.is_empty() {
            return 0.0;
        }
        let index = ((sorted.len() - 1) as f64 * p).round() as usize;
        sorted[index]
    }

    /// Sequential new connections: handshake with the userspace stack, then
    /// the first echoed byte, which includes the outbound dial.
    fn connect_latency(count: usize) -> io::Result<Value> {
        let mut handshake = Vec::with_capacity(count);
        let mut first_byte = Vec::with_capacity(count);
        for _ in 0..count {
            let begin = Instant::now();
            let mut stream = TcpStream::connect_timeout(&target(), Duration::from_secs(10))?;
            handshake.push(begin.elapsed().as_secs_f64() * 1000.0);
            stream.set_nodelay(true)?;
            stream.write_all(b"Ex")?;
            let mut byte = [0u8; 1];
            stream.read_exact(&mut byte)?;
            first_byte.push(begin.elapsed().as_secs_f64() * 1000.0);
        }
        handshake.sort_by(f64::total_cmp);
        first_byte.sort_by(f64::total_cmp);
        Ok(json!({
            "count": count,
            "handshake_p50_ms": percentile(&handshake, 0.5),
            "handshake_p99_ms": percentile(&handshake, 0.99),
            "first_byte_p50_ms": percentile(&first_byte, 0.5),
            "first_byte_p90_ms": percentile(&first_byte, 0.9),
            "first_byte_p99_ms": percentile(&first_byte, 0.99),
        }))
    }

    fn throughput(before: &Value, after: &Value, bytes: f64, secs: f64) -> Value {
        let cpu_ms = delta(before, after, "cpu_us") / 1000.0;
        json!({
            "mbps": bytes * 8.0 / secs / 1e6,
            "cpu_ms_per_gib": if bytes > 0.0 { cpu_ms / (bytes / GIB) } else { 0.0 },
            "cpu_util": cpu_ms / 1000.0 / secs,
            "rss_kb": get(after, "rss_kb"),
        })
    }

    fn download(children: &Children, flows: usize, secs: f64) -> io::Result<Value> {
        let streams = (0..flows)
            .map(|_| connect(b'D'))
            .collect::<io::Result<Vec<_>>>()?;
        let before = stats(children)?;
        let begin = Instant::now();
        let deadline = begin + Duration::from_secs_f64(secs);
        let workers: Vec<_> = streams
            .into_iter()
            .map(|mut stream| {
                thread::spawn(move || {
                    let mut buf = vec![0u8; CHUNK];
                    let mut total = 0u64;
                    while Instant::now() < deadline {
                        match stream.read(&mut buf) {
                            Ok(0) | Err(_) => break,
                            Ok(n) => total += n as u64,
                        }
                    }
                    total
                })
            })
            .collect();
        let bytes: u64 = workers.into_iter().map(|w| w.join().unwrap_or(0)).sum();
        let elapsed = begin.elapsed().as_secs_f64();
        let after = stats(children)?;
        let mut result = throughput(&before, &after, bytes as f64, elapsed);
        result["flows"] = json!(flows);
        Ok(result)
    }

    fn upload(children: &Children, secs: f64) -> io::Result<Value> {
        let mut stream = connect(b'U')?;
        let before = stats(children)?;
        let begin = Instant::now();
        let deadline = begin + Duration::from_secs_f64(secs);
        let buf = vec![0x33u8; CHUNK];
        while Instant::now() < deadline {
            stream.write_all(&buf)?;
        }
        stream.shutdown(Shutdown::Write)?;
        let mut total = [0u8; 8];
        stream.read_exact(&mut total)?;
        let elapsed = begin.elapsed().as_secs_f64();
        let after = stats(children)?;
        let mut result = throughput(&before, &after, u64::from_be_bytes(total) as f64, elapsed);
        result["flows"] = json!(1);
        Ok(result)
    }

    /// `conns` downloads the app does not read: every buffer on the path
    /// fills up, the worst case of a slow app. Then all close.
    fn memory(children: &Children, conns: usize) -> io::Result<Value> {
        let before = stats(children)?;
        let streams = (0..conns)
            .map(|_| connect(b'D'))
            .collect::<io::Result<Vec<_>>>()?;
        thread::sleep(Duration::from_secs(3));
        let stalled = stats(children)?;
        drop(streams);
        thread::sleep(Duration::from_secs(3));
        let closed = stats(children)?;
        let base = get(&before, "rss_kb");
        Ok(json!({
            "conns": conns,
            "rss_before_kb": base,
            "rss_stalled_kb": get(&stalled, "rss_kb"),
            "per_conn_kb": (get(&stalled, "rss_kb") - base) / conns.max(1) as f64,
            "rss_after_close_kb": get(&closed, "rss_kb"),
        }))
    }

    // ---- scale: concurrent connections ------------------------------------

    /// Fails the command when `failures` is not empty.
    fn verdict(args: &Args, mut report: Value, failures: Vec<String>) -> io::Result<()> {
        report["pass"] = json!(failures.is_empty());
        report["failures"] = json!(failures);
        write_report(args, &report)?;
        if failures.is_empty() {
            Ok(())
        } else {
            Err(io::Error::other(failures.join("; ")))
        }
    }

    fn rss_limit(args: &Args, rss_kb: f64, failures: &mut Vec<String>) -> io::Result<()> {
        if args.contains_key("max-rss-mb") {
            let limit = num(args, "max-rss-mb", 0)?;
            if rss_kb / 1024.0 > limit as f64 {
                failures.push(format!(
                    "RSS {:.1} MiB is above the {limit} MiB limit",
                    rss_kb / 1024.0
                ));
            }
        }
        Ok(())
    }

    /// Sends one byte and reads the echo.
    fn echo_once(stream: &mut TcpStream) -> io::Result<()> {
        stream.set_read_timeout(Some(Duration::from_secs(10)))?;
        stream.write_all(b"x")?;
        let mut byte = [0u8; 1];
        stream.read_exact(&mut byte)
    }

    /// `--concurrent N` echo connections open at once: opened from parallel
    /// threads, then each echoes one byte while all of them are open.
    fn scale(args: &Args) -> io::Result<()> {
        let count = num(args, "concurrent", 5000)? as usize;
        let threads = (num(args, "threads", 32)? as usize).clamp(1, count.max(1));
        let (children, _) = start(args)?;
        thread::sleep(Duration::from_secs(1));
        let before = stats(&children)?;

        let begin = Instant::now();
        let per = count.div_ceil(threads);
        let openers: Vec<_> = (0..threads)
            .map(|index| {
                let n = per.min(count.saturating_sub(index * per));
                thread::spawn(move || {
                    let mut streams = Vec::with_capacity(n);
                    let mut failed = 0usize;
                    for _ in 0..n {
                        match connect(b'E') {
                            Ok(stream) => streams.push(stream),
                            Err(_) => failed += 1,
                        }
                    }
                    (streams, failed)
                })
            })
            .collect();
        let mut groups = Vec::with_capacity(threads);
        let mut connect_failed = 0;
        for opener in openers {
            let (streams, failed) = opener
                .join()
                .map_err(|_| io::Error::other("opener thread panicked"))?;
            connect_failed += failed;
            groups.push(streams);
        }
        let open_secs = begin.elapsed().as_secs_f64();
        let established: usize = groups.iter().map(Vec::len).sum();
        thread::sleep(Duration::from_secs(2));
        let open = stats(&children)?;

        // One byte through every connection while all stay open.
        let echoers: Vec<_> = groups
            .into_iter()
            .map(|mut streams| {
                thread::spawn(move || {
                    let mut latencies = Vec::with_capacity(streams.len());
                    let mut failed = 0usize;
                    for stream in &mut streams {
                        let begin = Instant::now();
                        let echoed = echo_once(stream);
                        match echoed {
                            Ok(()) => latencies.push(begin.elapsed().as_secs_f64() * 1000.0),
                            Err(_) => failed += 1,
                        }
                    }
                    (streams, latencies, failed)
                })
            })
            .collect();
        let mut held = Vec::with_capacity(established);
        let mut latencies = Vec::with_capacity(established);
        let mut echo_failed = 0;
        for echoer in echoers {
            let (streams, mut times, failed) = echoer
                .join()
                .map_err(|_| io::Error::other("echo thread panicked"))?;
            held.extend(streams);
            latencies.append(&mut times);
            echo_failed += failed;
        }
        latencies.sort_by(f64::total_cmp);
        let echoed = stats(&children)?;
        drop(held);
        thread::sleep(Duration::from_secs(5));
        let closed = stats(&children)?;

        let base = get(&before, "rss_kb");
        let rss_open = get(&open, "rss_kb").max(get(&echoed, "rss_kb"));
        let tunnel = |sample: &Value, key: &str| sample["tunnel"][key].as_f64().unwrap_or(0.0);
        let mut report = json!({
            "outbound": arg(args, "outbound", "redirect"),
            "concurrent": count,
            "threads": threads,
            "established": established,
            "connect_failed": connect_failed,
            "open_secs": open_secs,
            "echo_ok": latencies.len(),
            "echo_failed": echo_failed,
            "echo_p50_ms": percentile(&latencies, 0.5),
            "echo_p99_ms": percentile(&latencies, 0.99),
            "echo_max_ms": latencies.last().copied().unwrap_or(0.0),
            "tcp_active_open": tunnel(&open, "tcp_active"),
            "tcp_rejected": tunnel(&closed, "tcp_rejected") - tunnel(&before, "tcp_rejected"),
            "rss_before_kb": base,
            "rss_open_kb": rss_open,
            "per_conn_kb": (rss_open - base) / established.max(1) as f64,
            "rss_after_close_kb": get(&closed, "rss_kb"),
            "tcp_active_after_close": tunnel(&closed, "tcp_active"),
            "cpu_ms_open": delta(&before, &open, "cpu_us") / 1000.0,
            "hwm_kb": get(&closed, "hwm_kb"),
        });
        let mut failures = Vec::new();
        if established < count {
            failures.push(format!("{established} of {count} connections established"));
        }
        if echo_failed > 0 {
            failures.push(format!("{echo_failed} connections did not echo"));
        }
        rss_limit(args, rss_open, &mut failures)?;
        report["max_rss_mb"] = json!(args.get("max-rss-mb"));
        verdict(args, report, failures)
    }

    // ---- udp-sessions: UDP flow table at scale ----------------------------

    /// Keeps every UDP flow open: sends are counted and dropped, replies
    /// never come, so a flow lives until the tunnel's idle timeout.
    struct UdpHold;

    struct HoldSend;

    impl DatagramSend for HoldSend {
        fn send<'a>(&'a mut self, _payload: &'a [u8]) -> BoxFuture<'a, io::Result<()>> {
            Box::pin(async { Ok(()) })
        }
    }

    struct HoldRecv;

    impl DatagramRecv for HoldRecv {
        fn recv(&mut self) -> BoxFuture<'_, io::Result<Vec<u8>>> {
            Box::pin(std::future::pending())
        }
    }

    impl TcpOutbound for UdpHold {
        fn protocol(&self) -> &'static str {
            "bench-udp-hold"
        }

        fn connect<'a>(&'a self, _target: &'a TargetAddr) -> BoxFuture<'a, io::Result<BoxStream>> {
            Box::pin(async { Err(io::Error::other("udp-sessions opens no TCP")) })
        }

        fn open_udp<'a>(&'a self, _target: &'a TargetAddr) -> BoxFuture<'a, io::Result<UdpFlow>> {
            Box::pin(async { Ok(UdpFlow::new(Box::new(HoldSend), Box::new(HoldRecv))) })
        }
    }

    fn rss_kb() -> f64 {
        std::fs::read_to_string("/proc/self/status")
            .unwrap_or_default()
            .lines()
            .find_map(|line| line.strip_prefix("VmRSS:"))
            .and_then(|rest| rest.split_whitespace().next())
            .and_then(|value| value.parse().ok())
            .unwrap_or(0.0)
    }

    /// One UDP datagram from app socket `index` (10.64.0.0/10, one port per
    /// address block) to a fixed destination.
    fn udp_packet(index: usize) -> Vec<u8> {
        let host = (index / 50_000) as u32 + 1;
        let port = 10_000 + (index % 50_000) as u16;
        let source = (0x0a40_0000u32 + host).to_be_bytes();
        let mut packet = Vec::with_capacity(64);
        etherparse::PacketBuilder::ipv4(source, [203, 0, 113, 9], 64)
            .udp(port, 4000)
            .write(&mut packet, &[0x42; 32])
            .expect("UDP packet builds");
        packet
    }

    fn udp_sessions(args: &Args) -> io::Result<()> {
        let flows = num(args, "flows", 100_000)? as usize;
        let settings = TunnelSettings {
            mtu: 1500,
            tcp_window_bytes: 16 * 1024,
            max_tcp_connections: 128,
            max_udp_flows: flows + 1024,
            tcp_evict_idle: engine_embedded::tunnel::DEFAULT_TCP_EVICT_IDLE,
            udp_evict_idle: engine_embedded::tunnel::DEFAULT_UDP_EVICT_IDLE,
            max_dns_in_flight: 32,
            idle_timeout: Duration::from_secs(300),
            connect_timeout: Duration::from_secs(10),
            dns: Arc::new(DnsPolicy::tcp(
                SocketAddr::from(([127, 0, 0, 1], 53)),
                Duration::from_secs(5),
            )),
            worker_threads: workers(args)?,
        };
        let rss_before = rss_kb();
        let sink: PacketSink = Box::new(|_packet: &[u8]| {});
        let tunnel = Tunnel::start(settings, Arc::new(UdpHold), sink)?;
        thread::sleep(Duration::from_millis(500));
        let rss_started = rss_kb();

        // Feed every flow's first datagram; back off while the queue is full.
        let begin = Instant::now();
        let mut retries = 0u64;
        for index in 0..flows {
            let packet = udp_packet(index);
            while !tunnel.input_packet(&packet) {
                retries += 1;
                thread::sleep(Duration::from_micros(200));
            }
        }
        let fed_secs = begin.elapsed().as_secs_f64();
        // The tunnel closes a flow after 60 s without traffic: wait for the
        // flows to open, well inside that.
        let deadline = Instant::now() + Duration::from_secs(40);
        let mut snapshot = tunnel.stats();
        while (snapshot.udp_flows + snapshot.udp_failed + snapshot.udp_dropped) < flows as u64
            && Instant::now() < deadline
        {
            thread::sleep(Duration::from_millis(100));
            snapshot = tunnel.stats();
        }
        let open_secs = begin.elapsed().as_secs_f64();
        thread::sleep(Duration::from_secs(2));
        let rss_open = rss_kb();
        let snapshot = tunnel.stats();

        let report = json!({
            "flows": flows,
            "opened": snapshot.udp_flows,
            "failed": snapshot.udp_failed,
            "dropped": snapshot.udp_dropped,
            "input_retries": retries,
            "fed_secs": fed_secs,
            "open_secs": open_secs,
            "flows_per_s": snapshot.udp_flows as f64 / open_secs.max(1e-9),
            "rss_before_kb": rss_before,
            "rss_started_kb": rss_started,
            "rss_open_kb": rss_open,
            "per_flow_kb": (rss_open - rss_started) / flows.max(1) as f64,
            "max_rss_mb": args.get("max-rss-mb"),
            "tunnel": serde_json::to_value(&snapshot).unwrap_or(Value::Null),
        });
        let mut failures = Vec::new();
        if snapshot.udp_flows < flows as u64 {
            failures.push(format!(
                "{} of {flows} UDP flows opened ({} failed, {} dropped)",
                snapshot.udp_flows, snapshot.udp_failed, snapshot.udp_dropped
            ));
        }
        rss_limit(args, rss_open, &mut failures)?;
        drop(tunnel);
        verdict(args, report, failures)
    }

    // ---- soak: memory trend over hours ------------------------------------

    /// One short connection: 1 KiB echoed, then closed.
    fn short_echo() -> io::Result<()> {
        let mut stream = connect(b'E')?;
        stream.set_read_timeout(Some(Duration::from_secs(10)))?;
        let payload = [0x5au8; 1024];
        stream.write_all(&payload)?;
        let mut back = [0u8; 1024];
        stream.read_exact(&mut back)?;
        if back != payload {
            return Err(io::Error::other("echo differs"));
        }
        Ok(())
    }

    /// Least-squares slope of `points` (x, y).
    fn slope(points: &[(f64, f64)]) -> Option<f64> {
        if points.len() < 3 {
            return None;
        }
        let n = points.len() as f64;
        let mean_x = points.iter().map(|p| p.0).sum::<f64>() / n;
        let mean_y = points.iter().map(|p| p.1).sum::<f64>() / n;
        let (mut covariance, mut variance) = (0.0, 0.0);
        for (x, y) in points {
            covariance += (x - mean_x) * (y - mean_y);
            variance += (x - mean_x) * (x - mean_x);
        }
        (variance > 0.0).then_some(covariance / variance)
    }

    fn soak(args: &Args) -> io::Result<()> {
        let minutes = fnum(args, "minutes", 60.0)?;
        let sample_secs = num(args, "sample-secs", 60)?.max(1);
        let rate = num(args, "conns-per-s", 20)? as usize;
        let pool = num(args, "pool", 50)? as usize;
        let warmup = fnum(args, "warmup-share", 0.15)?.clamp(0.0, 0.9);
        let max_slope = fnum(args, "max-slope-mb-per-h", 1.0)?;
        let max_failure_ratio = fnum(args, "max-failure-ratio", 0.001)?;
        let (children, _) = start(args)?;
        thread::sleep(Duration::from_secs(1));
        let baseline = stats(&children)?;

        let mut held = Vec::with_capacity(pool);
        for _ in 0..pool {
            held.push(connect(b'H')?);
        }
        let begin = Instant::now();
        let end = begin + Duration::from_secs_f64(minutes * 60.0);
        let sample_every = Duration::from_secs(sample_secs);
        let mut next_sample = begin;
        let mut next_burst = begin + Duration::from_secs(30);
        let mut next_turnover = begin + Duration::from_secs(60);
        let mut tick = begin;
        let mut samples: Vec<(f64, Value)> = Vec::new();
        let (mut opened, mut failed, mut bursts, mut burst_failed) = (0u64, 0u64, 0u64, 0u64);
        let mut burst_mbps = Vec::new();
        let mut turnover = 0usize;

        while Instant::now() < end {
            let now = Instant::now();
            if now >= next_sample {
                let sample = stats(&children)?;
                let hours = begin.elapsed().as_secs_f64() / 3600.0;
                eprintln!(
                    "soak {:>7.3} h: rss {} KiB, fds {}, tcp_active {}, conns {opened}, failed {failed}",
                    hours,
                    get(&sample, "rss_kb"),
                    get(&sample, "fds"),
                    sample["tunnel"]["tcp_active"],
                );
                samples.push((hours, sample));
                next_sample += sample_every;
            }
            for _ in 0..rate {
                match short_echo() {
                    Ok(()) => opened += 1,
                    Err(_) => failed += 1,
                }
            }
            if now >= next_burst {
                bursts += 1;
                match download(&children, 4, 2.0) {
                    Ok(result) => burst_mbps.push(get(&result, "mbps")),
                    Err(_) => burst_failed += 1,
                }
                next_burst += Duration::from_secs(30);
            }
            if now >= next_turnover && !held.is_empty() {
                let count = (pool / 10).clamp(1, held.len());
                let first = turnover % held.len();
                for slot in first..first + count {
                    let slot = slot % held.len();
                    match connect(b'H') {
                        Ok(stream) => held[slot] = stream,
                        Err(_) => failed += 1,
                    }
                }
                turnover += count;
                next_turnover += Duration::from_secs(60);
            }
            tick += Duration::from_secs(1);
            if let Some(wait) = tick.checked_duration_since(Instant::now()) {
                thread::sleep(wait);
            } else {
                tick = Instant::now();
            }
        }

        let during = stats(&children)?;
        samples.push((begin.elapsed().as_secs_f64() / 3600.0, during));
        drop(held);
        thread::sleep(Duration::from_secs(10));
        let closed = stats(&children)?;

        let skip = ((samples.len() as f64) * warmup).floor() as usize;
        let trend: Vec<(f64, f64)> = samples
            .iter()
            .skip(skip)
            .map(|(hours, sample)| (*hours, get(sample, "rss_kb") / 1024.0))
            .collect();
        let rss_slope = slope(&trend);
        let fds_trend: Vec<(f64, f64)> = samples
            .iter()
            .skip(skip)
            .map(|(hours, sample)| (*hours, get(sample, "fds")))
            .collect();
        burst_mbps.sort_by(f64::total_cmp);
        let attempts = opened + failed;
        let failure_ratio = if attempts > 0 {
            failed as f64 / attempts as f64
        } else {
            0.0
        };
        let tunnel = |sample: &Value, key: &str| sample["tunnel"][key].as_f64().unwrap_or(0.0);
        let series: Vec<Value> = samples
            .iter()
            .map(|(hours, sample)| {
                json!({
                    "h": hours,
                    "rss_kb": get(sample, "rss_kb"),
                    "fds": get(sample, "fds"),
                    "threads": get(sample, "threads"),
                    "tcp_active": tunnel(sample, "tcp_active"),
                    "cpu_s": get(sample, "cpu_us") / 1e6,
                })
            })
            .collect();
        let report = json!({
            "outbound": arg(args, "outbound", "redirect"),
            "minutes": minutes,
            "hours": begin.elapsed().as_secs_f64() / 3600.0,
            "conns_per_s": rate,
            "pool": pool,
            "connections": opened,
            "failed": failed,
            "failure_ratio": failure_ratio,
            "bursts": bursts,
            "burst_failed": burst_failed,
            "burst_mbps_p50": percentile(&burst_mbps, 0.5),
            "burst_mbps_min": burst_mbps.first().copied().unwrap_or(0.0),
            "samples": samples.len(),
            "warmup_samples": skip,
            "rss_baseline_kb": get(&baseline, "rss_kb"),
            "rss_first_kb": trend.first().map_or(0.0, |p| p.1 * 1024.0),
            "rss_last_kb": trend.last().map_or(0.0, |p| p.1 * 1024.0),
            "rss_max_kb": samples.iter().map(|(_, s)| get(s, "rss_kb")).fold(0.0, f64::max),
            "rss_slope_mb_per_h": rss_slope,
            "max_slope_mb_per_h": max_slope,
            "fds_slope_per_h": slope(&fds_trend),
            "fds_baseline": get(&baseline, "fds"),
            "fds_after_close": get(&closed, "fds"),
            "tcp_active_after_close": tunnel(&closed, "tcp_active"),
            "rss_after_close_kb": get(&closed, "rss_kb"),
            "cpu_s": (get(&closed, "cpu_us") - get(&baseline, "cpu_us")) / 1e6,
            "tunnel": closed["tunnel"].clone(),
            "series": series,
        });
        let mut failures = Vec::new();
        match rss_slope {
            Some(value) if value > max_slope => failures.push(format!(
                "RSS grows {value:.3} MiB/h after warm-up, above {max_slope} MiB/h"
            )),
            Some(_) => {}
            None => failures.push("too few samples for a trend".to_string()),
        }
        if failure_ratio > max_failure_ratio {
            failures.push(format!(
                "{failed} of {attempts} connections failed ({:.4}%)",
                failure_ratio * 100.0
            ));
        }
        if bursts > 0 && burst_failed * 100 > bursts {
            failures.push(format!("{burst_failed} of {bursts} download bursts failed"));
        }
        let leftover = tunnel(&closed, "tcp_active");
        if leftover > 8.0 {
            failures.push(format!(
                "{leftover} TCP flows still active after every connection closed"
            ));
        }
        let fds_left = get(&closed, "fds") - get(&baseline, "fds");
        if fds_left > 32.0 {
            failures.push(format!(
                "{fds_left} more file descriptors open than at the start"
            ));
        }
        verdict(args, report, failures)
    }
}
