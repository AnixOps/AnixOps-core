//! Capture quality and overhead benchmark: the packet tunnel of the iOS
//! Network Extension with HTTPS decryption, driven through a Linux TUN device.
//!
//! This example only provides the processes; `.github/scripts/capture-gates.py`
//! moves the TUN device into a network namespace, runs the clients (curl and a
//! raw TCP reader) there and applies the gates (docs/performance-ci.md):
//!
//! - `origin --root-out PATH`: local servers in front of the tunnel's
//!   outbound. A raw TCP port (the client sends a big-endian `u64` length and
//!   reads that many bytes), a plain HTTP/1.1 port and an HTTPS port for
//!   `bench.test` (`GET /bytes/N` answers N bytes). The HTTPS certificate is
//!   issued by a fresh root written to PATH as PEM. Prints
//!   `READY <raw> <http> <https>`.
//! - `tunnel --tun NAME --hosts PATH --device-root-out PATH [--raw P --http P
//!   --https P --origin-root PATH] [--capture on|off] [--capture-bytes N]`:
//!   one [`Tunnel`] on the TUN device with the [`MitmEngine`] of a policy
//!   whose `[MITM] hostname` list is `bench.test` plus every host in the
//!   hosts file. The device root is generated here and written to PATH as PEM
//!   for the client to trust. Flows to 198.18.0.2 go to the raw port, flows
//!   to 198.18.0.3 (or `bench.test`) port 80/443 to the HTTP/HTTPS ports, and
//!   everything else straight to its address. Without `--origin-root` the
//!   upstream TLS client is the production one (webpki roots), as for real
//!   sites. Prints `READY <control port>`; each line sent to the control port
//!   is either `sample` (process memory and CPU, tunnel counters),
//!   `reset_peak` (VmHWM starts again from the current RSS) or a
//!   runtime control request such as `{"cmd":"export_capture","format":"har"}`,
//!   answered with one JSON line.

#[cfg(target_os = "linux")]
fn main() {
    if let Err(err) = linux::main() {
        eprintln!("capture_bench: {err}");
        std::process::exit(1);
    }
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("capture_bench needs Linux (a TUN device)");
}

#[cfg(target_os = "linux")]
mod linux {
    use std::collections::HashMap;
    use std::io::{self, BufRead, BufReader, Write};
    use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener};
    use std::os::fd::RawFd;
    use std::sync::Arc;
    use std::thread;
    use std::time::Duration;

    use base64::Engine as _;
    use engine_embedded::config::MitmConfig;
    use engine_embedded::connections::Dispatcher;
    use engine_embedded::control;
    use engine_embedded::dns_policy::DnsPolicy;
    use engine_embedded::mitm::MitmEngine;
    use engine_embedded::tunnel::{FlowInterceptor, PacketSink, Tunnel, TunnelSettings};
    use engine_outbound::{BoxFuture, BoxStream, TargetAddr, TcpOutbound};
    use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair, KeyUsagePurpose};
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    use rustls::{ClientConfig, RootCertStore, ServerConfig};
    use serde_json::{json, Value};
    use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

    const BENCH_HOST: &str = "bench.test";
    const RAW_IP: Ipv4Addr = Ipv4Addr::new(198, 18, 0, 2);
    const ORIGIN_IP: Ipv4Addr = Ipv4Addr::new(198, 18, 0, 3);
    const CHUNK: usize = 64 * 1024;

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
            "origin" => origin(&args),
            "tunnel" => tunnel(&args),
            _ => Err(io::Error::other(
                "usage: capture_bench origin --root-out PATH \
                 | capture_bench tunnel --tun NAME --hosts PATH --device-root-out PATH ...",
            )),
        }
    }

    fn arg<'a>(args: &'a Args, key: &str) -> Option<&'a str> {
        args.get(key)
            .map(String::as_str)
            .filter(|value| !value.is_empty())
    }

    fn port(args: &Args, key: &str) -> io::Result<u16> {
        match arg(args, key) {
            Some(value) => value
                .parse()
                .map_err(|_| io::Error::other(format!("--{key} is not a port"))),
            None => Ok(0),
        }
    }

    fn pem(certificate: &[u8]) -> String {
        let encoded = base64::engine::general_purpose::STANDARD.encode(certificate);
        let mut out = String::from("-----BEGIN CERTIFICATE-----\n");
        for line in encoded.as_bytes().chunks(64) {
            out.push_str(std::str::from_utf8(line).unwrap_or_default());
            out.push('\n');
        }
        out.push_str("-----END CERTIFICATE-----\n");
        out
    }

    struct Root {
        certificate: CertificateDer<'static>,
        key: KeyPair,
        params: CertificateParams,
    }

    fn root(name: &str) -> io::Result<Root> {
        let key = KeyPair::generate().map_err(io::Error::other)?;
        let mut params = CertificateParams::new(Vec::<String>::new()).map_err(io::Error::other)?;
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, name);
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let certificate = params
            .self_signed(&key)
            .map_err(io::Error::other)?
            .der()
            .clone();
        Ok(Root {
            certificate,
            key,
            params,
        })
    }

    fn provider() -> Arc<rustls::crypto::CryptoProvider> {
        Arc::new(rustls::crypto::ring::default_provider())
    }

    // ---- origin process -------------------------------------------------

    fn origin(args: &Args) -> io::Result<()> {
        let root_out = arg(args, "root-out").ok_or_else(|| io::Error::other("--root-out"))?;
        let origin_root = root("capture_bench origin root")?;
        std::fs::write(root_out, pem(&origin_root.certificate))?;
        let key = KeyPair::generate().map_err(io::Error::other)?;
        let issuer = rcgen::Issuer::from_params(&origin_root.params, &origin_root.key);
        let leaf = CertificateParams::new(vec![BENCH_HOST.to_string()])
            .map_err(io::Error::other)?
            .signed_by(&key, &issuer)
            .map_err(io::Error::other)?;
        let mut tls = ServerConfig::builder_with_provider(provider())
            .with_safe_default_protocol_versions()
            .map_err(io::Error::other)?
            .with_no_client_auth()
            .with_single_cert(
                vec![leaf.der().clone()],
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())),
            )
            .map_err(io::Error::other)?;
        tls.alpn_protocols = vec![b"http/1.1".to_vec()];
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls));

        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()?;
        runtime.block_on(async move {
            let raw = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
            let http = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
            let https = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
            println!(
                "READY {} {} {}",
                raw.local_addr()?.port(),
                http.local_addr()?.port(),
                https.local_addr()?.port()
            );
            io::stdout().flush()?;
            tokio::spawn(async move {
                while let Ok((stream, _)) = raw.accept().await {
                    let _ = stream.set_nodelay(true);
                    tokio::spawn(async move {
                        let _ = raw_connection(stream).await;
                    });
                }
            });
            tokio::spawn(async move {
                while let Ok((stream, _)) = http.accept().await {
                    let _ = stream.set_nodelay(true);
                    tokio::spawn(async move {
                        let _ = http_connection(stream).await;
                    });
                }
            });
            while let Ok((stream, _)) = https.accept().await {
                let _ = stream.set_nodelay(true);
                let acceptor = acceptor.clone();
                tokio::spawn(async move {
                    if let Ok(stream) = acceptor.accept(stream).await {
                        let _ = http_connection(stream).await;
                    }
                });
            }
            Ok::<(), io::Error>(())
        })
    }

    async fn send_bytes(stream: &mut (impl AsyncWrite + Unpin), mut left: u64) -> io::Result<()> {
        let chunk = vec![0x5au8; CHUNK];
        while left > 0 {
            let n = left.min(CHUNK as u64) as usize;
            stream.write_all(&chunk[..n]).await?;
            left -= n as u64;
        }
        stream.flush().await
    }

    async fn raw_connection(mut stream: tokio::net::TcpStream) -> io::Result<()> {
        let mut length = [0u8; 8];
        stream.read_exact(&mut length).await?;
        send_bytes(&mut stream, u64::from_be_bytes(length)).await?;
        stream.shutdown().await
    }

    /// HTTP/1.1 with keep-alive: `GET /bytes/N` answers N bytes, any other
    /// path 1 KiB.
    async fn http_connection(mut stream: impl AsyncRead + AsyncWrite + Unpin) -> io::Result<()> {
        let mut buf = Vec::new();
        let mut chunk = vec![0u8; 8192];
        loop {
            let end = loop {
                if let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                    break end;
                }
                if buf.len() > 64 * 1024 {
                    return Ok(());
                }
                let n = stream.read(&mut chunk).await?;
                if n == 0 {
                    return Ok(());
                }
                buf.extend_from_slice(&chunk[..n]);
            };
            let head = String::from_utf8_lossy(&buf[..end]).into_owned();
            buf.drain(..end + 4);
            let path = head
                .lines()
                .next()
                .and_then(|line| line.split_whitespace().nth(1))
                .unwrap_or("/");
            let length: u64 = path
                .strip_prefix("/bytes/")
                .and_then(|rest| rest.split('?').next())
                .and_then(|value| value.parse().ok())
                .unwrap_or(1024);
            let close = head.lines().any(|line| {
                line.split_once(':').is_some_and(|(key, value)| {
                    key.trim().eq_ignore_ascii_case("connection")
                        && value.trim().eq_ignore_ascii_case("close")
                })
            });
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: {length}\r\n{}\r\n",
                if close { "Connection: close\r\n" } else { "" }
            );
            stream.write_all(response.as_bytes()).await?;
            send_bytes(&mut stream, length).await?;
            if close {
                return stream.shutdown().await;
            }
        }
    }

    // ---- tunnel process -------------------------------------------------

    /// Bench addresses to the local origin, everything else as addressed.
    struct Split {
        raw: u16,
        http: u16,
        https: u16,
    }

    impl Split {
        fn local(&self, port: u16) -> Option<SocketAddr> {
            let local = match port {
                80 => self.http,
                443 => self.https,
                _ => return None,
            };
            (local != 0).then(|| SocketAddr::from(([127, 0, 0, 1], local)))
        }
    }

    impl TcpOutbound for Split {
        fn protocol(&self) -> &'static str {
            "bench-split"
        }

        fn connect<'a>(&'a self, target: &'a TargetAddr) -> BoxFuture<'a, io::Result<BoxStream>> {
            Box::pin(async move {
                let stream = match target {
                    TargetAddr::Ip(addr) if addr.ip() == IpAddr::V4(RAW_IP) && self.raw != 0 => {
                        tokio::net::TcpStream::connect(("127.0.0.1", self.raw)).await?
                    }
                    TargetAddr::Ip(addr) if addr.ip() == IpAddr::V4(ORIGIN_IP) => {
                        let local = self
                            .local(addr.port())
                            .ok_or_else(|| io::Error::other("no local origin for this port"))?;
                        tokio::net::TcpStream::connect(local).await?
                    }
                    TargetAddr::Ip(addr) => tokio::net::TcpStream::connect(*addr).await?,
                    TargetAddr::Domain(host, port) if host == BENCH_HOST => {
                        let local = self
                            .local(*port)
                            .ok_or_else(|| io::Error::other("no local origin for this port"))?;
                        tokio::net::TcpStream::connect(local).await?
                    }
                    TargetAddr::Domain(host, port) => {
                        tokio::net::TcpStream::connect((host.as_str(), *port)).await?
                    }
                };
                stream.set_nodelay(true)?;
                Ok(Box::new(stream) as BoxStream)
            })
        }
    }

    fn hosts(path: Option<&str>) -> io::Result<Vec<String>> {
        let mut hosts = vec![BENCH_HOST.to_string()];
        if let Some(path) = path {
            for line in std::fs::read_to_string(path)?.lines() {
                let host = line.split('#').next().unwrap_or_default().trim();
                if !host.is_empty() && !hosts.iter().any(|known| known == host) {
                    hosts.push(host.to_string());
                }
            }
        }
        Ok(hosts)
    }

    fn tunnel(args: &Args) -> io::Result<()> {
        let device_root = root("capture_bench device root")?;
        let root_out =
            arg(args, "device-root-out").ok_or_else(|| io::Error::other("--device-root-out"))?;
        std::fs::write(root_out, pem(&device_root.certificate))?;

        let base64 = base64::engine::general_purpose::STANDARD;
        // One harmless rule, so every request goes through the rewrite hook's
        // planning as with a real plugin; no rule reads a body.
        let policy = format!(
            "[Plugin]\nname = capture_bench\n\n[URL Rewrite]\n^https://never\\.bench\\.test/ reject\n\n\
             [MITM]\nenable = true\nhostname = {}\n",
            hosts(arg(args, "hosts"))?.join(", ")
        );
        let config = MitmConfig {
            policy,
            plugins: Vec::new(),
            ca_certificate: base64.encode(&device_root.certificate),
            // A desktop root is kept as PKCS#8, which the engine accepts too.
            ca_private_key: base64.encode(device_root.key.serialize_der()),
            script_assets: Default::default(),
            resource_assets: Default::default(),
            script_store_path: None,
        };
        let mut engine = MitmEngine::new(&config).map_err(io::Error::other)?;
        if let Some(path) = arg(args, "origin-root") {
            // The local origin's own root; real sites keep the production
            // upstream client (webpki roots) by leaving this out.
            let text = std::fs::read_to_string(path)?;
            let body: String = text
                .lines()
                .filter(|line| !line.starts_with("-----"))
                .collect();
            let der = base64.decode(body).map_err(io::Error::other)?;
            let mut roots = RootCertStore::empty();
            roots
                .add(CertificateDer::from(der))
                .map_err(io::Error::other)?;
            let mut upstream = ClientConfig::builder_with_provider(provider())
                .with_safe_default_protocol_versions()
                .map_err(io::Error::other)?
                .with_root_certificates(roots)
                .with_no_client_auth();
            upstream.alpn_protocols = vec![b"http/1.1".to_vec()];
            engine = engine.with_upstream_config(upstream);
        }
        let interceptor: Arc<dyn FlowInterceptor> = Arc::new(engine);

        let dispatcher = Arc::new(Dispatcher::single(Arc::new(Split {
            raw: port(args, "raw")?,
            http: port(args, "http")?,
            https: port(args, "https")?,
        })));
        if arg(args, "capture") == Some("on") {
            let budget = match arg(args, "capture-bytes") {
                Some(value) => format!(
                    r#","max_total_bytes":{}"#,
                    value
                        .parse::<u64>()
                        .map_err(|_| io::Error::other("--capture-bytes is not a number"))?
                ),
                None => String::new(),
            };
            let request = format!(r#"{{"cmd":"set_capture","enabled":true{budget}}}"#);
            control::handle(&dispatcher, request.as_bytes()).map_err(io::Error::other)?;
        }

        let fd = open_tun(arg(args, "tun").unwrap_or("cap0"))?;
        let settings = TunnelSettings {
            mtu: 1500,
            tcp_window_bytes: 64 * 1024,
            max_tcp_connections: 512,
            max_udp_flows: 256,
            max_dns_in_flight: 32,
            idle_timeout: Duration::from_secs(300),
            connect_timeout: Duration::from_secs(10),
            dns: Arc::new(DnsPolicy::tcp(
                SocketAddr::from(([127, 0, 0, 1], 53)),
                Duration::from_secs(5),
            )),
        };
        let sink: PacketSink = Box::new(move |packet: &[u8]| {
            // SAFETY: `fd` stays open for the life of the process.
            let _ = unsafe { libc::write(fd, packet.as_ptr().cast(), packet.len()) };
        });
        let tunnel = Arc::new(Tunnel::start_with_dispatcher(
            settings,
            dispatcher.clone(),
            Some(interceptor),
            None,
            sink,
        )?);

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

        let listener = TcpListener::bind("127.0.0.1:0")?;
        println!("READY {}", listener.local_addr()?.port());
        io::stdout().flush()?;
        for stream in listener.incoming() {
            let mut stream = stream?;
            let mut line = String::new();
            BufReader::new(&stream).read_line(&mut line)?;
            let line = line.trim();
            let answer = if line == "sample" {
                sample(&tunnel, &dispatcher)
            } else if line == "reset_peak" {
                // Resets VmHWM to the current RSS, so the next sample's
                // peak covers one phase only.
                json!({ "reset": std::fs::write("/proc/self/clear_refs", "5").is_ok() })
            } else {
                match control::handle(&dispatcher, line.as_bytes()) {
                    Ok(bytes) => serde_json::from_slice(&bytes).unwrap_or(Value::Null),
                    Err(err) => json!({ "error": err.to_string() }),
                }
            };
            writeln!(stream, "{answer}")?;
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

    /// Process memory and CPU, the tunnel counters and the capture status.
    fn sample(tunnel: &Tunnel, dispatcher: &Dispatcher) -> Value {
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
            "cpu_us": micros(usage.ru_utime) + micros(usage.ru_stime),
            "tunnel": serde_json::to_value(tunnel.stats()).unwrap_or(Value::Null),
            "capture": serde_json::to_value(dispatcher.tracker().capture().status())
                .unwrap_or(Value::Null),
        })
    }
}
