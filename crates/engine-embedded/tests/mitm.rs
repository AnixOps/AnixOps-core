//! HTTPS decryption end to end over in-memory streams: a client that trusts
//! the device root, the MITM engine, and a TLS origin behind a test outbound.
#![cfg(feature = "mitm")]

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use base64::Engine as _;
use engine_embedded::config::MitmConfig;
use engine_embedded::connections::Dispatcher;
use engine_embedded::control;
use engine_embedded::mitm::{p256_pkcs8_from_x963, MitmEngine};
use engine_embedded::tunnel::{FlowInterceptor, InterceptedFlow};
use engine_embedded::{EmbeddedRuntime, RuntimeErrorCode};
use engine_outbound::{BoxFuture, BoxStream, TargetAddr, TcpOutbound};
use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair, KeyUsagePurpose};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;

const HOST: &str = "api.example.test";
const POLICY: &str = "[Plugin]\n\
name = NetworkCore MITM Test\n\
\n\
[URL Rewrite]\n\
^https://api\\.example\\.test/blocked reject\n\
\n\
[MITM]\n\
enable = true\n\
hostname = api.example.test\n";
/// A Loon plugin listed next to the policy; its hosts join the merged list.
const PLUGIN: &str = "#!name = Second\n\
[Rewrite]\n\
^https://cdn\\.example\\.test/ads/ reject\n\
\n\
[MITM]\n\
hostname = %APPEND% cdn.example.test\n";

struct Root {
    certificate: CertificateDer<'static>,
    key: KeyPair,
    params: CertificateParams,
}

fn root(name: &str) -> Root {
    let key = KeyPair::generate().unwrap();
    let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, name);
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let certificate = params.self_signed(&key).unwrap().der().clone();
    Root {
        certificate,
        key,
        params,
    }
}

/// The root key the way the Swift side stores it: X9.63 `04 || X || Y || D`.
fn x963(key: &KeyPair) -> Vec<u8> {
    let pkcs8 = key.serialize_der();
    assert_eq!(pkcs8.len(), 138, "ring P-256 PKCS#8 layout");
    let mut raw = pkcs8[73..138].to_vec();
    raw.extend_from_slice(&pkcs8[36..68]);
    raw
}

fn mitm_config(device_root: &Root) -> MitmConfig {
    let base64 = base64::engine::general_purpose::STANDARD;
    MitmConfig {
        policy: POLICY.to_string(),
        plugins: vec![PLUGIN.to_string()],
        ca_certificate: base64.encode(&device_root.certificate),
        ca_private_key: base64.encode(x963(&device_root.key)),
        script_assets: Default::default(),
        resource_assets: Default::default(),
        script_store_path: None,
    }
}

fn trusting(root: &CertificateDer<'static>, alpn: &[&[u8]]) -> ClientConfig {
    let mut roots = RootCertStore::empty();
    roots.add(root.clone()).unwrap();
    let mut config =
        ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
    config.alpn_protocols = alpn.iter().map(|value| value.to_vec()).collect();
    config
}

/// A TLS origin for `HOST`: records each request head and answers with a
/// fixed body.
struct Origin {
    acceptor: tokio_rustls::TlsAcceptor,
    requests: mpsc::UnboundedSender<String>,
}

impl Origin {
    fn new(origin_root: &Root, requests: mpsc::UnboundedSender<String>) -> Self {
        let key = KeyPair::generate().unwrap();
        let issuer = rcgen::Issuer::from_params(&origin_root.params, &origin_root.key);
        let certificate = CertificateParams::new(vec![HOST.to_string()])
            .unwrap()
            .signed_by(&key, &issuer)
            .unwrap();
        let mut config =
            ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_no_client_auth()
                .with_single_cert(
                    vec![certificate.der().clone()],
                    PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())),
                )
                .unwrap();
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        Self {
            acceptor: tokio_rustls::TlsAcceptor::from(Arc::new(config)),
            requests,
        }
    }
}

impl TcpOutbound for Origin {
    fn protocol(&self) -> &'static str {
        "test-origin"
    }

    fn connect<'a>(&'a self, _target: &'a TargetAddr) -> BoxFuture<'a, io::Result<BoxStream>> {
        Box::pin(async move {
            let (near, far) = tokio::io::duplex(64 * 1024);
            let acceptor = self.acceptor.clone();
            let requests = self.requests.clone();
            tokio::spawn(async move {
                let mut stream = acceptor.accept(far).await.unwrap();
                let mut buf = Vec::new();
                let mut chunk = [0u8; 4096];
                loop {
                    let n = stream.read(&mut chunk).await.unwrap_or(0);
                    if n == 0 {
                        return;
                    }
                    buf.extend_from_slice(&chunk[..n]);
                    while let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                        let head = String::from_utf8_lossy(&buf[..end]).into_owned();
                        buf.drain(..end + 4);
                        requests.send(head).unwrap();
                        let body = b"hello from origin";
                        let response = format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\r\n",
                            body.len()
                        );
                        stream.write_all(response.as_bytes()).await.unwrap();
                        stream.write_all(body).await.unwrap();
                        stream.flush().await.unwrap();
                    }
                }
            });
            Ok(Box::new(near) as BoxStream)
        })
    }
}

async fn read_response(stream: &mut (impl AsyncReadExt + Unpin)) -> (String, String) {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        if let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            let head = String::from_utf8_lossy(&buf[..end]).into_owned();
            let length = head
                .lines()
                .find_map(|line| {
                    let (key, value) = line.split_once(':')?;
                    key.eq_ignore_ascii_case("content-length")
                        .then(|| value.trim().parse::<usize>().unwrap())
                })
                .unwrap_or(0);
            while buf.len() < end + 4 + length {
                let n = stream.read(&mut chunk).await.unwrap();
                assert!(n > 0, "response cut short");
                buf.extend_from_slice(&chunk[..n]);
            }
            let body = String::from_utf8_lossy(&buf[end + 4..end + 4 + length]).into_owned();
            return (head, body);
        }
        let n = stream.read(&mut chunk).await.unwrap();
        assert!(n > 0, "connection closed before a response");
        buf.extend_from_slice(&chunk[..n]);
    }
}

#[tokio::test]
async fn decrypts_rewrites_and_relays_https_for_listed_hosts() {
    let device_root = root("NetworkCore Test Device Root");
    let origin_root = root("NetworkCore Test Origin Root");
    let engine = Arc::new(
        MitmEngine::new(&mitm_config(&device_root))
            .unwrap()
            .with_upstream_config(trusting(&origin_root.certificate, &[b"http/1.1"])),
    );
    let (requests_tx, mut requests) = mpsc::unbounded_channel();
    let origin = Arc::new(Origin::new(&origin_root, requests_tx));
    let target: SocketAddr = "192.0.2.10:443".parse().unwrap();

    let (app, tunnel_side) = tokio::io::duplex(64 * 1024);
    let client = tokio::spawn({
        let config = trusting(&device_root.certificate, &[b"h2", b"http/1.1"]);
        async move {
            let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
            let mut stream = connector
                .connect(ServerName::try_from(HOST).unwrap(), app)
                .await
                .expect("the client trusts the device root");
            assert_eq!(stream.get_ref().1.alpn_protocol(), Some(&b"http/1.1"[..]));

            stream
                .write_all(b"GET /blocked/ad.js HTTP/1.1\r\nHost: api.example.test\r\n\r\n")
                .await
                .unwrap();
            let (head, _) = read_response(&mut stream).await;
            assert!(head.starts_with("HTTP/1.1 4"), "rejected: {head}");

            stream
                .write_all(
                    b"GET /data HTTP/1.1\r\nHost: api.example.test\r\nAccept-Encoding: gzip, br\r\n\r\n",
                )
                .await
                .unwrap();
            let (head, body) = read_response(&mut stream).await;
            assert!(head.starts_with("HTTP/1.1 200"), "relayed: {head}");
            assert_eq!(body, "hello from origin");
        }
    });

    let mut tunnel_side = tunnel_side;
    let mut first = vec![0u8; 4096];
    let n = tunnel_side.read(&mut first).await.unwrap();
    first.truncate(n);
    let host = engine
        .claim(&first, target)
        .expect("the listed host is intercepted");
    assert_eq!(host, HOST);
    let other: SocketAddr = "192.0.2.10:8443".parse().unwrap();
    assert_eq!(engine.claim(&first, other), None, "only port 443");
    assert!(!engine.intercepts("www.example.test"));
    assert!(
        engine.intercepts("cdn.example.test"),
        "plugin hosts are merged"
    );

    let flow = InterceptedFlow {
        inbound: Box::new(tunnel_side),
        first,
        host,
        target,
    };
    let server = tokio::spawn({
        let engine = engine.clone();
        let origin = origin.clone();
        async move {
            let _ = engine
                .serve_flow(
                    flow,
                    origin.as_ref(),
                    Duration::from_secs(5),
                    Duration::from_secs(5),
                )
                .await;
        }
    });

    tokio::time::timeout(Duration::from_secs(10), client)
        .await
        .expect("client finished")
        .unwrap();
    // Only the second request reached the origin, asking for an identity body.
    let head = requests.recv().await.unwrap();
    assert!(head.starts_with("GET /data HTTP/1.1"), "{head}");
    // No rule reads this response, so it may arrive compressed and streams
    // through as sent.
    assert!(head.contains("Accept-Encoding: gzip, br"), "{head}");
    assert!(requests.try_recv().is_err());
    server.abort();
}

/// A plain HTTP origin: answers every request head it reads with a fixed body.
struct PlainOrigin {
    requests: mpsc::UnboundedSender<String>,
    body: Vec<u8>,
    /// Header lines added to every response, each ending in CRLF.
    extra_headers: &'static str,
}

impl TcpOutbound for PlainOrigin {
    fn protocol(&self) -> &'static str {
        "test-plain-origin"
    }

    fn connect<'a>(&'a self, _target: &'a TargetAddr) -> BoxFuture<'a, io::Result<BoxStream>> {
        Box::pin(async move {
            let (near, mut far) = tokio::io::duplex(64 * 1024);
            let requests = self.requests.clone();
            let body = self.body.clone();
            let extra_headers = self.extra_headers;
            tokio::spawn(async move {
                let mut buf = Vec::new();
                let mut chunk = [0u8; 4096];
                loop {
                    let n = far.read(&mut chunk).await.unwrap_or(0);
                    if n == 0 {
                        return;
                    }
                    buf.extend_from_slice(&chunk[..n]);
                    while let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                        let head = String::from_utf8_lossy(&buf[..end]).into_owned();
                        buf.drain(..end + 4);
                        // Tests that do not read the heads drop the receiver.
                        let _ = requests.send(head);
                        let response = format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n{extra_headers}Content-Length: {}\r\n\r\n",
                            body.len()
                        );
                        far.write_all(response.as_bytes()).await.unwrap();
                        far.write_all(&body).await.unwrap();
                    }
                }
            });
            Ok(Box::new(near) as BoxStream)
        })
    }
}

#[tokio::test]
async fn rewrites_plain_http_without_a_mitm_hostname() {
    let device_root = root("NetworkCore Test Device Root");
    let mut config = mitm_config(&device_root);
    config.plugins.push(
        "#!name = Plain\n[Rewrite]\n^http://plain\\.example\\.test/ads/ reject\n".to_string(),
    );
    let engine = Arc::new(MitmEngine::new(&config).unwrap());
    let (requests_tx, mut requests) = mpsc::unbounded_channel();
    let origin = Arc::new(PlainOrigin {
        requests: requests_tx,
        body: b"plain origin".to_vec(),
        extra_headers: "",
    });
    let target: SocketAddr = "192.0.2.20:80".parse().unwrap();

    let first = b"GET /ads/banner.js HTTP/1.1\r\nHost: plain.example.test\r\n\r\n".to_vec();
    assert!(
        !engine.intercepts("plain.example.test"),
        "not a [MITM] host"
    );
    let host = engine
        .claim(&first, target)
        .expect("plain HTTP is relayed through the rewrite hook");
    assert_eq!(host, "plain.example.test");
    assert_eq!(
        engine.claim(
            b"CONNECT a.test:443 HTTP/1.1\r\nHost: a.test\r\n\r\n",
            target
        ),
        None,
        "CONNECT keeps its own path"
    );
    assert_eq!(engine.claim(b"\x00\x01binary", target), None);

    let (mut app, tunnel_side) = tokio::io::duplex(64 * 1024);
    let flow = InterceptedFlow {
        inbound: Box::new(tunnel_side),
        first,
        host,
        target,
    };
    let server = tokio::spawn({
        let engine = engine.clone();
        let origin = origin.clone();
        async move {
            let _ = engine
                .serve_flow(
                    flow,
                    origin.as_ref(),
                    Duration::from_secs(5),
                    Duration::from_secs(5),
                )
                .await;
        }
    });

    let (head, _) = tokio::time::timeout(Duration::from_secs(10), read_response(&mut app))
        .await
        .expect("rejected in time");
    assert!(head.starts_with("HTTP/1.1 4"), "rejected: {head}");

    app.write_all(b"GET /index.html HTTP/1.1\r\nHost: plain.example.test\r\n\r\n")
        .await
        .unwrap();
    let (head, body) = tokio::time::timeout(Duration::from_secs(10), read_response(&mut app))
        .await
        .expect("relayed in time");
    assert!(head.starts_with("HTTP/1.1 200"), "relayed: {head}");
    assert_eq!(body, "plain origin");
    let head = requests.recv().await.unwrap();
    assert!(head.starts_with("GET /index.html HTTP/1.1"), "{head}");
    assert!(
        requests.try_recv().is_err(),
        "the rejected request stayed local"
    );
    server.abort();
}

/// mitm-scripts-04: `reject-dict` and `reject-img` answer with a body the
/// app parses (`{}`, a 1x1 GIF); a HEAD answer keeps the length and sends no
/// body, so the connection stays in step.
#[tokio::test]
async fn reject_variants_answer_with_parseable_bodies() {
    let device_root = root("NetworkCore Test Device Root");
    let mut config = mitm_config(&device_root);
    config.plugins.push(
        "#!name = Bodies\n[Rewrite]\n\
         ^http://plain\\.example\\.test/dict reject-dict\n\
         ^http://plain\\.example\\.test/img reject-img\n"
            .to_string(),
    );
    let engine = Arc::new(MitmEngine::new(&config).unwrap());
    let (requests_tx, mut requests) = mpsc::unbounded_channel();
    let origin = Arc::new(PlainOrigin {
        requests: requests_tx,
        body: b"plain origin".to_vec(),
        extra_headers: "",
    });
    let target: SocketAddr = "192.0.2.20:80".parse().unwrap();
    let first = b"GET /dict HTTP/1.1\r\nHost: plain.example.test\r\n\r\n".to_vec();
    let host = engine
        .claim(&first, target)
        .expect("plain HTTP is relayed through the rewrite hook");

    let (mut app, tunnel_side) = tokio::io::duplex(64 * 1024);
    let flow = InterceptedFlow {
        inbound: Box::new(tunnel_side),
        first,
        host,
        target,
    };
    let server = tokio::spawn({
        let engine = engine.clone();
        let origin = origin.clone();
        async move {
            let _ = engine
                .serve_flow(
                    flow,
                    origin.as_ref(),
                    Duration::from_secs(5),
                    Duration::from_secs(5),
                )
                .await;
        }
    });

    let header = |head: &str, name: &str| -> Option<String> {
        head.lines().find_map(|line| {
            let (key, value) = line.split_once(':')?;
            key.trim()
                .eq_ignore_ascii_case(name)
                .then(|| value.trim().to_string())
        })
    };

    let (head, body) = tokio::time::timeout(Duration::from_secs(10), read_response(&mut app))
        .await
        .expect("answered in time");
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    assert_eq!(
        header(&head, "Content-Type").as_deref(),
        Some("application/json; charset=utf-8"),
        "{head}"
    );
    assert_eq!(body, "{}");

    app.write_all(b"GET /img HTTP/1.1\r\nHost: plain.example.test\r\n\r\n")
        .await
        .unwrap();
    let (head, body) = tokio::time::timeout(Duration::from_secs(10), read_response(&mut app))
        .await
        .expect("answered in time");
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    assert_eq!(header(&head, "Content-Type").as_deref(), Some("image/gif"));
    assert_eq!(header(&head, "Content-Length").as_deref(), Some("43"));
    assert!(body.starts_with("GIF89a"), "{body:?}");

    // HEAD: the GET's length, no body; the connection closes after it.
    app.write_all(b"HEAD /dict HTTP/1.1\r\nHost: plain.example.test\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let mut rest = Vec::new();
    tokio::time::timeout(Duration::from_secs(10), app.read_to_end(&mut rest))
        .await
        .expect("closed in time")
        .unwrap();
    let end = rest
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .expect("a response head");
    let head = String::from_utf8_lossy(&rest[..end]).into_owned();
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    assert_eq!(header(&head, "Content-Length").as_deref(), Some("2"));
    assert!(rest[end + 4..].is_empty(), "a HEAD answer has no body");

    assert!(requests.try_recv().is_err(), "every answer stayed local");
    server.abort();
}

#[tokio::test]
async fn a_body_rule_reads_a_body_the_origin_compressed_anyway() {
    use std::io::Write;

    let device_root = root("NetworkCore Test Device Root");
    let mut config = mitm_config(&device_root);
    config.plugins.push(
        "#!name = Body\n[Body Rewrite]\nhttp-response ^http://plain\\.example\\.test/ origin edited\n"
            .to_string(),
    );
    let engine = Arc::new(MitmEngine::new(&config).unwrap());
    let mut gzip = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    gzip.write_all(b"hello from the origin").unwrap();
    let (requests_tx, mut requests) = mpsc::unbounded_channel();
    // The origin answers gzip although asked for identity.
    let origin = Arc::new(PlainOrigin {
        requests: requests_tx,
        body: gzip.finish().unwrap(),
        extra_headers: "Content-Encoding: gzip\r\n",
    });
    let target: SocketAddr = "192.0.2.21:80".parse().unwrap();
    let first =
        b"GET /page HTTP/1.1\r\nHost: plain.example.test\r\nAccept-Encoding: gzip\r\n\r\n".to_vec();
    let host = engine.claim(&first, target).unwrap();
    let (mut app, tunnel_side) = tokio::io::duplex(64 * 1024);
    let flow = InterceptedFlow {
        inbound: Box::new(tunnel_side),
        first,
        host,
        target,
    };
    let server = tokio::spawn({
        let engine = engine.clone();
        let origin = origin.clone();
        async move {
            let _ = engine
                .serve_flow(
                    flow,
                    origin.as_ref(),
                    Duration::from_secs(5),
                    Duration::from_secs(5),
                )
                .await;
        }
    });

    let (head, body) = tokio::time::timeout(Duration::from_secs(10), read_response(&mut app))
        .await
        .expect("answered in time");
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    // The rule saw the text and the app gets it plain.
    assert_eq!(body, "hello from the edited");
    assert!(
        !head.to_ascii_lowercase().contains("content-encoding"),
        "{head}"
    );
    let request = requests.recv().await.unwrap();
    assert!(request.contains("Accept-Encoding: identity"), "{request}");
    server.abort();
}

#[tokio::test]
async fn bodies_no_rule_reads_stream_past_the_body_limit_and_keep_the_connection() {
    let device_root = root("NetworkCore Test Device Root");
    let mut config = mitm_config(&device_root);
    config.plugins.push(
        "#!name = Plain\n[Rewrite]\n^http://plain\\.example\\.test/ads/ reject\n".to_string(),
    );
    let engine = Arc::new(MitmEngine::new(&config).unwrap());
    let (requests_tx, mut requests) = mpsc::unbounded_channel();
    // Twice the limit a body that rules read may have.
    let large = vec![b'z'; 2 * 1024 * 1024];
    let origin = Arc::new(PlainOrigin {
        requests: requests_tx,
        body: large.clone(),
        extra_headers: "",
    });
    let target: SocketAddr = "192.0.2.20:80".parse().unwrap();
    let first = b"GET /video.bin HTTP/1.1\r\nHost: plain.example.test\r\n\r\n".to_vec();
    let host = engine.claim(&first, target).expect("plain HTTP is claimed");
    let (mut app, tunnel_side) = tokio::io::duplex(64 * 1024);
    let flow = InterceptedFlow {
        inbound: Box::new(tunnel_side),
        first,
        host,
        target,
    };
    let server = tokio::spawn({
        let engine = engine.clone();
        let origin = origin.clone();
        async move {
            let _ = engine
                .serve_flow(
                    flow,
                    origin.as_ref(),
                    Duration::from_secs(5),
                    Duration::from_secs(5),
                )
                .await;
        }
    });

    let (head, body) = tokio::time::timeout(Duration::from_secs(10), read_response(&mut app))
        .await
        .expect("streamed in time");
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    assert_eq!(body.len(), large.len());
    assert!(body.bytes().all(|byte| byte == b'z'));

    // The same connection still carries requests the rules act on.
    app.write_all(b"GET /ads/banner.js HTTP/1.1\r\nHost: plain.example.test\r\n\r\n")
        .await
        .unwrap();
    let (head, _) = tokio::time::timeout(Duration::from_secs(10), read_response(&mut app))
        .await
        .expect("rejected in time");
    assert!(head.starts_with("HTTP/1.1 4"), "rejected: {head}");
    let head = requests.recv().await.unwrap();
    assert!(head.starts_with("GET /video.bin HTTP/1.1"), "{head}");
    assert!(requests.try_recv().is_err());
    server.abort();
}

/// A plain HTTP origin that sends the raw bytes of the first request it
/// reads to `requests`, answers with `response` exactly as given and
/// closes.
struct RawOrigin {
    requests: mpsc::UnboundedSender<Vec<u8>>,
    response: &'static [u8],
}

impl TcpOutbound for RawOrigin {
    fn protocol(&self) -> &'static str {
        "test-raw-origin"
    }

    fn connect<'a>(&'a self, _target: &'a TargetAddr) -> BoxFuture<'a, io::Result<BoxStream>> {
        Box::pin(async move {
            let (near, mut far) = tokio::io::duplex(64 * 1024);
            let requests = self.requests.clone();
            let response = self.response;
            tokio::spawn(async move {
                let mut buf = Vec::new();
                let mut chunk = [0u8; 4096];
                while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
                    let n = far.read(&mut chunk).await.unwrap_or(0);
                    if n == 0 {
                        return;
                    }
                    buf.extend_from_slice(&chunk[..n]);
                }
                let _ = requests.send(buf);
                far.write_all(response).await.unwrap();
                let _ = far.shutdown().await;
            });
            Ok(Box::new(near) as BoxStream)
        })
    }
}

/// Relays `request` (the first bytes of a plain HTTP flow) to an origin
/// answering `response`: what the app got, to the end, and what the
/// origin was sent.
async fn plain_exchange(request: &[u8], response: &'static [u8]) -> (Vec<u8>, Vec<u8>) {
    let device_root = root("NetworkCore Test Device Root");
    let engine = Arc::new(MitmEngine::new(&mitm_config(&device_root)).unwrap());
    let (requests_tx, mut requests) = mpsc::unbounded_channel();
    let origin = Arc::new(RawOrigin {
        requests: requests_tx,
        response,
    });
    let target: SocketAddr = "192.0.2.22:80".parse().unwrap();
    let host = engine
        .claim(request, target)
        .expect("plain HTTP is claimed");
    let (mut app, tunnel_side) = tokio::io::duplex(64 * 1024);
    let flow = InterceptedFlow {
        inbound: Box::new(tunnel_side),
        first: request.to_vec(),
        host,
        target,
    };
    let server = tokio::spawn({
        let engine = engine.clone();
        let origin = origin.clone();
        async move {
            let _ = engine
                .serve_flow(
                    flow,
                    origin.as_ref(),
                    Duration::from_secs(5),
                    Duration::from_secs(5),
                )
                .await;
        }
    });
    let mut received = Vec::new();
    tokio::time::timeout(Duration::from_secs(10), app.read_to_end(&mut received))
        .await
        .expect("relayed in time")
        .unwrap();
    let sent = tokio::time::timeout(Duration::from_secs(10), requests.recv())
        .await
        .expect("the origin was asked")
        .unwrap();
    // The app is done: a connection relayed raw ends both ways.
    drop(app);
    tokio::time::timeout(Duration::from_secs(10), server)
        .await
        .expect("served in time")
        .unwrap();
    (received, sent)
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

#[tokio::test]
async fn plain_http_the_relay_cannot_rewrite_still_goes_through() {
    let get = b"GET /report HTTP/1.1\r\nHost: plain.example.test\r\n\r\n";

    // A file name in GBK, as an old server sends it.
    let gbk: &'static [u8] = b"HTTP/1.1 200 OK\r\nContent-Disposition: attachment; filename=\"\xb1\xa8\xb1\xed.xls\"\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello";
    let (received, _) = plain_exchange(get, gbk).await;
    assert!(
        contains(&received, b"filename=\"\xb1\xa8\xb1\xed.xls\"\r\n"),
        "{}",
        String::from_utf8_lossy(&received)
    );
    assert!(received.ends_with(b"\r\n\r\nhello"));

    // An internet radio stream answers `ICY 200 OK`.
    let icy: &'static [u8] = b"ICY 200 OK\r\nicy-name: radio\r\n\r\nAUDIO-FRAMES";
    let (received, _) = plain_exchange(get, icy).await;
    assert_eq!(received, icy);

    // Lines ending in a bare LF, and a length given twice alike.
    let lf: &'static [u8] = b"HTTP/1.1 200 OK\nContent-Length: 5, 5\nConnection: close\n\nhello";
    let (received, _) = plain_exchange(get, lf).await;
    assert!(received.starts_with(b"HTTP/1.1 200"), "{received:?}");
    assert!(received.ends_with(b"\r\n\r\nhello"));

    // Lengths that disagree are not guessed at: the app gets a 502.
    let conflicting: &'static [u8] =
        b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nContent-Length: 6\r\n\r\nhello!";
    let (received, _) = plain_exchange(get, conflicting).await;
    assert!(received.starts_with(b"HTTP/1.1 502"), "{received:?}");

    // A request head the relay cannot read goes to the origin as it came.
    let odd = b"GET /x HTTP/1.1\r\nHost: plain.example.test\r\nBad Name: \xff\r\n\r\n";
    let ok: &'static [u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";
    let (received, sent) = plain_exchange(odd, ok).await;
    assert_eq!(sent, odd);
    assert_eq!(received, ok);
}

#[test]
fn plain_requests_to_a_forward_proxy_are_left_alone() {
    let device_root = root("NetworkCore Test Device Root");
    let engine = MitmEngine::new(&mitm_config(&device_root)).unwrap();
    let target: SocketAddr = "192.0.2.23:3128".parse().unwrap();
    assert_eq!(
        engine.claim(
            b"GET http://plain.example.test/ HTTP/1.1\r\nHost: plain.example.test\r\n\r\n",
            target
        ),
        None
    );
    assert_eq!(
        engine.claim(
            b"OPTIONS * HTTP/1.1\r\nHost: plain.example.test\r\n\r\n",
            target
        ),
        None
    );
    assert!(engine
        .claim(
            b"GET / HTTP/1.1\r\nHost: plain.example.test\r\n\r\n",
            target
        )
        .is_some());
}

#[test]
fn plugins_over_one_mib_are_accepted() {
    let device_root = root("NetworkCore Test Device Root");
    let mut config = mitm_config(&device_root);
    let mut large = String::from("#!name = Large\n[Rule]\n");
    let mut index = 0;
    while large.len() < 3 * 1024 * 1024 {
        large.push_str(&format!("DOMAIN-SUFFIX,ads{index}.example.test,REJECT\n"));
        index += 1;
    }
    large.push_str("[MITM]\nhostname = large.example.test\n");
    config.plugins.push(large);
    let engine = MitmEngine::new(&config).expect("a 3 MiB plugin loads");
    assert!(engine.intercepts("large.example.test"));
    assert_eq!(engine.plugin_rules().len(), index);
}

#[test]
fn x963_keys_convert_to_ring_pkcs8() {
    let key = KeyPair::generate().unwrap();
    assert_eq!(
        p256_pkcs8_from_x963(&x963(&key)).unwrap(),
        key.serialize_der()
    );
    assert_eq!(p256_pkcs8_from_x963(&[0x04; 96]), None);
}

#[test]
fn runtime_config_accepts_and_validates_the_mitm_section() {
    let device_root = root("NetworkCore Test Device Root");
    let config = mitm_config(&device_root);
    let envelope = |mitm: serde_json::Value| {
        serde_json::to_vec(&serde_json::json!({
            "schema_version": 1,
            "profile_id": "mitm-test",
            "outbound": { "type": "direct" },
            "mitm": mitm,
        }))
        .unwrap()
    };
    let valid = serde_json::json!({
        "policy": config.policy,
        "ca_certificate": config.ca_certificate,
        "ca_private_key": config.ca_private_key,
    });
    assert!(EmbeddedRuntime::from_json(&envelope(valid.clone())).is_ok());
    let plugins_only = serde_json::json!({
        "plugins": [PLUGIN],
        "ca_certificate": config.ca_certificate,
        "ca_private_key": config.ca_private_key,
    });
    assert!(EmbeddedRuntime::from_json(&envelope(plugins_only.clone())).is_ok());
    let mut empty_plugin = plugins_only;
    empty_plugin["plugins"] = serde_json::json!(["  "]);
    let error = EmbeddedRuntime::from_json(&envelope(empty_plugin))
        .err()
        .unwrap();
    assert_eq!(error.code, RuntimeErrorCode::ConfigRejected);

    let mut bad_key = valid.clone();
    bad_key["ca_private_key"] = serde_json::json!("AAAA");
    let error = EmbeddedRuntime::from_json(&envelope(bad_key))
        .err()
        .unwrap();
    assert_eq!(error.code, RuntimeErrorCode::ConfigRejected);

    let mut unknown = valid;
    unknown["extra"] = serde_json::json!(true);
    let error = EmbeddedRuntime::from_json(&envelope(unknown))
        .err()
        .unwrap();
    assert_eq!(error.code, RuntimeErrorCode::ConfigRejected);
}

/// One request through a TLS client that trusts `device_root`, the engine
/// and `origin`; returns the response head and body.
#[cfg(feature = "scripts")]
async fn exchange(
    engine: Arc<MitmEngine>,
    origin: Arc<Origin>,
    device_root: &Root,
    request: &'static [u8],
) -> (String, String) {
    let target: SocketAddr = "192.0.2.10:443".parse().unwrap();
    let (app, mut tunnel_side) = tokio::io::duplex(64 * 1024);
    let client = tokio::spawn({
        let config = trusting(&device_root.certificate, &[b"http/1.1"]);
        async move {
            let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
            let mut stream = connector
                .connect(ServerName::try_from(HOST).unwrap(), app)
                .await
                .expect("the client trusts the device root");
            stream.write_all(request).await.unwrap();
            read_response(&mut stream).await
        }
    });
    let mut first = vec![0u8; 4096];
    let n = tunnel_side.read(&mut first).await.unwrap();
    first.truncate(n);
    let host = engine.claim(&first, target).expect("intercepted");
    let flow = InterceptedFlow {
        inbound: Box::new(tunnel_side),
        first,
        host,
        target,
    };
    let server = tokio::spawn(async move {
        let _ = engine
            .serve_flow(
                flow,
                origin.as_ref(),
                Duration::from_secs(5),
                Duration::from_secs(5),
            )
            .await;
    });
    let response = tokio::time::timeout(Duration::from_secs(10), client)
        .await
        .expect("client finished")
        .unwrap();
    server.abort();
    response
}

#[cfg(feature = "scripts")]
#[tokio::test]
async fn consented_scripts_rewrite_responses_in_quickjs() {
    let dir = std::env::temp_dir().join(format!("networkcore-mitm-scripts-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let script = dir.join("upper.js");
    std::fs::write(
        &script,
        "$persistentStore.write('seen', 'count');\n\
         $done({ body: $response.body.toUpperCase(), headers: { 'X-Script': '1' } });",
    )
    .unwrap();
    let plugin = "#!name = Upper\n\
[Script]\n\
http-response ^https://api\\.example\\.test/data script-path=https://scripts.example.test/upper.js, requires-body=true, tag=upper\n\
\n\
[MITM]\n\
hostname = api.example.test\n";
    let device_root = root("NetworkCore Test Device Root");
    let origin_root = root("NetworkCore Test Origin Root");
    let base64 = base64::engine::general_purpose::STANDARD;
    let config = MitmConfig {
        policy: String::new(),
        plugins: vec![plugin.to_string()],
        ca_certificate: base64.encode(&device_root.certificate),
        ca_private_key: base64.encode(x963(&device_root.key)),
        script_assets: [(
            "https://scripts.example.test/upper.js".to_string(),
            script.display().to_string(),
        )]
        .into(),
        resource_assets: Default::default(),
        script_store_path: Some(dir.join("store.json").display().to_string()),
    };
    let engine = Arc::new(
        MitmEngine::new(&config)
            .unwrap()
            .with_upstream_config(trusting(&origin_root.certificate, &[b"http/1.1"])),
    );
    let (requests_tx, _requests) = mpsc::unbounded_channel();
    let origin = Arc::new(Origin::new(&origin_root, requests_tx));

    let (head, body) = exchange(
        engine,
        origin,
        &device_root,
        b"GET /data HTTP/1.1\r\nHost: api.example.test\r\n\r\n",
    )
    .await;
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    assert!(head.to_ascii_lowercase().contains("x-script: 1"), "{head}");
    assert_eq!(body, "HELLO FROM ORIGIN");
    let store = std::fs::read_to_string(dir.join("store.json")).unwrap_or_default();
    assert!(store.contains("count"), "persistent store: {store}");

    // Every consented script must exist when the runtime starts.
    let mut missing = config.clone();
    missing.script_assets.insert(
        "https://scripts.example.test/missing.js".to_string(),
        dir.join("missing.js").display().to_string(),
    );
    assert!(MitmEngine::new(&missing).is_err());
    let _ = std::fs::remove_dir_all(&dir);
}

/// A response script reads the request it answers (`$request.headers`) as
/// the request rules left it.
#[cfg(feature = "scripts")]
#[tokio::test]
async fn response_scripts_read_the_request_headers() {
    let dir = std::env::temp_dir().join(format!(
        "networkcore-mitm-request-scripts-{}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let script = dir.join("echo.js");
    std::fs::write(
        &script,
        "$done({ body: [$request.method, $request.headers['X-Token'], $request.headers['Cookie'],\
         $request.headers['X-Added'], $response.body].join('|') });",
    )
    .unwrap();
    let plugin = "#!name = Echo\n\
[Rewrite]\n\
^https://api\\.example\\.test/data header-add X-Added rule\n\
\n\
[Script]\n\
http-response ^https://api\\.example\\.test/data script-path=https://scripts.example.test/echo.js, requires-body=true, tag=echo\n\
\n\
[MITM]\n\
hostname = api.example.test\n";
    let device_root = root("NetworkCore Test Device Root");
    let origin_root = root("NetworkCore Test Origin Root");
    let base64 = base64::engine::general_purpose::STANDARD;
    let config = MitmConfig {
        policy: String::new(),
        plugins: vec![plugin.to_string()],
        ca_certificate: base64.encode(&device_root.certificate),
        ca_private_key: base64.encode(x963(&device_root.key)),
        script_assets: [(
            "https://scripts.example.test/echo.js".to_string(),
            script.display().to_string(),
        )]
        .into(),
        resource_assets: Default::default(),
        script_store_path: None,
    };
    let engine = Arc::new(
        MitmEngine::new(&config)
            .unwrap()
            .with_upstream_config(trusting(&origin_root.certificate, &[b"http/1.1"])),
    );
    let (requests_tx, _requests) = mpsc::unbounded_channel();
    let origin = Arc::new(Origin::new(&origin_root, requests_tx));

    let (head, body) = exchange(
        engine,
        origin,
        &device_root,
        b"GET /data HTTP/1.1\r\nHost: api.example.test\r\nX-Token: abc\r\nCookie: a=1; b=2\r\n\r\n",
    )
    .await;
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    assert_eq!(body, "GET|abc|a=1; b=2|rule|hello from origin");
    let _ = std::fs::remove_dir_all(&dir);
}

#[cfg(feature = "scripts")]
#[tokio::test]
async fn scheduled_scripts_run_by_hand_and_on_network_changes() {
    use engine_embedded::control::ScriptControl;

    let dir = std::env::temp_dir().join(format!("networkcore-mitm-cron-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let checkin = dir.join("checkin.js");
    std::fs::write(
        &checkin,
        "$notification.post('Check-in', $script.type, typeof $request + ',' + $argument);\n$done();",
    )
    .unwrap();
    let net = dir.join("net.js");
    std::fs::write(
        &net,
        "$notification.post('Net', $event.name, '');\n$done();",
    )
    .unwrap();
    let plugin = "#!name = Tasks\n\
[Script]\n\
cron \"0 9 * * *\" script-path=https://scripts.example.test/checkin.js, tag=checkin, argument=a=1\n\
network-changed script-path=https://scripts.example.test/net.js, tag=net\n\
\n\
[MITM]\n\
hostname = api.example.test\n";
    let device_root = root("NetworkCore Test Device Root");
    let base64 = base64::engine::general_purpose::STANDARD;
    let config = MitmConfig {
        policy: String::new(),
        plugins: vec![plugin.to_string()],
        ca_certificate: base64.encode(&device_root.certificate),
        ca_private_key: base64.encode(x963(&device_root.key)),
        script_assets: [
            (
                "https://scripts.example.test/checkin.js".to_string(),
                checkin.display().to_string(),
            ),
            (
                "https://scripts.example.test/net.js".to_string(),
                net.display().to_string(),
            ),
        ]
        .into(),
        resource_assets: Default::default(),
        script_store_path: None,
    };
    let engine = Arc::new(MitmEngine::new(&config).unwrap());
    let scripts = engine.script_control(&ScriptControl::Scripts).unwrap();
    assert_eq!(scripts["scripts"][0]["tag"], "checkin");
    assert_eq!(scripts["scripts"][0]["trigger"], "cron");
    assert!(
        scripts["scripts"][0]["next_run"].as_str().is_some(),
        "{scripts}"
    );
    assert_eq!(scripts["scripts"][1]["trigger"], "network-changed");

    let background = engine.clone().background().expect("scheduled scripts run");
    tokio::spawn(background);
    let run = engine
        .script_control(&ScriptControl::Run {
            tag: "checkin".to_string(),
        })
        .unwrap();
    assert_eq!(run["scheduled"], true);
    let changed = engine
        .script_control(&ScriptControl::NetworkChanged)
        .unwrap();
    assert_eq!(changed["scheduled"], 1);

    let mut seen = Vec::new();
    for _ in 0..200 {
        let notifications = engine
            .script_control(&ScriptControl::Notifications)
            .unwrap();
        for notification in notifications["notifications"].as_array().unwrap() {
            seen.push(format!(
                "{}|{}|{}",
                notification["title"].as_str().unwrap(),
                notification["subtitle"].as_str().unwrap(),
                notification["content"].as_str().unwrap()
            ));
        }
        if seen.len() >= 2 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert_eq!(
        seen,
        ["Check-in|cron|undefined,a=1", "Net|network-changed|"],
        "notifications; scripts: {}",
        engine.script_control(&ScriptControl::Scripts).unwrap()
    );
    let scripts = engine.script_control(&ScriptControl::Scripts).unwrap();
    assert_eq!(scripts["scripts"][0]["last_status"], "done");
    let _ = std::fs::remove_dir_all(&dir);
}

/// Desktop: the same `mitm` section on the local SOCKS5/HTTP listener. A
/// listed host is answered with a leaf signed by the device root before any
/// outbound connection exists; other tunnels are relayed untouched.
#[cfg(feature = "local-proxy")]
#[tokio::test]
async fn local_proxy_decrypts_listed_hosts_and_relays_the_rest() {
    use engine_embedded::local_proxy::LocalProxy;
    use inbound_mixed::MixedSettings;
    use tokio::net::{TcpListener, TcpStream};

    const ESTABLISHED: &[u8] = b"HTTP/1.1 200 Connection established\r\n\r\n";
    async fn connect(proxy: SocketAddr, authority: &str) -> TcpStream {
        let mut stream = TcpStream::connect(proxy).await.unwrap();
        let request = format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n");
        stream.write_all(request.as_bytes()).await.unwrap();
        let mut answer = vec![0u8; ESTABLISHED.len()];
        stream.read_exact(&mut answer).await.unwrap();
        assert_eq!(answer, ESTABLISHED);
        stream
    }

    let device_root = root("NetworkCore Test Device Root");
    let config = mitm_config(&device_root);
    let envelope = serde_json::to_vec(&serde_json::json!({
        "schema_version": 1,
        "profile_id": "mitm-desktop",
        "outbound": { "type": "direct" },
        "mitm": {
            "policy": config.policy,
            "ca_certificate": config.ca_certificate,
            // A desktop root is kept as PKCS#8 instead of X9.63.
            "ca_private_key": base64::engine::general_purpose::STANDARD
                .encode(device_root.key.serialize_der()),
        },
    }))
    .unwrap();
    let proxy = LocalProxy::start(
        &envelope,
        "127.0.0.1:0".parse().unwrap(),
        MixedSettings::default(),
    )
    .unwrap();
    assert!(proxy.decrypts_https());

    let stream = connect(proxy.local_addr(), &format!("{HOST}:443")).await;
    let trust = trusting(&device_root.certificate, &[b"http/1.1"]);
    let tls = tokio_rustls::TlsConnector::from(Arc::new(trust))
        .connect(ServerName::try_from(HOST).unwrap(), stream)
        .await
        .expect("the listed host is served with a leaf from the device root");
    drop(tls);
    assert_eq!(proxy.mitm_stats().mitm_flows, 1);

    let echo = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let echo_addr = echo.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = echo.accept().await {
            tokio::spawn(async move {
                let (mut reader, mut writer) = stream.split();
                let _ = tokio::io::copy(&mut reader, &mut writer).await;
            });
        }
    });
    let mut stream = connect(proxy.local_addr(), &echo_addr.to_string()).await;
    stream.write_all(b"not for decryption").await.unwrap();
    let mut echoed = [0u8; 18];
    tokio::time::timeout(Duration::from_secs(10), stream.read_exact(&mut echoed))
        .await
        .expect("relayed in time")
        .unwrap();
    assert_eq!(&echoed, b"not for decryption");
    assert_eq!(proxy.mitm_stats().mitm_flows, 1);

    // Without the section the listener only relays.
    let plain = LocalProxy::start(
        br#"{"schema_version":1,"profile_id":"desktop","outbound":{"type":"direct"}}"#,
        "127.0.0.1:0".parse().unwrap(),
        MixedSettings::default(),
    )
    .unwrap();
    assert!(!plain.decrypts_https());
}

fn base64_field(value: &serde_json::Value) -> Vec<u8> {
    base64::engine::general_purpose::STANDARD
        .decode(value.as_str().expect("a base64 string"))
        .unwrap()
}

fn control_json(dispatcher: &Dispatcher, request: &str) -> serde_json::Value {
    serde_json::from_slice(&control::handle(dispatcher, request.as_bytes()).unwrap()).unwrap()
}

#[tokio::test]
async fn capture_keeps_decrypted_http_under_the_origin_connection() {
    let device_root = root("NetworkCore Test Device Root");
    let engine = Arc::new(MitmEngine::new(&mitm_config(&device_root)).unwrap());
    let (requests_tx, _requests) = mpsc::unbounded_channel();
    let dispatcher = Arc::new(Dispatcher::single(Arc::new(PlainOrigin {
        requests: requests_tx,
        body: b"captured body".to_vec(),
        extra_headers: "",
    })));
    let status = control_json(&dispatcher, r#"{"cmd":"set_capture","enabled":true}"#);
    assert_eq!(status["enabled"], true);

    let target: SocketAddr = "192.0.2.20:80".parse().unwrap();
    let first =
        b"POST /submit?x=1 HTTP/1.1\r\nHost: plain.example.test\r\nContent-Length: 5\r\n\r\nhello"
            .to_vec();
    let host = engine
        .claim(&first, target)
        .expect("plain HTTP is taken over");
    let (mut app, tunnel_side) = tokio::io::duplex(64 * 1024);
    let flow = InterceptedFlow {
        inbound: Box::new(tunnel_side),
        first,
        host,
        target,
    };
    let server = tokio::spawn({
        let engine = engine.clone();
        let dispatcher = dispatcher.clone();
        async move {
            let _ = engine
                .serve_flow(
                    flow,
                    dispatcher.as_ref(),
                    Duration::from_secs(5),
                    Duration::from_secs(5),
                )
                .await;
        }
    });
    let (head, body) = tokio::time::timeout(Duration::from_secs(10), read_response(&mut app))
        .await
        .expect("relayed in time");
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    assert_eq!(body, "captured body");

    let list = dispatcher.tracker().connections();
    let connection = list
        .active
        .iter()
        .chain(&list.closed)
        .next()
        .expect("the origin connection is listed");
    assert!(connection.captured);
    let request = format!(r#"{{"cmd":"capture_connection","id":{}}}"#, connection.id);
    let mut capture = serde_json::Value::Null;
    for _ in 0..100 {
        capture = control_json(&dispatcher, &request)["capture"].clone();
        // Filed as the request arrives, finished once answered.
        if capture["http"][0]["state"] == "done" {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(capture["decrypted"], true, "{capture}");
    assert!(capture["chunks"].as_array().unwrap().is_empty());
    let exchange = &capture["http"][0];
    assert_eq!(exchange["method"], "POST");
    assert!(
        exchange["url"].as_str().unwrap().ends_with("/submit?x=1"),
        "{exchange}"
    );
    assert_eq!(exchange["status"], 200);
    assert_eq!(
        base64_field(&exchange["request"]["body"]["data_base64"]),
        b"hello"
    );
    assert_eq!(
        base64_field(&exchange["response"]["body"]["data_base64"]),
        b"captured body"
    );

    let export = control_json(&dispatcher, r#"{"cmd":"export_capture","format":"har"}"#);
    assert_eq!(export["format"], "har");
    let har: serde_json::Value =
        serde_json::from_slice(&base64_field(&export["data_base64"])).unwrap();
    let entry = &har["log"]["entries"][0];
    assert_eq!(entry["request"]["postData"]["text"], "hello");
    assert_eq!(entry["response"]["content"]["text"], "captured body");

    let export = control_json(&dispatcher, r#"{"cmd":"export_capture","format":"pcapng"}"#);
    let pcap = base64_field(&export["data_base64"]);
    assert!(pcap.windows(13).any(|window| window == b"captured body"));

    // One row per request, filtered by the shared expression syntax.
    let rows = control_json(
        &dispatcher,
        r#"{"cmd":"capture_requests","filter":"method:post status:2xx path:/submit"}"#,
    );
    let row = &rows["requests"][0];
    assert_eq!(row["connection_id"], connection.id, "{rows}");
    assert_eq!(row["index"], 0);
    assert_eq!(row["http_version"], "HTTP/1.1");
    assert_eq!(row["request_size"], 5);
    let none = control_json(
        &dispatcher,
        r#"{"cmd":"capture_requests","filter":"status:5xx"}"#,
    );
    assert!(none["requests"].as_array().unwrap().is_empty(), "{none}");
    let bad = control_json(
        &dispatcher,
        r#"{"cmd":"capture_requests","filter":"status:abc"}"#,
    );
    assert_eq!(bad["error"]["code"], "invalid_filter");
    assert_eq!(bad["error"]["at"], 7);

    let curl = control_json(
        &dispatcher,
        &format!(
            r#"{{"cmd":"export_capture","format":"curl","id":{},"exchange":0}}"#,
            connection.id
        ),
    );
    assert_eq!(curl["redacted"], true);
    let script = String::from_utf8(base64_field(&curl["data_base64"])).unwrap();
    assert!(script.contains("curl -X 'POST'"), "{script}");
    assert!(script.contains("--data-binary 'hello'"), "{script}");

    // Saved sessions: sealed on disk, listed, loaded back after a clear.
    let dir = std::env::temp_dir().join(format!("anixops-sessions-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let key = base64::engine::general_purpose::STANDARD.encode([9u8; 32]);
    let set = control_json(
        &dispatcher,
        &serde_json::json!({
            "cmd": "set_capture_storage",
            "dir": dir.to_str().unwrap(),
            "key_base64": key,
        })
        .to_string(),
    );
    assert_eq!(set["retention_days"], 7, "{set}");
    let saved = control_json(&dispatcher, r#"{"cmd":"save_capture","name":"plain"}"#);
    let session = saved["session"]["session"].as_str().unwrap().to_string();
    assert_eq!(saved["session"]["requests"], 1, "{saved}");
    let listed = control_json(&dispatcher, r#"{"cmd":"capture_sessions"}"#);
    assert_eq!(listed["sessions"][0]["session"], session.as_str());
    control_json(&dispatcher, r#"{"cmd":"clear_capture"}"#);
    let loaded = control_json(
        &dispatcher,
        &format!(r#"{{"cmd":"load_capture","session":"{session}"}}"#),
    );
    assert_eq!(loaded["enabled"], false, "{loaded}");
    let rows = control_json(&dispatcher, r#"{"cmd":"capture_requests"}"#);
    assert_eq!(rows["requests"][0]["method"], "POST", "{rows}");
    let deleted = control_json(
        &dispatcher,
        &format!(r#"{{"cmd":"delete_capture","session":"{session}"}}"#),
    );
    assert_eq!(deleted["deleted"], true);
    let _ = std::fs::remove_dir_all(&dir);
    server.abort();
}

/// A plain HTTP origin that answers with a chunked event stream: two events
/// at once (the first split across chunks), a third and the end once
/// `release` is notified.
struct EventOrigin {
    release: Arc<tokio::sync::Notify>,
}

impl TcpOutbound for EventOrigin {
    fn protocol(&self) -> &'static str {
        "test-event-origin"
    }

    fn connect<'a>(&'a self, _target: &'a TargetAddr) -> BoxFuture<'a, io::Result<BoxStream>> {
        Box::pin(async move {
            let (near, mut far) = tokio::io::duplex(64 * 1024);
            let release = self.release.clone();
            tokio::spawn(async move {
                let mut buf = Vec::new();
                let mut chunk = [0u8; 4096];
                while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
                    let n = far.read(&mut chunk).await.unwrap_or(0);
                    if n == 0 {
                        return;
                    }
                    buf.extend_from_slice(&chunk[..n]);
                }
                let chunked = |data: &str| format!("{:x}\r\n{data}\r\n", data.len());
                let mut first = String::from(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n",
                );
                first.push_str(&chunked(": hello\n\nevent: tick\ndata: origin o"));
                first.push_str(&chunked("ne\n\nid: 7\r\ndata: origin two\r\n\r\n"));
                far.write_all(first.as_bytes()).await.unwrap();
                release.notified().await;
                let rest = format!("{}0\r\n\r\n", chunked("data: origin three\n\n"));
                far.write_all(rest.as_bytes()).await.unwrap();
                // Hold the connection until the engine lets go.
                let _ = far.read(&mut chunk).await;
            });
            Ok(Box::new(near) as BoxStream)
        })
    }
}

/// Reads from `stream` until what came holds `needle`.
async fn read_until(stream: &mut (impl AsyncReadExt + Unpin), seen: &mut Vec<u8>, needle: &[u8]) {
    let mut chunk = [0u8; 4096];
    while !seen.windows(needle.len()).any(|w| w == needle) {
        let n = tokio::time::timeout(Duration::from_secs(10), stream.read(&mut chunk))
            .await
            .expect("read in time")
            .unwrap();
        assert!(n > 0, "closed before {:?}", String::from_utf8_lossy(needle));
        seen.extend_from_slice(&chunk[..n]);
    }
}

/// Polls `capture_requests` by `since_rev` until `done` accepts a row.
async fn wait_for_row(
    dispatcher: &Dispatcher,
    done: impl Fn(&serde_json::Value) -> bool,
) -> serde_json::Value {
    let mut rows = serde_json::Value::Null;
    for _ in 0..200 {
        rows = control_json(dispatcher, r#"{"cmd":"capture_requests","since_rev":0}"#);
        if let Some(row) = rows["requests"]
            .as_array()
            .and_then(|rows| rows.iter().find(|row| done(row)))
        {
            return row.clone();
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("no matching row: {rows}");
}

#[tokio::test]
async fn event_streams_relay_live_and_capture_their_events() {
    let device_root = root("NetworkCore Test Device Root");
    let mut config = mitm_config(&device_root);
    // A body rule matches the stream, but a stream is not held to rewrite.
    config.plugins.push(
        "#!name = Body\n[Body Rewrite]\nhttp-response ^http://plain\\.example\\.test/ origin edited\n"
            .to_string(),
    );
    let engine = Arc::new(MitmEngine::new(&config).unwrap());
    let release = Arc::new(tokio::sync::Notify::new());
    let dispatcher = Arc::new(Dispatcher::single(Arc::new(EventOrigin {
        release: release.clone(),
    })));
    control_json(&dispatcher, r#"{"cmd":"set_capture","enabled":true}"#);

    let target: SocketAddr = "192.0.2.22:80".parse().unwrap();
    let first = b"GET /events HTTP/1.1\r\nHost: plain.example.test\r\n\r\n".to_vec();
    let host = engine.claim(&first, target).unwrap();
    let (mut app, tunnel_side) = tokio::io::duplex(64 * 1024);
    let flow = InterceptedFlow {
        inbound: Box::new(tunnel_side),
        first,
        host,
        target,
    };
    let server = tokio::spawn({
        let engine = engine.clone();
        let dispatcher = dispatcher.clone();
        async move {
            let _ = engine
                .serve_flow(
                    flow,
                    dispatcher.as_ref(),
                    Duration::from_secs(5),
                    Duration::from_secs(5),
                )
                .await;
        }
    });

    // The first events reach the app while the stream is still open.
    let mut seen = Vec::new();
    read_until(&mut app, &mut seen, b"origin two\r\n\r\n").await;
    let text = String::from_utf8_lossy(&seen).into_owned();
    assert!(text.contains("text/event-stream"), "{text}");
    assert!(!text.contains("edited"), "not rewritten: {text}");

    let row = wait_for_row(&dispatcher, |row| row["message_count"] == 2).await;
    assert_eq!(row["state"], "in_progress", "{row}");
    assert_eq!(row["seq"], 0);
    assert_eq!(row["status"], 200);
    assert_eq!(row["note"], "streaming");
    assert_eq!(row["rules_skipped"], true);
    let (id, index) = (row["connection_id"].clone(), row["index"].clone());

    let detail = control_json(
        &dispatcher,
        &format!(r#"{{"cmd":"capture_exchange","id":{id},"index":{index},"since_message":1}}"#),
    );
    let exchange = &detail["exchange"];
    assert_eq!(exchange["messages"]["seen"], 2, "{detail}");
    let kept = exchange["messages"]["kept"].as_array().unwrap();
    assert_eq!(kept.len(), 1);
    assert_eq!(kept[0]["index"], 1);
    assert_eq!(kept[0]["kind"], "sse");
    assert_eq!(kept[0]["id"], "7");
    assert_eq!(kept[0]["text"], "origin two");
    let all = control_json(
        &dispatcher,
        &format!(r#"{{"cmd":"capture_exchange","id":{id},"index":{index}}}"#),
    );
    let first_event = &all["exchange"]["messages"]["kept"][0];
    assert_eq!(first_event["label"], "tick", "{all}");
    assert_eq!(first_event["text"], "origin one");

    release.notify_one();
    read_until(&mut app, &mut seen, b"0\r\n\r\n").await;
    let row = wait_for_row(&dispatcher, |row| row["state"] == "done").await;
    assert_eq!(row["message_count"], 3, "{row}");
    assert!(row["seq"].as_u64().unwrap() > 0);
    // Listed once by `since_seq`, finished.
    let rows = control_json(&dispatcher, r#"{"cmd":"capture_requests"}"#);
    assert_eq!(rows["requests"].as_array().unwrap().len(), 1, "{rows}");
    assert_eq!(rows["requests"][0]["state"], "done");
    server.abort();
}

/// A plain HTTP origin that accepts a WebSocket upgrade with
/// `permessage-deflate`, reads one message and answers a compressed "Hello"
/// (RFC 7692 §7.2.3.1) and a close.
struct WebSocketOrigin;

impl TcpOutbound for WebSocketOrigin {
    fn protocol(&self) -> &'static str {
        "test-websocket-origin"
    }

    fn connect<'a>(&'a self, _target: &'a TargetAddr) -> BoxFuture<'a, io::Result<BoxStream>> {
        Box::pin(async move {
            let (near, mut far) = tokio::io::duplex(64 * 1024);
            tokio::spawn(async move {
                let mut seen = Vec::new();
                read_until(&mut far, &mut seen, b"\r\n\r\n").await;
                far.write_all(
                    b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
                      Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\
                      Sec-WebSocket-Extensions: permessage-deflate\r\n\r\n",
                )
                .await
                .unwrap();
                let mut frame = [0u8; 11];
                far.read_exact(&mut frame).await.unwrap();
                far.write_all(&[
                    0xc1, 0x07, 0xf2, 0x48, 0xcd, 0xc9, 0xc9, 0x07, 0x00, 0x88, 0x02, 0x03, 0xe8,
                ])
                .await
                .unwrap();
                let mut rest = [0u8; 64];
                while far.read(&mut rest).await.unwrap_or(0) > 0 {}
            });
            Ok(Box::new(near) as BoxStream)
        })
    }
}

#[tokio::test]
async fn websocket_messages_are_captured_as_they_pass_unchanged() {
    let device_root = root("NetworkCore Test Device Root");
    let engine = Arc::new(MitmEngine::new(&mitm_config(&device_root)).unwrap());
    let dispatcher = Arc::new(Dispatcher::single(Arc::new(WebSocketOrigin)));
    control_json(&dispatcher, r#"{"cmd":"set_capture","enabled":true}"#);

    let target: SocketAddr = "192.0.2.23:80".parse().unwrap();
    let first = b"GET /chat HTTP/1.1\r\nHost: plain.example.test\r\nUpgrade: websocket\r\n\
        Connection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
        Sec-WebSocket-Version: 13\r\nSec-WebSocket-Extensions: permessage-deflate\r\n\r\n"
        .to_vec();
    let host = engine.claim(&first, target).unwrap();
    let (mut app, tunnel_side) = tokio::io::duplex(64 * 1024);
    let flow = InterceptedFlow {
        inbound: Box::new(tunnel_side),
        first,
        host,
        target,
    };
    let server = tokio::spawn({
        let engine = engine.clone();
        let dispatcher = dispatcher.clone();
        async move {
            let _ = engine
                .serve_flow(
                    flow,
                    dispatcher.as_ref(),
                    Duration::from_secs(5),
                    Duration::from_secs(5),
                )
                .await;
        }
    });

    let mut seen = Vec::new();
    read_until(&mut app, &mut seen, b"\r\n\r\n").await;
    assert!(
        seen.starts_with(b"HTTP/1.1 101"),
        "{:?}",
        String::from_utf8_lossy(&seen)
    );
    // RFC 6455 §5.7: a masked "Hello" from the app.
    app.write_all(&[
        0x81, 0x85, 0x37, 0xfa, 0x21, 0x3d, 0x7f, 0x9f, 0x4d, 0x51, 0x58,
    ])
    .await
    .unwrap();
    // The origin's frames reach the app as they were sent.
    let head_end = seen.len();
    read_until(&mut app, &mut seen, &[0x88, 0x02, 0x03, 0xe8]).await;
    assert_eq!(
        &seen[head_end..],
        &[0xc1, 0x07, 0xf2, 0x48, 0xcd, 0xc9, 0xc9, 0x07, 0x00, 0x88, 0x02, 0x03, 0xe8]
    );

    let row = wait_for_row(&dispatcher, |row| row["message_count"] == 3).await;
    assert_eq!(row["status"], 101, "{row}");
    assert_eq!(row["note"], "streaming");
    assert_eq!(row["state"], "in_progress");
    let (id, index) = (row["connection_id"].clone(), row["index"].clone());
    let detail = control_json(
        &dispatcher,
        &format!(r#"{{"cmd":"capture_exchange","id":{id},"index":{index}}}"#),
    );
    let kept = detail["exchange"]["messages"]["kept"]
        .as_array()
        .unwrap()
        .clone();
    assert_eq!(kept.len(), 3, "{detail}");
    assert_eq!(kept[0]["dir"], "up");
    assert_eq!(kept[0]["kind"], "text");
    assert_eq!(kept[0]["text"], "Hello");
    assert_eq!(kept[1]["dir"], "down");
    assert_eq!(kept[1]["text"], "Hello", "inflated for the view");
    assert_eq!(kept[2]["kind"], "close");
    assert_eq!(kept[2]["code"], 1000);

    // Closing the app ends the relay and the exchange.
    drop(app);
    let row = wait_for_row(&dispatcher, |row| row["state"] == "done").await;
    assert_eq!(row["message_count"], 3, "{row}");
    server.abort();
}

/// Counts the connections opened through an outbound.
struct Counting {
    inner: Arc<dyn TcpOutbound>,
    opened: Arc<std::sync::atomic::AtomicUsize>,
}

impl TcpOutbound for Counting {
    fn protocol(&self) -> &'static str {
        "test-counting"
    }

    fn connect<'a>(&'a self, target: &'a TargetAddr) -> BoxFuture<'a, io::Result<BoxStream>> {
        self.opened
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        self.inner.connect(target)
    }
}

/// Two nodes that answer with their own name, and rules that send some
/// requests of one decrypted connection to the other node or reject them.
fn request_routed(rules: &[&str]) -> (Arc<Dispatcher>, [Arc<std::sync::atomic::AtomicUsize>; 2]) {
    use config_core::routing::RoutingSpec;
    use engine_embedded::routing::RoutedOutbound;

    let counters = [Arc::default(), Arc::default()];
    let node = |name: &'static str, opened: &Arc<std::sync::atomic::AtomicUsize>| {
        let (requests, _) = mpsc::unbounded_channel();
        Arc::new(Counting {
            inner: Arc::new(PlainOrigin {
                requests,
                body: name.as_bytes().to_vec(),
                extra_headers: "",
            }),
            opened: opened.clone(),
        }) as Arc<dyn TcpOutbound>
    };
    let nodes = std::collections::BTreeMap::from([
        ("node-a".to_string(), node("node-a", &counters[0])),
        ("node-b".to_string(), node("node-b", &counters[1])),
    ]);
    let spec = RoutingSpec {
        rules: rules.iter().map(|rule| rule.to_string()).collect(),
        groups: Vec::new(),
    };
    let direct = node("direct", &Arc::default());
    let routed = RoutedOutbound::new(&spec, direct, nodes).unwrap();
    (Arc::new(Dispatcher::routed(Arc::new(routed))), counters)
}

async fn get(app: &mut tokio::io::DuplexStream, path: &str, agent: &str) -> (String, String) {
    let request =
        format!("GET {path} HTTP/1.1\r\nHost: plain.example.test\r\nUser-Agent: {agent}\r\n\r\n");
    app.write_all(request.as_bytes()).await.unwrap();
    tokio::time::timeout(Duration::from_secs(10), read_response(app))
        .await
        .expect("answered in time")
}

#[tokio::test]
async fn each_decrypted_http1_request_is_routed_on_its_own() {
    let device_root = root("NetworkCore Test Device Root");
    let engine = Arc::new(MitmEngine::new(&mitm_config(&device_root)).unwrap());
    let (dispatcher, [a, b]) = request_routed(&[
        r"URL-REGEX,^http://plain\.example\.test/video/,node-b",
        "USER-AGENT,Special*,node-b",
        r#"AND,((URL-REGEX,"^http://plain\.example\.test/ads/"),(DST-PORT,80)),REJECT"#,
        "FINAL,node-a",
    ]);
    let target: SocketAddr = "192.0.2.20:80".parse().unwrap();
    let first =
        b"GET /index.html HTTP/1.1\r\nHost: plain.example.test\r\nUser-Agent: App\r\n\r\n".to_vec();
    let (mut app, tunnel_side) = tokio::io::duplex(64 * 1024);
    let server = tokio::spawn({
        let engine = engine.clone();
        let dispatcher = dispatcher.clone();
        async move {
            let http = engine_outbound::sniff::http_request_head(&first);
            let outbound = dispatcher.with_request("plain.example.test", http.as_ref());
            let flow = InterceptedFlow {
                inbound: Box::new(tunnel_side),
                first,
                host: "plain.example.test".to_string(),
                target,
            };
            let _ = engine
                .serve_flow(
                    flow,
                    &outbound,
                    Duration::from_secs(5),
                    Duration::from_secs(5),
                )
                .await;
        }
    });

    // The first request was sent with the flow.
    let (head, body) = tokio::time::timeout(Duration::from_secs(10), read_response(&mut app))
        .await
        .unwrap();
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    assert_eq!(body, "node-a");
    // URL-REGEX and USER-AGENT see every request, not only the first.
    assert_eq!(get(&mut app, "/video/1.ts", "App").await.1, "node-b");
    assert_eq!(get(&mut app, "/video/2.ts", "App").await.1, "node-b");
    assert_eq!(get(&mut app, "/feed", "SpecialPlayer/2").await.1, "node-b");
    assert_eq!(get(&mut app, "/feed", "App").await.1, "node-a");
    // REJECT answers here and keeps the connection.
    let (head, _) = get(&mut app, "/ads/banner.js", "App").await;
    assert!(head.starts_with("HTTP/1.1 403"), "{head}");
    assert_eq!(get(&mut app, "/index.html", "App").await.1, "node-a");
    // One origin connection per switch, none for repeats on the same node.
    let opened = |count: &Arc<std::sync::atomic::AtomicUsize>| {
        count.load(std::sync::atomic::Ordering::SeqCst)
    };
    assert_eq!(opened(&a), 2);
    assert_eq!(opened(&b), 1);
    // Each origin connection is listed with the rule of the request that
    // opened it: the USER-AGENT request reused the node-b connection the
    // URL-REGEX request opened, so it opened none.
    let list = control_json(&dispatcher, r#"{"cmd":"connections"}"#);
    let mut rules: Vec<String> = list["active"]
        .as_array()
        .into_iter()
        .chain(list["closed"].as_array())
        .flatten()
        .map(|connection| connection["rule"].as_str().unwrap_or_default().to_string())
        .collect();
    rules.sort();
    assert_eq!(
        rules,
        [
            "FINAL",
            "FINAL",
            r"URL-REGEX,^http://plain\.example\.test/video/",
        ],
        "{rules:?}"
    );
    server.abort();
}

#[tokio::test]
async fn rules_that_ignore_requests_keep_one_origin_connection() {
    let device_root = root("NetworkCore Test Device Root");
    let engine = Arc::new(MitmEngine::new(&mitm_config(&device_root)).unwrap());
    let (dispatcher, [a, b]) =
        request_routed(&["DOMAIN-SUFFIX,video.example.test,node-b", "FINAL,node-a"]);
    let target: SocketAddr = "192.0.2.20:80".parse().unwrap();
    let first = b"GET / HTTP/1.1\r\nHost: plain.example.test\r\n\r\n".to_vec();
    let (mut app, tunnel_side) = tokio::io::duplex(64 * 1024);
    let server = tokio::spawn({
        let engine = engine.clone();
        let dispatcher = dispatcher.clone();
        async move {
            let outbound = dispatcher.with_host("plain.example.test");
            let flow = InterceptedFlow {
                inbound: Box::new(tunnel_side),
                first,
                host: "plain.example.test".to_string(),
                target,
            };
            let _ = engine
                .serve_flow(
                    flow,
                    &outbound,
                    Duration::from_secs(5),
                    Duration::from_secs(5),
                )
                .await;
        }
    });
    let (_, body) = tokio::time::timeout(Duration::from_secs(10), read_response(&mut app))
        .await
        .unwrap();
    assert_eq!(body, "node-a");
    for _ in 0..3 {
        assert_eq!(get(&mut app, "/video/1.ts", "App").await.1, "node-a");
    }
    assert_eq!(a.load(std::sync::atomic::Ordering::SeqCst), 1);
    assert_eq!(b.load(std::sync::atomic::Ordering::SeqCst), 0);
    server.abort();
}

/// Runs one TLS connection from an app with `app_config` through the engine
/// to `origin`, and returns whether the app's handshake completed.
async fn one_connection(
    engine: &Arc<MitmEngine>,
    origin: &Arc<Origin>,
    app_config: ClientConfig,
) -> bool {
    let target: SocketAddr = "192.0.2.10:443".parse().unwrap();
    let (app, mut tunnel_side) = tokio::io::duplex(64 * 1024);
    let client = tokio::spawn(async move {
        let connector = tokio_rustls::TlsConnector::from(Arc::new(app_config));
        // Held open like a real app's, so the engine finishes its side.
        connector
            .connect(ServerName::try_from(HOST).unwrap(), app)
            .await
            .ok()
    });
    let mut first = vec![0u8; 4096];
    let n = tunnel_side.read(&mut first).await.unwrap();
    first.truncate(n);
    let host = engine
        .claim(&first, target)
        .expect("the listed host is intercepted");
    let flow = InterceptedFlow {
        inbound: Box::new(tunnel_side),
        first,
        host,
        target,
    };
    let server = tokio::spawn({
        let engine = engine.clone();
        let origin = origin.clone();
        async move {
            let _ = engine
                .serve_flow(
                    flow,
                    origin.as_ref(),
                    Duration::from_secs(5),
                    Duration::from_secs(5),
                )
                .await;
        }
    });
    let stream = tokio::time::timeout(Duration::from_secs(10), client)
        .await
        .expect("client finished")
        .unwrap();
    // The engine records the outcome as its side of the handshake ends.
    let _ = tokio::time::timeout(Duration::from_secs(2), server).await;
    stream.is_some()
}

#[tokio::test]
async fn mitm_hosts_marks_apps_that_refuse_the_device_root() {
    let device_root = root("NetworkCore Test Device Root");
    let origin_root = root("NetworkCore Test Origin Root");
    let engine = Arc::new(
        MitmEngine::new(&mitm_config(&device_root))
            .unwrap()
            .with_upstream_config(trusting(&origin_root.certificate, &[b"http/1.1"])),
    );
    let (requests_tx, _requests) = mpsc::unbounded_channel();
    let origin = Arc::new(Origin::new(&origin_root, requests_tx));

    let empty = engine.mitm_hosts(false).expect("the engine decrypts");
    assert_eq!(empty, serde_json::json!({ "enabled": true, "hosts": [] }));

    // An app that trusts only the origin's own root, as a pinning app does,
    // refuses the leaf the engine issues.
    let pinned = trusting(&origin_root.certificate, &[b"http/1.1"]);
    assert!(!one_connection(&engine, &origin, pinned).await);
    let hosts = engine.mitm_hosts(false).unwrap();
    let entry = &hosts["hosts"][0];
    assert_eq!(entry["host"], HOST, "{hosts}");
    assert_eq!(entry["decrypted"], 0);
    assert_eq!(entry["failed"], 1);
    assert_eq!(
        entry["last_failure"], "client_rejected_certificate",
        "{hosts}"
    );
    assert!(entry["last_failure_at_ms"].as_u64().unwrap() > 0);

    // An app that trusts the device root is decrypted.
    let trusting_app = trusting(&device_root.certificate, &[b"http/1.1"]);
    assert!(one_connection(&engine, &origin, trusting_app).await);
    let hosts = engine.mitm_hosts(false).unwrap();
    let entry = &hosts["hosts"][0];
    assert_eq!(entry["decrypted"], 1, "{hosts}");
    assert_eq!(entry["failed"], 1);
    assert_eq!(entry["failures"]["client_rejected_certificate"], 1);

    let cleared = engine.mitm_hosts(true).unwrap();
    assert_eq!(cleared["hosts"], serde_json::json!([]));
}

#[test]
fn mitm_hosts_answers_without_decryption() {
    let dispatcher = Dispatcher::single(Arc::new(PlainOrigin {
        requests: mpsc::unbounded_channel().0,
        body: Vec::new(),
        extra_headers: "",
    }));
    assert_eq!(
        control_json(&dispatcher, r#"{"cmd":"mitm_hosts"}"#),
        serde_json::json!({ "enabled": false, "hosts": [] })
    );
    assert_eq!(
        control_json(&dispatcher, r#"{"cmd":"clear_mitm_hosts"}"#),
        serde_json::json!({ "enabled": false, "hosts": [] })
    );
}
