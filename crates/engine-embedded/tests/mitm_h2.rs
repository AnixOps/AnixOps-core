//! HTTPS decryption over HTTP/2: an app and an origin that both speak
//! `h2`, the MITM engine between them, rewrite rules, trailers and capture.
#![cfg(feature = "mitm")]

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use base64::Engine as _;
use bytes::Bytes;
use engine_embedded::config::MitmConfig;
use engine_embedded::connections::Dispatcher;
use engine_embedded::control;
use engine_embedded::mitm::MitmEngine;
use engine_embedded::tunnel::{FlowInterceptor, InterceptedFlow};
use engine_outbound::{BoxFuture, BoxStream, TargetAddr, TcpOutbound};
use http::{HeaderMap, Request, Response, StatusCode};
use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair, KeyUsagePurpose};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use tokio::io::AsyncReadExt;
use tokio::sync::mpsc;

const HOST: &str = "api.example.test";
const POLICY: &str = "[Plugin]\n\
name = NetworkCore HTTP/2 MITM Test\n\
\n\
[URL Rewrite]\n\
^https://api\\.example\\.test/blocked reject\n\
\n\
[MITM]\n\
enable = true\n\
hostname = api.example.test\n";

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

fn mitm_config(device_root: &Root) -> MitmConfig {
    let base64 = base64::engine::general_purpose::STANDARD;
    MitmConfig {
        policy: POLICY.to_string(),
        plugins: Vec::new(),
        ca_certificate: base64.encode(&device_root.certificate),
        // A desktop root is kept as PKCS#8.
        ca_private_key: base64.encode(device_root.key.serialize_der()),
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

/// An HTTP/2 origin for `HOST`: records each request and answers
/// `h2 <path> <request body length>` followed by a `grpc-status` trailer.
struct H2Origin {
    acceptor: tokio_rustls::TlsAcceptor,
    requests: mpsc::UnboundedSender<String>,
}

impl H2Origin {
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
        config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        Self {
            acceptor: tokio_rustls::TlsAcceptor::from(Arc::new(config)),
            requests,
        }
    }
}

impl TcpOutbound for H2Origin {
    fn protocol(&self) -> &'static str {
        "test-h2-origin"
    }

    fn connect<'a>(&'a self, _target: &'a TargetAddr) -> BoxFuture<'a, io::Result<BoxStream>> {
        Box::pin(async move {
            let (near, far) = tokio::io::duplex(256 * 1024);
            let acceptor = self.acceptor.clone();
            let requests = self.requests.clone();
            tokio::spawn(async move {
                let Ok(tls) = acceptor.accept(far).await else {
                    return;
                };
                if tls.get_ref().1.alpn_protocol() != Some(&b"h2"[..]) {
                    return;
                }
                let Ok(mut connection) = h2::server::handshake(tls).await else {
                    return;
                };
                while let Some(Ok((request, mut respond))) = connection.accept().await {
                    let requests = requests.clone();
                    tokio::spawn(async move {
                        let (parts, mut body) = request.into_parts();
                        let data = read_body(&mut body).await;
                        let encoding = parts
                            .headers
                            .get("accept-encoding")
                            .and_then(|value| value.to_str().ok())
                            .unwrap_or("-")
                            .to_string();
                        requests
                            .send(format!(
                                "{} {} {} {encoding}",
                                parts.method,
                                parts.uri,
                                data.len()
                            ))
                            .unwrap();
                        let response = Response::builder()
                            .status(200)
                            .header("content-type", "text/plain")
                            .body(())
                            .unwrap();
                        let mut send = respond.send_response(response, false).unwrap();
                        let text = format!("h2 {} {}", parts.uri.path(), data.len());
                        send.send_data(Bytes::from(text), false).unwrap();
                        let mut trailers = HeaderMap::new();
                        trailers.insert("grpc-status", "0".parse().unwrap());
                        send.send_trailers(trailers).unwrap();
                    });
                }
            });
            Ok(Box::new(near) as BoxStream)
        })
    }
}

async fn read_body(body: &mut h2::RecvStream) -> Vec<u8> {
    let mut data = Vec::new();
    while let Some(chunk) = body.data().await {
        let chunk = chunk.unwrap();
        let _ = body.flow_control().release_capacity(chunk.len());
        data.extend_from_slice(&chunk);
    }
    data
}

struct Answer {
    status: StatusCode,
    body: String,
    trailers: Option<HeaderMap>,
}

async fn send(
    client: &h2::client::SendRequest<Bytes>,
    method: &str,
    url: &str,
    body: &[u8],
) -> Answer {
    let mut client = client.clone().ready().await.unwrap();
    let request = Request::builder().method(method).uri(url).body(()).unwrap();
    let (response, mut stream) = client.send_request(request, body.is_empty()).unwrap();
    if !body.is_empty() {
        stream
            .send_data(Bytes::copy_from_slice(body), true)
            .unwrap();
    }
    let (parts, mut received) = response.await.unwrap().into_parts();
    let data = read_body(&mut received).await;
    let trailers = received.trailers().await.unwrap();
    Answer {
        status: parts.status,
        body: String::from_utf8(data).unwrap(),
        trailers,
    }
}

fn control_json(dispatcher: &Dispatcher, request: &str) -> serde_json::Value {
    serde_json::from_slice(&control::handle(dispatcher, request.as_bytes()).unwrap()).unwrap()
}

#[tokio::test]
async fn relays_http2_streams_through_rules_and_capture() {
    let device_root = root("NetworkCore Test Device Root");
    let origin_root = root("NetworkCore Test Origin Root");
    let engine = Arc::new(
        MitmEngine::new(&mitm_config(&device_root))
            .unwrap()
            .with_upstream_config(trusting(&origin_root.certificate, &[b"http/1.1"])),
    );
    let (requests_tx, mut requests) = mpsc::unbounded_channel();
    let dispatcher = Arc::new(Dispatcher::single(Arc::new(H2Origin::new(
        &origin_root,
        requests_tx,
    ))));
    control_json(&dispatcher, r#"{"cmd":"set_capture","enabled":true}"#);
    let target: SocketAddr = "192.0.2.30:443".parse().unwrap();

    let (app, tunnel_side) = tokio::io::duplex(256 * 1024);
    let client = tokio::spawn({
        let config = trusting(&device_root.certificate, &[b"h2", b"http/1.1"]);
        async move {
            let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
            let tls = connector
                .connect(ServerName::try_from(HOST).unwrap(), app)
                .await
                .expect("the client trusts the device root");
            assert_eq!(
                tls.get_ref().1.alpn_protocol(),
                Some(&b"h2"[..]),
                "the origin chose h2, so the app gets it"
            );
            let (client, connection) = h2::client::handshake(tls).await.unwrap();
            tokio::spawn(async move {
                let _ = connection.await;
            });

            // Concurrent streams on one connection.
            let (blocked, data, upload, other) = tokio::join!(
                send(
                    &client,
                    "GET",
                    "https://api.example.test/blocked/ad.js",
                    b""
                ),
                send(&client, "GET", "https://api.example.test/data?x=1", b""),
                send(
                    &client,
                    "POST",
                    "https://api.example.test/grpc",
                    &[7u8; 300_000]
                ),
                send(&client, "GET", "https://other.example.test/", b""),
            );
            assert!(blocked.status.is_client_error(), "{}", blocked.status);
            assert_eq!(data.status, StatusCode::OK);
            assert_eq!(data.body, "h2 /data 0");
            let trailers = data.trailers.expect("trailers are relayed");
            assert_eq!(trailers.get("grpc-status").unwrap(), "0");
            assert_eq!(upload.body, "h2 /grpc 300000");
            assert_eq!(other.status, StatusCode::MISDIRECTED_REQUEST);
        }
    });

    let mut tunnel_side = tunnel_side;
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

    tokio::time::timeout(Duration::from_secs(20), client)
        .await
        .expect("client finished")
        .unwrap();

    // The blocked and misdirected requests never reached the origin; the
    // others kept their encoding (no rule reads these bodies).
    let mut seen = vec![
        requests.recv().await.unwrap(),
        requests.recv().await.unwrap(),
    ];
    seen.sort();
    assert_eq!(
        seen[0], "GET https://api.example.test/data?x=1 0 -",
        "{seen:?}"
    );
    assert_eq!(
        seen[1], "POST https://api.example.test/grpc 300000 -",
        "{seen:?}"
    );
    assert!(requests.try_recv().is_err());

    let mut rows = serde_json::Value::Null;
    for _ in 0..100 {
        rows = control_json(
            &dispatcher,
            r#"{"cmd":"capture_requests","filter":"version:h2"}"#,
        );
        if rows["requests"]
            .as_array()
            .is_some_and(|rows| rows.len() >= 3)
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let rows = rows["requests"].as_array().unwrap().clone();
    assert_eq!(rows.len(), 3, "{rows:?}");
    assert!(rows.iter().all(|row| row["http_version"] == "HTTP/2"));
    let upload = rows
        .iter()
        .find(|row| row["method"] == "POST")
        .expect("the upload is captured");
    assert_eq!(upload["request_size"], 300_000);
    assert_eq!(upload["status"], 200);
    let blocked = rows
        .iter()
        .find(|row| row["url"].as_str().unwrap().contains("blocked"))
        .unwrap();
    assert_eq!(blocked["note"], "answered_locally");

    let har = control_json(&dispatcher, r#"{"cmd":"export_capture","format":"har"}"#);
    let har: serde_json::Value = serde_json::from_slice(
        &base64::engine::general_purpose::STANDARD
            .decode(har["data_base64"].as_str().unwrap())
            .unwrap(),
    )
    .unwrap();
    assert_eq!(har["log"]["entries"][0]["request"]["httpVersion"], "HTTP/2");
    server.abort();
}

#[tokio::test]
async fn apps_offering_only_http1_stay_on_http1() {
    let device_root = root("NetworkCore Test Device Root");
    let origin_root = root("NetworkCore Test Origin Root");
    let engine = Arc::new(
        MitmEngine::new(&mitm_config(&device_root))
            .unwrap()
            .with_upstream_config(trusting(&origin_root.certificate, &[b"http/1.1"])),
    );
    let (requests_tx, _requests) = mpsc::unbounded_channel();
    let origin = Arc::new(H2Origin::new(&origin_root, requests_tx));
    let target: SocketAddr = "192.0.2.31:443".parse().unwrap();
    let (app, mut tunnel_side) = tokio::io::duplex(64 * 1024);
    let client = tokio::spawn({
        let config = trusting(&device_root.certificate, &[b"http/1.1"]);
        async move {
            let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
            let tls = connector
                .connect(ServerName::try_from(HOST).unwrap(), app)
                .await
                .unwrap();
            assert_eq!(tls.get_ref().1.alpn_protocol(), Some(&b"http/1.1"[..]));
        }
    });
    let mut first = vec![0u8; 4096];
    let n = tunnel_side.read(&mut first).await.unwrap();
    first.truncate(n);
    let host = engine.claim(&first, target).unwrap();
    let flow = InterceptedFlow {
        inbound: Box::new(tunnel_side),
        first,
        host,
        target,
    };
    // The app offers only http/1.1, so the engine offers the origin only
    // http/1.1 and the app gets http/1.1 too.
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
    tokio::time::timeout(Duration::from_secs(10), client)
        .await
        .expect("handshake finished")
        .unwrap();
    server.abort();
}
