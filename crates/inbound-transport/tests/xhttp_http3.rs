//! XHTTP under TLS with ALPN `h3`: the engine's XHTTP client over HTTP/3
//! against the QUIC side of a toy inbound, and over HTTP/2 against its TCP
//! side on the same port number; and over HTTP/3 through a `via` that
//! relays its datagrams.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use engine_inbound::server::{serve, InboundStats, ServeSettings};
use engine_inbound::{Accepted, Rejected, StreamInbound, UserStore};
use engine_outbound::{
    BoxFuture, BoxStream, Dialer, OutboundDialer, TargetAddr, TcpDialer, TcpOutbound, UdpFlow,
};
use inbound_transport::{wrap_all, TlsServerSettings, TransportSettings};
use rcgen::{CertificateParams, KeyPair};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use transport_tls::{TlsConnector, TlsSettings};
use transport_xhttp::{
    HttpVersion, Mode, Range, Security, XhttpConnector, XhttpSettings, XhttpTarget,
};

const TIMEOUT: Duration = Duration::from_secs(20);
const SERVER_NAME: &str = "node.test";
const LEN: usize = 200_000;

/// Sends every client to `target` without a handshake.
struct Passthrough {
    users: Arc<UserStore>,
    target: SocketAddr,
}

impl StreamInbound for Passthrough {
    fn protocol(&self) -> &'static str {
        "passthrough"
    }

    fn users(&self) -> &Arc<UserStore> {
        &self.users
    }

    fn accept<'a>(
        &'a self,
        stream: BoxStream,
        _peer: SocketAddr,
    ) -> BoxFuture<'a, Result<Accepted, Rejected>> {
        Box::pin(async move {
            Ok(Accepted {
                user: None,
                target: TargetAddr::Ip(self.target),
                stream,
                udp: None,
                mux: false,
            })
        })
    }
}

struct Direct;

impl TcpOutbound for Direct {
    fn protocol(&self) -> &'static str {
        "direct"
    }

    fn connect<'a>(&'a self, target: &'a TargetAddr) -> BoxFuture<'a, std::io::Result<BoxStream>> {
        Box::pin(async move {
            let stream = TcpStream::connect((target.host(), target.port())).await?;
            Ok(Box::new(stream) as BoxStream)
        })
    }
}

async fn echo_server() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let (mut reader, mut writer) = stream.split();
                let _ = tokio::io::copy(&mut reader, &mut writer).await;
            });
        }
    });
    addr
}

async fn inbound(alpn: &[&str]) -> Arc<dyn StreamInbound> {
    let key = KeyPair::generate().unwrap();
    let cert = CertificateParams::new(vec![SERVER_NAME.to_string()])
        .unwrap()
        .self_signed(&key)
        .unwrap();
    let tls = TlsServerSettings {
        certificate: Some(cert.pem()),
        key: Some(key.serialize_pem()),
        alpn: alpn.iter().map(|protocol| protocol.to_string()).collect(),
        ..TlsServerSettings::default()
    };
    let transport = TransportSettings::Xhttp(XhttpSettings {
        path: "/xh".into(),
        ..XhttpSettings::default()
    });
    let inner = Arc::new(Passthrough {
        users: Arc::new(UserStore::default()),
        target: echo_server().await,
    });
    wrap_all(inner, Some(&transport), Some(&tls)).unwrap_or_else(|err| panic!("{err}"))
}

fn tls(alpn: &[&str]) -> TlsSettings {
    TlsSettings {
        server_name: SERVER_NAME.into(),
        alpn: alpn.iter().map(|protocol| protocol.to_string()).collect(),
        insecure: true,
        ..TlsSettings::default()
    }
}

/// A `via` without TCP that relays UDP to the loopback inbound whatever
/// target it is asked for, and records the targets.
struct UdpRelay {
    port: u16,
    asked: std::sync::Mutex<Vec<TargetAddr>>,
}

impl TcpOutbound for UdpRelay {
    fn protocol(&self) -> &'static str {
        "relay"
    }

    fn connect<'a>(&'a self, _target: &'a TargetAddr) -> BoxFuture<'a, std::io::Result<BoxStream>> {
        Box::pin(async { Err(std::io::Error::other("the relay carries no tcp")) })
    }

    fn open_udp<'a>(&'a self, target: &'a TargetAddr) -> BoxFuture<'a, std::io::Result<UdpFlow>> {
        self.asked.lock().unwrap().push(target.clone());
        Box::pin(async move { TcpDialer.open_datagram("127.0.0.1", self.port).await })
    }
}

/// The QUIC side of an inbound with ALPN `h3`, on a loopback port.
async fn http3_server() -> u16 {
    let inbound = inbound(&["h3"]).await;
    let (_listener, port, socket) = tcp_and_udp_on_one_loopback_port().await;
    let quic = inbound.packet().expect("alpn h3 gives xhttp a quic side");
    tokio::spawn(quic.serve(
        socket,
        Arc::new(Direct),
        None,
        ServeSettings::default(),
        Arc::new(InboundStats::default()),
    ));
    port
}

fn connector(
    server: &str,
    port: u16,
    mode: Mode,
    security: Security,
    version: HttpVersion,
    dialer: Arc<dyn Dialer>,
) -> XhttpConnector {
    let settings = XhttpSettings {
        path: "/xh".into(),
        mode,
        sc_min_posts_interval_ms: Range::fixed(1),
        ..XhttpSettings::default()
    };
    XhttpConnector::new(
        &settings,
        XhttpTarget {
            server: server.into(),
            port,
            default_host: SERVER_NAME.into(),
            security,
            version,
            dialer,
        },
    )
    .unwrap()
}

async fn round_trip(port: u16, mode: Mode, security: Security, version: HttpVersion) {
    round_trip_through(
        "127.0.0.1",
        port,
        mode,
        security,
        version,
        Arc::new(TcpDialer),
    )
    .await;
}

async fn round_trip_through(
    server: &str,
    port: u16,
    mode: Mode,
    security: Security,
    version: HttpVersion,
    dialer: Arc<dyn Dialer>,
) {
    let connector = connector(server, port, mode, security, version, dialer);
    let stream = tokio::time::timeout(TIMEOUT, connector.connect())
        .await
        .unwrap_or_else(|_| panic!("{mode:?} {version:?} did not connect"))
        .unwrap();
    let (mut reader, mut writer) = tokio::io::split(stream);
    let sent: Vec<u8> = (0..LEN).map(|i| (i % 251) as u8).collect();
    let expected = sent.clone();
    let writing = tokio::spawn(async move {
        for piece in sent.chunks(9_973) {
            writer.write_all(piece).await.unwrap();
            writer.flush().await.unwrap();
        }
        writer
    });
    let mut received = vec![0u8; LEN];
    tokio::time::timeout(TIMEOUT, reader.read_exact(&mut received))
        .await
        .unwrap_or_else(|_| panic!("{mode:?} {version:?} timed out"))
        .unwrap();
    assert!(received == expected, "{mode:?} {version:?}");
    drop(writing.await.unwrap());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn alpn_h3_serves_http3_beside_http2() {
    let inbound = inbound(&["h3"]).await;
    let (listener, port, socket) = tcp_and_udp_on_one_loopback_port().await;
    let quic = inbound.packet().expect("alpn h3 gives xhttp a quic side");
    let stats = Arc::new(InboundStats::default());
    tokio::spawn(quic.serve(
        socket,
        Arc::new(Direct),
        None,
        ServeSettings::default(),
        stats.clone(),
    ));
    tokio::spawn(serve(
        listener,
        inbound,
        Arc::new(Direct),
        ServeSettings::default(),
        stats,
    ));

    for mode in [Mode::PacketUp, Mode::StreamUp, Mode::StreamOne] {
        let security = Security::quic("127.0.0.1", port, &tls(&[])).unwrap();
        round_trip(port, mode, security, HttpVersion::Http3).await;
    }
    // The TCP side offers `h2` and `http/1.1`, as without `h3`.
    let security = Security::Tls(TlsConnector::new(&tls(&["h2"])).unwrap());
    round_trip(port, Mode::StreamUp, security, HttpVersion::Http2).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn http3_runs_through_a_via_that_resolves_the_server() {
    let port = http3_server().await;
    // No resolver knows this name: only the `via` may look it up, and it
    // sends the datagrams to the inbound.
    let server = "xhttp-server.invalid";
    let relay = Arc::new(UdpRelay {
        port,
        asked: std::sync::Mutex::new(Vec::new()),
    });
    for mode in [Mode::PacketUp, Mode::StreamUp, Mode::StreamOne] {
        let security = Security::quic(server, port, &tls(&[])).unwrap();
        let dialer = Arc::new(OutboundDialer(relay.clone()));
        round_trip_through(server, port, mode, security, HttpVersion::Http3, dialer).await;
    }
    let asked = relay.asked.lock().unwrap().clone();
    assert_eq!(asked.len(), 3, "one quic connection per session");
    assert!(asked
        .iter()
        .all(|target| *target == TargetAddr::Domain(server.into(), port)));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn http3_through_a_via_without_udp_fails_instead_of_connecting_directly() {
    // The server answers on loopback, so a direct connection would succeed.
    let port = http3_server().await;
    let security = Security::quic("127.0.0.1", port, &tls(&[])).unwrap();
    // `Direct` here carries TCP only.
    let dialer = Arc::new(OutboundDialer(Arc::new(Direct)));
    let connector = connector(
        "127.0.0.1",
        port,
        Mode::PacketUp,
        security,
        HttpVersion::Http3,
        dialer,
    );
    let error = match tokio::time::timeout(TIMEOUT, connector.connect())
        .await
        .expect("a via without udp fails at once")
    {
        Ok(_) => panic!("http/3 bypassed the via"),
        Err(error) => error,
    };
    assert_eq!(error.kind(), std::io::ErrorKind::Unsupported, "{error}");
}

#[tokio::test]
async fn only_alpn_h3_adds_the_quic_side() {
    assert!(inbound(&[]).await.packet().is_none());
    assert!(inbound(&["h2", "http/1.1"]).await.packet().is_none());
    assert!(inbound(&["h2", "h3"]).await.packet().is_some());
}

/// HTTP/3 shares the HTTP/2 port. A free TCP port can still be refused for
/// UDP (on Windows, a port in an excluded range answers WSAEACCES), and
/// Windows hands out TCP ephemeral ports in sequence, so retrying from the TCP
/// side alone can stay inside one excluded UDP block. Alternate between letting
/// UDP and letting TCP pick the port, then claim the same port for the other.
async fn tcp_and_udp_on_one_loopback_port() -> (TcpListener, u16, std::net::UdpSocket) {
    let mut last_error = None;
    for attempt in 0..32 {
        let candidate = if attempt % 2 == 0 {
            let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
            let port = socket.local_addr().unwrap().port();
            TcpListener::bind(("127.0.0.1", port))
                .await
                .map(|listener| (listener, port, socket))
        } else {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let port = listener.local_addr().unwrap().port();
            std::net::UdpSocket::bind(("127.0.0.1", port)).map(|socket| (listener, port, socket))
        };
        match candidate {
            Ok(found) => return found,
            Err(error) => last_error = Some(error),
        }
    }
    panic!(
        "no loopback port binds both TCP and UDP: {}",
        last_error.expect("a failed attempt records its error")
    )
}
