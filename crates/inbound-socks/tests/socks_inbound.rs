//! The SOCKS5 server inbound against a client written from RFC 1928 and
//! RFC 1929, over loopback.

use std::future::Future;
use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use engine_inbound::registry::InboundFactory;
use engine_inbound::server::{serve, InboundStats, ServeSettings};
use engine_inbound::StreamInbound;
use engine_outbound::{BoxFuture, BoxStream, TargetAddr};
use inbound_socks::SocksInboundFactory;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const TIMEOUT: Duration = Duration::from_secs(10);
const LOGIN: &str = "tmp-7";
const PASSWORD: &str = "0123456789abcdef";

async fn within<F: Future>(future: F) -> F::Output {
    tokio::time::timeout(TIMEOUT, future)
        .await
        .expect("timed out")
}

struct Direct;

impl engine_outbound::TcpOutbound for Direct {
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

/// A loopback address nothing listens on; the socket stays bound until
/// dropped so no other test takes the port.
fn refused_addr() -> (tokio::net::TcpSocket, SocketAddr) {
    let socket = tokio::net::TcpSocket::new_v4().unwrap();
    socket.bind("127.0.0.1:0".parse().unwrap()).unwrap();
    let addr = socket.local_addr().unwrap();
    (socket, addr)
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

struct Server {
    addr: SocketAddr,
    inbound: Arc<dyn StreamInbound>,
    stats: Arc<InboundStats>,
}

async fn start() -> Server {
    let settings = serde_json::json!({
        "users": [{"name": "7", "username": LOGIN, "password": PASSWORD}]
    });
    let settings = settings.as_object().unwrap().clone();
    let inbound = SocksInboundFactory.build(&settings).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let stats = Arc::new(InboundStats::default());
    let serve_settings = ServeSettings {
        handshake_timeout: Duration::from_secs(5),
        connect_timeout: Duration::from_secs(5),
        ..ServeSettings::default()
    };
    tokio::spawn(serve(
        listener,
        inbound.clone(),
        Arc::new(Direct),
        serve_settings,
        stats.clone(),
    ));
    Server {
        addr,
        inbound,
        stats,
    }
}

/// Greets with the password method, authenticates and returns the
/// authentication status.
async fn authenticate(client: &mut TcpStream, login: &str, password: &str) -> u8 {
    client.write_all(&[5, 1, 2]).await.unwrap();
    let mut choice = [0u8; 2];
    client.read_exact(&mut choice).await.unwrap();
    assert_eq!(choice, [5, 2]);
    let mut auth = vec![1, login.len() as u8];
    auth.extend_from_slice(login.as_bytes());
    auth.push(password.len() as u8);
    auth.extend_from_slice(password.as_bytes());
    client.write_all(&auth).await.unwrap();
    let mut status = [0u8; 2];
    client.read_exact(&mut status).await.unwrap();
    assert_eq!(status[0], 1);
    status[1]
}

/// Sends a request with `command` for an IPv4 `target`; returns the reply
/// code.
async fn request(client: &mut TcpStream, command: u8, target: SocketAddr) -> u8 {
    let SocketAddr::V4(target) = target else {
        panic!("IPv4 targets only")
    };
    let mut request = vec![5, command, 0, 1];
    request.extend_from_slice(&target.ip().octets());
    request.extend_from_slice(&target.port().to_be_bytes());
    client.write_all(&request).await.unwrap();
    let mut reply = [0u8; 10];
    client.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply[0], 5);
    reply[1]
}

async fn closed(client: &mut TcpStream) -> bool {
    let mut buf = [0u8; 16];
    matches!(client.read(&mut buf).await, Ok(0) | Err(_))
}

#[tokio::test]
async fn relays_connect_for_an_authenticated_user() {
    within(async {
        let server = start().await;
        let echo = echo_server().await;
        let mut client = TcpStream::connect(server.addr).await.unwrap();
        assert_eq!(authenticate(&mut client, LOGIN, PASSWORD).await, 0);
        assert_eq!(request(&mut client, 1, echo).await, 0);
        client.write_all(b"hello through socks").await.unwrap();
        let mut echoed = [0u8; 19];
        client.read_exact(&mut echoed).await.unwrap();
        assert_eq!(&echoed, b"hello through socks");
        drop(client);
        // Charged as the relay moves the bytes; wait for both directions.
        loop {
            let traffic = server.inbound.users().traffic(false);
            let user = traffic.iter().find(|t| t.name == "7").unwrap();
            if (user.up, user.down) == (19, 19) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await;
}

#[tokio::test]
async fn domain_targets_are_resolved_by_the_outbound() {
    within(async {
        let server = start().await;
        let echo = echo_server().await;
        let mut client = TcpStream::connect(server.addr).await.unwrap();
        assert_eq!(authenticate(&mut client, LOGIN, PASSWORD).await, 0);
        let mut request = vec![5, 1, 0, 3, 9];
        request.extend_from_slice(b"localhost");
        request.extend_from_slice(&echo.port().to_be_bytes());
        client.write_all(&request).await.unwrap();
        let mut reply = [0u8; 10];
        client.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply[1], 0);
        client.write_all(b"ping").await.unwrap();
        let mut echoed = [0u8; 4];
        client.read_exact(&mut echoed).await.unwrap();
        assert_eq!(&echoed, b"ping");
    })
    .await;
}

#[tokio::test]
async fn refuses_clients_without_the_password_method() {
    within(async {
        let server = start().await;
        let mut client = TcpStream::connect(server.addr).await.unwrap();
        client.write_all(&[5, 1, 0]).await.unwrap();
        let mut choice = [0u8; 2];
        client.read_exact(&mut choice).await.unwrap();
        assert_eq!(choice, [5, 0xFF]);
        assert!(closed(&mut client).await);
        assert_eq!(server.stats.handshake_failed.load(Ordering::Relaxed), 1);
    })
    .await;
}

#[tokio::test]
async fn refuses_wrong_credentials() {
    within(async {
        let server = start().await;
        for (login, password) in [(LOGIN, "fedcba9876543210"), ("7", PASSWORD), ("x", "y")] {
            let mut client = TcpStream::connect(server.addr).await.unwrap();
            assert_eq!(authenticate(&mut client, login, password).await, 1);
            assert!(closed(&mut client).await);
        }
        assert_eq!(server.stats.handshake_failed.load(Ordering::Relaxed), 3);
    })
    .await;
}

#[tokio::test]
async fn answers_other_commands_with_not_supported() {
    within(async {
        let server = start().await;
        let echo = echo_server().await;
        for command in [2u8, 3] {
            let mut client = TcpStream::connect(server.addr).await.unwrap();
            assert_eq!(authenticate(&mut client, LOGIN, PASSWORD).await, 0);
            assert_eq!(request(&mut client, command, echo).await, 7);
            assert!(closed(&mut client).await);
        }
    })
    .await;
}

#[tokio::test]
async fn answers_unknown_address_types() {
    within(async {
        let server = start().await;
        let mut client = TcpStream::connect(server.addr).await.unwrap();
        assert_eq!(authenticate(&mut client, LOGIN, PASSWORD).await, 0);
        client.write_all(&[5, 1, 0, 9, 0, 0]).await.unwrap();
        let mut reply = [0u8; 10];
        client.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply[1], 8);
    })
    .await;
}

#[tokio::test]
async fn reports_refused_targets() {
    within(async {
        let server = start().await;
        let (_socket, refused) = refused_addr();
        let mut client = TcpStream::connect(server.addr).await.unwrap();
        assert_eq!(authenticate(&mut client, LOGIN, PASSWORD).await, 0);
        // Linux and Windows refuse a bound port that does not listen
        // (0x05); macOS drops the connection attempt until the outbound's
        // timeout (0x04). The mapping of each error kind is checked by the
        // unit test connect_failures_get_their_reply.
        let reply = request(&mut client, 1, refused).await;
        assert!(reply == 5 || reply == 4, "reply {reply}");
        assert!(closed(&mut client).await);
        assert_eq!(server.stats.connect_failed.load(Ordering::Relaxed), 1);
    })
    .await;
}

#[tokio::test]
async fn removing_the_user_closes_its_connections() {
    within(async {
        let server = start().await;
        let echo = echo_server().await;
        let mut client = TcpStream::connect(server.addr).await.unwrap();
        assert_eq!(authenticate(&mut client, LOGIN, PASSWORD).await, 0);
        assert_eq!(request(&mut client, 1, echo).await, 0);
        client.write_all(b"x").await.unwrap();
        let mut one = [0u8; 1];
        client.read_exact(&mut one).await.unwrap();
        assert!(server.inbound.users().remove("7"));
        assert!(closed(&mut client).await);

        let mut again = TcpStream::connect(server.addr).await.unwrap();
        assert_eq!(authenticate(&mut again, LOGIN, PASSWORD).await, 1);
    })
    .await;
}
