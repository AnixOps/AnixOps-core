//! End-to-end tests: a client speaks SOCKS5 or HTTP to the mixed inbound, which
//! relays through a direct test outbound to a local server.

use std::io;
use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use engine_outbound::reject::{self, RejectAction};
use engine_outbound::{
    BoxFuture, BoxStream, DatagramRecv, DatagramSend, TargetAddr, TcpOutbound, UdpFlow,
};
use inbound_mixed::{
    serve, serve_intercepted, ClientAddrs, ClientConnector, ClientInterceptor, Credentials,
    MixedSettings, MixedStats,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

const WAIT: Duration = Duration::from_secs(10);

struct Direct;

impl TcpOutbound for Direct {
    fn protocol(&self) -> &'static str {
        "test-direct"
    }

    fn connect<'a>(&'a self, target: &'a TargetAddr) -> BoxFuture<'a, io::Result<BoxStream>> {
        Box::pin(async move {
            let stream = TcpStream::connect((target.host().as_str(), target.port())).await?;
            Ok(Box::new(stream) as BoxStream)
        })
    }

    fn open_udp<'a>(&'a self, target: &'a TargetAddr) -> BoxFuture<'a, io::Result<UdpFlow>> {
        Box::pin(async move {
            let addr = tokio::net::lookup_host((target.host().as_str(), target.port()))
                .await?
                .find(SocketAddr::is_ipv4)
                .ok_or_else(|| io::Error::other("no ipv4 address"))?;
            let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await?);
            socket.connect(addr).await?;
            Ok(UdpFlow::new(
                Box::new(UdpSend(socket.clone())),
                Box::new(UdpRecv(socket)),
            ))
        })
    }
}

struct UdpSend(Arc<UdpSocket>);

impl DatagramSend for UdpSend {
    fn send<'a>(&'a mut self, payload: &'a [u8]) -> BoxFuture<'a, io::Result<()>> {
        Box::pin(async move { self.0.send(payload).await.map(|_| ()) })
    }
}

struct UdpRecv(Arc<UdpSocket>);

impl DatagramRecv for UdpRecv {
    fn recv(&mut self) -> BoxFuture<'_, io::Result<Vec<u8>>> {
        Box::pin(async move {
            let mut buf = vec![0u8; 65_535];
            let n = self.0.recv(&mut buf).await?;
            buf.truncate(n);
            Ok(buf)
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

/// An unused port: bound once, then released.
async fn closed_port() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    listener.local_addr().unwrap()
}

async fn proxy(credentials: Option<Credentials>) -> (SocketAddr, Arc<MixedStats>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let stats = Arc::new(MixedStats::default());
    let settings = MixedSettings {
        credentials,
        ..MixedSettings::default()
    };
    tokio::spawn(serve(listener, Arc::new(Direct), settings, stats.clone()));
    (addr, stats)
}

fn credentials() -> Credentials {
    Credentials {
        username: "user".into(),
        password: "pa:ss".into(),
    }
}

async fn read_n(stream: &mut TcpStream, n: usize) -> Vec<u8> {
    let mut buf = vec![0u8; n];
    tokio::time::timeout(WAIT, stream.read_exact(&mut buf))
        .await
        .expect("read timed out")
        .unwrap();
    buf
}

async fn read_to_end(stream: &mut TcpStream) -> String {
    let mut buf = Vec::new();
    tokio::time::timeout(WAIT, stream.read_to_end(&mut buf))
        .await
        .expect("read timed out")
        .unwrap();
    String::from_utf8(buf).unwrap()
}

fn socks_connect_ipv4(target: SocketAddr) -> Vec<u8> {
    let SocketAddr::V4(v4) = target else {
        panic!("ipv4 target expected");
    };
    let mut request = vec![0x05, 0x01, 0x00, 0x01];
    request.extend_from_slice(&v4.ip().octets());
    request.extend_from_slice(&v4.port().to_be_bytes());
    request
}

async fn assert_echo(stream: &mut TcpStream) {
    stream.write_all(b"ping through proxy").await.unwrap();
    assert_eq!(read_n(stream, 18).await, b"ping through proxy");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn socks5_connect_relays_bytes() {
    let echo = echo_server().await;
    let (proxy, stats) = proxy(None).await;
    let mut client = TcpStream::connect(proxy).await.unwrap();
    client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
    assert_eq!(read_n(&mut client, 2).await, [0x05, 0x00]);
    client.write_all(&socks_connect_ipv4(echo)).await.unwrap();
    assert_eq!(read_n(&mut client, 10).await[..2], [0x05, 0x00]);
    assert_echo(&mut client).await;
    assert_eq!(stats.accepted.load(Ordering::Relaxed), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn socks5_domain_targets_are_passed_to_the_outbound() {
    let echo = echo_server().await;
    let (proxy, _) = proxy(None).await;
    let mut client = TcpStream::connect(proxy).await.unwrap();
    client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
    read_n(&mut client, 2).await;
    let host = b"127.0.0.1";
    let mut request = vec![0x05, 0x01, 0x00, 0x03, host.len() as u8];
    request.extend_from_slice(host);
    request.extend_from_slice(&echo.port().to_be_bytes());
    client.write_all(&request).await.unwrap();
    assert_eq!(read_n(&mut client, 10).await[1], 0x00);
    assert_echo(&mut client).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn socks5_password_auth_is_enforced() {
    let echo = echo_server().await;
    let (proxy, _) = proxy(Some(credentials())).await;

    // No-auth only: refused.
    let mut client = TcpStream::connect(proxy).await.unwrap();
    client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
    assert_eq!(read_n(&mut client, 2).await, [0x05, 0xFF]);

    // Wrong password.
    let mut client = TcpStream::connect(proxy).await.unwrap();
    client.write_all(&[0x05, 0x01, 0x02]).await.unwrap();
    assert_eq!(read_n(&mut client, 2).await, [0x05, 0x02]);
    client
        .write_all(&[0x01, 4, b'u', b's', b'e', b'r', 3, b'b', b'a', b'd'])
        .await
        .unwrap();
    assert_eq!(read_n(&mut client, 2).await, [0x01, 0x01]);

    // Right password.
    let mut client = TcpStream::connect(proxy).await.unwrap();
    client.write_all(&[0x05, 0x02, 0x00, 0x02]).await.unwrap();
    assert_eq!(read_n(&mut client, 2).await, [0x05, 0x02]);
    let mut auth = vec![0x01, 4];
    auth.extend_from_slice(b"user");
    auth.push(5);
    auth.extend_from_slice(b"pa:ss");
    client.write_all(&auth).await.unwrap();
    assert_eq!(read_n(&mut client, 2).await, [0x01, 0x00]);
    client.write_all(&socks_connect_ipv4(echo)).await.unwrap();
    assert_eq!(read_n(&mut client, 10).await[1], 0x00);
    assert_echo(&mut client).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn socks5_udp_associate_is_not_supported() {
    let (proxy, _) = proxy(None).await;
    let mut client = TcpStream::connect(proxy).await.unwrap();
    client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
    read_n(&mut client, 2).await;
    client
        .write_all(&[0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        .await
        .unwrap();
    assert_eq!(read_n(&mut client, 10).await[1], 0x07);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn socks5_connect_failure_is_reported() {
    let target = closed_port().await;
    let (proxy, stats) = proxy(None).await;
    let mut client = TcpStream::connect(proxy).await.unwrap();
    client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
    read_n(&mut client, 2).await;
    client.write_all(&socks_connect_ipv4(target)).await.unwrap();
    assert_eq!(read_n(&mut client, 10).await[1], 0x01);
    assert_eq!(stats.connect_failed.load(Ordering::Relaxed), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn http_connect_tunnels_bytes_including_early_data() {
    let echo = echo_server().await;
    let (proxy, _) = proxy(None).await;
    let mut client = TcpStream::connect(proxy).await.unwrap();
    // The first tunnel bytes arrive in the same write as the request head.
    let request = format!("CONNECT {echo} HTTP/1.1\r\nHost: {echo}\r\n\r\nearly");
    client.write_all(request.as_bytes()).await.unwrap();
    let established = b"HTTP/1.1 200 Connection established\r\n\r\n";
    assert_eq!(read_n(&mut client, established.len()).await, established);
    assert_eq!(read_n(&mut client, 5).await, b"early");
    assert_echo(&mut client).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn http_proxy_auth_is_enforced() {
    let echo = echo_server().await;
    let (proxy, _) = proxy(Some(credentials())).await;

    let mut client = TcpStream::connect(proxy).await.unwrap();
    let request = format!("CONNECT {echo} HTTP/1.1\r\n\r\n");
    client.write_all(request.as_bytes()).await.unwrap();
    assert!(read_to_end(&mut client)
        .await
        .starts_with("HTTP/1.1 407 Proxy Authentication Required\r\n"));

    let mut client = TcpStream::connect(proxy).await.unwrap();
    // base64("user:pa:ss")
    let request =
        format!("CONNECT {echo} HTTP/1.1\r\nProxy-Authorization: Basic dXNlcjpwYTpzcw==\r\n\r\n");
    client.write_all(request.as_bytes()).await.unwrap();
    let established = b"HTTP/1.1 200 Connection established\r\n\r\n";
    assert_eq!(read_n(&mut client, established.len()).await, established);
    assert_echo(&mut client).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn plain_http_is_forwarded_in_origin_form() {
    let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin_addr = origin.local_addr().unwrap();
    let seen = tokio::spawn(async move {
        let (mut stream, _) = origin.accept().await.unwrap();
        let mut head = Vec::new();
        let mut byte = [0u8; 1];
        while !head.ends_with(b"\r\n\r\n") {
            stream.read_exact(&mut byte).await.unwrap();
            head.push(byte[0]);
        }
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
            .await
            .unwrap();
        String::from_utf8(head).unwrap()
    });

    let (proxy, _) = proxy(None).await;
    let mut client = TcpStream::connect(proxy).await.unwrap();
    let request = format!(
        "GET http://{origin_addr}/path?q=1 HTTP/1.1\r\nHost: {origin_addr}\r\nProxy-Connection: keep-alive\r\nUser-Agent: test\r\n\r\n"
    );
    client.write_all(request.as_bytes()).await.unwrap();
    let response = read_to_end(&mut client).await;
    assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(response.ends_with("ok"));

    let head = seen.await.unwrap();
    assert_eq!(
        head,
        format!(
            "GET /path?q=1 HTTP/1.1\r\nHost: {origin_addr}\r\nUser-Agent: test\r\nConnection: close\r\n\r\n"
        )
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn malformed_http_gets_400_and_connect_failure_gets_502() {
    let (proxy, _) = proxy(None).await;
    let mut client = TcpStream::connect(proxy).await.unwrap();
    client
        .write_all(b"GET /relative HTTP/1.1\r\n\r\n")
        .await
        .unwrap();
    assert!(read_to_end(&mut client).await.starts_with("HTTP/1.1 400 "));

    let target = closed_port().await;
    let mut client = TcpStream::connect(proxy).await.unwrap();
    let request = format!("CONNECT {target} HTTP/1.1\r\n\r\n");
    client.write_all(request.as_bytes()).await.unwrap();
    assert!(read_to_end(&mut client).await.starts_with("HTTP/1.1 502 "));
}

/// Refuses every connect the way a routing rule does, with `action`.
struct Rejects(RejectAction);

impl TcpOutbound for Rejects {
    fn protocol(&self) -> &'static str {
        "test-reject"
    }

    fn connect<'a>(&'a self, _target: &'a TargetAddr) -> BoxFuture<'a, io::Result<BoxStream>> {
        let action = self.0;
        Box::pin(async move { Err(reject::rejected(action)) })
    }
}

async fn rejecting_proxy(action: RejectAction) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(serve(
        listener,
        Arc::new(Rejects(action)),
        MixedSettings::default(),
        Arc::new(MixedStats::default()),
    ));
    addr
}

const PLAIN_GET: &[u8] = b"GET http://ads.example/pixel.gif HTTP/1.1\r\nHost: ads.example\r\n\r\n";

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reject_tinygif_answers_plain_http_with_a_gif() {
    let proxy = rejecting_proxy(RejectAction::TinyGif).await;
    let mut client = TcpStream::connect(proxy).await.unwrap();
    client.write_all(PLAIN_GET).await.unwrap();
    let mut response = Vec::new();
    tokio::time::timeout(WAIT, client.read_to_end(&mut response))
        .await
        .expect("read timed out")
        .unwrap();
    assert_eq!(response, reject::tiny_gif_response());

    // A tunnel has no request to answer: it fails as with REJECT.
    let mut client = TcpStream::connect(proxy).await.unwrap();
    client
        .write_all(b"CONNECT ads.example:443 HTTP/1.1\r\n\r\n")
        .await
        .unwrap();
    assert!(read_to_end(&mut client).await.starts_with("HTTP/1.1 502 "));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reject_drop_answers_nothing_and_keeps_the_connection_open() {
    let proxy = rejecting_proxy(RejectAction::Drop).await;
    for request in [
        PLAIN_GET.to_vec(),
        b"CONNECT ads.example:443 HTTP/1.1\r\n\r\n".to_vec(),
    ] {
        let mut client = TcpStream::connect(proxy).await.unwrap();
        client.write_all(&request).await.unwrap();
        let mut byte = [0u8; 1];
        let read = tokio::time::timeout(Duration::from_millis(500), client.read(&mut byte)).await;
        assert!(
            read.is_err(),
            "a dropped request must get no answer or close"
        );
        // The client can still give up on its own.
        drop(client);
    }

    // SOCKS5 gets the method reply (before routing) and then nothing.
    let mut client = TcpStream::connect(proxy).await.unwrap();
    client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
    assert_eq!(read_n(&mut client, 2).await, [0x05, 0x00]);
    client
        .write_all(&socks_connect_ipv4("192.0.2.1:443".parse().unwrap()))
        .await
        .unwrap();
    let mut byte = [0u8; 1];
    let read = tokio::time::timeout(Duration::from_millis(500), client.read(&mut byte)).await;
    assert!(read.is_err(), "a dropped SOCKS5 connect must get no reply");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reject_close_gets_the_usual_failure_reply() {
    let proxy = rejecting_proxy(RejectAction::Close).await;
    let mut client = TcpStream::connect(proxy).await.unwrap();
    client.write_all(PLAIN_GET).await.unwrap();
    assert!(read_to_end(&mut client).await.starts_with("HTTP/1.1 502 "));
}

/// Takes connections whose first bytes start with `take` and answers them
/// itself; everything else is left to the relay.
struct TakesMarked;

impl ClientInterceptor for TakesMarked {
    fn claim(&self, target: &TargetAddr, first: &[u8]) -> Option<String> {
        first.starts_with(b"take").then(|| target.host())
    }

    fn serve<'a>(
        &'a self,
        _client: ClientAddrs,
        target: &'a TargetAddr,
        host: String,
        mut stream: BoxStream,
        first: Vec<u8>,
    ) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            let answer = format!("taken {host}:{} after {} bytes", target.port(), first.len());
            let _ = stream.write_all(answer.as_bytes()).await;
            let _ = stream.shutdown().await;
        })
    }
}

struct DirectClients;

impl ClientConnector for DirectClients {
    fn connect_client<'a>(
        &'a self,
        _client: ClientAddrs,
        target: &'a TargetAddr,
    ) -> BoxFuture<'a, io::Result<BoxStream>> {
        Direct.connect(target)
    }
}

async fn intercepted_proxy() -> (SocketAddr, Arc<MixedStats>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let stats = Arc::new(MixedStats::default());
    tokio::spawn(serve_intercepted(
        listener,
        Arc::new(DirectClients),
        Some(Arc::new(TakesMarked)),
        MixedSettings::default(),
        stats.clone(),
    ));
    (addr, stats)
}

const ESTABLISHED: &[u8] = b"HTTP/1.1 200 Connection established\r\n\r\n";

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn interceptor_takes_claimed_tunnels_before_any_outbound_connection() {
    // Nothing listens on the target: a claimed tunnel never dials it.
    let target = closed_port().await;
    let (proxy, stats) = intercepted_proxy().await;

    let mut client = TcpStream::connect(proxy).await.unwrap();
    let request = format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n");
    client.write_all(request.as_bytes()).await.unwrap();
    assert_eq!(read_n(&mut client, ESTABLISHED.len()).await, ESTABLISHED);
    client.write_all(b"take me").await.unwrap();
    assert_eq!(
        read_to_end(&mut client).await,
        format!("taken 127.0.0.1:{} after 7 bytes", target.port())
    );

    let mut client = TcpStream::connect(proxy).await.unwrap();
    client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
    read_n(&mut client, 2).await;
    client.write_all(&socks_connect_ipv4(target)).await.unwrap();
    assert_eq!(read_n(&mut client, 10).await[1], 0x00);
    client.write_all(b"take").await.unwrap();
    assert!(read_to_end(&mut client).await.starts_with("taken "));
    assert_eq!(stats.connect_failed.load(Ordering::Relaxed), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn interceptor_leaves_other_tunnels_to_the_relay() {
    let echo = echo_server().await;
    let (proxy, stats) = intercepted_proxy().await;

    // The first bytes the interceptor looked at reach the target too.
    let mut client = TcpStream::connect(proxy).await.unwrap();
    let request = format!("CONNECT {echo} HTTP/1.1\r\nHost: {echo}\r\n\r\n");
    client.write_all(request.as_bytes()).await.unwrap();
    assert_eq!(read_n(&mut client, ESTABLISHED.len()).await, ESTABLISHED);
    client.write_all(b"hello").await.unwrap();
    assert_eq!(read_n(&mut client, 5).await, b"hello");
    assert_echo(&mut client).await;

    // Early data sent with the request head is judged without waiting.
    let mut client = TcpStream::connect(proxy).await.unwrap();
    let request = format!("CONNECT {echo} HTTP/1.1\r\nHost: {echo}\r\n\r\nearly");
    client.write_all(request.as_bytes()).await.unwrap();
    assert_eq!(read_n(&mut client, ESTABLISHED.len()).await, ESTABLISHED);
    assert_eq!(read_n(&mut client, 5).await, b"early");

    // A client that waits for the server is relayed after the short wait.
    let mut client = TcpStream::connect(proxy).await.unwrap();
    let request = format!("CONNECT {echo} HTTP/1.1\r\nHost: {echo}\r\n\r\n");
    client.write_all(request.as_bytes()).await.unwrap();
    assert_eq!(read_n(&mut client, ESTABLISHED.len()).await, ESTABLISHED);
    tokio::time::sleep(Duration::from_millis(600)).await;
    assert_echo(&mut client).await;

    // An unreachable target can only be reported by closing the tunnel.
    let target = closed_port().await;
    let mut client = TcpStream::connect(proxy).await.unwrap();
    let request = format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n");
    client.write_all(request.as_bytes()).await.unwrap();
    assert_eq!(read_n(&mut client, ESTABLISHED.len()).await, ESTABLISHED);
    client.write_all(b"hello").await.unwrap();
    assert_eq!(read_to_end(&mut client).await, "");
    assert_eq!(stats.connect_failed.load(Ordering::Relaxed), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn interceptor_is_offered_plain_http_requests() {
    let target = closed_port().await;
    let (proxy, _) = intercepted_proxy().await;
    let mut client = TcpStream::connect(proxy).await.unwrap();
    // The interceptor sees the origin-form head, which starts with the method.
    let request = format!("take http://{target}/path HTTP/1.1\r\nHost: {target}\r\n\r\n");
    client.write_all(request.as_bytes()).await.unwrap();
    assert!(read_to_end(&mut client)
        .await
        .starts_with("taken 127.0.0.1"));
}

async fn udp_echo_server() -> SocketAddr {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = socket.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 65_535];
        while let Ok((n, from)) = socket.recv_from(&mut buf).await {
            let _ = socket.send_to(&buf[..n], from).await;
        }
    });
    addr
}

async fn udp_proxy() -> (SocketAddr, Arc<MixedStats>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let stats = Arc::new(MixedStats::default());
    let settings = MixedSettings {
        udp: true,
        ..MixedSettings::default()
    };
    tokio::spawn(serve(listener, Arc::new(Direct), settings, stats.clone()));
    (addr, stats)
}

/// Opens a UDP association and returns the control connection and the relay.
async fn associate(proxy: SocketAddr) -> (TcpStream, SocketAddr) {
    let mut control = TcpStream::connect(proxy).await.unwrap();
    control.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
    assert_eq!(read_n(&mut control, 2).await, [0x05, 0x00]);
    control
        .write_all(&[0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        .await
        .unwrap();
    let reply = read_n(&mut control, 10).await;
    assert_eq!(reply[..4], [0x05, 0x00, 0x00, 0x01], "associate reply");
    let ip = std::net::Ipv4Addr::new(reply[4], reply[5], reply[6], reply[7]);
    let port = u16::from_be_bytes([reply[8], reply[9]]);
    assert_ne!(port, 0);
    (control, SocketAddr::from((ip, port)))
}

fn udp_packet(header_addr: &[u8], port: u16, payload: &[u8]) -> Vec<u8> {
    let mut packet = vec![0, 0, 0];
    packet.extend_from_slice(header_addr);
    packet.extend_from_slice(&port.to_be_bytes());
    packet.extend_from_slice(payload);
    packet
}

async fn recv_udp(socket: &UdpSocket) -> Vec<u8> {
    let mut buf = vec![0u8; 65_535];
    let n = tokio::time::timeout(WAIT, socket.recv(&mut buf))
        .await
        .expect("udp reply timed out")
        .unwrap();
    buf.truncate(n);
    buf
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn socks5_udp_associate_relays_to_ip_and_domain_targets() {
    let echo = udp_echo_server().await;
    let (proxy, stats) = udp_proxy().await;
    let (_control, relay) = associate(proxy).await;
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    client.connect(relay).await.unwrap();

    // IPv4 destination: the reply carries the same address.
    let mut ipv4 = vec![0x01];
    ipv4.extend_from_slice(&[127, 0, 0, 1]);
    client
        .send(&udp_packet(&ipv4, echo.port(), b"quic initial"))
        .await
        .unwrap();
    assert_eq!(
        recv_udp(&client).await,
        udp_packet(&ipv4, echo.port(), b"quic initial")
    );

    // A name is handed to the outbound unresolved and kept in the reply.
    let mut name = vec![0x03, 9];
    name.extend_from_slice(b"localhost");
    client
        .send(&udp_packet(&name, echo.port(), b"by name"))
        .await
        .unwrap();
    assert_eq!(
        recv_udp(&client).await,
        udp_packet(&name, echo.port(), b"by name")
    );

    // A second datagram on the same flow reuses it.
    client
        .send(&udp_packet(&ipv4, echo.port(), b"again"))
        .await
        .unwrap();
    assert_eq!(
        recv_udp(&client).await,
        udp_packet(&ipv4, echo.port(), b"again")
    );
    assert_eq!(stats.udp_associations.load(Ordering::Relaxed), 1);
    // The relay counts a reply after sending it, so the last reply can
    // arrive before its bytes are counted.
    let counted = tokio::time::timeout(Duration::from_secs(2), async {
        while stats.bytes_down.load(Ordering::Relaxed) < 24 {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await;
    assert!(
        counted.is_ok(),
        "{}",
        stats.bytes_down.load(Ordering::Relaxed)
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn socks5_udp_drops_fragments_and_ends_with_the_control_connection() {
    let echo = udp_echo_server().await;
    let (proxy, _) = udp_proxy().await;
    let (control, relay) = associate(proxy).await;
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    client.connect(relay).await.unwrap();

    let mut ipv4 = vec![0x01];
    ipv4.extend_from_slice(&[127, 0, 0, 1]);
    let mut fragment = udp_packet(&ipv4, echo.port(), b"fragment");
    fragment[2] = 1;
    client.send(&fragment).await.unwrap();
    client
        .send(&udp_packet(&ipv4, echo.port(), b"whole"))
        .await
        .unwrap();
    // Only the whole datagram comes back.
    assert_eq!(
        recv_udp(&client).await,
        udp_packet(&ipv4, echo.port(), b"whole")
    );

    drop(control);
    tokio::time::sleep(Duration::from_millis(200)).await;
    client
        .send(&udp_packet(&ipv4, echo.port(), b"after close"))
        .await
        .ok();
    let mut buf = [0u8; 64];
    let late = tokio::time::timeout(Duration::from_millis(500), client.recv(&mut buf)).await;
    assert!(
        !matches!(late, Ok(Ok(_))),
        "relay must stop once the control connection closes"
    );
}
