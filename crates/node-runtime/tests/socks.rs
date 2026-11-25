//! The internal-network SOCKS5 inbound in the node: it listens on internal
//! addresses only, must expire, and is gone once it has.

use std::net::SocketAddr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use node_runtime::{default_registry, InboundConfig, Node, NodeError};
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const TIMEOUT: Duration = Duration::from_secs(10);
const LOGIN: &str = "tmp-1";
const PASSWORD: &str = "0123456789abcdef";

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

fn socks(tag: &str, listen: &str, expires_at_ms: Option<u64>) -> InboundConfig {
    let mut value = json!({
        "tag": tag, "type": "socks", "listen": listen, "listen_port": 0,
        "users": [{"name": "1", "username": LOGIN, "password": PASSWORD}]
    });
    if let Some(at) = expires_at_ms {
        value["expires_at_ms"] = at.into();
    }
    serde_json::from_value(value).unwrap()
}

fn invalid(result: Result<SocketAddr, NodeError>) -> String {
    match result {
        Err(NodeError::Invalid(reason)) => reason.to_owned(),
        Err(other) => panic!("unexpected error: {other}"),
        Ok(addr) => panic!("added on {addr}"),
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

/// Authenticates and asks for `target`; returns the connected client.
async fn connect(server: SocketAddr, target: SocketAddr) -> TcpStream {
    let SocketAddr::V4(target) = target else {
        panic!("IPv4 targets only")
    };
    let mut client = TcpStream::connect(server).await.unwrap();
    client.write_all(&[5, 1, 2]).await.unwrap();
    let mut choice = [0u8; 2];
    client.read_exact(&mut choice).await.unwrap();
    assert_eq!(choice, [5, 2]);
    let mut auth = vec![1, LOGIN.len() as u8];
    auth.extend_from_slice(LOGIN.as_bytes());
    auth.push(PASSWORD.len() as u8);
    auth.extend_from_slice(PASSWORD.as_bytes());
    client.write_all(&auth).await.unwrap();
    let mut status = [0u8; 2];
    client.read_exact(&mut status).await.unwrap();
    assert_eq!(status, [1, 0]);
    let mut request = vec![5, 1, 0, 1];
    request.extend_from_slice(&target.ip().octets());
    request.extend_from_slice(&target.port().to_be_bytes());
    client.write_all(&request).await.unwrap();
    let mut reply = [0u8; 10];
    client.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply[1], 0);
    client
}

#[tokio::test]
async fn socks_needs_an_internal_listen_address_and_an_expiry() {
    let node = Node::new(default_registry(), true);
    let soon = now_ms() + 60_000;
    let no_expiry = invalid(node.add_inbound(socks("a", "127.0.0.1", None)).await);
    assert!(no_expiry.contains("expires_at_ms"), "{no_expiry}");
    let past = invalid(node.add_inbound(socks("a", "127.0.0.1", Some(now_ms() - 1))).await);
    assert!(past.contains("not in the future"), "{past}");
    let far = now_ms() + 8 * 24 * 60 * 60 * 1000;
    let too_far = invalid(node.add_inbound(socks("a", "127.0.0.1", Some(far))).await);
    assert!(too_far.contains("seven days"), "{too_far}");
    for listen in ["::", "0.0.0.0", "8.8.8.8", "2001:db8::1"] {
        let public = invalid(node.add_inbound(socks("a", listen, Some(soon))).await);
        assert!(public.contains("internal address"), "{listen}: {public}");
    }
    assert!(node.list().is_empty());

    node.add_inbound(socks("a", "127.0.0.1", Some(soon)))
        .await
        .unwrap();
    let listed = node.list();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].kind, "socks");
    assert_eq!(listed[0].expires_at_ms, Some(soon));
}

#[tokio::test]
async fn an_expired_inbound_closes_its_connections_and_frees_its_tag() {
    tokio::time::timeout(TIMEOUT, async {
        let node = Node::new(default_registry(), true);
        let echo = echo_server().await;
        let server = node
            .add_inbound(socks("tmp", "127.0.0.1", Some(now_ms() + 1_000)))
            .await
            .unwrap();
        let mut client = connect(server, echo).await;
        client.write_all(b"before").await.unwrap();
        let mut echoed = [0u8; 6];
        client.read_exact(&mut echoed).await.unwrap();
        assert_eq!(&echoed, b"before");

        // The connection ends when the inbound expires.
        let mut rest = [0u8; 16];
        assert!(matches!(client.read(&mut rest).await, Ok(0) | Err(_)));
        assert!(node.list().is_empty());
        assert!(TcpStream::connect(server).await.is_err());

        // The tag can be used again.
        node.add_inbound(socks("tmp", "127.0.0.1", Some(now_ms() + 60_000)))
            .await
            .unwrap();
        assert_eq!(node.list().len(), 1);
    })
    .await
    .expect("timed out");
}

#[tokio::test]
async fn any_inbound_may_expire() {
    tokio::time::timeout(TIMEOUT, async {
        let node = Node::new(default_registry(), true);
        let config: InboundConfig = serde_json::from_value(json!({
            "tag": "ss", "type": "shadowsocks", "listen": "127.0.0.1", "listen_port": 0,
            "method": "2022-blake3-aes-128-gcm", "password": "AQEBAQEBAQEBAQEBAQEBAQ==",
            "users": [{"name": "1001", "password": "AgICAgICAgICAgICAgICAg=="}],
            "expires_at_ms": now_ms() + 300
        }))
        .unwrap();
        let server = node.add_inbound(config).await.unwrap();
        assert_eq!(node.list().len(), 1);
        tokio::time::sleep(Duration::from_millis(600)).await;
        assert!(node.list().is_empty());
        assert!(TcpStream::connect(server).await.is_err());
    })
    .await
    .expect("timed out");
}
