//! Clients that misbehave before the handshake completes, against every
//! stream inbound the node serves on TCP: one that sends nothing, one that
//! trickles a byte at a time (slowloris), one that sends half a handshake
//! and closes its side, and one that resets the connection mid-handshake.
//!
//! Each must be closed by the node within the handshake timeout plus the
//! reject hold, and leave no active connection behind. A full connection
//! table must refuse new clients at once and take them again when the
//! stalled ones time out.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use engine_inbound::server::ServeSettings;
use node_runtime::{default_registry, InboundConfig, Node};
use rcgen::{CertificateParams, KeyPair};
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

const HANDSHAKE_TIMEOUT: Duration = Duration::from_millis(500);
const REJECT_HOLD: Duration = Duration::from_millis(200);
/// Scheduling slack on a loaded CI runner.
const SLACK: Duration = Duration::from_secs(3);
const UUID: &str = "b831381d-6324-4d53-ad4f-8cda48b30811";
const PASSWORD: &str = "alice-secret";
const SS2022_SERVER_KEY: &str = "AQIDBAUGBwgJCgsMDQ4PEA==";
const SS2022_USER_KEY: &str = "EA8ODQwLCgkIBwYFBAMCAQ==";
const SNELL_PSK: &str = "fault-injection-psk";
/// A TLS record header announcing a 512-byte handshake record: a TLS server
/// waits for the rest.
const TLS_RECORD_START: &[u8] = &[0x16, 0x03, 0x01, 0x02, 0x00];

fn deadline() -> Duration {
    HANDSHAKE_TIMEOUT + REJECT_HOLD + SLACK
}

fn node(max_connections: usize) -> Arc<Node> {
    Arc::new(
        Node::new(default_registry(), false).with_serve_settings(ServeSettings {
            max_connections,
            handshake_timeout: HANDSHAKE_TIMEOUT,
            reject_hold: REJECT_HOLD,
            ..ServeSettings::default()
        }),
    )
}

/// The stream inbounds on TCP, each with what a client of it sends first
/// that makes the server wait for more.
fn inbounds() -> Vec<(&'static str, Value, &'static [u8])> {
    let key = KeyPair::generate().unwrap();
    let cert = CertificateParams::new(vec!["node.test".to_string()])
        .unwrap()
        .self_signed(&key)
        .unwrap();
    let tls = json!({"certificate": cert.pem(), "key": key.serialize_pem()});
    vec![
        (
            "vless",
            json!({"type": "vless", "users": [{"name": "alice", "uuid": UUID}]}),
            &[0x00, 0xb8, 0x31],
        ),
        (
            "vmess",
            json!({"type": "vmess", "users": [{"name": "alice", "uuid": UUID}]}),
            &[0x5a; 8],
        ),
        (
            "trojan",
            json!({"type": "trojan", "users": [{"name": "alice", "password": PASSWORD}]}),
            b"ef59aaa3cc37",
        ),
        (
            "trojan-tls",
            json!({"type": "trojan", "users": [{"name": "alice", "password": PASSWORD}],
                "tls": tls.clone()}),
            TLS_RECORD_START,
        ),
        (
            "ss-aead",
            json!({"type": "shadowsocks", "method": "aes-256-gcm",
                "users": [{"name": "alice", "password": PASSWORD}]}),
            &[0x42; 8],
        ),
        (
            "ss-2022",
            json!({"type": "shadowsocks", "method": "2022-blake3-aes-128-gcm",
                "password": SS2022_SERVER_KEY,
                "users": [{"name": "alice", "password": SS2022_USER_KEY}]}),
            &[0x42; 8],
        ),
        (
            "snell",
            json!({"type": "snell", "psk": SNELL_PSK, "version": 4}),
            &[0x42; 8],
        ),
        (
            "anytls",
            json!({"type": "anytls", "users": [{"name": "alice", "password": PASSWORD}],
                "tls": tls.clone()}),
            TLS_RECORD_START,
        ),
        (
            "naive",
            json!({"type": "naive", "users": [{"name": "alice", "password": PASSWORD}],
                "tls": tls}),
            TLS_RECORD_START,
        ),
    ]
}

async fn add(node: &Node, tag: &str, mut config: Value) -> SocketAddr {
    let object = config.as_object_mut().unwrap();
    object.insert("tag".into(), tag.into());
    object.insert("listen".into(), "127.0.0.1".into());
    object.insert("listen_port".into(), 0.into());
    let config: InboundConfig = serde_json::from_value(config).unwrap();
    node.add_inbound(config)
        .await
        .unwrap_or_else(|error| panic!("{tag}: {error:?}"))
}

/// Waits until the node closes `stream`: end of stream or an error on read.
/// Panics past `deadline()` from `started`.
async fn closed_by_node(tag: &str, fault: &str, stream: &mut TcpStream, started: Instant) {
    let mut buf = [0u8; 4096];
    let closed = tokio::time::timeout(deadline(), async {
        loop {
            match stream.read(&mut buf).await {
                Ok(0) | Err(_) => return,
                Ok(_) => {}
            }
        }
    })
    .await;
    assert!(
        closed.is_ok(),
        "{tag}: a client that {fault} was still open after {:?}",
        started.elapsed()
    );
}

/// Waits until `tag` has taken `accepted` clients and none of them is
/// still active.
async fn settles(node: &Node, tag: &str, accepted: u64) {
    let started = Instant::now();
    loop {
        let info = node
            .list()
            .into_iter()
            .find(|info| info.tag == tag)
            .unwrap();
        if info.accepted == accepted && info.active == 0 {
            return;
        }
        assert!(
            started.elapsed() < deadline(),
            "{tag}: {} of {accepted} clients taken, {} still active",
            info.accepted,
            info.active
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn misbehaving_clients_are_closed_and_leave_nothing_behind() {
    let node = node(64);
    for (tag, config, start) in inbounds() {
        let server = add(&node, tag, config).await;

        // Silent: connects and sends nothing.
        let started = Instant::now();
        let mut silent = TcpStream::connect(server).await.unwrap();
        closed_by_node(tag, "sends nothing", &mut silent, started).await;

        // Slowloris: the start of a handshake, then a byte every 100 ms for
        // longer than the node may wait. The trickle runs beside the read so
        // that the node's close is seen when it happens.
        let started = Instant::now();
        let slow = TcpStream::connect(server).await.unwrap();
        let (mut read, mut write) = slow.into_split();
        let trickle = tokio::spawn(async move {
            for byte in start.iter().copied().chain(std::iter::repeat(0x41)) {
                if write.write_all(&[byte]).await.is_err() {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        });
        let mut buf = [0u8; 4096];
        let closed = tokio::time::timeout(deadline(), async {
            loop {
                match read.read(&mut buf).await {
                    Ok(0) | Err(_) => return,
                    Ok(_) => {}
                }
            }
        })
        .await;
        trickle.abort();
        assert!(
            closed.is_ok(),
            "{tag}: a client that trickles bytes was still open after {:?}",
            started.elapsed()
        );

        // Half a handshake, then the client closes its side.
        let started = Instant::now();
        let mut half = TcpStream::connect(server).await.unwrap();
        half.write_all(start).await.unwrap();
        half.shutdown().await.unwrap();
        closed_by_node(
            tag,
            "half-closed after part of a handshake",
            &mut half,
            started,
        )
        .await;

        // Half a handshake, then a reset (a zero linger time makes the
        // close send RST).
        let mut reset = TcpStream::connect(server).await.unwrap();
        reset.write_all(start).await.unwrap();
        // Newer tokio versions name this `set_zero_linger`.
        #[allow(deprecated)]
        reset.set_linger(Some(Duration::ZERO)).unwrap();
        drop(reset);

        settles(&node, tag, 4).await;
        node.remove_inbound(tag).unwrap();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_full_table_refuses_at_once_and_recovers_after_the_timeout() {
    const SLOTS: usize = 4;
    let node = node(SLOTS);
    let server = add(
        &node,
        "vless",
        json!({"type": "vless", "users": [{"name": "alice", "uuid": UUID}]}),
    )
    .await;

    let mut stalled = Vec::new();
    for _ in 0..SLOTS {
        stalled.push(TcpStream::connect(server).await.unwrap());
    }
    // The accept loop takes the stalled clients in order; wait until all of
    // them hold a slot.
    let started = Instant::now();
    while node.list()[0].active < SLOTS as u64 {
        assert!(started.elapsed() < deadline(), "stalled clients not taken");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    // Over the limit: closed at once, well before any handshake timeout.
    let started = Instant::now();
    let mut refused = TcpStream::connect(server).await.unwrap();
    let mut buf = [0u8; 16];
    let read = tokio::time::timeout(HANDSHAKE_TIMEOUT, refused.read(&mut buf)).await;
    assert!(
        matches!(read, Ok(Ok(0) | Err(_))),
        "a client over the limit was not refused within {:?}",
        started.elapsed()
    );

    // The stalled clients time out and free their slots.
    for (n, stream) in stalled.iter_mut().enumerate() {
        closed_by_node("vless", &format!("stalled (#{n})"), stream, started).await;
    }
    settles(&node, "vless", SLOTS as u64).await;

    // A new client is taken again: it is held until the handshake timeout,
    // not refused at once.
    let mut again = TcpStream::connect(server).await.unwrap();
    let started = Instant::now();
    let _ = tokio::time::timeout(deadline(), again.read(&mut buf)).await;
    assert!(
        started.elapsed() >= HANDSHAKE_TIMEOUT - Duration::from_millis(50),
        "a client after recovery was closed after {:?}, as if still refused",
        started.elapsed()
    );
    assert_eq!(node.list()[0].accepted, SLOTS as u64 + 1);
}
