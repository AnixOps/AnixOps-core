//! Two nodes of one network in this process, each as an outbound with its
//! own private stack: a TCP connection and a UDP flow between their virtual
//! addresses, and nothing sent outside the network.

#![cfg(feature = "outbound")]

use std::io::ErrorKind;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use engine_outbound::registry::{OutboundFactory, Settings};
use engine_outbound::{TargetAddr, TcpDialer, TcpOutbound};
use outbound_mesh::outbound::engine::{EngineSlot, GRACE};
use outbound_mesh::outbound::{Failure, MeshFactory, MeshOutbound};
use outbound_mesh::{MeshConfig, MeshSettings};
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::{sleep, timeout, Instant};

fn settings(node: serde_json::Value, peers: serde_json::Value) -> MeshSettings {
    let config: MeshConfig = serde_json::from_value(json!({
        "config_version": 1,
        "network": {"name": "outbound-test", "secret": "s3cr3t", "kind": "legacy"},
        "node": node,
        "peers": peers,
    }))
    .unwrap();
    config.validate().unwrap()
}

fn free_port() -> u16 {
    std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn target(text: &str) -> TargetAddr {
    TargetAddr::Ip(text.parse::<SocketAddr>().unwrap())
}

/// A full node listening on loopback, and a node that dials it.
fn two_nodes() -> (MeshOutbound, MeshOutbound) {
    let port = free_port();
    let server = settings(
        json!({
            "address": "10.144.0.1/24",
            "role": "full",
            "listen": [{"transport": "tcp", "port": port, "address": "127.0.0.1"}],
        }),
        json!([]),
    );
    let client = settings(
        json!({"address": "10.144.0.2/24", "role": "full"}),
        json!([{"server": "127.0.0.1", "port": port, "transport": "tcp"}]),
    );
    // One network twice in a process: neither may replace the other.
    (
        MeshOutbound::unshared(server).unwrap(),
        MeshOutbound::unshared(client).unwrap(),
    )
}

#[tokio::test]
async fn a_connection_and_a_flow_reach_the_other_node() {
    let (server, client) = two_nodes();
    server.instance().start();

    let accepting = {
        let server = server.clone();
        tokio::spawn(async move {
            let mut stream = server.accept_tcp(7000).await.unwrap();
            let mut buffer = [0u8; 5];
            stream.read_exact(&mut buffer).await.unwrap();
            stream.write_all(&buffer).await.unwrap();
            stream.flush().await.unwrap();
            // Keep the connection open while the client checks that
            // retiring its network ends it.
            let _ = timeout(Duration::from_secs(3), stream.read(&mut buffer)).await;
        })
    };

    // The link comes up in the background; retry until it carries the SYN.
    let deadline = Instant::now() + Duration::from_secs(30);
    let mut stream = loop {
        match client.connect(&target("10.144.0.1:7000")).await {
            Ok(stream) => break stream,
            Err(error) if Instant::now() < deadline => {
                assert_ne!(error.kind(), ErrorKind::InvalidInput, "{error}");
                sleep(Duration::from_millis(200)).await;
            }
            Err(error) => panic!("no connection: {error}"),
        }
    };
    stream.write_all(b"hello").await.unwrap();
    let mut echo = [0u8; 5];
    timeout(Duration::from_secs(10), stream.read_exact(&mut echo))
        .await
        .expect("echo in time")
        .unwrap();
    assert_eq!(&echo, b"hello");
    timeout(Duration::from_secs(10), accepting)
        .await
        .expect("server done")
        .unwrap();

    // UDP between the virtual addresses, on a fixed port on the far side.
    let mut answer = server
        .open_udp_on(5353, &target("10.144.0.2:5354"))
        .await
        .unwrap();
    let mut question = client
        .open_udp_on(5354, &target("10.144.0.1:5353"))
        .await
        .unwrap();
    question.send.send(b"ping").await.unwrap();
    let received = timeout(Duration::from_secs(10), answer.recv.recv())
        .await
        .expect("datagram in time")
        .unwrap();
    assert_eq!(received, b"ping");

    let health = client.health().unwrap();
    assert_eq!(health["running"], json!(true));
    assert_eq!(health["failure"], json!(null));

    // Retiring the network ends the connection it still carries, and no
    // new one opens on it.
    client.instance().retire();
    assert!(stream.write_all(b"more").await.is_err());
    let error = client
        .connect(&target("10.144.0.1:7000"))
        .await
        .err()
        .unwrap();
    assert_eq!(error.kind(), ErrorKind::ConnectionReset);
    assert_eq!(client.health().unwrap()["running"], json!(false));
}

#[tokio::test]
async fn nothing_outside_the_network_is_dialed() {
    let (_, client) = two_nodes();
    for outside in ["192.0.2.1:80", "10.144.1.1:80", "[2001:db8::1]:443"] {
        let error = client.connect(&target(outside)).await.err().unwrap();
        assert_eq!(error.kind(), ErrorKind::InvalidInput, "{outside}");
    }
    // Its own virtual address is not a destination either.
    let error = client
        .connect(&target("10.144.0.2:80"))
        .await
        .err()
        .unwrap();
    assert_eq!(error.kind(), ErrorKind::InvalidInput);
    let error = client
        .connect(&TargetAddr::Domain("10.144.9.9".into(), 80))
        .await
        .err()
        .unwrap();
    assert_eq!(error.kind(), ErrorKind::InvalidInput);
}

#[tokio::test]
async fn a_managed_network_without_this_node_in_its_key_list_waits() {
    let config: MeshConfig = serde_json::from_value(json!({
        "config_version": 1,
        "network": {
            "name": "outbound-managed",
            "secret": "s3cr3t",
            "native_keys": ["AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="],
        },
        "node": {"address": "10.145.0.2/24", "role": "access"},
        "peers": [{"server": "127.0.0.1", "port": 1}],
    }))
    .unwrap();
    let outbound = MeshOutbound::unshared(config.validate().unwrap()).unwrap();
    let error = outbound
        .connect(&target("10.145.0.1:80"))
        .await
        .err()
        .unwrap();
    assert_eq!(error.kind(), ErrorKind::NotConnected);
    assert_eq!(
        outbound.instance().state(),
        (false, Some(Failure::NativeKeysPending))
    );
}

fn access_node(name: &str, address: &str) -> MeshSettings {
    let config: MeshConfig = serde_json::from_value(json!({
        "config_version": 1,
        "network": {"name": name, "secret": "s3cr3t", "kind": "legacy"},
        "node": {"address": address, "role": "access"},
        "peers": [{"server": "127.0.0.1", "port": 1}],
    }))
    .unwrap();
    config.validate().unwrap()
}

static SLOT: EngineSlot = EngineSlot::new(GRACE);

fn outbound_settings(name: &str, address: &str) -> Settings {
    let value = json!({
        "config_version": 1,
        "network": {"name": name, "secret": "s3cr3t", "kind": "legacy"},
        "node": {"address": address, "role": "access"},
        "peers": [{"server": "127.0.0.1", "port": 1}],
    });
    value.as_object().unwrap().clone()
}

#[tokio::test]
async fn building_an_outbound_starts_nothing_until_the_engine_commits() {
    let built = Arc::new(Mutex::new(Vec::new()));
    let factory = MeshFactory::bound(&SLOT, built.clone());
    let outbound = factory
        .build(
            &outbound_settings("outbound-commit", "10.146.0.2/24"),
            Arc::new(TcpDialer),
        )
        .unwrap();
    // Built, not adopted: no engine runs and nothing started.
    assert!(SLOT.current().is_none());
    let error = outbound
        .connect(&target("10.146.0.1:80"))
        .await
        .err()
        .unwrap();
    assert_eq!(error.kind(), ErrorKind::NotConnected);
    let engine = SLOT.acquire().unwrap();
    engine
        .registry()
        .commit(std::mem::take(&mut *built.lock().unwrap()));
    let networks = engine.registry().networks();
    assert_eq!(networks.len(), 1);
    let instance = networks[0].instance.clone().unwrap();
    // A draft profile with other settings builds without touching it.
    let draft = factory
        .build(
            &outbound_settings("outbound-commit", "10.146.0.9/24"),
            Arc::new(TcpDialer),
        )
        .unwrap();
    let error = draft.connect(&target("10.146.0.1:80")).await.err().unwrap();
    assert_eq!(error.kind(), ErrorKind::NotConnected);
    assert!(!instance.is_retired());
    SLOT.release(true);
    assert!(engine.is_stopped());
    assert!(instance.is_retired());
}

#[tokio::test]
async fn a_detached_outbound_is_unsupported() {
    let outbound = MeshFactory::detached()
        .build(
            &outbound_settings("outbound-detached", "10.148.0.2/24"),
            Arc::new(TcpDialer),
        )
        .unwrap();
    let error = outbound
        .connect(&target("10.148.0.1:80"))
        .await
        .err()
        .unwrap();
    assert_eq!(error.kind(), ErrorKind::Unsupported);
    let error = outbound
        .open_udp(&target("10.148.0.1:53"))
        .await
        .err()
        .unwrap();
    assert_eq!(error.kind(), ErrorKind::Unsupported);
}

#[test]
fn a_driver_whose_runtime_is_gone_counts_as_stopped() {
    let outbound =
        MeshOutbound::unshared(access_node("outbound-runtime", "10.149.0.2/24")).unwrap();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    // Started on a runtime that is dropped before the driver task ever ran.
    runtime.block_on(async { outbound.instance().start() });
    assert_eq!(outbound.instance().state(), (true, None));
    drop(runtime);
    assert_eq!(outbound.instance().state(), (false, Some(Failure::Stopped)));
}
