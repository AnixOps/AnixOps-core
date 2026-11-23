//! WireGuard tunnel tests against an in-process boringtun peer that reflects
//! every UDP packet back to its sender.

#![cfg(feature = "wireguard")]

use std::collections::HashMap;
use std::net::{SocketAddr, UdpSocket};
use std::sync::mpsc::{self, Receiver};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use base64::Engine;
use boringtun::noise::{Tunn, TunnResult};
use boringtun::x25519::{PublicKey, StaticSecret};
use engine_embedded::tunnel::PacketSink;
use engine_embedded::{EmbeddedRuntime, RuntimeErrorCode, RuntimeState};
use etherparse::{PacketBuilder, SlicedPacket, TransportSlice};

const CLIENT_KEY: [u8; 32] = [7; 32];
const PEER_KEY: [u8; 32] = [9; 32];
const PRESHARED: [u8; 32] = [3; 32];
const APP: [u8; 4] = [10, 7, 0, 2];
const REMOTE: [u8; 4] = [10, 7, 0, 1];
const WAIT: Duration = Duration::from_secs(10);

fn b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

fn public_key(private: [u8; 32]) -> [u8; 32] {
    PublicKey::from(&StaticSecret::from(private)).to_bytes()
}

fn config(port: u16, preshared: Option<&str>) -> Vec<u8> {
    config_to("127.0.0.1", port, preshared)
}

fn config_to(server: &str, port: u16, preshared: Option<&str>) -> Vec<u8> {
    let mut outbound = serde_json::json!({
        "type": "wireguard",
        "private_key": b64(&CLIENT_KEY),
        "peer_public_key": b64(&public_key(PEER_KEY)),
        "server": server,
        "port": port,
        "persistent_keepalive_secs": 25,
    });
    if let Some(preshared) = preshared {
        outbound["preshared_key"] = preshared.into();
    }
    serde_json::to_vec(&serde_json::json!({
        "schema_version": 1,
        "profile_id": "wg-test",
        "mtu": 1420,
        "outbound": outbound,
    }))
    .unwrap()
}

/// Swaps the addresses and ports of a UDP/IPv4 packet.
fn reflect(packet: &[u8]) -> Option<Vec<u8>> {
    let sliced = SlicedPacket::from_ip(packet).ok()?;
    let Some(etherparse::NetSlice::Ipv4(ip)) = &sliced.net else {
        return None;
    };
    let Some(TransportSlice::Udp(udp)) = &sliced.transport else {
        return None;
    };
    let mut reply = Vec::new();
    PacketBuilder::ipv4(ip.header().destination(), ip.header().source(), 64)
        .udp(udp.destination_port(), udp.source_port())
        .write(&mut reply, udp.payload())
        .ok()?;
    Some(reply)
}

/// Runs a WireGuard peer on a loopback UDP socket until the test process exits.
fn start_peer(preshared: Option<[u8; 32]>) -> u16 {
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    let port = socket.local_addr().unwrap().port();
    thread::spawn(move || {
        let mut tunn = Tunn::new(
            StaticSecret::from(PEER_KEY),
            PublicKey::from(public_key(CLIENT_KEY)),
            preshared,
            None,
            1,
            None,
        );
        let mut datagram = vec![0u8; 65_536];
        let mut out = vec![0u8; 65_536 + 148];
        let mut sealed = vec![0u8; 65_536 + 148];
        loop {
            let Ok((len, from)) = socket.recv_from(&mut datagram) else {
                return;
            };
            let mut input = &datagram[..len];
            loop {
                match tunn.decapsulate(Some(from.ip()), input, &mut out) {
                    TunnResult::WriteToNetwork(reply) => {
                        let _ = socket.send_to(reply, from);
                        input = &[];
                    }
                    TunnResult::WriteToTunnelV4(packet, _) => {
                        if let Some(reply) = reflect(packet) {
                            if let TunnResult::WriteToNetwork(data) =
                                tunn.encapsulate(&reply, &mut sealed)
                            {
                                let _ = socket.send_to(data, from);
                            }
                        }
                        break;
                    }
                    _ => break,
                }
            }
        }
    });
    port
}

/// A UDP relay in front of the peer that gives each client address its own
/// upstream socket, like a NAT mapping, so the peer sees a client that moved
/// as a new address. `cut` drops the paths of every client address seen so
/// far, in both directions, like a network the device left. A twin copy
/// lives in `crates/outbound-wireguard/tests/loopback.rs`; keep them in sync.
struct Relay {
    port: u16,
    state: Arc<Mutex<RelayState>>,
}

#[derive(Default)]
struct RelayState {
    /// Client addresses in the order they appeared.
    clients: Vec<SocketAddr>,
    cut: Vec<SocketAddr>,
}

impl Relay {
    fn start(upstream: SocketAddr) -> Self {
        let front = UdpSocket::bind("127.0.0.1:0").unwrap();
        let port = front.local_addr().unwrap().port();
        let state = Arc::new(Mutex::new(RelayState::default()));
        let shared = state.clone();
        thread::spawn(move || {
            let mut mappings: HashMap<SocketAddr, UdpSocket> = HashMap::new();
            let mut datagram = vec![0u8; 65_536];
            loop {
                // Windows reports an ICMP error for an earlier send here.
                let Ok((len, client)) = front.recv_from(&mut datagram) else {
                    thread::sleep(Duration::from_millis(10));
                    continue;
                };
                {
                    let mut state = shared.lock().unwrap();
                    if state.cut.contains(&client) {
                        continue;
                    }
                    if !state.clients.contains(&client) {
                        state.clients.push(client);
                    }
                }
                let mapping = mappings
                    .entry(client)
                    .or_insert_with(|| map(&front, client, upstream, shared.clone()));
                let _ = mapping.send(&datagram[..len]);
            }
        });
        Self { port, state }
    }

    fn clients(&self) -> Vec<SocketAddr> {
        self.state.lock().unwrap().clients.clone()
    }

    fn cut(&self) {
        let mut state = self.state.lock().unwrap();
        let clients = state.clients.clone();
        state.cut.extend(clients);
    }
}

/// A new upstream socket for `client`, with a thread that relays the peer's
/// datagrams back to it until its path is cut.
fn map(
    front: &UdpSocket,
    client: SocketAddr,
    upstream: SocketAddr,
    state: Arc<Mutex<RelayState>>,
) -> UdpSocket {
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    socket.connect(upstream).unwrap();
    let answers = socket.try_clone().unwrap();
    let front = front.try_clone().unwrap();
    thread::spawn(move || {
        let mut datagram = vec![0u8; 65_536];
        loop {
            let Ok(len) = answers.recv(&mut datagram) else {
                thread::sleep(Duration::from_millis(10));
                continue;
            };
            if state.lock().unwrap().cut.contains(&client) {
                continue;
            }
            let _ = front.send_to(&datagram[..len], client);
        }
    });
    socket
}

fn capture() -> (PacketSink, Receiver<Vec<u8>>) {
    let (tx, rx) = mpsc::channel();
    let tx = Mutex::new(tx);
    let sink: PacketSink = Box::new(move |packet: &[u8]| {
        let _ = tx.lock().unwrap().send(packet.to_vec());
    });
    (sink, rx)
}

fn udp_packet(payload: &[u8]) -> Vec<u8> {
    let mut packet = Vec::new();
    PacketBuilder::ipv4(APP, REMOTE, 64)
        .udp(40000, 9000)
        .write(&mut packet, payload)
        .unwrap();
    packet
}

/// Sends packets until the reflected one comes back: the first ones may be
/// queued behind the handshake.
fn round_trip(runtime: &EmbeddedRuntime, rx: &Receiver<Vec<u8>>, payload: &[u8]) {
    let deadline = Instant::now() + WAIT;
    while Instant::now() < deadline {
        assert!(runtime.input_packet(&udp_packet(payload)));
        while let Ok(packet) = rx.recv_timeout(Duration::from_millis(200)) {
            let sliced = SlicedPacket::from_ip(&packet).unwrap();
            if let Some(TransportSlice::Udp(udp)) = &sliced.transport {
                assert_eq!(udp.source_port(), 9000);
                assert_eq!(udp.destination_port(), 40000);
                assert_eq!(udp.payload(), payload);
                return;
            }
        }
    }
    panic!("reflected packet did not come back through the tunnel");
}

/// Whether the reflection of one packet with `payload` comes back within
/// `wait`; other packets are skipped.
fn comes_back(
    runtime: &EmbeddedRuntime,
    rx: &Receiver<Vec<u8>>,
    payload: &[u8],
    wait: Duration,
) -> bool {
    assert!(runtime.input_packet(&udp_packet(payload)));
    let deadline = Instant::now() + wait;
    while let Some(left) = deadline.checked_duration_since(Instant::now()) {
        let Ok(packet) = rx.recv_timeout(left) else {
            return false;
        };
        let sliced = SlicedPacket::from_ip(&packet).unwrap();
        if let Some(TransportSlice::Udp(udp)) = &sliced.transport {
            if udp.payload() == payload {
                return true;
            }
        }
    }
    false
}

fn control(runtime: &EmbeddedRuntime, request: &str) -> serde_json::Value {
    serde_json::from_slice(&runtime.control_json(request.as_bytes()).unwrap()).unwrap()
}

#[test]
fn packets_round_trip_through_a_wireguard_peer() {
    let port = start_peer(None);
    let mut runtime = EmbeddedRuntime::from_json(&config(port, None)).unwrap();
    let (sink, rx) = capture();
    runtime.start(sink).unwrap();

    round_trip(&runtime, &rx, b"hello through wireguard");
    round_trip(&runtime, &rx, &[0x5a; 1200]);

    let status = runtime.status();
    assert_eq!(status.outbound, "wireguard");
    assert_eq!(status.state, RuntimeState::Running);
    assert!(status.stats.packets_out >= 2);
    assert!(status.stats.bytes_down > 0);
    runtime.stop();
    runtime.stop();
    assert_eq!(runtime.status().state, RuntimeState::Stopped);
}

#[test]
fn preshared_key_is_used() {
    let port = start_peer(Some(PRESHARED));
    let mut runtime = EmbeddedRuntime::from_json(&config(port, Some(&b64(&PRESHARED)))).unwrap();
    let (sink, rx) = capture();
    runtime.start(sink).unwrap();
    round_trip(&runtime, &rx, b"with psk");
    runtime.stop();
}

#[test]
fn invalid_keys_are_rejected_without_echoing_them() {
    let mut bad = serde_json::from_slice::<serde_json::Value>(&config(51820, None)).unwrap();
    bad["outbound"]["private_key"] = "c2hvcnQ=".into();
    let err = match EmbeddedRuntime::from_json(&serde_json::to_vec(&bad).unwrap()) {
        Ok(_) => panic!("a short key must be rejected"),
        Err(err) => err,
    };
    assert_eq!(err.code, RuntimeErrorCode::ConfigRejected);
    assert!(!err.message.contains("c2hvcnQ"));

    let mut bad = serde_json::from_slice::<serde_json::Value>(&config(51820, None)).unwrap();
    bad["outbound"]["port"] = 0.into();
    assert!(EmbeddedRuntime::from_json(&serde_json::to_vec(&bad).unwrap()).is_err());
}

#[test]
fn status_never_contains_key_material() {
    let runtime = EmbeddedRuntime::from_json(&config(51820, Some(&b64(&PRESHARED)))).unwrap();
    let status = serde_json::to_string(&runtime.status()).unwrap();
    for secret in [
        b64(&CLIENT_KEY),
        b64(&PRESHARED),
        b64(&public_key(PEER_KEY)),
    ] {
        assert!(!status.contains(&secret));
    }
    assert!(!status.contains("127.0.0.1"));
}

#[test]
fn reset_network_moves_the_tunnel_to_a_new_socket() {
    let relay = Relay::start(SocketAddr::from(([127, 0, 0, 1], start_peer(None))));
    // A name, so that the move resolves it again.
    let mut runtime =
        EmbeddedRuntime::from_json(&config_to("localhost", relay.port, None)).unwrap();
    // No tunnel runs yet: nothing to move.
    assert_eq!(control(&runtime, r#"{"cmd":"reset_network"}"#)["reset"], 0);
    let (sink, rx) = capture();
    runtime.start(sink).unwrap();
    round_trip(&runtime, &rx, b"before the network change");
    assert_eq!(relay.clients().len(), 1);

    // The device left that network: its old path drops everything.
    relay.cut();
    assert!(
        !comes_back(&runtime, &rx, b"lost", Duration::from_secs(1)),
        "a cut path still delivered"
    );

    // The client reports the new network. The answer has the fields the
    // client decodes; the tunnel has no connections to close.
    let reset = control(
        &runtime,
        r#"{"cmd":"reset_network","close_connections":true}"#,
    );
    assert_eq!(reset["reset"], 1);
    assert_eq!(reset["closed"], 0);
    round_trip(&runtime, &rx, b"after the network change");
    assert!(relay.clients().len() >= 2, "the tunnel kept its old socket");

    // set_network is accepted and changes nothing; flow commands stay
    // refused.
    let network = control(&runtime, r#"{"cmd":"set_network","type":"cellular"}"#);
    assert_eq!(network["changed"], false);
    let refused = runtime
        .control_json(br#"{"cmd":"connections"}"#)
        .unwrap_err();
    assert_eq!(refused.code, RuntimeErrorCode::InvalidArgument);

    runtime.stop();
    assert_eq!(control(&runtime, r#"{"cmd":"reset_network"}"#)["reset"], 0);
}
