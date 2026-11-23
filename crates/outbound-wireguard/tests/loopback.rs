//! The routable outbound against an in-process WireGuard hub: every client
//! is a peer of the hub, which forwards a packet to the client that owns its
//! destination address and reflects UDP sent to its own address.

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use base64::Engine;
use boringtun::noise::{Tunn, TunnResult};
use boringtun::x25519::{PublicKey, StaticSecret};
use engine_outbound::registry::{OutboundFactory, Settings};
use engine_outbound::{BoxStream, TargetAddr, TcpDialer, TcpOutbound};
use outbound_wireguard::{WireGuardConfig, WireGuardFactory, WireGuardOutbound};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const HUB_KEY: [u8; 32] = [9; 32];
const HUB_V4: &str = "10.7.0.1";
const HUB_V6: &str = "fd00:7::1";
const WAIT: Duration = Duration::from_secs(10);

/// One client of the hub: its key and tunnel addresses.
#[derive(Clone, Copy)]
struct Client {
    key: [u8; 32],
    v4: &'static str,
    v6: &'static str,
}

const A: Client = Client {
    key: [7; 32],
    v4: "10.7.0.2",
    v6: "fd00:7::2",
};
const B: Client = Client {
    key: [5; 32],
    v4: "10.7.0.3",
    v6: "fd00:7::3",
};
const C: Client = Client {
    key: [3; 32],
    v4: "10.7.0.4",
    v6: "fd00:7::4",
};

fn b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

fn public_key(private: [u8; 32]) -> [u8; 32] {
    PublicKey::from(&StaticSecret::from(private)).to_bytes()
}

struct Slot {
    client: Client,
    tunn: Tunn,
    socket: UdpSocket,
    peer: Option<SocketAddr>,
}

/// Starts the hub for `clients` and returns the UDP port of each one.
fn start_hub(clients: &[Client]) -> Vec<u16> {
    let mut slots = Vec::new();
    let mut ports = Vec::new();
    for (index, client) in clients.iter().enumerate() {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        ports.push(socket.local_addr().unwrap().port());
        slots.push(Slot {
            client: *client,
            tunn: Tunn::new(
                StaticSecret::from(HUB_KEY),
                PublicKey::from(public_key(client.key)),
                None,
                None,
                index as u32 + 1,
                None,
            ),
            socket,
            peer: None,
        });
    }
    let receivers: Vec<UdpSocket> = slots
        .iter()
        .map(|slot| slot.socket.try_clone().unwrap())
        .collect();
    let hub = Arc::new(Mutex::new(slots));
    for (index, socket) in receivers.into_iter().enumerate() {
        let hub = hub.clone();
        thread::spawn(move || serve(hub, index, socket));
    }
    ports
}

fn serve(hub: Arc<Mutex<Vec<Slot>>>, index: usize, socket: UdpSocket) {
    let mut datagram = vec![0u8; 65_536];
    let mut out = vec![0u8; 65_536 + 148];
    loop {
        let Ok((len, from)) = socket.recv_from(&mut datagram) else {
            return;
        };
        let mut slots = hub.lock().unwrap();
        slots[index].peer = Some(from);
        let mut input = &datagram[..len];
        loop {
            let packet = match slots[index]
                .tunn
                .decapsulate(Some(from.ip()), input, &mut out)
            {
                TunnResult::WriteToNetwork(reply) => {
                    let _ = socket.send_to(reply, from);
                    input = &[];
                    continue;
                }
                TunnResult::WriteToTunnelV4(packet, _) | TunnResult::WriteToTunnelV6(packet, _) => {
                    packet.to_vec()
                }
                _ => break,
            };
            if !packet.is_empty() {
                route(&mut slots, index, packet);
            }
            break;
        }
    }
}

/// Reflects UDP to the hub's own address; forwards the rest by destination.
fn route(slots: &mut [Slot], from: usize, mut packet: Vec<u8>) {
    let Some(destination) = destination(&packet) else {
        return;
    };
    let target = if destination == HUB_V4.parse::<IpAddr>().unwrap()
        || destination == HUB_V6.parse::<IpAddr>().unwrap()
    {
        if !reflect_udp(&mut packet) {
            return;
        }
        from
    } else {
        match slots.iter().position(|slot| {
            destination == slot.client.v4.parse::<IpAddr>().unwrap()
                || destination == slot.client.v6.parse::<IpAddr>().unwrap()
        }) {
            Some(target) => target,
            None => return,
        }
    };
    let slot = &mut slots[target];
    let Some(peer) = slot.peer else {
        return;
    };
    let mut sealed = vec![0u8; packet.len() + 148];
    if let TunnResult::WriteToNetwork(datagram) = slot.tunn.encapsulate(&packet, &mut sealed) {
        let _ = slot.socket.send_to(datagram, peer);
    }
}

fn destination(packet: &[u8]) -> Option<IpAddr> {
    match packet.first()? >> 4 {
        4 => {
            let bytes: [u8; 4] = packet.get(16..20)?.try_into().ok()?;
            Some(IpAddr::from(bytes))
        }
        6 => {
            let bytes: [u8; 16] = packet.get(24..40)?.try_into().ok()?;
            Some(IpAddr::from(bytes))
        }
        _ => None,
    }
}

/// Swaps the addresses and ports of a UDP packet in place. Both checksums
/// are sums over the swapped fields, so they stay valid.
fn reflect_udp(packet: &mut [u8]) -> bool {
    let (source, destination, udp) = match packet[0] >> 4 {
        4 if packet[9] == 17 => (12, 16, usize::from(packet[0] & 0x0F) * 4),
        6 if packet[6] == 17 => (8, 24, 40),
        _ => return false,
    };
    let width = destination - source;
    if packet.len() < udp + 8 {
        return false;
    }
    for offset in 0..width {
        packet.swap(source + offset, destination + offset);
    }
    for offset in 0..2 {
        packet.swap(udp + offset, udp + 2 + offset);
    }
    true
}

/// A UDP relay in front of one hub port that gives each client address its
/// own upstream socket, like a NAT mapping, so the hub sees a client that
/// moved as a new address. `cut` drops the paths of every client address
/// seen so far, in both directions, like a network the device left.
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

/// A new upstream socket for `client`, with a thread that relays the hub's
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

fn settings(client: Client, port: u16, extra: serde_json::Value) -> Settings {
    let mut value = serde_json::json!({
        "server": "127.0.0.1",
        "port": port,
        "private_key": b64(&client.key),
        "peer_public_key": b64(&public_key(HUB_KEY)),
        "local_address": [format!("{}/32", client.v4), format!("{}/128", client.v6)],
        "allowed_ips": ["10.7.0.0/24", "fd00:7::/64"],
        "persistent_keepalive_secs": 25,
    });
    for (key, field) in extra.as_object().unwrap() {
        value[key] = field.clone();
    }
    value.as_object().unwrap().clone()
}

fn outbound(client: Client, port: u16, extra: serde_json::Value) -> WireGuardOutbound {
    let config: WireGuardConfig =
        serde_json::from_value(serde_json::Value::Object(settings(client, port, extra))).unwrap();
    WireGuardOutbound::new(config.validate().ok().unwrap())
}

fn target(address: &str, port: u16) -> TargetAddr {
    TargetAddr::Ip(SocketAddr::new(address.parse().unwrap(), port))
}

async fn tcp_round_trip(a: &WireGuardOutbound, b: &WireGuardOutbound, address: &str, port: u16) {
    let accept = {
        let b = b.clone();
        tokio::spawn(async move {
            let mut stream = b.accept_tcp(port).await.unwrap();
            let mut buffer = vec![0u8; 64 * 1024];
            loop {
                let read = stream.read(&mut buffer).await.unwrap();
                if read == 0 {
                    break;
                }
                stream.write_all(&buffer[..read]).await.unwrap();
            }
        })
    };
    // Let B listen before A's SYN arrives.
    tokio::time::sleep(Duration::from_millis(200)).await;
    let mut stream = tokio::time::timeout(WAIT, a.connect(&target(address, port)))
        .await
        .expect("connect timed out")
        .unwrap();
    let payload: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
    let (mut reader, mut writer) = tokio::io::split(&mut stream);
    let expected = payload.clone();
    let reading = async move {
        let mut echoed = vec![0u8; expected.len()];
        reader.read_exact(&mut echoed).await.unwrap();
        assert_eq!(echoed, expected);
    };
    let writing = async move {
        writer.write_all(&payload).await.unwrap();
    };
    tokio::time::timeout(WAIT, async { tokio::join!(reading, writing) })
        .await
        .expect("echo timed out");
    drop(stream);
    accept.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tcp_runs_between_two_nodes_over_ipv4_and_ipv6() {
    let ports = start_hub(&[A, B]);
    let a = outbound(A, ports[0], serde_json::json!({}));
    let b = outbound(B, ports[1], serde_json::json!({}));
    tcp_round_trip(&a, &b, B.v4, 7000).await;
    tcp_round_trip(&a, &b, B.v6, 7001).await;
    let health = a.health().unwrap();
    assert_eq!(health["running"], true);
    assert!(health.get("last_handshake_secs").is_some());
}

async fn udp_echo(outbound: &WireGuardOutbound, address: &str, payload: &[u8]) {
    let mut flow = outbound.open_udp(&target(address, 9000)).await.unwrap();
    // The first datagrams may be queued behind the handshake; retry.
    for _ in 0..20 {
        flow.send.send(payload).await.unwrap();
        if let Ok(reply) = tokio::time::timeout(Duration::from_millis(500), flow.recv.recv()).await
        {
            assert_eq!(reply.unwrap(), payload);
            return;
        }
    }
    panic!("udp reply did not come back through the tunnel");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn udp_flows_are_reflected_by_the_peer() {
    let ports = start_hub(&[A]);
    let a = outbound(A, ports[0], serde_json::json!({}));
    udp_echo(&a, HUB_V4, b"udp over wireguard").await;
    udp_echo(&a, HUB_V6, &[0x5a; 1200]).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn destinations_outside_allowed_ips_are_refused() {
    let ports = start_hub(&[A]);
    let a = outbound(
        A,
        ports[0],
        serde_json::json!({"allowed_ips": ["10.7.0.1/32"], "local_address": ["10.7.0.2"]}),
    );
    for address in [B.v4, "192.0.2.1"] {
        let err = match a.connect(&target(address, 80)).await {
            Ok(_) => panic!("{address} is outside allowed_ips"),
            Err(err) => err,
        };
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
        assert!(a.open_udp(&target(address, 53)).await.is_err());
    }
    // No IPv6 address on the interface.
    let err = match a.connect(&target(HUB_V6, 80)).await {
        Ok(_) => panic!("there is no local IPv6 address"),
        Err(err) => err,
    };
    assert_eq!(err.kind(), io::ErrorKind::AddrNotAvailable);
    udp_echo(&a, HUB_V4, b"inside allowed_ips").await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn packets_from_sources_outside_allowed_ips_are_dropped() {
    let ports = start_hub(&[B, C]);
    let b = outbound(B, ports[0], serde_json::json!({}));
    let c = outbound(
        C,
        ports[1],
        serde_json::json!({"allowed_ips": ["10.7.0.1/32"]}),
    );

    // C talks to the hub, so its session is up and its port 5000 is bound.
    let mut flow = c.open_udp_on(5000, &target(HUB_V4, 9000)).await.unwrap();
    let mut up = false;
    for _ in 0..20 {
        flow.send.send(b"hello hub").await.unwrap();
        if let Ok(reply) = tokio::time::timeout(Duration::from_millis(500), flow.recv.recv()).await
        {
            assert_eq!(reply.unwrap(), b"hello hub");
            up = true;
            break;
        }
    }
    assert!(up, "c never reached the hub");

    // B may send to C (B's allowed_ips cover C), but C does not allow B.
    let mut from_b = b.open_udp(&target(C.v4, 5000)).await.unwrap();
    for _ in 0..10 {
        from_b.send.send(b"blocked").await.unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let received = tokio::time::timeout(Duration::from_secs(1), flow.recv.recv()).await;
    assert!(
        received.is_err(),
        "a packet from outside allowed_ips arrived"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn factory_builds_from_settings_and_rejects_bad_ones() {
    let factory = WireGuardFactory;
    assert_eq!(factory.type_name(), "wireguard");
    assert!(!factory.supports_via());
    let dialer = Arc::new(TcpDialer);
    let built = factory
        .build(&settings(A, 51820, serde_json::json!({})), dialer.clone())
        .ok()
        .unwrap();
    assert_eq!(built.protocol(), "wireguard");
    let message = match factory.build(
        &settings(A, 51820, serde_json::json!({"private_key": "c2hvcnQ="})),
        dialer,
    ) {
        Ok(_) => panic!("a short key must be rejected"),
        Err(message) => message,
    };
    assert!(!message.contains("c2hvcnQ"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reset_sessions_moves_the_node_to_a_new_socket() {
    let ports = start_hub(&[A]);
    let relay = Relay::start(SocketAddr::from(([127, 0, 0, 1], ports[0])));
    // A name, so that the move resolves it again.
    let a = outbound(A, relay.port, serde_json::json!({"server": "localhost"}));
    // No session runs before the first connection: nothing to move.
    assert_eq!(a.reset_sessions(), 0);
    udp_echo(&a, HUB_V4, b"before the network change").await;
    assert_eq!(relay.clients().len(), 1);

    // The device left that network: its old path drops everything.
    relay.cut();
    let mut flow = a.open_udp(&target(HUB_V4, 9000)).await.unwrap();
    flow.send.send(b"lost").await.unwrap();
    assert!(
        tokio::time::timeout(Duration::from_secs(1), flow.recv.recv())
            .await
            .is_err(),
        "a cut path still delivered"
    );

    // The client reports the new network: the node resolves the endpoint
    // again, moves to a new socket and handshakes there.
    assert_eq!(a.reset_sessions(), 1);
    udp_echo(&a, HUB_V4, b"after the network change").await;
    assert!(relay.clients().len() >= 2, "the node kept its old socket");
    drop(flow);
}

async fn echo(stream: &mut BoxStream, payload: &[u8]) {
    tokio::time::timeout(WAIT, async {
        stream.write_all(payload).await.unwrap();
        let mut echoed = vec![0u8; payload.len()];
        stream.read_exact(&mut echoed).await.unwrap();
        assert_eq!(echoed, payload);
    })
    .await
    .expect("echo timed out");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn open_connections_survive_a_path_move() {
    let ports = start_hub(&[A, B]);
    let relay = Relay::start(SocketAddr::from(([127, 0, 0, 1], ports[0])));
    let a = outbound(A, relay.port, serde_json::json!({}));
    let b = outbound(B, ports[1], serde_json::json!({}));
    let accept = {
        let b = b.clone();
        tokio::spawn(async move {
            let mut stream = b.accept_tcp(7100).await.unwrap();
            let mut buffer = vec![0u8; 1024];
            loop {
                let read = stream.read(&mut buffer).await.unwrap();
                if read == 0 {
                    break;
                }
                stream.write_all(&buffer[..read]).await.unwrap();
            }
        })
    };
    // Let B listen before A's SYN arrives.
    tokio::time::sleep(Duration::from_millis(200)).await;
    let mut stream = tokio::time::timeout(WAIT, a.connect(&target(B.v4, 7100)))
        .await
        .expect("connect timed out")
        .unwrap();
    echo(&mut stream, b"before the network change").await;

    relay.cut();
    assert_eq!(a.reset_sessions(), 1);
    // The same connection: the session and the stack outlive the socket.
    echo(&mut stream, b"after the network change").await;
    assert!(relay.clients().len() >= 2, "the node kept its old socket");
    drop(stream);
    accept.abort();
}
