//! Packet-level tunnel tests: raw IP packets in, raw IP packets out.

use std::collections::BTreeMap;
use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, UdpSocket};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{self, Receiver};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use config_core::redirect::RedirectTable;
use engine_embedded::config::{DnsConfig, DnsRuleConfig, DnsServerConfig, DnsVia, FakeIpConfig};
use engine_embedded::connections::Dispatcher;
use engine_embedded::dns_policy::DnsPolicy;
use engine_embedded::fake_ip::FakeIpPool;
use engine_embedded::tunnel::{PacketSink, Tunnel, TunnelSettings};
use engine_outbound::reject::{self, RejectAction};
use engine_outbound::{
    BoxFuture, BoxStream, DatagramRecv, DatagramSend, TargetAddr, TcpOutbound, UdpFlow,
};
use etherparse::{PacketBuilder, SlicedPacket, TransportSlice};

const APP: [u8; 4] = [10, 0, 0, 2];
const REMOTE: [u8; 4] = [10, 0, 0, 80];
const DNS: [u8; 4] = [10, 0, 0, 53];
const WAIT: Duration = Duration::from_secs(10);

/// Test outbound that sends every flow to one local server, whatever the target.
struct Redirect(SocketAddr);

impl TcpOutbound for Redirect {
    fn protocol(&self) -> &'static str {
        "test-redirect"
    }

    fn connect<'a>(&'a self, _target: &'a TargetAddr) -> BoxFuture<'a, io::Result<BoxStream>> {
        Box::pin(async move {
            let stream = tokio::net::TcpStream::connect(self.0).await?;
            Ok(Box::new(stream) as BoxStream)
        })
    }
}

/// Test outbound whose UDP flows all go to one local UDP server.
struct UdpRedirect(SocketAddr);

impl TcpOutbound for UdpRedirect {
    fn protocol(&self) -> &'static str {
        "test-udp-redirect"
    }

    fn connect<'a>(&'a self, _target: &'a TargetAddr) -> BoxFuture<'a, io::Result<BoxStream>> {
        Box::pin(async { Err(io::Error::other("test outbound carries udp only")) })
    }

    fn open_udp<'a>(&'a self, _target: &'a TargetAddr) -> BoxFuture<'a, io::Result<UdpFlow>> {
        Box::pin(async move {
            let socket = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await?);
            socket.connect(self.0).await?;
            Ok(UdpFlow::new(
                Box::new(SocketSend(socket.clone())),
                Box::new(SocketRecv(socket)),
            ))
        })
    }
}

struct SocketSend(Arc<tokio::net::UdpSocket>);

impl DatagramSend for SocketSend {
    fn send<'a>(&'a mut self, payload: &'a [u8]) -> BoxFuture<'a, io::Result<()>> {
        Box::pin(async move { self.0.send(payload).await.map(|_| ()) })
    }
}

struct SocketRecv(Arc<tokio::net::UdpSocket>);

impl DatagramRecv for SocketRecv {
    fn recv(&mut self) -> BoxFuture<'_, io::Result<Vec<u8>>> {
        Box::pin(async move {
            let mut buf = vec![0u8; 2048];
            let n = self.0.recv(&mut buf).await?;
            buf.truncate(n);
            Ok(buf)
        })
    }
}

/// Answers every datagram with `echo:` and the payload.
fn start_udp_echo_server() -> SocketAddr {
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    let addr = socket.local_addr().unwrap();
    thread::spawn(move || {
        let mut buf = [0u8; 2048];
        while let Ok((n, peer)) = socket.recv_from(&mut buf) {
            let mut reply = b"echo:".to_vec();
            reply.extend_from_slice(&buf[..n]);
            let _ = socket.send_to(&reply, peer);
        }
    });
    addr
}

fn settings() -> TunnelSettings {
    TunnelSettings {
        mtu: 1500,
        tcp_window_bytes: 64 * 1024,
        max_tcp_connections: 8,
        max_udp_flows: 256,
        tcp_evict_idle: Duration::from_secs(30),
        udp_evict_idle: Duration::from_secs(15),
        max_dns_in_flight: 4,
        idle_timeout: Duration::from_secs(30),
        connect_timeout: Duration::from_secs(5),
        dns: Arc::new(DnsPolicy::tcp(
            SocketAddr::from((Ipv4Addr::new(1, 1, 1, 1), 53)),
            Duration::from_secs(5),
        )),
        worker_threads: 1,
    }
}

fn capture() -> (PacketSink, Receiver<Vec<u8>>) {
    let (tx, rx) = mpsc::channel();
    let tx = Mutex::new(tx);
    let sink: PacketSink = Box::new(move |packet: &[u8]| {
        let _ = tx.lock().unwrap().send(packet.to_vec());
    });
    (sink, rx)
}

/// Waits for the first emitted packet accepted by `pick`.
fn wait_for<T>(rx: &Receiver<Vec<u8>>, mut pick: impl FnMut(&SlicedPacket<'_>) -> Option<T>) -> T {
    let deadline = Instant::now() + WAIT;
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        let packet = rx
            .recv_timeout(left)
            .expect("expected packet was not emitted");
        if let Ok(sliced) = SlicedPacket::from_ip(&packet) {
            if let Some(found) = pick(&sliced) {
                return found;
            }
        }
    }
}

fn start_echo_server() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { return };
            thread::spawn(move || {
                let mut buf = [0u8; 1024];
                while let Ok(n) = stream.read(&mut buf) {
                    if n == 0 || stream.write_all(&buf[..n]).is_err() {
                        break;
                    }
                }
            });
        }
    });
    addr
}

/// DNS-over-TCP server that answers each query with the query itself, QR bit set.
fn start_dns_server() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { return };
            thread::spawn(move || {
                let mut length = [0u8; 2];
                if stream.read_exact(&mut length).is_err() {
                    return;
                }
                let mut query = vec![0u8; usize::from(u16::from_be_bytes(length))];
                if stream.read_exact(&mut query).is_err() {
                    return;
                }
                query[2] |= 0x80;
                let _ = stream.write_all(&length);
                let _ = stream.write_all(&query);
            });
        }
    });
    addr
}

fn dns_query() -> Vec<u8> {
    let mut query = vec![
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    query.extend_from_slice(b"\x07example\x03com\x00\x00\x01\x00\x01");
    query
}

#[test]
fn udp_dns_query_is_answered_over_tcp() {
    let dns_server = start_dns_server();
    let (sink, rx) = capture();
    let mut tunnel = Tunnel::start(settings(), Arc::new(Redirect(dns_server)), sink).unwrap();

    let query = dns_query();
    let mut packet = Vec::new();
    PacketBuilder::ipv4(APP, DNS, 64)
        .udp(5353, 53)
        .write(&mut packet, &query)
        .unwrap();
    assert!(tunnel.input_packet(&packet));

    let response = wait_for(&rx, |sliced| match &sliced.transport {
        Some(TransportSlice::Udp(udp)) if udp.destination_port() == 5353 => {
            assert_eq!(udp.source_port(), 53);
            Some(udp.payload().to_vec())
        }
        _ => None,
    });
    assert_eq!(&response[..2], &query[..2]);
    assert_eq!(response[2] & 0x80, 0x80);
    assert_eq!(&response[3..], &query[3..]);

    let stats = tunnel.stats();
    assert_eq!(stats.dns_queries, 1);
    assert_eq!(stats.dns_failed, 0);
    assert_eq!(stats.dns_last_failure, None);
    tunnel.stop();
    tunnel.stop();
}

/// Server that accepts and closes every connection, like a proxy that drops a
/// request it cannot authenticate.
fn start_closing_server() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    thread::spawn(move || {
        for stream in listener.incoming() {
            drop(stream);
        }
    });
    addr
}

#[test]
fn dns_failure_reports_its_stage() {
    let (sink, _rx) = capture();
    let mut tunnel =
        Tunnel::start(settings(), Arc::new(Redirect(start_closing_server())), sink).unwrap();

    let mut packet = Vec::new();
    PacketBuilder::ipv4(APP, DNS, 64)
        .udp(5353, 53)
        .write(&mut packet, &dns_query())
        .unwrap();
    assert!(tunnel.input_packet(&packet));

    let deadline = Instant::now() + WAIT;
    while tunnel.stats().dns_failed == 0 {
        assert!(Instant::now() < deadline, "DNS query should fail");
        thread::sleep(Duration::from_millis(20));
    }
    assert_eq!(tunnel.stats().dns_last_failure, Some("reply_closed"));
    tunnel.stop();
}

/// Sends `query` from the app to the tunnel's DNS address and returns the
/// reply it emits.
fn ask(tunnel: &Tunnel, rx: &Receiver<Vec<u8>>, query: &[u8]) -> Vec<u8> {
    let mut packet = Vec::new();
    PacketBuilder::ipv4(APP, DNS, 64)
        .udp(5353, 53)
        .write(&mut packet, query)
        .unwrap();
    assert!(tunnel.input_packet(&packet));
    wait_for(rx, |sliced| match &sliced.transport {
        Some(TransportSlice::Udp(udp)) if udp.destination_port() == 5353 => {
            Some(udp.payload().to_vec())
        }
        _ => None,
    })
}

/// DNS-over-TCP server that answers every query on a connection (the query
/// itself, QR bit set) and counts connections and queries.
fn start_counting_dns_server() -> (SocketAddr, Arc<(AtomicUsize, AtomicUsize)>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let counts = Arc::new((AtomicUsize::new(0), AtomicUsize::new(0)));
    let server_counts = counts.clone();
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { return };
            server_counts.0.fetch_add(1, Ordering::SeqCst);
            let counts = server_counts.clone();
            thread::spawn(move || loop {
                let mut length = [0u8; 2];
                if stream.read_exact(&mut length).is_err() {
                    return;
                }
                let mut query = vec![0u8; usize::from(u16::from_be_bytes(length))];
                if stream.read_exact(&mut query).is_err() {
                    return;
                }
                counts.1.fetch_add(1, Ordering::SeqCst);
                query[2] |= 0x80;
                let _ = stream.write_all(&length);
                let _ = stream.write_all(&query);
            });
        }
    });
    (addr, counts)
}

#[test]
fn dns_answers_are_cached_and_connections_kept() {
    let (server, counts) = start_counting_dns_server();
    let (sink, rx) = capture();
    let mut tunnel = Tunnel::start(settings(), Arc::new(Redirect(server)), sink).unwrap();

    let first = dns_query();
    let response = ask(&tunnel, &rx, &first);
    assert_eq!(&response[..2], &first[..2]);

    // The same question again, another id and letter case: from the cache.
    let mut again = dns_query();
    again[..2].copy_from_slice(&[0x56, 0x78]);
    again[13] = b'E';
    let response = ask(&tunnel, &rx, &again);
    assert_eq!(&response[..2], &[0x56, 0x78]);
    assert_eq!(&response[12..again.len()], &again[12..]);
    assert_eq!(counts.1.load(Ordering::SeqCst), 1, "one query upstream");
    assert_eq!(tunnel.stats().dns_cached, 1);

    // Another name goes upstream on the kept connection.
    let mut other = dns_query();
    other[..2].copy_from_slice(&[0x9a, 0xbc]);
    other[13] = b'x';
    let response = ask(&tunnel, &rx, &other);
    assert_eq!(&response[..2], &[0x9a, 0xbc]);
    assert_eq!(counts.1.load(Ordering::SeqCst), 2);
    assert_eq!(counts.0.load(Ordering::SeqCst), 1, "connection reused");
    let stats = tunnel.stats();
    assert_eq!(stats.dns_queries, 3);
    assert_eq!(stats.dns_failed, 0);
    tunnel.stop();
}

#[test]
fn dns_hosts_are_answered_without_the_outbound() {
    let config = DnsConfig {
        hosts: BTreeMap::from([(
            "example.com".to_string(),
            vec!["192.0.2.7".parse().unwrap()],
        )]),
        ..DnsConfig::default()
    };
    let settings = TunnelSettings {
        dns: Arc::new(DnsPolicy::from_config(&config).unwrap()),
        ..settings()
    };
    let (sink, rx) = capture();
    let mut tunnel =
        Tunnel::start(settings, Arc::new(Redirect(start_closing_server())), sink).unwrap();

    let response = ask(&tunnel, &rx, &dns_query());
    assert_eq!(&response[..2], &[0x12, 0x34]);
    assert_eq!(&response[6..8], &[0, 1], "one answer");
    assert!(response.ends_with(&[192, 0, 2, 7]));
    let stats = tunnel.stats();
    assert_eq!(stats.dns_queries, 1);
    assert_eq!(stats.dns_failed, 0);
    tunnel.stop();
}

#[test]
fn dns_rules_send_names_to_a_direct_server() {
    let local = start_dns_server();
    let config = DnsConfig {
        servers: vec![
            DnsServerConfig {
                name: "remote".into(),
                url: "tcp://8.8.8.8".into(),
                server_name: None,
                via: DnsVia::Proxy,
            },
            DnsServerConfig {
                name: "local".into(),
                url: format!("tcp://{local}"),
                server_name: None,
                via: DnsVia::Direct,
            },
        ],
        rules: vec![DnsRuleConfig {
            domain_suffix: vec!["com".into()],
            server: "local".into(),
            ..DnsRuleConfig::default()
        }],
        ..DnsConfig::default()
    };
    let settings = TunnelSettings {
        dns: Arc::new(DnsPolicy::from_config(&config).unwrap()),
        ..settings()
    };
    let (sink, rx) = capture();
    // The proxy drops everything; only the direct server can answer.
    let mut tunnel =
        Tunnel::start(settings, Arc::new(Redirect(start_closing_server())), sink).unwrap();

    let query = dns_query();
    let response = ask(&tunnel, &rx, &query);
    assert_eq!(&response[..2], &query[..2]);
    assert_eq!(response[2] & 0x80, 0x80);
    assert_eq!(tunnel.stats().dns_failed, 0);
    tunnel.stop();
}

/// A DNS over UDP server answering every query with 10.9.8.7.
fn start_udp_dns_server() -> SocketAddr {
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    let addr = socket.local_addr().unwrap();
    thread::spawn(move || {
        let mut buf = [0u8; 1500];
        while let Ok((len, from)) = socket.recv_from(&mut buf) {
            let mut answer = buf[..len].to_vec();
            answer[2] |= 0x80;
            answer[3] = 0x80;
            answer[7] = 1;
            answer.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 10, 9, 8, 7]);
            let _ = socket.send_to(&answer, from);
        }
    });
    addr
}

#[test]
fn system_servers_are_asked_directly_when_the_proxy_fails() {
    let system = start_udp_dns_server();
    let config = DnsConfig {
        servers: vec![
            DnsServerConfig {
                name: "remote".into(),
                url: "tcp://8.8.8.8".into(),
                server_name: None,
                via: DnsVia::Proxy,
            },
            DnsServerConfig {
                name: "sys".into(),
                url: "system".into(),
                server_name: None,
                // Ignored: the device's resolvers are always reached directly.
                via: DnsVia::Proxy,
            },
        ],
        fallback: Some("sys".into()),
        system_servers: vec![system.to_string()],
        ..DnsConfig::default()
    };
    let settings = TunnelSettings {
        dns: Arc::new(DnsPolicy::from_config(&config).unwrap()),
        ..settings()
    };
    let (sink, rx) = capture();
    // The proxy drops everything: only the fallback to the system servers answers.
    let mut tunnel =
        Tunnel::start(settings, Arc::new(Redirect(start_closing_server())), sink).unwrap();

    let query = dns_query();
    let response = ask(&tunnel, &rx, &query);
    assert_eq!(&response[..2], &query[..2]);
    assert!(response.ends_with(&[10, 9, 8, 7]));
    assert_eq!(tunnel.stats().dns_failed, 0);
    tunnel.stop();
}

#[test]
fn quic_is_refused_with_icmp_when_the_outbound_has_no_udp() {
    let (sink, rx) = capture();
    let mut tunnel =
        Tunnel::start(settings(), Arc::new(Redirect(start_echo_server())), sink).unwrap();
    let mut packet = Vec::new();
    PacketBuilder::ipv4(APP, REMOTE, 64)
        .udp(40002, 443)
        .write(&mut packet, &[0xc0; 1200])
        .unwrap();
    assert!(tunnel.input_packet(&packet));

    let quoted = wait_for(&rx, |sliced| match &sliced.transport {
        Some(TransportSlice::Icmpv4(icmp)) => Some(icmp.slice().to_vec()),
        _ => None,
    });
    assert_eq!(&quoted[..2], &[3, 3], "port unreachable");
    // The quoted IPv4 header and UDP ports name the refused flow.
    assert_eq!(&quoted[8 + 12..8 + 16], &APP);
    assert_eq!(&quoted[8 + 16..8 + 20], &REMOTE);
    assert_eq!(&quoted[8 + 20..8 + 22], &40002u16.to_be_bytes());
    assert_eq!(&quoted[8 + 22..8 + 24], &443u16.to_be_bytes());
    tunnel.stop();
}

#[test]
fn udp_is_dropped_when_the_outbound_has_no_udp() {
    let (sink, _rx) = capture();
    let mut tunnel =
        Tunnel::start(settings(), Arc::new(Redirect(start_echo_server())), sink).unwrap();
    let mut packet = Vec::new();
    PacketBuilder::ipv4(APP, REMOTE, 64)
        .udp(40001, 443)
        .write(&mut packet, b"quic")
        .unwrap();
    assert!(tunnel.input_packet(&packet));

    let deadline = Instant::now() + WAIT;
    while tunnel.stats().udp_dropped == 0 {
        assert!(
            Instant::now() < deadline,
            "UDP/443 should be counted as dropped"
        );
        thread::sleep(Duration::from_millis(20));
    }
    assert_eq!(tunnel.stats().udp_failed, 1);
    assert_eq!(tunnel.stats().udp_flows, 0);
    tunnel.stop();
}

#[test]
fn udp_flow_is_relayed_through_the_outbound() {
    let echo = start_udp_echo_server();
    let (sink, rx) = capture();
    let mut tunnel = Tunnel::start(settings(), Arc::new(UdpRedirect(echo)), sink).unwrap();

    for payload in [&b"first"[..], &b"second"[..]] {
        let mut packet = Vec::new();
        PacketBuilder::ipv4(APP, REMOTE, 64)
            .udp(40001, 443)
            .write(&mut packet, payload)
            .unwrap();
        assert!(tunnel.input_packet(&packet));

        let mut expected = b"echo:".to_vec();
        expected.extend_from_slice(payload);
        wait_for(&rx, |sliced| match (&sliced.net, &sliced.transport) {
            (Some(etherparse::NetSlice::Ipv4(ip)), Some(TransportSlice::Udp(udp)))
                if udp.source_port() == 443
                    && udp.destination_port() == 40001
                    && udp.payload() == expected.as_slice() =>
            {
                assert_eq!(ip.header().source(), REMOTE);
                assert_eq!(ip.header().destination(), APP);
                Some(())
            }
            _ => None,
        });
    }
    // Both datagrams shared one flow.
    assert_eq!(tunnel.stats().udp_flows, 1);
    assert_eq!(tunnel.stats().udp_dropped, 0);
    tunnel.stop();
}

/// `packet`, an IPv4 packet without options, split into fragments of `chunk`
/// payload bytes (a multiple of 8), as the system splits a datagram larger
/// than the MTU.
fn fragments(packet: &[u8], chunk: usize) -> Vec<Vec<u8>> {
    let payload = &packet[20..];
    let count = payload.len().div_ceil(chunk);
    payload
        .chunks(chunk)
        .enumerate()
        .map(|(index, piece)| {
            let mut fragment = packet[..20].to_vec();
            fragment.extend_from_slice(piece);
            let total_len = (20 + piece.len()) as u16;
            fragment[2..4].copy_from_slice(&total_len.to_be_bytes());
            // More Fragments on all but the last; the offset counts 8 bytes.
            let more = if index + 1 < count { 0x2000 } else { 0 };
            let flags = more | (index * chunk / 8) as u16;
            fragment[6..8].copy_from_slice(&flags.to_be_bytes());
            fragment[10..12].fill(0);
            let checksum = ipv4_checksum(&fragment[..20]);
            fragment[10..12].copy_from_slice(&checksum.to_be_bytes());
            fragment
        })
        .collect()
}

fn ipv4_checksum(header: &[u8]) -> u16 {
    let mut sum: u32 = header
        .chunks(2)
        .map(|pair| u32::from(u16::from_be_bytes([pair[0], pair[1]])))
        .sum();
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

#[test]
fn a_fragmented_udp_datagram_is_relayed_whole() {
    let echo = start_udp_echo_server();
    let (sink, rx) = capture();
    let mut tunnel = Tunnel::start(settings(), Arc::new(UdpRedirect(echo)), sink).unwrap();

    // Larger than the MTU: it comes in two fragments, here the last first.
    let payload = vec![7u8; 2000];
    let pieces = fragments(&udp_to_remote(40002, &payload), 1480);
    assert_eq!(pieces.len(), 2);
    for piece in pieces.iter().rev() {
        assert!(tunnel.input_packet(piece));
    }
    echoed(&rx, 40002, &payload);

    let stats = tunnel.stats();
    assert_eq!(stats.udp_reassembled, 1);
    assert_eq!(stats.udp_flows, 1);
    assert_eq!(stats.ip_fragments_dropped, 0);
    tunnel.stop();
}

#[test]
fn a_malformed_or_fragmented_udp_packet_leaves_dns_working() {
    let (sink, rx) = capture();
    let mut tunnel =
        Tunnel::start(settings(), Arc::new(Redirect(start_dns_server())), sink).unwrap();

    // A UDP length field that counts more than the packet carries.
    let mut malformed = Vec::new();
    PacketBuilder::ipv4(APP, DNS, 64)
        .udp(5353, 53)
        .write(&mut malformed, &dns_query())
        .unwrap();
    malformed[24..26].copy_from_slice(&1000u16.to_be_bytes());
    assert!(tunnel.input_packet(&malformed));
    // The first fragment of a datagram whose other fragment never comes.
    let orphan = fragments(&udp_to_remote(40003, &[1; 2000]), 1480).remove(0);
    assert!(tunnel.input_packet(&orphan));

    let query = dns_query();
    let response = ask(&tunnel, &rx, &query);
    assert_eq!(&response[..2], &query[..2]);
    assert_eq!(response[2] & 0x80, 0x80);

    let stats = tunnel.stats();
    assert_eq!(stats.udp_malformed, 1);
    assert_eq!(stats.udp_reassembled, 0);
    assert_eq!(stats.dns_queries, 1);
    tunnel.stop();
}

/// DNS-over-TCP server like [`start_dns_server`], except that it pads the
/// answer about `example.com` to the largest DNS message, more than one UDP
/// datagram carries.
fn start_oversized_dns_server() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { return };
            thread::spawn(move || {
                let mut length = [0u8; 2];
                if stream.read_exact(&mut length).is_err() {
                    return;
                }
                let mut answer = vec![0u8; usize::from(u16::from_be_bytes(length))];
                if stream.read_exact(&mut answer).is_err() {
                    return;
                }
                answer[2] |= 0x80;
                if answer.windows(5).any(|name| name == b"\x03com\x00") {
                    answer.resize(usize::from(u16::MAX), 0);
                }
                let _ = stream.write_all(&(answer.len() as u16).to_be_bytes());
                let _ = stream.write_all(&answer);
            });
        }
    });
    addr
}

#[test]
fn an_answer_too_large_for_one_packet_leaves_dns_working() {
    let (sink, rx) = capture();
    let mut tunnel = Tunnel::start(
        settings(),
        Arc::new(Redirect(start_oversized_dns_server())),
        sink,
    )
    .unwrap();

    let mut packet = Vec::new();
    PacketBuilder::ipv4(APP, DNS, 64)
        .udp(5353, 53)
        .write(&mut packet, &dns_query())
        .unwrap();
    assert!(tunnel.input_packet(&packet));
    let deadline = Instant::now() + WAIT;
    while tunnel.stats().udp_unsendable == 0 {
        assert!(
            Instant::now() < deadline,
            "the answer too large for one packet should be counted"
        );
        thread::sleep(Duration::from_millis(20));
    }

    // The answer about another name still goes out.
    let mut query = vec![
        0x56, 0x78, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    query.extend_from_slice(b"\x07example\x03net\x00\x00\x01\x00\x01");
    let response = ask(&tunnel, &rx, &query);
    assert_eq!(&response[..2], &query[..2]);
    assert_eq!(response.len(), query.len());
    assert_eq!(tunnel.stats().udp_unsendable, 1);
    tunnel.stop();
}

/// Test outbound whose UDP flows go to their target, as DIRECT does.
struct UdpToTarget;

impl TcpOutbound for UdpToTarget {
    fn protocol(&self) -> &'static str {
        "test-udp-to-target"
    }

    fn connect<'a>(&'a self, _target: &'a TargetAddr) -> BoxFuture<'a, io::Result<BoxStream>> {
        Box::pin(async { Err(io::Error::other("test outbound carries udp only")) })
    }

    fn open_udp<'a>(&'a self, target: &'a TargetAddr) -> BoxFuture<'a, io::Result<UdpFlow>> {
        Box::pin(async move {
            let TargetAddr::Ip(addr) = target else {
                return Err(io::Error::other("test outbound needs an address"));
            };
            let socket = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await?);
            socket.connect(addr).await?;
            Ok(UdpFlow::new(
                Box::new(SocketSend(socket.clone())),
                Box::new(SocketRecv(socket)),
            ))
        })
    }
}

#[test]
fn redirected_udp_replies_come_from_the_original_destination() {
    let echo = start_udp_echo_server();
    let (sink, rx) = capture();
    let redirects = RedirectTable::parse(&[format!("IP-CIDR,10.0.0.80/32,{echo}")]).unwrap();
    let dispatcher = Arc::new(Dispatcher::single(Arc::new(UdpToTarget)).with_redirects(redirects));
    let mut tunnel =
        Tunnel::start_with_dispatcher(settings(), dispatcher.clone(), None, None, sink).unwrap();

    let mut packet = Vec::new();
    PacketBuilder::ipv4(APP, REMOTE, 64)
        .udp(40003, 7000)
        .write(&mut packet, b"login")
        .unwrap();
    assert!(tunnel.input_packet(&packet));

    wait_for(&rx, |sliced| match (&sliced.net, &sliced.transport) {
        (Some(etherparse::NetSlice::Ipv4(ip)), Some(TransportSlice::Udp(udp)))
            if udp.destination_port() == 40003 && udp.payload() == b"echo:login" =>
        {
            // The app sees the server it asked for, not the dev server.
            assert_eq!(ip.header().source(), REMOTE);
            assert_eq!(udp.source_port(), 7000);
            Some(())
        }
        _ => None,
    });
    let list = dispatcher.tracker().connections();
    assert_eq!(list.active[0].destination, "10.0.0.80:7000");
    assert_eq!(
        list.active[0].redirect.as_ref().unwrap().destination,
        echo.to_string()
    );
    tunnel.stop();
}

#[test]
fn tcp_flow_is_relayed_through_the_outbound() {
    let echo = start_echo_server();
    let (sink, rx) = capture();
    let mut tunnel = Tunnel::start(settings(), Arc::new(Redirect(echo)), sink).unwrap();

    let client_isn: u32 = 1000;
    let mut syn = Vec::new();
    PacketBuilder::ipv4(APP, REMOTE, 64)
        .tcp(40000, 80, client_isn, 65535)
        .syn()
        .write(&mut syn, &[])
        .unwrap();
    assert!(tunnel.input_packet(&syn));

    let server_isn = wait_for(&rx, |sliced| match &sliced.transport {
        Some(TransportSlice::Tcp(tcp))
            if tcp.syn() && tcp.ack() && tcp.destination_port() == 40000 =>
        {
            Some(tcp.sequence_number())
        }
        _ => None,
    });

    let mut data = Vec::new();
    PacketBuilder::ipv4(APP, REMOTE, 64)
        .tcp(40000, 80, client_isn + 1, 65535)
        .ack(server_isn.wrapping_add(1))
        .psh()
        .write(&mut data, b"ping")
        .unwrap();
    assert!(tunnel.input_packet(&data));

    let echoed = wait_for(&rx, |sliced| match &sliced.transport {
        Some(TransportSlice::Tcp(tcp))
            if tcp.destination_port() == 40000 && !tcp.payload().is_empty() =>
        {
            Some(tcp.payload().to_vec())
        }
        _ => None,
    });
    assert_eq!(echoed, b"ping");

    let stats = tunnel.stats();
    assert_eq!(stats.tcp_total, 1);
    assert_eq!(stats.tcp_connect_failed, 0);
    tunnel.stop();
}

/// Test outbound that records each target and sends the flow to one server.
struct RecordingRedirect(SocketAddr, Arc<Mutex<Vec<TargetAddr>>>);

impl TcpOutbound for RecordingRedirect {
    fn protocol(&self) -> &'static str {
        "test-recording"
    }

    fn connect<'a>(&'a self, target: &'a TargetAddr) -> BoxFuture<'a, io::Result<BoxStream>> {
        self.1.lock().unwrap().push(target.clone());
        Box::pin(async move {
            let stream = tokio::net::TcpStream::connect(self.0).await?;
            Ok(Box::new(stream) as BoxStream)
        })
    }
}

#[test]
fn fake_ip_answers_dns_and_sends_the_flow_by_name() {
    let pool = FakeIpPool::from_config(&FakeIpConfig {
        enabled: true,
        ..FakeIpConfig::default()
    })
    .unwrap()
    .unwrap();
    let targets = Arc::new(Mutex::new(Vec::new()));
    let outbound = Arc::new(RecordingRedirect(start_echo_server(), targets.clone()));
    let dispatcher = Arc::new(Dispatcher::single(outbound).with_fake_ip(Some(pool)));
    let (sink, rx) = capture();
    let mut tunnel =
        Tunnel::start_with_dispatcher(settings(), dispatcher, None, None, sink).unwrap();

    // example.com gets a fake address at once, without the upstream.
    let response = ask(&tunnel, &rx, &dns_query());
    assert_eq!(&response[..2], &[0x12, 0x34]);
    assert_eq!(&response[6..8], &[0, 1], "one answer");
    let fake: [u8; 4] = response[response.len() - 4..].try_into().unwrap();
    assert_eq!(&fake[..2], &[198, 18]);
    assert_eq!(
        &response[response.len() - 10..response.len() - 6],
        &[0, 0, 0, 1]
    );
    let stats = tunnel.stats();
    assert_eq!(stats.dns_queries, 1);
    assert_eq!(stats.dns_fake, 1);

    // A plain TCP flow (nothing to sniff) to the fake address leaves by name.
    let client_isn: u32 = 7000;
    let mut syn = Vec::new();
    PacketBuilder::ipv4(APP, fake, 64)
        .tcp(40100, 22, client_isn, 65535)
        .syn()
        .write(&mut syn, &[])
        .unwrap();
    assert!(tunnel.input_packet(&syn));
    let server_isn = wait_for(&rx, |sliced| match &sliced.transport {
        Some(TransportSlice::Tcp(tcp))
            if tcp.syn() && tcp.ack() && tcp.destination_port() == 40100 =>
        {
            Some(tcp.sequence_number())
        }
        _ => None,
    });
    let mut data = Vec::new();
    PacketBuilder::ipv4(APP, fake, 64)
        .tcp(40100, 22, client_isn + 1, 65535)
        .ack(server_isn.wrapping_add(1))
        .psh()
        .write(&mut data, b"SSH-2.0-test\r\n")
        .unwrap();
    assert!(tunnel.input_packet(&data));
    let echoed = wait_for(&rx, |sliced| match &sliced.transport {
        Some(TransportSlice::Tcp(tcp))
            if tcp.destination_port() == 40100 && !tcp.payload().is_empty() =>
        {
            Some(tcp.payload().to_vec())
        }
        _ => None,
    });
    assert_eq!(echoed, b"SSH-2.0-test\r\n");
    assert_eq!(
        *targets.lock().unwrap(),
        vec![TargetAddr::Domain("example.com".to_string(), 22)]
    );
    tunnel.stop();
}

/// Server that answers the first bytes of each connection with `pong` and
/// closes, so the tunnel's side sends its FIN first (and so ends in TIME-WAIT).
fn start_answer_and_close_server() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { return };
            thread::spawn(move || {
                let mut buf = [0u8; 64];
                if stream.read(&mut buf).unwrap_or(0) > 0 {
                    let _ = stream.write_all(b"pong");
                }
            });
        }
    });
    addr
}

/// A short connection the tunnel closes first is released right after the
/// app's FIN, not after smoltcp's 10 s TIME-WAIT: the relay ends at once
/// (its outbound and buffers go) and the socket, with its two windows of
/// buffers, is gone shortly after. Hundreds of such connections in
/// a burst used to keep ~140 KiB each alive for 10 s (88 MiB peak for 600).
#[test]
fn a_short_connection_closed_by_the_tunnel_is_released_promptly() {
    let server = start_answer_and_close_server();
    let (sink, rx) = capture();
    let mut tunnel = Tunnel::start(settings(), Arc::new(Redirect(server)), sink).unwrap();

    let client_isn: u32 = 7000;
    let mut syn = Vec::new();
    PacketBuilder::ipv4(APP, REMOTE, 64)
        .tcp(40100, 80, client_isn, 65535)
        .syn()
        .write(&mut syn, &[])
        .unwrap();
    assert!(tunnel.input_packet(&syn));
    let server_isn = wait_for(&rx, |sliced| match &sliced.transport {
        Some(TransportSlice::Tcp(tcp))
            if tcp.syn() && tcp.ack() && tcp.destination_port() == 40100 =>
        {
            Some(tcp.sequence_number())
        }
        _ => None,
    });

    let mut request = Vec::new();
    PacketBuilder::ipv4(APP, REMOTE, 64)
        .tcp(40100, 80, client_isn + 1, 65535)
        .ack(server_isn.wrapping_add(1))
        .psh()
        .write(&mut request, b"ping")
        .unwrap();
    assert!(tunnel.input_packet(&request));

    // The answer and the tunnel's FIN, in one segment or several.
    let mut answer = Vec::new();
    let fin_end = wait_for(&rx, |sliced| match &sliced.transport {
        Some(TransportSlice::Tcp(tcp)) if tcp.destination_port() == 40100 => {
            answer.extend_from_slice(tcp.payload());
            tcp.fin().then(|| {
                tcp.sequence_number()
                    .wrapping_add(tcp.payload().len() as u32)
                    .wrapping_add(1)
            })
        }
        _ => None,
    });
    assert_eq!(answer, b"pong");

    // The app acknowledges everything and closes its side: the tunnel's
    // socket goes to TIME-WAIT.
    let client_fin_seq = client_isn + 1 + 4;
    let mut fin = Vec::new();
    PacketBuilder::ipv4(APP, REMOTE, 64)
        .tcp(40100, 80, client_fin_seq, 65535)
        .ack(fin_end)
        .fin()
        .write(&mut fin, &[])
        .unwrap();
    assert!(tunnel.input_packet(&fin));
    let closed_at = Instant::now();

    // The relay ends without waiting for TIME-WAIT.
    while tunnel.stats().tcp_active != 0 {
        assert!(
            closed_at.elapsed() < Duration::from_secs(3),
            "relay still active {:?} after both FINs",
            closed_at.elapsed()
        );
        thread::sleep(Duration::from_millis(20));
    }

    // After the short TIME-WAIT the socket is gone: a retransmitted FIN no
    // longer matches a socket and is answered with a RST.
    thread::sleep(Duration::from_millis(2500));
    while rx.try_recv().is_ok() {}
    assert!(tunnel.input_packet(&fin));
    let reset = wait_for(&rx, |sliced| match &sliced.transport {
        Some(TransportSlice::Tcp(tcp)) if tcp.destination_port() == 40100 => Some(tcp.rst()),
        _ => None,
    });
    assert!(
        reset,
        "the socket was still in TIME-WAIT 2.5 s after closing"
    );
    tunnel.stop();
}

/// Interceptor that decrypts nothing over TCP here but names the hosts whose
/// QUIC it refuses, as HTTPS decryption does for its `[MITM]` hosts.
struct RefusesQuic(&'static [&'static str]);

impl engine_embedded::tunnel::FlowInterceptor for RefusesQuic {
    fn claim(&self, _first: &[u8], _target: SocketAddr) -> Option<String> {
        None
    }

    fn refuses_quic(&self, host: &str) -> bool {
        self.0.contains(&host)
    }

    fn serve<'a>(
        &'a self,
        _flow: engine_embedded::tunnel::InterceptedFlow,
        _outbound: &'a dyn TcpOutbound,
        _settings: &'a TunnelSettings,
        _stats: &'a engine_embedded::tunnel::TunnelStats,
    ) -> BoxFuture<'a, ()> {
        Box::pin(async {})
    }
}

fn quic_tunnel(decrypted: &'static [&'static str]) -> (Tunnel, Arc<Dispatcher>, Receiver<Vec<u8>>) {
    let echo = start_udp_echo_server();
    let dispatcher = Arc::new(Dispatcher::single(Arc::new(UdpRedirect(echo))));
    let (sink, rx) = capture();
    let tunnel = Tunnel::start_with_dispatcher(
        settings(),
        dispatcher.clone(),
        Some(Arc::new(RefusesQuic(decrypted))),
        None,
        sink,
    )
    .unwrap();
    (tunnel, dispatcher, rx)
}

fn udp_to_remote(port: u16, payload: &[u8]) -> Vec<u8> {
    let mut packet = Vec::new();
    PacketBuilder::ipv4(APP, REMOTE, 64)
        .udp(port, 443)
        .write(&mut packet, payload)
        .unwrap();
    packet
}

fn icmp_port_unreachable(rx: &Receiver<Vec<u8>>, port: u16) {
    let quoted = wait_for(rx, |sliced| match &sliced.transport {
        Some(TransportSlice::Icmpv4(icmp)) => Some(icmp.slice().to_vec()),
        _ => None,
    });
    assert_eq!(&quoted[..2], &[3, 3], "port unreachable");
    assert_eq!(&quoted[8 + 20..8 + 22], &port.to_be_bytes());
}

fn echoed(rx: &Receiver<Vec<u8>>, port: u16, payload: &[u8]) {
    let mut expected = b"echo:".to_vec();
    expected.extend_from_slice(payload);
    wait_for(rx, |sliced| match &sliced.transport {
        Some(TransportSlice::Udp(udp))
            if udp.destination_port() == port && udp.payload() == expected.as_slice() =>
        {
            Some(())
        }
        _ => None,
    });
}

fn hex(text: &str) -> Vec<u8> {
    let digits: Vec<u8> = text
        .bytes()
        .filter(|b| b.is_ascii_hexdigit())
        .map(|b| (b as char).to_digit(16).unwrap() as u8)
        .collect();
    digits
        .chunks(2)
        .map(|pair| (pair[0] << 4) | pair[1])
        .collect()
}

#[test]
fn quic_to_a_decrypted_host_is_refused_so_the_app_uses_tcp() {
    // RFC 9001 appendix A.2: a real client Initial naming example.com.
    let initial = hex(include_str!(
        "../../engine-outbound/testdata/rfc9001-a2-client-initial.hex"
    ));
    let (mut tunnel, dispatcher, rx) = quic_tunnel(&["example.com"]);
    assert!(tunnel.input_packet(&udp_to_remote(40010, &initial)));
    icmp_port_unreachable(&rx, 40010);
    let stats = tunnel.stats();
    assert_eq!(stats.quic_mitm_fallback, 1);
    assert_eq!(stats.udp_flows, 0, "never opened through the outbound");

    let refused: Vec<_> = dispatcher
        .tracker()
        .connections()
        .closed
        .into_iter()
        .filter(|c| c.error == Some("quic_mitm_fallback"))
        .collect();
    assert_eq!(refused.len(), 1);
    assert_eq!(refused[0].rule, "MITM-QUIC");
    assert_eq!(refused[0].host.as_deref(), Some("example.com"));
    tunnel.stop();
}

#[test]
fn a_client_hello_over_two_initials_is_read_before_refusing() {
    use engine_outbound::quic_sniff::testing::{client_hello, crypto, initial};
    use engine_outbound::quic_sniff::V1;

    let hello = client_hello("video.example.com");
    let dcid = [9u8; 8];
    let one = initial(V1, &dcid, &crypto(0, &hello[..900]));
    let two = initial(V1, &dcid, &crypto(900, &hello[900..]));
    let (mut tunnel, _dispatcher, rx) = quic_tunnel(&["video.example.com"]);
    assert!(tunnel.input_packet(&udp_to_remote(40011, &one)));
    assert!(tunnel.input_packet(&udp_to_remote(40011, &two)));
    icmp_port_unreachable(&rx, 40011);
    assert_eq!(tunnel.stats().quic_mitm_fallback, 1);
    tunnel.stop();
}

#[test]
fn quic_to_other_hosts_passes_with_the_packets_read_in_order() {
    use engine_outbound::quic_sniff::testing::{client_hello, crypto, initial};
    use engine_outbound::quic_sniff::V1;

    let hello = client_hello("video.example.com");
    let dcid = [7u8; 8];
    let one = initial(V1, &dcid, &crypto(0, &hello[..900]));
    let two = initial(V1, &dcid, &crypto(900, &hello[900..]));
    let (mut tunnel, _dispatcher, rx) = quic_tunnel(&["example.com"]);
    assert!(tunnel.input_packet(&udp_to_remote(40012, &one)));
    assert!(tunnel.input_packet(&udp_to_remote(40012, &two)));
    echoed(&rx, 40012, &one);
    echoed(&rx, 40012, &two);
    // Not QUIC at all: relayed without waiting.
    assert!(tunnel.input_packet(&udp_to_remote(40013, b"plain")));
    echoed(&rx, 40013, b"plain");
    let stats = tunnel.stats();
    assert_eq!(stats.quic_mitm_fallback, 0);
    assert_eq!(stats.udp_flows, 2);
    assert_eq!(stats.udp_dropped, 0);
    tunnel.stop();
}

#[test]
fn a_hello_that_never_completes_passes_after_a_short_wait() {
    use engine_outbound::quic_sniff::testing::{client_hello, crypto, initial};
    use engine_outbound::quic_sniff::V1;

    let hello = client_hello("example.com");
    let one = initial(V1, &[5u8; 8], &crypto(0, &hello[..900]));
    let (mut tunnel, _dispatcher, rx) = quic_tunnel(&["example.com"]);
    let sent = Instant::now();
    assert!(tunnel.input_packet(&udp_to_remote(40014, &one)));
    echoed(&rx, 40014, &one);
    assert!(sent.elapsed() < Duration::from_secs(2));
    assert_eq!(tunnel.stats().quic_mitm_fallback, 0);
    tunnel.stop();
}

/// Test outbound that refuses every flow the way a routing rule does.
struct Rejects(RejectAction);

impl TcpOutbound for Rejects {
    fn protocol(&self) -> &'static str {
        "test-reject"
    }

    fn connect<'a>(&'a self, _target: &'a TargetAddr) -> BoxFuture<'a, io::Result<BoxStream>> {
        let action = self.0;
        Box::pin(async move { Err(reject::rejected(action)) })
    }

    fn open_udp<'a>(&'a self, _target: &'a TargetAddr) -> BoxFuture<'a, io::Result<UdpFlow>> {
        let action = self.0;
        Box::pin(async move { Err(reject::rejected(action)) })
    }
}

/// Opens a TCP flow from the app to `REMOTE:port` and sends `payload`;
/// returns the sequence number the app sends next and the tunnel's ISN.
fn open_tcp(tunnel: &Tunnel, rx: &Receiver<Vec<u8>>, port: u16, payload: &[u8]) -> (u32, u32) {
    let client_isn: u32 = 7000;
    let mut syn = Vec::new();
    PacketBuilder::ipv4(APP, REMOTE, 64)
        .tcp(40100, port, client_isn, 65535)
        .syn()
        .write(&mut syn, &[])
        .unwrap();
    assert!(tunnel.input_packet(&syn));
    let server_isn = wait_for(rx, |sliced| match &sliced.transport {
        Some(TransportSlice::Tcp(tcp))
            if tcp.syn() && tcp.ack() && tcp.destination_port() == 40100 =>
        {
            Some(tcp.sequence_number())
        }
        _ => None,
    });
    let mut data = Vec::new();
    PacketBuilder::ipv4(APP, REMOTE, 64)
        .tcp(40100, port, client_isn + 1, 65535)
        .ack(server_isn.wrapping_add(1))
        .psh()
        .write(&mut data, payload)
        .unwrap();
    assert!(tunnel.input_packet(&data));
    (client_isn + 1 + payload.len() as u32, server_isn)
}

/// Payload bytes the tunnel sends the app until it closes (FIN or RST).
fn read_until_closed(rx: &Receiver<Vec<u8>>) -> Vec<u8> {
    let mut received = Vec::new();
    loop {
        let closed = wait_for(rx, |sliced| match &sliced.transport {
            Some(TransportSlice::Tcp(tcp)) if tcp.destination_port() == 40100 => {
                Some((tcp.payload().to_vec(), tcp.fin() || tcp.rst()))
            }
            _ => None,
        });
        received.extend_from_slice(&closed.0);
        if closed.1 {
            return received;
        }
    }
}

/// Whether the tunnel sends the app anything but bare ACKs within `quiet`.
fn answers_within(rx: &Receiver<Vec<u8>>, quiet: Duration) -> bool {
    let deadline = Instant::now() + quiet;
    while let Ok(packet) = rx.recv_timeout(deadline.saturating_duration_since(Instant::now())) {
        let Ok(sliced) = SlicedPacket::from_ip(&packet) else {
            continue;
        };
        match &sliced.transport {
            Some(TransportSlice::Tcp(tcp)) if tcp.destination_port() == 40100 => {
                if !tcp.payload().is_empty() || tcp.fin() || tcp.rst() {
                    return true;
                }
            }
            Some(TransportSlice::Icmpv4(_)) => return true,
            _ => {}
        }
    }
    false
}

/// Test outbound whose connection answers `partial` and then breaks, like a
/// node that drops in the middle of a response.
struct BreaksMidResponse;

impl TcpOutbound for BreaksMidResponse {
    fn protocol(&self) -> &'static str {
        "test-breaks"
    }

    fn connect<'a>(&'a self, _target: &'a TargetAddr) -> BoxFuture<'a, io::Result<BoxStream>> {
        Box::pin(async { Ok(Box::new(BrokenStream { answered: false }) as BoxStream) })
    }
}

struct BrokenStream {
    answered: bool,
}

impl tokio::io::AsyncRead for BrokenStream {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        if self.answered {
            return std::task::Poll::Ready(Err(io::ErrorKind::ConnectionReset.into()));
        }
        self.answered = true;
        buf.put_slice(b"partial");
        std::task::Poll::Ready(Ok(()))
    }
}

impl tokio::io::AsyncWrite for BrokenStream {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<io::Result<usize>> {
        std::task::Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }
}

/// Whether the tunnel ends the flow to `app_port` with a RST (rather than
/// a FIN).
fn ends_with_reset(rx: &Receiver<Vec<u8>>, app_port: u16) -> bool {
    wait_for(rx, |sliced| match &sliced.transport {
        Some(TransportSlice::Tcp(tcp))
            if tcp.destination_port() == app_port && (tcp.fin() || tcp.rst()) =>
        {
            Some(tcp.rst())
        }
        _ => None,
    })
}

/// A flow whose outbound breaks is reset: with a FIN the app would take the
/// cut response (one that ends with the connection) as whole.
#[test]
fn a_flow_whose_outbound_breaks_is_reset() {
    let (sink, rx) = capture();
    let mut tunnel = Tunnel::start(settings(), Arc::new(BreaksMidResponse), sink).unwrap();
    open_tcp(&tunnel, &rx, 80, b"GET /file HTTP/1.0\r\n\r\n");
    assert!(
        ends_with_reset(&rx, 40100),
        "the broken flow ended with a FIN"
    );
    tunnel.stop();
}

/// A flow whose outbound cannot connect is reset too.
#[test]
fn a_flow_whose_outbound_fails_is_reset() {
    let (sink, rx) = capture();
    let mut tunnel = Tunnel::start(
        settings(),
        Arc::new(UdpRedirect(start_udp_echo_server())),
        sink,
    )
    .unwrap();
    open_tcp(&tunnel, &rx, 80, b"GET / HTTP/1.1\r\n\r\n");
    assert!(
        ends_with_reset(&rx, 40100),
        "the failed flow ended with a FIN"
    );
    tunnel.stop();
}

/// A SYN the app sent again before the SYN-ACK came opens one flow, not a
/// second one that would wait for a first payload that never comes.
#[test]
fn a_retransmitted_syn_opens_one_flow() {
    let echo = start_echo_server();
    let (sink, rx) = capture();
    let mut tunnel = Tunnel::start(settings(), Arc::new(Redirect(echo)), sink).unwrap();
    tcp_syn(&tunnel, 41200);
    let client_isn = tcp_syn(&tunnel, 41200);
    let server_isn = wait_for(&rx, |sliced| syn_ack(sliced, 41200));
    tcp_send(
        &tunnel,
        41200,
        client_isn + 1,
        server_isn.wrapping_add(1),
        b"once",
    );
    assert_eq!(wait_for(&rx, |sliced| tcp_payload(sliced, 41200)), b"once");
    thread::sleep(Duration::from_millis(300));
    assert_eq!(tunnel.stats().tcp_total, 1);
    tunnel.stop();
}

#[test]
fn reject_tinygif_answers_plain_http_in_the_tunnel() {
    let (sink, rx) = capture();
    let mut tunnel =
        Tunnel::start(settings(), Arc::new(Rejects(RejectAction::TinyGif)), sink).unwrap();
    open_tcp(
        &tunnel,
        &rx,
        80,
        b"GET /ad.gif HTTP/1.1\r\nHost: ads.example\r\n\r\n",
    );
    assert_eq!(read_until_closed(&rx), reject::tiny_gif_response());
    tunnel.stop();
}

#[test]
fn reject_close_closes_the_flow_without_an_answer() {
    let (sink, rx) = capture();
    let mut tunnel =
        Tunnel::start(settings(), Arc::new(Rejects(RejectAction::Close)), sink).unwrap();
    open_tcp(
        &tunnel,
        &rx,
        80,
        b"GET /ad.gif HTTP/1.1\r\nHost: ads.example\r\n\r\n",
    );
    assert!(read_until_closed(&rx).is_empty());
    tunnel.stop();
}

#[test]
fn reject_drop_keeps_the_flow_silent() {
    let (sink, rx) = capture();
    let mut tunnel =
        Tunnel::start(settings(), Arc::new(Rejects(RejectAction::Drop)), sink).unwrap();
    open_tcp(
        &tunnel,
        &rx,
        80,
        b"GET /ad.gif HTTP/1.1\r\nHost: ads.example\r\n\r\n",
    );
    assert!(
        !answers_within(&rx, Duration::from_millis(800)),
        "a dropped flow gets neither data nor a close"
    );
    assert_eq!(tunnel.stats().tcp_active, 1, "the flow is held open");

    // QUIC gets no ICMP either, so the app waits instead of retrying.
    assert!(tunnel.input_packet(&udp_to_remote(40200, &[0xc0; 1200])));
    assert!(
        !answers_within(&rx, Duration::from_millis(800)),
        "a dropped QUIC flow gets no ICMP"
    );
    tunnel.stop();
}

#[test]
fn reject_close_refuses_quic_with_icmp() {
    let (sink, rx) = capture();
    let mut tunnel =
        Tunnel::start(settings(), Arc::new(Rejects(RejectAction::Close)), sink).unwrap();
    assert!(tunnel.input_packet(&udp_to_remote(40201, &[0xc0; 1200])));
    icmp_port_unreachable(&rx, 40201);
    tunnel.stop();
}

/// A server that greets first, like SMTP or MySQL, and then echoes.
fn start_greeting_server() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { return };
            thread::spawn(move || {
                if stream.write_all(b"220 ready\r\n").is_err() {
                    return;
                }
                let mut buf = [0u8; 1024];
                while let Ok(n) = stream.read(&mut buf) {
                    if n == 0 || stream.write_all(&buf[..n]).is_err() {
                        break;
                    }
                }
            });
        }
    });
    addr
}

/// Opens a TCP flow from `app_port` to `REMOTE:port` and waits for the
/// server's first bytes without sending any.
fn greeting(tunnel: &Tunnel, rx: &Receiver<Vec<u8>>, app_port: u16, port: u16) -> Vec<u8> {
    let client_isn: u32 = 7000;
    let mut syn = Vec::new();
    PacketBuilder::ipv4(APP, REMOTE, 64)
        .tcp(app_port, port, client_isn, 65535)
        .syn()
        .write(&mut syn, &[])
        .unwrap();
    assert!(tunnel.input_packet(&syn));
    let server_isn = wait_for(rx, |sliced| match &sliced.transport {
        Some(TransportSlice::Tcp(tcp))
            if tcp.syn() && tcp.ack() && tcp.destination_port() == app_port =>
        {
            Some(tcp.sequence_number())
        }
        _ => None,
    });
    let mut ack = Vec::new();
    PacketBuilder::ipv4(APP, REMOTE, 64)
        .tcp(app_port, port, client_isn + 1, 65535)
        .ack(server_isn.wrapping_add(1))
        .write(&mut ack, &[])
        .unwrap();
    assert!(tunnel.input_packet(&ack));
    wait_for(rx, |sliced| match &sliced.transport {
        Some(TransportSlice::Tcp(tcp))
            if tcp.destination_port() == app_port && !tcp.payload().is_empty() =>
        {
            Some(tcp.payload().to_vec())
        }
        _ => None,
    })
}

#[test]
fn server_first_ports_connect_without_waiting_for_the_app() {
    let server = start_greeting_server();
    let (sink, rx) = capture();
    let mut tunnel = Tunnel::start(settings(), Arc::new(Redirect(server)), sink).unwrap();

    for (app_port, port) in [(41000, 25), (41001, 3306), (41002, 21)] {
        assert_eq!(greeting(&tunnel, &rx, app_port, port), b"220 ready\r\n");
    }
    let stats = tunnel.stats();
    assert_eq!(stats.tcp_total, 3);
    assert_eq!(stats.tcp_first_wait_skipped, 3);
    tunnel.stop();
}

#[test]
fn a_destination_that_stayed_silent_is_connected_at_once_next_time() {
    let server = start_greeting_server();
    let (sink, rx) = capture();
    let mut tunnel = Tunnel::start(settings(), Arc::new(Redirect(server)), sink).unwrap();

    // Unknown port: the first flow waits for the app. One silent wait (a
    // busy or preconnecting app) is not enough to learn the destination.
    assert_eq!(greeting(&tunnel, &rx, 42000, 2525), b"220 ready\r\n");
    assert_eq!(tunnel.stats().tcp_first_wait_skipped, 0);
    // The second flow waits too, and stays silent again: learned.
    assert_eq!(greeting(&tunnel, &rx, 42001, 2525), b"220 ready\r\n");
    assert_eq!(tunnel.stats().tcp_first_wait_skipped, 0);
    // The next flow to the same destination does not wait.
    assert_eq!(greeting(&tunnel, &rx, 42002, 2525), b"220 ready\r\n");
    assert_eq!(tunnel.stats().tcp_first_wait_skipped, 1);
    // Another port on the same address is still sniffed.
    assert_eq!(greeting(&tunnel, &rx, 42003, 2526), b"220 ready\r\n");
    assert_eq!(tunnel.stats().tcp_first_wait_skipped, 1);
    tunnel.stop();
}

#[test]
fn https_waits_for_the_app_even_when_it_is_silent() {
    let server = start_greeting_server();
    let (sink, rx) = capture();
    let mut tunnel = Tunnel::start(settings(), Arc::new(Redirect(server)), sink).unwrap();

    let started = Instant::now();
    assert_eq!(greeting(&tunnel, &rx, 43000, 443), b"220 ready\r\n");
    // Held for the whole client-first wait (1 s) because nothing came.
    assert!(started.elapsed() >= Duration::from_millis(900));
    assert_eq!(greeting(&tunnel, &rx, 43001, 443), b"220 ready\r\n");
    assert_eq!(tunnel.stats().tcp_first_wait_skipped, 0);
    tunnel.stop();
}

#[test]
fn flows_on_a_multi_thread_tunnel_are_relayed_in_order() {
    let echo = start_echo_server();
    let (sink, rx) = capture();
    let settings = TunnelSettings {
        worker_threads: 4,
        max_tcp_connections: 32,
        ..settings()
    };
    let mut tunnel = Tunnel::start(settings, Arc::new(Redirect(echo)), sink).unwrap();

    // Open every flow first, then send on all of them, so their relays run
    // at the same time on the worker threads.
    let ports: Vec<u16> = (44000..44016).collect();
    let mut opened = Vec::new();
    for &port in &ports {
        let mut syn = Vec::new();
        PacketBuilder::ipv4(APP, REMOTE, 64)
            .tcp(port, 80, 1000, 65535)
            .syn()
            .write(&mut syn, &[])
            .unwrap();
        assert!(tunnel.input_packet(&syn));
        let server_isn = wait_for(&rx, |sliced| match &sliced.transport {
            Some(TransportSlice::Tcp(tcp))
                if tcp.syn() && tcp.ack() && tcp.destination_port() == port =>
            {
                Some(tcp.sequence_number())
            }
            _ => None,
        });
        opened.push((port, server_isn));
    }
    for &(port, server_isn) in &opened {
        let mut data = Vec::new();
        PacketBuilder::ipv4(APP, REMOTE, 64)
            .tcp(port, 80, 1001, 65535)
            .ack(server_isn.wrapping_add(1))
            .psh()
            .write(
                &mut data,
                format!("GET /{port} HTTP/1.1\r\n\r\n").as_bytes(),
            )
            .unwrap();
        assert!(tunnel.input_packet(&data));
    }
    let mut echoed: BTreeMap<u16, Vec<u8>> = BTreeMap::new();
    let deadline = Instant::now() + WAIT;
    while echoed.len() < ports.len() {
        let left = deadline.saturating_duration_since(Instant::now());
        let packet = rx.recv_timeout(left).expect("every flow is echoed");
        let Ok(sliced) = SlicedPacket::from_ip(&packet) else {
            continue;
        };
        if let Some(TransportSlice::Tcp(tcp)) = &sliced.transport {
            let port = tcp.destination_port();
            if ports.contains(&port) && !tcp.payload().is_empty() {
                // The echo is one small segment; a retransmit repeats it.
                echoed.entry(port).or_insert_with(|| tcp.payload().to_vec());
            }
        }
    }
    for port in ports {
        // Each flow got its own bytes back, whatever thread relayed it.
        let want = format!("GET /{port} HTTP/1.1\r\n\r\n");
        assert_eq!(echoed[&port], want.as_bytes(), "port {port}");
    }
    let stats = tunnel.stats();
    assert_eq!(stats.tcp_total, 16);
    assert_eq!(stats.tcp_connect_failed, 0);
    tunnel.stop();
}

#[test]
fn dns_is_answered_on_a_multi_thread_tunnel() {
    let config = DnsConfig {
        hosts: BTreeMap::from([(
            "example.com".to_string(),
            vec!["192.0.2.7".parse().unwrap()],
        )]),
        ..DnsConfig::default()
    };
    let settings = TunnelSettings {
        dns: Arc::new(DnsPolicy::from_config(&config).unwrap()),
        worker_threads: 4,
        ..settings()
    };
    let (sink, rx) = capture();
    let mut tunnel =
        Tunnel::start(settings, Arc::new(Redirect(start_closing_server())), sink).unwrap();
    let response = ask(&tunnel, &rx, &dns_query());
    assert!(response.ends_with(&[192, 0, 2, 7]));
    tunnel.stop();
}

/// Sends a SYN from `app_port` to `REMOTE:80`; returns the client's ISN.
fn tcp_syn(tunnel: &Tunnel, app_port: u16) -> u32 {
    let client_isn: u32 = 9000;
    let mut syn = Vec::new();
    PacketBuilder::ipv4(APP, REMOTE, 64)
        .tcp(app_port, 80, client_isn, 65535)
        .syn()
        .write(&mut syn, &[])
        .unwrap();
    assert!(tunnel.input_packet(&syn));
    client_isn
}

/// Sends `payload` on an open flow from `app_port`.
fn tcp_send(tunnel: &Tunnel, app_port: u16, seq: u32, ack: u32, payload: &[u8]) {
    let mut data = Vec::new();
    PacketBuilder::ipv4(APP, REMOTE, 64)
        .tcp(app_port, 80, seq, 65535)
        .ack(ack)
        .psh()
        .write(&mut data, payload)
        .unwrap();
    assert!(tunnel.input_packet(&data));
}

/// The tunnel's ISN from its SYN-ACK to `app_port`.
fn syn_ack(sliced: &SlicedPacket<'_>, app_port: u16) -> Option<u32> {
    match &sliced.transport {
        Some(TransportSlice::Tcp(tcp))
            if tcp.syn() && tcp.ack() && tcp.destination_port() == app_port =>
        {
            Some(tcp.sequence_number())
        }
        _ => None,
    }
}

/// Payload the tunnel sends `app_port`, if any.
fn tcp_payload(sliced: &SlicedPacket<'_>, app_port: u16) -> Option<Vec<u8>> {
    match &sliced.transport {
        Some(TransportSlice::Tcp(tcp))
            if tcp.destination_port() == app_port && !tcp.payload().is_empty() =>
        {
            Some(tcp.payload().to_vec())
        }
        _ => None,
    }
}

/// Whether the tunnel closes the flow to `app_port` (FIN or RST).
fn tcp_closed(sliced: &SlicedPacket<'_>, app_port: u16) -> bool {
    matches!(
        &sliced.transport,
        Some(TransportSlice::Tcp(tcp)) if tcp.destination_port() == app_port && (tcp.fin() || tcp.rst())
    )
}

/// Opens a relayed flow from `app_port` and checks that `payload` echoes;
/// returns (next client sequence, next acknowledgement).
fn echo_flow(tunnel: &Tunnel, rx: &Receiver<Vec<u8>>, app_port: u16, payload: &[u8]) -> (u32, u32) {
    let client_isn = tcp_syn(tunnel, app_port);
    let server_isn = wait_for(rx, |sliced| syn_ack(sliced, app_port));
    tcp_send(
        tunnel,
        app_port,
        client_isn + 1,
        server_isn.wrapping_add(1),
        payload,
    );
    let echoed = wait_for(rx, |sliced| tcp_payload(sliced, app_port));
    assert_eq!(echoed, payload);
    let len = payload.len() as u32;
    let (seq, ack) = (client_isn + 1 + len, server_isn.wrapping_add(1 + len));
    // Acknowledge the echo so the tunnel has nothing left to resend.
    let mut packet = Vec::new();
    PacketBuilder::ipv4(APP, REMOTE, 64)
        .tcp(app_port, 80, seq, 65535)
        .ack(ack)
        .write(&mut packet, &[])
        .unwrap();
    assert!(tunnel.input_packet(&packet));
    (seq, ack)
}

/// At `max_tcp_connections` a new connection takes the place of the one
/// that has been idle longest instead of being closed at once.
#[test]
fn a_new_tcp_connection_at_the_limit_closes_the_idle_one() {
    let echo = start_echo_server();
    let (sink, rx) = capture();
    let settings = TunnelSettings {
        max_tcp_connections: 1,
        tcp_evict_idle: Duration::from_millis(300),
        ..settings()
    };
    let mut tunnel = Tunnel::start(settings, Arc::new(Redirect(echo)), sink).unwrap();

    echo_flow(&tunnel, &rx, 41000, b"one");
    thread::sleep(Duration::from_millis(600));

    // The new flow is relayed, and the idle one is closed for it.
    let client_isn = tcp_syn(&tunnel, 41001);
    let mut idle_closed = false;
    let server_isn = wait_for(&rx, |sliced| {
        idle_closed |= tcp_closed(sliced, 41000);
        syn_ack(sliced, 41001)
    });
    tcp_send(
        &tunnel,
        41001,
        client_isn + 1,
        server_isn.wrapping_add(1),
        b"two",
    );
    let mut echoed = None;
    wait_for(&rx, |sliced| {
        idle_closed |= tcp_closed(sliced, 41000);
        if echoed.is_none() {
            echoed = tcp_payload(sliced, 41001);
        }
        (idle_closed && echoed.is_some()).then_some(())
    });
    assert_eq!(echoed.unwrap(), b"two");

    let stats = tunnel.stats();
    assert_eq!(stats.tcp_evicted, 1);
    assert_eq!(stats.tcp_rejected, 0);
    assert_eq!(stats.tcp_total, 2);
    tunnel.stop();
}

/// A connection that carried data recently is not closed for a new one:
/// the new one is refused.
#[test]
fn an_active_tcp_connection_is_not_closed_for_a_new_one() {
    let echo = start_echo_server();
    let (sink, rx) = capture();
    let settings = TunnelSettings {
        max_tcp_connections: 1,
        tcp_evict_idle: Duration::from_secs(30),
        ..settings()
    };
    let mut tunnel = Tunnel::start(settings, Arc::new(Redirect(echo)), sink).unwrap();

    let (seq, ack) = echo_flow(&tunnel, &rx, 41100, b"one");
    tcp_syn(&tunnel, 41101);
    let deadline = Instant::now() + WAIT;
    while tunnel.stats().tcp_rejected == 0 {
        assert!(Instant::now() < deadline, "the new connection is refused");
        thread::sleep(Duration::from_millis(20));
    }
    assert_eq!(tunnel.stats().tcp_evicted, 0);
    // Refused with a RST, as from a full listen queue.
    assert!(ends_with_reset(&rx, 41101));

    // The first connection still relays.
    tcp_send(&tunnel, 41100, seq, ack, b"again");
    // The unacknowledged first echo may come again before it.
    wait_for(&rx, |sliced| {
        tcp_payload(sliced, 41100).filter(|payload| payload.as_slice() == b"again")
    });
    tunnel.stop();
}

/// At `max_udp_flows` a new flow takes the place of an idle one; the
/// active flow keeps relaying on the same flow.
#[test]
fn a_new_udp_flow_at_the_limit_replaces_the_idle_one() {
    let echo = start_udp_echo_server();
    let (sink, rx) = capture();
    let settings = TunnelSettings {
        max_udp_flows: 2,
        udp_evict_idle: Duration::from_millis(300),
        ..settings()
    };
    let mut tunnel = Tunnel::start(settings, Arc::new(UdpRedirect(echo)), sink).unwrap();

    assert!(tunnel.input_packet(&udp_to_remote(45001, b"idle")));
    echoed(&rx, 45001, b"idle");
    assert!(tunnel.input_packet(&udp_to_remote(45002, b"busy")));
    echoed(&rx, 45002, b"busy");
    thread::sleep(Duration::from_millis(600));
    assert!(tunnel.input_packet(&udp_to_remote(45002, b"still busy")));
    echoed(&rx, 45002, b"still busy");

    assert!(tunnel.input_packet(&udp_to_remote(45003, b"new")));
    echoed(&rx, 45003, b"new");
    let stats = tunnel.stats();
    assert_eq!(stats.udp_evicted, 1);
    assert_eq!(stats.udp_dropped, 0);
    assert_eq!(stats.udp_flows, 3);

    // The busy flow was kept: no new flow is opened for it.
    assert!(tunnel.input_packet(&udp_to_remote(45002, b"kept")));
    echoed(&rx, 45002, b"kept");
    assert_eq!(tunnel.stats().udp_flows, 3);
    tunnel.stop();
}
