//! DNS upstreams beyond TCP: plain UDP (retries, truncation, outbounds
//! without UDP), servers raced against each other, the fallback servers, and
//! the device's own resolvers (`system`).

use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use engine_embedded::config::{DnsConfig, DnsVia};
use engine_embedded::direct::DirectOutbound;
use engine_embedded::dns::{self, TYPE_A};
use engine_embedded::dns_cache::DnsPools;
use engine_embedded::dns_client;
use engine_embedded::dns_policy::{DnsPolicy, Plan};
use engine_outbound::{BoxFuture, BoxStream, TargetAddr, TcpDialer, TcpOutbound};
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};

/// How a test server answers.
#[derive(Clone, Copy)]
struct Behaviour {
    rcode: u8,
    address: [u8; 4],
    delay: Duration,
    /// Set TC instead of answering.
    truncate: bool,
    /// Drop this many queries before answering.
    drop_first: usize,
    /// Send a datagram with another id before the answer.
    spoof_first: bool,
}

const ANSWER: Behaviour = Behaviour {
    rcode: 0,
    address: [192, 0, 2, 1],
    delay: Duration::ZERO,
    truncate: false,
    drop_first: 0,
    spoof_first: false,
};

/// `query` answered with `rcode` and, for NOERROR, one A record.
fn answer(query: &[u8], rcode: u8, address: [u8; 4], truncate: bool) -> Vec<u8> {
    let mut response = query.to_vec();
    response[2] |= 0x80 | if truncate { 0x02 } else { 0 };
    response[3] = 0x80 | rcode;
    if rcode == 0 && !truncate {
        response[7] = 1;
        response.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4]);
        response.extend_from_slice(&address);
    }
    response
}

/// A UDP DNS server; the counter is the queries it received.
async fn udp_server(behaviour: Behaviour) -> (SocketAddr, Arc<AtomicUsize>) {
    let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let address = socket.local_addr().unwrap();
    let received = Arc::new(AtomicUsize::new(0));
    let counter = received.clone();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 4096];
        while let Ok((len, from)) = socket.recv_from(&mut buf).await {
            let seen = counter.fetch_add(1, Ordering::SeqCst);
            if seen < behaviour.drop_first {
                continue;
            }
            let query = buf[..len].to_vec();
            let socket = socket.clone();
            tokio::spawn(async move {
                tokio::time::sleep(behaviour.delay).await;
                if behaviour.spoof_first {
                    let mut spoofed = answer(&query, 0, [6, 6, 6, 6], false);
                    spoofed[1] = spoofed[1].wrapping_add(1);
                    let _ = socket.send_to(&spoofed, from).await;
                }
                let reply = answer(
                    &query,
                    behaviour.rcode,
                    behaviour.address,
                    behaviour.truncate,
                );
                let _ = socket.send_to(&reply, from).await;
            });
        }
    });
    (address, received)
}

/// A DNS over TCP server on `address`'s port of 127.0.0.1 (when free), else
/// on a port of its own; answers with `address_answer`.
async fn tcp_server(port: Option<u16>, address_answer: [u8; 4]) -> (SocketAddr, Arc<AtomicUsize>) {
    let listener = TcpListener::bind(("127.0.0.1", port.unwrap_or(0)))
        .await
        .unwrap();
    let address = listener.local_addr().unwrap();
    let received = Arc::new(AtomicUsize::new(0));
    let counter = received.clone();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            let counter = counter.clone();
            tokio::spawn(async move {
                loop {
                    let mut length = [0u8; 2];
                    if stream.read_exact(&mut length).await.is_err() {
                        return;
                    }
                    let mut query = vec![0u8; usize::from(u16::from_be_bytes(length))];
                    if stream.read_exact(&mut query).await.is_err() {
                        return;
                    }
                    counter.fetch_add(1, Ordering::SeqCst);
                    let reply = answer(&query, 0, address_answer, false);
                    let mut framed = (reply.len() as u16).to_be_bytes().to_vec();
                    framed.extend_from_slice(&reply);
                    if stream.write_all(&framed).await.is_err() {
                        return;
                    }
                }
            });
        }
    });
    (address, received)
}

fn policy(section: serde_json::Value) -> DnsPolicy {
    let config: DnsConfig = serde_json::from_value(section).unwrap();
    DnsPolicy::from_config(&config).unwrap()
}

fn direct() -> Arc<dyn TcpOutbound> {
    Arc::new(DirectOutbound::new(Arc::new(TcpDialer)))
}

/// Resolves `name` with `policy`, every server through `outbound`.
async fn resolve_with(
    policy: &DnsPolicy,
    name: &str,
    outbound: Arc<dyn TcpOutbound>,
) -> Result<Vec<u8>, dns::OutboundFailure> {
    let query = dns::query(0x5a5a, name, TYPE_A).unwrap();
    let Plan::Forward(target) = policy.plan(&query, None) else {
        panic!("expected a forwarded query");
    };
    let pools = DnsPools::default();
    let outbound_for = move |_: usize| Some(outbound.clone());
    let response = dns_client::resolve(policy, target, &query, &outbound_for, &pools).await?;
    assert_eq!(&response[..2], &[0x5a, 0x5a], "the app's id comes back");
    assert!(dns::answers(&query, &response));
    Ok(response)
}

async fn resolve(policy: &DnsPolicy, name: &str) -> Result<Vec<u8>, dns::OutboundFailure> {
    resolve_with(policy, name, direct()).await
}

#[tokio::test]
async fn udp_servers_answer_and_retry_lost_queries() {
    let (server, received) = udp_server(Behaviour {
        drop_first: 1,
        ..ANSWER
    })
    .await;
    let policy = policy(json!({
        "servers": [{ "name": "udp", "url": format!("udp://{server}"), "via": "direct" }],
    }));
    assert_eq!(policy.view()[0].scheme, "udp");
    let response = resolve(&policy, "example.com").await.unwrap();
    assert!(response.ends_with(&[192, 0, 2, 1]));
    assert_eq!(
        received.load(Ordering::SeqCst),
        2,
        "sent again after a loss"
    );
}

#[tokio::test]
async fn datagrams_for_another_query_are_ignored() {
    let (server, _) = udp_server(Behaviour {
        spoof_first: true,
        ..ANSWER
    })
    .await;
    let policy = policy(json!({
        "servers": [{ "name": "udp", "url": format!("udp://{server}"), "via": "direct" }],
    }));
    let response = resolve(&policy, "example.com").await.unwrap();
    assert!(response.ends_with(&[192, 0, 2, 1]));
}

#[tokio::test]
async fn truncated_udp_answers_are_asked_again_over_tcp() {
    let (server, _) = udp_server(Behaviour {
        truncate: true,
        ..ANSWER
    })
    .await;
    // The same port over TCP; skip when another program holds it.
    let Ok(listener) = std::net::TcpListener::bind(server) else {
        return;
    };
    drop(listener);
    let (_, tcp_received) = tcp_server(Some(server.port()), [192, 0, 2, 99]).await;
    let policy = policy(json!({
        "servers": [{ "name": "udp", "url": format!("udp://{server}"), "via": "direct" }],
    }));
    let response = resolve(&policy, "example.com").await.unwrap();
    assert!(response.ends_with(&[192, 0, 2, 99]));
    assert_eq!(response[2] & 0x02, 0, "the full answer");
    assert_eq!(tcp_received.load(Ordering::SeqCst), 1);
}

/// Relays TCP only, as an HTTP proxy does.
struct TcpOnly(Arc<dyn TcpOutbound>);

impl TcpOutbound for TcpOnly {
    fn protocol(&self) -> &'static str {
        "tcp-only"
    }

    fn connect<'a>(&'a self, target: &'a TargetAddr) -> BoxFuture<'a, io::Result<BoxStream>> {
        self.0.connect(target)
    }
}

#[tokio::test]
async fn udp_servers_go_over_tcp_through_an_outbound_without_udp() {
    let (server, received) = tcp_server(None, [192, 0, 2, 7]).await;
    let policy = policy(json!({
        "servers": [{ "name": "udp", "url": format!("udp://{server}") }],
    }));
    let response = resolve_with(&policy, "example.com", Arc::new(TcpOnly(direct())))
        .await
        .unwrap();
    assert!(response.ends_with(&[192, 0, 2, 7]));
    assert_eq!(received.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn raced_servers_give_the_first_answer() {
    let (fast, _) = udp_server(ANSWER).await;
    let (slow, _) = udp_server(Behaviour {
        delay: Duration::from_secs(3),
        address: [192, 0, 2, 2],
        ..ANSWER
    })
    .await;
    let policy = policy(json!({
        "servers": [
            { "name": "slow", "url": format!("udp://{slow}"), "via": "direct" },
            { "name": "fast", "url": format!("udp://{fast}"), "via": "direct" },
        ],
        "default": ["slow", "fast"],
    }));
    let views = policy.view();
    assert!(views.iter().all(|view| view.default));
    let started = Instant::now();
    let response = resolve(&policy, "example.com").await.unwrap();
    assert!(response.ends_with(&[192, 0, 2, 1]));
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "did not wait for the slow server"
    );
}

#[tokio::test]
async fn an_answer_beats_a_faster_nxdomain() {
    // Split DNS: the public server does not know the company's name.
    let (public, _) = udp_server(Behaviour { rcode: 3, ..ANSWER }).await;
    let (company, _) = udp_server(Behaviour {
        delay: Duration::from_millis(300),
        address: [10, 0, 0, 5],
        ..ANSWER
    })
    .await;
    let policy = policy(json!({
        "servers": [
            { "name": "public", "url": format!("udp://{public}"), "via": "direct" },
            { "name": "company", "url": format!("udp://{company}"), "via": "direct" },
        ],
        "default": ["public", "company"],
    }));
    let response = resolve(&policy, "intranet.corp.example").await.unwrap();
    assert!(response.ends_with(&[10, 0, 0, 5]));
}

#[tokio::test]
async fn failing_servers_fall_back() {
    let (broken, _) = udp_server(Behaviour { rcode: 2, ..ANSWER }).await;
    let (fallback, fallback_received) = udp_server(Behaviour {
        address: [192, 0, 2, 3],
        ..ANSWER
    })
    .await;
    let policy = policy(json!({
        "servers": [
            { "name": "broken", "url": format!("udp://{broken}"), "via": "direct" },
            { "name": "backup", "url": format!("udp://{fallback}"), "via": "direct" },
        ],
        "fallback": "backup",
    }));
    assert!(policy.view()[1].fallback);
    let response = resolve(&policy, "example.com").await.unwrap();
    assert!(response.ends_with(&[192, 0, 2, 3]));
    assert_eq!(fallback_received.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn nxdomain_does_not_fall_back() {
    let (primary, _) = udp_server(Behaviour { rcode: 3, ..ANSWER }).await;
    let (fallback, fallback_received) = udp_server(ANSWER).await;
    let policy = policy(json!({
        "servers": [
            { "name": "primary", "url": format!("udp://{primary}"), "via": "direct" },
            { "name": "backup", "url": format!("udp://{fallback}"), "via": "direct" },
        ],
        "fallback": "backup",
    }));
    let response = resolve(&policy, "missing.example").await.unwrap();
    assert_eq!(dns::rcode(&response), dns::RCODE_NXDOMAIN);
    assert_eq!(fallback_received.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn unreachable_servers_fall_back_to_the_system_servers() {
    let (system, received) = udp_server(Behaviour {
        address: [10, 1, 2, 3],
        ..ANSWER
    })
    .await;
    // Nothing listens on the primary's TCP port.
    let closed = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let primary = closed.local_addr().unwrap();
    drop(closed);
    let policy = policy(json!({
        "servers": [
            { "name": "primary", "url": format!("tcp://{primary}") },
            { "name": "sys", "url": "system" },
        ],
        "fallback": "sys",
        "system_servers": [system.to_string()],
    }));
    let sys = &policy.servers()[1];
    assert_eq!(sys.via, DnsVia::Direct, "system servers are always direct");
    assert_eq!(sys.upstream.scheme(), "system");
    assert_eq!(policy.view()[1].via, "direct");
    let response = resolve(&policy, "intranet.corp.example").await.unwrap();
    assert!(response.ends_with(&[10, 1, 2, 3]));
    assert_eq!(received.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn the_system_resolver_answers_without_system_servers() {
    let policy = policy(json!({
        "servers": [{ "name": "sys", "url": "system" }],
    }));
    let response = resolve(&policy, "localhost").await.unwrap();
    assert_eq!(dns::rcode(&response), dns::RCODE_NOERROR);
    assert!(response.ends_with(&[127, 0, 0, 1]), "{response:?}");
    // Types the system resolver cannot look up are SERVFAIL, so a fallback
    // can take them.
    let mx = dns::query(7, "localhost", 15).unwrap();
    let Plan::Forward(target) = policy.plan(&mx, None) else {
        panic!("expected a forwarded query");
    };
    let outbound = direct();
    let outbound_for = move |_: usize| Some(outbound.clone());
    let response = dns_client::resolve(&policy, target, &mx, &outbound_for, &DnsPools::default())
        .await
        .unwrap();
    assert_eq!(dns::rcode(&response), dns::RCODE_SERVFAIL);
}

#[test]
fn server_lists_are_checked() {
    let check = |section: serde_json::Value| {
        let config: DnsConfig = serde_json::from_value(section).unwrap();
        DnsPolicy::from_config(&config).map(|_| ())
    };
    let servers = json!([
        { "name": "a", "url": "udp://192.0.2.1" },
        { "name": "b", "url": "udp://192.0.2.2" },
        { "name": "c", "url": "udp://192.0.2.3" },
        { "name": "d", "url": "udp://192.0.2.4" },
        { "name": "e", "url": "udp://192.0.2.5" },
    ]);
    assert!(check(json!({ "servers": servers, "default": ["a", "b", "c", "d"] })).is_ok());
    for bad in [
        json!({ "servers": servers, "default": ["a", "b", "c", "d", "e"] }),
        json!({ "servers": servers, "default": [] }),
        json!({ "servers": servers, "default": ["a", "a"] }),
        json!({ "servers": servers, "fallback": "nowhere" }),
        json!({ "fallback": "a" }),
        json!({ "servers": servers, "system_servers": ["not an address"] }),
        json!({ "servers": servers, "system_servers": ["0.0.0.0"] }),
        json!({ "servers": servers, "rules": [{ "domain": ["x.example"], "server": ["a", "zz"] }] }),
    ] {
        assert!(check(bad.clone()).is_err(), "{bad}");
    }
    // The same set in another order is the same target.
    let config: DnsConfig = serde_json::from_value(json!({
        "servers": servers,
        "default": ["a", "b"],
        "rules": [{ "domain": ["x.example"], "server": ["b", "a"] }],
    }))
    .unwrap();
    let policy = DnsPolicy::from_config(&config).unwrap();
    assert_eq!(
        policy.server_for("x.example", None),
        policy.server_for("y.example", None)
    );
    assert_eq!(policy.target(policy.server_for("x.example", None)), &[0, 1]);
}
