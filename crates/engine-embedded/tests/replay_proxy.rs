//! The `127.0.0.1` listener for the client's own requests (replays): one-time
//! credentials, routing under the `Replay` process name, and its control
//! requests.

#![cfg(feature = "local-proxy")]

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::thread;
use std::time::Duration;

use base64::Engine as _;
use engine_embedded::local_proxy::LocalProxy;
use inbound_mixed::MixedSettings;
use serde_json::Value;

const WAIT: Duration = Duration::from_secs(10);
const DIRECT: &[u8] =
    br#"{"schema_version":1,"profile_id":"desktop","outbound":{"type":"direct"}}"#;

fn loopback() -> SocketAddr {
    "127.0.0.1:0".parse().unwrap()
}

fn control(proxy: &LocalProxy, request: &str) -> Value {
    serde_json::from_slice(&proxy.control_json(request.as_bytes()).unwrap()).unwrap()
}

fn echo_server() -> SocketAddr {
    let listener = TcpListener::bind(loopback()).unwrap();
    let addr = listener.local_addr().unwrap();
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { break };
            thread::spawn(move || {
                let mut reader = stream.try_clone().unwrap();
                let _ = std::io::copy(&mut reader, &mut stream);
            });
        }
    });
    addr
}

fn replay_addr(status: &Value) -> SocketAddr {
    assert_eq!(status["host"], "127.0.0.1");
    let port = status["port"].as_u64().unwrap();
    format!("127.0.0.1:{port}").parse().unwrap()
}

fn basic(status: &Value) -> String {
    let pair = format!(
        "{}:{}",
        status["username"].as_str().unwrap(),
        status["password"].as_str().unwrap()
    );
    base64::engine::general_purpose::STANDARD.encode(pair)
}

#[test]
fn replay_proxy_needs_its_credentials_and_names_its_connections() {
    let mut proxy = LocalProxy::start(DIRECT, loopback(), MixedSettings::default()).unwrap();
    let stopped = control(&proxy, r#"{"cmd":"replay_proxy"}"#);
    assert_eq!(stopped["running"], false);
    assert!(stopped["password"].is_null());

    let status = control(&proxy, r#"{"cmd":"start_replay_proxy"}"#);
    assert_eq!(status["running"], true);
    // No `mitm` section: nothing to decrypt with.
    assert_eq!(status["https_decryption"], false);
    assert_eq!(status["password"].as_str().unwrap().len(), 32);
    let replay = replay_addr(&status);
    let echo = echo_server();

    // Without the credentials: refused.
    let mut refused = TcpStream::connect(replay).unwrap();
    refused.set_read_timeout(Some(WAIT)).unwrap();
    write!(refused, "CONNECT {echo} HTTP/1.1\r\nHost: {echo}\r\n\r\n").unwrap();
    let mut answer = Vec::new();
    let _ = refused.read_to_end(&mut answer);
    assert!(answer.starts_with(b"HTTP/1.1 407"), "{answer:?}");

    // With them: relayed, under the `Replay` process name.
    let mut stream = TcpStream::connect(replay).unwrap();
    stream.set_read_timeout(Some(WAIT)).unwrap();
    write!(
        stream,
        "CONNECT {echo} HTTP/1.1\r\nHost: {echo}\r\nProxy-Authorization: Basic {}\r\n\r\n",
        basic(&status)
    )
    .unwrap();
    let mut established = [0u8; 39];
    stream.read_exact(&mut established).unwrap();
    assert_eq!(&established, b"HTTP/1.1 200 Connection established\r\n\r\n");
    stream.write_all(b"hello").unwrap();
    let mut echoed = [0u8; 5];
    stream.read_exact(&mut echoed).unwrap();
    assert_eq!(&echoed, b"hello");
    let connections = control(&proxy, r#"{"cmd":"connections"}"#);
    let active = connections["active"].as_array().unwrap();
    assert!(
        active
            .iter()
            .any(|connection| connection["process"] == "Replay"),
        "{connections}"
    );
    drop(stream);

    // A restart makes new credentials; the old ones stop working.
    let restarted = control(&proxy, r#"{"cmd":"start_replay_proxy","decrypt":false}"#);
    assert_ne!(restarted["password"], status["password"]);

    let stopped = control(&proxy, r#"{"cmd":"stop_replay_proxy"}"#);
    assert_eq!(stopped["running"], false);
    let last = replay_addr(&restarted);
    assert!(TcpStream::connect(last).is_err());

    // Stopping the local proxy stops the listener too.
    let again = replay_addr(&control(&proxy, r#"{"cmd":"start_replay_proxy"}"#));
    proxy.stop();
    assert!(TcpStream::connect(again).is_err());
}

/// Answers every request with `200` and the request line it got.
fn http_server() -> SocketAddr {
    let listener = TcpListener::bind(loopback()).unwrap();
    let addr = listener.local_addr().unwrap();
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { break };
            thread::spawn(move || {
                let mut head = Vec::new();
                let mut byte = [0u8; 1];
                while !head.ends_with(b"\r\n\r\n") {
                    match stream.read(&mut byte) {
                        Ok(1) => head.push(byte[0]),
                        _ => return,
                    }
                }
                let line = String::from_utf8_lossy(&head)
                    .lines()
                    .next()
                    .unwrap_or_default()
                    .to_string();
                let _ = write!(
                    stream,
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{line}",
                    line.len()
                );
            });
        }
    });
    addr
}

#[test]
fn plain_http_rules_see_replayed_requests() {
    // Plain HTTP to `blocked.test/ad` and from the `BadAgent` user agent is
    // refused; everything else goes through the node.
    const ROUTED: &[u8] = br#"{"schema_version":1,"profile_id":"desktop","routing":{"outbounds":{"node":{"type":"direct"}},"rules":["OR,((URL-REGEX,\"^http://blocked\\.test/ad\"),(USER-AGENT,BadAgent*)),REJECT","FINAL,node"]}}"#;
    let mut proxy = LocalProxy::start(ROUTED, loopback(), MixedSettings::default()).unwrap();
    let status = control(&proxy, r#"{"cmd":"start_replay_proxy","decrypt":false}"#);
    let replay = replay_addr(&status);
    let origin = http_server();
    let get = |host: &str, agent: &str| {
        let mut stream = TcpStream::connect(replay).unwrap();
        stream.set_read_timeout(Some(WAIT)).unwrap();
        write!(
            stream,
            "GET http://{origin}/ad HTTP/1.1\r\nHost: {host}\r\nUser-Agent: {agent}\r\nProxy-Authorization: Basic {}\r\n\r\n",
            basic(&status)
        )
        .unwrap();
        let mut answer = Vec::new();
        let _ = stream.read_to_end(&mut answer);
        String::from_utf8_lossy(&answer).into_owned()
    };

    let allowed = get("allowed.test", "curl/8");
    assert!(allowed.starts_with("HTTP/1.1 200"), "{allowed}");
    let by_url = get("blocked.test", "curl/8");
    assert!(by_url.starts_with("HTTP/1.1 502"), "URL-REGEX: {by_url}");
    let by_agent = get("allowed.test", "BadAgent/1.0");
    assert!(
        by_agent.starts_with("HTTP/1.1 502"),
        "USER-AGENT: {by_agent}"
    );
    proxy.stop();
}
