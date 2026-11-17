//! The packet tunnel's `127.0.0.1` listener for the system proxy setting:
//! its control requests and lifetime, relaying through the tunnel's dispatcher, and
//! `URL-REGEX` / `USER-AGENT` rules on plain HTTP requests sent through it.

#![cfg(feature = "local-proxy")]

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::thread;
use std::time::Duration;

use engine_embedded::local_proxy::LocalProxy;
use engine_embedded::tunnel::PacketWriter;
use engine_embedded::EmbeddedRuntime;
use inbound_mixed::MixedSettings;
use serde_json::Value;

const WAIT: Duration = Duration::from_secs(10);
const DIRECT: &[u8] = br#"{"schema_version":1,"profile_id":"ios","outbound":{"type":"direct"}}"#;
/// Plain HTTP to `blocked.test/ad` and from the `BadAgent` user agent is
/// refused (`URL-REGEX` only goes inside `AND` / `OR` / `NOT`); everything
/// else goes direct.
const ROUTED: &[u8] = br#"{"schema_version":1,"profile_id":"ios","routing":{"outbounds":{"node":{"type":"direct"}},"rules":["OR,((URL-REGEX,\"^http://blocked\\.test/ad\"),(USER-AGENT,BadAgent*)),REJECT","FINAL,node"]}}"#;

/// The tunnel's packets go nowhere: these tests only use the listener.
struct Discard;

impl PacketWriter for Discard {
    fn write(&self, _packet: &[u8]) {}
}

fn control(runtime: &EmbeddedRuntime, request: &str) -> Value {
    serde_json::from_slice(&runtime.control_json(request.as_bytes()).unwrap()).unwrap()
}

fn running(config: &[u8]) -> EmbeddedRuntime {
    let mut runtime = EmbeddedRuntime::from_json(config).unwrap();
    runtime.start(Discard).unwrap();
    runtime
}

fn proxy_addr(status: &Value) -> SocketAddr {
    assert_eq!(status["running"], true, "{status}");
    assert_eq!(status["host"], "127.0.0.1");
    let port = status["port"].as_u64().unwrap();
    format!("127.0.0.1:{port}").parse().unwrap()
}

fn echo_server() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
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

/// Answers every request with `200` and the request line it got.
fn http_server() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
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

/// Sends a plain HTTP proxy request and returns the whole answer.
fn proxied_get(
    proxy: SocketAddr,
    origin: SocketAddr,
    host: &str,
    path: &str,
    agent: &str,
) -> String {
    let mut stream = TcpStream::connect(proxy).unwrap();
    stream.set_read_timeout(Some(WAIT)).unwrap();
    write!(
        stream,
        "GET http://{origin}{path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: {agent}\r\nProxy-Connection: keep-alive\r\n\r\n"
    )
    .unwrap();
    let mut answer = Vec::new();
    let _ = stream.read_to_end(&mut answer);
    String::from_utf8_lossy(&answer).into_owned()
}

#[test]
fn the_listener_starts_before_the_tunnel_and_stops_with_the_runtime() {
    let mut runtime = EmbeddedRuntime::from_json(DIRECT).unwrap();
    let stopped = control(&runtime, r#"{"cmd":"system_proxy"}"#);
    assert_eq!(stopped["running"], false);
    assert!(stopped["port"].is_null());

    // The provider learns the port before it applies the interface settings
    // and starts the tunnel.
    let proxy = proxy_addr(&control(
        &runtime,
        r#"{"cmd":"start_system_proxy","port":0}"#,
    ));
    let echo = echo_server();
    let mut stream = TcpStream::connect(proxy).unwrap();
    stream.set_read_timeout(Some(WAIT)).unwrap();
    write!(stream, "CONNECT {echo} HTTP/1.1\r\nHost: {echo}\r\n\r\n").unwrap();
    let mut established = [0u8; 39];
    stream.read_exact(&mut established).unwrap();
    assert_eq!(&established, b"HTTP/1.1 200 Connection established\r\n\r\n");
    drop(stream);

    runtime.start(Discard).unwrap();
    assert_eq!(
        control(&runtime, r#"{"cmd":"system_proxy"}"#)["running"],
        true
    );
    runtime.stop();
    assert!(TcpStream::connect(proxy).is_err());

    // Dropping a runtime that never started stops it too.
    let unstarted = EmbeddedRuntime::from_json(DIRECT).unwrap();
    let proxy = proxy_addr(&control(
        &unstarted,
        r#"{"cmd":"start_system_proxy","port":0}"#,
    ));
    drop(unstarted);
    assert!(TcpStream::connect(proxy).is_err());
}

#[test]
fn connections_through_the_listener_use_the_tunnel_dispatcher() {
    let mut runtime = running(DIRECT);
    let status = control(&runtime, r#"{"cmd":"start_system_proxy","port":0}"#);
    // No `mitm` section: nothing to decrypt with.
    assert_eq!(status["https_decryption"], false);
    let proxy = proxy_addr(&status);
    let echo = echo_server();

    // No credentials asked for.
    let mut stream = TcpStream::connect(proxy).unwrap();
    stream.set_read_timeout(Some(WAIT)).unwrap();
    write!(stream, "CONNECT {echo} HTTP/1.1\r\nHost: {echo}\r\n\r\n").unwrap();
    let mut established = [0u8; 39];
    stream.read_exact(&mut established).unwrap();
    assert_eq!(&established, b"HTTP/1.1 200 Connection established\r\n\r\n");
    stream.write_all(b"hello").unwrap();
    let mut echoed = [0u8; 5];
    stream.read_exact(&mut echoed).unwrap();
    assert_eq!(&echoed, b"hello");

    // The tunnel's connection list shows it, without a process name on a
    // platform that gives none to rules that do not ask.
    let connections = control(&runtime, r#"{"cmd":"connections"}"#);
    let active = connections["active"].as_array().unwrap();
    assert!(
        active
            .iter()
            .any(|connection| connection["destination"] == echo.to_string()),
        "{connections}"
    );
    drop(stream);

    let counted = control(&runtime, r#"{"cmd":"system_proxy"}"#);
    assert!(counted["accepted"].as_u64().unwrap() >= 1, "{counted}");

    // Stopping it closes the port; stopping the runtime stops a new one.
    let stopped = control(&runtime, r#"{"cmd":"stop_system_proxy"}"#);
    assert_eq!(stopped["running"], false);
    assert!(TcpStream::connect(proxy).is_err());
    let again = proxy_addr(&control(
        &runtime,
        r#"{"cmd":"start_system_proxy","port":0}"#,
    ));
    runtime.stop();
    assert!(TcpStream::connect(again).is_err());
}

#[test]
fn a_restart_keeps_the_preferred_port_and_a_taken_one_falls_back() {
    let runtime = running(DIRECT);
    let first = proxy_addr(&control(
        &runtime,
        r#"{"cmd":"start_system_proxy","port":0}"#,
    ));
    // Asking again for the port in use restarts on that port: the old
    // listener frees it first.
    let request = format!(r#"{{"cmd":"start_system_proxy","port":{}}}"#, first.port());
    let restarted = proxy_addr(&control(&runtime, &request));
    assert_eq!(restarted, first);

    // Another program holds the port: a free one is used and reported.
    let taken = TcpListener::bind("127.0.0.1:0").unwrap();
    let busy = taken.local_addr().unwrap().port();
    let request = format!(r#"{{"cmd":"start_system_proxy","port":{busy}}}"#);
    let moved = proxy_addr(&control(&runtime, &request));
    assert_ne!(moved.port(), busy);
    assert!(TcpStream::connect(moved).is_ok());
}

#[test]
fn plain_http_rules_see_requests_through_the_listener() {
    let runtime = running(ROUTED);
    let proxy = proxy_addr(&control(
        &runtime,
        r#"{"cmd":"start_system_proxy","port":0}"#,
    ));
    let origin = http_server();

    let allowed = proxied_get(proxy, origin, "allowed.test", "/ad", "curl/8");
    assert!(allowed.starts_with("HTTP/1.1 200"), "{allowed}");
    // Forwarded in origin form, without the proxy's own headers.
    assert!(allowed.ends_with("GET /ad HTTP/1.1"), "{allowed}");

    let by_url = proxied_get(proxy, origin, "blocked.test", "/ad", "curl/8");
    assert!(by_url.starts_with("HTTP/1.1 502"), "URL-REGEX: {by_url}");

    let by_agent = proxied_get(proxy, origin, "allowed.test", "/", "BadAgent/1.0");
    assert!(
        by_agent.starts_with("HTTP/1.1 502"),
        "USER-AGENT: {by_agent}"
    );

    let listed = control(&runtime, r#"{"cmd":"connections"}"#);
    let closed = listed["closed"].as_array().unwrap();
    assert_eq!(
        closed
            .iter()
            .filter(|connection| connection["error"] == "rejected")
            .count(),
        2,
        "{listed}"
    );
}

#[test]
fn plain_http_rules_see_requests_through_the_desktop_local_proxy() {
    let proxy = LocalProxy::start(
        ROUTED,
        "127.0.0.1:0".parse().unwrap(),
        MixedSettings::default(),
    )
    .unwrap();
    let origin = http_server();
    let allowed = proxied_get(proxy.local_addr(), origin, "allowed.test", "/ad", "curl/8");
    assert!(allowed.starts_with("HTTP/1.1 200"), "{allowed}");
    let blocked = proxied_get(proxy.local_addr(), origin, "blocked.test", "/ad", "curl/8");
    assert!(blocked.starts_with("HTTP/1.1 502"), "{blocked}");
}
