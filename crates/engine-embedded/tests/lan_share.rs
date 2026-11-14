//! Sharing the desktop local proxy with phones on the local network: the
//! share listener, its setup page and its control requests.

#![cfg(feature = "local-proxy")]

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::thread;
use std::time::Duration;

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

/// One plain HTTP exchange; the share closes after a page.
fn fetch(addr: SocketAddr, request: &str) -> String {
    let mut stream = TcpStream::connect(addr).unwrap();
    stream.set_read_timeout(Some(WAIT)).unwrap();
    stream.write_all(request.as_bytes()).unwrap();
    let mut answer = Vec::new();
    let _ = stream.read_to_end(&mut answer);
    String::from_utf8_lossy(&answer).into_owned()
}

fn share_addr(status: &Value) -> SocketAddr {
    let port = status["port"].as_u64().unwrap();
    format!("127.0.0.1:{port}").parse().unwrap()
}

#[test]
fn share_serves_the_setup_page_and_relays_with_a_device_label() {
    let mut proxy = LocalProxy::start(DIRECT, loopback(), MixedSettings::default()).unwrap();
    let stopped = control(&proxy, r#"{"cmd":"lan_share"}"#);
    assert_eq!(stopped["running"], false);

    let status = control(&proxy, r#"{"cmd":"start_lan_share","port":0}"#);
    assert_eq!(status["running"], true);
    assert_eq!(status["page_host"], "cert.anixops");
    // No `mitm` section: no decryption and no certificate to offer.
    assert_eq!(status["https_decryption"], false);
    assert_eq!(status["certificate"], false);
    let share = share_addr(&status);

    // A browser that opened the share's own address.
    let page = fetch(share, "GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n");
    assert!(page.starts_with("HTTP/1.1 200 OK\r\n"), "{page}");
    assert!(page.contains("text/html"));
    assert!(page.contains(&format!("127.0.0.1:{}", share.port())));
    assert!(!page.contains("/ca.mobileconfig"));
    // The same page through the proxy says the proxy works.
    let proxied = fetch(
        share,
        "GET http://cert.anixops/ HTTP/1.1\r\nHost: cert.anixops\r\n\r\n",
    );
    assert!(proxied.contains("代理已生效"), "{proxied}");
    let missing = fetch(share, "GET /ca.pem HTTP/1.1\r\n\r\n");
    assert!(missing.starts_with("HTTP/1.1 404"), "{missing}");

    // An ordinary tunnel through the share, named after the phone.
    let echo = echo_server();
    let mut stream = TcpStream::connect(share).unwrap();
    stream.set_read_timeout(Some(WAIT)).unwrap();
    write!(stream, "CONNECT {echo} HTTP/1.1\r\nHost: {echo}\r\n\r\n").unwrap();
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
            .any(|connection| connection["process"] == "LAN 127.0.0.1"),
        "{connections}"
    );
    drop(stream);

    let counted = control(&proxy, r#"{"cmd":"lan_share"}"#);
    assert!(counted["pages"].as_u64().unwrap() >= 3);

    let stopped = control(&proxy, r#"{"cmd":"stop_lan_share"}"#);
    assert_eq!(stopped["running"], false);
    assert!(TcpStream::connect(share).is_err());
    proxy.stop();
}

#[test]
fn share_with_credentials_still_serves_the_page_without_them() {
    let mut proxy = LocalProxy::start(DIRECT, loopback(), MixedSettings::default()).unwrap();
    let status = control(
        &proxy,
        r#"{"cmd":"start_lan_share","port":0,"username":"phone","password":"secret"}"#,
    );
    assert_eq!(status["credentials"], true);
    let share = share_addr(&status);
    let page = fetch(share, "GET / HTTP/1.1\r\n\r\n");
    assert!(page.starts_with("HTTP/1.1 200 OK\r\n"), "{page}");
    let refused = fetch(share, "CONNECT example.com:443 HTTP/1.1\r\n\r\n");
    assert!(refused.starts_with("HTTP/1.1 407"), "{refused}");
    // Half a pair of credentials is refused.
    assert!(proxy
        .control_json(br#"{"cmd":"start_lan_share","port":0,"password":"x"}"#)
        .is_err());

    // Stopping the proxy stops its share.
    proxy.stop();
    assert!(TcpStream::connect(share).is_err());
}

#[test]
fn share_restarts_on_a_new_port_and_reports_busy_ports() {
    let mut proxy = LocalProxy::start(DIRECT, loopback(), MixedSettings::default()).unwrap();
    let first = share_addr(&control(&proxy, r#"{"cmd":"start_lan_share","port":0}"#));
    let busy = TcpListener::bind("0.0.0.0:0").unwrap();
    let busy_port = busy.local_addr().unwrap().port();
    let refused =
        proxy.control_json(format!(r#"{{"cmd":"start_lan_share","port":{busy_port}}}"#).as_bytes());
    assert!(refused.is_err());
    // The old share was stopped before the new port was tried.
    assert!(TcpStream::connect(first).is_err());
    assert_eq!(control(&proxy, r#"{"cmd":"lan_share"}"#)["running"], false);
    proxy.stop();
}
