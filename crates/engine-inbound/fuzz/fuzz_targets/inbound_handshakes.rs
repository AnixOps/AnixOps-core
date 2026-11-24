//! Fuzzes the server side of the stream protocols with the bytes a client
//! sends first: VLESS, Trojan, VMess, Shadowsocks AEAD and Shadowsocks 2022,
//! each built from settings the way the node builds them.
//!
//! The first input byte picks the protocol and the rest is what the client
//! sends, after which the client closes its side. Answers from the server are
//! discarded. For VLESS and Trojan, odd selector values put a valid
//! credential in front of the fuzzed bytes, so the command, address and
//! add-on parsing behind authentication is reached and not only the
//! credential check. The encrypted protocols are reached only up to their
//! authentication, which random bytes do not pass.
//!
//! A panic, a sanitizer report or an allocation above the libFuzzer RSS limit
//! is a finding; a handshake that is rejected, times out or accepts is not.

#![no_main]

use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::pin::Pin;
use std::sync::{Arc, OnceLock};
use std::task::{Context, Poll};
use std::time::Duration;

use engine_inbound::registry::InboundFactory;
use engine_inbound::StreamInbound;
use engine_outbound::BoxStream;
use libfuzzer_sys::fuzz_target;
use serde_json::json;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

const USER_UUID: [u8; 16] = [
    0xb8, 0x31, 0x38, 0x1d, 0x63, 0x24, 0x4d, 0x53, 0xad, 0x4f, 0x8c, 0xda, 0x48, 0xb3, 0x08, 0x11,
];
const USER_UUID_TEXT: &str = "b831381d-6324-4d53-ad4f-8cda48b30811";
const TROJAN_PASSWORD: &str = "alice-secret";
/// Hex SHA-224 of [`TROJAN_PASSWORD`], the credential a Trojan client sends.
const TROJAN_CREDENTIAL: &[u8; 56] = b"ef59aaa3cc37793d3465aab561c339ab53ecbd7066134e24f57292e7";
const SS2022_SERVER_KEY: &str = "AQIDBAUGBwgJCgsMDQ4PEA==";
const SS2022_USER_KEY: &str = "EA8ODQwLCgkIBwYFBAMCAQ==";

/// Longer than any handshake deadline of the protocols; with paused time
/// it costs nothing when the handshake finishes first.
const DEADLINE: Duration = Duration::from_secs(300);

struct Inbounds {
    vless: Arc<dyn StreamInbound>,
    trojan: Arc<dyn StreamInbound>,
    vmess: Arc<dyn StreamInbound>,
    shadowsocks: Arc<dyn StreamInbound>,
    shadowsocks_2022: Arc<dyn StreamInbound>,
}

fn build(factory: &dyn InboundFactory, settings: serde_json::Value) -> Arc<dyn StreamInbound> {
    let inbound = factory
        .build(settings.as_object().expect("settings are an object"))
        .expect("fuzz inbound settings are valid");
    assert!(
        !inbound.serves_connections(),
        "{} serves whole connections; this target calls accept",
        inbound.protocol()
    );
    inbound
}

fn inbounds() -> &'static Inbounds {
    static INBOUNDS: OnceLock<Inbounds> = OnceLock::new();
    INBOUNDS.get_or_init(|| Inbounds {
        vless: build(
            &inbound_vless::VlessInboundFactory,
            json!({"users": [{"name": "alice", "uuid": USER_UUID_TEXT}]}),
        ),
        trojan: build(
            &inbound_trojan::TrojanInboundFactory,
            json!({"users": [{"name": "alice", "password": TROJAN_PASSWORD}]}),
        ),
        vmess: build(
            &inbound_vmess::VmessInboundFactory,
            json!({"users": [{"name": "alice", "uuid": USER_UUID_TEXT}]}),
        ),
        shadowsocks: build(
            &inbound_shadowsocks::ShadowsocksInboundFactory,
            json!({"method": "aes-256-gcm", "users": [{"name": "alice", "password": TROJAN_PASSWORD}]}),
        ),
        shadowsocks_2022: build(
            &inbound_shadowsocks::ShadowsocksInboundFactory,
            json!({"method": "2022-blake3-aes-128-gcm", "password": SS2022_SERVER_KEY,
                "users": [{"name": "alice", "password": SS2022_USER_KEY}]}),
        ),
    })
}

/// The client side: reads return the fuzz input and then end of stream,
/// writes are accepted and dropped.
struct Client {
    input: Vec<u8>,
    read: usize,
}

impl AsyncRead for Client {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let rest = &self.input[self.read..];
        let n = rest.len().min(buf.remaining());
        buf.put_slice(&rest[..n]);
        self.read += n;
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for Client {
    fn poll_write(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

fn runtime() -> &'static tokio::runtime::Runtime {
    static RUNTIME: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
    RUNTIME.get_or_init(|| {
        tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .start_paused(true)
            .build()
            .expect("fuzz runtime")
    })
}

fuzz_target!(|data: &[u8]| {
    let Some((&selector, rest)) = data.split_first() else {
        return;
    };
    let inbounds = inbounds();
    let authenticated = selector & 1 == 1;
    let (inbound, input) = match (selector >> 1) % 5 {
        0 => {
            let mut input = Vec::with_capacity(rest.len() + 17);
            if authenticated {
                input.push(0);
                input.extend_from_slice(&USER_UUID);
            }
            input.extend_from_slice(rest);
            (&inbounds.vless, input)
        }
        1 => {
            let mut input = Vec::with_capacity(rest.len() + 58);
            if authenticated {
                input.extend_from_slice(TROJAN_CREDENTIAL);
                input.extend_from_slice(b"\r\n");
            }
            input.extend_from_slice(rest);
            (&inbounds.trojan, input)
        }
        2 => (&inbounds.vmess, rest.to_vec()),
        3 => (&inbounds.shadowsocks, rest.to_vec()),
        _ => (&inbounds.shadowsocks_2022, rest.to_vec()),
    };
    let client: BoxStream = Box::new(Client { input, read: 0 });
    let peer = SocketAddr::from((Ipv4Addr::LOCALHOST, 40000));
    runtime().block_on(async {
        let _ = tokio::time::timeout(DEADLINE, inbound.accept(client, peer)).await;
    });
});
