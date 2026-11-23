//! Settings of a `"type": "iwan"` outbound (spec §11).

use std::net::Ipv4Addr;

use serde::Deserialize;

use crate::client::{ClientConfig, DEFAULT_MTU, MAX_MTU, MIN_MTU};
use crate::packet::MAX_USERNAME_LEN;

/// Default send buffer of each private-stack TCP connection, and the
/// receive buffer an explicit `tcp_buffer_bytes` replaces both with.
pub const DEFAULT_TCP_BUFFER: u32 = 64 * 1024;
/// Default receive buffer of each private-stack TCP connection. It bounds
/// the window one connection advertises, so one connection's download is at
/// most this much per round trip: 64 KiB is about 3.5 Mbit/s at 150 ms.
/// Desktop systems take 512 KiB (about 28 Mbit/s at 150 ms); Android 256
/// KiB; iOS keeps 64 KiB, as the Network Extension's memory budget
/// (about 50 MB, up to 128 connections) cannot hold more. The send buffer
/// stays at [`DEFAULT_TCP_BUFFER`]: the private stack runs no congestion
/// control, and a larger one would only send larger bursts.
#[cfg(target_os = "ios")]
pub const DEFAULT_TCP_RECEIVE_BUFFER: u32 = 64 * 1024;
/// Default receive buffer of each private-stack TCP connection (see the
/// iOS value for the trade-off).
#[cfg(target_os = "android")]
pub const DEFAULT_TCP_RECEIVE_BUFFER: u32 = 256 * 1024;
/// Default receive buffer of each private-stack TCP connection (see the
/// iOS value for the trade-off).
#[cfg(not(any(target_os = "ios", target_os = "android")))]
pub const DEFAULT_TCP_RECEIVE_BUFFER: u32 = 512 * 1024;
pub const MIN_TCP_BUFFER: u32 = 4 * 1024;
pub const MAX_TCP_BUFFER: u32 = 1024 * 1024;
const MAX_PIPE_ID: u16 = 0x7FFF;

/// One iWAN node as it appears in the config. The password is injected from
/// the Keychain like the other protocols. Has no `Debug`: it holds the password.
#[derive(Deserialize)]
pub struct IwanConfig {
    /// IPv4 address or host name.
    pub server: String,
    pub port: u16,
    pub username: String,
    pub password: String,
    #[serde(default = "default_mtu")]
    pub mtu: u16,
    #[serde(default)]
    pub encrypt: bool,
    #[serde(default)]
    pub pipe_id: u16,
    #[serde(default)]
    pub pipe_idx: u8,
    /// Replaces the DNS servers from OPENACK.
    #[serde(default)]
    pub dns: Vec<Ipv4Addr>,
    /// Per-connection TCP send and receive buffer of the private stack,
    /// both directions. Absent: [`DEFAULT_TCP_RECEIVE_BUFFER`] and
    /// [`DEFAULT_TCP_BUFFER`].
    #[serde(default)]
    pub tcp_buffer_bytes: Option<u32>,
}

fn default_mtu() -> u16 {
    DEFAULT_MTU
}

/// Validated settings. Has no `Debug`: it holds the password.
#[derive(Clone)]
pub struct IwanSettings {
    pub server: String,
    pub port: u16,
    pub client: ClientConfig,
    pub dns: Vec<Ipv4Addr>,
    /// Receive buffer of each private-stack TCP connection.
    pub tcp_receive_buffer_bytes: u32,
    /// Send buffer of each private-stack TCP connection.
    pub tcp_send_buffer_bytes: u32,
}

impl IwanConfig {
    pub fn validate(self) -> Result<IwanSettings, &'static str> {
        let server = self.server.trim();
        if server.is_empty() || self.port == 0 {
            return Err("iwan server is invalid");
        }
        // The protocol runs over IPv4 only (spec §1).
        if server.contains(':') {
            return Err("iwan server must be an IPv4 address or a host name");
        }
        if self.username.is_empty() || self.username.len() > MAX_USERNAME_LEN {
            return Err("iwan username must be 1 to 253 bytes");
        }
        if self.password.is_empty() {
            return Err("iwan password is missing");
        }
        if !(MIN_MTU..=MAX_MTU).contains(&self.mtu) {
            return Err("iwan mtu must be between 46 and 1600");
        }
        if self.pipe_id > MAX_PIPE_ID || self.pipe_idx > 1 {
            return Err("iwan pipe is out of range");
        }
        if self.dns.len() > 2 || self.dns.iter().any(Ipv4Addr::is_unspecified) {
            return Err("iwan dns must be at most two IPv4 addresses");
        }
        let (tcp_receive_buffer_bytes, tcp_send_buffer_bytes) = match self.tcp_buffer_bytes {
            Some(bytes) if !(MIN_TCP_BUFFER..=MAX_TCP_BUFFER).contains(&bytes) => {
                return Err("iwan tcp buffer is out of range");
            }
            Some(bytes) => (bytes, bytes),
            None => (DEFAULT_TCP_RECEIVE_BUFFER, DEFAULT_TCP_BUFFER),
        };
        let resolve = server.parse::<Ipv4Addr>().is_err();
        Ok(IwanSettings {
            server: server.to_owned(),
            port: self.port,
            client: ClientConfig {
                username: self.username.into_bytes(),
                password: self.password.into_bytes(),
                mtu: self.mtu,
                encrypt: self.encrypt,
                pipe_id: self.pipe_id,
                pipe_idx: self.pipe_idx,
                resolve,
            },
            dns: self.dns,
            tcp_receive_buffer_bytes,
            tcp_send_buffer_bytes,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(json: serde_json::Value) -> Result<IwanSettings, &'static str> {
        serde_json::from_value::<IwanConfig>(json)
            .map_err(|_| "invalid json")?
            .validate()
    }

    #[test]
    fn defaults() {
        let settings = parse(serde_json::json!({
            "server": "198.51.100.7", "port": 4567, "username": "u", "password": "p"
        }))
        .unwrap();
        assert_eq!(settings.client.mtu, 1400);
        assert!(!settings.client.encrypt);
        assert!(!settings.client.resolve);
        assert!(settings.dns.is_empty());
        assert_eq!(
            settings.tcp_receive_buffer_bytes,
            DEFAULT_TCP_RECEIVE_BUFFER
        );
        assert_eq!(settings.tcp_send_buffer_bytes, DEFAULT_TCP_BUFFER);
        #[cfg(target_os = "ios")]
        assert_eq!(DEFAULT_TCP_RECEIVE_BUFFER, 64 * 1024);
        #[cfg(target_os = "android")]
        assert_eq!(DEFAULT_TCP_RECEIVE_BUFFER, 256 * 1024);
        #[cfg(not(any(target_os = "ios", target_os = "android")))]
        assert_eq!(DEFAULT_TCP_RECEIVE_BUFFER, 512 * 1024);
        // An explicit size sets both directions, as before.
        let explicit = parse(serde_json::json!({
            "server": "198.51.100.7", "port": 4567, "username": "u", "password": "p",
            "tcp_buffer_bytes": 16384
        }))
        .unwrap();
        assert_eq!(explicit.tcp_receive_buffer_bytes, 16384);
        assert_eq!(explicit.tcp_send_buffer_bytes, 16384);
        let named = parse(serde_json::json!({
            "server": "iwan.example", "port": 4567, "username": "u", "password": "p",
            "encrypt": true, "pipe_id": 7, "pipe_idx": 1, "dns": ["1.1.1.1"]
        }))
        .unwrap();
        assert!(named.client.resolve);
        assert_eq!(named.client.pipe_id, 7);
        assert_eq!(named.dns, vec![Ipv4Addr::new(1, 1, 1, 1)]);
    }

    #[test]
    fn rejects_out_of_range_values() {
        let base = serde_json::json!({
            "server": "198.51.100.7", "port": 4567, "username": "u", "password": "p"
        });
        for (key, value) in [
            ("mtu", serde_json::json!(45)),
            ("mtu", serde_json::json!(1601)),
            ("pipe_id", serde_json::json!(32768)),
            ("pipe_idx", serde_json::json!(2)),
            ("server", serde_json::json!("2001:db8::1")),
            ("username", serde_json::json!("")),
            ("password", serde_json::json!("")),
            ("dns", serde_json::json!(["1.1.1.1", "8.8.8.8", "9.9.9.9"])),
            ("tcp_buffer_bytes", serde_json::json!(1024)),
        ] {
            let mut json = base.clone();
            json[key] = value;
            assert!(parse(json).is_err(), "{key} should be rejected");
        }
    }
}
