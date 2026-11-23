//! WireGuard: IP packets from the TUN side are sealed straight into UDP
//! datagrams to one peer, with no userspace TCP/IP stack in between.
//!
//! The Noise state machine is boringtun's `Tunn` (BSD-3-Clause). This module
//! only moves bytes between the packet queue, the UDP path to the peer and
//! the [`PacketSink`], and drives the handshake and keepalive timers. The
//! peer's `AllowedIPs` are applied by the Network Extension routes, not here.
//!
//! The path is `outbound_wireguard::path::Path`, shared with the routable
//! WireGuard outbound: one connected UDP socket that moves to a new one, with
//! the endpoint resolved again, after a network change
//! ([`PathControl::reset`], the `reset_network` control request), when the
//! socket protector pins to another interface, when a send fails because the
//! source address or the route is gone, and when handshakes go unanswered.
//! The session keeps its keys across a move; a fresh handshake on the new
//! socket moves the peer to the new address at once.

use std::io;
use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use base64::Engine;
use boringtun::noise::{Tunn, TunnResult};
use boringtun::x25519::{PublicKey, StaticSecret};
use engine_outbound::registry::{parse_settings, Settings};
use outbound_wireguard::path::{self, Path, Received};
use ring::rand::{SecureRandom, SystemRandom};
use serde::Deserialize;
use tokio::sync::mpsc;
use tokio::time::MissedTickBehavior;

use crate::tunnel::{bump, PacketSink, TunnelStats};

pub const PROTOCOL: &str = "wireguard";
/// Config `type` name of a WireGuard outbound.
pub const TYPE_NAME: &str = "wireguard";

/// boringtun needs `src.len() + 32` and at least 148 bytes; a UDP datagram is
/// at most 64 KiB, so one buffer of this size fits every case.
const BUFFER_BYTES: usize = 65_536 + 148;
/// boringtun's timers have a 250 ms granularity.
const TIMER_TICK: Duration = Duration::from_millis(250);

/// Settings for one peer. Holds key material, so it has no `Debug`.
#[derive(Clone)]
pub struct WireGuardSettings {
    pub private_key: [u8; 32],
    pub peer_public_key: [u8; 32],
    pub preshared_key: Option<[u8; 32]>,
    pub server: String,
    pub port: u16,
    pub persistent_keepalive_secs: Option<u16>,
}

/// One WireGuard peer as it appears in the config. Keys are standard base64,
/// as in a `wg-quick` file; the private and preshared keys are injected from
/// the Keychain.
#[derive(Deserialize)]
struct WireGuardConfig {
    private_key: String,
    peer_public_key: String,
    #[serde(default)]
    preshared_key: Option<String>,
    server: String,
    port: u16,
    #[serde(default)]
    persistent_keepalive_secs: Option<u16>,
}

/// Parses and validates the settings of a `"type": "wireguard"` outbound.
pub fn settings_from(settings: &Settings) -> Result<WireGuardSettings, &'static str> {
    let config: WireGuardConfig =
        parse_settings(settings, "wireguard settings are missing or invalid")?;
    let private_key = decode_key(&config.private_key)
        .ok_or("wireguard private key must be 32 bytes of base64")?;
    let peer_public_key = decode_key(&config.peer_public_key)
        .ok_or("wireguard peer public key must be 32 bytes of base64")?;
    let preshared_key = match config.preshared_key.as_deref() {
        None | Some("") => None,
        Some(key) => {
            Some(decode_key(key).ok_or("wireguard preshared key must be 32 bytes of base64")?)
        }
    };
    let server = config.server.trim();
    if server.is_empty() || config.port == 0 {
        return Err("wireguard endpoint is invalid");
    }
    Ok(WireGuardSettings {
        private_key,
        peer_public_key,
        preshared_key,
        server: server.to_owned(),
        port: config.port,
        persistent_keepalive_secs: config.persistent_keepalive_secs,
    })
}

/// Decodes a standard base64 WireGuard key.
pub fn decode_key(encoded: &str) -> Option<[u8; 32]> {
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(encoded.trim())
        .ok()?;
    bytes.try_into().ok()
}

/// The endpoint's addresses, IPv4 first; the socket tries each in turn. The
/// Network Extension's own sockets never route through the tunnel, so the
/// system resolver is safe to use for the endpoint.
fn resolve(server: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
    let host = server.trim_start_matches('[').trim_end_matches(']');
    let addresses = path::ordered((host, port).to_socket_addrs()?);
    if addresses.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "endpoint did not resolve",
        ));
    }
    Ok(addresses)
}

fn session_index() -> io::Result<u32> {
    let mut bytes = [0u8; 4];
    SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| io::Error::other("random index is unavailable"))?;
    // boringtun shifts the index left by 8 bits.
    Ok(u32::from_le_bytes(bytes) >> 8)
}

/// Asks a running WireGuard tunnel to move to a new UDP socket. The runtime
/// keeps one for its config and hands it to every tunnel it starts, so a
/// control request reaches the tunnel's driver without blocking.
#[derive(Default)]
pub struct PathControl {
    /// Moves asked for so far; the driver serves each new count once.
    requests: AtomicU64,
    /// Whether a tunnel's driver runs to serve them.
    running: AtomicBool,
}

impl PathControl {
    /// Asks the running tunnel to resolve the endpoint again and move to a
    /// new UDP socket, after the device changed networks or woke up. Returns
    /// at once; the driver moves within one timer tick. Returns 1 when a
    /// tunnel runs, else 0, counted like
    /// [`engine_outbound::TcpOutbound::reset_sessions`].
    pub fn reset(&self) -> usize {
        if !self.running.load(Ordering::Acquire) {
            return 0;
        }
        self.requests.fetch_add(1, Ordering::AcqRel);
        1
    }
}

/// Marks the tunnel running while its driver task lives, also when the
/// runtime drops the task as the tunnel stops.
struct Running(Arc<PathControl>);

impl Running {
    fn new(control: Arc<PathControl>) -> Self {
        control.running.store(true, Ordering::Release);
        Self(control)
    }
}

impl Drop for Running {
    fn drop(&mut self) {
        self.0.running.store(false, Ordering::Release);
    }
}

/// Starts the WireGuard driver on the current tokio runtime. The endpoint
/// resolves and the first socket connects before this returns.
pub(crate) fn spawn_tasks(
    settings: WireGuardSettings,
    control: Arc<PathControl>,
    sink: PacketSink,
    packet_rx: mpsc::Receiver<Vec<u8>>,
    stats: Arc<TunnelStats>,
) -> io::Result<()> {
    let addresses = resolve(&settings.server, settings.port)?;
    let path = Path::connect(&settings.server, settings.port, &addresses)?;
    let tunn = Tunn::new(
        StaticSecret::from(settings.private_key),
        PublicKey::from(settings.peer_public_key),
        settings.preshared_key,
        settings.persistent_keepalive_secs.filter(|secs| *secs > 0),
        session_index()?,
        None,
    );
    // Requests from before this tunnel are moot: its socket is new.
    let served = control.requests.load(Ordering::Acquire);
    let running = Running::new(control);
    tokio::spawn(drive(tunn, path, running, served, sink, packet_rx, stats));
    Ok(())
}

/// Moves packets between the TUN queue and the peer, runs the handshake and
/// keepalive timers, and moves the path when asked to. Ends when the tunnel
/// stops.
async fn drive(
    mut tunn: Tunn,
    mut path: Path,
    running: Running,
    mut served: u64,
    sink: PacketSink,
    mut packet_rx: mpsc::Receiver<Vec<u8>>,
    stats: Arc<TunnelStats>,
) {
    let control = running.0.clone();
    let mut buffer = vec![0u8; BUFFER_BYTES];
    let mut datagram = vec![0u8; BUFFER_BYTES];
    if let TunnResult::WriteToNetwork(initiation) =
        tunn.format_handshake_initiation(&mut buffer, false)
    {
        let _ = path.send(initiation).await;
    }
    let mut ticker = tokio::time::interval(TIMER_TICK);
    ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);
    loop {
        let requested = control.requests.load(Ordering::Acquire);
        if requested != served {
            served = requested;
            path.renew();
        }
        path.maintain(Instant::now());
        tokio::select! {
            // TUN -> peer. The first packet also starts the handshake.
            packet = packet_rx.recv() => {
                // The tunnel stopped.
                let Some(packet) = packet else {
                    return;
                };
                if let TunnResult::WriteToNetwork(sealed) = tunn.encapsulate(&packet, &mut buffer) {
                    if path.send(sealed).await.is_ok() {
                        stats
                            .bytes_up
                            .fetch_add(packet.len() as u64, Ordering::Relaxed);
                    }
                }
            }
            // Peer -> TUN, or the end of a move.
            received = path.recv(&mut datagram) => match received {
                Received::Datagram(len) => {
                    receive(&mut tunn, &mut path, &datagram[..len], &mut buffer, &sink, &stats)
                        .await;
                }
                // A fresh handshake on the new socket moves the peer to the
                // new address at once and proves the path.
                Received::Rebound => {
                    if let TunnResult::WriteToNetwork(initiation) =
                        tunn.format_handshake_initiation(&mut buffer, true)
                    {
                        let _ = path.send(initiation).await;
                    }
                }
                Received::Failed | Received::Unchanged => {}
            },
            // Handshake, rekey and keepalive timers.
            _ = ticker.tick() => {
                if let TunnResult::WriteToNetwork(sealed) = tunn.update_timers(&mut buffer) {
                    let _ = path.send(sealed).await;
                }
            }
        }
    }
}

/// Opens one datagram from the peer and hands what it carries to the TUN
/// side; handshake replies and packets queued behind the handshake go back
/// out on the path.
async fn receive(
    tunn: &mut Tunn,
    path: &mut Path,
    datagram: &[u8],
    buffer: &mut [u8],
    sink: &PacketSink,
    stats: &TunnelStats,
) {
    let peer = Some(path.endpoint().ip());
    let mut input = datagram;
    loop {
        let result = tunn.decapsulate(peer, input, buffer);
        if !input.is_empty() && !matches!(result, TunnResult::Err(_)) {
            // Only a message the peer authenticated gets past the first call.
            path.heard();
        }
        match result {
            // Handshake replies and queued packets: keep draining with an
            // empty datagram until boringtun reports it is done.
            TunnResult::WriteToNetwork(reply) => {
                let _ = path.send(reply).await;
                input = &[];
            }
            TunnResult::WriteToTunnelV4(packet, _) | TunnResult::WriteToTunnelV6(packet, _) => {
                // A keepalive decrypts to an empty packet.
                if !packet.is_empty() {
                    bump(&stats.packets_out);
                    stats
                        .bytes_down
                        .fetch_add(packet.len() as u64, Ordering::Relaxed);
                    sink(packet);
                }
                return;
            }
            TunnResult::Done | TunnResult::Err(_) => return,
        }
    }
}
