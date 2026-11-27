//! `"type": "mesh"` as a routable outbound of the embedded engine
//! (`docs/architecture/mesh-module.md`, 分流): every TCP connection and UDP
//! flow to a member's virtual address, or to a subnet a member advertises,
//! opens inside the network's private stack ([`stack`]); nothing is sent for
//! any other destination.
//!
//! The networks run in the [`engine::MeshEngine`], not in the outbounds: an
//! outbound only names its network (`network.name`, not the outbound's
//! key) and the settings it was built with, and takes the running instance
//! from the engine's [`registry::Registry`] at each connection. Building an
//! outbound starts and stops nothing; the engine commits a profile's
//! networks once it adopted the profile. A network whose settings did not
//! change keeps running across profiles, its sessions and member links
//! included; changed settings stop the old network at once, connections
//! included, and start a new one: the old one would keep the previous
//! `native_keys` (spec §8.3.1) and dial with the same identity.

pub mod control;
pub mod engine;
pub mod name_book;
pub mod registry;
pub mod snapshot;
mod stack;

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use engine_outbound::registry::{parse_settings, BuildError, OutboundFactory, Settings};
use engine_outbound::{
    BoxFuture, BoxStream, DatagramRecv, DatagramSend, Dialer, TargetAddr, TcpOutbound, UdpFlow,
};
use smoltcp::iface::SocketHandle;
use smoltcp::socket::tcp;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::{MeshConfig, MeshSettings, TYPE_NAME};

use engine::EngineSlot;
use stack::{closed, unreachable_address, UdpHandle};
pub use stack::{Failure, Instance};

/// How long a TCP connection may take to establish inside the network.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// How long a domain target may take to resolve.
const RESOLVE_TIMEOUT: Duration = Duration::from_secs(5);

/// Whether a running network can serve `settings` as it is. [`IpNet`]
/// equality compares networks only, so the node's own addresses are
/// compared apart: a new address inside the same subnet is a new network.
fn same_settings(running: &MeshSettings, wanted: &MeshSettings) -> bool {
    running == wanted && running.local_addresses() == wanted.local_addresses()
}

/// Builds `"type": "mesh"` outbounds.
pub struct MeshFactory {
    binding: Option<Binding>,
}

struct Binding {
    slot: &'static EngineSlot,
    built: Arc<Mutex<Vec<MeshSettings>>>,
}

impl MeshFactory {
    /// Outbounds that refuse every connection as unsupported: for delay
    /// tests and checkups, which must neither start a network nor take one
    /// over from the running profile.
    pub fn detached() -> Self {
        Self { binding: None }
    }

    /// Outbounds that find their network in the engine of `slot` at each
    /// connection. `built` collects the settings of every outbound built,
    /// for the engine to commit once it adopted the profile.
    pub fn bound(slot: &'static EngineSlot, built: Arc<Mutex<Vec<MeshSettings>>>) -> Self {
        Self {
            binding: Some(Binding { slot, built }),
        }
    }
}

impl OutboundFactory for MeshFactory {
    fn type_name(&self) -> &'static str {
        TYPE_NAME
    }

    /// The network runs over its own sockets, which a `via` cannot carry.
    fn supports_via(&self) -> bool {
        false
    }

    /// The network runs over its own sockets, so the dialer is unused.
    fn build(
        &self,
        settings: &Settings,
        _dialer: Arc<dyn Dialer>,
    ) -> Result<Arc<dyn TcpOutbound>, BuildError> {
        let config: MeshConfig = parse_settings(settings, "mesh settings are missing or invalid")?;
        let settings = config.validate()?;
        let Some(binding) = &self.binding else {
            return Ok(Arc::new(DetachedOutbound));
        };
        let mut built = binding
            .built
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        // One device has one instance ID (`mesh-module.md`,
        // `node.instance_id`): a profile whose networks name different ones
        // is refused. Only the profile is checked, not the engine, so that
        // building never depends on the networks running now; the engine
        // takes the profile's ID at commit.
        let conflicting = built.iter().any(|other| {
            other.network_name != settings.network_name && other.instance_id != settings.instance_id
        });
        if conflicting {
            return Err("mesh node instance_id differs from that of another mesh network");
        }
        built.push(settings.clone());
        drop(built);
        Ok(Arc::new(RegistryOutbound {
            slot: binding.slot,
            settings,
        }))
    }
}

/// A mesh outbound outside the engine's adopted profile.
struct DetachedOutbound;

fn unsupported() -> io::Error {
    io::Error::new(
        io::ErrorKind::Unsupported,
        "mesh networks are only reached through the running engine",
    )
}

impl TcpOutbound for DetachedOutbound {
    fn protocol(&self) -> &'static str {
        TYPE_NAME
    }

    fn connect<'a>(&'a self, _target: &'a TargetAddr) -> BoxFuture<'a, io::Result<BoxStream>> {
        Box::pin(async { Err(unsupported()) })
    }

    fn open_udp<'a>(&'a self, _target: &'a TargetAddr) -> BoxFuture<'a, io::Result<UdpFlow>> {
        Box::pin(async { Err(unsupported()) })
    }
}

/// A mesh outbound of a profile: the network named in `settings`, taken
/// from the engine at each connection.
struct RegistryOutbound {
    slot: &'static EngineSlot,
    settings: MeshSettings,
}

impl RegistryOutbound {
    fn resolve(&self) -> io::Result<MeshOutbound> {
        let engine = self.slot.current().ok_or_else(|| {
            io::Error::new(io::ErrorKind::NotConnected, "mesh engine is not running")
        })?;
        let instance = engine
            .registry()
            .instance(&self.settings.network_name, &self.settings)?;
        Ok(MeshOutbound { instance })
    }
}

impl TcpOutbound for RegistryOutbound {
    fn protocol(&self) -> &'static str {
        TYPE_NAME
    }

    fn connect<'a>(&'a self, target: &'a TargetAddr) -> BoxFuture<'a, io::Result<BoxStream>> {
        Box::pin(async move { self.resolve()?.tcp(target).await })
    }

    fn open_udp<'a>(&'a self, target: &'a TargetAddr) -> BoxFuture<'a, io::Result<UdpFlow>> {
        Box::pin(async move { self.resolve()?.udp_flow(None, target).await })
    }

    fn health(&self) -> Option<serde_json::Value> {
        match self.resolve() {
            Ok(outbound) => outbound.health(),
            Err(_) => Some(serde_json::json!({"running": false, "members": 0})),
        }
    }
}

/// One mesh network instance as an outbound. Clones share the network.
#[derive(Clone)]
pub struct MeshOutbound {
    instance: Arc<Instance>,
}

impl MeshOutbound {
    pub fn instance(&self) -> &Arc<Instance> {
        &self.instance
    }

    /// An outbound for `settings` on a network of its own, which the engine
    /// does not find by name; for tests that run several nodes of one
    /// network in a process.
    #[doc(hidden)]
    pub fn unshared(settings: MeshSettings) -> io::Result<Self> {
        Ok(Self {
            instance: Instance::new(settings)?,
        })
    }

    /// Accepts one TCP connection to `port` of this node's virtual
    /// address. A client only dials out in normal use; this serves tests
    /// that pass traffic between two nodes.
    #[doc(hidden)]
    pub async fn accept_tcp(&self, port: u16) -> io::Result<BoxStream> {
        self.instance.ensure_running()?;
        let handle = self.instance.listen_tcp(port)?;
        let stream = MeshTcpStream {
            instance: self.instance.clone(),
            handle,
        };
        self.instance.wake();
        stream.wait_established(true).await?;
        Ok(Box::new(stream))
    }

    /// Like [`TcpOutbound::open_udp`] with a fixed local port; for tests.
    #[doc(hidden)]
    pub async fn open_udp_on(&self, port: u16, target: &TargetAddr) -> io::Result<UdpFlow> {
        self.udp_flow(Some(port), target).await
    }

    /// The address to reach `target` at: an IP target as it is, a domain
    /// through the system resolver; either way only an address the network
    /// reaches (spec §15.4: nothing outside the mesh routes is sent).
    async fn remote(&self, target: &TargetAddr) -> io::Result<SocketAddr> {
        let checked = |address: SocketAddr| {
            if self.instance.reaches(address.ip()) {
                Ok(address)
            } else {
                Err(unreachable_address())
            }
        };
        match target {
            TargetAddr::Ip(address) => checked(*address),
            TargetAddr::Domain(host, port) => {
                if let Ok(address) = host.parse::<IpAddr>() {
                    return checked(SocketAddr::new(address, *port));
                }
                let lookup = tokio::net::lookup_host((host.as_str(), *port));
                let addresses = tokio::time::timeout(RESOLVE_TIMEOUT, lookup)
                    .await
                    .map_err(|_| {
                        io::Error::new(io::ErrorKind::TimedOut, "domain did not resolve")
                    })??;
                let mut addresses = addresses.collect::<Vec<_>>();
                addresses.sort_by_key(SocketAddr::is_ipv6);
                addresses
                    .into_iter()
                    .find(|address| self.instance.reaches(address.ip()))
                    .ok_or_else(|| {
                        io::Error::new(
                            io::ErrorKind::NotFound,
                            "domain has no address in the mesh network",
                        )
                    })
            }
        }
    }

    async fn tcp(&self, target: &TargetAddr) -> io::Result<BoxStream> {
        self.instance.ensure_running()?;
        let remote = self.remote(target).await?;
        let handle = self.instance.open_tcp(remote)?;
        let stream = MeshTcpStream {
            instance: self.instance.clone(),
            handle,
        };
        self.instance.wake();
        match tokio::time::timeout(CONNECT_TIMEOUT, stream.wait_established(false)).await {
            Ok(Ok(())) => Ok(Box::new(stream)),
            Ok(Err(err)) => Err(err),
            Err(_) => Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "mesh connection timed out",
            )),
        }
    }

    async fn udp_flow(&self, port: Option<u16>, target: &TargetAddr) -> io::Result<UdpFlow> {
        self.instance.ensure_running()?;
        let remote = self.remote(target).await?;
        let socket = Arc::new(UdpHandle::open(&self.instance, port)?);
        Ok(UdpFlow::new(
            Box::new(MeshUdpSend {
                socket: socket.clone(),
                remote,
            }),
            Box::new(MeshUdpRecv { socket, remote }),
        ))
    }
}

impl TcpOutbound for MeshOutbound {
    fn protocol(&self) -> &'static str {
        TYPE_NAME
    }

    fn connect<'a>(&'a self, target: &'a TargetAddr) -> BoxFuture<'a, io::Result<BoxStream>> {
        Box::pin(self.tcp(target))
    }

    fn open_udp<'a>(&'a self, target: &'a TargetAddr) -> BoxFuture<'a, io::Result<UdpFlow>> {
        Box::pin(self.udp_flow(None, target))
    }

    fn health(&self) -> Option<serde_json::Value> {
        let (running, failure) = self.instance.state();
        let members = self.instance.snapshot().borrow().members.len();
        Some(serde_json::json!({
            "running": running,
            "members": members,
            "failure": failure.map(Failure::code),
        }))
    }
}

/// A TCP connection of the private stack.
struct MeshTcpStream {
    instance: Arc<Instance>,
    handle: SocketHandle,
}

impl MeshTcpStream {
    /// Waits for the handshake; `listening` sockets may also sit in LISTEN.
    async fn wait_established(&self, listening: bool) -> io::Result<()> {
        std::future::poll_fn(|cx| {
            self.instance
                .with_socket::<tcp::Socket, _>(self.handle, |socket| match socket.state() {
                    tcp::State::Established | tcp::State::CloseWait => Poll::Ready(Ok(())),
                    tcp::State::SynSent | tcp::State::SynReceived => {
                        socket.register_send_waker(cx.waker());
                        Poll::Pending
                    }
                    tcp::State::Listen if listening => {
                        socket.register_send_waker(cx.waker());
                        Poll::Pending
                    }
                    _ => Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::ConnectionRefused,
                        "mesh connection was refused",
                    ))),
                })
        })
        .await
    }
}

impl AsyncRead for MeshTcpStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let read = self
            .instance
            .with_socket::<tcp::Socket, _>(self.handle, |socket| {
                if socket.can_recv() {
                    return match socket.recv_slice(buf.initialize_unfilled()) {
                        Ok(read) => Poll::Ready(Ok(read)),
                        Err(_) => Poll::Ready(Ok(0)),
                    };
                }
                if !socket.may_recv() {
                    // End of stream, or the connection was reset.
                    return Poll::Ready(Ok(0));
                }
                socket.register_recv_waker(cx.waker());
                Poll::Pending
            });
        match read {
            Poll::Ready(Ok(read)) => {
                buf.advance(read);
                if read > 0 {
                    // The window opened; let the stack tell the peer.
                    self.instance.wake();
                }
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(err)) => Poll::Ready(Err(err)),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWrite for MeshTcpStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        let written = self
            .instance
            .with_socket::<tcp::Socket, _>(self.handle, |socket| {
                if !socket.may_send() {
                    return Poll::Ready(Err(closed()));
                }
                if socket.can_send() {
                    return Poll::Ready(socket.send_slice(data).map_err(|_| closed()));
                }
                socket.register_send_waker(cx.waker());
                Poll::Pending
            });
        if matches!(written, Poll::Ready(Ok(_))) {
            self.instance.wake();
        }
        written
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.instance
            .with_socket::<tcp::Socket, _>(self.handle, |socket| socket.close());
        self.instance.wake();
        Poll::Ready(Ok(()))
    }
}

impl Drop for MeshTcpStream {
    fn drop(&mut self) {
        self.instance.release_tcp(self.handle);
    }
}

struct MeshUdpSend {
    socket: Arc<UdpHandle>,
    remote: SocketAddr,
}

impl DatagramSend for MeshUdpSend {
    fn send<'a>(&'a mut self, payload: &'a [u8]) -> BoxFuture<'a, io::Result<()>> {
        Box::pin(self.socket.send_to(payload, self.remote))
    }
}

/// Only datagrams from the flow's destination: another member cannot
/// answer for it.
struct MeshUdpRecv {
    socket: Arc<UdpHandle>,
    remote: SocketAddr,
}

impl DatagramRecv for MeshUdpRecv {
    fn recv(&mut self) -> BoxFuture<'_, io::Result<Vec<u8>>> {
        Box::pin(self.socket.recv(Some(self.remote)))
    }
}
