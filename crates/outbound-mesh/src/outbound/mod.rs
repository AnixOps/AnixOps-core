//! `"type": "mesh"` as a routable outbound of the embedded engine
//! (`docs/architecture/mesh-module.md`, 分流): every TCP connection and UDP
//! flow to a member's virtual address, or to a subnet a member advertises,
//! opens inside the network's private stack ([`stack`]); nothing is sent for
//! any other destination.
//!
//! The engine finds a network by its `network.name`, not by the outbound's
//! key: building the same settings again (a new profile that keeps the
//! network) returns the running network, so its sessions and member links
//! stay ([`MeshFactory`]). Changed settings stop the old network at once,
//! connections included, and start a new one: the old one would keep the
//! previous `native_keys` (spec §8.3.1) and dial with the same identity.

pub mod snapshot;
mod stack;

use std::collections::BTreeMap;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::{Arc, Mutex, Weak};
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

use stack::{closed, unreachable_address, UdpHandle};
pub use stack::{Failure, Instance};

/// How long a TCP connection may take to establish inside the network.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// How long a domain target may take to resolve.
const RESOLVE_TIMEOUT: Duration = Duration::from_secs(5);

/// The networks built so far, by `network.name`; an entry lives as long as
/// an outbound uses it.
static INSTANCES: Mutex<BTreeMap<String, Weak<Instance>>> = Mutex::new(BTreeMap::new());

/// The running network for `settings`, or a new one.
fn instance_for(settings: MeshSettings) -> io::Result<Arc<Instance>> {
    let mut instances = INSTANCES
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    instances.retain(|_, instance| instance.strong_count() > 0);
    if let Some(instance) = instances
        .get(&settings.network_name)
        .and_then(Weak::upgrade)
        .filter(|instance| !instance.is_retired())
    {
        if same_settings(instance.settings(), &settings) {
            return Ok(instance);
        }
        instance.retire();
    }
    let name = settings.network_name.clone();
    let instance = Instance::new(settings)?;
    instances.insert(name, Arc::downgrade(&instance));
    Ok(instance)
}

/// Whether a running network can serve `settings` as it is. [`IpNet`]
/// equality compares networks only, so the node's own addresses are
/// compared apart: a new address inside the same subnet is a new network.
fn same_settings(running: &MeshSettings, wanted: &MeshSettings) -> bool {
    running == wanted && running.local_addresses() == wanted.local_addresses()
}

/// The running network named `name` (`network.name`), while an outbound
/// uses it.
pub fn instance(name: &str) -> Option<Arc<Instance>> {
    INSTANCES
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .get(name)
        .and_then(Weak::upgrade)
        .filter(|instance| !instance.is_retired())
}

pub struct MeshFactory;

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
        let instance = instance_for(settings).map_err(|_| "mesh static key could not be made")?;
        Ok(Arc::new(MeshOutbound { instance }))
    }
}

/// One mesh network as an outbound. Clones share the network.
#[derive(Clone)]
pub struct MeshOutbound {
    instance: Arc<Instance>,
}

impl MeshOutbound {
    /// An outbound for `settings`, sharing a running network with the same
    /// settings.
    pub fn new(settings: MeshSettings) -> io::Result<Self> {
        Ok(Self {
            instance: instance_for(settings)?,
        })
    }

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
