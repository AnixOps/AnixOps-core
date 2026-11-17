//! Direct outbound: connects to the target without a proxy protocol.
//!
//! With `"interface": "<name>"` (Surge `direct, interface=...`) every socket
//! is pinned to that network interface instead, such as a company VPN's,
//! and a domain target is resolved by the system resolver (which follows the
//! VPN's split DNS on desktop systems); see [`crate::interface`].

use std::io;
use std::sync::Arc;

use engine_outbound::registry::{parse_settings, BuildError, OutboundFactory, Settings};
use engine_outbound::{
    BoxFuture, BoxStream, DatagramRecv, DatagramSend, Dialer, TargetAddr, TcpOutbound, UdpFlow,
    MAX_DATAGRAM,
};
use tokio::net::UdpSocket;

pub const PROTOCOL: &str = "direct";

pub struct DirectOutbound {
    dialer: Arc<dyn Dialer>,
    /// The interface every socket is pinned to, if any.
    interface: Option<String>,
}

impl DirectOutbound {
    pub fn new(dialer: Arc<dyn Dialer>) -> Self {
        Self {
            dialer,
            interface: None,
        }
    }

    /// A direct outbound whose sockets all leave through interface `name`.
    pub fn bound_to(dialer: Arc<dyn Dialer>, name: impl Into<String>) -> Self {
        Self {
            dialer,
            interface: Some(name.into()),
        }
    }

    /// The interface this outbound is pinned to.
    pub fn interface(&self) -> Option<&str> {
        self.interface.as_deref()
    }
}

/// The addresses of `target`, a domain resolved by the system.
async fn addresses(target: &TargetAddr) -> io::Result<Vec<std::net::SocketAddr>> {
    let addresses: Vec<_> = match target {
        TargetAddr::Ip(address) => vec![*address],
        TargetAddr::Domain(domain, port) => tokio::net::lookup_host((domain.as_str(), *port))
            .await?
            .collect(),
    };
    if addresses.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "target did not resolve",
        ));
    }
    Ok(addresses)
}

impl TcpOutbound for DirectOutbound {
    fn protocol(&self) -> &'static str {
        PROTOCOL
    }

    fn connect<'a>(&'a self, target: &'a TargetAddr) -> BoxFuture<'a, io::Result<BoxStream>> {
        Box::pin(async move {
            let Some(interface) = self.interface.as_deref() else {
                let host = target.host();
                return self.dialer.dial(&host, target.port()).await;
            };
            let mut last_error = None;
            for address in addresses(target).await? {
                match crate::interface::connect_tcp(interface, address).await {
                    Ok(stream) => {
                        let _ = stream.set_nodelay(true);
                        return Ok(Box::new(stream) as BoxStream);
                    }
                    // A missing interface is missing for every address.
                    Err(error) if error.kind() == io::ErrorKind::NotFound => return Err(error),
                    Err(error) => last_error = Some(error),
                }
            }
            Err(last_error.unwrap_or_else(|| io::Error::from(io::ErrorKind::NotFound)))
        })
    }

    /// A connected UDP socket of its own; a domain is resolved by the system.
    fn open_udp<'a>(&'a self, target: &'a TargetAddr) -> BoxFuture<'a, io::Result<UdpFlow>> {
        Box::pin(async move {
            let address = match target {
                TargetAddr::Ip(address) => *address,
                TargetAddr::Domain(domain, port) => {
                    tokio::net::lookup_host((domain.as_str(), *port))
                        .await?
                        .next()
                        .ok_or_else(|| {
                            io::Error::new(io::ErrorKind::NotFound, "udp target did not resolve")
                        })?
                }
            };
            let socket = match self.interface.as_deref() {
                Some(interface) => {
                    Arc::new(crate::interface::connect_udp(interface, address).await?)
                }
                None => {
                    let socket = engine_outbound::protect::bind_udp(address)?;
                    socket.connect(address).await?;
                    Arc::new(socket)
                }
            };
            Ok(UdpFlow::new(
                Box::new(DirectSend(socket.clone())),
                Box::new(DirectRecv {
                    socket,
                    buf: vec![0u8; MAX_DATAGRAM],
                }),
            ))
        })
    }
}

struct DirectSend(Arc<UdpSocket>);

impl DatagramSend for DirectSend {
    fn send<'a>(&'a mut self, payload: &'a [u8]) -> BoxFuture<'a, io::Result<()>> {
        Box::pin(async move { self.0.send(payload).await.map(|_| ()) })
    }
}

struct DirectRecv {
    socket: Arc<UdpSocket>,
    buf: Vec<u8>,
}

impl DatagramRecv for DirectRecv {
    fn recv(&mut self) -> BoxFuture<'_, io::Result<Vec<u8>>> {
        Box::pin(async move {
            let n = self.socket.recv(&mut self.buf).await?;
            Ok(self.buf[..n].to_vec())
        })
    }
}

/// Registry entry for `"type": "direct"`. Its one optional setting is
/// `interface`, the network interface every socket is pinned to.
pub struct DirectFactory;

#[derive(serde::Deserialize)]
struct DirectSettings {
    #[serde(default)]
    interface: Option<String>,
}

impl OutboundFactory for DirectFactory {
    fn type_name(&self) -> &'static str {
        PROTOCOL
    }

    fn build(
        &self,
        settings: &Settings,
        dialer: Arc<dyn Dialer>,
    ) -> Result<Arc<dyn TcpOutbound>, BuildError> {
        if !settings.contains_key("interface") {
            return Ok(Arc::new(DirectOutbound::new(dialer)));
        }
        let parsed: DirectSettings =
            parse_settings(settings, "direct interface must be an interface name")?;
        match parsed.interface {
            Some(name) if crate::interface::valid_name(&name) => {
                Ok(Arc::new(DirectOutbound::bound_to(dialer, name)))
            }
            Some(_) => Err("direct interface must be an interface name"),
            None => Ok(Arc::new(DirectOutbound::new(dialer))),
        }
    }
}
