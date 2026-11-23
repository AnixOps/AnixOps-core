//! Direct outbound: connects to the target without a proxy protocol.
//!
//! With `"interface": "<name>"` (Surge `direct, interface=...`) every socket
//! is pinned to that network interface instead, such as a company VPN's,
//! and a domain target is resolved by the system resolver (which follows the
//! VPN's split DNS on desktop systems); see [`crate::interface`].

use std::io;
use std::sync::Arc;

use engine_outbound::happy_eyeballs::{self, Schedule, Transport};
use engine_outbound::registry::{parse_settings, BuildError, OutboundFactory, Settings};
use engine_outbound::{BoxFuture, BoxStream, Dialer, TargetAddr, TcpOutbound, UdpFlow};

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

/// The addresses of `target` in the order to try them over `transport`, a
/// domain resolved by the system ([`happy_eyeballs::resolve`]).
async fn addresses(
    target: &TargetAddr,
    transport: Transport,
) -> io::Result<Vec<std::net::SocketAddr>> {
    match target {
        TargetAddr::Ip(address) => Ok(vec![*address]),
        TargetAddr::Domain(domain, port) => happy_eyeballs::resolve(domain, *port, transport)
            .await
            .map_err(|error| match error.kind() {
                io::ErrorKind::NotFound => {
                    io::Error::new(io::ErrorKind::NotFound, "target did not resolve")
                }
                _ => error,
            }),
    }
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
            let addresses = addresses(target, Transport::Tcp).await?;
            let (address, stream) = happy_eyeballs::connect(&addresses, Schedule::TCP, |address| {
                crate::interface::connect_tcp(interface, address)
            })
            .await?;
            if let TargetAddr::Domain(domain, _) = target {
                happy_eyeballs::remember(domain, Transport::Tcp, address);
            }
            let _ = stream.set_nodelay(true);
            Ok(Box::new(stream) as BoxStream)
        })
    }

    /// A connected UDP socket of its own; a domain is resolved by the system.
    fn open_udp<'a>(&'a self, target: &'a TargetAddr) -> BoxFuture<'a, io::Result<UdpFlow>> {
        Box::pin(async move {
            // No handshake to race on: the first address in
            // `happy_eyeballs` order for UDP, the family QUIC last connected
            // with, else the family TCP did.
            let address = match target {
                TargetAddr::Ip(address) => *address,
                TargetAddr::Domain(..) => {
                    addresses(target, Transport::Udp)
                        .await
                        .map_err(|error| match error.kind() {
                            io::ErrorKind::NotFound => io::Error::new(
                                io::ErrorKind::NotFound,
                                "udp target did not resolve",
                            ),
                            _ => error,
                        })?[0]
                }
            };
            let socket = match self.interface.as_deref() {
                Some(interface) => crate::interface::connect_udp(interface, address).await?,
                None => {
                    let socket = engine_outbound::protect::bind_udp(address)?;
                    socket.connect(address).await?;
                    socket
                }
            };
            Ok(UdpFlow::connected_socket(Arc::new(socket)))
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
