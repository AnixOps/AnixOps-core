//! QUIC transport for QUIC-based protocols (Hysteria2, TUIC, ...): quinn
//! over rustls, with TLS settings, roots, certificate pins and `insecure`
//! from `transport-tls` on the client side, and [`server_endpoint`] for
//! server inbounds.
//!
//! [`QuicConnector`] resolves the server, binds a UDP socket of the matching
//! family and returns an established [`QuicConnection`]; when the server
//! has several addresses they are tried one after another in Happy Eyeballs
//! order ([`engine_outbound::happy_eyeballs`]), so an address family whose
//! UDP is dropped does not take the whole handshake timeout; the protocol crate
//! authenticates on it and opens one stream per proxied connection.
//! [`QuicStream`] turns a bidirectional stream into a [`BoxStream`].
//! [`QuicConnector::with_salamander`] obfuscates every datagram with
//! [`salamander::Salamander`]. [`QuicConnector::connect_over`] runs the
//! connection on a proxied [`engine_outbound::UdpFlow`] instead
//! ([`flow::FlowSocket`]); [`QuicConnector::connect_through`] picks between
//! the two by the [`engine_outbound::Dialer`] the caller was given.

pub mod flow;
pub mod salamander;
pub mod shared;

use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use engine_outbound::BoxStream;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use transport_tls::TlsSettings;

pub use quinn;

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
/// How long a handshake with one of the server's addresses may run before
/// the next address is tried, when there is one. The last address has the
/// rest of [`HANDSHAKE_TIMEOUT`]. Long enough for a few Initial
/// retransmissions on a lossy path, short enough that an address family
/// whose UDP is dropped (IPv6 first, by the resolver's order) leaves most
/// of the budget to the other.
const ADDRESS_ATTEMPT_LIMIT: Duration = Duration::from_secs(3);
const MAX_IDLE_TIMEOUT: Duration = Duration::from_secs(30);
const KEEP_ALIVE_INTERVAL: Duration = Duration::from_secs(10);
const STREAM_RECEIVE_WINDOW: u32 = 8 * 1024 * 1024;
const CONNECTION_RECEIVE_WINDOW: u32 = 20 * 1024 * 1024;
/// Largest UDP payload MTU discovery probes for, as quinn's default.
const MAX_UDP_PAYLOAD: u16 = 1452;

/// Congestion controller of the connection.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Congestion {
    #[default]
    Cubic,
    NewReno,
    Bbr,
}

impl Congestion {
    /// Parses the names share links and configs use (`cubic`, `new_reno`,
    /// `newreno`, `bbr`).
    pub fn from_name(name: &str) -> Option<Self> {
        match name.to_ascii_lowercase().as_str() {
            "cubic" => Some(Self::Cubic),
            "new_reno" | "newreno" | "new-reno" => Some(Self::NewReno),
            "bbr" => Some(Self::Bbr),
            _ => None,
        }
    }
}

/// A configured client for one server; cheap to share.
pub struct QuicConnector {
    server: String,
    port: u16,
    server_name: String,
    congestion: Congestion,
    client_config: quinn::ClientConfig,
    salamander: Option<salamander::Salamander>,
}

/// An established connection and the endpoint that drives its socket.
pub struct QuicConnection {
    pub connection: quinn::Connection,
    _endpoint: quinn::Endpoint,
}

impl QuicConnector {
    /// `tls.alpn` falls back to `default_alpn` when empty.
    pub fn new(
        server: impl Into<String>,
        port: u16,
        tls: &TlsSettings,
        default_alpn: &[&str],
        congestion: Congestion,
    ) -> io::Result<Self> {
        let server = server.into();
        if server.is_empty() || port == 0 {
            return Err(invalid("quic server address is empty"));
        }
        let mut tls = tls.clone();
        if tls.alpn.is_empty() {
            tls.alpn = default_alpn.iter().map(|alpn| (*alpn).to_owned()).collect();
        }
        let crypto =
            quinn::crypto::rustls::QuicClientConfig::try_from(transport_tls::client_config(&tls)?)
                .map_err(|_| invalid("tls settings are unusable for quic"))?;
        let mut client_config = quinn::ClientConfig::new(Arc::new(crypto));
        client_config.transport_config(Arc::new(transport_config(congestion, 0)?));
        Ok(Self {
            server,
            port,
            server_name: tls.server_name,
            congestion,
            client_config,
            salamander: None,
        })
    }

    /// Obfuscates every datagram of this connector's connections.
    pub fn with_salamander(mut self, salamander: salamander::Salamander) -> io::Result<Self> {
        // The salt makes each datagram longer; keep them within the usual
        // path MTU.
        self.client_config
            .transport_config(Arc::new(transport_config(
                self.congestion,
                salamander::SALT_LEN as u16,
            )?));
        self.salamander = Some(salamander);
        Ok(self)
    }

    /// No keep-alive: an idle connection closes after the idle timeout, for
    /// clients (DNS over QUIC) that only need it while queries are sent.
    pub fn without_keep_alive(mut self) -> io::Result<Self> {
        let mut transport = transport_config(self.congestion, 0)?;
        transport.keep_alive_interval(None);
        self.client_config.transport_config(Arc::new(transport));
        Ok(self)
    }

    /// Completes the QUIC handshake on `flow`, a UDP flow already open to
    /// the server (through a proxy, or the direct outbound), within a
    /// timeout. Salamander is not applied.
    pub async fn connect_over(
        &self,
        flow: engine_outbound::UdpFlow,
        timeout: Duration,
    ) -> io::Result<QuicConnection> {
        let peer = match self.server.parse::<std::net::IpAddr>() {
            Ok(ip) => std::net::SocketAddr::new(ip, self.port),
            Err(_) => flow::FlowSocket::placeholder_peer(self.port),
        };
        let socket = flow::FlowSocket::new(flow, peer);
        let runtime = quinn::default_runtime()
            .ok_or_else(|| io::Error::other("no async runtime for quic"))?;
        let endpoint = quinn::Endpoint::new_with_abstract_socket(
            quinn::EndpointConfig::default(),
            None,
            socket,
            runtime,
        )?;
        let connecting = endpoint
            .connect_with(self.client_config.clone(), peer, &self.server_name)
            .map_err(|_| invalid("quic connect settings are invalid"))?;
        let connection = tokio::time::timeout(timeout.min(HANDSHAKE_TIMEOUT), connecting)
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "quic handshake timed out"))?
            .map_err(quic_error)?;
        Ok(QuicConnection {
            connection,
            _endpoint: endpoint,
        })
    }

    /// Completes the QUIC handshake with the server reached through
    /// `dialer`, within a timeout. The system dialer
    /// ([`engine_outbound::Dialer::is_system`]) gets a socket of this
    /// connector's own, as [`QuicConnector::connect`]. Any other dialer (a
    /// `via` chain, a host dialer with its own resolver) opens the datagram
    /// flow ([`engine_outbound::Dialer::open_datagram`]) and resolves the
    /// server name itself; when it cannot carry UDP the connection fails and
    /// never falls back to a socket of its own.
    pub async fn connect_through(
        &self,
        dialer: &dyn engine_outbound::Dialer,
    ) -> io::Result<QuicConnection> {
        if dialer.is_system() {
            return self.connect().await;
        }
        if self.salamander.is_some() {
            // `connect_over` does not obfuscate, and the datagrams must not
            // leave in the clear.
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "quic with salamander cannot run through another dialer",
            ));
        }
        let deadline = tokio::time::Instant::now() + HANDSHAKE_TIMEOUT;
        let flow = tokio::time::timeout_at(deadline, dialer.open_datagram(&self.server, self.port))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "quic handshake timed out"))?
            .map_err(|error| {
                io::Error::new(
                    error.kind(),
                    format!("no udp path to the quic server through the dialer: {error}"),
                )
            })?;
        let left = deadline.saturating_duration_since(tokio::time::Instant::now());
        self.connect_over(flow, left).await
    }

    /// Resolves the server with the system resolver and completes the QUIC
    /// handshake on a protected socket of its own, within a timeout. Every
    /// resolved address is tried ([`QuicConnector::connect_addresses`]),
    /// and the family that answered goes first next time.
    pub async fn connect(&self) -> io::Result<QuicConnection> {
        tokio::time::timeout(HANDSHAKE_TIMEOUT, self.connect_inner())
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "quic handshake timed out"))?
    }

    async fn connect_inner(&self) -> io::Result<QuicConnection> {
        engine_outbound::happy_eyeballs::connect_host(
            &self.server,
            self.port,
            engine_outbound::happy_eyeballs::Transport::Udp,
            engine_outbound::happy_eyeballs::Schedule::Sequential {
                limit: ADDRESS_ATTEMPT_LIMIT,
            },
            |addr| self.connect_address(addr),
        )
        .await
        .map(|(_addr, connection)| connection)
        .map_err(|error| match error.kind() {
            io::ErrorKind::NotFound => {
                io::Error::new(io::ErrorKind::NotFound, "quic server not found")
            }
            _ => error,
        })
    }

    /// Completes the QUIC handshake with the first of `addresses` that
    /// answers, on protected sockets of this connector's own, within a
    /// timeout. The addresses are tried in the given order, one at a time:
    /// a handshake that has not finished within a few seconds is dropped
    /// for the next address, and the last address has the rest of the
    /// time. [`QuicConnector::connect`] resolves the server and calls this
    /// with its addresses in Happy Eyeballs order
    /// ([`engine_outbound::happy_eyeballs`]).
    pub async fn connect_addresses(
        &self,
        addresses: &[std::net::SocketAddr],
    ) -> io::Result<QuicConnection> {
        let attempts = engine_outbound::happy_eyeballs::connect(
            addresses,
            engine_outbound::happy_eyeballs::Schedule::Sequential {
                limit: ADDRESS_ATTEMPT_LIMIT,
            },
            |addr| self.connect_address(addr),
        );
        tokio::time::timeout(HANDSHAKE_TIMEOUT, attempts)
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "quic handshake timed out"))?
            .map(|(_addr, connection)| connection)
    }

    /// One handshake with `addr`, on a socket of the address's family (the
    /// protector pins each family to its own interface) with its own
    /// endpoint, so a dropped attempt takes its socket with it.
    async fn connect_address(&self, addr: std::net::SocketAddr) -> io::Result<QuicConnection> {
        // An explicit socket instead of `Endpoint::client`, so the host's
        // socket protector keeps it off a packet tunnel.
        let socket = engine_outbound::protect::bind_std_udp(
            engine_outbound::protect::unspecified_for(addr),
            addr,
        )?;
        let runtime = quinn::default_runtime()
            .ok_or_else(|| io::Error::other("no async runtime for quic"))?;
        let socket = runtime.wrap_udp_socket(socket)?;
        let socket: Arc<dyn quinn::AsyncUdpSocket> = match &self.salamander {
            None => socket,
            Some(salamander) => salamander::SalamanderSocket::new(socket, salamander.clone())
                as Arc<dyn quinn::AsyncUdpSocket>,
        };
        let endpoint = quinn::Endpoint::new_with_abstract_socket(
            quinn::EndpointConfig::default(),
            None,
            socket,
            runtime,
        )?;
        let connection = endpoint
            .connect_with(self.client_config.clone(), addr, &self.server_name)
            .map_err(|_| invalid("quic connect settings are invalid"))?
            .await
            .map_err(quic_error)?;
        Ok(QuicConnection {
            connection,
            _endpoint: endpoint,
        })
    }
}

/// A server endpoint on `socket` with the transport settings clients use,
/// optionally obfuscating every datagram with Salamander.
pub fn server_endpoint(
    socket: std::net::UdpSocket,
    crypto: Arc<quinn::crypto::rustls::QuicServerConfig>,
    congestion: Congestion,
    salamander: Option<salamander::Salamander>,
) -> io::Result<quinn::Endpoint> {
    let overhead = if salamander.is_some() {
        salamander::SALT_LEN as u16
    } else {
        0
    };
    let mut server_config = quinn::ServerConfig::with_crypto(crypto);
    server_config.transport_config(Arc::new(transport_config(congestion, overhead)?));
    let runtime =
        quinn::default_runtime().ok_or_else(|| io::Error::other("no async runtime for quic"))?;
    socket.set_nonblocking(true)?;
    let socket = runtime.wrap_udp_socket(socket)?;
    let socket: Arc<dyn quinn::AsyncUdpSocket> = match salamander {
        Some(salamander) => {
            salamander::SalamanderSocket::new(socket, salamander) as Arc<dyn quinn::AsyncUdpSocket>
        }
        None => socket,
    };
    quinn::Endpoint::new_with_abstract_socket(
        quinn::EndpointConfig::default(),
        Some(server_config),
        socket,
        runtime,
    )
}

/// Windows, keep-alive, idle timeout and congestion control; `overhead` bytes
/// per datagram are kept free below the MTU discovery limit.
fn transport_config(congestion: Congestion, overhead: u16) -> io::Result<quinn::TransportConfig> {
    let mut transport = quinn::TransportConfig::default();
    transport
        .stream_receive_window(quinn::VarInt::from_u32(STREAM_RECEIVE_WINDOW))
        .receive_window(quinn::VarInt::from_u32(CONNECTION_RECEIVE_WINDOW))
        .keep_alive_interval(Some(KEEP_ALIVE_INTERVAL))
        .max_idle_timeout(Some(
            quinn::IdleTimeout::try_from(MAX_IDLE_TIMEOUT)
                .map_err(|_| invalid("quic idle timeout is invalid"))?,
        ));
    if overhead > 0 {
        let mut mtu = quinn::MtuDiscoveryConfig::default();
        mtu.upper_bound(MAX_UDP_PAYLOAD - overhead);
        transport.mtu_discovery_config(Some(mtu));
    }
    match congestion {
        Congestion::Cubic => {}
        Congestion::NewReno => {
            transport.congestion_controller_factory(Arc::new(
                quinn::congestion::NewRenoConfig::default(),
            ));
        }
        Congestion::Bbr => {
            transport
                .congestion_controller_factory(Arc::new(quinn::congestion::BbrConfig::default()));
        }
    }
    Ok(transport)
}

/// One proxied connection on a bidirectional QUIC stream. The tokio trait
/// methods are called by path because quinn's inherent `poll_read` and
/// `poll_write` return quinn error types.
pub struct QuicStream {
    send: quinn::SendStream,
    recv: quinn::RecvStream,
    /// What keeps the stream's connection open while the stream lives,
    /// such as a [`shared::Hold`].
    _hold: Option<Box<dyn std::any::Any + Send + Sync>>,
}

impl QuicStream {
    pub fn new(send: quinn::SendStream, recv: quinn::RecvStream) -> Self {
        Self {
            send,
            recv,
            _hold: None,
        }
    }

    pub fn boxed(send: quinn::SendStream, recv: quinn::RecvStream) -> BoxStream {
        Box::new(Self::new(send, recv))
    }

    /// Keeps `hold` (a [`shared::Hold`] on the connection) until the stream
    /// is dropped.
    pub fn holding(mut self, hold: impl std::any::Any + Send + Sync) -> Self {
        self._hold = Some(Box::new(hold));
        self
    }
}

impl AsyncRead for QuicStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        AsyncRead::poll_read(Pin::new(&mut self.recv), cx, buf)
    }
}

impl AsyncWrite for QuicStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        AsyncWrite::poll_write(Pin::new(&mut self.send), cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        AsyncWrite::poll_flush(Pin::new(&mut self.send), cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        AsyncWrite::poll_shutdown(Pin::new(&mut self.send), cx)
    }
}

/// Maps a quinn connection error to `ConnectionAborted`.
pub fn quic_error(err: impl std::error::Error + Send + Sync + 'static) -> io::Error {
    io::Error::new(io::ErrorKind::ConnectionAborted, err)
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}
