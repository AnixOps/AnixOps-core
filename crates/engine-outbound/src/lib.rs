//! Outbound interfaces shared by `engine-embedded` and its protocol crates.
//!
//! A protocol crate (Shadowsocks-2022, VLESS + REALITY, ...) implements
//! [`TcpOutbound`]. The engine builds each outbound with an injected
//! [`Dialer`], so the Network Extension can replace [`TcpDialer`] with a
//! dialer bound to the physical interface or using its own resolver.
//!
//! [`registry`] maps config `type` names to per-protocol factories, so an
//! engine can add or drop protocols with cargo features.
//!
//! UDP goes through [`TcpOutbound::open_udp`], one [`UdpFlow`] per
//! destination; protocols without UDP keep its default, which fails with
//! [`io::ErrorKind::Unsupported`].
//!
//! Errors are plain [`std::io::Error`] values. Implementations must keep
//! credentials (UUIDs, passwords, private keys) out of error messages.

pub mod accept;
pub mod backbone;
pub mod gauge;
pub mod happy_eyeballs;
pub mod mux;
pub mod protect;
pub mod quic_sniff;
pub mod registry;
pub mod reject;
pub mod sniff;

use std::fmt;
use std::future::Future;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::net::UdpSocket;

/// Boxed `Send` future used by the object-safe traits in this crate.
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// A bidirectional byte stream returned by dialers and outbounds.
pub trait ProxyStream: AsyncRead + AsyncWrite + Unpin + Send + 'static {}

impl<T: AsyncRead + AsyncWrite + Unpin + Send + 'static> ProxyStream for T {}

/// Owned, type-erased [`ProxyStream`].
pub type BoxStream = Box<dyn ProxyStream>;

/// Destination requested by the routing layer.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum TargetAddr {
    Ip(SocketAddr),
    Domain(String, u16),
}

impl TargetAddr {
    pub fn port(&self) -> u16 {
        match self {
            TargetAddr::Ip(addr) => addr.port(),
            TargetAddr::Domain(_, port) => *port,
        }
    }

    /// An address target when `host` is an IP address, else a name.
    pub fn from_host(host: &str, port: u16) -> Self {
        match host
            .trim_start_matches('[')
            .trim_end_matches(']')
            .parse::<IpAddr>()
        {
            Ok(ip) => TargetAddr::Ip(SocketAddr::new(ip, port)),
            Err(_) => TargetAddr::Domain(host.to_string(), port),
        }
    }

    /// Host part without the port, suitable for a [`Dialer`].
    pub fn host(&self) -> String {
        match self {
            TargetAddr::Ip(addr) => addr.ip().to_string(),
            TargetAddr::Domain(domain, _) => domain.clone(),
        }
    }
}

impl From<SocketAddr> for TargetAddr {
    fn from(addr: SocketAddr) -> Self {
        TargetAddr::Ip(addr)
    }
}

impl From<(IpAddr, u16)> for TargetAddr {
    fn from((ip, port): (IpAddr, u16)) -> Self {
        TargetAddr::Ip(SocketAddr::new(ip, port))
    }
}

impl fmt::Display for TargetAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TargetAddr::Ip(addr) => write!(f, "{addr}"),
            TargetAddr::Domain(domain, port) => write!(f, "{domain}:{port}"),
        }
    }
}

/// `host` as it goes in a URI authority or an HTTP `Host` header: an IPv6
/// address literal in brackets (RFC 3986 §3.2.2), anything else (a name, an
/// IPv4 address, an already bracketed address, a `host:port`) unchanged.
pub fn uri_host(host: &str) -> std::borrow::Cow<'_, str> {
    if host.parse::<std::net::Ipv6Addr>().is_ok() {
        std::borrow::Cow::Owned(format!("[{host}]"))
    } else {
        std::borrow::Cow::Borrowed(host)
    }
}

/// Opens the underlying transport connection to a proxy server.
pub trait Dialer: Send + Sync {
    fn dial<'a>(&'a self, host: &'a str, port: u16) -> BoxFuture<'a, io::Result<BoxStream>>;

    /// Opens a datagram path to a proxy server, for protocols whose UDP
    /// goes to the server as datagrams (Shadowsocks, SOCKS5 UDP ASSOCIATE).
    /// The default is a system UDP socket connected to the server.
    fn open_datagram<'a>(&'a self, host: &'a str, port: u16) -> BoxFuture<'a, io::Result<UdpFlow>> {
        Box::pin(socket_flow(host, port))
    }

    /// Whether this is the system dialer ([`TcpDialer`]): its connections
    /// and datagrams are protected system sockets to the address the system
    /// resolver gives. Only then may a transport that wants a socket of its
    /// own (QUIC) open one the same way. With any other dialer (a `via`
    /// chain, a host dialer with its own resolver or interface) it must send
    /// its datagrams through [`Dialer::open_datagram`] and leave the server
    /// name to the dialer. The default is `false`.
    fn is_system(&self) -> bool {
        false
    }
}

/// Default dialer: a plain tokio TCP connection with `TCP_NODELAY`.
#[derive(Clone, Copy, Debug, Default)]
pub struct TcpDialer;

impl Dialer for TcpDialer {
    fn dial<'a>(&'a self, host: &'a str, port: u16) -> BoxFuture<'a, io::Result<BoxStream>> {
        Box::pin(async move {
            let stream = protect::connect_tcp_host(host, port).await?;
            stream.set_nodelay(true)?;
            Ok(Box::new(stream) as BoxStream)
        })
    }

    fn is_system(&self) -> bool {
        true
    }
}

/// Dials through another outbound: the `via` of a node (a proxy chain). TCP
/// connections to the server are the outbound's connections and datagrams
/// its UDP flows; host names are left to the outbound to resolve.
pub struct OutboundDialer(pub std::sync::Arc<dyn TcpOutbound>);

impl Dialer for OutboundDialer {
    fn dial<'a>(&'a self, host: &'a str, port: u16) -> BoxFuture<'a, io::Result<BoxStream>> {
        Box::pin(async move { self.0.connect(&TargetAddr::from_host(host, port)).await })
    }

    fn open_datagram<'a>(&'a self, host: &'a str, port: u16) -> BoxFuture<'a, io::Result<UdpFlow>> {
        Box::pin(async move { self.0.open_udp(&TargetAddr::from_host(host, port)).await })
    }
}

/// A system UDP socket connected to `host:port`, as a flow. UDP has no
/// handshake to race the resolved addresses on, so it takes the first in
/// [`happy_eyeballs::resolve`] order for UDP: the family QUIC last
/// connected to the host with, else the family TCP did, else the
/// resolver's first.
async fn socket_flow(host: &str, port: u16) -> io::Result<UdpFlow> {
    let addr = happy_eyeballs::resolve(host, port, happy_eyeballs::Transport::Udp)
        .await
        .map_err(|error| match error.kind() {
            io::ErrorKind::NotFound => {
                io::Error::new(io::ErrorKind::NotFound, "proxy server not found")
            }
            _ => error,
        })?[0];
    let socket = protect::bind_udp(addr)?;
    socket.connect(addr).await?;
    Ok(UdpFlow::connected_socket(std::sync::Arc::new(socket)))
}

struct SocketSend(std::sync::Arc<UdpSocket>);

impl DatagramSend for SocketSend {
    fn send<'a>(&'a mut self, payload: &'a [u8]) -> BoxFuture<'a, io::Result<()>> {
        Box::pin(async move { self.0.send(payload).await.map(|_| ()) })
    }
}

/// Receives from a connected UDP socket without a buffer of its own: an
/// idle flow (and there may be hundreds) holds no receive buffer. Each
/// datagram is read into a per-thread scratch buffer of [`MAX_DATAGRAM`]
/// bytes once the socket is readable, and copied out at its length.
struct SocketRecv {
    socket: std::sync::Arc<UdpSocket>,
}

impl DatagramRecv for SocketRecv {
    fn recv(&mut self) -> BoxFuture<'_, io::Result<Vec<u8>>> {
        Box::pin(async move {
            loop {
                self.socket.readable().await?;
                match read_with_scratch(|buf| self.socket.try_recv(buf)) {
                    Ok(datagram) => return Ok(datagram),
                    // Readiness can be spurious; it is not the end of the
                    // flow.
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => continue,
                    Err(error) => return Err(error),
                }
            }
        })
    }
}

/// Runs `read` on this thread's scratch buffer of [`MAX_DATAGRAM`] bytes and
/// returns what it read as an owned datagram. `read` must not wait: the
/// buffer is borrowed for its call only, and a task may move to another
/// thread at any await. The buffer is the full datagram size, so nothing is
/// truncated (or, on Windows, refused as too large).
fn read_with_scratch(read: impl FnOnce(&mut [u8]) -> io::Result<usize>) -> io::Result<Vec<u8>> {
    thread_local! {
        static SCRATCH: std::cell::RefCell<Box<[u8]>> =
            std::cell::RefCell::new(vec![0u8; MAX_DATAGRAM].into_boxed_slice());
    }
    SCRATCH.with(|scratch| {
        let mut buf = scratch.borrow_mut();
        let n = read(&mut buf)?;
        Ok(buf[..n].to_vec())
    })
}

/// A TCP-capable outbound protocol.
///
/// Implementations receive their [`Dialer`] at construction time; `connect`
/// returns a stream that carries the payload for `target` once the protocol
/// handshake has been started.
pub trait TcpOutbound: Send + Sync {
    /// Short protocol tag for diagnostics, e.g. `"vless"` or `"shadowsocks"`.
    fn protocol(&self) -> &'static str;

    fn connect<'a>(&'a self, target: &'a TargetAddr) -> BoxFuture<'a, io::Result<BoxStream>>;

    /// Opens a UDP flow to `target`. Protocols without UDP keep this default,
    /// which fails with [`io::ErrorKind::Unsupported`].
    fn open_udp<'a>(&'a self, target: &'a TargetAddr) -> BoxFuture<'a, io::Result<UdpFlow>> {
        let _ = target;
        Box::pin(async { Err(udp_unsupported()) })
    }

    /// Checks that `target` answers through this outbound within `timeout`
    /// and returns the round trip, for active health checks. The default
    /// times [`TcpOutbound::connect`], which is the whole path for an
    /// outbound that dials before it returns. An outbound whose `connect`
    /// returns before the far end has dialed (a stream opened on a
    /// multiplexed session, say) overrides this to wait for the far end's
    /// answer and to report the path's round trip, not a local open.
    fn probe<'a>(
        &'a self,
        target: &'a TargetAddr,
        timeout: Duration,
    ) -> BoxFuture<'a, io::Result<Duration>> {
        Box::pin(async move {
            let began = tokio::time::Instant::now();
            match tokio::time::timeout(timeout, self.connect(target)).await {
                Ok(Ok(_stream)) => Ok(began.elapsed()),
                Ok(Err(error)) => Err(error),
                Err(_) => Err(probe_timed_out()),
            }
        })
    }

    /// Protocol-specific health of this outbound as a JSON object (dial
    /// outcome counters, a stopped state, hints for the user), for the app to
    /// show and to report to its panel. Outbounds that keep none return the
    /// default `None`. Counters only; never destinations.
    fn health(&self) -> Option<serde_json::Value> {
        None
    }

    /// How this outbound reuses connections and TLS sessions, as a JSON
    /// object: the multiplexer's pool (`mux`) and TLS resumption counters
    /// (`tls_handshakes`, `tls_resumed`). Outbounds that keep none return
    /// the default `None`. Counters only; never destinations.
    fn reuse_stats(&self) -> Option<serde_json::Value> {
        None
    }

    /// Clears a state in which the outbound stopped dialing on its own (say,
    /// the server kept rejecting its credentials), after the user retried or
    /// refreshed the subscription. Returns whether anything changed; the
    /// default has no such state.
    fn resume(&self) -> bool {
        false
    }

    /// Stops reusing the connections this outbound keeps between flows (a
    /// shared QUIC connection, a pool of idle streams), after the device
    /// changed networks or woke from sleep: they may still use the old path
    /// and would stall the next flows until they time out. The next flow
    /// dials afresh. Returns how many sessions or idle connections were
    /// dropped or retired; the default keeps none. Flows already open are
    /// left alone: a connection that carries open flows is retired, not
    /// closed, and closes when its last flow ends (the engine closes the
    /// flows itself when it means to).
    fn reset_sessions(&self) -> usize {
        0
    }

    /// Routes the requests of a decrypted HTTP connection one by one, for
    /// `URL-REGEX` and `USER-AGENT` rules (see [`RequestRouter`]). Plain
    /// outbounds keep the default `None`: every request goes where the
    /// connection went.
    fn request_router(&self) -> Option<&dyn RequestRouter> {
        None
    }
}

/// Picks an outbound per HTTP request inside one decrypted connection,
/// after MITM, instead of once per connection from its host.
pub trait RequestRouter: Send + Sync {
    /// Where a request to `target` goes: an outbound name (a node id,
    /// `DIRECT` or `REJECT`). `request` is the request's URL and
    /// `User-Agent`; `None` asks for the connection as it was opened. `None`
    /// back means no rule looks at requests, so every request keeps the
    /// connection's outbound and nothing needs comparing.
    fn request_route<'a>(
        &'a self,
        target: &'a TargetAddr,
        request: Option<&'a sniff::HttpRequestHead>,
    ) -> BoxFuture<'a, Option<String>>;

    /// Opens a connection to `target` routed for `request`, listed like any
    /// other flow.
    fn connect_request<'a>(
        &'a self,
        target: &'a TargetAddr,
        request: &'a sniff::HttpRequestHead,
    ) -> BoxFuture<'a, io::Result<BoxStream>>;
}

/// The error a [`TcpOutbound::probe`] that ran out of time fails with.
pub fn probe_timed_out() -> io::Error {
    io::Error::new(io::ErrorKind::TimedOut, "probe timed out")
}

/// The error [`TcpOutbound::open_udp`] returns for protocols without UDP.
pub fn udp_unsupported() -> io::Error {
    io::Error::new(io::ErrorKind::Unsupported, "outbound does not relay udp")
}

/// Largest datagram a [`UdpFlow`] built from a stream reads at once.
pub const MAX_DATAGRAM: usize = 64 * 1024;

/// Sends the datagrams of one UDP flow.
pub trait DatagramSend: Send {
    /// Sends `payload` as one datagram to the flow's destination.
    fn send<'a>(&'a mut self, payload: &'a [u8]) -> BoxFuture<'a, io::Result<()>>;
}

/// Receives the datagrams of one UDP flow.
pub trait DatagramRecv: Send {
    /// The next datagram from the flow's destination. Fails once the flow
    /// has ended.
    fn recv(&mut self) -> BoxFuture<'_, io::Result<Vec<u8>>>;
}

/// UDP to one destination: replies are attributed to that destination
/// whatever source the proxy reports.
pub struct UdpFlow {
    pub send: Box<dyn DatagramSend>,
    pub recv: Box<dyn DatagramRecv>,
}

impl UdpFlow {
    pub fn new(send: Box<dyn DatagramSend>, recv: Box<dyn DatagramRecv>) -> Self {
        Self { send, recv }
    }

    /// A flow over a UDP socket already connected to its destination. The
    /// flow keeps no receive buffer while it waits.
    pub fn connected_socket(socket: std::sync::Arc<UdpSocket>) -> Self {
        Self::new(
            Box::new(SocketSend(socket.clone())),
            Box::new(SocketRecv { socket }),
        )
    }

    /// A flow over a stream where each write carries one datagram and each
    /// read returns one, such as a VMess UDP session. A read takes up to
    /// [`MAX_DATAGRAM`] bytes, allocated for that read only (not zeroed), so
    /// an idle flow holds no buffer.
    pub fn message_stream(stream: BoxStream) -> Self {
        let (reader, writer) = tokio::io::split(stream);
        Self::new(
            Box::new(MessageSend(writer)),
            Box::new(MessageRecv { reader }),
        )
    }
}

struct MessageSend(WriteHalf<BoxStream>);

impl DatagramSend for MessageSend {
    fn send<'a>(&'a mut self, payload: &'a [u8]) -> BoxFuture<'a, io::Result<()>> {
        Box::pin(async move {
            self.0.write_all(payload).await?;
            self.0.flush().await
        })
    }
}

struct MessageRecv {
    reader: ReadHalf<BoxStream>,
}

impl DatagramRecv for MessageRecv {
    fn recv(&mut self) -> BoxFuture<'_, io::Result<Vec<u8>>> {
        Box::pin(async move {
            // One read is one datagram, so the buffer must hold the largest;
            // it is spare capacity, written only as far as the read goes.
            let mut buf = Vec::with_capacity(MAX_DATAGRAM);
            let n = self.reader.read_buf(&mut buf).await?;
            if n == 0 {
                return Err(io::ErrorKind::UnexpectedEof.into());
            }
            buf.shrink_to_fit();
            Ok(buf)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uri_hosts_bracket_ipv6_literals_only() {
        assert_eq!(uri_host("2001:db8::1"), "[2001:db8::1]");
        assert_eq!(uri_host("[2001:db8::1]"), "[2001:db8::1]");
        assert_eq!(uri_host("::1"), "[::1]");
        assert_eq!(uri_host("198.51.100.20"), "198.51.100.20");
        assert_eq!(uri_host("cdn.example"), "cdn.example");
        assert_eq!(uri_host("cdn.example:8443"), "cdn.example:8443");
        assert_eq!(uri_host("[2001:db8::1]:8443"), "[2001:db8::1]:8443");
    }

    #[test]
    fn from_host_tells_addresses_from_names() {
        assert_eq!(
            TargetAddr::from_host("198.51.100.20", 8388),
            TargetAddr::Ip("198.51.100.20:8388".parse().unwrap())
        );
        assert_eq!(
            TargetAddr::from_host("[2001:db8::1]", 443),
            TargetAddr::Ip("[2001:db8::1]:443".parse().unwrap())
        );
        assert_eq!(
            TargetAddr::from_host("2001:db8::1", 443),
            TargetAddr::Ip("[2001:db8::1]:443".parse().unwrap())
        );
        assert_eq!(
            TargetAddr::from_host("land.example", 443),
            TargetAddr::Domain("land.example".to_string(), 443)
        );
    }

    struct NoOutbound;

    impl TcpOutbound for NoOutbound {
        fn protocol(&self) -> &'static str {
            "none"
        }

        fn connect<'a>(&'a self, _target: &'a TargetAddr) -> BoxFuture<'a, io::Result<BoxStream>> {
            Box::pin(async { Err(io::Error::other("unused")) })
        }
    }

    #[test]
    fn only_the_system_dialer_lets_transports_open_their_own_sockets() {
        assert!(TcpDialer.is_system());
        // A `via` chain carries everything itself.
        assert!(!OutboundDialer(std::sync::Arc::new(NoOutbound)).is_system());
    }
}
