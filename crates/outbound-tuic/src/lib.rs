//! TUIC v5 TCP outbound over QUIC.
//!
//! The client opens one QUIC connection per outbound and authenticates on a
//! unidirectional stream with
//!
//! ```text
//! VER 0x05 | TYPE 0x00 (Authenticate) | UUID (16) | TOKEN (32)
//! ```
//!
//! where TOKEN is the TLS keying material exported with the UUID as label and
//! the password as context, so the password never crosses the wire. The
//! server sends no answer. Each proxied TCP connection is a bidirectional
//! stream that starts with
//!
//! ```text
//! VER 0x05 | TYPE 0x01 (Connect) | ADDR
//! ```
//!
//! (ADDR: `0x00 len domain`, `0x01 ipv4` or `0x02 ipv6`, then a big-endian
//! port) and then carries the payload both ways.
//!
//! The connection is shared by every stream and opened again when it closes;
//! QUIC keep-alives keep it open between connections.
//! [`TuicOutbound::udp_session`] relays UDP in native mode over QUIC
//! datagrams (see [`udp`]).
//!
//! [`TuicFactory`] registers the outbound under `"type": "tuic"`.

mod factory;
pub mod udp;

use std::io;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};

use engine_outbound::{
    BoxFuture, BoxStream, DatagramRecv, DatagramSend, TargetAddr, TcpOutbound, UdpFlow,
};
use tokio::sync::Mutex;
use transport_quic::shared::{Hold, Shared};
use transport_quic::{quic_error, quinn, Congestion, QuicConnection, QuicConnector, QuicStream};
use transport_tls::TlsSettings;

pub use factory::{parse_uuid, TuicFactory, TYPE_NAME};
pub use udp::TuicUdpSession;

pub const PROTOCOL: &str = "tuic";

pub const VERSION: u8 = 0x05;
pub const CMD_AUTHENTICATE: u8 = 0x00;
pub const CMD_CONNECT: u8 = 0x01;
pub const ADDR_DOMAIN: u8 = 0x00;
pub const ADDR_IPV4: u8 = 0x01;
pub const ADDR_IPV6: u8 = 0x02;

pub struct TuicOutbound {
    uuid: [u8; 16],
    password: Vec<u8>,
    quic: QuicConnector,
    /// The connection new flows use. Every flow holds it
    /// ([`transport_quic::shared::Hold`]), so a connection taken out of
    /// this slot (retired) stays open until its last flow ends.
    session: Mutex<Option<Arc<Shared<Session>>>>,
    /// Bumped by [`TcpOutbound::reset_sessions`]; a session from an older
    /// generation is never reused.
    generation: AtomicU64,
}

/// One authenticated QUIC connection.
struct Session {
    /// Owns the endpoint that drives the connection's socket.
    _quic: QuicConnection,
    /// The outbound's generation when this session was opened.
    generation: u64,
    /// Started with the first UDP session.
    udp: OnceLock<Arc<udp::Dispatch>>,
}

impl TuicOutbound {
    pub fn new(
        server: impl Into<String>,
        port: u16,
        uuid: [u8; 16],
        password: impl Into<String>,
        tls: &TlsSettings,
        congestion: Congestion,
    ) -> io::Result<Self> {
        let password = password.into();
        if password.is_empty() {
            return Err(invalid("tuic password is empty"));
        }
        Ok(Self {
            uuid,
            password: password.into_bytes(),
            quic: QuicConnector::new(server, port, tls, &["h3"], congestion)?,
            session: Mutex::new(None),
            generation: AtomicU64::new(0),
        })
    }

    /// Opens a UDP association on the shared connection.
    pub async fn udp_session(&self) -> io::Result<TuicUdpSession> {
        let hold = self.live().await?;
        let shared = hold.shared();
        let connection = shared.connection().clone();
        let dispatch = shared
            .value()
            .udp
            .get_or_init(|| udp::Dispatch::new(connection.clone()))
            .clone();
        Ok(TuicUdpSession::new(connection, dispatch)?.holding(hold))
    }

    /// The live QUIC connection, authenticating a new one if needed, with a
    /// hold that keeps it open for the flow about to use it.
    async fn connection(&self) -> io::Result<(quinn::Connection, Hold<Session>)> {
        let hold = self.live().await?;
        Ok((hold.shared().connection().clone(), hold))
    }

    async fn live(&self) -> io::Result<Hold<Session>> {
        let mut session = self.session.lock().await;
        let generation = self.generation.load(Ordering::Acquire);
        if let Some(current) = session.as_ref() {
            if current.value().generation == generation
                && current.connection().close_reason().is_none()
            {
                return Ok(current.hold());
            }
        }
        if let Some(stale) = session.take() {
            // From before a reset (or already closed): flows still on it
            // keep it until they end.
            stale.retire();
        }
        let fresh = self.quic.connect().await?;
        authenticate(&fresh.connection, &self.uuid, &self.password).await?;
        let connection = fresh.connection.clone();
        let fresh = Shared::new(
            Session {
                _quic: fresh,
                generation,
                udp: OnceLock::new(),
            },
            connection,
        );
        let hold = fresh.hold();
        *session = Some(fresh);
        Ok(hold)
    }
}

/// Sends the Authenticate command on its own unidirectional stream.
async fn authenticate(
    connection: &quinn::Connection,
    uuid: &[u8; 16],
    password: &[u8],
) -> io::Result<()> {
    let mut command = Vec::with_capacity(2 + 16 + 32);
    command.extend_from_slice(&[VERSION, CMD_AUTHENTICATE]);
    command.extend_from_slice(uuid);
    command.extend_from_slice(&auth_token(connection, uuid, password)?);
    let mut stream = connection.open_uni().await.map_err(quic_error)?;
    stream.write_all(&command).await?;
    stream
        .finish()
        .map_err(|_| io::Error::other("tuic authentication stream closed"))?;
    Ok(())
}

/// TLS exporter output for this connection, label UUID, context password.
pub fn auth_token(
    connection: &quinn::Connection,
    uuid: &[u8; 16],
    password: &[u8],
) -> io::Result<[u8; 32]> {
    let mut token = [0u8; 32];
    connection
        .export_keying_material(&mut token, uuid, password)
        .map_err(|_| io::Error::other("tuic token export failed"))?;
    Ok(token)
}

impl TcpOutbound for TuicOutbound {
    fn protocol(&self) -> &'static str {
        PROTOCOL
    }

    /// Retires the shared QUIC connection, which may still point at the old
    /// network after the device changed networks or woke up: the next flow
    /// opens a fresh one, and flows already open keep the old one until they
    /// end (it closes with the last of them, at once when there are none).
    /// When the engine closes those flows too (`close_connections`), the old
    /// connection closes with them.
    fn reset_sessions(&self) -> usize {
        self.generation.fetch_add(1, Ordering::AcqRel);
        match self.session.try_lock() {
            Ok(mut session) => match session.take() {
                Some(stale) => {
                    stale.retire();
                    1
                }
                None => 0,
            },
            // A dial holds the lock; it sees the new generation next time.
            Err(_) => 1,
        }
    }

    fn connect<'a>(&'a self, target: &'a TargetAddr) -> BoxFuture<'a, io::Result<BoxStream>> {
        Box::pin(async move {
            let header = connect_header(target)?;
            let (connection, hold) = self.connection().await?;
            let (mut send, recv) = connection.open_bi().await.map_err(quic_error)?;
            send.write_all(&header).await?;
            Ok(Box::new(QuicStream::new(send, recv).holding(hold)) as BoxStream)
        })
    }

    fn open_udp<'a>(&'a self, target: &'a TargetAddr) -> BoxFuture<'a, io::Result<UdpFlow>> {
        Box::pin(async move {
            let session = Arc::new(self.udp_session().await?);
            Ok(UdpFlow::new(
                Box::new(FlowSend {
                    session: session.clone(),
                    target: target.clone(),
                }),
                Box::new(FlowRecv { session }),
            ))
        })
    }
}

struct FlowSend {
    session: Arc<TuicUdpSession>,
    target: TargetAddr,
}

impl DatagramSend for FlowSend {
    fn send<'a>(&'a mut self, payload: &'a [u8]) -> BoxFuture<'a, io::Result<()>> {
        Box::pin(async move { self.session.send_to(&self.target, payload) })
    }
}

struct FlowRecv {
    session: Arc<TuicUdpSession>,
}

impl DatagramRecv for FlowRecv {
    fn recv(&mut self) -> BoxFuture<'_, io::Result<Vec<u8>>> {
        Box::pin(async move {
            // The session hands over the payload it owns: an idle flow keeps
            // no receive buffer.
            let (payload, _source) = self.session.recv_owned().await?;
            Ok(payload)
        })
    }
}

/// The Connect command for `target`.
pub fn connect_header(target: &TargetAddr) -> io::Result<Vec<u8>> {
    let mut out = Vec::with_capacity(2 + 1 + 256 + 2);
    out.extend_from_slice(&[VERSION, CMD_CONNECT]);
    match target {
        TargetAddr::Ip(addr) => match addr.ip() {
            IpAddr::V4(ip) => {
                out.push(ADDR_IPV4);
                out.extend_from_slice(&ip.octets());
            }
            IpAddr::V6(ip) => {
                out.push(ADDR_IPV6);
                out.extend_from_slice(&ip.octets());
            }
        },
        TargetAddr::Domain(domain, _) => {
            let len = u8::try_from(domain.len())
                .ok()
                .filter(|len| *len > 0)
                .ok_or_else(|| invalid("tuic target domain length is invalid"))?;
            out.push(ADDR_DOMAIN);
            out.push(len);
            out.extend_from_slice(domain.as_bytes());
        }
    }
    out.extend_from_slice(&target.port().to_be_bytes());
    Ok(out)
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}
