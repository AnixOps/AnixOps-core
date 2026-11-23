//! The UDP path from a WireGuard session to its peer, shared by the routable
//! outbound ([`crate::WireGuardOutbound`]) and the whole-device tunnel of
//! `engine-embedded`.
//!
//! A [`Path`] is one connected UDP socket to the endpoint. A connected
//! socket keeps the source address (and, with a protector, the interface)
//! it was made with, so after the device moves to another network its sends
//! fail or go nowhere. The path then resolves the endpoint again and moves to
//! a new socket, while the session keeps its keys and the peer follows the
//! new source address (WireGuard roaming). It moves:
//!
//! - when the holder asks for it ([`Path::renew`]), after the client
//!   reported a network change or a wake from sleep;
//! - when the socket protector changed, such as a new bound interface (see
//!   [`protect::path_generation`]);
//! - when a send or receive fails with a path error (the source address or
//!   the route is gone, the system tore the socket down), paced by a
//!   back-off from 1 s to 30 s;
//! - when handshake initiations went unanswered for 20 s (doubling up to
//!   320 s while the peer stays silent): the endpoint's name may point
//!   elsewhere now, or a NAT dropped the mapping. The other addresses of the
//!   name are tried first.
//!
//! The lookup runs beside the traffic: the old socket keeps working until the
//! new one is ready, and a failed lookup keeps it. After a move the holder
//! sends a fresh handshake initiation ([`Received::Rebound`]), which also
//! tells the peer the new address at once.

use std::future::Future;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::time::{Duration, Instant};

use engine_outbound::protect;
use tokio::net::UdpSocket;

/// How long one lookup of the endpoint's name may take.
const RESOLVE_TIMEOUT: Duration = Duration::from_secs(5);
/// First wait between two moves after path errors; it doubles up to
/// [`MAX_RETRY`] and falls back once the peer answers.
const MIN_RETRY: Duration = Duration::from_secs(1);
const MAX_RETRY: Duration = Duration::from_secs(30);
/// Pause after a receive error (an ICMP error on the connected socket)
/// instead of spinning while the peer is unreachable.
const RECV_PAUSE: Duration = Duration::from_millis(250);
/// Handshake initiations unanswered this long move the path; the wait
/// doubles up to [`MAX_STALL`] until the peer answers.
const HANDSHAKE_STALL: Duration = Duration::from_secs(20);
const MAX_STALL: Duration = Duration::from_secs(320);
/// An initiation this recent means the session is still trying to
/// handshake: boringtun sends one every 5 s while a handshake is due.
const RETRYING: Duration = Duration::from_secs(12);
/// A handshake initiation is 148 bytes and starts with message type 1.
const INITIATION_LEN: usize = 148;
const INITIATION_TYPE: u8 = 1;

type Lookup = Pin<Box<dyn Future<Output = io::Result<Vec<SocketAddr>>> + Send>>;

/// The endpoint's addresses, IPv4 first, for `server` (a name or an IP
/// literal, IPv6 with or without brackets). The engine's own sockets never
/// route through a tunnel, so the system resolver is safe to use for it.
pub async fn resolve(server: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
    let host = host(server);
    if let Ok(address) = host.parse::<IpAddr>() {
        return Ok(vec![SocketAddr::new(address, port)]);
    }
    let lookup = tokio::net::lookup_host((host, port));
    let addresses = tokio::time::timeout(RESOLVE_TIMEOUT, lookup)
        .await
        .map_err(|_| not_resolved(io::ErrorKind::TimedOut))??;
    let addresses = ordered(addresses);
    if addresses.is_empty() {
        return Err(not_resolved(io::ErrorKind::NotFound));
    }
    Ok(addresses)
}

/// IPv4 addresses first, then IPv6, each once, otherwise in the resolver's
/// order.
pub fn ordered(addresses: impl IntoIterator<Item = SocketAddr>) -> Vec<SocketAddr> {
    let (v4, v6): (Vec<SocketAddr>, Vec<SocketAddr>) =
        addresses.into_iter().partition(SocketAddr::is_ipv4);
    let mut ordered = Vec::with_capacity(v4.len() + v6.len());
    for address in v4.into_iter().chain(v6) {
        if !ordered.contains(&address) {
            ordered.push(address);
        }
    }
    ordered
}

/// `server` without surrounding whitespace and IPv6 brackets.
fn host(server: &str) -> &str {
    server.trim().trim_start_matches('[').trim_end_matches(']')
}

fn not_resolved(kind: io::ErrorKind) -> io::Error {
    io::Error::new(kind, "wireguard endpoint did not resolve")
}

/// A UDP socket connected to `endpoint`, protected first: the kernel then
/// drops datagrams from any other source.
fn connect_udp(endpoint: SocketAddr) -> io::Result<UdpSocket> {
    let socket = protect::bind_std_udp(protect::unspecified_for(endpoint), endpoint)?;
    socket.connect(endpoint)?;
    UdpSocket::from_std(socket)
}

/// The first of `addresses` a socket connects to, `avoid` last. A UDP
/// connect fails at once when there is no route (an IPv4 address on an
/// IPv6-only network), so the next address gets its turn.
fn connect_first(
    addresses: &[SocketAddr],
    avoid: Option<SocketAddr>,
) -> io::Result<(SocketAddr, UdpSocket)> {
    let preferred = addresses.iter().filter(|address| Some(**address) != avoid);
    let avoided = addresses.iter().filter(|address| Some(**address) == avoid);
    let mut last_error = None;
    for &endpoint in preferred.chain(avoided) {
        match connect_udp(endpoint) {
            Ok(socket) => return Ok((endpoint, socket)),
            Err(error) => last_error = Some(error),
        }
    }
    Err(last_error.unwrap_or_else(|| not_resolved(io::ErrorKind::NotFound)))
}

fn is_initiation(datagram: &[u8]) -> bool {
    datagram.len() == INITIATION_LEN && datagram[0] == INITIATION_TYPE
}

/// Errors that mean the socket's path is gone rather than that the peer
/// refused: the source address left the device (`EADDRNOTAVAIL`; on Linux
/// and Android a connected IPv4 socket keeps the source chosen at `connect`
/// and its sends then fail with `EINVAL`, as the route lookup cannot use
/// it), there is no route or no network (`ENETUNREACH`, `EHOSTUNREACH`,
/// `ENETDOWN`), or the system tore the socket down (`EPIPE`, `ENOTCONN`).
/// On a connected UDP socket with a valid buffer `EINVAL` has no other
/// cause worth keeping the socket for, and a false positive costs one
/// paced move.
fn is_path_error(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::AddrNotAvailable
            | io::ErrorKind::InvalidInput
            | io::ErrorKind::NetworkUnreachable
            | io::ErrorKind::HostUnreachable
            | io::ErrorKind::NetworkDown
            | io::ErrorKind::BrokenPipe
            | io::ErrorKind::NotConnected
    )
}

/// What [`Path::recv`] saw.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Received {
    /// A datagram of this length from the peer.
    Datagram(usize),
    /// The socket reported an error, such as an ICMP error from the peer.
    Failed,
    /// The path moved to a new socket: send a fresh handshake initiation.
    Rebound,
    /// A move found no address that connects; the old socket stays.
    Unchanged,
}

enum Event {
    Socket(io::Result<usize>),
    Lookup(io::Result<Vec<SocketAddr>>),
}

/// Spacing of moves after path errors.
struct Backoff {
    delay: Duration,
    next: Option<Instant>,
}

impl Default for Backoff {
    fn default() -> Self {
        Self {
            delay: MIN_RETRY,
            next: None,
        }
    }
}

impl Backoff {
    fn ready(&self, now: Instant) -> bool {
        self.next.is_none_or(|next| now >= next)
    }

    /// An attempt starts now: the next one waits, each time twice as long.
    fn wait(&mut self, now: Instant) {
        self.next = Some(now + self.delay);
        self.delay = (self.delay * 2).min(MAX_RETRY);
    }

    fn reset(&mut self) {
        *self = Self::default();
    }

    /// The path works: the next failure starts over from the shortest wait.
    fn relax(&mut self) {
        self.delay = MIN_RETRY;
    }
}

/// One connected UDP socket to the peer that moves to a new one when the
/// network under it changed. See the module docs.
pub struct Path {
    /// The endpoint as configured, for later lookups.
    server: String,
    port: u16,
    socket: UdpSocket,
    endpoint: SocketAddr,
    /// Whether a protector kept `socket` off the tunnel when it was made.
    protected: bool,
    /// [`protect::path_generation`] as last seen.
    generation: u64,
    /// A move was asked for and has not started yet.
    wanted: bool,
    /// A lookup in flight; the socket moves when it finishes.
    lookup: Option<Lookup>,
    /// The endpoint that lookup tries last.
    avoid: Option<SocketAddr>,
    /// A send or receive failed with a path error since the last move.
    broken: bool,
    retry: Backoff,
    /// No receive before then, after a receive error.
    recv_paused_until: Option<Instant>,
    /// Since when handshake initiations have gone unanswered.
    unanswered_since: Option<Instant>,
    last_initiation: Option<Instant>,
    stall_after: Duration,
}

impl Path {
    /// Connects to the first of `addresses` (from [`resolve`]) that has a
    /// route; `server` and `port` are kept for later lookups.
    pub fn connect(server: &str, port: u16, addresses: &[SocketAddr]) -> io::Result<Self> {
        // Read before the socket is made, so a change in between moves it.
        let generation = protect::path_generation();
        let (endpoint, socket) = connect_first(addresses, None)?;
        Ok(Self {
            server: host(server).to_owned(),
            port,
            socket,
            endpoint,
            protected: protect::socket_protector_installed(),
            generation,
            wanted: false,
            lookup: None,
            avoid: None,
            broken: false,
            retry: Backoff::default(),
            recv_paused_until: None,
            unanswered_since: None,
            last_initiation: None,
            stall_after: HANDSHAKE_STALL,
        })
    }

    /// The peer address the socket is connected to.
    pub fn endpoint(&self) -> SocketAddr {
        self.endpoint
    }

    /// Sends one datagram to the peer. A path error marks the path for a
    /// move; a handshake initiation starts the stall clock.
    pub async fn send(&mut self, datagram: &[u8]) -> io::Result<()> {
        if is_initiation(datagram) {
            self.initiation_sent(Instant::now());
        }
        let sent = self.socket.send(datagram).await;
        match sent {
            Ok(_) => Ok(()),
            Err(error) => {
                self.failed(&error);
                Err(error)
            }
        }
    }

    /// Waits for a datagram from the peer, or for a move started by
    /// [`Path::maintain`] to finish. Cancel safe: a lookup in flight
    /// survives a dropped call.
    pub async fn recv(&mut self, buffer: &mut [u8]) -> Received {
        let paused = self
            .recv_paused_until
            .filter(|until| *until > Instant::now());
        let socket = &self.socket;
        let lookup = &mut self.lookup;
        let event = tokio::select! {
            received = async {
                if let Some(until) = paused {
                    tokio::time::sleep_until(tokio::time::Instant::from_std(until)).await;
                }
                socket.recv(buffer).await
            } => Event::Socket(received),
            addresses = async {
                match lookup.as_mut() {
                    Some(lookup) => lookup.await,
                    None => std::future::pending().await,
                }
            } => Event::Lookup(addresses),
        };
        match event {
            Event::Socket(Ok(len)) => Received::Datagram(len),
            Event::Socket(Err(error)) => {
                self.failed(&error);
                self.recv_paused_until = Some(Instant::now() + RECV_PAUSE);
                Received::Failed
            }
            Event::Lookup(addresses) => {
                self.lookup = None;
                self.rebind(addresses)
            }
        }
    }

    /// Asks for a move now, after the network changed: the endpoint
    /// resolves again and the path moves to a new socket. A lookup already
    /// in flight is dropped, since it may have used the old network.
    pub fn renew(&mut self) {
        self.lookup = None;
        self.avoid = None;
        self.wanted = true;
        self.retry.reset();
        self.unanswered_since = None;
        self.stall_after = HANDSHAKE_STALL;
    }

    /// Something authenticated came from the peer: the path works, so an
    /// earlier failure (a path error, a move that found no address) no
    /// longer asks for a move. A move asked for with [`Path::renew`] stays
    /// asked for.
    pub fn heard(&mut self) {
        self.broken = false;
        self.unanswered_since = None;
        self.stall_after = HANDSHAKE_STALL;
        self.retry.relax();
    }

    /// Starts a move when one is due (see the module docs); it finishes in
    /// [`Path::recv`]. Call it before each `recv`.
    pub fn maintain(&mut self, now: Instant) {
        self.maintain_at(now, protect::path_generation());
    }

    fn maintain_at(&mut self, now: Instant, generation: u64) {
        if generation != self.generation {
            self.generation = generation;
            self.renew();
        }
        if self.lookup.is_some() {
            return;
        }
        if self.wanted || (self.broken && self.retry.ready(now)) {
            if self.may_rebind() {
                self.start(now, None);
            }
        } else if self.stalled(now) && self.may_rebind() {
            // Try the endpoint's other addresses first, and give the next
            // socket longer before moving again.
            self.unanswered_since = Some(now);
            self.stall_after = (self.stall_after * 2).min(MAX_STALL);
            self.start(now, Some(self.endpoint));
        }
    }

    /// A socket made while a protector kept it off the tunnel is never
    /// replaced by an unprotected one: with the protector removed (macOS
    /// while no physical network is up), a new socket would route into the
    /// tunnel itself. Installing a protector again moves the generation, and
    /// the move runs then.
    fn may_rebind(&self) -> bool {
        !self.protected || protect::socket_protector_installed()
    }

    fn start(&mut self, now: Instant, avoid: Option<SocketAddr>) {
        self.wanted = false;
        self.avoid = avoid;
        self.retry.wait(now);
        let server = self.server.clone();
        let port = self.port;
        self.lookup = Some(Box::pin(async move { resolve(&server, port).await }));
    }

    /// Moves to a socket for the first address of a finished lookup that
    /// connects; keeps the old socket when there is none.
    fn rebind(&mut self, addresses: io::Result<Vec<SocketAddr>>) -> Received {
        let avoid = self.avoid.take();
        match addresses.and_then(|addresses| connect_first(&addresses, avoid)) {
            Ok((endpoint, socket)) => {
                self.socket = socket;
                self.endpoint = endpoint;
                self.protected = protect::socket_protector_installed();
                self.broken = false;
                // `stall_after` stays doubled: it relaxes only when the peer
                // answers (`heard`), so a peer that stays silent across moves
                // is not retried every 20 s.
                self.unanswered_since = None;
                self.recv_paused_until = None;
                Received::Rebound
            }
            Err(_) => {
                // Try again after the back-off.
                self.broken = true;
                Received::Unchanged
            }
        }
    }

    fn initiation_sent(&mut self, now: Instant) {
        self.last_initiation = Some(now);
        self.unanswered_since = Some(self.unanswered_since.unwrap_or(now));
    }

    /// Notes a socket error; a path error asks for a move.
    fn failed(&mut self, error: &io::Error) {
        if is_path_error(error) {
            self.broken = true;
        }
    }

    /// Whether handshakes have gone unanswered for `stall_after` while the
    /// session still tries; a session that stopped trying sends no
    /// initiations and never stalls.
    fn stalled(&self, now: Instant) -> bool {
        let unanswered = self
            .unanswered_since
            .is_some_and(|since| now.saturating_duration_since(since) >= self.stall_after);
        let retrying = self
            .last_initiation
            .is_some_and(|last| now.saturating_duration_since(last) <= RETRYING);
        unanswered && retrying
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn local_port(path: &Path) -> u16 {
        path.socket.local_addr().unwrap().port()
    }

    #[test]
    fn addresses_are_ordered_ipv4_first_without_duplicates() {
        let v6: SocketAddr = "[2001:db8::1]:51820".parse().unwrap();
        let v4: SocketAddr = "192.0.2.1:51820".parse().unwrap();
        let other: SocketAddr = "192.0.2.2:51820".parse().unwrap();
        assert_eq!(ordered([v6, v4, v6, other, v4]), [v4, other, v6]);
    }

    #[tokio::test]
    async fn literals_resolve_without_a_lookup() {
        let v4: SocketAddr = "192.0.2.1:51820".parse().unwrap();
        let v6: SocketAddr = "[2001:db8::1]:51820".parse().unwrap();
        assert_eq!(resolve("192.0.2.1", 51820).await.unwrap(), [v4]);
        assert_eq!(resolve(" [2001:db8::1] ", 51820).await.unwrap(), [v6]);
    }

    #[test]
    fn only_initiations_and_path_errors_count() {
        let mut initiation = [0u8; INITIATION_LEN];
        initiation[0] = INITIATION_TYPE;
        assert!(is_initiation(&initiation));
        assert!(!is_initiation(&initiation[..32]));
        initiation[0] = 4;
        assert!(!is_initiation(&initiation));

        for kind in [
            io::ErrorKind::AddrNotAvailable,
            io::ErrorKind::InvalidInput,
            io::ErrorKind::NetworkUnreachable,
            io::ErrorKind::HostUnreachable,
            io::ErrorKind::NetworkDown,
            io::ErrorKind::BrokenPipe,
            io::ErrorKind::NotConnected,
        ] {
            assert!(is_path_error(&kind.into()), "{kind:?}");
        }
        for kind in [
            io::ErrorKind::ConnectionRefused,
            io::ErrorKind::ConnectionReset,
            io::ErrorKind::WouldBlock,
            io::ErrorKind::Other,
        ] {
            assert!(!is_path_error(&kind.into()), "{kind:?}");
        }
    }

    #[tokio::test]
    async fn a_path_error_moves_the_path_to_a_new_socket() {
        let peer = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        peer.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let address = peer.local_addr().unwrap();
        let mut path = Path::connect("127.0.0.1", address.port(), &[address]).unwrap();
        let first = local_port(&path);
        let generation = path.generation;

        // The source address left the device.
        path.failed(&io::ErrorKind::AddrNotAvailable.into());
        let now = Instant::now();
        path.maintain_at(now, generation);
        assert!(path.lookup.is_some(), "the first move starts at once");
        let mut buffer = [0u8; 64];
        let received = tokio::time::timeout(Duration::from_secs(5), path.recv(&mut buffer))
            .await
            .expect("the move did not finish");
        assert_eq!(received, Received::Rebound);
        assert!(!path.broken);
        assert_eq!(path.endpoint(), address);
        let second = local_port(&path);
        assert_ne!(first, second);

        // The new socket reaches the peer.
        path.send(b"after the move").await.unwrap();
        let mut datagram = [0u8; 64];
        let (len, from) = peer.recv_from(&mut datagram).unwrap();
        assert_eq!(&datagram[..len], b"after the move");
        assert_eq!(from.port(), second);

        // Another failure right after waits for the back-off.
        path.failed(&io::ErrorKind::NetworkUnreachable.into());
        path.maintain_at(now, generation);
        assert!(path.lookup.is_none());
        path.maintain_at(now + MIN_RETRY, generation);
        assert!(path.lookup.is_some());
    }

    #[tokio::test]
    async fn a_refusing_peer_does_not_move_the_path() {
        let address: SocketAddr = "127.0.0.1:9".parse().unwrap();
        let mut path = Path::connect("127.0.0.1", 9, &[address]).unwrap();
        let generation = path.generation;
        path.failed(&io::ErrorKind::ConnectionRefused.into());
        path.failed(&io::ErrorKind::ConnectionReset.into());
        path.maintain_at(Instant::now(), generation);
        assert!(!path.broken);
        assert!(path.lookup.is_none());
    }

    #[tokio::test]
    async fn renew_and_a_new_generation_move_the_path_at_once() {
        let address: SocketAddr = "127.0.0.1:9".parse().unwrap();
        let mut path = Path::connect("127.0.0.1", 9, &[address]).unwrap();
        let generation = path.generation;
        let now = Instant::now();
        path.maintain_at(now, generation);
        assert!(path.lookup.is_none());

        path.maintain_at(now, generation + 1);
        assert!(path.lookup.is_some());
        assert_eq!(path.rebind(Ok(vec![address])), Received::Rebound);

        // Asked again right away: an explicit move skips the back-off.
        path.lookup = None;
        path.renew();
        path.maintain_at(now, generation + 1);
        assert!(path.lookup.is_some());

        // A lookup that found nothing keeps the socket and retries later.
        path.lookup = None;
        let port = local_port(&path);
        assert_eq!(
            path.rebind(Err(not_resolved(io::ErrorKind::NotFound))),
            Received::Unchanged
        );
        assert_eq!(local_port(&path), port);
        assert!(path.broken);
    }

    #[tokio::test]
    async fn a_protected_socket_waits_for_a_protector() {
        let address: SocketAddr = "127.0.0.1:9".parse().unwrap();
        let mut path = Path::connect("127.0.0.1", 9, &[address]).unwrap();
        let generation = path.generation;
        // As if a protector pinned the socket and was removed since.
        path.protected = true;
        path.renew();
        path.maintain_at(Instant::now(), generation);
        assert!(path.lookup.is_none(), "an unprotected socket replaced it");
        path.protected = false;
        path.maintain_at(Instant::now(), generation);
        assert!(path.lookup.is_some());
    }

    #[tokio::test]
    async fn unanswered_handshakes_try_the_next_address() {
        let first: SocketAddr = "127.0.0.1:9".parse().unwrap();
        let second: SocketAddr = "127.0.0.1:10".parse().unwrap();
        let mut path = Path::connect("localhost", 9, &[first, second]).unwrap();
        assert_eq!(path.endpoint(), first);
        let generation = path.generation;
        let start = Instant::now();

        // An answered handshake never stalls.
        path.initiation_sent(start);
        path.heard();
        path.maintain_at(start + HANDSHAKE_STALL, generation);
        assert!(path.lookup.is_none());

        // A session that stopped trying never stalls either.
        path.initiation_sent(start);
        path.maintain_at(start + Duration::from_secs(60), generation);
        assert!(path.lookup.is_none());

        // Initiations every 5 s, none answered.
        path.heard();
        for secs in [0, 5, 10, 15] {
            path.initiation_sent(start + Duration::from_secs(secs));
        }
        path.maintain_at(start + Duration::from_secs(19), generation);
        assert!(path.lookup.is_none());
        path.maintain_at(start + HANDSHAKE_STALL, generation);
        assert!(path.lookup.is_some());
        assert_eq!(path.avoid, Some(first));
        assert_eq!(path.stall_after, HANDSHAKE_STALL * 2);

        // The silent address goes last.
        path.lookup = None;
        assert_eq!(path.rebind(Ok(vec![first, second])), Received::Rebound);
        assert_eq!(path.endpoint(), second);
        assert!(path.unanswered_since.is_none());
    }
}
