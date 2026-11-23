use std::{
    net::IpAddr,
    pin::Pin,
    sync::Arc,
    task::{ready, Context, Poll},
    time::Instant,
};

use futures::{Sink, Stream};
use smoltcp::wire::IpProtocol;
use tokio::sync::mpsc::{channel, Receiver};
use tokio_util::sync::PollSender;
use tracing::{debug, trace};

use crate::{
    filter::{IpFilter, IpFilters},
    packet::{AnyIpPktFrame, IpPacket},
    reassembly::{self, Piece, Reassembler},
    runner::Runner,
    stats::StackStats,
    tcp::TcpListener,
    udp::UdpSocket,
};

pub struct StackBuilder {
    enable_udp: bool,
    enable_tcp: bool,
    enable_icmp: bool,
    stack_buffer_size: usize,
    udp_buffer_size: usize,
    tcp_buffer_size: usize,
    // Per-socket TCP receive/send window (bytes). Bounds single-flow throughput
    // via window ÷ RTT. Defaults to the historical ~320 KiB; configurable so
    // high-BDP hosts can raise it without recompiling.
    tcp_recv_buffer_size: u32,
    tcp_send_buffer_size: u32,
    mtu: usize,
    ip_filters: IpFilters<'static>,
    stats: Arc<StackStats>,
}

impl Default for StackBuilder {
    fn default() -> Self {
        Self {
            enable_udp: false,
            enable_tcp: false,
            enable_icmp: false,
            stack_buffer_size: 1024,
            udp_buffer_size: 512,
            tcp_buffer_size: 512,
            // Historical per-socket TCP window, `0x3FFF * 20` (~320 KiB, i.e.
            // 20 AEAD packets). This is the smoltcp send/recv `SocketBuffer`
            // capacity; steady single-flow throughput is bounded by window ÷ RTT
            // (the TCP bandwidth-delay product). Keeping this as the default
            // leaves behavior unchanged unless the caller raises it via
            // `tcp_{recv,send}_buffer_size` for a high-BDP path.
            tcp_recv_buffer_size: 0x3FFF * 20,
            tcp_send_buffer_size: 0x3FFF * 20,
            mtu: 1504, // 1500 for Ethernet + 4 for VLAN
            ip_filters: IpFilters::with_non_broadcast(),
            stats: Arc::default(),
        }
    }
}

#[allow(unused)]
impl StackBuilder {
    pub fn enable_udp(mut self, enable: bool) -> Self {
        self.enable_udp = enable;
        self
    }

    pub fn enable_tcp(mut self, enable: bool) -> Self {
        self.enable_tcp = enable;
        self
    }

    pub fn enable_icmp(mut self, enable: bool) -> Self {
        self.enable_icmp = enable;
        self
    }

    pub fn stack_buffer_size(mut self, size: usize) -> Self {
        self.stack_buffer_size = size;
        self
    }

    pub fn udp_buffer_size(mut self, size: usize) -> Self {
        self.udp_buffer_size = size;
        self
    }

    pub fn tcp_buffer_size(mut self, size: usize) -> Self {
        self.tcp_buffer_size = size;
        self
    }

    /// Set the per-socket TCP **receive** window in bytes (the smoltcp rx
    /// `SocketBuffer` capacity). Steady single-flow throughput is bounded by
    /// `window ÷ RTT`, so raising this helps high-BDP (high bandwidth × RTT)
    /// paths. Note this is distinct from [`Self::tcp_buffer_size`], which sizes
    /// the internal mpsc channel (item count), not the TCP window.
    pub fn tcp_recv_buffer_size(mut self, size: u32) -> Self {
        self.tcp_recv_buffer_size = size;
        self
    }

    /// Set the per-socket TCP **send** window in bytes (the smoltcp tx
    /// `SocketBuffer` capacity). See [`Self::tcp_recv_buffer_size`].
    pub fn tcp_send_buffer_size(mut self, size: u32) -> Self {
        self.tcp_send_buffer_size = size;
        self
    }

    pub fn set_ip_filters(mut self, filters: IpFilters<'static>) -> Self {
        self.ip_filters = filters;
        self
    }

    pub fn add_ip_filter(mut self, filter: IpFilter<'static>) -> Self {
        self.ip_filters.add(filter);
        self
    }

    pub fn add_ip_filter_fn<F>(mut self, filter: F) -> Self
    where
        F: Fn(&IpAddr, &IpAddr) -> bool + Send + Sync + 'static,
    {
        self.ip_filters.add_fn(filter);
        self
    }

    pub fn mtu(mut self, mtu: usize) -> Self {
        self.mtu = mtu;
        self
    }

    /// Where the stack and its UDP socket count the packets they drop or
    /// rebuild; see [`StackStats`]. Each stack counts into its own set
    /// unless one is handed in here.
    pub fn stats(mut self, stats: Arc<StackStats>) -> Self {
        self.stats = stats;
        self
    }

    #[allow(clippy::type_complexity)]
    pub fn build(
        self,
    ) -> std::io::Result<(
        Stack,
        Option<Runner>,
        Option<UdpSocket>,
        Option<TcpListener>,
    )> {
        let (stack_tx, stack_rx) = channel(self.stack_buffer_size);

        let (udp_tx, udp_rx) = if self.enable_udp {
            let (udp_tx, udp_rx) = channel(self.udp_buffer_size);
            (Some(PollSender::new(udp_tx)), Some(udp_rx))
        } else {
            (None, None)
        };

        let (tcp_tx, tcp_rx) = if self.enable_tcp {
            let (tcp_tx, tcp_rx) = channel(self.tcp_buffer_size);
            (Some(PollSender::new(tcp_tx)), Some(tcp_rx))
        } else {
            (None, None)
        };

        // ICMP is handled by TCP's Interface.
        // smoltcp's interface will always send replies to EchoRequest
        if self.enable_icmp && !self.enable_tcp {
            use std::io::{Error, ErrorKind::InvalidInput};
            return Err(Error::new(InvalidInput, "ICMP requires TCP"));
        }
        let icmp_tx = if self.enable_icmp {
            tcp_tx.clone()
        } else {
            None
        };

        let udp_socket =
            udp_rx.map(|udp_rx| UdpSocket::new(udp_rx, stack_tx.clone(), self.stats.clone()));

        let (tcp_runner, tcp_listener) = if let Some(tcp_rx) = tcp_rx {
            let (tcp_runner, tcp_listener) = TcpListener::new(
                tcp_rx,
                stack_tx,
                self.mtu,
                self.tcp_recv_buffer_size,
                self.tcp_send_buffer_size,
            )?;
            (Some(tcp_runner), Some(tcp_listener))
        } else {
            (None, None)
        };

        let stack = Stack {
            ip_filters: self.ip_filters,
            stack_rx,
            sink_buf: None,
            udp_tx,
            tcp_tx,
            icmp_tx,
            fragments: Reassembler::new(self.stats),
        };

        Ok((stack, tcp_runner, udp_socket, tcp_listener))
    }
}

pub struct Stack {
    ip_filters: IpFilters<'static>,
    sink_buf: Option<(AnyIpPktFrame, IpProtocol)>,
    udp_tx: Option<PollSender<AnyIpPktFrame>>,
    tcp_tx: Option<PollSender<AnyIpPktFrame>>,
    icmp_tx: Option<PollSender<AnyIpPktFrame>>,
    stack_rx: Receiver<AnyIpPktFrame>,
    /// UDP datagrams that came in fragments, held until they are whole.
    fragments: Reassembler,
}

impl Stack {
    fn poll_send(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), std::io::Error>> {
        let (item, proto) = match self.sink_buf.take() {
            Some(val) => val,
            None => return Poll::Ready(Ok(())),
        };

        let tx = match proto {
            IpProtocol::Tcp => self.tcp_tx.as_mut(),
            IpProtocol::Udp => self.udp_tx.as_mut(),
            IpProtocol::Icmp | IpProtocol::Icmpv6 => self.icmp_tx.as_mut(),
            _ => unreachable!(),
        };

        let Some(tx) = tx else {
            return Poll::Ready(Ok(()));
        };

        match tx.poll_reserve(cx) {
            Poll::Pending => {
                self.sink_buf = Some((item, proto));
                Poll::Pending
            }
            Poll::Ready(Err(_)) => Poll::Ready(Err(channel_closed_err("channel is closed"))),
            Poll::Ready(Ok(_)) => match tx.send_item(item) {
                Ok(()) => Poll::Ready(Ok(())),
                Err(_) => Poll::Ready(Err(channel_closed_err("channel is closed"))),
            },
        }
    }
}

// Recv from stack.
impl Stream for Stack {
    type Item = std::io::Result<AnyIpPktFrame>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        match self.stack_rx.poll_recv(cx) {
            Poll::Ready(Some(pkt)) => Poll::Ready(Some(Ok(pkt))),
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }
}

// Send to stack.
impl Sink<AnyIpPktFrame> for Stack {
    type Error = std::io::Error;

    fn poll_ready(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        // If a buffered item exists, try to flush it first. This also properly
        // registers the waker via poll_reserve so we get woken when the channel
        // has capacity. Without this, returning Pending here with _cx unused
        // means the task never gets rescheduled.
        if self.sink_buf.is_some() {
            ready!(self.poll_send(cx))?;
        }
        Poll::Ready(Ok(()))
    }

    fn start_send(mut self: Pin<&mut Self>, item: AnyIpPktFrame) -> Result<(), Self::Error> {
        if item.is_empty() {
            return Ok(());
        }

        use std::io::{Error, ErrorKind::InvalidInput};
        let packet = IpPacket::new_checked(item.as_slice())
            .map_err(|err| Error::new(InvalidInput, format!("invalid IP packet: {err}")))?;

        let src_ip = packet.src_addr();
        let dst_ip = packet.dst_addr();

        let addr_allowed = self.ip_filters.is_allowed(&src_ip, &dst_ip);
        if !addr_allowed {
            trace!("IP packet {src_ip} -> {dst_ip} (allowed? {addr_allowed}) throwing away",);
            return Ok(());
        }

        let protocol = packet.protocol();
        // A fragment goes on only as part of its whole datagram: the UDP
        // socket cannot read one alone, and smoltcp refuses them. Fragments
        // of UDP datagrams are joined; the others are dropped.
        let (item, protocol) = match reassembly::classify(item.as_slice(), &packet) {
            Piece::Whole => (item, protocol),
            Piece::Udp(fragment) if self.udp_tx.is_some() => {
                match self.fragments.push(fragment, Instant::now()) {
                    Some(datagram) => (datagram, IpProtocol::Udp),
                    None => return Ok(()),
                }
            }
            Piece::Udp(_) | Piece::Other => {
                self.fragments.refuse();
                return Ok(());
            }
        };
        if matches!(
            protocol,
            IpProtocol::Tcp | IpProtocol::Udp | IpProtocol::Icmp | IpProtocol::Icmpv6
        ) {
            self.sink_buf.replace((item, protocol));
        } else {
            debug!("tun IP packet ignored (protocol: {:?})", protocol);
        }

        Ok(())
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.poll_send(cx)
    }

    fn poll_close(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        self.stack_rx.close();
        Poll::Ready(Ok(()))
    }
}

fn channel_closed_err<E>(err: E) -> std::io::Error
where
    E: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    std::io::Error::new(std::io::ErrorKind::BrokenPipe, err)
}

#[cfg(test)]
mod tcp_window_tests {
    use super::*;

    // The configurable TCP window must (a) default to the historical ~320 KiB so
    // existing callers are behavior-identical, and (b) carry an override verbatim
    // into the builder fields that the socket-creation path
    // (`TcpListener::new` → `create` → `handle_socket`) reads. Those fields are
    // the only input to the per-socket `SocketBuffer` sizing, so asserting them
    // is asserting the window smoltcp will allocate.
    #[test]
    fn tcp_window_defaults_to_historical_and_threads_overrides() {
        let d = StackBuilder::default();
        assert_eq!(d.tcp_recv_buffer_size, 0x3FFF * 20);
        assert_eq!(d.tcp_send_buffer_size, 0x3FFF * 20);

        let b = StackBuilder::default()
            .tcp_recv_buffer_size(1 << 20)
            .tcp_send_buffer_size(2 << 20);
        assert_eq!(b.tcp_recv_buffer_size, 1 << 20);
        assert_eq!(b.tcp_send_buffer_size, 2 << 20);
        // The mpsc-depth knob is independent and must not be conflated.
        assert_eq!(b.tcp_buffer_size, 512);
    }
}

#[cfg(test)]
mod udp_tests {
    use std::{net::SocketAddr, time::Duration};

    use futures::{SinkExt, StreamExt};
    use smoltcp::wire::IPV6_HEADER_LEN;

    use super::*;
    use crate::{
        reassembly::testing::{fragments4, fragments6, udp4, udp6, APP4, APP6, DNS4, DNS6},
        udp::{ReadHalf, UdpMsg},
    };

    fn stack() -> (Stack, ReadHalf, Arc<StackStats>) {
        let stats = Arc::new(StackStats::default());
        let (stack, _runner, udp, _tcp) = StackBuilder::default()
            .enable_udp(true)
            .stats(stats.clone())
            .build()
            .unwrap();
        let (udp, _replies) = udp.unwrap().split();
        (stack, udp, stats)
    }

    async fn next(udp: &mut ReadHalf) -> Option<UdpMsg> {
        tokio::time::timeout(Duration::from_secs(5), udp.next())
            .await
            .expect("the UDP socket stalled")
    }

    // A malformed packet, a datagram missing a fragment and a datagram in
    // fragments leave the UDP socket reading: the whole datagram comes out,
    // and so does the DNS query after them.
    #[tokio::test]
    async fn bad_and_fragmented_packets_leave_udp_flowing() {
        let (mut stack, mut udp, stats) = stack();
        let app = SocketAddr::from((APP4, 5353));
        let dns = SocketAddr::from((DNS4, 53));

        // A UDP length field that counts more than the packet carries.
        let mut malformed = udp4(&[0; 100], 1);
        malformed[24..26].copy_from_slice(&200u16.to_be_bytes());
        stack.send(malformed).await.unwrap();
        // The first fragment of a datagram whose other fragment never comes.
        let orphan = fragments4(&udp4(&[1; 2000], 2), 1480).remove(0);
        stack.send(orphan).await.unwrap();
        // A datagram in three fragments, out of order.
        let big = vec![2; 3000];
        let fragments = fragments4(&udp4(&big, 3), 1480);
        for index in [1, 2, 0] {
            stack.send(fragments[index].clone()).await.unwrap();
        }
        stack.send(udp4(b"query", 4)).await.unwrap();

        assert_eq!(next(&mut udp).await, Some((big, app, dns)));
        assert_eq!(next(&mut udp).await, Some((b"query".to_vec(), app, dns)));
        assert_eq!(stats.udp_malformed(), 1);
        assert_eq!(stats.udp_reassembled(), 1);
        assert_eq!(stats.ip_fragments_dropped(), 0);
    }

    #[tokio::test]
    async fn ipv6_fragments_reach_the_udp_socket_whole() {
        let (mut stack, mut udp, stats) = stack();
        let app = SocketAddr::from((APP6, 5353));
        let dns = SocketAddr::from((DNS6, 53));

        let big = vec![3; 3000];
        for fragment in fragments6(&udp6(&big), 0x0102_0304, 1232).into_iter().rev() {
            stack.send(fragment).await.unwrap();
        }
        // A fragment of TCP is dropped and counted.
        let mut tcp = fragments6(&udp6(&[0; 2000]), 5, 1232).remove(0);
        tcp[IPV6_HEADER_LEN] = 6;
        stack.send(tcp).await.unwrap();
        stack.send(udp6(b"query")).await.unwrap();

        assert_eq!(next(&mut udp).await, Some((big, app, dns)));
        assert_eq!(next(&mut udp).await, Some((b"query".to_vec(), app, dns)));
        assert_eq!(stats.udp_reassembled(), 1);
        assert_eq!(stats.ip_fragments_dropped(), 1);
    }

    #[tokio::test]
    async fn fragments_are_dropped_without_udp() {
        let stats = Arc::new(StackStats::default());
        let (mut stack, _runner, udp, _tcp) = StackBuilder::default()
            .stats(stats.clone())
            .build()
            .unwrap();
        assert!(udp.is_none());
        for fragment in fragments4(&udp4(&[4; 2000], 5), 1480) {
            stack.send(fragment).await.unwrap();
        }
        assert_eq!(stats.ip_fragments_dropped(), 2);
        assert_eq!(stats.udp_reassembled(), 0);
    }
}
