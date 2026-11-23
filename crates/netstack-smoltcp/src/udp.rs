use std::{
    net::SocketAddr,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use etherparse::PacketBuilder;
use futures::{ready, Sink, SinkExt, Stream};
use smoltcp::wire::UdpPacket;
use tokio::sync::mpsc::{Receiver, Sender};
use tokio_util::sync::PollSender;
use tracing::{debug, trace};

use crate::{
    packet::{AnyIpPktFrame, IpPacket},
    stats::StackStats,
};

pub type UdpMsg = (
    Vec<u8>,    /* payload */
    SocketAddr, /* local */
    SocketAddr, /* remote */
);

pub struct UdpSocket {
    udp_rx: Receiver<AnyIpPktFrame>,
    stack_tx: PollSender<AnyIpPktFrame>,
    stats: Arc<StackStats>,
}

impl UdpSocket {
    pub(super) fn new(
        udp_rx: Receiver<AnyIpPktFrame>,
        stack_tx: Sender<AnyIpPktFrame>,
        stats: Arc<StackStats>,
    ) -> Self {
        Self {
            udp_rx,
            stack_tx: PollSender::new(stack_tx),
            stats,
        }
    }

    pub fn split(self) -> (ReadHalf, WriteHalf) {
        (
            ReadHalf {
                udp_rx: self.udp_rx,
                stats: self.stats.clone(),
            },
            WriteHalf {
                stack_tx: self.stack_tx,
                stats: self.stats,
            },
        )
    }
}

/// The UDP datagrams from the TUN side. It ends only when the stack is
/// gone: a packet whose UDP header does not parse is dropped and counted
/// ([`StackStats::udp_malformed`]), and the next one is read.
pub struct ReadHalf {
    udp_rx: Receiver<AnyIpPktFrame>,
    stats: Arc<StackStats>,
}

/// Sends UDP datagrams to the TUN side, each as one IP packet. A datagram
/// that cannot be built into one is dropped and counted
/// ([`StackStats::udp_unsendable`]) like a datagram lost on the way, so the
/// ones after it still go out; the sink fails only once the stack is gone.
pub struct WriteHalf {
    stack_tx: PollSender<AnyIpPktFrame>,
    stats: Arc<StackStats>,
}

impl Stream for ReadHalf {
    type Item = UdpMsg;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Option<Self::Item>> {
        loop {
            let Some(frame) = ready!(self.udp_rx.poll_recv(cx)) else {
                return Poll::Ready(None);
            };
            match parse(&frame) {
                Some(msg) => return Poll::Ready(Some(msg)),
                None => self.stats.count_udp_malformed(),
            }
        }
    }
}

/// The UDP datagram in `frame`, an IP packet the stack passed on as UDP;
/// `None` when it does not parse.
fn parse(frame: &[u8]) -> Option<UdpMsg> {
    let packet = match IpPacket::new_checked(frame) {
        Ok(packet) => packet,
        Err(err) => {
            debug!("UDP packet dropped: invalid IP packet: {err}");
            return None;
        }
    };
    let payload = packet.payload();
    let udp = match UdpPacket::new_checked(payload) {
        Ok(udp) => udp,
        Err(err) => {
            debug!(
                "UDP packet dropped: invalid UDP header: {err} ({} bytes)",
                payload.len()
            );
            return None;
        }
    };

    let src_addr = SocketAddr::new(packet.src_addr(), udp.src_port());
    let dst_addr = SocketAddr::new(packet.dst_addr(), udp.dst_port());

    trace!("created UDP socket for {src_addr} <-> {dst_addr}");

    Some((udp.payload().to_vec(), src_addr, dst_addr))
}

/// `data` from `src` to `dst` as one IP packet; `None` when the addresses
/// are of two families or the datagram is larger than an IP packet carries.
fn build(data: &[u8], src: SocketAddr, dst: SocketAddr) -> Option<AnyIpPktFrame> {
    let builder = match (src, dst) {
        (SocketAddr::V4(src), SocketAddr::V4(dst)) => {
            PacketBuilder::ipv4(src.ip().octets(), dst.ip().octets(), 20)
                .udp(src.port(), dst.port())
        }
        (SocketAddr::V6(src), SocketAddr::V6(dst)) => {
            PacketBuilder::ipv6(src.ip().octets(), dst.ip().octets(), 20)
                .udp(src.port(), dst.port())
        }
        _ => {
            debug!("UDP datagram dropped: source and destination of two address families");
            return None;
        }
    };

    let mut packet = Vec::with_capacity(builder.size(data.len()));
    match builder.write(&mut packet, data) {
        Ok(()) => Some(packet),
        Err(err) => {
            debug!(
                "UDP datagram dropped: {} bytes do not fit in one IP packet: {err}",
                data.len()
            );
            None
        }
    }
}

impl Sink<UdpMsg> for WriteHalf {
    type Error = std::io::Error;

    fn poll_ready(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        match ready!(self.stack_tx.poll_ready_unpin(cx)) {
            Ok(()) => Poll::Ready(Ok(())),
            Err(err) => Poll::Ready(Err(std::io::Error::other(err))),
        }
    }

    fn start_send(mut self: Pin<&mut Self>, item: UdpMsg) -> Result<(), Self::Error> {
        let (data, src_addr, dst_addr) = item;

        if data.is_empty() {
            return Ok(());
        }

        // Dropped like a datagram lost on the way; the channel slot
        // `poll_ready` reserved stays reserved for the next one.
        let Some(packet) = build(&data, src_addr, dst_addr) else {
            self.stats.count_udp_unsendable();
            return Ok(());
        };

        match self.stack_tx.start_send_unpin(packet) {
            Ok(()) => Ok(()),
            Err(err) => Err(std::io::Error::other(format!("send error: {err}"))),
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        use std::io::Error;
        match ready!(self.stack_tx.poll_flush_unpin(cx)) {
            Ok(()) => Poll::Ready(Ok(())),
            Err(err) => Poll::Ready(Err(Error::other(format!("flush error: {err}")))),
        }
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        use std::io::Error;
        match ready!(self.stack_tx.poll_close_unpin(cx)) {
            Ok(()) => Poll::Ready(Ok(())),
            Err(err) => Poll::Ready(Err(Error::other(format!("close error: {err}")))),
        }
    }
}

#[cfg(test)]
mod tests {
    use futures::StreamExt;
    use smoltcp::wire::Ipv4Packet;
    use tokio::sync::mpsc::channel;

    use super::*;
    use crate::reassembly::testing::{udp4, APP4, DNS4, DNS6};

    fn socket() -> (
        UdpSocket,
        Sender<AnyIpPktFrame>,
        Receiver<AnyIpPktFrame>,
        Arc<StackStats>,
    ) {
        let (udp_tx, udp_rx) = channel(8);
        let (stack_tx, stack_rx) = channel(8);
        let stats = Arc::new(StackStats::default());
        let socket = UdpSocket::new(udp_rx, stack_tx, stats.clone());
        (socket, udp_tx, stack_rx, stats)
    }

    #[tokio::test]
    async fn a_packet_that_does_not_parse_is_skipped() {
        let (socket, udp_tx, _stack_rx, stats) = socket();
        let (mut read, _write) = socket.split();
        let app = SocketAddr::from((APP4, 5353));
        let dns = SocketAddr::from((DNS4, 53));

        // A UDP length field that counts more than the packet carries, as in
        // the first fragment of a datagram.
        let mut long = udp4(&[0; 100], 1);
        long[24..26].copy_from_slice(&200u16.to_be_bytes());
        udp_tx.send(long).await.unwrap();
        // A UDP header cut short.
        let mut short = udp4(b"", 2);
        short.truncate(24);
        let mut ip = Ipv4Packet::new_unchecked(&mut short[..]);
        ip.set_total_len(24);
        ip.fill_checksum();
        udp_tx.send(short).await.unwrap();
        // Then a DNS query.
        udp_tx.send(udp4(b"query", 3)).await.unwrap();

        assert_eq!(read.next().await, Some((b"query".to_vec(), app, dns)));
        assert_eq!(stats.udp_malformed(), 2);

        // The stream ends with the stack only.
        drop(udp_tx);
        assert_eq!(read.next().await, None);
    }

    #[tokio::test]
    async fn a_datagram_that_cannot_be_built_is_dropped() {
        let (socket, _udp_tx, mut stack_rx, stats) = socket();
        let (_read, mut write) = socket.split();
        let app = SocketAddr::from((APP4, 5353));
        let dns = SocketAddr::from((DNS4, 53));
        let dns6 = SocketAddr::from((DNS6, 53));

        // Addresses of two families.
        write.send((b"answer".to_vec(), dns6, app)).await.unwrap();
        // More than an IPv4 packet carries.
        write.send((vec![0; 65_508], dns, app)).await.unwrap();
        // The answer after them still goes out.
        write.send((b"answer".to_vec(), dns, app)).await.unwrap();
        assert_eq!(stats.udp_unsendable(), 2);

        let packet = stack_rx.recv().await.unwrap();
        assert_eq!(parse(&packet), Some((b"answer".to_vec(), dns, app)));
        assert!(stack_rx.try_recv().is_err());
    }
}
