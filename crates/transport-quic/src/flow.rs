//! QUIC over a proxied UDP flow.
//!
//! [`FlowSocket`] lets quinn run on a [`UdpFlow`] (the UDP relay of an
//! outbound, or the direct outbound's own socket) instead of a socket of its
//! own, so a QUIC client such as DNS over QUIC can reach its server through
//! any outbound that relays UDP. The flow has one destination, so every
//! datagram quinn sends goes there and every datagram received is reported as
//! coming from the peer address the connection was opened to.

use std::fmt;
use std::io::{self, IoSliceMut};
use std::net::{Ipv4Addr, SocketAddr};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use engine_outbound::UdpFlow;
use quinn::udp::{RecvMeta, Transmit};
use quinn::{AsyncUdpSocket, UdpPoller};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

/// Datagrams queued in each direction. A full send queue drops the datagram,
/// as a congested socket would; QUIC recovers it.
const QUEUE: usize = 256;

/// A quinn socket backed by one [`UdpFlow`]; see the module docs.
pub struct FlowSocket {
    peer: SocketAddr,
    outgoing: mpsc::Sender<Vec<u8>>,
    incoming: Mutex<mpsc::Receiver<Vec<u8>>>,
    tasks: [JoinHandle<()>; 2],
}

impl fmt::Debug for FlowSocket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FlowSocket").finish_non_exhaustive()
    }
}

impl FlowSocket {
    /// Pumps `flow` on the current tokio runtime. `peer` is the address quinn
    /// connects to; it only has to be the same on both sides of the socket.
    pub fn new(flow: UdpFlow, peer: SocketAddr) -> Arc<Self> {
        let UdpFlow { mut send, mut recv } = flow;
        let (outgoing, mut to_send) = mpsc::channel::<Vec<u8>>(QUEUE);
        let (received, incoming) = mpsc::channel::<Vec<u8>>(QUEUE);
        let sender = tokio::spawn(async move {
            while let Some(datagram) = to_send.recv().await {
                if send.send(&datagram).await.is_err() {
                    break;
                }
            }
        });
        let receiver = tokio::spawn(async move {
            while let Ok(datagram) = recv.recv().await {
                if received.send(datagram).await.is_err() {
                    break;
                }
            }
        });
        Arc::new(Self {
            peer,
            outgoing,
            incoming: Mutex::new(incoming),
            tasks: [sender, receiver],
        })
    }

    /// A stand-in peer address for a server known by name: quinn needs an
    /// address, and the flow carries the datagrams whatever it is.
    pub fn placeholder_peer(port: u16) -> SocketAddr {
        SocketAddr::from((Ipv4Addr::new(192, 0, 2, 1), port))
    }
}

impl Drop for FlowSocket {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}

#[derive(Debug)]
struct AlwaysWritable;

impl UdpPoller for AlwaysWritable {
    fn poll_writable(self: Pin<&mut Self>, _cx: &mut Context) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl AsyncUdpSocket for FlowSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        Box::pin(AlwaysWritable)
    }

    fn try_send(&self, transmit: &Transmit) -> io::Result<()> {
        // `max_transmit_segments` is 1, so a transmit is one datagram.
        match self.outgoing.try_send(transmit.contents.to_vec()) {
            Ok(()) | Err(mpsc::error::TrySendError::Full(_)) => Ok(()),
            Err(mpsc::error::TrySendError::Closed(_)) => {
                Err(io::Error::new(io::ErrorKind::BrokenPipe, "udp flow ended"))
            }
        }
    }

    fn poll_recv(
        &self,
        cx: &mut Context,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        let (Some(buf), Some(meta)) = (bufs.first_mut(), meta.first_mut()) else {
            return Poll::Ready(Ok(0));
        };
        let mut incoming = self.incoming.lock().unwrap_or_else(|e| e.into_inner());
        match incoming.poll_recv(cx) {
            Poll::Ready(Some(datagram)) => {
                // A datagram longer than the buffer is cut, as a socket would.
                let len = datagram.len().min(buf.len());
                buf[..len].copy_from_slice(&datagram[..len]);
                meta.addr = self.peer;
                meta.len = len;
                meta.stride = len;
                meta.ecn = None;
                meta.dst_ip = None;
                Poll::Ready(Ok(1))
            }
            Poll::Ready(None) => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "udp flow ended",
            ))),
            Poll::Pending => Poll::Pending,
        }
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        // Same family as the peer, so quinn does not map addresses.
        Ok(match self.peer {
            SocketAddr::V4(_) => SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)),
            SocketAddr::V6(_) => SocketAddr::from((std::net::Ipv6Addr::UNSPECIFIED, 0)),
        })
    }

    fn may_fragment(&self) -> bool {
        // The relay may carry datagrams in a stream or re-send them from a
        // socket of its own: nothing promises they are not fragmented.
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use engine_outbound::{BoxFuture, DatagramRecv, DatagramSend};

    struct ChannelSend(mpsc::UnboundedSender<Vec<u8>>);
    impl DatagramSend for ChannelSend {
        fn send<'a>(&'a mut self, payload: &'a [u8]) -> BoxFuture<'a, io::Result<()>> {
            let sent = self.0.send(payload.to_vec());
            Box::pin(async move { sent.map_err(|_| io::ErrorKind::BrokenPipe.into()) })
        }
    }
    struct ChannelRecv(mpsc::UnboundedReceiver<Vec<u8>>);
    impl DatagramRecv for ChannelRecv {
        fn recv(&mut self) -> BoxFuture<'_, io::Result<Vec<u8>>> {
            Box::pin(async move {
                self.0
                    .recv()
                    .await
                    .ok_or_else(|| io::ErrorKind::UnexpectedEof.into())
            })
        }
    }

    #[tokio::test]
    async fn datagrams_go_through_the_flow_and_come_back_from_the_peer() {
        let (sent_tx, mut sent_rx) = mpsc::unbounded_channel();
        let (reply_tx, reply_rx) = mpsc::unbounded_channel();
        let flow = UdpFlow::new(
            Box::new(ChannelSend(sent_tx)),
            Box::new(ChannelRecv(reply_rx)),
        );
        let peer = FlowSocket::placeholder_peer(853);
        let socket = FlowSocket::new(flow, peer);
        socket
            .try_send(&Transmit {
                destination: peer,
                ecn: None,
                contents: b"hello",
                segment_size: None,
                src_ip: None,
            })
            .unwrap();
        assert_eq!(sent_rx.recv().await.unwrap(), b"hello");

        reply_tx.send(b"world".to_vec()).unwrap();
        let mut storage = [0u8; 16];
        let mut meta = [RecvMeta::default()];
        let count = std::future::poll_fn(|cx| {
            let mut bufs = [IoSliceMut::new(&mut storage)];
            socket.poll_recv(cx, &mut bufs, &mut meta)
        })
        .await
        .unwrap();
        assert_eq!(count, 1);
        assert_eq!(meta[0].addr, peer);
        assert_eq!(&storage[..meta[0].len], b"world");
        assert!(socket.local_addr().unwrap().is_ipv4());

        // The far end going away ends the socket.
        drop(reply_tx);
        let ended = std::future::poll_fn(|cx| {
            let mut bufs = [IoSliceMut::new(&mut storage)];
            socket.poll_recv(cx, &mut bufs, &mut meta)
        })
        .await;
        assert!(ended.is_err());
    }
}
