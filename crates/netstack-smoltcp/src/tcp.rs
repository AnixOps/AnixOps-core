use std::{
    collections::HashMap,
    net::SocketAddr,
    pin::Pin,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    task::{Context, Poll, Waker},
};

use futures::Stream;
use smoltcp::{
    iface::{Config as InterfaceConfig, Interface, SocketHandle, SocketSet},
    phy::Device,
    socket::tcp::{Socket as TcpSocket, SocketBuffer as TcpSocketBuffer, State as TcpState},
    storage::RingBuffer,
    time::{Duration, Instant},
    wire::{
        HardwareAddress, IpAddress, IpCidr, IpEndpoint, IpProtocol, Ipv4Address, Ipv6Address,
        TcpPacket,
    },
};
use spin::Mutex as SpinMutex;
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    sync::{
        mpsc::{unbounded_channel, Receiver, Sender, UnboundedReceiver, UnboundedSender},
        Notify,
    },
};
use tracing::{error, trace};

use crate::{
    device::VirtualDevice,
    packet::{AnyIpPktFrame, IpPacket},
    Runner,
};

/// Largest staging buffer between a smoltcp socket and its [`TcpStream`].
///
/// The TCP window lives in the smoltcp socket buffers; these only hand bytes
/// to and from the stream's reader and writer, which move at most a few KiB
/// per call. Upstream sized them like the window, doubling every
/// connection's memory (4 x 64 KiB at the tunnel's default window).
const STREAM_BUFFER_MAX: usize = 16 * 1024;

fn stream_buffer_size(window: u32) -> usize {
    (window as usize).min(STREAM_BUFFER_MAX)
}

/// Longest park of the socket loop when no socket has anything scheduled.
const IDLE_PARK: Duration = Duration::from_secs(10);

/// How long a socket stays in TIME-WAIT before it is removed.
///
/// smoltcp keeps TIME-WAIT for 10 s, and with it the socket's receive and
/// send buffers (two windows, 128 KiB at the tunnel's default): every short
/// connection the tunnel closes first stayed at full size for 10 s, so a
/// burst of a few hundred short connections pushed the iOS extension
/// towards its memory limit. Even 1 s kept ~30 MiB alive in a burst of 200
/// connections at 16 at a time (capture-gates F8).
///
/// The peer is the device's own TCP stack across the TUN interface, where
/// segments are neither delayed nor duplicated, so the old-duplicate
/// protection of TIME-WAIT buys nothing. The linger only lets smoltcp send
/// the final ACK, which it may delay by its ACK delay (10 ms). Should that
/// ACK be lost, the peer's retransmitted FIN is answered with a RST, which a
/// peer in LAST-ACK takes as the end of the connection: its application
/// has already closed, so nothing is lost either way.
const TIME_WAIT_LINGER: Duration = Duration::from_millis(100);

/// How long a socket made for a SYN may stay in LISTEN, once every queued
/// frame has been handed to smoltcp, before it is removed.
///
/// A socket in LISTEN accepts a SYN from any source to its address, so one
/// left over would take the next connection to the same destination. Each
/// SYN gets its own socket right before the frame is queued, so the socket
/// normally leaves LISTEN in the same poll; one that does not saw its SYN
/// refused by smoltcp (a bad checksum, say). Only removed while no frame
/// is queued: a SYN still waiting for room in the egress queue would be
/// answered with a RST if its socket went first.
const LISTEN_GRACE: Duration = Duration::from_secs(2);

/// How long a socket may outlive its [`TcpStream`] before it is reset.
///
/// After the stream is dropped the socket still sends what was written and
/// the FIN, and reads and discards what the app still sends so its window
/// stays open and its FIN can arrive. An app that never finishes (a stalled
/// upload, a zero window) would keep the socket and both its buffers alive
/// for as long as keep-alives are answered, outside the tunnel's connection
/// limit; like Linux's `tcp_fin_timeout` for orphaned sockets, it is reset
/// after this long instead.
const ORPHAN_LINGER: Duration = Duration::from_secs(60);

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum TcpSocketState {
    Normal,
    Close,
    Closing,
    Closed,
}

struct TcpSocketControl {
    send_buffer: RingBuffer<'static, u8>,
    send_waker: Option<Waker>,
    recv_buffer: RingBuffer<'static, u8>,
    recv_waker: Option<Waker>,
    recv_state: TcpSocketState,
    send_state: TcpSocketState,
    /// Set by [`TcpStream::abort`]: the socket sends a RST and is removed.
    abort: bool,
    /// The [`TcpStream`] was dropped: nobody reads any more.
    dropped: bool,
}

/// A SYN that may open a connection, with its frame. Only the socket loop
/// hands it to smoltcp, and only once it decided the SYN needs a socket.
struct SynRequest {
    src_addr: SocketAddr,
    dst_addr: SocketAddr,
    frame: Vec<u8>,
}

type SharedNotify = Arc<Notify>;
type SharedControl = Arc<SpinMutex<TcpSocketControl>>;

/// A socket of the set with its stream's side.
struct SocketEntry {
    control: SharedControl,
    /// The (app, destination) pair this socket is indexed under in the
    /// loop's connection table: the SYN it was made for, then, once the
    /// socket left LISTEN, the endpoints smoltcp actually connected it to.
    key: (SocketAddr, SocketAddr),
    /// When the socket was made, or last given a SYN, for [`LISTEN_GRACE`].
    created: Instant,
    /// The number [`VirtualDevice::queue_syn`] gave the SYN frame queued
    /// for this socket: smoltcp has read that frame once
    /// [`VirtualDevice::syn_taken`] reaches it.
    syn_seq: u64,
    /// Whether its [`TcpStream`] went to the listener. That happens once the
    /// socket left LISTEN, never before: a socket in LISTEN takes a SYN from
    /// any source, so only then are its endpoints known.
    emitted: bool,
    /// Once the socket is in TIME-WAIT, when it is removed ([`TIME_WAIT_LINGER`]).
    time_wait_until: Option<Instant>,
    /// Once the stream was dropped, when the socket is reset ([`ORPHAN_LINGER`]).
    orphan_until: Option<Instant>,
}

/// Marks both halves of the stream closed and wakes its reader and writer:
/// reads return EOF, writes fail with `BrokenPipe`, a shutdown completes.
fn close_stream(control: &mut TcpSocketControl) {
    control.send_state = TcpSocketState::Closed;
    control.recv_state = TcpSocketState::Closed;
    if let Some(waker) = control.send_waker.take() {
        waker.wake();
    }
    if let Some(waker) = control.recv_waker.take() {
        waker.wake();
    }
}

fn socket_addr(endpoint: IpEndpoint) -> SocketAddr {
    SocketAddr::new(endpoint.addr.into(), endpoint.port)
}

/// The (app, destination) pair `socket` is connected to; `None` in LISTEN
/// and CLOSED.
fn connected_key(socket: &TcpSocket) -> Option<(SocketAddr, SocketAddr)> {
    let (Some(remote), Some(local)) = (socket.remote_endpoint(), socket.local_endpoint()) else {
        return None;
    };
    Some((socket_addr(remote), socket_addr(local)))
}

/// What the socket loop builds sockets and streams with.
struct SocketTemplate {
    notify: SharedNotify,
    stream_tx: UnboundedSender<TcpStream>,
    tcp_recv_buffer_size: u32,
    tcp_send_buffer_size: u32,
}

impl SocketTemplate {
    /// A socket listening for the SYN from `src_addr` to `dst_addr`, and
    /// the control its stream will share.
    fn socket(
        &self,
        src_addr: SocketAddr,
        dst_addr: SocketAddr,
    ) -> Option<(TcpSocket<'static>, SharedControl)> {
        let mut socket = TcpSocket::new(
            TcpSocketBuffer::new(vec![0u8; self.tcp_recv_buffer_size as usize]),
            TcpSocketBuffer::new(vec![0u8; self.tcp_send_buffer_size as usize]),
        );
        socket.set_keep_alive(Some(Duration::from_secs(28)));
        // FIXME: It should follow system's setting. 7200 is Linux's default.
        socket.set_timeout(Some(Duration::from_secs(7200)));
        // NO ACK delay
        // socket.set_ack_delay(None);

        if let Err(err) = socket.listen(dst_addr) {
            error!("listen error: {:?}", err);
            return None;
        }

        trace!("created TCP connection for {} <-> {}", src_addr, dst_addr);

        let control = Arc::new(SpinMutex::new(TcpSocketControl {
            send_buffer: RingBuffer::new(vec![0u8; stream_buffer_size(self.tcp_send_buffer_size)]),
            send_waker: None,
            recv_buffer: RingBuffer::new(vec![0u8; stream_buffer_size(self.tcp_recv_buffer_size)]),
            recv_waker: None,
            recv_state: TcpSocketState::Normal,
            send_state: TcpSocketState::Normal,
            abort: false,
            dropped: false,
        }));
        Some((socket, control))
    }
}

struct TcpListenerRunner;

impl TcpListenerRunner {
    #[allow(clippy::too_many_arguments)]
    fn create(
        device: VirtualDevice,
        iface: Interface,
        iface_ingress_tx: UnboundedSender<Vec<u8>>,
        iface_ingress_tx_avail: Arc<AtomicBool>,
        tcp_rx: Receiver<AnyIpPktFrame>,
        stream_tx: UnboundedSender<TcpStream>,
        sockets: HashMap<SocketHandle, SocketEntry>,
        tcp_recv_buffer_size: u32,
        tcp_send_buffer_size: u32,
    ) -> Runner {
        Runner::new(async move {
            let notify = Arc::new(Notify::new());
            let (syn_tx, syn_rx) = unbounded_channel::<SynRequest>();
            let template = SocketTemplate {
                notify: notify.clone(),
                stream_tx,
                tcp_recv_buffer_size,
                tcp_send_buffer_size,
            };
            let res = tokio::select! {
                v = Self::handle_packet(notify.clone(), iface_ingress_tx, iface_ingress_tx_avail.clone(), tcp_rx, syn_tx) => v,
                v = Self::handle_socket(notify, device, iface, iface_ingress_tx_avail, sockets, syn_rx, template) => v,
            };
            res?;
            trace!("VirtDevice::poll thread exited");
            Ok(())
        })
    }

    async fn handle_packet(
        notify: SharedNotify,
        iface_ingress_tx: UnboundedSender<Vec<u8>>,
        iface_ingress_tx_avail: Arc<AtomicBool>,
        mut tcp_rx: Receiver<AnyIpPktFrame>,
        syn_tx: UnboundedSender<SynRequest>,
    ) -> std::io::Result<()> {
        while let Some(frame) = tcp_rx.recv().await {
            let packet = match IpPacket::new_checked(frame.as_slice()) {
                Ok(p) => p,
                Err(err) => {
                    error!("invalid TCP IP packet: {:?}", err,);
                    continue;
                }
            };

            // Specially handle icmp packet by TCP interface.
            if matches!(packet.protocol(), IpProtocol::Icmp | IpProtocol::Icmpv6) {
                iface_ingress_tx
                    .send(frame)
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::BrokenPipe, e))?;
                iface_ingress_tx_avail.store(true, Ordering::Release);
                notify.notify_one();
                continue;
            }

            let src_ip = packet.src_addr();
            let dst_ip = packet.dst_addr();
            let payload = packet.payload();

            let packet = match TcpPacket::new_checked(payload) {
                Ok(p) => p,
                Err(err) => {
                    error!("invalid TCP err: {err}, src_ip: {src_ip}, dst_ip: {dst_ip}, payload: {payload:?}");
                    continue;
                }
            };
            let src_port = packet.src_port();
            let dst_port = packet.dst_port();

            let src_addr = SocketAddr::new(src_ip, src_port);
            let dst_addr = SocketAddr::new(dst_ip, dst_port);

            // A SYN may open a connection. The socket loop decides, as the
            // only owner of the socket set, and queues the frame for smoltcp
            // itself, right after the socket it made for it. A retransmitted
            // SYN of a connection it already has never reaches smoltcp: a
            // socket in LISTEN takes a SYN from any source to its address,
            // so another connection's socket would take it and open a second
            // connection on the same endpoints.
            if packet.syn() && !packet.ack() {
                syn_tx
                    .send(SynRequest {
                        src_addr,
                        dst_addr,
                        frame,
                    })
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::BrokenPipe, e))?;
                notify.notify_one();
                continue;
            }

            // Pipeline tcp stream packet
            iface_ingress_tx
                .send(frame)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::BrokenPipe, e))?;
            iface_ingress_tx_avail.store(true, Ordering::Release);
            notify.notify_one();
        }
        Ok(())
    }

    /// Removes the socket of `handle`, its entry and its index entry, and
    /// ends its stream.
    fn remove_socket(
        handle: SocketHandle,
        sockets: &mut HashMap<SocketHandle, SocketEntry>,
        socket_set: &mut SocketSet<'static>,
        connections: &mut HashMap<(SocketAddr, SocketAddr), SocketHandle>,
    ) {
        if let Some(entry) = sockets.remove(&handle) {
            if connections.get(&entry.key) == Some(&handle) {
                connections.remove(&entry.key);
            }
            close_stream(&mut entry.control.lock());
        }
        socket_set.remove(handle);
    }

    async fn handle_socket(
        notify: SharedNotify,
        mut device: VirtualDevice,
        mut iface: Interface,
        iface_ingress_tx_avail: Arc<AtomicBool>,
        mut sockets: HashMap<SocketHandle, SocketEntry>,
        mut syn_rx: UnboundedReceiver<SynRequest>,
        template: SocketTemplate,
    ) -> std::io::Result<()> {
        let mut socket_set = SocketSet::new(vec![]);
        // The socket of each (app, destination) pair, so a SYN the app sent
        // again (no SYN-ACK within its retransmission timeout) is dropped
        // instead of opening a second connection: given to smoltcp, it would
        // go to whichever socket in LISTEN comes first, of any source.
        let mut connections: HashMap<(SocketAddr, SocketAddr), SocketHandle> = HashMap::new();
        loop {
            let now = Instant::now();
            while let Ok(SynRequest {
                src_addr,
                dst_addr,
                frame,
            }) = syn_rx.try_recv()
            {
                let key = (src_addr, dst_addr);
                if let Some(&handle) = connections.get(&key) {
                    let state = socket_set.get::<TcpSocket>(handle).state();
                    if state == TcpState::Listen {
                        if let Some(entry) = sockets.get_mut(&handle) {
                            if !entry.emitted && device.syn_taken() >= entry.syn_seq {
                                // smoltcp refused the first SYN (a bad
                                // checksum, say) and the socket still
                                // listens: this one gets its chance.
                                entry.syn_seq = device.queue_syn(frame);
                                entry.created = now;
                            }
                        }
                        // Otherwise the first SYN still waits in the queue
                        // and the socket takes that one.
                        continue;
                    }
                    if !matches!(state, TcpState::Closed | TcpState::TimeWait) {
                        // A retransmitted SYN of a connection under way:
                        // dropped. smoltcp ignores a SYN without an ACK
                        // from SYN-RECEIVED on, and resends its SYN-ACK on
                        // its own timer.
                        continue;
                    }
                    // The app reuses the port of a connection that is over:
                    // the old socket would take the SYN, so it goes first.
                    Self::remove_socket(handle, &mut sockets, &mut socket_set, &mut connections);
                }
                let Some((socket, control)) = template.socket(src_addr, dst_addr) else {
                    continue;
                };
                let handle = socket_set.add(socket);
                connections.insert(key, handle);
                let syn_seq = device.queue_syn(frame);
                sockets.insert(
                    handle,
                    SocketEntry {
                        control,
                        key,
                        created: now,
                        syn_seq,
                        emitted: false,
                        time_wait_until: None,
                        orphan_until: None,
                    },
                );
            }

            let before_poll = Instant::now();
            let updated_sockets = iface.poll(before_poll, &mut device, &mut socket_set);
            if matches!(
                updated_sockets,
                smoltcp::iface::PollResult::SocketStateChanged
            ) {
                trace!("VirtDevice::poll costed {}", Instant::now() - before_poll);
            }

            // Check all the sockets' status
            let mut sockets_to_remove = Vec::new();

            // Earliest TIME-WAIT removal, orphan reset or LISTEN removal
            // still to come, for the park below.
            let mut next_deadline: Option<Instant> = None;
            // Whether every queued frame has been handed to smoltcp.
            let ingress_drained =
                !iface_ingress_tx_avail.load(Ordering::Acquire) && !device.syn_pending();

            for (socket_handle, entry) in sockets.iter_mut() {
                let socket_handle = *socket_handle;

                if !entry.emitted {
                    let socket = socket_set.get::<TcpSocket>(socket_handle);
                    match socket.state() {
                        TcpState::Listen => {
                            // Its SYN was not taken (another socket listening
                            // on the same address took it, and this one takes
                            // the other SYN in turn) or was refused.
                            let until = entry.created + LISTEN_GRACE;
                            if before_poll < until {
                                next_deadline =
                                    Some(next_deadline.map_or(until, |next| next.min(until)));
                            } else if ingress_drained {
                                sockets_to_remove.push(socket_handle);
                                trace!("removed TCP socket that never left LISTEN");
                            }
                            continue;
                        }
                        // Reset before it was handed out: nothing to tell.
                        TcpState::Closed => {
                            sockets_to_remove.push(socket_handle);
                            continue;
                        }
                        _ => {}
                    }
                    let Some(key) = connected_key(socket) else {
                        continue;
                    };
                    // A socket in LISTEN takes a SYN from any source to its
                    // address: of two SYNs to one destination in one poll,
                    // each socket may hold the other's. The stream carries
                    // the endpoints the socket is connected to, and the
                    // index follows them.
                    if key != entry.key {
                        if let Some(&other) = connections.get(&key) {
                            if other != socket_handle
                                && connected_key(socket_set.get::<TcpSocket>(other)) == Some(key)
                            {
                                // Another socket is already connected to these
                                // endpoints: this one took a SYN of that
                                // connection, which should never have reached
                                // smoltcp. Removed without a RST (that would
                                // reset the app's connection) and without a
                                // stream. (Two SYNs to one destination that
                                // each socket took the other's of are no
                                // duplicate: the other socket is connected to
                                // its own endpoints.)
                                error!("second TCP socket for {} <-> {}", key.0, key.1);
                                sockets_to_remove.push(socket_handle);
                                continue;
                            }
                        }
                        if connections.get(&entry.key) == Some(&socket_handle) {
                            connections.remove(&entry.key);
                        }
                        connections.insert(key, socket_handle);
                        entry.key = key;
                    }
                    entry.emitted = true;
                    template
                        .stream_tx
                        .send(TcpStream {
                            src_addr: key.0,
                            dst_addr: key.1,
                            notify: template.notify.clone(),
                            control: entry.control.clone(),
                        })
                        .map_err(|e| std::io::Error::new(std::io::ErrorKind::BrokenPipe, e))?;
                }

                let socket = socket_set.get_mut::<TcpSocket>(socket_handle);
                let mut control = entry.control.lock();

                // Remove the socket only when it is in the closed state.
                if socket.state() == TcpState::Closed {
                    sockets_to_remove.push(socket_handle);
                    close_stream(&mut control);
                    trace!("closed TCP connection");
                    continue;
                }

                // A RST from the app in SYN-RECEIVED puts smoltcp's socket
                // back into LISTEN, where it would take the next SYN to this
                // address from any source, with the stream already handed
                // out for this one. The connection is over: the stream ends.
                if socket.state() == TcpState::Listen {
                    socket.abort();
                    sockets_to_remove.push(socket_handle);
                    close_stream(&mut control);
                    trace!("removed TCP socket reset in SYN-RECEIVED");
                    continue;
                }

                // The stream asked for a reset: smoltcp sends the RST in the
                // next poll, then the socket is CLOSED and removed above.
                if control.abort {
                    trace!("aborting TCP connection, {:?}", socket.state());
                    socket.abort();
                    control.recv_buffer.clear();
                    control.send_buffer.clear();
                    close_stream(&mut control);
                    continue;
                }

                // Both sides have sent their FIN and ours is acknowledged:
                // keep the socket only for TIME_WAIT_LINGER, not smoltcp's
                // 10 s, so its buffers go back right away.
                if socket.state() == TcpState::TimeWait {
                    let until = *entry
                        .time_wait_until
                        .get_or_insert(before_poll + TIME_WAIT_LINGER);
                    if before_poll < until {
                        next_deadline = Some(next_deadline.map_or(until, |next| next.min(until)));
                    } else if socket.recv_queue() == 0
                        || !matches!(control.recv_state, TcpSocketState::Normal)
                    {
                        // Removed once every received byte has been handed
                        // to the stream (or nobody reads any more): bytes
                        // still in the socket's buffer would be lost. A
                        // stream that reads notifies the loop.
                        sockets_to_remove.push(socket_handle);
                        close_stream(&mut control);
                        trace!("removed TCP connection in TIME-WAIT");
                        continue;
                    }
                }

                // The stream is gone: past ORPHAN_LINGER the socket is reset.
                if control.dropped {
                    let until = *entry
                        .orphan_until
                        .get_or_insert(before_poll + ORPHAN_LINGER);
                    if before_poll >= until {
                        trace!("resetting orphaned TCP connection, {:?}", socket.state());
                        socket.abort();
                        control.recv_buffer.clear();
                        control.send_buffer.clear();
                        close_stream(&mut control);
                        continue;
                    }
                    next_deadline = Some(next_deadline.map_or(until, |next| next.min(until)));
                }

                // SHUT_WR — only close once the send_buffer has been fully
                // drained into the smoltcp socket.  Closing earlier transitions
                // the socket to FIN_WAIT_1, making can_send() return false, so
                // the send loop below never runs and the remaining data is lost.
                //
                // Not in SYN-RECEIVED: smoltcp's close() there goes to
                // FIN-WAIT-1 counting the SYN as acknowledged, takes the
                // app's handshake ACK as the ACK of a FIN it never sent and
                // sits in FIN-WAIT-2 without sending one. The handshake ACK
                // wakes the loop and the close happens from ESTABLISHED.
                if matches!(control.send_state, TcpSocketState::Close)
                    && control.send_buffer.is_empty()
                    && socket.state() != TcpState::SynReceived
                {
                    trace!("closing TCP Write Half, {:?}", socket.state());

                    socket.close();
                    control.send_state = TcpSocketState::Closing;

                    // The FIN is queued behind every byte written: a pending
                    // `poll_shutdown` is done, as `shutdown(SHUT_WR)` is on
                    // an OS socket.
                    if let Some(waker) = control.send_waker.take() {
                        waker.wake();
                    }
                }

                // Check if readable
                let mut wake_receiver = false;
                if control.dropped {
                    // Nobody reads any more: what the app still sends is
                    // taken and discarded, so the window stays open and the
                    // app's FIN can arrive. Kept, it filled the staging
                    // buffer and then the window, and the socket stayed with
                    // a zero window (FIN-WAIT-2, kept alive) until the app
                    // gave up.
                    control.recv_buffer.clear();
                    while socket.can_recv() {
                        if let Err(err) = socket.recv(|buffer| (buffer.len(), ())) {
                            error!("socket recv error: {:?}, {:?}", err, socket.state());
                            socket.abort();
                            break;
                        }
                    }
                }
                while socket.can_recv() && !control.recv_buffer.is_full() {
                    let result = socket.recv(|buffer| {
                        let n = control.recv_buffer.enqueue_slice(buffer);
                        (n, ())
                    });

                    match result {
                        Ok(..) => wake_receiver = true,
                        Err(err) => {
                            error!("socket recv error: {:?}, {:?}", err, socket.state());

                            // Don't know why. Abort the connection.
                            socket.abort();

                            if matches!(control.recv_state, TcpSocketState::Normal) {
                                control.recv_state = TcpSocketState::Closed;
                            }
                            wake_receiver = true;

                            // The socket will be recycled in the next poll.
                            break;
                        }
                    }
                }

                // If socket is not in ESTABLISH, FIN-WAIT-1, FIN-WAIT-2,
                // the local client have closed our receiver.
                let states = [
                    TcpState::Listen,
                    TcpState::SynReceived,
                    TcpState::Established,
                    TcpState::FinWait1,
                    TcpState::FinWait2,
                ];
                if matches!(control.recv_state, TcpSocketState::Normal)
                    && !socket.may_recv()
                    && !states.contains(&socket.state())
                {
                    trace!("closed TCP Read Half, {:?}", socket.state());

                    // Let TcpStream::poll_read returns EOF.
                    control.recv_state = TcpSocketState::Closed;
                    wake_receiver = true;
                }

                if wake_receiver && control.recv_waker.is_some() {
                    if let Some(waker) = control.recv_waker.take() {
                        waker.wake();
                    }
                }

                // Check if writable
                let mut wake_sender = false;
                while socket.can_send() && !control.send_buffer.is_empty() {
                    let result = socket.send(|buffer| {
                        let n = control.send_buffer.dequeue_slice(buffer);
                        (n, ())
                    });

                    match result {
                        Ok(..) => wake_sender = true,
                        Err(err) => {
                            error!("socket send error: {:?}, {:?}", err, socket.state());

                            // Don't know why. Abort the connection.
                            socket.abort();

                            if matches!(control.send_state, TcpSocketState::Normal) {
                                control.send_state = TcpSocketState::Closed;
                            }
                            wake_sender = true;

                            // The socket will be recycled in the next poll.
                            break;
                        }
                    }
                }

                if wake_sender && control.send_waker.is_some() {
                    if let Some(waker) = control.send_waker.take() {
                        waker.wake();
                    }
                }
            }

            for socket_handle in sockets_to_remove {
                Self::remove_socket(
                    socket_handle,
                    &mut sockets,
                    &mut socket_set,
                    &mut connections,
                );
            }

            // Ensure every loop iteration yields to the runtime. When egress
            // capacity is available OR when `poll_delay` returns ZERO ("re-poll
            // now"), this loop otherwise takes no `.await`, so under an active
            // flow it busy-spins. Because `handle_socket` and `handle_packet`
            // are arms of one `tokio::select!` future, a never-yielding
            // `handle_socket` never returns control to the sibling SYN-accept
            // arm: one core pins flat at 100% and new inbound connections are
            // starved (observed as connect timeouts with no SYN-ACK). A
            // cooperative `yield_now()` keeps the re-poll just as prompt while
            // letting `handle_packet` make progress.
            //
            // With nothing scheduled (`poll_delay` is `None`: no socket has a
            // timer or data due) the loop parks until something calls
            // `notify_one`: a new packet, a new socket, or a stream reading,
            // writing, shutting down, dropping or aborting. `Notify` keeps
            // that permit when no one is waiting yet, so a wake between the
            // poll and the park is not lost. Upstream re-polled every 5 ms
            // here, about 200 wakeups a second on an idle phone; IDLE_PARK is
            // only a backstop.
            if iface_ingress_tx_avail.load(Ordering::Acquire) || device.syn_pending() {
                tokio::task::yield_now().await;
            } else {
                let mut next_duration = iface
                    .poll_delay(before_poll, &socket_set)
                    .unwrap_or(IDLE_PARK);
                if let Some(until) = next_deadline {
                    next_duration = next_duration.min(until - before_poll);
                }
                if next_duration != Duration::ZERO {
                    let _ = tokio::time::timeout(
                        tokio::time::Duration::from(next_duration),
                        notify.notified(),
                    )
                    .await;
                } else {
                    tokio::task::yield_now().await;
                }
            }
        }
    }
}

pub struct TcpListener {
    stream_rx: UnboundedReceiver<TcpStream>,
}

impl TcpListener {
    pub(super) fn new(
        tcp_rx: Receiver<AnyIpPktFrame>,
        stack_tx: Sender<AnyIpPktFrame>,
        mtu: usize,
        tcp_recv_buffer_size: u32,
        tcp_send_buffer_size: u32,
    ) -> std::io::Result<(Runner, Self)> {
        let (mut device, iface_ingress_tx, iface_ingress_tx_avail) =
            VirtualDevice::new(stack_tx, mtu);
        let iface = Self::create_interface(&mut device)?;

        let (stream_tx, stream_rx) = unbounded_channel();

        let runner = TcpListenerRunner::create(
            device,
            iface,
            iface_ingress_tx,
            iface_ingress_tx_avail,
            tcp_rx,
            stream_tx,
            HashMap::new(),
            tcp_recv_buffer_size,
            tcp_send_buffer_size,
        );

        Ok((runner, Self { stream_rx }))
    }

    fn create_interface<D>(device: &mut D) -> std::io::Result<Interface>
    where
        D: Device + ?Sized,
    {
        let mut iface_config = InterfaceConfig::new(HardwareAddress::Ip);
        iface_config.random_seed = rand::random();
        let mut iface = Interface::new(iface_config, device, Instant::now());
        iface.update_ip_addrs(|ip_addrs| {
            ip_addrs
                .push(IpCidr::new(IpAddress::v4(0, 0, 0, 1), 0))
                .expect("iface IPv4");
            ip_addrs
                .push(IpCidr::new(IpAddress::v6(0, 0, 0, 0, 0, 0, 0, 1), 0))
                .expect("iface IPv6");
        });
        iface
            .routes_mut()
            .add_default_ipv4_route(Ipv4Address::new(0, 0, 0, 1))
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::AddrNotAvailable, e))?;
        iface
            .routes_mut()
            .add_default_ipv6_route(Ipv6Address::new(0, 0, 0, 0, 0, 0, 0, 1))
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::AddrNotAvailable, e))?;
        iface.set_any_ip(true);
        Ok(iface)
    }
}

impl Stream for TcpListener {
    type Item = (TcpStream, SocketAddr, SocketAddr);

    fn poll_next(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        self.stream_rx.poll_recv(cx).map(|stream| {
            stream.map(|stream| {
                let local_addr = *stream.local_addr();
                let remote_addr: SocketAddr = *stream.remote_addr();
                (stream, local_addr, remote_addr)
            })
        })
    }
}

pub struct TcpStream {
    src_addr: SocketAddr,
    dst_addr: SocketAddr,
    notify: SharedNotify,
    control: SharedControl,
}

impl Drop for TcpStream {
    fn drop(&mut self) {
        let mut control = self.control.lock();

        if matches!(control.recv_state, TcpSocketState::Normal) {
            control.recv_state = TcpSocketState::Close;
        }

        if matches!(control.send_state, TcpSocketState::Normal) {
            control.send_state = TcpSocketState::Close;
        }
        control.dropped = true;

        self.notify.notify_one();
    }
}

impl TcpStream {
    pub fn local_addr(&self) -> &SocketAddr {
        &self.src_addr
    }

    pub fn remote_addr(&self) -> &SocketAddr {
        &self.dst_addr
    }

    /// Resets the connection: the app gets a RST instead of the FIN that
    /// dropping the stream sends after what was written, so it sees the
    /// connection fail rather than end (a response that ends with the
    /// connection is not taken as whole). Unsent bytes are discarded, reads
    /// return EOF and writes fail from then on.
    pub fn abort(&self) {
        abort_control(&self.control, &self.notify);
    }

    /// A handle that resets this connection ([`TcpStream::abort`]) from
    /// wherever the stream itself went, such as into a wrapper.
    pub fn abort_handle(&self) -> TcpAbortHandle {
        TcpAbortHandle {
            notify: self.notify.clone(),
            control: self.control.clone(),
        }
    }
}

/// Resets the connection of a [`TcpStream`]; see [`TcpStream::abort`].
#[derive(Clone)]
pub struct TcpAbortHandle {
    notify: SharedNotify,
    control: SharedControl,
}

impl TcpAbortHandle {
    pub fn abort(&self) {
        abort_control(&self.control, &self.notify);
    }
}

fn abort_control(control: &SharedControl, notify: &SharedNotify) {
    control.lock().abort = true;
    notify.notify_one();
}

impl AsyncRead for TcpStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let mut control = self.control.lock();

        // Read from buffer
        if control.recv_buffer.is_empty() {
            // If socket is already closed / half closed, just return EOF directly.
            if matches!(control.recv_state, TcpSocketState::Closed) {
                return Ok(()).into();
            }

            // Nothing could be read. Wait for notify.
            if let Some(old_waker) = control.recv_waker.replace(cx.waker().clone()) {
                if !old_waker.will_wake(cx.waker()) {
                    old_waker.wake();
                }
            }

            return Poll::Pending;
        }

        let recv_buf = buf.initialize_unfilled();
        let n = control.recv_buffer.dequeue_slice(recv_buf);
        buf.advance(n);

        if n > 0 {
            self.notify.notify_one();
        }

        Ok(()).into()
    }
}

impl AsyncWrite for TcpStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let mut control = self.control.lock();

        // If state == Close | Closing | Closed, the TCP stream WR half is closed.
        if !matches!(control.send_state, TcpSocketState::Normal) {
            return Err(std::io::ErrorKind::BrokenPipe.into()).into();
        }

        // Write to buffer

        if control.send_buffer.is_full() {
            if let Some(old_waker) = control.send_waker.replace(cx.waker().clone()) {
                if !old_waker.will_wake(cx.waker()) {
                    old_waker.wake();
                }
            }

            return Poll::Pending;
        }

        let n = control.send_buffer.enqueue_slice(buf);

        if n > 0 {
            self.notify.notify_one();
        }

        Ok(n).into()
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Ok(()).into()
    }

    /// Completes once every byte written is in the smoltcp socket and the
    /// FIN is queued behind it, like `shutdown(SHUT_WR)` on an OS socket.
    ///
    /// It used to wait for the socket to reach CLOSED, which for a
    /// connection the tunnel closes first means the peer's FIN plus all of
    /// TIME-WAIT: every relay of a short connection (its outbound, TLS state
    /// and buffers) stayed alive for seconds after both sides were done.
    /// smoltcp still sends the queued bytes and the FIN after the stream is
    /// dropped.
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let mut control = self.control.lock();

        if matches!(
            control.send_state,
            TcpSocketState::Closing | TcpSocketState::Closed
        ) {
            return Ok(()).into();
        }

        // SHUT_WR
        if matches!(control.send_state, TcpSocketState::Normal) {
            control.send_state = TcpSocketState::Close;
        }

        if let Some(old_waker) = control.send_waker.replace(cx.waker().clone()) {
            if !old_waker.will_wake(cx.waker()) {
                old_waker.wake();
            }
        }

        self.notify.notify_one();

        Poll::Pending
    }
}

#[cfg(test)]
mod tests {
    use std::{
        net::{Ipv4Addr, SocketAddr},
        pin::Pin,
        task::Poll,
        time::Duration as StdDuration,
    };

    use etherparse::{PacketBuilder, SlicedPacket, TransportSlice};
    use futures::{SinkExt, StreamExt};
    use tokio::io::{AsyncRead, ReadBuf};

    use super::{TcpListener, TcpStream};
    use crate::{Stack, StackBuilder};

    const APP: [u8; 4] = [10, 0, 0, 2];
    const SERVER: [u8; 4] = [10, 0, 0, 80];
    const SERVER_PORT: u16 = 8443;
    const WAIT: StdDuration = StdDuration::from_secs(5);

    fn app(port: u16) -> SocketAddr {
        SocketAddr::from((Ipv4Addr::from(APP), port))
    }

    fn server() -> SocketAddr {
        SocketAddr::from((Ipv4Addr::from(SERVER), SERVER_PORT))
    }

    /// A stack passing TCP with `window` bytes per socket buffer, its
    /// runner spawned.
    fn start(window: u32) -> (Stack, TcpListener) {
        let (stack, runner, _udp, listener) = StackBuilder::default()
            .enable_tcp(true)
            .tcp_recv_buffer_size(window)
            .tcp_send_buffer_size(window)
            .build()
            .unwrap();
        tokio::spawn(runner.unwrap());
        (stack, listener.unwrap())
    }

    /// A segment from the app's `port` to the server; `flags` holds `S`,
    /// `A` (with `ack`), `R` and `F`.
    fn tcp(port: u16, seq: u32, ack: u32, flags: &str, payload: &[u8]) -> Vec<u8> {
        let mut builder = PacketBuilder::ipv4(APP, SERVER, 64).tcp(port, SERVER_PORT, seq, 65535);
        if flags.contains('S') {
            builder = builder.syn();
        }
        if flags.contains('A') {
            builder = builder.ack(ack);
        }
        if flags.contains('R') {
            builder = builder.rst();
        }
        if flags.contains('F') {
            builder = builder.fin();
        }
        let mut packet = Vec::new();
        builder.write(&mut packet, payload).unwrap();
        packet
    }

    /// A segment the stack sent the app.
    #[derive(Debug)]
    struct Seg {
        syn: bool,
        ack: bool,
        rst: bool,
        fin: bool,
        seq: u32,
        ack_number: u32,
    }

    /// The next segment the stack sends the app, with the app's port.
    async fn any_segment(stack: &mut Stack) -> (u16, Seg) {
        loop {
            let frame = tokio::time::timeout(WAIT, stack.next())
                .await
                .expect("the stack sent nothing")
                .expect("the stack ended")
                .unwrap();
            let Ok(sliced) = SlicedPacket::from_ip(&frame) else {
                continue;
            };
            if let Some(TransportSlice::Tcp(tcp)) = &sliced.transport {
                return (
                    tcp.destination_port(),
                    Seg {
                        syn: tcp.syn(),
                        ack: tcp.ack(),
                        rst: tcp.rst(),
                        fin: tcp.fin(),
                        seq: tcp.sequence_number(),
                        ack_number: tcp.acknowledgment_number(),
                    },
                );
            }
        }
    }

    /// The next segment the stack sends the app's `port`.
    async fn segment(stack: &mut Stack, port: u16) -> Seg {
        loop {
            let (to, seg) = any_segment(stack).await;
            if to == port {
                return seg;
            }
        }
    }

    async fn segment_where(stack: &mut Stack, port: u16, pick: impl Fn(&Seg) -> bool) -> Seg {
        loop {
            let seg = segment(stack, port).await;
            if pick(&seg) {
                return seg;
            }
        }
    }

    /// Every segment the stack sends the app within `quiet`, with the app's
    /// port.
    async fn all_segments_within(stack: &mut Stack, quiet: StdDuration) -> Vec<(u16, Seg)> {
        let mut segments = Vec::new();
        let _ = tokio::time::timeout(quiet, async {
            loop {
                segments.push(any_segment(stack).await);
            }
        })
        .await;
        segments
    }

    /// Every segment the stack sends the app's `port` within `quiet`.
    async fn segments_within(stack: &mut Stack, port: u16, quiet: StdDuration) -> Vec<Seg> {
        let mut segments = Vec::new();
        let _ = tokio::time::timeout(quiet, async {
            loop {
                segments.push(segment(stack, port).await);
            }
        })
        .await;
        segments
    }

    async fn accept(listener: &mut TcpListener) -> (TcpStream, SocketAddr, SocketAddr) {
        tokio::time::timeout(WAIT, listener.next())
            .await
            .expect("no connection came")
            .expect("the listener ended")
    }

    async fn no_connection(listener: &mut TcpListener, quiet: StdDuration) -> bool {
        tokio::time::timeout(quiet, listener.next()).await.is_err()
    }

    /// What one read of `stream` returns; empty at EOF.
    async fn read(stream: &mut TcpStream) -> Vec<u8> {
        let mut buf = vec![0u8; 4096];
        let n = tokio::time::timeout(
            WAIT,
            std::future::poll_fn(|cx| {
                let mut read = ReadBuf::new(&mut buf);
                match Pin::new(&mut *stream).poll_read(cx, &mut read) {
                    Poll::Ready(result) => Poll::Ready(result.map(|()| read.filled().len())),
                    Poll::Pending => Poll::Pending,
                }
            }),
        )
        .await
        .expect("the read stalled")
        .unwrap();
        buf.truncate(n);
        buf
    }

    /// Opens a connection from the app's `port` with `isn`: SYN, the stack's
    /// SYN-ACK, ACK. Returns the stack's ISN.
    async fn handshake(stack: &mut Stack, port: u16, isn: u32) -> u32 {
        stack.send(tcp(port, isn, 0, "S", &[])).await.unwrap();
        let syn_ack = segment_where(stack, port, |seg| seg.syn && seg.ack).await;
        assert_eq!(syn_ack.ack_number, isn.wrapping_add(1));
        stack
            .send(tcp(
                port,
                isn.wrapping_add(1),
                syn_ack.seq.wrapping_add(1),
                "A",
                &[],
            ))
            .await
            .unwrap();
        syn_ack.seq
    }

    // A SYN the app sends again before the SYN-ACK came reaches the socket
    // of the first one: one connection, one ISN, and no socket left in
    // LISTEN to take the next connection to the same destination.
    #[tokio::test]
    async fn a_retransmitted_syn_opens_one_connection() {
        let (mut stack, mut listener) = start(64 * 1024);
        stack.send(tcp(40000, 100, 0, "S", &[])).await.unwrap();
        stack.send(tcp(40000, 100, 0, "S", &[])).await.unwrap();

        let syn_ack = segment_where(&mut stack, 40000, |seg| seg.syn && seg.ack).await;
        let (_first, local, remote) = accept(&mut listener).await;
        assert_eq!((local, remote), (app(40000), server()));
        assert!(
            no_connection(&mut listener, StdDuration::from_millis(300)).await,
            "a retransmitted SYN opened a second connection"
        );
        for seg in segments_within(&mut stack, 40000, StdDuration::from_millis(200)).await {
            assert!(!seg.syn || seg.seq == syn_ack.seq, "two ISNs: {seg:?}");
        }

        // The next connection to the same destination gets its own socket,
        // and its bytes come out of its own stream.
        let isn = handshake(&mut stack, 40001, 500).await;
        let (mut second, local, _) = accept(&mut listener).await;
        assert_eq!(local, app(40001));
        stack
            .send(tcp(40001, 501, isn.wrapping_add(1), "A", b"second"))
            .await
            .unwrap();
        assert_eq!(read(&mut second).await, b"second");
    }

    // A retransmitted SYN never reaches the socket made for another
    // connection to the same destination. Here that socket sits in a lower
    // slot than the first connection's, so smoltcp, which hands a SYN to the
    // first socket in LISTEN, would give it the retransmitted SYN: a second
    // connection on the first one's endpoints with another ISN, and a RST
    // for the other connection's own SYN.
    #[tokio::test]
    async fn a_retransmitted_syn_is_not_taken_by_another_connection() {
        let (mut stack, mut listener) = start(64 * 1024);
        // A connection in the lowest slot, kept until the next one has the
        // slot after it.
        let isn = handshake(&mut stack, 40050, 100).await;
        let (mut lowest, local, _) = accept(&mut listener).await;
        assert_eq!(local, app(40050));

        stack.send(tcp(40051, 1000, 0, "S", &[])).await.unwrap();
        let syn_ack = segment_where(&mut stack, 40051, |seg| seg.syn && seg.ack).await;
        let (mut first, local, _) = accept(&mut listener).await;
        assert_eq!(local, app(40051));

        // The app resets the connection in the lowest slot: its socket goes,
        // and the slot is the one the next socket gets.
        stack
            .send(tcp(40050, 101, isn.wrapping_add(1), "RA", &[]))
            .await
            .unwrap();
        assert!(read(&mut lowest).await.is_empty(), "the stream ends");

        // The first connection's SYN again, together with another
        // connection's SYN to the same destination.
        stack.send(tcp(40051, 1000, 0, "S", &[])).await.unwrap();
        stack.send(tcp(40052, 2000, 0, "S", &[])).await.unwrap();

        let segments = all_segments_within(&mut stack, StdDuration::from_millis(500)).await;
        let mut second_syn_ack = None;
        for (port, seg) in &segments {
            assert!(!seg.rst, "a RST to {port}: {seg:?}");
            match *port {
                40051 => assert!(!seg.syn || seg.seq == syn_ack.seq, "two ISNs: {seg:?}"),
                40052 if seg.syn && seg.ack => {
                    assert_eq!(seg.ack_number, 2001);
                    second_syn_ack = Some(seg.seq);
                }
                _ => {}
            }
        }
        let second_isn = second_syn_ack.expect("no SYN-ACK for the second connection");

        let (mut second, local, remote) = accept(&mut listener).await;
        assert_eq!((local, remote), (app(40052), server()));
        assert!(
            no_connection(&mut listener, StdDuration::from_millis(300)).await,
            "a retransmitted SYN opened a second connection"
        );

        // Both handshakes complete, each connection's bytes come out of its
        // own stream, and neither is reset.
        stack
            .send(tcp(40051, 1001, syn_ack.seq.wrapping_add(1), "A", b"first"))
            .await
            .unwrap();
        stack
            .send(tcp(40052, 2001, second_isn.wrapping_add(1), "A", b"second"))
            .await
            .unwrap();
        assert_eq!(read(&mut first).await, b"first");
        assert_eq!(read(&mut second).await, b"second");
        for (port, seg) in all_segments_within(&mut stack, StdDuration::from_millis(200)).await {
            assert!(!seg.rst, "a RST to {port}: {seg:?}");
        }
    }

    // A SYN smoltcp refuses (here: a bad checksum) leaves its socket in
    // LISTEN. The next connection to that destination still comes out with
    // its own endpoints and bytes, whichever socket took its SYN.
    #[tokio::test]
    async fn a_refused_syn_does_not_take_the_next_connection() {
        let (mut stack, mut listener) = start(64 * 1024);
        let mut bad = tcp(40030, 100, 0, "S", &[]);
        bad[36] ^= 0xff;
        stack.send(bad).await.unwrap();

        let isn = handshake(&mut stack, 40031, 300).await;
        let (mut stream, local, _) = accept(&mut listener).await;
        assert_eq!(local, app(40031));
        stack
            .send(tcp(40031, 301, isn.wrapping_add(1), "A", b"mine"))
            .await
            .unwrap();
        assert_eq!(read(&mut stream).await, b"mine");
        assert!(no_connection(&mut listener, StdDuration::from_millis(300)).await);
    }

    // A RST in SYN-RECEIVED ends the stream handed out for it; the socket,
    // which smoltcp put back into LISTEN, does not take the next SYN.
    #[tokio::test]
    async fn a_connection_reset_in_syn_received_ends_its_stream() {
        let (mut stack, mut listener) = start(64 * 1024);
        stack.send(tcp(40010, 100, 0, "S", &[])).await.unwrap();
        let syn_ack = segment_where(&mut stack, 40010, |seg| seg.syn && seg.ack).await;
        let (mut first, local, _) = accept(&mut listener).await;
        assert_eq!(local, app(40010));
        stack
            .send(tcp(40010, 101, syn_ack.seq.wrapping_add(1), "RA", &[]))
            .await
            .unwrap();
        assert!(read(&mut first).await.is_empty(), "the stream ends");

        let isn = handshake(&mut stack, 40011, 200).await;
        let (mut second, local, _) = accept(&mut listener).await;
        assert_eq!(local, app(40011));
        stack
            .send(tcp(40011, 201, isn.wrapping_add(1), "A", b"next"))
            .await
            .unwrap();
        assert_eq!(read(&mut second).await, b"next");
    }

    // An aborted stream resets the connection: the app gets a RST.
    #[tokio::test]
    async fn an_aborted_stream_resets_the_connection() {
        let (mut stack, mut listener) = start(64 * 1024);
        handshake(&mut stack, 40020, 100).await;
        let (stream, _, _) = accept(&mut listener).await;
        stream.abort();
        segment_where(&mut stack, 40020, |seg| seg.rst).await;
        drop(stream);
    }

    // After the stream is dropped, what the app still sends is taken and
    // discarded: the window stays open and the app's FIN is acknowledged,
    // instead of the socket sitting on a zero window.
    #[tokio::test]
    async fn a_socket_without_its_stream_keeps_taking_data() {
        let window = 4096;
        let (mut stack, mut listener) = start(window);
        let isn = handshake(&mut stack, 40040, 1000).await;
        let (stream, _, _) = accept(&mut listener).await;
        drop(stream);
        // The stack sends its FIN once the stream is gone; the app's
        // segments below acknowledge it.
        let fin = segment_where(&mut stack, 40040, |seg| seg.fin).await;
        assert_eq!(fin.seq, isn.wrapping_add(1));

        // Eight times what the socket and the stream's buffer hold.
        let chunk = [7u8; 1000];
        let mut seq: u32 = 1001;
        // Our FIN (sent once the stream is gone) takes one sequence number.
        let ack = isn.wrapping_add(2);
        for _ in 0..(8 * 2 * window as usize / chunk.len()) {
            stack.send(tcp(40040, seq, ack, "A", &chunk)).await.unwrap();
            let next = seq.wrapping_add(chunk.len() as u32);
            segment_where(&mut stack, 40040, |seg| seg.ack && seg.ack_number == next).await;
            seq = next;
        }
        stack.send(tcp(40040, seq, ack, "AF", &[])).await.unwrap();
        let fin_end = seq.wrapping_add(1);
        segment_where(&mut stack, 40040, |seg| {
            seg.ack && seg.ack_number == fin_end
        })
        .await;
    }
}
