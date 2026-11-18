//! SOCKS5 `UDP ASSOCIATE` (RFC 1928 §7): a relay socket on the listener's
//! address, one outbound UDP flow per destination the client sends to.
//!
//! The association lives as long as the client's TCP connection. Only
//! datagrams from the client's own IP are relayed, and the first source port
//! seen is the only one answered. Replies are sent back with the destination
//! the client asked for (a name stays a name), which is what a [`UdpFlow`]
//! attributes them to. Fragments are dropped.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use engine_outbound::{TargetAddr, UdpFlow, MAX_DATAGRAM};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::mpsc;
use tokio::task::JoinSet;

use crate::{close_gracefully, socks5, ClientAddrs, ClientConnector, MixedStats};

/// Destinations one association may have open at once.
const MAX_FLOWS: usize = 64;
/// Datagrams queued for a flow that is still opening or sending; further
/// ones are dropped, as UDP would.
const FLOW_QUEUE: usize = 64;
/// Largest SOCKS5 UDP header: RSV, FRAG, ATYP, a 255-byte name, its length
/// byte and the port.
const MAX_HEADER: usize = 3 + 1 + 1 + 255 + 2;

pub(crate) async fn associate(
    mut client: TcpStream,
    addrs: ClientAddrs,
    connector: Arc<dyn ClientConnector>,
    connect_timeout: Duration,
    stats: Arc<MixedStats>,
) {
    let socket = match UdpSocket::bind(SocketAddr::new(addrs.local.ip(), 0)).await {
        Ok(socket) => Arc::new(socket),
        Err(_) => {
            let _ = client
                .write_all(&socks5::reply(socks5::REP_GENERAL_FAILURE))
                .await;
            close_gracefully(client).await;
            return;
        }
    };
    let Ok(bound) = socket.local_addr() else {
        return;
    };
    if client.write_all(&socks5::bound_reply(bound)).await.is_err() {
        return;
    }
    stats.udp_associations.fetch_add(1, Ordering::Relaxed);

    let mut flows: HashMap<TargetAddr, mpsc::Sender<Vec<u8>>> = HashMap::new();
    let mut tasks = JoinSet::new();
    let mut client_udp: Option<SocketAddr> = None;
    let mut buf = vec![0u8; MAX_DATAGRAM + MAX_HEADER];
    let mut control = [0u8; 64];
    loop {
        tokio::select! {
            read = client.read(&mut control) => match read {
                // Nothing is expected on the control connection; its end
                // ends the association.
                Ok(0) | Err(_) => break,
                Ok(_) => {}
            },
            received = socket.recv_from(&mut buf) => {
                let Ok((n, from)) = received else { break };
                if from.ip() != addrs.peer.ip() {
                    continue;
                }
                match client_udp {
                    None => client_udp = Some(from),
                    Some(known) if known != from => continue,
                    Some(_) => {}
                }
                let Some((target, payload)) = socks5::parse_udp(&buf[..n]) else {
                    continue;
                };
                stats.bytes_up.fetch_add(payload.len() as u64, Ordering::Relaxed);
                let existing = flows.get(&target).filter(|sender| !sender.is_closed()).cloned();
                let sender = match existing {
                    Some(sender) => sender,
                    None => {
                        if flows.len() >= MAX_FLOWS {
                            flows.retain(|_, sender| !sender.is_closed());
                            if flows.len() >= MAX_FLOWS {
                                continue;
                            }
                        }
                        let (tx, rx) = mpsc::channel(FLOW_QUEUE);
                        tasks.spawn(flow(
                            connector.clone(),
                            addrs,
                            target.clone(),
                            rx,
                            socket.clone(),
                            from,
                            connect_timeout,
                            stats.clone(),
                        ));
                        flows.insert(target, tx.clone());
                        tx
                    }
                };
                let _ = sender.try_send(payload.to_vec());
            }
        }
    }
    // Dropping the senders ends each flow's send side; the JoinSet aborts the
    // rest when it goes out of scope.
    drop(flows);
    tasks.abort_all();
}

#[allow(clippy::too_many_arguments)]
async fn flow(
    connector: Arc<dyn ClientConnector>,
    addrs: ClientAddrs,
    target: TargetAddr,
    mut queue: mpsc::Receiver<Vec<u8>>,
    socket: Arc<UdpSocket>,
    client_udp: SocketAddr,
    connect_timeout: Duration,
    stats: Arc<MixedStats>,
) {
    let opened =
        tokio::time::timeout(connect_timeout, connector.open_client_udp(addrs, &target)).await;
    let UdpFlow { mut send, mut recv } = match opened {
        Ok(Ok(flow)) => flow,
        Ok(Err(_)) | Err(_) => {
            stats.connect_failed.fetch_add(1, Ordering::Relaxed);
            return;
        }
    };
    let header = socks5::udp_header(&target);
    let replies = async {
        while let Ok(payload) = recv.recv().await {
            let mut out = Vec::with_capacity(header.len() + payload.len());
            out.extend_from_slice(&header);
            out.extend_from_slice(&payload);
            if socket.send_to(&out, client_udp).await.is_err() {
                break;
            }
            stats
                .bytes_down
                .fetch_add(payload.len() as u64, Ordering::Relaxed);
        }
    };
    let sends = async {
        while let Some(payload) = queue.recv().await {
            if send.send(&payload).await.is_err() {
                break;
            }
        }
    };
    tokio::select! {
        _ = replies => {}
        _ = sends => {}
    }
}
