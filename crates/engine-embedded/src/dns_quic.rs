//! DNS over QUIC (RFC 9250).
//!
//! A `quic://` server is reached through the outbound's UDP relay (the direct
//! outbound's own socket for `via: direct`): the QUIC handshake runs on that
//! flow ([`transport_quic::QuicConnector::connect_over`]), ALPN `doq`, with
//! the certificate always checked. Each query is one bidirectional stream:
//! the message behind a two-byte length with id 0, the stream finished, and
//! the answer read to the end of the stream. The connection is kept per
//! server and outbound and carries the following queries at once; it has no
//! keep-alive and closes after 30 s without queries.

use std::collections::HashMap;
use std::io;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use engine_outbound::{TargetAddr, TcpOutbound};
use tokio::time::Instant;
use transport_quic::{QuicConnection, QuicConnector};

use crate::dns::OutboundFailure;
use crate::dns_cache::PoolKey;

/// Connections kept at most, over every server and outbound.
pub const MAX_CONNECTIONS: usize = 16;
/// A connection unused for this long is not reused: it is about to reach the
/// idle timeout, or the server has closed it.
pub const MAX_IDLE: Duration = Duration::from_secs(20);
/// Longest DNS message, behind its two-byte length.
const MAX_ANSWER: usize = 2 + 65_535;

/// DNS over QUIC connections by server and outbound.
#[derive(Default)]
pub struct QuicPool {
    connections: HashMap<PoolKey, (Arc<QuicConnection>, std::time::Instant)>,
}

impl QuicPool {
    /// The live connection kept for `key`, marked used.
    fn get(&mut self, key: PoolKey, now: std::time::Instant) -> Option<Arc<QuicConnection>> {
        let (connection, used) = self.connections.get_mut(&key)?;
        if now.saturating_duration_since(*used) >= MAX_IDLE
            || connection.connection.close_reason().is_some()
        {
            self.connections.remove(&key);
            return None;
        }
        *used = now;
        Some(connection.clone())
    }

    fn put(&mut self, key: PoolKey, connection: Arc<QuicConnection>, now: std::time::Instant) {
        self.connections.retain(|_, (kept, used)| {
            now.saturating_duration_since(*used) < MAX_IDLE
                && kept.connection.close_reason().is_none()
        });
        if self.connections.len() >= MAX_CONNECTIONS && !self.connections.contains_key(&key) {
            return;
        }
        self.connections.insert(key, (connection, now));
    }

    fn forget(&mut self, key: PoolKey, connection: &Arc<QuicConnection>) {
        if self
            .connections
            .get(&key)
            .is_some_and(|(kept, _)| Arc::ptr_eq(kept, connection))
        {
            self.connections.remove(&key);
        }
    }

    /// Connections kept now.
    pub fn len(&self) -> usize {
        self.connections.len()
    }

    pub fn is_empty(&self) -> bool {
        self.connections.is_empty()
    }
}

/// One query to the DNS over QUIC server `target` through `outbound`. A kept
/// connection is tried first (for at most half the time left); a new one is
/// dialed when there is none or it failed, and kept for later queries.
pub async fn exchange(
    connector: &QuicConnector,
    target: &TargetAddr,
    outbound: &dyn TcpOutbound,
    query: &[u8],
    deadline: Instant,
    pool: Option<(&Mutex<QuicPool>, PoolKey)>,
) -> Result<Vec<u8>, OutboundFailure> {
    if let Some((pool, key)) = pool {
        let kept = lock(pool).get(key, std::time::Instant::now());
        if let Some(connection) = kept {
            let now = Instant::now();
            let budget = now + deadline.saturating_duration_since(now) / 2;
            match tokio::time::timeout_at(budget, ask(&connection, query)).await {
                Ok(Ok(response)) => return Ok(response),
                _ => lock(pool).forget(key, &connection),
            }
        }
    }
    let dial = async {
        let flow = outbound
            .open_udp(target)
            .await
            .map_err(|err| OutboundFailure::connect(&err))?;
        let left = deadline.saturating_duration_since(Instant::now());
        connector
            .connect_over(flow, left)
            .await
            .map_err(|err| OutboundFailure::connect(&err))
    };
    let connection = match tokio::time::timeout_at(deadline, dial).await {
        Ok(Ok(connection)) => Arc::new(connection),
        Ok(Err(failure)) => return Err(failure),
        Err(_) => return Err(OutboundFailure::ConnectTimeout),
    };
    let result = match tokio::time::timeout_at(deadline, ask(&connection, query)).await {
        Ok(Ok(response)) => Ok(response),
        Ok(Err(err)) => Err(OutboundFailure::reply(&err)),
        Err(_) => Err(OutboundFailure::ReplyTimeout),
    };
    if let Some((pool, key)) = pool {
        if result.is_ok() {
            lock(pool).put(key, connection, std::time::Instant::now());
        }
    }
    result
}

fn lock(pool: &Mutex<QuicPool>) -> std::sync::MutexGuard<'_, QuicPool> {
    pool.lock().unwrap_or_else(|e| e.into_inner())
}

/// One query on its own stream of `connection`; the answer carries the
/// query's id.
async fn ask(connection: &QuicConnection, query: &[u8]) -> io::Result<Vec<u8>> {
    let (mut send, mut recv) = connection
        .connection
        .open_bi()
        .await
        .map_err(transport_quic::quic_error)?;
    let mut message = Vec::with_capacity(2 + query.len());
    message.extend_from_slice(&(query.len() as u16).to_be_bytes());
    message.extend_from_slice(query);
    // The id is 0 on the wire (RFC 9250 §4.2.1).
    message[2..4].copy_from_slice(&[0, 0]);
    send.write_all(&message)
        .await
        .map_err(transport_quic::quic_error)?;
    send.finish().map_err(transport_quic::quic_error)?;
    let data = recv.read_to_end(MAX_ANSWER).await.map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "DNS over QUIC answer was not read",
        )
    })?;
    answer_of(&data, query)
}

/// The answer in a stream's data: one message behind its length, whose id
/// is 0, given back with the query's id.
fn answer_of(data: &[u8], query: &[u8]) -> io::Result<Vec<u8>> {
    let invalid = |message: &'static str| io::Error::new(io::ErrorKind::InvalidData, message);
    let length = data
        .get(..2)
        .map(|length| usize::from(u16::from_be_bytes([length[0], length[1]])))
        .ok_or_else(|| invalid("DNS over QUIC answer is too short"))?;
    let mut response = data[2..].to_vec();
    if response.len() != length || response.len() < 12 {
        return Err(invalid("DNS over QUIC answer has the wrong length"));
    }
    if response[..2] != [0, 0] {
        return Err(invalid("DNS over QUIC answer id is not 0"));
    }
    response[..2].copy_from_slice(&query[..2]);
    if !crate::dns::answers(query, &response) {
        return Err(invalid("DNS over QUIC answer does not match the query"));
    }
    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use rcgen::{CertificateParams, KeyPair};
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    use transport_quic::quinn;

    /// A DNS over QUIC server answering every query with 192.0.2.1; the
    /// counter is the connections it accepted.
    fn doq_server() -> (std::net::SocketAddr, Arc<AtomicUsize>) {
        let key = KeyPair::generate().unwrap();
        let cert = CertificateParams::new(vec!["doq.test".to_string()])
            .unwrap()
            .self_signed(&key)
            .unwrap();
        let mut crypto = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![CertificateDer::from(cert.der().to_vec())],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())),
        )
        .unwrap();
        crypto.alpn_protocols = vec![b"doq".to_vec()];
        let config = quinn::ServerConfig::with_crypto(Arc::new(
            quinn::crypto::rustls::QuicServerConfig::try_from(crypto).unwrap(),
        ));
        let endpoint = quinn::Endpoint::server(config, "127.0.0.1:0".parse().unwrap()).unwrap();
        let address = endpoint.local_addr().unwrap();
        let connections = Arc::new(AtomicUsize::new(0));
        let counter = connections.clone();
        tokio::spawn(async move {
            while let Some(incoming) = endpoint.accept().await {
                let counter = counter.clone();
                tokio::spawn(async move {
                    let Ok(connection) = incoming.await else {
                        return;
                    };
                    counter.fetch_add(1, Ordering::SeqCst);
                    while let Ok((mut send, mut recv)) = connection.accept_bi().await {
                        tokio::spawn(async move {
                            let Ok(data) = recv.read_to_end(MAX_ANSWER).await else {
                                return;
                            };
                            // Id 0 on the wire, one message behind its length.
                            assert_eq!(&data[2..4], &[0, 0]);
                            assert_eq!(
                                usize::from(u16::from_be_bytes([data[0], data[1]])),
                                data.len() - 2
                            );
                            let mut answer = data[2..].to_vec();
                            answer[2] |= 0x80;
                            answer[3] = 0x80;
                            answer[7] = 1;
                            answer.extend_from_slice(&[
                                0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 192, 0, 2, 1,
                            ]);
                            let mut framed = (answer.len() as u16).to_be_bytes().to_vec();
                            framed.extend_from_slice(&answer);
                            let _ = send.write_all(&framed).await;
                            let _ = send.finish();
                        });
                    }
                });
            }
        });
        (address, connections)
    }

    #[tokio::test]
    async fn queries_share_one_connection_through_the_direct_outbound() {
        let (server, connections) = doq_server();
        // Only the test skips the certificate check: the server's is self-signed.
        let connector = QuicConnector::new(
            server.ip().to_string(),
            server.port(),
            &transport_tls::TlsSettings {
                server_name: "doq.test".to_string(),
                alpn: vec!["doq".to_string()],
                insecure: true,
                ..transport_tls::TlsSettings::default()
            },
            &["doq"],
            transport_quic::Congestion::Cubic,
        )
        .unwrap()
        .without_keep_alive()
        .unwrap();
        let direct = crate::direct::DirectOutbound::new(Arc::new(engine_outbound::TcpDialer));
        let pool = Mutex::new(QuicPool::default());
        let target = TargetAddr::Ip(server);
        for (id, name) in [(0x0101u16, "a.example"), (0x0202, "b.example")] {
            let query = crate::dns::query(id, name, crate::dns::TYPE_A).unwrap();
            let deadline = Instant::now() + Duration::from_secs(10);
            let response = exchange(
                &connector,
                &target,
                &direct,
                &query,
                deadline,
                Some((&pool, (0, 0))),
            )
            .await
            .unwrap();
            assert_eq!(&response[..2], &id.to_be_bytes());
            assert!(response.ends_with(&[192, 0, 2, 1]));
        }
        assert_eq!(
            connections.load(Ordering::SeqCst),
            1,
            "the connection was kept"
        );
        assert_eq!(pool.lock().unwrap().len(), 1);
    }

    #[test]
    fn answers_are_framed_and_take_the_query_id() {
        let query = crate::dns::query(0xbeef, "example.com", crate::dns::TYPE_A).unwrap();
        let mut answer = query.clone();
        answer[..2].copy_from_slice(&[0, 0]);
        answer[2] |= 0x80;
        let mut data = (answer.len() as u16).to_be_bytes().to_vec();
        data.extend_from_slice(&answer);
        let response = answer_of(&data, &query).unwrap();
        assert_eq!(&response[..2], &[0xbe, 0xef]);

        let mut short = data.clone();
        short.pop();
        assert!(answer_of(&short, &query).is_err());
        let mut wrong_id = data.clone();
        wrong_id[3] = 1;
        assert!(answer_of(&wrong_id, &query).is_err());
        let other = crate::dns::query(0xbeef, "example.org", crate::dns::TYPE_A).unwrap();
        assert!(answer_of(&data, &other).is_err());
    }
}
