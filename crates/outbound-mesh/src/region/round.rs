//! One measurement round over UDP (appendix D.4), feature `runtime`.
//!
//! Each border node gets its own socket, connected to its probe address,
//! so only datagrams from that address and port are read (D.3: the source
//! must be the probe's target). Each border node gets a fresh ephemeral
//! key, wiped when the round ends.

use std::collections::{BTreeMap, HashMap};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use ring::rand::{SecureRandom, SystemRandom};
use tokio::net::UdpSocket;
use tokio::sync::Semaphore;
use tokio::time::Instant;
use zeroize::Zeroizing;

use super::directory::{Border, Directory};
use super::measure::{border_median, region_result, BorderResult, RegionResult, PROBES_PER_BORDER};
use super::probe::{Prober, ANSWER_LEN, NONCE_LEN};

/// Gap between two probes to one border node (D.4 item 1).
pub const PROBE_GAP: Duration = Duration::from_millis(100);
/// Longest wait for one answer (D.4 item 2).
pub const ANSWER_TIMEOUT: Duration = Duration::from_millis(1000);
/// Border nodes probed at once (D.4 item 1).
pub const PARALLEL_BORDERS: usize = 16;
/// Longest random wait before a round (D.4 item 1).
pub const START_JITTER: Duration = Duration::from_secs(30);

/// The outcome of one round: each reachable region's result, and the
/// regions none of whose border nodes answered enough.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct RoundResult {
    pub regions: BTreeMap<String, RegionResult>,
    pub unreachable: Vec<String>,
}

impl RoundResult {
    /// The region RTTs as the enrolment's `latencies` and the history's
    /// round (D.4, D.5).
    pub fn latencies(&self) -> BTreeMap<String, f64> {
        self.regions
            .iter()
            .map(|(code, result)| (code.clone(), result.rtt_ms))
            .collect()
    }
}

/// A uniformly random duration in `[0, max]`.
pub fn jitter(max: Duration) -> Duration {
    let mut bytes = [0u8; 8];
    if SystemRandom::new().fill(&mut bytes).is_err() {
        return Duration::ZERO;
    }
    let millis = max.as_millis().min(u128::from(u64::MAX)) as u64;
    Duration::from_millis(u64::from_be_bytes(bytes) % millis.saturating_add(1))
}

/// Measures every region of `directory` once, without the start jitter
/// (the caller waits [`jitter`]`(START_JITTER)` first; `enroll` is run by
/// hand and does not). A region without border nodes is unreachable.
pub async fn measure(directory: &Directory) -> RoundResult {
    let permits = Arc::new(Semaphore::new(PARALLEL_BORDERS));
    let mut tasks = Vec::new();
    for (code, border) in directory.borders() {
        let permits = Arc::clone(&permits);
        let code = code.to_owned();
        let border = border.clone();
        tasks.push(tokio::spawn(async move {
            let _permit = permits.acquire_owned().await.ok();
            let samples = probe_border(&border).await;
            (
                code,
                BorderResult {
                    name: border.name.clone(),
                    median_ms: border_median(&samples),
                },
            )
        }));
    }
    let mut by_region: BTreeMap<String, Vec<BorderResult>> = directory
        .regions
        .iter()
        .map(|region| (region.code.clone(), Vec::new()))
        .collect();
    for task in tasks {
        if let Ok((code, result)) = task.await {
            by_region.entry(code).or_default().push(result);
        }
    }
    let mut out = RoundResult::default();
    for (code, borders) in by_region {
        match region_result(&borders) {
            Some(result) => {
                out.regions.insert(code, result);
            }
            None => out.unreachable.push(code),
        }
    }
    out
}

fn unspecified(target: &SocketAddr) -> SocketAddr {
    match target.ip() {
        IpAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
        IpAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
    }
}

/// The RTTs in milliseconds of the probes to one border node that got an
/// authentic answer in time; empty when the socket could not be opened.
async fn probe_border(border: &Border) -> Vec<f64> {
    let rng = SystemRandom::new();
    let mut secret = Zeroizing::new([0u8; 32]);
    if rng.fill(&mut secret[..]).is_err() {
        return Vec::new();
    }
    let Some(prober) = Prober::new(*secret, &border.key) else {
        return Vec::new();
    };
    let Ok(socket) = UdpSocket::bind(unspecified(&border.probe)).await else {
        return Vec::new();
    };
    if socket.connect(border.probe).await.is_err() {
        return Vec::new();
    }
    let mut sent: HashMap<([u8; NONCE_LEN], u32), Instant> = HashMap::new();
    let mut rtts = Vec::new();
    let mut buf = [0u8; ANSWER_LEN + 1];
    let mut next_send = Instant::now();
    let mut seq: u32 = 0;
    loop {
        let deadline = if (seq as usize) < PROBES_PER_BORDER {
            next_send
        } else {
            match sent.values().max() {
                Some(last) => *last + ANSWER_TIMEOUT,
                None => break,
            }
        };
        tokio::select! {
            _ = tokio::time::sleep_until(deadline) => {
                if (seq as usize) < PROBES_PER_BORDER {
                    let mut nonce = [0u8; NONCE_LEN];
                    if rng.fill(&mut nonce).is_err() {
                        break;
                    }
                    let request = prober.request(nonce, seq);
                    // A failed send counts as a lost probe.
                    let at = Instant::now();
                    if socket.send(&request).await.is_ok() {
                        sent.insert((nonce, seq), at);
                    }
                    seq += 1;
                    next_send = at + PROBE_GAP;
                } else {
                    break;
                }
            }
            received = socket.recv(&mut buf) => {
                let Ok(len) = received else { continue };
                let now = Instant::now();
                if let Some(key) = prober.check(&buf[..len]) {
                    if let Some(at) = sent.remove(&key) {
                        let rtt = now.saturating_duration_since(at);
                        if rtt <= ANSWER_TIMEOUT {
                            rtts.push(rtt.as_secs_f64() * 1000.0);
                        }
                    }
                }
            }
        }
        // Forget probes past their timeout so the final wait ends with
        // the last one that can still be answered.
        let now = Instant::now();
        sent.retain(|_, at| now.saturating_duration_since(*at) <= ANSWER_TIMEOUT);
        if seq as usize >= PROBES_PER_BORDER && sent.is_empty() {
            break;
        }
    }
    rtts
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::IpNet;
    use crate::region::directory::Region;
    use crate::region::probe::Responder;
    use x25519_dalek::{PublicKey, StaticSecret};

    async fn responder(private: [u8; 32], answer: bool, delay: Duration) -> SocketAddr {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = socket.local_addr().unwrap();
        tokio::spawn(async move {
            let mut responder = Responder::new(private, std::time::Instant::now());
            let mut buf = [0u8; 256];
            loop {
                let Ok((len, from)) = socket.recv_from(&mut buf).await else {
                    return;
                };
                if let Ok(reply) =
                    responder.handle(&buf[..len], from.ip(), std::time::Instant::now())
                {
                    if answer {
                        tokio::time::sleep(delay).await;
                        let _ = socket.send_to(&reply, from).await;
                    }
                }
            }
        });
        address
    }

    fn public(private: [u8; 32]) -> [u8; 32] {
        PublicKey::from(&StaticSecret::from(private)).to_bytes()
    }

    #[tokio::test]
    async fn a_round_measures_answering_regions_and_lists_silent_ones() {
        let key = [3u8; 32];
        let near = responder(key, true, Duration::ZERO).await;
        let silent = responder(key, false, Duration::ZERO).await;
        // A responder holding another key: its answers do not verify.
        let impostor = responder([4u8; 32], true, Duration::ZERO).await;
        let directory = Directory {
            preferred: None,
            regions: vec![
                Region {
                    code: "eu".into(),
                    subnet: IpNet::parse("10.130.0.0/16").unwrap(),
                    borders: vec![Border {
                        name: "near".into(),
                        probe: near,
                        key: public(key),
                    }],
                },
                Region {
                    code: "ap".into(),
                    subnet: IpNet::parse("10.131.0.0/16").unwrap(),
                    borders: vec![
                        Border {
                            name: "silent".into(),
                            probe: silent,
                            key: public(key),
                        },
                        Border {
                            name: "impostor".into(),
                            probe: impostor,
                            key: public(key),
                        },
                    ],
                },
                Region {
                    code: "na".into(),
                    subnet: IpNet::parse("10.132.0.0/16").unwrap(),
                    borders: vec![],
                },
            ],
            rejected: 0,
        };
        let result = measure(&directory).await;
        assert_eq!(result.regions.len(), 1);
        let eu = &result.regions["eu"];
        assert_eq!(eu.border, "near");
        assert!(eu.rtt_ms < 1000.0);
        assert_eq!(result.unreachable, vec!["ap".to_owned(), "na".to_owned()]);
        assert_eq!(result.latencies().len(), 1);
    }

    #[test]
    fn jitter_stays_within_its_bound() {
        for _ in 0..100 {
            assert!(jitter(Duration::from_millis(50)) <= Duration::from_millis(50));
        }
        assert_eq!(jitter(Duration::ZERO), Duration::ZERO);
    }
}
