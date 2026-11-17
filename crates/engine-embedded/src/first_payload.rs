//! How long a new TUN flow waits for the application's first bytes.
//!
//! The tunnel holds a new TCP flow until the application speaks, so the
//! first bytes (a ClientHello, an HTTP request) can be sniffed for the host
//! name and travel inside the proxy request header. Protocols where the
//! server speaks first (SMTP, FTP, POP3, IMAP, MySQL, VNC) never send
//! anything before the server's greeting, so that wait is pure delay.
//!
//! So the tunnel does not wait for those:
//!
//! - Ports whose standard protocol is server-first ([`SERVER_FIRST_PORTS`])
//!   connect at once.
//! - Any other destination whose application stayed silent for the whole
//!   wait is remembered for [`LEARNED_TTL`]; later flows to the same address
//!   and port connect at once. At most [`LEARNED_MAX`] destinations are kept;
//!   the oldest is dropped first.
//!
//! HTTP and HTTPS (ports 80 and 443) always wait, so a flow to them is never
//! sent before its host name is known, and they are never learned.
//! Skipping the wait only moves where the first bytes go: when an
//! application does speak first after all, its bytes follow the proxy
//! request on the same stream instead of riding inside it.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Ports whose standard protocol has the server speak first: FTP, SMTP,
/// POP3, NNTP, IMAP, SMTP submission, MySQL and VNC.
pub const SERVER_FIRST_PORTS: &[u16] = &[21, 25, 110, 119, 143, 587, 3306, 5900];
/// How long a silent destination is remembered.
pub const LEARNED_TTL: Duration = Duration::from_secs(30 * 60);
/// Destinations remembered at once.
pub const LEARNED_MAX: usize = 1024;

/// What a new flow does before connecting.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Wait {
    /// Wait for the first bytes; a silent wait may be learned.
    Sniff,
    /// Wait for the first bytes; never learned (HTTP and HTTPS).
    ClientFirst,
    /// Connect at once.
    Skip,
}

/// Destinations known to stay silent until the server speaks.
#[derive(Default)]
pub struct ServerFirst {
    learned: Mutex<HashMap<SocketAddr, Instant>>,
}

impl ServerFirst {
    pub fn wait(&self, target: SocketAddr) -> Wait {
        self.wait_at(target, Instant::now())
    }

    pub fn wait_at(&self, target: SocketAddr, now: Instant) -> Wait {
        match target.port() {
            80 | 443 => return Wait::ClientFirst,
            port if SERVER_FIRST_PORTS.contains(&port) => return Wait::Skip,
            _ => {}
        }
        let mut learned = self.learned.lock().unwrap_or_else(|e| e.into_inner());
        match learned.get(&target) {
            Some(at) if now.saturating_duration_since(*at) < LEARNED_TTL => Wait::Skip,
            Some(_) => {
                learned.remove(&target);
                Wait::Sniff
            }
            None => Wait::Sniff,
        }
    }

    /// Records that the application at `target` stayed silent for the whole
    /// wait. Ignored for HTTP, HTTPS and the static server-first ports.
    pub fn learn(&self, target: SocketAddr) {
        self.learn_at(target, Instant::now());
    }

    pub fn learn_at(&self, target: SocketAddr, now: Instant) {
        if matches!(target.port(), 80 | 443) || SERVER_FIRST_PORTS.contains(&target.port()) {
            return;
        }
        let mut learned = self.learned.lock().unwrap_or_else(|e| e.into_inner());
        if learned.len() >= LEARNED_MAX && !learned.contains_key(&target) {
            learned.retain(|_, at| now.saturating_duration_since(*at) < LEARNED_TTL);
            if learned.len() >= LEARNED_MAX {
                if let Some(oldest) = learned.iter().min_by_key(|(_, at)| **at).map(|(k, _)| *k) {
                    learned.remove(&oldest);
                }
            }
        }
        learned.insert(target, now);
    }

    /// Destinations remembered now, expired ones included until next looked up.
    pub fn len(&self) -> usize {
        self.learned.lock().unwrap_or_else(|e| e.into_inner()).len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Forgets every learned destination (after a network change).
    pub fn clear(&self) {
        self.learned
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(port: u16) -> SocketAddr {
        SocketAddr::from(([198, 51, 100, 7], port))
    }

    #[test]
    fn well_known_server_first_ports_never_wait() {
        let cache = ServerFirst::default();
        for port in [21, 25, 110, 119, 143, 587, 3306, 5900] {
            assert_eq!(cache.wait(at(port)), Wait::Skip, "port {port}");
        }
        assert_eq!(cache.wait(at(22)), Wait::Sniff);
        assert_eq!(cache.wait(at(5432)), Wait::Sniff);
    }

    #[test]
    fn http_and_https_always_wait_and_are_never_learned() {
        let cache = ServerFirst::default();
        cache.learn(at(80));
        cache.learn(at(443));
        assert!(cache.is_empty());
        assert_eq!(cache.wait(at(80)), Wait::ClientFirst);
        assert_eq!(cache.wait(at(443)), Wait::ClientFirst);
    }

    #[test]
    fn a_silent_destination_skips_the_wait_until_it_expires() {
        let cache = ServerFirst::default();
        let start = Instant::now();
        let target = at(2222);
        assert_eq!(cache.wait_at(target, start), Wait::Sniff);
        cache.learn_at(target, start);
        assert_eq!(
            cache.wait_at(target, start + Duration::from_secs(60)),
            Wait::Skip
        );
        // Same address, other port: still sniffed.
        assert_eq!(cache.wait_at(at(2223), start), Wait::Sniff);
        assert_eq!(cache.wait_at(target, start + LEARNED_TTL), Wait::Sniff);
        assert!(cache.is_empty());
    }

    #[test]
    fn the_cache_is_bounded_and_drops_the_oldest() {
        let cache = ServerFirst::default();
        let start = Instant::now();
        let target = |i: usize| SocketAddr::from(([10, 0, (i >> 8) as u8, i as u8], 4000));
        for i in 0..LEARNED_MAX {
            cache.learn_at(target(i), start + Duration::from_millis(i as u64));
        }
        assert_eq!(cache.len(), LEARNED_MAX);
        let later = start + Duration::from_secs(5);
        cache.learn_at(at(9000), later);
        assert_eq!(cache.len(), LEARNED_MAX);
        assert_eq!(cache.wait_at(target(0), later), Wait::Sniff);
        assert_eq!(cache.wait_at(target(1), later), Wait::Skip);
        assert_eq!(cache.wait_at(at(9000), later), Wait::Skip);
    }

    #[test]
    fn clear_forgets_everything() {
        let cache = ServerFirst::default();
        cache.learn(at(2222));
        cache.clear();
        assert_eq!(cache.wait(at(2222)), Wait::Sniff);
    }
}
