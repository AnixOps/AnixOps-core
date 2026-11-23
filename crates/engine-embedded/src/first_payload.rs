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
//!   wait [`LEARN_AFTER`] times in a row, within [`SILENCE_WINDOW`] of the
//!   first time, is remembered for [`LEARNED_TTL`]; later flows to the same
//!   address and port connect at once. A flow whose application speaks
//!   within the wait starts the count over. At most [`LEARNED_MAX`]
//!   destinations are kept; the oldest is dropped first. A network change
//!   (`reset_network`) forgets them all.
//!
//! Ports whose standard protocol is client-first, HTTP and TLS above all
//! ([`CLIENT_FIRST_PORTS`]), always wait (longer, see the tunnel), so a flow
//! to them is never sent before its host name is known, and they are never
//! learned.
//!
//! Skipping the wait means the flow is sent without its first bytes: when an
//! application does speak first after all, its bytes follow the proxy
//! request on the same stream instead of riding inside it, and the flow has
//! no sniffed host name. Rules on the domain (and `USER-AGENT`, `URL-REGEX`)
//! cannot match it unless Fake-IP gave the name, it shows no host in the
//! connection list, and plain HTTP on it is not rewritten. That is why one
//! late first payload (a busy app, a preconnected socket) is not enough to
//! learn a destination.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Ports whose standard protocol has the server speak first: FTP, SMTP,
/// POP3, NNTP, IMAP, SMTP submission, MySQL and VNC.
pub const SERVER_FIRST_PORTS: &[u16] = &[21, 25, 110, 119, 143, 587, 3306, 5900];
/// Ports whose standard protocol has the client speak first: HTTP and
/// HTTPS, SMTPS, DNS over TLS, IMAPS, POP3S, the alternative HTTPS ports
/// of common CDNs, push services (5223, 5228) and HTTP and HTTPS on 8080
/// and 8443.
pub const CLIENT_FIRST_PORTS: &[u16] = &[
    80, 443, 465, 853, 993, 995, 2053, 2083, 2087, 2096, 5223, 5228, 8080, 8443,
];
/// Silent waits in a row after which a destination is learned (2 or more).
pub const LEARN_AFTER: u8 = 2;
/// How long the silent waits of a destination count towards
/// [`LEARN_AFTER`] after the first of them.
pub const SILENCE_WINDOW: Duration = Duration::from_secs(10 * 60);
/// How long a silent destination is remembered.
pub const LEARNED_TTL: Duration = Duration::from_secs(30 * 60);
/// Destinations remembered at once (learned or still counting).
pub const LEARNED_MAX: usize = 1024;

/// What a new flow does before connecting.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Wait {
    /// Wait for the first bytes; a silent wait counts towards learning.
    Sniff,
    /// Wait for the first bytes; never learned ([`CLIENT_FIRST_PORTS`]).
    ClientFirst,
    /// Connect at once.
    Skip,
}

/// What is known about one destination.
#[derive(Clone, Copy, Debug)]
struct Entry {
    /// Silent waits in a row.
    silences: u8,
    /// When the first of them was.
    since: Instant,
    /// When it was learned, once [`LEARN_AFTER`] waits were silent.
    learned_at: Option<Instant>,
}

impl Entry {
    /// Whether the entry still means something at `now`.
    fn live(&self, now: Instant) -> bool {
        match self.learned_at {
            Some(at) => now.saturating_duration_since(at) < LEARNED_TTL,
            None => now.saturating_duration_since(self.since) < SILENCE_WINDOW,
        }
    }

    fn last(&self) -> Instant {
        self.learned_at.unwrap_or(self.since)
    }
}

/// Destinations known to stay silent until the server speaks.
#[derive(Default)]
pub struct ServerFirst {
    learned: Mutex<HashMap<SocketAddr, Entry>>,
}

fn client_first(port: u16) -> bool {
    CLIENT_FIRST_PORTS.contains(&port)
}

impl ServerFirst {
    fn table(&self) -> std::sync::MutexGuard<'_, HashMap<SocketAddr, Entry>> {
        self.learned.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub fn wait(&self, target: SocketAddr) -> Wait {
        self.wait_at(target, Instant::now())
    }

    pub fn wait_at(&self, target: SocketAddr, now: Instant) -> Wait {
        match target.port() {
            port if client_first(port) => return Wait::ClientFirst,
            port if SERVER_FIRST_PORTS.contains(&port) => return Wait::Skip,
            _ => {}
        }
        let mut learned = self.table();
        match learned.get(&target) {
            Some(entry) if !entry.live(now) => {
                learned.remove(&target);
                Wait::Sniff
            }
            Some(entry) if entry.learned_at.is_some() => Wait::Skip,
            _ => Wait::Sniff,
        }
    }

    /// Records that the application at `target` stayed silent for the whole
    /// wait; after [`LEARN_AFTER`] such waits in a row the destination is
    /// learned. Ignored for the client-first and the static server-first
    /// ports.
    pub fn learn(&self, target: SocketAddr) {
        self.learn_at(target, Instant::now());
    }

    pub fn learn_at(&self, target: SocketAddr, now: Instant) {
        if client_first(target.port()) || SERVER_FIRST_PORTS.contains(&target.port()) {
            return;
        }
        let mut learned = self.table();
        if let Some(entry) = learned.get_mut(&target) {
            if entry.live(now) {
                if entry.learned_at.is_none() {
                    entry.silences = entry.silences.saturating_add(1);
                    if entry.silences >= LEARN_AFTER {
                        entry.learned_at = Some(now);
                    }
                }
                return;
            }
            learned.remove(&target);
        }
        if learned.len() >= LEARNED_MAX {
            learned.retain(|_, entry| entry.live(now));
            if learned.len() >= LEARNED_MAX {
                if let Some(oldest) = learned
                    .iter()
                    .min_by_key(|(_, entry)| entry.last())
                    .map(|(k, _)| *k)
                {
                    learned.remove(&oldest);
                }
            }
        }
        learned.insert(
            target,
            Entry {
                silences: 1,
                since: now,
                learned_at: None,
            },
        );
    }

    /// Records that the application at `target` spoke within the wait: the
    /// silent waits counted so far start over.
    pub fn heard(&self, target: SocketAddr) {
        self.table().remove(&target);
    }

    /// Destinations remembered now (learned or still counting), expired
    /// ones included until next looked up.
    pub fn len(&self) -> usize {
        self.table().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Destinations learned now, expired ones included until next looked up.
    pub fn learned(&self) -> usize {
        self.table()
            .values()
            .filter(|entry| entry.learned_at.is_some())
            .count()
    }

    /// Forgets every destination (after a network change: the servers
    /// behind an address may differ on the new network); returns how many
    /// were learned.
    pub fn clear(&self) -> usize {
        let mut learned = self.table();
        let count = learned
            .values()
            .filter(|entry| entry.learned_at.is_some())
            .count();
        learned.clear();
        count
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
    fn client_first_ports_always_wait_and_are_never_learned() {
        let cache = ServerFirst::default();
        for port in [80, 443, 465, 853, 993, 995, 5223, 8080, 8443] {
            for _ in 0..LEARN_AFTER {
                cache.learn(at(port));
            }
            assert_eq!(cache.wait(at(port)), Wait::ClientFirst, "port {port}");
        }
        assert!(cache.is_empty());
    }

    /// Silent `LEARN_AFTER` times in a row at `now`.
    fn silent(cache: &ServerFirst, target: SocketAddr, now: Instant) {
        for _ in 0..LEARN_AFTER {
            assert_eq!(cache.wait_at(target, now), Wait::Sniff);
            cache.learn_at(target, now);
        }
    }

    #[test]
    fn one_silent_wait_is_not_enough() {
        let cache = ServerFirst::default();
        let start = Instant::now();
        let target = at(2222);
        cache.learn_at(target, start);
        assert_eq!(cache.wait_at(target, start), Wait::Sniff);
        assert_eq!(cache.learned(), 0);
        // The app spoke the next time: the count starts over.
        cache.heard(target);
        cache.learn_at(target, start);
        assert_eq!(cache.wait_at(target, start), Wait::Sniff);
        // Silent waits too far apart do not add up.
        cache.learn_at(target, start + SILENCE_WINDOW);
        assert_eq!(cache.wait_at(target, start + SILENCE_WINDOW), Wait::Sniff);
        cache.learn_at(target, start + SILENCE_WINDOW);
        assert_eq!(cache.wait_at(target, start + SILENCE_WINDOW), Wait::Skip);
        assert_eq!(cache.learned(), 1);
    }

    #[test]
    fn a_silent_destination_skips_the_wait_until_it_expires() {
        let cache = ServerFirst::default();
        let start = Instant::now();
        let target = at(2222);
        silent(&cache, target, start);
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
            silent(&cache, target(i), start + Duration::from_millis(i as u64));
        }
        assert_eq!(cache.len(), LEARNED_MAX);
        let later = start + Duration::from_secs(5);
        silent(&cache, at(9000), later);
        assert_eq!(cache.len(), LEARNED_MAX);
        assert_eq!(cache.wait_at(target(0), later), Wait::Sniff);
        assert_eq!(cache.wait_at(target(1), later), Wait::Skip);
        assert_eq!(cache.wait_at(at(9000), later), Wait::Skip);
    }

    #[test]
    fn clear_forgets_everything() {
        let cache = ServerFirst::default();
        silent(&cache, at(2222), Instant::now());
        cache.learn(at(2223));
        assert_eq!(cache.clear(), 1);
        assert_eq!(cache.wait(at(2222)), Wait::Sniff);
        assert!(cache.is_empty());
    }
}
