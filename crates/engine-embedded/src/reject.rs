//! REJECT policies at run time: what each kind asks of the inbound, and the
//! retry-storm guard that answers a host rejected too often like
//! `REJECT-DROP`.
//!
//! An app whose request is refused at once often retries at once, and a
//! blocked analytics or ad endpoint can then be dialed hundreds of times a
//! minute, each a new flow through the engine. As in Surge, when one host
//! has been rejected by a plain `REJECT` more than [`STORM_LIMIT`] times
//! within [`STORM_WINDOW`], its next rejections are answered like
//! `REJECT-DROP` (nothing at all), so the app waits for its own timeout
//! instead of spinning. The host goes back to a plain `REJECT` once it has
//! been rejected no more than [`STORM_LIMIT`] times in the last
//! [`STORM_WINDOW`]. `REJECT-NO-DROP` is never upgraded.

use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use config_core::routing::RejectKind;
use engine_outbound::reject::RejectAction;

/// Rejections of one host within [`STORM_WINDOW`] that are still answered
/// as `REJECT`; the next one is dropped.
pub const STORM_LIMIT: usize = 10;

/// The window [`STORM_LIMIT`] counts over.
pub const STORM_WINDOW: Duration = Duration::from_secs(30);

/// Hosts tracked at once. Past this, hosts with no rejection in the window
/// are forgotten first, then the one rejected longest ago.
pub const STORM_MAX_HOSTS: usize = 1024;

/// The answer a REJECT kind asks the inbound for.
pub fn action(kind: RejectKind) -> RejectAction {
    match kind {
        RejectKind::Reject | RejectKind::NoDrop => RejectAction::Close,
        RejectKind::Drop => RejectAction::Drop,
        RejectKind::TinyGif => RejectAction::TinyGif,
    }
}

/// Recent plain-`REJECT` times per host; see the module docs.
#[derive(Debug, Default)]
pub struct RejectStorm {
    hosts: Mutex<HashMap<String, VecDeque<Instant>>>,
}

impl RejectStorm {
    /// Records one plain `REJECT` of `host` at `now` and returns the kind to
    /// answer it with: `REJECT`, or `REJECT-DROP` while the host storms.
    pub fn settle(&self, host: &str, now: Instant) -> RejectKind {
        let mut hosts = self
            .hosts
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if !hosts.contains_key(host) && hosts.len() >= STORM_MAX_HOSTS {
            evict(&mut hosts, now);
        }
        let times = hosts.entry(host.to_string()).or_default();
        while times
            .front()
            .is_some_and(|&first| now.saturating_duration_since(first) >= STORM_WINDOW)
        {
            times.pop_front();
        }
        times.push_back(now);
        // Only the count up to one past the limit matters.
        if times.len() > STORM_LIMIT + 1 {
            times.pop_front();
        }
        if times.len() > STORM_LIMIT {
            RejectKind::Drop
        } else {
            RejectKind::Reject
        }
    }

    /// Hosts tracked now.
    pub fn len(&self) -> usize {
        self.hosts
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Makes room for one more host: drops every host with no rejection in the
/// window, or else the one whose last rejection is oldest.
fn evict(hosts: &mut HashMap<String, VecDeque<Instant>>, now: Instant) {
    hosts.retain(|_, times| {
        times
            .back()
            .is_some_and(|&last| now.saturating_duration_since(last) < STORM_WINDOW)
    });
    if hosts.len() < STORM_MAX_HOSTS {
        return;
    }
    let oldest = hosts
        .iter()
        .min_by_key(|(_, times)| times.back().copied())
        .map(|(host, _)| host.clone());
    if let Some(oldest) = oldest {
        hosts.remove(&oldest);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kinds_map_to_actions() {
        assert_eq!(action(RejectKind::Reject), RejectAction::Close);
        assert_eq!(action(RejectKind::NoDrop), RejectAction::Close);
        assert_eq!(action(RejectKind::Drop), RejectAction::Drop);
        assert_eq!(action(RejectKind::TinyGif), RejectAction::TinyGif);
    }

    #[test]
    fn the_eleventh_rejection_within_thirty_seconds_is_dropped() {
        let storm = RejectStorm::default();
        let start = Instant::now();
        for second in 0..10 {
            let at = start + Duration::from_secs(second * 2);
            assert_eq!(storm.settle("ads.example", at), RejectKind::Reject);
        }
        let at = start + Duration::from_secs(25);
        assert_eq!(storm.settle("ads.example", at), RejectKind::Drop);
        // Another host is counted on its own.
        assert_eq!(storm.settle("other.example", at), RejectKind::Reject);
    }

    #[test]
    fn retries_spread_over_more_than_the_window_are_never_dropped() {
        let storm = RejectStorm::default();
        let start = Instant::now();
        // One every 3 s: at most 10 within any 30 s.
        for step in 0..40 {
            let at = start + Duration::from_secs(step * 3);
            assert_eq!(storm.settle("slow.example", at), RejectKind::Reject);
        }
    }

    #[test]
    fn a_storm_ends_once_the_retries_calm_down() {
        let storm = RejectStorm::default();
        let start = Instant::now();
        for _ in 0..10 {
            storm.settle("loop.example", start);
        }
        // Dropped answers count too: a client that keeps hammering stays
        // dropped.
        for millis in 1..=20 {
            let at = start + Duration::from_millis(millis * 100);
            assert_eq!(storm.settle("loop.example", at), RejectKind::Drop);
        }
        // 30 s after the burst there are no recent rejections left.
        let later = start + Duration::from_secs(33);
        assert_eq!(storm.settle("loop.example", later), RejectKind::Reject);
    }

    #[test]
    fn hosts_are_bounded() {
        let storm = RejectStorm::default();
        let start = Instant::now();
        for host in 0..STORM_MAX_HOSTS + 50 {
            storm.settle(&format!("h{host}.example"), start);
        }
        assert_eq!(storm.len(), STORM_MAX_HOSTS);
        // Quiet hosts go first once the window has passed.
        let later = start + STORM_WINDOW;
        storm.settle("new.example", later);
        assert_eq!(storm.len(), 1);
    }
}
