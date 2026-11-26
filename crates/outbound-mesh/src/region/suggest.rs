//! Re-measurement history and the region change suggestion (appendix
//! D.6), without I/O. The history is what the node keeps in
//! `region-probe.json`.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// Interval between two rounds (spec §15.8 item 5).
pub const ROUND_INTERVAL_S: u64 = 6 * 3600;
/// Most random delay added to each interval (D.6 item 1).
pub const ROUND_JITTER_S: u64 = 600;
/// First round after joining: 1 to 5 minutes (D.6 item 1).
pub const FIRST_ROUND_MIN_S: u64 = 60;
pub const FIRST_ROUND_MAX_S: u64 = 300;
/// Largest gap between two rounds of one streak (D.6 item 4).
pub const MAX_GAP_S: u64 = 7 * 3600;
/// Span a streak needs before it is suggested (D.6 item 5).
pub const MIN_SPAN_S: u64 = 24 * 3600;
/// Rounds kept (D.6 item 2).
pub const MAX_ROUNDS: usize = 8;
/// The other region must be at most this share of the current RTT ...
pub const RATIO: f64 = 0.7;
/// ... and at least this much lower, in milliseconds.
pub const MIN_GAIN_MS: f64 = 30.0;

/// One round: when it finished (Unix seconds) and each reachable region's
/// RTT (milliseconds, 0.1 ms).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Round {
    pub at: u64,
    pub regions: BTreeMap<String, f64>,
}

/// The saved history: the region the rounds were measured from, and the
/// rounds, oldest first.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct History {
    pub version: u32,
    pub region: Option<String>,
    pub rounds: Vec<Round>,
}

/// A suggestion (D.6 item 5, mesh-status.md `self.regionSuggestion`).
#[derive(Debug, Clone, PartialEq)]
pub struct Suggestion {
    pub region: String,
    pub current_median_ms: f64,
    pub suggested_median_ms: f64,
    /// Unix seconds of the streak's first round.
    pub since: u64,
}

/// Whether `round` favours `other` over `current` (D.6 item 3).
pub fn favours(round: &Round, current: &str, other: &str) -> bool {
    match (round.regions.get(current), round.regions.get(other)) {
        (Some(&cur), Some(&rtt)) => rtt <= RATIO * cur && cur - rtt >= MIN_GAIN_MS,
        _ => false,
    }
}

impl History {
    pub const VERSION: u32 = 1;

    /// An empty history for `region`.
    pub fn new(region: Option<String>) -> Self {
        Self {
            version: Self::VERSION,
            region,
            rounds: Vec::new(),
        }
    }

    /// Read back from the saved file; anything unexpected starts afresh
    /// (D.6 item 2), as does a file saved for another region (item 6).
    pub fn load(text: &str, region: Option<&str>) -> Self {
        match serde_json::from_str::<History>(text) {
            Ok(mut history)
                if history.version == Self::VERSION
                    && history.region.as_deref() == region
                    && history.rounds.len() <= MAX_ROUNDS
                    && history.rounds.windows(2).all(|w| w[0].at <= w[1].at)
                    && history
                        .rounds
                        .iter()
                        .all(|r| r.regions.values().all(|v| v.is_finite() && *v >= 0.0)) =>
            {
                history.region = region.map(str::to_owned);
                history
            }
            _ => Self::new(region.map(str::to_owned)),
        }
    }

    pub fn save(&self) -> String {
        serde_json::to_string(self).unwrap_or_default()
    }

    /// Sets the current region; a change drops every round (D.6 item 6,
    /// D.8 item 5).
    pub fn set_region(&mut self, region: Option<&str>) {
        if self.region.as_deref() != region {
            *self = Self::new(region.map(str::to_owned));
        }
    }

    /// Adds a finished round. A round older than the newest kept one (a
    /// clock step back) drops the history first: the streak's time order
    /// cannot be trusted across it.
    pub fn push(&mut self, round: Round) {
        if self.rounds.last().is_some_and(|last| round.at < last.at) {
            self.rounds.clear();
        }
        self.rounds.push(round);
        if self.rounds.len() > MAX_ROUNDS {
            let extra = self.rounds.len() - MAX_ROUNDS;
            self.rounds.drain(..extra);
        }
    }

    /// The suggestion, if any (D.6 items 3–5). `pending` is whether the
    /// network has a pending request: then there is none (mesh-status.md).
    pub fn suggestion(&self, pending: bool) -> Option<Suggestion> {
        let current = self.region.as_deref()?;
        if pending {
            return None;
        }
        let latest = self.rounds.last()?;
        let mut best: Option<Suggestion> = None;
        for (other, &rtt) in &latest.regions {
            if other == current || !favours(latest, current, other) {
                continue;
            }
            let Some(since) = self.streak_start(current, other) else {
                continue;
            };
            if latest.at.saturating_sub(since) < MIN_SPAN_S {
                continue;
            }
            let better = match &best {
                None => true,
                Some(b) => {
                    rtt < b.suggested_median_ms
                        || (rtt == b.suggested_median_ms && *other < b.region)
                }
            };
            if better {
                best = Some(Suggestion {
                    region: other.clone(),
                    current_median_ms: latest.regions[current],
                    suggested_median_ms: rtt,
                    since,
                });
            }
        }
        best
    }

    /// The first round of the streak that ends with the latest round, every
    /// round of it favouring `other`, with gaps of at most [`MAX_GAP_S`].
    fn streak_start(&self, current: &str, other: &str) -> Option<u64> {
        let mut start = None;
        let mut next_at: Option<u64> = None;
        for round in self.rounds.iter().rev() {
            if let Some(next) = next_at {
                if next.saturating_sub(round.at) > MAX_GAP_S {
                    break;
                }
            }
            if !favours(round, current, other) {
                break;
            }
            start = Some(round.at);
            next_at = Some(round.at);
        }
        start
    }
}

/// Integer milliseconds for the status (mesh-status.md).
pub fn whole_ms(ms: f64) -> u64 {
    if ms.is_finite() && ms > 0.0 {
        ms.round() as u64
    } else {
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const H: u64 = 3600;

    fn round(at: u64, items: &[(&str, f64)]) -> Round {
        Round {
            at,
            regions: items.iter().map(|(k, v)| ((*k).to_owned(), *v)).collect(),
        }
    }

    fn history(rounds: Vec<Round>) -> History {
        let mut h = History::new(Some("eu".into()));
        for r in rounds {
            h.push(r);
        }
        h
    }

    /// Rounds every 6 hours from `t0`, `n` of them, eu = `cur`, ap = `alt`.
    fn steady(t0: u64, n: u64, cur: f64, alt: f64) -> Vec<Round> {
        (0..n)
            .map(|i| round(t0 + i * 6 * H, &[("eu", cur), ("ap", alt)]))
            .collect()
    }

    #[test]
    fn the_threshold_needs_both_thirty_percent_and_thirty_ms() {
        // 30% lower but only 15 ms: no.
        assert!(!favours(
            &round(0, &[("eu", 50.0), ("ap", 35.0)]),
            "eu",
            "ap"
        ));
        // 30 ms lower but only 20%: no.
        assert!(!favours(
            &round(0, &[("eu", 150.0), ("ap", 120.0)]),
            "eu",
            "ap"
        ));
        // Exactly 0.7× and exactly 30 ms: yes.
        assert!(favours(
            &round(0, &[("eu", 100.0), ("ap", 70.0)]),
            "eu",
            "ap"
        ));
        assert!(!favours(
            &round(0, &[("eu", 100.0), ("ap", 70.1)]),
            "eu",
            "ap"
        ));
        // A region missing from the round never favours.
        assert!(!favours(&round(0, &[("ap", 10.0)]), "eu", "ap"));
    }

    #[test]
    fn twenty_four_hours_of_rounds_are_needed() {
        let t0 = 1_700_000_000;
        // Four rounds span 18 hours: not yet.
        assert_eq!(history(steady(t0, 4, 200.0, 100.0)).suggestion(false), None);
        // Five rounds span 24 hours.
        let s = history(steady(t0, 5, 200.0, 100.0))
            .suggestion(false)
            .unwrap();
        assert_eq!(s.region, "ap");
        assert_eq!(s.since, t0);
        assert_eq!(s.current_median_ms, 200.0);
        assert_eq!(s.suggested_median_ms, 100.0);
        // A pending request hides it.
        assert_eq!(history(steady(t0, 5, 200.0, 100.0)).suggestion(true), None);
    }

    #[test]
    fn one_failing_round_restarts_the_streak() {
        let t0 = 1_700_000_000;
        let mut rounds = steady(t0, 5, 200.0, 100.0);
        // The third round is within the hysteresis band.
        rounds[2] = round(rounds[2].at, &[("eu", 120.0), ("ap", 100.0)]);
        rounds.push(round(t0 + 30 * H, &[("eu", 200.0), ("ap", 100.0)]));
        let h = history(rounds);
        // The streak now starts at the fourth round (18 h): 12 h long.
        assert_eq!(h.suggestion(false), None);
        // The latest round failing withdraws an existing suggestion.
        let mut h = history(steady(t0, 6, 200.0, 100.0));
        assert!(h.suggestion(false).is_some());
        h.push(round(t0 + 36 * H, &[("eu", 200.0), ("ap", 180.0)]));
        assert_eq!(h.suggestion(false), None);
    }

    #[test]
    fn an_unreachable_current_region_or_an_empty_round_breaks_the_streak() {
        let t0 = 1_700_000_000;
        let mut rounds = steady(t0, 6, 200.0, 100.0);
        rounds[1] = round(rounds[1].at, &[("ap", 100.0)]);
        assert_eq!(history(rounds.clone()).suggestion(false), None);
        rounds[1] = round(rounds[1].at, &[]);
        assert_eq!(history(rounds).suggestion(false), None);
    }

    #[test]
    fn a_gap_longer_than_seven_hours_breaks_the_streak() {
        let t0 = 1_700_000_000;
        let mut rounds = steady(t0, 3, 200.0, 100.0);
        // Node off for 8 hours, then 3 more rounds: 12 h after the gap.
        let resume = t0 + 12 * H + 8 * H;
        rounds.extend(steady(resume, 3, 200.0, 100.0));
        assert_eq!(history(rounds).suggestion(false), None);
        // 6 h 10 min (the most jitter) still counts.
        let rounds: Vec<Round> = (0..5)
            .map(|i| round(t0 + i * (6 * H + 600), &[("eu", 200.0), ("ap", 100.0)]))
            .collect();
        assert!(history(rounds).suggestion(false).is_some());
    }

    #[test]
    fn the_best_of_several_qualifying_regions_is_suggested() {
        let t0 = 1_700_000_000;
        let rounds: Vec<Round> = (0..5)
            .map(|i| {
                round(
                    t0 + i * 6 * H,
                    &[("eu", 300.0), ("ap", 120.0), ("na", 90.0), ("cn", 90.0)],
                )
            })
            .collect();
        let s = history(rounds).suggestion(false).unwrap();
        assert_eq!(s.region, "cn");
    }

    #[test]
    fn a_region_change_or_a_clock_step_back_starts_afresh() {
        let t0 = 1_700_000_000;
        let mut h = history(steady(t0, 5, 200.0, 100.0));
        h.set_region(Some("eu"));
        assert_eq!(h.rounds.len(), 5);
        h.set_region(Some("ap"));
        assert!(h.rounds.is_empty());
        assert_eq!(h.suggestion(false), None);

        let mut h = history(steady(t0, 5, 200.0, 100.0));
        h.push(round(t0, &[("eu", 200.0), ("ap", 100.0)]));
        assert_eq!(h.rounds.len(), 1);
    }

    #[test]
    fn only_eight_rounds_are_kept() {
        let h = history(steady(1_700_000_000, 12, 200.0, 100.0));
        assert_eq!(h.rounds.len(), MAX_ROUNDS);
        assert!(h.suggestion(false).is_some());
    }

    #[test]
    fn the_saved_file_round_trips_and_bad_files_start_afresh() {
        let h = history(steady(1_700_000_000, 5, 200.0, 100.0));
        let text = h.save();
        assert_eq!(History::load(&text, Some("eu")), h);
        // Saved for another region.
        assert!(History::load(&text, Some("ap")).rounds.is_empty());
        for bad in [
            "",
            "{}",
            "not json",
            r#"{"version":2,"region":"eu","rounds":[]}"#,
            r#"{"version":1,"region":"eu","rounds":[{"at":2,"regions":{}},{"at":1,"regions":{}}]}"#,
            r#"{"version":1,"region":"eu","rounds":[{"at":1,"regions":{"eu":-1}}]}"#,
            r#"{"version":1,"region":"eu","rounds":[],"extra":1}"#,
        ] {
            let loaded = History::load(bad, Some("eu"));
            assert!(loaded.rounds.is_empty(), "{bad}");
            assert_eq!(loaded.region.as_deref(), Some("eu"));
        }
    }

    #[test]
    fn whole_milliseconds() {
        assert_eq!(whole_ms(18.4), 18);
        assert_eq!(whole_ms(18.5), 19);
        assert_eq!(whole_ms(f64::NAN), 0);
    }
}
