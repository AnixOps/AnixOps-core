//! One measurement round (appendix D.4) and the first choice of a region
//! (D.5), without I/O.

use std::collections::BTreeMap;

/// Probes sent to each border node per round.
pub const PROBES_PER_BORDER: usize = 10;
/// Valid answers a border node needs for its median to count.
pub const MIN_ANSWERS: usize = 5;
/// Factor applied to the preferred region's RTT (spec §15.8 item 4).
pub const PREFERRED_FACTOR: f64 = 0.8;

/// The median of `samples` (milliseconds) when at least [`MIN_ANSWERS`]
/// are valid (finite, not negative); the mean of the middle two for an
/// even count.
pub fn border_median(samples: &[f64]) -> Option<f64> {
    let mut valid: Vec<f64> = samples
        .iter()
        .copied()
        .filter(|rtt| rtt.is_finite() && *rtt >= 0.0)
        .collect();
    if valid.len() < MIN_ANSWERS {
        return None;
    }
    valid.sort_by(f64::total_cmp);
    let mid = valid.len() / 2;
    Some(if valid.len().is_multiple_of(2) {
        (valid[mid - 1] + valid[mid]) / 2.0
    } else {
        valid[mid]
    })
}

/// Rounds to 0.1 ms (D.4 item 5).
pub fn round_tenth(ms: f64) -> f64 {
    (ms * 10.0).round() / 10.0
}

/// One border node's result in a round.
#[derive(Debug, Clone, PartialEq)]
pub struct BorderResult {
    /// Display name (D.2.2).
    pub name: String,
    /// Median RTT, `None` when the border node had too few answers.
    pub median_ms: Option<f64>,
}

/// One region's result: the smallest valid border median, and the border
/// node it came from (for `self.regionBasis.border`).
#[derive(Debug, Clone, PartialEq)]
pub struct RegionResult {
    pub rtt_ms: f64,
    pub border: String,
}

/// The region RTT (D.4 item 4): the smallest valid border median, rounded
/// to 0.1 ms; ties go to the border listed first. `None` when no border
/// node is valid.
pub fn region_result(borders: &[BorderResult]) -> Option<RegionResult> {
    let mut best: Option<(f64, &str)> = None;
    for border in borders {
        if let Some(median) = border.median_ms {
            if best.is_none_or(|(rtt, _)| median < rtt) {
                best = Some((median, &border.name));
            }
        }
    }
    best.map(|(rtt, name)| RegionResult {
        rtt_ms: round_tenth(rtt),
        border: name.to_owned(),
    })
}

/// The first region choice (D.5 item 3): the smallest score, the preferred
/// region's RTT times 0.8. `order` is the panel's region order, used for
/// ties; regions missing from it come after it, by code. `None` when no
/// region has an RTT.
///
/// The panel makes this choice; the node uses the same function only to
/// show what it would be, and the tests pin the rule for both sides.
pub fn choose(
    latencies: &BTreeMap<String, f64>,
    preferred: Option<&str>,
    order: &[&str],
) -> Option<String> {
    let rank = |code: &str| order.iter().position(|c| *c == code).unwrap_or(order.len());
    latencies
        .iter()
        .filter(|(_, rtt)| rtt.is_finite() && **rtt >= 0.0)
        .map(|(code, rtt)| {
            let score = if Some(code.as_str()) == preferred {
                rtt * PREFERRED_FACTOR
            } else {
                *rtt
            };
            (score, rank(code), code)
        })
        .min_by(|a, b| a.0.total_cmp(&b.0).then(a.1.cmp(&b.1)).then(a.2.cmp(b.2)))
        .map(|(_, _, code)| code.clone())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn border_median_needs_five_answers() {
        assert_eq!(border_median(&[10.0, 11.0, 12.0, 13.0]), None);
        assert_eq!(border_median(&[13.0, 10.0, 12.0, 11.0, 50.0]), Some(12.0));
        assert_eq!(border_median(&[1.0, 2.0, 3.0, 4.0, 5.0, 6.0]), Some(3.5));
        // Invalid samples do not count towards the five.
        assert_eq!(
            border_median(&[1.0, 2.0, 3.0, 4.0, f64::NAN, -1.0, f64::INFINITY]),
            None
        );
        let ten = [
            20.0, 21.0, 19.0, 300.0, 22.0, 20.5, 19.5, 21.5, 20.0, 1000.0,
        ];
        assert_eq!(border_median(&ten), Some(20.75));
    }

    #[test]
    fn a_region_takes_its_nearest_valid_border() {
        let borders = vec![
            BorderResult {
                name: "a".into(),
                median_ms: Some(40.04),
            },
            BorderResult {
                name: "b".into(),
                median_ms: None,
            },
            BorderResult {
                name: "c".into(),
                median_ms: Some(18.26),
            },
            BorderResult {
                name: "d".into(),
                median_ms: Some(18.26),
            },
        ];
        assert_eq!(
            region_result(&borders),
            Some(RegionResult {
                rtt_ms: 18.3,
                border: "c".into()
            })
        );
        assert_eq!(
            region_result(&[BorderResult {
                name: "b".into(),
                median_ms: None
            }]),
            None
        );
        assert_eq!(region_result(&[]), None);
    }

    fn map(items: &[(&str, f64)]) -> BTreeMap<String, f64> {
        items.iter().map(|(k, v)| ((*k).to_owned(), *v)).collect()
    }

    #[test]
    fn the_lowest_rtt_wins_without_a_preference() {
        let latencies = map(&[("cn", 35.0), ("ap", 60.0), ("eu", 180.0)]);
        assert_eq!(
            choose(&latencies, None, &["cn", "ap", "eu"]).as_deref(),
            Some("cn")
        );
    }

    #[test]
    fn the_preferred_region_is_discounted_by_a_fifth() {
        // 40 × 0.8 = 32 < 35.
        let latencies = map(&[("cn", 35.0), ("ap", 40.0)]);
        assert_eq!(
            choose(&latencies, Some("ap"), &["cn", "ap"]).as_deref(),
            Some("ap")
        );
        // 45 × 0.8 = 36 > 35.
        let latencies = map(&[("cn", 35.0), ("ap", 45.0)]);
        assert_eq!(
            choose(&latencies, Some("ap"), &["cn", "ap"]).as_deref(),
            Some("cn")
        );
        // A preferred region without an RTT changes nothing.
        let latencies = map(&[("cn", 35.0), ("ap", 45.0)]);
        assert_eq!(
            choose(&latencies, Some("eu"), &["cn", "ap"]).as_deref(),
            Some("cn")
        );
    }

    #[test]
    fn ties_follow_the_panel_order_then_the_code() {
        // 50 × 0.8 = 40: tied with cn; ap comes first in the panel order.
        let latencies = map(&[("cn", 40.0), ("ap", 50.0)]);
        assert_eq!(
            choose(&latencies, Some("ap"), &["ap", "cn"]).as_deref(),
            Some("ap")
        );
        assert_eq!(
            choose(&latencies, Some("ap"), &["cn", "ap"]).as_deref(),
            Some("cn")
        );
        let latencies = map(&[("zz", 10.0), ("yy", 10.0)]);
        assert_eq!(choose(&latencies, None, &[]).as_deref(), Some("yy"));
    }

    #[test]
    fn nothing_to_choose_from() {
        assert_eq!(choose(&BTreeMap::new(), None, &[]), None);
        assert_eq!(
            choose(&map(&[("cn", f64::NAN), ("eu", -1.0)]), None, &[]),
            None
        );
    }
}
