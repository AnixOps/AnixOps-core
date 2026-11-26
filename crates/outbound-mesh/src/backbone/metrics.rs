//! Link measurement and cost (spec §17.3.4, appendix A.4, A.6 items 1–2).

use std::collections::VecDeque;
use std::time::{Duration, Instant};

use super::msg::{Probe, MAX_COST_MILLI};

/// Probes kept for loss and jitter (spec §17.3.4).
pub const PROBE_WINDOW: usize = 30;
/// One probe per second while any field needs probing.
pub const PROBE_INTERVAL: Duration = Duration::from_secs(1);
/// A probe not answered within this time counts as lost (appendix A.4).
pub const PROBE_TIMEOUT: Duration = Duration::from_secs(3);
/// Smoothing of the probed round trip.
pub const RTT_ALPHA: f64 = 0.2;
/// A link must look good this long before it is used (spec §17.3.4).
pub const STABLE_FOR: Duration = Duration::from_secs(10);

#[derive(Clone, Copy, Debug)]
struct Sent {
    seq: u64,
    at: Instant,
    sent_us: u64,
    rtt: Option<Duration>,
}

/// The probes of one link, for the fields the link does not report.
#[derive(Clone, Debug)]
pub struct ProbeWindow {
    epoch: Instant,
    next_seq: u64,
    sent: VecDeque<Sent>,
    rtt_ewma_ms: Option<f64>,
}

impl ProbeWindow {
    pub fn new(epoch: Instant) -> Self {
        Self {
            epoch,
            next_seq: 1,
            sent: VecDeque::with_capacity(PROBE_WINDOW),
            rtt_ewma_ms: None,
        }
    }

    /// Records and returns the next probe to send.
    pub fn next(&mut self, now: Instant) -> Probe {
        let seq = self.next_seq;
        self.next_seq += 1;
        let sent_us = u64::try_from(now.saturating_duration_since(self.epoch).as_micros())
            .unwrap_or(u64::MAX);
        if self.sent.len() == PROBE_WINDOW {
            self.sent.pop_front();
        }
        self.sent.push_back(Sent {
            seq,
            at: now,
            sent_us,
            rtt: None,
        });
        Probe { seq, sent_us }
    }

    /// Takes one acknowledgement. Only acks of an unanswered probe in the
    /// window, echoing its send time and arriving within the timeout count.
    pub fn on_ack(&mut self, ack: Probe, now: Instant) -> bool {
        let Some(sent) = self.sent.iter_mut().find(|s| s.seq == ack.seq) else {
            return false;
        };
        if sent.rtt.is_some() || sent.sent_us != ack.sent_us {
            return false;
        }
        let rtt = now.saturating_duration_since(sent.at);
        if rtt > PROBE_TIMEOUT {
            return false;
        }
        sent.rtt = Some(rtt);
        let ms = rtt.as_secs_f64() * 1000.0;
        self.rtt_ewma_ms = Some(match self.rtt_ewma_ms {
            None => ms,
            Some(prev) => prev + RTT_ALPHA * (ms - prev),
        });
        true
    }

    /// Smoothed round trip of the answered probes.
    pub fn rtt_ms(&self) -> Option<f64> {
        self.rtt_ewma_ms
    }

    /// Lost share of the resolved probes in the window (answered, or older
    /// than the timeout); `None` before any probe is resolved.
    pub fn loss(&self, now: Instant) -> Option<f64> {
        let mut resolved = 0u32;
        let mut lost = 0u32;
        for sent in &self.sent {
            if sent.rtt.is_some() {
                resolved += 1;
            } else if now.saturating_duration_since(sent.at) > PROBE_TIMEOUT {
                resolved += 1;
                lost += 1;
            }
        }
        (resolved > 0).then(|| f64::from(lost) / f64::from(resolved))
    }

    /// Mean absolute difference of consecutive answered round trips in the
    /// window; `None` with fewer than two answers.
    pub fn jitter_ms(&self) -> Option<f64> {
        let rtts: Vec<f64> = self
            .sent
            .iter()
            .filter_map(|s| s.rtt)
            .map(|d| d.as_secs_f64() * 1000.0)
            .collect();
        if rtts.len() < 2 {
            return None;
        }
        let sum: f64 = rtts.windows(2).map(|w| (w[1] - w[0]).abs()).sum();
        Some(sum / (rtts.len() - 1) as f64)
    }
}

/// What a backbone link reports about itself. Fields it cannot measure are
/// `None` and are filled from probes instead (appendix A.6 item 2).
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct LinkReport {
    pub up: bool,
    pub forward_secrecy: bool,
    pub rtt_ms: Option<f64>,
    /// 0–1.
    pub loss: Option<f64>,
    pub jitter_ms: Option<f64>,
    /// 0–1.
    pub utilization: Option<f64>,
}

impl LinkReport {
    /// Whether probes are needed for at least one field.
    pub fn needs_probe(&self) -> bool {
        self.rtt_ms.is_none() || self.loss.is_none() || self.jitter_ms.is_none()
    }
}

fn finite_non_negative(value: Option<f64>) -> Option<f64> {
    value.filter(|v| v.is_finite() && *v >= 0.0)
}

fn unit(value: Option<f64>) -> Option<f64> {
    finite_non_negative(value).map(|v| v.min(1.0))
}

/// The measured values of one link, each from a single source.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Metrics {
    pub rtt_ms: f64,
    pub loss: f64,
    pub jitter_ms: f64,
    pub utilization: Option<f64>,
}

impl Metrics {
    /// Takes each field from the link when it reports it and from the probes
    /// otherwise, never mixing the two for one field. `None` until both the
    /// round trip and the loss are known; an unknown jitter counts as 0 until
    /// the probes have two answers.
    pub fn combine(report: &LinkReport, probes: &ProbeWindow, now: Instant) -> Option<Self> {
        let rtt_ms = match report.rtt_ms {
            Some(_) => finite_non_negative(report.rtt_ms),
            None => probes.rtt_ms(),
        }?;
        let loss = match report.loss {
            Some(_) => unit(report.loss),
            None => probes.loss(now),
        }?;
        let jitter_ms = match report.jitter_ms {
            Some(_) => finite_non_negative(report.jitter_ms),
            None => probes.jitter_ms(),
        }
        .unwrap_or(0.0);
        Some(Self {
            rtt_ms,
            loss,
            jitter_ms,
            utilization: unit(report.utilization),
        })
    }

    /// The congestion factor of the cost; 1 without a utilization.
    pub fn congestion_factor(&self) -> f64 {
        1.0 + 5.0 * (self.utilization.unwrap_or(0.0) - 0.8).max(0.0)
    }

    /// Link cost (spec §17.3.4).
    pub fn cost(&self) -> f64 {
        (self.rtt_ms * (1.0 + 10.0 * self.loss) + 2.0 * self.jitter_ms) * self.congestion_factor()
    }
}

/// A cost as carried in LinkState (appendix A.3).
pub fn cost_milli(cost: f64) -> u32 {
    if !cost.is_finite() || cost < 0.0 {
        return MAX_COST_MILLI;
    }
    let milli = (cost * 1000.0).round();
    if milli >= f64::from(MAX_COST_MILLI) {
        MAX_COST_MILLI
    } else {
        milli as u32
    }
}

/// One link as the selection sees it.
#[derive(Clone, Debug)]
pub struct LinkTracker {
    probes: ProbeWindow,
    report: LinkReport,
    metrics: Option<Metrics>,
    good_since: Option<Instant>,
    usable: bool,
    last_probe: Option<Instant>,
}

impl LinkTracker {
    pub fn new(now: Instant) -> Self {
        Self {
            probes: ProbeWindow::new(now),
            report: LinkReport::default(),
            metrics: None,
            good_since: None,
            usable: false,
            last_probe: None,
        }
    }

    /// Takes the link's latest report and re-evaluates. Returns whether the
    /// usable state changed.
    pub fn update(&mut self, report: LinkReport, now: Instant) -> bool {
        self.report = report;
        self.metrics = Metrics::combine(&report, &self.probes, now);
        let good = report.up && report.forward_secrecy && self.metrics.is_some();
        let usable = if good {
            let since = *self.good_since.get_or_insert(now);
            now.saturating_duration_since(since) >= STABLE_FOR
        } else {
            self.good_since = None;
            false
        };
        let changed = usable != self.usable;
        self.usable = usable;
        changed
    }

    /// The probe to send now, if one is due: only while the link is up with
    /// forward secrecy and some field needs probing.
    pub fn probe_due(&mut self, now: Instant) -> Option<Probe> {
        if !(self.report.up && self.report.forward_secrecy && self.report.needs_probe()) {
            return None;
        }
        if self
            .last_probe
            .is_some_and(|last| now.saturating_duration_since(last) < PROBE_INTERVAL)
        {
            return None;
        }
        self.last_probe = Some(now);
        Some(self.probes.next(now))
    }

    pub fn on_probe_ack(&mut self, ack: Probe, now: Instant) -> bool {
        self.probes.on_ack(ack, now)
    }

    /// Up, forward-secret, measured and stable for [`STABLE_FOR`].
    pub fn usable(&self) -> bool {
        self.usable
    }

    /// Up but without forward secrecy: unusable and alerted (A.6 item 1).
    pub fn insecure(&self) -> bool {
        self.report.up && !self.report.forward_secrecy
    }

    pub fn report(&self) -> &LinkReport {
        &self.report
    }

    pub fn metrics(&self) -> Option<&Metrics> {
        self.metrics.as_ref()
    }

    /// The cost, or `None` (infinite) when the link is not usable.
    pub fn cost(&self) -> Option<f64> {
        if self.usable {
            self.metrics.map(|m| m.cost())
        } else {
            None
        }
    }

    /// The loss while usable.
    pub fn loss(&self) -> Option<f64> {
        if self.usable {
            self.metrics.map(|m| m.loss)
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ms(n: u64) -> Duration {
        Duration::from_millis(n)
    }

    #[test]
    fn probes_measure_rtt_loss_and_jitter() {
        let t0 = Instant::now();
        let mut w = ProbeWindow::new(t0);
        let p1 = w.next(t0);
        assert!(w.on_ack(p1, t0 + ms(100)));
        assert!(!w.on_ack(p1, t0 + ms(101)), "second ack ignored");
        let p2 = w.next(t0 + ms(1000));
        assert!(w.on_ack(p2, t0 + ms(1150)));
        let p3 = w.next(t0 + ms(2000));
        // Forged send time.
        assert!(!w.on_ack(
            Probe {
                seq: p3.seq,
                sent_us: p3.sent_us + 1
            },
            t0 + ms(2050)
        ));
        let rtt = w.rtt_ms().unwrap();
        assert!((rtt - (100.0 + 0.2 * 50.0)).abs() < 1e-6, "{rtt}");
        assert!((w.jitter_ms().unwrap() - 50.0).abs() < 1e-6);
        // p3 unresolved until the timeout, then lost.
        assert_eq!(w.loss(t0 + ms(2500)), Some(0.0));
        let loss = w.loss(t0 + ms(5001)).unwrap();
        assert!((loss - 1.0 / 3.0).abs() < 1e-9);
        // Late ack does not count.
        assert!(!w.on_ack(p3, t0 + ms(5002)));
    }

    #[test]
    fn window_keeps_thirty_probes() {
        let t0 = Instant::now();
        let mut w = ProbeWindow::new(t0);
        let first = w.next(t0);
        for i in 1..=PROBE_WINDOW as u64 {
            w.next(t0 + ms(i));
        }
        assert!(!w.on_ack(first, t0 + ms(40)), "fell out of the window");
        assert_eq!(w.sent.len(), PROBE_WINDOW);
    }

    #[test]
    fn link_values_win_per_field_without_mixing() {
        let t0 = Instant::now();
        let mut w = ProbeWindow::new(t0);
        let p = w.next(t0);
        w.on_ack(p, t0 + ms(80));
        let p = w.next(t0 + ms(1000));
        w.on_ack(p, t0 + ms(1120));
        let report = LinkReport {
            up: true,
            forward_secrecy: true,
            rtt_ms: Some(30.0),
            loss: Some(0.01),
            jitter_ms: None,
            utilization: None,
        };
        let m = Metrics::combine(&report, &w, t0 + ms(1200)).unwrap();
        assert_eq!(m.rtt_ms, 30.0, "link rtt, not the probes'");
        assert_eq!(m.loss, 0.01);
        assert!((m.jitter_ms - 40.0).abs() < 1e-6, "jitter from the probes");
        // Without any source for rtt or loss there are no metrics.
        let empty = ProbeWindow::new(t0);
        assert!(Metrics::combine(&LinkReport::default(), &empty, t0).is_none());
        // A reported but invalid value is not replaced by the probes.
        let bad = LinkReport {
            rtt_ms: Some(f64::NAN),
            loss: Some(0.0),
            ..report
        };
        assert!(Metrics::combine(&bad, &w, t0 + ms(1200)).is_none());
    }

    #[test]
    fn cost_formula() {
        let m = Metrics {
            rtt_ms: 100.0,
            loss: 0.02,
            jitter_ms: 5.0,
            utilization: None,
        };
        assert!((m.cost() - (100.0 * 1.2 + 10.0)).abs() < 1e-9);
        let busy = Metrics {
            utilization: Some(0.9),
            ..m
        };
        assert!((busy.cost() - 130.0 * 1.5).abs() < 1e-9);
        assert_eq!(cost_milli(130.0), 130_000);
        assert_eq!(cost_milli(f64::INFINITY), MAX_COST_MILLI);
        assert_eq!(cost_milli(1e12), MAX_COST_MILLI);
    }

    #[test]
    fn tracker_needs_forward_secrecy_and_ten_stable_seconds() {
        let t0 = Instant::now();
        let mut t = LinkTracker::new(t0);
        let good = LinkReport {
            up: true,
            forward_secrecy: true,
            rtt_ms: Some(20.0),
            loss: Some(0.0),
            jitter_ms: Some(1.0),
            utilization: None,
        };
        assert!(!t.update(good, t0));
        assert!(!t.usable());
        assert!(t.cost().is_none());
        assert!(!t.update(good, t0 + ms(9_999)));
        assert!(t.update(good, t0 + ms(10_000)));
        assert!(t.usable());
        assert_eq!(t.cost(), Some(22.0));
        // Losing forward secrecy makes it unusable at once and alerts.
        let insecure = LinkReport {
            forward_secrecy: false,
            ..good
        };
        assert!(t.update(insecure, t0 + ms(11_000)));
        assert!(t.insecure());
        assert!(t.cost().is_none());
        assert!(
            t.probe_due(t0 + ms(11_000)).is_none(),
            "no probes on an insecure link"
        );
        // Back to good: another ten seconds.
        t.update(good, t0 + ms(12_000));
        assert!(!t.usable());
        t.update(good, t0 + ms(22_000));
        assert!(t.usable());
    }

    #[test]
    fn probes_are_sent_once_a_second_only_when_needed() {
        let t0 = Instant::now();
        let mut t = LinkTracker::new(t0);
        let report = LinkReport {
            up: true,
            forward_secrecy: true,
            rtt_ms: Some(20.0),
            loss: Some(0.0),
            jitter_ms: None,
            utilization: None,
        };
        t.update(report, t0);
        assert!(t.probe_due(t0).is_some());
        assert!(t.probe_due(t0 + ms(999)).is_none());
        assert!(t.probe_due(t0 + ms(1000)).is_some());
        let full = LinkReport {
            jitter_ms: Some(1.0),
            ..report
        };
        t.update(full, t0 + ms(2000));
        assert!(t.probe_due(t0 + ms(3000)).is_none());
    }
}
