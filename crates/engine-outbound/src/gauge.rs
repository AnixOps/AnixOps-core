//! Counters of live things that cannot drift.
//!
//! A gauge such as "connections open" that is raised when a task starts and
//! lowered after its work returns stays raised for good when that work
//! panics or the task is aborted. [`Gauge`] lowers it when it is dropped,
//! which unwinding and cancellation do too.

use std::sync::atomic::{AtomicU64, Ordering};

/// Holds one unit of a gauge counter while it lives.
#[must_use = "the gauge is lowered again when this is dropped"]
pub struct Gauge<'a> {
    counter: &'a AtomicU64,
}

impl<'a> Gauge<'a> {
    /// Raises `counter` by one until the returned guard is dropped.
    pub fn hold(counter: &'a AtomicU64) -> Self {
        counter.fetch_add(1, Ordering::Relaxed);
        Self { counter }
    }
}

impl Drop for Gauge<'_> {
    fn drop(&mut self) {
        self.counter.fetch_sub(1, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lowers_on_drop_and_on_unwind() {
        let counter = AtomicU64::new(0);
        {
            let _one = Gauge::hold(&counter);
            let _two = Gauge::hold(&counter);
            assert_eq!(counter.load(Ordering::Relaxed), 2);
        }
        assert_eq!(counter.load(Ordering::Relaxed), 0);
        let unwound = std::panic::catch_unwind(|| {
            let _held = Gauge::hold(&counter);
            panic!("the work panicked");
        });
        assert!(unwound.is_err());
        assert_eq!(counter.load(Ordering::Relaxed), 0);
    }
}
