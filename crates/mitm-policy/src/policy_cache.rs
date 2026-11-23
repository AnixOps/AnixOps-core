//! Compiled forms of a loaded policy, kept per policy revision.
//!
//! Loading a policy into the core parses it and compiles every rule's
//! regex, which for large plugins costs far more than evaluating one
//! message. The data plane asks the same questions of the same policy for
//! every connection and message (is this host decrypted, does a Map Local
//! or header-block rule match), so each answer's compiled form is built once
//! per policy revision ([`PolicyFingerprint`]) and shared. A new revision
//! builds its own. The owner of a loaded policy releases its revision when it
//! stops using it ([`crate::CompiledPolicyRelease`]), so compiled forms live
//! only as long as their policy; the small capacity only bounds what callers
//! that never release keep.

use std::sync::{Arc, Mutex, MutexGuard};

use crate::{AnixOpsMitmPolicyEngine, PolicyFingerprint};
use control_domain::DomainResult;

/// An engine shared between threads. The core writes its last error into
/// the engine on every call, so one thread uses it at a time.
pub(crate) struct SharedEngine(Mutex<SendEngine>);

struct SendEngine(AnixOpsMitmPolicyEngine);

// SAFETY: the mitm_anixops C engine keeps all its state in the engine value,
// with no globals or thread-local data, so it may move between threads; the
// mutex hands it to one thread at a time.
unsafe impl Send for SendEngine {}

impl SharedEngine {
    pub(crate) fn new(engine: AnixOpsMitmPolicyEngine) -> Self {
        Self(Mutex::new(SendEngine(engine)))
    }

    /// Runs `f` with the engine. A panic in an earlier `f` leaves the
    /// engine usable: evaluation keeps no state between calls.
    pub(crate) fn with<R>(&self, f: impl FnOnce(&mut AnixOpsMitmPolicyEngine) -> R) -> R {
        let mut guard = self
            .0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        f(&mut guard.0)
    }
}

/// Compiled values keyed by policy revision, at most `capacity` revisions,
/// least recently used first out.
pub(crate) struct PolicyCache<T> {
    capacity: usize,
    entries: Mutex<Vec<(PolicyFingerprint, Arc<T>)>>,
}

impl<T> PolicyCache<T> {
    pub(crate) const fn new(capacity: usize) -> Self {
        Self {
            capacity,
            entries: Mutex::new(Vec::new()),
        }
    }

    /// The value compiled for `source`, built with `build` the first time.
    /// Building runs outside the lock, so other revisions are answered
    /// meanwhile; when two threads build the same revision at once, the
    /// first one stored is kept. A failed build is not stored.
    pub(crate) fn get_or_build(
        &self,
        source: &str,
        build: impl FnOnce(&str) -> DomainResult<T>,
    ) -> DomainResult<Arc<T>> {
        let policy = PolicyFingerprint::of(source);
        if let Some(found) = Self::take_recent(&mut self.lock(), policy) {
            return Ok(found);
        }
        let built = Arc::new(build(source)?);
        let mut entries = self.lock();
        if let Some(found) = Self::take_recent(&mut entries, policy) {
            return Ok(found);
        }
        entries.push((policy, built.clone()));
        while entries.len() > self.capacity.max(1) {
            entries.remove(0);
        }
        Ok(built)
    }

    /// Drops the value compiled for `policy`. Holders of its `Arc` keep
    /// theirs until they finish with it.
    pub(crate) fn remove(&self, policy: PolicyFingerprint) {
        let removed = {
            let mut entries = self.lock();
            let (removed, kept) = std::mem::take(&mut *entries)
                .into_iter()
                .partition::<Vec<_>, _>(|(key, _)| *key == policy);
            *entries = kept;
            removed
        };
        // Compiled values are freed outside the lock.
        drop(removed);
    }

    /// The entry for `policy`, moved to the most recently used end.
    fn take_recent(
        entries: &mut Vec<(PolicyFingerprint, Arc<T>)>,
        policy: PolicyFingerprint,
    ) -> Option<Arc<T>> {
        let index = entries.iter().position(|(key, _)| *key == policy)?;
        let entry = entries.remove(index);
        let found = entry.1.clone();
        entries.push(entry);
        Some(found)
    }

    fn lock(&self) -> MutexGuard<'_, Vec<(PolicyFingerprint, Arc<T>)>> {
        self.entries
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    #[test]
    fn a_revision_is_built_once_and_the_oldest_leaves_first() {
        let cache = PolicyCache::<String>::new(2);
        let builds = Cell::new(0);
        let get = |source: &str| {
            cache
                .get_or_build(source, |source| {
                    builds.set(builds.get() + 1);
                    Ok(source.to_uppercase())
                })
                .expect("build succeeds")
        };
        assert_eq!(*get("a"), "A");
        assert_eq!(*get("a"), "A");
        assert_eq!(builds.get(), 1);
        get("b");
        get("a"); // `a` is now the most recent
        get("c"); // drops `b`
        assert_eq!(builds.get(), 3);
        get("a");
        assert_eq!(builds.get(), 3, "`a` stayed");
        get("b");
        assert_eq!(builds.get(), 4, "`b` was dropped and is built again");
    }

    #[test]
    fn a_removed_revision_is_released_and_built_again() {
        let cache = PolicyCache::<String>::new(2);
        let builds = Cell::new(0);
        let get = |source: &str| {
            cache
                .get_or_build(source, |source| {
                    builds.set(builds.get() + 1);
                    Ok(source.to_uppercase())
                })
                .expect("build succeeds")
        };
        let held = get("a");
        get("b");
        cache.remove(PolicyFingerprint::of("a"));
        assert_eq!(cache.lock().len(), 1, "only `b` is kept");
        assert_eq!(*held, "A", "a holder keeps its value");
        get("b");
        assert_eq!(builds.get(), 2, "`b` stayed");
        get("a");
        assert_eq!(builds.get(), 3, "`a` was released");
    }

    #[test]
    fn a_failed_build_is_not_kept() {
        let cache = PolicyCache::<u8>::new(2);
        let failed = cache.get_or_build("x", |_| {
            Err(control_domain::DomainError::new("test.failed", "failed"))
        });
        assert!(failed.is_err());
        let built = cache.get_or_build("x", |_| Ok(7)).expect("second build");
        assert_eq!(*built, 7);
    }
}
