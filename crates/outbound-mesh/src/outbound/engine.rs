//! The mesh engine of an embedding program: the [`Registry`] of its
//! networks and a runtime of its own, on a thread of its own, that every
//! driver runs on.
//!
//! A profile is one engine runtime, and the client starts a new one for
//! each profile it hands over; the networks must outlive that switch
//! (`mesh-status.md`, 隧道生命周期). So the mesh engine lives in an
//! [`EngineSlot`]: each runtime with mesh outbounds holds it while it runs.
//! When the last holder lets go, the engine stops after a grace period,
//! long enough for the next profile to take it over whichever order the
//! client stops and starts them in, or at once when the client says the
//! VPN is closing. A stopped engine retires every network and ends its
//! thread.

use std::io;
use std::sync::{Arc, Mutex, MutexGuard};
use std::thread::JoinHandle;
use std::time::Duration;

use tokio::runtime::Handle;
use tokio::sync::oneshot;

use super::registry::Registry;

/// How long the engine waits for a new holder after the last one let go.
pub const GRACE: Duration = Duration::from_secs(5);

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

pub struct MeshEngine {
    registry: Registry,
    runtime: Handle,
    stop: Mutex<Option<oneshot::Sender<()>>>,
    thread: Mutex<Option<JoinHandle<()>>>,
}

impl MeshEngine {
    /// Starts the engine's runtime on a thread of its own.
    pub fn start() -> io::Result<Arc<Self>> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        let handle = runtime.handle().clone();
        let (stop, stopped) = oneshot::channel::<()>();
        let thread = std::thread::Builder::new()
            .name("networkcore-mesh".into())
            .spawn(move || {
                runtime.block_on(async {
                    let _ = stopped.await;
                });
                // The tasks left (retired drivers, a pump) end with the
                // runtime.
                drop(runtime);
            })?;
        Ok(Arc::new(Self {
            registry: Registry::new(handle.clone()),
            runtime: handle,
            stop: Mutex::new(Some(stop)),
            thread: Mutex::new(Some(thread)),
        }))
    }

    pub fn registry(&self) -> &Registry {
        &self.registry
    }

    /// Retires every network, then ends the runtime and its thread.
    /// Idempotent. Called on the engine's own thread (by the grace timer),
    /// it does not wait for the thread, which ends as soon as the calling
    /// task returns.
    pub fn stop(&self) {
        self.registry.shutdown();
        if let Some(stop) = lock(&self.stop).take() {
            let _ = stop.send(());
        }
        if let Some(thread) = lock(&self.thread).take() {
            if thread.thread().id() != std::thread::current().id() {
                let _ = thread.join();
            }
        }
    }

    /// Whether [`Self::stop`] ran.
    pub fn is_stopped(&self) -> bool {
        lock(&self.stop).is_none()
    }
}

impl Drop for MeshEngine {
    fn drop(&mut self) {
        self.stop();
    }
}

#[derive(Default)]
struct SlotState {
    engine: Option<Arc<MeshEngine>>,
    holders: usize,
    /// Changes at every acquire and release, so that a grace timer only
    /// stops the engine when nothing happened since it was set.
    generation: u64,
}

/// Where the engine of a process lives: started by the first holder,
/// stopped after the last one.
pub struct EngineSlot {
    grace: Duration,
    state: Mutex<SlotState>,
}

impl EngineSlot {
    pub const fn new(grace: Duration) -> Self {
        Self {
            grace,
            state: Mutex::new(SlotState {
                engine: None,
                holders: 0,
                generation: 0,
            }),
        }
    }

    /// Holds the engine, starting it if none runs, and cancels a pending
    /// stop. Every acquire needs one [`Self::release`].
    pub fn acquire(&self) -> io::Result<Arc<MeshEngine>> {
        let mut state = lock(&self.state);
        state.generation += 1;
        let engine = match &state.engine {
            Some(engine) => engine.clone(),
            None => {
                let engine = MeshEngine::start()?;
                state.engine = Some(engine.clone());
                engine
            }
        };
        state.holders += 1;
        Ok(engine)
    }

    /// The running engine, without holding it.
    pub fn current(&self) -> Option<Arc<MeshEngine>> {
        lock(&self.state).engine.clone()
    }

    /// Lets go of the engine. After the last holder the engine stops once
    /// the grace period passes without a new one, or at once with `now`
    /// (the user closed the VPN).
    pub fn release(&'static self, now: bool) {
        let mut state = lock(&self.state);
        state.holders = state.holders.saturating_sub(1);
        if state.holders > 0 {
            return;
        }
        state.generation += 1;
        let generation = state.generation;
        if now {
            let engine = state.engine.take();
            drop(state);
            if let Some(engine) = engine {
                engine.stop();
            }
            return;
        }
        let Some(engine) = state.engine.clone() else {
            return;
        };
        drop(state);
        let grace = self.grace;
        // On the engine's own thread, which runs as long as the engine.
        engine.runtime.spawn(async move {
            tokio::time::sleep(grace).await;
            self.expire(generation);
        });
    }

    /// Stops the engine if nothing acquired or released it since the
    /// release that set `generation`. The check and the take happen under
    /// the one lock `acquire` takes, so an engine a new holder just took
    /// is never stopped.
    fn expire(&self, generation: u64) {
        let engine = {
            let mut state = lock(&self.state);
            if state.holders > 0 || state.generation != generation {
                return;
            }
            state.engine.take()
        };
        if let Some(engine) = engine {
            engine.stop();
        }
    }

    #[cfg(test)]
    fn generation(&self) -> u64 {
        lock(&self.state).generation
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn slot(grace: Duration) -> &'static EngineSlot {
        Box::leak(Box::new(EngineSlot::new(grace)))
    }

    #[test]
    fn a_new_holder_within_the_grace_period_keeps_the_engine() {
        let slot = slot(Duration::from_millis(300));
        let engine = slot.acquire().unwrap();
        slot.release(false);
        let again = slot.acquire().unwrap();
        assert!(Arc::ptr_eq(&engine, &again));
        std::thread::sleep(Duration::from_millis(900));
        assert!(!engine.is_stopped());
        assert!(slot.current().is_some());
        slot.release(false);
        std::thread::sleep(Duration::from_millis(900));
        assert!(engine.is_stopped());
        assert!(slot.current().is_none());
        // The next holder starts a new engine.
        let next = slot.acquire().unwrap();
        assert!(!Arc::ptr_eq(&engine, &next));
        slot.release(true);
        assert!(next.is_stopped());
    }

    #[test]
    fn a_timer_set_before_a_new_holder_does_not_stop_its_engine() {
        // A long grace period: the timers never fire, the test calls
        // `expire` itself.
        let slot = slot(Duration::from_secs(3600));
        let engine = slot.acquire().unwrap();
        slot.release(false);
        let stale = slot.generation();
        // A new profile takes the engine over just as the timer fires.
        let _again = slot.acquire().unwrap();
        slot.expire(stale);
        assert!(!engine.is_stopped());
        assert!(slot.current().is_some());
        // Released again: only the newest timer counts.
        slot.release(false);
        slot.expire(stale);
        assert!(!engine.is_stopped());
        slot.expire(slot.generation());
        assert!(engine.is_stopped());
        assert!(slot.current().is_none());
    }

    #[test]
    fn closing_the_vpn_stops_the_engine_at_once() {
        let slot = slot(Duration::from_secs(3600));
        let engine = slot.acquire().unwrap();
        let _second = slot.acquire().unwrap();
        slot.release(true);
        // Another runtime still holds it.
        assert!(!engine.is_stopped());
        slot.release(true);
        assert!(engine.is_stopped());
        assert!(slot.current().is_none());
    }
}
