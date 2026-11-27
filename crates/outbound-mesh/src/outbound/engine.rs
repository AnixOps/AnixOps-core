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
use std::net::IpAddr;
use std::sync::{Arc, Mutex, MutexGuard, Weak};
use std::thread::JoinHandle;
use std::time::Duration;

use tokio::runtime::Handle;
use tokio::sync::{oneshot, Notify};

use super::registry::Registry;
use crate::IpNet;

/// Reads the networks of this machine's interfaces, leaving out the
/// interface that carries any of the given addresses (the tunnel's own);
/// `None` when they cannot be read. A blocking call.
pub type LocalReader = Arc<dyn Fn(&[IpAddr]) -> Option<Vec<IpNet>> + Send + Sync>;

/// When this machine's networks are read (spec §15.4): again every
/// `every` once read, every `retry` until then, each read cut off after
/// `limit` (it may go on in the background; the next one waits for it).
#[derive(Clone, Copy, Debug)]
pub struct LocalTiming {
    pub retry: Duration,
    pub every: Duration,
    pub limit: Duration,
}

/// The timing of spec §15.4.
pub const LOCAL_TIMING: LocalTiming = LocalTiming {
    retry: Duration::from_secs(5),
    every: Duration::from_secs(30),
    limit: Duration::from_secs(10),
};

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
    /// Wakes the reader of this machine's networks, once it runs.
    reader: Mutex<Option<Arc<Notify>>>,
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
                // runtime. A peer name still resolving on the blocking
                // pool is not waited for: closing the VPN must not hang
                // on a slow resolver.
                runtime.shutdown_background();
            })?;
        Ok(Arc::new(Self {
            registry: Registry::new(handle.clone()),
            runtime: handle,
            stop: Mutex::new(Some(stop)),
            thread: Mutex::new(Some(thread)),
            reader: Mutex::new(None),
        }))
    }

    pub fn registry(&self) -> &Registry {
        &self.registry
    }

    /// Starts reading this machine's networks with `read` on the engine's
    /// own runtime, off every caller's thread, on [`LOCAL_TIMING`]; the
    /// registry gets each read that succeeds. A failed read keeps the
    /// networks read last. Once started, later calls change nothing.
    /// Whether this call started it.
    pub fn read_local_networks(self: &Arc<Self>, read: LocalReader) -> bool {
        self.read_local_networks_with(read, LOCAL_TIMING)
    }

    /// [`Self::read_local_networks`] on `timing`.
    pub fn read_local_networks_with(
        self: &Arc<Self>,
        read: LocalReader,
        timing: LocalTiming,
    ) -> bool {
        let mut reader = lock(&self.reader);
        if reader.is_some() {
            return false;
        }
        let now = Arc::new(Notify::new());
        *reader = Some(now.clone());
        self.runtime
            .spawn(read_local(Arc::downgrade(self), read, now, timing));
        true
    }

    /// Reads this machine's networks again (the tunnel started, the client
    /// reported a network change): at once, or right after the read under
    /// way; a read cut off by its time limit and still running is not
    /// stacked on, and the next scheduled round tries again.
    pub fn reread_local_networks(&self) {
        if let Some(now) = &*lock(&self.reader) {
            now.notify_one();
        }
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

/// Reads this machine's networks until the engine is gone (spec §15.4):
/// one read at a time, so that a slow one is not stacked on.
async fn read_local(
    engine: Weak<MeshEngine>,
    read: LocalReader,
    now: Arc<Notify>,
    timing: LocalTiming,
) {
    let mut pending: Option<tokio::task::JoinHandle<Option<Vec<IpNet>>>> = None;
    let mut known = false;
    loop {
        if pending.as_ref().is_none_or(|read| read.is_finished()) {
            let Some(own) = engine
                .upgrade()
                .map(|engine| engine.registry.own_addresses())
            else {
                return;
            };
            let read = read.clone();
            let mut handle = tokio::task::spawn_blocking(move || read(&own));
            pending = match tokio::time::timeout(timing.limit, &mut handle).await {
                Ok(Ok(Some(found))) => {
                    let Some(engine) = engine.upgrade() else {
                        return;
                    };
                    engine.registry.set_local_networks(found);
                    known = true;
                    None
                }
                // Failed: the networks read last stay.
                Ok(_) => None,
                // Too slow: not waited for, not read again before it ends.
                Err(_) => Some(handle),
            };
        }
        let wait = if known { timing.every } else { timing.retry };
        tokio::select! {
            () = tokio::time::sleep(wait) => {}
            () = now.notified() => {}
        }
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
    /// stop. Dropping the hold lets go of it; [`EngineHold::close`] lets
    /// go and stops the engine at once if it was the last hold.
    pub fn acquire(&'static self) -> io::Result<EngineHold> {
        let engine = self.take_hold()?;
        Ok(EngineHold {
            slot: self,
            engine,
            released: false,
        })
    }

    fn take_hold(&self) -> io::Result<Arc<MeshEngine>> {
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
    fn release(&'static self, now: bool) {
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
    fn holders(&self) -> usize {
        lock(&self.state).holders
    }

    #[cfg(test)]
    fn generation(&self) -> u64 {
        lock(&self.state).generation
    }
}

/// One holder's hold on the engine; see [`EngineSlot::acquire`]. Each
/// hold is let go exactly once, so one holder cannot release another's.
pub struct EngineHold {
    slot: &'static EngineSlot,
    engine: Arc<MeshEngine>,
    released: bool,
}

impl EngineHold {
    pub fn engine(&self) -> &Arc<MeshEngine> {
        &self.engine
    }

    /// Lets go and, if no other hold remains, stops the engine at once
    /// instead of after the grace period: the user closed the VPN.
    pub fn close(mut self) {
        self.released = true;
        self.slot.release(true);
    }
}

impl Drop for EngineHold {
    fn drop(&mut self) {
        if !self.released {
            self.slot.release(false);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Instant;

    /// Waits up to five seconds for `done`.
    fn wait_for(done: impl Fn() -> bool) {
        let deadline = Instant::now() + Duration::from_secs(5);
        while !done() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(5));
        }
        assert!(done(), "timed out");
    }

    #[test]
    fn this_machines_networks_are_read_again_and_a_failed_read_keeps_the_last() {
        let engine = MeshEngine::start().unwrap();
        let calls = Arc::new(AtomicUsize::new(0));
        let lan = IpNet::parse("192.168.1.0/24").unwrap();
        let read: LocalReader = {
            let calls = calls.clone();
            Arc::new(move |_own: &[IpAddr]| {
                match calls.fetch_add(1, Ordering::SeqCst) {
                    // Retried until it succeeds once, then failures keep it.
                    0 => None,
                    1 => Some(vec![lan]),
                    _ => None,
                }
            })
        };
        let timing = LocalTiming {
            retry: Duration::from_millis(10),
            every: Duration::from_millis(10),
            limit: Duration::from_secs(5),
        };
        assert_eq!(engine.registry().local_networks(), None);
        assert!(engine.read_local_networks_with(read, timing));
        wait_for(|| calls.load(Ordering::SeqCst) >= 4);
        assert_eq!(engine.registry().local_networks(), Some(vec![lan]));
        engine.stop();
    }

    #[test]
    fn a_slow_read_is_not_stacked_on() {
        let engine = MeshEngine::start().unwrap();
        let running = Arc::new(AtomicUsize::new(0));
        let most = Arc::new(AtomicUsize::new(0));
        let calls = Arc::new(AtomicUsize::new(0));
        let read: LocalReader = {
            let (running, most, calls) = (running.clone(), most.clone(), calls.clone());
            Arc::new(move |_own: &[IpAddr]| {
                calls.fetch_add(1, Ordering::SeqCst);
                let now = running.fetch_add(1, Ordering::SeqCst) + 1;
                most.fetch_max(now, Ordering::SeqCst);
                std::thread::sleep(Duration::from_millis(100));
                running.fetch_sub(1, Ordering::SeqCst);
                None
            })
        };
        let timing = LocalTiming {
            retry: Duration::from_millis(5),
            every: Duration::from_millis(5),
            limit: Duration::from_millis(20),
        };
        assert!(engine.read_local_networks_with(read, timing));
        wait_for(|| calls.load(Ordering::SeqCst) >= 3);
        assert_eq!(most.load(Ordering::SeqCst), 1);
        engine.stop();
    }

    #[test]
    fn a_read_is_asked_for_at_once_and_the_tunnel_is_left_out() {
        let engine = MeshEngine::start().unwrap();
        let calls = Arc::new(AtomicUsize::new(0));
        let seen = Arc::new(Mutex::new(Vec::new()));
        let read: LocalReader = {
            let (calls, seen) = (calls.clone(), seen.clone());
            Arc::new(move |own: &[IpAddr]| {
                calls.fetch_add(1, Ordering::SeqCst);
                *lock(&seen) = own.to_vec();
                Some(Vec::new())
            })
        };
        let timing = LocalTiming {
            retry: Duration::from_secs(3600),
            every: Duration::from_secs(3600),
            limit: Duration::from_secs(5),
        };
        let config: crate::MeshConfig = serde_json::from_value(serde_json::json!({
            "config_version": 1,
            "network": {"name": "office", "secret": "s3cr3t", "kind": "legacy"},
            "node": {"address": "10.157.0.2/24", "role": "access"},
            "peers": [{"server": "127.0.0.1", "port": 1}],
        }))
        .unwrap();
        engine.registry().commit(vec![config.validate().unwrap()]);
        assert!(engine.read_local_networks_with(read.clone(), timing));
        wait_for(|| calls.load(Ordering::SeqCst) == 1);
        // The reader is told the virtual addresses, so that it leaves out
        // the interface that carries them.
        assert!(lock(&seen).contains(&"10.157.0.2".parse::<IpAddr>().unwrap()));
        // Started once only.
        assert!(!engine.read_local_networks_with(read, timing));
        engine.reread_local_networks();
        wait_for(|| calls.load(Ordering::SeqCst) == 2);
        std::thread::sleep(Duration::from_millis(50));
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        engine.stop();
    }

    fn slot(grace: Duration) -> &'static EngineSlot {
        Box::leak(Box::new(EngineSlot::new(grace)))
    }

    #[test]
    fn a_new_holder_keeps_the_engine_and_the_last_one_stops_it() {
        // A long grace period: the timers never fire within the test, which
        // calls `expire` itself as the timer would.
        let slot = slot(Duration::from_secs(3600));
        let first = slot.acquire().unwrap();
        let engine = first.engine().clone();
        drop(first);
        let stale = slot.generation();
        // A new profile takes the engine over just as the timer fires.
        let again = slot.acquire().unwrap();
        assert!(Arc::ptr_eq(&engine, again.engine()));
        slot.expire(stale);
        assert!(!engine.is_stopped());
        assert!(slot.current().is_some());
        // Let go again: only the newest timer counts.
        drop(again);
        slot.expire(stale);
        assert!(!engine.is_stopped());
        slot.expire(slot.generation());
        assert!(engine.is_stopped());
        assert!(slot.current().is_none());
        // The next holder starts a new engine.
        let next = slot.acquire().unwrap();
        assert!(!Arc::ptr_eq(&engine, next.engine()));
        let next_engine = next.engine().clone();
        next.close();
        assert!(next_engine.is_stopped());
    }

    #[test]
    fn the_grace_timer_stops_the_engine_on_its_own_thread() {
        let slot = slot(Duration::from_millis(10));
        let hold = slot.acquire().unwrap();
        let engine = hold.engine().clone();
        drop(hold);
        // Generous: only the order matters, not the time.
        let deadline = std::time::Instant::now() + Duration::from_secs(30);
        while !engine.is_stopped() && std::time::Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(engine.is_stopped());
        assert!(slot.current().is_none());
    }

    #[test]
    fn closing_the_vpn_stops_the_engine_at_once() {
        let slot = slot(Duration::from_secs(3600));
        let first = slot.acquire().unwrap();
        let second = slot.acquire().unwrap();
        let engine = first.engine().clone();
        first.close();
        // Another runtime still holds it.
        assert!(!engine.is_stopped());
        assert_eq!(slot.holders(), 1);
        second.close();
        assert!(engine.is_stopped());
        assert!(slot.current().is_none());
        assert_eq!(slot.holders(), 0);
    }

    #[test]
    fn stopping_does_not_wait_for_a_name_still_resolving() {
        let slot = slot(Duration::from_secs(3600));
        let hold = slot.acquire().unwrap();
        let engine = hold.engine().clone();
        // A resolver call stuck on the blocking pool.
        engine
            .runtime
            .spawn_blocking(|| std::thread::sleep(Duration::from_secs(60)));
        let started = std::time::Instant::now();
        hold.close();
        assert!(engine.is_stopped());
        assert!(started.elapsed() < Duration::from_secs(30));
    }
}
