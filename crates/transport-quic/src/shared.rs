//! A QUIC connection shared by many proxied flows that can be retired
//! instead of closed.
//!
//! QUIC-based outbounds (Hysteria2, TUIC) keep one connection for all their
//! flows. After a network change or a wake from sleep the engine asks them
//! to stop reusing it ([`engine_outbound::TcpOutbound::reset_sessions`]),
//! but flows already open on it must be left alone: a short sleep on the
//! same network keeps the path working, and the engine closes those flows
//! itself when it means to. [`Shared::retire`] therefore only marks the
//! connection; it is closed when the last [`Hold`] on it goes, or at once
//! when nothing holds it. A connection whose path really died ends on its
//! own by the idle timeout (keep-alives go unanswered).
//!
//! Every flow (a stream, a UDP session) keeps a [`Hold`]; the outbound's
//! slot for the current connection keeps the [`Shared`] itself.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;

use crate::quinn;

/// Application close reason sent when a retired connection closes.
const RETIRED_REASON: &[u8] = b"network changed";

/// How long a retired connection stays open after its last flow ended, so
/// what that flow wrote last (a finished stream not yet acknowledged) is
/// still delivered before the connection closes.
const LINGER: std::time::Duration = std::time::Duration::from_secs(1);

/// `value` (an authenticated session) on `connection`, with a count of the
/// flows that use it.
pub struct Shared<T> {
    value: T,
    connection: quinn::Connection,
    users: AtomicUsize,
    retired: AtomicBool,
}

impl<T> Shared<T> {
    pub fn new(value: T, connection: quinn::Connection) -> Arc<Self> {
        Arc::new(Self {
            value,
            connection,
            users: AtomicUsize::new(0),
            retired: AtomicBool::new(false),
        })
    }

    pub fn value(&self) -> &T {
        &self.value
    }

    pub fn connection(&self) -> &quinn::Connection {
        &self.connection
    }

    /// A hold for one flow: the connection stays open while it lives.
    pub fn hold(self: &Arc<Self>) -> Hold<T> {
        self.users.fetch_add(1, Ordering::SeqCst);
        Hold(self.clone())
    }

    /// How many flows hold the connection.
    pub fn users(&self) -> usize {
        self.users.load(Ordering::SeqCst)
    }

    /// Whether [`Shared::retire`] was called.
    pub fn is_retired(&self) -> bool {
        self.retired.load(Ordering::SeqCst)
    }

    /// Stops new flows from being expected on the connection: it closes
    /// now if no flow holds it, else when the last [`Hold`] goes.
    pub fn retire(&self) {
        self.retired.store(true, Ordering::SeqCst);
        if self.users.load(Ordering::SeqCst) == 0 {
            self.close();
        }
    }

    /// Closes the connection at once, whatever holds it. Closing twice is
    /// harmless.
    pub fn close(&self) {
        self.connection.close(0u32.into(), RETIRED_REASON);
    }
}

/// Keeps a [`Shared`] connection, and the session it carries, alive for one
/// flow. Dropping the last hold of a retired connection closes it, a
/// second later so the flow's last data is delivered.
pub struct Hold<T>(Arc<Shared<T>>);

impl<T> Hold<T> {
    pub fn shared(&self) -> &Arc<Shared<T>> {
        &self.0
    }
}

impl<T> Drop for Hold<T> {
    fn drop(&mut self) {
        // Sequentially consistent with `retire`: of a last hold going and a
        // retirement racing, at least one sees the other and closes.
        if self.0.users.fetch_sub(1, Ordering::SeqCst) == 1 && self.0.is_retired() {
            let connection = self.0.connection.clone();
            match tokio::runtime::Handle::try_current() {
                Ok(runtime) => {
                    runtime.spawn(async move {
                        tokio::time::sleep(LINGER).await;
                        connection.close(0u32.into(), RETIRED_REASON);
                    });
                }
                Err(_) => connection.close(0u32.into(), RETIRED_REASON),
            }
        }
    }
}
