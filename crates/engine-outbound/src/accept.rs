//! Accept loops that outlive transient `accept` errors.
//!
//! `accept(2)` fails for reasons that concern one connection (the client
//! reset it before it was taken: `ECONNABORTED` on macOS and iOS,
//! `WSAECONNRESET` on Windows) or the whole process for a moment (out of
//! file descriptors, memory or socket buffers: `EMFILE`, `ENFILE`,
//! `ENOMEM`, `ENOBUFS`). Neither means the listener is gone, so a serve loop
//! that returned on them would stop a local proxy for good after one reset
//! or one burst of open files. [`accept`] takes the next connection at once
//! after the first kind and after a growing pause ([`AcceptBackoff`]) after
//! the second, so it never spins while descriptors stay exhausted, and
//! returns only errors that mean the listening socket itself is unusable.

use std::future::Future;
use std::io;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

/// First pause after an error that is not about one connection.
pub const MIN_BACKOFF: Duration = Duration::from_millis(50);
/// Longest pause between attempts while such errors go on.
pub const MAX_BACKOFF: Duration = Duration::from_secs(1);
/// Connection errors in a row after which [`accept`] pauses as well, so a
/// platform that reports a lasting condition as a connection error cannot
/// make the loop spin.
const CONNECTION_ERROR_STREAK: u32 = 64;

/// What an `accept` error means for the loop.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AcceptError {
    /// It concerns one connection, which is gone: take the next one now.
    Connection,
    /// The process is short of descriptors, memory or buffers, or the
    /// cause is unknown: wait a little and try again.
    Resources,
    /// The listening socket itself is unusable: stop serving.
    Listener,
}

/// Sorts an error of `TcpListener::accept`.
pub fn classify(error: &io::Error) -> AcceptError {
    if is_unusable_listener(error) {
        return AcceptError::Listener;
    }
    match error.kind() {
        io::ErrorKind::ConnectionAborted
        | io::ErrorKind::ConnectionReset
        | io::ErrorKind::ConnectionRefused
        | io::ErrorKind::Interrupted
        | io::ErrorKind::TimedOut
        // Linux: a firewall rule refused this one connection.
        | io::ErrorKind::PermissionDenied => AcceptError::Connection,
        // EINVAL: the socket is not listening (any more); EOPNOTSUPP: it is
        // not a stream socket.
        io::ErrorKind::InvalidInput | io::ErrorKind::Unsupported => AcceptError::Listener,
        // EMFILE, ENFILE, ENOBUFS, ENOMEM (OutOfMemory), network errors of
        // the new socket (EPROTO, ENETDOWN, ...) and anything unknown.
        _ => AcceptError::Resources,
    }
}

/// A descriptor that is not (or no longer) a socket.
fn is_unusable_listener(error: &io::Error) -> bool {
    error.raw_os_error().is_some_and(is_unusable_code)
}

/// EBADF (9 on every Unix) and ENOTSOCK.
#[cfg(unix)]
fn is_unusable_code(code: i32) -> bool {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    const ENOTSOCK: i32 = 88;
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    const ENOTSOCK: i32 = 38;
    code == 9 || code == ENOTSOCK
}

/// WSAEBADF, WSAEINVAL and WSAENOTSOCK.
#[cfg(windows)]
fn is_unusable_code(code: i32) -> bool {
    matches!(code, 10009 | 10022 | 10038)
}

#[cfg(not(any(unix, windows)))]
fn is_unusable_code(_code: i32) -> bool {
    false
}

/// The pause before the next attempt after an error: [`MIN_BACKOFF`],
/// doubling up to [`MAX_BACKOFF`], back to the start after a connection is
/// accepted.
#[derive(Debug)]
pub struct AcceptBackoff {
    next: Duration,
    streak: u32,
}

impl Default for AcceptBackoff {
    fn default() -> Self {
        Self {
            next: MIN_BACKOFF,
            streak: 0,
        }
    }
}

impl AcceptBackoff {
    /// A connection was accepted.
    pub fn reset(&mut self) {
        *self = Self::default();
    }

    /// How long to wait after `error`; `None` to try again at once.
    pub fn after(&mut self, error: AcceptError) -> Option<Duration> {
        if error == AcceptError::Connection {
            self.streak = self.streak.saturating_add(1);
            if self.streak <= CONNECTION_ERROR_STREAK {
                return None;
            }
        }
        let delay = self.next;
        self.next = (delay * 2).min(MAX_BACKOFF);
        Some(delay)
    }
}

/// Runs `attempt` (one `listener.accept()`) until it yields a connection.
/// Each error is counted in `errors`; errors of one connection are skipped,
/// others are retried after the pause of `backoff`. Returns an error only
/// when the listener is unusable ([`AcceptError::Listener`]).
pub async fn accept<T, F, Fut>(
    mut attempt: F,
    backoff: &mut AcceptBackoff,
    errors: Option<&AtomicU64>,
) -> io::Result<T>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = io::Result<T>>,
{
    loop {
        match attempt().await {
            Ok(accepted) => {
                backoff.reset();
                return Ok(accepted);
            }
            Err(error) => {
                if let Some(errors) = errors {
                    errors.fetch_add(1, Ordering::Relaxed);
                }
                let kind = classify(&error);
                if kind == AcceptError::Listener {
                    return Err(error);
                }
                match backoff.after(kind) {
                    Some(delay) => tokio::time::sleep(delay).await,
                    // Let the connections already accepted run first.
                    None => tokio::task::yield_now().await,
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::sync::Mutex;

    fn os_error(kind: io::ErrorKind) -> io::Error {
        io::Error::new(kind, "test")
    }

    #[test]
    fn errors_are_sorted_by_what_they_mean_for_the_listener() {
        for kind in [
            io::ErrorKind::ConnectionAborted,
            io::ErrorKind::ConnectionReset,
            io::ErrorKind::Interrupted,
        ] {
            assert_eq!(classify(&os_error(kind)), AcceptError::Connection);
        }
        assert_eq!(
            classify(&os_error(io::ErrorKind::OutOfMemory)),
            AcceptError::Resources
        );
        assert_eq!(
            classify(&io::Error::other("unknown")),
            AcceptError::Resources
        );
        assert_eq!(
            classify(&os_error(io::ErrorKind::InvalidInput)),
            AcceptError::Listener
        );
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[test]
    fn descriptor_exhaustion_is_retried_and_a_bad_descriptor_stops() {
        // EMFILE, ENFILE, ENOBUFS.
        for code in [24, 23, 105] {
            let error = io::Error::from_raw_os_error(code);
            assert_eq!(classify(&error), AcceptError::Resources, "errno {code}");
        }
        // ECONNABORTED.
        assert_eq!(
            classify(&io::Error::from_raw_os_error(103)),
            AcceptError::Connection
        );
        // EBADF, ENOTSOCK, EINVAL.
        for code in [9, 88, 22] {
            let error = io::Error::from_raw_os_error(code);
            assert_eq!(classify(&error), AcceptError::Listener, "errno {code}");
        }
    }

    #[cfg(windows)]
    #[test]
    fn a_reset_before_accept_is_skipped_on_windows() {
        // WSAECONNRESET, WSAEMFILE, WSAENOBUFS, WSAENOTSOCK.
        assert_eq!(
            classify(&io::Error::from_raw_os_error(10054)),
            AcceptError::Connection
        );
        assert_eq!(
            classify(&io::Error::from_raw_os_error(10024)),
            AcceptError::Resources
        );
        assert_eq!(
            classify(&io::Error::from_raw_os_error(10055)),
            AcceptError::Resources
        );
        assert_eq!(
            classify(&io::Error::from_raw_os_error(10038)),
            AcceptError::Listener
        );
    }

    #[test]
    fn the_pause_doubles_up_to_the_limit_and_restarts_after_a_connection() {
        let mut backoff = AcceptBackoff::default();
        let delays: Vec<_> = (0..7)
            .map(|_| backoff.after(AcceptError::Resources).unwrap())
            .collect();
        assert_eq!(delays[0], MIN_BACKOFF);
        assert_eq!(delays[1], MIN_BACKOFF * 2);
        assert_eq!(*delays.last().unwrap(), MAX_BACKOFF);
        assert!(delays.windows(2).all(|pair| pair[0] <= pair[1]));
        backoff.reset();
        assert_eq!(backoff.after(AcceptError::Resources), Some(MIN_BACKOFF));
    }

    #[test]
    fn a_long_run_of_connection_errors_pauses_too() {
        let mut backoff = AcceptBackoff::default();
        for _ in 0..CONNECTION_ERROR_STREAK {
            assert_eq!(backoff.after(AcceptError::Connection), None);
        }
        assert_eq!(backoff.after(AcceptError::Connection), Some(MIN_BACKOFF));
    }

    /// An `accept` that returns the scripted results in order.
    struct Script(Mutex<VecDeque<io::Result<u32>>>);

    impl Script {
        fn new(results: Vec<io::Result<u32>>) -> Self {
            Self(Mutex::new(results.into()))
        }

        async fn next(&self) -> io::Result<u32> {
            self.0
                .lock()
                .unwrap()
                .pop_front()
                .unwrap_or_else(|| Err(os_error(io::ErrorKind::InvalidInput)))
        }
    }

    #[tokio::test(start_paused = true)]
    async fn transient_errors_are_survived_with_a_pause_for_exhaustion() {
        let script = Script::new(vec![
            Err(os_error(io::ErrorKind::ConnectionAborted)),
            Err(os_error(io::ErrorKind::ConnectionReset)),
            Ok(1),
            Err(io::Error::other("out of descriptors")),
            Err(io::Error::other("out of descriptors")),
            Err(io::Error::other("out of descriptors")),
            Ok(2),
            Err(os_error(io::ErrorKind::InvalidInput)),
        ]);
        let errors = AtomicU64::new(0);
        let mut backoff = AcceptBackoff::default();

        let started = tokio::time::Instant::now();
        let first = accept(|| script.next(), &mut backoff, Some(&errors)).await;
        assert_eq!(first.unwrap(), 1);
        assert_eq!(started.elapsed(), Duration::ZERO, "no pause for resets");

        let started = tokio::time::Instant::now();
        let second = accept(|| script.next(), &mut backoff, Some(&errors)).await;
        assert_eq!(second.unwrap(), 2);
        // 50 + 100 + 200 ms: the loop waited instead of spinning.
        assert_eq!(started.elapsed(), Duration::from_millis(350));

        let stopped = accept(|| script.next(), &mut backoff, Some(&errors)).await;
        assert_eq!(stopped.unwrap_err().kind(), io::ErrorKind::InvalidInput);
        assert_eq!(errors.load(Ordering::Relaxed), 6);
    }
}
