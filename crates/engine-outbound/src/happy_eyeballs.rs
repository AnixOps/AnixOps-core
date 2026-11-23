//! Connecting to a host that resolves to several addresses, in the manner
//! of RFC 8305 ("Happy Eyeballs").
//!
//! A proxy server's name often resolves to IPv6 and IPv4 addresses, and the
//! system resolver puts IPv6 first (RFC 6724). On a network whose IPv6 path
//! silently drops packets, trying the first address alone, or each address
//! in turn without a limit, stalls until the caller's overall timeout and
//! never reaches IPv4. This module:
//!
//! - orders the resolved addresses ([`sort_addresses`]): duplicates go,
//!   families alternate, and the family that last connected to the host
//!   goes first ([`remember`], [`preferred_family`]);
//! - tries them under a [`Schedule`] ([`connect`], [`connect_host`]): TCP
//!   starts the next attempt 250 ms after the previous one while that keeps
//!   running, and the first to succeed wins; QUIC tries one address at a
//!   time with a limit per attempt. The last attempt never has a limit of
//!   its own: it runs until the caller's overall timeout, so a slow but
//!   working path is not cut short.
//!
//! Attempts run inside the caller's task (no spawned tasks), so when the
//! caller's timeout drops the future every attempt still in flight is
//! dropped with it. UDP without a handshake has no success signal to race
//! on; it takes the first address of [`resolve`], which follows the family
//! TCP and QUIC last connected with.
//!
//! The remembered families are forgotten when the path out of the device
//! changes ([`crate::protect::path_generation`]) and when the engine resets
//! its sessions after a network change or wake ([`forget_families`]).

use std::collections::HashMap;
use std::future::{poll_fn, Future};
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::{Mutex, OnceLock};
use std::task::Poll;
use std::time::{Duration, Instant};

/// How long an attempt runs alone before the next address is tried as
/// well (RFC 8305 §5, "Connection Attempt Delay").
pub const CONNECTION_ATTEMPT_DELAY: Duration = Duration::from_millis(250);

/// The most TCP attempts in flight at once, so a name with many addresses
/// does not send a burst of SYNs.
pub const MAX_ATTEMPTS_IN_FLIGHT: usize = 4;

/// How long the family that last connected to a host stays preferred.
const FAMILY_TTL: Duration = Duration::from_secs(10 * 60);

/// Most hosts whose family is remembered; older entries are dropped first.
const MAX_REMEMBERED: usize = 1024;

/// An address family.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Family {
    V4,
    V6,
}

impl Family {
    pub fn of(address: &SocketAddr) -> Self {
        if address.is_ipv4() {
            Family::V4
        } else {
            Family::V6
        }
    }
}

/// When the next address is tried.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Schedule {
    /// The next attempt starts when the running ones have not finished
    /// within `delay`, or at once when one fails; earlier attempts keep
    /// running, at most `max_in_flight` at a time. For TCP.
    Staggered {
        delay: Duration,
        max_in_flight: usize,
    },
    /// One attempt at a time. An attempt that has not finished within
    /// `limit` is dropped for the next address, and one that fails moves
    /// on at once. The last attempt has no limit of its own. For
    /// handshakes that are costly to run twice (QUIC).
    Sequential { limit: Duration },
}

impl Schedule {
    /// RFC 8305 for TCP: 250 ms between attempts, at most
    /// [`MAX_ATTEMPTS_IN_FLIGHT`] at once.
    pub const TCP: Schedule = Schedule::Staggered {
        delay: CONNECTION_ATTEMPT_DELAY,
        max_in_flight: MAX_ATTEMPTS_IN_FLIGHT,
    };
}

/// `addresses` in the order to try them: duplicates dropped, then the two
/// families interleaved (RFC 8305 §4), each family keeping the resolver's
/// order. The first family is `preferred` when it has an address, else the
/// family of the resolver's first address. Nothing is ever dropped for its
/// family: on an IPv6-only network with NAT64 the only usable addresses
/// may all be IPv6.
pub fn sort_addresses(
    addresses: impl IntoIterator<Item = SocketAddr>,
    preferred: Option<Family>,
) -> Vec<SocketAddr> {
    let mut unique: Vec<SocketAddr> = Vec::new();
    for address in addresses {
        if !unique.contains(&address) {
            unique.push(address);
        }
    }
    let Some(first) = unique.first() else {
        return unique;
    };
    let (v6, v4): (Vec<SocketAddr>, Vec<SocketAddr>) =
        unique.iter().partition(|address| address.is_ipv6());
    let lead = match preferred {
        Some(Family::V6) if !v6.is_empty() => Family::V6,
        Some(Family::V4) if !v4.is_empty() => Family::V4,
        _ => Family::of(first),
    };
    let (primary, secondary) = match lead {
        Family::V6 => (v6, v4),
        Family::V4 => (v4, v6),
    };
    let mut sorted = Vec::with_capacity(unique.len());
    let mut primary = primary.into_iter();
    let mut secondary = secondary.into_iter();
    loop {
        match (primary.next(), secondary.next()) {
            (None, None) => break,
            (a, b) => sorted.extend(a.into_iter().chain(b)),
        }
    }
    sorted
}

/// The addresses of `host:port` from the system resolver, in the order to
/// try them ([`sort_addresses`] with the host's [`preferred_family`]).
/// Fails with [`io::ErrorKind::NotFound`] when there are none.
pub async fn resolve(host: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
    let found: Vec<SocketAddr> = tokio::net::lookup_host((host, port)).await?.collect();
    if found.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "host did not resolve to an address",
        ));
    }
    Ok(sort_addresses(found, preferred_family(host)))
}

/// Resolves `host:port` ([`resolve`]), tries its addresses under
/// `schedule` ([`connect`]) and remembers the family that connected.
pub async fn connect_host<T, F, Fut>(
    host: &str,
    port: u16,
    schedule: Schedule,
    attempt: F,
) -> io::Result<(SocketAddr, T)>
where
    F: FnMut(SocketAddr) -> Fut,
    Fut: Future<Output = io::Result<T>>,
{
    let addresses = resolve(host, port).await?;
    let (address, connected) = connect(&addresses, schedule, attempt).await?;
    remember(host, address);
    Ok((address, connected))
}

/// Runs `attempt` for `addresses` in order under `schedule` and returns the
/// first that succeeds with its address. Attempts still running when one
/// succeeds, or when the returned future is dropped, are dropped. When
/// every attempt fails, the error is the last one that was not a timeout,
/// else the last one.
pub async fn connect<T, F, Fut>(
    addresses: &[SocketAddr],
    schedule: Schedule,
    mut attempt: F,
) -> io::Result<(SocketAddr, T)>
where
    F: FnMut(SocketAddr) -> Fut,
    Fut: Future<Output = io::Result<T>>,
{
    enum Event<T> {
        Done(SocketAddr, io::Result<T>),
        Timer,
    }

    let Some(&first) = addresses.first() else {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "host did not resolve to an address",
        ));
    };
    let (delay, max_in_flight, abandon) = match schedule {
        Schedule::Staggered {
            delay,
            max_in_flight,
        } => (delay, max_in_flight.max(1), false),
        Schedule::Sequential { limit } => (limit, 1, true),
    };

    let mut running: Vec<(SocketAddr, Pin<Box<Fut>>)> = vec![(first, Box::pin(attempt(first)))];
    let mut next = 1;
    let mut timer = std::pin::pin!(tokio::time::sleep(delay));
    let mut failure: Option<io::Error> = None;
    // A timeout never replaces a more telling error (refused, unreachable).
    fn keep(error: io::Error, failure: &mut Option<io::Error>) {
        let is_timeout = error.kind() == io::ErrorKind::TimedOut;
        let had_other = failure
            .as_ref()
            .is_some_and(|kept| kept.kind() != io::ErrorKind::TimedOut);
        if !(is_timeout && had_other) {
            *failure = Some(error);
        }
    }

    loop {
        let event = poll_fn(|cx| {
            let finished = running
                .iter_mut()
                .enumerate()
                .find_map(|(index, (_, pending))| match pending.as_mut().poll(cx) {
                    Poll::Ready(result) => Some((index, result)),
                    Poll::Pending => None,
                });
            if let Some((index, result)) = finished {
                let (address, _) = running.swap_remove(index);
                return Poll::Ready(Event::Done(address, result));
            }
            // The timer only matters while there is an address left and
            // room to start it (or, sequentially, one to abandon for it).
            let can_start = next < addresses.len() && (abandon || running.len() < max_in_flight);
            if can_start && timer.as_mut().poll(cx).is_ready() {
                return Poll::Ready(Event::Timer);
            }
            Poll::Pending
        })
        .await;

        match event {
            Event::Done(address, Ok(connected)) => return Ok((address, connected)),
            Event::Done(_, Err(error)) => {
                keep(error, &mut failure);
                if next >= addresses.len() && running.is_empty() {
                    break;
                }
            }
            Event::Timer => {
                if abandon {
                    running.clear();
                    keep(
                        io::Error::new(io::ErrorKind::TimedOut, "connection attempt timed out"),
                        &mut failure,
                    );
                }
            }
        }
        // A failure or the timer starts the next address, if there is room.
        if next < addresses.len() && (abandon || running.len() < max_in_flight) {
            let address = addresses[next];
            next += 1;
            running.push((address, Box::pin(attempt(address))));
            timer.as_mut().reset(tokio::time::Instant::now() + delay);
        }
    }
    Err(failure.unwrap_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            "host did not resolve to an address",
        )
    }))
}

struct Remembered {
    family: Family,
    at: Instant,
    generation: u64,
}

fn remembered() -> &'static Mutex<HashMap<String, Remembered>> {
    static REMEMBERED: OnceLock<Mutex<HashMap<String, Remembered>>> = OnceLock::new();
    REMEMBERED.get_or_init(|| Mutex::new(HashMap::new()))
}

fn is_literal(host: &str) -> bool {
    host.trim_start_matches('[')
        .trim_end_matches(']')
        .parse::<IpAddr>()
        .is_ok()
}

/// Notes that `host` connected over `address`'s family, so the next
/// connection to it tries that family first. Address literals are not
/// remembered.
pub fn remember(host: &str, address: SocketAddr) {
    if is_literal(host) {
        return;
    }
    let mut map = remembered()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if map.len() >= MAX_REMEMBERED && !map.contains_key(host) {
        let generation = crate::protect::path_generation();
        map.retain(|_, entry| entry.generation == generation && entry.at.elapsed() < FAMILY_TTL);
        if map.len() >= MAX_REMEMBERED {
            map.clear();
        }
    }
    map.insert(
        host.to_ascii_lowercase(),
        Remembered {
            family: Family::of(&address),
            at: Instant::now(),
            generation: crate::protect::path_generation(),
        },
    );
}

/// The family `host` last connected with on the current path, if that was
/// within the last ten minutes.
pub fn preferred_family(host: &str) -> Option<Family> {
    let map = remembered()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let entry = map.get(&host.to_ascii_lowercase())?;
    (entry.generation == crate::protect::path_generation() && entry.at.elapsed() < FAMILY_TTL)
        .then_some(entry.family)
}

/// Forgets every remembered family, after the device changed networks or
/// woke from sleep.
pub fn forget_families() {
    remembered()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .clear();
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    fn a(text: &str) -> SocketAddr {
        text.parse().unwrap()
    }

    #[test]
    fn families_alternate_from_the_resolvers_first() {
        let sorted = sort_addresses(
            [
                a("[2001:db8::1]:443"),
                a("[2001:db8::2]:443"),
                a("192.0.2.1:443"),
                a("192.0.2.2:443"),
                a("192.0.2.3:443"),
            ],
            None,
        );
        assert_eq!(
            sorted,
            vec![
                a("[2001:db8::1]:443"),
                a("192.0.2.1:443"),
                a("[2001:db8::2]:443"),
                a("192.0.2.2:443"),
                a("192.0.2.3:443"),
            ]
        );
    }

    #[test]
    fn one_family_keeps_its_order_and_duplicates_go() {
        let sorted = sort_addresses(
            [a("192.0.2.2:443"), a("192.0.2.1:443"), a("192.0.2.2:443")],
            Some(Family::V6),
        );
        assert_eq!(sorted, vec![a("192.0.2.2:443"), a("192.0.2.1:443")]);
        assert!(sort_addresses([], None).is_empty());
    }

    #[test]
    fn the_preferred_family_leads_but_nothing_is_dropped() {
        let sorted = sort_addresses(
            [
                a("[2001:db8::1]:443"),
                a("[2001:db8::2]:443"),
                a("192.0.2.1:443"),
            ],
            Some(Family::V4),
        );
        assert_eq!(
            sorted,
            vec![
                a("192.0.2.1:443"),
                a("[2001:db8::1]:443"),
                a("[2001:db8::2]:443"),
            ]
        );
    }

    #[test]
    fn remembered_families_follow_the_host_and_can_be_forgotten() {
        // Other tests move the path generation, which forgets families.
        let _serial = crate::protect::TEST_SERIAL
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        remember("Family.Example", a("192.0.2.1:443"));
        assert_eq!(preferred_family("family.example"), Some(Family::V4));
        remember("family.example", a("[2001:db8::1]:443"));
        assert_eq!(preferred_family("family.example"), Some(Family::V6));
        // Literals are their own family; nothing is kept for them.
        remember("192.0.2.9", a("192.0.2.9:443"));
        assert_eq!(preferred_family("192.0.2.9"), None);
        forget_families();
        assert_eq!(preferred_family("family.example"), None);
    }

    #[tokio::test(start_paused = true)]
    async fn a_stalled_first_address_hands_over_after_the_delay() {
        let addresses = [a("[2001:db8::1]:443"), a("192.0.2.1:443")];
        let began = tokio::time::Instant::now();
        let (winner, value) = connect(&addresses, Schedule::TCP, |address| async move {
            if address.is_ipv6() {
                std::future::pending::<()>().await;
            }
            Ok::<_, io::Error>(address.port())
        })
        .await
        .unwrap();
        assert_eq!(winner, a("192.0.2.1:443"));
        assert_eq!(value, 443);
        assert_eq!(began.elapsed(), CONNECTION_ATTEMPT_DELAY);
    }

    #[tokio::test(start_paused = true)]
    async fn a_failed_attempt_starts_the_next_at_once() {
        let addresses = [a("[2001:db8::1]:443"), a("192.0.2.1:443")];
        let began = tokio::time::Instant::now();
        let (winner, ()) = connect(&addresses, Schedule::TCP, |address| async move {
            if address.is_ipv6() {
                return Err(io::Error::from(io::ErrorKind::ConnectionRefused));
            }
            Ok(())
        })
        .await
        .unwrap();
        assert_eq!(winner, a("192.0.2.1:443"));
        assert_eq!(began.elapsed(), Duration::ZERO);
    }

    #[tokio::test(start_paused = true)]
    async fn a_slow_first_attempt_keeps_running_and_can_still_win() {
        let addresses = [a("[2001:db8::1]:443"), a("192.0.2.1:443")];
        let (winner, ()) = connect(&addresses, Schedule::TCP, |address| async move {
            if address.is_ipv6() {
                tokio::time::sleep(Duration::from_secs(1)).await;
                Ok(())
            } else {
                tokio::time::sleep(Duration::from_secs(5)).await;
                Ok(())
            }
        })
        .await
        .unwrap();
        assert_eq!(winner, a("[2001:db8::1]:443"));
    }

    #[tokio::test(start_paused = true)]
    async fn staggered_attempts_are_capped() {
        let addresses: Vec<SocketAddr> = (1..=10)
            .map(|n| SocketAddr::from(([192, 0, 2, n], 443)))
            .collect();
        let started = Arc::new(AtomicUsize::new(0));
        let counter = started.clone();
        let outcome = tokio::time::timeout(
            Duration::from_secs(10),
            connect(&addresses, Schedule::TCP, move |_address| {
                counter.fetch_add(1, Ordering::SeqCst);
                std::future::pending::<io::Result<()>>()
            }),
        )
        .await;
        assert!(outcome.is_err());
        assert_eq!(started.load(Ordering::SeqCst), MAX_ATTEMPTS_IN_FLIGHT);
    }

    #[tokio::test(start_paused = true)]
    async fn sequential_attempts_drop_the_stalled_one_and_never_limit_the_last() {
        struct Dropped(Arc<AtomicUsize>);
        impl Drop for Dropped {
            fn drop(&mut self) {
                self.0.fetch_add(1, Ordering::SeqCst);
            }
        }
        let dropped = Arc::new(AtomicUsize::new(0));
        let addresses = [a("[2001:db8::1]:443"), a("192.0.2.1:443")];
        let began = tokio::time::Instant::now();
        let schedule = Schedule::Sequential {
            limit: Duration::from_secs(3),
        };
        let marker = dropped.clone();
        let (winner, ()) = connect(&addresses, schedule, move |address| {
            let guard = Dropped(marker.clone());
            async move {
                let _guard = guard;
                if address.is_ipv6() {
                    std::future::pending::<()>().await;
                }
                // Longer than the limit: the last attempt is not cut short.
                tokio::time::sleep(Duration::from_secs(5)).await;
                Ok(())
            }
        })
        .await
        .unwrap();
        assert_eq!(winner, a("192.0.2.1:443"));
        assert_eq!(began.elapsed(), Duration::from_secs(8));
        // The stalled IPv6 attempt was dropped when IPv4 started, the
        // winner when it returned.
        assert_eq!(dropped.load(Ordering::SeqCst), 2);
    }

    #[tokio::test(start_paused = true)]
    async fn a_single_address_runs_until_the_callers_timeout() {
        let addresses = [a("192.0.2.1:443")];
        let schedule = Schedule::Sequential {
            limit: Duration::from_secs(1),
        };
        let (winner, ()) = connect(&addresses, schedule, |_address| async {
            tokio::time::sleep(Duration::from_secs(7)).await;
            Ok(())
        })
        .await
        .unwrap();
        assert_eq!(winner, a("192.0.2.1:443"));
    }

    #[tokio::test(start_paused = true)]
    async fn when_everything_fails_the_informative_error_is_kept() {
        let addresses = [a("[2001:db8::1]:443"), a("192.0.2.1:443")];
        let schedule = Schedule::Sequential {
            limit: Duration::from_secs(1),
        };
        let error = connect(&addresses, schedule, |address| async move {
            if address.is_ipv6() {
                return Err::<(), _>(io::Error::from(io::ErrorKind::ConnectionRefused));
            }
            Err(io::Error::from(io::ErrorKind::TimedOut))
        })
        .await
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::ConnectionRefused);

        let error = connect(&[], Schedule::TCP, |_address| async { Ok(()) })
            .await
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::NotFound);
    }
}
