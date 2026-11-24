//! The process's file-descriptor budget and the connection caps that fit it.
//!
//! Each relayed TCP connection and UDP flow holds at least one outbound
//! socket (a system-proxy connection holds two: the app's and the outbound
//! one). The default soft `RLIMIT_NOFILE` is 1024 on Linux and Android and
//! often 256 on macOS and iOS, below the desktop defaults of
//! [`crate::tunnel::DEFAULT_MAX_TCP_CONNECTIONS`] and
//! [`crate::tunnel::DEFAULT_MAX_UDP_FLOWS`]. If descriptors ran out first,
//! new connections would fail at outbound connect ("too many open files")
//! instead of taking the place of idle ones, and DNS, rule-set updates,
//! health checks and the local proxy would fail with them.
//!
//! So on Linux, Android, macOS and iOS the runtime raises the soft limit to
//! the hard one once (on Apple platforms at most `kern.maxfilesperproc`,
//! since `setrlimit` refuses more there) and then caps the connection and
//! flow limits to what the resulting budget holds, keeping a reserve for
//! everything else the process opens. The caps are sized for the tunnel and
//! the system proxy running in the same process with every connection
//! open, so `tunnel TCP + UDP + 2 x proxy TCP + reserve` never passes the
//! budget (see [`clamp_to_budget`]). Windows has no such per-process limit
//! and keeps the configured values.

use crate::config::Limits;

/// Descriptors kept for everything but relayed connections (DNS, rule sets,
/// health checks, listeners, the TUN device, logs and the host app), as a
/// quarter of the budget within these bounds.
const RESERVED_MIN: usize = 64;
const RESERVED_MAX: usize = 512;

/// Connection caps that fit the process's descriptor budget together.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ConnectionCaps {
    /// TCP connections relayed by the tunnel: one descriptor each (the
    /// outbound socket; the app's side lives in the user-space stack).
    pub tunnel_tcp: usize,
    /// UDP flows relayed by the tunnel: one descriptor each.
    pub udp: usize,
    /// Connections of the system proxy: two descriptors each (the app's
    /// and the outbound one). It can run in the same process as the tunnel
    /// (the Apple providers register it with the tunnel's settings).
    pub proxy_tcp: usize,
}

impl ConnectionCaps {
    /// Descriptors these caps hold at most, all of them full at once.
    #[cfg(test)]
    fn descriptors(&self) -> usize {
        self.tunnel_tcp + self.udp + 2 * self.proxy_tcp
    }
}

/// The tunnel's TCP and UDP caps and the system proxy's connection cap for
/// `limits`, lowered to the process's descriptor budget where there is one
/// (see [`clamp_to_budget`]). This applies to values set in the config too:
/// a cap above the budget cannot be reached anyway, and below it idle
/// connections make room instead of new ones failing.
pub(crate) fn connection_limits(limits: &Limits) -> ConnectionCaps {
    match descriptor_budget() {
        Some(descriptors) => clamp_to_budget(
            limits.max_tcp_connections,
            limits.max_udp_flows,
            descriptors,
        ),
        None => ConnectionCaps {
            tunnel_tcp: limits.max_tcp_connections,
            udp: limits.max_udp_flows,
            proxy_tcp: limits.max_tcp_connections,
        },
    }
}

/// Caps for a TCP cap `tcp` (the tunnel's and the system proxy's) and a UDP
/// cap `udp`, lowered so that with `descriptors` open files allowed, the
/// tunnel, the system proxy and the reserve all fit at once:
/// `tunnel_tcp + udp + 2 * proxy_tcp + reserve <= descriptors`.
///
/// Caps that fit together are kept. Otherwise what is left after the
/// reserve is split in three equal parts, one for the tunnel's TCP, one for
/// the proxy (two descriptors per connection) and one for UDP; a part a cap
/// does not use goes to UDP, then to the tunnel's TCP. Every cap stays at
/// least 1, so a budget too small for even that (under about 70
/// descriptors) is the only case where the sum can pass it.
pub(crate) fn clamp_to_budget(tcp: usize, udp: usize, descriptors: usize) -> ConnectionCaps {
    let reserve = reserve_for(descriptors);
    let available = descriptors.saturating_sub(reserve);
    let wanted = ConnectionCaps {
        tunnel_tcp: tcp,
        udp,
        proxy_tcp: tcp,
    };
    if wanted
        .tunnel_tcp
        .checked_add(wanted.udp)
        .and_then(|sum| sum.checked_add(wanted.proxy_tcp.checked_mul(2)?))
        .is_some_and(|sum| sum <= available)
    {
        return wanted;
    }
    let part = available / 3;
    let tunnel_tcp = tcp.min(part);
    let proxy_tcp = tcp.min(part / 2);
    let udp = udp.min(available - tunnel_tcp - 2 * proxy_tcp);
    let left = available - tunnel_tcp - 2 * proxy_tcp - udp;
    let tunnel_tcp = tunnel_tcp + (tcp - tunnel_tcp).min(left);
    ConnectionCaps {
        tunnel_tcp: tunnel_tcp.max(1),
        udp: udp.max(1),
        proxy_tcp: proxy_tcp.max(1),
    }
}

/// Descriptors kept back from a budget of `descriptors`.
fn reserve_for(descriptors: usize) -> usize {
    (descriptors / 4).clamp(RESERVED_MIN, RESERVED_MAX)
}

/// The soft open-file limit after raising it once for the process, or
/// `None` where there is no limit to respect.
fn descriptor_budget() -> Option<usize> {
    static BUDGET: std::sync::OnceLock<Option<usize>> = std::sync::OnceLock::new();
    *BUDGET.get_or_init(raise_nofile_limit)
}

#[cfg(any(
    target_os = "linux",
    target_os = "android",
    target_os = "macos",
    target_os = "ios"
))]
fn raise_nofile_limit() -> Option<usize> {
    let mut limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: getrlimit only writes the `rlimit` it is given.
    if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) } != 0 {
        return None;
    }
    let target = nofile_target(limit.rlim_max);
    if limit.rlim_cur != libc::RLIM_INFINITY && limit.rlim_cur < target {
        let raised = libc::rlimit {
            rlim_cur: target,
            rlim_max: limit.rlim_max,
        };
        // SAFETY: setrlimit only reads the `rlimit` it is given. Failing
        // leaves the limit as it was, which is read back below.
        unsafe {
            libc::setrlimit(libc::RLIMIT_NOFILE, &raised);
        }
        // SAFETY: as above.
        if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) } != 0 {
            return None;
        }
    }
    if limit.rlim_cur == libc::RLIM_INFINITY {
        return None;
    }
    Some(to_usize(limit.rlim_cur))
}

#[cfg(not(any(
    target_os = "linux",
    target_os = "android",
    target_os = "macos",
    target_os = "ios"
)))]
fn raise_nofile_limit() -> Option<usize> {
    None
}

/// The soft limit to ask for: the hard limit, at most
/// `kern.maxfilesperproc` (or `OPEN_MAX` when that cannot be read) on Apple
/// platforms, which refuse more, and at most `UNBOUNDED_TARGET` when the
/// hard limit is unlimited elsewhere.
#[cfg(any(target_os = "macos", target_os = "ios"))]
fn nofile_target(hard: libc::rlim_t) -> libc::rlim_t {
    /// `OPEN_MAX` from `<sys/syslimits.h>`.
    const OPEN_MAX: libc::rlim_t = 10240;
    let mut per_process: libc::c_int = 0;
    let mut size = std::mem::size_of::<libc::c_int>();
    // SAFETY: the name is NUL-terminated and the output buffer is a c_int
    // with its size passed alongside; nothing is written to the kernel.
    let read = unsafe {
        libc::sysctlbyname(
            c"kern.maxfilesperproc".as_ptr(),
            std::ptr::addr_of_mut!(per_process).cast(),
            &mut size,
            std::ptr::null_mut(),
            0,
        )
    };
    let cap = match libc::rlim_t::try_from(per_process) {
        Ok(cap) if read == 0 && cap > 0 => cap,
        _ => OPEN_MAX,
    };
    hard.min(cap)
}

/// Asked for when the hard limit is unlimited: Linux's default `nr_open`.
#[cfg(any(target_os = "linux", target_os = "android"))]
const UNBOUNDED_TARGET: libc::rlim_t = 1 << 20;

#[cfg(any(target_os = "linux", target_os = "android"))]
fn nofile_target(hard: libc::rlim_t) -> libc::rlim_t {
    if hard == libc::RLIM_INFINITY {
        UNBOUNDED_TARGET
    } else {
        hard
    }
}

/// `value` as `usize`, saturating; generic because `rlim_t` is 32 or 64
/// bits depending on the target.
#[cfg(any(
    target_os = "linux",
    target_os = "android",
    target_os = "macos",
    target_os = "ios"
))]
fn to_usize<T: TryInto<usize>>(value: T) -> usize {
    value.try_into().unwrap_or(usize::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn caps(tunnel_tcp: usize, udp: usize, proxy_tcp: usize) -> ConnectionCaps {
        ConnectionCaps {
            tunnel_tcp,
            udp,
            proxy_tcp,
        }
    }

    #[test]
    fn caps_fit_a_small_descriptor_budget() {
        // macOS's usual 256: 64 kept back, 192 split in three parts of 64.
        assert_eq!(clamp_to_budget(1024, 4096, 256), caps(64, 64, 32));
        // Linux's usual 1024: 256 kept back, three parts of 256.
        assert_eq!(clamp_to_budget(1024, 4096, 1024), caps(256, 256, 128));
        // A smaller TCP cap leaves its part to UDP.
        assert_eq!(clamp_to_budget(100, 4096, 1024), caps(100, 468, 100));
        // A smaller UDP cap leaves its part to the tunnel's TCP.
        assert_eq!(clamp_to_budget(1024, 16, 1024), caps(496, 16, 128));
        // Caps that fit together are kept.
        assert_eq!(clamp_to_budget(128, 256, 1024), caps(128, 256, 128));
        assert_eq!(clamp_to_budget(1024, 4096, 1 << 20), caps(1024, 4096, 1024));
        // Never zero, even with almost no descriptors.
        assert_eq!(clamp_to_budget(1024, 4096, 16), caps(1, 1, 1));
    }

    #[test]
    fn mixed_caps_and_the_reserve_never_exceed_the_budget() {
        let requests = [1, 2, 16, 100, 128, 256, 512, 1000, 1024, 4096, usize::MAX];
        for descriptors in (70..=70_000).step_by(37).chain([256, 1024, 10240, 65536]) {
            let reserve = reserve_for(descriptors);
            for tcp in requests {
                for udp in requests {
                    let caps = clamp_to_budget(tcp, udp, descriptors);
                    // Tunnel TCP, tunnel UDP and the system proxy's two
                    // descriptors per connection, all full at once.
                    assert!(
                        caps.descriptors() + reserve <= descriptors,
                        "{descriptors} {tcp} {udp}: {caps:?}"
                    );
                    assert!(caps.tunnel_tcp >= 1 && caps.udp >= 1 && caps.proxy_tcp >= 1);
                    assert!(caps.tunnel_tcp <= tcp && caps.proxy_tcp <= tcp && caps.udp <= udp);
                }
            }
        }
    }

    #[test]
    fn the_budget_holds_the_default_caps_or_lowers_them() {
        let caps = connection_limits(&Limits::default());
        assert!((1..=crate::tunnel::DEFAULT_MAX_TCP_CONNECTIONS).contains(&caps.tunnel_tcp));
        assert!((1..=crate::tunnel::DEFAULT_MAX_TCP_CONNECTIONS).contains(&caps.proxy_tcp));
        assert!((1..=crate::tunnel::DEFAULT_MAX_UDP_FLOWS).contains(&caps.udp));
        if let Some(descriptors) = descriptor_budget() {
            assert!(caps.descriptors() + reserve_for(descriptors) <= descriptors);
        }
    }
}
