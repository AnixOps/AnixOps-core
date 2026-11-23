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
//! everything else the process opens. Windows has no such per-process limit
//! and keeps the configured values.

use crate::config::Limits;

/// Descriptors kept for everything but relayed connections (DNS, rule sets,
/// health checks, listeners, the TUN device, logs and the host app), as a
/// quarter of the budget within these bounds.
const RESERVED_MIN: usize = 64;
const RESERVED_MAX: usize = 512;

/// The tunnel's and system proxy's TCP connection cap and the tunnel's UDP
/// flow cap for `limits`, lowered to the process's descriptor budget where
/// there is one (see [`clamp_to_budget`]). This applies to values set in the
/// config too: a cap above the budget cannot be reached anyway, and below it
/// idle connections make room instead of new ones failing.
pub(crate) fn connection_limits(limits: &Limits) -> (usize, usize) {
    match descriptor_budget() {
        Some(descriptors) => clamp_to_budget(
            limits.max_tcp_connections,
            limits.max_udp_flows,
            descriptors,
        ),
        None => (limits.max_tcp_connections, limits.max_udp_flows),
    }
}

/// `(tcp, udp)` lowered so that, with `descriptors` open files allowed,
/// a reserve stays free: TCP gets at most half of the rest (a system-proxy
/// connection uses two descriptors), UDP at most what TCP leaves. Both stay
/// at least 1.
pub(crate) fn clamp_to_budget(tcp: usize, udp: usize, descriptors: usize) -> (usize, usize) {
    let reserve = (descriptors / 4).clamp(RESERVED_MIN, RESERVED_MAX);
    let available = descriptors.saturating_sub(reserve);
    let tcp = tcp.min(available / 2).max(1);
    let udp = udp.min(available.saturating_sub(tcp)).max(1);
    (tcp, udp)
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

    #[test]
    fn caps_fit_a_small_descriptor_budget() {
        // macOS's usual 256: 64 kept back, TCP half of the rest, UDP the rest.
        assert_eq!(clamp_to_budget(1024, 4096, 256), (96, 96));
        // Linux's usual 1024: 256 kept back.
        assert_eq!(clamp_to_budget(1024, 4096, 1024), (384, 384));
        // A smaller TCP cap leaves more for UDP.
        assert_eq!(clamp_to_budget(100, 4096, 1024), (100, 668));
        // Caps that fit are kept.
        assert_eq!(clamp_to_budget(128, 256, 1024), (128, 256));
        assert_eq!(clamp_to_budget(1024, 4096, 1 << 20), (1024, 4096));
        // Never zero, even with almost no descriptors.
        assert_eq!(clamp_to_budget(1024, 4096, 16), (1, 1));
    }

    #[test]
    fn the_caps_and_the_reserve_never_exceed_the_budget() {
        for descriptors in [100, 256, 1000, 1024, 4096, 10240, 65536] {
            let (tcp, udp) = clamp_to_budget(usize::MAX, usize::MAX, descriptors);
            let reserve = (descriptors / 4).clamp(RESERVED_MIN, RESERVED_MAX);
            // A system-proxy connection holds two descriptors.
            assert!(2 * tcp + reserve <= descriptors, "{descriptors}");
            assert!(tcp + udp + reserve <= descriptors, "{descriptors}");
        }
    }

    #[test]
    fn the_budget_holds_the_default_caps_or_lowers_them() {
        let (tcp, udp) = connection_limits(&Limits::default());
        assert!((1..=crate::tunnel::DEFAULT_MAX_TCP_CONNECTIONS).contains(&tcp));
        assert!((1..=crate::tunnel::DEFAULT_MAX_UDP_FLOWS).contains(&udp));
        if let Some(descriptors) = descriptor_budget() {
            assert!(tcp + udp < descriptors);
        }
    }
}
