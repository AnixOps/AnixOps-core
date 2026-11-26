//! The host-wide mesh lock (recheck of spec #357, Y2), shared by the
//! external bridge and the Linux subnet router (spec §15.12 item 9,
//! `docs/architecture/mesh-module.md`).
//!
//! Bridge tables are host-wide, and the start-up cleanup deletes every one
//! carrying our mark. A second node program on the same host would delete
//! the first one's tables without either noticing, so a node takes this
//! lock before its start-up cleanup and holds it while it runs. A node that
//! cannot take it does not declare [`crate::FEATURE`], does not clean up
//! and raises [`LOCK_HELD_ALERT`].
//!
//! The lock is `flock` on [`LOCK_PATH`]; the kernel releases it when the
//! process ends, so a crash leaves no stale lock.

use std::io;

/// Where the lock lives.
pub const LOCK_PATH: &str = "/run/anixops-mesh-host.lock";

/// Raised when another process holds the lock.
pub const LOCK_HELD_ALERT: &str = "external_bridge_lock_held";

/// Held while it lives; dropping it releases the lock.
#[derive(Debug)]
pub struct HostLock {
    #[cfg(target_os = "linux")]
    _file: std::fs::File,
}

impl HostLock {
    /// Takes the lock at [`LOCK_PATH`] without waiting.
    pub fn acquire() -> io::Result<Self> {
        Self::acquire_at(LOCK_PATH)
    }

    /// Takes the lock at `path` without waiting. `WouldBlock` means another
    /// process holds it. Not supported outside Linux.
    #[cfg(target_os = "linux")]
    pub fn acquire_at(path: &str) -> io::Result<Self> {
        use std::os::fd::AsRawFd;
        use std::os::unix::fs::OpenOptionsExt;

        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(path)?;
        // SAFETY: `file` owns a valid descriptor for this call.
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::EWOULDBLOCK) {
                return Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    format!("{path} is held by another process"),
                ));
            }
            return Err(error);
        }
        Ok(Self { _file: file })
    }

    #[cfg(not(target_os = "linux"))]
    pub fn acquire_at(_path: &str) -> io::Result<Self> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "the external bridge runs on Linux only",
        ))
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    #[test]
    fn a_second_holder_is_refused_until_the_first_lets_go() {
        let dir = std::env::temp_dir().join(format!("mesh-bridge-lock-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("bridge.lock");
        let path = path.to_str().unwrap();
        let first = HostLock::acquire_at(path).unwrap();
        // flock locks belong to the open file, so a second open in the same
        // process conflicts just as another process would.
        let second = HostLock::acquire_at(path).unwrap_err();
        assert_eq!(second.kind(), io::ErrorKind::WouldBlock);
        drop(first);
        let again = HostLock::acquire_at(path).unwrap();
        drop(again);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
