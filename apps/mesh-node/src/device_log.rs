//! Where the Windows device service writes its log. A service has no
//! console, so started by the service manager `device` sends standard error
//! to `device.log` in its state directory (open to SYSTEM and the
//! administrators only, like the rest of it). The log holds the JSON lines
//! the service writes anyway; it never holds a token, credential or network
//! secret (`docs/deploy/mesh-device.md`). At each start a log over
//! [`MAX_LOG`] bytes is moved to `device.log.1`, replacing the one before.

use std::io;
use std::path::Path;

/// Size from which the log is set aside at the next start.
pub const MAX_LOG: u64 = 1 << 20;

/// Sends standard error to `<state_dir>/device.log`. Nothing changes when
/// the state directory does not pass the state checks or the file cannot
/// be opened; the service then fails on the same checks and the service
/// manager records its exit code.
pub fn redirect_stderr(state_dir: &Path) {
    let _ = try_redirect(state_dir);
}

fn try_redirect(state_dir: &Path) -> io::Result<()> {
    use std::os::windows::io::IntoRawHandle;
    use windows_sys::Win32::System::Console::{SetStdHandle, STD_ERROR_HANDLE};

    crate::host::windows::check_state_dir(state_dir)?;
    let path = state_dir.join("device.log");
    if std::fs::metadata(&path).is_ok_and(|metadata| metadata.len() > MAX_LOG) {
        std::fs::rename(&path, state_dir.join("device.log.1"))?;
    }
    let file = std::fs::OpenOptions::new()
        .append(true)
        .create(true)
        .open(&path)?;
    // The handle stays open for the life of the process.
    let handle = file.into_raw_handle();
    // SAFETY: an open file handle this process keeps.
    if unsafe { SetStdHandle(STD_ERROR_HANDLE, handle) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}
