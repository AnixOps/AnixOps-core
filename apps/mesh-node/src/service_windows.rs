//! `run` under the Windows service manager.
//!
//! The installer registers `anixops-mesh run --config F` as an own-process
//! service. Started that way, the program must connect to the service
//! manager, report its state and stop when asked; started from a console it
//! runs as it does elsewhere and stops on Ctrl+C. [`dispatch`] tells the two
//! apart: the service manager refuses the connection of a console process
//! with `ERROR_FAILED_SERVICE_CONTROLLER_CONNECT`.
//!
//! A stop or shutdown request reaches the node through [`stop_requested`],
//! the same way Ctrl+C does. A node that stops with a non-zero exit code is
//! reported as stopped with a service-specific error carrying that code, so
//! the recovery actions the installer sets (`sc failure`, with
//! `sc failureflag 1`) restart it.

use std::sync::atomic::{AtomicPtr, AtomicU8, Ordering};
use std::sync::{Mutex, OnceLock, PoisonError};

use tokio::sync::watch;
use windows_sys::Win32::Foundation::{
    GetLastError, ERROR_CALL_NOT_IMPLEMENTED, ERROR_FAILED_SERVICE_CONTROLLER_CONNECT,
    ERROR_SERVICE_SPECIFIC_ERROR, NO_ERROR,
};
use windows_sys::Win32::System::Services::{
    RegisterServiceCtrlHandlerExW, SetServiceStatus, StartServiceCtrlDispatcherW,
    SERVICE_ACCEPT_SHUTDOWN, SERVICE_ACCEPT_STOP, SERVICE_CONTROL_INTERROGATE,
    SERVICE_CONTROL_SHUTDOWN, SERVICE_CONTROL_STOP, SERVICE_RUNNING, SERVICE_STATUS,
    SERVICE_STATUS_CURRENT_STATE, SERVICE_STATUS_HANDLE, SERVICE_STOPPED, SERVICE_STOP_PENDING,
    SERVICE_TABLE_ENTRYW, SERVICE_WIN32_OWN_PROCESS,
};

/// The node body the service runs, returning its exit code.
type Body = Box<dyn FnOnce() -> u8 + Send>;

static BODY: Mutex<Option<Body>> = Mutex::new(None);
static EXIT_CODE: AtomicU8 = AtomicU8::new(0);
static STATUS_HANDLE: AtomicPtr<core::ffi::c_void> = AtomicPtr::new(std::ptr::null_mut());

fn stop_channel() -> &'static watch::Sender<bool> {
    static STOP: OnceLock<watch::Sender<bool>> = OnceLock::new();
    STOP.get_or_init(|| watch::channel(false).0)
}

/// Resolves once the service manager asks the service to stop (or the
/// machine shuts down). Never resolves for a console process.
pub async fn stop_requested() {
    let mut stop = stop_channel().subscribe();
    // An error means the sender is gone, which never happens: it is static.
    let _ = stop.wait_for(|stopped| *stopped).await;
}

/// The status to report for `state`; a stopped service carries the exit
/// code as a service-specific error when it is not zero.
fn status(state: SERVICE_STATUS_CURRENT_STATE, exit_code: u8) -> SERVICE_STATUS {
    let accepts = if state == SERVICE_RUNNING {
        SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN
    } else {
        0
    };
    let (win32, specific) = if state == SERVICE_STOPPED && exit_code != 0 {
        (ERROR_SERVICE_SPECIFIC_ERROR, u32::from(exit_code))
    } else {
        (NO_ERROR, 0)
    };
    SERVICE_STATUS {
        dwServiceType: SERVICE_WIN32_OWN_PROCESS,
        dwCurrentState: state,
        dwControlsAccepted: accepts,
        dwWin32ExitCode: win32,
        dwServiceSpecificExitCode: specific,
        dwCheckPoint: 0,
        dwWaitHint: if state == SERVICE_STOP_PENDING {
            10_000
        } else {
            0
        },
    }
}

fn report(state: SERVICE_STATUS_CURRENT_STATE, exit_code: u8) {
    let handle: SERVICE_STATUS_HANDLE = STATUS_HANDLE.load(Ordering::Acquire);
    if handle.is_null() {
        return;
    }
    let status = status(state, exit_code);
    // SAFETY: a handle the service manager gave this service.
    unsafe { SetServiceStatus(handle, &status) };
}

unsafe extern "system" fn handler(
    control: u32,
    _event_type: u32,
    _event_data: *mut core::ffi::c_void,
    _context: *mut core::ffi::c_void,
) -> u32 {
    match control {
        SERVICE_CONTROL_STOP | SERVICE_CONTROL_SHUTDOWN => {
            report(SERVICE_STOP_PENDING, 0);
            stop_channel().send_replace(true);
            NO_ERROR
        }
        SERVICE_CONTROL_INTERROGATE => NO_ERROR,
        _ => ERROR_CALL_NOT_IMPLEMENTED,
    }
}

unsafe extern "system" fn service_main(_argc: u32, argv: *mut windows_sys::core::PWSTR) {
    // The first argument is the service's name.
    // SAFETY: the service manager passes at least the name.
    let name = unsafe {
        if argv.is_null() {
            std::ptr::null()
        } else {
            (*argv).cast_const()
        }
    };
    // SAFETY: the name is the service manager's string; the handler is a
    // function with the expected signature.
    let handle = unsafe { RegisterServiceCtrlHandlerExW(name, Some(handler), std::ptr::null()) };
    if handle.is_null() {
        EXIT_CODE.store(1, Ordering::Release);
        return;
    }
    STATUS_HANDLE.store(handle, Ordering::Release);
    report(SERVICE_RUNNING, 0);
    let body = BODY.lock().unwrap_or_else(PoisonError::into_inner).take();
    let code = body.map_or(1, |body| body());
    EXIT_CODE.store(code, Ordering::Release);
    report(SERVICE_STOPPED, code);
}

/// Runs `body` as the service when the service manager started this
/// process, and returns its exit code; `None` for a console process, which
/// runs the node itself.
pub fn dispatch(body: impl FnOnce() -> u8 + Send + 'static) -> Option<u8> {
    *BODY.lock().unwrap_or_else(PoisonError::into_inner) = Some(Box::new(body));
    // An own-process service may give an empty name.
    let mut name = [0u16; 1];
    let table = [
        SERVICE_TABLE_ENTRYW {
            lpServiceName: name.as_mut_ptr(),
            lpServiceProc: Some(service_main),
        },
        SERVICE_TABLE_ENTRYW {
            lpServiceName: std::ptr::null_mut(),
            lpServiceProc: None,
        },
    ];
    // SAFETY: the table ends with a null entry and outlives the call, which
    // returns when the service has stopped.
    if unsafe { StartServiceCtrlDispatcherW(table.as_ptr()) } != 0 {
        return Some(EXIT_CODE.load(Ordering::Acquire));
    }
    // SAFETY: plain call.
    let error = unsafe { GetLastError() };
    if error != ERROR_FAILED_SERVICE_CONTROLLER_CONNECT {
        let detail = std::io::Error::from_raw_os_error(error as i32).to_string();
        eprintln!(
            "{}",
            serde_json::json!({ "warning": "service", "detail": detail })
        );
    }
    // Not started by the service manager: the console runs it.
    BODY.lock().unwrap_or_else(PoisonError::into_inner).take();
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_running_service_accepts_stop_and_shutdown() {
        let running = status(SERVICE_RUNNING, 0);
        assert_eq!(
            running.dwControlsAccepted,
            SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN
        );
        assert_eq!(running.dwWin32ExitCode, NO_ERROR);
        assert_eq!(status(SERVICE_STOP_PENDING, 0).dwControlsAccepted, 0);
    }

    #[test]
    fn a_failed_node_is_a_service_specific_error() {
        let stopped = status(SERVICE_STOPPED, 3);
        assert_eq!(stopped.dwWin32ExitCode, ERROR_SERVICE_SPECIFIC_ERROR);
        assert_eq!(stopped.dwServiceSpecificExitCode, 3);
        let clean = status(SERVICE_STOPPED, 0);
        assert_eq!(clean.dwWin32ExitCode, NO_ERROR);
        assert_eq!(clean.dwServiceSpecificExitCode, 0);
    }

    #[test]
    fn a_console_process_is_not_a_service() {
        assert_eq!(dispatch(|| 9), None);
        assert!(BODY.lock().unwrap().is_none());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn a_stop_request_ends_the_wait() {
        stop_channel().send_replace(true);
        stop_requested().await;
        stop_channel().send_replace(false);
    }
}
