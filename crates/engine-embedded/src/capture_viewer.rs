//! The capture viewer: saved capture sessions opened with no engine
//! running, in the client's own process. The tunnel keeps capture while it
//! runs and seals it into a session when it stops; with the tunnel off,
//! the app still lists, opens, filters and exports those sessions here.
//!
//! The viewer is one process-wide [`CaptureStore`] that never captures:
//! the client names its own session folder and key (`set_capture_storage`),
//! then sends the same capture commands it sends a running engine
//! (`capture_sessions`, `load_capture`, `capture_requests`,
//! `capture_connection`, `capture_exchange`, `capture_h2_frames`,
//! `export_capture`, `delete_capture`, `clear_capture`), and `connections`
//! for the loaded connections. A client whose tunnel keeps its own key
//! (the Apple tunnels) copies each session across with `copy_capture` on
//! the engine, which seals it again under the app's key, and
//! `import_capture` here. See [`crate::control::handle_capture_viewer`].

use std::sync::LazyLock;

use crate::capture::CaptureStore;
use crate::control;
use crate::RuntimeError;

static VIEWER: LazyLock<CaptureStore> = LazyLock::new(CaptureStore::default);

/// Answers one JSON request with the process-wide viewer.
pub fn control(request: &[u8]) -> Result<Vec<u8>, RuntimeError> {
    control::handle_capture_viewer(&VIEWER, request)
}
