//! The local status socket of `device` (`docs/deploy/mesh-device.md`,
//! "本机状态套接字"): a Unix domain socket, mode 0660 and group
//! `anixops-mesh`, that answers one line of JSON, `{"cmd":"mesh_status"}`,
//! with the managed mesh's status and the device fields. Any other request
//! gets `{"ok":false,"error":{"code":"unsupported"}}`. No TCP or UDP port
//! is opened (requirement R11). `device-status` reads it with read and
//! write timeouts of 3 seconds each, so a caller (rpcd calls
//! synchronously) never hangs.

use std::io::{self, BufRead, BufReader, Write};
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::Duration;

use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixListener;

/// The group that may read the socket.
pub const GROUP: &str = "anixops-mesh";
/// Read and write timeout of a client, and of the service per connection.
pub const TIMEOUT: Duration = Duration::from_secs(3);
/// Longest request line.
const MAX_REQUEST: usize = 4096;

/// The answer to one request line; `snapshot` makes the status only when
/// it is asked for.
pub fn answer(request: &str, snapshot: impl FnOnce() -> Value) -> Value {
    match serde_json::from_str::<Value>(request.trim()) {
        Ok(Value::Object(fields))
            if fields.len() == 1 && fields.get("cmd") == Some(&json!("mesh_status")) =>
        {
            snapshot()
        }
        _ => json!({ "ok": false, "error": { "code": "unsupported" } }),
    }
}

/// Binds the socket at `path`: a socket left by an earlier run is
/// replaced, any other file is refused. Mode 0660, group [`GROUP`] when it
/// exists.
pub fn bind(path: &Path) -> io::Result<UnixListener> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_socket() => std::fs::remove_file(path)?,
        Ok(_) => {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "status.sock exists and is not a socket",
            ))
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    let listener = UnixListener::bind(path)?;
    if let Some(gid) = group_id(GROUP) {
        let name = std::ffi::CString::new(path.as_os_str().as_encoded_bytes())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path holds a NUL"))?;
        // SAFETY: a valid C string; -1 keeps the owner.
        if unsafe { libc::lchown(name.as_ptr(), u32::MAX, gid) } != 0 {
            return Err(io::Error::last_os_error());
        }
    }
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o660))?;
    Ok(listener)
}

fn group_id(name: &str) -> Option<libc::gid_t> {
    let name = std::ffi::CString::new(name).ok()?;
    // SAFETY: getgrnam returns null or a pointer into static storage that
    // is read at once; the program reads groups from one thread here.
    let entry = unsafe { libc::getgrnam(name.as_ptr()) };
    if entry.is_null() {
        None
    } else {
        // SAFETY: not null, see above.
        Some(unsafe { (*entry).gr_gid })
    }
}

/// Answers connections until the listener fails; each connection gets
/// [`TIMEOUT`] to send its line and take the answer.
pub async fn serve<F>(listener: UnixListener, snapshot: F)
where
    F: Fn() -> Value + Clone + Send + 'static,
{
    loop {
        let Ok((stream, _)) = listener.accept().await else {
            tokio::time::sleep(Duration::from_millis(100)).await;
            continue;
        };
        let snapshot = snapshot.clone();
        tokio::spawn(async move {
            let _ = tokio::time::timeout(TIMEOUT, one(stream, snapshot)).await;
        });
    }
}

async fn one<F: Fn() -> Value>(stream: tokio::net::UnixStream, snapshot: F) -> io::Result<()> {
    let (read, mut write) = stream.into_split();
    let mut line = Vec::new();
    let mut reader = tokio::io::BufReader::new(read).take(MAX_REQUEST as u64);
    reader.read_until(b'\n', &mut line).await?;
    let request = String::from_utf8_lossy(&line);
    let mut text = answer(&request, snapshot).to_string();
    text.push('\n');
    write.write_all(text.as_bytes()).await?;
    write.shutdown().await
}

/// `device-status`: asks the service at `path` and returns its answer.
pub fn query(path: &Path) -> io::Result<Value> {
    let mut stream = UnixStream::connect(path)?;
    stream.set_read_timeout(Some(TIMEOUT))?;
    stream.set_write_timeout(Some(TIMEOUT))?;
    stream.write_all(b"{\"cmd\":\"mesh_status\"}\n")?;
    let mut line = String::new();
    // At most 4 MiB of answer.
    BufReader::new(io::Read::take(stream, 4 << 20)).read_line(&mut line)?;
    serde_json::from_str(line.trim()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "the service gave no JSON answer",
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_mesh_status_is_answered() {
        let status = || json!({ "ok": true, "mesh": {} });
        assert_eq!(answer("{\"cmd\":\"mesh_status\"}\n", status), status());
        let unsupported = json!({ "ok": false, "error": { "code": "unsupported" } });
        assert_eq!(answer("{\"cmd\":\"mesh_join\"}", status), unsupported);
        assert_eq!(
            answer("{\"cmd\":\"mesh_status\",\"x\":1}", status),
            unsupported
        );
        assert_eq!(answer("not json", status), unsupported);
        assert_eq!(answer("", status), unsupported);
        let mut called = false;
        answer("{\"cmd\":\"other\"}", || {
            called = true;
            json!({})
        });
        assert!(!called, "the status is made only when asked for");
    }

    #[test]
    fn the_socket_answers_a_status_request() {
        let dir = std::env::temp_dir().join(format!("anixops-mesh-sock-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("status.sock");
        // A file that is not a socket is never replaced.
        std::fs::write(&path, b"x").unwrap();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .enable_time()
            .build()
            .unwrap();
        runtime.block_on(async {
            assert!(bind(&path).is_err());
        });
        std::fs::remove_file(&path).unwrap();
        let answer = std::thread::scope(|scope| {
            let (ready, wait) = std::sync::mpsc::channel();
            let server_path = path.clone();
            scope.spawn(move || {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_io()
                    .enable_time()
                    .build()
                    .unwrap();
                runtime.block_on(async move {
                    let listener = bind(&server_path).unwrap();
                    ready.send(()).unwrap();
                    let _ = tokio::time::timeout(
                        Duration::from_secs(2),
                        serve(
                            listener,
                            || json!({ "ok": true, "mesh": { "networks": [] } }),
                        ),
                    )
                    .await;
                });
            });
            wait.recv().unwrap();
            query(&path).unwrap()
        });
        assert_eq!(answer, json!({ "ok": true, "mesh": { "networks": [] } }));
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o660);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_missing_service_is_an_error() {
        assert!(query(Path::new("/nonexistent/anixops-mesh/status.sock")).is_err());
    }
}
