//! The local status endpoint of `device` (`docs/deploy/mesh-device.md`,
//! "本机状态接口"). It answers one line of JSON, `{"cmd":"mesh_status"}`,
//! with the managed mesh's status and the device fields; any other request
//! gets `{"ok":false,"error":{"code":"unsupported"}}`. No TCP or UDP port
//! is opened (requirement R11). `device-status` reads it with read and
//! write timeouts of 3 seconds each, so a caller (rpcd calls
//! synchronously) never hangs.
//!
//! - Linux and macOS: the Unix domain socket `status.sock` in the state
//!   directory, mode 0660, group [`GROUP`] (`anixops-mesh` on Linux,
//!   `admin` on macOS).
//! - Windows: a named pipe whose name is derived from the same path
//!   ([`pipe_name`]), open to SYSTEM and the administrators, and to the
//!   local users for their one request (`win_security::PIPE_SDDL`); remote
//!   clients are refused. A client only trusts a pipe owned by SYSTEM, the
//!   administrators or itself, and does not let it impersonate the client.

use std::io;
use std::time::Duration;

use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

#[cfg(unix)]
pub use self::unix::{bind, query, serve, Listener, GROUP};
#[cfg(windows)]
pub use self::windows::{bind, pipe_name, query, serve, Listener};

/// Read and write timeout of a client, and of the service per connection.
pub const TIMEOUT: Duration = Duration::from_secs(3);
/// Longest request line.
const MAX_REQUEST: usize = 4096;
/// Longest answer a client reads.
const MAX_ANSWER: u64 = 4 << 20;
/// The one request.
const REQUEST: &[u8] = b"{\"cmd\":\"mesh_status\"}\n";

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

/// Serves one connection: reads one line (at most [`MAX_REQUEST`] bytes)
/// and writes the answer line.
async fn one<S, F>(stream: S, snapshot: F) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite,
    F: Fn() -> Value,
{
    let (read, mut write) = tokio::io::split(stream);
    let mut line = Vec::new();
    let mut reader = tokio::io::BufReader::new(read).take(MAX_REQUEST as u64);
    reader.read_until(b'\n', &mut line).await?;
    let request = String::from_utf8_lossy(&line);
    let mut text = answer(&request, snapshot).to_string();
    text.push('\n');
    write.write_all(text.as_bytes()).await?;
    write.flush().await?;
    write.shutdown().await?;
    // Windows discards what the client has not read yet when the server
    // end closes first: wait (within the connection's time) until the
    // client has read the answer and closed its end.
    if cfg!(windows) {
        let mut rest = [0u8; 64];
        while reader.get_mut().get_mut().read(&mut rest).await? > 0 {}
    }
    Ok(())
}

/// Sends the request on `stream` and reads the answer line, each within
/// [`TIMEOUT`].
async fn ask<S: AsyncRead + AsyncWrite>(stream: S) -> io::Result<Value> {
    let (read, mut write) = tokio::io::split(stream);
    let timed_out = || {
        io::Error::new(
            io::ErrorKind::TimedOut,
            "the service did not answer in time",
        )
    };
    tokio::time::timeout(TIMEOUT, async {
        write.write_all(REQUEST).await?;
        write.flush().await
    })
    .await
    .map_err(|_| timed_out())??;
    let mut line = Vec::new();
    let mut reader = tokio::io::BufReader::new(read).take(MAX_ANSWER);
    tokio::time::timeout(TIMEOUT, reader.read_until(b'\n', &mut line))
        .await
        .map_err(|_| timed_out())??;
    serde_json::from_slice(trim(&line)).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "the service gave no JSON answer",
        )
    })
}

fn trim(line: &[u8]) -> &[u8] {
    let end = line
        .iter()
        .rposition(|b| !b.is_ascii_whitespace())
        .map_or(0, |at| at + 1);
    &line[..end]
}

fn client_runtime() -> io::Result<tokio::runtime::Runtime> {
    tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()
}

#[cfg(unix)]
mod unix {
    use std::io;
    use std::os::unix::fs::{FileTypeExt, PermissionsExt};
    use std::path::Path;
    use std::time::Duration;

    use serde_json::Value;
    use tokio::net::UnixListener;

    use super::{ask, client_runtime, one, TIMEOUT};

    /// The group that may use the socket.
    #[cfg(target_os = "macos")]
    pub const GROUP: &str = "admin";
    /// The group that may use the socket.
    #[cfg(not(target_os = "macos"))]
    pub const GROUP: &str = "anixops-mesh";

    pub type Listener = UnixListener;

    /// Binds the socket at `path`: a socket left by an earlier run is
    /// replaced, any other file is refused. Mode 0660, group [`GROUP`]
    /// when it exists.
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
        // SAFETY: getgrnam returns null or a pointer into static storage
        // that is read at once; the program reads groups from one thread
        // here.
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

    /// `device-status`: asks the service at `path` and returns its answer.
    pub fn query(path: &Path) -> io::Result<Value> {
        client_runtime()?.block_on(async {
            let stream = tokio::time::timeout(TIMEOUT, tokio::net::UnixStream::connect(path))
                .await
                .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "connect timed out"))??;
            ask(stream).await
        })
    }
}

#[cfg(windows)]
mod windows {
    use std::io;
    use std::path::Path;
    use std::time::Duration;

    use serde_json::Value;
    use sha2::{Digest, Sha256};
    use tokio::net::windows::named_pipe::{
        NamedPipeClient, NamedPipeServer, PipeMode, ServerOptions,
    };
    use windows_sys::Win32::Foundation::{ERROR_PIPE_BUSY, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, FILE_FLAG_OVERLAPPED, FILE_GENERIC_READ, FILE_WRITE_DATA, OPEN_EXISTING,
        SECURITY_IDENTIFICATION, SECURITY_SQOS_PRESENT,
    };

    use super::{ask, client_runtime, one, TIMEOUT};
    use crate::win_security::{self, SecurityDescriptor, PIPE_SDDL};

    /// The pipe of the state directory at `path`'s folder:
    /// `\\.\pipe\anixops-mesh-device-<16 hex>`, the hex digits the start
    /// of the SHA-256 of the lowercase absolute path of `path`. Pipe
    /// names are one namespace for the whole machine; the digest keeps
    /// two state directories apart.
    pub fn pipe_name(path: &Path) -> io::Result<String> {
        let absolute = std::path::absolute(path)?;
        let text = absolute.to_string_lossy().to_lowercase();
        let digest = Sha256::digest(text.as_bytes());
        let hex: String = digest[..8].iter().map(|b| format!("{b:02x}")).collect();
        Ok(format!(r"\\.\pipe\anixops-mesh-device-{hex}"))
    }

    /// The first pipe instance and the name to make the next ones under.
    pub struct Listener {
        name: String,
        first: NamedPipeServer,
    }

    fn create(name: &str, first: bool) -> io::Result<NamedPipeServer> {
        let descriptor = SecurityDescriptor::from_sddl(PIPE_SDDL)?;
        let mut attributes = descriptor.attributes();
        // SAFETY: the attributes point at a descriptor that lives until
        // the call returns; the pipe keeps its own copy.
        unsafe {
            ServerOptions::new()
                // Refuses to start when anyone already made this pipe.
                .first_pipe_instance(first)
                .reject_remote_clients(true)
                .pipe_mode(PipeMode::Byte)
                .access_inbound(true)
                .access_outbound(true)
                .create_with_security_attributes_raw(
                    name,
                    std::ptr::from_mut(&mut attributes).cast(),
                )
        }
    }

    /// Makes the pipe for the state directory of `path`. Fails when the
    /// pipe already exists, whoever made it: an earlier service still
    /// running, or another program in the way.
    pub fn bind(path: &Path) -> io::Result<Listener> {
        let name = pipe_name(path)?;
        let first = create(&name, true)?;
        Ok(Listener { name, first })
    }

    /// Answers connections, one pipe instance each, until the service
    /// stops; each connection gets [`TIMEOUT`].
    pub async fn serve<F>(listener: Listener, snapshot: F)
    where
        F: Fn() -> Value + Clone + Send + 'static,
    {
        let Listener { name, first } = listener;
        let mut server = first;
        loop {
            let connected = server.connect().await;
            let next = loop {
                match create(&name, false) {
                    Ok(next) => break next,
                    Err(_) => tokio::time::sleep(Duration::from_millis(100)).await,
                }
            };
            let current = std::mem::replace(&mut server, next);
            if connected.is_err() {
                continue;
            }
            let snapshot = snapshot.clone();
            tokio::spawn(async move {
                let _ = tokio::time::timeout(TIMEOUT, one(current, snapshot)).await;
            });
        }
    }

    /// Opens the pipe asking only for what [`PIPE_SDDL`] grants the local
    /// users: read (with `READ_CONTROL`, for the owner check) and writing
    /// the request (`FILE_WRITE_DATA`). Generic write would also ask for
    /// the append right, which on a pipe creates instances, and is refused
    /// to them. The service may identify the caller but not act as it.
    fn open_client(name: &str) -> io::Result<NamedPipeClient> {
        let wide: Vec<u16> = name.encode_utf16().chain(Some(0)).collect();
        // SAFETY: `wide` is NUL-terminated; no security attributes or
        // template are passed.
        let handle = unsafe {
            CreateFileW(
                wide.as_ptr(),
                FILE_GENERIC_READ | FILE_WRITE_DATA,
                0,
                std::ptr::null(),
                OPEN_EXISTING,
                FILE_FLAG_OVERLAPPED | SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION,
                std::ptr::null_mut(),
            )
        };
        if handle == INVALID_HANDLE_VALUE {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: a pipe handle just opened for overlapped I/O, owned from
        // here on by the client.
        unsafe { NamedPipeClient::from_raw_handle(handle) }
    }

    /// `device-status`: asks the service of the state directory of `path`
    /// and returns its answer. The pipe must belong to SYSTEM, the
    /// administrators or the caller; the service may identify the caller
    /// but not act as it.
    pub fn query(path: &Path) -> io::Result<Value> {
        let name = pipe_name(path)?;
        client_runtime()?.block_on(async {
            let client = tokio::time::timeout(TIMEOUT, async {
                loop {
                    match open_client(&name) {
                        Ok(client) => return Ok(client),
                        Err(error) if error.raw_os_error() == Some(ERROR_PIPE_BUSY as i32) => {
                            tokio::time::sleep(Duration::from_millis(50)).await;
                        }
                        Err(error) => return Err(error),
                    }
                }
            })
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "connect timed out"))??;
            let owner = win_security::handle_owner(&client)?;
            let caller = win_security::current_account()?;
            if !win_security::trusted_pipe_owner(&owner, &caller) {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    format!("the status pipe belongs to {owner}, not to the service"),
                ));
            }
            ask(client).await
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

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

    #[cfg(unix)]
    #[test]
    fn the_socket_answers_a_status_request() {
        use std::os::unix::fs::PermissionsExt;
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

    #[cfg(windows)]
    #[test]
    fn pipe_names_follow_the_state_directory() {
        let one = pipe_name(Path::new(r"C:\ProgramData\AnixOps\Mesh\device\status.sock")).unwrap();
        let same = pipe_name(Path::new(r"c:\programdata\anixops\mesh\DEVICE\status.sock")).unwrap();
        let other = pipe_name(Path::new(r"C:\ProgramData\AnixOps\Mesh\other\status.sock")).unwrap();
        assert_eq!(one, same);
        assert_ne!(one, other);
        assert!(one.starts_with(r"\\.\pipe\anixops-mesh-device-"));
        assert_eq!(one.len(), r"\\.\pipe\anixops-mesh-device-".len() + 16);
    }

    #[cfg(windows)]
    #[test]
    fn the_pipe_answers_a_status_request_and_is_made_once() {
        let path = std::env::temp_dir()
            .join(format!("anixops-mesh-pipe-{}", std::process::id()))
            .join("status.sock");
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
                    // A second service on the same state directory, or a
                    // program squatting the name, is refused.
                    assert!(bind(&server_path).is_err());
                    ready.send(()).unwrap();
                    let _ = tokio::time::timeout(
                        Duration::from_secs(3),
                        serve(
                            listener,
                            || json!({ "ok": true, "mesh": { "networks": [] } }),
                        ),
                    )
                    .await;
                });
            });
            wait.recv().unwrap();
            let first = query(&path).unwrap();
            // Each connection gets an instance of its own.
            assert_eq!(query(&path).unwrap(), first);
            first
        });
        assert_eq!(answer, json!({ "ok": true, "mesh": { "networks": [] } }));
    }
}
