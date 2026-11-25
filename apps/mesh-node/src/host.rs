//! The machine the program inspects and changes, behind a trait so tests
//! can run every step against a fake file system and fake commands.

use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Output of a finished command.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CommandOutput {
    /// `None` when the command was killed by a signal.
    pub code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
}

impl CommandOutput {
    pub fn success(&self) -> bool {
        self.code == Some(0)
    }
}

/// A started background process.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Spawn {
    pub argv: Vec<String>,
    pub env: Vec<(String, String)>,
    /// `env` is the whole environment: start from an empty one.
    pub clear_env: bool,
    pub cwd: Option<String>,
    /// Run as this user and group (Unix; needs root to change).
    pub uid: Option<u32>,
    pub gid: Option<u32>,
    /// Supplementary groups; `None` keeps none when the user changes.
    pub groups: Option<Vec<u32>>,
}

/// Runs in the parent while a new process waits: given its pid, returns
/// what it did or why it could not.
pub type Hold<'a> = &'a dyn Fn(u32) -> Result<String, String>;

/// A started process.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Spawned {
    pub pid: u32,
    /// What `hold` returned; `None` when it did not run.
    pub held: Option<Result<String, String>>,
}

/// The largest text file the program reads: configuration files, unit
/// files, scripts and its own profile and manifest are all far smaller.
pub const MAX_TEXT_FILE: u64 = 1024 * 1024;

fn too_large() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!("file is larger than {} bytes", MAX_TEXT_FILE),
    )
}

pub trait Host {
    fn read(&self, path: &Path) -> io::Result<Vec<u8>>;
    /// Reads a text file of at most [`MAX_TEXT_FILE`] bytes.
    fn read_to_string(&self, path: &Path) -> io::Result<String> {
        let bytes = self.read(path)?;
        if bytes.len() as u64 > MAX_TEXT_FILE {
            return Err(too_large());
        }
        String::from_utf8(bytes).map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
    }
    /// Entries of a directory, full paths, sorted.
    fn list_dir(&self, path: &Path) -> io::Result<Vec<PathBuf>>;
    fn read_link(&self, path: &Path) -> io::Result<PathBuf>;
    fn is_file(&self, path: &Path) -> bool;
    fn exists(&self, path: &Path) -> bool;
    /// Writes a file atomically (temporary file, then rename) with the
    /// given Unix mode and, when given, owner and group.
    fn write(
        &self,
        path: &Path,
        contents: &[u8],
        mode: u32,
        owner: Option<(u32, u32)>,
    ) -> io::Result<()>;
    /// Unix mode bits, owner and group of a file.
    fn stat(&self, path: &Path) -> io::Result<FileStat>;
    /// Takes an exclusive lock on the file, creating it, and writes
    /// `holder` into it for people to read. The kernel releases the lock when
    /// the holder exits, however it exits, so a lock is never stale and the
    /// file is never removed. `Ok(false)` while another process holds it.
    fn try_lock(&self, path: &Path, holder: &str) -> io::Result<bool>;
    /// Releases a lock this process took with [`Host::try_lock`].
    fn unlock(&self, path: &Path);
    fn remove_file(&self, path: &Path) -> io::Result<()>;
    /// Seconds since the Unix epoch.
    fn now_unix(&self) -> u64;
    fn create_dir_all(&self, path: &Path, mode: u32) -> io::Result<()>;
    /// Runs a program and waits for it.
    fn run(&self, program: &str, args: &[&str]) -> io::Result<CommandOutput>;
    /// Whether a program is on the search path.
    fn has_program(&self, program: &str) -> bool;
    /// Sends a signal; `Ok(false)` when the process is already gone.
    fn signal(&self, pid: u32, signal: Signal) -> io::Result<bool>;
    /// Starts a detached process in its own session. With `hold`, the new
    /// process waits before running its program until `hold` has run with
    /// its pid (on Linux; elsewhere `hold` is not called), so `hold` can move
    /// it, say into a cgroup, before it can start anything of its own.
    fn spawn_detached(&self, spawn: &Spawn, hold: Option<Hold<'_>>) -> io::Result<Spawned>;
    fn sleep_ms(&self, ms: u64);
    fn own_pid(&self) -> u32;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileStat {
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Signal {
    Terminate,
    Kill,
}

/// The real machine.
#[derive(Default)]
pub struct RealHost {
    /// Lock files this process holds; closing one releases its lock.
    locks: std::cell::RefCell<std::collections::BTreeMap<PathBuf, std::fs::File>>,
}

fn write_then_rename(
    options: &std::fs::OpenOptions,
    temporary: &Path,
    path: &Path,
    contents: &[u8],
    owner: Option<(u32, u32)>,
) -> io::Result<()> {
    use std::io::Write;
    let mut file = options.open(temporary)?;
    file.write_all(contents)?;
    file.sync_all()?;
    drop(file);
    #[cfg(unix)]
    {
        if let Some((uid, gid)) = owner {
            std::os::unix::fs::chown(temporary, Some(uid), Some(gid))?;
        }
    }
    #[cfg(not(unix))]
    let _ = owner;
    std::fs::rename(temporary, path)
}

/// Opens (creating) the lock file inside its directory without following
/// links, checking the directory itself rather than its name: the state
/// directory may come from the command line, and a planted link or a
/// directory others can write could redirect what we write there. The
/// directory is opened first and checked through its descriptor, and the
/// file is opened relative to that descriptor, so nothing can be swapped in
/// between the check and the open.
#[cfg(unix)]
fn open_lock_file(path: &Path) -> io::Result<std::fs::File> {
    use std::ffi::CString;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::MetadataExt;
    let dir = match path.parent() {
        Some(dir) if !dir.as_os_str().is_empty() => dir,
        _ => Path::new("."),
    };
    let name = path
        .file_name()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "lock path has no file name"))?;
    let invalid = |_| io::Error::new(io::ErrorKind::InvalidInput, "path contains a NUL byte");
    let dir_c = CString::new(dir.as_os_str().as_bytes()).map_err(invalid)?;
    let name_c = CString::new(name.as_bytes()).map_err(invalid)?;
    // SAFETY: a valid C string; the descriptor is owned right away.
    let dir_fd = unsafe {
        libc::open(
            dir_c.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if dir_fd == -1 {
        let error = io::Error::last_os_error();
        return Err(io::Error::new(
            error.kind(),
            format!(
                "{}: {error} (must be a directory, not a link)",
                dir.display()
            ),
        ));
    }
    // SAFETY: open just returned it and nothing else owns it.
    let dir_fd = unsafe { OwnedFd::from_raw_fd(dir_fd) };
    let metadata = std::fs::File::from(dir_fd.try_clone()?).metadata()?;
    // SAFETY: geteuid has no preconditions.
    let euid = unsafe { libc::geteuid() };
    if metadata.uid() != euid || metadata.mode() & 0o022 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "{} must belong to this user and not be writable by others",
                dir.display()
            ),
        ));
    }
    // SAFETY: a valid directory descriptor and C string; never truncates,
    // never follows a link planted where the lock file goes.
    let fd = unsafe {
        libc::openat(
            dir_fd.as_raw_fd(),
            name_c.as_ptr(),
            libc::O_RDWR | libc::O_CREAT | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600 as libc::c_uint,
        )
    };
    if fd == -1 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: openat just returned it and nothing else owns it.
    Ok(std::fs::File::from(unsafe { OwnedFd::from_raw_fd(fd) }))
}

impl Host for RealHost {
    fn read(&self, path: &Path) -> io::Result<Vec<u8>> {
        std::fs::read(path)
    }

    fn read_to_string(&self, path: &Path) -> io::Result<String> {
        use std::io::Read;
        // Never more than the limit in memory, whatever the file's size.
        let mut bytes = Vec::new();
        std::fs::File::open(path)?
            .take(MAX_TEXT_FILE + 1)
            .read_to_end(&mut bytes)?;
        if bytes.len() as u64 > MAX_TEXT_FILE {
            return Err(too_large());
        }
        String::from_utf8(bytes).map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
    }

    fn list_dir(&self, path: &Path) -> io::Result<Vec<PathBuf>> {
        let mut entries = std::fs::read_dir(path)?
            .filter_map(|entry| entry.ok().map(|entry| entry.path()))
            .collect::<Vec<_>>();
        entries.sort();
        Ok(entries)
    }

    fn read_link(&self, path: &Path) -> io::Result<PathBuf> {
        std::fs::read_link(path)
    }

    fn is_file(&self, path: &Path) -> bool {
        path.is_file()
    }

    fn exists(&self, path: &Path) -> bool {
        path.exists()
    }

    fn write(
        &self,
        path: &Path,
        contents: &[u8],
        mode: u32,
        owner: Option<(u32, u32)>,
    ) -> io::Result<()> {
        let parent = path.parent().unwrap_or_else(|| Path::new("."));
        let name = path
            .file_name()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "path has no file name"))?;
        let temporary = parent.join(format!(
            ".{}.tmp-{}",
            name.to_string_lossy(),
            std::process::id()
        ));
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(mode);
        }
        #[cfg(not(unix))]
        let _ = mode;
        let result = write_then_rename(&options, &temporary, path, contents, owner);
        if result.is_err() {
            let _ = std::fs::remove_file(&temporary);
        }
        result
    }

    #[cfg(unix)]
    fn stat(&self, path: &Path) -> io::Result<FileStat> {
        use std::os::unix::fs::MetadataExt;
        let metadata = std::fs::metadata(path)?;
        Ok(FileStat {
            mode: metadata.mode() & 0o7777,
            uid: metadata.uid(),
            gid: metadata.gid(),
        })
    }

    #[cfg(not(unix))]
    fn stat(&self, path: &Path) -> io::Result<FileStat> {
        std::fs::metadata(path)?;
        Ok(FileStat {
            mode: 0o644,
            uid: 0,
            gid: 0,
        })
    }

    fn try_lock(&self, path: &Path, holder: &str) -> io::Result<bool> {
        use std::io::Write;
        #[cfg(unix)]
        let mut file = open_lock_file(path)?;
        #[cfg(not(unix))]
        let mut file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            // Never truncate on open: the holder's text stays until we hold it.
            .truncate(false)
            .open(path)?;
        match file.try_lock() {
            Ok(()) => {}
            Err(std::fs::TryLockError::WouldBlock) => return Ok(false),
            Err(std::fs::TryLockError::Error(error)) => return Err(error),
        }
        file.set_len(0)?;
        file.write_all(holder.as_bytes())?;
        self.locks.borrow_mut().insert(path.to_path_buf(), file);
        Ok(true)
    }

    fn unlock(&self, path: &Path) {
        // Dropping the file closes it, which releases the lock.
        self.locks.borrow_mut().remove(path);
    }

    fn remove_file(&self, path: &Path) -> io::Result<()> {
        std::fs::remove_file(path)
    }

    fn now_unix(&self) -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|elapsed| elapsed.as_secs())
            .unwrap_or(0)
    }

    fn create_dir_all(&self, path: &Path, mode: u32) -> io::Result<()> {
        let mut builder = std::fs::DirBuilder::new();
        builder.recursive(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(mode);
        }
        #[cfg(not(unix))]
        let _ = mode;
        builder.create(path)
    }

    fn run(&self, program: &str, args: &[&str]) -> io::Result<CommandOutput> {
        let output = Command::new(program)
            .args(args)
            .env("LC_ALL", "C")
            .env("SYSTEMD_PAGER", "")
            .output()?;
        Ok(CommandOutput {
            code: output.status.code(),
            stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        })
    }

    fn has_program(&self, program: &str) -> bool {
        let Some(path) = std::env::var_os("PATH") else {
            return false;
        };
        std::env::split_paths(&path).any(|dir| dir.join(program).is_file())
    }

    #[cfg(unix)]
    fn signal(&self, pid: u32, signal: Signal) -> io::Result<bool> {
        let pid = libc::pid_t::try_from(pid)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "pid out of range"))?;
        if pid <= 1 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "refusing to signal pid 0 or 1",
            ));
        }
        let number = match signal {
            Signal::Terminate => libc::SIGTERM,
            Signal::Kill => libc::SIGKILL,
        };
        // SAFETY: kill(2) has no memory-safety preconditions.
        let result = unsafe { libc::kill(pid, number) };
        if result == 0 {
            return Ok(true);
        }
        let error = io::Error::last_os_error();
        if error.raw_os_error() == Some(libc::ESRCH) {
            Ok(false)
        } else {
            Err(error)
        }
    }

    #[cfg(not(unix))]
    fn signal(&self, _pid: u32, _signal: Signal) -> io::Result<bool> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "process signals are only implemented on Unix",
        ))
    }

    // The child runs in its own session and is meant to outlive this short
    // command; init reaps it once this process exits.
    #[allow(clippy::zombie_processes)]
    fn spawn_detached(&self, spawn: &Spawn, hold: Option<Hold<'_>>) -> io::Result<Spawned> {
        let (program, args) = spawn
            .argv
            .split_first()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "empty command"))?;
        let mut command = Command::new(program);
        command
            .args(args)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null());
        if spawn.clear_env {
            command.env_clear();
        }
        for (name, value) in &spawn.env {
            command.env(name, value);
        }
        if let Some(cwd) = &spawn.cwd {
            command.current_dir(cwd);
        }
        #[cfg(target_os = "linux")]
        let handshake = match hold {
            Some(_) => Some(Handshake::new()?),
            None => None,
        };
        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt;
            // Identity is changed here rather than with Command::uid/gid,
            // which drop every supplementary group when root changes user.
            let groups: Vec<libc::gid_t> = spawn.groups.clone().unwrap_or_default();
            let (uid, gid) = (spawn.uid, spawn.gid);
            let change_groups = uid.is_some() || spawn.groups.is_some();
            #[cfg(target_os = "linux")]
            let child_fds = handshake.as_ref().map(Handshake::child_fds);
            // SAFETY: only async-signal-safe calls (close, getpid, write,
            // read, setsid, setgroups, setgid, setuid) on memory prepared
            // before the fork.
            unsafe {
                command.pre_exec(move || {
                    #[cfg(target_os = "linux")]
                    if let Some(fds) = child_fds {
                        wait_for_parent(fds)?;
                    }
                    if libc::setsid() == -1 {
                        return Err(io::Error::last_os_error());
                    }
                    // Groups, then the group, then the user: once the user
                    // changes, neither can.
                    if change_groups
                        && libc::geteuid() == 0
                        && libc::setgroups(groups.len() as _, groups.as_ptr()) == -1
                    {
                        return Err(io::Error::last_os_error());
                    }
                    if let Some(gid) = gid {
                        if libc::setgid(gid) == -1 {
                            return Err(io::Error::last_os_error());
                        }
                    }
                    if let Some(uid) = uid {
                        if libc::setuid(uid) == -1 {
                            return Err(io::Error::last_os_error());
                        }
                    }
                    Ok(())
                });
            }
        }
        #[cfg(target_os = "linux")]
        if let (Some(handshake), Some(hold)) = (handshake, hold) {
            return handshake.spawn(command, hold);
        }
        #[cfg(not(target_os = "linux"))]
        let _ = hold;
        let child = command.spawn()?;
        Ok(Spawned {
            pid: child.id(),
            held: None,
        })
    }

    fn sleep_ms(&self, ms: u64) {
        std::thread::sleep(std::time::Duration::from_millis(ms));
    }

    fn own_pid(&self) -> u32 {
        std::process::id()
    }
}

/// Pipes between the parent and a new process that waits before running
/// its program (Linux). Command::spawn only returns once the program runs,
/// so the spawn happens on another thread while this one reads the pid,
/// runs the hold and lets the process go on.
#[cfg(target_os = "linux")]
struct Handshake {
    pid_read: std::os::fd::OwnedFd,
    pid_write: std::os::fd::OwnedFd,
    go_read: std::os::fd::OwnedFd,
    go_write: std::os::fd::OwnedFd,
}

/// The descriptors a waiting child uses: (pid_read, pid_write, go_read,
/// go_write); it closes the two ends that belong to the parent.
#[cfg(target_os = "linux")]
type ChildFds = (i32, i32, i32, i32);

/// How long the parent waits for the new process to report its pid.
#[cfg(target_os = "linux")]
const HANDSHAKE_TIMEOUT_MS: i32 = 10_000;

#[cfg(target_os = "linux")]
fn cloexec_pipe() -> io::Result<(std::os::fd::OwnedFd, std::os::fd::OwnedFd)> {
    use std::os::fd::FromRawFd;
    let mut fds = [0; 2];
    // SAFETY: fds has room for the two descriptors pipe2 writes.
    if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } == -1 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: pipe2 just returned these descriptors and nothing else owns
    // them.
    Ok(unsafe {
        (
            std::os::fd::OwnedFd::from_raw_fd(fds[0]),
            std::os::fd::OwnedFd::from_raw_fd(fds[1]),
        )
    })
}

/// In the child, between fork and exec: report the pid, then wait for the
/// parent's go. End of file (the parent gave up) stops the spawn.
///
/// # Safety
/// Called only in a forked child; uses only async-signal-safe calls.
#[cfg(target_os = "linux")]
unsafe fn wait_for_parent((pid_read, pid_write, go_read, go_write): ChildFds) -> io::Result<()> {
    // Without the parent's ends, a parent that gives up shows as end of file.
    libc::close(pid_read);
    libc::close(go_write);
    let pid = (libc::getpid() as u32).to_ne_bytes();
    if libc::write(pid_write, pid.as_ptr().cast(), pid.len()) != pid.len() as isize {
        return Err(io::Error::last_os_error());
    }
    let mut go = [0u8; 1];
    loop {
        match libc::read(go_read, go.as_mut_ptr().cast(), 1) {
            1 => return Ok(()),
            0 => return Err(io::Error::from_raw_os_error(libc::ECANCELED)),
            _ if io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) => continue,
            _ => return Err(io::Error::last_os_error()),
        }
    }
}

#[cfg(target_os = "linux")]
impl Handshake {
    fn new() -> io::Result<Self> {
        let (pid_read, pid_write) = cloexec_pipe()?;
        let (go_read, go_write) = cloexec_pipe()?;
        Ok(Handshake {
            pid_read,
            pid_write,
            go_read,
            go_write,
        })
    }

    fn child_fds(&self) -> ChildFds {
        use std::os::fd::AsRawFd;
        (
            self.pid_read.as_raw_fd(),
            self.pid_write.as_raw_fd(),
            self.go_read.as_raw_fd(),
            self.go_write.as_raw_fd(),
        )
    }

    // As in RealHost::spawn_detached: the child outlives this command.
    #[allow(clippy::zombie_processes)]
    fn spawn(self, mut command: Command, hold: Hold<'_>) -> io::Result<Spawned> {
        use std::io::{Read, Write};
        use std::os::fd::AsRawFd;
        let Handshake {
            pid_read,
            pid_write,
            go_read,
            go_write,
        } = self;
        // The child's ends stay open in this process until the spawn is
        // done; the child closes the parent's ends in its own copy.
        let worker = std::thread::spawn(move || {
            let result = command.spawn().map(|child| child.id());
            drop((pid_write, go_read));
            result
        });
        let mut poll = libc::pollfd {
            fd: pid_read.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // A signal interrupts poll; wait again for whatever time is left.
        let deadline = std::time::Instant::now()
            + std::time::Duration::from_millis(HANDSHAKE_TIMEOUT_MS as u64);
        let ready = loop {
            let left = deadline.saturating_duration_since(std::time::Instant::now());
            // SAFETY: one valid pollfd.
            let ready = unsafe { libc::poll(&mut poll, 1, left.as_millis() as i32) };
            if ready == -1
                && io::Error::last_os_error().raw_os_error() == Some(libc::EINTR)
                && !left.is_zero()
            {
                continue;
            }
            break ready;
        };
        let mut pid_bytes = [0u8; 4];
        let reported = if ready == 1 {
            std::fs::File::from(pid_read)
                .read_exact(&mut pid_bytes)
                .ok()
                .map(|()| u32::from_ne_bytes(pid_bytes))
        } else {
            None
        };
        let held = reported.map(hold);
        // Go, or (no pid) end of file so a child still waiting gives up.
        let mut go = std::fs::File::from(go_write);
        if reported.is_some() {
            let _ = go.write_all(&[1]);
        }
        drop(go);
        let pid = worker
            .join()
            .map_err(|_| io::Error::other("spawn thread panicked"))??;
        Ok(Spawned { pid, held })
    }
}

#[cfg(all(test, target_os = "linux"))]
mod real_tests {
    use super::*;

    #[test]
    fn a_held_process_runs_nothing_until_released() {
        let host = RealHost::default();
        let own_exe = std::fs::read_link("/proc/self/exe").unwrap();
        let seen = std::cell::RefCell::new(None);
        let hold = |pid: u32| {
            // Still this test program: the new process has not run its
            // own program yet.
            let exe = std::fs::read_link(format!("/proc/{pid}/exe")).map_err(|e| e.to_string())?;
            *seen.borrow_mut() = Some(exe.clone());
            Ok(format!("held {pid}"))
        };
        let spawned = host
            .spawn_detached(
                &Spawn {
                    argv: vec!["/bin/sh".into(), "-c".into(), "exit 0".into()],
                    env: Vec::new(),
                    clear_env: true,
                    cwd: None,
                    uid: None,
                    gid: None,
                    groups: None,
                },
                Some(&hold as Hold<'_>),
            )
            .unwrap();
        assert_eq!(spawned.held, Some(Ok(format!("held {}", spawned.pid))));
        assert_eq!(seen.borrow().as_deref(), Some(own_exe.as_path()));
    }

    #[test]
    fn the_lock_refuses_links_and_open_directories() {
        use std::os::unix::fs::PermissionsExt;
        let base = std::env::temp_dir().join(format!("mesh-lock-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(base.join("state")).unwrap();
        std::fs::set_permissions(base.join("state"), std::fs::Permissions::from_mode(0o700))
            .unwrap();
        let host = RealHost::default();
        assert!(host.try_lock(&base.join("state/lock"), "1").unwrap());
        // A second holder in the same process is refused by the kernel.
        let other = RealHost::default();
        assert!(!other.try_lock(&base.join("state/lock"), "2").unwrap());
        host.unlock(&base.join("state/lock"));
        // A link where the lock file goes is never followed.
        std::fs::write(base.join("target"), "keep").unwrap();
        std::os::unix::fs::symlink(base.join("target"), base.join("state/linked")).unwrap();
        assert!(other.try_lock(&base.join("state/linked"), "2").is_err());
        assert_eq!(
            std::fs::read_to_string(base.join("target")).unwrap(),
            "keep"
        );
        // A directory reached through a link, or writable by others.
        std::os::unix::fs::symlink(base.join("state"), base.join("via")).unwrap();
        assert!(other.try_lock(&base.join("via/lock"), "2").is_err());
        std::fs::set_permissions(base.join("state"), std::fs::Permissions::from_mode(0o777))
            .unwrap();
        assert!(other.try_lock(&base.join("state/lock"), "2").is_err());
        let _ = std::fs::remove_dir_all(&base);
    }
}

#[cfg(test)]
pub(crate) mod fake {
    //! An in-memory machine for tests.
    #![allow(dead_code)]

    use super::*;
    use std::cell::RefCell;
    use std::collections::{BTreeMap, BTreeSet};

    #[derive(Default)]
    pub(crate) struct FakeHost {
        pub files: RefCell<BTreeMap<PathBuf, Vec<u8>>>,
        pub links: RefCell<BTreeMap<PathBuf, PathBuf>>,
        pub dirs: RefCell<BTreeSet<PathBuf>>,
        pub programs: BTreeSet<String>,
        /// Answers keyed by "program arg arg".
        pub answers: RefCell<BTreeMap<String, CommandOutput>>,
        /// Every command run, in order.
        pub ran: RefCell<Vec<String>>,
        /// Live processes; a signal removes them unless listed in `stubborn`.
        pub alive: RefCell<BTreeSet<u32>>,
        pub stubborn: RefCell<BTreeSet<u32>>,
        pub signals: RefCell<Vec<(u32, Signal)>>,
        pub spawned: RefCell<Vec<Spawn>>,
        pub stats: RefCell<BTreeMap<PathBuf, FileStat>>,
        /// Locks this process holds.
        pub locks: RefCell<BTreeSet<PathBuf>>,
        /// Locks another live process holds.
        pub held_by_others: RefCell<BTreeSet<PathBuf>>,
        /// Live processes no signal ends.
        pub unkillable: RefCell<BTreeSet<u32>>,
        /// Every wait, in milliseconds.
        pub slept: RefCell<Vec<u64>>,
        /// Processes (pid, argv, cgroup) that appear at the next wait of a
        /// second or more.
        pub respawn_after_sleep: RefCell<Vec<(u32, Vec<String>, String)>>,
    }

    impl FakeHost {
        pub fn file(&self, path: &str, contents: &str) {
            self.add_parents(Path::new(path));
            self.files
                .borrow_mut()
                .insert(PathBuf::from(path), contents.as_bytes().to_vec());
        }

        pub fn link(&self, path: &str, target: &str) {
            self.add_parents(Path::new(path));
            self.links
                .borrow_mut()
                .insert(PathBuf::from(path), PathBuf::from(target));
        }

        pub fn answer(&self, command: &str, code: i32, stdout: &str) {
            self.answers.borrow_mut().insert(
                command.to_string(),
                CommandOutput {
                    code: Some(code),
                    stdout: stdout.to_string(),
                    stderr: String::new(),
                },
            );
        }

        pub fn text(&self, path: &str) -> Option<String> {
            self.files
                .borrow()
                .get(Path::new(path))
                .map(|bytes| String::from_utf8_lossy(bytes).into_owned())
        }

        /// A running process with the given exe, argv and environment.
        pub fn process(&self, pid: u32, exe: &str, argv: &[&str], env: &[&str], cgroup: &str) {
            let base = format!("/proc/{pid}");
            self.link(&format!("{base}/exe"), exe);
            self.link(&format!("{base}/cwd"), "/");
            let mut cmdline = argv.join("\0");
            cmdline.push('\0');
            self.file(&format!("{base}/cmdline"), &cmdline);
            let mut environ = env.join("\0");
            environ.push('\0');
            self.file(&format!("{base}/environ"), &environ);
            self.file(&format!("{base}/cgroup"), cgroup);
            self.alive.borrow_mut().insert(pid);
        }

        fn add_parents(&self, path: &Path) {
            let mut dirs = self.dirs.borrow_mut();
            let mut current = path.parent();
            while let Some(dir) = current {
                dirs.insert(dir.to_path_buf());
                current = dir.parent();
            }
        }

        fn remove_process(&self, pid: u32) {
            let base = PathBuf::from(format!("/proc/{pid}"));
            self.files
                .borrow_mut()
                .retain(|path, _| !path.starts_with(&base));
            self.links
                .borrow_mut()
                .retain(|path, _| !path.starts_with(&base));
            self.dirs.borrow_mut().remove(&base);
            self.alive.borrow_mut().remove(&pid);
        }
    }

    impl Host for FakeHost {
        fn read(&self, path: &Path) -> io::Result<Vec<u8>> {
            self.files
                .borrow()
                .get(path)
                .cloned()
                .ok_or_else(|| io::Error::from(io::ErrorKind::NotFound))
        }

        fn list_dir(&self, path: &Path) -> io::Result<Vec<PathBuf>> {
            if !self.dirs.borrow().contains(path) {
                return Err(io::Error::from(io::ErrorKind::NotFound));
            }
            let mut out = BTreeSet::new();
            let files = self.files.borrow();
            let links = self.links.borrow();
            let dirs = self.dirs.borrow();
            for candidate in files.keys().chain(links.keys()).chain(dirs.iter()) {
                if candidate.parent() == Some(path) {
                    out.insert(candidate.clone());
                }
            }
            Ok(out.into_iter().collect())
        }

        fn read_link(&self, path: &Path) -> io::Result<PathBuf> {
            self.links
                .borrow()
                .get(path)
                .cloned()
                .ok_or_else(|| io::Error::from(io::ErrorKind::NotFound))
        }

        fn is_file(&self, path: &Path) -> bool {
            self.files.borrow().contains_key(path)
        }

        fn exists(&self, path: &Path) -> bool {
            self.files.borrow().contains_key(path)
                || self.links.borrow().contains_key(path)
                || self.dirs.borrow().contains(path)
        }

        fn write(
            &self,
            path: &Path,
            contents: &[u8],
            mode: u32,
            owner: Option<(u32, u32)>,
        ) -> io::Result<()> {
            self.add_parents(path);
            self.files
                .borrow_mut()
                .insert(path.to_path_buf(), contents.to_vec());
            let (uid, gid) = owner.unwrap_or((0, 0));
            self.stats
                .borrow_mut()
                .insert(path.to_path_buf(), FileStat { mode, uid, gid });
            Ok(())
        }

        fn stat(&self, path: &Path) -> io::Result<FileStat> {
            if !self.files.borrow().contains_key(path) {
                return Err(io::Error::from(io::ErrorKind::NotFound));
            }
            Ok(self.stats.borrow().get(path).copied().unwrap_or(FileStat {
                mode: 0o644,
                uid: 0,
                gid: 0,
            }))
        }

        fn try_lock(&self, path: &Path, holder: &str) -> io::Result<bool> {
            if self.held_by_others.borrow().contains(path) || self.locks.borrow().contains(path) {
                return Ok(false);
            }
            self.file(&path.display().to_string(), holder);
            self.locks.borrow_mut().insert(path.to_path_buf());
            Ok(true)
        }

        fn unlock(&self, path: &Path) {
            self.locks.borrow_mut().remove(path);
        }

        fn remove_file(&self, path: &Path) -> io::Result<()> {
            self.files
                .borrow_mut()
                .remove(path)
                .map(|_| ())
                .ok_or_else(|| io::Error::from(io::ErrorKind::NotFound))
        }

        fn now_unix(&self) -> u64 {
            1_700_000_000
        }

        fn create_dir_all(&self, path: &Path, _mode: u32) -> io::Result<()> {
            self.add_parents(&path.join("x"));
            Ok(())
        }

        fn run(&self, program: &str, args: &[&str]) -> io::Result<CommandOutput> {
            let mut key = program.to_string();
            for arg in args {
                key.push(' ');
                key.push_str(arg);
            }
            self.ran.borrow_mut().push(key.clone());
            // systemd moving a process into a new scope.
            if program == "busctl" && args.contains(&"StartTransientUnit") {
                if let (Some(scope), Some(pid)) = (args.get(6), args.get(12)) {
                    self.file(
                        &format!("/proc/{pid}/cgroup"),
                        &format!("0::/system.slice/{scope}\n"),
                    );
                }
            }
            Ok(self
                .answers
                .borrow()
                .get(&key)
                .cloned()
                .unwrap_or(CommandOutput {
                    code: Some(0),
                    stdout: String::new(),
                    stderr: String::new(),
                }))
        }

        fn has_program(&self, program: &str) -> bool {
            self.programs.contains(program)
        }

        fn signal(&self, pid: u32, signal: Signal) -> io::Result<bool> {
            self.signals.borrow_mut().push((pid, signal));
            if !self.alive.borrow().contains(&pid) {
                return Ok(false);
            }
            if self.unkillable.borrow().contains(&pid) {
                return Ok(true);
            }
            let stubborn = self.stubborn.borrow().contains(&pid);
            if !stubborn || signal == Signal::Kill {
                self.remove_process(pid);
            }
            Ok(true)
        }

        fn spawn_detached(&self, spawn: &Spawn, hold: Option<Hold<'_>>) -> io::Result<Spawned> {
            self.spawned.borrow_mut().push(spawn.clone());
            Ok(Spawned {
                pid: 4242,
                held: hold.map(|hold| hold(4242)),
            })
        }

        fn sleep_ms(&self, ms: u64) {
            self.slept.borrow_mut().push(ms);
            // Processes a supervisor starts again while we wait out its
            // restart delay (not during the short polls for an exit).
            if ms < 1_000 {
                return;
            }
            let respawn: Vec<_> = self.respawn_after_sleep.borrow_mut().drain(..).collect();
            for (pid, argv, cgroup) in respawn {
                let argv: Vec<&str> = argv.iter().map(String::as_str).collect();
                self.process(pid, argv[0], &argv, &[], &cgroup);
            }
        }

        fn own_pid(&self) -> u32 {
            1
        }
    }
}
