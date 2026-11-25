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
    /// Writes an owner-only file (mode 0600) in one of the program's
    /// state directories, which must belong to this user and not be
    /// writable by others, with every directory above it belonging to root
    /// or this user; on Unix through the directory's descriptor, never
    /// following a link.
    fn write_state(&self, path: &Path, contents: &[u8]) -> io::Result<()> {
        self.write(path, contents, 0o600, None)
    }
    /// Reads a file of at most [`MAX_TEXT_FILE`] bytes from one of the
    /// program's state directories, checked as for [`Host::write_state`].
    fn read_state(&self, path: &Path) -> io::Result<Vec<u8>> {
        let bytes = self.read(path)?;
        if bytes.len() as u64 > MAX_TEXT_FILE {
            return Err(too_large());
        }
        Ok(bytes)
    }
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
    /// Every process id, where processes are not files under `/proc`
    /// (macOS). Elsewhere the program reads `/proc` instead.
    fn list_pids(&self) -> io::Result<Vec<u32>> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "no process table on this system",
        ))
    }
    /// What a process runs and as whom, where processes are not files
    /// under `/proc` (macOS). `NotFound` once it is gone.
    fn process_info(&self, _pid: u32) -> io::Result<ProcInfo> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "no process table on this system",
        ))
    }
}

/// A process as the system's process table describes it (macOS).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProcInfo {
    /// The program file; `None` when it cannot be read.
    pub exe: Option<String>,
    /// Full argv; empty when it cannot be read.
    pub argv: Vec<String>,
    pub environ: Vec<(String, String)>,
    /// Real user and group; `None` when they cannot be read.
    pub uid: Option<u32>,
    pub gid: Option<u32>,
    /// The user's groups, as a login gives them.
    pub groups: Option<Vec<u32>>,
    pub cwd: Option<String>,
}

/// Splits the `KERN_PROCARGS2` buffer of a macOS process: the argument
/// count (a native-endian 32-bit integer), the program path, padding, then
/// the arguments and the environment, each ending in NUL. `None` when the
/// buffer is shorter than its own count says.
pub fn parse_procargs2(buffer: &[u8]) -> Option<(Vec<String>, Vec<(String, String)>)> {
    let count = i32::from_ne_bytes(buffer.get(..4)?.try_into().ok()?);
    let count = usize::try_from(count).ok()?;
    let mut rest = &buffer[4..];
    // The program path, then the NULs that pad it.
    let end = rest.iter().position(|byte| *byte == 0)?;
    rest = &rest[end..];
    let start = rest.iter().position(|byte| *byte != 0)?;
    rest = &rest[start..];
    let mut strings = rest.split(|byte| *byte == 0);
    let mut argv = Vec::with_capacity(count);
    for _ in 0..count {
        argv.push(String::from_utf8_lossy(strings.next()?).into_owned());
    }
    let mut environ = Vec::new();
    for string in strings {
        // The environment ends at the first empty string.
        if string.is_empty() {
            break;
        }
        let text = String::from_utf8_lossy(string);
        if let Some((name, value)) = text.split_once('=') {
            environ.push((name.to_string(), value.to_string()));
        }
    }
    Some((argv, environ))
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

/// Opens a directory the program keeps its state in and checks every
/// directory on the way to it, through descriptors and never following a
/// link: each one above it must belong to root or this user and not be
/// writable by others (a sticky directory such as `/tmp` is allowed, since
/// others can neither rename nor remove what we own in it), and the
/// directory itself must belong to this user and not be writable by others.
/// The state directory may come from the command line; a link or a
/// directory others can write anywhere on its path could otherwise redirect
/// what we read and write there, including the record a rollback trusts to
/// start programs as other users. Files are then opened relative to the
/// returned descriptor, so nothing can be swapped in between the check and
/// the use.
#[cfg(unix)]
fn open_checked_dir(dir: &Path) -> io::Result<std::os::fd::OwnedFd> {
    use std::ffi::CString;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::MetadataExt;
    use std::path::Component;
    let absolute = if dir.is_absolute() {
        dir.to_path_buf()
    } else {
        std::env::current_dir()?.join(dir)
    };
    // SAFETY: geteuid has no preconditions.
    let euid = unsafe { libc::geteuid() };
    // S_ISVTX; libc's constant is a different integer type on each system.
    const STICKY: u32 = 0o1000;
    let refuse = |what: &Path, why: &str| {
        io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("{}: {why}", what.display()),
        )
    };
    let check = |fd: &OwnedFd, at: &Path, last: bool| -> io::Result<()> {
        let metadata = std::fs::File::from(fd.try_clone()?).metadata()?;
        let writable = metadata.mode() & 0o022 != 0;
        if last {
            if metadata.uid() != euid || writable {
                return Err(refuse(
                    at,
                    "must belong to this user and not be writable by others",
                ));
            }
        } else if (metadata.uid() != 0 && metadata.uid() != euid)
            || (writable && metadata.mode() & STICKY == 0)
        {
            return Err(refuse(
                at,
                "every directory above the state directory must belong to root or this user and not be writable by others",
            ));
        }
        Ok(())
    };
    let open_flags = libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC;
    // SAFETY: a valid C string; the descriptor is owned right away.
    let root = unsafe { libc::open(c"/".as_ptr(), open_flags) };
    if root == -1 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: open just returned it and nothing else owns it.
    let mut fd = unsafe { OwnedFd::from_raw_fd(root) };
    let names: Vec<&std::ffi::OsStr> = absolute
        .components()
        .filter_map(|component| match component {
            Component::Normal(name) => Some(Ok(name)),
            Component::RootDir | Component::CurDir => None,
            Component::ParentDir | Component::Prefix(_) => Some(Err(())),
        })
        .collect::<Result<_, ()>>()
        .map_err(|()| refuse(dir, "must not contain .."))?;
    let mut at = PathBuf::from("/");
    check(&fd, &at, names.is_empty())?;
    for (index, name) in names.iter().enumerate() {
        at.push(name);
        let name_c = CString::new(name.as_bytes()).map_err(nul_in_path)?;
        // SAFETY: a valid directory descriptor and C string.
        let next = unsafe { libc::openat(fd.as_raw_fd(), name_c.as_ptr(), open_flags) };
        if next == -1 {
            let error = io::Error::last_os_error();
            return Err(io::Error::new(
                error.kind(),
                format!(
                    "{}: {error} (must be a directory, not a link)",
                    at.display()
                ),
            ));
        }
        // SAFETY: openat just returned it and nothing else owns it.
        fd = unsafe { OwnedFd::from_raw_fd(next) };
        check(&fd, &at, index + 1 == names.len())?;
    }
    Ok(fd)
}

/// Reads a file of at most [`MAX_TEXT_FILE`] bytes from a checked state
/// directory, relative to its descriptor and never following a link.
#[cfg(unix)]
fn read_state_file(path: &Path) -> io::Result<Vec<u8>> {
    use std::io::Read;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    let (dir, name_c) = split_state_path(path)?;
    let dir_fd = open_checked_dir(dir)?;
    // SAFETY: a valid directory descriptor and C string.
    let fd = unsafe {
        libc::openat(
            dir_fd.as_raw_fd(),
            name_c.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd == -1 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: openat just returned it and nothing else owns it.
    let file = std::fs::File::from(unsafe { OwnedFd::from_raw_fd(fd) });
    if !file.metadata()?.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{}: not a regular file", path.display()),
        ));
    }
    let mut bytes = Vec::new();
    file.take(MAX_TEXT_FILE + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_TEXT_FILE {
        return Err(too_large());
    }
    Ok(bytes)
}

#[cfg(unix)]
fn nul_in_path<T>(_: T) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, "path contains a NUL byte")
}

/// The directory and file name of a path inside a state directory.
#[cfg(unix)]
fn split_state_path(path: &Path) -> io::Result<(&Path, std::ffi::CString)> {
    use std::os::unix::ffi::OsStrExt;
    let dir = match path.parent() {
        Some(dir) if !dir.as_os_str().is_empty() => dir,
        _ => Path::new("."),
    };
    let name = path
        .file_name()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "path has no file name"))?;
    let name = std::ffi::CString::new(name.as_bytes()).map_err(nul_in_path)?;
    Ok((dir, name))
}

/// Opens (creating) the lock file inside its checked directory without
/// following links; see [`open_checked_dir`].
#[cfg(unix)]
fn open_lock_file(path: &Path) -> io::Result<std::fs::File> {
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    let (dir, name_c) = split_state_path(path)?;
    let dir_fd = open_checked_dir(dir)?;
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

/// Writes an owner-only file in a checked state directory: a temporary file
/// created next to it through the directory's descriptor, then renamed over
/// it through the same descriptor, so neither the write nor the rename can
/// be redirected by swapping the directory or planting a link.
#[cfg(unix)]
fn write_state_file(path: &Path, contents: &[u8]) -> io::Result<()> {
    use std::io::Write;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    let (dir, name_c) = split_state_path(path)?;
    let dir_fd = open_checked_dir(dir)?;
    let mut temporary = b".".to_vec();
    temporary.extend_from_slice(name_c.as_bytes());
    temporary.extend_from_slice(format!(".tmp-{}", std::process::id()).as_bytes());
    let temporary = std::ffi::CString::new(temporary).map_err(nul_in_path)?;
    let remove_temporary = || {
        // SAFETY: a valid directory descriptor and C string.
        unsafe { libc::unlinkat(dir_fd.as_raw_fd(), temporary.as_ptr(), 0) };
    };
    let create = || {
        // SAFETY: a valid directory descriptor and C string; O_EXCL with
        // O_NOFOLLOW never opens an existing file or a link.
        unsafe {
            libc::openat(
                dir_fd.as_raw_fd(),
                temporary.as_ptr(),
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0o600 as libc::c_uint,
            )
        }
    };
    let mut fd = create();
    if fd == -1 && io::Error::last_os_error().kind() == io::ErrorKind::AlreadyExists {
        // Left by an earlier run that crashed with the same pid; the
        // directory is ours alone, so it is ours to remove.
        remove_temporary();
        fd = create();
    }
    if fd == -1 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: openat just returned it and nothing else owns it.
    let mut file = std::fs::File::from(unsafe { OwnedFd::from_raw_fd(fd) });
    let written = file.write_all(contents).and_then(|()| file.sync_all());
    drop(file);
    if let Err(error) = written {
        remove_temporary();
        return Err(error);
    }
    // SAFETY: valid descriptors and C strings.
    let renamed = unsafe {
        libc::renameat(
            dir_fd.as_raw_fd(),
            temporary.as_ptr(),
            dir_fd.as_raw_fd(),
            name_c.as_ptr(),
        )
    };
    if renamed == -1 {
        let error = io::Error::last_os_error();
        remove_temporary();
        return Err(error);
    }
    // The rename itself survives a crash only once the directory is synced.
    std::fs::File::from(dir_fd).sync_all()
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
    fn write_state(&self, path: &Path, contents: &[u8]) -> io::Result<()> {
        write_state_file(path, contents)
    }

    #[cfg(unix)]
    fn read_state(&self, path: &Path) -> io::Result<Vec<u8>> {
        read_state_file(path)
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

    #[cfg(target_os = "macos")]
    fn list_pids(&self) -> io::Result<Vec<u32>> {
        darwin::list_pids()
    }

    #[cfg(target_os = "macos")]
    fn process_info(&self, pid: u32) -> io::Result<ProcInfo> {
        darwin::process_info(pid)
    }
}

/// The macOS process table, read through libproc and sysctl: the program
/// path, arguments and environment exactly as the kernel holds them.
#[cfg(target_os = "macos")]
mod darwin {
    use super::{parse_procargs2, ProcInfo};
    use std::ffi::{CStr, CString};
    use std::io;
    use std::mem::{size_of, MaybeUninit};

    fn pid_arg(pid: u32) -> io::Result<libc::c_int> {
        libc::c_int::try_from(pid)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "pid out of range"))
    }

    /// `NotFound` for a process that is gone, the OS error otherwise.
    fn os_error() -> io::Error {
        let error = io::Error::last_os_error();
        if error.raw_os_error() == Some(libc::ESRCH) {
            io::Error::from(io::ErrorKind::NotFound)
        } else {
            error
        }
    }

    pub(super) fn list_pids() -> io::Result<Vec<u32>> {
        // SAFETY: a null buffer asks only for the count.
        let count = unsafe { libc::proc_listallpids(std::ptr::null_mut(), 0) };
        if count <= 0 {
            return Err(io::Error::last_os_error());
        }
        // Room for processes started since the count.
        let mut pids: Vec<libc::c_int> = vec![0; count as usize + 256];
        let bytes = libc::c_int::try_from(pids.len() * size_of::<libc::c_int>())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "too many processes"))?;
        // SAFETY: the buffer holds `bytes` bytes.
        let got = unsafe { libc::proc_listallpids(pids.as_mut_ptr().cast(), bytes) };
        if got < 0 {
            return Err(io::Error::last_os_error());
        }
        pids.truncate((got as usize).min(pids.len()));
        Ok(pids
            .into_iter()
            .filter_map(|pid| u32::try_from(pid).ok())
            .filter(|pid| *pid > 0)
            .collect())
    }

    fn bsd_info(pid: libc::c_int) -> io::Result<libc::proc_bsdinfo> {
        let mut info = MaybeUninit::<libc::proc_bsdinfo>::zeroed();
        let size = size_of::<libc::proc_bsdinfo>() as libc::c_int;
        // SAFETY: the buffer is a proc_bsdinfo of `size` bytes.
        let got = unsafe {
            libc::proc_pidinfo(
                pid,
                libc::PROC_PIDTBSDINFO,
                0,
                info.as_mut_ptr().cast(),
                size,
            )
        };
        if got != size {
            return Err(os_error());
        }
        // SAFETY: proc_pidinfo filled all `size` bytes.
        Ok(unsafe { info.assume_init() })
    }

    fn program_path(pid: libc::c_int) -> Option<String> {
        let mut buffer = vec![0u8; libc::PROC_PIDPATHINFO_MAXSIZE as usize];
        // SAFETY: the buffer holds PROC_PIDPATHINFO_MAXSIZE bytes.
        let len =
            unsafe { libc::proc_pidpath(pid, buffer.as_mut_ptr().cast(), buffer.len() as u32) };
        if len <= 0 {
            return None;
        }
        buffer.truncate(len as usize);
        String::from_utf8(buffer).ok()
    }

    fn arguments(pid: libc::c_int) -> Option<(Vec<String>, Vec<(String, String)>)> {
        let mut max: libc::c_int = 0;
        let mut size = size_of::<libc::c_int>();
        let mut mib = [libc::CTL_KERN, libc::KERN_ARGMAX];
        // SAFETY: `max` is a c_int and `size` its size.
        let result = unsafe {
            libc::sysctl(
                mib.as_mut_ptr(),
                2,
                (&mut max as *mut libc::c_int).cast(),
                &mut size,
                std::ptr::null_mut(),
                0,
            )
        };
        if result != 0 || max <= 0 {
            return None;
        }
        let mut buffer = vec![0u8; max as usize];
        let mut size = buffer.len();
        let mut mib = [libc::CTL_KERN, libc::KERN_PROCARGS2, pid];
        // SAFETY: the buffer holds `size` bytes; sysctl writes at most that
        // and sets `size` to what it wrote.
        let result = unsafe {
            libc::sysctl(
                mib.as_mut_ptr(),
                3,
                buffer.as_mut_ptr().cast(),
                &mut size,
                std::ptr::null_mut(),
                0,
            )
        };
        if result != 0 {
            return None;
        }
        buffer.truncate(size);
        parse_procargs2(&buffer)
    }

    fn working_directory(pid: libc::c_int) -> Option<String> {
        let mut info = MaybeUninit::<libc::proc_vnodepathinfo>::zeroed();
        let size = size_of::<libc::proc_vnodepathinfo>() as libc::c_int;
        // SAFETY: the buffer is a proc_vnodepathinfo of `size` bytes.
        let got = unsafe {
            libc::proc_pidinfo(
                pid,
                libc::PROC_PIDVNODEPATHINFO,
                0,
                info.as_mut_ptr().cast(),
                size,
            )
        };
        if got != size {
            return None;
        }
        // SAFETY: proc_pidinfo filled all `size` bytes.
        let info = unsafe { info.assume_init() };
        let bytes: Vec<u8> = info
            .pvi_cdir
            .vip_path
            .iter()
            .flatten()
            .map(|byte| *byte as u8)
            .take_while(|byte| *byte != 0)
            .collect();
        if bytes.is_empty() {
            return None;
        }
        String::from_utf8(bytes).ok()
    }

    /// The groups a login as this user gets, which is what launchd and a
    /// shell started as the user give its processes.
    fn login_groups(uid: u32, gid: u32) -> Option<Vec<u32>> {
        let mut record = MaybeUninit::<libc::passwd>::zeroed();
        let mut text = vec![0 as libc::c_char; 16 * 1024];
        let mut found: *mut libc::passwd = std::ptr::null_mut();
        // SAFETY: every buffer outlives the call and has the size passed.
        let result = unsafe {
            libc::getpwuid_r(
                uid,
                record.as_mut_ptr(),
                text.as_mut_ptr(),
                text.len(),
                &mut found,
            )
        };
        if result != 0 || found.is_null() {
            return None;
        }
        // SAFETY: getpwuid_r succeeded, so the record and its name are set.
        let name: CString = unsafe { CStr::from_ptr((*found).pw_name) }.to_owned();
        let mut count: libc::c_int = 64;
        loop {
            let mut groups: Vec<libc::c_int> = vec![0; count as usize];
            let mut got = count;
            // SAFETY: `groups` holds `got` entries.
            let result = unsafe {
                libc::getgrouplist(
                    name.as_ptr(),
                    gid as libc::c_int,
                    groups.as_mut_ptr(),
                    &mut got,
                )
            };
            if result == 0 {
                groups.truncate((got as usize).min(groups.len()));
                return Some(groups.into_iter().map(|group| group as u32).collect());
            }
            if count >= 4096 {
                return None;
            }
            count *= 4;
        }
    }

    pub(super) fn process_info(pid: u32) -> io::Result<ProcInfo> {
        let pid = pid_arg(pid)?;
        let info = bsd_info(pid)?;
        let (argv, environ) = arguments(pid).unwrap_or_default();
        let (uid, gid) = (info.pbi_ruid, info.pbi_rgid);
        Ok(ProcInfo {
            exe: program_path(pid),
            argv,
            environ,
            uid: Some(uid),
            gid: Some(gid),
            groups: login_groups(uid, gid),
            cwd: working_directory(pid),
        })
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
        // Whatever the umask, only we can write above the state directory.
        std::fs::set_permissions(&base, std::fs::Permissions::from_mode(0o755)).unwrap();
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

    #[test]
    fn state_files_are_written_through_the_checked_directory() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let base = std::env::temp_dir().join(format!("mesh-state-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(base.join("state")).unwrap();
        // Whatever the umask, only we can write above the state directory.
        std::fs::set_permissions(&base, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::set_permissions(base.join("state"), std::fs::Permissions::from_mode(0o700))
            .unwrap();
        let host = RealHost::default();
        host.write_state(&base.join("state/takeover.json"), b"one")
            .unwrap();
        host.write_state(&base.join("state/takeover.json"), b"two")
            .unwrap();
        assert_eq!(
            std::fs::read_to_string(base.join("state/takeover.json")).unwrap(),
            "two"
        );
        let metadata = std::fs::metadata(base.join("state/takeover.json")).unwrap();
        assert_eq!(metadata.mode() & 0o777, 0o600);
        // No temporary file is left behind.
        assert_eq!(std::fs::read_dir(base.join("state")).unwrap().count(), 1);
        // A link where the file goes is replaced, never written through.
        std::fs::write(base.join("target"), "keep").unwrap();
        std::os::unix::fs::symlink(base.join("target"), base.join("state/linked")).unwrap();
        host.write_state(&base.join("state/linked"), b"new")
            .unwrap();
        assert_eq!(
            std::fs::read_to_string(base.join("target")).unwrap(),
            "keep"
        );
        // A directory reached through a link, or writable by others.
        std::os::unix::fs::symlink(base.join("state"), base.join("via")).unwrap();
        assert!(host.write_state(&base.join("via/other"), b"x").is_err());
        std::fs::set_permissions(base.join("state"), std::fs::Permissions::from_mode(0o777))
            .unwrap();
        assert!(host
            .write_state(&base.join("state/takeover.json"), b"three")
            .is_err());
        std::fs::set_permissions(base.join("state"), std::fs::Permissions::from_mode(0o700))
            .unwrap();
        assert_eq!(
            host.read_state(&base.join("state/takeover.json")).unwrap(),
            b"two"
        );
        // A file reached through a link is not read.
        std::os::unix::fs::symlink(base.join("target"), base.join("state/planted")).unwrap();
        assert!(host.read_state(&base.join("state/planted")).is_err());
        // A directory above it that others can write (and is not sticky)
        // could have the state directory swapped: refused for both.
        std::fs::create_dir_all(base.join("open/state")).unwrap();
        std::fs::set_permissions(
            base.join("open/state"),
            std::fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        std::fs::set_permissions(base.join("open"), std::fs::Permissions::from_mode(0o777))
            .unwrap();
        assert!(host
            .write_state(&base.join("open/state/takeover.json"), b"x")
            .is_err());
        assert!(host
            .read_state(&base.join("open/state/takeover.json"))
            .is_err());
        // The same directory made sticky is fine, as /tmp is.
        std::fs::set_permissions(base.join("open"), std::fs::Permissions::from_mode(0o1777))
            .unwrap();
        host.write_state(&base.join("open/state/takeover.json"), b"x")
            .unwrap();
        // A temporary file a crashed run left behind does not block saving.
        std::fs::write(
            base.join(format!("state/.takeover.json.tmp-{}", std::process::id())),
            "stale",
        )
        .unwrap();
        host.write_state(&base.join("state/takeover.json"), b"four")
            .unwrap();
        assert_eq!(
            std::fs::read_to_string(base.join("state/takeover.json")).unwrap(),
            "four"
        );
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
        /// A process table instead of `/proc` (macOS), when set.
        pub table: RefCell<Option<BTreeMap<u32, ProcInfo>>>,
        /// launchd jobs by "domain/label": job file, process, loaded.
        pub launchd: RefCell<BTreeMap<String, (String, Option<u32>, bool)>>,
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

        /// A running process in the process table (macOS), run by `uid`.
        pub fn table_process(&self, pid: u32, exe: &str, argv: &[&str], env: &[&str], uid: u32) {
            let info = ProcInfo {
                exe: Some(exe.to_string()),
                argv: argv.iter().map(|arg| arg.to_string()).collect(),
                environ: env
                    .iter()
                    .filter_map(|pair| pair.split_once('='))
                    .map(|(name, value)| (name.to_string(), value.to_string()))
                    .collect(),
                uid: Some(uid),
                gid: Some(20),
                groups: Some(vec![20]),
                cwd: Some("/".into()),
            };
            self.table
                .borrow_mut()
                .get_or_insert_with(BTreeMap::new)
                .insert(pid, info);
            self.alive.borrow_mut().insert(pid);
        }

        /// launchctl for the jobs in `launchd`; `None` for anything else.
        fn launchctl(&self, program: &str, args: &[&str]) -> Option<CommandOutput> {
            if program != "launchctl" {
                return None;
            }
            let done = |code: i32, stdout: String| {
                Some(CommandOutput {
                    code: Some(code),
                    stdout,
                    stderr: String::new(),
                })
            };
            match args {
                ["print", target] => {
                    let jobs = self.launchd.borrow();
                    let (_, pid, loaded) = jobs.get(*target)?;
                    if !loaded {
                        return done(113, String::new());
                    }
                    let pid = pid
                        .map(|pid| format!("\tpid = {pid}\n"))
                        .unwrap_or_default();
                    done(0, format!("{target} = {{\n\tstate = running\n{pid}}}\n"))
                }
                ["bootout", target] => {
                    let pid = {
                        let mut jobs = self.launchd.borrow_mut();
                        let job = jobs.get_mut(*target)?;
                        if !job.2 {
                            return done(113, String::new());
                        }
                        job.2 = false;
                        job.1.take()
                    };
                    if let Some(pid) = pid {
                        self.remove_process(pid);
                    }
                    done(0, String::new())
                }
                ["bootstrap", domain, plist] => {
                    let mut jobs = self.launchd.borrow_mut();
                    let (_, job) = jobs.iter_mut().find(|(target, job)| {
                        target.starts_with(&format!("{domain}/")) && job.0 == *plist
                    })?;
                    job.2 = true;
                    done(0, String::new())
                }
                _ => None,
            }
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
            if let Some(table) = self.table.borrow_mut().as_mut() {
                table.remove(&pid);
            }
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
            if let Some(output) = self.launchctl(program, args) {
                return Ok(output);
            }
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

        fn list_pids(&self) -> io::Result<Vec<u32>> {
            match self.table.borrow().as_ref() {
                Some(table) => Ok(table.keys().copied().collect()),
                None => Err(io::Error::from(io::ErrorKind::Unsupported)),
            }
        }

        fn process_info(&self, pid: u32) -> io::Result<ProcInfo> {
            match self.table.borrow().as_ref() {
                Some(table) => table
                    .get(&pid)
                    .cloned()
                    .ok_or_else(|| io::Error::from(io::ErrorKind::NotFound)),
                None => Err(io::Error::from(io::ErrorKind::Unsupported)),
            }
        }
    }
}

#[cfg(test)]
mod procargs_tests {
    use super::parse_procargs2;

    fn buffer(count: i32, rest: &[u8]) -> Vec<u8> {
        let mut out = count.to_ne_bytes().to_vec();
        out.extend_from_slice(rest);
        out
    }

    #[test]
    fn arguments_and_environment_are_split_exactly() {
        let bytes = buffer(
            3,
            b"/usr/local/bin/demo\0\0\0\0demo\0-c\0/etc/a b.toml\0HOME=/var/root\0A=1=2\0\0junk\0",
        );
        let (argv, environ) = parse_procargs2(&bytes).unwrap();
        assert_eq!(argv, ["demo", "-c", "/etc/a b.toml"]);
        assert_eq!(
            environ,
            [
                ("HOME".to_string(), "/var/root".to_string()),
                ("A".to_string(), "1=2".to_string()),
            ]
        );
    }

    #[test]
    fn a_short_buffer_is_not_guessed() {
        assert_eq!(parse_procargs2(&buffer(3, b"/bin/x\0\0x\0")), None);
        assert_eq!(parse_procargs2(b"\x01\x00"), None);
        assert_eq!(parse_procargs2(&buffer(-1, b"/bin/x\0\0x\0")), None);
    }
}
