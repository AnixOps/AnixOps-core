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
    /// Starts a detached process in its own session.
    fn spawn_detached(&self, spawn: &Spawn) -> io::Result<u32>;
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
        let mut options = std::fs::OpenOptions::new();
        // Never truncate on open: the holder's text stays until we hold it.
        options.read(true).write(true).create(true).truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(path)?;
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
    fn spawn_detached(&self, spawn: &Spawn) -> io::Result<u32> {
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
        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt;
            // Identity is changed here rather than with Command::uid/gid,
            // which drop every supplementary group when root changes user.
            let groups: Vec<libc::gid_t> = spawn.groups.clone().unwrap_or_default();
            let (uid, gid) = (spawn.uid, spawn.gid);
            let change_groups = uid.is_some() || spawn.groups.is_some();
            // SAFETY: only async-signal-safe calls (setsid, setgroups,
            // setgid, setuid) on memory prepared before the fork.
            unsafe {
                command.pre_exec(move || {
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
        let child = command.spawn()?;
        Ok(child.id())
    }

    fn sleep_ms(&self, ms: u64) {
        std::thread::sleep(std::time::Duration::from_millis(ms));
    }

    fn own_pid(&self) -> u32 {
        std::process::id()
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
        /// Every wait, in milliseconds.
        pub slept: RefCell<Vec<u64>>,
        /// Processes (pid, exe, cgroup) that appear at the next wait of a
        /// second or more.
        pub respawn_after_sleep: RefCell<Vec<(u32, String, String)>>,
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
            let stubborn = self.stubborn.borrow().contains(&pid);
            if !stubborn || signal == Signal::Kill {
                self.remove_process(pid);
            }
            Ok(true)
        }

        fn spawn_detached(&self, spawn: &Spawn) -> io::Result<u32> {
            self.spawned.borrow_mut().push(spawn.clone());
            Ok(4242)
        }

        fn sleep_ms(&self, ms: u64) {
            self.slept.borrow_mut().push(ms);
            // Processes a supervisor starts again while we wait out its
            // restart delay (not during the short polls for an exit).
            if ms < 1_000 {
                return;
            }
            let respawn: Vec<_> = self.respawn_after_sleep.borrow_mut().drain(..).collect();
            for (pid, exe, cgroup) in respawn {
                self.process(pid, &exe, &[exe.as_str()], &[], &cgroup);
            }
        }

        fn own_pid(&self) -> u32 {
            1
        }
    }
}
