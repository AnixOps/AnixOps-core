//! `$persistentStore` backends.

use std::collections::BTreeMap;
use std::io::{self, Write as _};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

pub const SCRIPT_STORE_MAX_KEY_BYTES: usize = 256;
pub const SCRIPT_STORE_MAX_VALUE_BYTES: usize = 512 * 1024;
pub const SCRIPT_STORE_MAX_TOTAL_BYTES: usize = 8 * 1024 * 1024;

/// Key-value storage shared by all scripts of one runtime, as in Loon.
pub trait ScriptStore: Send + Sync {
    fn read(&self, key: &str) -> Option<String>;
    /// Returns `false` when the write is refused (size limits) or not durable.
    fn write(&self, key: &str, value: &str) -> bool;
    fn remove(&self, key: &str) -> bool;
}

fn write_allowed(entries: &BTreeMap<String, String>, key: &str, value: &str) -> bool {
    if key.is_empty()
        || key.len() > SCRIPT_STORE_MAX_KEY_BYTES
        || value.len() > SCRIPT_STORE_MAX_VALUE_BYTES
    {
        return false;
    }
    let total = entries
        .iter()
        .filter(|(existing, _)| existing.as_str() != key)
        .map(|(existing, existing_value)| existing.len() + existing_value.len())
        .sum::<usize>();
    total + key.len() + value.len() <= SCRIPT_STORE_MAX_TOTAL_BYTES
}

/// In-memory store, used by tests and when no store path is configured.
#[derive(Debug, Default)]
pub struct MemoryScriptStore {
    entries: Mutex<BTreeMap<String, String>>,
}

impl MemoryScriptStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_entries(entries: BTreeMap<String, String>) -> Self {
        Self {
            entries: Mutex::new(entries),
        }
    }

    pub fn snapshot(&self) -> BTreeMap<String, String> {
        self.entries
            .lock()
            .map(|entries| entries.clone())
            .unwrap_or_default()
    }
}

impl ScriptStore for MemoryScriptStore {
    fn read(&self, key: &str) -> Option<String> {
        self.entries.lock().ok()?.get(key).cloned()
    }

    fn write(&self, key: &str, value: &str) -> bool {
        let Ok(mut entries) = self.entries.lock() else {
            return false;
        };
        if !write_allowed(&entries, key, value) {
            return false;
        }
        entries.insert(key.to_string(), value.to_string());
        true
    }

    fn remove(&self, key: &str) -> bool {
        self.entries
            .lock()
            .map(|mut entries| entries.remove(key).is_some())
            .unwrap_or(false)
    }
}

/// Store persisted as one JSON object. Every successful write replaces the
/// file through a temporary sibling, so a crash never leaves partial JSON.
#[derive(Debug)]
pub struct JsonFileScriptStore {
    path: PathBuf,
    entries: Mutex<BTreeMap<String, String>>,
}

impl JsonFileScriptStore {
    /// Opens `path`. A missing file is an empty store; a file that is not a
    /// JSON object of strings is an error, so it is never overwritten.
    pub fn open(path: impl Into<PathBuf>) -> io::Result<Self> {
        let path = path.into();
        let entries = match std::fs::read(&path) {
            Ok(bytes) => serde_json::from_slice::<BTreeMap<String, String>>(&bytes)
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?,
            Err(error) if error.kind() == io::ErrorKind::NotFound => BTreeMap::new(),
            Err(error) => return Err(error),
        };
        Ok(Self {
            path,
            entries: Mutex::new(entries),
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Writes `entries` to a temporary sibling, flushes it to disk and moves
    /// it over the store, so the file on disk is always either the old or
    /// the new store, never a torn one.
    fn persist(&self, entries: &BTreeMap<String, String>) -> bool {
        let Ok(json) = serde_json::to_vec(entries) else {
            return false;
        };
        let temporary = sibling(&self.path, ".tmp");
        let written = std::fs::File::create(&temporary).and_then(|mut file| {
            file.write_all(&json)?;
            file.sync_all()
        });
        if written.is_err() || replace_with_retry(&temporary, &self.path).is_err() {
            let _ = std::fs::remove_file(&temporary);
            return false;
        }
        sync_parent_directory(&self.path);
        true
    }
}

/// Suffix of the copy a store that cannot be read is moved to. Only the most
/// recent copy is kept, so a store that keeps breaking does not pile up files.
pub const SCRIPT_STORE_QUARANTINE_SUFFIX: &str = ".corrupt";

/// How [`open_script_store`] opened the persistent store.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScriptStoreRecovery {
    /// The file was read (or was missing, an empty store).
    Opened,
    /// The file was not a JSON object of strings. It was moved to `backup`
    /// and the store starts empty at the original path.
    Quarantined { backup: PathBuf },
    /// The file could neither be read nor moved aside. Scripts get an
    /// in-memory store for this run, and the file is left as it is.
    InMemory,
}

/// Opens the persistent store at `path` for a runtime that must start
/// whatever the file holds. A file that is not a JSON object of strings
/// (truncated, edited by hand, empty) is moved aside to
/// `<path>.corrupt`, replacing an older copy, and the store starts empty.
/// When the file cannot be read or moved, scripts get an in-memory store
/// and the file is never overwritten. The recovery never names the store's
/// contents, which may hold tokens.
pub fn open_script_store(path: impl Into<PathBuf>) -> (Arc<dyn ScriptStore>, ScriptStoreRecovery) {
    let path = path.into();
    match JsonFileScriptStore::open(&path) {
        Ok(store) => (Arc::new(store), ScriptStoreRecovery::Opened),
        Err(error) if error.kind() == io::ErrorKind::InvalidData => {
            let backup = sibling(&path, SCRIPT_STORE_QUARANTINE_SUFFIX);
            // `rename` does not replace an existing file on every platform.
            let _ = std::fs::remove_file(&backup);
            if replace_with_retry(&path, &backup).is_ok() {
                if let Ok(store) = JsonFileScriptStore::open(&path) {
                    return (Arc::new(store), ScriptStoreRecovery::Quarantined { backup });
                }
            }
            (
                Arc::new(MemoryScriptStore::new()),
                ScriptStoreRecovery::InMemory,
            )
        }
        Err(_) => (
            Arc::new(MemoryScriptStore::new()),
            ScriptStoreRecovery::InMemory,
        ),
    }
}

fn sibling(path: &Path, suffix: &str) -> PathBuf {
    let mut sibling = path.as_os_str().to_os_string();
    sibling.push(suffix);
    PathBuf::from(sibling)
}

/// Moves `from` over `to`. Windows refuses the move while another process
/// (an indexer, an antivirus scanner) briefly holds the target open, so a
/// refused move is retried a few times with a short backoff.
fn replace_with_retry(from: &Path, to: &Path) -> io::Result<()> {
    const ATTEMPTS: u32 = 5;
    let mut attempt = 0;
    loop {
        match std::fs::rename(from, to) {
            Ok(()) => return Ok(()),
            Err(error) if attempt + 1 < ATTEMPTS && is_transient_rename_error(&error) => {
                attempt += 1;
                std::thread::sleep(Duration::from_millis(10 * u64::from(attempt)));
            }
            Err(error) => return Err(error),
        }
    }
}

fn is_transient_rename_error(error: &io::Error) -> bool {
    if cfg!(windows) {
        // ERROR_ACCESS_DENIED (5), ERROR_SHARING_VIOLATION (32),
        // ERROR_LOCK_VIOLATION (33).
        error.kind() == io::ErrorKind::PermissionDenied
            || matches!(error.raw_os_error(), Some(5 | 32 | 33))
    } else {
        false
    }
}

/// Makes the rename itself durable where the platform allows it.
fn sync_parent_directory(path: &Path) {
    #[cfg(unix)]
    {
        let parent = match path.parent() {
            Some(parent) if !parent.as_os_str().is_empty() => parent,
            _ => Path::new("."),
        };
        if let Ok(directory) = std::fs::File::open(parent) {
            let _ = directory.sync_all();
        }
    }
    #[cfg(not(unix))]
    let _ = path;
}

impl ScriptStore for JsonFileScriptStore {
    fn read(&self, key: &str) -> Option<String> {
        self.entries.lock().ok()?.get(key).cloned()
    }

    fn write(&self, key: &str, value: &str) -> bool {
        let Ok(mut entries) = self.entries.lock() else {
            return false;
        };
        if !write_allowed(&entries, key, value) {
            return false;
        }
        if entries.get(key).is_some_and(|existing| existing == value) {
            // Nothing changes, so nothing is written.
            return true;
        }
        let previous = entries.insert(key.to_string(), value.to_string());
        if self.persist(&entries) {
            return true;
        }
        match previous {
            Some(previous) => entries.insert(key.to_string(), previous),
            None => entries.remove(key),
        };
        false
    }

    fn remove(&self, key: &str) -> bool {
        let Ok(mut entries) = self.entries.lock() else {
            return false;
        };
        let Some(previous) = entries.remove(key) else {
            return false;
        };
        if self.persist(&entries) {
            return true;
        }
        entries.insert(key.to_string(), previous);
        false
    }
}
