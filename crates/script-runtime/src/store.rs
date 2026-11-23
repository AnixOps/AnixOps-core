//! `$persistentStore` backends.

use std::collections::{BTreeMap, HashMap};
use std::io::{self, Write as _};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock, Weak};
use std::time::{Duration, SystemTime};

pub const SCRIPT_STORE_MAX_KEY_BYTES: usize = 256;
pub const SCRIPT_STORE_MAX_VALUE_BYTES: usize = 512 * 1024;
pub const SCRIPT_STORE_MAX_TOTAL_BYTES: usize = 8 * 1024 * 1024;

/// Key-value storage shared by all scripts of one runtime, as plugin scripts expect.
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
/// file through a temporary sibling of its own (unique per process and
/// write), so a crash never leaves partial JSON and two writers never write
/// into one temporary file.
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
        remove_stale_temporaries(&path);
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
        let temporary = sibling(&self.path, &temporary_suffix());
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
/// and the file is never overwritten. Within one process every caller that
/// opens the same file while an earlier store of it is still in use gets
/// that store (reported as [`ScriptStoreRecovery::Opened`]). The recovery
/// never names the store's contents, which may hold tokens.
pub fn open_script_store(path: impl Into<PathBuf>) -> (Arc<dyn ScriptStore>, ScriptStoreRecovery) {
    let path = path.into();
    let key = store_key(&path);
    let mut stores = open_stores()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    stores.retain(|_, store| store.strong_count() > 0);
    if let Some(store) = stores.get(&key).and_then(Weak::upgrade) {
        return (store, ScriptStoreRecovery::Opened);
    }
    let mut share = |store: JsonFileScriptStore| {
        let store = Arc::new(store);
        stores.insert(key.clone(), Arc::downgrade(&store));
        store
    };
    match JsonFileScriptStore::open(&path) {
        Ok(store) => (share(store), ScriptStoreRecovery::Opened),
        Err(error) if error.kind() == io::ErrorKind::InvalidData => {
            let backup = sibling(&path, SCRIPT_STORE_QUARANTINE_SUFFIX);
            // `rename` does not replace an existing file on every platform.
            let _ = std::fs::remove_file(&backup);
            if replace_with_retry(&path, &backup).is_ok() {
                if let Ok(store) = JsonFileScriptStore::open(&path) {
                    return (share(store), ScriptStoreRecovery::Quarantined { backup });
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

/// Temporary files of [`JsonFileScriptStore::persist`] are named
/// `<store>.tmp-<pid>-<n>`.
const TEMPORARY_INFIX: &str = ".tmp";

/// A temporary sibling older than this is left over from a crash; a live
/// write finishes with it within milliseconds.
const STALE_TEMPORARY_AGE: Duration = Duration::from_secs(60);

fn temporary_suffix() -> String {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    format!(
        "{TEMPORARY_INFIX}-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    )
}

/// Removes temporary siblings a crash left behind: the fixed `<store>.tmp`
/// of older versions, and `<store>.tmp-*` files no write has touched for
/// [`STALE_TEMPORARY_AGE`] (a younger one may belong to a live writer in
/// another process).
fn remove_stale_temporaries(path: &Path) {
    let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
        return;
    };
    let legacy = format!("{name}{TEMPORARY_INFIX}");
    let prefix = format!("{name}{TEMPORARY_INFIX}-");
    let parent = match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    };
    let Ok(entries) = std::fs::read_dir(parent) else {
        return;
    };
    let now = SystemTime::now();
    for entry in entries.flatten() {
        let file_name = entry.file_name();
        let Some(file_name) = file_name.to_str() else {
            continue;
        };
        let stale = if file_name == legacy {
            true
        } else if file_name.starts_with(&prefix) {
            entry
                .metadata()
                .and_then(|metadata| metadata.modified())
                .ok()
                .and_then(|modified| now.duration_since(modified).ok())
                .is_some_and(|age| age >= STALE_TEMPORARY_AGE)
        } else {
            false
        };
        if stale && entry.file_type().is_ok_and(|kind| kind.is_file()) {
            let _ = std::fs::remove_file(entry.path());
        }
    }
}

/// The stores [`open_script_store`] handed out that are still in use, by
/// path. Two runtimes of one process (a reload, or the tunnel and a local
/// proxy side by side) that open one file share one store, so neither
/// writes back a copy that drops the other's changes.
fn open_stores() -> &'static Mutex<HashMap<PathBuf, Weak<JsonFileScriptStore>>> {
    static STORES: OnceLock<Mutex<HashMap<PathBuf, Weak<JsonFileScriptStore>>>> = OnceLock::new();
    STORES.get_or_init(|| Mutex::new(HashMap::new()))
}

/// `path` with its directory resolved, so two spellings of one file meet in
/// [`open_stores`]; the file itself need not exist yet.
fn store_key(path: &Path) -> PathBuf {
    let resolved = match (path.parent(), path.file_name()) {
        (Some(parent), Some(name)) => {
            let parent = if parent.as_os_str().is_empty() {
                Path::new(".")
            } else {
                parent
            };
            std::fs::canonicalize(parent)
                .ok()
                .map(|parent| parent.join(name))
        }
        _ => None,
    };
    resolved.unwrap_or_else(|| path.to_path_buf())
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
