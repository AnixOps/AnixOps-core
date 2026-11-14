//! Saved capture sessions (加密落盘): what the capture store holds, written
//! to a file in a directory the client names, encrypted with a key the
//! client keeps (the Keychain, the platform key store). The engine never
//! writes the key anywhere.
//!
//! A session file is `<saved_at_ms>-<random>.anxcap`:
//!
//! ```text
//! "ANXCAP" 0x01
//! nonce (12) | meta length (u32 BE) | ChaCha20-Poly1305(meta JSON)
//! nonce (12) | ChaCha20-Poly1305(connections, binary)
//! ```
//!
//! The small meta part (name, time, counts) is sealed apart from the
//! connections, so listing sessions never decrypts their contents. Files
//! older than the retention (default [`DEFAULT_RETENTION_DAYS`]) are
//! deleted when storage is set, on every save and on every listing; their
//! age comes from the name, so even files a lost key cannot open go.

use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, CHACHA20_POLY1305, NONCE_LEN};
use ring::rand::{SecureRandom, SystemRandom};
use serde_json::{json, Value};

use super::{Captured, CapturedBody, Chunk, Direction, HttpExchange, Inner, HTTP_1_1, HTTP_2};
use crate::connections::Network;

/// Days a saved session is kept when `set_capture_storage` names none.
pub const DEFAULT_RETENTION_DAYS: u32 = 7;
/// Longest retention accepted.
pub const MAX_RETENTION_DAYS: u32 = 365;
/// Length of the session key.
pub const KEY_LEN: usize = 32;
/// Session names are cut to this many characters.
pub const MAX_NAME_CHARS: usize = 120;
const MAGIC: &[u8; 7] = b"ANXCAP\x01";
const EXTENSION: &str = "anxcap";
const DAY_MS: u64 = 24 * 60 * 60 * 1000;
/// Largest connections part read back: the store's own limit and room
/// for headers.
const MAX_BODY_FILE: usize = 64 * 1024 * 1024;

/// Where sessions go and how to seal them.
pub struct Storage {
    dir: PathBuf,
    key: LessSafeKey,
    retention_days: u32,
}

impl std::fmt::Debug for Storage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The key never reaches a log line.
        f.debug_struct("Storage")
            .field("retention_days", &self.retention_days)
            .finish_non_exhaustive()
    }
}

/// Why a storage request failed; fixed strings, no paths or key bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StorageError {
    NotConfigured,
    InvalidKey,
    InvalidDirectory,
    NoSuchSession,
    Unreadable,
    WriteFailed,
}

impl StorageError {
    pub fn message(self) -> &'static str {
        match self {
            Self::NotConfigured => "capture storage is not set",
            Self::InvalidKey => "capture storage key must be 32 bytes of base64",
            Self::InvalidDirectory => "capture storage directory is unusable",
            Self::NoSuchSession => "no such capture session",
            Self::Unreadable => "capture session cannot be read with this key",
            Self::WriteFailed => "capture session could not be written",
        }
    }
}

impl Storage {
    /// Checks the key and creates `dir` when missing.
    pub fn new(dir: &str, key: &[u8], retention_days: Option<u32>) -> Result<Self, StorageError> {
        if key.len() != KEY_LEN {
            return Err(StorageError::InvalidKey);
        }
        let key = UnboundKey::new(&CHACHA20_POLY1305, key).map_err(|_| StorageError::InvalidKey)?;
        if dir.trim().is_empty() {
            return Err(StorageError::InvalidDirectory);
        }
        let dir = PathBuf::from(dir);
        fs::create_dir_all(&dir).map_err(|_| StorageError::InvalidDirectory)?;
        Ok(Self {
            dir,
            key: LessSafeKey::new(key),
            retention_days: retention_days
                .unwrap_or(DEFAULT_RETENTION_DAYS)
                .clamp(1, MAX_RETENTION_DAYS),
        })
    }

    pub fn retention_days(&self) -> u32 {
        self.retention_days
    }

    fn retention_ms(&self) -> u64 {
        u64::from(self.retention_days) * DAY_MS
    }

    /// Deletes sessions older than the retention; how many went.
    pub fn purge(&self, now_ms: u64) -> usize {
        let Ok(entries) = fs::read_dir(&self.dir) else {
            return 0;
        };
        let mut purged = 0;
        for entry in entries.flatten() {
            let path = entry.path();
            let Some(saved_at) = session_id(&path).and_then(|id| saved_at(&id)) else {
                continue;
            };
            if now_ms.saturating_sub(saved_at) > self.retention_ms()
                && fs::remove_file(&path).is_ok()
            {
                purged += 1;
            }
        }
        purged
    }

    /// Seals `inner` into a new session file; its listing entry.
    pub(super) fn save(
        &self,
        inner: &Inner,
        name: Option<&str>,
        now_ms: u64,
    ) -> Result<Value, StorageError> {
        let random = SystemRandom::new();
        let mut tag = [0u8; 4];
        random
            .fill(&mut tag)
            .map_err(|_| StorageError::WriteFailed)?;
        let id = format!("{now_ms}-{}", hex(&tag));
        let requests: usize = inner.connections.values().map(|c| c.http.len()).sum();
        let name: String = name
            .map(str::trim)
            .filter(|name| !name.is_empty())
            .unwrap_or("")
            .chars()
            .take(MAX_NAME_CHARS)
            .collect();
        let meta = json!({
            "name": name,
            "saved_at_ms": now_ms,
            "connections": inner.connections.len(),
            "requests": requests,
        });
        let mut meta = serde_json::to_vec(&meta).map_err(|_| StorageError::WriteFailed)?;
        let mut body = encode(inner);

        let mut file = Vec::with_capacity(MAGIC.len() + meta.len() + body.len() + 64);
        file.extend_from_slice(MAGIC);
        self.seal(&random, &mut meta, 0, &mut file)?;
        self.seal(&random, &mut body, 1, &mut file)?;
        drop(body);

        let path = self.dir.join(format!("{id}.{EXTENSION}"));
        let partial = self.dir.join(format!(".{id}.partial"));
        fs::write(&partial, &file)
            .and_then(|()| fs::rename(&partial, &path))
            .map_err(|_| {
                let _ = fs::remove_file(&partial);
                StorageError::WriteFailed
            })?;
        Ok(self.entry(
            &id,
            &path,
            Some(meta_value(
                &id,
                now_ms,
                &name,
                inner.connections.len(),
                requests,
            )),
        ))
    }

    /// `part` 0 is the meta part (length-prefixed), 1 the connections.
    fn seal(
        &self,
        random: &SystemRandom,
        data: &mut Vec<u8>,
        part: u8,
        file: &mut Vec<u8>,
    ) -> Result<(), StorageError> {
        let mut nonce = [0u8; NONCE_LEN];
        random
            .fill(&mut nonce)
            .map_err(|_| StorageError::WriteFailed)?;
        self.key
            .seal_in_place_append_tag(
                Nonce::assume_unique_for_key(nonce),
                Aad::from(aad(part)),
                data,
            )
            .map_err(|_| StorageError::WriteFailed)?;
        file.extend_from_slice(&nonce);
        if part == 0 {
            let len = u32::try_from(data.len()).map_err(|_| StorageError::WriteFailed)?;
            file.extend_from_slice(&len.to_be_bytes());
        }
        file.extend_from_slice(data);
        Ok(())
    }

    fn open<'a>(&self, nonce: &[u8], part: u8, data: &'a mut [u8]) -> Option<&'a mut [u8]> {
        let nonce = Nonce::try_assume_unique_for_key(nonce).ok()?;
        self.key
            .open_in_place(nonce, Aad::from(aad(part)), data)
            .ok()
    }

    /// The saved sessions, newest first.
    pub fn list(&self, now_ms: u64) -> Vec<Value> {
        self.purge(now_ms);
        let Ok(entries) = fs::read_dir(&self.dir) else {
            return Vec::new();
        };
        let mut sessions = BTreeMap::new();
        for entry in entries.flatten() {
            let path = entry.path();
            let Some(id) = session_id(&path) else {
                continue;
            };
            let meta = self.read_meta(&path).and_then(|meta| {
                Some(meta_value(
                    &id,
                    meta.get("saved_at_ms")?.as_u64()?,
                    meta.get("name")?.as_str()?,
                    meta.get("connections")?.as_u64()? as usize,
                    meta.get("requests")?.as_u64()? as usize,
                ))
            });
            sessions.insert(id.clone(), self.entry(&id, &path, meta));
        }
        sessions.into_values().rev().collect()
    }

    fn entry(&self, id: &str, path: &Path, meta: Option<Value>) -> Value {
        let size = fs::metadata(path)
            .map(|metadata| metadata.len())
            .unwrap_or(0);
        let saved_at = saved_at(id).unwrap_or(0);
        let mut entry = meta.unwrap_or_else(
            || json!({ "session": id, "saved_at_ms": saved_at, "unreadable": true }),
        );
        entry["size"] = json!(size);
        entry["expires_at_ms"] = json!(saved_at.saturating_add(self.retention_ms()));
        entry
    }

    fn read_meta(&self, path: &Path) -> Option<Value> {
        use std::io::Read;
        let mut file = fs::File::open(path).ok()?;
        let mut head = [0u8; MAGIC.len() + NONCE_LEN + 4];
        file.read_exact(&mut head).ok()?;
        if &head[..MAGIC.len()] != MAGIC {
            return None;
        }
        let nonce = &head[MAGIC.len()..MAGIC.len() + NONCE_LEN];
        let len = u32::from_be_bytes(head[MAGIC.len() + NONCE_LEN..].try_into().ok()?) as usize;
        if len > 64 * 1024 {
            return None;
        }
        let mut meta = vec![0u8; len];
        file.read_exact(&mut meta).ok()?;
        let plain = self.open(nonce, 0, &mut meta)?;
        serde_json::from_slice(plain).ok()
    }

    /// The connections of session `id`.
    pub(super) fn load(&self, id: &str) -> Result<Vec<(u64, Captured)>, StorageError> {
        let path = self.path(id)?;
        let mut file = fs::read(&path).map_err(|_| StorageError::NoSuchSession)?;
        if file.len() > MAX_BODY_FILE || !file.starts_with(MAGIC) {
            return Err(StorageError::Unreadable);
        }
        let mut at = MAGIC.len() + NONCE_LEN;
        let meta_len = file
            .get(at..at + 4)
            .and_then(|bytes| bytes.try_into().ok())
            .map(u32::from_be_bytes)
            .ok_or(StorageError::Unreadable)? as usize;
        at += 4 + meta_len;
        let body_nonce: [u8; NONCE_LEN] = file
            .get(at..at + NONCE_LEN)
            .and_then(|bytes| bytes.try_into().ok())
            .ok_or(StorageError::Unreadable)?;
        let body = &mut file[at + NONCE_LEN..];
        let plain = self
            .open(&body_nonce, 1, body)
            .ok_or(StorageError::Unreadable)?;
        decode(plain).ok_or(StorageError::Unreadable)
    }

    pub fn delete(&self, id: &str) -> Result<bool, StorageError> {
        let path = self.path(id)?;
        match fs::remove_file(path) {
            Ok(()) => Ok(true),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(_) => Err(StorageError::WriteFailed),
        }
    }

    /// The file of session `id`; ids are only digits, `-` and hex, so no
    /// path can be named.
    fn path(&self, id: &str) -> Result<PathBuf, StorageError> {
        if saved_at(id).is_none() {
            return Err(StorageError::NoSuchSession);
        }
        Ok(self.dir.join(format!("{id}.{EXTENSION}")))
    }
}

fn meta_value(id: &str, saved_at: u64, name: &str, connections: usize, requests: usize) -> Value {
    json!({
        "session": id,
        "name": name,
        "saved_at_ms": saved_at,
        "connections": connections,
        "requests": requests,
    })
}

fn aad(part: u8) -> [u8; 8] {
    let mut aad = [0u8; 8];
    aad[..MAGIC.len()].copy_from_slice(MAGIC);
    aad[7] = part;
    aad
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// The session id of a session file's path.
fn session_id(path: &Path) -> Option<String> {
    if path.extension()? != EXTENSION {
        return None;
    }
    let id = path.file_stem()?.to_str()?;
    saved_at(id).map(|_| id.to_string())
}

/// The save time in a session id `<ms>-<8 hex>`.
fn saved_at(id: &str) -> Option<u64> {
    let (millis, tag) = id.split_once('-')?;
    let valid = tag.len() == 8 && tag.bytes().all(|b| b.is_ascii_hexdigit());
    if !valid || millis.is_empty() || !millis.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    millis.parse().ok()
}

// Binary layout of the connections part: integers big-endian, strings and
// byte strings as a u32 length and the bytes, options as a 0/1 byte first.

struct Writer(Vec<u8>);

impl Writer {
    fn u8(&mut self, value: u8) {
        self.0.push(value);
    }
    fn u16(&mut self, value: u16) {
        self.0.extend_from_slice(&value.to_be_bytes());
    }
    fn u64(&mut self, value: u64) {
        self.0.extend_from_slice(&value.to_be_bytes());
    }
    fn bytes(&mut self, value: &[u8]) {
        self.0
            .extend_from_slice(&(value.len() as u32).to_be_bytes());
        self.0.extend_from_slice(value);
    }
    fn str(&mut self, value: &str) {
        self.bytes(value.as_bytes());
    }
    fn opt_u64(&mut self, value: Option<u64>) {
        match value {
            Some(value) => {
                self.u8(1);
                self.u64(value);
            }
            None => self.u8(0),
        }
    }
    fn opt_str(&mut self, value: Option<&str>) {
        match value {
            Some(value) => {
                self.u8(1);
                self.str(value);
            }
            None => self.u8(0),
        }
    }
    fn headers(&mut self, headers: &[(String, String)]) {
        self.u64(headers.len() as u64);
        for (name, value) in headers {
            self.str(name);
            self.str(value);
        }
    }
    fn body(&mut self, body: &CapturedBody) {
        self.u64(body.size);
        self.bytes(&body.data);
    }
}

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, len: usize) -> Option<&'a [u8]> {
        if self.0.len() < len {
            return None;
        }
        let (head, rest) = self.0.split_at(len);
        self.0 = rest;
        Some(head)
    }
    fn u8(&mut self) -> Option<u8> {
        self.take(1).map(|bytes| bytes[0])
    }
    fn u16(&mut self) -> Option<u16> {
        self.take(2)
            .map(|bytes| u16::from_be_bytes([bytes[0], bytes[1]]))
    }
    fn u64(&mut self) -> Option<u64> {
        self.take(8)
            .and_then(|bytes| bytes.try_into().ok())
            .map(u64::from_be_bytes)
    }
    fn bytes(&mut self) -> Option<&'a [u8]> {
        let len = u32::from_be_bytes(self.take(4)?.try_into().ok()?) as usize;
        self.take(len)
    }
    fn string(&mut self) -> Option<String> {
        String::from_utf8(self.bytes()?.to_vec()).ok()
    }
    fn opt_u64(&mut self) -> Option<Option<u64>> {
        match self.u8()? {
            0 => Some(None),
            1 => self.u64().map(Some),
            _ => None,
        }
    }
    fn opt_string(&mut self) -> Option<Option<String>> {
        match self.u8()? {
            0 => Some(None),
            1 => self.string().map(Some),
            _ => None,
        }
    }
    /// A count no larger than what the rest could hold at `min` bytes each.
    fn count(&mut self, min: usize) -> Option<usize> {
        let count = usize::try_from(self.u64()?).ok()?;
        (count <= self.0.len() / min.max(1)).then_some(count)
    }
    fn headers(&mut self) -> Option<Vec<(String, String)>> {
        let count = self.count(8)?;
        let mut headers = Vec::with_capacity(count);
        for _ in 0..count {
            headers.push((self.string()?, self.string()?));
        }
        Some(headers)
    }
    fn body(&mut self) -> Option<CapturedBody> {
        let size = self.u64()?;
        let data = self.bytes()?.to_vec();
        Some(CapturedBody { data, size })
    }
}

fn static_version(version: &str) -> &'static str {
    if version == HTTP_2 {
        HTTP_2
    } else {
        HTTP_1_1
    }
}

fn static_note(note: &str) -> Option<&'static str> {
    ["answered_locally", "streaming", "too_large"]
        .into_iter()
        .find(|known| *known == note)
}

fn encode(inner: &Inner) -> Vec<u8> {
    let mut out = Writer(Vec::with_capacity(inner.used + 64));
    out.u64(inner.connections.len() as u64);
    for (&id, captured) in &inner.connections {
        out.u64(id);
        out.u8(match captured.network {
            Network::Tcp => 0,
            Network::Udp => 1,
        });
        out.opt_str(captured.host.as_deref());
        out.str(&captured.destination);
        out.u64(captured.started_at_ms);
        out.opt_u64(captured.ended_at_ms);
        out.u8(u8::from(captured.decrypted));
        out.u64(captured.kept[0] as u64);
        out.u64(captured.kept[1] as u64);
        out.u64(captured.seen[0]);
        out.u64(captured.seen[1]);
        out.u64(captured.chunks.len() as u64);
        for chunk in &captured.chunks {
            out.u8(u8::from(chunk.direction == Direction::Down));
            out.u64(chunk.at_ms);
            out.bytes(&chunk.data);
        }
        out.u64(captured.http.len() as u64);
        for exchange in &captured.http {
            out.u64(exchange.seq);
            out.str(exchange.http_version);
            out.u64(exchange.started_at_ms);
            out.opt_u64(exchange.ended_at_ms);
            out.str(&exchange.method);
            out.str(&exchange.url);
            out.headers(&exchange.request_headers);
            out.body(&exchange.request_body);
            out.opt_u64(exchange.status.map(u64::from));
            out.headers(&exchange.response_headers);
            out.body(&exchange.response_body);
            out.opt_str(exchange.note);
        }
        out.u16(0);
    }
    out.0
}

fn decode(data: &[u8]) -> Option<Vec<(u64, Captured)>> {
    let mut input = Reader(data);
    let count = input.count(16)?;
    let mut connections = Vec::with_capacity(count);
    for _ in 0..count {
        let id = input.u64()?;
        let network = match input.u8()? {
            0 => Network::Tcp,
            1 => Network::Udp,
            _ => return None,
        };
        let host = input.opt_string()?;
        let destination = input.string()?;
        let started_at_ms = input.u64()?;
        let ended_at_ms = input.opt_u64()?;
        let decrypted = input.u8()? != 0;
        let kept = [
            usize::try_from(input.u64()?).ok()?,
            usize::try_from(input.u64()?).ok()?,
        ];
        let seen = [input.u64()?, input.u64()?];
        let chunk_count = input.count(13)?;
        let mut chunks = Vec::with_capacity(chunk_count);
        for _ in 0..chunk_count {
            let direction = if input.u8()? == 1 {
                Direction::Down
            } else {
                Direction::Up
            };
            let at_ms = input.u64()?;
            let data = input.bytes()?.to_vec();
            chunks.push(Chunk {
                direction,
                at_ms,
                data,
            });
        }
        let exchange_count = input.count(32)?;
        let mut http = Vec::with_capacity(exchange_count);
        for _ in 0..exchange_count {
            let seq = input.u64()?;
            let http_version = static_version(&input.string()?);
            let started_at_ms = input.u64()?;
            let ended_at_ms = input.opt_u64()?;
            let method = input.string()?;
            let url = input.string()?;
            let request_headers = input.headers()?;
            let request_body = input.body()?;
            let status = match input.opt_u64()? {
                Some(status) => Some(u16::try_from(status).ok()?),
                None => None,
            };
            let response_headers = input.headers()?;
            let response_body = input.body()?;
            let note = input.opt_string()?.as_deref().and_then(static_note);
            http.push(HttpExchange {
                seq,
                http_version,
                started_at_ms,
                ended_at_ms,
                method,
                url,
                request_headers,
                request_body,
                status,
                response_headers,
                response_body,
                note,
            });
        }
        if input.u16()? != 0 {
            return None;
        }
        let mut captured = Captured {
            network,
            host,
            destination,
            started_at_ms,
            ended_at_ms,
            decrypted,
            chunks,
            kept,
            seen,
            http,
            memory: 0,
        };
        captured.memory = captured.memory_estimate();
        connections.push((id, captured));
    }
    input.0.is_empty().then_some(connections)
}

#[cfg(test)]
mod tests {
    use super::super::{CaptureStore, MAX_TOTAL_BYTES_LIMIT};
    use super::*;

    fn temp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "anixops-capture-{name}-{}-{}",
            std::process::id(),
            super::super::unix_millis()
        ));
        let _ = fs::remove_dir_all(&dir);
        dir
    }

    fn sample_store() -> CaptureStore {
        let store = CaptureStore::default();
        store.set(true, Some(MAX_TOTAL_BYTES_LIMIT));
        store.begin(1, Network::Udp, None, "192.0.2.1:53", 1);
        store.record(1, Direction::Up, b"query");
        store.begin(2, Network::Tcp, Some("a.test"), "a.test:443", 2);
        store.mark_decrypted(2);
        let mut exchange =
            HttpExchange::new("GET", "https://a.test/x", &[("A".into(), "b".into())]);
        exchange.http_version = HTTP_2;
        exchange.status = Some(200);
        exchange.response_body = CapturedBody::of(b"secret payload");
        exchange.note = Some("streaming");
        store.add_exchange(2, exchange);
        store
    }

    #[test]
    fn sessions_round_trip_encrypted() {
        let dir = temp_dir("round-trip");
        let key = [7u8; KEY_LEN];
        let storage = Storage::new(dir.to_str().unwrap(), &key, None).unwrap();
        assert_eq!(storage.retention_days(), DEFAULT_RETENTION_DAYS);
        let store = sample_store();
        let entry = {
            let inner = super::super::lock(&store.inner);
            storage
                .save(&inner, Some(" morning run "), 1_000_000)
                .unwrap()
        };
        let id = entry["session"].as_str().unwrap().to_string();
        assert_eq!(entry["name"], "morning run");
        assert_eq!(entry["requests"], 1);
        assert_eq!(entry["expires_at_ms"], 1_000_000 + 7 * DAY_MS);

        // Nothing readable on disk.
        let raw = fs::read(dir.join(format!("{id}.anxcap"))).unwrap();
        assert!(!raw.windows(14).any(|w| w == b"secret payload"));
        assert!(!raw.windows(6).any(|w| w == b"a.test"));

        let listed = storage.list(1_000_001);
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0]["session"], id.as_str());
        assert_eq!(listed[0]["connections"], 2);

        let loaded = storage.load(&id).unwrap();
        assert_eq!(loaded.len(), 2);
        let (_, tcp) = &loaded[1];
        assert_eq!(tcp.http[0].http_version, HTTP_2);
        assert_eq!(tcp.http[0].note, Some("streaming"));
        assert_eq!(tcp.http[0].response_body.data, b"secret payload");
        assert_eq!(loaded[0].1.chunks[0].data, b"query");

        // Another key reads nothing.
        let other = Storage::new(dir.to_str().unwrap(), &[8u8; KEY_LEN], None).unwrap();
        assert_eq!(other.load(&id).unwrap_err(), StorageError::Unreadable);
        assert_eq!(other.list(1_000_001)[0]["unreadable"], true);

        assert!(storage.delete(&id).unwrap());
        assert!(!storage.delete(&id).unwrap());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn old_sessions_are_purged_and_ids_cannot_name_paths() {
        let dir = temp_dir("purge");
        let storage = Storage::new(dir.to_str().unwrap(), &[1u8; KEY_LEN], Some(7)).unwrap();
        let store = sample_store();
        {
            let inner = super::super::lock(&store.inner);
            storage.save(&inner, None, 1_000).unwrap();
            storage.save(&inner, None, 1_000 + 6 * DAY_MS).unwrap();
        }
        fs::write(dir.join("notes.txt"), b"keep").unwrap();
        assert_eq!(storage.purge(1_000 + 7 * DAY_MS + 1), 1);
        assert_eq!(storage.list(1_000 + 7 * DAY_MS + 1).len(), 1);
        assert!(dir.join("notes.txt").exists());
        assert_eq!(
            storage.load("../../etc/passwd").unwrap_err(),
            StorageError::NoSuchSession
        );
        assert_eq!(
            storage.delete("1-zz").unwrap_err(),
            StorageError::NoSuchSession
        );
        assert_eq!(
            Storage::new(dir.to_str().unwrap(), &[1u8; 16], None).unwrap_err(),
            StorageError::InvalidKey
        );
        let _ = fs::remove_dir_all(&dir);
    }
}
