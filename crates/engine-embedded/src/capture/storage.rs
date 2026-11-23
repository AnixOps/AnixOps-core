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

use super::h2frames::{H2Frame, H2Frames, Link, MAX_FRAMES};
use super::stream::{MessageKind, Messages, StreamMessage};
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
        let key = sealing_key(key)?;
        if dir.trim().is_empty() {
            return Err(StorageError::InvalidDirectory);
        }
        let dir = PathBuf::from(dir);
        fs::create_dir_all(&dir).map_err(|_| StorageError::InvalidDirectory)?;
        Ok(Self {
            dir,
            key,
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

    /// Seals `inner` into a session file; its listing entry. The file is
    /// session `id` when given (it replaces a session of that id: the
    /// engine's own run, see [`super::CaptureStore::run_session`]), else a
    /// new one.
    pub(super) fn save(
        &self,
        inner: &Inner,
        name: Option<&str>,
        now_ms: u64,
        id: Option<&str>,
    ) -> Result<Value, StorageError> {
        let id = match id {
            Some(id) => {
                self.path(id)?;
                id.to_string()
            }
            None => new_session_id(now_ms).ok_or(StorageError::WriteFailed)?,
        };
        let sealed = seal_inner(&self.key, inner, name, now_ms)?;
        let path = self.write(&id, &sealed.file)?;
        Ok(self.entry(
            &id,
            &path,
            Some(meta_value(
                &id,
                now_ms,
                &sealed.name,
                sealed.connections,
                sealed.requests,
            )),
        ))
    }

    /// Writes a session file in one step: a partial file renamed into place.
    fn write(&self, id: &str, file: &[u8]) -> Result<PathBuf, StorageError> {
        let path = self.dir.join(format!("{id}.{EXTENSION}"));
        let partial = self.dir.join(format!(".{id}.partial"));
        fs::write(&partial, file)
            .and_then(|()| fs::rename(&partial, &path))
            .map_err(|_| {
                let _ = fs::remove_file(&partial);
                StorageError::WriteFailed
            })?;
        Ok(path)
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
        let (_, body) = self.open_file(&mut file)?;
        decode(body).ok_or(StorageError::Unreadable)
    }

    /// The meta and connections parts of a whole session file, opened in
    /// place.
    fn open_file<'a>(&self, file: &'a mut [u8]) -> Result<(Value, &'a [u8]), StorageError> {
        if file.len() > MAX_BODY_FILE || !file.starts_with(MAGIC) {
            return Err(StorageError::Unreadable);
        }
        let length_at = MAGIC.len() + NONCE_LEN;
        let meta_at = length_at + 4;
        let meta_len = file
            .get(length_at..meta_at)
            .and_then(|bytes| bytes.try_into().ok())
            .map(u32::from_be_bytes)
            .ok_or(StorageError::Unreadable)? as usize;
        let body_at = meta_at
            .checked_add(meta_len)
            .filter(|at| at.saturating_add(NONCE_LEN) <= file.len())
            .ok_or(StorageError::Unreadable)?;
        let (head, rest) = file.split_at_mut(body_at);
        let (nonces, meta) = head.split_at_mut(meta_at);
        let meta = self
            .open(&nonces[MAGIC.len()..length_at], 0, meta)
            .and_then(|plain| serde_json::from_slice(plain).ok())
            .ok_or(StorageError::Unreadable)?;
        let (body_nonce, body) = rest.split_at_mut(NONCE_LEN);
        let body: &'a [u8] = self
            .open(body_nonce, 1, body)
            .ok_or(StorageError::Unreadable)?;
        Ok((meta, body))
    }

    /// Session `id` sealed again under `key` (32 bytes), with the same
    /// contents: the file a client copies into a store of its own (the app
    /// beside a tunnel that keeps its key to itself). Never written here.
    pub fn reseal(&self, id: &str, key: &[u8]) -> Result<Vec<u8>, StorageError> {
        let target = sealing_key(key)?;
        let path = self.path(id)?;
        let mut file = fs::read(&path).map_err(|_| StorageError::NoSuchSession)?;
        let (meta, body) = self.open_file(&mut file)?;
        let meta = serde_json::to_vec(&meta).map_err(|_| StorageError::Unreadable)?;
        let body = body.to_vec();
        drop(file);
        sealed_file(&target, meta, body)
    }

    /// Keeps `file`, a whole session file sealed with this storage's key
    /// (from [`Self::reseal`]), as session `id`; its listing entry. A file
    /// this key cannot open is refused, so nothing unreadable is kept; a
    /// session already there is replaced (the same id is the same save).
    pub fn import(&self, id: &str, file: &[u8]) -> Result<Value, StorageError> {
        self.path(id)?;
        // Opened on a copy: `open_file` decrypts in place, and the sealed
        // bytes are what is kept.
        let mut check = file.to_vec();
        let (meta, body) = self.open_file(&mut check)?;
        decode(body).ok_or(StorageError::Unreadable)?;
        let entry = meta_value(
            id,
            meta.get("saved_at_ms")
                .and_then(Value::as_u64)
                .ok_or(StorageError::Unreadable)?,
            meta.get("name").and_then(Value::as_str).unwrap_or(""),
            meta.get("connections").and_then(Value::as_u64).unwrap_or(0) as usize,
            meta.get("requests").and_then(Value::as_u64).unwrap_or(0) as usize,
        );
        drop(check);
        let path = self.write(id, file)?;
        Ok(self.entry(id, &path, Some(entry)))
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

/// A new session id `<now_ms>-<8 random hex>`.
pub(super) fn new_session_id(now_ms: u64) -> Option<String> {
    let mut tag = [0u8; 4];
    SystemRandom::new().fill(&mut tag).ok()?;
    Some(format!("{now_ms}-{}", hex(&tag)))
}

/// What [`seal_inner`] made.
pub(super) struct Sealed {
    pub name: String,
    pub connections: usize,
    pub requests: usize,
    pub file: Vec<u8>,
}

/// `inner` as a whole session file sealed with `key`, named `name` (cut to
/// [`MAX_NAME_CHARS`]) and dated `now_ms`.
pub(super) fn seal_inner(
    key: &LessSafeKey,
    inner: &Inner,
    name: Option<&str>,
    now_ms: u64,
) -> Result<Sealed, StorageError> {
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
    let meta = serde_json::to_vec(&meta).map_err(|_| StorageError::WriteFailed)?;
    let file = sealed_file(key, meta, encode(inner))?;
    Ok(Sealed {
        name,
        connections: inner.connections.len(),
        requests,
        file,
    })
}

/// The AEAD key of 32 raw bytes.
pub(super) fn sealing_key(key: &[u8]) -> Result<LessSafeKey, StorageError> {
    if key.len() != KEY_LEN {
        return Err(StorageError::InvalidKey);
    }
    UnboundKey::new(&CHACHA20_POLY1305, key)
        .map(LessSafeKey::new)
        .map_err(|_| StorageError::InvalidKey)
}

/// A whole session file: the meta part (length-prefixed), then the
/// connections, each under a fresh nonce.
fn sealed_file(
    key: &LessSafeKey,
    mut meta: Vec<u8>,
    mut body: Vec<u8>,
) -> Result<Vec<u8>, StorageError> {
    let random = SystemRandom::new();
    let mut file = Vec::with_capacity(MAGIC.len() + meta.len() + body.len() + 64);
    file.extend_from_slice(MAGIC);
    for (part, data) in [(0u8, &mut meta), (1, &mut body)] {
        let mut nonce = [0u8; NONCE_LEN];
        random
            .fill(&mut nonce)
            .map_err(|_| StorageError::WriteFailed)?;
        key.seal_in_place_append_tag(
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
    }
    Ok(file)
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
pub(super) fn saved_at(id: &str) -> Option<u64> {
    let (millis, tag) = id.split_once('-')?;
    let valid = tag.len() == 8 && tag.bytes().all(|b| b.is_ascii_hexdigit());
    if !valid || millis.is_empty() || !millis.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    millis.parse().ok()
}

// Binary layout of the connections part: integers big-endian, strings and
// byte strings as a u32 length and the bytes, options as a 0/1 byte first.
// Each connection ends with its extensions: a u16 count, then per
// extension a u16 tag and its bytes; a reader skips tags it does not know.
// Tag 1 is the stream state of one exchange (see `stream_extension`).

/// Extension tag: an exchange's `rules_skipped` and stream messages.
const EXT_STREAM: u16 = 1;
/// Extension tag: the connection's HTTP/2 frames.
const EXT_H2_FRAMES: u16 = 2;

const MESSAGE_KINDS: [MessageKind; 6] = [
    MessageKind::Sse,
    MessageKind::Text,
    MessageKind::Binary,
    MessageKind::Ping,
    MessageKind::Pong,
    MessageKind::Close,
];

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
    [
        "answered_locally",
        "streaming",
        "too_large",
        "rejected",
        "connect_failed",
        "unparsed",
        "busy",
    ]
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
        let streams = captured
            .http
            .iter()
            .enumerate()
            .filter(|(_, exchange)| exchange.rules_skipped || !exchange.messages.is_empty())
            .collect::<Vec<_>>();
        let streams = &streams[..streams.len().min(usize::from(u16::MAX) - 1)];
        let frames = !captured.h2.is_empty();
        out.u16(streams.len() as u16 + u16::from(frames));
        for (index, exchange) in streams {
            out.u16(EXT_STREAM);
            out.bytes(&stream_extension(*index, exchange));
        }
        if frames {
            out.u16(EXT_H2_FRAMES);
            out.bytes(&h2_extension(&captured.h2));
        }
    }
    out.0
}

/// Extension [`EXT_STREAM`]: the exchange's index, `rules_skipped`, the
/// message counters and the kept messages.
fn stream_extension(index: usize, exchange: &HttpExchange) -> Vec<u8> {
    let messages = &exchange.messages;
    let mut out = Writer(Vec::with_capacity(32 + messages.memory()));
    out.u64(index as u64);
    out.u8(u8::from(exchange.rules_skipped));
    out.u64(messages.seen);
    out.u64(messages.dropped);
    out.u64(messages.kept.len() as u64);
    for message in &messages.kept {
        out.u64(message.index);
        out.u64(message.at_ms);
        out.u8(u8::from(message.direction == Direction::Down));
        let kind = MESSAGE_KINDS.iter().position(|kind| *kind == message.kind);
        out.u8(kind.unwrap_or(0) as u8);
        out.opt_str(message.label.as_deref());
        out.opt_str(message.id.as_deref());
        out.opt_u64(message.code.map(u64::from));
        out.u64(message.size);
        out.bytes(&message.data);
    }
    out.0
}

/// Extension [`EXT_H2_FRAMES`]: the counters and the kept frames.
fn h2_extension(frames: &H2Frames) -> Vec<u8> {
    let mut out = Writer(Vec::with_capacity(24 + frames.kept.len() * 40));
    out.u64(frames.seen);
    out.u64(frames.dropped);
    out.u64(frames.kept.len() as u64);
    for frame in &frames.kept {
        out.u64(frame.index);
        out.u64(frame.at_ms);
        out.u8(u8::from(frame.link == Link::Origin));
        out.u8(u8::from(frame.direction == Direction::Down));
        out.u8(frame.kind);
        out.u8(frame.flags);
        out.u64(u64::from(frame.stream));
        out.u64(u64::from(frame.length));
        out.opt_u64(frame.error.map(u64::from));
        out.opt_u64(frame.value.map(u64::from));
    }
    out.0
}

fn read_h2_extension(data: &[u8]) -> Option<H2Frames> {
    let mut input = Reader(data);
    let seen = input.u64()?;
    let dropped = input.u64()?;
    let count = input.count(38)?;
    let mut kept = std::collections::VecDeque::with_capacity(count.min(MAX_FRAMES));
    let small = |value: u64| u32::try_from(value).ok();
    for _ in 0..count {
        let index = input.u64()?;
        let at_ms = input.u64()?;
        let link = if input.u8()? == 1 {
            Link::Origin
        } else {
            Link::App
        };
        let direction = if input.u8()? == 1 {
            Direction::Down
        } else {
            Direction::Up
        };
        let kind = input.u8()?;
        let flags = input.u8()?;
        let stream = small(input.u64()?)?;
        let length = small(input.u64()?)?;
        let error = match input.opt_u64()? {
            Some(value) => Some(small(value)?),
            None => None,
        };
        let value = match input.opt_u64()? {
            Some(value) => Some(small(value)?),
            None => None,
        };
        if kept.len() == MAX_FRAMES {
            return None;
        }
        kept.push_back(H2Frame {
            index,
            at_ms,
            link,
            direction,
            kind,
            flags,
            stream,
            length,
            error,
            value,
        });
    }
    input.0.is_empty().then_some(H2Frames {
        kept,
        seen,
        dropped,
    })
}

/// Reads an [`EXT_STREAM`] extension into `http`.
fn read_stream_extension(data: &[u8], http: &mut [HttpExchange]) -> Option<()> {
    let mut input = Reader(data);
    let index = usize::try_from(input.u64()?).ok()?;
    let rules_skipped = input.u8()? != 0;
    let seen = input.u64()?;
    let dropped = input.u64()?;
    let count = input.count(33)?;
    let mut kept = std::collections::VecDeque::with_capacity(count);
    for _ in 0..count {
        let index = input.u64()?;
        let at_ms = input.u64()?;
        let direction = if input.u8()? == 1 {
            Direction::Down
        } else {
            Direction::Up
        };
        let kind = *MESSAGE_KINDS.get(usize::from(input.u8()?))?;
        let label = input.opt_string()?;
        let id = input.opt_string()?;
        let code = match input.opt_u64()? {
            Some(code) => Some(u16::try_from(code).ok()?),
            None => None,
        };
        let size = input.u64()?;
        let data = input.bytes()?.to_vec();
        kept.push_back(StreamMessage {
            index,
            at_ms,
            direction,
            kind,
            label,
            id,
            code,
            data,
            size,
        });
    }
    if !input.0.is_empty() {
        return None;
    }
    let exchange = http.get_mut(index)?;
    exchange.rules_skipped = rules_skipped;
    exchange.messages = Messages::restore(kept, seen, dropped);
    Some(())
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
                ..HttpExchange::default()
            });
        }
        let mut h2 = H2Frames::default();
        for _ in 0..input.u16()? {
            let tag = input.u16()?;
            let data = input.bytes()?;
            match tag {
                EXT_STREAM => read_stream_extension(data, &mut http)?,
                EXT_H2_FRAMES => h2 = read_h2_extension(data)?,
                _ => {}
            }
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
            http_base: 0,
            h2,
            memory: 0,
            loaded: false,
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
        exchange.rules_skipped = true;
        let index = store.open_exchange(2, exchange).unwrap();
        for (i, kind) in MESSAGE_KINDS.into_iter().enumerate() {
            store.push_message(
                2,
                index,
                StreamMessage {
                    index: 0,
                    at_ms: 10 + i as u64,
                    direction: if i % 2 == 0 {
                        Direction::Down
                    } else {
                        Direction::Up
                    },
                    kind,
                    label: (i == 0).then(|| "update".to_string()),
                    id: (i == 0).then(|| "42".to_string()),
                    code: (kind == MessageKind::Close).then_some(1000),
                    data: format!("message {i}").into_bytes(),
                    size: 9 + i as u64,
                },
            );
        }
        store.finish_exchange(2, index, None);
        let mut scanner = super::super::h2frames::FrameScanner::new(Link::Origin, Direction::Down);
        // A WINDOW_UPDATE and an RST_STREAM (CANCEL).
        let frames = scanner.feed(
            &[
                0, 0, 4, 8, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 4, 3, 0, 0, 0, 0, 3, 0, 0, 0, 8,
            ],
            20,
        );
        assert_eq!(frames.len(), 2);
        store.push_h2_frames(2, frames);
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
                .save(&inner, Some(" morning run "), 1_000_000, None)
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
        assert!(tcp.http[0].rules_skipped);
        let saved = {
            let inner = super::super::lock(&store.inner);
            inner.connections[&2].http[0].messages.clone()
        };
        assert_eq!(saved.seen, MESSAGE_KINDS.len() as u64);
        assert_eq!(tcp.http[0].messages, saved);
        let saved_frames = {
            let inner = super::super::lock(&store.inner);
            inner.connections[&2].h2.clone()
        };
        assert_eq!(saved_frames.seen, 2);
        assert_eq!(tcp.h2, saved_frames);
        assert!(loaded[0].1.h2.is_empty());
        assert_eq!(tcp.memory, tcp.memory_estimate());
        assert_eq!(loaded[0].1.chunks[0].data, b"query");

        // Another key reads nothing.
        let other = Storage::new(dir.to_str().unwrap(), &[8u8; KEY_LEN], None).unwrap();
        assert_eq!(other.load(&id).err(), Some(StorageError::Unreadable));
        assert_eq!(other.list(1_000_001)[0]["unreadable"], true);

        assert!(storage.delete(&id).unwrap());
        assert!(!storage.delete(&id).unwrap());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn resealed_sessions_open_only_in_the_store_of_the_new_key() {
        let tunnel_dir = temp_dir("reseal-tunnel");
        let app_dir = temp_dir("reseal-app");
        let tunnel = Storage::new(tunnel_dir.to_str().unwrap(), &[1u8; KEY_LEN], None).unwrap();
        let app = Storage::new(app_dir.to_str().unwrap(), &[2u8; KEY_LEN], None).unwrap();
        let store = sample_store();
        let now = super::super::unix_millis();
        let id = {
            let inner = super::super::lock(&store.inner);
            tunnel
                .save(&inner, Some("on disconnect"), now, None)
                .unwrap()["session"]
                .as_str()
                .unwrap()
                .to_string()
        };

        assert_eq!(tunnel.reseal(&id, &[2u8; 3]), Err(StorageError::InvalidKey));
        assert_eq!(
            tunnel.reseal("1-00000000", &[2u8; KEY_LEN]),
            Err(StorageError::NoSuchSession)
        );
        // The tunnel's own file is not the app's: refused, nothing kept.
        let original = fs::read(tunnel_dir.join(format!("{id}.anxcap"))).unwrap();
        assert_eq!(app.import(&id, &original), Err(StorageError::Unreadable));
        assert!(app.list(now).is_empty());

        let copy = tunnel.reseal(&id, &[2u8; KEY_LEN]).unwrap();
        assert_ne!(copy, original);
        assert!(!copy.windows(14).any(|w| w == b"secret payload"));
        assert_eq!(app.import("../x", &copy), Err(StorageError::NoSuchSession));
        let entry = app.import(&id, &copy).unwrap();
        assert_eq!(entry["session"], id.as_str());
        assert_eq!(entry["name"], "on disconnect");
        assert_eq!(entry["connections"], 2);
        assert_eq!(entry["requests"], 1);
        assert_eq!(entry["size"], copy.len() as u64);
        // Importing again replaces it.
        app.import(&id, &copy).unwrap();
        let listed = app.list(now);
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0]["name"], "on disconnect");

        let loaded = app.load(&id).unwrap();
        assert_eq!(loaded.len(), 2);
        assert_eq!(loaded[1].1.http[0].response_body.data, b"secret payload");
        // Damaged copies are refused.
        let mut damaged = copy.clone();
        let last = damaged.len() - 1;
        damaged[last] ^= 1;
        assert_eq!(app.import(&id, &damaged), Err(StorageError::Unreadable));
        assert_eq!(
            app.import(&id, &copy[..copy.len() / 2]),
            Err(StorageError::Unreadable)
        );
        assert_eq!(app.import(&id, b""), Err(StorageError::Unreadable));
        let _ = fs::remove_dir_all(&tunnel_dir);
        let _ = fs::remove_dir_all(&app_dir);
    }

    #[test]
    fn old_sessions_are_purged_and_ids_cannot_name_paths() {
        let dir = temp_dir("purge");
        let storage = Storage::new(dir.to_str().unwrap(), &[1u8; KEY_LEN], Some(7)).unwrap();
        let store = sample_store();
        {
            let inner = super::super::lock(&store.inner);
            storage.save(&inner, None, 1_000, None).unwrap();
            storage
                .save(&inner, None, 1_000 + 6 * DAY_MS, None)
                .unwrap();
        }
        fs::write(dir.join("notes.txt"), b"keep").unwrap();
        assert_eq!(storage.purge(1_000 + 7 * DAY_MS + 1), 1);
        assert_eq!(storage.list(1_000 + 7 * DAY_MS + 1).len(), 1);
        assert!(dir.join("notes.txt").exists());
        assert_eq!(
            storage.load("../../etc/passwd").err(),
            Some(StorageError::NoSuchSession)
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
