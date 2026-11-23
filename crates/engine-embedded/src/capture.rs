//! Capture (抓包): the bytes and HTTP messages of connections, for the
//! client's request detail and for export.
//!
//! Off by default. The client turns it on with the `set_capture` control
//! command; from then on every new connection the [`crate::connections`]
//! dispatcher opens keeps the first [`MAX_DIRECTION_BYTES`] of each
//! direction (the app's own payload, before any proxy protocol: plain text
//! for plain protocols, TLS records for HTTPS) and, for connections HTTPS
//! decryption (`mitm`) took over, the decrypted HTTP/1.1 requests and
//! responses with the first [`MAX_HTTP_BODY_BYTES`] of each body. All of it
//! stays in memory under one budget (`max_total_bytes`, default
//! [`DEFAULT_MAX_TOTAL_BYTES`], at most [`MAX_TOTAL_BYTES_LIMIT`]), so the
//! Network Extension stays inside its memory limit. One connection holds at
//! most half of the budget: past that its own oldest finished exchanges give
//! up their bodies (the rows stay, marked truncated) and then are forgotten,
//! so one busy connection never empties the rest of the capture. Past the
//! whole budget, connections loaded from a session and then closed
//! connections are dropped first, oldest first; open connections give up
//! their bodies before they are dropped, and a dropped (or cleared) open
//! connection keeps recording new exchanges afterwards. The counts of what
//! was let go are in the status (`dropped_exchanges`, `dropped_bodies`).
//!
//! What is captured is returned only to an explicit `capture_connection` or
//! `export_capture` request and is never written to status, logs or errors.
//! Exports are `pcapng` (each connection as a synthetic TCP or UDP flow over
//! raw IP that Wireshark reads; a decrypted connection carries its HTTP text,
//! a domain destination gets an address from 198.18.0.0/15 named in a name
//! resolution block) and `har` (HAR 1.2 of the decrypted HTTP messages),
//! and for decrypted requests `curl` (a shell script), `code` (Python,
//! JavaScript, Swift, Kotlin or Go, see [`export::Language`]), `postman`
//! (a Postman collection v2.1) and `insomnia` (an Insomnia export v4).
//! Exports are redacted unless the request says `redact: false`: see
//! [`redact`] for what is masked.
//!
//! `capture_requests` lists the decrypted HTTP exchanges one row each, in
//! the order they were filed (`seq`), filtered by the expression syntax of
//! [`filter`].
//!
//! Only what the app itself sent and got is ever kept: bytes before any
//! proxy protocol and decrypted HTTP. The wire bytes of the outbound
//! protocol (ANX, Shadowsocks, VLESS, ...) never reach this module, so no
//! capture, export or saved session can show them.
//!
//! With `set_capture_storage` the client names a directory and a key it
//! keeps; `save_capture` then seals what the store holds into an encrypted
//! session file there, `load_capture` brings one back for viewing and
//! export, and sessions older than the retention (default 7 days) are
//! deleted. See [`storage`].

pub mod decode;
pub mod export;
pub mod filter;
pub mod h2frames;
pub mod redact;
pub mod storage;
pub mod stream;
pub mod websocket;

use std::borrow::Cow;
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::future::Future;
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use serde::Serialize;
use serde_json::{json, Value};

use crate::connections::Network;

pub use self::export::Language;
use self::filter::Filter;

/// `http_version` of an HTTP/1.x exchange.
pub const HTTP_1_1: &str = "HTTP/1.1";
/// `http_version` of an HTTP/2 exchange.
pub const HTTP_2: &str = "HTTP/2";
/// Rows `capture_requests` returns when the request names no `limit`.
pub const DEFAULT_REQUEST_ROWS: usize = 500;
/// Most rows one `capture_requests` answer holds.
pub const MAX_REQUEST_ROWS: usize = 2000;

/// Capture budget when `set_capture` names none.
pub const DEFAULT_MAX_TOTAL_BYTES: usize = 2 * 1024 * 1024;
/// Largest budget `set_capture` accepts.
pub const MAX_TOTAL_BYTES_LIMIT: usize = 16 * 1024 * 1024;
/// Smallest budget `set_capture` accepts.
pub const MIN_TOTAL_BYTES: usize = 64 * 1024;
/// Bytes kept per connection and direction.
pub const MAX_DIRECTION_BYTES: usize = 64 * 1024;
/// Datagrams (or TCP reads and writes that could not be merged) kept per
/// connection.
pub const MAX_CHUNKS: usize = 512;
/// Bytes kept of one HTTP request or response body.
pub const MAX_HTTP_BODY_BYTES: usize = 64 * 1024;
/// HTTP exchanges kept per connection.
pub const MAX_HTTP_EXCHANGES: usize = 64;
/// Connections kept at most, whatever their size.
pub const MAX_CAPTURED_CONNECTIONS: usize = 1024;
/// Connections loaded from a saved session are numbered from here, apart
/// from the ids live connections get (which count up from 1 each time the
/// tunnel starts), so nothing live ever writes into loaded data. Below 2^53
/// so clients that hold ids as JavaScript numbers read them exactly.
pub const LOADED_ID_BASE: u64 = 1 << 52;
/// Bytes counted for one connection besides its data, so many empty
/// connections still use the budget.
const CONNECTION_OVERHEAD: usize = 256;
/// Largest piece one chunk of a TCP stream is kept in.
const CHUNK_PIECE_BYTES: usize = 16 * 1024;
/// Bytes counted for one chunk besides its data.
const CHUNK_OVERHEAD: usize = 32;

/// Which way bytes went: from the app (`up`) or to it (`down`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Direction {
    Up,
    Down,
}

impl Direction {
    fn index(self) -> usize {
        match self {
            Self::Up => 0,
            Self::Down => 1,
        }
    }
}

struct Chunk {
    direction: Direction,
    at_ms: u64,
    data: Vec<u8>,
}

/// The first bytes of a body and how long it was.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CapturedBody {
    pub data: Vec<u8>,
    /// Bytes the body had, captured or not.
    pub size: u64,
}

impl CapturedBody {
    /// The first [`MAX_HTTP_BODY_BYTES`] of `body`.
    pub fn of(body: &[u8]) -> Self {
        Self {
            data: body[..body.len().min(MAX_HTTP_BODY_BYTES)].to_vec(),
            size: body.len() as u64,
        }
    }

    fn truncated(&self) -> bool {
        self.size > self.data.len() as u64
    }

    fn json(&self) -> Value {
        json!({
            "size": self.size,
            "truncated": self.truncated(),
            "data_base64": base64_encode(&self.data),
        })
    }
}

/// One decrypted HTTP request and its response.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct HttpExchange {
    /// Order in which the store filed it, from 1; 0 until it is filed.
    pub seq: u64,
    /// [`HTTP_1_1`] or [`HTTP_2`].
    pub http_version: &'static str,
    pub started_at_ms: u64,
    pub ended_at_ms: Option<u64>,
    pub method: String,
    pub url: String,
    /// The request as the app sent it.
    pub request_headers: Vec<(String, String)>,
    pub request_body: CapturedBody,
    /// The response as the app got it; `None` when none came.
    pub status: Option<u16>,
    pub response_headers: Vec<(String, String)>,
    pub response_body: CapturedBody,
    /// `answered_locally` (a rewrite rule answered), `streaming` (an
    /// upgrade or event stream, body not kept), `too_large` (relayed
    /// without decryption from there on), `unparsed` (a response head the
    /// relay could not read, relayed unchanged from there on, or a
    /// response whose framing could not be read, answered with 502),
    /// `busy` (the body was not held because the bodies of other messages
    /// already used the memory set aside for them), `rejected` or
    /// `connect_failed`.
    pub note: Option<&'static str>,
    /// A body rule matched but did not run: the body streamed (`streaming`),
    /// was too large to hold (`too_large`), could not be read (`unparsed`)
    /// or found no memory to be held in (`busy`).
    pub rules_skipped: bool,
    /// The kept tail of the messages inside a stream (server-sent events).
    pub messages: stream::Messages,
    /// When the store last changed it, in the store's order of changes:
    /// `capture_requests` with `since_rev` lists exchanges still in
    /// progress and each change to them.
    pub rev: u64,
}

impl HttpExchange {
    pub fn new(method: &str, url: &str, headers: &[(String, String)]) -> Self {
        Self {
            http_version: HTTP_1_1,
            started_at_ms: unix_millis(),
            method: method.to_string(),
            url: url.to_string(),
            request_headers: headers.to_vec(),
            ..Self::default()
        }
    }

    /// Lets go of the kept body bytes and stream messages, keeping the
    /// request line, headers, times and sizes (so the bodies read as
    /// truncated). Returns the bytes freed.
    fn drop_bodies(&mut self) -> usize {
        let before = self.memory();
        self.request_body.data = Vec::new();
        self.response_body.data = Vec::new();
        if !self.messages.kept.is_empty() {
            let dropped = self.messages.dropped + self.messages.kept.len() as u64;
            self.messages =
                stream::Messages::restore(Default::default(), self.messages.seen, dropped);
        }
        before.saturating_sub(self.memory())
    }

    fn memory(&self) -> usize {
        let headers = |headers: &[(String, String)]| {
            headers
                .iter()
                .map(|(name, value)| name.len() + value.len() + 16)
                .sum::<usize>()
        };
        self.method.len()
            + self.url.len()
            + headers(&self.request_headers)
            + headers(&self.response_headers)
            + self.request_body.data.len()
            + self.response_body.data.len()
            + self.messages.memory()
            + CHUNK_OVERHEAD
    }

    /// `in_progress` until the exchange ended (its response, or stream,
    /// is still coming), then `done`.
    fn state(&self) -> &'static str {
        if self.ended_at_ms.is_some() {
            "done"
        } else {
            "in_progress"
        }
    }

    /// The messages from index `since` on, as `capture_exchange` and
    /// `capture_connection` show them.
    fn messages_json(&self, since: u64) -> Value {
        json!({
            "seen": self.messages.seen,
            "dropped": self.messages.dropped,
            "kept": self.messages.json_since(since),
        })
    }

    fn json(&self) -> Value {
        let headers = |headers: &[(String, String)]| {
            headers
                .iter()
                .map(|(name, value)| json!([name, value]))
                .collect::<Vec<_>>()
        };
        json!({
            "seq": self.seq,
            "http_version": self.http_version,
            "started_at_ms": self.started_at_ms,
            "ended_at_ms": self.ended_at_ms,
            "method": self.method,
            "url": self.url,
            "status": self.status,
            "note": self.note,
            "state": self.state(),
            "rev": self.rev,
            "rules_skipped": self.rules_skipped,
            "messages": self.messages_json(0),
            "request": {
                "headers": headers(&self.request_headers),
                "body": self.request_body.json(),
            },
            "response": {
                "headers": headers(&self.response_headers),
                "body": self.response_body.json(),
            },
        })
    }
}

struct Captured {
    network: Network,
    host: Option<String>,
    destination: String,
    started_at_ms: u64,
    ended_at_ms: Option<u64>,
    /// HTTPS decryption took the connection over: its raw bytes are the
    /// re-encrypted upstream, so only its HTTP messages are kept.
    decrypted: bool,
    chunks: Vec<Chunk>,
    /// Bytes kept, by direction.
    kept: [usize; 2],
    /// Bytes seen while capturing, by direction.
    seen: [u64; 2],
    http: Vec<HttpExchange>,
    /// The index of `http[0]`. Exchanges are only ever let go of from the
    /// front, so every kept exchange keeps the index `open_exchange` gave
    /// it and an index is never given twice on one connection.
    http_base: usize,
    /// The HTTP/2 frame timeline of a decrypted `h2` connection.
    h2: h2frames::H2Frames,
    /// What this connection counts against the budget.
    memory: usize,
    /// Loaded from a saved session: live capture never writes into it.
    loaded: bool,
}

/// What [`Captured::trim`] let go of.
#[derive(Default)]
struct Trimmed {
    freed: usize,
    bodies: u64,
    exchanges: u64,
    last_seq: u64,
}

impl Captured {
    /// Exchange `index`, as `open_exchange` returned it.
    fn exchange(&self, index: usize) -> Option<&HttpExchange> {
        self.http.get(index.checked_sub(self.http_base)?)
    }

    fn exchange_mut(&mut self, index: usize) -> Option<&mut HttpExchange> {
        let position = index.checked_sub(self.http_base)?;
        self.http.get_mut(position)
    }

    /// The oldest exchange, taken out when it has ended (one still in
    /// progress is updated by index later, so it stays).
    fn take_oldest_exchange(&mut self) -> Option<HttpExchange> {
        if self.http.first()?.ended_at_ms.is_none() {
            return None;
        }
        self.http_base += 1;
        let exchange = self.http.remove(0);
        self.memory = self.memory.saturating_sub(exchange.memory());
        Some(exchange)
    }

    /// Frees memory until the connection counts at most `target` bytes, or
    /// nothing more can go, without forgetting the connection: first the
    /// bodies of its finished exchanges, oldest first, then its HTTP/2
    /// frame timeline, then its oldest finished exchanges themselves, then
    /// the bodies of exchanges still in progress. Raw bytes stay: they are
    /// at most [`MAX_DIRECTION_BYTES`] a direction and stop being kept at
    /// the connection's share instead (see [`CaptureStore::record`]).
    fn trim(&mut self, target: usize) -> Trimmed {
        let mut trimmed = Trimmed::default();
        for exchange in self.http.iter_mut() {
            if self.memory <= target {
                return trimmed;
            }
            if exchange.ended_at_ms.is_none() {
                continue;
            }
            let freed = exchange.drop_bodies();
            if freed > 0 {
                self.memory = self.memory.saturating_sub(freed);
                trimmed.freed += freed;
                trimmed.bodies += 1;
            }
        }
        if self.memory > target && !self.h2.kept.is_empty() {
            let freed = self.h2.memory();
            self.h2.dropped += self.h2.kept.len() as u64;
            self.h2.kept = Default::default();
            self.memory = self.memory.saturating_sub(freed);
            trimmed.freed += freed;
        }
        while self.memory > target {
            let Some(exchange) = self.take_oldest_exchange() else {
                break;
            };
            trimmed.freed += exchange.memory();
            trimmed.exchanges += 1;
            trimmed.last_seq = trimmed.last_seq.max(exchange.seq);
        }
        for exchange in self.http.iter_mut() {
            if self.memory <= target {
                break;
            }
            let freed = exchange.drop_bodies();
            if freed > 0 {
                self.memory = self.memory.saturating_sub(freed);
                trimmed.freed += freed;
                trimmed.bodies += 1;
            }
        }
        trimmed
    }

    /// The connection with everything it kept let go of, ready to record
    /// again: later exchanges get indexes after every earlier one.
    fn into_shell(mut self) -> Self {
        self.http_base += self.http.len();
        self.http = Vec::new();
        self.chunks = Vec::new();
        self.kept = [0, 0];
        self.seen = [0, 0];
        self.h2.dropped += self.h2.kept.len() as u64;
        self.h2.kept = Default::default();
        self.memory = self.memory_estimate();
        self
    }

    /// The chunks with the pieces of one TCP run joined again.
    fn joined_chunks(&self) -> Vec<(Direction, u64, Vec<u8>)> {
        let mut joined: Vec<(Direction, u64, Vec<u8>)> = Vec::new();
        for chunk in &self.chunks {
            match joined.last_mut() {
                Some(last) if self.network == Network::Tcp && last.0 == chunk.direction => {
                    last.2.extend_from_slice(&chunk.data);
                }
                _ => joined.push((chunk.direction, chunk.at_ms, chunk.data.clone())),
            }
        }
        joined
    }

    /// What the connection counts against the budget, from its contents.
    fn memory_estimate(&self) -> usize {
        CONNECTION_OVERHEAD
            + self.destination.len()
            + self.host.as_ref().map_or(0, String::len)
            + self
                .chunks
                .iter()
                .map(|chunk| chunk.data.len() + CHUNK_OVERHEAD)
                .sum::<usize>()
            + self.http.iter().map(HttpExchange::memory).sum::<usize>()
            + self.h2.memory()
    }

    fn json(&self, id: u64) -> Value {
        let direction = |index: usize| {
            json!({
                "seen": self.seen[index],
                "captured": self.kept[index],
                "truncated": self.seen[index] > self.kept[index] as u64,
            })
        };
        json!({
            "id": id,
            "network": self.network,
            "host": self.host,
            "destination": self.destination,
            "started_at_ms": self.started_at_ms,
            "ended_at_ms": self.ended_at_ms,
            "decrypted": self.decrypted,
            "upload": direction(0),
            "download": direction(1),
            "chunks": self.joined_chunks()
                .into_iter()
                .map(|(direction, at_ms, data)| json!({
                    "dir": direction,
                    "at_ms": at_ms,
                    "data_base64": base64_encode(&data),
                }))
                .collect::<Vec<_>>(),
            "http": self
                .http
                .iter()
                .enumerate()
                .map(|(position, exchange)| {
                    let mut value = exchange.json();
                    value["index"] = json!(self.http_base + position);
                    value
                })
                .collect::<Vec<_>>(),
            "h2_frames": {
                "seen": self.h2.seen,
                "dropped": self.h2.dropped,
            },
        })
    }
}

#[derive(Default)]
struct Inner {
    connections: BTreeMap<u64, Captured>,
    /// Open connections whose capture was dropped for the budget or
    /// cleared: empty and outside the budget, they come back into
    /// `connections` with their next decrypted exchange, so a connection
    /// is never left out for the rest of its life. Forgotten when they
    /// close.
    dormant: BTreeMap<u64, Captured>,
    used: usize,
    /// The highest `seq` of an exchange let go of.
    dropped_seq: u64,
    /// The last `rev` given to an exchange.
    rev: u64,
    /// Exchanges let go of for the budget or the per-connection limit
    /// since the last clear.
    dropped_exchanges: u64,
    /// Exchanges whose bodies were let go of for the budget since the last
    /// clear.
    dropped_bodies: u64,
}

impl Inner {
    fn next_rev(&mut self) -> u64 {
        self.rev += 1;
        self.rev
    }

    /// Forgets connection `id`, freeing its budget. An open live
    /// connection stays as a dormant shell, so it records again.
    fn remove(&mut self, id: u64) {
        let Some(dropped) = self.connections.remove(&id) else {
            return;
        };
        self.used = self.used.saturating_sub(dropped.memory);
        self.dropped_exchanges += dropped.http.len() as u64;
        if let Some(last) = dropped.http.iter().map(|exchange| exchange.seq).max() {
            self.dropped_seq = self.dropped_seq.max(last);
        }
        if dropped.ended_at_ms.is_none() && !dropped.loaded {
            self.park(id, dropped.into_shell());
        }
    }

    /// Keeps the emptied open connection `id` for later exchanges.
    fn park(&mut self, id: u64, shell: Captured) {
        self.dormant.insert(id, shell);
        while self.dormant.len() > MAX_CAPTURED_CONNECTIONS {
            self.dormant.pop_first();
        }
    }

    /// Brings dormant connection `id` back into the capture.
    fn revive(&mut self, id: u64) {
        if self.connections.contains_key(&id) {
            return;
        }
        if let Some(shell) = self.dormant.remove(&id) {
            self.used += shell.memory;
            self.connections.insert(id, shell);
        }
    }

    /// Forgets everything kept; open live connections stay dormant.
    fn forget_all(&mut self, dropped_seq: u64) {
        for (id, captured) in std::mem::take(&mut self.connections) {
            if captured.ended_at_ms.is_none() && !captured.loaded {
                self.park(id, captured.into_shell());
            }
        }
        self.used = 0;
        self.dropped_seq = dropped_seq;
        self.dropped_exchanges = 0;
        self.dropped_bodies = 0;
    }

    /// Trims connection `id` down to `target` bytes (see
    /// [`Captured::trim`]).
    fn trim(&mut self, id: u64, target: usize) {
        let Some(captured) = self.connections.get_mut(&id) else {
            return;
        };
        let trimmed = captured.trim(target);
        self.used = self.used.saturating_sub(trimmed.freed);
        self.dropped_bodies += trimmed.bodies;
        self.dropped_exchanges += trimmed.exchanges;
        self.dropped_seq = self.dropped_seq.max(trimmed.last_seq);
    }

    fn over(&self, budget: usize) -> bool {
        self.used > budget || self.connections.len() > MAX_CAPTURED_CONNECTIONS
    }

    /// Lets go of what is needed for the budget to hold, `keep` (the
    /// connection that just grew) last:
    ///
    /// 1. `keep` never holds more than half the budget: past that its own
    ///    oldest bodies and exchanges go (see [`Captured::trim`]), so one
    ///    busy connection does not empty the rest of the capture;
    /// 2. connections loaded from a session, then closed ones, oldest
    ///    first;
    /// 3. the bodies and finished exchanges of other open connections,
    ///    oldest first, then of `keep`;
    /// 4. other open connections, oldest first (they stay dormant and
    ///    record again with their next exchange).
    fn make_room(&mut self, keep: u64, budget: usize) {
        let share = budget / 2;
        if self
            .connections
            .get(&keep)
            .is_some_and(|captured| captured.memory > share)
        {
            self.trim(keep, share);
        }
        while self.over(budget) {
            let victim = self
                .connections
                .iter()
                .find(|(id, captured)| **id != keep && captured.loaded)
                .or_else(|| {
                    self.connections
                        .iter()
                        .find(|(id, captured)| **id != keep && captured.ended_at_ms.is_some())
                })
                .map(|(&id, _)| id);
            let Some(victim) = victim else {
                break;
            };
            self.remove(victim);
        }
        if self.used > budget {
            let others = self
                .connections
                .keys()
                .copied()
                .filter(|&id| id != keep)
                .collect::<Vec<_>>();
            for id in others.into_iter().chain([keep]) {
                let excess = self.used.saturating_sub(budget);
                if excess == 0 {
                    break;
                }
                let memory = self
                    .connections
                    .get(&id)
                    .map_or(0, |captured| captured.memory);
                self.trim(id, memory.saturating_sub(excess));
            }
        }
        while self.over(budget) {
            let Some(oldest) = self.connections.keys().copied().find(|&id| id != keep) else {
                break;
            };
            self.remove(oldest);
        }
    }

    /// `dropped_before_seq`: every exchange with a `seq` up to it was let
    /// go of. It never passes an exchange still kept, so a client that
    /// drops its rows up to it never drops one the store still has.
    fn dropped_before_seq(&self) -> u64 {
        let oldest_kept = self
            .connections
            .values()
            .flat_map(|captured| captured.http.iter())
            .map(|exchange| exchange.seq)
            .filter(|&seq| seq > 0)
            .min();
        match oldest_kept {
            Some(oldest) => self.dropped_seq.min(oldest - 1),
            None => self.dropped_seq,
        }
    }
}

/// Makes room in `buf` for `more` bytes, doubling like `Vec` does but never
/// past `limit`, the most `buf` will ever hold, so a kept piece takes about
/// the memory the budget counts for it instead of up to twice that.
pub(crate) fn reserve_capped(buf: &mut Vec<u8>, more: usize, limit: usize) {
    let needed = buf.len() + more;
    if needed <= buf.capacity() {
        return;
    }
    let target = (buf.capacity() * 2).clamp(needed, limit.max(needed));
    buf.reserve_exact(target - buf.len());
}

/// The capture switch, its budget and what it kept.
pub struct CaptureStore {
    enabled: AtomicBool,
    max_total_bytes: AtomicUsize,
    /// The `seq` the next filed exchange gets.
    next_seq: AtomicU64,
    inner: Mutex<Inner>,
    /// Where `save_capture` writes sessions, once the client set it.
    storage: Mutex<Option<storage::Storage>>,
}

impl Default for CaptureStore {
    fn default() -> Self {
        Self {
            enabled: AtomicBool::new(false),
            max_total_bytes: AtomicUsize::new(DEFAULT_MAX_TOTAL_BYTES),
            next_seq: AtomicU64::new(1),
            inner: Mutex::default(),
            storage: Mutex::default(),
        }
    }
}

/// The `capture`, `set_capture` and `clear_capture` answer.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct CaptureStatus {
    pub enabled: bool,
    pub max_total_bytes: usize,
    pub used_bytes: usize,
    pub connections: usize,
    /// Exchanges let go of for the budget or the per-connection limit of
    /// [`MAX_HTTP_EXCHANGES`] since the last clear.
    pub dropped_exchanges: u64,
    /// Exchanges whose bodies were let go of for the budget since the
    /// last clear (their rows stay, bodies marked truncated).
    pub dropped_bodies: u64,
}

impl CaptureStore {
    pub fn enabled(&self) -> bool {
        self.enabled.load(Ordering::Relaxed)
    }

    /// Turns capture on or off for later connections and data. `max_total_bytes`
    /// is clamped to [`MIN_TOTAL_BYTES`]..=[`MAX_TOTAL_BYTES_LIMIT`]; a smaller
    /// budget drops the oldest connections at once.
    pub fn set(&self, enabled: bool, max_total_bytes: Option<usize>) {
        if let Some(budget) = max_total_bytes {
            let budget = budget.clamp(MIN_TOTAL_BYTES, MAX_TOTAL_BYTES_LIMIT);
            self.max_total_bytes.store(budget, Ordering::Relaxed);
            lock(&self.inner).make_room(u64::MAX, budget);
        }
        self.enabled.store(enabled, Ordering::Relaxed);
    }

    /// Forgets everything captured; the switch stays as it is. Connections
    /// still open keep recording their later exchanges, under new indexes.
    pub fn clear(&self) {
        let dropped_seq = self.next_seq.load(Ordering::Relaxed).saturating_sub(1);
        lock(&self.inner).forget_all(dropped_seq);
    }

    pub fn status(&self) -> CaptureStatus {
        let inner = lock(&self.inner);
        CaptureStatus {
            enabled: self.enabled(),
            max_total_bytes: self.max_total_bytes.load(Ordering::Relaxed),
            used_bytes: inner.used,
            connections: inner.connections.len(),
            dropped_exchanges: inner.dropped_exchanges,
            dropped_bodies: inner.dropped_bodies,
        }
    }

    /// Starts capturing a new connection when capture is on; `true` when it
    /// does.
    pub(crate) fn begin(
        &self,
        id: u64,
        network: Network,
        host: Option<&str>,
        destination: &str,
        started_at_ms: u64,
    ) -> bool {
        if !self.enabled() {
            return false;
        }
        let memory = CONNECTION_OVERHEAD + destination.len() + host.map_or(0, str::len);
        let budget = self.max_total_bytes.load(Ordering::Relaxed);
        let mut inner = lock(&self.inner);
        // Ids are not reused while the tunnel runs; should one come again,
        // what it held is accounted for before it is replaced.
        inner.dormant.remove(&id);
        if let Some(old) = inner.connections.remove(&id) {
            inner.used = inner.used.saturating_sub(old.memory);
        }
        inner.connections.insert(
            id,
            Captured {
                network,
                host: host.map(str::to_string),
                destination: destination.to_string(),
                started_at_ms,
                ended_at_ms: None,
                decrypted: false,
                chunks: Vec::new(),
                kept: [0, 0],
                seen: [0, 0],
                http: Vec::new(),
                http_base: 0,
                h2: h2frames::H2Frames::default(),
                memory,
                loaded: false,
            },
        );
        inner.used += memory;
        inner.make_room(id, budget);
        true
    }

    /// Keeps the bytes of one read, write or datagram of connection `id`.
    pub(crate) fn record(&self, id: u64, direction: Direction, data: &[u8]) {
        if data.is_empty() || !self.enabled() {
            return;
        }
        let budget = self.max_total_bytes.load(Ordering::Relaxed);
        let mut inner = lock(&self.inner);
        // A dormant connection (dropped for the budget, or cleared) keeps
        // no more raw bytes: they would start in the middle of its stream.
        let Some(captured) = inner.connections.get_mut(&id) else {
            return;
        };
        if captured.loaded {
            return;
        }
        let index = direction.index();
        // A TCP direction is kept as its first bytes without gaps: once a
        // byte of it was left out, nothing later is kept.
        let gap =
            captured.network == Network::Tcp && captured.seen[index] > captured.kept[index] as u64;
        captured.seen[index] = captured.seen[index].saturating_add(data.len() as u64);
        if captured.decrypted || gap {
            return;
        }
        let room = MAX_DIRECTION_BYTES - captured.kept[index];
        let take = data.len().min(room);
        if take == 0 {
            return;
        }
        // A TCP stream is one byte stream per direction: consecutive pieces
        // the same way join one chunk, up to CHUNK_PIECE_BYTES so the
        // allocator reuses the freed pieces instead of growing the heap with
        // ever larger buffers (shown joined again, see `Captured::json`).
        // Datagrams stay apart.
        let merge = captured.network == Network::Tcp
            && captured.chunks.last().is_some_and(|last| {
                last.direction == direction && last.data.len() + take <= CHUNK_PIECE_BYTES
            });
        // One connection keeps at most half the budget: past it the rest of
        // its bytes are only counted (`seen`), so the direction reads as
        // truncated, and no other connection is dropped for them.
        let overhead = if merge { 0 } else { CHUNK_OVERHEAD };
        let share = (budget / 2).saturating_sub(captured.memory + overhead);
        let take = take.min(share);
        if take == 0 {
            return;
        }
        let data = &data[..take];
        let now = unix_millis();
        let added = if merge {
            if let Some(last) = captured.chunks.last_mut() {
                reserve_capped(&mut last.data, take, CHUNK_PIECE_BYTES);
                last.data.extend_from_slice(data);
            }
            take
        } else {
            if captured.chunks.len() >= MAX_CHUNKS {
                return;
            }
            captured.chunks.push(Chunk {
                direction,
                at_ms: now,
                data: data.to_vec(),
            });
            take + CHUNK_OVERHEAD
        };
        captured.kept[index] += take;
        captured.memory += added;
        inner.used += added;
        inner.make_room(id, budget);
    }

    /// Marks connection `id` as taken over by HTTPS decryption: its raw
    /// bytes are dropped and only its HTTP messages are kept.
    pub(crate) fn mark_decrypted(&self, id: u64) {
        let mut inner = lock(&self.inner);
        if let Some(shell) = inner.dormant.get_mut(&id) {
            shell.decrypted = true;
            return;
        }
        let Some(captured) = inner.connections.get_mut(&id) else {
            return;
        };
        if captured.loaded {
            return;
        }
        captured.decrypted = true;
        let freed: usize = captured
            .chunks
            .drain(..)
            .map(|chunk| chunk.data.len() + CHUNK_OVERHEAD)
            .sum();
        captured.kept = [0, 0];
        captured.memory = captured.memory.saturating_sub(freed);
        inner.used = inner.used.saturating_sub(freed);
    }

    /// Adds one decrypted HTTP exchange to connection `id`, ended.
    #[cfg_attr(not(feature = "mitm"), allow(dead_code))]
    pub(crate) fn add_exchange(&self, id: u64, exchange: HttpExchange) {
        if let Some(index) = self.open_exchange(id, exchange) {
            self.finish_exchange(id, index, None);
        }
    }

    /// Files an exchange of connection `id` that is still in progress (its
    /// `ended_at_ms` is left as given). Its `seq` comes when it is finished,
    /// so `capture_requests` by `since_seq` lists it once, done; by
    /// `since_rev` it is listed now and again after each change. Returns
    /// its index (stable for the life of the connection, never given
    /// twice), or `None` when capture is off, the connection is not kept,
    /// or it holds [`MAX_HTTP_EXCHANGES`] already and the oldest of them
    /// is still in progress. Otherwise past that limit the oldest
    /// finished exchange is let go of.
    #[cfg_attr(not(feature = "mitm"), allow(dead_code))]
    pub(crate) fn open_exchange(&self, id: u64, mut exchange: HttpExchange) -> Option<usize> {
        if !self.enabled() {
            return None;
        }
        exchange.seq = 0;
        let budget = self.max_total_bytes.load(Ordering::Relaxed);
        let memory = exchange.memory();
        let mut inner = lock(&self.inner);
        exchange.rev = inner.next_rev();
        inner.revive(id);
        let captured = inner.connections.get_mut(&id)?;
        if captured.loaded {
            return None;
        }
        let mut rolled = None;
        if captured.http.len() >= MAX_HTTP_EXCHANGES {
            match captured.take_oldest_exchange() {
                Some(oldest) => rolled = Some((oldest.memory(), oldest.seq)),
                None => {
                    inner.dropped_exchanges += 1;
                    return None;
                }
            }
        }
        let index = captured.http_base + captured.http.len();
        captured.http.push(exchange);
        captured.memory += memory;
        if let Some((freed, seq)) = rolled {
            inner.used = inner.used.saturating_sub(freed);
            inner.dropped_exchanges += 1;
            inner.dropped_seq = inner.dropped_seq.max(seq);
        }
        inner.used += memory;
        inner.make_room(id, budget);
        Some(index)
    }

    /// Replaces what exchange `index` of connection `id` holds with
    /// `exchange`, keeping its `seq` and messages.
    #[cfg_attr(not(feature = "mitm"), allow(dead_code))]
    pub(crate) fn update_exchange(&self, id: u64, index: usize, exchange: &HttpExchange) {
        self.change(id, index, |kept| {
            let seq = kept.seq;
            let messages = std::mem::take(&mut kept.messages);
            *kept = HttpExchange {
                seq,
                messages,
                ..exchange.clone()
            };
        });
    }

    /// Ends exchange `index` of connection `id`, first replacing what it
    /// holds with `exchange` when given (see [`CaptureStore::update_exchange`]).
    #[cfg_attr(not(feature = "mitm"), allow(dead_code))]
    pub(crate) fn finish_exchange(&self, id: u64, index: usize, exchange: Option<HttpExchange>) {
        let seq = &self.next_seq;
        self.change(id, index, |kept| {
            if let Some(exchange) = exchange {
                let messages = std::mem::take(&mut kept.messages);
                *kept = HttpExchange {
                    messages,
                    ..exchange
                };
            }
            if kept.ended_at_ms.is_none() {
                kept.ended_at_ms = Some(unix_millis());
            }
            if kept.seq == 0 {
                kept.seq = seq.fetch_add(1, Ordering::Relaxed);
            }
        });
    }

    /// Adds one message of the stream inside exchange `index` of
    /// connection `id`, dropping its oldest past the limits of
    /// [`stream`].
    #[cfg_attr(not(feature = "mitm"), allow(dead_code))]
    pub(crate) fn push_message(&self, id: u64, index: usize, message: stream::StreamMessage) {
        if !self.enabled() {
            return;
        }
        self.change(id, index, |kept| {
            kept.messages.push(message);
        });
    }

    /// Applies `edit` to exchange `index` of connection `id`, giving it a
    /// new `rev` and accounting the change in memory against the budget.
    #[cfg_attr(not(feature = "mitm"), allow(dead_code))]
    fn change(&self, id: u64, index: usize, edit: impl FnOnce(&mut HttpExchange)) {
        let budget = self.max_total_bytes.load(Ordering::Relaxed);
        let mut inner = lock(&self.inner);
        let rev = inner.next_rev();
        let Some(captured) = inner.connections.get_mut(&id) else {
            return;
        };
        if captured.loaded {
            return;
        }
        let Some(kept) = captured.exchange_mut(index) else {
            return;
        };
        let before = kept.memory();
        edit(kept);
        kept.rev = rev;
        let after = kept.memory();
        captured.memory = (captured.memory + after).saturating_sub(before);
        inner.used = (inner.used + after).saturating_sub(before);
        if after > before {
            inner.make_room(id, budget);
        }
    }

    /// Adds HTTP/2 frames seen on decrypted connection `id`.
    #[cfg_attr(not(feature = "mitm"), allow(dead_code))]
    pub(crate) fn push_h2_frames(&self, id: u64, frames: Vec<h2frames::H2Frame>) {
        if frames.is_empty() || !self.enabled() {
            return;
        }
        let budget = self.max_total_bytes.load(Ordering::Relaxed);
        let mut inner = lock(&self.inner);
        inner.revive(id);
        let Some(captured) = inner.connections.get_mut(&id) else {
            return;
        };
        if captured.loaded {
            return;
        }
        let delta = captured.h2.push(frames);
        captured.memory = captured.memory.saturating_add_signed(delta);
        inner.used = inner.used.saturating_add_signed(delta);
        if delta > 0 {
            inner.make_room(id, budget);
        }
    }

    /// The `capture_h2_frames` answer: the kept HTTP/2 frames of connection
    /// `id` from index `since` on; `null` when the connection is not kept.
    pub fn h2_frames_json(&self, id: u64, since: u64) -> Value {
        let inner = lock(&self.inner);
        let Some(captured) = inner.connections.get(&id) else {
            return Value::Null;
        };
        json!({
            "seen": captured.h2.seen,
            "dropped": captured.h2.dropped,
            "frames": captured.h2.json_since(since),
        })
    }

    /// Notes that connection `id` closed.
    pub(crate) fn end(&self, id: u64, ended_at_ms: u64) {
        let mut inner = lock(&self.inner);
        inner.dormant.remove(&id);
        if let Some(captured) = inner.connections.get_mut(&id) {
            if !captured.loaded {
                captured.ended_at_ms = Some(ended_at_ms);
            }
        }
    }

    /// What was kept of connection `id`, as the `capture_connection` answer
    /// shows it; `None` when nothing was (capture was off, or the
    /// connection was dropped for newer ones).
    pub fn connection_json(&self, id: u64) -> Option<Value> {
        lock(&self.inner)
            .connections
            .get(&id)
            .map(|captured| captured.json(id))
    }

    /// The captured connections (all, or only `id`) as a pcapng file,
    /// with credentials masked when `redact`.
    pub fn export_pcapng(&self, id: Option<u64>, redact: bool) -> Vec<u8> {
        let inner = lock(&self.inner);
        let mut file = pcapng::File::new();
        let mut names = Vec::new();
        for (&connection, captured) in selected(&inner, id) {
            let flow = pcapng::Flow::new(connection, captured);
            if let Some(host) = &captured.host {
                if host.parse::<IpAddr>().is_err() {
                    names.push((flow.server.ip(), host.clone()));
                }
            }
            flow.write(&mut file, captured, redact);
        }
        file.finish(&names)
    }

    /// The decrypted HTTP messages (all, or only connection `id`'s) as HAR
    /// 1.2 JSON, with credentials masked when `redact`.
    pub fn export_har(&self, id: Option<u64>, redact: bool) -> Vec<u8> {
        let inner = lock(&self.inner);
        let mut entries = Vec::new();
        for (&connection, captured) in selected(&inner, id) {
            for exchange in &captured.http {
                let exchange = redacted(exchange, redact);
                entries.push(har::entry(connection, captured, &exchange));
            }
        }
        let har = json!({
            "log": {
                "version": "1.2",
                "creator": { "name": "AnixOps Net", "version": env!("CARGO_PKG_VERSION") },
                "entries": entries,
            }
        });
        serde_json::to_vec_pretty(&har).unwrap_or_default()
    }

    /// Sets where sessions are saved and the key that seals them, and
    /// deletes sessions past the retention:
    /// `{"retention_days", "purged"}`.
    pub fn set_storage(
        &self,
        dir: &str,
        key: &[u8],
        retention_days: Option<u32>,
    ) -> Result<Value, storage::StorageError> {
        let storage = storage::Storage::new(dir, key, retention_days)?;
        let purged = storage.purge(unix_millis());
        let answer = json!({
            "retention_days": storage.retention_days(),
            "purged": purged,
        });
        *lock(&self.storage) = Some(storage);
        Ok(answer)
    }

    /// Seals what the store holds into a new session: `{"session": {...}}`.
    pub fn save_session(&self, name: Option<&str>) -> Result<Value, storage::StorageError> {
        let storage = lock(&self.storage);
        let storage = storage
            .as_ref()
            .ok_or(storage::StorageError::NotConfigured)?;
        let now = unix_millis();
        storage.purge(now);
        let inner = lock(&self.inner);
        let session = storage.save(&inner, name, now)?;
        Ok(json!({ "session": session }))
    }

    /// The saved sessions, newest first: `{"sessions": [...]}`.
    pub fn sessions(&self) -> Result<Value, storage::StorageError> {
        let storage = lock(&self.storage);
        let storage = storage
            .as_ref()
            .ok_or(storage::StorageError::NotConfigured)?;
        Ok(json!({ "sessions": storage.list(unix_millis()) }))
    }

    /// Replaces what the store holds with session `id` and turns live
    /// capture off. Its exchanges get new `seq`s after every earlier one,
    /// and `dropped_before_seq` covers all earlier rows. Its connections
    /// get new ids from [`LOADED_ID_BASE`] up, in their saved order, so no
    /// live connection (whose ids count from 1 again in every tunnel run)
    /// shares one and writes into them.
    pub fn load_session(&self, id: &str) -> Result<CaptureStatus, storage::StorageError> {
        let loaded = {
            let storage = lock(&self.storage);
            storage
                .as_ref()
                .ok_or(storage::StorageError::NotConfigured)?
                .load(id)?
        };
        self.enabled.store(false, Ordering::Relaxed);
        {
            let mut inner = lock(&self.inner);
            inner.forget_all(self.next_seq.load(Ordering::Relaxed).saturating_sub(1));
            let mut connections = loaded
                .into_iter()
                .enumerate()
                .map(|(rank, (_, mut captured))| {
                    captured.loaded = true;
                    captured.http_base = 0;
                    inner.used += captured.memory;
                    (LOADED_ID_BASE + rank as u64, captured)
                })
                .collect::<Vec<_>>();
            let mut order = connections
                .iter_mut()
                .flat_map(|(_, captured)| captured.http.iter_mut())
                .collect::<Vec<_>>();
            order.sort_by_key(|exchange| exchange.seq);
            for exchange in order {
                exchange.seq = self.next_seq.fetch_add(1, Ordering::Relaxed);
                exchange.rev = inner.next_rev();
            }
            inner.connections.extend(connections);
            let budget = self.max_total_bytes.load(Ordering::Relaxed);
            if inner.used > budget {
                self.max_total_bytes
                    .store(inner.used.min(MAX_TOTAL_BYTES_LIMIT), Ordering::Relaxed);
            }
        }
        Ok(self.status())
    }

    /// Deletes session `id`: `{"deleted": bool}`.
    pub fn delete_session(&self, id: &str) -> Result<Value, storage::StorageError> {
        let storage = lock(&self.storage);
        let storage = storage
            .as_ref()
            .ok_or(storage::StorageError::NotConfigured)?;
        Ok(json!({ "deleted": storage.delete(id)? }))
    }

    /// Copies of the selected decrypted exchanges, redacted when asked.
    fn exchanges(&self, selection: Selection, redact: bool) -> Vec<HttpExchange> {
        let inner = lock(&self.inner);
        selected(&inner, selection.id)
            .into_iter()
            .flat_map(|(_, captured)| match selection.exchange {
                Some(index) => captured
                    .exchange(index)
                    .map_or(&[][..], std::slice::from_ref),
                None => captured.http.as_slice(),
            })
            .map(|exchange| redacted(exchange, redact).into_owned())
            .collect()
    }

    /// The `capture_requests` answer: one row per decrypted exchange
    /// finished after `since_seq`, oldest first, at most `limit`
    /// (default [`DEFAULT_REQUEST_ROWS`], at most [`MAX_REQUEST_ROWS`]).
    /// With `since_rev`, instead one row per exchange that changed after
    /// that `rev`, in the order of their last change, those still in
    /// progress included; a client that keeps the `last_rev` it was given
    /// sees each exchange open, change and end.
    pub fn requests_json(
        &self,
        since_seq: u64,
        since_rev: Option<u64>,
        limit: Option<usize>,
        filter: &Filter,
    ) -> Value {
        let limit = limit
            .unwrap_or(DEFAULT_REQUEST_ROWS)
            .clamp(1, MAX_REQUEST_ROWS);
        let inner = lock(&self.inner);
        let mut rows = inner
            .connections
            .iter()
            .flat_map(|(&id, captured)| {
                captured
                    .http
                    .iter()
                    .enumerate()
                    .filter(|(_, exchange)| match since_rev {
                        Some(since_rev) => exchange.rev > since_rev,
                        None => exchange.seq > since_seq,
                    })
                    .map(move |(position, exchange)| (id, captured.http_base + position, exchange))
            })
            .collect::<Vec<_>>();
        if since_rev.is_some() {
            rows.sort_unstable_by_key(|(_, _, exchange)| exchange.rev);
        } else {
            rows.sort_unstable_by_key(|(_, _, exchange)| exchange.seq);
        }
        let last_seq = self.next_seq.load(Ordering::Relaxed).saturating_sub(1);
        let requests = rows
            .into_iter()
            .filter(|(_, _, exchange)| filter.matches(exchange))
            .take(limit)
            .map(|(id, index, exchange)| request_row(id, index, exchange))
            .collect::<Vec<_>>();
        json!({
            "requests": requests,
            "last_seq": last_seq,
            "last_rev": inner.rev,
            "dropped_before_seq": inner.dropped_before_seq(),
        })
    }

    /// The `capture_exchange` answer: exchange `index` of connection `id`
    /// with its stream messages from index `since_message` on; `null` when
    /// it is not kept.
    pub fn exchange_json(&self, id: u64, index: usize, since_message: u64) -> Value {
        let inner = lock(&self.inner);
        let Some(exchange) = inner
            .connections
            .get(&id)
            .and_then(|captured| captured.exchange(index))
        else {
            return Value::Null;
        };
        let mut value = exchange.json();
        value["connection_id"] = json!(id);
        value["index"] = json!(index);
        value["messages"] = exchange.messages_json(since_message);
        value
    }
}

/// One `capture_requests` row.
fn request_row(id: u64, index: usize, exchange: &HttpExchange) -> Value {
    let content_type = exchange
        .response_headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("content-type"))
        .map(|(_, value)| value.as_str());
    let host = exchange
        .url
        .split_once("://")
        .map_or(exchange.url.as_str(), |(_, rest)| rest)
        .split(['/', '?', '#'])
        .next()
        .unwrap_or("");
    json!({
        "seq": exchange.seq,
        "connection_id": id,
        "index": index,
        "method": exchange.method,
        "url": exchange.url,
        "host": host,
        "status": exchange.status,
        "note": exchange.note,
        "http_version": exchange.http_version,
        "started_at_ms": exchange.started_at_ms,
        "ended_at_ms": exchange.ended_at_ms,
        "request_size": exchange.request_body.size,
        "response_size": exchange.response_body.size,
        "response_content_type": content_type,
        "state": exchange.state(),
        "rev": exchange.rev,
        "rules_skipped": exchange.rules_skipped,
        "message_count": exchange.messages.seen,
    })
}

fn redacted(exchange: &HttpExchange, redact: bool) -> Cow<'_, HttpExchange> {
    if redact {
        Cow::Owned(redact::exchange(exchange))
    } else {
        Cow::Borrowed(exchange)
    }
}

fn selected(inner: &Inner, id: Option<u64>) -> Vec<(&u64, &Captured)> {
    match id {
        Some(id) => inner.connections.get_key_value(&id).into_iter().collect(),
        None => inner.connections.iter().collect(),
    }
}

/// The export formats of `export_capture`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExportFormat {
    Pcapng,
    Har,
    Curl,
    Code,
    Postman,
    Insomnia,
}

impl ExportFormat {
    pub fn content_type(self) -> &'static str {
        match self {
            Self::Pcapng => "application/vnd.tcpdump.pcap",
            Self::Har | Self::Postman | Self::Insomnia => "application/json",
            Self::Curl => "application/x-sh",
            Self::Code => "text/plain; charset=utf-8",
        }
    }

    /// The file name suffix, for `code` in `language`.
    pub fn extension(self, language: Language) -> &'static str {
        match self {
            Self::Pcapng => "pcapng",
            Self::Har => "har",
            Self::Curl => "sh",
            Self::Code => language.extension(),
            Self::Postman => "postman_collection.json",
            Self::Insomnia => "insomnia.json",
        }
    }
}

/// Which connection and exchange an export covers.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Selection {
    /// One connection, or all.
    pub id: Option<u64>,
    /// One exchange of that connection (an index of its `http` list), or all.
    pub exchange: Option<usize>,
}

/// What `export_capture` asks for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExportRequest {
    pub format: ExportFormat,
    pub selection: Selection,
    /// The language of a `code` export.
    pub language: Language,
    /// Mask credentials (the default).
    pub redact: bool,
}

impl ExportRequest {
    pub fn new(format: ExportFormat) -> Self {
        Self {
            format,
            selection: Selection::default(),
            language: Language::default(),
            redact: true,
        }
    }
}

/// The exported file.
pub fn export_file(store: &CaptureStore, request: &ExportRequest) -> Vec<u8> {
    let redact = request.redact;
    let id = request.selection.id;
    let name = match id {
        Some(id) => format!("AnixOps capture {id}"),
        None => "AnixOps capture".to_string(),
    };
    match request.format {
        ExportFormat::Pcapng => store.export_pcapng(id, redact),
        ExportFormat::Har => store.export_har(id, redact),
        format => {
            let exchanges = store.exchanges(request.selection, redact);
            let exchanges = exchanges.iter().collect::<Vec<_>>();
            match format {
                ExportFormat::Curl => export::curl(&exchanges).into_bytes(),
                ExportFormat::Code => export::code(&exchanges, request.language).into_bytes(),
                ExportFormat::Postman => {
                    serde_json::to_vec_pretty(&export::postman(&exchanges, &name))
                        .unwrap_or_default()
                }
                _ => serde_json::to_vec_pretty(&export::insomnia(&exchanges, &name, unix_millis()))
                    .unwrap_or_default(),
            }
        }
    }
}

/// The `export_capture` answer, written straight into one buffer so the
/// file is not copied again on its way out:
/// `{"format", "file_name", "content_type", "size", "redacted", "data_base64"}`.
pub fn export_answer(store: &CaptureStore, request: &ExportRequest) -> Vec<u8> {
    let file = export_file(store, request);
    let stem = match (request.selection.id, request.selection.exchange) {
        (Some(id), Some(exchange)) => format!("anixops-capture-{id}-{exchange}"),
        (Some(id), None) => format!("anixops-capture-{id}"),
        _ => format!("anixops-capture-{}", unix_millis() / 1000),
    };
    let head = json!({
        "format": request.format,
        "file_name": format!("{stem}.{}", request.format.extension(request.language)),
        "content_type": request.format.content_type(),
        "size": file.len(),
        "redacted": request.redact,
    })
    .to_string();
    // `head` is a JSON object: reopen it to append the data field.
    let mut answer = String::with_capacity(head.len() + file.len() * 4 / 3 + 32);
    answer.push_str(&head[..head.len() - 1]);
    answer.push_str(",\"data_base64\":\"");
    base64::engine::general_purpose::STANDARD.encode_string(&file, &mut answer);
    drop(file);
    answer.push_str("\"}");
    answer.into_bytes()
}

tokio::task_local! {
    /// The connection a decrypted flow opened to the origin, so the HTTPS
    /// decryption running in the same task can file its HTTP messages
    /// under it.
    static FLOW: RefCell<Option<(Arc<CaptureStore>, u64)>>;
}

/// Runs `future` (one decrypted flow) with a slot for the connection it
/// opens; see [`current_flow`].
#[cfg_attr(not(feature = "mitm"), allow(dead_code))]
pub(crate) async fn scope<F: Future>(future: F) -> F::Output {
    FLOW.scope(RefCell::new(None), future).await
}

/// Called by the dispatcher for each connection it opens with capture on:
/// the first one inside a [`scope`] is the flow's.
pub(crate) fn note_flow(store: &Arc<CaptureStore>, id: u64) {
    let _ = FLOW.try_with(|slot| {
        let mut slot = slot.borrow_mut();
        if slot.is_none() {
            *slot = Some((store.clone(), id));
        }
    });
}

/// The capture store and connection of the current decrypted flow, when
/// capture was on as it opened. Its raw bytes stop being kept.
#[cfg_attr(not(feature = "mitm"), allow(dead_code))]
pub(crate) fn current_flow() -> Option<(Arc<CaptureStore>, u64)> {
    let flow = FLOW.try_with(|slot| slot.borrow().clone()).ok().flatten()?;
    flow.0.mark_decrypted(flow.1);
    Some(flow)
}

fn base64_encode(data: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(data)
}

pub(crate) fn unix_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// The port of `destination` (`host:port`, `[v6]:port`), or 0.
fn destination_port(destination: &str) -> u16 {
    destination
        .rsplit_once(':')
        .and_then(|(_, port)| port.parse().ok())
        .unwrap_or(0)
}

/// The header that carries an original `Content-Length` or
/// `Transfer-Encoding` in the pcapng text, prefixed to the original name.
const ORIGINAL_HEADER_PREFIX: &str = "X-AnixOps-Original-";
/// Added to a message in the pcapng text whose body capture kept only in
/// part: `<bytes written>/<bytes the body had>`.
pub const TRUNCATED_HEADER: &str = "X-AnixOps-Truncated";

/// The HTTP/1.1 text of decrypted exchanges, as the pcapng export carries
/// a decrypted connection: requests up, responses down.
///
/// The headers are the ones recorded, but the body written is what was
/// kept of it: the decoded chunks of a chunked body, at most
/// [`MAX_HTTP_BODY_BYTES`], masked when redacted, and an HTTP/2 response
/// names no length at all. So the framing is rewritten to match what is
/// written, or a packet analyser would run one message into the next:
/// `Transfer-Encoding` and `Content-Length` become
/// `X-AnixOps-Original-...` and a `Content-Length` of the written bytes
/// follows; a body kept only in part also gets [`TRUNCATED_HEADER`] and
/// loses its `Content-Encoding` the same way, since its compressed start
/// alone does not decode. A message that has no body by its status or
/// method (1xx, 204, 304, a response to `HEAD`) keeps its headers as they
/// were.
fn http_text(exchange: &HttpExchange) -> (Vec<u8>, Vec<u8>) {
    let path = exchange
        .url
        .find("://")
        .and_then(|scheme| {
            let rest = &exchange.url[scheme + 3..];
            rest.find('/').map(|slash| &rest[slash..])
        })
        .unwrap_or("/");
    let mut up = format!("{} {} HTTP/1.1\r\n", exchange.method, path).into_bytes();
    let framed = exchange.request_body.size > 0
        || !exchange.request_body.data.is_empty()
        || framing_header(&exchange.request_headers);
    framed_message(
        &mut up,
        &exchange.request_headers,
        &exchange.request_body,
        framed,
    );
    let mut down = Vec::new();
    if let Some(status) = exchange.status {
        down.extend_from_slice(
            format!("HTTP/1.1 {status} {}\r\n", har::status_text(status)).as_bytes(),
        );
        let bodyless = (100..200).contains(&status)
            || status == 204
            || status == 304
            || exchange.method.eq_ignore_ascii_case("HEAD");
        framed_message(
            &mut down,
            &exchange.response_headers,
            &exchange.response_body,
            !bodyless,
        );
    }
    (up, down)
}

fn framing_header(headers: &[(String, String)]) -> bool {
    headers.iter().any(|(name, _)| {
        name.eq_ignore_ascii_case("content-length")
            || name.eq_ignore_ascii_case("transfer-encoding")
    })
}

/// Writes `headers` and `body` into `out`; with `framed`, the framing
/// headers rewritten for the bytes written (see [`http_text`]).
fn framed_message(
    out: &mut Vec<u8>,
    headers: &[(String, String)],
    body: &CapturedBody,
    framed: bool,
) {
    let truncated = body.truncated();
    for (name, value) in headers {
        let renamed = framed
            && (name.eq_ignore_ascii_case("content-length")
                || name.eq_ignore_ascii_case("transfer-encoding")
                || (truncated && name.eq_ignore_ascii_case("content-encoding")));
        if renamed {
            out.extend_from_slice(
                format!("{ORIGINAL_HEADER_PREFIX}{name}: {value}\r\n").as_bytes(),
            );
        } else {
            out.extend_from_slice(format!("{name}: {value}\r\n").as_bytes());
        }
    }
    if framed {
        if truncated {
            out.extend_from_slice(
                format!("{TRUNCATED_HEADER}: {}/{}\r\n", body.data.len(), body.size).as_bytes(),
            );
        }
        out.extend_from_slice(format!("Content-Length: {}\r\n", body.data.len()).as_bytes());
    }
    out.extend_from_slice(b"\r\n");
    if framed {
        out.extend_from_slice(&body.data);
    }
}

mod pcapng {
    //! A minimal pcapng writer: one raw-IP interface, synthetic IPv4/IPv6
    //! TCP and UDP packets, and a name resolution block.

    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

    use super::{destination_port, http_text, Captured, Direction, Network};

    /// `LINKTYPE_RAW`: packets start with the IP header.
    const LINKTYPE_RAW: u16 = 101;
    /// Largest TCP or UDP payload per synthetic packet.
    const SEGMENT: usize = 16 * 1024;
    const CLIENT_V4: Ipv4Addr = Ipv4Addr::new(10, 7, 0, 1);
    const CLIENT_V6: Ipv6Addr = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1);
    const TCP_FIN: u8 = 0x01;
    const TCP_SYN: u8 = 0x02;
    const TCP_PSH: u8 = 0x08;
    const TCP_ACK: u8 = 0x10;

    pub(super) struct File {
        packets: Vec<u8>,
    }

    impl File {
        pub(super) fn new() -> Self {
            Self {
                packets: Vec::new(),
            }
        }

        /// One enhanced packet block, with an optional comment.
        fn packet(&mut self, at_ms: u64, packet: &[u8], comment: Option<&str>) {
            let micros = at_ms.saturating_mul(1000);
            let mut options = Vec::new();
            if let Some(comment) = comment {
                option(&mut options, 1, comment.as_bytes());
                option(&mut options, 0, &[]);
            }
            let mut body = Vec::with_capacity(20 + packet.len() + 3 + options.len());
            body.extend_from_slice(&0u32.to_le_bytes());
            body.extend_from_slice(&((micros >> 32) as u32).to_le_bytes());
            body.extend_from_slice(&(micros as u32).to_le_bytes());
            body.extend_from_slice(&(packet.len() as u32).to_le_bytes());
            body.extend_from_slice(&(packet.len() as u32).to_le_bytes());
            body.extend_from_slice(packet);
            pad(&mut body);
            body.extend_from_slice(&options);
            block(&mut self.packets, 6, &body);
        }

        /// The whole file: section header, interface, names, packets.
        pub(super) fn finish(self, names: &[(IpAddr, String)]) -> Vec<u8> {
            let mut out = Vec::with_capacity(self.packets.len() + 256);
            let mut section = Vec::new();
            section.extend_from_slice(&0x1A2B_3C4Du32.to_le_bytes());
            section.extend_from_slice(&1u16.to_le_bytes());
            section.extend_from_slice(&0u16.to_le_bytes());
            section.extend_from_slice(&(-1i64).to_le_bytes());
            let mut options = Vec::new();
            option(&mut options, 4, b"AnixOps Net");
            option(&mut options, 0, &[]);
            section.extend_from_slice(&options);
            block(&mut out, 0x0A0D_0D0A, &section);

            let mut interface = Vec::new();
            interface.extend_from_slice(&LINKTYPE_RAW.to_le_bytes());
            interface.extend_from_slice(&0u16.to_le_bytes());
            interface.extend_from_slice(&0u32.to_le_bytes());
            let mut options = Vec::new();
            option(&mut options, 2, b"anixops-tunnel");
            option(&mut options, 0, &[]);
            interface.extend_from_slice(&options);
            block(&mut out, 1, &interface);

            if !names.is_empty() {
                let mut records = Vec::new();
                for (address, name) in names {
                    let mut value = match address {
                        IpAddr::V4(v4) => v4.octets().to_vec(),
                        IpAddr::V6(v6) => v6.octets().to_vec(),
                    };
                    value.extend_from_slice(name.as_bytes());
                    value.push(0);
                    let kind = if address.is_ipv4() { 1 } else { 2 };
                    option(&mut records, kind, &value);
                }
                option(&mut records, 0, &[]);
                block(&mut out, 4, &records);
            }
            out.extend_from_slice(&self.packets);
            out
        }
    }

    /// A block: type, total length, body, total length.
    fn block(out: &mut Vec<u8>, kind: u32, body: &[u8]) {
        let total = (12 + body.len()) as u32;
        out.extend_from_slice(&kind.to_le_bytes());
        out.extend_from_slice(&total.to_le_bytes());
        out.extend_from_slice(body);
        out.extend_from_slice(&total.to_le_bytes());
    }

    /// An option (or name record): code, length, value padded to 32 bits.
    fn option(out: &mut Vec<u8>, code: u16, value: &[u8]) {
        out.extend_from_slice(&code.to_le_bytes());
        out.extend_from_slice(&(value.len() as u16).to_le_bytes());
        out.extend_from_slice(value);
        pad(out);
    }

    fn pad(out: &mut Vec<u8>) {
        while !out.len().is_multiple_of(4) {
            out.push(0);
        }
    }

    /// One connection as a synthetic flow between a fixed client address
    /// and its server.
    pub(super) struct Flow {
        id: u64,
        network: Network,
        client: SocketAddr,
        pub(super) server: SocketAddr,
        client_seq: u32,
        server_seq: u32,
    }

    impl Flow {
        pub(super) fn new(id: u64, captured: &Captured) -> Self {
            let port = destination_port(&captured.destination);
            let server = captured
                .destination
                .parse::<SocketAddr>()
                .unwrap_or_else(|_| {
                    // 198.18.0.0/15, one address per connection.
                    let low = (id & 0x1_ffff) as u32;
                    let address = Ipv4Addr::from(0xC612_0000 | low);
                    SocketAddr::new(IpAddr::V4(address), port)
                });
            let client_ip = if server.is_ipv4() {
                IpAddr::V4(CLIENT_V4)
            } else {
                IpAddr::V6(CLIENT_V6)
            };
            let client_port = 10_000 + (id % 50_000) as u16;
            Self {
                id,
                network: captured.network,
                client: SocketAddr::new(client_ip, client_port),
                server,
                client_seq: 1_000,
                server_seq: 50_000,
            }
        }

        pub(super) fn write(mut self, file: &mut File, captured: &Captured, redact: bool) {
            let comment = format!(
                "anixops connection {}: {}{}",
                self.id,
                captured
                    .host
                    .as_deref()
                    .map(|host| format!("{host} "))
                    .unwrap_or_default(),
                captured.destination,
            );
            let pieces: Vec<(Direction, u64, Vec<u8>)> = if captured.decrypted {
                // Exchanges with no response yet go last, so each response
                // pairs with its own request when the stream is read in
                // order.
                let (answered, unanswered): (Vec<_>, Vec<_>) = captured
                    .http
                    .iter()
                    .partition(|exchange| exchange.status.is_some());
                answered
                    .into_iter()
                    .chain(unanswered)
                    .flat_map(|exchange| {
                        let exchange = super::redacted(exchange, redact);
                        let (up, down) = http_text(&exchange);
                        let ended = exchange.ended_at_ms.unwrap_or(exchange.started_at_ms);
                        [
                            (Direction::Up, exchange.started_at_ms, up),
                            (Direction::Down, ended, down),
                        ]
                    })
                    .filter(|(_, _, data)| !data.is_empty())
                    .collect()
            } else {
                // Joined so that masking sees each TCP run whole, not the
                // pieces it is kept in.
                captured
                    .joined_chunks()
                    .into_iter()
                    .map(|(direction, at_ms, data)| {
                        let data = if redact {
                            super::redact::http1_text(&data).into_owned()
                        } else {
                            data
                        };
                        (direction, at_ms, data)
                    })
                    .collect()
            };
            match self.network {
                Network::Tcp => {
                    let start = captured.started_at_ms;
                    self.tcp(file, start, TCP_SYN, Direction::Up, &[], Some(&comment));
                    self.tcp(file, start, TCP_SYN | TCP_ACK, Direction::Down, &[], None);
                    self.tcp(file, start, TCP_ACK, Direction::Up, &[], None);
                    for (direction, at_ms, data) in pieces {
                        for segment in data.chunks(SEGMENT) {
                            self.tcp(file, at_ms, TCP_PSH | TCP_ACK, direction, segment, None);
                        }
                    }
                    if let Some(end) = captured.ended_at_ms {
                        self.tcp(file, end, TCP_FIN | TCP_ACK, Direction::Up, &[], None);
                        self.tcp(file, end, TCP_FIN | TCP_ACK, Direction::Down, &[], None);
                        self.tcp(file, end, TCP_ACK, Direction::Up, &[], None);
                    }
                }
                Network::Udp => {
                    let mut first = Some(comment.as_str());
                    for (direction, at_ms, data) in pieces {
                        for datagram in data.chunks(SEGMENT) {
                            let packet =
                                self.ip(direction, 17, &udp(self.ends(direction), datagram));
                            file.packet(at_ms, &packet, first.take());
                        }
                    }
                }
            }
        }

        fn ends(&self, direction: Direction) -> (SocketAddr, SocketAddr) {
            match direction {
                Direction::Up => (self.client, self.server),
                Direction::Down => (self.server, self.client),
            }
        }

        fn tcp(
            &mut self,
            file: &mut File,
            at_ms: u64,
            flags: u8,
            direction: Direction,
            payload: &[u8],
            comment: Option<&str>,
        ) {
            let (seq, ack) = match direction {
                Direction::Up => (self.client_seq, self.server_seq),
                Direction::Down => (self.server_seq, self.client_seq),
            };
            let ack = if flags & TCP_ACK != 0 { ack } else { 0 };
            let (source, destination) = self.ends(direction);
            let mut segment = Vec::with_capacity(20 + payload.len());
            segment.extend_from_slice(&source.port().to_be_bytes());
            segment.extend_from_slice(&destination.port().to_be_bytes());
            segment.extend_from_slice(&seq.to_be_bytes());
            segment.extend_from_slice(&ack.to_be_bytes());
            segment.push(5 << 4);
            segment.push(flags);
            segment.extend_from_slice(&65_535u16.to_be_bytes());
            segment.extend_from_slice(&[0, 0, 0, 0]);
            segment.extend_from_slice(payload);
            let checksum = transport_checksum(source.ip(), destination.ip(), 6, &segment);
            segment[16..18].copy_from_slice(&checksum.to_be_bytes());
            let advance = payload.len() as u32 + u32::from(flags & (TCP_SYN | TCP_FIN) != 0);
            match direction {
                Direction::Up => self.client_seq = self.client_seq.wrapping_add(advance),
                Direction::Down => self.server_seq = self.server_seq.wrapping_add(advance),
            }
            let packet = self.ip(direction, 6, &segment);
            file.packet(at_ms, &packet, comment);
        }

        fn ip(&self, direction: Direction, protocol: u8, payload: &[u8]) -> Vec<u8> {
            let (source, destination) = self.ends(direction);
            match (source.ip(), destination.ip()) {
                (IpAddr::V4(source), IpAddr::V4(destination)) => {
                    let total = (20 + payload.len()) as u16;
                    let mut header = Vec::with_capacity(20 + payload.len());
                    header.extend_from_slice(&[0x45, 0]);
                    header.extend_from_slice(&total.to_be_bytes());
                    header.extend_from_slice(&[0, 0, 0x40, 0, 64, protocol, 0, 0]);
                    header.extend_from_slice(&source.octets());
                    header.extend_from_slice(&destination.octets());
                    let checksum = fold(sum(&header, 0));
                    header[10..12].copy_from_slice(&checksum.to_be_bytes());
                    header.extend_from_slice(payload);
                    header
                }
                (source, destination) => {
                    let mut header = Vec::with_capacity(40 + payload.len());
                    header.extend_from_slice(&[0x60, 0, 0, 0]);
                    header.extend_from_slice(&(payload.len() as u16).to_be_bytes());
                    header.push(protocol);
                    header.push(64);
                    header.extend_from_slice(&v6(source).octets());
                    header.extend_from_slice(&v6(destination).octets());
                    header.extend_from_slice(payload);
                    header
                }
            }
        }
    }

    fn v6(address: IpAddr) -> Ipv6Addr {
        match address {
            IpAddr::V4(v4) => v4.to_ipv6_mapped(),
            IpAddr::V6(v6) => v6,
        }
    }

    fn udp((source, destination): (SocketAddr, SocketAddr), payload: &[u8]) -> Vec<u8> {
        let length = (8 + payload.len()) as u16;
        let mut datagram = Vec::with_capacity(8 + payload.len());
        datagram.extend_from_slice(&source.port().to_be_bytes());
        datagram.extend_from_slice(&destination.port().to_be_bytes());
        datagram.extend_from_slice(&length.to_be_bytes());
        datagram.extend_from_slice(&[0, 0]);
        datagram.extend_from_slice(payload);
        let checksum = match transport_checksum(source.ip(), destination.ip(), 17, &datagram) {
            0 => 0xffff,
            value => value,
        };
        datagram[6..8].copy_from_slice(&checksum.to_be_bytes());
        datagram
    }

    /// The TCP/UDP checksum over the pseudo header and `segment`.
    fn transport_checksum(
        source: IpAddr,
        destination: IpAddr,
        protocol: u8,
        segment: &[u8],
    ) -> u16 {
        let mut pseudo = Vec::with_capacity(40);
        match (source, destination) {
            (IpAddr::V4(source), IpAddr::V4(destination)) => {
                pseudo.extend_from_slice(&source.octets());
                pseudo.extend_from_slice(&destination.octets());
                pseudo.extend_from_slice(&[0, protocol]);
                pseudo.extend_from_slice(&(segment.len() as u16).to_be_bytes());
            }
            (source, destination) => {
                pseudo.extend_from_slice(&v6(source).octets());
                pseudo.extend_from_slice(&v6(destination).octets());
                pseudo.extend_from_slice(&(segment.len() as u32).to_be_bytes());
                pseudo.extend_from_slice(&[0, 0, 0, protocol]);
            }
        }
        fold(sum(segment, sum(&pseudo, 0)))
    }

    fn sum(bytes: &[u8], mut acc: u32) -> u32 {
        let (pairs, rest) = bytes.as_chunks::<2>();
        for pair in pairs {
            acc = acc.wrapping_add(u32::from(u16::from_be_bytes(*pair)));
        }
        if let [last] = rest {
            acc = acc.wrapping_add(u32::from(*last) << 8);
        }
        acc
    }

    fn fold(mut acc: u32) -> u16 {
        while acc >> 16 != 0 {
            acc = (acc & 0xffff) + (acc >> 16);
        }
        !(acc as u16)
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn checksums_verify_to_zero() {
            let header = [
                0x45u8, 0, 0, 0x1c, 0, 0, 0x40, 0, 64, 17, 0, 0, 10, 7, 0, 1, 192, 0, 2, 1,
            ];
            let checksum = fold(sum(&header, 0));
            let mut filled = header;
            filled[10..12].copy_from_slice(&checksum.to_be_bytes());
            assert_eq!(fold(sum(&filled, 0)), 0);
        }
    }
}

mod har {
    //! HAR 1.2 entries for decrypted HTTP exchanges.

    use std::net::SocketAddr;

    use serde_json::{json, Value};

    use super::{base64_encode, decode, Captured, CapturedBody, HttpExchange, MAX_HTTP_BODY_BYTES};

    pub(super) fn entry(id: u64, captured: &Captured, exchange: &HttpExchange) -> Value {
        let ended = exchange.ended_at_ms.unwrap_or(exchange.started_at_ms);
        let wait = ended.saturating_sub(exchange.started_at_ms);
        let header = |name: &str, headers: &[(String, String)]| {
            headers
                .iter()
                .find(|(key, _)| key.eq_ignore_ascii_case(name))
                .map(|(_, value)| value.clone())
        };
        let headers = |headers: &[(String, String)]| {
            headers
                .iter()
                .map(|(name, value)| json!({ "name": name, "value": value }))
                .collect::<Vec<_>>()
        };
        let mut request = json!({
            "method": exchange.method,
            "url": exchange.url,
            "httpVersion": exchange.http_version,
            "cookies": [],
            "headers": headers(&exchange.request_headers),
            "queryString": query(&exchange.url),
            "headersSize": -1,
            "bodySize": exchange.request_body.size,
        });
        let mut comment = Vec::new();
        if exchange.request_body.size > 0 {
            let mime = header("Content-Type", &exchange.request_headers).unwrap_or_default();
            let mut post = json!({ "mimeType": mime });
            let encoding = header("Content-Encoding", &exchange.request_headers);
            comment.extend(text(&mut post, &exchange.request_body, encoding.as_deref()));
            request["postData"] = post;
        }
        let status = exchange.status.unwrap_or(0);
        let mime = header("Content-Type", &exchange.response_headers).unwrap_or_default();
        let mut content = json!({ "size": exchange.response_body.size, "mimeType": mime });
        let encoding = header("Content-Encoding", &exchange.response_headers);
        comment.extend(text(
            &mut content,
            &exchange.response_body,
            encoding.as_deref(),
        ));
        let body_size = if exchange.status.is_some() {
            exchange.response_body.size as i64
        } else {
            -1
        };
        let mut entry = json!({
            "startedDateTime": iso8601(exchange.started_at_ms),
            "time": wait,
            "request": request,
            "response": {
                "status": status,
                "statusText": status_text(status),
                "httpVersion": exchange.http_version,
                "cookies": [],
                "headers": headers(&exchange.response_headers),
                "content": content,
                "redirectURL": header("Location", &exchange.response_headers).unwrap_or_default(),
                "headersSize": -1,
                "bodySize": body_size,
            },
            "cache": {},
            "timings": { "send": 0, "wait": wait, "receive": 0 },
            "connection": id.to_string(),
        });
        if let Ok(address) = captured.destination.parse::<SocketAddr>() {
            entry["serverIPAddress"] = json!(address.ip().to_string());
        }
        if let Some(note) = exchange.note {
            comment.insert(0, note.to_string());
        }
        if exchange.request_body.truncated() || exchange.response_body.truncated() {
            comment.push(format!("bodies truncated to {MAX_HTTP_BODY_BYTES} bytes"));
        }
        if !comment.is_empty() {
            entry["comment"] = json!(comment.join("; "));
        }
        entry
    }

    /// `text` (UTF-8) or `text` + `encoding: base64`, with `Content-Encoding`
    /// undone first as HAR asks (`size` then counts the decoded bytes and
    /// `compression` the bytes saved). Returns a comment when the body could
    /// not be decoded, or only in part.
    fn text(
        target: &mut Value,
        body: &CapturedBody,
        content_encoding: Option<&str>,
    ) -> Option<String> {
        if body.data.is_empty() {
            return None;
        }
        let mut comment = None;
        let mut data = std::borrow::Cow::Borrowed(body.data.as_slice());
        if let Some(coding) = content_encoding.filter(|coding| !decode::codings(coding).is_empty())
        {
            match decode::decode_body(
                &body.data,
                coding,
                !body.truncated(),
                decode::DecodeLimits::EXTENSION,
            ) {
                Ok(decoded) => {
                    if decoded.truncated {
                        comment = Some(format!(
                            "{coding} body decoded only in part ({} bytes)",
                            decoded.data.len()
                        ));
                    } else {
                        let size = decoded.data.len() as u64;
                        target["size"] = json!(size);
                        target["compression"] = json!(size.saturating_sub(body.size));
                    }
                    data = std::borrow::Cow::Owned(decoded.data);
                }
                Err(error) => comment = Some(format!("{coding} body left encoded: {error}")),
            }
        }
        match std::str::from_utf8(&data) {
            Ok(text) => target["text"] = json!(text),
            Err(_) => {
                target["text"] = json!(base64_encode(&data));
                target["encoding"] = json!("base64");
            }
        }
        comment
    }

    fn query(url: &str) -> Vec<Value> {
        let Some((_, query)) = url.split_once('?') else {
            return Vec::new();
        };
        let query = query.split('#').next().unwrap_or("");
        query
            .split('&')
            .filter(|pair| !pair.is_empty())
            .map(|pair| {
                let (name, value) = pair.split_once('=').unwrap_or((pair, ""));
                json!({ "name": name, "value": value })
            })
            .collect()
    }

    pub(super) fn status_text(status: u16) -> &'static str {
        match status {
            200 => "OK",
            201 => "Created",
            204 => "No Content",
            206 => "Partial Content",
            301 => "Moved Permanently",
            302 => "Found",
            304 => "Not Modified",
            307 => "Temporary Redirect",
            308 => "Permanent Redirect",
            400 => "Bad Request",
            401 => "Unauthorized",
            403 => "Forbidden",
            404 => "Not Found",
            429 => "Too Many Requests",
            500 => "Internal Server Error",
            502 => "Bad Gateway",
            503 => "Service Unavailable",
            504 => "Gateway Timeout",
            _ => "",
        }
    }

    /// `2026-11-14T09:57:13.123Z` for Unix milliseconds.
    pub(super) fn iso8601(millis: u64) -> String {
        let seconds = millis / 1000;
        let days = (seconds / 86_400) as i64;
        let rest = seconds % 86_400;
        // Civil date from days since 1970-01-01 (H. Hinnant).
        let z = days + 719_468;
        let era = z.div_euclid(146_097);
        let doe = z.rem_euclid(146_097);
        let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
        let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
        let mp = (5 * doy + 2) / 153;
        let day = doy - (153 * mp + 2) / 5 + 1;
        let month = if mp < 10 { mp + 3 } else { mp - 9 };
        let year = yoe + era * 400 + i64::from(month <= 2);
        format!(
            "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}.{:03}Z",
            rest / 3600,
            rest % 3600 / 60,
            rest % 60,
            millis % 1000,
        )
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn formats_utc_times() {
            assert_eq!(iso8601(0), "1970-01-01T00:00:00.000Z");
            assert_eq!(iso8601(1_794_995_833_123), "2026-11-18T09:57:13.123Z");
            assert_eq!(iso8601(951_782_400_000), "2000-02-29T00:00:00.000Z");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store(budget: usize) -> CaptureStore {
        let store = CaptureStore::default();
        store.set(true, Some(budget));
        store
    }

    #[test]
    fn off_by_default_and_keeps_nothing() {
        let store = CaptureStore::default();
        assert!(!store.begin(1, Network::Tcp, None, "192.0.2.1:80", 1));
        store.record(1, Direction::Up, b"GET /");
        assert_eq!(store.status().connections, 0);
        assert!(store.connection_json(1).is_none());
    }

    #[test]
    fn keeps_the_first_bytes_of_each_direction_and_merges_tcp() {
        let store = store(MAX_TOTAL_BYTES_LIMIT);
        assert!(store.begin(7, Network::Tcp, Some("example.test"), "192.0.2.1:80", 1));
        store.record(7, Direction::Up, b"GET / HTTP/1.1\r\n");
        store.record(7, Direction::Up, b"\r\n");
        store.record(7, Direction::Down, &vec![b'x'; MAX_DIRECTION_BYTES + 10]);
        store.end(7, 2);
        let value = store.connection_json(7).unwrap();
        let chunks = value["chunks"].as_array().unwrap();
        assert_eq!(chunks.len(), 2);
        assert_eq!(chunks[0]["dir"], "up");
        assert_eq!(
            chunks[0]["data_base64"],
            base64_encode(b"GET / HTTP/1.1\r\n\r\n")
        );
        assert_eq!(value["download"]["captured"], MAX_DIRECTION_BYTES);
        assert_eq!(value["download"]["truncated"], true);
        assert_eq!(value["upload"]["truncated"], false);
        assert_eq!(value["ended_at_ms"], 2);
    }

    #[test]
    fn udp_datagrams_stay_apart() {
        let store = store(MAX_TOTAL_BYTES_LIMIT);
        store.begin(3, Network::Udp, None, "192.0.2.1:53", 1);
        store.record(3, Direction::Up, b"q1");
        store.record(3, Direction::Up, b"q2");
        let value = store.connection_json(3).unwrap();
        assert_eq!(value["chunks"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn the_budget_drops_the_oldest_connections() {
        let store = store(MIN_TOTAL_BYTES);
        for id in 1..=4 {
            store.begin(id, Network::Tcp, None, "192.0.2.1:80", 1);
            store.record(id, Direction::Down, &vec![0u8; 30 * 1024]);
        }
        let status = store.status();
        assert!(status.used_bytes <= MIN_TOTAL_BYTES, "{status:?}");
        assert!(store.connection_json(1).is_none());
        assert!(store.connection_json(4).is_some());
        store.clear();
        assert_eq!(store.status().used_bytes, 0);
    }

    #[test]
    fn decrypted_connections_keep_http_only_and_export() {
        let store = Arc::new(store(MAX_TOTAL_BYTES_LIMIT));
        store.begin(
            9,
            Network::Tcp,
            Some("api.example.test"),
            "api.example.test:443",
            1_000,
        );
        store.record(9, Direction::Up, b"\x16\x03\x01tls");
        store.mark_decrypted(9);
        store.record(9, Direction::Up, b"\x17\x03\x03more");
        let mut exchange = HttpExchange::new(
            "GET",
            "https://api.example.test/a?x=1&y",
            &[("Host".to_string(), "api.example.test".to_string())],
        );
        exchange.status = Some(200);
        exchange.response_headers = vec![("Content-Type".to_string(), "text/plain".to_string())];
        exchange.response_body = CapturedBody::of(b"hello");
        store.add_exchange(9, exchange);

        let value = store.connection_json(9).unwrap();
        assert_eq!(value["decrypted"], true);
        assert!(value["chunks"].as_array().unwrap().is_empty());
        assert_eq!(value["http"][0]["status"], 200);
        assert_eq!(
            value["http"][0]["response"]["body"]["data_base64"],
            base64_encode(b"hello")
        );

        let har: Value = serde_json::from_slice(&store.export_har(None, true)).unwrap();
        let entry = &har["log"]["entries"][0];
        assert_eq!(har["log"]["version"], "1.2");
        assert_eq!(entry["request"]["method"], "GET");
        assert_eq!(entry["request"]["queryString"][0]["name"], "x");
        assert_eq!(entry["response"]["content"]["text"], "hello");

        let pcap = store.export_pcapng(Some(9), true);
        assert_eq!(&pcap[..4], &[0x0A, 0x0D, 0x0D, 0x0A]);
        assert!(pcap.windows(5).any(|window| window == b"hello"));
        assert!(pcap.windows(16).any(|window| window == b"api.example.test"));
        assert!(pcap.len().is_multiple_of(4));

        let answer: Value = serde_json::from_slice(&export_answer(&store, &{
            let mut request = ExportRequest::new(ExportFormat::Pcapng);
            request.selection.id = Some(9);
            request
        }))
        .unwrap();
        assert_eq!(answer["file_name"], "anixops-capture-9.pcapng");
        assert_eq!(answer["size"], pcap.len());
        let data = base64::engine::general_purpose::STANDARD
            .decode(answer["data_base64"].as_str().unwrap())
            .unwrap();
        assert_eq!(data.len(), pcap.len());
    }

    #[test]
    fn har_carries_encoded_bodies_decoded() {
        use std::io::Write;

        let store = Arc::new(store(MAX_TOTAL_BYTES_LIMIT));
        store.begin(
            4,
            Network::Tcp,
            Some("cdn.example.test"),
            "192.0.2.4:443",
            1,
        );
        store.mark_decrypted(4);
        let text = "hello ".repeat(500);
        let mut gzip = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        gzip.write_all(text.as_bytes()).unwrap();
        let wire = gzip.finish().unwrap();
        let header = |name: &str, value: &str| (name.to_string(), value.to_string());
        let mut exchange = HttpExchange::new("GET", "https://cdn.example.test/a", &[]);
        exchange.status = Some(200);
        exchange.response_headers = vec![
            header("Content-Type", "text/plain"),
            header("Content-Encoding", "gzip"),
        ];
        exchange.response_body = CapturedBody::of(&wire);
        store.add_exchange(4, exchange.clone());
        // An encoding nobody decodes stays as captured, with a comment.
        exchange.response_headers[1].1 = "compress".to_string();
        exchange.response_body = CapturedBody::of(b"\x1f\x9d\x90");
        store.add_exchange(4, exchange);

        // Redacted, a body that cannot be decoded to be checked is left out.
        let redacted: Value = serde_json::from_slice(&store.export_har(Some(4), true)).unwrap();
        let omitted = &redacted["log"]["entries"][1]["response"];
        assert!(omitted["content"].get("text").is_none(), "{omitted}");
        assert_eq!(omitted["content"]["size"], 3);
        assert!(omitted["headers"]
            .as_array()
            .unwrap()
            .iter()
            .any(|header| header["name"] == redact::REDACTED_BODY_HEADER));
        assert_eq!(
            redacted["log"]["entries"][0]["response"]["content"]["text"],
            text.as_str()
        );

        let har: Value = serde_json::from_slice(&store.export_har(Some(4), false)).unwrap();
        let decoded = &har["log"]["entries"][0]["response"];
        assert_eq!(decoded["content"]["text"], text.as_str());
        assert_eq!(decoded["content"]["size"], text.len());
        assert_eq!(decoded["content"]["compression"], text.len() - wire.len());
        assert_eq!(decoded["bodySize"], wire.len());
        // The headers stay as sent.
        assert_eq!(decoded["headers"][1]["value"], "gzip");

        let left = &har["log"]["entries"][1];
        assert_eq!(left["response"]["content"]["encoding"], "base64");
        assert!(left["comment"]
            .as_str()
            .unwrap()
            .contains("compress body left encoded"));
    }

    #[test]
    fn exports_udp_over_ipv6() {
        let store = store(MAX_TOTAL_BYTES_LIMIT);
        store.begin(2, Network::Udp, None, "[2001:db8::1]:53", 1);
        store.record(2, Direction::Up, b"query");
        store.record(2, Direction::Down, b"answer");
        let pcap = store.export_pcapng(None, true);
        assert!(pcap.windows(6).any(|window| window == b"answer"));
        // The synthetic client fd00::1 talks to the real IPv6 server.
        let client = [0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        assert!(pcap.windows(16).any(|window| window == client));
    }

    #[test]
    fn a_long_tcp_run_is_kept_in_pieces_and_shown_whole() {
        let store = store(MAX_TOTAL_BYTES_LIMIT);
        store.begin(3, Network::Tcp, None, "192.0.2.1:80", 1);
        let block = vec![7u8; 1460];
        for _ in 0..40 {
            store.record(3, Direction::Down, &block);
        }
        {
            let inner = lock(&store.inner);
            let captured = &inner.connections[&3];
            assert!(captured.chunks.len() > 1);
            assert!(captured
                .chunks
                .iter()
                .all(|chunk| chunk.data.capacity() <= CHUNK_PIECE_BYTES));
        }
        let value = store.connection_json(3).unwrap();
        let chunks = value["chunks"].as_array().unwrap();
        assert_eq!(chunks.len(), 1);
        let data = base64::engine::general_purpose::STANDARD
            .decode(chunks[0]["data_base64"].as_str().unwrap())
            .unwrap();
        assert_eq!(data.len(), 40 * 1460);
    }

    #[test]
    fn kept_pieces_grow_no_further_than_their_limit() {
        let mut buf = Vec::new();
        for _ in 0..44 {
            reserve_capped(&mut buf, 1460, MAX_DIRECTION_BYTES);
            buf.extend_from_slice(&[0u8; 1460]);
        }
        assert_eq!(buf.len(), 44 * 1460);
        assert_eq!(buf.capacity(), MAX_DIRECTION_BYTES);
    }

    fn filed(store: &CaptureStore, id: u64, method: &str, url: &str, status: u16) {
        let mut exchange = HttpExchange::new(
            method,
            url,
            &[(
                "Authorization".to_string(),
                "Bearer secret-value".to_string(),
            )],
        );
        exchange.status = Some(status);
        store.add_exchange(id, exchange);
    }

    #[test]
    fn requests_list_rows_in_order_and_filter() {
        let store = store(MAX_TOTAL_BYTES_LIMIT);
        store.begin(1, Network::Tcp, Some("a.test"), "a.test:443", 1);
        store.begin(2, Network::Tcp, Some("b.test"), "b.test:443", 2);
        store.mark_decrypted(1);
        store.mark_decrypted(2);
        filed(&store, 2, "GET", "https://b.test/one", 200);
        filed(&store, 1, "POST", "https://a.test/two", 500);
        filed(&store, 2, "GET", "https://b.test/three", 404);

        let all = store.requests_json(0, None, None, &Filter::default());
        let rows = all["requests"].as_array().unwrap();
        assert_eq!(rows.len(), 3);
        assert_eq!(rows[0]["seq"], 1);
        assert_eq!(rows[0]["connection_id"], 2);
        assert_eq!(rows[0]["index"], 0);
        assert_eq!(rows[1]["connection_id"], 1);
        assert_eq!(rows[2]["index"], 1);
        assert_eq!(rows[2]["host"], "b.test");
        assert_eq!(rows[2]["http_version"], HTTP_1_1);
        assert_eq!(all["last_seq"], 3);
        assert_eq!(all["dropped_before_seq"], 0);

        let since = store.requests_json(1, None, Some(1), &Filter::default());
        assert_eq!(since["requests"].as_array().unwrap().len(), 1);
        assert_eq!(since["requests"][0]["seq"], 2);

        let errors = store.requests_json(
            0,
            None,
            None,
            &Filter::parse("status:>=400 -host:a.test").unwrap(),
        );
        assert_eq!(errors["requests"].as_array().unwrap().len(), 1);
        assert_eq!(errors["requests"][0]["url"], "https://b.test/three");

        store.clear();
        let cleared = store.requests_json(0, None, None, &Filter::default());
        assert!(cleared["requests"].as_array().unwrap().is_empty());
        assert_eq!(cleared["dropped_before_seq"], 3);
    }

    #[test]
    fn exchanges_in_progress_are_listed_by_rev_and_keep_their_messages() {
        use stream::{MessageKind, StreamMessage};
        let store = store(MAX_TOTAL_BYTES_LIMIT);
        store.begin(7, Network::Tcp, Some("a.test"), "a.test:443", 1);
        store.mark_decrypted(7);
        let used = store.status().used_bytes;
        let mut exchange = HttpExchange::new("GET", "https://a.test/events", &[]);
        let index = store.open_exchange(7, exchange.clone()).unwrap();

        // Not finished: only `since_rev` lists it.
        let by_seq = store.requests_json(0, None, None, &Filter::default());
        assert!(by_seq["requests"].as_array().unwrap().is_empty());
        let by_rev = store.requests_json(0, Some(0), None, &Filter::default());
        assert_eq!(by_rev["requests"][0]["state"], "in_progress");
        assert_eq!(by_rev["requests"][0]["seq"], 0);
        let last_rev = by_rev["last_rev"].as_u64().unwrap();

        exchange.status = Some(200);
        exchange.note = Some("streaming");
        exchange.rules_skipped = true;
        store.update_exchange(7, index, &exchange);
        for i in 0..3u8 {
            store.push_message(
                7,
                index,
                StreamMessage {
                    index: 0,
                    at_ms: 5,
                    direction: Direction::Down,
                    kind: MessageKind::Sse,
                    label: Some("tick".into()),
                    id: None,
                    code: None,
                    data: vec![b'0' + i],
                    size: 1,
                },
            );
        }
        let changed = store.requests_json(0, Some(last_rev), None, &Filter::default());
        let rows = changed["requests"].as_array().unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0]["status"], 200);
        assert_eq!(rows[0]["message_count"], 3);
        assert_eq!(rows[0]["rules_skipped"], true);
        let last_rev = changed["last_rev"].as_u64().unwrap();
        let unchanged = store.requests_json(0, Some(last_rev), None, &Filter::default());
        assert!(unchanged["requests"].as_array().unwrap().is_empty());

        let detail = store.exchange_json(7, index, 1);
        assert_eq!(detail["messages"]["seen"], 3);
        let kept = detail["messages"]["kept"].as_array().unwrap();
        assert_eq!(kept.len(), 2);
        assert_eq!(kept[0]["index"], 1);
        assert_eq!(kept[0]["label"], "tick");
        assert_eq!(kept[1]["text"], "2");

        // Finishing keeps the messages and files it by `seq`.
        store.finish_exchange(7, index, Some(exchange.clone()));
        let done = store.requests_json(0, None, None, &Filter::default());
        assert_eq!(done["requests"][0]["state"], "done");
        assert_eq!(done["requests"][0]["seq"], 1);
        assert_eq!(store.exchange_json(7, index, 0)["messages"]["seen"], 3);
        assert_eq!(store.exchange_json(7, 9, 0), Value::Null);

        // The memory the exchange holds is what the budget counts.
        let expected = {
            let inner = lock(&store.inner);
            inner.connections[&7].http[index].memory()
        };
        assert_eq!(store.status().used_bytes, used + expected);
        // One lock at a time: a second `lock` in the same statement would
        // wait for the first guard forever.
        let inner = lock(&store.inner);
        let captured = &inner.connections[&7];
        assert_eq!(captured.memory, captured.memory_estimate());
    }

    #[test]
    fn a_stream_of_many_messages_stays_within_its_budget() {
        use stream::{MessageKind, StreamMessage, MAX_MESSAGES, MAX_MESSAGE_BYTES_TOTAL};
        let store = store(MAX_TOTAL_BYTES_LIMIT);
        store.begin(8, Network::Tcp, Some("a.test"), "a.test:443", 1);
        store.mark_decrypted(8);
        let index = store
            .open_exchange(8, HttpExchange::new("GET", "https://a.test/s", &[]))
            .unwrap();
        for i in 0..20_000u64 {
            store.push_message(
                8,
                index,
                StreamMessage {
                    index: 0,
                    at_ms: i,
                    direction: Direction::Down,
                    kind: MessageKind::Sse,
                    label: None,
                    id: None,
                    code: None,
                    data: vec![b'x'; 700],
                    size: 700,
                },
            );
        }
        let inner = lock(&store.inner);
        let exchange = &inner.connections[&8].http[index];
        assert_eq!(exchange.messages.seen, 20_000);
        assert!(exchange.messages.kept.len() <= MAX_MESSAGES);
        assert!(exchange.messages.memory() <= MAX_MESSAGE_BYTES_TOTAL + MAX_MESSAGES * 64);
        assert_eq!(inner.used, inner.connections[&8].memory);
        assert_eq!(
            inner.connections[&8].memory,
            inner.connections[&8].memory_estimate()
        );
    }

    #[test]
    fn exports_are_redacted_unless_asked_not_to() {
        let store = store(MAX_TOTAL_BYTES_LIMIT);
        store.begin(4, Network::Tcp, Some("a.test"), "a.test:443", 1);
        store.mark_decrypted(4);
        filed(&store, 4, "GET", "https://a.test/x?token=tok-value-1", 200);
        filed(&store, 4, "GET", "https://a.test/y", 200);

        let contains = |file: &[u8], needle: &[u8]| file.windows(needle.len()).any(|w| w == needle);
        for format in [
            ExportFormat::Pcapng,
            ExportFormat::Har,
            ExportFormat::Curl,
            ExportFormat::Code,
            ExportFormat::Postman,
            ExportFormat::Insomnia,
        ] {
            let request = ExportRequest::new(format);
            let file = export_file(&store, &request);
            assert!(!contains(&file, b"secret-value"), "{format:?}");
            assert!(!contains(&file, b"tok-value-1"), "{format:?}");
            assert!(contains(&file, redact::MASK.as_bytes()), "{format:?}");
            let raw = ExportRequest {
                redact: false,
                ..request
            };
            assert!(
                contains(&export_file(&store, &raw), b"secret-value"),
                "{format:?}"
            );
        }

        let one = ExportRequest {
            selection: Selection {
                id: Some(4),
                exchange: Some(1),
            },
            ..ExportRequest::new(ExportFormat::Curl)
        };
        let script = String::from_utf8(export_file(&store, &one)).unwrap();
        assert!(script.contains("https://a.test/y"));
        assert!(!script.contains("https://a.test/x"));
        let answer: Value = serde_json::from_slice(&export_answer(&store, &one)).unwrap();
        assert_eq!(answer["file_name"], "anixops-capture-4-1.sh");
        assert_eq!(answer["redacted"], true);
    }

    fn decrypted(store: &CaptureStore, id: u64) {
        store.begin(id, Network::Tcp, Some("a.test"), "a.test:443", 1);
        store.mark_decrypted(id);
    }

    /// What the budget counts is what the connections hold.
    fn assert_accounted(store: &CaptureStore) {
        let inner = lock(&store.inner);
        let sum: usize = inner
            .connections
            .values()
            .map(|captured| captured.memory)
            .sum();
        assert_eq!(inner.used, sum);
        for captured in inner.connections.values() {
            assert_eq!(captured.memory, captured.memory_estimate());
        }
    }

    #[test]
    fn one_busy_connection_gives_up_its_own_oldest_bodies_only() {
        let store = store(DEFAULT_MAX_TOTAL_BYTES);
        decrypted(&store, 1);
        filed(&store, 1, "GET", "https://a.test/other", 200);
        decrypted(&store, 2);
        // One HTTP/2 connection loading images of 64 KiB each.
        let mut last = None;
        for i in 0..40 {
            let mut exchange = HttpExchange::new("GET", &format!("https://a.test/image/{i}"), &[]);
            exchange.status = Some(200);
            exchange.response_body = CapturedBody::of(&vec![b'x'; MAX_HTTP_BODY_BYTES]);
            let index = store.open_exchange(2, exchange);
            assert_eq!(index, Some(i), "every exchange is still filed");
            store.finish_exchange(2, i, None);
            last = index;
        }
        assert_eq!(last, Some(39));
        let status = store.status();
        assert!(status.used_bytes <= DEFAULT_MAX_TOTAL_BYTES, "{status:?}");
        assert!(status.dropped_bodies > 0, "{status:?}");
        assert_eq!(status.dropped_exchanges, 0, "{status:?}");
        assert!(
            store.connection_json(1).is_some(),
            "the other connection is not emptied for it"
        );
        let value = store.connection_json(2).unwrap();
        let http = value["http"].as_array().unwrap();
        assert_eq!(http.len(), 40);
        assert_eq!(http[39]["index"], 39);
        assert_eq!(http[39]["response"]["body"]["truncated"], false);
        // The oldest rows stay, their bodies marked truncated.
        assert_eq!(http[0]["url"], "https://a.test/image/0");
        assert_eq!(http[0]["response"]["body"]["truncated"], true);
        assert_eq!(http[0]["response"]["body"]["size"], MAX_HTTP_BODY_BYTES);
        {
            let inner = lock(&store.inner);
            assert!(inner.connections[&2].memory <= DEFAULT_MAX_TOTAL_BYTES / 2);
        }
        let rows = store.requests_json(0, None, None, &Filter::default());
        assert_eq!(rows["requests"].as_array().unwrap().len(), 41);
        assert_eq!(rows["dropped_before_seq"], 0);
        assert_accounted(&store);
    }

    #[test]
    fn raw_bytes_past_a_connections_share_are_counted_not_kept() {
        let store = store(MIN_TOTAL_BYTES);
        store.begin(1, Network::Tcp, None, "192.0.2.1:80", 1);
        store.record(1, Direction::Up, b"GET / HTTP/1.1\r\n\r\n");
        store.begin(2, Network::Tcp, None, "192.0.2.1:80", 1);
        for _ in 0..40 {
            store.record(2, Direction::Down, &[7u8; 1460]);
        }
        // A gap would make the kept bytes lie: nothing past it is kept.
        store.record(2, Direction::Down, b"x");
        let value = store.connection_json(2).unwrap();
        assert_eq!(value["download"]["seen"], 40 * 1460 + 1);
        assert_eq!(value["download"]["truncated"], true);
        assert!(value["download"]["captured"].as_u64().unwrap() < 40 * 1460);
        assert!(store.connection_json(1).is_some(), "not dropped for it");
        assert_accounted(&store);
    }

    #[test]
    fn clearing_keeps_open_connections_recording_under_new_indexes() {
        let store = store(MAX_TOTAL_BYTES_LIMIT);
        decrypted(&store, 3);
        let old = store
            .open_exchange(3, HttpExchange::new("GET", "https://a.test/old", &[]))
            .unwrap();
        assert_eq!(old, 0);
        store.clear();
        let status = store.status();
        assert_eq!((status.connections, status.used_bytes), (0, 0));

        let new = store
            .open_exchange(3, HttpExchange::new("GET", "https://a.test/new", &[]))
            .expect("the open connection records again");
        assert_eq!(new, 1, "an index is never given twice");
        // The request in flight across the clear ends without touching the
        // new one.
        let mut late = HttpExchange::new("GET", "https://a.test/old", &[]);
        late.status = Some(200);
        store.finish_exchange(3, old, Some(late));
        store.finish_exchange(3, new, None);
        let rows = store.requests_json(0, None, None, &Filter::default());
        let rows = rows["requests"].as_array().unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0]["url"], "https://a.test/new");
        assert_eq!(rows[0]["index"], 1);
        assert_eq!(store.exchange_json(3, 0, 0), Value::Null);
        assert_eq!(store.exchange_json(3, 1, 0)["url"], "https://a.test/new");
        assert_accounted(&store);

        // Closed and cleared, it is gone for good.
        store.end(3, 9);
        store.clear();
        assert!(store
            .open_exchange(3, HttpExchange::new("GET", "https://a.test/after", &[]))
            .is_none());
    }

    #[test]
    fn exchanges_past_the_limit_roll_and_kept_rows_are_never_reported_dropped() {
        let store = store(MAX_TOTAL_BYTES_LIMIT);
        decrypted(&store, 1);
        filed(&store, 1, "GET", "https://a.test/first", 200);
        decrypted(&store, 2);
        for i in 0..MAX_HTTP_EXCHANGES + 6 {
            filed(&store, 2, "GET", &format!("https://a.test/{i}"), 200);
        }
        let value = store.connection_json(2).unwrap();
        let http = value["http"].as_array().unwrap();
        assert_eq!(http.len(), MAX_HTTP_EXCHANGES);
        assert_eq!(http[0]["index"], 6);
        assert_eq!(http[0]["url"], "https://a.test/6");
        assert_eq!(store.exchange_json(2, 5, 0), Value::Null);
        let newest = MAX_HTTP_EXCHANGES + 5;
        assert_eq!(
            store.exchange_json(2, newest, 0)["url"],
            format!("https://a.test/{newest}")
        );
        assert_eq!(store.status().dropped_exchanges, 6);
        let rows = store.requests_json(0, None, Some(MAX_REQUEST_ROWS), &Filter::default());
        // The first row (connection 1) is older than the rolled ones but
        // still kept, so a client must not drop it.
        assert_eq!(rows["dropped_before_seq"], 0);
        assert_eq!(
            rows["requests"].as_array().unwrap().len(),
            MAX_HTTP_EXCHANGES + 1
        );
        assert_accounted(&store);
    }

    #[test]
    fn an_open_connection_dropped_for_the_budget_records_again() {
        let store = store(MIN_TOTAL_BYTES);
        decrypted(&store, 1);
        filed(&store, 1, "GET", "https://a.test/one", 200);
        for id in 2..=4 {
            store.begin(id, Network::Tcp, None, "192.0.2.1:80", 1);
            store.record(id, Direction::Down, &vec![0u8; 30 * 1024]);
        }
        assert!(store.connection_json(1).is_none(), "dropped for newer ones");
        let index = store
            .open_exchange(1, HttpExchange::new("GET", "https://a.test/two", &[]))
            .expect("not left out for the rest of its life");
        assert_eq!(index, 1);
        store.finish_exchange(1, index, None);
        let value = store.connection_json(1).unwrap();
        assert_eq!(value["http"][0]["url"], "https://a.test/two");
        assert!(store.status().used_bytes <= MIN_TOTAL_BYTES);
        assert_accounted(&store);
    }

    #[test]
    fn loaded_sessions_take_ids_no_live_connection_has() {
        let dir = std::env::temp_dir().join(format!(
            "anixops-capture-load-{}-{}",
            std::process::id(),
            unix_millis()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        let store = store(MAX_TOTAL_BYTES_LIMIT);
        store
            .set_storage(dir.to_str().unwrap(), &[3u8; storage::KEY_LEN], None)
            .unwrap();
        decrypted(&store, 12);
        filed(&store, 12, "GET", "https://saved.test/1", 200);
        filed(&store, 12, "GET", "https://saved.test/2", 200);
        store.end(12, 5);
        let saved = store.save_session(Some("yesterday")).unwrap();
        let session = saved["session"]["session"].as_str().unwrap().to_string();
        store.clear();

        // A later tunnel run numbers its connections from 1 again: a live
        // request on connection 12 is in flight as the session loads.
        decrypted(&store, 12);
        let live = store
            .open_exchange(12, HttpExchange::new("POST", "https://live.test/x", &[]))
            .unwrap();
        store.load_session(&session).unwrap();
        let mut finished = HttpExchange::new("POST", "https://live.test/x", &[]);
        finished.status = Some(201);
        store.update_exchange(12, live, &finished);
        store.finish_exchange(12, live, Some(finished));
        store.end(12, 99);

        assert!(store.connection_json(12).is_none());
        let loaded = store.connection_json(LOADED_ID_BASE).unwrap();
        assert_eq!(loaded["id"], LOADED_ID_BASE);
        assert_eq!(loaded["http"][0]["url"], "https://saved.test/1");
        assert_eq!(loaded["http"][1]["url"], "https://saved.test/2");
        assert_eq!(loaded["ended_at_ms"], 5);
        let rows = store.requests_json(0, None, None, &Filter::default());
        let rows = rows["requests"].as_array().unwrap();
        assert_eq!(rows.len(), 2);
        assert!(rows.iter().all(
            |row| row["connection_id"] == LOADED_ID_BASE && row["url"] != "https://live.test/x"
        ));

        // Capture back on: a live connection whatever its id leaves the
        // loaded one alone, and the budget counts both once.
        store.set(true, None);
        decrypted(&store, 12);
        assert!(store.connection_json(LOADED_ID_BASE).is_some());
        assert_eq!(store.status().connections, 2);
        assert_accounted(&store);
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn head_value<'a>(text: &'a str, name: &str) -> Option<&'a str> {
        text.split("\r\n\r\n").next()?.lines().find_map(|line| {
            let (key, value) = line.split_once(": ")?;
            key.eq_ignore_ascii_case(name).then_some(value)
        })
    }

    fn body_of(text: &str) -> &str {
        text.split_once("\r\n\r\n").map_or("", |(_, body)| body)
    }

    #[test]
    fn pcapng_text_frames_the_bytes_it_writes() {
        let header = |name: &str, value: &str| (name.to_string(), value.to_string());
        let text = |bytes: Vec<u8>| String::from_utf8(bytes).unwrap();

        // Chunked on the wire, kept without its chunk framing.
        let mut chunked = HttpExchange::new("GET", "https://a.test/c", &[]);
        chunked.status = Some(200);
        chunked.response_headers = vec![header("Transfer-Encoding", "chunked")];
        chunked.response_body = CapturedBody::of(b"hello");
        let down = text(http_text(&chunked).1);
        assert_eq!(head_value(&down, "Transfer-Encoding"), None);
        assert_eq!(
            head_value(&down, "X-AnixOps-Original-Transfer-Encoding"),
            Some("chunked")
        );
        assert_eq!(head_value(&down, "Content-Length"), Some("5"));
        assert_eq!(body_of(&down), "hello");

        // Kept only in part.
        let mut cut = HttpExchange::new("GET", "https://a.test/big", &[]);
        cut.status = Some(200);
        cut.response_headers = vec![
            header("Content-Length", "2000000"),
            header("Content-Encoding", "gzip"),
        ];
        cut.response_body = CapturedBody {
            data: vec![b'x'; MAX_HTTP_BODY_BYTES],
            size: 2_000_000,
        };
        let down = text(http_text(&cut).1);
        assert_eq!(head_value(&down, "Content-Length"), Some("65536"));
        assert_eq!(
            head_value(&down, "X-AnixOps-Original-Content-Length"),
            Some("2000000")
        );
        assert_eq!(head_value(&down, TRUNCATED_HEADER), Some("65536/2000000"));
        assert_eq!(head_value(&down, "Content-Encoding"), None);
        assert_eq!(body_of(&down).len(), MAX_HTTP_BODY_BYTES);

        // HTTP/2 names no length at all.
        let mut h2 = HttpExchange::new("GET", "https://a.test/h2", &[]);
        h2.http_version = HTTP_2;
        h2.status = Some(200);
        h2.response_body = CapturedBody::of(b"{}");
        let down = text(http_text(&h2).1);
        assert_eq!(head_value(&down, "Content-Length"), Some("2"));

        // Masking changes the length of what is written.
        let mut login = HttpExchange::new(
            "POST",
            "https://a.test/login",
            &[
                header("Content-Type", "application/json"),
                header("Content-Length", "36"),
            ],
        );
        login.request_body = CapturedBody::of(br#"{"user":"a","password":"hunter2-x"}"#);
        login.status = Some(204);
        let up = text(http_text(&redacted(&login, true)).0);
        let written = body_of(&up);
        assert!(written.contains(redact::MASK), "{up}");
        assert_eq!(
            head_value(&up, "Content-Length"),
            Some(written.len().to_string().as_str())
        );
        assert_eq!(
            head_value(&up, "X-AnixOps-Original-Content-Length"),
            Some("36")
        );

        // No body by status or method: the head stays as it was.
        for (method, status) in [("HEAD", 200), ("GET", 204), ("GET", 304), ("GET", 101)] {
            let mut bodiless = HttpExchange::new(method, "https://a.test/n", &[]);
            bodiless.status = Some(status);
            bodiless.response_headers = vec![header("Content-Length", "1234")];
            let down = text(http_text(&bodiless).1);
            assert_eq!(
                head_value(&down, "Content-Length"),
                Some("1234"),
                "{method} {status}"
            );
            assert_eq!(head_value(&down, "X-AnixOps-Original-Content-Length"), None);
            assert_eq!(body_of(&down), "");
        }
        // A request without a body names no length.
        let get = text(http_text(&HttpExchange::new("GET", "https://a.test/", &[])).0);
        assert_eq!(head_value(&get, "Content-Length"), None);
    }

    /// The TCP payload a pcapng export carries from `server_port`.
    fn payload_from(pcap: &[u8], server_port: u16) -> Vec<u8> {
        let mut out = Vec::new();
        let mut at = 0;
        while at + 8 <= pcap.len() {
            let kind = u32::from_le_bytes(pcap[at..at + 4].try_into().unwrap());
            let length = u32::from_le_bytes(pcap[at + 4..at + 8].try_into().unwrap()) as usize;
            if kind == 6 {
                let body = &pcap[at + 8..at + length - 4];
                let captured = u32::from_le_bytes(body[12..16].try_into().unwrap()) as usize;
                let packet = &body[20..20 + captured];
                if packet[0] >> 4 == 4 && packet[9] == 6 {
                    let tcp = &packet[20..];
                    if u16::from_be_bytes([tcp[0], tcp[1]]) == server_port {
                        out.extend_from_slice(&tcp[20..]);
                    }
                }
            }
            at += length;
        }
        out
    }

    #[test]
    fn pcapng_responses_read_back_one_by_one() {
        let store = store(MAX_TOTAL_BYTES_LIMIT);
        decrypted(&store, 6);
        let header = |name: &str, value: &str| (name.to_string(), value.to_string());
        // Still waiting for its response: written after the answered ones.
        store
            .open_exchange(6, HttpExchange::new("GET", "https://a.test/pending", &[]))
            .unwrap();
        let mut chunked = HttpExchange::new("GET", "https://a.test/chunked", &[]);
        chunked.status = Some(200);
        chunked.response_headers = vec![header("Transfer-Encoding", "chunked")];
        chunked.response_body = CapturedBody::of(b"hello");
        store.add_exchange(6, chunked);
        let mut h2 = HttpExchange::new("GET", "https://a.test/h2", &[]);
        h2.http_version = HTTP_2;
        h2.status = Some(200);
        h2.response_headers = vec![header("Content-Type", "application/json")];
        h2.response_body = CapturedBody::of(br#"{"access_token":"t-1","n":1}"#);
        store.add_exchange(6, h2);
        let mut cut = HttpExchange::new("GET", "https://a.test/big", &[]);
        cut.status = Some(200);
        cut.response_headers = vec![header("Content-Length", "2000000")];
        cut.response_body = CapturedBody {
            data: vec![b'x'; MAX_HTTP_BODY_BYTES],
            size: 2_000_000,
        };
        store.add_exchange(6, cut);
        let mut empty = HttpExchange::new("DELETE", "https://a.test/item", &[]);
        empty.status = Some(204);
        store.add_exchange(6, empty);

        for redact in [true, false] {
            let pcap = store.export_pcapng(Some(6), redact);
            let down = payload_from(&pcap, 443);
            let mut stream = down.as_slice();
            let mut statuses = Vec::new();
            while !stream.is_empty() {
                let end = stream
                    .windows(4)
                    .position(|window| window == b"\r\n\r\n")
                    .expect("a whole head")
                    + 4;
                let head = std::str::from_utf8(&stream[..end]).unwrap();
                assert!(head.starts_with("HTTP/1.1 "), "{head}");
                statuses.push(head[9..12].to_string());
                let length = head
                    .lines()
                    .find_map(|line| line.strip_prefix("Content-Length: "))
                    .map_or(0, |value| value.trim().parse::<usize>().unwrap());
                stream = &stream[end + length..];
            }
            assert_eq!(statuses, ["200", "200", "200", "204"], "redact {redact}");
            let up = payload_from(&pcap, 10_000 + 6);
            let up = String::from_utf8_lossy(&up);
            let last_request = up.rfind("GET /pending HTTP/1.1").unwrap();
            assert!(up.rfind("DELETE /item").unwrap() < last_request);
        }
    }

    #[test]
    fn pcapng_masks_plain_http_heads() {
        let store = store(MAX_TOTAL_BYTES_LIMIT);
        store.begin(5, Network::Tcp, None, "192.0.2.1:80", 1);
        store.record(
            5,
            Direction::Up,
            b"GET / HTTP/1.1\r\nCookie: sid=plain-secret\r\n\r\n",
        );
        let masked = store.export_pcapng(None, true);
        assert!(!masked.windows(12).any(|w| w == b"plain-secret"));
        let raw = store.export_pcapng(None, false);
        assert!(raw.windows(12).any(|w| w == b"plain-secret"));
    }
}
