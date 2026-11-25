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

pub mod archive;
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
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};
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

    /// [`Self::messages_json`] without what the messages carry: their
    /// text, data, event names and ids.
    fn messages_outline_json(&self, since: u64) -> Value {
        json!({
            "seen": self.messages.seen,
            "dropped": self.messages.dropped,
            "kept": self.messages.outline_since(since),
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
        self.http.first()?.ended_at_ms?;
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
    /// The session id of this store's own capture ([`Self::run_session`]).
    run_session: String,
}

impl Default for CaptureStore {
    fn default() -> Self {
        let now = unix_millis();
        Self {
            enabled: AtomicBool::new(false),
            max_total_bytes: AtomicUsize::new(DEFAULT_MAX_TOTAL_BYTES),
            next_seq: AtomicU64::new(1),
            inner: Mutex::default(),
            storage: Mutex::default(),
            // Should the system refuse randomness, a count still keeps the
            // stores of one process apart.
            run_session: storage::new_session_id(now).unwrap_or_else(|| {
                static STORES: AtomicU32 = AtomicU32::new(0);
                let count = STORES.fetch_add(1, Ordering::Relaxed);
                format!("{now}-{:08x}", std::process::id() ^ count.rotate_left(16))
            }),
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
    /// The session id this capture is saved under by `save_capture` with
    /// `run`, and copied under by `copy_capture` without `session`: one id
    /// per engine run, so the app's copies and the tunnel's save on stop
    /// are the same session.
    pub run_session: String,
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
            run_session: self.run_session.clone(),
        }
    }

    /// The session id of what this store captures in this run.
    pub fn run_session(&self) -> &str {
        &self.run_session
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

    /// Seals what the store holds into a new session, or with `run` into
    /// the run's own session ([`Self::run_session`], replaced each time):
    /// `{"session": {...}}`.
    pub fn save_session(
        &self,
        name: Option<&str>,
        run: bool,
    ) -> Result<Value, storage::StorageError> {
        let storage = lock(&self.storage);
        let storage = storage
            .as_ref()
            .ok_or(storage::StorageError::NotConfigured)?;
        let now = unix_millis();
        storage.purge(now);
        let inner = lock(&self.inner);
        let id = run.then_some(self.run_session.as_str());
        let session = storage.save(&inner, name, now, id)?;
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
    /// shares one and writes into them; with `keep_ids` (the capture
    /// viewer, where nothing is live) they keep the ids they were saved
    /// with, so a connection the app showed live is found again.
    pub fn load_session(
        &self,
        id: &str,
        keep_ids: bool,
    ) -> Result<CaptureStatus, storage::StorageError> {
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
                .map(|(rank, (saved_id, mut captured))| {
                    captured.loaded = true;
                    captured.http_base = 0;
                    inner.used += captured.memory;
                    let id = if keep_ids {
                        saved_id
                    } else {
                        LOADED_ID_BASE + rank as u64
                    };
                    (id, captured)
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

    /// The `copy_capture` answer: session `id` sealed again under `key`,
    /// for a client to keep in a store of its own (see
    /// [`storage::Storage::reseal`]):
    /// `{"session", "file_name", "size", "data_base64"}`.
    /// Without `id`, what the store holds now is sealed as
    /// [`Self::run_session`] named `name`, with no storage needed: the app
    /// keeps a copy while the tunnel runs, which the tunnel's own save on
    /// stop (`save_capture` with `run`) later replaces.
    pub fn copy_session(
        &self,
        id: Option<&str>,
        key: &[u8],
        name: Option<&str>,
    ) -> Result<Vec<u8>, storage::StorageError> {
        let (id, file) = match id {
            Some(id) => {
                let storage = lock(&self.storage);
                let file = storage
                    .as_ref()
                    .ok_or(storage::StorageError::NotConfigured)?
                    .reseal(id, key)?;
                (id, file)
            }
            None => {
                let key = storage::sealing_key(key)?;
                let inner = lock(&self.inner);
                let sealed = storage::seal_inner(&key, &inner, name, unix_millis())?;
                (self.run_session.as_str(), sealed.file)
            }
        };
        let head = json!({
            "session": id,
            "file_name": format!("{id}.anxcap"),
            "size": file.len(),
        })
        .to_string();
        let mut answer = String::with_capacity(head.len() + file.len() * 4 / 3 + 32);
        answer.push_str(&head[..head.len() - 1]);
        answer.push_str(",\"data_base64\":\"");
        base64::engine::general_purpose::STANDARD.encode_string(&file, &mut answer);
        answer.push_str("\"}");
        Ok(answer.into_bytes())
    }

    /// Keeps a session file from `copy_capture` as session `id`:
    /// `{"session": {...}}`.
    pub fn import_session(&self, id: &str, file: &[u8]) -> Result<Value, storage::StorageError> {
        let storage = lock(&self.storage);
        let storage = storage
            .as_ref()
            .ok_or(storage::StorageError::NotConfigured)?;
        Ok(json!({ "session": storage.import(id, file)? }))
    }

    /// What the capture viewer answers to `connections`: the connections
    /// the store holds, in the shape of the engine's list, all closed and
    /// newest first. Capture keeps no rule or outbound, so those are
    /// empty; the bytes are those seen while capturing. One still open
    /// when it was saved ends at its last kept bytes or message.
    pub fn connections_json(&self) -> Value {
        let inner = lock(&self.inner);
        let closed =
            inner
                .connections
                .iter()
                .rev()
                .map(|(&id, captured)| {
                    let last =
                        captured
                            .chunks
                            .iter()
                            .map(|chunk| chunk.at_ms)
                            .chain(captured.http.iter().map(|exchange| {
                                exchange.ended_at_ms.unwrap_or(exchange.started_at_ms)
                            }))
                            .max()
                            .unwrap_or(captured.started_at_ms)
                            .max(captured.started_at_ms);
                    json!({
                        "id": id,
                        "network": captured.network,
                        "host": captured.host,
                        "destination": captured.destination,
                        "rule": "",
                        "chain": [],
                        "outbound": "",
                        "started_at_ms": captured.started_at_ms,
                        "ended_at_ms": captured.ended_at_ms.unwrap_or(last),
                        "upload": captured.seen[0],
                        "download": captured.seen[1],
                        "error": null,
                        "captured": true,
                    })
                })
                .collect::<Vec<_>>();
        json!({
            "traffic": {
                "upload_total": 0,
                "download_total": 0,
                "upload_rate": 0,
                "download_rate": 0,
                "active": 0,
            },
            "active": [],
            "closed": closed,
        })
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
        redact: bool,
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
        // Redacted rows are filtered in their redacted form, so a filter
        // cannot test for a value the rows would not show.
        let requests = rows
            .into_iter()
            .map(|(id, index, exchange)| (id, index, redacted(exchange, redact)))
            .filter(|(_, _, exchange)| filter.matches(exchange))
            .take(limit)
            .map(|(id, index, exchange)| request_row(id, index, &exchange))
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
    /// it is not kept. With `redact`, the exchange is masked as an export
    /// is ([`redact`]) and the stream messages, which that does not check,
    /// keep only their place, direction, kind and size.
    pub fn exchange_json(&self, id: u64, index: usize, since_message: u64, redact: bool) -> Value {
        let inner = lock(&self.inner);
        let Some(exchange) = inner
            .connections
            .get(&id)
            .and_then(|captured| captured.exchange(index))
        else {
            return Value::Null;
        };
        let mut value = redacted(exchange, redact).json();
        value["connection_id"] = json!(id);
        value["index"] = json!(index);
        value["messages"] = if redact {
            exchange.messages_outline_json(since_message)
        } else {
            exchange.messages_json(since_message)
        };
        value["redacted"] = json!(redact);
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
    /// Everything at once ([`archive`]): a listing of the connections,
    /// HAR and pcapng, in one ZIP file.
    Zip,
}

impl ExportFormat {
    pub fn content_type(self) -> &'static str {
        match self {
            Self::Pcapng => "application/vnd.tcpdump.pcap",
            Self::Har | Self::Postman | Self::Insomnia => "application/json",
            Self::Curl => "application/x-sh",
            Self::Code => "text/plain; charset=utf-8",
            Self::Zip => "application/zip",
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
            Self::Zip => "zip",
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
        ExportFormat::Zip => archive::capture_zip(store, id, redact, unix_millis()),
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

mod pcapng;

mod har;

#[cfg(test)]
mod tests;
