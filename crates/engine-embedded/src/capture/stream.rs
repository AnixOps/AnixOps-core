//! Messages inside one long-lived HTTP exchange: server-sent events
//! (`text/event-stream`) and, later, WebSocket messages. The bytes are
//! relayed as they arrive; capture keeps a bounded tail of the messages so a
//! stream that runs for hours costs the same memory as one that runs for a
//! second.
//!
//! Per exchange at most [`MAX_MESSAGES`] messages and
//! [`MAX_MESSAGE_BYTES_TOTAL`] bytes of message data are kept, each message
//! cut to [`MAX_MESSAGE_BYTES`]; older messages are dropped first and
//! counted in `dropped`.

use std::collections::VecDeque;

use serde::Serialize;
use serde_json::{json, Value};

use super::{base64_encode, Direction};

/// Messages kept per exchange.
pub const MAX_MESSAGES: usize = 512;
/// Bytes kept of one message's data.
pub const MAX_MESSAGE_BYTES: usize = 4 * 1024;
/// Bytes of message data kept per exchange.
pub const MAX_MESSAGE_BYTES_TOTAL: usize = 64 * 1024;
/// Bytes counted for one message besides its data.
const MESSAGE_OVERHEAD: usize = 48;
/// Longest SSE line looked at; the rest of a longer line is counted only.
const MAX_SSE_LINE: usize = MAX_MESSAGE_BYTES + 256;

/// What a message is.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MessageKind {
    /// One server-sent event.
    Sse,
    Text,
    Binary,
    Ping,
    Pong,
    Close,
}

/// One message of a stream.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StreamMessage {
    /// Order within the exchange, from 0, counting dropped ones.
    pub index: u64,
    pub at_ms: u64,
    pub direction: Direction,
    pub kind: MessageKind,
    /// SSE `event:` (the type) or a WebSocket close reason.
    pub label: Option<String>,
    /// SSE `id:`.
    pub id: Option<String>,
    /// WebSocket close code.
    pub code: Option<u16>,
    /// The first [`MAX_MESSAGE_BYTES`] of the data.
    pub data: Vec<u8>,
    /// Bytes the data had.
    pub size: u64,
}

impl StreamMessage {
    fn memory(&self) -> usize {
        MESSAGE_OVERHEAD
            + self.data.len()
            + self.label.as_ref().map_or(0, String::len)
            + self.id.as_ref().map_or(0, String::len)
    }

    pub fn json(&self) -> Value {
        let text = std::str::from_utf8(&self.data).ok();
        json!({
            "index": self.index,
            "at_ms": self.at_ms,
            "dir": self.direction,
            "kind": self.kind,
            "label": self.label,
            "id": self.id,
            "code": self.code,
            "size": self.size,
            "truncated": self.size > self.data.len() as u64,
            "text": text,
            "data_base64": if text.is_none() { Some(base64_encode(&self.data)) } else { None },
        })
    }
}

/// The kept tail of an exchange's messages.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Messages {
    pub kept: VecDeque<StreamMessage>,
    /// Messages seen, kept or not.
    pub seen: u64,
    /// Older messages dropped to stay within the limits.
    pub dropped: u64,
    data_bytes: usize,
    /// [`Messages::memory`], kept up to date so it costs nothing to ask.
    memory: usize,
}

impl Messages {
    pub fn is_empty(&self) -> bool {
        self.seen == 0
    }

    /// Memory the kept messages count against the capture budget.
    pub fn memory(&self) -> usize {
        self.memory
    }

    /// Adds `message` (its `index` is set here), dropping the oldest ones
    /// past the limits. Returns the change in [`Messages::memory`].
    pub fn push(&mut self, mut message: StreamMessage) -> isize {
        message.data.truncate(MAX_MESSAGE_BYTES);
        message.index = self.seen;
        self.seen += 1;
        let mut delta = message.memory() as isize;
        self.data_bytes += message.data.len();
        self.memory += message.memory();
        self.kept.push_back(message);
        while self.kept.len() > MAX_MESSAGES || self.data_bytes > MAX_MESSAGE_BYTES_TOTAL {
            let Some(old) = self.kept.pop_front() else {
                break;
            };
            self.data_bytes -= old.data.len();
            self.memory -= old.memory();
            self.dropped += 1;
            delta -= old.memory() as isize;
        }
        delta
    }

    /// The kept messages from index `since` on.
    pub fn json_since(&self, since: u64) -> Vec<Value> {
        self.kept
            .iter()
            .filter(|message| message.index >= since)
            .map(StreamMessage::json)
            .collect()
    }

    /// Rebuilds the byte count after loading saved messages.
    pub fn restore(kept: VecDeque<StreamMessage>, seen: u64, dropped: u64) -> Self {
        let data_bytes = kept.iter().map(|message| message.data.len()).sum();
        let memory = kept.iter().map(StreamMessage::memory).sum();
        Self {
            kept,
            seen,
            dropped,
            data_bytes,
            memory,
        }
    }
}

/// Splits a `text/event-stream` body into events as its bytes arrive
/// (HTML Living Standard, "Interpreting an event stream"): lines end in
/// CRLF, LF or CR; `data:` lines join with LF; an empty line ends the event;
/// comments (`:`) and unknown fields are ignored. Memory stays bounded
/// whatever the stream sends: one line of at most [`MAX_SSE_LINE`] bytes and
/// one event of at most [`MAX_MESSAGE_BYTES`] kept.
#[derive(Debug, Default)]
pub struct SseParser {
    line: Vec<u8>,
    /// Bytes of the current line past [`MAX_SSE_LINE`], skipped but
    /// counted in the event's size.
    line_skipped: u64,
    /// The last byte was CR, so an LF right after it ends nothing more.
    after_cr: bool,
    /// Whether the stream's first bytes (a BOM) were looked at.
    started: bool,
    event: Option<String>,
    id: Option<String>,
    data: Vec<u8>,
    data_size: u64,
    has_data: bool,
}

impl SseParser {
    /// Feeds body bytes; returns the events they complete, in order.
    pub fn feed(&mut self, mut bytes: &[u8], at_ms: u64) -> Vec<StreamMessage> {
        if !self.started && !bytes.is_empty() {
            self.started = true;
            if let Some(rest) = bytes.strip_prefix(b"\xef\xbb\xbf") {
                bytes = rest;
            }
        }
        let mut events = Vec::new();
        for &byte in bytes {
            match byte {
                b'\n' if self.after_cr => self.after_cr = false,
                b'\n' | b'\r' => {
                    self.after_cr = byte == b'\r';
                    if let Some(event) = self.end_line(at_ms) {
                        events.push(event);
                    }
                }
                _ => {
                    self.after_cr = false;
                    if self.line.len() < MAX_SSE_LINE {
                        self.line.push(byte);
                    } else {
                        self.line_skipped += 1;
                    }
                }
            }
        }
        events
    }

    fn end_line(&mut self, at_ms: u64) -> Option<StreamMessage> {
        let line = std::mem::take(&mut self.line);
        let skipped = std::mem::take(&mut self.line_skipped);
        if line.is_empty() {
            return self.dispatch(at_ms);
        }
        if line[0] == b':' {
            return None;
        }
        let (field, value) = match line.iter().position(|&byte| byte == b':') {
            Some(colon) => {
                let value = &line[colon + 1..];
                (&line[..colon], value.strip_prefix(b" ").unwrap_or(value))
            }
            None => (&line[..], &[][..]),
        };
        match field {
            b"data" => {
                if self.has_data {
                    self.append_data(b"\n", 1);
                }
                self.has_data = true;
                let size = value.len() as u64 + skipped;
                self.append_data(value, size);
            }
            b"event" => self.event = Some(String::from_utf8_lossy(value).into_owned()),
            b"id" if !value.contains(&0) => {
                self.id = Some(String::from_utf8_lossy(value).into_owned());
            }
            _ => {}
        }
        None
    }

    fn append_data(&mut self, bytes: &[u8], size: u64) {
        self.data_size += size;
        let room = MAX_MESSAGE_BYTES.saturating_sub(self.data.len());
        self.data.extend_from_slice(&bytes[..bytes.len().min(room)]);
    }

    /// An empty line: the event so far, when it had data.
    fn dispatch(&mut self, at_ms: u64) -> Option<StreamMessage> {
        let event = self.event.take();
        let data = std::mem::take(&mut self.data);
        let size = std::mem::take(&mut self.data_size);
        if !std::mem::take(&mut self.has_data) {
            return None;
        }
        Some(StreamMessage {
            index: 0,
            at_ms,
            direction: Direction::Down,
            kind: MessageKind::Sse,
            label: event,
            // The last event id persists across events, as browsers keep it.
            id: self.id.clone(),
            code: None,
            data,
            size,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn texts(events: &[StreamMessage]) -> Vec<(Option<&str>, Option<&str>, &str)> {
        events
            .iter()
            .map(|event| {
                (
                    event.label.as_deref(),
                    event.id.as_deref(),
                    std::str::from_utf8(&event.data).unwrap(),
                )
            })
            .collect()
    }

    #[test]
    fn parses_the_standard_examples() {
        let mut parser = SseParser::default();
        let events = parser.feed(
            b"\xef\xbb\xbfdata: YHOO\ndata: +2\ndata: 10\n\n: comment\n\nevent: add\nid: 7\ndata:73857293\n\ndata\ndata\n\nretry: 10\nfoo: bar\n\n",
            1,
        );
        assert_eq!(
            texts(&events),
            vec![
                (None, None, "YHOO\n+2\n10"),
                (Some("add"), Some("7"), "73857293"),
                (None, Some("7"), "\n"),
            ]
        );
    }

    #[test]
    fn events_split_anywhere_and_any_line_ending_work() {
        let stream = b"event: a\r\ndata: one\r\n\r\nevent: b\rdata: two\r\rdata: three\n\n";
        let whole = SseParser::default().feed(stream, 0);
        for split in 1..stream.len() {
            let mut parser = SseParser::default();
            let mut events = parser.feed(&stream[..split], 0);
            events.extend(parser.feed(&stream[split..], 0));
            assert_eq!(events, whole, "split at {split}");
        }
        assert_eq!(
            texts(&whole),
            vec![
                (Some("a"), None, "one"),
                (Some("b"), None, "two"),
                (None, None, "three"),
            ]
        );
    }

    #[test]
    fn a_huge_event_keeps_its_start_and_counts_its_size() {
        let mut parser = SseParser::default();
        let mut stream = b"data: ".to_vec();
        stream.extend(std::iter::repeat_n(b'x', 1024 * 1024));
        stream.extend_from_slice(b"\ndata: tail\n\n");
        let mut events = Vec::new();
        for piece in stream.chunks(1000) {
            events.extend(parser.feed(piece, 0));
        }
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].data.len(), MAX_MESSAGE_BYTES);
        // The whole first line, the joining LF and "tail".
        assert_eq!(events[0].size, 1024 * 1024 + 1 + 4);
        assert!(parser.line.capacity() <= MAX_SSE_LINE * 2);
    }

    #[test]
    fn the_kept_tail_stays_within_its_limits() {
        let mut messages = Messages::default();
        let mut memory = 0isize;
        for i in 0..100_000u64 {
            memory += messages.push(StreamMessage {
                index: 0,
                at_ms: i,
                direction: Direction::Down,
                kind: MessageKind::Sse,
                label: None,
                id: None,
                code: None,
                data: vec![b'a'; 300],
                size: 300,
            });
            assert_eq!(memory, messages.memory() as isize);
            if i % 97 == 0 {
                assert_eq!(
                    messages.memory(),
                    messages
                        .kept
                        .iter()
                        .map(StreamMessage::memory)
                        .sum::<usize>()
                );
            }
        }
        assert_eq!(messages.seen, 100_000);
        assert!(messages.kept.len() <= MAX_MESSAGES);
        assert!(messages.memory() <= MAX_MESSAGE_BYTES_TOTAL + MAX_MESSAGES * 64);
        assert_eq!(messages.dropped + messages.kept.len() as u64, messages.seen);
        assert_eq!(messages.kept.back().unwrap().index, 99_999);
        assert_eq!(messages.json_since(99_998).len(), 2);
    }
}
