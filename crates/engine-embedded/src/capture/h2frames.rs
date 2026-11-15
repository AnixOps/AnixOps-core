//! The HTTP/2 frame timeline of one decrypted connection: the header of
//! every frame (RFC 9113 §4.1) on both of its links, the app's and the
//! origin's, read passively from the plaintext as the `h2` crate writes and
//! reads it. It shows what the request list cannot: flow control
//! (`WINDOW_UPDATE`), resets (`RST_STREAM` and its error code), `GOAWAY`,
//! `SETTINGS` and `PING`.
//!
//! Nothing is held but the 9-byte header being read and the first 8 bytes
//! of a payload; a connection keeps its last [`MAX_FRAMES`] frames and
//! counts older ones in `dropped`.

use std::collections::VecDeque;

use serde::Serialize;
use serde_json::{json, Value};

use super::Direction;

/// Frames kept per connection.
pub const MAX_FRAMES: usize = 512;
/// Bytes counted for one kept frame.
pub const FRAME_MEMORY: usize = 32;
/// The client connection preface (RFC 9113 §3.4).
const PREFACE: &[u8; 24] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

/// Which TLS connection of the relay a frame went over.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Link {
    /// Between the app and the relay.
    App,
    /// Between the relay and the origin.
    Origin,
}

/// One frame header and what its first bytes say.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct H2Frame {
    /// Order within the connection, from 0, counting dropped ones.
    pub index: u64,
    pub at_ms: u64,
    pub link: Link,
    /// `Up` toward the origin, `Down` toward the app.
    pub direction: Direction,
    pub kind: u8,
    pub flags: u8,
    pub stream: u32,
    pub length: u32,
    /// `RST_STREAM` and `GOAWAY`: the error code.
    pub error: Option<u32>,
    /// `WINDOW_UPDATE`: the increment; `GOAWAY`: the last stream id;
    /// `SETTINGS`: how many settings it carries.
    pub value: Option<u32>,
}

impl H2Frame {
    pub fn json(&self) -> Value {
        json!({
            "index": self.index,
            "at_ms": self.at_ms,
            "link": self.link,
            "dir": self.direction,
            "type": kind_name(self.kind),
            "type_code": self.kind,
            "flags": self.flags,
            "flag_names": flag_names(self.kind, self.flags),
            "stream": self.stream,
            "length": self.length,
            "error": self.error.map(error_name),
            "error_code": self.error,
            "value": self.value,
        })
    }
}

/// RFC 9113 §6 frame type names.
pub fn kind_name(kind: u8) -> &'static str {
    match kind {
        0 => "DATA",
        1 => "HEADERS",
        2 => "PRIORITY",
        3 => "RST_STREAM",
        4 => "SETTINGS",
        5 => "PUSH_PROMISE",
        6 => "PING",
        7 => "GOAWAY",
        8 => "WINDOW_UPDATE",
        9 => "CONTINUATION",
        _ => "UNKNOWN",
    }
}

fn flag_names(kind: u8, flags: u8) -> Vec<&'static str> {
    let known: &[(u8, &str)] = match kind {
        0 => &[(0x1, "END_STREAM"), (0x8, "PADDED")],
        1 => &[
            (0x1, "END_STREAM"),
            (0x4, "END_HEADERS"),
            (0x8, "PADDED"),
            (0x20, "PRIORITY"),
        ],
        4 | 6 => &[(0x1, "ACK")],
        5 => &[(0x4, "END_HEADERS"), (0x8, "PADDED")],
        9 => &[(0x4, "END_HEADERS")],
        _ => &[],
    };
    known
        .iter()
        .filter(|(bit, _)| flags & bit != 0)
        .map(|(_, name)| *name)
        .collect()
}

/// RFC 9113 §7 error code names.
pub fn error_name(code: u32) -> &'static str {
    match code {
        0x0 => "NO_ERROR",
        0x1 => "PROTOCOL_ERROR",
        0x2 => "INTERNAL_ERROR",
        0x3 => "FLOW_CONTROL_ERROR",
        0x4 => "SETTINGS_TIMEOUT",
        0x5 => "STREAM_CLOSED",
        0x6 => "FRAME_SIZE_ERROR",
        0x7 => "REFUSED_STREAM",
        0x8 => "CANCEL",
        0x9 => "COMPRESSION_ERROR",
        0xa => "CONNECT_ERROR",
        0xb => "ENHANCE_YOUR_CALM",
        0xc => "INADEQUATE_SECURITY",
        0xd => "HTTP_1_1_REQUIRED",
        _ => "UNKNOWN",
    }
}

/// The kept tail of a connection's frames.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct H2Frames {
    pub kept: VecDeque<H2Frame>,
    pub seen: u64,
    pub dropped: u64,
}

impl H2Frames {
    pub fn is_empty(&self) -> bool {
        self.seen == 0
    }

    pub fn memory(&self) -> usize {
        self.kept.len() * FRAME_MEMORY
    }

    /// Adds `frames` (their `index` is set here), dropping the oldest past
    /// [`MAX_FRAMES`]; returns the change in [`H2Frames::memory`].
    pub fn push(&mut self, frames: impl IntoIterator<Item = H2Frame>) -> isize {
        let before = self.memory() as isize;
        for mut frame in frames {
            frame.index = self.seen;
            self.seen += 1;
            if self.kept.len() == MAX_FRAMES {
                self.kept.pop_front();
                self.dropped += 1;
            }
            self.kept.push_back(frame);
        }
        self.memory() as isize - before
    }

    /// The kept frames from index `since` on.
    pub fn json_since(&self, since: u64) -> Vec<Value> {
        self.kept
            .iter()
            .filter(|frame| frame.index >= since)
            .map(H2Frame::json)
            .collect()
    }
}

/// Reads the frame headers of one direction of one link as its bytes pass.
#[derive(Debug)]
pub struct FrameScanner {
    link: Link,
    direction: Direction,
    /// Preface bytes still to skip (the client side of each link sends it).
    preface: usize,
    header: [u8; 9],
    header_len: usize,
    /// The frame whose payload is passing, its first 8 bytes and how many
    /// payload bytes are left.
    frame: Option<(H2Frame, [u8; 8], usize, u32)>,
    /// The preface did not match: not HTTP/2, nothing more is read.
    failed: bool,
}

impl FrameScanner {
    /// A scanner for frames going `direction` on `link`; the client side of
    /// each link (`Up`) starts with the connection preface.
    pub fn new(link: Link, direction: Direction) -> Self {
        Self {
            link,
            direction,
            preface: if direction == Direction::Up {
                PREFACE.len()
            } else {
                0
            },
            header: [0; 9],
            header_len: 0,
            frame: None,
            failed: false,
        }
    }

    /// Feeds bytes that passed; returns the frames whose header (and the
    /// payload bytes looked at) they complete.
    pub fn feed(&mut self, mut bytes: &[u8], at_ms: u64) -> Vec<H2Frame> {
        let mut frames = Vec::new();
        while !bytes.is_empty() && !self.failed {
            if self.preface > 0 {
                let offset = PREFACE.len() - self.preface;
                let take = self.preface.min(bytes.len());
                if bytes[..take] != PREFACE[offset..offset + take] {
                    self.failed = true;
                    break;
                }
                self.preface -= take;
                bytes = &bytes[take..];
                continue;
            }
            if let Some((frame, first, remaining, looked)) = &mut self.frame {
                let take = (*remaining).min(bytes.len());
                let want = (8 - *looked as usize).min(take);
                first[*looked as usize..*looked as usize + want].copy_from_slice(&bytes[..want]);
                *looked += want as u32;
                *remaining -= take;
                bytes = &bytes[take..];
                if *remaining == 0 {
                    let mut frame = frame.clone();
                    let first = *first;
                    describe(&mut frame, &first);
                    frames.push(frame);
                    self.frame = None;
                }
                continue;
            }
            let take = (9 - self.header_len).min(bytes.len());
            self.header[self.header_len..self.header_len + take].copy_from_slice(&bytes[..take]);
            self.header_len += take;
            bytes = &bytes[take..];
            if self.header_len < 9 {
                continue;
            }
            self.header_len = 0;
            let h = self.header;
            let length = u32::from_be_bytes([0, h[0], h[1], h[2]]);
            let frame = H2Frame {
                index: 0,
                at_ms,
                link: self.link,
                direction: self.direction,
                kind: h[3],
                flags: h[4],
                stream: u32::from_be_bytes([h[5], h[6], h[7], h[8]]) & 0x7fff_ffff,
                length,
                error: None,
                value: None,
            };
            if length == 0 {
                let mut frame = frame;
                describe(&mut frame, &[0; 8]);
                frames.push(frame);
            } else {
                self.frame = Some((frame, [0; 8], length as usize, 0));
            }
        }
        frames
    }
}

/// Fills in what the first payload bytes of `frame` say.
fn describe(frame: &mut H2Frame, first: &[u8; 8]) {
    let word =
        |at: usize| u32::from_be_bytes([first[at], first[at + 1], first[at + 2], first[at + 3]]);
    match frame.kind {
        3 if frame.length >= 4 => frame.error = Some(word(0)),
        4 => frame.value = Some(frame.length / 6),
        7 if frame.length >= 8 => {
            frame.value = Some(word(0) & 0x7fff_ffff);
            frame.error = Some(word(4));
        }
        8 if frame.length >= 4 => frame.value = Some(word(0) & 0x7fff_ffff),
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(kind: u8, flags: u8, stream: u32, payload: &[u8]) -> Vec<u8> {
        let length = payload.len() as u32;
        let mut out = length.to_be_bytes()[1..].to_vec();
        out.push(kind);
        out.push(flags);
        out.extend(stream.to_be_bytes());
        out.extend_from_slice(payload);
        out
    }

    fn connection() -> Vec<u8> {
        let mut out = PREFACE.to_vec();
        out.extend(frame(4, 0, 0, &[0, 3, 0, 0, 0, 100, 0, 4, 0, 1, 0, 0]));
        out.extend(frame(1, 0x5, 1, b"\x82\x86\x84"));
        out.extend(frame(0, 0x1, 1, &[b'x'; 40_000]));
        out.extend(frame(8, 0, 0, &65_535u32.to_be_bytes()));
        out.extend(frame(3, 0, 3, &8u32.to_be_bytes()));
        let mut goaway = 5u32.to_be_bytes().to_vec();
        goaway.extend(0xbu32.to_be_bytes());
        goaway.extend(b"calm down");
        out.extend(frame(7, 0, 0, &goaway));
        out.extend(frame(6, 1, 0, &[0; 8]));
        out
    }

    #[test]
    fn reads_every_frame_header_however_the_bytes_are_split() {
        let stream = connection();
        let whole = FrameScanner::new(Link::App, Direction::Up).feed(&stream, 1);
        let kinds: Vec<_> = whole.iter().map(|frame| kind_name(frame.kind)).collect();
        assert_eq!(
            kinds,
            [
                "SETTINGS",
                "HEADERS",
                "DATA",
                "WINDOW_UPDATE",
                "RST_STREAM",
                "GOAWAY",
                "PING"
            ]
        );
        assert_eq!(whole[0].value, Some(2), "two settings");
        assert_eq!(whole[1].stream, 1);
        assert_eq!(
            flag_names(whole[1].kind, whole[1].flags),
            ["END_STREAM", "END_HEADERS"]
        );
        assert_eq!(whole[2].length, 40_000);
        assert_eq!(whole[3].value, Some(65_535));
        assert_eq!(whole[4].error.map(error_name), Some("CANCEL"));
        assert_eq!(whole[5].value, Some(5));
        assert_eq!(whole[5].error.map(error_name), Some("ENHANCE_YOUR_CALM"));
        assert_eq!(flag_names(whole[6].kind, whole[6].flags), ["ACK"]);
        for size in [1, 2, 7, 9, 13, 4096] {
            let mut scanner = FrameScanner::new(Link::App, Direction::Up);
            let frames: Vec<_> = stream
                .chunks(size)
                .flat_map(|piece| scanner.feed(piece, 1))
                .collect();
            assert_eq!(frames, whole, "pieces of {size}");
        }
    }

    #[test]
    fn the_server_side_sends_no_preface_and_garbage_stops_scanning() {
        let stream = connection();
        let down = FrameScanner::new(Link::Origin, Direction::Down).feed(&stream[24..], 1);
        assert_eq!(down.len(), 7);
        assert!(down.iter().all(|frame| frame.link == Link::Origin));
        let mut scanner = FrameScanner::new(Link::App, Direction::Up);
        assert!(scanner.feed(b"GET / HTTP/1.1\r\n\r\n", 1).is_empty());
        assert!(scanner.feed(&stream, 1).is_empty());
    }

    #[test]
    fn the_kept_tail_is_bounded() {
        let mut frames = H2Frames::default();
        let mut memory = 0isize;
        let one = FrameScanner::new(Link::App, Direction::Down).feed(&frame(0, 0, 1, b"x"), 1);
        for _ in 0..5_000 {
            memory += frames.push(one.clone());
        }
        assert_eq!(frames.seen, 5_000);
        assert_eq!(frames.kept.len(), MAX_FRAMES);
        assert_eq!(frames.dropped, 5_000 - MAX_FRAMES as u64);
        assert_eq!(memory, frames.memory() as isize);
        assert_eq!(frames.json_since(4_999).len(), 1);
        assert_eq!(frames.kept.back().unwrap().index, 4_999);
    }
}
