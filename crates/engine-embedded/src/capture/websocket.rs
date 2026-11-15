//! WebSocket messages (RFC 6455) read from one direction of an upgraded
//! connection as its bytes are relayed, for capture only: the bytes go on
//! unchanged (decision D2: view only), and a parse error stops parsing, never
//! the relay. `permessage-deflate` (RFC 7692) messages are inflated for the
//! view, keeping the shared window across messages unless the handshake
//! turned context takeover off.
//!
//! Memory stays bounded whatever the peer sends: a frame header of at most
//! 14 bytes, a control frame of at most 125, the first
//! [`MAX_MESSAGE_BYTES`] of a data message, and one inflate state (its 32 KiB
//! window) only once a compressed message arrives. A compressed message is
//! inflated up to [`MAX_INFLATED_BYTES`]; past that the direction stops
//! inflating (the shared window is lost) and later compressed messages are
//! kept as they came, labelled `permessage-deflate`.

use flate2::{Decompress, FlushDecompress, Status};

use super::stream::{MessageKind, StreamMessage, MAX_MESSAGE_BYTES};
use super::Direction;

/// Output inflated of one message before inflating stops for the direction.
pub const MAX_INFLATED_BYTES: u64 = 1024 * 1024;
/// RFC 7692 §7.2.2: the tail each compressed message lost.
const DEFLATE_TAIL: [u8; 4] = [0x00, 0x00, 0xff, 0xff];
/// Label of a compressed message kept without inflating it.
const STILL_COMPRESSED: &str = "permessage-deflate";

/// What the handshake agreed for `permessage-deflate`, from the `101`
/// response's `Sec-WebSocket-Extensions`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Deflate {
    /// The server resets its window after each message it sends.
    pub server_no_context_takeover: bool,
    /// The client resets its window after each message it sends.
    pub client_no_context_takeover: bool,
}

impl Deflate {
    /// The agreed `permessage-deflate` parameters, when the response names
    /// the extension.
    pub fn from_response(extensions: &str) -> Option<Self> {
        extensions.split(',').find_map(|extension| {
            let mut params = extension.split(';').map(str::trim);
            if !params.next()?.eq_ignore_ascii_case("permessage-deflate") {
                return None;
            }
            let mut deflate = Self::default();
            for param in params {
                let name = param.split('=').next().unwrap_or("").trim();
                if name.eq_ignore_ascii_case("server_no_context_takeover") {
                    deflate.server_no_context_takeover = true;
                } else if name.eq_ignore_ascii_case("client_no_context_takeover") {
                    deflate.client_no_context_takeover = true;
                }
            }
            Some(deflate)
        })
    }
}

struct Frame {
    fin: bool,
    opcode: u8,
    mask: Option<[u8; 4]>,
    /// Payload bytes still to come.
    remaining: u64,
    /// Payload bytes read so far, for the mask.
    offset: u64,
}

/// A data message whose frames are still arriving.
struct Assembling {
    kind: MessageKind,
    compressed: bool,
    data: Vec<u8>,
    size: u64,
}

/// The messages of one direction of a WebSocket connection.
pub struct WsParser {
    direction: Direction,
    /// `Some` when `permessage-deflate` was agreed: whether this direction
    /// resets its window after each message.
    deflate: Option<bool>,
    header: Vec<u8>,
    frame: Option<Frame>,
    control: Vec<u8>,
    message: Option<Assembling>,
    inflate: Option<Decompress>,
    /// Inflating stopped for this direction (see the module docs).
    inflate_off: bool,
    /// A protocol error: nothing more is parsed.
    failed: bool,
}

impl WsParser {
    /// A parser for the messages that go `direction` (`Up` is what the app
    /// sends), with `deflate` as the handshake agreed it.
    pub fn new(direction: Direction, deflate: Option<Deflate>) -> Self {
        Self {
            direction,
            deflate: deflate.map(|deflate| match direction {
                Direction::Up => deflate.client_no_context_takeover,
                Direction::Down => deflate.server_no_context_takeover,
            }),
            header: Vec::with_capacity(14),
            frame: None,
            control: Vec::new(),
            message: None,
            inflate: None,
            inflate_off: false,
            failed: false,
        }
    }

    /// Whether a protocol error stopped parsing.
    pub fn failed(&self) -> bool {
        self.failed
    }

    /// Feeds bytes that went this direction; returns the messages they
    /// complete, in order.
    pub fn feed(&mut self, mut bytes: &[u8], at_ms: u64) -> Vec<StreamMessage> {
        let mut messages = Vec::new();
        while !bytes.is_empty() && !self.failed {
            if self.frame.is_none() {
                let used = self.read_header(bytes);
                bytes = &bytes[used..];
                if self.frame.is_none() {
                    continue;
                }
                // A frame with no payload ends here.
                if self
                    .frame
                    .as_ref()
                    .is_some_and(|frame| frame.remaining == 0)
                {
                    if let Some(message) = self.end_frame(at_ms) {
                        messages.push(message);
                    }
                }
                continue;
            }
            let Some(frame) = &mut self.frame else {
                continue;
            };
            let take = usize::try_from(frame.remaining)
                .unwrap_or(usize::MAX)
                .min(bytes.len());
            // Only what is looked at is copied: all of a control frame or a
            // compressed message, the part of a data message still kept.
            let looked_at = match &self.message {
                Some(message) if frame.opcode < 8 && !(message.compressed && !self.inflate_off) => {
                    MAX_MESSAGE_BYTES
                        .saturating_sub(message.data.len())
                        .min(take)
                }
                _ => take,
            };
            let mut payload = bytes[..looked_at].to_vec();
            if let Some(mask) = frame.mask {
                for (i, byte) in payload.iter_mut().enumerate() {
                    *byte ^= mask[((frame.offset + i as u64) % 4) as usize];
                }
            }
            frame.offset += take as u64;
            frame.remaining -= take as u64;
            let done = frame.remaining == 0;
            let opcode = frame.opcode;
            bytes = &bytes[take..];
            self.payload(opcode, &payload, take as u64);
            if done {
                if let Some(message) = self.end_frame(at_ms) {
                    messages.push(message);
                }
            }
        }
        messages
    }

    /// Reads header bytes; returns how many of `bytes` it used.
    fn read_header(&mut self, bytes: &[u8]) -> usize {
        let mut used = 0;
        loop {
            let needed = header_len(&self.header);
            if self.header.len() >= needed {
                break;
            }
            let Some(&byte) = bytes.get(used) else {
                return used;
            };
            self.header.push(byte);
            used += 1;
        }
        let header = std::mem::take(&mut self.header);
        let fin = header[0] & 0x80 != 0;
        let rsv1 = header[0] & 0x40 != 0;
        let opcode = header[0] & 0x0f;
        let masked = header[1] & 0x80 != 0;
        let (length, rest) = match header[1] & 0x7f {
            126 => (u64::from(u16::from_be_bytes([header[2], header[3]])), 4),
            127 => {
                let mut length = [0u8; 8];
                length.copy_from_slice(&header[2..10]);
                (u64::from_be_bytes(length), 10)
            }
            length => (u64::from(length), 2),
        };
        let mask = masked.then(|| {
            [
                header[rest],
                header[rest + 1],
                header[rest + 2],
                header[rest + 3],
            ]
        });
        let rsv23 = header[0] & 0x30 != 0;
        self.header = header;
        self.header.clear();
        let control = opcode >= 8;
        let valid = header_ok(opcode, fin, rsv1, length, rsv23)
            && (!rsv1 || self.deflate.is_some())
            // A continuation needs a message to continue, a new data frame
            // needs none in progress.
            && match opcode {
                0 => self.message.is_some(),
                1 | 2 => self.message.is_none(),
                _ => true,
            };
        if !valid {
            self.fail();
            return used;
        }
        if control {
            self.control.clear();
        } else if opcode != 0 {
            self.message = Some(Assembling {
                kind: if opcode == 1 {
                    MessageKind::Text
                } else {
                    MessageKind::Binary
                },
                compressed: rsv1,
                data: Vec::new(),
                size: 0,
            });
        }
        self.frame = Some(Frame {
            fin,
            opcode,
            mask,
            remaining: length,
            offset: 0,
        });
        used
    }

    /// `payload` is the start (or all) of `size` payload bytes.
    fn payload(&mut self, opcode: u8, payload: &[u8], size: u64) {
        if opcode >= 8 {
            self.control.extend_from_slice(payload);
            return;
        }
        let Some(message) = &mut self.message else {
            return;
        };
        if !message.compressed || self.inflate_off {
            message.size += size;
            keep(&mut message.data, payload);
            return;
        }
        self.inflate_into(payload);
    }

    /// Inflates `input` into the message being assembled. An inflate error,
    /// or more than [`MAX_INFLATED_BYTES`] out of one message, stops
    /// inflating for the direction.
    fn inflate_into(&mut self, mut input: &[u8]) {
        let Some(message) = &mut self.message else {
            return;
        };
        let inflate = self.inflate.get_or_insert_with(|| Decompress::new(false));
        let mut scratch = [0u8; 4096];
        loop {
            let before_in = inflate.total_in();
            let before_out = inflate.total_out();
            let status = inflate.decompress(input, &mut scratch, FlushDecompress::Sync);
            let read = (inflate.total_in() - before_in) as usize;
            let wrote = (inflate.total_out() - before_out) as usize;
            input = &input[read..];
            message.size += wrote as u64;
            keep(&mut message.data, &scratch[..wrote]);
            if status.is_err() || message.size > MAX_INFLATED_BYTES {
                self.inflate = None;
                self.inflate_off = true;
                return;
            }
            if matches!(status, Ok(Status::StreamEnd)) {
                // A final block ends the window; a later message starts a
                // new one.
                self.inflate = None;
                return;
            }
            let more_output = wrote == scratch.len();
            if (input.is_empty() && !more_output) || (read == 0 && wrote == 0) {
                return;
            }
        }
    }

    /// The current frame's payload is complete.
    fn end_frame(&mut self, at_ms: u64) -> Option<StreamMessage> {
        let frame = self.frame.take()?;
        if frame.opcode >= 8 {
            let data = std::mem::take(&mut self.control);
            return Some(self.control_message(frame.opcode, data, at_ms));
        }
        if !frame.fin {
            return None;
        }
        let compressed = self.message.as_ref()?.compressed;
        if compressed && !self.inflate_off {
            self.inflate_into(&DEFLATE_TAIL);
            if self.deflate == Some(true) {
                // No context takeover: the next message starts afresh.
                self.inflate = None;
            }
        }
        let message = self.message.take()?;
        let label = (compressed && self.inflate_off).then(|| STILL_COMPRESSED.to_string());
        Some(StreamMessage {
            index: 0,
            at_ms,
            direction: self.direction,
            kind: message.kind,
            label,
            id: None,
            code: None,
            data: message.data,
            size: message.size,
        })
    }

    fn control_message(&mut self, opcode: u8, data: Vec<u8>, at_ms: u64) -> StreamMessage {
        let size = data.len() as u64;
        let (kind, code, label, data) = match opcode {
            8 => {
                let code = (data.len() >= 2).then(|| u16::from_be_bytes([data[0], data[1]]));
                let reason = data
                    .get(2..)
                    .filter(|reason| !reason.is_empty())
                    .map(|reason| String::from_utf8_lossy(reason).into_owned());
                (MessageKind::Close, code, reason, Vec::new())
            }
            9 => (MessageKind::Ping, None, None, data),
            _ => (MessageKind::Pong, None, None, data),
        };
        StreamMessage {
            index: 0,
            at_ms,
            direction: self.direction,
            kind,
            label,
            id: None,
            code,
            data,
            size,
        }
    }

    fn fail(&mut self) {
        self.failed = true;
        self.frame = None;
        self.message = None;
        self.inflate = None;
        self.control = Vec::new();
        self.header = Vec::new();
    }
}

/// Bytes the header in `header` needs in all, from what it has so far.
fn header_len(header: &[u8]) -> usize {
    let Some(&second) = header.get(1) else {
        return 2;
    };
    let length = match second & 0x7f {
        126 => 2,
        127 => 8,
        _ => 0,
    };
    let mask = if second & 0x80 != 0 { 4 } else { 0 };
    2 + length + mask
}

/// RFC 6455 §5.2 and §5.5: known opcodes, RSV2/RSV3 clear, control frames
/// short and unfragmented, compression only on a message's first frame, a
/// 64-bit length with its top bit clear.
fn header_ok(opcode: u8, fin: bool, rsv1: bool, length: u64, rsv23: bool) -> bool {
    let known = matches!(opcode, 0 | 1 | 2 | 8 | 9 | 10);
    let control = opcode >= 8;
    known
        && !rsv23
        && length >> 63 == 0
        && (!control || (fin && length <= 125 && !rsv1))
        && !(opcode == 0 && rsv1)
}

/// Appends what fits of `bytes` under [`MAX_MESSAGE_BYTES`].
fn keep(data: &mut Vec<u8>, bytes: &[u8]) {
    let room = MAX_MESSAGE_BYTES.saturating_sub(data.len());
    data.extend_from_slice(&bytes[..bytes.len().min(room)]);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(text: &str) -> Vec<u8> {
        text.split_whitespace()
            .map(|byte| u8::from_str_radix(byte, 16).unwrap())
            .collect()
    }

    fn summary(messages: &[StreamMessage]) -> Vec<(MessageKind, String, u64)> {
        messages
            .iter()
            .map(|message| {
                (
                    message.kind,
                    String::from_utf8_lossy(&message.data).into_owned(),
                    message.size,
                )
            })
            .collect()
    }

    /// Every way of splitting `stream` in two gives the same messages.
    fn parse_any_split(stream: &[u8], deflate: Option<Deflate>) -> Vec<StreamMessage> {
        let whole = WsParser::new(Direction::Down, deflate).feed(stream, 1);
        for split in 1..stream.len() {
            let mut parser = WsParser::new(Direction::Down, deflate);
            let mut messages = parser.feed(&stream[..split], 1);
            messages.extend(parser.feed(&stream[split..], 1));
            assert_eq!(messages, whole, "split at {split}");
        }
        whole
    }

    #[test]
    fn parses_the_rfc_6455_examples() {
        // §5.7: unmasked and masked "Hello", a fragmented one, a ping, a
        // masked pong, and 256 and 65536 byte binary messages.
        let mut stream = hex("81 05 48 65 6c 6c 6f \
             81 85 37 fa 21 3d 7f 9f 4d 51 58 \
             01 03 48 65 6c 89 05 48 65 6c 6c 6f 80 02 6c 6f \
             8a 85 37 fa 21 3d 7f 9f 4d 51 58");
        stream.extend(hex("82 7e 01 00"));
        stream.extend(std::iter::repeat_n(b'a', 256));
        stream.extend(hex("82 7f 00 00 00 00 00 01 00 00"));
        stream.extend(std::iter::repeat_n(b'b', 65536));
        let mut parser = WsParser::new(Direction::Down, None);
        let mut messages = Vec::new();
        for piece in stream.chunks(7) {
            messages.extend(parser.feed(piece, 1));
        }
        let got = summary(&messages);
        assert_eq!(got.len(), 7);
        assert_eq!(got[0], (MessageKind::Text, "Hello".into(), 5));
        assert_eq!(got[1], (MessageKind::Text, "Hello".into(), 5));
        // The ping inside the fragmented message comes out first.
        assert_eq!(got[2], (MessageKind::Ping, "Hello".into(), 5));
        assert_eq!(got[3], (MessageKind::Text, "Hello".into(), 5));
        assert_eq!(got[4], (MessageKind::Pong, "Hello".into(), 5));
        assert_eq!(got[5].0, MessageKind::Binary);
        assert_eq!(got[5].2, 256);
        assert_eq!(got[6].2, 65536);
        assert_eq!(messages[6].data.len(), MAX_MESSAGE_BYTES);
        assert!(!parser.failed());
        assert_eq!(
            parse_any_split(&stream[..45], None).len(),
            5,
            "the short ones split anywhere"
        );
    }

    #[test]
    fn close_frames_carry_code_and_reason() {
        let messages = parse_any_split(&hex("88 06 03 e8 62 79 65 21"), None);
        assert_eq!(messages[0].kind, MessageKind::Close);
        assert_eq!(messages[0].code, Some(1000));
        assert_eq!(messages[0].label.as_deref(), Some("bye!"));
        let empty = WsParser::new(Direction::Up, None).feed(&hex("88 00"), 1);
        assert_eq!(empty[0].code, None);
    }

    #[test]
    fn inflates_the_rfc_7692_examples() {
        let deflate = Some(Deflate::default());
        // §7.2.3.1: "Hello" compressed; §7.2.3.2: the same twice, the second
        // using the shared window; §7.2.3.1 fragmented.
        let messages = parse_any_split(
            &hex("c1 07 f2 48 cd c9 c9 07 00 \
                 c1 05 f2 00 11 00 00 \
                 41 03 f2 48 cd 80 04 c9 c9 07 00"),
            deflate,
        );
        assert_eq!(
            summary(&messages),
            vec![
                (MessageKind::Text, "Hello".into(), 5),
                (MessageKind::Text, "Hello".into(), 5),
                (MessageKind::Text, "Hello".into(), 5),
            ]
        );
        assert!(messages.iter().all(|message| message.label.is_none()));
        // §7.2.3.3: an uncompressed block inside a compressed message.
        let stored = parse_any_split(&hex("c1 0b 00 05 00 fa ff 48 65 6c 6c 6f 00"), deflate);
        assert_eq!(
            summary(&stored),
            vec![(MessageKind::Text, "Hello".into(), 5)]
        );
    }

    #[test]
    fn no_context_takeover_resets_the_window() {
        // The second message refers back into the first one's window.
        let stream = hex("c1 07 f2 48 cd c9 c9 07 00 c1 05 f2 00 11 00 00");
        let shared = WsParser::new(Direction::Down, Some(Deflate::default())).feed(&stream, 1);
        assert_eq!(shared[1].data, b"Hello");
        let reset = Some(Deflate {
            server_no_context_takeover: true,
            client_no_context_takeover: false,
        });
        let messages = WsParser::new(Direction::Down, reset).feed(&stream, 1);
        assert_eq!(messages[0].data, b"Hello");
        assert_ne!(messages[1].data, b"Hello", "the window was reset");
        assert_eq!(messages[1].label.as_deref(), Some(STILL_COMPRESSED));
        // The client's own setting applies to what the app sends.
        let up = WsParser::new(Direction::Up, reset).feed(&stream, 1);
        assert_eq!(up[1].data, b"Hello");
        assert_eq!(
            Deflate::from_response(
                "permessage-deflate; server_no_context_takeover; client_max_window_bits=10"
            ),
            reset
        );
        assert_eq!(Deflate::from_response("x-webkit-deflate-frame"), None);
    }

    #[test]
    fn a_compression_bomb_stops_inflating_but_not_parsing() {
        use std::io::Write;
        let mut encoder =
            flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::best());
        encoder.write_all(&vec![0u8; 8 * 1024 * 1024]).unwrap();
        let body = encoder.finish().unwrap();
        let mut stream = vec![0xc2, 0x7f];
        stream.extend((body.len() as u64).to_be_bytes());
        stream.extend(&body);
        stream.extend(hex("81 05 48 65 6c 6c 6f"));
        let mut parser = WsParser::new(Direction::Down, Some(Deflate::default()));
        let messages = parser.feed(&stream, 1);
        assert_eq!(messages.len(), 2);
        assert_eq!(messages[0].data.len(), MAX_MESSAGE_BYTES);
        assert!(messages[0].size <= MAX_INFLATED_BYTES + 4096);
        assert_eq!(messages[0].label.as_deref(), Some(STILL_COMPRESSED));
        assert_eq!(messages[1].data, b"Hello");
        assert!(parser.inflate.is_none());
    }

    #[test]
    fn protocol_errors_stop_parsing() {
        for bad in [
            "83 00",       // unknown opcode
            "09 00",       // fragmented ping
            "89 7e 00 7e", // long ping
            "80 01 41",    // continuation of nothing
            "c1 01 00",    // RSV1 without the extension
            "b1 00",       // RSV2
        ] {
            let mut parser = WsParser::new(Direction::Down, None);
            assert!(parser.feed(&hex(bad), 1).is_empty(), "{bad}");
            assert!(parser.failed(), "{bad}");
            assert!(parser.feed(&hex("81 01 41"), 1).is_empty());
        }
        let mut parser = WsParser::new(Direction::Down, None);
        parser.feed(&hex("01 01 41"), 1);
        parser.feed(&hex("01 01 41"), 1);
        assert!(parser.failed(), "a new message inside a fragmented one");
    }
}
