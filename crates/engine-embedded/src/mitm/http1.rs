//! Minimal HTTP/1.1 framing for decrypted MITM flows: message heads, bodies
//! framed by `Content-Length`, chunked coding or connection close, all with
//! hard size limits. Bytes read past a message stay buffered for the next one.
//!
//! Heads are read the way servers and browsers read them, not only the way
//! RFC 9112 writes them: lines may end in a bare LF, an obsolete folded
//! line continues the header before it, and header bytes that are not
//! UTF-8 (a GBK or Latin-1 file name in `Content-Disposition`) are kept
//! exactly: each such byte becomes one character of [`ESCAPE_BASE`]` +
//! byte` in the `String`, and [`Head::encode`] writes it back as that byte,
//! so a head the rules do not touch goes on as it came. [`display`] shows
//! those bytes as Latin-1 for capture. A head that still cannot be read is
//! an `InvalidData` error with its bytes left buffered, so the caller can
//! relay the connection on unchanged.

use std::borrow::Cow;

use std::io;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Largest message head (start line plus headers).
pub const MAX_HEAD_BYTES: usize = 64 * 1024;
const MAX_HEADERS: usize = 128;
const READ_CHUNK: usize = 8 * 1024;
/// A byte of a head that is not UTF-8 is held as the character
/// `ESCAPE_BASE + byte` (U+F780 to U+F7FF, private use, which no header
/// carries) and written back as the byte.
pub const ESCAPE_BASE: u32 = 0xF700;

pub struct Head {
    pub start_line: String,
    pub headers: Vec<(String, String)>,
}

impl Head {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }

    pub fn has_token(&self, name: &str, token: &str) -> bool {
        self.headers
            .iter()
            .filter(|(key, _)| key.eq_ignore_ascii_case(name))
            .flat_map(|(_, value)| value.split(','))
            .any(|item| item.trim().eq_ignore_ascii_case(token))
    }

    /// How the body that follows this head is delimited. Repeated
    /// `Content-Length` values (`5, 5`, or the header twice) are one length
    /// when they agree (RFC 9110 section 8.6); lengths that disagree are an
    /// error, since the two ends could read different messages.
    pub fn framing(&self) -> io::Result<Framing> {
        if self.has_token("Transfer-Encoding", "chunked") {
            return Ok(Framing::Chunked);
        }
        if self.header("Transfer-Encoding").is_some() {
            return Err(invalid("unsupported transfer coding"));
        }
        let mut length = None;
        for value in self
            .headers
            .iter()
            .filter(|(key, _)| key.eq_ignore_ascii_case("Content-Length"))
            .map(|(_, value)| value)
        {
            for item in value.split(',') {
                let item = item.trim();
                if item.is_empty() || !item.bytes().all(|b| b.is_ascii_digit()) {
                    return Err(invalid("invalid content length"));
                }
                let parsed = item
                    .parse::<usize>()
                    .map_err(|_| invalid("invalid content length"))?;
                if length.is_some_and(|length| length != parsed) {
                    return Err(invalid("conflicting content lengths"));
                }
                length = Some(parsed);
            }
        }
        Ok(Framing::Length(length.unwrap_or(0)))
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(256);
        encode_text(&self.start_line, &mut bytes);
        bytes.extend_from_slice(b"\r\n");
        for (key, value) in &self.headers {
            encode_text(key, &mut bytes);
            bytes.extend_from_slice(b": ");
            encode_text(value, &mut bytes);
            bytes.extend_from_slice(b"\r\n");
        }
        bytes.extend_from_slice(b"\r\n");
        bytes
    }
}

fn is_escape(c: char) -> bool {
    (ESCAPE_BASE + 0x80..=ESCAPE_BASE + 0xFF).contains(&u32::from(c))
}

/// `bytes` as a `String`, each byte that is not part of valid UTF-8 held
/// as an escape character (see [`ESCAPE_BASE`]).
fn decode_text(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len());
    let mut rest = bytes;
    loop {
        match std::str::from_utf8(rest) {
            Ok(text) => {
                out.push_str(text);
                return out;
            }
            Err(error) => {
                let valid = error.valid_up_to();
                out.push_str(std::str::from_utf8(&rest[..valid]).unwrap_or_default());
                let bad = error.error_len().unwrap_or(rest.len() - valid);
                for &byte in &rest[valid..valid + bad] {
                    out.push(char::from_u32(ESCAPE_BASE + u32::from(byte)).unwrap_or('\u{FFFD}'));
                }
                rest = &rest[valid + bad..];
            }
        }
    }
}

/// Writes `text` as bytes, escape characters back as the bytes they hold.
fn encode_text(text: &str, out: &mut Vec<u8>) {
    if !text.chars().any(is_escape) {
        out.extend_from_slice(text.as_bytes());
        return;
    }
    for c in text.chars() {
        if is_escape(c) {
            out.push((u32::from(c) - ESCAPE_BASE) as u8);
        } else {
            let mut buf = [0u8; 4];
            out.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
        }
    }
}

/// `text` with the bytes escaped by the head parser shown as Latin-1, for
/// capture and logs.
pub fn display(text: &str) -> Cow<'_, str> {
    if !text.chars().any(is_escape) {
        return Cow::Borrowed(text);
    }
    Cow::Owned(
        text.chars()
            .map(|c| {
                if is_escape(c) {
                    char::from((u32::from(c) - ESCAPE_BASE) as u8)
                } else {
                    c
                }
            })
            .collect(),
    )
}

/// `headers` as [`display`] shows them.
pub fn display_headers(headers: &[(String, String)]) -> Vec<(String, String)> {
    headers
        .iter()
        .map(|(name, value)| (display(name).into_owned(), display(value).into_owned()))
        .collect()
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Framing {
    Length(usize),
    Chunked,
    /// Response body that ends when the server closes the connection.
    UntilClose,
}

pub enum Body {
    Complete(Vec<u8>),
    /// Larger than the limit (or, for a chunked body, framed with more
    /// extension or trailer bytes than are held): the message is relayed on
    /// unread from here.
    TooLarge {
        /// The bytes consumed so far, still framed as on the wire, to be
        /// sent on first.
        raw: Vec<u8>,
        /// The start of the body they carry without chunk framing, at most
        /// [`crate::capture::MAX_HTTP_BODY_BYTES`], for capture.
        body: Vec<u8>,
        /// Body bytes read so far (the length named, for a
        /// `Content-Length` body).
        size: u64,
    },
}

impl Body {
    fn too_large(raw: Vec<u8>, mut body: Vec<u8>) -> Self {
        let size = body.len() as u64;
        body.truncate(crate::capture::MAX_HTTP_BODY_BYTES);
        Self::TooLarge { raw, body, size }
    }
}

/// A stream with a read buffer.
pub struct Conn<S> {
    io: S,
    buf: Vec<u8>,
    /// While set, [`Conn::copy_body`] keeps the first bytes of the body it
    /// copies (without chunk framing), for capture.
    tap: Option<Tap>,
}

/// Kept as the pieces read and joined once at the end, so a body costs one
/// allocation of its kept size instead of a chain of ever larger buffers.
struct Tap {
    pieces: Vec<Vec<u8>>,
    kept: usize,
    size: u64,
    limit: usize,
}

impl Tap {
    fn keep(&mut self, bytes: &[u8]) {
        self.size = self.size.saturating_add(bytes.len() as u64);
        let take = bytes.len().min(self.limit.saturating_sub(self.kept));
        if take > 0 {
            self.pieces.push(bytes[..take].to_vec());
            self.kept += take;
        }
    }

    fn into_data(self) -> Vec<u8> {
        let mut data = Vec::with_capacity(self.kept);
        for piece in self.pieces {
            data.extend_from_slice(&piece);
        }
        data
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> Conn<S> {
    pub fn new(io: S, prefix: Vec<u8>) -> Self {
        Self {
            io,
            buf: prefix,
            tap: None,
        }
    }

    /// Keeps the first `limit` bytes of the next bodies [`Conn::copy_body`]
    /// copies, until [`Conn::take_tap`].
    pub fn start_tap(&mut self, limit: usize) {
        self.tap = Some(Tap {
            pieces: Vec::new(),
            kept: 0,
            size: 0,
            limit,
        });
    }

    /// The bytes kept since [`Conn::start_tap`] and the body length seen.
    pub fn take_tap(&mut self) -> Option<(Vec<u8>, u64)> {
        self.tap.take().map(|tap| {
            let size = tap.size;
            (tap.into_data(), size)
        })
    }

    /// The stream and any bytes read but not consumed.
    pub fn into_parts(self) -> (S, Vec<u8>) {
        (self.io, self.buf)
    }

    pub async fn write_all(&mut self, bytes: &[u8]) -> io::Result<()> {
        self.io.write_all(bytes).await?;
        self.io.flush().await
    }

    /// Reads one message head. `Ok(None)` means the peer closed cleanly
    /// between messages.
    /// A head that cannot be read is an `InvalidData` error and its bytes
    /// stay buffered, so [`Conn::into_parts`] still has them.
    pub async fn read_head(&mut self) -> io::Result<Option<Head>> {
        loop {
            if let Some((end, consumed)) = head_end(&self.buf) {
                let head = parse_head(&self.buf[..end])?;
                self.buf.drain(..consumed);
                return Ok(Some(head));
            }
            if self.buf.len() > MAX_HEAD_BYTES {
                return Err(invalid("message head is too large"));
            }
            if self.fill().await? == 0 {
                return if self.buf.is_empty() {
                    Ok(None)
                } else {
                    Err(io::ErrorKind::UnexpectedEof.into())
                };
            }
        }
    }

    pub async fn read_body(&mut self, framing: Framing, limit: usize) -> io::Result<Body> {
        match framing {
            Framing::Length(length) => {
                if length > limit {
                    return Ok(Body::TooLarge {
                        raw: Vec::new(),
                        body: Vec::new(),
                        size: length as u64,
                    });
                }
                while self.buf.len() < length {
                    if self.fill().await? == 0 {
                        return Err(io::ErrorKind::UnexpectedEof.into());
                    }
                }
                Ok(Body::Complete(self.buf.drain(..length).collect()))
            }
            Framing::Chunked => self.read_chunked(limit).await,
            Framing::UntilClose => loop {
                if self.buf.len() > limit {
                    let raw = std::mem::take(&mut self.buf);
                    let body = raw[..raw.len().min(crate::capture::MAX_HTTP_BODY_BYTES)].to_vec();
                    return Ok(Body::TooLarge {
                        size: raw.len() as u64,
                        raw,
                        body,
                    });
                }
                if self.fill().await? == 0 {
                    return Ok(Body::Complete(std::mem::take(&mut self.buf)));
                }
            },
        }
    }

    /// A chunked body, whole when its data fits `limit`. The framing it
    /// is read with (size lines with their extensions, trailers) is held
    /// too, to be sent on as it came if the body turns out too large, so
    /// it is bounded as well: all held bytes stay within `limit` plus
    /// [`MAX_HEAD_BYTES`], and trailers within [`MAX_HEADERS`] lines;
    /// past either the body is [`Body::TooLarge`] and relayed unread.
    async fn read_chunked(&mut self, limit: usize) -> io::Result<Body> {
        let mut raw = Vec::new();
        let mut body = Vec::new();
        let held = limit.saturating_add(MAX_HEAD_BYTES);
        loop {
            let line = self.read_line(&mut raw).await?;
            let size = chunk_size(&line)?;
            if raw.len() > held {
                return Ok(Body::too_large(raw, body));
            }
            if size == 0 {
                // Trailers end with an empty line.
                let mut trailers = 0usize;
                while !self.read_line(&mut raw).await?.is_empty() {
                    trailers += 1;
                    if trailers > MAX_HEADERS || raw.len() > held {
                        return Ok(Body::too_large(raw, body));
                    }
                }
                return Ok(Body::Complete(body));
            }
            // `size` is checked against what is left before anything is
            // added to it, so nothing below can overflow.
            if size > limit.saturating_sub(body.len()) {
                return Ok(Body::too_large(raw, body));
            }
            while self.buf.len() < size + 2 {
                if self.fill().await? == 0 {
                    return Err(io::ErrorKind::UnexpectedEof.into());
                }
            }
            raw.extend_from_slice(&self.buf[..size + 2]);
            body.extend_from_slice(&self.buf[..size]);
            if &self.buf[size..size + 2] != b"\r\n" {
                return Err(invalid("chunk is not terminated"));
            }
            self.buf.drain(..size + 2);
        }
    }

    /// Forwards one body to `dst` as it arrives, framed as on the wire, so
    /// a body nobody rewrites is never held whole. Bytes past the body stay
    /// buffered for the next message.
    pub async fn copy_body<W>(&mut self, framing: Framing, dst: &mut Conn<W>) -> io::Result<()>
    where
        W: AsyncRead + AsyncWrite + Unpin,
    {
        self.copy_body_with(framing, dst, |_| {}, false).await
    }

    /// [`Conn::copy_body`] for a stream (server-sent events): each piece of
    /// the body is flushed to `dst` as it arrives and then handed to
    /// `observe` (without chunk framing).
    pub async fn copy_body_observed<W, F>(
        &mut self,
        framing: Framing,
        dst: &mut Conn<W>,
        observe: F,
    ) -> io::Result<()>
    where
        W: AsyncRead + AsyncWrite + Unpin,
        F: FnMut(&[u8]),
    {
        self.copy_body_with(framing, dst, observe, true).await
    }

    async fn copy_body_with<W, F>(
        &mut self,
        framing: Framing,
        dst: &mut Conn<W>,
        mut observe: F,
        flush: bool,
    ) -> io::Result<()>
    where
        W: AsyncRead + AsyncWrite + Unpin,
        F: FnMut(&[u8]),
    {
        let observe = &mut observe;
        match framing {
            Framing::Length(length) => self.copy_exact(length, dst, Some(observe), flush).await?,
            Framing::Chunked => loop {
                let mut line = Vec::new();
                let size = chunk_size(&self.read_line(&mut line).await?)?;
                dst.io.write_all(&line).await?;
                if size == 0 {
                    loop {
                        let mut trailer = Vec::new();
                        let done = self.read_line(&mut trailer).await?.is_empty();
                        dst.io.write_all(&trailer).await?;
                        if done {
                            break;
                        }
                    }
                    break;
                }
                self.copy_exact(size, dst, Some(&mut *observe), false)
                    .await?;
                self.copy_exact::<W, F>(2, dst, None, flush).await?;
            },
            Framing::UntilClose => loop {
                if !self.buf.is_empty() {
                    dst.io.write_all(&self.buf).await?;
                    if flush {
                        dst.io.flush().await?;
                    }
                    if let Some(tap) = &mut self.tap {
                        tap.keep(&self.buf);
                    }
                    observe(&self.buf);
                    self.buf.clear();
                }
                if self.fill().await? == 0 {
                    break;
                }
            },
        }
        dst.io.flush().await
    }

    /// Copies `remaining` bytes; body bytes (those with an `observe`) are
    /// also tapped and observed.
    async fn copy_exact<W, F>(
        &mut self,
        mut remaining: usize,
        dst: &mut Conn<W>,
        mut observe: Option<&mut F>,
        flush: bool,
    ) -> io::Result<()>
    where
        W: AsyncRead + AsyncWrite + Unpin,
        F: FnMut(&[u8]),
    {
        while remaining > 0 {
            if self.buf.is_empty() && self.fill().await? == 0 {
                return Err(io::ErrorKind::UnexpectedEof.into());
            }
            let take = remaining.min(self.buf.len());
            dst.io.write_all(&self.buf[..take]).await?;
            if let Some(observe) = observe.as_deref_mut() {
                if let Some(kept) = &mut self.tap {
                    kept.keep(&self.buf[..take]);
                }
                observe(&self.buf[..take]);
            }
            if flush {
                dst.io.flush().await?;
            }
            self.buf.drain(..take);
            remaining -= take;
        }
        Ok(())
    }

    /// One CRLF-terminated line without the CRLF; the raw bytes go to `raw`.
    async fn read_line(&mut self, raw: &mut Vec<u8>) -> io::Result<String> {
        loop {
            if let Some(end) = find(&self.buf, b"\r\n") {
                let line = String::from_utf8_lossy(&self.buf[..end]).into_owned();
                raw.extend_from_slice(&self.buf[..end + 2]);
                self.buf.drain(..end + 2);
                return Ok(line);
            }
            if self.buf.len() > MAX_HEAD_BYTES {
                return Err(invalid("chunk line is too long"));
            }
            if self.fill().await? == 0 {
                return Err(io::ErrorKind::UnexpectedEof.into());
            }
        }
    }

    async fn fill(&mut self) -> io::Result<usize> {
        let start = self.buf.len();
        self.buf.resize(start + READ_CHUNK, 0);
        let read = self.io.read(&mut self.buf[start..]).await;
        let n = *read.as_ref().unwrap_or(&0);
        self.buf.truncate(start + n);
        read
    }
}

/// The size on a chunk size line: hexadecimal digits only (no sign, at
/// most 16 of them), before an optional extension. A line is at most
/// [`MAX_HEAD_BYTES`] (see [`Conn::read_line`]) and the lines a held body
/// collects are bounded in [`Conn::read_chunked`].
fn chunk_size(line: &str) -> io::Result<usize> {
    let size_text = line.split(';').next().unwrap_or("");
    let size_text = size_text.trim_matches([' ', '\t']);
    if size_text.is_empty()
        || size_text.len() > 16
        || !size_text.bytes().all(|b| b.is_ascii_hexdigit())
    {
        return Err(invalid("invalid chunk size"));
    }
    usize::from_str_radix(size_text, 16).map_err(|_| invalid("invalid chunk size"))
}

/// Where the head in `buf` ends: its length up to the empty line, and the
/// bytes it takes with that line. Lines end in CRLF or a bare LF.
fn head_end(buf: &[u8]) -> Option<(usize, usize)> {
    let mut line_start = 0;
    let mut seen_line = false;
    for (index, &byte) in buf.iter().enumerate() {
        if byte != b'\n' {
            continue;
        }
        let line = &buf[line_start..index];
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        if line.is_empty() {
            // Empty lines before the start line are skipped (RFC 9112
            // section 2.2).
            if seen_line {
                return Some((line_start, index + 1));
            }
        } else {
            seen_line = true;
        }
        line_start = index + 1;
    }
    None
}

fn is_token(name: &str) -> bool {
    !name.is_empty()
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b))
}

fn parse_head(bytes: &[u8]) -> io::Result<Head> {
    let mut lines = bytes
        .split(|&b| b == b'\n')
        .map(|line| line.strip_suffix(b"\r").unwrap_or(line))
        .skip_while(|line| line.is_empty());
    let start_line = decode_text(lines.next().unwrap_or(&[]));
    if start_line.trim().is_empty() {
        return Err(invalid("empty start line"));
    }
    let mut headers: Vec<(String, String)> = Vec::new();
    for line in lines {
        if line.is_empty() {
            continue;
        }
        if line[0] == b' ' || line[0] == b'\t' {
            // An obsolete folded line continues the header before it
            // (RFC 9112 section 5.2): joined with one space.
            let Some((_, value)) = headers.last_mut() else {
                return Err(invalid("folded line before any header"));
            };
            let more = decode_text(line);
            let more = more.trim();
            if !more.is_empty() {
                if !value.is_empty() {
                    value.push(' ');
                }
                value.push_str(more);
            }
            continue;
        }
        if headers.len() == MAX_HEADERS {
            return Err(invalid("too many headers"));
        }
        let colon = line
            .iter()
            .position(|&b| b == b':')
            .ok_or_else(|| invalid("malformed header"))?;
        // A name is a token: anything else could be read as another header
        // by the next hop. Spaces before the colon are dropped, as before.
        let key = std::str::from_utf8(&line[..colon])
            .map_err(|_| invalid("malformed header name"))?
            .trim_end_matches([' ', '\t']);
        if !is_token(key) {
            return Err(invalid("malformed header name"));
        }
        let value = decode_text(&line[colon + 1..]);
        headers.push((key.to_string(), value.trim_matches([' ', '\t']).to_string()));
    }
    Ok(Head {
        start_line,
        headers,
    })
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn buffered(bytes: &[u8]) -> Conn<tokio::io::DuplexStream> {
        let (near, _far) = tokio::io::duplex(64);
        Conn::new(near, bytes.to_vec())
    }

    #[tokio::test]
    async fn reads_heads_and_length_bodies_back_to_back() {
        let mut conn = buffered(
            b"POST /a HTTP/1.1\r\nHost: x\r\nContent-Length: 3\r\n\r\nabcGET /b HTTP/1.1\r\n\r\n",
        );
        let head = conn.read_head().await.unwrap().unwrap();
        assert_eq!(head.start_line, "POST /a HTTP/1.1");
        assert_eq!(head.header("host"), Some("x"));
        let Body::Complete(body) = conn.read_body(head.framing().unwrap(), 16).await.unwrap()
        else {
            panic!("body should fit");
        };
        assert_eq!(body, b"abc");
        let next = conn.read_head().await.unwrap().unwrap();
        assert_eq!(next.start_line, "GET /b HTTP/1.1");
        assert_eq!(next.framing().unwrap(), Framing::Length(0));
    }

    #[tokio::test]
    async fn decodes_chunked_bodies_and_reports_oversize() {
        let mut conn = buffered(b"4\r\nwiki\r\n5;x=1\r\npedia\r\n0\r\nTrailer: y\r\n\r\nrest");
        let Body::Complete(body) = conn.read_body(Framing::Chunked, 64).await.unwrap() else {
            panic!("body should fit");
        };
        assert_eq!(body, b"wikipedia");
        assert_eq!(conn.into_parts().1, b"rest");

        let mut conn = buffered(b"4\r\nwiki\r\n5\r\npedia\r\n0\r\n\r\n");
        let Body::TooLarge { raw, body, size } = conn.read_body(Framing::Chunked, 6).await.unwrap()
        else {
            panic!("body should be too large");
        };
        assert_eq!(raw, b"4\r\nwiki\r\n5\r\n");
        // What capture keeps is the body without its chunk framing.
        assert_eq!(body, b"wiki");
        assert_eq!(size, 4);
    }

    #[tokio::test]
    async fn chunk_sizes_that_would_overflow_are_too_large_not_a_panic() {
        let mut conn = buffered(b"1\r\nA\r\nffffffffffffffff\r\nX\r\n");
        let Body::TooLarge { raw, .. } = conn.read_body(Framing::Chunked, 1024).await.unwrap()
        else {
            panic!("a chunk past the limit is too large");
        };
        assert_eq!(raw, b"1\r\nA\r\nffffffffffffffff\r\n");
        // Signs, empty and over-long sizes are not sizes.
        for line in ["+5", "", "-1", "00000000000000001", "0x5"] {
            assert!(chunk_size(line).is_err(), "{line:?}");
        }
        assert_eq!(chunk_size("1a;name=value").unwrap(), 26);
    }

    #[tokio::test]
    async fn chunk_framing_held_for_relaying_stays_bounded() {
        // Endless trailers after the last chunk.
        let mut bytes = b"1\r\nA\r\n0\r\n".to_vec();
        for _ in 0..(MAX_HEADERS + 10) {
            bytes.extend_from_slice(b"X-Trailer: aaaaaaaa\r\n");
        }
        let mut conn = buffered(&bytes);
        let Body::TooLarge { raw, body, .. } =
            conn.read_body(Framing::Chunked, 1024).await.unwrap()
        else {
            panic!("too many trailers to hold");
        };
        assert_eq!(body, b"A");
        assert!(bytes.starts_with(&raw), "raw is what was read, as it came");
        assert!(raw.len() < bytes.len());

        // One-byte chunks with long extensions: held up to the limit plus
        // one head's worth, then relayed on as read.
        let extension = format!(";x={}", "e".repeat(60 * 1024));
        let mut bytes = Vec::new();
        for _ in 0..8 {
            bytes.extend_from_slice(format!("1{extension}\r\nA\r\n").as_bytes());
        }
        let mut conn = buffered(&bytes);
        let Body::TooLarge { raw, .. } = conn.read_body(Framing::Chunked, 1024).await.unwrap()
        else {
            panic!("the framing is too large to hold");
        };
        assert!(raw.len() <= 1024 + MAX_HEAD_BYTES + extension.len() + 8);
        assert!(bytes.starts_with(&raw));
        let (_, rest) = conn.into_parts();
        assert_eq!([raw.as_slice(), rest.as_slice()].concat(), bytes);
    }

    #[tokio::test]
    async fn heads_with_bytes_that_are_not_utf8_go_on_unchanged() {
        let head = b"HTTP/1.1 200 OK\r\nContent-Disposition: attachment; filename=\"\xb1\xa8\xb1\xed.xls\"\r\nContent-Length: 0\r\n\r\n";
        let mut conn = buffered(head);
        let parsed = conn.read_head().await.unwrap().unwrap();
        assert_eq!(parsed.encode(), head.to_vec());
        assert_eq!(
            display(parsed.header("content-disposition").unwrap()),
            "attachment; filename=\"\u{b1}\u{a8}\u{b1}\u{ed}.xls\""
        );
        // A genuine UTF-8 value stays UTF-8.
        let head = "HTTP/1.1 200 OK\r\nX-Name: 报表\r\n\r\n".as_bytes();
        let mut conn = buffered(head);
        let parsed = conn.read_head().await.unwrap().unwrap();
        assert_eq!(parsed.header("x-name"), Some("报表"));
        assert_eq!(parsed.encode(), head.to_vec());
    }

    #[tokio::test]
    async fn heads_with_bare_line_feeds_and_folded_lines_are_read() {
        let mut conn =
            buffered(b"\r\nHTTP/1.1 200 OK\nX-A: 1\n  continued\nContent-Length: 2\n\nokNEXT");
        let head = conn.read_head().await.unwrap().unwrap();
        assert_eq!(head.start_line, "HTTP/1.1 200 OK");
        assert_eq!(head.header("x-a"), Some("1 continued"));
        let Body::Complete(body) = conn.read_body(head.framing().unwrap(), 16).await.unwrap()
        else {
            panic!("body should fit");
        };
        assert_eq!(body, b"ok");
        assert_eq!(conn.into_parts().1, b"NEXT");
    }

    #[tokio::test]
    async fn heads_that_cannot_be_read_stay_buffered() {
        let bytes = b"GET / HTTP/1.1\r\nBad Name: x\r\n\r\n";
        let mut conn = buffered(bytes);
        let error = conn.read_head().await.err().unwrap();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert_eq!(conn.into_parts().1, bytes.to_vec());
    }

    #[test]
    fn repeated_content_lengths_must_agree() {
        let head = parse_head(b"HTTP/1.1 200 OK\r\nContent-Length: 5, 5").unwrap();
        assert_eq!(head.framing().unwrap(), Framing::Length(5));
        let head =
            parse_head(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nContent-Length: 5").unwrap();
        assert_eq!(head.framing().unwrap(), Framing::Length(5));
        let head =
            parse_head(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nContent-Length: 6").unwrap();
        assert!(head.framing().is_err());
        let head = parse_head(b"HTTP/1.1 200 OK\r\nContent-Length: +5").unwrap();
        assert!(head.framing().is_err());
    }

    #[tokio::test]
    async fn taps_keep_body_bytes_without_chunk_framing() {
        let (out, _far) = tokio::io::duplex(1024);
        let mut dst = Conn::new(out, Vec::new());
        let mut conn = buffered(b"4\r\nwiki\r\n5\r\npedia\r\n0\r\n\r\n");
        conn.start_tap(6);
        conn.copy_body(Framing::Chunked, &mut dst).await.unwrap();
        assert_eq!(conn.take_tap(), Some((b"wikipe".to_vec(), 9)));
        assert_eq!(conn.take_tap(), None);
    }

    #[tokio::test]
    async fn copies_bodies_as_framed_and_keeps_what_follows() {
        let (out, mut far) = tokio::io::duplex(1024);
        let mut dst = Conn::new(out, Vec::new());
        let mut conn = buffered(b"abcdeNEXT");
        conn.copy_body(Framing::Length(5), &mut dst).await.unwrap();
        let mut conn2 = buffered(b"4\r\nwiki\r\n0\r\nTrailer: y\r\n\r\nREST");
        conn2.copy_body(Framing::Chunked, &mut dst).await.unwrap();
        drop(dst);
        let mut copied = Vec::new();
        far.read_to_end(&mut copied).await.unwrap();
        assert_eq!(copied, b"abcde4\r\nwiki\r\n0\r\nTrailer: y\r\n\r\n");
        assert_eq!(conn.into_parts().1, b"NEXT");
        assert_eq!(conn2.into_parts().1, b"REST");
    }

    #[test]
    fn rejects_bad_framing() {
        let head = parse_head(b"HTTP/1.1 200 OK\r\nContent-Length: x").unwrap();
        assert!(head.framing().is_err());
        assert!(parse_head(b"GET / HTTP/1.1\r\nno colon").is_err());
    }
}
