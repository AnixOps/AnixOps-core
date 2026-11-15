//! `Content-Encoding` undone for inspection, export and body rewrites:
//! `gzip` (`x-gzip`), `deflate` (zlib or raw), `br` and `zstd`, several in a
//! row (`gzip, br`) undone last first. All decoders are pure Rust.
//!
//! Decoding never trusts the stream's own sizes:
//!
//! - Output stops at [`DecodeLimits::output`] and is marked `truncated`, so a
//!   small body that inflates to gigabytes (a decompression bomb) costs at
//!   most the limit.
//! - `br` and `zstd` keep a window of past output whose size the stream
//!   names in its header, allocated up front. A window over
//!   [`DecodeLimits::window`] is refused before anything is allocated; zstd
//!   windows over 8 MiB are refused everywhere, as RFC 9659 allows HTTP
//!   senders no more. Inside the iOS Network Extension
//!   ([`DecodeLimits::EXTENSION`]) the window cap is 4 MiB, which covers
//!   brotli's default 22-bit window and zstd's default levels.
//! - A body capture cut short (`complete: false`) decodes as far as it goes
//!   and is marked `truncated`; a complete body that fails to decode is an
//!   error, and the caller shows the bytes as they came.

use std::io::{self, Read};

use super::MAX_HTTP_BODY_BYTES;

/// How much one decode may produce and hold.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DecodeLimits {
    /// Decoded bytes kept; more marks the result `truncated`.
    pub output: usize,
    /// Largest `br` or `zstd` window accepted.
    pub window: usize,
}

/// zstd windows HTTP allows (RFC 9659 section 3).
pub const ZSTD_HTTP_MAX_WINDOW: usize = 8 * 1024 * 1024;
/// Brotli's largest standard window (RFC 7932: 2^24 - 16).
const BROTLI_MAX_WINDOW: usize = (1 << 24) - 16;

impl DecodeLimits {
    /// Inside the packet tunnel, where the iOS Network Extension has about
    /// 50 MB: as much text as capture keeps of a body, 4 MiB windows.
    pub const EXTENSION: Self = Self {
        output: MAX_HTTP_BODY_BYTES,
        window: 4 * 1024 * 1024,
    };
    /// In the app's own process (inspectors): 16 MiB of text, every
    /// standard window.
    pub const APP: Self = Self {
        output: 16 * 1024 * 1024,
        window: BROTLI_MAX_WINDOW,
    };
}

/// A decoded body.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Decoded {
    pub data: Vec<u8>,
    /// Output stopped at the limit, or the input was cut short.
    pub truncated: bool,
    /// The codings undone, in the header's order; empty for `identity` or
    /// no header.
    pub codings: Vec<String>,
}

/// Why a body could not be decoded.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DecodeError {
    /// A coding this decoder does not know (`compress`, `dcb`, ...).
    Unsupported(String),
    /// The stream asks for a window over the limit.
    WindowTooLarge { coding: &'static str, window: u64 },
    /// zstd with a dictionary, which HTTP `zstd` never uses.
    Dictionary,
    /// The complete body is not valid in that coding.
    Corrupt(&'static str),
}

impl std::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unsupported(coding) => write!(f, "unsupported content coding {coding}"),
            Self::WindowTooLarge { coding, window } => {
                write!(f, "{coding} window of {window} bytes is over the limit")
            }
            Self::Dictionary => write!(f, "zstd with a dictionary is not supported"),
            Self::Corrupt(coding) => write!(f, "body is not valid {coding}"),
        }
    }
}

impl std::error::Error for DecodeError {}

/// The codings a `Content-Encoding` value names, in order, lowercased,
/// `identity` left out.
pub fn codings(content_encoding: &str) -> Vec<String> {
    content_encoding
        .split(',')
        .map(|coding| coding.trim().to_ascii_lowercase())
        .filter(|coding| !coding.is_empty() && coding != "identity")
        .collect()
}

/// Whether every coding in `content_encoding` can be undone here.
pub fn supported(content_encoding: &str) -> bool {
    codings(content_encoding)
        .iter()
        .all(|coding| Coding::parse(coding).is_some())
}

/// Undoes `content_encoding` on `data`. `complete` is false when capture
/// kept only the start of the body.
pub fn decode_body(
    data: &[u8],
    content_encoding: &str,
    complete: bool,
    limits: DecodeLimits,
) -> Result<Decoded, DecodeError> {
    let names = codings(content_encoding);
    let mut steps = Vec::with_capacity(names.len());
    for name in &names {
        steps.push(Coding::parse(name).ok_or_else(|| DecodeError::Unsupported(name.clone()))?);
    }
    let mut current: Option<Vec<u8>> = None;
    let mut truncated = !complete;
    for coding in steps.into_iter().rev() {
        let input = current.as_deref().unwrap_or(data);
        let (out, cut) = coding.decode(input, !truncated, limits)?;
        truncated |= cut;
        current = Some(out);
    }
    Ok(Decoded {
        data: current.unwrap_or_else(|| data.to_vec()),
        truncated,
        codings: names,
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Coding {
    Gzip,
    Deflate,
    Brotli,
    Zstd,
}

impl Coding {
    fn parse(name: &str) -> Option<Self> {
        match name {
            "gzip" | "x-gzip" => Some(Self::Gzip),
            "deflate" => Some(Self::Deflate),
            "br" => Some(Self::Brotli),
            "zstd" => Some(Self::Zstd),
            _ => None,
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::Gzip => "gzip",
            Self::Deflate => "deflate",
            Self::Brotli => "br",
            Self::Zstd => "zstd",
        }
    }

    /// The decoded bytes and whether they stop short of the whole body.
    fn decode(
        self,
        input: &[u8],
        complete: bool,
        limits: DecodeLimits,
    ) -> Result<(Vec<u8>, bool), DecodeError> {
        let name = self.name();
        match self {
            Self::Gzip => drain(
                flate2::read::MultiGzDecoder::new(input),
                limits.output,
                complete,
                name,
            ),
            Self::Deflate => inflate(input, is_zlib(input), limits.output, complete),
            Self::Brotli => {
                if input.is_empty() {
                    return empty(complete, name);
                }
                let window = brotli_window(input).ok_or(DecodeError::Corrupt(name))?;
                if window > limits.window.min(BROTLI_MAX_WINDOW) as u64 {
                    return Err(DecodeError::WindowTooLarge {
                        coding: name,
                        window,
                    });
                }
                drain(
                    brotli_decompressor::Decompressor::new(input, 4096),
                    limits.output,
                    complete,
                    name,
                )
            }
            Self::Zstd => zstd(input, complete, limits),
        }
    }
}

fn empty(complete: bool, coding: &'static str) -> Result<(Vec<u8>, bool), DecodeError> {
    if complete {
        Err(DecodeError::Corrupt(coding))
    } else {
        Ok((Vec::new(), true))
    }
}

/// Reads `reader` to the end or to `limit` bytes. A read error ends a cut
/// body quietly (it is truncated anyway) and fails a complete one.
fn drain(
    mut reader: impl Read,
    limit: usize,
    complete: bool,
    coding: &'static str,
) -> Result<(Vec<u8>, bool), DecodeError> {
    let mut out = Vec::new();
    let mut buf = vec![0u8; 16 * 1024];
    loop {
        match reader.read(&mut buf) {
            Ok(0) => return Ok((out, false)),
            Ok(n) => {
                let room = limit - out.len();
                if n > room {
                    out.extend_from_slice(&buf[..room]);
                    return Ok((out, true));
                }
                out.extend_from_slice(&buf[..n]);
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(_) if !complete => return Ok((out, true)),
            Err(_) => return Err(DecodeError::Corrupt(coding)),
        }
    }
}

/// Inflates a zlib (RFC 1950) or raw deflate (RFC 1951) stream. Unlike
/// `flate2`'s readers, input that ends before the final block counts as cut
/// short, so a truncated complete body is an error and not quietly short.
fn inflate(
    input: &[u8],
    zlib: bool,
    limit: usize,
    complete: bool,
) -> Result<(Vec<u8>, bool), DecodeError> {
    const NAME: &str = "deflate";
    let mut state = flate2::Decompress::new(zlib);
    let mut out = Vec::new();
    let mut buf = vec![0u8; 16 * 1024];
    loop {
        let consumed = state.total_in() as usize;
        let produced_before = state.total_out();
        let status = state.decompress(&input[consumed..], &mut buf, flate2::FlushDecompress::None);
        let produced = (state.total_out() - produced_before) as usize;
        let room = limit - out.len();
        if produced > room {
            out.extend_from_slice(&buf[..room]);
            return Ok((out, true));
        }
        out.extend_from_slice(&buf[..produced]);
        match status {
            Ok(flate2::Status::StreamEnd) => return Ok((out, false)),
            Ok(_) if produced == 0 && state.total_in() as usize == consumed => {
                // All input used and the stream not ended.
                return if complete {
                    Err(DecodeError::Corrupt(NAME))
                } else {
                    Ok((out, true))
                };
            }
            Ok(_) => {}
            Err(_) if !complete => return Ok((out, true)),
            Err(_) => return Err(DecodeError::Corrupt(NAME)),
        }
    }
}

/// A zlib header (RFC 1950): deflate method and a valid check value.
fn is_zlib(input: &[u8]) -> bool {
    input.len() >= 2
        && input[0] & 0x0f == 8
        && input[0] >> 4 <= 7
        && ((u16::from(input[0]) << 8) | u16::from(input[1])) % 31 == 0
}

/// The window a brotli stream names in its first bits (RFC 7932 section
/// 9.1); `None` for the non-standard large-window marker.
fn brotli_window(input: &[u8]) -> Option<u64> {
    let first = *input.first()?;
    let bits = if first & 1 == 0 {
        16
    } else {
        let n = (first >> 1) & 0x07;
        if n != 0 {
            17 + u32::from(n)
        } else {
            match (first >> 4) & 0x07 {
                0 => 17,
                1 => return None,
                m => 8 + u32::from(m),
            }
        }
    };
    Some((1u64 << bits) - 16)
}

const ZSTD_MAGIC: u32 = 0xFD2F_B528;

/// What a zstd frame header says about memory.
struct ZstdHeader {
    window: u64,
    dictionary: bool,
}

/// Reads the header of the zstd frame `input` starts with (RFC 8878
/// section 3.1.1.1); `None` when it is not one or is cut short.
fn zstd_header(input: &[u8]) -> Option<ZstdHeader> {
    if u32::from_le_bytes(input.get(..4)?.try_into().ok()?) != ZSTD_MAGIC {
        return None;
    }
    let descriptor = *input.get(4)?;
    let content_size_flag = descriptor >> 6;
    let single_segment = descriptor & 0x20 != 0;
    let dictionary_flag = descriptor & 0x03;
    let mut at = 5;
    let mut window = 0u64;
    if !single_segment {
        let byte = *input.get(at)?;
        at += 1;
        let base = 1u64 << (10 + u32::from(byte >> 3));
        window = base + (base / 8) * u64::from(byte & 0x07);
    }
    let dictionary_len = [0, 1, 2, 4][usize::from(dictionary_flag)];
    let dictionary = input
        .get(at..at + dictionary_len)?
        .iter()
        .any(|byte| *byte != 0);
    at += dictionary_len;
    if single_segment {
        let len = [1, 2, 4, 8][usize::from(content_size_flag)];
        let raw = input.get(at..at + len)?;
        let mut size = 0u64;
        for (i, byte) in raw.iter().enumerate() {
            size |= u64::from(*byte) << (8 * i);
        }
        if len == 2 {
            size += 256;
        }
        window = size;
    }
    Some(ZstdHeader { window, dictionary })
}

/// Decodes the zstd frames of `input` in turn, skippable frames skipped.
fn zstd(
    input: &[u8],
    complete: bool,
    limits: DecodeLimits,
) -> Result<(Vec<u8>, bool), DecodeError> {
    const NAME: &str = "zstd";
    let window_limit = limits.window.min(ZSTD_HTTP_MAX_WINDOW) as u64;
    let mut rest = input;
    let mut out = Vec::new();
    if rest.is_empty() {
        return empty(complete, NAME);
    }
    while !rest.is_empty() {
        let magic = rest
            .get(..4)
            .and_then(|bytes| bytes.try_into().ok())
            .map(u32::from_le_bytes);
        match magic {
            Some(magic) if magic & 0xFFFF_FFF0 == 0x184D_2A50 => {
                let Some(len) = rest
                    .get(4..8)
                    .and_then(|bytes| bytes.try_into().ok())
                    .map(u32::from_le_bytes)
                else {
                    return if complete {
                        Err(DecodeError::Corrupt(NAME))
                    } else {
                        Ok((out, true))
                    };
                };
                let skip = 8usize.saturating_add(len as usize);
                if skip > rest.len() {
                    return if complete {
                        Err(DecodeError::Corrupt(NAME))
                    } else {
                        Ok((out, true))
                    };
                }
                rest = &rest[skip..];
                continue;
            }
            _ => {}
        }
        let Some(header) = zstd_header(rest) else {
            return if complete || (out.is_empty() && rest.len() >= 18) {
                Err(DecodeError::Corrupt(NAME))
            } else {
                Ok((out, true))
            };
        };
        if header.dictionary {
            return Err(DecodeError::Dictionary);
        }
        if header.window > window_limit {
            return Err(DecodeError::WindowTooLarge {
                coding: NAME,
                window: header.window,
            });
        }
        let mut reader = rest;
        let room = limits.output - out.len();
        let decoder = match ruzstd::decoding::StreamingDecoder::new(&mut reader) {
            Ok(decoder) => decoder,
            Err(_) if !complete => return Ok((out, true)),
            Err(_) => return Err(DecodeError::Corrupt(NAME)),
        };
        // One more byte than fits tells a cut frame from one that fits.
        let (frame, cut) = drain(decoder, room, complete, NAME)?;
        out.extend_from_slice(&frame);
        if cut {
            return Ok((out, true));
        }
        if reader.len() == rest.len() {
            // Nothing consumed: never loop on the same bytes.
            return Err(DecodeError::Corrupt(NAME));
        }
        rest = reader;
    }
    Ok((out, false))
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use super::*;

    const LIMITS: DecodeLimits = DecodeLimits {
        output: 1024 * 1024,
        window: 4 * 1024 * 1024,
    };

    fn text() -> Vec<u8> {
        (0..2000)
            .flat_map(|i| format!("{{\"line\":{i},\"text\":\"hello world\"}}\n").into_bytes())
            .collect()
    }

    fn gzip(data: &[u8]) -> Vec<u8> {
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(data).unwrap();
        encoder.finish().unwrap()
    }

    fn zlib(data: &[u8]) -> Vec<u8> {
        let mut encoder =
            flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(data).unwrap();
        encoder.finish().unwrap()
    }

    fn raw_deflate(data: &[u8]) -> Vec<u8> {
        let mut encoder =
            flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(data).unwrap();
        encoder.finish().unwrap()
    }

    fn zstd(data: &[u8]) -> Vec<u8> {
        ruzstd::encoding::compress_to_vec(data, ruzstd::encoding::CompressionLevel::Fastest)
    }

    fn hex(text: &str) -> Vec<u8> {
        let digits: Vec<u8> = text
            .bytes()
            .filter(|b| b.is_ascii_hexdigit())
            .map(|b| (b as char).to_digit(16).unwrap() as u8)
            .collect();
        digits
            .chunks(2)
            .map(|pair| (pair[0] << 4) | pair[1])
            .collect()
    }

    /// "hello hello hello\n" compressed by Google's brotli (Python
    /// `brotli.compress(quality=11, lgwin=22)`): window bits 22.
    const BROTLI_HELLO_W22: &str = "8b088068656c6c6f2068656c6c6f2068656c6c6f0a03";
    /// The same with `lgwin=16`.
    const BROTLI_HELLO_W16: &str = "10011068656c6c6f2068656c6c6f2068656c6c6f0a03";
    /// [`text`] compressed by Google's brotli, quality 5, window bits 18.
    const BROTLI_LINES: &[u8] = include_bytes!("../../testdata/lines-q5-w18.br");
    /// 64 MiB of zeros in 405 bytes of brotli (quality 5, window bits 20).
    const BROTLI_ZEROS: &[u8] = include_bytes!("../../testdata/zeros-64mib-w20.br");

    #[test]
    fn identity_and_no_header_return_the_bytes() {
        for header in ["", "identity", " Identity "] {
            let decoded = super::decode_body(b"plain", header, true, LIMITS).unwrap();
            assert_eq!(decoded.data, b"plain");
            assert!(!decoded.truncated);
            assert!(decoded.codings.is_empty());
        }
    }

    #[test]
    fn gzip_deflate_and_zstd_round_trip() {
        let text = text();
        for (header, body) in [
            ("gzip", gzip(&text)),
            ("x-gzip", gzip(&text)),
            ("deflate", zlib(&text)),
            ("deflate", raw_deflate(&text)),
            ("zstd", zstd(&text)),
            ("ZSTD", zstd(&text)),
            ("br", BROTLI_LINES.to_vec()),
        ] {
            let decoded = super::decode_body(&body, header, true, LIMITS)
                .unwrap_or_else(|error| panic!("{header}: {error}"));
            assert_eq!(decoded.data, text, "{header}");
            assert!(!decoded.truncated, "{header}");
        }
    }

    #[test]
    fn brotli_reads_its_window_and_decodes() {
        for body in [BROTLI_HELLO_W22, BROTLI_HELLO_W16] {
            let body = hex(body);
            let decoded = super::decode_body(&body, "br", true, LIMITS).unwrap();
            assert_eq!(decoded.data, b"hello hello hello\n");
        }
        assert_eq!(brotli_window(&hex(BROTLI_HELLO_W22)), Some((1 << 22) - 16));
        assert_eq!(brotli_window(&hex(BROTLI_HELLO_W16)), Some((1 << 16) - 16));
        // The first byte alone names every standard window.
        assert_eq!(brotli_window(&[0x00]), Some((1 << 16) - 16));
        assert_eq!(brotli_window(&[0x0f]), Some((1 << 24) - 16));
        assert_eq!(brotli_window(&[0x01]), Some((1 << 17) - 16));
        assert_eq!(brotli_window(&[0x21]), Some((1 << 10) - 16));
        assert_eq!(brotli_window(&[0x11]), None, "large-window marker");
    }

    #[test]
    fn several_codings_are_undone_last_first() {
        let text = text();
        let body = zstd(&gzip(&text));
        let decoded = super::decode_body(&body, "gzip, zstd", true, LIMITS).unwrap();
        assert_eq!(decoded.data, text);
        assert_eq!(decoded.codings, vec!["gzip", "zstd"]);
        assert!(supported("gzip, zstd"));
        assert!(!supported("gzip, compress"));
    }

    #[test]
    fn unknown_codings_and_corrupt_bodies_are_errors() {
        assert_eq!(
            super::decode_body(b"x", "compress", true, LIMITS),
            Err(DecodeError::Unsupported("compress".into()))
        );
        for header in ["gzip", "deflate", "br", "zstd"] {
            let garbage = [0x5au8; 64];
            assert!(
                super::decode_body(&garbage, header, true, LIMITS).is_err(),
                "{header}"
            );
        }
        let mut body = gzip(&text());
        let middle = body.len() / 2;
        body[middle] ^= 0xff;
        assert!(super::decode_body(&body, "gzip", true, LIMITS).is_err());
    }

    #[test]
    fn a_cut_capture_decodes_as_far_as_it_goes() {
        let text = text();
        for (header, body) in [
            ("gzip", gzip(&text)),
            ("deflate", zlib(&text)),
            ("deflate", raw_deflate(&text)),
            ("zstd", zstd(&text)),
            ("br", BROTLI_LINES.to_vec()),
        ] {
            let cut = &body[..body.len() / 2];
            let decoded = super::decode_body(cut, header, false, LIMITS)
                .unwrap_or_else(|error| panic!("{header}: {error}"));
            assert!(decoded.truncated, "{header}");
            assert!(text.starts_with(&decoded.data), "{header}");
            // The same bytes said to be the whole body are corrupt.
            assert!(super::decode_body(cut, header, true, LIMITS).is_err());
        }
    }

    #[test]
    fn a_bomb_stops_at_the_output_limit() {
        // 64 MiB of zeros in about 64 KiB of gzip, a few KiB of zstd and
        // 405 bytes of brotli.
        let zeros = vec![0u8; 64 * 1024 * 1024];
        let limits = DecodeLimits {
            output: 256 * 1024,
            window: 4 * 1024 * 1024,
        };
        for (header, body) in [
            ("gzip", gzip(&zeros)),
            ("zstd", zstd(&zeros)),
            ("br", BROTLI_ZEROS.to_vec()),
        ] {
            assert!(body.len() < 128 * 1024, "{header}: {}", body.len());
            let decoded = super::decode_body(&body, header, true, limits).unwrap();
            assert_eq!(decoded.data.len(), limits.output, "{header}");
            assert!(decoded.truncated, "{header}");
        }
    }

    #[test]
    fn zstd_windows_over_the_limit_are_refused_before_decoding() {
        // Frame header: magic, descriptor without single segment, window
        // descriptor 0x58 (exponent 11 → 2^21 = 2 MiB, no mantissa).
        let mut frame = ZSTD_MAGIC.to_le_bytes().to_vec();
        frame.extend_from_slice(&[0x00, 0x58]);
        assert_eq!(zstd_header(&frame).unwrap().window, 2 * 1024 * 1024);
        // Exponent 14 → 16 MiB: over RFC 9659's 8 MiB even for the app.
        frame[5] = 0x70;
        assert_eq!(
            super::decode_body(&frame, "zstd", true, DecodeLimits::APP),
            Err(DecodeError::WindowTooLarge {
                coding: "zstd",
                window: 16 * 1024 * 1024
            })
        );
        // Exponent 12 → 4 MiB plus mantissa 1 → 4.5 MiB: over the extension's
        // limit, not the app's.
        frame[5] = 0x61;
        assert!(matches!(
            super::decode_body(&frame, "zstd", true, DecodeLimits::EXTENSION),
            Err(DecodeError::WindowTooLarge { .. })
        ));
        // Single segment: the window is the content size (8-byte field).
        let mut single = ZSTD_MAGIC.to_le_bytes().to_vec();
        single.push(0xe0);
        single.extend_from_slice(&(64u64 * 1024 * 1024).to_le_bytes());
        assert_eq!(zstd_header(&single).unwrap().window, 64 * 1024 * 1024);
        assert!(matches!(
            super::decode_body(&single, "zstd", true, DecodeLimits::APP),
            Err(DecodeError::WindowTooLarge { .. })
        ));
        // A dictionary id.
        let mut dictionary = ZSTD_MAGIC.to_le_bytes().to_vec();
        dictionary.extend_from_slice(&[0x01, 0x58, 0x07]);
        assert_eq!(
            super::decode_body(&dictionary, "zstd", true, LIMITS),
            Err(DecodeError::Dictionary)
        );
    }

    #[test]
    fn brotli_windows_over_the_limit_are_refused() {
        let body = hex(BROTLI_HELLO_W22);
        let small = DecodeLimits {
            output: 1024,
            window: 1024 * 1024,
        };
        assert!(matches!(
            super::decode_body(&body, "br", true, small),
            Err(DecodeError::WindowTooLarge { coding: "br", .. })
        ));
        assert!(super::decode_body(&hex(BROTLI_HELLO_W16), "br", true, small).is_ok());
    }

    #[test]
    fn skippable_zstd_frames_are_skipped() {
        let text = text();
        let mut body = 0x184D_2A53u32.to_le_bytes().to_vec();
        body.extend_from_slice(&3u32.to_le_bytes());
        body.extend_from_slice(b"abc");
        body.extend(zstd(&text[..1000]));
        body.extend(zstd(&text[1000..]));
        let decoded = super::decode_body(&body, "zstd", true, LIMITS).unwrap();
        assert_eq!(decoded.data, text);
    }
}
