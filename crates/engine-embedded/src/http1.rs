//! HTTP/1.x response parsing shared by rule set downloads and DNS over HTTPS.

/// Longest response head accepted.
pub const MAX_HEAD_BYTES: usize = 16 * 1024;

/// Why a download failed, as a stable code.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FetchError {
    InvalidUrl,
    Timeout,
    ConnectFailed,
    /// The answer was not HTTP/1.x or its framing was broken.
    BadResponse,
    /// An answer other than 200 (a redirect without a `Location` included).
    Status,
    TooLarge,
    /// A download followed more redirects than it may.
    TooManyRedirects,
    /// A download over `https` was redirected to `http`.
    InsecureRedirect,
}

impl FetchError {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::InvalidUrl => "invalid_url",
            Self::Timeout => "timeout",
            Self::ConnectFailed => "connect_failed",
            Self::BadResponse => "bad_response",
            Self::Status => "http_status",
            Self::TooLarge => "too_large",
            Self::TooManyRedirects => "too_many_redirects",
            Self::InsecureRedirect => "redirect_insecure",
        }
    }
}

/// The body of a complete HTTP/1.x `200` response. Every other status,
/// redirects included, is [`FetchError::Status`]: DNS over HTTPS never
/// follows one; rule set downloads (`fetch`) follow them before this.
pub fn parse_response(raw: &[u8], max_bytes: usize) -> Result<Vec<u8>, FetchError> {
    let head_end = raw
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .ok_or(FetchError::BadResponse)?;
    if head_end > MAX_HEAD_BYTES {
        return Err(FetchError::BadResponse);
    }
    let head = std::str::from_utf8(&raw[..head_end]).map_err(|_| FetchError::BadResponse)?;
    let body = &raw[head_end + 4..];
    let mut lines = head.split("\r\n");
    let status = lines.next().unwrap_or_default();
    if !status.starts_with("HTTP/1.") {
        return Err(FetchError::BadResponse);
    }
    match status.split(' ').nth(1) {
        Some("200") => {}
        Some(code) if code.len() == 3 && code.bytes().all(|b| b.is_ascii_digit()) => {
            return Err(FetchError::Status)
        }
        _ => return Err(FetchError::BadResponse),
    }
    let mut length = None;
    let mut chunked = false;
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let (name, value) = (name.trim(), value.trim());
        if name.eq_ignore_ascii_case("content-length") {
            length = Some(
                value
                    .parse::<usize>()
                    .map_err(|_| FetchError::BadResponse)?,
            );
        } else if name.eq_ignore_ascii_case("transfer-encoding") {
            chunked = value.to_ascii_lowercase().contains("chunked");
        }
    }
    let body = if chunked {
        dechunk(body, max_bytes)?
    } else if let Some(length) = length {
        if body.len() < length {
            return Err(FetchError::BadResponse);
        }
        body[..length].to_vec()
    } else {
        body.to_vec()
    };
    if body.len() > max_bytes {
        return Err(FetchError::TooLarge);
    }
    Ok(body)
}

/// The data of a chunked body, at most `max_bytes` of it. A chunk size is
/// 1 to 16 hexadecimal digits (RFC 9112: `1*HEXDIG`, so no sign and no
/// spaces inside), optionally followed by an extension, and every chunk's
/// data ends in CRLF. A size is checked against what is left of
/// `max_bytes` before anything is added to it, so a huge size (such as
/// `ffffffffffffffff`) is refused instead of overflowing.
fn dechunk(mut body: &[u8], max_bytes: usize) -> Result<Vec<u8>, FetchError> {
    let mut out = Vec::new();
    loop {
        let line_end = body
            .windows(2)
            .position(|window| window == b"\r\n")
            .ok_or(FetchError::BadResponse)?;
        let size = chunk_size(&body[..line_end])?;
        body = &body[line_end + 2..];
        if size == 0 {
            return Ok(out);
        }
        if size > max_bytes.saturating_sub(out.len()) {
            return Err(FetchError::TooLarge);
        }
        let end = size.checked_add(2).ok_or(FetchError::BadResponse)?;
        if body.len() < end || &body[size..end] != b"\r\n" {
            return Err(FetchError::BadResponse);
        }
        out.extend_from_slice(&body[..size]);
        body = &body[end..];
    }
}

/// The size on a chunk size line; see [`dechunk`].
fn chunk_size(line: &[u8]) -> Result<usize, FetchError> {
    let line = std::str::from_utf8(line).map_err(|_| FetchError::BadResponse)?;
    let size = line.split(';').next().unwrap_or_default();
    let size = size.trim_matches([' ', '\t']);
    if size.is_empty() || size.len() > 16 || !size.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(FetchError::BadResponse);
    }
    usize::from_str_radix(size, 16).map_err(|_| FetchError::BadResponse)
}

/// Whether `raw` holds a whole response: its `Content-Length` arrived, or the
/// last chunk of a chunked body. Other answers end with the stream.
pub fn response_complete(raw: &[u8]) -> bool {
    let Some(head_end) = raw.windows(4).position(|window| window == b"\r\n\r\n") else {
        return false;
    };
    let body = &raw[head_end + 4..];
    let Ok(head) = std::str::from_utf8(&raw[..head_end]) else {
        return false;
    };
    for line in head.split("\r\n").skip(1) {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let (name, value) = (name.trim(), value.trim());
        if name.eq_ignore_ascii_case("content-length") {
            return value
                .parse::<usize>()
                .is_ok_and(|length| body.len() >= length);
        }
        if name.eq_ignore_ascii_case("transfer-encoding")
            && value.to_ascii_lowercase().contains("chunked")
        {
            return body.ends_with(b"0\r\n\r\n");
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bodies_follow_their_framing() {
        let plain = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello trailing";
        assert_eq!(parse_response(plain, 64).unwrap(), b"hello");
        let chunked =
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n2;x=1\r\nde\r\n0\r\n\r\n";
        assert_eq!(parse_response(chunked, 64).unwrap(), b"abcde");
        let until_close = b"HTTP/1.0 200 OK\r\n\r\nall of it";
        assert_eq!(parse_response(until_close, 64).unwrap(), b"all of it");
    }

    #[test]
    fn complete_responses_are_detected() {
        assert!(response_complete(
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"
        ));
        assert!(!response_complete(
            b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nok"
        ));
        assert!(response_complete(
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nok\r\n0\r\n\r\n"
        ));
        assert!(!response_complete(b"HTTP/1.1 200 OK\r\n\r\nuntil close"));
        assert!(!response_complete(b"HTTP/1.1 200 OK\r\n"));
    }

    #[test]
    fn bad_answers_are_classified() {
        assert_eq!(
            parse_response(b"HTTP/1.1 404 Not Found\r\n\r\n", 64),
            Err(FetchError::Status)
        );
        assert_eq!(
            parse_response(b"HTTP/1.1 200 OK\r\nContent-Length: 9\r\n\r\nshort", 64),
            Err(FetchError::BadResponse)
        );
        assert_eq!(
            parse_response(b"HTTP/1.1 200 OK\r\n\r\ntoo long", 3),
            Err(FetchError::TooLarge)
        );
        assert_eq!(
            parse_response(b"SSH-2.0\r\n\r\n", 64),
            Err(FetchError::BadResponse)
        );
        assert_eq!(
            parse_response(
                b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\n",
                64
            ),
            Err(FetchError::BadResponse)
        );
    }

    fn chunked(body: &[u8]) -> Vec<u8> {
        let mut raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec();
        raw.extend_from_slice(body);
        raw
    }

    // Chunk sizes that overflowed `size + 2` (and then panicked slicing the
    // body), signs, overlong or empty sizes, chunks larger than allowed and
    // chunks without their CRLF are refused, never a panic.
    #[test]
    fn bad_chunk_sizes_are_refused() {
        // Sizes past `usize` on a 32-bit target do not parse at all, so
        // only the refusal is checked for them.
        for body in [
            &b"ffffffffffffffff\r\nX\r\n0\r\n\r\n"[..],
            &b"fffffffffffffffe\r\n0\r\n\r\n"[..],
            &b"3\r\nabc\r\nffffffffffffffff\r\nX\r\n"[..],
        ] {
            assert!(parse_response(&chunked(body), 64).is_err(), "{body:?}");
        }
        for (body, error) in [
            (&b"10000000000000000\r\nX\r\n"[..], FetchError::BadResponse),
            (&b"+5\r\nhello\r\n0\r\n\r\n"[..], FetchError::BadResponse),
            (&b"-1\r\nX\r\n"[..], FetchError::BadResponse),
            (&b"\r\nX\r\n"[..], FetchError::BadResponse),
            (&b";ext\r\nX\r\n"[..], FetchError::BadResponse),
            (&b"4\r\nabcdXY0\r\n\r\n"[..], FetchError::BadResponse),
            (&b"4\r\nab"[..], FetchError::BadResponse),
            (&b"41\r\n"[..], FetchError::TooLarge),
            (&b"fffffff\r\nX\r\n"[..], FetchError::TooLarge),
        ] {
            assert_eq!(parse_response(&chunked(body), 64), Err(error), "{body:?}");
        }
        // An extension and blanks around the size are fine.
        assert_eq!(
            parse_response(&chunked(b"5 ;name=value\r\nhello\r\n0\r\n\r\n"), 64).unwrap(),
            b"hello"
        );
        // A body that fits exactly.
        assert_eq!(
            parse_response(&chunked(b"2\r\nab\r\n2\r\ncd\r\n0\r\n\r\n"), 4).unwrap(),
            b"abcd"
        );
        assert_eq!(
            parse_response(&chunked(b"2\r\nab\r\n3\r\ncde\r\n0\r\n\r\n"), 4),
            Err(FetchError::TooLarge)
        );
    }
}
