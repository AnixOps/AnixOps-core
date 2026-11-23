//! Downloads through an outbound: the plain HTTP/1.1 GET remote rule sets
//! use to refresh while the engine runs.
//!
//! One request per connection, `Connection: close`, no compression; the body
//! ends at `Content-Length`, the last chunk of a chunked answer, or the end
//! of the stream. A `301`, `302`, `303`, `307` or `308` answer with a
//! `Location` is followed, up to [`MAX_REDIRECTS`] times, each hop over a new
//! connection through the same outbound (and a TLS session for the new
//! host): list URLs such as `github.com/<owner>/<repo>/raw/...` or
//! `/releases/latest/download/...` answer with one. A redirect from `https`
//! to `http` is refused; the whole chain shares one timeout. Errors are
//! fixed codes without URLs or payloads.

use std::io;
use std::time::Duration;

use engine_outbound::{BoxStream, TcpOutbound};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::delay::{tls_for, ProbeUrl};
pub use crate::http1::FetchError;
use crate::http1::{parse_response, MAX_HEAD_BYTES};

/// Redirects followed at most for one download.
pub const MAX_REDIRECTS: usize = 5;

/// The body of a `200` answer to a GET of `url` through `outbound`, at most
/// `max_bytes` long, within `timeout`, following redirects (see the module
/// docs).
pub async fn fetch(
    outbound: &dyn TcpOutbound,
    url: &str,
    timeout: Duration,
    max_bytes: usize,
) -> Result<Vec<u8>, FetchError> {
    let mut url = ProbeUrl::parse(url).ok_or(FetchError::InvalidUrl)?;
    let exchange = async {
        let mut redirects = 0;
        loop {
            match get(outbound, &url, max_bytes).await? {
                Answer::Body(body) => return Ok(body),
                Answer::Redirect(location) => {
                    if redirects == MAX_REDIRECTS {
                        return Err(FetchError::TooManyRedirects);
                    }
                    redirects += 1;
                    url = next_hop(&url, &location)?;
                }
            }
        }
    };
    tokio::time::timeout(timeout, exchange)
        .await
        .unwrap_or(Err(FetchError::Timeout))
}

/// What one request brought back.
enum Answer {
    Body(Vec<u8>),
    /// A redirect, with its `Location` as sent.
    Redirect(String),
}

/// One GET of `url` over a new connection through `outbound`.
async fn get(
    outbound: &dyn TcpOutbound,
    url: &ProbeUrl,
    max_bytes: usize,
) -> Result<Answer, FetchError> {
    let tls = tls_for(url).map_err(|_| FetchError::InvalidUrl)?;
    let mut stream: BoxStream = outbound
        .connect(&url.target())
        .await
        .map_err(|_| FetchError::ConnectFailed)?;
    if let Some(tls) = &tls {
        stream = tls
            .connect(stream)
            .await
            .map_err(|_| FetchError::ConnectFailed)?;
    }
    let request = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: networkcore\r\nAccept: */*\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n",
        url.path,
        url.host_header()
    );
    let io = |_: io::Error| FetchError::BadResponse;
    stream.write_all(request.as_bytes()).await.map_err(io)?;
    stream.flush().await.map_err(io)?;
    let mut raw = Vec::new();
    let mut buf = vec![0u8; 16 * 1024];
    let mut head_checked = false;
    loop {
        let read = match stream.read(&mut buf).await {
            Ok(read) => read,
            // Many servers reset instead of closing TLS cleanly; what
            // arrived is judged by its framing below.
            Err(_) if !raw.is_empty() => 0,
            Err(_) => return Err(FetchError::BadResponse),
        };
        if read == 0 {
            break;
        }
        raw.extend_from_slice(&buf[..read]);
        // A redirect is decided by its head; its body is not read.
        if !head_checked && raw.windows(4).any(|window| window == b"\r\n\r\n") {
            head_checked = true;
            if let Some(location) = redirect_location(&raw) {
                return Ok(Answer::Redirect(location));
            }
        }
        if raw.len() > MAX_HEAD_BYTES + max_bytes {
            return Err(FetchError::TooLarge);
        }
    }
    parse_response(&raw, max_bytes).map(Answer::Body)
}

/// The `Location` of a redirect (`301`, `302`, `303`, `307`, `308`) whose
/// head `raw` starts with; `None` for any other answer, or a redirect
/// without a `Location` (which then fails as `http_status`).
fn redirect_location(raw: &[u8]) -> Option<String> {
    let head_end = raw.windows(4).position(|window| window == b"\r\n\r\n")?;
    if head_end > MAX_HEAD_BYTES {
        return None;
    }
    let head = std::str::from_utf8(&raw[..head_end]).ok()?;
    let mut lines = head.split("\r\n");
    let status = lines.next()?;
    if !status.starts_with("HTTP/1.") {
        return None;
    }
    if !matches!(
        status.split(' ').nth(1),
        Some("301" | "302" | "303" | "307" | "308")
    ) {
        return None;
    }
    lines
        .filter_map(|line| line.split_once(':'))
        .find(|(name, _)| name.trim().eq_ignore_ascii_case("location"))
        .map(|(_, value)| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

/// Where a redirect from `url` to `location` goes: never from `https` to
/// `http`.
fn next_hop(url: &ProbeUrl, location: &str) -> Result<ProbeUrl, FetchError> {
    let next = resolve_location(url, location).ok_or(FetchError::BadResponse)?;
    if url.tls && !next.tls {
        return Err(FetchError::InsecureRedirect);
    }
    Ok(next)
}

/// `location` read against the URL `base` it came from: an absolute
/// `http(s)://` URL, a scheme-relative `//host/path`, an absolute path, a
/// query, or a path relative to `base`'s directory. `None` when the result
/// is not a URL a download can use (another scheme, credentials, spaces).
fn resolve_location(base: &ProbeUrl, location: &str) -> Option<ProbeUrl> {
    let scheme = if base.tls { "https" } else { "http" };
    let authority = {
        let host = if base.host.contains(':') {
            format!("[{}]", base.host)
        } else {
            base.host.clone()
        };
        format!("{host}:{}", base.port)
    };
    // A scheme is letters, digits, `+`, `-` and `.` before `://`; a path or
    // query that merely contains `://` (`/go?to=https://...`) is not one.
    let with_scheme = location.split_once("://").filter(|(given, _)| {
        !given.is_empty()
            && given
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'))
    });
    let absolute = if let Some((given, rest)) = with_scheme {
        let given = given.to_ascii_lowercase();
        if given != "http" && given != "https" {
            return None;
        }
        format!("{given}://{rest}")
    } else if let Some(rest) = location.strip_prefix("//") {
        format!("{scheme}://{rest}")
    } else if location.starts_with('/') {
        format!("{scheme}://{authority}{location}")
    } else {
        let path = base.path.split('?').next().unwrap_or("/");
        let joined = if location.starts_with('?') {
            format!("{path}{location}")
        } else {
            let directory = &path[..path.rfind('/').map_or(0, |index| index + 1)];
            format!("{directory}{location}")
        };
        let joined = if joined.starts_with('/') {
            joined
        } else {
            format!("/{joined}")
        };
        format!("{scheme}://{authority}{joined}")
    };
    ProbeUrl::parse(&absolute)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base(url: &str) -> ProbeUrl {
        ProbeUrl::parse(url).unwrap()
    }

    fn resolved(from: &str, location: &str) -> Option<(bool, String, u16, String)> {
        resolve_location(&base(from), location).map(|url| (url.tls, url.host, url.port, url.path))
    }

    #[test]
    fn locations_resolve_against_the_url_they_came_from() {
        let from = "https://github.com/owner/repo/raw/main/x.list?v=1";
        assert_eq!(
            resolved(
                from,
                "https://raw.githubusercontent.com/owner/repo/main/x.list"
            ),
            Some((
                true,
                "raw.githubusercontent.com".into(),
                443,
                "/owner/repo/main/x.list".into()
            ))
        );
        assert_eq!(
            resolved(from, "HTTPS://Objects.Example/a?sig=1#frag"),
            Some((true, "objects.example".into(), 443, "/a?sig=1".into()))
        );
        assert_eq!(
            resolved(from, "//cdn.example/b"),
            Some((true, "cdn.example".into(), 443, "/b".into()))
        );
        assert_eq!(
            resolved(from, "/other/y.list"),
            Some((true, "github.com".into(), 443, "/other/y.list".into()))
        );
        assert_eq!(
            resolved(from, "y.list"),
            Some((
                true,
                "github.com".into(),
                443,
                "/owner/repo/raw/main/y.list".into()
            ))
        );
        assert_eq!(
            resolved(from, "?v=2"),
            Some((
                true,
                "github.com".into(),
                443,
                "/owner/repo/raw/main/x.list?v=2".into()
            ))
        );
        assert_eq!(
            resolved("http://[::1]:8080/a/b", "/c"),
            Some((false, "::1".into(), 8080, "/c".into()))
        );
        assert_eq!(
            resolved(from, "/go?to=https://elsewhere.example/z"),
            Some((
                true,
                "github.com".into(),
                443,
                "/go?to=https://elsewhere.example/z".into()
            ))
        );
        assert_eq!(
            resolved("http://example.com/a", "https://example.com/a"),
            Some((true, "example.com".into(), 443, "/a".into()))
        );
    }

    #[test]
    fn unusable_locations_are_refused() {
        let from = "https://example.com/list";
        for location in [
            "ftp://example.com/list",
            "https://user:pass@example.com/list",
            "/a b",
            "https://",
        ] {
            assert!(resolved(from, location).is_none(), "{location}");
        }
    }

    #[test]
    fn redirects_never_leave_https_for_http() {
        let secure = base("https://example.com/list");
        assert_eq!(
            next_hop(&secure, "http://example.com/list"),
            Err(FetchError::InsecureRedirect)
        );
        assert_eq!(
            next_hop(&secure, "//cdn.example/list").map(|url| url.tls),
            Ok(true)
        );
        assert_eq!(
            next_hop(&secure, "ftp://example.com/list"),
            Err(FetchError::BadResponse)
        );
        // Plain HTTP may move up to HTTPS.
        let plain = base("http://example.com/list");
        assert_eq!(
            next_hop(&plain, "https://example.com/list").map(|url| url.tls),
            Ok(true)
        );
    }

    #[test]
    fn only_redirects_with_a_location_are_followed() {
        assert_eq!(
            redirect_location(b"HTTP/1.1 302 Found\r\nlocation:  /next \r\n\r\nbody"),
            Some("/next".to_string())
        );
        for status in ["301", "303", "307", "308"] {
            let head = format!("HTTP/1.1 {status} X\r\nLocation: /n\r\n\r\n");
            assert_eq!(
                redirect_location(head.as_bytes()),
                Some("/n".to_string()),
                "{status}"
            );
        }
        // Not a redirect, or one without a place to go: answered as a status.
        assert_eq!(
            redirect_location(b"HTTP/1.1 300 Multiple\r\nLocation: /n\r\n\r\n"),
            None
        );
        assert_eq!(
            redirect_location(b"HTTP/1.1 304 Not Modified\r\nLocation: /n\r\n\r\n"),
            None
        );
        assert_eq!(redirect_location(b"HTTP/1.1 302 Found\r\n\r\n"), None);
        assert_eq!(
            redirect_location(b"HTTP/1.1 302 Found\r\nLocation:\r\n\r\n"),
            None
        );
        assert_eq!(
            redirect_location(b"HTTP/1.1 200 OK\r\nLocation: /n\r\n\r\n"),
            None
        );
    }
}
