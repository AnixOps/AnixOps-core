//! Export redaction (导出脱敏): credentials in captured HTTP messages are
//! masked before a file leaves the engine, unless the export asks for
//! `redact: false`.
//!
//! Masked: the `Cookie`, `Set-Cookie`, `Authorization` and
//! `Proxy-Authorization` headers, and every header, query parameter, JSON
//! field or form field whose name contains one of [`SENSITIVE_PARTS`]. The
//! value becomes [`MASK`]; names, order and everything else stay, so the
//! export still shows what was sent.
//!
//! A body with a `Content-Encoding` (gzip, br, zstd, ...) is decoded first
//! (see [`super::decode`]), so credentials inside it are masked too. When
//! something was masked, the export carries the masked plain text and the
//! header becomes [`DECODED_ENCODING_HEADER`], since the original bytes
//! cannot be re-encoded without them.

use std::borrow::Cow;

use serde_json::Value;

use super::{CapturedBody, HttpExchange};

/// What a masked value becomes.
pub const MASK: &str = "<redacted>";

/// Replaces `Content-Encoding` on a message whose body redaction decoded and
/// masked: its value is the coding the body had.
pub const DECODED_ENCODING_HEADER: &str = "X-AnixOps-Decoded-Content-Encoding";

/// Headers masked whatever their value.
const SENSITIVE_HEADERS: [&str; 4] = [
    "cookie",
    "set-cookie",
    "authorization",
    "proxy-authorization",
];

/// A header, parameter or field whose lower-cased name contains one of
/// these is masked.
pub const SENSITIVE_PARTS: [&str; 10] = [
    "token",
    "secret",
    "password",
    "passwd",
    "api-key",
    "apikey",
    "api_key",
    "session",
    "signature",
    "credential",
];

/// Whether a header, parameter or field called `name` is masked.
pub fn sensitive_name(name: &str) -> bool {
    let lower = name.trim().to_ascii_lowercase();
    SENSITIVE_HEADERS.contains(&lower.as_str())
        || SENSITIVE_PARTS.iter().any(|part| lower.contains(part))
}

/// `exchange` with its credentials masked.
pub fn exchange(exchange: &HttpExchange) -> HttpExchange {
    let (request_headers, request_body) =
        message(&exchange.request_headers, &exchange.request_body);
    let (response_headers, response_body) =
        message(&exchange.response_headers, &exchange.response_body);
    HttpExchange {
        url: url(&exchange.url).into_owned(),
        request_headers,
        request_body,
        response_headers,
        response_body,
        ..exchange.clone()
    }
}

/// The headers and body of one message, masked; an encoded body is masked
/// in its decoded form.
fn message(
    original: &[(String, String)],
    captured: &CapturedBody,
) -> (Vec<(String, String)>, CapturedBody) {
    let content_type = header(original, "content-type");
    let masked_headers = headers(original);
    let coding = header(original, "content-encoding")
        .filter(|coding| !super::decode::codings(coding).is_empty());
    let Some(coding) = coding else {
        return (masked_headers, body(captured, content_type.as_deref()));
    };
    let Ok(decoded) = super::decode::decode_body(
        &captured.data,
        &coding,
        !captured.truncated(),
        super::decode::DecodeLimits::EXTENSION,
    ) else {
        // Not decodable here: nothing in it can be read either.
        return (masked_headers, captured.clone());
    };
    let cut = decoded.truncated;
    let plain = CapturedBody {
        size: decoded.data.len() as u64,
        data: decoded.data,
    };
    let mut masked = body(&plain, content_type.as_deref());
    if masked.data == plain.data {
        return (masked_headers, captured.clone());
    }
    // A cut body stays marked as cut: `size` past the kept bytes.
    masked.size = masked.data.len() as u64 + u64::from(cut);
    let headers = masked_headers
        .into_iter()
        .map(|(name, value)| {
            if name.eq_ignore_ascii_case("content-encoding") {
                (DECODED_ENCODING_HEADER.to_string(), value)
            } else {
                (name, value)
            }
        })
        .collect();
    (headers, masked)
}

fn header(headers: &[(String, String)], name: &str) -> Option<String> {
    headers
        .iter()
        .find(|(key, _)| key.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.to_ascii_lowercase())
}

fn headers(headers: &[(String, String)]) -> Vec<(String, String)> {
    headers
        .iter()
        .map(|(name, value)| {
            if sensitive_name(name) {
                (name.clone(), MASK.to_string())
            } else {
                (name.clone(), value.clone())
            }
        })
        .collect()
}

/// `url` with sensitive query parameter values masked.
pub fn url(url: &str) -> Cow<'_, str> {
    let Some((base, rest)) = url.split_once('?') else {
        return Cow::Borrowed(url);
    };
    let (query, fragment) = match rest.split_once('#') {
        Some((query, fragment)) => (query, Some(fragment)),
        None => (rest, None),
    };
    let masked = form(query);
    if masked == query {
        return Cow::Borrowed(url);
    }
    let mut out = format!("{base}?{masked}");
    if let Some(fragment) = fragment {
        out.push('#');
        out.push_str(fragment);
    }
    Cow::Owned(out)
}

/// `a=1&token=x` → `a=1&token=<redacted>`.
fn form(query: &str) -> String {
    query
        .split('&')
        .map(|pair| match pair.split_once('=') {
            Some((name, _)) if sensitive_name(&percent_decode(name)) => format!("{name}={MASK}"),
            _ => pair.to_string(),
        })
        .collect::<Vec<_>>()
        .join("&")
}

fn percent_decode(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'%' if index + 2 < bytes.len() => {
                let hex = std::str::from_utf8(&bytes[index + 1..index + 3]).unwrap_or("");
                match u8::from_str_radix(hex, 16) {
                    Ok(byte) => {
                        out.push(byte);
                        index += 3;
                    }
                    Err(_) => {
                        out.push(b'%');
                        index += 1;
                    }
                }
            }
            b'+' => {
                out.push(b' ');
                index += 1;
            }
            byte => {
                out.push(byte);
                index += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// A JSON or form body with sensitive fields masked. Other bodies, and a
/// body cut short by the capture limit that no longer parses, stay as they
/// are.
fn body(body: &CapturedBody, content_type: Option<&str>) -> CapturedBody {
    let Ok(text) = std::str::from_utf8(&body.data) else {
        return body.clone();
    };
    let content_type = content_type.unwrap_or("");
    let masked = if content_type.contains("json") || looks_like_json(text) {
        serde_json::from_str::<Value>(text)
            .ok()
            .and_then(|mut value| {
                mask_json(&mut value).then(|| serde_json::to_string(&value).unwrap_or_default())
            })
    } else if content_type.contains("x-www-form-urlencoded") {
        let masked = form(text);
        (masked != text).then_some(masked)
    } else {
        None
    };
    match masked {
        Some(masked) => CapturedBody {
            data: masked.into_bytes(),
            size: body.size,
        },
        None => body.clone(),
    }
}

fn looks_like_json(text: &str) -> bool {
    let trimmed = text.trim_start();
    trimmed.starts_with('{') || trimmed.starts_with('[')
}

/// Masks sensitive fields at any depth; `true` when one was.
fn mask_json(value: &mut Value) -> bool {
    match value {
        Value::Object(map) => {
            let mut changed = false;
            for (key, field) in map.iter_mut() {
                if sensitive_name(key) && !field.is_object() && !field.is_array() {
                    *field = Value::String(MASK.to_string());
                    changed = true;
                } else {
                    changed |= mask_json(field);
                }
            }
            changed
        }
        Value::Array(items) => items
            .iter_mut()
            .fold(false, |changed, item| mask_json(item) | changed),
        _ => false,
    }
}

/// Plain (not decrypted) HTTP/1 text in a captured chunk with sensitive
/// header values masked, for the pcapng export. Bytes that are not an
/// HTTP/1 head (TLS records, other protocols) come back unchanged.
pub fn http1_text(data: &[u8]) -> Cow<'_, [u8]> {
    if !starts_like_http1(data) {
        return Cow::Borrowed(data);
    }
    let head_end = data
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map_or(data.len(), |end| end + 4);
    let (head, rest) = data.split_at(head_end);
    let Ok(head) = std::str::from_utf8(head) else {
        return Cow::Borrowed(data);
    };
    let mut changed = false;
    let mut out = String::with_capacity(head.len());
    for (index, line) in head.split_inclusive("\r\n").enumerate() {
        if index > 0 {
            if let Some((name, _)) = line.split_once(':') {
                if sensitive_name(name) {
                    out.push_str(name);
                    out.push_str(": ");
                    out.push_str(MASK);
                    if line.ends_with("\r\n") {
                        out.push_str("\r\n");
                    }
                    changed = true;
                    continue;
                }
            }
        } else if let Some(masked) = request_line(line) {
            out.push_str(&masked);
            changed = true;
            continue;
        }
        out.push_str(line);
    }
    if !changed {
        return Cow::Borrowed(data);
    }
    let mut bytes = out.into_bytes();
    bytes.extend_from_slice(rest);
    Cow::Owned(bytes)
}

/// The request line with a masked query, when it has something to mask.
fn request_line(line: &str) -> Option<String> {
    let mut parts = line.splitn(3, ' ');
    let method = parts.next()?;
    let target = parts.next()?;
    let rest = parts.next()?;
    match url(target) {
        Cow::Owned(masked) => Some(format!("{method} {masked} {rest}")),
        Cow::Borrowed(_) => None,
    }
}

fn starts_like_http1(data: &[u8]) -> bool {
    const STARTS: [&[u8]; 10] = [
        b"GET ",
        b"POST ",
        b"PUT ",
        b"DELETE ",
        b"HEAD ",
        b"OPTIONS ",
        b"PATCH ",
        b"TRACE ",
        b"CONNECT ",
        b"HTTP/1.",
    ];
    STARTS.iter().any(|start| data.starts_with(start))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pair(name: &str, value: &str) -> (String, String) {
        (name.to_string(), value.to_string())
    }

    #[test]
    fn masks_credential_headers_query_and_bodies() {
        let mut exchange = HttpExchange::new(
            "POST",
            "https://api.example.test/login?user=a&access_token=xyz#top",
            &[
                pair("Authorization", "Bearer abc"),
                pair("Cookie", "sid=1"),
                pair("X-Api-Key", "k"),
                pair("Content-Type", "application/json"),
                pair("Accept", "*/*"),
            ],
        );
        exchange.request_body =
            CapturedBody::of(br#"{"user":"a","password":"p","nested":{"refresh_token":"r"}}"#);
        exchange.response_headers = vec![
            pair("Set-Cookie", "sid=2; Path=/"),
            pair("Content-Type", "application/x-www-form-urlencoded"),
        ];
        exchange.response_body = CapturedBody::of(b"ok=1&session_id=s");

        let masked = super::exchange(&exchange);
        assert_eq!(
            masked.url,
            "https://api.example.test/login?user=a&access_token=<redacted>#top"
        );
        assert_eq!(masked.request_headers[0].1, MASK);
        assert_eq!(masked.request_headers[1].1, MASK);
        assert_eq!(masked.request_headers[2].1, MASK);
        assert_eq!(masked.request_headers[3].1, "application/json");
        assert_eq!(masked.request_headers[4].1, "*/*");
        let body: Value = serde_json::from_slice(&masked.request_body.data).unwrap();
        assert_eq!(body["user"], "a");
        assert_eq!(body["password"], MASK);
        assert_eq!(body["nested"]["refresh_token"], MASK);
        assert_eq!(masked.request_body.size, exchange.request_body.size);
        assert_eq!(masked.response_headers[0].1, MASK);
        assert_eq!(masked.response_body.data, b"ok=1&session_id=<redacted>");
    }

    #[test]
    fn leaves_harmless_messages_alone() {
        assert!(matches!(url("https://a.test/x?q=1"), Cow::Borrowed(_)));
        assert!(matches!(url("https://a.test/x"), Cow::Borrowed(_)));
        let tls = b"\x16\x03\x01\x00\x05hello";
        assert!(matches!(http1_text(tls), Cow::Borrowed(_)));
    }

    #[test]
    fn masks_plain_http1_heads() {
        let text = b"GET /p?token=1&a=2 HTTP/1.1\r\nHost: a.test\r\nCookie: x=1\r\n\r\nbody";
        let masked = http1_text(text);
        assert_eq!(
            masked.as_ref(),
            b"GET /p?token=<redacted>&a=2 HTTP/1.1\r\nHost: a.test\r\nCookie: <redacted>\r\n\r\nbody"
                .as_slice()
        );
    }

    fn gzip(data: &[u8]) -> Vec<u8> {
        use std::io::Write;
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(data).unwrap();
        encoder.finish().unwrap()
    }

    #[test]
    fn credentials_inside_an_encoded_body_are_masked() {
        let mut exchange = HttpExchange::new("GET", "https://api.example.test/me", &[]);
        exchange.status = Some(200);
        exchange.response_headers = vec![
            pair("Content-Type", "application/json"),
            pair("Content-Encoding", "gzip"),
        ];
        exchange.response_body =
            CapturedBody::of(&gzip(br#"{"name":"a","access_token":"secret-value"}"#));

        let masked = super::exchange(&exchange);
        let body: Value = serde_json::from_slice(&masked.response_body.data).unwrap();
        assert_eq!(body["name"], "a");
        assert_eq!(body["access_token"], MASK);
        assert!(!masked.response_body.truncated());
        assert_eq!(
            masked.response_headers[1],
            pair(DECODED_ENCODING_HEADER, "gzip")
        );
        assert!(!masked
            .response_headers
            .iter()
            .any(|(name, _)| name.eq_ignore_ascii_case("content-encoding")));
    }

    #[test]
    fn an_encoded_body_with_nothing_to_mask_stays_as_captured() {
        let mut exchange = HttpExchange::new("GET", "https://api.example.test/", &[]);
        exchange.status = Some(200);
        exchange.response_headers = vec![
            pair("Content-Type", "application/json"),
            pair("Content-Encoding", "gzip"),
        ];
        let wire = gzip(br#"{"name":"a"}"#);
        exchange.response_body = CapturedBody::of(&wire);
        let masked = super::exchange(&exchange);
        assert_eq!(masked.response_body.data, wire);
        assert_eq!(masked.response_headers[1], pair("Content-Encoding", "gzip"));
    }
}
