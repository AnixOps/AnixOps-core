//! Export redaction (导出脱敏): credentials in captured HTTP messages are
//! masked before a file leaves the engine, unless the export asks for
//! `redact: false`.
//!
//! Masked, wherever the name appears (header, query or fragment parameter,
//! JSON field, form field, multipart part, XML element):
//!
//! - the `Cookie`, `Set-Cookie`, `Authorization` and `Proxy-Authorization`
//!   headers;
//! - names containing one of [`SENSITIVE_PARTS`] (`token`, `secret`,
//!   `access_key`, `authorization`, `sessid`, ...);
//! - names that are, or have as one word (split at `-`, `_`, `.` and
//!   camel case), one of [`SENSITIVE_WORDS`] (`key`, `sig`, `auth`, `sid`,
//!   `otp`): `X-Auth-Key` and `user_sid` are masked, `keyword`, `signal`
//!   and `author` are not;
//! - query, fragment and form parameters named exactly one of
//!   [`SENSITIVE_PARAMETERS`] (`code`, an OAuth authorization code, which
//!   travels in redirect URLs and token requests; a JSON `code` is usually
//!   a status, and `status_code` and `zipCode` stay everywhere).
//!
//! The value becomes [`MASK`]; names, order and everything else stay, so
//! the export still shows what was sent. Headers that carry a URL
//! (`Location`, `Content-Location`, `Referer`, `Link`, `Refresh`) have its
//! query and fragment parameters masked like the request URL.
//!
//! JSON that does not parse whole (cut at the capture limit, NDJSON, a
//! `)]}'` prefix) is masked field by field as it is read, a value cut off
//! at the end masked to the end. Multipart parts and XML elements with a
//! sensitive name have their content masked.
//!
//! A body with a `Content-Encoding` (gzip, br, zstd, ...) is decoded first
//! (see [`super::decode`]), so credentials inside it are masked too. When
//! something was masked, or the decoded text was longer than could be
//! checked, the export carries the masked plain text and the header
//! becomes [`DECODED_ENCODING_HEADER`], since the original bytes cannot be
//! re-encoded without them. A body that cannot be decoded here cannot be
//! checked either, so its bytes are left out (its size stays) and
//! [`REDACTED_BODY_HEADER`] says so.

use std::borrow::Cow;

use serde_json::Value;

use super::{CapturedBody, HttpExchange};

/// What a masked value becomes.
pub const MASK: &str = "<redacted>";

/// Replaces `Content-Encoding` on a message whose body redaction decoded and
/// masked: its value is the coding the body had.
pub const DECODED_ENCODING_HEADER: &str = "X-AnixOps-Decoded-Content-Encoding";

/// Added to a message whose body redaction left out because it could not
/// be decoded to be checked.
pub const REDACTED_BODY_HEADER: &str = "X-AnixOps-Redacted-Body";

/// Headers masked whatever their value.
const SENSITIVE_HEADERS: [&str; 4] = [
    "cookie",
    "set-cookie",
    "authorization",
    "proxy-authorization",
];

/// A header, parameter or field whose lower-cased name contains one of
/// these is masked.
pub const SENSITIVE_PARTS: [&str; 25] = [
    "token",
    "secret",
    "password",
    "passwd",
    "passcode",
    "api-key",
    "apikey",
    "api_key",
    "session",
    "sessid",
    "signature",
    "credential",
    "authorization",
    "access_key",
    "access-key",
    "accesskey",
    "auth_key",
    "auth-key",
    "authkey",
    "private_key",
    "private-key",
    "privatekey",
    "subscription-key",
    "jwt",
    "pwd",
];

/// Masked when the name is one of these or has one as a word of it: short
/// words that are also parts of harmless names (`keyword`, `signal`,
/// `author`, `inside`), so never matched inside a word.
pub const SENSITIVE_WORDS: [&str; 5] = ["key", "sig", "auth", "sid", "otp"];

/// Query, fragment and form parameters masked only as the whole name:
/// `code` is an OAuth authorization code there, but also a word of many
/// harmless names (`status_code`, `zipCode`) and the status field of many
/// JSON APIs.
pub const SENSITIVE_PARAMETERS: [&str; 1] = ["code"];

/// Headers whose value is (or holds) a URL whose parameters are masked.
const URL_HEADERS: [&str; 3] = ["location", "content-location", "referer"];

/// Whether a header, parameter or field called `name` is masked.
pub fn sensitive_name(name: &str) -> bool {
    let name = name.trim();
    let lower = name.to_ascii_lowercase();
    SENSITIVE_HEADERS.contains(&lower.as_str())
        || SENSITIVE_PARTS.iter().any(|part| lower.contains(part))
        || has_sensitive_word(name)
}

/// Whether a query, fragment or form parameter called `name` is masked.
fn sensitive_parameter(name: &str) -> bool {
    sensitive_name(name)
        || SENSITIVE_PARAMETERS
            .iter()
            .any(|parameter| name.trim().eq_ignore_ascii_case(parameter))
}

/// Whether one word of `name` is one of [`SENSITIVE_WORDS`]: words are
/// split at anything but ASCII letters and digits and where a lower-case
/// letter or digit is followed by an upper-case one.
fn has_sensitive_word(name: &str) -> bool {
    let mut spaced = String::with_capacity(name.len() + 8);
    let mut after_lower = false;
    for c in name.chars() {
        if c.is_ascii_uppercase() && after_lower {
            spaced.push(' ');
        }
        after_lower = c.is_ascii_lowercase() || c.is_ascii_digit();
        spaced.push(c.to_ascii_lowercase());
    }
    spaced
        .split(|c: char| !c.is_ascii_alphanumeric())
        .any(|word| SENSITIVE_WORDS.contains(&word))
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
    let mut masked_headers = headers(original);
    let coding = header(original, "content-encoding")
        .filter(|coding| !super::decode::codings(coding).is_empty());
    let Some(coding) = coding else {
        return (masked_headers, body(captured, content_type));
    };
    if captured.data.is_empty() {
        return (masked_headers, captured.clone());
    }
    let limits = super::decode::DecodeLimits::EXTENSION;
    let Ok(decoded) =
        super::decode::decode_body(&captured.data, coding, !captured.truncated(), limits)
    else {
        // Not decodable here, so not checked: whoever gets the file might
        // decode it with other tools, so its bytes stay out.
        masked_headers.push((REDACTED_BODY_HEADER.to_string(), "omitted".to_string()));
        return (
            masked_headers,
            CapturedBody {
                data: Vec::new(),
                size: captured.size,
            },
        );
    };
    let cut = decoded.truncated;
    // Decoding stopped at its output limit: the rest of the text was never
    // checked, so the original bytes (which decode further) stay out.
    let unchecked = decoded.data.len() >= limits.output;
    let plain = CapturedBody {
        size: decoded.data.len() as u64,
        data: decoded.data,
    };
    let mut masked = body(&plain, content_type);
    if masked.data == plain.data && !unchecked {
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

fn header<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(key, _)| key.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.as_str())
}

fn headers(headers: &[(String, String)]) -> Vec<(String, String)> {
    headers
        .iter()
        .map(|(name, value)| match header_value(name, value) {
            Some(masked) => (name.clone(), masked),
            None => (name.clone(), value.clone()),
        })
        .collect()
}

/// The masked value of header `name`, when something in it is masked.
fn header_value(name: &str, value: &str) -> Option<String> {
    if sensitive_name(name) {
        return Some(MASK.to_string());
    }
    let lower = name.trim().to_ascii_lowercase();
    if URL_HEADERS.contains(&lower.as_str()) {
        return match url(value) {
            Cow::Owned(masked) => Some(masked),
            Cow::Borrowed(_) => None,
        };
    }
    match lower.as_str() {
        "link" => link(value),
        "refresh" => refresh(value),
        _ => None,
    }
}

/// `Link: <url>; rel=...` with the parameters of each URL masked.
fn link(value: &str) -> Option<String> {
    let mut out = String::with_capacity(value.len());
    let mut rest = value;
    let mut changed = false;
    while let Some(open) = rest.find('<') {
        let Some(length) = rest[open..].find('>') else {
            break;
        };
        let close = open + length;
        out.push_str(&rest[..=open]);
        let masked = url(&rest[open + 1..close]);
        changed |= matches!(masked, Cow::Owned(_));
        out.push_str(&masked);
        rest = &rest[close..];
    }
    out.push_str(rest);
    changed.then_some(out)
}

/// `Refresh: 5; url=...` with the URL's parameters masked.
fn refresh(value: &str) -> Option<String> {
    let at = value.to_ascii_lowercase().find("url=")? + 4;
    match url(&value[at..]) {
        Cow::Owned(masked) => Some(format!("{}{masked}", &value[..at])),
        Cow::Borrowed(_) => None,
    }
}

/// `url` with sensitive query and fragment parameter values masked (the
/// fragment carries tokens in the OAuth implicit flow).
pub fn url(url: &str) -> Cow<'_, str> {
    let (before_fragment, fragment) = match url.split_once('#') {
        Some((before, fragment)) => (before, Some(fragment)),
        None => (url, None),
    };
    let (base, query) = match before_fragment.split_once('?') {
        Some((base, query)) => (base, Some(query)),
        None => (before_fragment, None),
    };
    let masked_query = query.map(form);
    let masked_fragment = fragment.map(|fragment| {
        if fragment.contains('=') {
            form(fragment)
        } else {
            fragment.to_string()
        }
    });
    let changed = query != masked_query.as_deref() || fragment != masked_fragment.as_deref();
    if !changed {
        return Cow::Borrowed(url);
    }
    let mut out = base.to_string();
    if let Some(query) = masked_query {
        out.push('?');
        out.push_str(&query);
    }
    if let Some(fragment) = masked_fragment {
        out.push('#');
        out.push_str(&fragment);
    }
    Cow::Owned(out)
}

/// `a=1&token=x` → `a=1&token=<redacted>`.
fn form(query: &str) -> String {
    query
        .split('&')
        .map(|pair| match pair.split_once('=') {
            Some((name, _)) if sensitive_parameter(&percent_decode(name)) => {
                format!("{name}={MASK}")
            }
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

/// A body with sensitive fields masked: JSON (whole, or field by field
/// when it does not parse), forms, multipart and XML. Other bodies stay as
/// they are.
fn body(body: &CapturedBody, content_type: Option<&str>) -> CapturedBody {
    if body.data.is_empty() {
        return body.clone();
    }
    let original_type = content_type.unwrap_or("");
    let content_type = original_type.to_ascii_lowercase();
    let masked = if content_type.contains("multipart/") {
        multipart(&body.data, original_type)
    } else {
        text_body(&body.data, &content_type)
    };
    match masked {
        Some(data) => {
            // A body capture kept only in part stays marked as such, even
            // when masking made it longer.
            let size = if body.truncated() {
                body.size.max(data.len() as u64 + 1)
            } else {
                body.size
            };
            CapturedBody { data, size }
        }
        None => body.clone(),
    }
}

/// JSON, form or XML text with sensitive fields masked; `None` when
/// nothing was.
fn text_body(data: &[u8], content_type: &str) -> Option<Vec<u8>> {
    let structured = content_type.contains("json")
        || content_type.contains("x-www-form-urlencoded")
        || content_type.contains("xml");
    // A body cut inside a character keeps its last bytes as they are.
    let (text, tail): (Cow<'_, str>, &[u8]) = match std::str::from_utf8(data) {
        Ok(text) => (Cow::Borrowed(text), &[]),
        Err(error) if error.error_len().is_none() => {
            let valid = error.valid_up_to();
            (
                Cow::Borrowed(std::str::from_utf8(&data[..valid]).unwrap_or_default()),
                &data[valid..],
            )
        }
        Err(_) if structured => (String::from_utf8_lossy(data), &[]),
        Err(_) => return None,
    };
    let masked = if content_type.contains("json") || looks_like_json(&text) {
        match serde_json::from_str::<Value>(&text) {
            Ok(mut value) => {
                mask_json(&mut value).then(|| serde_json::to_string(&value).unwrap_or_default())
            }
            Err(_) => json_text(&text),
        }
    } else if content_type.contains("x-www-form-urlencoded") {
        let masked = form(&text);
        (masked != text).then_some(masked)
    } else if content_type.contains("xml") {
        xml(&text)
    } else {
        None
    }?;
    let mut out = masked.into_bytes();
    out.extend_from_slice(tail);
    Some(out)
}

fn looks_like_json(text: &str) -> bool {
    let trimmed = text.trim_start();
    trimmed.starts_with('{') || trimmed.starts_with('[') || trimmed.starts_with(")]}'")
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

/// JSON text that does not parse whole (cut short, several documents, a
/// prefix) with the value of each sensitive key masked, read as it comes:
/// a string followed by `:` is a key; its value, a string or a scalar, is
/// replaced, to the end of the text when it is cut off. Objects and arrays
/// under a sensitive key are left to their own keys, as in [`mask_json`].
fn json_text(text: &str) -> Option<String> {
    let bytes = text.as_bytes();
    let mut out = String::with_capacity(text.len());
    let mut copied = 0;
    let mut index = 0;
    let mut changed = false;
    while index < bytes.len() {
        if bytes[index] != b'"' {
            index += 1;
            continue;
        }
        let Some(key_end) = string_end(bytes, index) else {
            break;
        };
        let colon = skip_space(bytes, key_end + 1);
        if bytes.get(colon) != Some(&b':') {
            index = key_end + 1;
            continue;
        }
        let value = skip_space(bytes, colon + 1);
        if value >= bytes.len() {
            break;
        }
        if !sensitive_name(&text[index + 1..key_end]) {
            index = value;
            continue;
        }
        let value_end = match bytes[value] {
            b'{' | b'[' => {
                index = value;
                continue;
            }
            b'"' => string_end(bytes, value).map_or(bytes.len(), |end| end + 1),
            _ => bytes[value..]
                .iter()
                .position(|&b| matches!(b, b',' | b'}' | b']') || b.is_ascii_whitespace())
                .map_or(bytes.len(), |length| value + length),
        };
        out.push_str(&text[copied..value]);
        out.push('"');
        out.push_str(MASK);
        out.push('"');
        copied = value_end;
        index = value_end;
        changed = true;
    }
    if !changed {
        return None;
    }
    out.push_str(&text[copied..]);
    Some(out)
}

/// The index of the quote that closes the JSON string opening at `start`.
fn string_end(bytes: &[u8], start: usize) -> Option<usize> {
    let mut index = start + 1;
    while index < bytes.len() {
        match bytes[index] {
            b'\\' => index += 2,
            b'"' => return Some(index),
            _ => index += 1,
        }
    }
    None
}

fn skip_space(bytes: &[u8], mut index: usize) -> usize {
    while bytes.get(index).is_some_and(u8::is_ascii_whitespace) {
        index += 1;
    }
    index
}

/// A `multipart/*` body with the content of each part whose
/// `Content-Disposition` names a sensitive field masked.
fn multipart(data: &[u8], content_type: &str) -> Option<Vec<u8>> {
    let boundary = content_type.split(';').skip(1).find_map(|parameter| {
        let (name, value) = parameter.split_once('=')?;
        name.trim()
            .eq_ignore_ascii_case("boundary")
            .then(|| value.trim().trim_matches('"'))
    })?;
    if boundary.is_empty() {
        return None;
    }
    let delimiter = format!("--{boundary}").into_bytes();
    let starts = data
        .windows(delimiter.len())
        .enumerate()
        .filter(|(_, window)| *window == delimiter.as_slice())
        .map(|(start, _)| start)
        .collect::<Vec<_>>();
    let first = *starts.first()?;
    let mut out = Vec::with_capacity(data.len());
    out.extend_from_slice(&data[..first]);
    let mut changed = false;
    for (index, &start) in starts.iter().enumerate() {
        let end = starts.get(index + 1).copied().unwrap_or(data.len());
        let part = &data[start..end];
        match masked_part(part, delimiter.len()) {
            Some(masked) => {
                out.extend_from_slice(&masked);
                changed = true;
            }
            None => out.extend_from_slice(part),
        }
    }
    changed.then_some(out)
}

/// One part (from its delimiter up to the next) with its content masked,
/// when its field name is sensitive. The line break before the next
/// delimiter stays.
fn masked_part(part: &[u8], delimiter: usize) -> Option<Vec<u8>> {
    let after = &part[delimiter..];
    let head_end = after.windows(4).position(|window| window == b"\r\n\r\n")? + 4;
    let head = String::from_utf8_lossy(&after[..head_end]);
    let name = head.lines().find_map(|line| {
        let (header, value) = line.split_once(':')?;
        if !header.trim().eq_ignore_ascii_case("content-disposition") {
            return None;
        }
        value.split(';').find_map(|parameter| {
            let (key, value) = parameter.split_once('=')?;
            key.trim()
                .eq_ignore_ascii_case("name")
                .then(|| value.trim().trim_matches('"').to_string())
        })
    })?;
    if !sensitive_name(&name) {
        return None;
    }
    let content = &after[head_end..];
    let tail = if content.ends_with(b"\r\n") { 2 } else { 0 };
    let mut out = part[..delimiter + head_end].to_vec();
    out.extend_from_slice(MASK.as_bytes());
    out.extend_from_slice(&content[content.len() - tail..]);
    Some(out)
}

/// XML text with the text content of each element whose (local) name is
/// sensitive masked: `<password>p</password>`, `<ns:Token>t</ns:Token>`.
fn xml(text: &str) -> Option<String> {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    let mut changed = false;
    while let Some(open) = rest.find('<') {
        let after = &rest[open + 1..];
        let Some(close) = after.find('>') else {
            break;
        };
        let content_start = open + 1 + close + 1;
        let tag = &after[..close];
        let name = tag
            .split(|c: char| c.is_whitespace() || c == '/')
            .next()
            .unwrap_or("");
        let opening = !name.is_empty() && !tag.starts_with(['/', '?', '!']) && !tag.ends_with('/');
        let local = name.rsplit(':').next().unwrap_or(name);
        if opening && sensitive_name(local) {
            let content = &rest[content_start..];
            let value_end = content.find('<').unwrap_or(content.len());
            if !content[..value_end].trim().is_empty() {
                out.push_str(&rest[..content_start]);
                out.push_str(MASK);
                rest = &content[value_end..];
                changed = true;
                continue;
            }
        }
        out.push_str(&rest[..content_start]);
        rest = &rest[content_start..];
    }
    out.push_str(rest);
    changed.then_some(out)
}

/// Plain (not decrypted) HTTP/1 text in a captured chunk with sensitive
/// header values masked, for the pcapng export. Bytes that are not an
/// HTTP/1 head (TLS records, other protocols) come back unchanged. The head
/// is read line by line as bytes, so a header that is not UTF-8 does not
/// keep the others from being masked.
pub fn http1_text(data: &[u8]) -> Cow<'_, [u8]> {
    if !starts_like_http1(data) {
        return Cow::Borrowed(data);
    }
    let head_end = data
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map_or(data.len(), |end| end + 4);
    let (head, rest) = data.split_at(head_end);
    let mut changed = false;
    let mut out = Vec::with_capacity(head.len());
    for (index, line) in head.split_inclusive(|&b| b == b'\n').enumerate() {
        let ending = if line.ends_with(b"\r\n") {
            2
        } else {
            usize::from(line.ends_with(b"\n"))
        };
        let (content, ending) = line.split_at(line.len() - ending);
        let masked = if index == 0 {
            std::str::from_utf8(content).ok().and_then(request_line)
        } else {
            content.iter().position(|&b| b == b':').and_then(|colon| {
                let name = std::str::from_utf8(&content[..colon]).ok()?;
                let value = std::str::from_utf8(&content[colon + 1..]).unwrap_or("");
                let masked = if sensitive_name(name) {
                    MASK.to_string()
                } else {
                    header_value(name, value.trim())?
                };
                Some(format!("{name}: {masked}"))
            })
        };
        match masked {
            Some(masked) => {
                out.extend_from_slice(masked.as_bytes());
                out.extend_from_slice(ending);
                changed = true;
            }
            None => out.extend_from_slice(line),
        }
    }
    if !changed {
        return Cow::Borrowed(data);
    }
    out.extend_from_slice(rest);
    Cow::Owned(out)
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

    fn json_response(body: &[u8], encoding: Option<&str>) -> HttpExchange {
        let mut exchange = HttpExchange::new("POST", "https://api.example.test/login", &[]);
        exchange.status = Some(200);
        exchange.response_headers = vec![pair("Content-Type", "application/json")];
        if let Some(encoding) = encoding {
            exchange
                .response_headers
                .push(pair("Content-Encoding", encoding));
        }
        exchange.response_body = CapturedBody::of(body);
        exchange
    }

    fn contains(haystack: &[u8], needle: &[u8]) -> bool {
        haystack
            .windows(needle.len())
            .any(|window| window == needle)
    }

    /// A JSON document longer than capture keeps, a token first.
    fn long_json() -> Vec<u8> {
        let mut json = br#"{"access_token":"tok-secret-1","items":["#.to_vec();
        while json.len() < 3 * super::super::MAX_HTTP_BODY_BYTES {
            json.extend_from_slice(br#"{"name":"item","value":12345},"#);
        }
        json.extend_from_slice(br#"{}],"refresh_token":"tok-secret-2"}"#);
        json
    }

    #[test]
    fn json_cut_by_the_capture_limit_is_still_masked() {
        let exchange = json_response(&long_json(), None);
        assert!(exchange.response_body.truncated());
        let masked = super::exchange(&exchange);
        assert!(!contains(&masked.response_body.data, b"tok-secret-1"));
        assert!(contains(&masked.response_body.data, MASK.as_bytes()));
        assert!(masked.response_body.truncated(), "still marked as cut");

        // Cut inside the sensitive value itself, and inside a character.
        let cut = CapturedBody {
            data: "{\"password\":\"hunt".as_bytes().to_vec(),
            size: 100,
        };
        let masked = body(&cut, Some("application/json"));
        assert_eq!(masked.data, br#"{"password":"<redacted>""#);
        let mut cut_char = "{\"a\":\"报\",\"token\":\"t\",\"b\":\"表"
            .as_bytes()
            .to_vec();
        cut_char.pop();
        let masked = body(
            &CapturedBody {
                data: cut_char.clone(),
                size: 100,
            },
            Some("application/json"),
        );
        assert!(!contains(&masked.data, b"\"t\""));
        assert!(masked.data.ends_with(&cut_char[cut_char.len() - 2..]));
    }

    #[test]
    fn ndjson_and_prefixed_json_are_masked() {
        let ndjson = b"{\"id\":1,\"token\":\"a1\"}\n{\"id\":2,\"secret\":42}\n";
        let masked = body(&CapturedBody::of(ndjson), Some("application/x-ndjson"));
        assert_eq!(
            masked.data,
            b"{\"id\":1,\"token\":\"<redacted>\"}\n{\"id\":2,\"secret\":\"<redacted>\"}\n"
        );
        let prefixed = b")]}'\n{\"session_id\":\"s-1\",\"ok\":true}";
        let masked = body(&CapturedBody::of(prefixed), None);
        assert_eq!(
            masked.data,
            b")]}'\n{\"session_id\":\"<redacted>\",\"ok\":true}"
        );
    }

    #[test]
    fn a_decoded_body_longer_than_was_checked_never_goes_out_encoded() {
        let wire = gzip(&long_json());
        let exchange = json_response(&wire, Some("gzip"));
        let masked = super::exchange(&exchange);
        assert!(!contains(&masked.response_body.data, b"tok-secret-1"));
        assert_ne!(masked.response_body.data, wire, "not the original bytes");
        assert!(masked
            .response_headers
            .iter()
            .any(|(name, value)| name == DECODED_ENCODING_HEADER && value == "gzip"));

        // A body that does not decode here is left out.
        let mut broken = json_response(b"\x1f\x8b\x08\x00garbage", Some("gzip"));
        broken.response_body = CapturedBody::of(b"\x1f\x8b\x08\x00garbage-access_token");
        let masked = super::exchange(&broken);
        assert!(masked.response_body.data.is_empty());
        assert_eq!(masked.response_body.size, broken.response_body.size);
        assert!(masked
            .response_headers
            .iter()
            .any(|(name, _)| name == REDACTED_BODY_HEADER));
    }

    #[test]
    fn multipart_fields_and_xml_elements_are_masked() {
        let form = b"--XyZ\r\nContent-Disposition: form-data; name=\"user\"\r\n\r\nalice\r\n--XyZ\r\nContent-Disposition: form-data; name=\"password\"\r\n\r\nhunter2\r\n--XyZ--\r\n";
        let masked = body(
            &CapturedBody::of(form),
            Some("multipart/form-data; boundary=XyZ"),
        );
        assert!(!contains(&masked.data, b"hunter2"));
        assert!(contains(&masked.data, b"alice"));
        assert!(contains(
            &masked.data,
            b"name=\"password\"\r\n\r\n<redacted>\r\n--XyZ--"
        ));

        let xml = b"<login><user>a</user><ns:Password>p</ns:Password><keyword>k</keyword><session/></login>";
        let masked = body(&CapturedBody::of(xml), Some("text/xml"));
        assert_eq!(
            masked.data,
            b"<login><user>a</user><ns:Password><redacted></ns:Password><keyword>k</keyword><session/></login>"
        );
    }

    #[test]
    fn urls_in_headers_and_fragments_are_masked() {
        let mut exchange = HttpExchange::new(
            "GET",
            "https://app.example.test/cb#access_token=t-1&state=s",
            &[
                pair("Referer", "https://app.example.test/p?token=t-2&a=1"),
                pair("X-Authorization", "Bearer t-3"),
                pair("X-Auth-Key", "t-4"),
            ],
        );
        exchange.status = Some(302);
        exchange.response_headers = vec![
            pair(
                "Location",
                "https://app.example.test/cb?code=AUTH-CODE&state=s",
            ),
            pair("Link", "<https://cdn.example.test/a?sig=t-5>; rel=preload"),
            pair("Refresh", "0; url=/next?key=t-6"),
        ];
        let masked = super::exchange(&exchange);
        assert_eq!(
            masked.url,
            "https://app.example.test/cb#access_token=<redacted>&state=s"
        );
        let all = format!("{:?} {:?}", masked.request_headers, masked.response_headers);
        for secret in ["t-1", "t-2", "t-3", "t-4", "AUTH-CODE", "t-5", "t-6"] {
            assert!(!all.contains(secret), "{secret}: {all}");
        }
        assert!(all.contains("state=s"));
        assert!(all.contains("rel=preload"));
    }

    #[test]
    fn credential_names_are_masked_and_harmless_words_are_not() {
        for name in [
            "X-Authorization",
            "X-Auth-Key",
            "x-functions-key",
            "key",
            "sig",
            "auth",
            "PHPSESSID",
            "user_sid",
            "access_key",
            "AWSAccessKeyId",
            "privateKey",
            "otp",
        ] {
            assert!(sensitive_name(name), "{name}");
        }
        for name in [
            "keyword",
            "zipcode",
            "zipCode",
            "status_code",
            "author",
            "signal",
            "design",
            "inside",
            "code",
        ] {
            assert!(!sensitive_name(name), "{name}");
        }
        // `code` is an authorization code as a query or form parameter.
        assert_eq!(
            url("https://a.test/cb?code=c-1&zipcode=1"),
            "https://a.test/cb?code=<redacted>&zipcode=1"
        );
        assert_eq!(
            url("https://a.test/x?key=k&sig=s&auth=a&keyword=w"),
            "https://a.test/x?key=<redacted>&sig=<redacted>&auth=<redacted>&keyword=w"
        );
    }

    #[test]
    fn plain_heads_with_bytes_that_are_not_utf8_are_still_masked() {
        let text = b"HTTP/1.1 200 OK\r\nContent-Disposition: attachment; filename=\"\xb1\xa8.xls\"\r\nSet-Cookie: sid=plain-secret\r\nLocation: /next?token=t-7\r\n\r\nbody";
        let masked = http1_text(text);
        assert!(!contains(&masked, b"plain-secret"));
        assert!(!contains(&masked, b"t-7"));
        assert!(contains(&masked, b"filename=\"\xb1\xa8.xls\""));
        assert!(masked.ends_with(b"\r\n\r\nbody"));
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
