//! HAR 1.2 entries for decrypted HTTP exchanges.

use std::net::SocketAddr;

use serde_json::{json, Value};

use super::{base64_encode, decode, Captured, CapturedBody, HttpExchange, MAX_HTTP_BODY_BYTES};

pub(super) fn entry(id: u64, captured: &Captured, exchange: &HttpExchange) -> Value {
    let ended = exchange.ended_at_ms.unwrap_or(exchange.started_at_ms);
    let wait = ended.saturating_sub(exchange.started_at_ms);
    let header = |name: &str, headers: &[(String, String)]| {
        headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.clone())
    };
    let headers = |headers: &[(String, String)]| {
        headers
            .iter()
            .map(|(name, value)| json!({ "name": name, "value": value }))
            .collect::<Vec<_>>()
    };
    let mut request = json!({
        "method": exchange.method,
        "url": exchange.url,
        "httpVersion": exchange.http_version,
        "cookies": [],
        "headers": headers(&exchange.request_headers),
        "queryString": query(&exchange.url),
        "headersSize": -1,
        "bodySize": exchange.request_body.size,
    });
    let mut comment = Vec::new();
    if exchange.request_body.size > 0 {
        let mime = header("Content-Type", &exchange.request_headers).unwrap_or_default();
        let mut post = json!({ "mimeType": mime });
        let encoding = header("Content-Encoding", &exchange.request_headers);
        comment.extend(text(&mut post, &exchange.request_body, encoding.as_deref()));
        request["postData"] = post;
    }
    let status = exchange.status.unwrap_or(0);
    let mime = header("Content-Type", &exchange.response_headers).unwrap_or_default();
    let mut content = json!({ "size": exchange.response_body.size, "mimeType": mime });
    let encoding = header("Content-Encoding", &exchange.response_headers);
    comment.extend(text(
        &mut content,
        &exchange.response_body,
        encoding.as_deref(),
    ));
    let body_size = if exchange.status.is_some() {
        exchange.response_body.size as i64
    } else {
        -1
    };
    let mut entry = json!({
        "startedDateTime": iso8601(exchange.started_at_ms),
        "time": wait,
        "request": request,
        "response": {
            "status": status,
            "statusText": status_text(status),
            "httpVersion": exchange.http_version,
            "cookies": [],
            "headers": headers(&exchange.response_headers),
            "content": content,
            "redirectURL": header("Location", &exchange.response_headers).unwrap_or_default(),
            "headersSize": -1,
            "bodySize": body_size,
        },
        "cache": {},
        "timings": { "send": 0, "wait": wait, "receive": 0 },
        "connection": id.to_string(),
    });
    if let Ok(address) = captured.destination.parse::<SocketAddr>() {
        entry["serverIPAddress"] = json!(address.ip().to_string());
    }
    if let Some(note) = exchange.note {
        comment.insert(0, note.to_string());
    }
    if exchange.request_body.truncated() || exchange.response_body.truncated() {
        comment.push(format!("bodies truncated to {MAX_HTTP_BODY_BYTES} bytes"));
    }
    if !comment.is_empty() {
        entry["comment"] = json!(comment.join("; "));
    }
    entry
}

/// `text` (UTF-8) or `text` + `encoding: base64`, with `Content-Encoding`
/// undone first as HAR asks (`size` then counts the decoded bytes and
/// `compression` the bytes saved). Returns a comment when the body could
/// not be decoded, or only in part.
fn text(target: &mut Value, body: &CapturedBody, content_encoding: Option<&str>) -> Option<String> {
    if body.data.is_empty() {
        return None;
    }
    let mut comment = None;
    let mut data = std::borrow::Cow::Borrowed(body.data.as_slice());
    if let Some(coding) = content_encoding.filter(|coding| !decode::codings(coding).is_empty()) {
        match decode::decode_body(
            &body.data,
            coding,
            !body.truncated(),
            decode::DecodeLimits::EXTENSION,
        ) {
            Ok(decoded) => {
                if decoded.truncated {
                    comment = Some(format!(
                        "{coding} body decoded only in part ({} bytes)",
                        decoded.data.len()
                    ));
                } else {
                    let size = decoded.data.len() as u64;
                    target["size"] = json!(size);
                    target["compression"] = json!(size.saturating_sub(body.size));
                }
                data = std::borrow::Cow::Owned(decoded.data);
            }
            Err(error) => comment = Some(format!("{coding} body left encoded: {error}")),
        }
    }
    match std::str::from_utf8(&data) {
        Ok(text) => target["text"] = json!(text),
        Err(_) => {
            target["text"] = json!(base64_encode(&data));
            target["encoding"] = json!("base64");
        }
    }
    comment
}

fn query(url: &str) -> Vec<Value> {
    let Some((_, query)) = url.split_once('?') else {
        return Vec::new();
    };
    let query = query.split('#').next().unwrap_or("");
    query
        .split('&')
        .filter(|pair| !pair.is_empty())
        .map(|pair| {
            let (name, value) = pair.split_once('=').unwrap_or((pair, ""));
            json!({ "name": name, "value": value })
        })
        .collect()
}

pub(super) fn status_text(status: u16) -> &'static str {
    match status {
        200 => "OK",
        201 => "Created",
        204 => "No Content",
        206 => "Partial Content",
        301 => "Moved Permanently",
        302 => "Found",
        304 => "Not Modified",
        307 => "Temporary Redirect",
        308 => "Permanent Redirect",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        429 => "Too Many Requests",
        500 => "Internal Server Error",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        504 => "Gateway Timeout",
        _ => "",
    }
}

/// `2026-11-14T09:57:13.123Z` for Unix milliseconds.
pub(super) fn iso8601(millis: u64) -> String {
    let seconds = millis / 1000;
    let days = (seconds / 86_400) as i64;
    let rest = seconds % 86_400;
    // Civil date from days since 1970-01-01 (H. Hinnant).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}.{:03}Z",
        rest / 3600,
        rest % 3600 / 60,
        rest % 60,
        millis % 1000,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_utc_times() {
        assert_eq!(iso8601(0), "1970-01-01T00:00:00.000Z");
        assert_eq!(iso8601(1_794_995_833_123), "2026-11-18T09:57:13.123Z");
        assert_eq!(iso8601(951_782_400_000), "2000-02-29T00:00:00.000Z");
    }
}
