//! The `$`-API host. Engine bindings expose [`ScriptHost::call`] to scripts as
//! one function named [`SCRIPT_HOST_FUNCTION`]; [`SCRIPT_PRELUDE`] builds the
//! Loon globals on top of it. Every operation takes and returns strings, so a
//! binding needs no knowledge of the API.

use crate::{
    ScriptHttpClientRequest, ScriptInvocation, ScriptLimits, ScriptMutation, ScriptNotification,
    ScriptPhase, ScriptResponse, ScriptStore, SCRIPT_ENVIRONMENT,
};
use serde_json::{json, Map, Value};
use std::collections::{BTreeMap, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Global the binding defines before evaluating [`SCRIPT_PRELUDE`]. The
/// prelude removes it from the global object.
pub const SCRIPT_HOST_FUNCTION: &str = "__nc_host";

/// Shared JavaScript prelude, evaluated unchanged by every engine binding.
pub const SCRIPT_PRELUDE: &str = include_str!("prelude.js");

const MAX_NOTIFICATIONS: usize = 16;
const MAX_LOG_LINES: usize = 128;
const MAX_LOG_LINE_BYTES: usize = 2048;
const MAX_TIMERS: usize = 64;
const MAX_HTTP_REQUESTS: usize = 16;

pub(crate) enum HostEvent {
    Http(u64, Result<ScriptHttpClientRequest, String>),
    Timer(u64),
    Wait(Instant),
    Idle,
}

pub(crate) struct HostResults {
    pub done: Option<Result<ScriptMutation, String>>,
    pub notifications: Vec<ScriptNotification>,
    pub logs: Vec<String>,
    pub logs_truncated: bool,
}

pub struct ScriptHost {
    context_json: String,
    phase: ScriptPhase,
    /// The header list of the message the script may change (the request
    /// in the request phase, the response in the response phase), to give
    /// fields joined for the script back as they were.
    phase_headers: Vec<(String, String)>,
    binary_body: bool,
    default_store_key: String,
    max_output_bytes: usize,
    store: Arc<dyn ScriptStore>,
    done: Option<Result<ScriptMutation, String>>,
    notifications: Vec<ScriptNotification>,
    logs: Vec<String>,
    logs_truncated: bool,
    next_id: u64,
    timers: BTreeMap<u64, Instant>,
    pending_http: VecDeque<(u64, Result<ScriptHttpClientRequest, String>)>,
    http_requests: usize,
}

impl ScriptHost {
    pub fn new(
        invocation: &ScriptInvocation,
        limits: &ScriptLimits,
        store: Arc<dyn ScriptStore>,
    ) -> Self {
        Self {
            context_json: context_json(invocation),
            phase: invocation.phase,
            phase_headers: match invocation.phase {
                ScriptPhase::Request => invocation.request.headers.clone(),
                ScriptPhase::Response => invocation
                    .response
                    .as_ref()
                    .map(|response| response.headers.clone())
                    .unwrap_or_default(),
                _ => Vec::new(),
            },
            binary_body: invocation.binary_body,
            default_store_key: format!("networkcore.script.{}", invocation.script_name),
            max_output_bytes: limits.max_output_bytes,
            store,
            done: None,
            notifications: Vec::new(),
            logs: Vec::new(),
            logs_truncated: false,
            next_id: 1,
            timers: BTreeMap::new(),
            pending_http: VecDeque::new(),
            http_requests: 0,
        }
    }

    /// Handles one host call from the prelude. Unknown operations return
    /// `None` (`undefined` in JavaScript).
    pub fn call(&mut self, op: &str, payload: &str) -> Option<String> {
        match op {
            "context" => Some(self.context_json.clone()),
            "done" => {
                if self.done.is_none() {
                    let mut done =
                        parse_done(self.phase, payload, self.max_output_bytes, self.binary_body);
                    if let Ok(mutation) = done.as_mut() {
                        if let Some(headers) = mutation.headers.take() {
                            mutation.headers =
                                Some(restore_joined_headers(&self.phase_headers, headers));
                        }
                    }
                    self.done = Some(done);
                }
                None
            }
            "store.read" => self.store.read(&self.store_key(payload)),
            "store.write" => Some(self.store_write(payload).to_string()),
            "store.remove" => Some(self.store.remove(&self.store_key(payload)).to_string()),
            "notify" => {
                self.notify(payload);
                None
            }
            "log" => {
                self.log(payload);
                None
            }
            "timer.set" => Some(self.set_timer(payload).to_string()),
            "timer.clear" => {
                if let Ok(id) = payload.trim().parse::<u64>() {
                    self.timers.remove(&id);
                }
                None
            }
            "http.request" => Some(self.queue_http(payload).to_string()),
            _ => None,
        }
    }

    pub fn is_done(&self) -> bool {
        self.done.is_some()
    }

    /// Next unit of asynchronous work: queued `$httpClient` calls first, then
    /// due timers in id order, then the earliest pending timer.
    pub(crate) fn next_event(&mut self, now: Instant) -> HostEvent {
        if let Some((id, request)) = self.pending_http.pop_front() {
            return HostEvent::Http(id, request);
        }
        let due = self
            .timers
            .iter()
            .find(|(_, at)| **at <= now)
            .map(|(id, _)| *id);
        if let Some(id) = due {
            self.timers.remove(&id);
            return HostEvent::Timer(id);
        }
        match self.timers.values().min() {
            Some(at) => HostEvent::Wait(*at),
            None => HostEvent::Idle,
        }
    }

    pub(crate) fn take_results(&mut self) -> HostResults {
        HostResults {
            done: self.done.take(),
            notifications: std::mem::take(&mut self.notifications),
            logs: std::mem::take(&mut self.logs),
            logs_truncated: self.logs_truncated,
        }
    }

    fn next_id(&mut self) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        id
    }

    fn store_key(&self, key: &str) -> String {
        if key.is_empty() {
            self.default_store_key.clone()
        } else {
            key.to_string()
        }
    }

    fn store_write(&self, payload: &str) -> bool {
        let Ok(value) = serde_json::from_str::<Value>(payload) else {
            return false;
        };
        let key = value.get("key").and_then(Value::as_str).unwrap_or("");
        let Some(data) = value.get("value").and_then(Value::as_str) else {
            return false;
        };
        self.store.write(&self.store_key(key), data)
    }

    fn notify(&mut self, payload: &str) {
        if self.notifications.len() >= MAX_NOTIFICATIONS {
            return;
        }
        let Ok(value) = serde_json::from_str::<Value>(payload) else {
            return;
        };
        let field = |name: &str| {
            truncate_utf8(
                value.get(name).and_then(Value::as_str).unwrap_or(""),
                MAX_LOG_LINE_BYTES,
            )
        };
        let open_url = Some(field("url")).filter(|url| !url.is_empty());
        self.notifications.push(ScriptNotification {
            title: field("title"),
            subtitle: field("subtitle"),
            content: field("content"),
            open_url,
        });
    }

    fn log(&mut self, line: &str) {
        if self.logs.len() >= MAX_LOG_LINES {
            self.logs_truncated = true;
            return;
        }
        if line.len() > MAX_LOG_LINE_BYTES {
            self.logs_truncated = true;
        }
        self.logs.push(truncate_utf8(line, MAX_LOG_LINE_BYTES));
    }

    /// Returns the timer id, or 0 when the timer limit is reached.
    fn set_timer(&mut self, payload: &str) -> u64 {
        if self.timers.len() >= MAX_TIMERS {
            return 0;
        }
        let delay_ms = payload
            .trim()
            .parse::<f64>()
            .ok()
            .filter(|delay| delay.is_finite() && *delay > 0.0)
            .unwrap_or(0.0)
            .min(u32::MAX as f64);
        let id = self.next_id();
        self.timers
            .insert(id, Instant::now() + Duration::from_millis(delay_ms as u64));
        id
    }

    /// Queues a `$httpClient` call. Invalid options still get an id so the
    /// script callback receives the error.
    fn queue_http(&mut self, payload: &str) -> u64 {
        let id = self.next_id();
        let request = if self.http_requests >= MAX_HTTP_REQUESTS {
            Err("networkcore: $httpClient request limit reached".to_string())
        } else {
            parse_http_request(payload)
        };
        self.http_requests += 1;
        self.pending_http.push_back((id, request));
        id
    }
}

fn context_json(invocation: &ScriptInvocation) -> String {
    let mut request = Map::new();
    request.insert("url".into(), json!(invocation.request.url));
    request.insert("method".into(), json!(invocation.request.method));
    request.insert(
        "headers".into(),
        headers_object(&invocation.request.headers),
    );
    if let Some(body) = &invocation.request.body {
        request.insert("body".into(), json!(body));
    }

    let mut context = Map::new();
    context.insert("phase".into(), json!(invocation.phase.as_str()));
    if let Some(event) = &invocation.event {
        context.insert("event".into(), json!(event));
    }
    context.insert("scriptName".into(), json!(invocation.script_name));
    context.insert("argument".into(), json!(invocation.argument));
    context.insert("environment".into(), json!(SCRIPT_ENVIRONMENT));
    context.insert("binaryBody".into(), json!(invocation.binary_body));
    context.insert("bodyIsBytes".into(), json!(invocation.body_is_bytes));
    // Scripts that both capture cookies and check in tell the two apart by
    // whether `$request` exists, so a scheduled run must not have one.
    if invocation.phase.is_http() {
        context.insert("request".into(), Value::Object(request));
    } else if invocation.phase == ScriptPhase::Rule {
        let rule = invocation.rule.clone().unwrap_or_default();
        context.insert(
            "request".into(),
            json!({
                "hostname": rule.hostname,
                "destIP": rule.dest_ip.map(|ip| ip.to_string()),
                "destPort": rule.dest_port,
                "sourceIP": rule.source_ip.map(|ip| ip.to_string()),
                "inPort": rule.in_port,
                "processName": rule.process_name,
                "protocol": rule.protocol,
                "userAgent": rule.user_agent,
                "url": rule.url,
            }),
        );
    }
    if let Some(response) = &invocation.response {
        let mut object = Map::new();
        object.insert("status".into(), json!(response.status));
        object.insert("headers".into(), headers_object(&response.headers));
        if let Some(body) = &response.body {
            object.insert("body".into(), json!(body));
        }
        context.insert("response".into(), Value::Object(object));
    }
    Value::Object(context).to_string()
}

/// Header lists become plain objects; repeated names are joined with ", ",
/// except `Cookie`, whose fields (HTTP/2 clients split it, RFC 9113
/// section 8.2.3) are joined with "; " so the value stays one valid cookie
/// list a script can read and hand back.
pub(crate) fn headers_object(headers: &[(String, String)]) -> Value {
    let mut object = Map::new();
    for (name, value) in headers {
        match object.get_mut(name) {
            Some(Value::String(existing)) => {
                existing.push_str(header_join_separator(name));
                existing.push_str(value);
            }
            _ => {
                object.insert(name.clone(), Value::String(value.clone()));
            }
        }
    }
    Value::Object(object)
}

/// What [`headers_object`] puts between repeated fields of `name`.
fn header_join_separator(name: &str) -> &'static str {
    if name.eq_ignore_ascii_case("cookie") {
        "; "
    } else {
        ", "
    }
}

/// Gives back the fields [`headers_object`] joined for a script, for the
/// header list the script returns with `$done({headers})`. A name that
/// `original` holds more than once, returned with exactly the joined value
/// (the script did not change it), becomes the original fields again, in
/// their order: several `Set-Cookie` fields cannot be joined into one
/// (their `Expires` dates hold commas), so a script that only removes
/// another header must not merge them. A value the script changed stays
/// one field; names the script removed stay removed.
pub fn restore_joined_headers(
    original: &[(String, String)],
    returned: Vec<(String, String)>,
) -> Vec<(String, String)> {
    let mut restored = Vec::with_capacity(returned.len());
    for (name, value) in returned {
        let mut fields = original.iter().filter(|(field, _)| *field == name);
        let first = fields.next();
        let joined = first.and_then(|(_, first)| {
            let mut joined = first.clone();
            let mut repeated = false;
            for (_, next) in fields {
                repeated = true;
                joined.push_str(header_join_separator(&name));
                joined.push_str(next);
            }
            repeated.then_some(joined)
        });
        if joined.as_deref() == Some(value.as_str()) {
            restored.extend(original.iter().filter(|(field, _)| *field == name).cloned());
        } else {
            restored.push((name, value));
        }
    }
    restored
}

fn present<'a>(object: &'a Map<String, Value>, key: &str) -> Option<&'a Value> {
    object.get(key).filter(|value| !value.is_null())
}

fn parse_done(
    phase: ScriptPhase,
    payload: &str,
    max_output_bytes: usize,
    binary: bool,
) -> Result<ScriptMutation, String> {
    let value = serde_json::from_str::<Value>(payload)
        .map_err(|_| "$done argument is not JSON-serializable".to_string())?;
    if phase == ScriptPhase::Rule {
        // `$done({matched: true})`; anything else is no match.
        let matched = value.get("matched").and_then(Value::as_bool) == Some(true);
        return Ok(ScriptMutation {
            matched: Some(matched),
            ..ScriptMutation::default()
        });
    }
    if !phase.is_http() {
        // Scheduled and event scripts end with `$done()` or `$done({})`;
        // whatever they pass has nothing to change.
        return Ok(ScriptMutation::default());
    }
    let Value::Object(object) = value else {
        return Err("$done argument must be an object".to_string());
    };

    let mut mutation = ScriptMutation::default();
    if let Some(headers) = present(&object, "headers") {
        mutation.headers = Some(parse_headers(headers)?);
    }
    let (body, mut bytes_given) = parse_message_body(&object, max_output_bytes, binary)?;
    mutation.body = body;
    let mut response_bytes = false;
    match phase {
        ScriptPhase::Request => {
            if let Some(url) = present(&object, "url") {
                let url = url
                    .as_str()
                    .ok_or_else(|| "$done url must be a string".to_string())?;
                if url.len() > max_output_bytes || url.contains(['\r', '\n']) {
                    return Err("$done url is invalid".to_string());
                }
                mutation.url = Some(url.to_string());
            }
            if let Some(response) = present(&object, "response") {
                let (response, bytes) = parse_response(response, max_output_bytes, binary)?;
                mutation.response = Some(response);
                response_bytes = bytes;
            } else if present(&object, "status").is_some() {
                // Quantumult X `script-echo-response`: `$done` gets the
                // response itself (`{status: "HTTP/1.1 200 OK", headers, body}`).
                let response = Value::Object(object.clone());
                let (response, bytes) = parse_response(&response, max_output_bytes, binary)?;
                mutation.response = Some(response);
                response_bytes = bytes;
                mutation.headers = None;
                mutation.body = None;
                bytes_given = false;
            }
        }
        ScriptPhase::Response => {
            if let Some(status) = present(&object, "status") {
                mutation.status = Some(parse_status(status)?);
            }
        }
        ScriptPhase::Cron | ScriptPhase::Event | ScriptPhase::Generic | ScriptPhase::Rule => {}
    }
    if !binary && (bytes_given || response_bytes) {
        // Quantumult X `bodyBytes` outside binary-body-mode: every body of
        // the mutation becomes a byte string, text as its UTF-8 bytes.
        if !bytes_given {
            if let Some(body) = mutation.body.as_mut() {
                *body = crate::binary_body_string(body.as_bytes());
            }
        }
        if !response_bytes {
            if let Some(body) = mutation
                .response
                .as_mut()
                .and_then(|response| response.body.as_mut())
            {
                *body = crate::binary_body_string(body.as_bytes());
            }
        }
        mutation.binary_bodies = true;
    }
    Ok(mutation)
}

/// A message's `body`, or outside binary-body-mode its Quantumult X
/// `bodyBytes` (a byte string from the prelude), which wins over `body` as
/// in Quantumult X. Returns whether the body is a byte string from
/// `bodyBytes`.
fn parse_message_body(
    object: &Map<String, Value>,
    max_output_bytes: usize,
    binary: bool,
) -> Result<(Option<String>, bool), String> {
    if !binary {
        if let Some(bytes) = present(object, "bodyBytes") {
            return Ok((Some(parse_body(bytes, max_output_bytes, true)?), true));
        }
    }
    match present(object, "body") {
        Some(body) => Ok((Some(parse_body(body, max_output_bytes, binary)?), false)),
        None => Ok((None, false)),
    }
}

/// The response a request script answers with, and whether its body is a
/// byte string from `bodyBytes`.
fn parse_response(
    value: &Value,
    max_output_bytes: usize,
    binary: bool,
) -> Result<(ScriptResponse, bool), String> {
    let Value::Object(object) = value else {
        return Err("$done response must be an object".to_string());
    };
    let status = match present(object, "status") {
        Some(status) => parse_status(status)?,
        None => 200,
    };
    let headers = match present(object, "headers") {
        Some(headers) => parse_headers(headers)?,
        None => Vec::new(),
    };
    let (body, bytes) = parse_message_body(object, max_output_bytes, binary)?;
    Ok((
        ScriptResponse {
            status,
            headers,
            body,
        },
        bytes,
    ))
}

/// Accepts a number or a status line such as `HTTP/1.1 404 Not Found`.
fn parse_status(value: &Value) -> Result<u16, String> {
    let status = match value {
        Value::Number(number) => number.as_u64(),
        Value::String(text) => text
            .split_whitespace()
            .find_map(|token| token.parse::<u64>().ok()),
        _ => None,
    };
    status
        .filter(|status| (100..=599).contains(status))
        .map(|status| status as u16)
        .ok_or_else(|| "$done status must be an HTTP status between 100 and 599".to_string())
}

fn parse_headers(value: &Value) -> Result<Vec<(String, String)>, String> {
    let Value::Object(object) = value else {
        return Err("$done headers must be an object".to_string());
    };
    let mut headers = Vec::with_capacity(object.len());
    for (name, value) in object {
        let value = match value {
            Value::Null => continue,
            Value::String(text) => text.clone(),
            Value::Number(number) => number.to_string(),
            Value::Bool(flag) => flag.to_string(),
            _ => return Err(format!("$done header {name} must be a string")),
        };
        let name_valid = !name.is_empty()
            && name
                .bytes()
                .all(|byte| byte.is_ascii_graphic() && byte != b':');
        if !name_valid || value.contains(['\r', '\n', '\0']) {
            return Err("$done headers contain an invalid name or value".to_string());
        }
        headers.push((name.clone(), value));
    }
    Ok(headers)
}

/// A text body, or in binary mode a byte string (the prelude converts
/// `Uint8Array`, `ArrayBuffer` and text bodies to one).
fn parse_body(value: &Value, max_output_bytes: usize, binary: bool) -> Result<String, String> {
    let body = value.as_str().ok_or_else(|| {
        if binary {
            "$done body must be a string, Uint8Array or ArrayBuffer".to_string()
        } else {
            "$done body must be a string; binary bodies need binary-body-mode".to_string()
        }
    })?;
    let len = if binary {
        if body.chars().any(|ch| u32::from(ch) > 0xff) {
            return Err("$done binary body is not a byte string".to_string());
        }
        body.chars().count()
    } else {
        body.len()
    };
    if len > max_output_bytes {
        return Err("$done body exceeds the output limit".to_string());
    }
    Ok(body.to_string())
}

fn parse_http_request(payload: &str) -> Result<ScriptHttpClientRequest, String> {
    let value = serde_json::from_str::<Value>(payload)
        .map_err(|_| "networkcore: invalid $httpClient options".to_string())?;
    // Checked here, in Rust: a script controls the whole payload (it can
    // replace `String.prototype.toUpperCase` or `JSON.stringify`), so the
    // prelude cannot be trusted to have passed a fixed method name.
    let method = value.get("method").and_then(Value::as_str).unwrap_or("GET");
    if !crate::is_http_method_token(method) {
        return Err(crate::SCRIPT_HTTP_CLIENT_INVALID_METHOD_MESSAGE.to_string());
    }
    let method = method.to_ascii_uppercase();
    let url = value.get("url").and_then(Value::as_str).unwrap_or("");
    if !(url.starts_with("https://") || url.starts_with("http://")) {
        return Err("networkcore: $httpClient needs an http or https URL".to_string());
    }
    let headers = match value.get("headers").filter(|headers| !headers.is_null()) {
        Some(headers) => parse_headers(headers)
            .map_err(|_| "networkcore: invalid $httpClient headers".to_string())?,
        None => Vec::new(),
    };
    let flag = |name: &str| value.get(name).and_then(Value::as_bool);
    let body_binary = flag("bodyBinary").unwrap_or(false);
    let body = value
        .get("body")
        .and_then(Value::as_str)
        .map(str::to_string);
    if body_binary
        && body
            .as_deref()
            .is_some_and(|body| body.chars().any(|ch| u32::from(ch) > 0xff))
    {
        return Err("networkcore: invalid $httpClient body".to_string());
    }
    let timeout_ms = value
        .get("timeout")
        .and_then(Value::as_f64)
        .filter(|timeout| timeout.is_finite() && *timeout > 0.0)
        .unwrap_or(0.0)
        .min(u32::MAX as f64);
    Ok(ScriptHttpClientRequest {
        method,
        url: url.to_string(),
        headers,
        body,
        body_binary,
        binary_response: flag("binaryMode").unwrap_or(false),
        follow_redirects: flag("followRedirects").unwrap_or(true),
        // Zero means "the rest of the dispatch budget"; the driver caps it.
        timeout: Duration::from_millis(timeout_ms as u64),
    })
}

pub(crate) fn truncate_utf8(text: &str, max_bytes: usize) -> String {
    if text.len() <= max_bytes {
        return text.to_string();
    }
    let mut end = max_bytes;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    text[..end].to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quantumult_body_bytes_outside_binary_mode_are_byte_strings() {
        // `bodyBytes` wins over `body`; the prelude sends it as a byte string.
        let mutation = parse_done(
            ScriptPhase::Response,
            r#"{"body":"ignored","bodyBytes":"\u0000\u00ff"}"#,
            1024,
            false,
        )
        .expect("bytes parse");
        assert_eq!(mutation.body.as_deref(), Some("\u{0}\u{ff}"));
        assert!(mutation.binary_bodies);

        // Text alone stays text.
        let mutation =
            parse_done(ScriptPhase::Response, r#"{"body":"é"}"#, 1024, false).expect("text parses");
        assert_eq!(mutation.body.as_deref(), Some("é"));
        assert!(!mutation.binary_bodies);

        // An echo response with bytes; a char above U+00FF is no byte.
        let mutation = parse_done(
            ScriptPhase::Request,
            r#"{"status":200,"bodyBytes":"\u0001"}"#,
            1024,
            false,
        )
        .expect("echo bytes parse");
        assert_eq!(
            mutation
                .response
                .and_then(|response| response.body)
                .as_deref(),
            Some("\u{1}")
        );
        assert!(mutation.binary_bodies);
        assert!(parse_done(ScriptPhase::Response, r#"{"bodyBytes":"é€"}"#, 1024, false).is_err());

        // A text body next to a byte-string response becomes its UTF-8 bytes.
        let mutation = parse_done(
            ScriptPhase::Request,
            r#"{"body":"é","response":{"bodyBytes":"\u0002"}}"#,
            1024,
            false,
        )
        .expect("mixed parse");
        assert_eq!(mutation.body.as_deref(), Some("\u{c3}\u{a9}"));
        assert!(mutation.binary_bodies);
    }

    #[test]
    fn http_client_methods_must_be_tokens() {
        let parse = |method: &str| {
            parse_http_request(
                &json!({"url": "http://127.0.0.1:6379/", "method": method}).to_string(),
            )
        };
        let too_long = "A".repeat(crate::SCRIPT_HTTP_CLIENT_MAX_METHOD_BYTES + 1);
        for bad in [
            "GET\r\nX",
            "FLUSHALL\r\nQUIT\r\nX",
            "G ET",
            "GET\u{0}",
            "",
            "GÉT",
            "GET/",
            too_long.as_str(),
        ] {
            assert_eq!(
                parse(bad).unwrap_err(),
                crate::SCRIPT_HTTP_CLIENT_INVALID_METHOD_MESSAGE,
                "{bad:?}"
            );
        }
        assert_eq!(parse("get").unwrap().method, "GET");
        assert_eq!(parse("PATCH").unwrap().method, "PATCH");
        assert_eq!(parse("propfind").unwrap().method, "PROPFIND");
        // No method is a GET.
        let request = parse_http_request(r#"{"url":"https://example.test/"}"#).unwrap();
        assert_eq!(request.method, "GET");
    }

    #[test]
    fn unchanged_repeated_fields_come_back_as_they_were() {
        let pairs = |list: &[(&str, &str)]| {
            list.iter()
                .map(|(name, value)| (name.to_string(), value.to_string()))
                .collect::<Vec<_>>()
        };
        let original = pairs(&[
            ("Set-Cookie", "a=1; Path=/"),
            ("Content-Security-Policy", "default-src 'self'"),
            ("Set-Cookie", "b=2; Expires=Wed, 21 Oct 2026 07:28:00 GMT"),
            ("Set-Cookie", "c=3"),
            ("Vary", "Accept"),
        ]);
        let object = headers_object(&original);
        // The script deletes one header and hands the rest back unchanged.
        let mut returned = parse_headers(&object).unwrap();
        returned.retain(|(name, _)| name != "Content-Security-Policy");
        let restored = restore_joined_headers(&original, returned);
        let cookies = restored
            .iter()
            .filter(|(name, _)| name == "Set-Cookie")
            .map(|(_, value)| value.as_str())
            .collect::<Vec<_>>();
        assert_eq!(
            cookies,
            [
                "a=1; Path=/",
                "b=2; Expires=Wed, 21 Oct 2026 07:28:00 GMT",
                "c=3"
            ]
        );
        assert!(restored.contains(&("Vary".to_string(), "Accept".to_string())));
        assert!(!restored
            .iter()
            .any(|(name, _)| name == "Content-Security-Policy"));

        // A changed value stays one field; a removed name stays removed.
        let restored = restore_joined_headers(
            &original,
            pairs(&[("Set-Cookie", "only=1"), ("Vary", "Accept")]),
        );
        assert_eq!(
            restored,
            pairs(&[("Set-Cookie", "only=1"), ("Vary", "Accept")])
        );
        let restored = restore_joined_headers(&original, pairs(&[("Vary", "Accept")]));
        assert_eq!(restored, pairs(&[("Vary", "Accept")]));
    }

    #[test]
    fn done_headers_keep_unchanged_set_cookie_fields() {
        let store: Arc<dyn ScriptStore> = Arc::new(crate::MemoryScriptStore::new());
        let invocation = ScriptInvocation {
            phase: ScriptPhase::Response,
            script_name: "test".to_string(),
            argument: String::new(),
            request: crate::ScriptRequest {
                url: "https://example.test/".to_string(),
                method: "GET".to_string(),
                headers: Vec::new(),
                body: None,
            },
            response: Some(ScriptResponse {
                status: 200,
                headers: vec![
                    ("Set-Cookie".to_string(), "a=1".to_string()),
                    ("Set-Cookie".to_string(), "b=2".to_string()),
                ],
                body: None,
            }),
            binary_body: false,
            body_is_bytes: false,
            event: None,
            rule: None,
        };
        let mut host = ScriptHost::new(&invocation, &ScriptLimits::default(), store);
        host.call("done", r#"{"headers":{"Set-Cookie":"a=1, b=2","X":"1"}}"#);
        let mutation = host.take_results().done.unwrap().unwrap();
        assert_eq!(
            mutation.headers.unwrap(),
            vec![
                ("Set-Cookie".to_string(), "a=1".to_string()),
                ("Set-Cookie".to_string(), "b=2".to_string()),
                ("X".to_string(), "1".to_string()),
            ]
        );
    }

    #[test]
    fn split_cookie_fields_join_as_one_cookie_list() {
        let pairs = |list: &[(&str, &str)]| {
            list.iter()
                .map(|(name, value)| (name.to_string(), value.to_string()))
                .collect::<Vec<_>>()
        };
        let object = headers_object(&pairs(&[
            ("cookie", "a=1"),
            ("accept", "x"),
            ("cookie", "b=2"),
            ("accept", "y"),
            ("Cookie", "c=3"),
            ("Cookie", "d=4"),
        ]));
        assert_eq!(object["cookie"], "a=1; b=2");
        assert_eq!(object["Cookie"], "c=3; d=4");
        assert_eq!(object["accept"], "x, y");
    }

    #[test]
    fn request_done_with_a_status_is_a_quantumult_echo_response() {
        let mutation = parse_done(
            ScriptPhase::Request,
            r#"{"status":"HTTP/1.1 200 OK","headers":{"Content-Type":"text/html"},"body":"ok"}"#,
            1024,
            false,
        )
        .expect("echo response should parse");
        let response = mutation.response.expect("echo $done is a response");
        assert_eq!(response.status, 200);
        assert_eq!(response.body.as_deref(), Some("ok"));
        assert_eq!(
            response.headers,
            vec![("Content-Type".to_string(), "text/html".to_string())]
        );
        assert!(mutation.headers.is_none() && mutation.body.is_none());

        // A plain request mutation is unchanged.
        let mutation = parse_done(ScriptPhase::Request, r#"{"body":"x"}"#, 1024, false)
            .expect("request mutation should parse");
        assert!(mutation.response.is_none());
        assert_eq!(mutation.body.as_deref(), Some("x"));
    }
}
