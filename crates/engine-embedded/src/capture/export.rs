//! Request exports of decrypted HTTP exchanges: cURL commands, code in a
//! few languages, a Postman collection (v2.1) and an Insomnia export (v4).
//!
//! Every function takes the exchanges already redacted (or not) by the
//! caller. Hop-by-hop and computed headers (`Host`, `Content-Length`,
//! `Connection`, HTTP/2 pseudo headers) are left out: the client that runs
//! the export sets them itself. A body that is not UTF-8, or that capture
//! cut short, is not inlined; a comment says so instead.

use serde_json::{json, Value};

use super::HttpExchange;

/// Code languages of the `code` export.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Language {
    /// Python `requests`.
    #[default]
    Python,
    /// JavaScript `fetch`.
    Javascript,
    /// Swift `URLSession`.
    Swift,
    /// Kotlin OkHttp.
    Kotlin,
    /// Go `net/http`.
    Go,
}

impl Language {
    pub fn extension(self) -> &'static str {
        match self {
            Self::Python => "py",
            Self::Javascript => "js",
            Self::Swift => "swift",
            Self::Kotlin => "kt",
            Self::Go => "go",
        }
    }
}

/// Headers the exporting client sets itself.
const SKIPPED_HEADERS: [&str; 7] = [
    "host",
    "content-length",
    "connection",
    "keep-alive",
    "proxy-connection",
    "transfer-encoding",
    "upgrade",
];

fn kept_headers(exchange: &HttpExchange) -> Vec<(&str, &str)> {
    exchange
        .request_headers
        .iter()
        .filter(|(name, _)| {
            !name.starts_with(':') && !SKIPPED_HEADERS.contains(&name.to_ascii_lowercase().as_str())
        })
        .map(|(name, value)| (name.as_str(), value.as_str()))
        .collect()
}

/// The request body as text, when it can be inlined.
enum BodyText<'a> {
    None,
    Text(&'a str),
    /// Not inlined; the reason, for a comment.
    Omitted(String),
}

fn body_text(exchange: &HttpExchange) -> BodyText<'_> {
    let body = &exchange.request_body;
    if body.size == 0 {
        return BodyText::None;
    }
    if body.size > body.data.len() as u64 {
        return BodyText::Omitted(format!(
            "request body of {} bytes was only partly captured and is not included",
            body.size
        ));
    }
    match std::str::from_utf8(&body.data) {
        Ok(text) => BodyText::Text(text),
        Err(_) => BodyText::Omitted(format!(
            "binary request body of {} bytes is not included",
            body.size
        )),
    }
}

fn title(exchange: &HttpExchange) -> String {
    format!("{} {}", exchange.method, exchange.url)
}

fn is_h2(exchange: &HttpExchange) -> bool {
    exchange.http_version == super::HTTP_2
}

/// One `curl` command per exchange, in a shell script.
pub fn curl(exchanges: &[&HttpExchange]) -> String {
    let mut out = String::from("#!/bin/sh\n# Exported by AnixOps Net\n");
    for exchange in exchanges {
        out.push('\n');
        out.push_str(&format!("# {}\n", one_line(&title(exchange))));
        let body = body_text(exchange);
        if let BodyText::Omitted(reason) = &body {
            out.push_str(&format!("# {reason}\n"));
        }
        out.push_str("curl");
        if is_h2(exchange) {
            out.push_str(" --http2");
        }
        if exchange.method != "GET" || matches!(body, BodyText::Text(_)) {
            out.push_str(&format!(" -X {}", shell(&exchange.method)));
        }
        out.push_str(&format!(" {}", shell(&exchange.url)));
        for (name, value) in kept_headers(exchange) {
            out.push_str(&format!(" \\\n  -H {}", shell(&format!("{name}: {value}"))));
        }
        if let BodyText::Text(text) = body {
            out.push_str(&format!(" \\\n  --data-binary {}", shell(text)));
        }
        out.push('\n');
    }
    out
}

/// POSIX single-quoted shell word.
fn shell(text: &str) -> String {
    format!("'{}'", text.replace('\'', r#"'"'"'"#))
}

fn one_line(text: &str) -> String {
    text.replace(['\r', '\n'], " ")
}

/// A string literal in `language`, escaped for it.
fn literal(text: &str, language: Language) -> String {
    let mut out = String::with_capacity(text.len() + 2);
    out.push('"');
    for ch in text.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '$' if language == Language::Kotlin => out.push_str("\\$"),
            ch if (ch as u32) < 0x20 || ch == '\u{7f}' => match language {
                Language::Swift => out.push_str(&format!("\\u{{{:x}}}", ch as u32)),
                Language::Go => out.push_str(&format!("\\x{:02x}", ch as u32)),
                _ => out.push_str(&format!("\\u{:04x}", ch as u32)),
            },
            // U+2028/2029 end a line in older JavaScript engines.
            '\u{2028}' | '\u{2029}' if language == Language::Javascript => {
                out.push_str(&format!("\\u{:04x}", ch as u32));
            }
            ch => out.push(ch),
        }
    }
    out.push('"');
    out
}

/// Code that sends each exchange's request again.
pub fn code(exchanges: &[&HttpExchange], language: Language) -> String {
    match language {
        Language::Python => python(exchanges),
        Language::Javascript => javascript(exchanges),
        Language::Swift => swift(exchanges),
        Language::Kotlin => kotlin(exchanges),
        Language::Go => go(exchanges),
    }
}

fn comment_lines(exchange: &HttpExchange, prefix: &str) -> String {
    let mut out = format!("{prefix} {}\n", one_line(&title(exchange)));
    if let BodyText::Omitted(reason) = body_text(exchange) {
        out.push_str(&format!("{prefix} {reason}\n"));
    }
    out
}

fn python(exchanges: &[&HttpExchange]) -> String {
    let lang = Language::Python;
    let mut out = String::from("# Exported by AnixOps Net\nimport requests\n");
    for (index, exchange) in exchanges.iter().enumerate() {
        out.push('\n');
        out.push_str(&comment_lines(exchange, "#"));
        out.push_str("headers = {\n");
        for (name, value) in kept_headers(exchange) {
            out.push_str(&format!(
                "    {}: {},\n",
                literal(name, lang),
                literal(value, lang)
            ));
        }
        out.push_str("}\n");
        let data = match body_text(exchange) {
            BodyText::Text(text) => format!(", data={}.encode()", literal(text, lang)),
            _ => String::new(),
        };
        out.push_str(&format!(
            "response_{index} = requests.request({}, {}, headers=headers{data})\n",
            literal(&exchange.method, lang),
            literal(&exchange.url, lang),
        ));
        out.push_str(&format!(
            "print(response_{index}.status_code, len(response_{index}.content))\n"
        ));
    }
    out
}

fn javascript(exchanges: &[&HttpExchange]) -> String {
    let lang = Language::Javascript;
    let mut out = String::from("// Exported by AnixOps Net (Node 18+ or a browser)\n");
    for exchange in exchanges {
        out.push('\n');
        out.push_str(&comment_lines(exchange, "//"));
        out.push_str(&format!(
            "await fetch({}, {{\n",
            literal(&exchange.url, lang)
        ));
        out.push_str(&format!("  method: {},\n", literal(&exchange.method, lang)));
        out.push_str("  headers: {\n");
        for (name, value) in kept_headers(exchange) {
            out.push_str(&format!(
                "    {}: {},\n",
                literal(name, lang),
                literal(value, lang)
            ));
        }
        out.push_str("  },\n");
        if let BodyText::Text(text) = body_text(exchange) {
            out.push_str(&format!("  body: {},\n", literal(text, lang)));
        }
        out.push_str("}).then(async (response) => console.log(response.status, (await response.text()).length));\n");
    }
    out
}

fn swift(exchanges: &[&HttpExchange]) -> String {
    let lang = Language::Swift;
    let mut out = String::from("// Exported by AnixOps Net\nimport Foundation\n");
    for (index, exchange) in exchanges.iter().enumerate() {
        out.push('\n');
        out.push_str(&comment_lines(exchange, "//"));
        out.push_str(&format!(
            "var request{index} = URLRequest(url: URL(string: {})!)\n",
            literal(&exchange.url, lang)
        ));
        out.push_str(&format!(
            "request{index}.httpMethod = {}\n",
            literal(&exchange.method, lang)
        ));
        for (name, value) in kept_headers(exchange) {
            out.push_str(&format!(
                "request{index}.setValue({}, forHTTPHeaderField: {})\n",
                literal(value, lang),
                literal(name, lang)
            ));
        }
        if let BodyText::Text(text) = body_text(exchange) {
            out.push_str(&format!(
                "request{index}.httpBody = Data({}.utf8)\n",
                literal(text, lang)
            ));
        }
        out.push_str(&format!(
            "let (data{index}, response{index}) = try await URLSession.shared.data(for: request{index})\n"
        ));
        out.push_str(&format!(
            "print((response{index} as? HTTPURLResponse)?.statusCode ?? 0, data{index}.count)\n"
        ));
    }
    out
}

fn kotlin(exchanges: &[&HttpExchange]) -> String {
    let lang = Language::Kotlin;
    let mut out = String::from(
        "// Exported by AnixOps Net\nimport okhttp3.OkHttpClient\nimport okhttp3.Request\nimport okhttp3.RequestBody.Companion.toRequestBody\n\nval client = OkHttpClient()\n",
    );
    for (index, exchange) in exchanges.iter().enumerate() {
        out.push('\n');
        out.push_str(&comment_lines(exchange, "//"));
        let body = match body_text(exchange) {
            BodyText::Text(text) => format!("{}.toRequestBody()", literal(text, lang)),
            _ if matches!(exchange.method.as_str(), "POST" | "PUT" | "PATCH") => {
                "ByteArray(0).toRequestBody()".to_string()
            }
            _ => "null".to_string(),
        };
        out.push_str(&format!("val request{index} = Request.Builder()\n"));
        out.push_str(&format!("    .url({})\n", literal(&exchange.url, lang)));
        out.push_str(&format!(
            "    .method({}, {body})\n",
            literal(&exchange.method, lang)
        ));
        for (name, value) in kept_headers(exchange) {
            out.push_str(&format!(
                "    .header({}, {})\n",
                literal(name, lang),
                literal(value, lang)
            ));
        }
        out.push_str("    .build()\n");
        out.push_str(&format!(
            "client.newCall(request{index}).execute().use {{ println(\"${{it.code}} ${{it.body?.bytes()?.size}}\") }}\n"
        ));
    }
    out
}

fn go(exchanges: &[&HttpExchange]) -> String {
    let lang = Language::Go;
    let mut out = String::from(
        "// Exported by AnixOps Net\npackage main\n\nimport (\n\t\"fmt\"\n\t\"io\"\n\t\"net/http\"\n\t\"strings\"\n)\n\nfunc main() {\n",
    );
    for (index, exchange) in exchanges.iter().enumerate() {
        if index > 0 {
            out.push('\n');
        }
        out.push_str(&comment_lines(exchange, "\t//"));
        let body = match body_text(exchange) {
            BodyText::Text(text) => format!("strings.NewReader({})", literal(text, lang)),
            _ => "nil".to_string(),
        };
        out.push_str(&format!(
            "\treq{index}, err := http.NewRequest({}, {}, {body})\n",
            literal(&exchange.method, lang),
            literal(&exchange.url, lang)
        ));
        out.push_str("\tif err != nil {\n\t\tpanic(err)\n\t}\n");
        for (name, value) in kept_headers(exchange) {
            out.push_str(&format!(
                "\treq{index}.Header.Set({}, {})\n",
                literal(name, lang),
                literal(value, lang)
            ));
        }
        out.push_str(&format!(
            "\tresp{index}, err := http.DefaultClient.Do(req{index})\n\tif err != nil {{\n\t\tpanic(err)\n\t}}\n"
        ));
        out.push_str(&format!(
            "\tbody{index}, _ := io.ReadAll(resp{index}.Body)\n\tresp{index}.Body.Close()\n\tfmt.Println(resp{index}.StatusCode, len(body{index}))\n"
        ));
    }
    out.push_str("\t_ = strings.NewReader\n}\n");
    out
}

/// A Postman collection (v2.1) with one request per exchange.
pub fn postman(exchanges: &[&HttpExchange], name: &str) -> Value {
    let items = exchanges
        .iter()
        .map(|exchange| {
            let mut request = json!({
                "method": exchange.method,
                "header": kept_headers(exchange)
                    .into_iter()
                    .map(|(key, value)| json!({ "key": key, "value": value }))
                    .collect::<Vec<_>>(),
                "url": postman_url(&exchange.url),
            });
            match body_text(exchange) {
                BodyText::Text(text) => {
                    request["body"] = json!({ "mode": "raw", "raw": text });
                }
                BodyText::Omitted(reason) => {
                    request["description"] = json!(reason);
                }
                BodyText::None => {}
            }
            json!({ "name": title(exchange), "request": request })
        })
        .collect::<Vec<_>>();
    json!({
        "info": {
            "name": name,
            "description": "Exported by AnixOps Net",
            "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json",
        },
        "item": items,
    })
}

fn postman_url(url: &str) -> Value {
    let (scheme, rest) = url.split_once("://").unwrap_or(("https", url));
    let before_fragment = rest.split('#').next().unwrap_or(rest);
    let (location, query) = match before_fragment.split_once('?') {
        Some((location, query)) => (location, Some(query)),
        None => (before_fragment, None),
    };
    let (authority, path) = location.split_once('/').unwrap_or((location, ""));
    let (host, port) = split_port(authority);
    let mut value = json!({
        "raw": url,
        "protocol": scheme,
        "host": host.split('.').collect::<Vec<_>>(),
        "path": path.split('/').collect::<Vec<_>>(),
    });
    if let Some(port) = port {
        value["port"] = json!(port);
    }
    if let Some(query) = query {
        value["query"] = json!(query
            .split('&')
            .filter(|pair| !pair.is_empty())
            .map(|pair| {
                let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
                json!({ "key": key, "value": value })
            })
            .collect::<Vec<_>>());
    }
    value
}

/// `host:port` or `[v6]:port` → host and the port, when one is given.
fn split_port(authority: &str) -> (&str, Option<&str>) {
    if let Some(bracketed) = authority.strip_prefix('[') {
        return match bracketed.split_once("]:") {
            Some((host, port)) => (host, Some(port)),
            None => (bracketed.trim_end_matches(']'), None),
        };
    }
    match authority.rsplit_once(':') {
        Some((host, port)) if !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()) => {
            (host, Some(port))
        }
        _ => (authority, None),
    }
}

/// An Insomnia export (format 4): one workspace with one request per
/// exchange.
pub fn insomnia(exchanges: &[&HttpExchange], name: &str, now_ms: u64) -> Value {
    let workspace = format!("wrk_anixops_{now_ms}");
    let mut resources = vec![json!({
        "_id": workspace,
        "_type": "workspace",
        "parentId": null,
        "name": name,
        "description": "Exported by AnixOps Net",
        "scope": "collection",
    })];
    for (index, exchange) in exchanges.iter().enumerate() {
        let mime = exchange
            .request_headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case("content-type"))
            .map(|(_, value)| value.as_str())
            .unwrap_or("");
        let body = match body_text(exchange) {
            BodyText::Text(text) => json!({ "mimeType": mime, "text": text }),
            _ => json!({}),
        };
        let description = match body_text(exchange) {
            BodyText::Omitted(reason) => reason,
            _ => String::new(),
        };
        resources.push(json!({
            "_id": format!("req_anixops_{now_ms}_{index}"),
            "_type": "request",
            "parentId": workspace,
            "name": title(exchange),
            "description": description,
            "method": exchange.method,
            "url": exchange.url,
            "headers": kept_headers(exchange)
                .into_iter()
                .map(|(name, value)| json!({ "name": name, "value": value }))
                .collect::<Vec<_>>(),
            "body": body,
            "parameters": [],
            "authentication": {},
        }));
    }
    json!({
        "_type": "export",
        "__export_format": 4,
        "__export_date": super::har::iso8601(now_ms),
        "__export_source": "anixops-net",
        "resources": resources,
    })
}

#[cfg(test)]
mod tests {
    use super::super::CapturedBody;
    use super::*;

    fn sample() -> HttpExchange {
        let mut exchange = HttpExchange::new(
            "POST",
            "https://api.example.test:8443/v1/items?a=1&b=it's",
            &[
                ("Host".to_string(), "api.example.test".to_string()),
                ("Content-Type".to_string(), "application/json".to_string()),
                ("Content-Length".to_string(), "13".to_string()),
                ("X-Note".to_string(), "price $5 \"x\"".to_string()),
            ],
        );
        exchange.request_body = CapturedBody::of(br#"{"name":"it"}"#);
        exchange
    }

    #[test]
    fn curl_quotes_and_skips_computed_headers() {
        let exchange = sample();
        let script = curl(&[&exchange]);
        assert!(script
            .contains("curl -X 'POST' 'https://api.example.test:8443/v1/items?a=1&b=it'\"'\"'s'"));
        assert!(script.contains("-H 'Content-Type: application/json'"));
        assert!(!script.contains("Host:"));
        assert!(!script.contains("Content-Length"));
        assert!(script.contains(r#"--data-binary '{"name":"it"}'"#));
    }

    #[test]
    fn omits_partial_and_binary_bodies() {
        let mut exchange = sample();
        exchange.request_body = CapturedBody {
            data: vec![1, 2],
            size: 10,
        };
        let script = curl(&[&exchange]);
        assert!(script.contains("only partly captured"));
        assert!(!script.contains("--data-binary"));
        exchange.request_body = CapturedBody::of(&[0xff, 0xfe]);
        assert!(code(&[&exchange], Language::Python).contains("binary request body"));
    }

    #[test]
    fn code_escapes_per_language() {
        let exchange = sample();
        assert!(code(&[&exchange], Language::Kotlin).contains(r#""price \$5 \"x\"""#));
        assert!(code(&[&exchange], Language::Swift).contains(r#"forHTTPHeaderField: "X-Note""#));
        assert!(code(&[&exchange], Language::Go).contains("http.NewRequest(\"POST\""));
        assert!(code(&[&exchange], Language::Javascript).contains("method: \"POST\""));
        assert!(code(&[&exchange], Language::Python).contains("requests.request(\"POST\""));
        assert_eq!(literal("a\u{1}b", Language::Swift), "\"a\\u{1}b\"");
        assert_eq!(literal("a\u{1}b", Language::Python), "\"a\\u0001b\"");
    }

    #[test]
    fn collections_hold_one_request_per_exchange() {
        let exchange = sample();
        let collection = postman(&[&exchange, &exchange], "capture");
        assert_eq!(collection["item"].as_array().unwrap().len(), 2);
        let url = &collection["item"][0]["request"]["url"];
        assert_eq!(url["port"], "8443");
        assert_eq!(url["host"][0], "api");
        assert_eq!(url["path"][1], "items");
        assert_eq!(url["query"][1]["key"], "b");
        assert_eq!(
            collection["item"][0]["request"]["body"]["raw"],
            r#"{"name":"it"}"#
        );

        let export = insomnia(&[&exchange], "capture", 1_000);
        let resources = export["resources"].as_array().unwrap();
        assert_eq!(resources.len(), 2);
        assert_eq!(resources[1]["parentId"], resources[0]["_id"]);
        assert_eq!(resources[1]["body"]["mimeType"], "application/json");
        assert_eq!(export["__export_format"], 4);
    }
}
