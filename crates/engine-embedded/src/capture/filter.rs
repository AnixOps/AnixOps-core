//! The filter expression of `capture_requests`: one syntax for every
//! client, parsed here so the iOS, macOS, desktop and Android lists agree.
//!
//! - Terms separated by spaces must all match; `OR` (upper case) joins
//!   alternatives of such groups.
//! - `-` before a term negates it; `"..."` keeps spaces in a value.
//! - A bare word matches the URL or host (case-insensitive substring).
//! - `field:value`, with these fields:
//!   `host:`, `url:`, `path:` (substring), `method:` (exact),
//!   `status:` (`200`, `4xx`, `>=400`, `<300`; `none` for no response),
//!   `type:` (response `Content-Type` substring), `version:` (`h1`, `h2`),
//!   `note:` (substring), `size:` (response body bytes, `>10k`, `<1m`,
//!   `512`), `header:` (a request or response header name, or
//!   `name=value-substring`), `body:` (substring of a captured body).
//!
//! A parse error names the 0-based character position it found.

use super::{HttpExchange, HTTP_1_1, HTTP_2};

/// Why a filter did not parse, and where (character index).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FilterError {
    pub at: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Compare {
    Eq(u64),
    Ge(u64),
    Gt(u64),
    Le(u64),
    Lt(u64),
    Class(u64),
    None,
}

impl Compare {
    fn matches(&self, value: Option<u64>) -> bool {
        match (self, value) {
            (Self::None, value) => value.is_none(),
            (_, None) => false,
            (Self::Eq(want), Some(value)) => value == *want,
            (Self::Ge(want), Some(value)) => value >= *want,
            (Self::Gt(want), Some(value)) => value > *want,
            (Self::Le(want), Some(value)) => value <= *want,
            (Self::Lt(want), Some(value)) => value < *want,
            (Self::Class(class), Some(value)) => value / 100 == *class,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Test {
    Text(String),
    Host(String),
    Url(String),
    Path(String),
    Method(String),
    Status(Compare),
    Type(String),
    Version(&'static str),
    Note(String),
    Size(Compare),
    Header(String, Option<String>),
    Body(String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Term {
    negated: bool,
    test: Test,
}

/// A parsed filter: alternatives of term groups.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Filter {
    groups: Vec<Vec<Term>>,
}

impl Filter {
    /// Parses `text`; an empty text matches everything.
    pub fn parse(text: &str) -> Result<Self, FilterError> {
        let mut groups = vec![Vec::new()];
        for (at, token) in tokens(text)? {
            if token == "OR" {
                if groups.last().is_some_and(Vec::is_empty) {
                    return Err(FilterError { at });
                }
                groups.push(Vec::new());
                continue;
            }
            let term = term(&token, at)?;
            if let Some(group) = groups.last_mut() {
                group.push(term);
            }
        }
        if groups.len() > 1 && groups.last().is_some_and(Vec::is_empty) {
            return Err(FilterError {
                at: text.chars().count(),
            });
        }
        groups.retain(|group| !group.is_empty());
        Ok(Self { groups })
    }

    pub fn matches(&self, exchange: &HttpExchange) -> bool {
        self.groups.is_empty()
            || self.groups.iter().any(|group| {
                group
                    .iter()
                    .all(|term| test(&term.test, exchange) != term.negated)
            })
    }
}

/// Whitespace-separated tokens with their character positions; quotes
/// keep spaces and are removed.
fn tokens(text: &str) -> Result<Vec<(usize, String)>, FilterError> {
    let mut out = Vec::new();
    let mut current: Option<(usize, String)> = None;
    let mut quoted: Option<usize> = None;
    for (at, ch) in text.chars().enumerate() {
        if ch == '"' {
            quoted = match quoted {
                Some(_) => None,
                None => Some(at),
            };
            current.get_or_insert_with(|| (at, String::new()));
            continue;
        }
        if ch.is_whitespace() && quoted.is_none() {
            if let Some(token) = current.take() {
                out.push(token);
            }
            continue;
        }
        current
            .get_or_insert_with(|| (at, String::new()))
            .1
            .push(ch);
    }
    if let Some(at) = quoted {
        return Err(FilterError { at });
    }
    if let Some(token) = current {
        out.push(token);
    }
    Ok(out)
}

fn term(token: &str, at: usize) -> Result<Term, FilterError> {
    let (negated, body, at) = match token.strip_prefix('-') {
        Some(rest) if !rest.is_empty() => (true, rest, at + 1),
        _ => (false, token, at),
    };
    let Some((field, value)) = body.split_once(':') else {
        return Ok(Term {
            negated,
            test: Test::Text(body.to_lowercase()),
        });
    };
    let value_at = at + field.chars().count() + 1;
    let bad = |offset: usize| FilterError {
        at: value_at + offset,
    };
    if value.is_empty() {
        return Err(bad(0));
    }
    let lower = value.to_lowercase();
    let test = match field.to_ascii_lowercase().as_str() {
        "host" => Test::Host(lower),
        "url" => Test::Url(lower),
        "path" => Test::Path(lower),
        "method" => Test::Method(value.to_ascii_uppercase()),
        "status" => Test::Status(status(&lower).ok_or_else(|| bad(0))?),
        "type" => Test::Type(lower),
        "version" => Test::Version(match lower.as_str() {
            "h1" | "http/1.1" | "http1" | "1.1" => HTTP_1_1,
            "h2" | "http/2" | "http2" | "2" => HTTP_2,
            _ => return Err(bad(0)),
        }),
        "note" => Test::Note(lower),
        "size" => Test::Size(size(&lower).ok_or_else(|| bad(0))?),
        "header" => match lower.split_once('=') {
            Some((name, _)) if name.is_empty() => return Err(bad(0)),
            Some((name, value)) => Test::Header(name.to_string(), Some(value.to_string())),
            None => Test::Header(lower, None),
        },
        "body" => Test::Body(lower),
        // A colon in a bare word (`a:b`, `https://x`) is plain text.
        _ if field.contains('/')
            || field.eq_ignore_ascii_case("http")
            || field.eq_ignore_ascii_case("https") =>
        {
            Test::Text(body.to_lowercase())
        }
        _ => return Err(FilterError { at }),
    };
    Ok(Term { negated, test })
}

fn comparison(text: &str) -> (fn(u64) -> Compare, &str) {
    if let Some(rest) = text.strip_prefix(">=") {
        (Compare::Ge, rest)
    } else if let Some(rest) = text.strip_prefix("<=") {
        (Compare::Le, rest)
    } else if let Some(rest) = text.strip_prefix('>') {
        (Compare::Gt, rest)
    } else if let Some(rest) = text.strip_prefix('<') {
        (Compare::Lt, rest)
    } else {
        (Compare::Eq, text.strip_prefix('=').unwrap_or(text))
    }
}

fn status(text: &str) -> Option<Compare> {
    if text == "none" {
        return Some(Compare::None);
    }
    if let Some(class) = text.strip_suffix("xx") {
        let class: u64 = class.parse().ok()?;
        return (1..=5).contains(&class).then_some(Compare::Class(class));
    }
    let (make, number) = comparison(text);
    number.parse().ok().map(make)
}

fn size(text: &str) -> Option<Compare> {
    let (make, number) = comparison(text);
    let (digits, scale) = match number.as_bytes().last()? {
        b'k' => (&number[..number.len() - 1], 1024),
        b'm' => (&number[..number.len() - 1], 1024 * 1024),
        b'b' => (&number[..number.len() - 1], 1),
        _ => (number, 1),
    };
    let value: u64 = digits.parse().ok()?;
    Some(make(value.checked_mul(scale)?))
}

fn contains(haystack: &str, needle: &str) -> bool {
    haystack.to_lowercase().contains(needle)
}

fn host_of(url: &str) -> &str {
    let rest = url.split_once("://").map_or(url, |(_, rest)| rest);
    rest.split(['/', '?', '#']).next().unwrap_or(rest)
}

fn path_of(url: &str) -> &str {
    let rest = url.split_once("://").map_or(url, |(_, rest)| rest);
    rest.find('/').map_or("/", |slash| &rest[slash..])
}

fn header(headers: &[(String, String)], name: &str) -> Option<String> {
    headers
        .iter()
        .find(|(key, _)| key.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.to_lowercase())
}

fn body_contains(data: &[u8], needle: &str) -> bool {
    if needle.is_empty() {
        return true;
    }
    let data = data.to_ascii_lowercase();
    let needle = needle.as_bytes();
    data.windows(needle.len()).any(|window| window == needle)
}

fn test(test: &Test, exchange: &HttpExchange) -> bool {
    match test {
        Test::Text(text) => contains(&exchange.url, text),
        Test::Host(text) => contains(host_of(&exchange.url), text),
        Test::Url(text) => contains(&exchange.url, text),
        Test::Path(text) => contains(path_of(&exchange.url), text),
        Test::Method(method) => exchange.method.eq_ignore_ascii_case(method),
        Test::Status(compare) => compare.matches(exchange.status.map(u64::from)),
        Test::Type(text) => header(&exchange.response_headers, "content-type")
            .is_some_and(|value| value.contains(text.as_str())),
        Test::Version(version) => exchange.http_version == *version,
        Test::Note(text) => exchange
            .note
            .is_some_and(|note| note.contains(text.as_str())),
        Test::Size(compare) => {
            compare.matches(exchange.status.map(|_| exchange.response_body.size))
        }
        Test::Header(name, value) => [&exchange.request_headers, &exchange.response_headers]
            .into_iter()
            .any(|headers| match (header(headers, name), value) {
                (Some(found), Some(value)) => found.contains(value.as_str()),
                (Some(_), None) => true,
                (None, _) => false,
            }),
        Test::Body(text) => {
            body_contains(&exchange.request_body.data, text)
                || body_contains(&exchange.response_body.data, text)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::CapturedBody;
    use super::*;

    fn exchange(method: &str, url: &str, status: Option<u16>) -> HttpExchange {
        let mut exchange = HttpExchange::new(method, url, &[("Accept".into(), "*/*".into())]);
        exchange.status = status;
        exchange.response_headers = vec![(
            "Content-Type".to_string(),
            "application/json; charset=utf-8".to_string(),
        )];
        exchange.response_body = CapturedBody::of(&vec![b'a'; 2048]);
        exchange
    }

    fn matches(filter: &str, exchange: &HttpExchange) -> bool {
        Filter::parse(filter).unwrap().matches(exchange)
    }

    #[test]
    fn fields_and_bare_words() {
        let get = exchange("GET", "https://api.example.test/v1/users?id=3", Some(404));
        assert!(matches("", &get));
        assert!(matches("users", &get));
        assert!(matches("API.example", &get));
        assert!(matches("host:example.test path:/v1 method:get", &get));
        assert!(matches("status:4xx", &get));
        assert!(matches("status:>=400 status:<500", &get));
        assert!(!matches("status:200", &get));
        assert!(matches("type:json", &get));
        assert!(matches("version:h1", &get));
        assert!(!matches("version:h2", &get));
        assert!(matches("size:>1k size:<=2k", &get));
        assert!(matches("header:accept", &get));
        assert!(matches("header:content-type=json", &get));
        assert!(!matches("header:cookie", &get));
        assert!(matches("body:aaaa", &get));
        assert!(matches("https://api.example.test", &get));
    }

    #[test]
    fn negation_quotes_and_or() {
        let get = exchange("GET", "https://a.test/x y", None);
        assert!(matches("status:none", &get));
        assert!(matches("-status:200", &get));
        assert!(matches("\"x y\"", &get));
        assert!(matches("method:post OR host:a.test", &get));
        assert!(!matches("method:post OR host:b.test", &get));
        assert!(!matches("-a.test", &get));
    }

    #[test]
    fn errors_name_the_position() {
        assert_eq!(Filter::parse("status:abc"), Err(FilterError { at: 7 }));
        assert_eq!(Filter::parse("a colour:red"), Err(FilterError { at: 2 }));
        assert_eq!(Filter::parse("\"open"), Err(FilterError { at: 0 }));
        assert_eq!(Filter::parse("OR a"), Err(FilterError { at: 0 }));
        assert_eq!(Filter::parse("a OR"), Err(FilterError { at: 4 }));
        assert_eq!(Filter::parse("version:h3"), Err(FilterError { at: 8 }));
        assert_eq!(Filter::parse("size:"), Err(FilterError { at: 5 }));
    }
}
