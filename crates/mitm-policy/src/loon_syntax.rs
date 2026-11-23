//! Tokens of Loon rewrite lines, split the same way the `mitm_anixops` core
//! splits them, so lines rewritten for the core keep their meaning.

/// Splits `text` into whitespace-separated tokens. A token that starts with
/// `"` or `'` runs to the matching quote; inside it, a backslash escapes only
/// that quote or another backslash.
pub(crate) fn tokens(text: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut chars = text.chars().peekable();
    loop {
        while chars.next_if(|ch| ch.is_whitespace()).is_some() {}
        let Some(&first) = chars.peek() else {
            break;
        };
        let quote = matches!(first, '"' | '\'').then_some(first);
        if quote.is_some() {
            chars.next();
        }
        let mut token = String::new();
        while let Some(ch) = chars.next() {
            match quote {
                Some(quote) if ch == quote => break,
                Some(quote) if ch == '\\' => {
                    match chars.next_if(|next| *next == quote || *next == '\\') {
                        Some(escaped) => token.push(escaped),
                        None => token.push(ch),
                    }
                }
                None if ch.is_whitespace() => break,
                _ => token.push(ch),
            }
        }
        tokens.push(token);
    }
    tokens
}

/// Writes `token` so that [`tokens`] (and the core) read it back unchanged:
/// as is when that is unambiguous, otherwise quoted.
pub(crate) fn quote(token: &str) -> String {
    if !token.is_empty() && !token.starts_with(['"', '\'']) && !token.contains(char::is_whitespace)
    {
        return token.to_string();
    }
    let mut quoted = String::with_capacity(token.len() + 2);
    quoted.push('"');
    for ch in token.chars() {
        if matches!(ch, '"' | '\\') {
            quoted.push('\\');
        }
        quoted.push(ch);
    }
    quoted.push('"');
    quoted
}

/// Parses `key=value` attributes after the first token. Values may be quoted
/// with `"` or `'` (backslash escapes the quote) and may then hold spaces.
pub(crate) fn attributes(text: &str) -> Vec<(String, String)> {
    let mut attributes = Vec::new();
    let mut chars = text.chars().peekable();
    loop {
        while chars
            .next_if(|ch| ch.is_whitespace() || *ch == ',')
            .is_some()
        {}
        if chars.peek().is_none() {
            break;
        }
        let mut key = String::new();
        while let Some(ch) = chars.next_if(|ch| *ch != '=' && !ch.is_whitespace()) {
            key.push(ch);
        }
        let mut value = String::new();
        if chars.next_if_eq(&'=').is_some() {
            let quote = chars.next_if(|ch| matches!(*ch, '"' | '\''));
            while let Some(ch) = chars.next() {
                match quote {
                    Some(quote) if ch == quote => break,
                    Some(quote) if ch == '\\' => {
                        match chars.next_if(|next| *next == quote || *next == '\\') {
                            Some(escaped) => value.push(escaped),
                            None => value.push(ch),
                        }
                    }
                    None if ch.is_whitespace() || ch == ',' => break,
                    _ => value.push(ch),
                }
            }
        }
        attributes.push((key.to_ascii_lowercase(), value));
    }
    attributes
}

/// Marks a script argument the importer resolved and encoded with
/// [`encode_core_argument`].
const CORE_ARGUMENT_MARK: char = '\u{E002}';
/// Stand-ins for `{` and `}` inside an encoded argument.
const CORE_ARGUMENT_OPEN: char = '\u{E000}';
const CORE_ARGUMENT_CLOSE: char = '\u{E001}';

/// A script argument the importer already resolved, written so the policy
/// core hands it back unchanged.
///
/// At dispatch the core reads a script's `argument=` as a template once
/// more: every `{name}` becomes the value of a declared argument, or nothing,
/// and a value that starts with `[` becomes a `name=value&...` list. A
/// resolved argument that still holds braces (JSON, an undeclared name) or
/// starts with `[` would be mangled, so it travels with its braces replaced
/// by private-use characters behind a mark, and [`decode_core_argument`]
/// restores it when the dispatch leaves the core. An argument with none of
/// that, or one that already holds the private-use characters, is returned
/// as it is.
pub(crate) fn encode_core_argument(argument: &str) -> String {
    let needs_encoding = argument.contains(['{', '}']) || argument.trim_start().starts_with('[');
    if !needs_encoding
        || argument.contains([CORE_ARGUMENT_MARK, CORE_ARGUMENT_OPEN, CORE_ARGUMENT_CLOSE])
    {
        return argument.to_string();
    }
    let mut encoded = String::with_capacity(argument.len() + 8);
    encoded.push(CORE_ARGUMENT_MARK);
    encoded.extend(argument.chars().map(|ch| match ch {
        '{' => CORE_ARGUMENT_OPEN,
        '}' => CORE_ARGUMENT_CLOSE,
        other => other,
    }));
    encoded
}

/// The script argument [`encode_core_argument`] wrote; any other argument is
/// returned as it is.
pub(crate) fn decode_core_argument(argument: &str) -> String {
    match argument.strip_prefix(CORE_ARGUMENT_MARK) {
        Some(encoded) => encoded
            .chars()
            .map(|ch| match ch {
                CORE_ARGUMENT_OPEN => '{',
                CORE_ARGUMENT_CLOSE => '}',
                other => other,
            })
            .collect(),
        None => argument.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encoded_core_arguments_round_trip() {
        for argument in [
            r#"{"captionLang":"zh","lyricLang":"off"}"#,
            r#"{"a":{"b":1}}"#,
            "[1,2]",
            "{undeclared}",
            "HideAds=true&Mode=strict",
            "",
        ] {
            let encoded = encode_core_argument(argument);
            assert!(!encoded.contains(['{', '}']), "{encoded}");
            assert!(!encoded.trim_start().starts_with('['), "{encoded}");
            assert_eq!(decode_core_argument(&encoded), argument);
        }
        assert_eq!(encode_core_argument("a=1&b=2"), "a=1&b=2");
        assert_eq!(decode_core_argument("plain"), "plain");
    }

    #[test]
    fn quoted_tokens_round_trip() {
        let line = r#"http-response ^https://a\.test/ "\"ad\":\d+" '"ad":0' "a\\b""#;
        let parsed = tokens(line);
        assert_eq!(
            parsed,
            vec![
                "http-response",
                r"^https://a\.test/",
                r#""ad":\d+"#,
                r#""ad":0"#,
                r"a\b"
            ]
        );
        let requoted = parsed
            .iter()
            .map(String::as_str)
            .map(quote)
            .collect::<Vec<_>>();
        assert_eq!(tokens(&requoted.join(" ")), parsed);
    }

    #[test]
    fn attributes_accept_quoted_values() {
        let parsed =
            attributes(r#"data-type=json data="{\"a\": 1}", status-code=201 header="A:1|B:2""#);
        assert_eq!(
            parsed,
            vec![
                ("data-type".to_string(), "json".to_string()),
                ("data".to_string(), r#"{"a": 1}"#.to_string()),
                ("status-code".to_string(), "201".to_string()),
                ("header".to_string(), "A:1|B:2".to_string()),
            ]
        );
    }
}
