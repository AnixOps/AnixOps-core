//! Translation for the MITM core: host patterns, module arguments, jq body
//! rewrites, long patterns, script switches and core attributes.

use super::*;

/// Whether the policy core reads a `[MITM] hostname` item: `*`, a host with
/// a leading `*.`, or a glob with `*` (any run, dots included) and `?` (one
/// character) inside labels, such as `*spclient.spotify.com` or `*.flyert.*`.
/// Mirrors the `mitm_anixops` core (v1.4.8 and later): a plain host needs
/// valid labels, and a glob must stay a host name and name at least one
/// literal character.
/// True for a hostname list item that no host name can match: it holds
/// whitespace or other characters a host name cannot have, or (without
/// wildcards) a label that is empty or starts or ends with `-`.
pub(crate) fn host_item_never_matches(item: &str) -> bool {
    let body = item.trim();
    if body.chars().any(|ch| {
        !(ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.' | '*' | '?' | ':' | '[' | ']'))
    }) {
        return true;
    }
    if body.contains(['*', '?', ':']) {
        return false;
    }
    let host = body.strip_suffix('.').unwrap_or(body);
    host.split('.')
        .any(|label| label.is_empty() || label.starts_with('-') || label.ends_with('-'))
}

pub(crate) fn core_host_pattern(item: &str) -> bool {
    let body = item.strip_prefix(['-', '!', '+']).unwrap_or(item).trim();
    if body == "*" {
        return true;
    }
    let rest = body.strip_prefix("*.").unwrap_or(body);
    if rest.is_empty() {
        return false;
    }
    if !rest.contains(['*', '?']) {
        // IPv6 literals and `host:port` are left to the core.
        if rest.contains(':') {
            return true;
        }
        // Plain host: labels of letters, digits and inner hyphens, as the
        // core checks them. Lists carry broken items such as
        // `a-zA-Z0-9_-.admobile.top`; one would make the core refuse the line.
        let host = rest.strip_suffix('.').unwrap_or(rest);
        return host.split('.').all(|label| {
            let bytes = label.as_bytes();
            !bytes.is_empty()
                && bytes.len() <= 63
                && bytes[0].is_ascii_alphanumeric()
                && bytes[bytes.len() - 1].is_ascii_alphanumeric()
                && bytes
                    .iter()
                    .all(|b| b.is_ascii_alphanumeric() || *b == b'-')
        });
    }
    let glob = body.strip_suffix('.').unwrap_or(body);
    glob.len() <= 253
        && !glob.starts_with('.')
        && !glob.ends_with('.')
        && !glob.contains("..")
        && glob.bytes().any(|b| b.is_ascii_alphanumeric())
        && glob
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'*' | b'?'))
}

/// Most plugin lines the policy core may refuse before the whole plugin is
/// treated as refused.
pub(crate) const MAX_REFUSED_LINES: usize = 256;

/// Stable report reason for a line the policy core refused, from its message.
pub(crate) fn refused_line_reason(message: &str) -> &'static str {
    let message = message.to_ascii_lowercase();
    if message.contains("hostname") {
        "mitm.hostname_invalid"
    } else if message.contains("cron") {
        "task.cron_invalid"
    } else if message.contains("regex") {
        "pattern.regex_invalid"
    } else if message.contains("rule") {
        "rule.invalid"
    } else {
        "policy_core.refused_line"
    }
}

/// A Quantumult X rewrite line outside any section: `<url> url <action>`.
pub(crate) fn is_quantumult_rewrite(line: &str) -> bool {
    tokens(line)
        .get(1)
        .is_some_and(|token| token.eq_ignore_ascii_case("url"))
}

pub(crate) fn is_hostname_line(line: &str) -> bool {
    line.split_once('=')
        .is_some_and(|(key, _)| key.trim().eq_ignore_ascii_case("hostname"))
}

/// Defaults of a Surge `#!arguments=name:value,...` line. A value may be
/// quoted to hold commas.
pub(crate) fn parse_module_arguments(value: &str) -> Vec<(String, String)> {
    let mut entries = Vec::new();
    let mut current = String::new();
    let mut quoted = false;
    for character in value.chars() {
        match character {
            '"' => {
                quoted = !quoted;
                current.push(character);
            }
            ',' if !quoted => entries.push(std::mem::take(&mut current)),
            _ => current.push(character),
        }
    }
    entries.push(current);
    entries
        .into_iter()
        .filter_map(|entry| {
            let (name, default) = entry.split_once(':')?;
            let name = name.trim();
            (!name.is_empty()).then(|| {
                (
                    name.to_string(),
                    default.trim().trim_matches('"').to_string(),
                )
            })
        })
        .collect()
}

/// Every `#!arguments` default in the plugin, last one winning.
pub(crate) fn module_argument_defaults(text: &str) -> BTreeMap<String, String> {
    let mut defaults = BTreeMap::new();
    for line in text.lines() {
        let Some(meta) = line.trim().strip_prefix("#!") else {
            continue;
        };
        let Some((key, value)) = meta.split_once('=') else {
            continue;
        };
        if key.trim().eq_ignore_ascii_case("arguments") {
            defaults.extend(parse_module_arguments(value));
        }
    }
    defaults
}

/// Replaces Surge `{{{name}}}` placeholders with argument defaults. Unknown
/// names are left as written.
pub(crate) fn substitute_module_arguments(
    line: &str,
    arguments: &BTreeMap<String, String>,
) -> String {
    if arguments.is_empty() || !line.contains("{{{") {
        return line.to_string();
    }
    let mut out = String::with_capacity(line.len());
    let mut rest = line;
    while let Some(start) = rest.find("{{{") {
        out.push_str(&rest[..start]);
        let after = &rest[start + 3..];
        match after.find("}}}") {
            Some(end) => match arguments.get(after[..end].trim()) {
                Some(value) => {
                    out.push_str(value);
                    rest = &after[end + 3..];
                }
                None => {
                    out.push_str("{{{");
                    rest = after;
                }
            },
            None => {
                out.push_str(&rest[start..]);
                rest = "";
            }
        }
    }
    out.push_str(rest);
    out.trim().to_string()
}

/// A jq body rewrite in any dialect as the core's
/// `<url> request-body-jq|response-body-jq <filter>` line, and whether it
/// rewrites the response:
/// - Surge / Loon `http-response-jq <url> <filter>`;
/// - Loon `<url> response-body-json-jq <filter>`;
/// - Quantumult X `<url> url jsonjq-response-body <filter>`;
/// - Loon JSON edits `<url> response-body-json-del <path>...`,
///   `-json-add`/`-json-replace <path> <value>...` and their `[Body Rewrite]`
///   form `http-response-json-del <url> <path>...`, written as jq.
pub(crate) fn jq_rewrite(parts: &[String]) -> Option<(String, bool)> {
    let lower = |index: usize| {
        parts
            .get(index)
            .map(|token| token.to_ascii_lowercase())
            .unwrap_or_default()
    };
    // (response, edit) for an action token.
    let action = |token: &str| -> Option<(bool, &'static str)> {
        let (response, rest) = if let Some(rest) = token.strip_prefix("response-body-") {
            (true, rest)
        } else if let Some(rest) = token.strip_prefix("request-body-") {
            (false, rest)
        } else if let Some(rest) = token.strip_prefix("http-response-") {
            (true, rest)
        } else if let Some(rest) = token.strip_prefix("http-request-") {
            (false, rest)
        } else {
            return match token {
                "jsonjq-response-body" => Some((true, "jq")),
                "jsonjq-request-body" => Some((false, "jq")),
                _ => None,
            };
        };
        let edit = match rest {
            "jq" | "json-jq" => "jq",
            "json-del" => "del",
            "json-add" => "add",
            "json-replace" => "replace",
            _ => return None,
        };
        Some((response, edit))
    };
    let first = lower(0);
    let (pattern, (response, edit), arguments) = if first.starts_with("http-") {
        // `[Body Rewrite]` action-first form; plain regex body rewrites
        // (`http-response <url> <regex> <replacement>`) are not jq.
        (parts.get(1)?, action(&first)?, &parts[2..])
    } else if lower(1) == "url" {
        (parts.first()?, action(&lower(2))?, parts.get(3..)?)
    } else {
        (parts.first()?, action(&lower(1))?, parts.get(2..)?)
    };
    let filter = match edit {
        "jq" => arguments.first()?.clone(),
        // The core reads `json-replace` with its own JSON path syntax.
        "replace" if !first.starts_with("http-") => return None,
        _ => json_edit_filter(edit, arguments)?,
    };
    if pattern.is_empty() || filter.trim().is_empty() {
        return None;
    }
    let action = if response {
        "response-body-jq"
    } else {
        "request-body-jq"
    };
    Some((
        format!("{} {action} {}", quote(pattern), quote(&filter)),
        response,
    ))
}

/// Loon's JSON edit lines as a jq filter: `del` takes paths; `add` sets each
/// `path value` pair; `replace` sets a path only when it holds a value.
pub(crate) fn json_edit_filter(edit: &str, arguments: &[String]) -> Option<String> {
    if arguments.is_empty() {
        return None;
    }
    if edit == "del" {
        let paths = arguments
            .iter()
            .map(|path| json_path(path))
            .collect::<Option<Vec<_>>>()?;
        return Some(format!("delpaths([{}])", paths.join(",")));
    }
    if !arguments.len().is_multiple_of(2) {
        return None;
    }
    let steps = arguments
        .chunks(2)
        .map(|pair| {
            let path = json_path(&pair[0])?;
            let value = json_literal(&pair[1]);
            Some(match edit {
                "add" => format!("setpath({path}; {value})"),
                _ => format!(
                    "if (try getpath({path}) catch null) != null then setpath({path}; {value}) else . end"
                ),
            })
        })
        .collect::<Option<Vec<_>>>()?;
    Some(steps.join(" | "))
}

/// `a.b[0].c` as the jq path array `["a","b",0,"c"]`.
pub(crate) fn json_path(path: &str) -> Option<String> {
    let mut keys = Vec::new();
    for segment in path
        .trim()
        .trim_start_matches('$')
        .trim_start_matches('.')
        .split('.')
    {
        let (name, mut rest) = match segment.find('[') {
            Some(at) => (&segment[..at], &segment[at..]),
            None => (segment, ""),
        };
        if !name.is_empty() {
            keys.push(json_string(name));
        } else if rest.is_empty() {
            return None;
        }
        while !rest.is_empty() {
            let close = rest.find(']')?;
            let index = rest.get(1..close)?;
            if index.is_empty() || !index.bytes().all(|byte| byte.is_ascii_digit()) {
                return None;
            }
            keys.push(index.to_string());
            rest = rest.get(close + 1..)?;
            if !rest.is_empty() && !rest.starts_with('[') {
                return None;
            }
        }
    }
    (!keys.is_empty()).then(|| format!("[{}]", keys.join(",")))
}

/// A Loon JSON edit value: JSON as written (numbers, booleans, objects,
/// quoted strings), anything else as a string.
pub(crate) fn json_literal(value: &str) -> String {
    let trimmed = value.trim();
    let json_like = matches!(trimmed, "true" | "false" | "null")
        || trimmed.parse::<f64>().is_ok_and(f64::is_finite)
        || (trimmed.starts_with('{') && trimmed.ends_with('}'))
        || (trimmed.starts_with('[') && trimmed.ends_with(']'))
        || (trimmed.len() >= 2 && trimmed.starts_with('"') && trimmed.ends_with('"'));
    if json_like {
        trimmed.to_string()
    } else {
        json_string(trimmed)
    }
}

pub(crate) fn json_string(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 2);
    out.push('"');
    for ch in text.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            ch if (ch as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", ch as u32);
            }
            ch => out.push(ch),
        }
    }
    out.push('"');
    out
}

/// `<url>, key=value, ...` (Quantumult X task lines) as attributes, with the
/// URL under `url`. Values run to the next comma, so `tag=Daily check-in`
/// keeps its spaces.
pub(crate) fn url_first_attributes(text: &str) -> Vec<(String, String)> {
    let text = text.trim();
    let end = text
        .find(|ch: char| ch == ',' || ch.is_whitespace())
        .unwrap_or(text.len());
    let mut attributes = vec![("url".to_string(), text[..end].to_string())];
    attributes.extend(text[end..].split(',').filter_map(|item| {
        let (key, value) = item.split_once('=')?;
        let value = value.trim();
        let value = value
            .strip_prefix('"')
            .and_then(|value| value.strip_suffix('"'))
            .unwrap_or(value);
        Some((key.trim().to_ascii_lowercase(), value.to_string()))
    }));
    attributes
}

/// A Surge script line whose quoted `pattern=` value has backslashes, with
/// them doubled so the core, which unquotes `\x` to `x`, reads the regex
/// unchanged. An escaped quote stays as it is (a literal quote either way).
pub(crate) fn surge_pattern_for_core(line: &str) -> Option<String> {
    let lower = line.to_ascii_lowercase();
    let start = lower.match_indices("pattern").find_map(|(at, _)| {
        let before = line[..at].chars().next_back();
        if !before.is_some_and(|ch| ch == ',' || ch.is_whitespace()) {
            return None;
        }
        let rest = line[at + "pattern".len()..].trim_start();
        let rest = rest.strip_prefix('=')?.trim_start();
        Some(line.len() - rest.len())
    })?;
    let mut chars = line[start..].char_indices();
    let (_, quote) = chars.next().filter(|(_, ch)| matches!(ch, '"' | '\''))?;
    let mut value = String::new();
    let mut end = None;
    let mut changed = false;
    while let Some((at, ch)) = chars.next() {
        if ch == quote {
            end = Some(start + at);
            break;
        }
        if ch == '\\' {
            match chars.next() {
                Some((_, next)) if next == quote => value.push_str(&format!("\\{quote}")),
                Some((_, next)) => {
                    value.push_str(if next == '\\' { "\\\\\\\\" } else { "\\\\" });
                    if next != '\\' {
                        value.push(next);
                    }
                    changed = true;
                }
                None => return None,
            }
            continue;
        }
        value.push(ch);
    }
    let end = end?;
    changed.then(|| format!("{}{value}{}", &line[..start + 1], &line[end..]))
}

/// Longest pattern the core reads whole (its buffers hold 511 bytes; the
/// rest is room for quotes and attribute syntax).
pub(crate) const MAX_CORE_PATTERN_LEN: usize = 480;

/// A line whose pattern is too long for the core, as several lines with the
/// same meaning: the pattern's top-level alternation (`^https?://(a|b|...)/`
/// or `a|b|...`) is spread over the copies. `None` when the line needs no
/// split or its pattern has no alternation that can be split safely.
pub(crate) fn split_long_pattern_line(line: &str) -> Option<Vec<String>> {
    if line.len() <= MAX_CORE_PATTERN_LEN || line.trim_start().starts_with('#') {
        return None;
    }
    // The pattern: Surge's `pattern=` attribute, the word after Loon's
    // `http-request`/`http-response`, or a url-first line's first word.
    let words = line.split_whitespace().collect::<Vec<_>>();
    let first = words.first()?.to_ascii_lowercase();
    let word = match words.iter().find(|word| word.starts_with("pattern=")) {
        Some(word) => *word,
        None if first == "http-request" || first == "http-response" => *words.get(1)?,
        None => words[0],
    };
    let pattern = word.strip_prefix("pattern=").unwrap_or(word);
    let pattern = pattern.strip_suffix(',').unwrap_or(pattern);
    let pattern = pattern
        .strip_prefix('"')
        .and_then(|pattern| pattern.strip_suffix('"'))
        .unwrap_or(pattern);
    if pattern.len() <= MAX_CORE_PATTERN_LEN || line.matches(pattern).count() != 1 {
        return None;
    }
    let chunks = split_alternation(pattern, MAX_CORE_PATTERN_LEN)?;
    Some(
        chunks
            .into_iter()
            .map(|chunk| line.replacen(pattern, &chunk, 1))
            .collect(),
    )
}

/// `pattern` as patterns of at most `max` bytes that together match what it
/// matches. Only alternations that can be split without changing the
/// meaning are used: the whole pattern's, or a top-level group that is not
/// a lookaround and has no quantifier.
pub(crate) fn split_alternation(pattern: &str, max: usize) -> Option<Vec<String>> {
    let bytes = pattern.as_bytes();
    // Top-level groups (open, close) and top-level `|` positions.
    let mut groups = Vec::new();
    let mut top_bars = Vec::new();
    let mut depth = 0usize;
    let mut open = 0usize;
    let mut index = 0usize;
    let mut in_class = false;
    while index < bytes.len() {
        match bytes[index] {
            b'\\' => index += 1,
            b']' if in_class => in_class = false,
            _ if in_class => {}
            b'[' => in_class = true,
            b'(' => {
                if depth == 0 {
                    open = index;
                }
                depth += 1;
            }
            b')' => {
                depth = depth.checked_sub(1)?;
                if depth == 0 {
                    groups.push((open, index));
                }
            }
            b'|' if depth == 0 => top_bars.push(index),
            _ => {}
        }
        index += 1;
    }
    if depth != 0 || in_class {
        return None;
    }
    let (prefix, content, suffix) = if !top_bars.is_empty() {
        ("", pattern, "")
    } else {
        let (open, close) = groups
            .into_iter()
            .filter(|(open, close)| {
                let head = &pattern[*open..];
                let lookaround = ["(?=", "(?!", "(?<=", "(?<!"]
                    .iter()
                    .any(|prefix| head.starts_with(prefix));
                let quantified = matches!(bytes.get(close + 1), Some(b'*' | b'+' | b'?' | b'{'));
                !lookaround && !quantified
            })
            .max_by_key(|(open, close)| close - open)?;
        let content_start = if pattern[open..].starts_with("(?:") {
            open + 3
        } else if pattern[open..].starts_with("(?") {
            // Named or flagged groups keep their head with the prefix.
            open + pattern[open..].find([':', '>'])? + 1
        } else {
            open + 1
        };
        (
            &pattern[..content_start],
            &pattern[content_start..close],
            &pattern[close..],
        )
    };
    // Alternatives of `content` at its own level.
    let content_bytes = content.as_bytes();
    let mut alternatives = Vec::new();
    let (mut depth, mut start, mut index, mut in_class) = (0usize, 0usize, 0usize, false);
    while index < content_bytes.len() {
        match content_bytes[index] {
            b'\\' => index += 1,
            b']' if in_class => in_class = false,
            _ if in_class => {}
            b'[' => in_class = true,
            b'(' => depth += 1,
            b')' => depth = depth.saturating_sub(1),
            b'|' if depth == 0 => {
                alternatives.push(&content[start..index]);
                start = index + 1;
            }
            _ => {}
        }
        index += 1;
    }
    alternatives.push(&content[start..]);
    if alternatives.len() < 2 {
        return None;
    }
    let room = max.checked_sub(prefix.len() + suffix.len())?;
    let mut chunks = Vec::new();
    let mut current = String::new();
    for alternative in alternatives {
        if alternative.len() > room {
            return None;
        }
        if !current.is_empty() && current.len() + 1 + alternative.len() > room {
            chunks.push(std::mem::take(&mut current));
        }
        if !current.is_empty() {
            current.push('|');
        }
        current.push_str(alternative);
    }
    chunks.push(current);
    Some(
        chunks
            .into_iter()
            .map(|chunk| format!("{prefix}{chunk}{suffix}"))
            .collect(),
    )
}

/// True when the core compiles the regex of a header-block rule.
pub(crate) fn header_block_regex_accepted(rule: &LoonHeaderBlockRule) -> bool {
    let config = format!(
        "[Rewrite]\n{} request-body-replace-regex {} {}\n",
        quote(&rule.url_pattern),
        quote(&rule.regex),
        quote(&rule.replacement)
    );
    AnixOpsMitmPolicyEngine::new()
        .and_then(|mut engine| engine.load_config(&config))
        .is_ok_and(|report| report.rewrite_rule_count == 1)
}

/// Loon's conditional script form,
/// `request if ${url} ~= /re/i then script("url") with tag="t", timeout=300`,
/// as the plain `http-request re script-path=url, ...` line. Only a URL
/// regex condition is read; anything else stays unsupported.
pub(crate) fn loon_conditional_script(text: &str) -> Option<String> {
    let lower = text.to_ascii_lowercase();
    let (kind, rest) = if lower.starts_with("request if ") {
        ("http-request", &text["request if ".len()..])
    } else if lower.starts_with("response if ") {
        ("http-response", &text["response if ".len()..])
    } else {
        return None;
    };
    let rest = rest.trim_start().strip_prefix("${url}")?.trim_start();
    let rest = rest.strip_prefix("~=")?.trim_start().strip_prefix('/')?;
    let then = rest.find(" then ")?;
    let (regex, flags) = rest[..then].trim_end().rsplit_once('/')?;
    if regex.is_empty() || !flags.chars().all(|flag| matches!(flag, 'i' | 'g')) {
        return None;
    }
    let call = rest[then + " then ".len()..].trim_start();
    let call = call.strip_prefix("script(")?.trim_start();
    let quote_char = call.chars().next().filter(|ch| matches!(ch, '"' | '\''))?;
    let call = &call[1..];
    let end = call.find(quote_char)?;
    let path = &call[..end];
    let rest = call[end + 1..].trim_start().strip_prefix(')')?.trim();
    let options = match rest.strip_prefix("with") {
        Some(options) => attributes(options),
        None if rest.is_empty() => Vec::new(),
        None => return None,
    };
    if path.is_empty() || path.contains(char::is_whitespace) {
        return None;
    }
    let pattern = if flags.contains('i') {
        format!("(?i){regex}")
    } else {
        regex.to_string()
    };
    let mut line = format!(
        "{kind} {} script-path={}",
        quote(&pattern),
        path.replace(',', "%2C")
    );
    let mut requires_body = false;
    for (key, value) in options {
        match key.as_str() {
            "requires-body" => requires_body = value.eq_ignore_ascii_case("true") || value == "1",
            "tag" | "timeout" | "argument" | "binary-body-mode" | "max-size" | "enable" => {
                let _ = write!(line, ", {key}={}", quote_attribute(&value));
            }
            _ => {}
        }
    }
    // The condition form has no body option in most published plugins;
    // their front-end scripts read form posts, so the body is buffered.
    if kind == "http-request" || requires_body {
        let _ = write!(line, ", requires-body=true");
    }
    Some(line)
}

/// Whether an HTTP script runs, from its `enable=` attribute.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ScriptSwitch {
    On,
    Off,
    /// `enable` names an argument the plugin does not declare; the script
    /// runs.
    Unresolved,
}

/// `false`, `0`, `no` or `off`: the plugin turns the script off.
pub(crate) fn switch_is_off(value: &str) -> bool {
    let value = value.trim();
    ["false", "0", "no", "off"]
        .iter()
        .any(|off| value.eq_ignore_ascii_case(off))
}

/// A value the core itself reads as on.
pub(crate) fn switch_is_on(value: &str) -> bool {
    let value = value.trim();
    value == "1"
        || ["true", "yes", "on"]
            .iter()
            .any(|on| value.eq_ignore_ascii_case(on))
}

/// The default of an `[Argument]` line's `kind,default,...` spec. A quoted
/// default may hold commas, as the core reads it.
pub(crate) fn argument_default(spec: &str) -> String {
    let mut fields = Vec::new();
    let mut field = String::new();
    let mut quote: Option<char> = None;
    let mut chars = spec.chars();
    while let Some(ch) = chars.next() {
        match quote {
            Some(open) if ch == open => {
                quote = None;
                field.push(ch);
            }
            Some(_) if ch == '\\' => {
                field.push(ch);
                if let Some(escaped) = chars.next() {
                    field.push(escaped);
                }
            }
            Some(_) => field.push(ch),
            None if matches!(ch, '"' | '\'') => {
                quote = Some(ch);
                field.push(ch);
            }
            None if ch == ',' => {
                fields.push(std::mem::take(&mut field));
                if fields.len() == 2 {
                    break;
                }
            }
            None => field.push(ch),
        }
    }
    if fields.len() < 2 {
        fields.push(field);
    }
    fields
        .get(1)
        .map(String::as_str)
        .map(unquote_core_value)
        .unwrap_or_default()
}

/// The size of the core's buffer for one attribute segment (`segment` in
/// `anixops_extract_attr`): a segment of this many bytes or more is cut.
pub(crate) const CORE_ATTRIBUTE_SEGMENT_CAP: usize = 4096;

/// Byte range of the value of attribute `key` in an HTTP script line, read
/// exactly the way the core reads it.
///
/// The core finds where the attributes start ([`core_script_attributes_start`])
/// and splits the rest into segments at each comma outside quotes and
/// brackets: a quote opens on `"` or `'` and closes on the same character,
/// inside quotes a backslash skips the character after it, and `[` `(` `{`
/// (and their closers) count only outside quotes. A segment names `key` when
/// its trimmed text before the first `=` equals `key`, ignoring ASCII case;
/// the first such segment wins. The returned range is the trimmed text after
/// that `=`, quotes included, so a quoted JSON value with unquoted inner
/// quotes (`argument="{"a":"b","c":1}"`) is read whole, as the core reads it.
pub(crate) fn core_attribute_span(line: &str, key: &str) -> Option<std::ops::Range<usize>> {
    core_attribute_segment(line, key).map(|(_, value)| value)
}

/// The segment ([`core_attribute_span`]) that holds attribute `key`, and the
/// range of its value.
pub(crate) fn core_attribute_segment(
    line: &str,
    key: &str,
) -> Option<(std::ops::Range<usize>, std::ops::Range<usize>)> {
    let bytes = line.as_bytes();
    let start = core_script_attributes_start(bytes)?;
    let mut segment_start = start;
    let mut quote: Option<u8> = None;
    let mut depth = 0usize;
    let mut index = start;
    loop {
        let at_end = match bytes.get(index) {
            None => true,
            Some(&byte) => match quote {
                Some(open) => {
                    if byte == open {
                        quote = None;
                    } else if byte == b'\\' && index + 1 < bytes.len() {
                        index += 1;
                    }
                    false
                }
                None => match byte {
                    b'"' | b'\'' => {
                        quote = Some(byte);
                        false
                    }
                    b'[' | b'(' | b'{' => {
                        depth += 1;
                        false
                    }
                    b']' | b')' | b'}' if depth > 0 => {
                        depth -= 1;
                        false
                    }
                    b',' => depth == 0,
                    _ => false,
                },
            },
        };
        if at_end {
            let end = index.min(bytes.len());
            if let Some(value) = core_segment_value(bytes, segment_start..end, key) {
                return Some((segment_start..end, value));
            }
            if index >= bytes.len() {
                return None;
            }
            index += 1;
            segment_start = index;
            continue;
        }
        index += 1;
    }
}

/// The value range of `segment` when its key is `key` (see
/// [`core_attribute_span`]). A segment without `=` or with an empty key names
/// nothing.
pub(crate) fn core_segment_value(
    bytes: &[u8],
    segment: std::ops::Range<usize>,
    key: &str,
) -> Option<std::ops::Range<usize>> {
    let eq = segment.start
        + bytes[segment.clone()]
            .iter()
            .position(|&byte| byte == b'=')?;
    let key_range = core_trim(bytes, segment.start..eq);
    if key_range.is_empty() || !bytes[key_range].eq_ignore_ascii_case(key.as_bytes()) {
        return None;
    }
    Some(core_trim(bytes, eq + 1..segment.end))
}

/// `range` without the leading and trailing white space the core's
/// `isspace` (C locale) removes.
pub(crate) fn core_trim(bytes: &[u8], range: std::ops::Range<usize>) -> std::ops::Range<usize> {
    let mut start = range.start;
    let mut end = range.end;
    while start < end && is_core_space(bytes[start]) {
        start += 1;
    }
    while end > start && is_core_space(bytes[end - 1]) {
        end -= 1;
    }
    start..end
}

/// White space as the core's `isspace` reads it in the C locale.
pub(crate) fn is_core_space(byte: u8) -> bool {
    matches!(byte, b' ' | b'\t' | b'\n' | 0x0b | 0x0c | b'\r')
}

/// Where the core starts reading the attributes of an HTTP script line:
/// - Loon `http-request|http-response <pattern> <attributes>` (or a
///   `script-request-*`/`script-response-*` kind first): after the pattern
///   token;
/// - Surge `name = type=..., pattern=..., ...`: after the first `=` of the
///   line.
///
/// `None` for a line whose attributes the core assembles from more than one
/// place (Quantumult X `<pattern> url script-... <path>, ...`) and for a
/// line the core skips (a kind with no pattern, or no `=` at all).
pub(crate) fn core_script_attributes_start(bytes: &[u8]) -> Option<usize> {
    let mut cursor = 0;
    let first = core_next_token(bytes, &mut cursor)?;
    if is_core_script_kind(&first) {
        core_next_token(bytes, &mut cursor)?;
        return Some(cursor);
    }
    // Quantumult X: `<pattern> <kind> <path>` or
    // `<pattern> url|header <kind> <path>`.
    let mut probe = cursor;
    if let Some(mode) = core_next_token(bytes, &mut probe) {
        let direct = if is_core_script_kind(&mode) {
            core_next_token(bytes, &mut probe).is_some()
        } else if mode.eq_ignore_ascii_case(b"url") || mode.eq_ignore_ascii_case(b"header") {
            core_next_token(bytes, &mut probe).is_some_and(|kind| is_core_script_kind(&kind))
                && core_next_token(bytes, &mut probe).is_some()
        } else {
            false
        };
        if direct {
            return None;
        }
    }
    bytes.iter().position(|&byte| byte == b'=').map(|eq| eq + 1)
}

/// A script kind token the core accepts in a script line.
pub(crate) fn is_core_script_kind(token: &[u8]) -> bool {
    [
        "http-request",
        "script-request-body",
        "script-request-header",
        "http-response",
        "script-response-body",
        "script-response-header",
    ]
    .iter()
    .any(|kind| token.eq_ignore_ascii_case(kind.as_bytes()))
}

/// The next white-space separated token, read as the core's tokenizer reads
/// it: a token that opens with a quote runs to the same quote (a backslash
/// before that quote or before a backslash keeps it), any other token runs to
/// the next white space. `cursor` moves past the token and the white space
/// after it.
pub(crate) fn core_next_token(bytes: &[u8], cursor: &mut usize) -> Option<Vec<u8>> {
    let mut index = *cursor;
    while index < bytes.len() && is_core_space(bytes[index]) {
        index += 1;
    }
    if index >= bytes.len() {
        *cursor = index;
        return None;
    }
    let mut quote: Option<u8> = None;
    if matches!(bytes[index], b'"' | b'\'') {
        quote = Some(bytes[index]);
        index += 1;
    }
    let mut token = Vec::new();
    while index < bytes.len() {
        let mut byte = bytes[index];
        match quote {
            Some(open) => {
                if byte == open {
                    index += 1;
                    break;
                }
                if byte == b'\\'
                    && index + 1 < bytes.len()
                    && (bytes[index + 1] == open || bytes[index + 1] == b'\\')
                {
                    index += 1;
                    byte = bytes[index];
                }
            }
            None if is_core_space(byte) => break,
            None => {}
        }
        token.push(byte);
        index += 1;
    }
    while index < bytes.len() && is_core_space(bytes[index]) {
        index += 1;
    }
    *cursor = index;
    Some(token)
}

/// An attribute value as the core reads it: white space trimmed, then the
/// surrounding quotes removed when the first and last characters are the same
/// quote; inside them a backslash keeps the character after it (a backslash
/// right before the closing quote stays as written).
pub(crate) fn unquote_core_value(raw: &str) -> String {
    let value = raw.trim_matches(|ch: char| ch.is_ascii() && is_core_space(ch as u8));
    let quoted = value.len() >= 2
        && ((value.starts_with('"') && value.ends_with('"'))
            || (value.starts_with('\'') && value.ends_with('\'')));
    if !quoted {
        return value.to_string();
    }
    let mut out = String::with_capacity(value.len());
    let mut chars = value[1..value.len() - 1].chars();
    while let Some(ch) = chars.next() {
        if ch == '\\' {
            match chars.next() {
                Some(escaped) => out.push(escaped),
                None => out.push(ch),
            }
        } else {
            out.push(ch);
        }
    }
    out
}

/// A value written back into an HTTP script line so that
/// [`core_attribute_span`] and [`unquote_core_value`], like the core, read it
/// back unchanged.
pub(crate) fn quote_core_attribute(value: &str) -> String {
    if !value.is_empty()
        && !value.contains([
            ' ', '\t', ',', '"', '\'', '\\', '[', ']', '(', ')', '{', '}',
        ])
    {
        return value.to_string();
    }
    format!("\"{}\"", value.replace('\\', "\\\\").replace('"', "\\\""))
}

/// An attribute value as [`attributes`] reads it back.
pub(crate) fn quote_attribute(value: &str) -> String {
    if value.is_empty() || value.contains([' ', ',', '"', '\'', '\t']) {
        format!("\"{}\"", value.replace('\\', "\\\\").replace('"', "\\\""))
    } else {
        value.to_string()
    }
}

pub(crate) fn is_reject_policy(target: &str) -> bool {
    let target = target.to_ascii_uppercase();
    target == "REJECT" || target.starts_with("REJECT-")
}

/// Returns the status, reason, and whether the action applies to responses.
pub(crate) fn classify_rewrite_action(action: &str) -> (LoonLineStatus, &'static str, bool) {
    match action {
        "reject" | "reject-200" | "reject-img" | "reject-tinygif" | "reject-dict"
        | "reject-array" | "reject-video" | "reject-drop" | "reject-no-drop" => {
            (LoonLineStatus::Supported, "rewrite.reject", false)
        }
        "301" | "302" | "303" | "307" | "308" => {
            (LoonLineStatus::Supported, "rewrite.redirect", false)
        }
        // Sent as a 302 (see `rewrite_line`).
        "header" => (LoonLineStatus::Supported, "rewrite.header_redirect", false),
        "header-add" | "header-del" | "header-replace" | "header-replace-regex" => {
            (LoonLineStatus::Supported, "rewrite.request_header", false)
        }
        "response-header-add"
        | "response-header-del"
        | "response-header-replace"
        | "response-header-replace-regex" => {
            (LoonLineStatus::Supported, "rewrite.response_header", true)
        }
        _ if action.strip_prefix("reject-").is_some_and(|code| {
            code.len() == 3 && code.bytes().all(|byte| byte.is_ascii_digit())
        }) =>
        {
            (LoonLineStatus::Supported, "rewrite.reject", false)
        }
        // Run with jaq (`loon_jq`).
        "request-body-jq" | "request-body-json-jq" | "jsonjq-request-body" | "http-request-jq" => {
            (LoonLineStatus::Supported, "rewrite.jq", false)
        }
        "response-body-jq"
        | "response-body-json-jq"
        | "jsonjq-response-body"
        | "http-response-jq" => (LoonLineStatus::Supported, "rewrite.jq", true),
        "request-body-replace-regex" | "request-body-json-replace" => {
            (LoonLineStatus::Supported, "rewrite.request_body", false)
        }
        "response-body-replace-regex" | "response-body-json-replace" => {
            (LoonLineStatus::Supported, "rewrite.response_body", true)
        }
        // Only the url-first `url ... mock-response-body` form reaches here;
        // the plain form is moved to `[Map Local]`.
        "mock-request-body" | "mock-response-body" => (
            LoonLineStatus::Unsupported,
            "rewrite.mock_body_unsupported",
            false,
        ),
        _ => (
            LoonLineStatus::Unsupported,
            "rewrite.action_unsupported",
            false,
        ),
    }
}
