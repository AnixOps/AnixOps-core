//! Reading command lines out of service definitions: word splitting,
//! systemd unit files, environment files and shell variable assignments.
//!
//! Only the subset that service definitions use in practice is understood.
//! Anything this module cannot read with certainty is reported as such, so
//! the import asks for confirmation instead of guessing.

use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SplitError {
    UnclosedQuote,
    TrailingBackslash,
}

/// Splits a command line into words the way a POSIX shell does for quotes
/// and backslashes. No expansion happens here.
pub fn split_words(line: &str) -> Result<Vec<String>, SplitError> {
    let mut words = Vec::new();
    let mut current = String::new();
    let mut in_word = false;
    let mut chars = line.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            ' ' | '\t' | '\n' | '\r' => {
                if in_word {
                    words.push(std::mem::take(&mut current));
                    in_word = false;
                }
            }
            '\'' => {
                in_word = true;
                loop {
                    match chars.next() {
                        Some('\'') => break,
                        Some(inner) => current.push(inner),
                        None => return Err(SplitError::UnclosedQuote),
                    }
                }
            }
            '"' => {
                in_word = true;
                loop {
                    match chars.next() {
                        Some('"') => break,
                        Some('\\') => match chars.next() {
                            Some(escaped @ ('"' | '\\' | '$' | '`')) => current.push(escaped),
                            Some('\n') => {}
                            Some(other) => {
                                current.push('\\');
                                current.push(other);
                            }
                            None => return Err(SplitError::UnclosedQuote),
                        },
                        Some(inner) => current.push(inner),
                        None => return Err(SplitError::UnclosedQuote),
                    }
                }
            }
            '\\' => match chars.next() {
                Some('\n') => {}
                Some(escaped) => {
                    in_word = true;
                    current.push(escaped);
                }
                None => return Err(SplitError::TrailingBackslash),
            },
            other => {
                in_word = true;
                current.push(other);
            }
        }
    }
    if in_word {
        words.push(current);
    }
    Ok(words)
}

/// The parts of a `[Service]` section an import needs.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UnitService {
    /// The last `ExecStart=` value, still unsplit.
    pub exec_start: Option<String>,
    pub environment: Vec<(String, String)>,
    /// `EnvironmentFile=` paths and whether a leading `-` made them optional.
    pub environment_files: Vec<(String, bool)>,
    pub working_directory: Option<String>,
}

/// Reads one unit file or drop-in into `service`. Later files override
/// earlier ones as systemd does: an empty assignment clears a list.
pub fn parse_unit(text: &str, service: &mut UnitService) {
    let mut section = String::new();
    for line in logical_lines(text) {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') {
            section = line[1..line.len() - 1].trim().to_string();
            continue;
        }
        if section != "Service" {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let value = value.trim();
        match key.trim() {
            "ExecStart" => {
                service.exec_start = if value.is_empty() {
                    None
                } else {
                    Some(value.to_string())
                };
            }
            "Environment" => {
                if value.is_empty() {
                    service.environment.clear();
                } else if let Ok(words) = split_words(value) {
                    for word in words {
                        if let Some((name, value)) = word.split_once('=') {
                            service
                                .environment
                                .push((name.to_string(), value.to_string()));
                        }
                    }
                }
            }
            "EnvironmentFile" => {
                if value.is_empty() {
                    service.environment_files.clear();
                } else if let Some(path) = value.strip_prefix('-') {
                    service.environment_files.push((path.to_string(), true));
                } else {
                    service.environment_files.push((value.to_string(), false));
                }
            }
            "WorkingDirectory" => {
                let value = value.trim_start_matches('-');
                service.working_directory = (!value.is_empty()).then(|| value.to_string());
            }
            _ => {}
        }
    }
}

/// Joins lines ending in a backslash, as unit files allow.
fn logical_lines(text: &str) -> Vec<String> {
    let mut lines = Vec::new();
    let mut current = String::new();
    for raw in text.lines() {
        if let Some(head) = raw.strip_suffix('\\') {
            current.push_str(head);
            current.push(' ');
        } else {
            current.push_str(raw);
            lines.push(std::mem::take(&mut current));
        }
    }
    if !current.is_empty() {
        lines.push(current);
    }
    lines
}

/// Why a unit's command line could not be read exactly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExecError {
    Split(SplitError),
    Empty,
    /// A `$NAME` the unit's environment does not define.
    UnknownVariable(String),
    /// The argument at this position (0 = the program) uses `$` in a way
    /// that cannot be expanded. Only the position is kept: the argument
    /// itself may hold a secret.
    Unexpandable(usize),
}

impl ExecError {
    /// For reports and notes: never contains an argument's value.
    pub fn describe(&self) -> String {
        match self {
            ExecError::Split(SplitError::UnclosedQuote) => "a quote is not closed".into(),
            ExecError::Split(SplitError::TrailingBackslash) => "it ends with a backslash".into(),
            ExecError::Empty => "it is empty".into(),
            ExecError::UnknownVariable(name) => format!("the variable ${name} is not defined"),
            ExecError::Unexpandable(position) => {
                format!("argument {position} uses $ in a way that cannot be expanded")
            }
        }
    }
}

/// Turns an `ExecStart=` value into argv: strips the systemd prefixes,
/// expands `%i`, `%I`, `%%` and `$NAME` / `${NAME}` from `environment`.
pub fn exec_argv(
    value: &str,
    instance: Option<&str>,
    environment: &BTreeMap<String, String>,
) -> Result<Vec<String>, ExecError> {
    let value = value.trim_start_matches(['-', '@', ':', '+', '!']);
    let mut expanded = String::with_capacity(value.len());
    let mut chars = value.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '%' {
            match chars.peek() {
                Some('%') => {
                    chars.next();
                    expanded.push('%');
                }
                Some('i' | 'I') => {
                    chars.next();
                    expanded.push_str(instance.unwrap_or(""));
                }
                _ => expanded.push('%'),
            }
        } else {
            expanded.push(c);
        }
    }
    let words = split_words(&expanded).map_err(ExecError::Split)?;
    let mut argv = Vec::with_capacity(words.len());
    for word in words {
        let position = argv.len();
        if let Some(name) = word
            .strip_prefix("${")
            .and_then(|rest| rest.strip_suffix('}'))
        {
            let value = environment
                .get(name)
                .ok_or_else(|| ExecError::UnknownVariable(name.to_string()))?;
            argv.push(value.clone());
        } else if let Some(name) = word.strip_prefix('$').filter(|name| is_variable_name(name)) {
            // `$NAME` alone splits the value into words.
            let value = environment
                .get(name)
                .ok_or_else(|| ExecError::UnknownVariable(name.to_string()))?;
            argv.extend(value.split_whitespace().map(str::to_string));
        } else if word.contains('$') {
            return Err(ExecError::Unexpandable(position));
        } else {
            argv.push(word);
        }
    }
    if argv.is_empty() {
        return Err(ExecError::Empty);
    }
    Ok(argv)
}

fn is_variable_name(name: &str) -> bool {
    let mut chars = name.chars();
    matches!(chars.next(), Some(c) if c == '_' || c.is_ascii_alphabetic())
        && chars.all(|c| c == '_' || c.is_ascii_alphanumeric())
}

/// Reads `KEY=VALUE` lines (environment files, `/etc/conf.d` files and the
/// plain assignments of an init script). Values in quotes are unquoted;
/// lines that are not plain assignments are skipped. Values that still hold
/// `$` are returned as they are, and callers treat them as unknown.
pub fn parse_assignments(text: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for line in logical_lines(text) {
        let line = line.trim();
        let line = line.strip_prefix("export ").unwrap_or(line).trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((name, value)) = line.split_once('=') else {
            continue;
        };
        if !is_variable_name(name) {
            continue;
        }
        let value = value.trim();
        let value = match split_words(value) {
            Ok(words) if words.len() == 1 => words.into_iter().next().unwrap_or_default(),
            Ok(words) if words.is_empty() => String::new(),
            // `a=b c` in a shell runs c; not an assignment we can use.
            _ => continue,
        };
        out.push((name.to_string(), value));
    }
    out
}

/// Splits a NUL-separated buffer such as `/proc/<pid>/cmdline`.
pub fn split_nul(bytes: &[u8]) -> Vec<String> {
    bytes
        .split(|byte| *byte == 0)
        .filter(|part| !part.is_empty())
        .map(|part| String::from_utf8_lossy(part).into_owned())
        .collect()
}

/// Splits a Windows command line the way the C runtime does (and
/// `CommandLineToArgvW`, apart from `""` inside quotes): the program name
/// ends at the closing quote or the first space, with no escapes; in the
/// arguments, 2n backslashes before a quote give n backslashes and the quote
/// opens or closes quoting, 2n+1 give n and a literal quote, other
/// backslashes are literal, and `""` inside quotes is a literal quote.
pub fn split_windows_command_line(line: &str) -> Vec<String> {
    let mut chars = line.trim_start_matches([' ', '\t']).chars().peekable();
    let mut out = Vec::new();
    if chars.peek().is_none() {
        return out;
    }
    let mut program = String::new();
    if chars.peek() == Some(&'"') {
        chars.next();
        for c in chars.by_ref() {
            if c == '"' {
                break;
            }
            program.push(c);
        }
    } else {
        while let Some(&c) = chars.peek() {
            if c == ' ' || c == '\t' {
                break;
            }
            program.push(c);
            chars.next();
        }
    }
    out.push(program);
    loop {
        while chars.peek().is_some_and(|c| *c == ' ' || *c == '\t') {
            chars.next();
        }
        if chars.peek().is_none() {
            return out;
        }
        let mut arg = String::new();
        let mut quoted = false;
        while let Some(&c) = chars.peek() {
            match c {
                '\\' => {
                    let mut count = 0;
                    while chars.peek() == Some(&'\\') {
                        chars.next();
                        count += 1;
                    }
                    if chars.peek() == Some(&'"') {
                        arg.extend(std::iter::repeat_n('\\', count / 2));
                        if count % 2 == 1 {
                            arg.push('"');
                            chars.next();
                        }
                    } else {
                        arg.extend(std::iter::repeat_n('\\', count));
                    }
                }
                '"' => {
                    chars.next();
                    if quoted && chars.peek() == Some(&'"') {
                        arg.push('"');
                        chars.next();
                    } else {
                        quoted = !quoted;
                    }
                }
                ' ' | '\t' if !quoted => break,
                _ => {
                    arg.push(c);
                    chars.next();
                }
            }
        }
        out.push(arg);
    }
}

/// The command a shell line runs when it starts with `executable` (after
/// optional wrappers such as `nohup`), cut at the first shell operator.
/// Returns argv including the program, or `None` when the line does not
/// start that program.
pub fn command_in_line(line: &str, executables: &[String]) -> Option<Vec<String>> {
    let words = split_words(line).ok()?;
    let start = words.iter().position(|word| {
        let base = word.rsplit('/').next().unwrap_or(word);
        executables.iter().any(|name| name == base)
    })?;
    // Everything before the program must be a known wrapper or an
    // environment assignment; otherwise the line does something else.
    for word in &words[..start] {
        let wrapper = matches!(
            word.as_str(),
            "nohup" | "exec" | "setsid" | "nice" | "ionice" | "sudo" | "env" | "/usr/bin/env"
        );
        let assignment = word
            .split_once('=')
            .is_some_and(|(name, _)| is_variable_name(name));
        if !(wrapper || assignment) {
            return None;
        }
    }
    let mut argv = Vec::new();
    for word in &words[start..] {
        let operator = matches!(word.as_str(), "&" | "&&" | ";" | "|" | "||")
            || word.starts_with('>')
            || word.starts_with('<')
            || word.starts_with("2>")
            || word.starts_with("1>")
            || word.starts_with("&>");
        if operator {
            break;
        }
        argv.push(word.trim_end_matches('&').to_string());
        if word.ends_with('&') {
            break;
        }
    }
    Some(argv)
}

/// Assignments placed before the program in a shell line (`A=1 prog`).
pub fn leading_assignments(line: &str) -> Vec<(String, String)> {
    let Ok(words) = split_words(line) else {
        return Vec::new();
    };
    words
        .iter()
        .map_while(|word| {
            word.split_once('=')
                .filter(|(name, _)| is_variable_name(name))
                .map(|(name, value)| (name.to_string(), value.to_string()))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_windows_command_lines() {
        assert_eq!(
            split_windows_command_line(
                r#""C:\Program Files\Demo\demo-meshd.exe" -c "C:\a b\x.toml" --name=lab"#
            ),
            vec![
                r"C:\Program Files\Demo\demo-meshd.exe",
                "-c",
                r"C:\a b\x.toml",
                "--name=lab"
            ]
        );
        // The program name has no escapes.
        assert_eq!(
            split_windows_command_line(r"C:\demo\x.exe a\\b"),
            vec![r"C:\demo\x.exe", r"a\\b"]
        );
        assert_eq!(
            split_windows_command_line(r#"x "a\"b" c\\"d e" f\\\"g"#),
            vec!["x", r#"a"b"#, r"c\d e", r#"f\"g"#]
        );
        assert_eq!(
            split_windows_command_line(r#"x "a""b" "" end"#),
            vec!["x", r#"a"b"#, "", "end"]
        );
        assert_eq!(split_windows_command_line("  "), Vec::<String>::new());
        assert_eq!(split_windows_command_line("x\t"), vec!["x"]);
    }

    #[test]
    fn splits_quotes_and_escapes() {
        assert_eq!(
            split_words(r#"a 'b c' "d \"e\" \$f" g\ h"#).unwrap(),
            vec!["a", "b c", "d \"e\" $f", "g h"]
        );
        assert_eq!(split_words("  ").unwrap(), Vec::<String>::new());
        assert_eq!(split_words("''").unwrap(), vec![""]);
        assert_eq!(split_words("'a").unwrap_err(), SplitError::UnclosedQuote);
        assert_eq!(
            split_words("a\\").unwrap_err(),
            SplitError::TrailingBackslash
        );
    }

    #[test]
    fn reads_units_and_drop_ins() {
        let mut service = UnitService::default();
        parse_unit(
            "[Unit]\nExecStart=/wrong\n[Service]\nEnvironment=\"A=1 2\" B=3\nEnvironmentFile=-/etc/default/x\nExecStart=/usr/bin/demo-meshd \\\n  -c /etc/x.toml\nWorkingDirectory=/opt\n",
            &mut service,
        );
        assert_eq!(
            service.exec_start.as_deref(),
            Some("/usr/bin/demo-meshd    -c /etc/x.toml")
        );
        assert_eq!(
            service.environment,
            vec![("A".into(), "1 2".into()), ("B".into(), "3".into())]
        );
        assert_eq!(
            service.environment_files,
            vec![("/etc/default/x".into(), true)]
        );
        assert_eq!(service.working_directory.as_deref(), Some("/opt"));

        parse_unit(
            "[Service]\nExecStart=\nExecStart=/usr/bin/demo-meshd --net-name x\nEnvironment=\n",
            &mut service,
        );
        assert_eq!(
            service.exec_start.as_deref(),
            Some("/usr/bin/demo-meshd --net-name x")
        );
        assert!(service.environment.is_empty());
    }

    #[test]
    fn expands_exec_start() {
        let env = BTreeMap::from([
            ("OPTS".to_string(), "--a 1  --b".to_string()),
            ("ONE".to_string(), "x y".to_string()),
        ]);
        assert_eq!(
            exec_argv("-/usr/bin/p $OPTS ${ONE} -m %i %%", Some("office"), &env).unwrap(),
            vec!["/usr/bin/p", "--a", "1", "--b", "x y", "-m", "office", "%"]
        );
        assert_eq!(
            exec_argv("/usr/bin/p $NOPE", None, &env).unwrap_err(),
            ExecError::UnknownVariable("NOPE".into())
        );
        let error = exec_argv("/usr/bin/p --secret=pa$$w0rd", None, &env).unwrap_err();
        assert_eq!(error, ExecError::Unexpandable(1));
        assert!(!error.describe().contains("w0rd"));
        assert!(!format!("{error:?}").contains("w0rd"));
        assert_eq!(exec_argv("", None, &env).unwrap_err(), ExecError::Empty);
    }

    #[test]
    fn reads_assignments() {
        let parsed = parse_assignments(
            "# c\nexport A=\"1 2\"\nB='x'\nC=plain\nD=a b\nnot an assignment\n1X=bad\nE=\n",
        );
        assert_eq!(
            parsed,
            vec![
                ("A".into(), "1 2".into()),
                ("B".into(), "x".into()),
                ("C".into(), "plain".into()),
                ("E".into(), String::new()),
            ]
        );
    }

    #[test]
    fn finds_commands_in_shell_lines() {
        let names = vec!["demo-meshd".to_string()];
        assert_eq!(
            command_in_line(
                "DEMO_X=1 nohup /opt/demo-meshd -c /etc/a.toml >/dev/null 2>&1 &",
                &names
            )
            .unwrap(),
            vec!["/opt/demo-meshd", "-c", "/etc/a.toml"]
        );
        assert_eq!(
            command_in_line("demo-meshd --net-name x&", &names).unwrap(),
            vec!["demo-meshd", "--net-name", "x"]
        );
        assert!(command_in_line("echo demo-meshd", &names).is_none());
        assert!(command_in_line("other --x", &names).is_none());
        assert_eq!(
            leading_assignments("DEMO_X=1 B=2 nohup demo-meshd"),
            vec![("DEMO_X".into(), "1".into()), ("B".into(), "2".into())]
        );
        assert_eq!(split_nul(b"a\0b c\0\0"), vec!["a", "b c"]);
    }
}
