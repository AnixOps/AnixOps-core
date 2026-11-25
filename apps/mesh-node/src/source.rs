//! Collecting one program invocation's settings: configuration files,
//! environment and command line, merged in the order the profile gives
//! (file, then environment, then command line).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use crate::host::Host;
use crate::profile::{DropReason, Field, FlagAction, Kind, Merge, Profile, Source};

/// The most configuration files one configuration directory may hold; a
/// directory with more is reported as unreadable rather than read.
pub const MAX_DIR_FILES: usize = 64;

/// How a program was started.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Invocation {
    /// Arguments after the program name.
    pub args: Vec<String>,
    /// Only the variables the profile cares about.
    pub env: BTreeMap<String, String>,
    /// Working directory, for relative file names.
    pub cwd: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RawValue {
    Text(String),
    Bool(bool),
    Integer(i64),
    List(Vec<ListItem>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListItem {
    pub value: String,
    /// A mapped network ("real->mapped"), requirement R15.
    pub mapped: Option<String>,
    /// Item keys that need confirmation.
    pub confirm: Vec<String>,
}

impl ListItem {
    fn plain(value: String) -> Self {
        ListItem {
            value,
            mapped: None,
            confirm: Vec::new(),
        }
    }
}

/// One setting and where it came from, such as `flag --x` or
/// `file /etc/a.toml: a.b`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Setting {
    pub value: RawValue,
    pub origin: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dropped {
    pub reason: DropReason,
    pub origin: String,
}

/// Something read but not understood.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Problem {
    /// A flag, file key, variable or argument no rule covers.
    Unknown(String),
    /// A value of the wrong type or format.
    BadValue { origin: String, why: String },
    /// A file that could not be read.
    Unreadable { path: String, why: String },
    /// The configuration comes from standard input.
    Stdin,
}

/// The settings of one network instance.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Collected {
    pub config_file: Option<String>,
    pub settings: BTreeMap<Field, Setting>,
    pub dropped: Vec<Dropped>,
    pub problems: Vec<Problem>,
}

impl Collected {
    pub fn text(&self, field: Field) -> Option<&str> {
        match self.settings.get(&field).map(|setting| &setting.value) {
            Some(RawValue::Text(text)) => Some(text),
            _ => None,
        }
    }

    pub fn bool(&self, field: Field) -> Option<bool> {
        match self.settings.get(&field).map(|setting| &setting.value) {
            Some(RawValue::Bool(value)) => Some(*value),
            _ => None,
        }
    }

    pub fn integer(&self, field: Field) -> Option<i64> {
        match self.settings.get(&field).map(|setting| &setting.value) {
            Some(RawValue::Integer(value)) => Some(*value),
            _ => None,
        }
    }

    pub fn list(&self, field: Field) -> Option<&[ListItem]> {
        match self.settings.get(&field).map(|setting| &setting.value) {
            Some(RawValue::List(items)) => Some(items),
            _ => None,
        }
    }

    pub fn origin(&self, field: Field) -> Option<&str> {
        self.settings
            .get(&field)
            .map(|setting| setting.origin.as_str())
    }
}

/// Command-line values before they are merged.
#[derive(Debug, Default)]
struct Args {
    settings: BTreeMap<Field, Setting>,
    files: Vec<String>,
    dirs: Vec<String>,
    dropped: Vec<Dropped>,
    problems: Vec<Problem>,
}

pub fn parse_bool(text: &str) -> Option<bool> {
    match text.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Some(true),
        "0" | "false" | "no" | "off" => Some(false),
        _ => None,
    }
}

fn looks_like_flag(word: &str) -> bool {
    word.len() > 1 && word.starts_with('-') && word.parse::<f64>().is_err()
}

/// Parses command-line or environment strings for `field`.
fn values_from_strings(
    source: &Source,
    field: Field,
    values: &[String],
) -> Result<RawValue, String> {
    match field.kind() {
        Kind::Text => values
            .last()
            .map(|value| RawValue::Text(value.clone()))
            .ok_or_else(|| "missing value".to_string()),
        Kind::Integer => {
            let value = values.last().ok_or("missing value")?;
            value
                .trim()
                .parse()
                .map(RawValue::Integer)
                .map_err(|_| format!("{value:?} is not an integer"))
        }
        Kind::Bool => {
            let value = values.last().ok_or("missing value")?;
            parse_bool(value)
                .map(RawValue::Bool)
                .ok_or_else(|| format!("{value:?} is not a boolean"))
        }
        Kind::List => {
            let mut items = Vec::new();
            for value in values {
                let parts: Vec<&str> = match source.split.as_deref() {
                    Some(split) if !split.is_empty() => value.split(split).collect(),
                    _ => vec![value.as_str()],
                };
                for part in parts {
                    let part = part.trim();
                    if part.is_empty() {
                        continue;
                    }
                    let item = match source
                        .mapped_separator
                        .as_deref()
                        .filter(|separator| !separator.is_empty())
                        .and_then(|separator| part.split_once(separator))
                    {
                        Some((real, mapped)) => ListItem {
                            value: real.trim().to_string(),
                            mapped: Some(mapped.trim().to_string()),
                            confirm: Vec::new(),
                        },
                        None => ListItem::plain(part.to_string()),
                    };
                    items.push(item);
                }
            }
            Ok(RawValue::List(items))
        }
    }
}

fn switch_value(field: Field, value: &serde_json::Value) -> RawValue {
    match field.kind() {
        Kind::Bool => RawValue::Bool(value.as_bool().unwrap_or(false)),
        _ => RawValue::List(Vec::new()),
    }
}

/// Adds a command-line or environment value for `field`; repeated list
/// flags accumulate, other fields keep the last value.
fn put(settings: &mut BTreeMap<Field, Setting>, field: Field, value: RawValue, origin: String) {
    if let RawValue::List(more) = &value {
        if let Some(existing) = settings.get_mut(&field) {
            if let RawValue::List(items) = &mut existing.value {
                items.extend(more.iter().cloned());
                if !existing.origin.contains(&origin) {
                    existing.origin.push_str(", ");
                    existing.origin.push_str(&origin);
                }
                return;
            }
        }
    }
    settings.insert(field, Setting { value, origin });
}

fn parse_args(profile: &Profile, args: &[String]) -> Args {
    let mut out = Args::default();
    let mut index = 0;
    while index < args.len() {
        let word = &args[index];
        index += 1;
        // Positional words are reported by position only: they may hold
        // values such as secrets that must not reach a report.
        if word == "--" {
            for position in index..args.len() {
                out.problems
                    .push(Problem::Unknown(format!("argument {}", position + 1)));
            }
            break;
        }
        if !looks_like_flag(word) {
            out.problems
                .push(Problem::Unknown(format!("argument {index}")));
            continue;
        }
        let (name, inline) = if word.starts_with("--") {
            match word.split_once('=') {
                Some((name, value)) => (name.to_string(), Some(value.to_string())),
                None => (word.clone(), None),
            }
        } else {
            let name: String = word.chars().take(2).collect();
            let rest: String = word.chars().skip(2).collect();
            let rest = rest.strip_prefix('=').map(str::to_string).unwrap_or(rest);
            (name, (!rest.is_empty()).then_some(rest))
        };
        let origin = format!("flag {name}");
        let Some(action) = profile.flag_action(&name) else {
            out.problems.push(Problem::Unknown(format!("flag {name}")));
            continue;
        };
        let mut values = Vec::new();
        if action.takes_value() {
            match inline {
                Some(value) => values.push(value),
                None if index < args.len() => {
                    values.push(args[index].clone());
                    index += 1;
                }
                None => {
                    out.problems.push(Problem::BadValue {
                        origin: origin.clone(),
                        why: "missing value".into(),
                    });
                    continue;
                }
            }
            let greedy = match &action {
                FlagAction::Field(field) => profile.fields.get(field).is_some_and(|s| s.greedy),
                _ => false,
            };
            if greedy {
                while index < args.len() && !looks_like_flag(&args[index]) {
                    values.push(args[index].clone());
                    index += 1;
                }
            }
        } else if let Some(value) = inline {
            values.push(value);
        } else if index < args.len() && parse_bool(&args[index]).is_some() {
            // `--switch true` / `--switch false`.
            if matches!(action, FlagAction::Field(_)) {
                values.push(args[index].clone());
                index += 1;
            }
        }
        match action {
            FlagAction::ConfigFile => out.files.extend(values),
            FlagAction::ConfigDir => out.dirs.extend(values),
            FlagAction::Drop { rule, .. } => out.dropped.push(Dropped {
                reason: profile.drop[rule].reason,
                origin,
            }),
            FlagAction::Set(field, value) => {
                put(
                    &mut out.settings,
                    field,
                    switch_value(field, &value),
                    origin,
                );
            }
            FlagAction::Field(field) => {
                let source = &profile.fields[&field];
                let values = if field.kind() == Kind::Bool && values.is_empty() {
                    vec!["true".to_string()]
                } else {
                    values
                };
                match values_from_strings(source, field, &values) {
                    Ok(value) => put(&mut out.settings, field, value, origin),
                    Err(why) => out.problems.push(Problem::BadValue { origin, why }),
                }
            }
        }
    }
    out
}

fn parse_env(profile: &Profile, env: &BTreeMap<String, String>) -> Args {
    let mut out = Args::default();
    for (field, source) in &profile.fields {
        if let Some(value) = source.env.as_ref().and_then(|name| env.get(name)) {
            let origin = format!("env {}", source.env.as_deref().unwrap_or_default());
            match values_from_strings(source, *field, std::slice::from_ref(value)) {
                Ok(value) => put(&mut out.settings, *field, value, origin),
                Err(why) => out.problems.push(Problem::BadValue { origin, why }),
            }
        }
        for switch in &source.set {
            if let Some(name) = &switch.env {
                if env.get(name).map(String::as_str).and_then(parse_bool) == Some(true) {
                    put(
                        &mut out.settings,
                        *field,
                        switch_value(*field, &switch.value),
                        format!("env {name}"),
                    );
                }
            }
        }
    }
    for rule in &profile.drop {
        for name in &rule.env {
            if env.contains_key(name) {
                out.dropped.push(Dropped {
                    reason: rule.reason,
                    origin: format!("env {name}"),
                });
            }
        }
    }
    if let Some(value) = profile
        .config
        .file_env
        .as_ref()
        .and_then(|name| env.get(name))
    {
        out.files.push(value.clone());
    }
    if let Some(value) = profile
        .config
        .dir_env
        .as_ref()
        .and_then(|name| env.get(name))
    {
        out.dirs.push(value.clone());
    }
    let known = profile.known_env();
    for name in env.keys() {
        if !known.contains(&name.as_str()) && profile.wants_env(name) {
            out.problems.push(Problem::Unknown(format!("env {name}")));
        }
    }
    out
}

fn lookup<'a>(table: &'a toml::Table, path: &str) -> Option<&'a toml::Value> {
    let mut parts = path.split('.');
    let mut value = table.get(parts.next()?)?;
    for part in parts {
        value = value.as_table()?.get(part)?;
    }
    Some(value)
}

fn file_value(
    source: &Source,
    field: Field,
    value: &toml::Value,
    origin: &str,
    problems: &mut Vec<Problem>,
) -> Option<RawValue> {
    let bad = |problems: &mut Vec<Problem>, why: &str| {
        problems.push(Problem::BadValue {
            origin: origin.to_string(),
            why: why.to_string(),
        });
        None
    };
    match field.kind() {
        Kind::Text => match value {
            toml::Value::String(text) => Some(RawValue::Text(text.clone())),
            toml::Value::Integer(number) => Some(RawValue::Text(number.to_string())),
            _ => bad(problems, "expected text"),
        },
        Kind::Bool => match value {
            toml::Value::Boolean(flag) => Some(RawValue::Bool(*flag)),
            _ => bad(problems, "expected a boolean"),
        },
        Kind::Integer => match value {
            toml::Value::Integer(number) => Some(RawValue::Integer(*number)),
            _ => bad(problems, "expected an integer"),
        },
        Kind::List => {
            let entries: Vec<&toml::Value> = match value {
                toml::Value::Array(items) => items.iter().collect(),
                other => vec![other],
            };
            let mut items = Vec::new();
            for (index, entry) in entries.into_iter().enumerate() {
                match entry {
                    toml::Value::String(text) => items.push(ListItem::plain(text.clone())),
                    toml::Value::Table(table) => {
                        let Some(key) = source.file_item.as_deref() else {
                            return bad(problems, "unexpected table in list");
                        };
                        let Some(text) = table.get(key).and_then(toml::Value::as_str) else {
                            problems.push(Problem::BadValue {
                                origin: format!("{origin}[{index}]"),
                                why: format!("missing text key {key}"),
                            });
                            continue;
                        };
                        let mapped = source
                            .file_item_mapped
                            .as_deref()
                            .and_then(|mapped| table.get(mapped))
                            .map(|mapped| match mapped {
                                toml::Value::String(text) => text.clone(),
                                other => other.to_string(),
                            });
                        let mut confirm = Vec::new();
                        for item_key in table.keys() {
                            let known = item_key == key
                                || source.file_item_mapped.as_deref() == Some(item_key.as_str());
                            if known {
                                continue;
                            }
                            if source.file_item_confirm.iter().any(|c| c == item_key) {
                                confirm.push(item_key.clone());
                            } else {
                                problems.push(Problem::Unknown(format!(
                                    "{origin}[{index}].{item_key}"
                                )));
                            }
                        }
                        items.push(ListItem {
                            value: text.to_string(),
                            mapped,
                            confirm,
                        });
                    }
                    _ => {
                        problems.push(Problem::BadValue {
                            origin: format!("{origin}[{index}]"),
                            why: "expected text or a table".into(),
                        });
                    }
                }
            }
            Some(RawValue::List(items))
        }
    }
}

/// Keys of the file that no rule claims.
fn unknown_keys(table: &toml::Table, prefix: &str, claimed: &[&str], out: &mut Vec<String>) {
    for (key, value) in table {
        let path = if prefix.is_empty() {
            key.clone()
        } else {
            format!("{prefix}.{key}")
        };
        let covered = claimed
            .iter()
            .any(|claim| *claim == path || path.starts_with(&format!("{claim}.")));
        if covered {
            continue;
        }
        let has_claimed_child = claimed
            .iter()
            .any(|claim| claim.starts_with(&format!("{path}.")));
        match value {
            toml::Value::Table(inner) if has_claimed_child => {
                unknown_keys(inner, &path, claimed, out);
            }
            _ => out.push(path),
        }
    }
}

fn collect_file(profile: &Profile, path: &str, table: &toml::Table) -> Collected {
    let mut collected = Collected {
        config_file: Some(path.to_string()),
        ..Collected::default()
    };
    let mut claimed: Vec<&str> = Vec::new();
    for (field, source) in &profile.fields {
        let Some(key) = source.file.as_deref() else {
            continue;
        };
        claimed.push(key);
        if let Some(value) = lookup(table, key) {
            let origin = format!("file {path}: {key}");
            if let Some(value) = file_value(source, *field, value, &origin, &mut collected.problems)
            {
                collected.settings.insert(*field, Setting { value, origin });
            }
        }
    }
    for rule in &profile.drop {
        for key in &rule.file {
            claimed.push(key);
            if lookup(table, key).is_some() {
                collected.dropped.push(Dropped {
                    reason: rule.reason,
                    origin: format!("file {path}: {key}"),
                });
            }
        }
    }
    claimed.extend(profile.config.ignore_file_keys.iter().map(String::as_str));
    let mut unknown = Vec::new();
    unknown_keys(table, "", &claimed, &mut unknown);
    collected.problems.extend(
        unknown
            .into_iter()
            .map(|key| Problem::Unknown(format!("file {path}: {key}"))),
    );
    collected
}

/// Lays `over` on top of `base`: lists that append are concatenated, every
/// other value is replaced.
fn overlay(profile: &Profile, base: &mut Collected, over: &BTreeMap<Field, Setting>) {
    for (field, setting) in over {
        let append = profile
            .fields
            .get(field)
            .is_some_and(|source| source.merge == Merge::Append);
        if let (true, RawValue::List(more)) = (append, &setting.value) {
            if let Some(existing) = base.settings.get_mut(field) {
                if let RawValue::List(items) = &mut existing.value {
                    items.extend(more.iter().cloned());
                    existing.origin = format!("{}, {}", existing.origin, setting.origin);
                    continue;
                }
            }
        }
        base.settings.insert(*field, setting.clone());
    }
}

fn resolve(path: &str, cwd: Option<&str>) -> PathBuf {
    let path = Path::new(path);
    if path.is_absolute() {
        return path.to_path_buf();
    }
    Path::new(cwd.unwrap_or("/")).join(path)
}

/// Reads every network instance of one invocation.
pub fn collect(host: &dyn Host, profile: &Profile, invocation: &Invocation) -> Vec<Collected> {
    let cli = parse_args(profile, &invocation.args);
    let env = parse_env(profile, &invocation.env);

    // The command line names files; otherwise the environment does.
    let files = if cli.files.is_empty() && cli.dirs.is_empty() {
        env.files.clone()
    } else {
        cli.files.clone()
    };
    let dirs = if cli.files.is_empty() && cli.dirs.is_empty() {
        env.dirs.clone()
    } else {
        cli.dirs.clone()
    };

    let mut common_problems = cli.problems.clone();
    common_problems.extend(env.problems.iter().cloned());
    let mut common_dropped = env.dropped.clone();
    common_dropped.extend(cli.dropped.iter().cloned());

    // Environment first, then the command line on top: the command line wins.
    let mut overrides = Collected::default();
    overlay(profile, &mut overrides, &env.settings);
    for (field, setting) in &cli.settings {
        overrides.settings.insert(*field, setting.clone());
    }

    let mut instances: Vec<Collected> = Vec::new();
    let mut paths: Vec<String> = Vec::new();
    for file in &files {
        if profile.config.stdin_name.as_deref() == Some(file.as_str()) {
            let mut stdin = Collected::default();
            stdin.problems.push(Problem::Stdin);
            instances.push(stdin);
        } else {
            paths.push(
                resolve(file, invocation.cwd.as_deref())
                    .display()
                    .to_string(),
            );
        }
    }
    for dir in &dirs {
        let dir = resolve(dir, invocation.cwd.as_deref());
        match host.list_dir(&dir) {
            Ok(entries) => {
                let found: Vec<String> = entries
                    .into_iter()
                    .filter(|entry| host.is_file(entry))
                    .filter(|entry| {
                        !entry
                            .file_name()
                            .is_some_and(|name| name.to_string_lossy().starts_with('.'))
                    })
                    .map(|entry| entry.display().to_string())
                    .collect();
                if found.len() > MAX_DIR_FILES {
                    let mut unreadable = Collected::default();
                    unreadable.problems.push(Problem::Unreadable {
                        path: dir.display().to_string(),
                        why: format!("more than {MAX_DIR_FILES} files"),
                    });
                    instances.push(unreadable);
                } else {
                    paths.extend(found);
                }
            }
            Err(error) => {
                let mut unreadable = Collected::default();
                unreadable.problems.push(Problem::Unreadable {
                    path: dir.display().to_string(),
                    why: error.to_string(),
                });
                instances.push(unreadable);
            }
        }
    }
    for path in &paths {
        let text = match host.read_to_string(Path::new(path)) {
            Ok(text) => text,
            Err(error) => {
                let mut unreadable = Collected {
                    config_file: Some(path.clone()),
                    ..Collected::default()
                };
                unreadable.problems.push(Problem::Unreadable {
                    path: path.clone(),
                    why: error.to_string(),
                });
                instances.push(unreadable);
                continue;
            }
        };
        match toml::from_str::<toml::Table>(&text) {
            Ok(table) => instances.push(collect_file(profile, path, &table)),
            Err(error) => {
                let mut unreadable = Collected {
                    config_file: Some(path.clone()),
                    ..Collected::default()
                };
                unreadable.problems.push(Problem::Unreadable {
                    path: path.clone(),
                    why: error.message().to_string(),
                });
                instances.push(unreadable);
            }
        }
    }

    if instances.is_empty() {
        instances.push(Collected::default());
    }

    // With one file the overrides apply to it; with several only to the
    // instance whose network name the command line names.
    let single = instances.len() == 1;
    let override_name = overrides.text(Field::NetworkName).map(str::to_string);
    let mut matched_override = single;
    for instance in &mut instances {
        let applies = single
            || override_name
                .as_deref()
                .is_some_and(|name| instance.text(Field::NetworkName) == Some(name));
        if applies {
            matched_override = true;
            overlay(profile, instance, &overrides.settings);
        }
        instance.problems.extend(common_problems.iter().cloned());
        instance.dropped.extend(common_dropped.iter().cloned());
    }
    if !matched_override && !overrides.settings.is_empty() {
        for instance in &mut instances {
            instance.problems.push(Problem::BadValue {
                origin: "command line".into(),
                why: "settings on the command line match no configured network".into(),
            });
        }
    }
    instances
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host::fake::FakeHost;
    use crate::profile::tests::demo;

    fn args(words: &[&str]) -> Invocation {
        Invocation {
            args: words.iter().map(|word| word.to_string()).collect(),
            ..Invocation::default()
        }
    }

    #[test]
    fn reads_command_line_only() {
        let host = FakeHost::default();
        let profile = demo();
        let collected = collect(
            &host,
            &profile,
            &args(&[
                "--net-name",
                "office",
                "--net-secret=s",
                "-i10.1.0.5/24",
                "-p",
                "tcp://a:1",
                "udp://b:2",
                "-p",
                "tcp://c:3,tcp://d:4",
                "--no-crypto",
                "--latency-first",
                "--mtu",
                "1400",
                "-n",
                "192.168.1.0/24->10.9.0.0/24",
                "--exit-nodes",
                "10.1.0.9",
                "--mystery",
                "--log-level",
                "info",
            ]),
        );
        assert_eq!(collected.len(), 1);
        let one = &collected[0];
        assert_eq!(one.text(Field::NetworkName), Some("office"));
        assert_eq!(one.text(Field::NetworkSecret), Some("s"));
        assert_eq!(one.text(Field::Ipv4), Some("10.1.0.5/24"));
        assert_eq!(one.bool(Field::Encryption), Some(false));
        assert_eq!(one.bool(Field::LatencyFirst), Some(true));
        assert_eq!(one.integer(Field::Mtu), Some(1400));
        let peers: Vec<&str> = one
            .list(Field::Peers)
            .unwrap()
            .iter()
            .map(|item| item.value.as_str())
            .collect();
        assert_eq!(
            peers,
            vec!["tcp://a:1", "udp://b:2", "tcp://c:3", "tcp://d:4"]
        );
        let subnets = one.list(Field::Subnets).unwrap();
        assert_eq!(subnets[0].value, "192.168.1.0/24");
        assert_eq!(subnets[0].mapped.as_deref(), Some("10.9.0.0/24"));
        assert_eq!(
            one.dropped
                .iter()
                .map(|dropped| dropped.reason)
                .collect::<Vec<_>>(),
            vec![DropReason::ExitNode, DropReason::Logging]
        );
        assert_eq!(
            one.problems,
            vec![Problem::Unknown("flag --mystery".into())]
        );
    }

    const FILE: &str = r#"
instance_name = "a"
instance_id = "x"
ipv4 = "10.1.0.5/24"
hostname = "node-a"
listen = ["tcp://0.0.0.0:20010"]
old_portal = "0.0.0.0:1"
surprise = 1

[identity]
name = "office"
secret = "s3"
extra = true

[options]
encrypt = true
cipher = "chacha20"
punch_off = true
unknown_flag = 1

[[peer]]
uri = "tcp://p1:20010"
public_key = "k"

[[peer]]
uri = "udp://p2:20010"
weird = 1

[[subnet]]
cidr = "192.168.5.0/24"
allow = ["x"]

[forward]
a = 1
"#;

    #[test]
    fn reads_files_and_overrides() {
        let host = FakeHost::default();
        host.file("/etc/demo/a.toml", FILE);
        let profile = demo();
        let mut invocation = args(&["-c", "a.toml", "-p", "tcp://p3:1", "--hostname", "b"]);
        invocation.cwd = Some("/etc/demo".into());
        invocation
            .env
            .insert("DEMO_NET_SECRET".into(), "from-env".into());
        invocation.env.insert("DEMO_STRANGE".into(), "1".into());
        let collected = collect(&host, &profile, &invocation);
        assert_eq!(collected.len(), 1);
        let one = &collected[0];
        // Relative names are joined to the working directory with the
        // platform's separator.
        let expected = Path::new("/etc/demo")
            .join("a.toml")
            .to_string_lossy()
            .into_owned();
        assert_eq!(one.config_file.as_deref(), Some(expected.as_str()));
        assert_eq!(one.text(Field::NetworkName), Some("office"));
        assert_eq!(one.text(Field::NetworkSecret), Some("from-env"));
        assert_eq!(one.text(Field::Hostname), Some("b"));
        assert_eq!(one.text(Field::Cipher), Some("chacha20"));
        let peers = one.list(Field::Peers).unwrap();
        assert_eq!(
            peers.iter().map(|p| p.value.as_str()).collect::<Vec<_>>(),
            vec!["tcp://p1:20010", "udp://p2:20010", "tcp://p3:1"]
        );
        assert_eq!(peers[0].confirm, vec!["public_key".to_string()]);
        let subnets = one.list(Field::Subnets).unwrap();
        assert_eq!(subnets[0].confirm, vec!["allow".to_string()]);
        let reasons: Vec<DropReason> = one.dropped.iter().map(|d| d.reason).collect();
        assert!(reasons.contains(&DropReason::Obsolete));
        assert!(reasons.contains(&DropReason::NatTraversal));
        assert!(reasons.contains(&DropReason::PortForward));
        let mut unknown: Vec<String> = one
            .problems
            .iter()
            .filter_map(|problem| match problem {
                Problem::Unknown(what) => Some(what.clone()),
                _ => None,
            })
            .collect();
        unknown.sort();
        assert_eq!(
            unknown,
            vec![
                "env DEMO_STRANGE".to_string(),
                format!("file {expected}: identity.extra"),
                format!("file {expected}: options.unknown_flag"),
                format!("file {expected}: peer[1].weird"),
                format!("file {expected}: surprise"),
            ]
        );
    }

    #[test]
    fn oversized_files_and_directories_are_not_read() {
        let host = FakeHost::default();
        let big = "#".repeat(crate::host::MAX_TEXT_FILE as usize + 1);
        host.file("/etc/demo/big.toml", &big);
        for index in 0..=MAX_DIR_FILES {
            host.file(
                &format!("/etc/demo/many/{index}.toml"),
                "ipv4 = \"10.1.0.1/24\"\n",
            );
        }
        let profile = demo();
        let unreadable = |collected: &[Collected]| -> Vec<String> {
            collected
                .iter()
                .flat_map(|instance| &instance.problems)
                .filter_map(|problem| match problem {
                    Problem::Unreadable { why, .. } => Some(why.clone()),
                    _ => None,
                })
                .collect()
        };
        let file = collect(
            &host,
            &profile,
            &args(&["--config-file", "/etc/demo/big.toml"]),
        );
        assert_eq!(file.len(), 1);
        let why = unreadable(&file);
        assert_eq!(why.len(), 1);
        assert!(why[0].contains("larger than"), "{why:?}");

        let dir = collect(&host, &profile, &args(&["--config-dir", "/etc/demo/many"]));
        assert_eq!(dir.len(), 1);
        assert_eq!(
            unreadable(&dir),
            vec![format!("more than {MAX_DIR_FILES} files")]
        );
    }

    #[test]
    fn directories_hold_one_instance_per_file() {
        let host = FakeHost::default();
        host.file(
            "/etc/demo/nets/a.toml",
            "ipv4 = \"10.1.0.1/24\"\n[identity]\nname = \"a\"\nsecret = \"x\"\n",
        );
        host.file(
            "/etc/demo/nets/b.toml",
            "ipv4 = \"10.2.0.1/24\"\n[identity]\nname = \"b\"\nsecret = \"y\"\n",
        );
        host.file("/etc/demo/nets/.hidden", "garbage");
        let profile = demo();
        let collected = collect(
            &host,
            &profile,
            &args(&[
                "--config-dir",
                "/etc/demo/nets",
                "--net-name",
                "b",
                "--mtu",
                "1300",
            ]),
        );
        assert_eq!(collected.len(), 2);
        assert_eq!(collected[0].text(Field::NetworkName), Some("a"));
        assert_eq!(collected[0].integer(Field::Mtu), None);
        assert_eq!(collected[1].text(Field::NetworkName), Some("b"));
        assert_eq!(collected[1].integer(Field::Mtu), Some(1300));

        let unmatched = collect(
            &host,
            &profile,
            &args(&["--config-dir", "/etc/demo/nets", "--net-name", "c"]),
        );
        assert!(unmatched.iter().all(|instance| instance
            .problems
            .iter()
            .any(|problem| matches!(problem, Problem::BadValue { .. }))));
    }

    #[test]
    fn stdin_and_unreadable_files_are_problems() {
        let host = FakeHost::default();
        host.file("/etc/bad.toml", "not = = toml");
        let profile = demo();
        let collected = collect(
            &host,
            &profile,
            &args(&["-c", "-", "-c", "/etc/bad.toml", "-c", "/nope.toml"]),
        );
        assert_eq!(collected.len(), 3);
        assert_eq!(collected[0].problems[0], Problem::Stdin);
        assert!(matches!(
            collected[1].problems[0],
            Problem::Unreadable { .. }
        ));
        assert!(matches!(
            collected[2].problems[0],
            Problem::Unreadable { .. }
        ));
    }

    #[test]
    fn switches_and_bad_values() {
        let host = FakeHost::default();
        let profile = demo();
        let collected = collect(
            &host,
            &profile,
            &args(&[
                "--secure",
                "false",
                "--mtu",
                "big",
                "--no-listen",
                "--net-name",
            ]),
        );
        let one = &collected[0];
        assert_eq!(one.bool(Field::SecureMode), Some(false));
        assert_eq!(one.list(Field::Listeners), Some(&[][..]));
        assert_eq!(one.integer(Field::Mtu), None);
        let bad = one
            .problems
            .iter()
            .filter(|problem| matches!(problem, Problem::BadValue { .. }))
            .count();
        assert_eq!(bad, 2);
    }
}
