//! Loon plugin import for the M3 P0 compatibility tier.
//!
//! A user-imported Loon plugin is split by owner: `#!` metadata and
//! `[Argument]` describe the plugin, `[MITM] hostname` feeds the MITM host
//! list, routing-level `[Rule]` lines become [`RoutingRule`]s for the shared
//! routing model, and HTTP rewrite lines stay in the plugin source that the
//! `mitm_anixops` core evaluates. Every non-comment line gets a support status,
//! so a plugin can be graded as fully, partially, or not supported before it
//! is enabled.
//!
//! P1 adds `[Script]` `http-request`/`http-response` lines, planned by the
//! `mitm_anixops` core and executed by the `script-runtime` QuickJS runtime on
//! desktop; `[Map Local]` (and `mock-response-body` rewrites), answered locally
//! by [`crate::loon_map_local`]; and `[Body Rewrite]`. The core only reads
//! url-first rewrite lines, so Loon's action-first body rewrites are
//! translated: `http-response <url> <regex> <replacement> ...` becomes one
//! `<url> response-body-replace-regex <regex> <replacement>` rule per pair.
//! The first rule replaces the original line and the rest are appended, and
//! core diagnostics are mapped back to the original line numbers.
//!
//! Surge modules and Quantumult X resources go through the same import.
//! Quantumult X `[rewrite_local]` / `[mitm]` sections, also behind commented
//! headers (`#[rewrite_local]`) or with no headers at all, are read; its
//! `<url> url script-*` lines become `[Script]` lines, and `url response-body`
//! lines become url-first body rewrites. Surge `[URL Rewrite]` lines
//! (`<url> <replacement> <type>`) and phase-prefixed `[Header Rewrite]` lines
//! are translated for the core. QX `echo-response` becomes a `[Map Local]`
//! line. Scheduled and event scripts (`cron`, `network-changed`, `generic`,
//! QX `[task_local]`) leave the core's source and are listed in
//! [`LoonPluginImport::scheduled_scripts`] for the host's scheduler; jq body
//! rewrites stay in the core, which matches them, and run in Rust. Lines with
//! no equivalent yet (header-block regexes) are graded unsupported and kept
//! away from the core.
//!
//! Remote files are never fetched here. [`LoonPluginImport::remote_resources`]
//! lists the `script-path`s and the `[Map Local]` `data` URLs the plugin
//! needs; the host downloads them and passes the bytes to
//! [`import_loon_plugin_with_resources`], which inlines `[Map Local]` data. A
//! `[Map Local]` line whose data was not supplied is graded unsupported.

use crate::loon_cron::CronSchedule;
use crate::loon_header_block::{header_block_rules, LoonHeaderBlockRule, HEADER_BLOCK_SECTION};
use crate::loon_map_local::{
    inline_remote_data, map_local_pattern_accepted, parse_map_local_line, pattern_source_len,
    remote_data_url,
};
use crate::loon_syntax::{attributes, encode_core_argument, quote, tokens};
use crate::{AnixOpsMitmPolicyEngine, MitmPolicyRuleDiagnosticStatus};
use config_core::routing::{
    parse_rule_line, PolicyTarget, RejectKind, RoutingModel, RoutingRule, RuleLine,
};
use control_domain::{
    DomainError, DomainResult, HookPoint, PluginManifest, PluginPackage, PluginPermission,
};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;

pub const LOON_PLUGIN_MAX_BYTES: usize = 8 * 1024 * 1024;

pub const LOON_PLUGIN_TOO_LARGE_CODE: &str = "mitm.policy.loon_plugin.too_large";
pub const LOON_PLUGIN_EMPTY_CODE: &str = "mitm.policy.loon_plugin.empty";
pub const LOON_PLUGIN_ID_INVALID_CODE: &str = "mitm.policy.loon_plugin.id_invalid";

/// Plugin-level metadata from `#!key = value` lines and `[Argument]`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LoonPluginMetadata {
    pub name: Option<String>,
    pub desc: Option<String>,
    pub author: Option<String>,
    pub homepage: Option<String>,
    pub icon: Option<String>,
    pub category: Option<String>,
    /// Declared arguments as `(name, default)` pairs, in declaration order.
    pub arguments: Vec<(String, String)>,
}

/// How a plugin's `[MITM] hostname` list combines with the existing list.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoonHostnameMode {
    /// `%APPEND%` / `%INSERT%`, or a plugin hostname line without a marker:
    /// plugins only ever add to the user's list.
    Append,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoonMitmHostnames {
    pub mode: LoonHostnameMode,
    /// Host patterns to decrypt, lower-cased, in declaration order.
    pub include: Vec<String>,
    /// Host patterns listed with a `-` or `!` prefix, without the prefix.
    pub exclude: Vec<String>,
}

impl Default for LoonMitmHostnames {
    fn default() -> Self {
        Self {
            mode: LoonHostnameMode::Append,
            include: Vec::new(),
            exclude: Vec::new(),
        }
    }
}

impl LoonMitmHostnames {
    /// Applies this plugin's hostname list to an existing list. Included
    /// patterns are appended once; excluded patterns are removed and recorded
    /// as `-pattern` so later plugins cannot re-enable them silently.
    pub fn apply(&self, existing: &[String]) -> Vec<String> {
        let mut merged = existing
            .iter()
            .filter(|pattern| {
                let pattern = pattern.trim().to_ascii_lowercase();
                !self.exclude.contains(&pattern)
            })
            .cloned()
            .collect::<Vec<_>>();
        for pattern in &self.include {
            if self.exclude.contains(pattern) {
                continue;
            }
            if !merged
                .iter()
                .any(|existing| existing.eq_ignore_ascii_case(pattern))
            {
                merged.push(pattern.clone());
            }
        }
        for pattern in &self.exclude {
            let marker = format!("-{pattern}");
            if !merged.contains(&marker) {
                merged.push(marker);
            }
        }
        merged
    }
}

/// Support status of one plugin line.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum LoonLineStatus {
    /// The line takes full effect.
    Supported,
    /// The line takes effect with narrower semantics than in Loon.
    Partial,
    /// The line belongs to a later tier (scripts, map local, body rewrites).
    Deferred,
    /// The line has no effect.
    Unsupported,
    /// Informational line that never affects traffic.
    Ignored,
}

impl LoonLineStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Supported => "supported",
            Self::Partial => "partial",
            Self::Deferred => "deferred",
            Self::Unsupported => "unsupported",
            Self::Ignored => "ignored",
        }
    }
}

/// Component that enforces a line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoonLineHandler {
    Metadata,
    MitmHostnames,
    Routing,
    PolicyEngine,
    /// Dispatch planned by the policy core, executed by the script runtime.
    ScriptRuntime,
    /// Answered locally by [`crate::loon_map_local`].
    MapLocal,
    /// Regex over the whole header block, run by
    /// [`crate::loon_header_block`].
    HeaderBlock,
    None,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoonLineReport {
    /// 1-based line number in the plugin text.
    pub line: usize,
    pub section: String,
    pub status: LoonLineStatus,
    pub handler: LoonLineHandler,
    /// Stable reason, for example `rewrite.reject` or `rule.type_unsupported`.
    pub reason: String,
}

/// Overall grade of a plugin.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoonSupportLevel {
    /// Every effective line is supported.
    Full,
    /// Some effective lines are partial, deferred, or unsupported.
    Partial,
    /// No effective line is supported, or the policy core refused the plugin.
    Unsupported,
}

impl LoonSupportLevel {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Full => "full",
            Self::Partial => "partial",
            Self::Unsupported => "unsupported",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoonPluginReport {
    pub level: LoonSupportLevel,
    pub lines: Vec<LoonLineReport>,
    /// Set when the `mitm_anixops` core refused the whole plugin.
    pub policy_load_error: Option<String>,
}

impl LoonPluginReport {
    pub fn count(&self, status: LoonLineStatus) -> usize {
        self.lines
            .iter()
            .filter(|line| line.status == status)
            .count()
    }

    /// Renders a stable, credential-free text summary for CI logs.
    pub fn render_text(&self, plugin_label: &str) -> String {
        let mut text = String::new();
        let _ = writeln!(
            text,
            "{plugin_label}: {} (supported {}, partial {}, deferred {}, unsupported {})",
            self.level.as_str(),
            self.count(LoonLineStatus::Supported),
            self.count(LoonLineStatus::Partial),
            self.count(LoonLineStatus::Deferred),
            self.count(LoonLineStatus::Unsupported),
        );
        if let Some(error) = &self.policy_load_error {
            let _ = writeln!(text, "  policy core refused the plugin: {error}");
        }
        for line in &self.lines {
            if matches!(
                line.status,
                LoonLineStatus::Supported | LoonLineStatus::Ignored
            ) {
                continue;
            }
            let _ = writeln!(
                text,
                "  line {} [{}] {}: {}",
                line.line,
                line.section,
                line.status.as_str(),
                line.reason
            );
        }
        text
    }
}

/// Routing rule contributed by a plugin `[Rule]` line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoonPluginRule {
    pub line: usize,
    pub rule: RoutingRule,
}

/// What a remote file named by a plugin is used for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum LoonRemoteResourceKind {
    /// A `script-path`, run only after the user consents to it.
    Script,
    /// A `[Map Local]` (or QX `echo-response`) body, served as data.
    MapLocalData,
}

impl LoonRemoteResourceKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Script => "script",
            Self::MapLocalData => "map_local_data",
        }
    }
}

/// A remote file the plugin needs, as written in the plugin.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoonRemoteResource {
    pub url: String,
    pub kind: LoonRemoteResourceKind,
    /// First plugin line that names it.
    pub line: usize,
}

/// What starts a [`LoonScheduledScript`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LoonScheduledTrigger {
    /// A cron expression ([`crate::loon_cron::CronSchedule`]), local time.
    Cron(String),
    /// The device's network changed.
    NetworkChanged,
    /// Run on demand (Surge panels and `generic` scripts).
    Generic,
}

/// A script that runs outside any HTTP flow, such as a daily check-in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoonScheduledScript {
    pub trigger: LoonScheduledTrigger,
    /// `script-path`; also listed in `remote_resources`.
    pub script_url: String,
    pub tag: String,
    /// `$argument`, with argument templates resolved.
    pub argument: String,
    pub timeout_secs: u32,
    /// Plugin line that declares it.
    pub line: usize,
}

/// Result of importing one Loon plugin.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoonPluginImport {
    pub metadata: LoonPluginMetadata,
    pub mitm_hostnames: LoonMitmHostnames,
    pub rules: Vec<LoonPluginRule>,
    pub report: LoonPluginReport,
    /// Remote files the plugin names, in plugin order without repeats.
    pub remote_resources: Vec<LoonRemoteResource>,
    /// Cron, network-change and generic scripts, which run outside HTTP flows.
    pub scheduled_scripts: Vec<LoonScheduledScript>,
    has_request_actions: bool,
    has_response_actions: bool,
    source: String,
}

impl LoonPluginImport {
    /// Plugin text evaluated by the `mitm_anixops` core, with Loon-only
    /// syntax translated (see the module docs).
    pub fn source(&self) -> &str {
        &self.source
    }

    pub fn routing_rules(&self) -> Vec<RoutingRule> {
        self.rules.iter().map(|rule| rule.rule.clone()).collect()
    }

    /// Builds the package loaded by [`crate::AnixOpsMitmPluginService`].
    /// Hooks and permissions cover only the phases the plugin rewrites.
    pub fn plugin_package(&self, id: &str, version: &str) -> DomainResult<PluginPackage> {
        let id = id.trim();
        if id.is_empty()
            || !id
                .chars()
                .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '-' | '_'))
        {
            return Err(DomainError::new(
                LOON_PLUGIN_ID_INVALID_CODE,
                "Loon plugin id must be non-empty ASCII letters, digits, '.', '-', or '_'",
            ));
        }

        let mut permissions = Vec::new();
        let mut hooks = Vec::new();
        if self.has_request_actions || !self.has_response_actions {
            permissions.extend([
                PluginPermission::ReadRequest,
                PluginPermission::ModifyRequest,
            ]);
            hooks.push(HookPoint::Request);
        }
        if self.has_response_actions {
            permissions.extend([
                PluginPermission::ReadResponse,
                PluginPermission::ModifyResponse,
            ]);
            hooks.push(HookPoint::Response);
        }

        Ok(PluginPackage {
            manifest: PluginManifest {
                id: id.to_string(),
                version: version.to_string(),
                permissions,
                hooks,
            },
            source: self.source.clone(),
        })
    }
}

/// Returns a copy of `model` whose rules start with the plugins' routing
/// rules, in plugin order. A plugin cannot know the user's policy names, so
/// a rule naming one (`PROXY`, or a module argument) uses the group of that
/// name when it exists, else the model's FINAL target when that is a proxy,
/// else the first group; with none of those the rule is left out.
pub fn routing_model_with_plugin_rules(
    model: &RoutingModel,
    plugins: &[&LoonPluginImport],
) -> RoutingModel {
    let fallback = match &model.final_target {
        PolicyTarget::Node(_) | PolicyTarget::Group(_) => Some(model.final_target.clone()),
        _ => model
            .groups
            .first()
            .map(|group| PolicyTarget::Group(group.id.clone())),
    };
    let mut rules = plugins
        .iter()
        .flat_map(|plugin| plugin.routing_rules())
        .filter_map(|mut rule| {
            if let PolicyTarget::Group(name) | PolicyTarget::Node(name) = &rule.target {
                rule.target = if name.eq_ignore_ascii_case("DIRECT") {
                    PolicyTarget::Direct
                } else if model.group(name).is_some() {
                    PolicyTarget::Group(name.clone())
                } else {
                    fallback.clone()?
                };
            }
            Some(rule)
        })
        .collect::<Vec<_>>();
    rules.extend(model.rules.iter().cloned());
    RoutingModel {
        rules,
        final_target: model.final_target.clone(),
        groups: model.groups.clone(),
        final_dns_failed: model.final_dns_failed,
    }
}

/// Combines several imported plugins into one policy text for the
/// `mitm_anixops` core, which loads a single config. Rewrite, script and
/// map-local lines keep plugin order under one header per section; the
/// `[MITM]` hostname lists are merged with [`LoonMitmHostnames::apply`].
/// Metadata and `[Argument]` lines are left out, and of `[Rule]` only the
/// URL-REGEX rejects stay: other rules belong to the routing model (see
/// [`routing_model_with_plugin_rules`]).
pub fn merged_plugin_source(name: &str, plugins: &[&LoonPluginImport]) -> String {
    let mut sections: Vec<(String, Vec<String>)> = Vec::new();
    let mut hostnames = Vec::new();
    for plugin in plugins {
        hostnames = plugin.mitm_hostnames.apply(&hostnames);
        let mut current: Option<usize> = None;
        for raw_line in plugin.source.lines() {
            let line = raw_line.trim();
            if line.is_empty()
                || line.starts_with('#')
                || line.starts_with(';')
                || line.starts_with("//")
            {
                continue;
            }
            if line.starts_with('[') && line.ends_with(']') {
                let header = line[1..line.len() - 1].trim();
                current = match Section::parse(header) {
                    Section::Rule
                    | Section::Rewrite
                    | Section::HeaderRewrite
                    | Section::BodyRewrite
                    | Section::Script
                    | Section::MapLocal
                    | Section::HeaderBlock => Some(
                        match sections
                            .iter()
                            .position(|(existing, _)| existing.eq_ignore_ascii_case(header))
                        {
                            Some(index) => index,
                            None => {
                                sections.push((header.to_string(), Vec::new()));
                                sections.len() - 1
                            }
                        },
                    ),
                    _ => None,
                };
                continue;
            }
            if let Some(index) = current {
                // Only URL-REGEX rejects are the core's; other rules belong
                // to the routing model.
                let rule_section = Section::parse(&sections[index].0) == Section::Rule;
                let url_regex = line
                    .get(..9)
                    .is_some_and(|head| head.eq_ignore_ascii_case("URL-REGEX"));
                if !rule_section || url_regex {
                    sections[index].1.push(line.to_string());
                }
            }
        }
    }

    // An exclusion from any plugin wins over another plugin's include.
    let excluded = hostnames
        .iter()
        .filter_map(|pattern| pattern.strip_prefix('-'))
        .map(str::to_string)
        .collect::<Vec<_>>();
    hostnames.retain(|pattern| pattern.starts_with('-') || !excluded.contains(pattern));

    let mut text = String::new();
    let _ = writeln!(text, "[Plugin]\nname = {}", name.trim());
    for (header, lines) in sections.iter().filter(|(_, lines)| !lines.is_empty()) {
        let _ = writeln!(text, "\n[{header}]");
        for line in lines {
            let _ = writeln!(text, "{line}");
        }
    }
    if hostnames.iter().any(|pattern| !pattern.starts_with('-')) {
        let _ = writeln!(
            text,
            "\n[MITM]\nenable = true\nhostname = {}",
            hostnames.join(", ")
        );
    }
    text
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Section {
    Preamble,
    Plugin,
    Argument,
    Rule,
    Rewrite,
    HeaderRewrite,
    BodyRewrite,
    Script,
    MapLocal,
    Mitm,
    /// Surge `[General]`: only `force-http-engine-hosts` concerns a plugin.
    General,
    /// Scheduled and event scripts (Quantumult X `[task_local]`).
    Task,
    /// Surge `[Panel]`: UI only.
    Panel,
    /// Header-block rewrites the importer wrote
    /// ([`crate::loon_header_block::HEADER_BLOCK_SECTION`]).
    HeaderBlock,
    Other,
}

impl Section {
    fn parse(name: &str) -> Self {
        match name.trim().to_ascii_lowercase().as_str() {
            "plugin" => Self::Plugin,
            "argument" => Self::Argument,
            "rule" => Self::Rule,
            "rewrite" | "url rewrite" | "remote rewrite" | "rewrite_local" | "rewrite local" => {
                Self::Rewrite
            }
            "header rewrite" | "remote header rewrite" => Self::HeaderRewrite,
            "body rewrite" | "remote body rewrite" => Self::BodyRewrite,
            "script" => Self::Script,
            "map local" => Self::MapLocal,
            "mitm" => Self::Mitm,
            "general" => Self::General,
            "task_local" | "task-local" => Self::Task,
            "panel" => Self::Panel,
            "anixops header block" => Self::HeaderBlock,
            _ => Self::Other,
        }
    }

    /// Quantumult X resources often comment their section headers out
    /// (`#[rewrite_local]`) so other clients skip them; only those names are
    /// read as headers when commented.
    fn is_quantumult_header(name: &str) -> bool {
        matches!(
            name.trim().to_ascii_lowercase().as_str(),
            "rewrite_local" | "rewrite_remote" | "mitm" | "task_local" | "filter_local"
        )
    }

    /// Header the core and [`merged_plugin_source`] read for this section.
    fn canonical_header(self) -> Option<&'static str> {
        match self {
            Self::Rewrite => Some("Rewrite"),
            // `force-http-engine-hosts` joins the MITM hostnames, as the
            // core reads it.
            Self::Mitm | Self::General => Some("MITM"),
            _ => None,
        }
    }
}

const METADATA_KEYS: [&str; 6] = ["name", "desc", "author", "homepage", "icon", "category"];

/// Parses a Loon plugin and grades every line. The `mitm_anixops` core is
/// consulted for the HTTP rewrite lines it owns; a plugin it refuses is graded
/// unsupported as a whole.
pub fn import_loon_plugin(text: &str) -> DomainResult<LoonPluginImport> {
    import_loon_plugin_with_resources(text, &BTreeMap::new())
}

/// [`import_loon_plugin`] with downloaded remote files, by URL as written in
/// the plugin. Only `[Map Local]` data is read from `resources`; scripts
/// reach the script runtime on their own consented path.
pub fn import_loon_plugin_with_resources(
    text: &str,
    resources: &BTreeMap<String, Vec<u8>>,
) -> DomainResult<LoonPluginImport> {
    if text.len() > LOON_PLUGIN_MAX_BYTES {
        return Err(DomainError::new(
            LOON_PLUGIN_TOO_LARGE_CODE,
            format!("Loon plugin exceeds {LOON_PLUGIN_MAX_BYTES} bytes"),
        ));
    }
    if text.trim().is_empty() {
        return Err(DomainError::new(
            LOON_PLUGIN_EMPTY_CODE,
            "Loon plugin is empty",
        ));
    }

    let mut parser = Parser {
        resources: Some(resources),
        ..Parser::default()
    };
    let module_arguments = module_argument_defaults(text);
    // Script lines resolve `{name}` with the declared defaults, wherever in
    // the plugin `[Argument]` stands.
    parser.declare_arguments(text);
    let mut section = Section::Preamble;
    let mut section_name = String::new();
    for (index, raw_line) in text.lines().enumerate() {
        let line_number = index + 1;
        let line = raw_line.trim();
        if line.is_empty() {
            continue;
        }
        if let Some(meta) = line.strip_prefix("#!") {
            parser.metadata_line(line_number, &section_name, meta);
            continue;
        }
        // Surge module arguments are text substitutions made before the
        // line is read; a value of `#` turns the line into a comment.
        let substituted = substitute_module_arguments(line, &module_arguments);
        if substituted != line {
            parser.replaced.insert(line_number, substituted.clone());
        }
        let line = substituted.as_str();
        let header = if line.starts_with('[') && line.ends_with(']') {
            Some((line[1..line.len() - 1].trim(), false))
        } else {
            line.strip_prefix('#')
                .map(str::trim_start)
                .filter(|rest| rest.starts_with('[') && rest.ends_with(']'))
                .map(|rest| rest[1..rest.len() - 1].trim())
                .filter(|name| Section::is_quantumult_header(name))
                .map(|name| (name, true))
        };
        if header.is_none()
            && (line.starts_with('#') || line.starts_with(';') || line.starts_with("//"))
        {
            continue;
        }
        if let Some((name, commented)) = header {
            section_name = name.to_string();
            section = Section::parse(&section_name);
            if commented || !name.eq_ignore_ascii_case(section.canonical_header().unwrap_or(name)) {
                let replacement = match section.canonical_header() {
                    Some(canonical) => format!("[{canonical}]"),
                    None if commented => line.to_string(),
                    None => format!("[{name}]"),
                };
                parser.replaced.insert(line_number, replacement);
            }
            if section == Section::Other {
                parser.push(
                    line_number,
                    &section_name,
                    LoonLineStatus::Unsupported,
                    LoonLineHandler::None,
                    "section.unsupported",
                );
            }
            continue;
        }

        match section {
            // A Quantumult X snippet may have no section headers at all.
            Section::Preamble if is_quantumult_rewrite(line) => {
                parser.rewrite_line(line_number, "rewrite_local", line, true)
            }
            Section::Preamble if is_hostname_line(line) => {
                parser.mitm_line(line_number, "mitm", line)
            }
            Section::Preamble | Section::Plugin => parser.push(
                line_number,
                &section_name,
                LoonLineStatus::Ignored,
                LoonLineHandler::Metadata,
                "metadata.plugin_section",
            ),
            Section::Argument => parser.argument_line(line_number, &section_name, line),
            Section::Rule => parser.rule_line(line_number, &section_name, line),
            Section::Rewrite | Section::HeaderRewrite => {
                parser.rewrite_line(line_number, &section_name, line, false)
            }
            Section::Task => parser.scheduled_script_line(line_number, &section_name, line),
            Section::Panel => parser.push(
                line_number,
                &section_name,
                LoonLineStatus::Ignored,
                LoonLineHandler::None,
                "section.panel_ignored",
            ),
            Section::BodyRewrite => parser.body_rewrite_line(line_number, &section_name, line),
            Section::Script => parser.script_line(line_number, &section_name, line),
            Section::MapLocal => {
                if let Some(effective) = parser.map_local_line(line_number, &section_name, line) {
                    if effective != line {
                        parser.replaced.insert(line_number, effective);
                    }
                }
            }
            Section::Mitm => parser.mitm_line(line_number, &section_name, line),
            Section::General => parser.general_line(line_number, &section_name, line),
            Section::HeaderBlock => {
                let rules = header_block_rules(&format!("[{HEADER_BLOCK_SECTION}]\n{line}"));
                let (status, handler, reason) = if rules.is_empty() {
                    (
                        LoonLineStatus::Unsupported,
                        LoonLineHandler::None,
                        "rewrite.invalid",
                    )
                } else {
                    (
                        LoonLineStatus::Supported,
                        LoonLineHandler::HeaderBlock,
                        "rewrite.header_block",
                    )
                };
                parser.push(line_number, &section_name, status, handler, reason);
            }
            Section::Other => parser.push(
                line_number,
                &section_name,
                LoonLineStatus::Unsupported,
                LoonLineHandler::None,
                "section.unsupported",
            ),
        }
    }

    let (mut source, line_origins) = parser.translated_source(text);
    let policy_load_error = parser.cross_check_with_policy_core(&mut source, &line_origins);
    let level = grade(&parser.lines, policy_load_error.is_some());
    Ok(LoonPluginImport {
        metadata: parser.metadata,
        mitm_hostnames: parser.mitm_hostnames,
        rules: parser.rules,
        report: LoonPluginReport {
            level,
            lines: parser.lines,
            policy_load_error,
        },
        remote_resources: parser.remote_resources,
        scheduled_scripts: parser.scheduled,
        has_request_actions: parser.has_request_actions,
        has_response_actions: parser.has_response_actions,
        source,
    })
}

#[derive(Default)]
struct Parser<'a> {
    /// Downloaded remote files by URL.
    resources: Option<&'a BTreeMap<String, Vec<u8>>>,
    remote_resources: Vec<LoonRemoteResource>,
    metadata: LoonPluginMetadata,
    mitm_hostnames: LoonMitmHostnames,
    rules: Vec<LoonPluginRule>,
    lines: Vec<LoonLineReport>,
    has_request_actions: bool,
    has_response_actions: bool,
    /// Replacement text for original lines, by 1-based line number.
    replaced: BTreeMap<usize, String>,
    /// Lines appended after the plugin: section, line, original line number.
    appended: Vec<(&'static str, String, usize)>,
    scheduled: Vec<LoonScheduledScript>,
    /// Every argument was declared up front by [`Parser::declare_arguments`],
    /// so the lines that declare one are only graded.
    arguments_declared: bool,
}

impl Parser<'_> {
    fn remote_resource(&mut self, line: usize, url: &str, kind: LoonRemoteResourceKind) {
        if !self
            .remote_resources
            .iter()
            .any(|resource| resource.url == url && resource.kind == kind)
        {
            self.remote_resources.push(LoonRemoteResource {
                url: url.to_string(),
                kind,
                line,
            });
        }
    }

    fn push(
        &mut self,
        line: usize,
        section: &str,
        status: LoonLineStatus,
        handler: LoonLineHandler,
        reason: &str,
    ) {
        self.lines.push(LoonLineReport {
            line,
            section: section.to_string(),
            status,
            handler,
            reason: reason.to_string(),
        });
    }

    fn metadata_line(&mut self, line: usize, section: &str, meta: &str) {
        let (key, value) = match meta.split_once('=') {
            Some((key, value)) => (key.trim().to_ascii_lowercase(), value.trim().to_string()),
            None => (meta.trim().to_ascii_lowercase(), String::new()),
        };
        let value = Some(value).filter(|value| !value.is_empty());
        match key.as_str() {
            "name" => self.metadata.name = value.or(self.metadata.name.take()),
            "desc" => self.metadata.desc = value.or(self.metadata.desc.take()),
            "author" => self.metadata.author = value.or(self.metadata.author.take()),
            "homepage" => self.metadata.homepage = value.or(self.metadata.homepage.take()),
            "icon" => self.metadata.icon = value.or(self.metadata.icon.take()),
            "category" => self.metadata.category = value.or(self.metadata.category.take()),
            "arguments" if !self.arguments_declared => {
                for (name, default) in parse_module_arguments(&value.unwrap_or_default()) {
                    self.add_argument(&name, &default);
                }
            }
            _ => {}
        }
        let reason = if METADATA_KEYS.contains(&key.as_str()) || key == "arguments" {
            "metadata.recognized"
        } else {
            "metadata.unrecognized"
        };
        self.push(
            line,
            section,
            LoonLineStatus::Ignored,
            LoonLineHandler::Metadata,
            reason,
        );
    }

    fn add_argument(&mut self, name: &str, default: &str) {
        let name = name.trim();
        if name.is_empty() {
            return;
        }
        let default = default.trim().trim_matches('"').to_string();
        if let Some(existing) = self
            .metadata
            .arguments
            .iter_mut()
            .find(|(existing, _)| existing == name)
        {
            existing.1 = default;
        } else {
            self.metadata.arguments.push((name.to_string(), default));
        }
    }

    /// Declares every `#!arguments` and `[Argument]` default of the plugin, in
    /// plugin order (a name declared twice keeps the last default, as the
    /// core does), before any line that uses them is read.
    fn declare_arguments(&mut self, text: &str) {
        let mut in_arguments = false;
        for raw_line in text.lines() {
            let line = raw_line.trim();
            if let Some(meta) = line.strip_prefix("#!") {
                if let Some((key, value)) = meta.split_once('=') {
                    if key.trim().eq_ignore_ascii_case("arguments") {
                        for (name, default) in parse_module_arguments(value.trim()) {
                            self.add_argument(&name, &default);
                        }
                    }
                }
                continue;
            }
            if line.starts_with('[') && line.ends_with(']') {
                in_arguments = Section::parse(&line[1..line.len() - 1]) == Section::Argument;
                continue;
            }
            if !in_arguments
                || line.is_empty()
                || line.starts_with('#')
                || line.starts_with(';')
                || line.starts_with("//")
            {
                continue;
            }
            if let Some((name, spec)) = line.split_once('=') {
                self.add_argument(name, &argument_default(spec));
            }
        }
        self.arguments_declared = true;
    }

    fn argument_line(&mut self, line: usize, section: &str, text: &str) {
        // `Name = kind,default[,tag=...]`
        let status = match text.split_once('=') {
            Some((name, spec)) => {
                if !self.arguments_declared {
                    self.add_argument(name, &argument_default(spec));
                }
                LoonLineStatus::Ignored
            }
            None => LoonLineStatus::Unsupported,
        };
        let reason = if status == LoonLineStatus::Ignored {
            "argument.declared"
        } else {
            "argument.invalid"
        };
        self.push(line, section, status, LoonLineHandler::Metadata, reason);
    }

    /// Surge `[General] force-http-engine-hosts` sends those hosts through
    /// the HTTP engine; the core reads the list as MITM hostnames, so the
    /// line becomes a `hostname` line. Other `[General]` options are the
    /// user's, not a plugin's.
    fn general_line(&mut self, line: usize, section: &str, text: &str) {
        let key = text
            .split_once('=')
            .map(|(key, _)| key.trim().to_ascii_lowercase().replace('_', "-"));
        match (key.as_deref(), text.split_once('=')) {
            (Some("force-http-engine-hosts"), Some((_, value))) => {
                let hostname = format!("hostname = {}", value.trim());
                self.replaced.insert(line, hostname.clone());
                self.mitm_line(line, section, &hostname);
            }
            _ => {
                self.replaced.insert(line, format!("# {text}"));
                self.push(
                    line,
                    section,
                    LoonLineStatus::Ignored,
                    LoonLineHandler::None,
                    "general.option_ignored",
                );
            }
        }
    }

    fn mitm_line(&mut self, line: usize, section: &str, text: &str) {
        let Some((key, value)) = text.split_once('=') else {
            self.push(
                line,
                section,
                LoonLineStatus::Unsupported,
                LoonLineHandler::None,
                "mitm.invalid",
            );
            return;
        };
        let key = key.trim().to_ascii_lowercase();
        match key.as_str() {
            "hostname" => {
                let mut marker_seen = None;
                let mut kept = Vec::new();
                let mut dropped_include = false;
                let mut dropped_live_include = false;
                let mut dropped_exclude = false;
                let mut accepted = Vec::new();
                for item in value.split(',') {
                    let mut item = item.trim();
                    for marker in ["%APPEND%", "%INSERT%"] {
                        if item
                            .get(..marker.len())
                            .is_some_and(|prefix| prefix.eq_ignore_ascii_case(marker))
                        {
                            marker_seen.get_or_insert(marker);
                            item = item[marker.len()..].trim();
                        }
                    }
                    if item.is_empty() {
                        continue;
                    }
                    if !core_host_pattern(item) {
                        if item.starts_with('-') || item.starts_with('!') {
                            dropped_exclude = true;
                        } else {
                            dropped_include = true;
                            dropped_live_include |= !host_item_never_matches(item);
                        }
                        continue;
                    }
                    kept.push(item.to_string());
                    accepted.push(item.to_ascii_lowercase());
                }
                if dropped_exclude || (dropped_include && kept.is_empty()) {
                    // An exclusion the core cannot read would widen what the
                    // plugin decrypts, so the whole line is dropped instead.
                    self.replaced.insert(line, format!("# {text}"));
                    self.push(
                        line,
                        section,
                        LoonLineStatus::Unsupported,
                        LoonLineHandler::None,
                        "mitm.hostname_pattern_unsupported",
                    );
                    return;
                }
                if dropped_include {
                    let marker = marker_seen.map(|m| format!("{m} ")).unwrap_or_default();
                    self.replaced
                        .insert(line, format!("hostname = {marker}{}", kept.join(", ")));
                }
                for pattern in accepted {
                    if let Some(excluded) = pattern
                        .strip_prefix('-')
                        .or_else(|| pattern.strip_prefix('!'))
                    {
                        let excluded = excluded.trim().to_string();
                        if !excluded.is_empty() && !self.mitm_hostnames.exclude.contains(&excluded)
                        {
                            self.mitm_hostnames.exclude.push(excluded);
                        }
                    } else if !self.mitm_hostnames.include.contains(&pattern) {
                        self.mitm_hostnames.include.push(pattern);
                    }
                }
                if dropped_include && !dropped_live_include {
                    // Only items no real host can have, such as
                    // `a-zA-Z0-9_-.admobile.top` or two lines run together:
                    // nothing is lost.
                    self.push(
                        line,
                        section,
                        LoonLineStatus::Supported,
                        LoonLineHandler::MitmHostnames,
                        "mitm.hostname_dead_items_dropped",
                    );
                } else if dropped_include {
                    // Hosts named only by a glob are not decrypted.
                    self.push(
                        line,
                        section,
                        LoonLineStatus::Partial,
                        LoonLineHandler::MitmHostnames,
                        "mitm.hostname_pattern_unsupported",
                    );
                } else {
                    self.push(
                        line,
                        section,
                        LoonLineStatus::Supported,
                        LoonLineHandler::MitmHostnames,
                        "mitm.hostname",
                    );
                }
            }
            // Certificate verification is never skipped for plugin hosts.
            "skip-server-cert-verify" => self.push(
                line,
                section,
                LoonLineStatus::Unsupported,
                LoonLineHandler::None,
                "mitm.skip_server_cert_verify_refused",
            ),
            _ => self.push(
                line,
                section,
                LoonLineStatus::Ignored,
                LoonLineHandler::None,
                "mitm.option_ignored",
            ),
        }
    }

    fn rule_line(&mut self, line: usize, section: &str, text: &str) {
        let kind = text
            .split(',')
            .next()
            .unwrap_or_default()
            .trim()
            .to_ascii_uppercase();

        match kind.as_str() {
            // Request URLs are only visible after decryption, so the policy
            // core enforces URL-REGEX rejects on MITM hosts; a URL-REGEX
            // with a node or group goes to the routing model.
            "URL-REGEX" => self.url_regex_rule_line(line, section, text),
            "FINAL" => self.push(
                line,
                section,
                LoonLineStatus::Unsupported,
                LoonLineHandler::None,
                "rule.final_in_plugin",
            ),
            // A Loon plugin rule may leave the policy out; it then takes the
            // policy the user picks for the plugin, which is the proxy here.
            "AND" | "OR" | "NOT" => self.routing_rule_line(line, section, text),
            _ if text
                .split(',')
                .filter(|field| !field.trim().is_empty())
                .count()
                == 2 =>
            {
                let with_policy = format!("{},PROXY", text.trim().trim_end_matches(','));
                self.routing_rule_line(line, section, &with_policy)
            }
            _ => self.routing_rule_line(line, section, text),
        }
    }

    fn url_regex_rule_line(&mut self, line: usize, section: &str, text: &str) {
        let target = text.rsplit(',').next().unwrap_or_default().trim();
        if !is_reject_policy(target) {
            // A node or group: the routing model picks it for each request
            // (decrypted ones request by request).
            self.routing_rule_line(line, section, text);
            return;
        }
        // Without a connection to drop after decryption, the drop variants
        // answer like a plain REJECT.
        let upper = target.to_ascii_uppercase();
        if matches!(upper.as_str(), "REJECT-DROP" | "REJECT-NO-DROP") {
            let cut = text.len() - text.rsplit(',').next().unwrap_or_default().len();
            self.replaced
                .insert(line, format!("{}REJECT", &text[..cut]));
        }
        self.has_request_actions = true;
        self.push(
            line,
            section,
            LoonLineStatus::Supported,
            LoonLineHandler::PolicyEngine,
            "rule.url_regex_reject",
        );
    }

    /// Domain, address, port and logical rules go to the routing model. The
    /// policy core does not see them, so its stricter rule grammar cannot
    /// refuse the plugin over one of them.
    fn routing_rule_line(&mut self, line: usize, section: &str, text: &str) {
        match parse_rule_line(text) {
            Ok(RuleLine::Rule {
                matcher,
                target,
                no_resolve,
            }) => {
                let (policy, reason) = if is_reject_policy(&target) {
                    // REJECT-DROP, REJECT-NO-DROP and REJECT-TINYGIF (Loon
                    // REJECT-IMG) keep their kind; the variants that answer
                    // only decrypted requests close like REJECT.
                    let kind = RejectKind::parse(&target).unwrap_or_default();
                    (PolicyTarget::Reject(kind), "rule.routing")
                } else if target.eq_ignore_ascii_case("DIRECT") {
                    (PolicyTarget::Direct, "rule.routing")
                } else {
                    // A plugin cannot know the user's node and group names:
                    // `PROXY` and other names resolve when the rules join
                    // the routing model.
                    (PolicyTarget::Group(target), "rule.routing_policy")
                };
                self.rules.push(LoonPluginRule {
                    line,
                    rule: RoutingRule {
                        matcher,
                        target: policy,
                        no_resolve,
                    },
                });
                self.replaced.insert(line, format!("# {text}"));
                self.push(
                    line,
                    section,
                    LoonLineStatus::Supported,
                    LoonLineHandler::Routing,
                    reason,
                );
            }
            Ok(RuleLine::Final { .. }) => self.push(
                line,
                section,
                LoonLineStatus::Unsupported,
                LoonLineHandler::None,
                "rule.final_in_plugin",
            ),
            Err(error) => {
                let reason =
                    if error.code == config_core::routing::ROUTING_RULE_TYPE_UNSUPPORTED_CODE {
                        "rule.type_unsupported"
                    } else {
                        "rule.invalid"
                    };
                self.push(
                    line,
                    section,
                    LoonLineStatus::Unsupported,
                    LoonLineHandler::None,
                    reason,
                );
            }
        }
    }

    /// Grades a url-first rewrite line. Quantumult X (`<url> url <action>`)
    /// and Surge (`<url> <replacement> <type>`, `http-request <url>
    /// header-add ...`) forms are translated to what the core reads. With
    /// `preamble`, the line stood outside any section and moves to an
    /// appended `[Rewrite]` section.
    fn rewrite_line(&mut self, line: usize, section: &str, text: &str, preamble: bool) {
        let parts = tokens(text);
        let lower = |index: usize| {
            parts
                .get(index)
                .map(|token| token.to_ascii_lowercase())
                .unwrap_or_default()
        };
        let first = lower(0);

        // A script line filed under `[Rewrite]` belongs to `[Script]`.
        if matches!(first.as_str(), "http-request" | "http-response")
            && text.to_ascii_lowercase().contains("script-path=")
        {
            let commented = format!("# {text}");
            let before = self.lines.len();
            self.script_line(line, section, text);
            // `script_line` leaves the line the core should read (with its
            // arguments resolved) in `replaced`; it moves to `[Script]` and
            // is commented out here.
            let core_line = self
                .replaced
                .insert(line, commented.clone())
                .filter(|core_line| *core_line != commented)
                .unwrap_or_else(|| text.to_string());
            if self.lines[before..].iter().all(|report| {
                !matches!(
                    report.status,
                    LoonLineStatus::Unsupported | LoonLineStatus::Ignored
                )
            }) {
                self.appended.push(("Script", core_line, line));
            }
            return;
        }

        // jq body rewrites run with jaq after the core matches them.
        if let Some((rule, response)) = jq_rewrite(&parts) {
            if response {
                self.has_response_actions = true;
            } else {
                self.has_request_actions = true;
            }
            self.push(
                line,
                section,
                LoonLineStatus::Supported,
                LoonLineHandler::PolicyEngine,
                "rewrite.jq",
            );
            self.emit_core_line(line, text, Some(rule), preamble);
            return;
        }

        if first != "url"
            && lower(1) == "url"
            && self.quantumult_rewrite_line(line, section, text, &parts, preamble)
        {
            return;
        }
        if matches!(first.as_str(), "http-request" | "http-response") && parts.len() >= 3 {
            let action = lower(2);
            if matches!(
                action.as_str(),
                "header-add" | "header-del" | "header-replace" | "header-replace-regex"
            ) {
                let action = if first == "http-response" {
                    format!("response-{action}")
                } else {
                    action
                };
                let mut rule = format!("{} {action}", quote(&parts[1]));
                for token in &parts[3..] {
                    rule.push(' ');
                    rule.push_str(&quote(token));
                }
                self.grade_rewrite(line, section, &action);
                self.emit_core_line(line, text, Some(rule), preamble);
                return;
            }
        }

        let action = if first == "url" || lower(1) == "url" {
            lower(2)
        } else {
            let second = lower(1);
            // Surge `[URL Rewrite]`: `<url> <replacement> <302|reject|header>`.
            if classify_rewrite_action(&second).1 == "rewrite.action_unsupported"
                && parts.len() >= 3
                && classify_rewrite_action(&lower(2)).1 != "rewrite.action_unsupported"
            {
                lower(2)
            } else {
                second
            }
        };

        if action == "mock-response-body" && first != "url" && lower(1) != "url" {
            self.mock_response_body_line(line, section, text);
            return;
        }
        // Loon `<url> header <new url>` and Surge `<url> <new url> header`
        // send the request to the new URL. The data plane cannot move a
        // request, so it becomes the closest equivalent, a 302.
        if action == "header" && first != "url" && lower(1) != "url" {
            let target = if lower(1) == "header" {
                parts.get(2)
            } else {
                parts.get(1)
            };
            match target.filter(|target| !target.is_empty()) {
                Some(target) => {
                    let rule = format!("{} 302 {}", quote(&parts[0]), quote(target));
                    self.grade_rewrite(line, section, "header");
                    self.emit_core_line(line, text, Some(rule), preamble);
                }
                None => {
                    self.replaced.insert(line, format!("# {text}"));
                    self.push(
                        line,
                        section,
                        LoonLineStatus::Unsupported,
                        LoonLineHandler::None,
                        "rewrite.invalid",
                    );
                }
            }
            return;
        }
        // The core reads a `200` action as a transparent URL rewrite, which
        // the data plane does not perform. Left in the source it would still
        // end the core's URL rule lookup and hide a later reject or redirect
        // for the same URL, so the line is graded unsupported and leaves the
        // core's source.
        if classify_rewrite_action(&action).0 == LoonLineStatus::Unsupported
            && (lower(1) == "200" || lower(2) == "200")
        {
            self.replaced.insert(line, format!("# {text}"));
            self.grade_rewrite(line, section, &action);
            return;
        }
        self.grade_rewrite(line, section, &action);
        if preamble {
            self.emit_core_line(line, text, None, true);
        }
    }

    fn grade_rewrite(&mut self, line: usize, section: &str, action: &str) {
        let (status, reason, response) = classify_rewrite_action(action);
        if status != LoonLineStatus::Unsupported {
            if response {
                self.has_response_actions = true;
            } else {
                self.has_request_actions = true;
            }
        }
        let handler = if status == LoonLineStatus::Unsupported {
            LoonLineHandler::None
        } else {
            LoonLineHandler::PolicyEngine
        };
        self.push(line, section, status, handler, reason);
    }

    /// Hands `rule` (or the line as written) to the core: in place, or for a
    /// line outside any section, in an appended `[Rewrite]` section.
    fn emit_core_line(&mut self, line: usize, text: &str, rule: Option<String>, preamble: bool) {
        let rule = rule.unwrap_or_else(|| text.to_string());
        if preamble {
            self.replaced.insert(line, format!("# {text}"));
            self.appended.push(("Rewrite", rule, line));
        } else {
            self.replaced.insert(line, rule);
        }
    }

    /// Quantumult X `<url> url <action> ...` lines whose meaning differs from
    /// the core's reading. Returns false for actions the core reads as is.
    fn quantumult_rewrite_line(
        &mut self,
        line: usize,
        section: &str,
        text: &str,
        parts: &[String],
        preamble: bool,
    ) -> bool {
        let action = parts
            .get(2)
            .map(|token| token.to_ascii_lowercase())
            .unwrap_or_default();
        let pattern = &parts[0];
        match action.as_str() {
            // `script-echo-response` answers the request itself: its `$done`
            // object is the response (the runtime reads a request-phase
            // `$done` with a `status` and no `response` key that way).
            "script-request-header"
            | "script-request-body"
            | "script-response-header"
            | "script-response-body"
            | "script-echo-response"
            | "script-analyze-echo-response" => {
                self.replaced.insert(line, format!("# {text}"));
                let Some(path) = parts.get(3).filter(|path| !path.is_empty()) else {
                    self.push(
                        line,
                        section,
                        LoonLineStatus::Unsupported,
                        LoonLineHandler::None,
                        "script.path_missing",
                    );
                    return true;
                };
                let response = action.starts_with("script-response");
                let requires_body = action.ends_with("-body") || action.contains("echo");
                let tag = path
                    .rsplit('/')
                    .next()
                    .unwrap_or(path)
                    .trim_end_matches(".js")
                    .replace(',', "_");
                let script = format!(
                    "{} {} script-path={}, requires-body={}, tag={}",
                    if response {
                        "http-response"
                    } else {
                        "http-request"
                    },
                    quote(pattern),
                    path.replace(',', "%2C"),
                    requires_body,
                    if tag.is_empty() { "script" } else { &tag },
                );
                let before = self.lines.len();
                self.script_line(line, section, &script);
                if self.lines[before..]
                    .iter()
                    .all(|report| report.status != LoonLineStatus::Unsupported)
                {
                    self.appended.push(("Script", script, line));
                }
                true
            }
            // `<url> url echo-response <mime> echo-response <body url>`
            // answers with a remote file: a `[Map Local]` line.
            "echo-response" => {
                self.replaced.insert(line, format!("# {text}"));
                let (Some(mime), Some(url)) = (parts.get(3), parts.get(5)) else {
                    self.push(
                        line,
                        section,
                        LoonLineStatus::Unsupported,
                        LoonLineHandler::None,
                        "rewrite.echo_response_invalid",
                    );
                    return true;
                };
                let map_local = format!(
                    "{} data-type=text data={} header={}",
                    quote(pattern),
                    quote(url),
                    quote(&format!("Content-Type:{mime}")),
                );
                if let Some(effective) = self.map_local_line(line, section, &map_local) {
                    self.appended.push(("Map Local", effective, line));
                }
                true
            }
            // `<url> url response-body <regex> response-body <replacement>`.
            "request-body" | "response-body" => {
                let (Some(pattern_body), Some(replacement)) = (parts.get(3), parts.get(5)) else {
                    self.replaced.insert(line, format!("# {text}"));
                    self.push(
                        line,
                        section,
                        LoonLineStatus::Unsupported,
                        LoonLineHandler::None,
                        "rewrite.invalid",
                    );
                    return true;
                };
                let core_action = format!("{action}-replace-regex");
                let rule = format!(
                    "{} {core_action} {} {}",
                    quote(pattern),
                    quote(pattern_body),
                    quote(replacement)
                );
                self.grade_rewrite(line, section, &core_action);
                self.emit_core_line(line, text, Some(rule), preamble);
                true
            }
            // `<url> url request-header <regex> request-header <replacement>`:
            // a regex over the whole header block, run by
            // `loon_header_block` from an appended section the core skips.
            "request-header" | "response-header" => {
                self.replaced.insert(line, format!("# {text}"));
                // The replacement is the rest of the line: it may hold
                // spaces (`$1User-Agent: Quantumult$2`).
                let rule = match (parts.get(3), parts.get(5..).filter(|rest| !rest.is_empty())) {
                    (Some(regex), Some(replacement)) => LoonHeaderBlockRule {
                        response: action == "response-header",
                        url_pattern: pattern.to_string(),
                        regex: regex.clone(),
                        replacement: replacement.join(" "),
                    },
                    _ => {
                        self.push(
                            line,
                            section,
                            LoonLineStatus::Unsupported,
                            LoonLineHandler::None,
                            "rewrite.invalid",
                        );
                        return true;
                    }
                };
                let accepted = map_local_pattern_accepted(&rule.url_pattern)
                    && header_block_regex_accepted(&rule);
                if accepted {
                    if rule.response {
                        self.has_response_actions = true;
                    } else {
                        self.has_request_actions = true;
                    }
                    self.appended
                        .push((HEADER_BLOCK_SECTION, rule.line(), line));
                    self.push(
                        line,
                        section,
                        LoonLineStatus::Supported,
                        LoonLineHandler::HeaderBlock,
                        "rewrite.header_block",
                    );
                } else {
                    self.push(
                        line,
                        section,
                        LoonLineStatus::Unsupported,
                        LoonLineHandler::None,
                        "pattern.regex_invalid",
                    );
                }
                true
            }
            _ => false,
        }
    }

    /// `<url> mock-response-body <map local attributes>` answers like a
    /// `[Map Local]` line, so it moves to an appended `[Map Local]` section.
    fn mock_response_body_line(&mut self, line: usize, section: &str, text: &str) {
        let pattern_len = pattern_source_len(text);
        let attributes = text[pattern_len..]
            .trim_start()
            .get("mock-response-body".len()..)
            .unwrap_or("");
        let pattern = tokens(text).into_iter().next().unwrap_or_default();
        let map_local = format!("{} {}", quote(&pattern), attributes.trim());
        self.replaced.insert(line, format!("# {text}"));
        if let Some(effective) = self.map_local_line(line, section, &map_local) {
            self.appended.push(("Map Local", effective, line));
        }
    }

    /// Grades a `[Map Local]` line. Returns the line to keep when it takes
    /// effect: `text`, or `text` with its remote data inlined.
    fn map_local_line(&mut self, line: usize, section: &str, text: &str) -> Option<String> {
        let mut effective = text.to_string();
        if let Some(url) = remote_data_url(text) {
            self.remote_resource(line, &url, LoonRemoteResourceKind::MapLocalData);
            let inlined = match self.resources.and_then(|resources| resources.get(&url)) {
                Some(body) => inline_remote_data(text, body),
                None => Err("map_local.remote_data_missing"),
            };
            match inlined {
                Ok(inlined) => effective = inlined,
                Err(reason) => {
                    self.push(
                        line,
                        section,
                        LoonLineStatus::Unsupported,
                        LoonLineHandler::None,
                        reason,
                    );
                    return None;
                }
            }
        }
        let (status, handler, reason) = match parse_map_local_line(&effective) {
            Ok(rule) if map_local_pattern_accepted(&rule.pattern) => {
                self.has_request_actions = true;
                (
                    LoonLineStatus::Supported,
                    LoonLineHandler::MapLocal,
                    "map_local.response",
                )
            }
            Ok(_) => (
                LoonLineStatus::Unsupported,
                LoonLineHandler::None,
                "map_local.pattern_rejected",
            ),
            Err(reason) => (LoonLineStatus::Unsupported, LoonLineHandler::None, reason),
        };
        self.push(line, section, status, handler, reason);
        (status == LoonLineStatus::Supported).then_some(effective)
    }

    /// Translates Loon's action-first `[Body Rewrite]` lines; url-first lines
    /// in the section are graded like `[Rewrite]` lines.
    fn body_rewrite_line(&mut self, line: usize, section: &str, text: &str) {
        let tokens = tokens(text);
        let kind = tokens
            .first()
            .map(|token| token.to_ascii_lowercase())
            .unwrap_or_default();
        let response = match kind.as_str() {
            "http-request" => false,
            "http-response" => true,
            "http-request-jq"
            | "http-response-jq"
            | "http-request-json-del"
            | "http-response-json-del"
            | "http-request-json-add"
            | "http-response-json-add"
            | "http-request-json-replace"
            | "http-response-json-replace" => {
                self.rewrite_line(line, section, text, false);
                return;
            }
            _ if tokens.len() >= 2
                && classify_rewrite_action(&tokens[1].to_ascii_lowercase()).1
                    != "rewrite.action_unsupported" =>
            {
                self.rewrite_line(line, section, text, false);
                return;
            }
            _ => {
                self.replaced.insert(line, format!("# {text}"));
                self.push(
                    line,
                    section,
                    LoonLineStatus::Unsupported,
                    LoonLineHandler::None,
                    "body_rewrite.type_unsupported",
                );
                return;
            }
        };
        if tokens.len() < 3 || tokens[1].is_empty() || tokens[2].is_empty() {
            self.replaced.insert(line, format!("# {text}"));
            self.push(
                line,
                section,
                LoonLineStatus::Unsupported,
                LoonLineHandler::None,
                "body_rewrite.invalid",
            );
            return;
        }

        let action = if response {
            "response-body-replace-regex"
        } else {
            "request-body-replace-regex"
        };
        let pattern = quote(&tokens[1]);
        for (index, pair) in tokens[2..].chunks(2).enumerate() {
            let replacement = pair.get(1).map(String::as_str).unwrap_or("");
            let rule = format!(
                "{pattern} {action} {} {}",
                quote(&pair[0]),
                quote(replacement)
            );
            if index == 0 {
                self.replaced.insert(line, rule);
            } else {
                self.appended.push(("Body Rewrite", rule, line));
            }
        }
        let reason = if response {
            self.has_response_actions = true;
            "body_rewrite.http_response"
        } else {
            self.has_request_actions = true;
            "body_rewrite.http_request"
        };
        self.push(
            line,
            section,
            LoonLineStatus::Supported,
            LoonLineHandler::PolicyEngine,
            reason,
        );
    }

    /// The plugin text for the core and, for each of its lines, the original
    /// 1-based line number it came from.
    fn translated_source(&self, text: &str) -> (String, Vec<usize>) {
        let mut lines = Vec::new();
        let mut origins = Vec::new();
        for (index, raw_line) in text.lines().enumerate() {
            let line = index + 1;
            lines.push(
                self.replaced
                    .get(&line)
                    .cloned()
                    .unwrap_or_else(|| raw_line.to_string()),
            );
            origins.push(line);
        }
        let mut current_section = None;
        for (section, rule, origin) in &self.appended {
            if current_section != Some(*section) {
                lines.push(format!("[{section}]"));
                origins.push(*origin);
                current_section = Some(*section);
            }
            lines.push(rule.clone());
            origins.push(*origin);
        }
        // The core reads at most `MAX_CORE_PATTERN_LEN` bytes of a pattern:
        // a longer one with a top-level alternation becomes several lines.
        let (lines, origins): (Vec<_>, Vec<_>) = lines
            .into_iter()
            .zip(origins)
            .flat_map(|(line, origin)| {
                split_long_pattern_line(&line)
                    .unwrap_or_else(|| vec![line])
                    .into_iter()
                    .map(move |line| (line, origin))
            })
            .unzip();
        let mut source = lines.join("\n");
        source.push('\n');
        (source, origins)
    }

    /// HTTP scripts run in the script runtime per flow; scheduled and event
    /// scripts go to `scheduled_script_line`.
    fn script_line(&mut self, line: usize, section: &str, text: &str) {
        if let Some(translated) = loon_conditional_script(text) {
            self.replaced.insert(line, translated.clone());
            return self.script_line(line, section, &translated);
        }
        // A rewrite line filed under `[Script]` (`<url> reject-dict`) belongs
        // to `[Rewrite]`.
        let parts = tokens(text);
        if parts.len() >= 2
            && !parts[0].contains('=')
            && !parts[0].to_ascii_lowercase().starts_with("http-")
            && !parts[0].eq_ignore_ascii_case("cron")
            && classify_rewrite_action(&parts[1].to_ascii_lowercase()).0
                != LoonLineStatus::Unsupported
        {
            return self.rewrite_line(line, section, text, true);
        }
        let lower = text.to_ascii_lowercase();
        let first = lower
            .split(|ch: char| ch.is_whitespace() || ch == ',')
            .next()
            .unwrap_or("");
        let response = match first {
            "http-request" => false,
            "http-response" => true,
            // Surge-style `name = type=http-response, pattern=..., ...`.
            _ if lower.contains("type=http-request") => false,
            _ if lower.contains("type=http-response") => true,
            _ => {
                self.scheduled_script_line(line, section, text);
                return;
            }
        };
        // The core drops every backslash of a quoted Surge attribute value,
        // so `pattern="a\?b"` would reach it as `a?b`.
        if !first.starts_with("http-") {
            if let Some(escaped) = surge_pattern_for_core(text) {
                self.replaced.insert(line, escaped);
            }
        }
        if !lower.contains("script-path") && !lower.contains("script_path") {
            self.push(
                line,
                section,
                LoonLineStatus::Unsupported,
                LoonLineHandler::None,
                "script.path_missing",
            );
            return;
        }
        // The core reads `enable=` and `argument=` as written and does not
        // know the plugin's `[Argument]` (the merged policy has none), so
        // both are resolved here.
        let current = self
            .replaced
            .get(&line)
            .cloned()
            .unwrap_or_else(|| text.to_string());
        let (resolved, switch, argument_too_long) = self.resolve_script_line(&current);
        if switch == ScriptSwitch::Off {
            self.replaced.insert(line, format!("# {current}"));
            self.push(
                line,
                section,
                LoonLineStatus::Ignored,
                LoonLineHandler::ScriptRuntime,
                "script.disabled",
            );
            return;
        }
        if resolved != current {
            self.replaced.insert(line, resolved);
        }
        if let Some(path) = attributes(text)
            .into_iter()
            .find(|(key, _)| key == "script-path" || key == "script_path")
            .map(|(_, path)| path)
            .filter(|path| !path.is_empty())
        {
            self.remote_resource(line, &path, LoonRemoteResourceKind::Script);
        }
        // The core cuts an attribute segment longer than its buffer, so the
        // script would get a truncated argument.
        let partial = if argument_too_long {
            Some("script.argument_too_long")
        } else if switch == ScriptSwitch::Unresolved {
            Some("script.enable_unresolved")
        } else {
            None
        };
        if let Some(reason) = partial {
            if response {
                self.has_response_actions = true;
            } else {
                self.has_request_actions = true;
            }
            self.push(
                line,
                section,
                LoonLineStatus::Partial,
                LoonLineHandler::ScriptRuntime,
                reason,
            );
            return;
        }
        if response {
            self.has_response_actions = true;
        } else {
            self.has_request_actions = true;
        }
        // `binary-body-mode` is reported per dispatch by the core and the
        // script runtime hands such bodies over as `Uint8Array`.
        let (status, reason) = if response {
            (LoonLineStatus::Supported, "script.http_response")
        } else {
            (LoonLineStatus::Supported, "script.http_request")
        };
        self.push(
            line,
            section,
            status,
            LoonLineHandler::ScriptRuntime,
            reason,
        );
    }

    /// Scheduled and event scripts: Loon `cron "expr" script-path=...`,
    /// `network-changed`/`generic script-path=...`; Surge `name =
    /// type=cron|event|generic, ...`; Quantumult X `[task_local]`
    /// `<cron> <url>, tag=...` and `event-network <url>`. They run outside
    /// any HTTP flow, so the line leaves the core's source.
    fn scheduled_script_line(&mut self, line: usize, section: &str, text: &str) {
        let (status, reason) = match self.scheduled_script(text) {
            Ok(Some(script)) => {
                self.remote_resource(line, &script.script_url, LoonRemoteResourceKind::Script);
                let reason = match script.trigger {
                    LoonScheduledTrigger::Cron(_) => "script.cron",
                    LoonScheduledTrigger::NetworkChanged => "script.network_changed",
                    LoonScheduledTrigger::Generic => "script.generic",
                };
                self.scheduled.push(LoonScheduledScript { line, ..script });
                (LoonLineStatus::Supported, reason)
            }
            Ok(None) => (LoonLineStatus::Ignored, "script.disabled"),
            Err(reason) => (LoonLineStatus::Unsupported, reason),
        };
        self.replaced.insert(line, format!("# {text}"));
        self.push(
            line,
            section,
            status,
            LoonLineHandler::ScriptRuntime,
            reason,
        );
    }

    /// `Ok(None)` for a script the plugin turns off (`enabled=false`).
    fn scheduled_script(&self, text: &str) -> Result<Option<LoonScheduledScript>, &'static str> {
        let text = text.trim();
        let lower = text.to_ascii_lowercase();
        let (trigger, name, attributes) = if let Some(rest) = lower
            .starts_with("cron ")
            .then(|| text["cron ".len()..].trim_start())
        {
            // Loon: the expression is quoted or an `{argument}`.
            let (expression, rest) = match rest.chars().next() {
                Some(quote @ ('"' | '\'')) => {
                    let end = rest[1..].find(quote).ok_or("script.cron_invalid")? + 1;
                    (rest[1..end].to_string(), &rest[end + 1..])
                }
                Some('{') => {
                    let end = rest.find('}').ok_or("script.cron_invalid")?;
                    (self.resolve_arguments(&rest[..=end]), &rest[end + 1..])
                }
                _ => return Err("script.cron_invalid"),
            };
            (
                LoonScheduledTrigger::Cron(expression),
                String::new(),
                attributes(rest),
            )
        } else if let Some(rest) = ["network-changed ", "event-network "]
            .iter()
            .find(|prefix| lower.starts_with(*prefix))
            .map(|prefix| text[prefix.len()..].trim_start())
        {
            // Loon `network-changed script-path=...`; Quantumult X
            // `event-network <url>, tag=...`.
            let attributes = if rest.starts_with("http://") || rest.starts_with("https://") {
                url_first_attributes(rest)
            } else {
                attributes(rest)
            };
            (
                LoonScheduledTrigger::NetworkChanged,
                String::new(),
                attributes,
            )
        } else if lower.starts_with("generic ") {
            (
                LoonScheduledTrigger::Generic,
                String::new(),
                attributes(&text["generic ".len()..]),
            )
        } else if let Some((name, rest)) = text
            .split_once('=')
            .filter(|(_, rest)| rest.to_ascii_lowercase().contains("type="))
        {
            // Surge: `name = type=cron, cronexp="...", script-path=...`.
            let attributes = attributes(rest);
            let value = |key: &str| {
                attributes
                    .iter()
                    .find(|(name, _)| name == key)
                    .map(|(_, value)| value.clone())
            };
            let trigger = match value("type")
                .unwrap_or_default()
                .to_ascii_lowercase()
                .as_str()
            {
                "cron" => {
                    LoonScheduledTrigger::Cron(value("cronexp").ok_or("script.cron_invalid")?)
                }
                "event" => match value("event-name").unwrap_or_default().as_str() {
                    "network-changed" => LoonScheduledTrigger::NetworkChanged,
                    _ => return Err("script.event_unsupported"),
                },
                "generic" => LoonScheduledTrigger::Generic,
                _ => return Err("script.type_unsupported"),
            };
            (trigger, name.trim().to_string(), attributes)
        } else {
            // Quantumult X `[task_local]`: cron fields, then the script URL.
            let words = text.split_whitespace().collect::<Vec<_>>();
            let at = words
                .iter()
                .position(|word| word.starts_with("http://") || word.starts_with("https://"))
                .ok_or("script.type_unsupported")?;
            if !(5..=6).contains(&at) {
                return Err("script.type_unsupported");
            }
            let expression = words[..at].join(" ");
            let start = text.find(words[at]).unwrap_or(0);
            (
                LoonScheduledTrigger::Cron(expression),
                String::new(),
                url_first_attributes(&text[start..]),
            )
        };
        let value = |key: &str| {
            attributes
                .iter()
                .find(|(name, _)| name == key)
                .map(|(_, value)| value.clone())
        };
        if value("enabled")
            .or_else(|| value("enable"))
            .is_some_and(|enabled| switch_is_off(&self.resolve_arguments(&enabled)))
        {
            return Ok(None);
        }
        if let LoonScheduledTrigger::Cron(expression) = &trigger {
            if CronSchedule::parse(expression).is_none() {
                return Err("script.cron_invalid");
            }
        }
        let script_url = value("script-path")
            .or_else(|| value("script_path"))
            .or_else(|| value("url"))
            .filter(|url| !url.is_empty())
            .ok_or("script.path_missing")?;
        let tag = value("tag").filter(|tag| !tag.is_empty()).unwrap_or(name);
        let tag = if tag.is_empty() {
            script_url
                .rsplit('/')
                .next()
                .unwrap_or("script")
                .trim_end_matches(".js")
                .to_string()
        } else {
            tag
        };
        let timeout_secs = value("timeout")
            .and_then(|timeout| timeout.parse::<u32>().ok())
            .filter(|timeout| *timeout > 0)
            .unwrap_or(60);
        Ok(Some(LoonScheduledScript {
            trigger,
            script_url,
            tag,
            argument: self.resolve_arguments(&value("argument").unwrap_or_default()),
            timeout_secs,
            line: 0,
        }))
    }

    /// Loon argument templates: `[{a},{b}]` becomes `a=x&b=y`; `{a}` and
    /// `{{{a}}}` elsewhere become the declared default. A name the plugin
    /// does not declare stays as written, so JSON and other text with braces
    /// passes through unchanged, and a bracketed value is a list only when
    /// every item in it is a `{name}`.
    fn resolve_arguments(&self, template: &str) -> String {
        let declared = |name: &str| {
            self.metadata
                .arguments
                .iter()
                .find(|(declared, _)| declared == name.trim())
                .map(|(_, value)| value.clone())
        };
        let trimmed = template.trim();
        if let Some(items) = trimmed
            .strip_prefix('[')
            .and_then(|rest| rest.strip_suffix(']'))
        {
            let names = items
                .split(',')
                .map(|item| {
                    item.trim()
                        .strip_prefix('{')
                        .and_then(|item| item.strip_suffix('}'))
                        .map(str::trim)
                        .filter(|name| !name.is_empty() && !name.contains(['{', '}']))
                })
                .collect::<Option<Vec<_>>>();
            if let Some(names) = names {
                return names
                    .iter()
                    .map(|name| format!("{name}={}", declared(name).unwrap_or_default()))
                    .collect::<Vec<_>>()
                    .join("&");
            }
        }
        let mut out = String::new();
        let mut rest = template;
        while let Some(start) = rest.find('{') {
            out.push_str(&rest[..start]);
            let (open, close) = if rest[start..].starts_with("{{{") {
                ("{{{", "}}}")
            } else {
                ("{", "}")
            };
            let inner = &rest[start + open.len()..];
            match inner.find(close) {
                Some(end) => {
                    match declared(&inner[..end]) {
                        Some(value) => out.push_str(&value),
                        None => out.push_str(&rest[start..start + open.len() + end + close.len()]),
                    }
                    rest = &inner[end + close.len()..];
                }
                None => {
                    out.push_str(&rest[start..]);
                    rest = "";
                }
            }
        }
        out.push_str(rest);
        out
    }

    /// An HTTP script line with `enable=` (or `enabled=`) and `argument=`
    /// resolved against the plugin's arguments, and whether the script runs.
    ///
    /// The core reads `enable` as a plain boolean, so `enable={Switch}`
    /// would always turn the script off; it is resolved here and written as
    /// `true` unless it is off (`false`, `0`, `no`, `off`), when the line
    /// leaves the core. `argument` is resolved and then encoded
    /// ([`encode_core_argument`]) so the core hands it to the script as is.
    /// The third value is true when the written `argument=` segment is longer
    /// than the core reads ([`CORE_ATTRIBUTE_SEGMENT_CAP`]).
    fn resolve_script_line(&self, text: &str) -> (String, ScriptSwitch, bool) {
        let mut line = text.to_string();
        let mut switch = ScriptSwitch::On;
        for key in ["enable", "enabled"] {
            // Like the core, an empty `enable=` falls through to `enabled=`.
            let span = core_attribute_span(&line, key);
            let Some(span) = span.filter(|span| !span.is_empty()) else {
                continue;
            };
            let value = unquote_core_value(&line[span.clone()]);
            let resolved = self.resolve_arguments(&value);
            switch = if switch_is_off(&resolved) {
                ScriptSwitch::Off
            } else if resolved.contains('{') {
                ScriptSwitch::Unresolved
            } else {
                ScriptSwitch::On
            };
            if switch != ScriptSwitch::Off && !switch_is_on(&value) {
                line.replace_range(span, "true");
            }
            break;
        }
        if let Some(span) = core_attribute_span(&line, "argument") {
            let value = unquote_core_value(&line[span.clone()]);
            let encoded = encode_core_argument(&self.resolve_arguments(&value));
            if encoded != value {
                line.replace_range(span, &quote_core_attribute(&encoded));
            }
        }
        let argument_too_long = core_attribute_segment(&line, "argument")
            .is_some_and(|(segment, _)| segment.len() >= CORE_ATTRIBUTE_SEGMENT_CAP);
        (line, switch, argument_too_long)
    }

    /// Loads the plugin into the policy core and downgrades lines it owns but
    /// did not accept.
    ///
    /// The core stops at the first line it cannot parse. Plugins in the wild
    /// carry such lines (an odd host pattern, a regex only one engine reads, a
    /// cron task), so instead of losing the whole plugin the refused line is
    /// commented out of `source`, reported as unsupported, and the load is
    /// retried. Returns the load error only when the core still refuses the
    /// text and no single line can be blamed.
    fn cross_check_with_policy_core(
        &mut self,
        source: &mut String,
        line_origins: &[usize],
    ) -> Option<String> {
        let mut engine = match AnixOpsMitmPolicyEngine::new() {
            Ok(engine) => engine,
            Err(error) => return Some(error.message),
        };
        let mut disabled = BTreeSet::new();
        let report = loop {
            let error = match engine.load_config(source) {
                Ok(report) => break report,
                Err(error) => error,
            };
            let core_line = engine.last_error_line();
            let lines: Vec<&str> = source.split('\n').collect();
            let blamed = core_line
                .checked_sub(1)
                .filter(|index| {
                    disabled.len() < MAX_REFUSED_LINES
                        && !disabled.contains(index)
                        && lines
                            .get(*index)
                            .is_some_and(|line| !line.trim_start().starts_with('['))
                })
                .and_then(|index| line_origins.get(index).map(|origin| (index, *origin)));
            let Some((index, origin)) = blamed else {
                return Some(error.message);
            };
            let rebuilt = lines
                .iter()
                .enumerate()
                .map(|(at, line)| {
                    if at == index {
                        format!("# {line}")
                    } else {
                        (*line).to_string()
                    }
                })
                .collect::<Vec<_>>()
                .join("\n");
            *source = rebuilt;
            disabled.insert(index);
            self.refuse_line(origin, refused_line_reason(&error.message));
        };
        for diagnostic in &report.rule_diagnostics {
            if diagnostic.status == MitmPolicyRuleDiagnosticStatus::Accepted {
                continue;
            }
            let Some(origin) = diagnostic
                .line
                .checked_sub(1)
                .and_then(|index| line_origins.get(index))
            else {
                continue;
            };
            for line in self.lines.iter_mut().filter(|line| line.line == *origin) {
                let owned_by_core = matches!(
                    line.handler,
                    LoonLineHandler::PolicyEngine | LoonLineHandler::ScriptRuntime
                );
                if owned_by_core && line.status != LoonLineStatus::Deferred {
                    line.status = LoonLineStatus::Unsupported;
                    line.handler = LoonLineHandler::None;
                    line.reason = match diagnostic.status {
                        MitmPolicyRuleDiagnosticStatus::Rejected => "policy_core.rejected",
                        _ => "policy_core.ignored",
                    }
                    .to_string();
                }
            }
        }
        None
    }

    /// Marks the plugin line the policy core refused as unsupported. A line
    /// the importer had already graded unsupported keeps its own reason.
    fn refuse_line(&mut self, origin: usize, reason: &str) {
        let mut found = false;
        for line in self.lines.iter_mut().filter(|line| line.line == origin) {
            found = true;
            if line.status != LoonLineStatus::Unsupported {
                line.status = LoonLineStatus::Unsupported;
                line.handler = LoonLineHandler::None;
                line.reason = reason.to_string();
            }
        }
        if !found {
            self.push(
                origin,
                "policy_core",
                LoonLineStatus::Unsupported,
                LoonLineHandler::None,
                reason,
            );
        }
    }
}

/// Whether the policy core reads a `[MITM] hostname` item: `*`, a host with
/// a leading `*.`, or a glob with `*` (any run, dots included) and `?` (one
/// character) inside labels, such as `*spclient.spotify.com` or `*.flyert.*`.
/// Mirrors the `mitm_anixops` core (v1.4.8 and later): a plain host needs
/// valid labels, and a glob must stay a host name and name at least one
/// literal character.
/// True for a hostname list item that no host name can match: it holds
/// whitespace or other characters a host name cannot have, or (without
/// wildcards) a label that is empty or starts or ends with `-`.
fn host_item_never_matches(item: &str) -> bool {
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

fn core_host_pattern(item: &str) -> bool {
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
const MAX_REFUSED_LINES: usize = 256;

/// Stable report reason for a line the policy core refused, from its message.
fn refused_line_reason(message: &str) -> &'static str {
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
fn is_quantumult_rewrite(line: &str) -> bool {
    tokens(line)
        .get(1)
        .is_some_and(|token| token.eq_ignore_ascii_case("url"))
}

fn is_hostname_line(line: &str) -> bool {
    line.split_once('=')
        .is_some_and(|(key, _)| key.trim().eq_ignore_ascii_case("hostname"))
}

/// Defaults of a Surge `#!arguments=name:value,...` line. A value may be
/// quoted to hold commas.
fn parse_module_arguments(value: &str) -> Vec<(String, String)> {
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
fn module_argument_defaults(text: &str) -> BTreeMap<String, String> {
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
fn substitute_module_arguments(line: &str, arguments: &BTreeMap<String, String>) -> String {
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
fn jq_rewrite(parts: &[String]) -> Option<(String, bool)> {
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
fn json_edit_filter(edit: &str, arguments: &[String]) -> Option<String> {
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
fn json_path(path: &str) -> Option<String> {
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
fn json_literal(value: &str) -> String {
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

fn json_string(text: &str) -> String {
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
fn url_first_attributes(text: &str) -> Vec<(String, String)> {
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
fn surge_pattern_for_core(line: &str) -> Option<String> {
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
const MAX_CORE_PATTERN_LEN: usize = 480;

/// A line whose pattern is too long for the core, as several lines with the
/// same meaning: the pattern's top-level alternation (`^https?://(a|b|...)/`
/// or `a|b|...`) is spread over the copies. `None` when the line needs no
/// split or its pattern has no alternation that can be split safely.
fn split_long_pattern_line(line: &str) -> Option<Vec<String>> {
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
fn header_block_regex_accepted(rule: &LoonHeaderBlockRule) -> bool {
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
fn loon_conditional_script(text: &str) -> Option<String> {
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
enum ScriptSwitch {
    On,
    Off,
    /// `enable` names an argument the plugin does not declare; the script
    /// runs.
    Unresolved,
}

/// `false`, `0`, `no` or `off`: the plugin turns the script off.
fn switch_is_off(value: &str) -> bool {
    let value = value.trim();
    ["false", "0", "no", "off"]
        .iter()
        .any(|off| value.eq_ignore_ascii_case(off))
}

/// A value the core itself reads as on.
fn switch_is_on(value: &str) -> bool {
    let value = value.trim();
    value == "1"
        || ["true", "yes", "on"]
            .iter()
            .any(|on| value.eq_ignore_ascii_case(on))
}

/// The default of an `[Argument]` line's `kind,default,...` spec. A quoted
/// default may hold commas, as the core reads it.
fn argument_default(spec: &str) -> String {
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
const CORE_ATTRIBUTE_SEGMENT_CAP: usize = 4096;

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
fn core_attribute_span(line: &str, key: &str) -> Option<std::ops::Range<usize>> {
    core_attribute_segment(line, key).map(|(_, value)| value)
}

/// The segment ([`core_attribute_span`]) that holds attribute `key`, and the
/// range of its value.
fn core_attribute_segment(
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
fn core_segment_value(
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
fn core_trim(bytes: &[u8], range: std::ops::Range<usize>) -> std::ops::Range<usize> {
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
fn is_core_space(byte: u8) -> bool {
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
fn core_script_attributes_start(bytes: &[u8]) -> Option<usize> {
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
fn is_core_script_kind(token: &[u8]) -> bool {
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
fn core_next_token(bytes: &[u8], cursor: &mut usize) -> Option<Vec<u8>> {
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
fn unquote_core_value(raw: &str) -> String {
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
fn quote_core_attribute(value: &str) -> String {
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
fn quote_attribute(value: &str) -> String {
    if value.is_empty() || value.contains([' ', ',', '"', '\'', '\t']) {
        format!("\"{}\"", value.replace('\\', "\\\\").replace('"', "\\\""))
    } else {
        value.to_string()
    }
}

fn is_reject_policy(target: &str) -> bool {
    let target = target.to_ascii_uppercase();
    target == "REJECT" || target.starts_with("REJECT-")
}

/// Returns the status, reason, and whether the action applies to responses.
fn classify_rewrite_action(action: &str) -> (LoonLineStatus, &'static str, bool) {
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

fn grade(lines: &[LoonLineReport], refused: bool) -> LoonSupportLevel {
    if refused {
        return LoonSupportLevel::Unsupported;
    }
    let effective = lines
        .iter()
        .filter(|line| line.status != LoonLineStatus::Ignored)
        .collect::<Vec<_>>();
    let supported = effective
        .iter()
        .filter(|line| line.status == LoonLineStatus::Supported)
        .count();
    if supported == 0 {
        LoonSupportLevel::Unsupported
    } else if supported == effective.len() {
        LoonSupportLevel::Full
    } else {
        LoonSupportLevel::Partial
    }
}
