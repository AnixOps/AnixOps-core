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

mod core_translation;
mod parser;

pub use core_translation::*;
pub use parser::*;

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
        final_dns_continue: model.final_dns_continue,
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
