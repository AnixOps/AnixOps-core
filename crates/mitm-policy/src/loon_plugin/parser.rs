//! The line parser: walks the plugin section by section and grades each
//! line.

use super::*;

#[derive(Default)]
pub(crate) struct Parser<'a> {
    /// Downloaded remote files by URL.
    pub(crate) resources: Option<&'a BTreeMap<String, Vec<u8>>>,
    pub(crate) remote_resources: Vec<LoonRemoteResource>,
    pub(crate) metadata: LoonPluginMetadata,
    pub(crate) mitm_hostnames: LoonMitmHostnames,
    pub(crate) rules: Vec<LoonPluginRule>,
    pub(crate) lines: Vec<LoonLineReport>,
    pub(crate) has_request_actions: bool,
    pub(crate) has_response_actions: bool,
    /// Replacement text for original lines, by 1-based line number.
    pub(crate) replaced: BTreeMap<usize, String>,
    /// Lines appended after the plugin: section, line, original line number.
    pub(crate) appended: Vec<(&'static str, String, usize)>,
    pub(crate) scheduled: Vec<LoonScheduledScript>,
    /// Every argument was declared up front by [`Parser::declare_arguments`],
    /// so the lines that declare one are only graded.
    pub(crate) arguments_declared: bool,
}

impl Parser<'_> {
    pub(crate) fn remote_resource(&mut self, line: usize, url: &str, kind: LoonRemoteResourceKind) {
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

    pub(crate) fn push(
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

    pub(crate) fn metadata_line(&mut self, line: usize, section: &str, meta: &str) {
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

    pub(crate) fn add_argument(&mut self, name: &str, default: &str) {
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
    pub(crate) fn declare_arguments(&mut self, text: &str) {
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

    pub(crate) fn argument_line(&mut self, line: usize, section: &str, text: &str) {
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
    pub(crate) fn general_line(&mut self, line: usize, section: &str, text: &str) {
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

    pub(crate) fn mitm_line(&mut self, line: usize, section: &str, text: &str) {
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

    pub(crate) fn rule_line(&mut self, line: usize, section: &str, text: &str) {
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

    pub(crate) fn url_regex_rule_line(&mut self, line: usize, section: &str, text: &str) {
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
    pub(crate) fn routing_rule_line(&mut self, line: usize, section: &str, text: &str) {
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
    pub(crate) fn rewrite_line(&mut self, line: usize, section: &str, text: &str, preamble: bool) {
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

    pub(crate) fn grade_rewrite(&mut self, line: usize, section: &str, action: &str) {
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
    pub(crate) fn emit_core_line(
        &mut self,
        line: usize,
        text: &str,
        rule: Option<String>,
        preamble: bool,
    ) {
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
    pub(crate) fn quantumult_rewrite_line(
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
    pub(crate) fn mock_response_body_line(&mut self, line: usize, section: &str, text: &str) {
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
    pub(crate) fn map_local_line(
        &mut self,
        line: usize,
        section: &str,
        text: &str,
    ) -> Option<String> {
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
    pub(crate) fn body_rewrite_line(&mut self, line: usize, section: &str, text: &str) {
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
    pub(crate) fn translated_source(&self, text: &str) -> (String, Vec<usize>) {
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
    pub(crate) fn script_line(&mut self, line: usize, section: &str, text: &str) {
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
    pub(crate) fn scheduled_script_line(&mut self, line: usize, section: &str, text: &str) {
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
    pub(crate) fn scheduled_script(
        &self,
        text: &str,
    ) -> Result<Option<LoonScheduledScript>, &'static str> {
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
    pub(crate) fn resolve_arguments(&self, template: &str) -> String {
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
    pub(crate) fn resolve_script_line(&self, text: &str) -> (String, ScriptSwitch, bool) {
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
    pub(crate) fn cross_check_with_policy_core(
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
    pub(crate) fn refuse_line(&mut self, origin: usize, reason: &str) {
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
