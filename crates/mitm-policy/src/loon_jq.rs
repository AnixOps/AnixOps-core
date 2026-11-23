//! jq body rewrites (`http-response-jq`, `response-body-jq`, Quantumult X
//! `jsonjq-response-body`, ...) run with jaq, a jq implementation in Rust.
//!
//! The `mitm_anixops` core is built without libjq. It still parses the
//! importer's `<url> response-body-jq <filter>` lines, matches them in the
//! body chain and leaves the body alone with the message
//! [`JQ_BACKEND_UNAVAILABLE`]. Those steps run here afterwards, in chain
//! order, on the body the core produced. The filter is read back from the
//! loaded source because the core's result value is capped at 2 KiB.

use crate::loon_syntax::tokens;
use crate::policy_cache::{PolicyCache, POLICY_REVISIONS};
use crate::{MitmPolicyBodyRewriteChain, MitmPolicyPhase};
use jaq_core::load::{Arena, File, Loader};
use jaq_core::{data, unwrap_valr, Compiler, Ctx, Vars};
use jaq_json::{read, Val};
use std::cell::Cell;
use std::collections::BTreeMap;
use std::sync::OnceLock;

/// Message of a jq step the core matched but could not run.
pub const JQ_BACKEND_UNAVAILABLE: &str = "jq backend unavailable";

/// Bodies larger than this are left alone.
pub const JQ_MAX_INPUT_BYTES: usize = 8 * 1024 * 1024;

/// Runs `filter` on the JSON `body` and returns the first output as compact
/// JSON. `None` when the body is not JSON, the filter does not compile, or it
/// fails or yields nothing; the body is then left unchanged, as jq-capable
/// clients do.
///
/// The filter is compiled for this call. Rules of a loaded policy go through
/// [`apply_jq_steps`], which compiles each filter once per policy revision.
pub fn run_jq(filter: &str, body: &str) -> Option<String> {
    let input = parse_body(body)?;
    run_compiled(&compile_jq(filter)?, input)
}

/// A compiled jq program. It owns its terms and native function pointers,
/// so it is `Send + Sync` and one copy serves every thread.
type JqFilter = jaq_core::Filter<data::JustLut<Val>>;

thread_local! {
    static JQ_COMPILATIONS: Cell<u64> = const { Cell::new(0) };
}

/// How many jq filters this thread has compiled; tests use it to check that
/// a rule's filter is compiled once per policy revision, not once per
/// message.
#[doc(hidden)]
pub fn jq_compilations_on_this_thread() -> u64 {
    JQ_COMPILATIONS.with(Cell::get)
}

/// The JSON value of `body`, or `None` when it is too large or not JSON.
fn parse_body(body: &str) -> Option<Val> {
    if body.len() > JQ_MAX_INPUT_BYTES {
        return None;
    }
    read::parse_single(body.trim().as_bytes()).ok()
}

/// Loads jaq's core, std and JSON definitions with `filter` and compiles
/// them. `None` when the filter does not compile.
fn compile_jq(filter: &str) -> Option<JqFilter> {
    JQ_COMPILATIONS.with(|count| count.set(count.get() + 1));
    let defs = jaq_core::defs()
        .chain(jaq_std::defs())
        .chain(jaq_json::defs());
    let funs = jaq_core::funs()
        .chain(jaq_std::funs())
        .chain(jaq_json::funs());
    let loader = Loader::new(defs);
    let arena = Arena::default();
    let modules = loader
        .load(
            &arena,
            File {
                code: filter,
                path: (),
            },
        )
        .ok()?;
    let compiled: JqFilter = Compiler::default().with_funs(funs).compile(modules).ok()?;
    Some(compiled)
}

/// Runs a compiled filter on `input` and returns its first output as compact
/// JSON.
fn run_compiled(compiled: &JqFilter, input: Val) -> Option<String> {
    let ctx = Ctx::<data::JustLut<Val>>::new(&compiled.lut, Vars::new([]));
    let mut outputs = compiled.id.run((ctx, input)).map(unwrap_valr);
    let first = outputs.next()?.ok()?;
    Some(first.to_string())
}

/// One `<pattern> request-body-jq|response-body-jq <filter>` line of a
/// loaded policy. Its filter is compiled the first time a message matches
/// it, and the compiled form lives as long as the policy revision.
struct JqRule {
    pattern: String,
    phase: MitmPolicyPhase,
    filter: String,
    /// `Some(None)` records a filter that does not compile, so it is not
    /// compiled again for every message.
    compiled: OnceLock<Option<JqFilter>>,
}

impl JqRule {
    fn compiled(&self) -> Option<&JqFilter> {
        self.compiled
            .get_or_init(|| compile_jq(&self.filter))
            .as_ref()
    }
}

/// The jq rules of a loaded policy source, in order.
fn jq_rules(source: &str) -> Vec<JqRule> {
    source
        .lines()
        .filter_map(|line| {
            let line = line.trim();
            if line.is_empty() || line.starts_with(['#', ';', '[']) {
                return None;
            }
            let parts = tokens(line);
            if parts.len() < 3 {
                return None;
            }
            let phase = match parts[1].to_ascii_lowercase().as_str() {
                "request-body-jq" => MitmPolicyPhase::Request,
                "response-body-jq" => MitmPolicyPhase::Response,
                _ => return None,
            };
            Some(JqRule {
                pattern: parts[0].clone(),
                phase,
                filter: parts[2].clone(),
                compiled: OnceLock::new(),
            })
        })
        .collect()
}

/// jq rules and their compiled filters, per policy in use; released with
/// the policy ([`crate::CompiledPolicyRelease`]).
static JQ_RULES: PolicyCache<Vec<JqRule>> = PolicyCache::new(POLICY_REVISIONS);

/// Drops the jq rules and compiled filters of a policy no longer in use.
pub(crate) fn release(policy: crate::PolicyFingerprint) {
    JQ_RULES.remove(policy);
}

/// Runs the jq steps of `chain` on `body`. `None` when no jq step changed it.
pub fn apply_jq_steps(
    source: &str,
    phase: MitmPolicyPhase,
    chain: &MitmPolicyBodyRewriteChain,
    body: &str,
) -> Option<String> {
    let steps = chain
        .rewrites
        .iter()
        .filter(|step| step.message == JQ_BACKEND_UNAVAILABLE)
        .collect::<Vec<_>>();
    if steps.is_empty() {
        return None;
    }
    // Read once per policy revision, not once per message; each rule's
    // filter is compiled on its first match and kept with the revision.
    let rules = JQ_RULES
        .get_or_build(source, |source| Ok(jq_rules(source)))
        .ok()?;
    let mut seen: BTreeMap<&str, usize> = BTreeMap::new();
    let mut current = body.to_string();
    let mut changed = false;
    for step in steps {
        let nth = seen.entry(step.matched_pattern.as_str()).or_default();
        let rule = rules
            .iter()
            .filter(|rule| rule.pattern == step.matched_pattern && rule.phase == phase)
            .nth(*nth);
        *nth += 1;
        let Some(input) = parse_body(&current) else {
            continue;
        };
        // A step the source does not list (the core's value is capped at
        // 2 KiB) is compiled for this message only.
        let output = match rule {
            Some(rule) => rule
                .compiled()
                .and_then(|compiled| run_compiled(compiled, input)),
            None => compile_jq(&step.value).and_then(|compiled| run_compiled(&compiled, input)),
        };
        if let Some(output) = output {
            changed |= output != current;
            current = output;
        }
    }
    changed.then_some(current)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filters_used_by_published_plugins_run() {
        assert_eq!(
            run_jq("del(.data.payment)", r#"{"data":{"payment":1,"a":2}}"#).as_deref(),
            Some(r#"{"data":{"a":2}}"#)
        );
        assert_eq!(
            run_jq(
                r#".data.modules |= map(select(.type != "TIP"))"#,
                r#"{"data":{"modules":[{"type":"TIP"},{"type":"A"}]}}"#
            )
            .as_deref(),
            Some(r#"{"data":{"modules":[{"type":"A"}]}}"#)
        );
        assert_eq!(
            run_jq(r#"delpaths([["a","b"]])"#, r#"{"a":{"b":1,"c":2}}"#).as_deref(),
            Some(r#"{"a":{"c":2}}"#)
        );
        assert_eq!(
            run_jq(
                r#".data[][]?="stun.example.com:3478""#,
                r#"{"data":{"x":["a","b"]}}"#
            )
            .as_deref(),
            Some(r#"{"data":{"x":["stun.example.com:3478","stun.example.com:3478"]}}"#)
        );
        assert_eq!(
            run_jq(
                r#"if .vip then .vip.status = 1 else . end | .x |= (. // 0)"#,
                r#"{"vip":{"status":0}}"#
            )
            .as_deref(),
            Some(r#"{"vip":{"status":1},"x":0}"#)
        );
        assert_eq!(run_jq(".a", "not json"), None);
        assert_eq!(run_jq("syntax error (", "{}"), None);
    }

    #[test]
    fn a_rule_filter_is_compiled_once_per_policy_revision() {
        // Unit tests run on their own threads, so the counter is this
        // test's alone; the source is unique to this test.
        let source = concat!(
            "# a_rule_filter_is_compiled_once_per_policy_revision\n",
            "^https://a\\.example\\.test/jq response-body-jq 'del(.b)'\n",
            "^https://a\\.example\\.test/bad response-body-jq 'syntax error ('\n",
        );
        let chain = |pattern: &str| MitmPolicyBodyRewriteChain {
            rewrites: vec![crate::MitmPolicyRewriteResult {
                action: crate::MitmPolicyRewriteAction::BodyMutation,
                status_code: 0,
                rule_index: 0,
                matched_pattern: pattern.to_string(),
                value: String::new(),
                message: JQ_BACKEND_UNAVAILABLE.to_string(),
                reject_body: crate::MitmPolicyRejectBody::Empty,
            }],
            rewritten: false,
            truncated: false,
        };
        let good = chain("^https://a\\.example\\.test/jq");
        let bad = chain("^https://a\\.example\\.test/bad");
        let before = jq_compilations_on_this_thread();
        for index in 0..20 {
            let body = format!(r#"{{"a":{index},"b":1}}"#);
            assert_eq!(
                apply_jq_steps(source, MitmPolicyPhase::Response, &good, &body),
                Some(format!(r#"{{"a":{index}}}"#))
            );
            assert_eq!(
                apply_jq_steps(source, MitmPolicyPhase::Response, &bad, &body),
                None
            );
        }
        assert_eq!(
            jq_compilations_on_this_thread() - before,
            2,
            "one compile for the filter and one for the broken filter"
        );
        // A body that is not JSON leaves the body alone without compiling.
        assert_eq!(
            apply_jq_steps(source, MitmPolicyPhase::Response, &good, "not json"),
            None
        );
        assert_eq!(jq_compilations_on_this_thread() - before, 2);

        // Released with its policy: the next message compiles again.
        release(crate::PolicyFingerprint::of(source));
        assert_eq!(
            apply_jq_steps(source, MitmPolicyPhase::Response, &good, r#"{"a":1,"b":2}"#),
            Some(r#"{"a":1}"#.to_string())
        );
        assert_eq!(jq_compilations_on_this_thread() - before, 3);
    }
}
