//! Rule scripts: `SCRIPT,<name>,<policy>` rules decided by a JavaScript
//! function, as Surge rule scripts (feature `scripts`, QuickJS).
//!
//! The routing section names each script (`routing.scripts`): a local file
//! the client saved, an optional `argument` and a `timeout_secs`. Files are
//! read once when the engine starts. Routing stops at a `SCRIPT` rule it
//! has no verdict for ([`config_core::routing::RouteMatch::ScriptPending`]),
//! runs the script here off the runtime threads and decides again, so the
//! rules before it still decide without running any script.
//!
//! A script sees the connection as `$request` (`hostname`, `destIP`,
//! `destPort`, `sourceIP`, `inPort`, `processName`, `protocol`,
//! `userAgent`, `url`; `null` when unknown) and matches only with
//! `$done({matched: true})`. A script that throws, times out, waits longer
//! than its timeout for a free slot, or never calls `$done` does not match.
//! Rule scripts get no network (`$httpClient` fails) and a
//! `$persistentStore` that lives in memory for the engine's lifetime. At
//! most [`MAX_RUNNING`] run at once, each within [`MEMORY_LIMIT_BYTES`].
//!
//! Decisions made without a connection (DNS server routing, status
//! queries) treat every `SCRIPT` rule as no match.

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use config_core::routing::RouteQuery;

/// Scripts one routing section may name.
pub const MAX_RULE_SCRIPTS: usize = 32;
/// Largest script file.
pub const MAX_SCRIPT_BYTES: usize = 1024 * 1024;
/// Timeout when the section gives none.
pub const DEFAULT_TIMEOUT_SECS: u32 = 1;
/// Longest timeout a script may ask for.
pub const MAX_TIMEOUT_SECS: u32 = 3;
/// Rule scripts running at once, process-wide per engine.
pub const MAX_RUNNING: usize = 2;
/// QuickJS heap limit of one run.
pub const MEMORY_LIMIT_BYTES: usize = 4 * 1024 * 1024;

/// One configured rule script.
#[derive(Clone, Debug)]
pub struct RuleScript {
    pub source: Arc<str>,
    pub argument: String,
    pub timeout: Duration,
}

/// The rule scripts of a routing section, by name.
pub struct RuleScripts {
    scripts: BTreeMap<String, RuleScript>,
    running: Arc<tokio::sync::Semaphore>,
    #[cfg(feature = "scripts")]
    runtime: script_runtime::QuickJsScriptRuntime,
}

impl Default for RuleScripts {
    fn default() -> Self {
        Self::new(BTreeMap::new())
    }
}

impl std::fmt::Debug for RuleScripts {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RuleScripts")
            .field("scripts", &self.scripts.keys().collect::<Vec<_>>())
            .finish_non_exhaustive()
    }
}

impl RuleScripts {
    pub fn new(scripts: BTreeMap<String, RuleScript>) -> Self {
        Self {
            scripts,
            running: Arc::new(tokio::sync::Semaphore::new(MAX_RUNNING)),
            #[cfg(feature = "scripts")]
            runtime: script_runtime::QuickJsScriptRuntime::new(
                Arc::new(script_runtime::MemoryScriptStore::new()),
                Arc::new(script_runtime::DisabledScriptHttpClient),
            ),
        }
    }

    pub fn contains(&self, name: &str) -> bool {
        self.scripts.contains_key(name)
    }

    pub fn is_empty(&self) -> bool {
        self.scripts.is_empty()
    }

    /// Runs script `name` on the connection `query` (with `resolved`, the
    /// address resolved for an earlier IP rule) and returns whether it
    /// matched. An unknown name never matches.
    pub async fn matches(&self, name: &str, query: &RouteQuery, resolved: Option<IpAddr>) -> bool {
        let Some(script) = self.scripts.get(name) else {
            return false;
        };
        let Ok(Ok(permit)) =
            tokio::time::timeout(script.timeout, self.running.clone().acquire_owned()).await
        else {
            return false;
        };
        self.run(name, script, query, resolved, permit).await
    }

    #[cfg(feature = "scripts")]
    async fn run(
        &self,
        name: &str,
        script: &RuleScript,
        query: &RouteQuery,
        resolved: Option<IpAddr>,
        permit: tokio::sync::OwnedSemaphorePermit,
    ) -> bool {
        use script_runtime::{
            ScriptInvocation, ScriptLimits, ScriptPhase, ScriptRuleRequest, ScriptRunStatus,
        };

        let mut invocation =
            ScriptInvocation::scheduled(ScriptPhase::Rule, name, script.argument.clone(), None);
        invocation.rule = Some(ScriptRuleRequest {
            hostname: query
                .domain
                .as_deref()
                .map(|domain| domain.trim_end_matches('.').to_ascii_lowercase()),
            dest_ip: query.ip.or(resolved),
            dest_port: query.port,
            source_ip: query.source,
            in_port: query.in_port,
            process_name: query.process.clone(),
            protocol: query.network.map(|network| match network {
                config_core::routing::RouteNetwork::Tcp => "TCP".to_string(),
                config_core::routing::RouteNetwork::Udp => "UDP".to_string(),
            }),
            user_agent: query.user_agent.clone(),
            url: query.url.clone(),
        });
        let limits = ScriptLimits {
            timeout: script.timeout,
            memory_limit_bytes: MEMORY_LIMIT_BYTES,
            ..ScriptLimits::default()
        };
        let runtime = self.runtime.clone();
        let source = script.source.clone();
        let outcome = tokio::task::spawn_blocking(move || {
            let _permit = permit;
            runtime.run(&source, &invocation, &limits)
        })
        .await;
        matches!(
            outcome,
            Ok(outcome) if outcome.status == ScriptRunStatus::Done
                && outcome.mutation.matched == Some(true)
        )
    }

    #[cfg(not(feature = "scripts"))]
    async fn run(
        &self,
        _name: &str,
        _script: &RuleScript,
        _query: &RouteQuery,
        _resolved: Option<IpAddr>,
        _permit: tokio::sync::OwnedSemaphorePermit,
    ) -> bool {
        false
    }
}
