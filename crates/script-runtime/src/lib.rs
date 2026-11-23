//! Loon-compatible HTTP script runtime for the M3 P1 plugin tier.
//!
//! The `$`-API (`$request`, `$response`, `$argument`, `$done`,
//! `$persistentStore`, `$notification`, `$httpClient`, `console`, timers) is
//! implemented once in Rust by [`ScriptHost`]. A JavaScript engine binding only
//! exposes one host function, evaluates the shared [`SCRIPT_PRELUDE`] and the
//! user script, and drains its job queue ([`JsEngineContext`]); the event loop
//! in [`run_script`] and the result mapping in [`finish_outcome`] are shared.
//!
//! QuickJS (quickjs-ng through rquickjs) is the desktop binding. The Apple
//! JavaScriptCore binding ([`JscScriptRuntime`], feature `javascriptcore`,
//! Apple targets only) implements the same trait and passes the same
//! conformance fixtures in `tests/fixtures/conformance`, except the heap limit
//! that JavaScriptCore's public API cannot enforce.
//!
//! Scripts never get file system, process, or network access of their own.
//! Everything they can reach goes through the host: the persistent store is
//! size-capped, notifications and logs are collected, and `$httpClient` calls
//! go to a [`ScriptHttpClient`] that is disabled unless the caller provides one.

mod driver;
mod host;
#[cfg(all(feature = "javascriptcore", target_vendor = "apple"))]
mod jsc;
#[cfg(feature = "quickjs")]
mod quickjs;
mod store;

pub use driver::{finish_outcome, run_script, JsEngineContext, JsEngineError};
pub use host::{ScriptHost, SCRIPT_HOST_FUNCTION, SCRIPT_PRELUDE};
#[cfg(all(feature = "javascriptcore", target_vendor = "apple"))]
pub use jsc::{JscScriptRuntime, MAX_STUCK_WORKERS};
#[cfg(feature = "quickjs")]
pub use quickjs::QuickJsScriptRuntime;
pub use store::{
    open_script_store, JsonFileScriptStore, MemoryScriptStore, ScriptStore, ScriptStoreRecovery,
    SCRIPT_STORE_MAX_KEY_BYTES, SCRIPT_STORE_MAX_TOTAL_BYTES, SCRIPT_STORE_MAX_VALUE_BYTES,
    SCRIPT_STORE_QUARANTINE_SUFFIX,
};

use std::time::Duration;

/// Environment string scripts see as `$loon`.
pub const SCRIPT_ENVIRONMENT: &str = concat!("NetworkCore/", env!("CARGO_PKG_VERSION"));

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScriptPhase {
    Request,
    Response,
    /// Scheduled script (Loon/Surge `cron`, Quantumult X `[task_local]`).
    /// No `$request` or `$response`; `$done` takes no changes.
    Cron,
    /// Event script; the event name is in [`ScriptInvocation::event`].
    Event,
    /// Script the user runs by hand (Loon/Surge `generic`).
    Generic,
    /// Surge rule script (`SCRIPT,<name>,<policy>`): `$request` describes
    /// the connection ([`ScriptInvocation::rule`]) and the script answers
    /// with `$done({matched: true})`.
    Rule,
}

impl ScriptPhase {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Request => "request",
            Self::Response => "response",
            Self::Cron => "cron",
            Self::Event => "event",
            Self::Generic => "generic",
            Self::Rule => "rule",
        }
    }

    /// Whether the script runs on an HTTP message.
    pub fn is_http(self) -> bool {
        matches!(self, Self::Request | Self::Response)
    }
}

/// Request visible to a script as `$request`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ScriptRequest {
    pub url: String,
    pub method: String,
    pub headers: Vec<(String, String)>,
    /// UTF-8 body; `None` when the script does not receive the body.
    pub body: Option<String>,
}

/// Response visible to a script as `$response`, or produced by a script.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ScriptResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Option<String>,
}

/// The connection a rule script decides on, visible as `$request`:
/// `hostname`, `destIP`, `destPort`, `sourceIP`, `inPort`, `processName`,
/// `protocol`, `userAgent` and `url`, each `null` when unknown.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ScriptRuleRequest {
    /// Destination domain, lower case.
    pub hostname: Option<String>,
    /// Destination address: the connection's, or the one resolved for an
    /// earlier IP rule.
    pub dest_ip: Option<std::net::IpAddr>,
    pub dest_port: Option<u16>,
    pub source_ip: Option<std::net::IpAddr>,
    /// Port of the local listener the connection came in on.
    pub in_port: Option<u16>,
    pub process_name: Option<String>,
    /// `TCP` or `UDP`.
    pub protocol: Option<String>,
    pub user_agent: Option<String>,
    pub url: Option<String>,
}

/// One script dispatch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScriptInvocation {
    pub phase: ScriptPhase,
    /// Script tag or name; also names the default persistent store key.
    pub script_name: String,
    /// The `argument=` value of the `[Script]` line, after argument expansion.
    pub argument: String,
    pub request: ScriptRequest,
    /// Present in the response phase.
    pub response: Option<ScriptResponse>,
    /// Loon/Surge `binary-body-mode`: the script sees bodies as `Uint8Array`
    /// (and Quantumult X `bodyBytes`). Request, response and `$done` bodies
    /// are then byte strings, one char (U+0000 to U+00FF) per byte; convert
    /// with [`binary_body_string`] and [`binary_body_bytes`].
    pub binary_body: bool,
    /// Text mode only: the phase's body (the request body in the request
    /// phase, the response body in the response phase) is not UTF-8 and is
    /// passed as a byte string. The script then gets it only as Quantumult X
    /// `bodyBytes`, with no text `body`.
    pub body_is_bytes: bool,
    /// Event name for [`ScriptPhase::Event`] (`$event.name`), such as
    /// `network-changed`.
    pub event: Option<String>,
    /// The connection a [`ScriptPhase::Rule`] script decides on.
    pub rule: Option<ScriptRuleRequest>,
}

impl ScriptInvocation {
    /// Invocation of a scheduled, event or generic script, which has no HTTP
    /// message.
    pub fn scheduled(
        phase: ScriptPhase,
        script_name: impl Into<String>,
        argument: impl Into<String>,
        event: Option<String>,
    ) -> Self {
        Self {
            phase,
            script_name: script_name.into(),
            argument: argument.into(),
            request: ScriptRequest::default(),
            response: None,
            binary_body: false,
            body_is_bytes: false,
            event,
            rule: None,
        }
    }

    /// Whether a request or response body is larger than `max_bytes`.
    #[cfg_attr(
        not(any(
            feature = "quickjs",
            all(feature = "javascriptcore", target_vendor = "apple")
        )),
        allow(dead_code)
    )]
    pub(crate) fn body_exceeds(&self, max_bytes: usize) -> bool {
        // A byte string holds one char per byte; text is counted in UTF-8.
        let len = |body: Option<&str>, bytes: bool| match body {
            None => 0,
            Some(body) if bytes => body.chars().count(),
            Some(body) => body.len(),
        };
        let phase_bytes =
            |phase: ScriptPhase| self.binary_body || (self.body_is_bytes && self.phase == phase);
        len(
            self.request.body.as_deref(),
            phase_bytes(ScriptPhase::Request),
        ) > max_bytes
            || len(
                self.response.as_ref().and_then(|r| r.body.as_deref()),
                phase_bytes(ScriptPhase::Response),
            ) > max_bytes
    }
}

/// Byte string for a binary body: one char per byte.
pub fn binary_body_string(bytes: &[u8]) -> String {
    bytes.iter().map(|&byte| char::from(byte)).collect()
}

/// Bytes of a byte string, or `None` when it holds a char above U+00FF.
pub fn binary_body_bytes(text: &str) -> Option<Vec<u8>> {
    text.chars()
        .map(|ch| u8::try_from(u32::from(ch)).ok())
        .collect()
}

/// Resource limits for one dispatch. They implement Loon's `timeout` and
/// `max-size` script options.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScriptLimits {
    /// Wall-clock budget for the whole dispatch, including timers and
    /// `$httpClient` callbacks.
    pub timeout: Duration,
    /// Heap limit (QuickJS only; JavaScriptCore cannot enforce one).
    pub memory_limit_bytes: usize,
    /// Larger bodies skip the script (Loon `max-size`).
    pub max_body_bytes: usize,
    /// Largest body or URL a script may return through `$done`.
    pub max_output_bytes: usize,
}

impl Default for ScriptLimits {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(10),
            memory_limit_bytes: 32 * 1024 * 1024,
            max_body_bytes: 1024 * 1024,
            max_output_bytes: 4 * 1024 * 1024,
        }
    }
}

/// Changes a script requested through `$done`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ScriptMutation {
    /// New request URL (request phase).
    pub url: Option<String>,
    /// New response status (response phase).
    pub status: Option<u16>,
    /// Replacement header set.
    pub headers: Option<Vec<(String, String)>>,
    /// Replacement body.
    pub body: Option<String>,
    /// Response returned without contacting the origin (request phase).
    pub response: Option<ScriptResponse>,
    /// Whether the connection matches (rule phase): `true` only when the
    /// script passed `matched: true`.
    pub matched: Option<bool>,
    /// Outside binary-body-mode, `body` and `response.body` are byte strings
    /// rather than text, because the script returned Quantumult X
    /// `bodyBytes`. In binary-body-mode bodies are always byte strings and
    /// this stays `false`.
    pub binary_bodies: bool,
}

impl ScriptMutation {
    pub fn is_empty(&self) -> bool {
        self.url.is_none()
            && self.status.is_none()
            && self.headers.is_none()
            && self.body.is_none()
            && self.response.is_none()
            && self.matched.is_none()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScriptNotification {
    pub title: String,
    pub subtitle: String,
    pub content: String,
    pub open_url: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScriptFailure {
    /// The body exceeds `max_body_bytes`; the script did not run.
    BodyTooLarge,
    Timeout,
    MemoryLimit,
    /// The script threw.
    Exception(String),
    /// `$done` received a value the host cannot apply.
    InvalidDone(String),
    Engine(String),
}

impl ScriptFailure {
    /// Stable code for diagnostics.
    pub fn code(&self) -> &'static str {
        match self {
            Self::BodyTooLarge => "script.body_too_large",
            Self::Timeout => "script.timeout",
            Self::MemoryLimit => "script.memory_limit",
            Self::Exception(_) => "script.exception",
            Self::InvalidDone(_) => "script.invalid_done",
            Self::Engine(_) => "script.engine",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScriptRunStatus {
    /// The script called `$done`.
    Done,
    /// The script ran out of work without calling `$done`; nothing changes.
    FinishedWithoutDone,
    Failed(ScriptFailure),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScriptOutcome {
    pub status: ScriptRunStatus,
    /// Empty unless `status` is [`ScriptRunStatus::Done`].
    pub mutation: ScriptMutation,
    pub notifications: Vec<ScriptNotification>,
    pub logs: Vec<String>,
    pub logs_truncated: bool,
}

impl ScriptOutcome {
    // Only the engines call this; a build with neither engine has none.
    #[cfg_attr(
        not(any(
            feature = "quickjs",
            all(feature = "javascriptcore", target_vendor = "apple")
        )),
        allow(dead_code)
    )]
    pub(crate) fn failed(failure: ScriptFailure) -> Self {
        Self {
            status: ScriptRunStatus::Failed(failure),
            mutation: ScriptMutation::default(),
            notifications: Vec::new(),
            logs: Vec::new(),
            logs_truncated: false,
        }
    }

    /// The mutation to apply, if the script finished with a non-empty one.
    pub fn applied_mutation(&self) -> Option<&ScriptMutation> {
        (self.status == ScriptRunStatus::Done && !self.mutation.is_empty())
            .then_some(&self.mutation)
    }
}

/// Redirects a `$httpClient` request follows at most before the last
/// redirect is handed to the script as it is.
pub const SCRIPT_HTTP_CLIENT_MAX_REDIRECTS: usize = 5;

/// Request a script made through `$httpClient`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScriptHttpClientRequest {
    pub method: String,
    pub url: String,
    pub headers: Vec<(String, String)>,
    /// Text, or a byte string (one char per byte) when `body_binary`.
    pub body: Option<String>,
    /// The script passed the body as bytes (`Uint8Array`, `ArrayBuffer`,
    /// Quantumult X `bodyBytes`); send [`Self::body_bytes`].
    pub body_binary: bool,
    /// Surge `binary-mode`: the client returns the answer's body as a byte
    /// string ([`binary_body_string`]) and the script gets a `Uint8Array`.
    /// Otherwise the body is UTF-8 text.
    pub binary_response: bool,
    /// Follow redirects, up to [`SCRIPT_HTTP_CLIENT_MAX_REDIRECTS`]. On
    /// unless the script set Surge `auto-redirect: false` or Quantumult X
    /// `opts.redirection: false`.
    pub follow_redirects: bool,
    /// Never longer than the time left in the dispatch; redirects share it.
    pub timeout: Duration,
}

impl ScriptHttpClientRequest {
    /// The body as it goes on the wire.
    pub fn body_bytes(&self) -> Vec<u8> {
        match self.body.as_deref() {
            None => Vec::new(),
            Some(body) if self.body_binary => binary_body_bytes(body).unwrap_or_default(),
            Some(body) => body.as_bytes().to_vec(),
        }
    }
}

/// Network access for `$httpClient`. Implementations decide which hosts and
/// methods are allowed; an error string is passed to the script callback.
pub trait ScriptHttpClient: Send + Sync {
    fn execute(&self, request: &ScriptHttpClientRequest) -> Result<ScriptResponse, String>;
}

/// Default client: every `$httpClient` call fails with an error the script
/// can observe.
#[derive(Debug, Clone, Copy, Default)]
pub struct DisabledScriptHttpClient;

pub const SCRIPT_HTTP_CLIENT_DISABLED_MESSAGE: &str =
    "networkcore: $httpClient is disabled for this script";

impl ScriptHttpClient for DisabledScriptHttpClient {
    fn execute(&self, _request: &ScriptHttpClientRequest) -> Result<ScriptResponse, String> {
        Err(SCRIPT_HTTP_CLIENT_DISABLED_MESSAGE.to_string())
    }
}
