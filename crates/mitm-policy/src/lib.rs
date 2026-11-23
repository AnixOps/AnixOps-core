//! Safe `mitm_anixops` policy adapter for NetworkCore.
//!
//! This crate owns the first domain-facing MITM policy boundary. It can load
//! plugin text through the pinned C ABI and expose stable diagnostics. It ships
//! no plugin of its own: every policy is text the user brought
//! ([`user_plugin_package`]). It does not apply live request/response mutations.

pub mod loon_cron;
pub mod loon_header_block;
pub mod loon_jq;
pub mod loon_map_local;
pub mod loon_plugin;
mod loon_syntax;
pub mod managed_sdwan;
mod policy_cache;

use control_domain::{
    AuditDecision, AuditEvent, CertificateTrustState, Diagnostic, DiagnosticSeverity, DomainError,
    DomainResult, GrantedPermissions, HookPoint, HttpBodyMutation, HttpEvent, HttpHeaderMutation,
    HttpHeaderMutationOperation, HttpMitmAction, HttpMitmEvent, HttpMitmOutcome, HttpMitmPhase,
    HttpMitmScriptDispatch, HttpMitmScriptKind, MetadataEntry, MitmHostnameDecision,
    MitmPluginService, PluginInstance, PluginManifest, PluginPackage, PluginPermission,
    PluginResult,
};
use mitm_anixops_sys as sys;
use std::cell::Cell;
use std::ffi::{CStr, CString};
use std::marker::PhantomData;
use std::mem::MaybeUninit;
use std::os::raw::{c_char, c_int};
use std::ptr::NonNull;

pub const SOURCE_MITM_POLICY: &str = "mitm.policy";

/// The id a plugin the user brought loads under. NetworkCore ships no plugin of its own
/// (no ad blocking, no site rules): every policy comes from the user.
pub const MITM_POLICY_USER_PLUGIN_ID: &str = "user";
pub const MITM_POLICY_ENGINE_ALLOC_FAILED_CODE: &str = "mitm.policy.engine.alloc_failed";
pub const MITM_POLICY_INPUT_NUL_BYTE_CODE: &str = "mitm.policy.input.nul_byte";
pub const MITM_POLICY_CONFIG_LOADED_CODE: &str = "mitm.policy.config.loaded";
pub const MITM_POLICY_CONFIG_PARSE_FAILED_CODE: &str = "mitm.policy.config.parse_failed";
pub const MITM_POLICY_RULE_ACCEPTED_CODE: &str = "mitm.policy.rule.accepted";
pub const MITM_POLICY_RULE_IGNORED_CODE: &str = "mitm.policy.rule.ignored";
pub const MITM_POLICY_RULE_REJECTED_CODE: &str = "mitm.policy.rule.rejected";
pub const MITM_POLICY_EVALUATION_FAILED_CODE: &str = "mitm.policy.evaluation.failed";
pub const MITM_POLICY_HEADER_LIST_CAPACITY_CODE: &str = "mitm.policy.header_list.capacity";
pub const MITM_POLICY_MANIFEST_ID_EMPTY_CODE: &str = "mitm.policy.manifest.id_empty";
pub const MITM_POLICY_MANIFEST_HOOK_MISSING_CODE: &str = "mitm.policy.manifest.hook_missing";
pub const MITM_POLICY_MANIFEST_PERMISSION_MISSING_CODE: &str =
    "mitm.policy.manifest.permission_missing";
pub const MITM_POLICY_PERMISSION_DENIED_CODE: &str = "mitm.policy.permission.denied";
pub const MITM_POLICY_HTTP_EVENT_MAP_LOCAL_CODE: &str = "mitm.policy.http_event.map_local";
pub const MITM_POLICY_HTTP_EVENT_MUTATION_PLANNED_CODE: &str =
    "mitm.policy.http_event.mutation_planned";
pub const MITM_POLICY_HTTP_EVENT_MUTATION_DEFERRED_CODE: &str =
    "mitm.policy.http_event.mutation_deferred";
pub const MITM_POLICY_HTTP_EVENT_SOURCE_MISSING_CODE: &str =
    "mitm.policy.http_event.source_missing";
/// Body rules matched a body that is not NUL-free UTF-8 text (protobuf,
/// gRPC, images): they are skipped, every other part of the plan stands.
pub const MITM_POLICY_HTTP_EVENT_BINARY_BODY_SKIPPED_CODE: &str =
    "mitm.policy.http_event.binary_body_rules_skipped";
/// The body rewrite chain could not be applied whole and was skipped.
pub const MITM_POLICY_HTTP_EVENT_BODY_REWRITE_SKIPPED_CODE: &str =
    "mitm.policy.http_event.body_rewrite_skipped";
/// More body rules matched than the core records; jq steps past the
/// recorded ones did not run.
pub const MITM_POLICY_HTTP_EVENT_BODY_REWRITE_RECORDS_CAPPED_CODE: &str =
    "mitm.policy.http_event.body_rewrite_records_capped";
/// A `header-replace-regex` rule left a header value as it was because the
/// core could not rewrite it (the result exceeds its value limit, or the
/// value holds a NUL byte).
pub const MITM_POLICY_HTTP_EVENT_HEADER_REGEX_SKIPPED_CODE: &str =
    "mitm.policy.http_event.header_regex_skipped";
/// More header rules matched than the core plans at once; the rest did not
/// apply.
pub const MITM_POLICY_HTTP_EVENT_HEADER_REWRITES_CAPPED_CODE: &str =
    "mitm.policy.http_event.header_rewrites_capped";
pub const MITM_POLICY_HTTP_EVENT_MUTATION_PLANNED_MESSAGE: &str = concat!(
    "mitm_anixops policy produced an HTTP mutation plan; applying it still requires ",
    "NetworkCore HTTP/TLS data plane integration",
);
pub const MITM_POLICY_HTTP_EVENT_MUTATION_DEFERRED_MESSAGE: &str = concat!(
    "mitm_anixops policy loaded, but request/response mutation is deferred until ",
    "NetworkCore HTTP/TLS data plane can apply the mutation plan",
);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MitmPolicyLoadReport {
    pub version: String,
    pub mitm_pattern_count: usize,
    pub rewrite_rule_count: usize,
    pub script_rule_count: usize,
    pub argument_count: usize,
    pub rule_diagnostics: Vec<MitmPolicyRuleDiagnostic>,
    pub diagnostics: Vec<Diagnostic>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MitmPolicyRuleDiagnosticStatus {
    Accepted,
    Ignored,
    Rejected,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MitmPolicyRuleDiagnostic {
    pub status: MitmPolicyRuleDiagnosticStatus,
    pub line: usize,
    pub section: String,
    pub action: String,
    pub message: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MitmPolicyPhase {
    Request,
    Response,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MitmPolicyMitmDecisionType {
    Bypass,
    Intercept,
    RejectQuic,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MitmPolicyMitmDecision {
    pub decision: MitmPolicyMitmDecisionType,
    pub reason: String,
    pub matched_pattern: String,
    pub message: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MitmPolicyRewriteAction {
    None,
    Redirect,
    Reject,
    BodyMutation,
    HeaderMutation,
    Other,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MitmPolicyHeaderOperation {
    Add,
    Replace,
    Delete,
    Set,
    /// `header-replace-regex` / `response-header-replace-regex`: the
    /// replacement applies to each current value of the header. A plan made
    /// without those values carries the unexpanded template, which must
    /// never be written as the header's value.
    ReplaceRegex,
}

/// What a reject rule answers with. Plugins pick a variant so the app can
/// parse the answer: `reject-dict` and `reject-array` exist so a config or
/// list request still yields valid (empty) JSON, `reject-img` so an image
/// slot still gets an image.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MitmPolicyRejectBody {
    /// No body: `reject`, `reject-200`, `reject-<status>`, and every action
    /// that is not a reject.
    Empty,
    /// `reject-img` / `reject-tinygif`: a 1x1 transparent GIF.
    TinyGif,
    /// `reject-video`: an empty `video/mp4` body.
    Video,
    /// `reject-dict`: the JSON object `{}`.
    JsonObject,
    /// `reject-array`: the JSON array `[]`.
    JsonArray,
}

impl MitmPolicyRejectBody {
    fn from_sys(action: sys::AnixOpsRewriteAction) -> Self {
        match action {
            sys::AnixOpsRewriteAction::RejectImg => Self::TinyGif,
            sys::AnixOpsRewriteAction::RejectVideo => Self::Video,
            sys::AnixOpsRewriteAction::RejectDict => Self::JsonObject,
            sys::AnixOpsRewriteAction::RejectArray => Self::JsonArray,
            _ => Self::Empty,
        }
    }

    /// The `Content-Type` and body of the answer; `None` for no body.
    pub fn content(self) -> Option<(&'static str, &'static [u8])> {
        let json = "application/json; charset=utf-8";
        let content: (&'static str, &'static [u8]) = match self {
            Self::Empty => return None,
            Self::TinyGif => ("image/gif", loon_map_local::TINY_GIF.as_slice()),
            Self::Video => ("video/mp4", b"".as_slice()),
            Self::JsonObject => (json, b"{}".as_slice()),
            Self::JsonArray => (json, b"[]".as_slice()),
        };
        Some(content)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MitmPolicyRewriteResult {
    pub action: MitmPolicyRewriteAction,
    pub status_code: i32,
    pub rule_index: i32,
    pub matched_pattern: String,
    pub value: String,
    pub message: String,
    /// For [`MitmPolicyRewriteAction::Reject`], the answer's body.
    pub reject_body: MitmPolicyRejectBody,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MitmPolicyBodyRewriteChain {
    pub rewrites: Vec<MitmPolicyRewriteResult>,
    pub rewritten: bool,
    pub truncated: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MitmPolicyHeaderRewriteResult {
    pub action: MitmPolicyRewriteAction,
    pub operation: MitmPolicyHeaderOperation,
    pub phase: MitmPolicyPhase,
    pub rule_index: i32,
    pub matched_pattern: String,
    pub header_name: String,
    pub value: String,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MitmPolicyHeaderField {
    pub name: String,
    pub value: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MitmPolicyHeaderList {
    pub fields: Vec<MitmPolicyHeaderField>,
    pub truncated: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MitmPolicyScriptKind {
    None,
    HttpRequest,
    HttpResponse,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MitmPolicyScriptDispatch {
    pub kind: MitmPolicyScriptKind,
    pub phase: MitmPolicyPhase,
    pub requires_body: bool,
    pub timeout_ms: usize,
    pub max_size: usize,
    pub rule_index: i32,
    pub matched_pattern: String,
    pub script_path: String,
    pub tag: String,
    pub argument: String,
    pub message: String,
    /// The rule sets `binary-body-mode`: the script gets the body as bytes.
    pub binary_body_mode: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MitmPolicyRewritePlan {
    pub phase: MitmPolicyPhase,
    pub body_available: bool,
    pub requires_body: bool,
    pub rewrite: MitmPolicyRewriteResult,
    pub header_rewrites: Vec<MitmPolicyHeaderRewriteResult>,
    pub header_rewrite_truncated: bool,
    pub script: MitmPolicyScriptDispatch,
}

/// Result of [`AnixOpsMitmPolicyEngine::apply_body_chain_whole`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MitmPolicyBodyChainOutcome {
    /// Every matching rule applied to `body`. `records_capped` when more
    /// rules matched than `chain` records (see [`sys::ANIXOPS_BODY_CHAIN_CAP`]).
    Applied {
        body: String,
        chain: MitmPolicyBodyRewriteChain,
        records_capped: bool,
    },
    /// The chain could not run whole, so none of it applies; `reason` says why.
    Skipped {
        chain: MitmPolicyBodyRewriteChain,
        reason: &'static str,
    },
}

/// Largest body a rewrite chain may grow to. The output buffer starts at the
/// body's size plus the core's value capacity and doubles up to this.
pub const MITM_POLICY_BODY_REWRITE_MAX_OUTPUT_BYTES: usize = 4 * 1024 * 1024;

/// Messages the core writes into rewrite results.
const CORE_HEADER_REWRITTEN: &str = "header rewritten";
const CORE_HEADER_REGEX_NOT_MATCHED: &str = "header regex not matched";
const CORE_BODY_TRUNCATED: &str = "body truncated";
const CORE_REPLACEMENT_TRUNCATED: &str = "replacement truncated";

#[derive(Debug, Clone, PartialEq, Eq)]
struct MitmPolicyLastError {
    status: c_int,
    line: usize,
    message: String,
}

pub struct AnixOpsMitmPolicyEngine {
    raw: NonNull<sys::AnixOpsEngine>,
    _not_sync: PhantomData<Cell<()>>,
}

impl AnixOpsMitmPolicyEngine {
    pub fn new() -> DomainResult<Self> {
        let raw = unsafe { sys::anixops_engine_new() };
        let raw = NonNull::new(raw).ok_or_else(|| {
            DomainError::new(
                MITM_POLICY_ENGINE_ALLOC_FAILED_CODE,
                "mitm_anixops engine allocation failed",
            )
        })?;

        Ok(Self {
            raw,
            _not_sync: PhantomData,
        })
    }

    pub fn load_config(&mut self, config_text: &str) -> DomainResult<MitmPolicyLoadReport> {
        POLICY_LOADS.with(|loads| loads.set(loads.get() + 1));
        let config = CString::new(config_text).map_err(|_| {
            DomainError::new(
                MITM_POLICY_INPUT_NUL_BYTE_CODE,
                "mitm plugin config contains an unsupported nul byte",
            )
        })?;

        let status = unsafe {
            sys::anixops_engine_clear(self.raw.as_ptr());
            // Clearing resets the engine to POSIX regex. Plugins are written
            // against Perl-style engines (NSRegularExpression, PCRE), so use
            // PCRE2 whenever this build has it.
            if sys::anixops_regex_backend_available(sys::AnixOpsRegexBackend::Pcre2) != 0 {
                sys::anixops_engine_set_regex_backend(
                    self.raw.as_ptr(),
                    sys::AnixOpsRegexBackend::Pcre2,
                );
            }
            sys::anixops_engine_load_config(self.raw.as_ptr(), config.as_ptr())
        };
        let rule_diagnostics = self.rule_diagnostics();

        if status != sys::ANIXOPS_OK {
            let last_error = self.last_error();
            let message = if last_error.message.is_empty() || last_error.message == "ok" {
                status_message(last_error.status)
            } else {
                last_error.message
            };
            return Err(DomainError::new(
                MITM_POLICY_CONFIG_PARSE_FAILED_CODE,
                format!(
                    "mitm_anixops config load failed at line {}: {}",
                    last_error.line, message
                ),
            ));
        }

        let mut diagnostics = vec![mitm_policy_diagnostic(
            DiagnosticSeverity::Info,
            MITM_POLICY_CONFIG_LOADED_CODE,
            "mitm_anixops policy config loaded",
        )];
        diagnostics.extend(rule_diagnostics.iter().map(rule_diagnostic_to_domain));

        let mitm_pattern_count =
            unsafe { sys::anixops_engine_mitm_pattern_count(self.raw.as_ptr()) };
        let rewrite_rule_count =
            unsafe { sys::anixops_engine_rewrite_rule_count(self.raw.as_ptr()) };
        let script_rule_count = unsafe { sys::anixops_engine_script_rule_count(self.raw.as_ptr()) };
        let argument_count = unsafe { sys::anixops_engine_argument_count(self.raw.as_ptr()) };

        Ok(MitmPolicyLoadReport {
            version: sys::version().to_string(),
            mitm_pattern_count,
            rewrite_rule_count,
            script_rule_count,
            argument_count,
            rule_diagnostics,
            diagnostics,
        })
    }

    pub fn set_jq_max_input_bytes(&mut self, max_input_bytes: usize) -> DomainResult<()> {
        let status = unsafe {
            sys::anixops_engine_set_jq_max_input_bytes(self.raw.as_ptr(), max_input_bytes)
        };
        if status != sys::ANIXOPS_OK {
            return Err(evaluation_error(status));
        }

        Ok(())
    }

    /// True when rules are compiled with PCRE2 rather than POSIX regex.
    pub fn uses_pcre2_regex(&self) -> bool {
        let backend = unsafe { sys::anixops_engine_regex_backend(self.raw.as_ptr()) };
        backend == sys::AnixOpsRegexBackend::Pcre2
    }

    pub fn jq_max_input_bytes(&self) -> usize {
        unsafe { sys::anixops_engine_jq_max_input_bytes(self.raw.as_ptr()) }
    }

    pub fn set_certificate_trust_state(&mut self, state: CertificateTrustState) {
        let state = match state {
            CertificateTrustState::NotInstalled => sys::AnixOpsCertState::NotInstalled,
            CertificateTrustState::InstalledUntrusted => sys::AnixOpsCertState::InstalledUntrusted,
            CertificateTrustState::Trusted => sys::AnixOpsCertState::Trusted,
            CertificateTrustState::Revoked => sys::AnixOpsCertState::Revoked,
            CertificateTrustState::Unknown => sys::AnixOpsCertState::Unknown,
        };

        unsafe { sys::anixops_engine_set_cert_state(self.raw.as_ptr(), state) };
    }

    pub fn evaluate_mitm(
        &self,
        hostname: &str,
        is_quic: bool,
    ) -> DomainResult<MitmPolicyMitmDecision> {
        let hostname = CString::new(hostname).map_err(|_| {
            DomainError::new(
                MITM_POLICY_INPUT_NUL_BYTE_CODE,
                "mitm hostname contains an unsupported nul byte",
            )
        })?;
        let mut out = MaybeUninit::<sys::AnixOpsMitmDecision>::uninit();
        let status = unsafe {
            sys::anixops_mitm_evaluate(
                self.raw.as_ptr(),
                hostname.as_ptr(),
                if is_quic { 1 } else { 0 },
                out.as_mut_ptr(),
            )
        };
        if status != sys::ANIXOPS_OK {
            return Err(evaluation_error(status));
        }

        let out = unsafe { out.assume_init() };
        Ok(MitmPolicyMitmDecision {
            decision: match out.decision {
                sys::AnixOpsMitmDecisionType::Bypass => MitmPolicyMitmDecisionType::Bypass,
                sys::AnixOpsMitmDecisionType::Intercept => MitmPolicyMitmDecisionType::Intercept,
                sys::AnixOpsMitmDecisionType::RejectQuic => MitmPolicyMitmDecisionType::RejectQuic,
            },
            reason: format!("{:?}", out.reason),
            matched_pattern: ffi_string(&out.matched_pattern),
            message: ffi_string(&out.message),
        })
    }

    pub fn evaluate_url_rewrite(
        &self,
        url: &str,
        phase: MitmPolicyPhase,
    ) -> DomainResult<MitmPolicyRewriteResult> {
        let url = CString::new(url).map_err(|_| {
            DomainError::new(
                MITM_POLICY_INPUT_NUL_BYTE_CODE,
                "mitm URL contains an unsupported nul byte",
            )
        })?;
        let mut out = MaybeUninit::<sys::AnixOpsRewriteResult>::uninit();
        let status = unsafe {
            sys::anixops_rewrite_evaluate_url(
                self.raw.as_ptr(),
                url.as_ptr(),
                phase.into(),
                out.as_mut_ptr(),
            )
        };
        if status != sys::ANIXOPS_OK {
            return Err(evaluation_error(status));
        }

        let out = unsafe { out.assume_init() };
        Ok(rewrite_result_from_sys(&out))
    }

    /// Runs every body rule matching `url` on `body`. The output buffer holds
    /// the body plus [`sys::ANIXOPS_VALUE_CAP`] bytes; a chain that grows the
    /// body further, or matches more than [`sys::ANIXOPS_BODY_CHAIN_CAP`]
    /// rules, comes back `truncated` (see [`Self::apply_body_chain_whole`]).
    pub fn apply_body_chain(
        &self,
        url: &str,
        phase: MitmPolicyPhase,
        body: &str,
    ) -> DomainResult<(String, MitmPolicyBodyRewriteChain)> {
        self.apply_body_chain_with_capacity(
            url,
            phase,
            body,
            body.len().saturating_add(sys::ANIXOPS_VALUE_CAP),
        )
    }

    /// [`Self::apply_body_chain`] that tells apart the two reasons the core
    /// reports `truncated`, since it sets the same flag for both:
    ///
    /// - A rule's output did not fit the buffer. The core then carries a cut
    ///   body on to the next rule, so the chain is run again with a buffer
    ///   twice as large, up to [`MITM_POLICY_BODY_REWRITE_MAX_OUTPUT_BYTES`].
    /// - More rules matched than the result records. The body itself is
    ///   whole: once two runs with different buffers produce the same body
    ///   and no recorded rule reports a cut, it is used as it is.
    ///
    /// A chain that still does not fit is [`MitmPolicyBodyChainOutcome::Skipped`]
    /// as a whole, never applied cut short.
    pub fn apply_body_chain_whole(
        &self,
        url: &str,
        phase: MitmPolicyPhase,
        body: &str,
    ) -> DomainResult<MitmPolicyBodyChainOutcome> {
        let mut capacity = body.len().saturating_add(sys::ANIXOPS_VALUE_CAP);
        let mut previous: Option<String> = None;
        loop {
            let (out, chain) = self.apply_body_chain_with_capacity(url, phase, body, capacity)?;
            if !chain.truncated {
                return Ok(MitmPolicyBodyChainOutcome::Applied {
                    body: out,
                    chain,
                    records_capped: false,
                });
            }
            // A mock body is cut to the core's value capacity whatever the
            // buffer: a larger one cannot help.
            if chain
                .rewrites
                .iter()
                .any(|rewrite| rewrite.message == CORE_REPLACEMENT_TRUNCATED)
            {
                return Ok(MitmPolicyBodyChainOutcome::Skipped {
                    chain,
                    reason: "a mock body exceeds the policy core's value capacity",
                });
            }
            let records_full = chain.rewrites.len() >= sys::ANIXOPS_BODY_CHAIN_CAP;
            let recorded_cut = chain
                .rewrites
                .iter()
                .any(|rewrite| rewrite.message == CORE_BODY_TRUNCATED);
            if records_full && !recorded_cut && previous.as_deref() == Some(out.as_str()) {
                return Ok(MitmPolicyBodyChainOutcome::Applied {
                    body: out,
                    chain,
                    records_capped: true,
                });
            }
            if capacity >= MITM_POLICY_BODY_REWRITE_MAX_OUTPUT_BYTES {
                return Ok(MitmPolicyBodyChainOutcome::Skipped {
                    chain,
                    reason: "the rewritten body exceeds the body rewrite output limit",
                });
            }
            previous = records_full.then_some(out);
            capacity = capacity
                .saturating_mul(2)
                .min(MITM_POLICY_BODY_REWRITE_MAX_OUTPUT_BYTES);
        }
    }

    fn apply_body_chain_with_capacity(
        &self,
        url: &str,
        phase: MitmPolicyPhase,
        body: &str,
        capacity: usize,
    ) -> DomainResult<(String, MitmPolicyBodyRewriteChain)> {
        let url = c_string(url, "mitm URL contains an unsupported nul byte")?;
        let body = c_string(body, "mitm body contains an unsupported nul byte")?;
        let mut out_body = vec![0 as c_char; capacity.max(1)];
        let mut out_chain = empty_body_rewrite_chain();
        let status = unsafe {
            sys::anixops_rewrite_apply_body_chain(
                self.raw.as_ptr(),
                url.as_ptr(),
                phase.into(),
                body.as_ptr(),
                out_body.as_mut_ptr(),
                out_body.len(),
                &mut out_chain,
            )
        };
        if status != sys::ANIXOPS_OK {
            return Err(evaluation_error(status));
        }

        Ok((
            ffi_string(&out_body),
            body_rewrite_chain_from_sys(&out_chain),
        ))
    }

    pub fn evaluate_named_header(
        &self,
        url: &str,
        phase: MitmPolicyPhase,
        start_index: usize,
        header_name: &str,
        current_header_value: &str,
    ) -> DomainResult<MitmPolicyHeaderRewriteResult> {
        let url = c_string(url, "mitm URL contains an unsupported nul byte")?;
        let header_name = c_string(
            header_name,
            "mitm header name contains an unsupported nul byte",
        )?;
        let current_header_value = c_string(
            current_header_value,
            "mitm header value contains an unsupported nul byte",
        )?;
        let mut out = MaybeUninit::<sys::AnixOpsHeaderRewriteResult>::uninit();
        let status = unsafe {
            sys::anixops_rewrite_evaluate_named_header(
                self.raw.as_ptr(),
                url.as_ptr(),
                phase.into(),
                start_index,
                header_name.as_ptr(),
                current_header_value.as_ptr(),
                out.as_mut_ptr(),
            )
        };
        if status != sys::ANIXOPS_OK {
            return Err(evaluation_error(status));
        }

        let out = unsafe { out.assume_init() };
        Ok(header_rewrite_result_from_sys(&out))
    }

    pub fn apply_headers(
        &self,
        url: &str,
        phase: MitmPolicyPhase,
        headers: &[MitmPolicyHeaderField],
    ) -> DomainResult<(MitmPolicyHeaderList, MitmPolicyRewritePlan)> {
        let url = c_string(url, "mitm URL contains an unsupported nul byte")?;
        let headers = header_list_to_sys(headers)?;
        let mut out_headers = empty_header_list();
        let mut out_plan = empty_rewrite_plan();
        let status = unsafe {
            sys::anixops_rewrite_apply_headers(
                self.raw.as_ptr(),
                url.as_ptr(),
                phase.into(),
                &headers,
                &mut out_headers,
                &mut out_plan,
            )
        };
        if status != sys::ANIXOPS_OK {
            return Err(evaluation_error(status));
        }

        Ok((
            header_list_from_sys(&out_headers),
            rewrite_plan_from_sys(&out_plan),
        ))
    }

    pub fn evaluate_script(
        &self,
        url: &str,
        phase: MitmPolicyPhase,
    ) -> DomainResult<MitmPolicyScriptDispatch> {
        let url = c_string(url, "mitm URL contains an unsupported nul byte")?;
        let mut out = MaybeUninit::<sys::AnixOpsScriptResult>::uninit();
        let status = unsafe {
            sys::anixops_script_evaluate_url(
                self.raw.as_ptr(),
                url.as_ptr(),
                phase.into(),
                out.as_mut_ptr(),
            )
        };
        if status != sys::ANIXOPS_OK {
            return Err(evaluation_error(status));
        }

        let out = unsafe { out.assume_init() };
        Ok(script_dispatch_from_sys(&out))
    }

    pub fn build_rewrite_plan(
        &self,
        url: &str,
        phase: MitmPolicyPhase,
        body: &str,
    ) -> DomainResult<(MitmPolicyRewritePlan, String)> {
        let url = c_string(url, "mitm URL contains an unsupported nul byte")?;
        let body = c_string(body, "mitm body contains an unsupported nul byte")?;
        let mut out_body = vec![0 as c_char; body.as_bytes().len() + sys::ANIXOPS_VALUE_CAP];
        let mut out_plan = empty_rewrite_plan();
        let status = unsafe {
            sys::anixops_rewrite_build_plan(
                self.raw.as_ptr(),
                url.as_ptr(),
                phase.into(),
                body.as_ptr(),
                out_body.as_mut_ptr(),
                out_body.len(),
                std::ptr::null(),
                &mut out_plan,
            )
        };
        if status != sys::ANIXOPS_OK {
            return Err(evaluation_error(status));
        }

        Ok((rewrite_plan_from_sys(&out_plan), ffi_string(&out_body)))
    }

    fn rule_diagnostics(&self) -> Vec<MitmPolicyRuleDiagnostic> {
        let count = unsafe { sys::anixops_engine_rule_diagnostic_count(self.raw.as_ptr()) };
        let mut diagnostics = Vec::with_capacity(count);

        for index in 0..count {
            let mut out = MaybeUninit::<sys::AnixOpsRuleDiagnostic>::uninit();
            let status = unsafe {
                sys::anixops_engine_copy_rule_diagnostic(self.raw.as_ptr(), index, out.as_mut_ptr())
            };
            if status != sys::ANIXOPS_OK {
                continue;
            }

            let out = unsafe { out.assume_init() };
            diagnostics.push(MitmPolicyRuleDiagnostic {
                status: match out.status {
                    sys::AnixOpsRuleDiagnosticStatus::Accepted => {
                        MitmPolicyRuleDiagnosticStatus::Accepted
                    }
                    sys::AnixOpsRuleDiagnosticStatus::Ignored => {
                        MitmPolicyRuleDiagnosticStatus::Ignored
                    }
                    sys::AnixOpsRuleDiagnosticStatus::Rejected => {
                        MitmPolicyRuleDiagnosticStatus::Rejected
                    }
                },
                line: out.line,
                section: ffi_string(&out.section),
                action: ffi_string(&out.action),
                message: ffi_string(&out.message),
            });
        }

        diagnostics
    }

    /// 1-based config line the last failed call stopped at, 0 when the failure
    /// was not tied to a line.
    pub fn last_error_line(&self) -> usize {
        self.last_error().line
    }

    fn last_error(&self) -> MitmPolicyLastError {
        let mut status = sys::ANIXOPS_OK;
        let mut line = 0usize;
        let mut message = [0 as c_char; sys::ANIXOPS_MESSAGE_CAP];
        let rc = unsafe {
            sys::anixops_engine_copy_last_error(
                self.raw.as_ptr(),
                &mut status,
                &mut line,
                message.as_mut_ptr(),
                message.len(),
            )
        };

        if rc != sys::ANIXOPS_OK {
            return MitmPolicyLastError {
                status: rc,
                line: 0,
                message: status_message(rc),
            };
        }

        MitmPolicyLastError {
            status,
            line,
            message: ffi_string(&message),
        }
    }
}

impl Drop for AnixOpsMitmPolicyEngine {
    fn drop(&mut self) {
        unsafe { sys::anixops_engine_free(self.raw.as_ptr()) };
    }
}

impl From<MitmPolicyPhase> for sys::AnixOpsPhase {
    fn from(value: MitmPolicyPhase) -> Self {
        match value {
            MitmPolicyPhase::Request => Self::Request,
            MitmPolicyPhase::Response => Self::Response,
        }
    }
}

impl From<sys::AnixOpsPhase> for MitmPolicyPhase {
    fn from(value: sys::AnixOpsPhase) -> Self {
        match value {
            sys::AnixOpsPhase::Request => Self::Request,
            sys::AnixOpsPhase::Response => Self::Response,
        }
    }
}

impl From<sys::AnixOpsRewriteAction> for MitmPolicyRewriteAction {
    fn from(value: sys::AnixOpsRewriteAction) -> Self {
        match value {
            sys::AnixOpsRewriteAction::None => Self::None,
            sys::AnixOpsRewriteAction::Redirect301
            | sys::AnixOpsRewriteAction::Redirect302
            | sys::AnixOpsRewriteAction::Redirect303
            | sys::AnixOpsRewriteAction::Redirect307
            | sys::AnixOpsRewriteAction::Redirect308 => Self::Redirect,
            sys::AnixOpsRewriteAction::Reject
            | sys::AnixOpsRewriteAction::Reject200
            | sys::AnixOpsRewriteAction::RejectImg
            | sys::AnixOpsRewriteAction::RejectVideo
            | sys::AnixOpsRewriteAction::RejectDict
            | sys::AnixOpsRewriteAction::RejectArray => Self::Reject,
            sys::AnixOpsRewriteAction::MockRequestBody
            | sys::AnixOpsRewriteAction::MockResponseBody
            | sys::AnixOpsRewriteAction::RequestBodyReplaceRegex
            | sys::AnixOpsRewriteAction::ResponseBodyReplaceRegex
            | sys::AnixOpsRewriteAction::RequestBodyJsonReplace
            | sys::AnixOpsRewriteAction::ResponseBodyJsonReplace
            | sys::AnixOpsRewriteAction::RequestBodyJq
            | sys::AnixOpsRewriteAction::ResponseBodyJq => Self::BodyMutation,
            sys::AnixOpsRewriteAction::HeaderReplace
            | sys::AnixOpsRewriteAction::HeaderAdd
            | sys::AnixOpsRewriteAction::HeaderReplaceRegex
            | sys::AnixOpsRewriteAction::ResponseHeaderDel
            | sys::AnixOpsRewriteAction::ResponseHeaderReplace
            | sys::AnixOpsRewriteAction::ResponseHeaderAdd
            | sys::AnixOpsRewriteAction::ResponseHeaderReplaceRegex
            | sys::AnixOpsRewriteAction::HeaderDel => Self::HeaderMutation,
            // A transparent URL rewrite has no outcome in the data plane, and
            // the importer grades the line unsupported: the message continues
            // unchanged. It must never become a redirect with status 200.
            sys::AnixOpsRewriteAction::UrlRewrite200 => Self::Other,
        }
    }
}

impl From<sys::AnixOpsScriptKind> for MitmPolicyScriptKind {
    fn from(value: sys::AnixOpsScriptKind) -> Self {
        match value {
            sys::AnixOpsScriptKind::None => Self::None,
            sys::AnixOpsScriptKind::HttpRequest => Self::HttpRequest,
            sys::AnixOpsScriptKind::HttpResponse => Self::HttpResponse,
        }
    }
}

thread_local! {
    static POLICY_LOADS: Cell<u64> = Cell::new(0);
}

/// How many times this thread has loaded text into an engine
/// ([`AnixOpsMitmPolicyEngine::load_config`]); tests use it to check that a
/// policy is compiled once per revision, not once per message or host.
#[doc(hidden)]
pub fn policy_loads_on_this_thread() -> u64 {
    POLICY_LOADS.with(Cell::get)
}

/// Loaded engines kept between HTTP events. Loading a policy parses it and
/// compiles every rule, far more work than planning one message, and a
/// policy with large plugins runs to megabytes.
static ENGINE_POOL: std::sync::Mutex<Vec<PooledEngine>> = std::sync::Mutex::new(Vec::new());
/// Idle engines kept. Scripted messages are planned in parallel on the
/// blocking pool, so a page loading several resources at once holds several
/// leases; engines of the current policy are kept before those of an older
/// one, and the extra ones are dropped afterwards.
const ENGINE_POOL_MAX_IDLE: usize = 4;
/// Policy text the idle engines may hold together. A loaded engine's memory
/// grows with its policy, so a large policy keeps fewer idle engines (one at
/// least) and a memory-limited extension does not hold several compiled
/// copies of a multi-megabyte policy.
const ENGINE_POOL_MAX_IDLE_POLICY_BYTES: usize = 2 * 1024 * 1024;

/// Policies up to this size are hashed whole; larger ones by samples, so a
/// multi-megabyte policy costs little per message. The embedded data plane
/// ends each policy it builds with a line unique to it, which the samples
/// always cover.
const POLICY_FULL_HASH_MAX_BYTES: usize = 256 * 1024;
const POLICY_SAMPLE_BYTES: usize = 64 * 1024;
const POLICY_STRIDE_SAMPLES: usize = 32;
const POLICY_STRIDE_SAMPLE_BYTES: usize = 512;

/// A policy's identity: its length and a hash of its text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PolicyFingerprint(usize, u64);

impl PolicyFingerprint {
    /// The policy's length in bytes.
    fn bytes(self) -> usize {
        self.0
    }
}

impl PolicyFingerprint {
    fn of(source: &str) -> Self {
        use std::hash::Hasher;
        let bytes = source.as_bytes();
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        if bytes.len() <= POLICY_FULL_HASH_MAX_BYTES {
            hasher.write(bytes);
        } else {
            hasher.write(&bytes[..POLICY_SAMPLE_BYTES]);
            hasher.write(&bytes[bytes.len() - POLICY_SAMPLE_BYTES..]);
            let stride = bytes.len() / POLICY_STRIDE_SAMPLES;
            for index in 0..POLICY_STRIDE_SAMPLES {
                let start = index * stride;
                let end = (start + POLICY_STRIDE_SAMPLE_BYTES).min(bytes.len());
                hasher.write(&bytes[start..end]);
            }
        }
        Self(bytes.len(), hasher.finish())
    }
}

struct PooledEngine {
    policy: PolicyFingerprint,
    engine: AnixOpsMitmPolicyEngine,
}

// SAFETY: the mitm_anixops C engine keeps all its state in the engine value,
// with no globals or thread-local data, so it may move between threads; the
// pool hands each engine to one thread at a time.
unsafe impl Send for PooledEngine {}

/// An engine loaded with one policy, taken from the pool or loaded fresh.
/// It goes back to the pool only after [`EngineLease::keep`], so an engine
/// that saw an error is never reused.
struct EngineLease {
    pooled: Option<PooledEngine>,
    keep: bool,
}

impl EngineLease {
    fn acquire(source: &str) -> DomainResult<Self> {
        let policy = PolicyFingerprint::of(source);
        let pooled = ENGINE_POOL.lock().ok().and_then(|mut pool| {
            let index = pool.iter().rposition(|entry| entry.policy == policy)?;
            Some(pool.remove(index))
        });
        let pooled = match pooled {
            Some(pooled) => pooled,
            None => {
                let mut engine = AnixOpsMitmPolicyEngine::new()?;
                engine.load_config(source)?;
                PooledEngine { policy, engine }
            }
        };
        Ok(Self {
            pooled: Some(pooled),
            keep: false,
        })
    }

    fn keep(&mut self) {
        self.keep = true;
    }
}

impl std::ops::Deref for EngineLease {
    type Target = AnixOpsMitmPolicyEngine;

    fn deref(&self) -> &Self::Target {
        &self
            .pooled
            .as_ref()
            .expect("a lease holds its engine")
            .engine
    }
}

impl std::ops::DerefMut for EngineLease {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self
            .pooled
            .as_mut()
            .expect("a lease holds its engine")
            .engine
    }
}

impl Drop for EngineLease {
    fn drop(&mut self) {
        let Some(pooled) = self.pooled.take().filter(|_| self.keep) else {
            return;
        };
        if let Ok(mut pool) = ENGINE_POOL.lock() {
            let current = pooled.policy;
            pool.push(pooled);
            let over_budget = |pool: &[PooledEngine]| {
                pool.len() > ENGINE_POOL_MAX_IDLE
                    || (pool.len() > 1
                        && pool.iter().map(|entry| entry.policy.bytes()).sum::<usize>()
                            > ENGINE_POOL_MAX_IDLE_POLICY_BYTES)
            };
            while over_budget(&pool) {
                // An engine of a replaced policy goes first, oldest first.
                let index = pool
                    .iter()
                    .position(|entry| entry.policy != current)
                    .unwrap_or(0);
                pool.remove(index);
            }
        }
    }
}

/// Number of idle loaded engines; tests use it to check that a released
/// policy leaves none behind.
#[doc(hidden)]
pub fn idle_policy_engines() -> usize {
    ENGINE_POOL.lock().map(|pool| pool.len()).unwrap_or(0)
}

/// Drops every compiled form of `source` the crate keeps between calls:
/// idle loaded engines, the hostname engine, and the compiled Map Local,
/// header-block and jq rules. Calls that still run with them finish first;
/// a later call for `source` compiles it again.
///
/// The owner of a loaded policy calls this, through
/// [`CompiledPolicyRelease`], when it stops using the policy, so compiled
/// copies of a replaced policy do not stay in memory until other revisions
/// push them out.
pub fn release_compiled_policy(source: &str) {
    release_policy(PolicyFingerprint::of(source));
}

fn release_policy(policy: PolicyFingerprint) {
    let idle = ENGINE_POOL.lock().ok().map(|mut pool| {
        let (released, kept) = std::mem::take(&mut *pool)
            .into_iter()
            .partition::<Vec<_>, _>(|entry| entry.policy == policy);
        *pool = kept;
        released
    });
    // Engines are freed outside the pool's lock.
    drop(idle);
    HOSTNAME_ENGINES.remove(policy);
    loon_map_local::release(policy);
    loon_header_block::release(policy);
    loon_jq::release(policy);
}

/// Releases a policy's compiled forms ([`release_compiled_policy`]) when
/// dropped. The owner of a loaded policy keeps one beside it, so the
/// compiled forms live as long as the policy is in use.
#[derive(Debug)]
pub struct CompiledPolicyRelease {
    policy: PolicyFingerprint,
}

impl CompiledPolicyRelease {
    /// Releases `source`'s compiled forms when dropped.
    pub fn new(source: &str) -> Self {
        Self {
            policy: PolicyFingerprint::of(source),
        }
    }
}

impl Drop for CompiledPolicyRelease {
    fn drop(&mut self) {
        release_policy(self.policy);
    }
}

/// Engines answering [`MitmPluginService::evaluate_mitm_hostname`], one per
/// policy in use, released with the policy ([`CompiledPolicyRelease`]). The
/// capacity only bounds what callers that never release keep. They only read
/// the hostname list and are set to a trusted certificate, so they are kept
/// apart from [`ENGINE_POOL`].
static HOSTNAME_ENGINES: policy_cache::PolicyCache<policy_cache::SharedEngine> =
    policy_cache::PolicyCache::new(2);

#[derive(Debug, Clone, Copy, Default)]
pub struct AnixOpsMitmPluginService;

impl AnixOpsMitmPluginService {
    pub const fn new() -> Self {
        Self
    }

    /// Whether planning a message to `url` in `phase` reads its body: a
    /// body rewrite (including jq) or a script with `requires-body=true`
    /// matches. When nothing does,
    /// the data plane can forward the body as it arrives instead of holding
    /// it whole, and only the head is planned.
    pub fn needs_body(
        &self,
        plugin_instance: &PluginInstance,
        url: &str,
        phase: HttpMitmPhase,
    ) -> DomainResult<bool> {
        let Some(source) = plugin_instance.loaded_source.as_deref() else {
            return Ok(false);
        };
        let mut engine = EngineLease::acquire(source)?;
        let phase = policy_phase_from_domain(phase);
        let (plan, _) = engine.build_rewrite_plan(url, phase, "")?;
        let (_, chain) = engine.apply_body_chain(url, phase, "")?;
        engine.keep();
        // `requires_body` covers a body rewrite and a script with
        // `requires-body=true`. A script without it never sees the body,
        // so matching one does not hold the body back.
        Ok(plan.requires_body || !chain.rewrites.is_empty() || chain.truncated)
    }
}

impl MitmPluginService for AnixOpsMitmPluginService {
    fn validate_manifest(&self, plugin_manifest: &PluginManifest) -> Vec<Diagnostic> {
        let mut diagnostics = Vec::new();

        if plugin_manifest.id.trim().is_empty() {
            diagnostics.push(mitm_policy_diagnostic(
                DiagnosticSeverity::Error,
                MITM_POLICY_MANIFEST_ID_EMPTY_CODE,
                "MITM plugin manifest id cannot be empty",
            ));
        }

        if plugin_manifest.hooks.is_empty() {
            diagnostics.push(mitm_policy_diagnostic(
                DiagnosticSeverity::Error,
                MITM_POLICY_MANIFEST_HOOK_MISSING_CODE,
                "MITM plugin manifest must declare request or response hooks",
            ));
        }

        let can_read_http = plugin_manifest.permissions.iter().any(|permission| {
            matches!(
                permission,
                PluginPermission::ReadRequest | PluginPermission::ReadResponse
            )
        });
        if !can_read_http {
            diagnostics.push(mitm_policy_diagnostic(
                DiagnosticSeverity::Error,
                MITM_POLICY_MANIFEST_PERMISSION_MISSING_CODE,
                "MITM plugin manifest must request request or response read permission",
            ));
        }

        diagnostics
    }

    fn load(
        &self,
        plugin_package: &PluginPackage,
        granted_permissions: &GrantedPermissions,
    ) -> DomainResult<PluginInstance> {
        reject_error_diagnostics(
            self.validate_manifest(&plugin_package.manifest),
            "MITM plugin manifest is invalid",
        )?;

        for permission in &plugin_package.manifest.permissions {
            if !permission_granted(granted_permissions, permission) {
                return Err(DomainError::new(
                    MITM_POLICY_PERMISSION_DENIED_CODE,
                    "MITM plugin requested a permission that was not granted",
                ));
            }
        }

        let mut engine = AnixOpsMitmPolicyEngine::new()?;
        engine.load_config(&plugin_package.source)?;

        Ok(PluginInstance {
            manifest: plugin_package.manifest.clone(),
            loaded_source: Some(plugin_package.source.clone()),
        })
    }

    fn handle_http_event(
        &self,
        plugin_instance: &PluginInstance,
        http_event: &HttpEvent,
    ) -> DomainResult<PluginResult> {
        Ok(PluginResult {
            audits: vec![AuditEvent {
                actor: plugin_instance.manifest.id.clone(),
                action: "mitm.policy.handle_http_event".to_string(),
                decision: AuditDecision::Allowed,
                reason: Some(format!(
                    "request {} accepted by policy adapter; live HTTP mutation is deferred",
                    http_event.request_id
                )),
            }],
            diagnostics: vec![mitm_policy_diagnostic(
                DiagnosticSeverity::Warning,
                MITM_POLICY_HTTP_EVENT_MUTATION_DEFERRED_CODE,
                MITM_POLICY_HTTP_EVENT_MUTATION_DEFERRED_MESSAGE,
            )],
        })
    }

    fn handle_http_mitm_event(
        &self,
        plugin_instance: &PluginInstance,
        http_event: &HttpMitmEvent,
    ) -> DomainResult<HttpMitmOutcome> {
        let Some(source) = plugin_instance.loaded_source.as_deref() else {
            return Ok(HttpMitmOutcome {
                action: HttpMitmAction::Continue,
                header_mutations: Vec::new(),
                body_mutation: None,
                script_dispatch: None,
                audits: vec![AuditEvent {
                    actor: plugin_instance.manifest.id.clone(),
                    action: "mitm.policy.plan_http_mitm_event".to_string(),
                    decision: AuditDecision::Allowed,
                    reason: Some(format!(
                        "request {} accepted by policy adapter; loaded plugin source is unavailable",
                        http_event.request_id
                    )),
                }],
                diagnostics: vec![mitm_policy_diagnostic(
                    DiagnosticSeverity::Warning,
                    MITM_POLICY_HTTP_EVENT_SOURCE_MISSING_CODE,
                    "loaded plugin source is unavailable, so HTTP mutation planning is deferred",
                )],
            });
        };

        if http_event.phase == HttpMitmPhase::Request {
            if let Some(rule) = loon_map_local::match_map_local(source, &http_event.url)? {
                return Ok(HttpMitmOutcome {
                    action: HttpMitmAction::Respond {
                        status_code: rule.status_code,
                        headers: rule.headers,
                        body: rule.body,
                    },
                    header_mutations: Vec::new(),
                    body_mutation: None,
                    script_dispatch: None,
                    audits: vec![AuditEvent {
                        actor: plugin_instance.manifest.id.clone(),
                        action: "mitm.policy.plan_http_mitm_event".to_string(),
                        decision: AuditDecision::Allowed,
                        reason: Some(format!(
                            "request {} answered by a [Map Local] rule",
                            http_event.request_id
                        )),
                    }],
                    diagnostics: vec![mitm_policy_diagnostic(
                        DiagnosticSeverity::Info,
                        MITM_POLICY_HTTP_EVENT_MAP_LOCAL_CODE,
                        "request matched a [Map Local] rule and is answered locally",
                    )],
                });
            }
        }

        // Quantumult X header-block rewrites: the core matches, the block
        // is rewritten as text, and a moved request is redirected.
        let header_block = loon_header_block::apply_header_block(
            source,
            &http_event.url,
            http_event.phase,
            http_event.method.as_deref(),
            http_event.status_code,
            &http_event.headers,
        )?;
        if let Some(location) = header_block
            .as_ref()
            .and_then(|outcome| outcome.redirect.clone())
        {
            return Ok(HttpMitmOutcome {
                action: HttpMitmAction::Redirect {
                    status_code: 302,
                    location,
                },
                header_mutations: Vec::new(),
                body_mutation: None,
                script_dispatch: None,
                audits: vec![AuditEvent {
                    actor: plugin_instance.manifest.id.clone(),
                    action: "mitm.policy.plan_http_mitm_event".to_string(),
                    decision: AuditDecision::Allowed,
                    reason: Some(format!(
                        "request {} moved by a header-block rewrite",
                        http_event.request_id
                    )),
                }],
                diagnostics: vec![mitm_policy_diagnostic(
                    DiagnosticSeverity::Info,
                    MITM_POLICY_HTTP_EVENT_MUTATION_PLANNED_CODE,
                    MITM_POLICY_HTTP_EVENT_MUTATION_PLANNED_MESSAGE,
                )],
            });
        }

        let mut engine = EngineLease::acquire(source)?;
        let phase = policy_phase_from_domain(http_event.phase);
        // The URL decides the action, the header rules and the script; the
        // body is never handed to the core here, so a binary body (NUL
        // bytes) cannot fail the plan and take the reject, redirect, header
        // rewrites and script dispatch down with it.
        let (plan, _) = engine.build_rewrite_plan(&http_event.url, phase, "")?;
        let mut diagnostics = vec![mitm_policy_diagnostic(
            DiagnosticSeverity::Info,
            MITM_POLICY_HTTP_EVENT_MUTATION_PLANNED_CODE,
            MITM_POLICY_HTTP_EVENT_MUTATION_PLANNED_MESSAGE,
        )];

        let action = domain_action_from_policy_rewrite(&plan.rewrite);
        let mut header_mutations = header_mutations_from_plan(
            &engine,
            &http_event.url,
            phase,
            &plan,
            &http_event.headers,
            &mut diagnostics,
        );
        if let Some(outcome) = header_block {
            header_mutations.extend(outcome.header_mutations);
        }
        // Every matching body rule applies in order, so one Loon
        // `[Body Rewrite]` line with several replacement pairs takes effect.
        // Body rules only run on text; whatever happens to them, the rest of
        // the plan stands.
        let mut keep_engine = true;
        let body_mutation = if plan.rewrite.action == MitmPolicyRewriteAction::BodyMutation {
            match text_body(&http_event.body) {
                None => {
                    diagnostics.push(mitm_policy_diagnostic(
                        DiagnosticSeverity::Warning,
                        MITM_POLICY_HTTP_EVENT_BINARY_BODY_SKIPPED_CODE,
                        "body rewrite rules match, but the body is not UTF-8 text without NUL bytes, so they were skipped",
                    ));
                    None
                }
                Some(body) => match engine.apply_body_chain_whole(&http_event.url, phase, body) {
                    Ok(MitmPolicyBodyChainOutcome::Applied {
                        body: mut chained_body,
                        chain,
                        records_capped,
                    }) => {
                        if records_capped {
                            diagnostics.push(mitm_policy_diagnostic(
                                DiagnosticSeverity::Warning,
                                MITM_POLICY_HTTP_EVENT_BODY_REWRITE_RECORDS_CAPPED_CODE,
                                format!(
                                    "more than {cap} body rules match; all of them applied, but jq steps after the first {cap} matching rules did not run",
                                    cap = sys::ANIXOPS_BODY_CHAIN_CAP
                                ),
                            ));
                        }
                        let mut rewritten = chain.rewritten;
                        // The core matches jq rules but has no jq backend; jaq runs them.
                        if let Some(jq_body) =
                            loon_jq::apply_jq_steps(source, phase, &chain, &chained_body)
                        {
                            chained_body = jq_body;
                            rewritten = true;
                        }
                        (rewritten && chained_body.as_bytes() != http_event.body.as_slice()).then(
                            || HttpBodyMutation {
                                body: chained_body.into_bytes(),
                                truncated: false,
                            },
                        )
                    }
                    Ok(MitmPolicyBodyChainOutcome::Skipped { reason, .. }) => {
                        diagnostics.push(mitm_policy_diagnostic(
                            DiagnosticSeverity::Warning,
                            MITM_POLICY_HTTP_EVENT_BODY_REWRITE_SKIPPED_CODE,
                            format!("body rewrite skipped: {reason}"),
                        ));
                        None
                    }
                    Err(error) => {
                        // An engine that saw an error is not pooled again.
                        keep_engine = false;
                        diagnostics.push(mitm_policy_diagnostic(
                            DiagnosticSeverity::Warning,
                            MITM_POLICY_HTTP_EVENT_BODY_REWRITE_SKIPPED_CODE,
                            format!("body rewrite skipped: {}", error.code),
                        ));
                        None
                    }
                },
            }
        } else {
            None
        };
        let script_dispatch = domain_script_dispatch_from_policy(&plan.script);
        if keep_engine {
            engine.keep();
        }

        Ok(HttpMitmOutcome {
            action,
            header_mutations,
            body_mutation,
            script_dispatch,
            audits: vec![AuditEvent {
                actor: plugin_instance.manifest.id.clone(),
                action: "mitm.policy.plan_http_mitm_event".to_string(),
                decision: AuditDecision::Allowed,
                reason: Some(format!(
                    "request {} produced a policy mutation plan; data-plane application is deferred",
                    http_event.request_id
                )),
            }],
            diagnostics,
        })
    }

    fn evaluate_mitm_hostname(
        &self,
        plugin_instance: &PluginInstance,
        hostname: &str,
        is_quic: bool,
    ) -> DomainResult<MitmHostnameDecision> {
        let Some(source) = plugin_instance.loaded_source.as_deref() else {
            return Ok(MitmHostnameDecision::Bypass);
        };

        // The data plane asks for every TLS and QUIC host it sees, so the
        // policy is compiled once per revision, not once per host.
        let engine = HOSTNAME_ENGINES.get_or_build(source, |source| {
            let mut engine = AnixOpsMitmPolicyEngine::new()?;
            engine.load_config(source)?;
            // The data plane only asks once the operator-supplied MITM CA is
            // active, so evaluate the hostname list as trusted.
            engine.set_certificate_trust_state(CertificateTrustState::Trusted);
            Ok(policy_cache::SharedEngine::new(engine))
        })?;
        let decision = engine.with(|engine| engine.evaluate_mitm(hostname, is_quic))?;
        Ok(match decision.decision {
            MitmPolicyMitmDecisionType::Bypass => MitmHostnameDecision::Bypass,
            MitmPolicyMitmDecisionType::Intercept => MitmHostnameDecision::Intercept,
            MitmPolicyMitmDecisionType::RejectQuic => MitmHostnameDecision::RejectQuic,
        })
    }

    fn audit(&self, plugin_result: &PluginResult) -> Vec<AuditEvent> {
        plugin_result.audits.clone()
    }
}

/// The linked `mitm_anixops` core's version.
pub fn engine_version() -> &'static str {
    sys::version()
}

/// The user's own plugin text as a package that may read and change requests and responses.
pub fn user_plugin_package(source: impl Into<String>) -> PluginPackage {
    PluginPackage {
        manifest: PluginManifest {
            id: MITM_POLICY_USER_PLUGIN_ID.to_string(),
            version: "user".to_string(),
            permissions: vec![
                PluginPermission::ReadRequest,
                PluginPermission::ModifyRequest,
                PluginPermission::ReadResponse,
                PluginPermission::ModifyResponse,
            ],
            hooks: vec![HookPoint::Request, HookPoint::Response],
        },
        source: source.into(),
    }
}

pub fn mitm_policy_diagnostic(
    severity: DiagnosticSeverity,
    code: impl Into<String>,
    message: impl Into<String>,
) -> Diagnostic {
    Diagnostic::new(
        severity,
        code,
        message,
        Some(SOURCE_MITM_POLICY.to_string()),
    )
}

fn reject_error_diagnostics(diagnostics: Vec<Diagnostic>, message: &str) -> DomainResult<()> {
    if let Some(diagnostic) = diagnostics
        .iter()
        .find(|diagnostic| diagnostic.severity == DiagnosticSeverity::Error)
    {
        return Err(DomainError::new(diagnostic.code.clone(), message));
    }

    Ok(())
}

fn permission_granted(
    granted_permissions: &GrantedPermissions,
    permission: &PluginPermission,
) -> bool {
    granted_permissions
        .permissions
        .iter()
        .any(|granted| granted == permission)
}

fn policy_phase_from_domain(phase: HttpMitmPhase) -> MitmPolicyPhase {
    match phase {
        HttpMitmPhase::Request => MitmPolicyPhase::Request,
        HttpMitmPhase::Response => MitmPolicyPhase::Response,
    }
}

fn domain_phase_from_policy(phase: MitmPolicyPhase) -> HttpMitmPhase {
    match phase {
        MitmPolicyPhase::Request => HttpMitmPhase::Request,
        MitmPolicyPhase::Response => HttpMitmPhase::Response,
    }
}

fn domain_action_from_policy_rewrite(rewrite: &MitmPolicyRewriteResult) -> HttpMitmAction {
    match rewrite.action {
        MitmPolicyRewriteAction::Redirect => HttpMitmAction::Redirect {
            status_code: http_status_or(rewrite.status_code, 302),
            location: rewrite.value.clone(),
        },
        // `reject-dict`, `reject-array`, `reject-img` and `reject-video`
        // answer with a body the app can parse; the others with none.
        MitmPolicyRewriteAction::Reject => match rewrite.reject_body.content() {
            Some((content_type, body)) => HttpMitmAction::Respond {
                status_code: http_status_or(rewrite.status_code, 200),
                headers: vec![MetadataEntry {
                    key: "Content-Type".to_string(),
                    value: content_type.to_string(),
                }],
                body: body.to_vec(),
            },
            None => HttpMitmAction::Reject {
                status_code: http_status_or(rewrite.status_code, 403),
            },
        },
        _ => HttpMitmAction::Continue,
    }
}

fn http_status_or(status_code: i32, default: u16) -> u16 {
    if status_code <= 0 {
        return default;
    }

    status_code.try_into().unwrap_or(default)
}

/// The body as text the core can rewrite: UTF-8 without NUL bytes. The core
/// reads C strings, so anything else is never handed to it.
fn text_body(body: &[u8]) -> Option<&str> {
    std::str::from_utf8(body)
        .ok()
        .filter(|text| !text.contains('\0'))
}

/// The header mutations of `plan`, in rule order, for a message that carries
/// `headers`.
///
/// The plan comes from the core without header values, so a regex rule in it
/// holds only its replacement template. Each one is evaluated here against
/// every current value of its header, after the rules before it, the way the
/// core's own header-list application does. A header whose values change is
/// deleted and added back value by value, so with several `Set-Cookie`
/// headers only the matching one changes. A value the core cannot rewrite is
/// left as it is, with a warning.
fn header_mutations_from_plan(
    engine: &AnixOpsMitmPolicyEngine,
    url: &str,
    phase: MitmPolicyPhase,
    plan: &MitmPolicyRewritePlan,
    headers: &[MetadataEntry],
    diagnostics: &mut Vec<Diagnostic>,
) -> Vec<HttpHeaderMutation> {
    let mut working = headers.to_vec();
    let mut mutations = Vec::new();
    let mut skipped = false;
    for rewrite in &plan.header_rewrites {
        if rewrite.operation != MitmPolicyHeaderOperation::ReplaceRegex {
            let mutation = domain_header_mutation_from_policy(rewrite);
            apply_header_mutation(&mut working, &mutation);
            mutations.push(mutation);
            continue;
        }
        let mut changed = false;
        for header in working
            .iter_mut()
            .filter(|header| header.key.eq_ignore_ascii_case(&rewrite.header_name))
        {
            match regex_header_value(engine, url, phase, rewrite, &header.value) {
                RegexHeaderValue::Rewritten(value) => {
                    if value != header.value {
                        header.value = value;
                        changed = true;
                    }
                }
                RegexHeaderValue::Unchanged => {}
                RegexHeaderValue::Skipped => skipped = true,
            }
        }
        if !changed {
            continue;
        }
        // Deleted and added back: the data plane appends what is added, so
        // the working copy moves the header to the end as well.
        let (same, others): (Vec<MetadataEntry>, Vec<MetadataEntry>) = std::mem::take(&mut working)
            .into_iter()
            .partition(|header| header.key.eq_ignore_ascii_case(&rewrite.header_name));
        working = others;
        mutations.push(HttpHeaderMutation {
            operation: HttpHeaderMutationOperation::Delete,
            name: rewrite.header_name.clone(),
            value: None,
        });
        mutations.extend(same.iter().map(|header| HttpHeaderMutation {
            operation: HttpHeaderMutationOperation::Add,
            name: header.key.clone(),
            value: Some(header.value.clone()),
        }));
        working.extend(same);
    }
    if skipped {
        diagnostics.push(mitm_policy_diagnostic(
            DiagnosticSeverity::Warning,
            MITM_POLICY_HTTP_EVENT_HEADER_REGEX_SKIPPED_CODE,
            "a header-replace-regex rule left a header value unchanged: the rewritten value exceeds the policy core's value capacity or the value could not be read",
        ));
    }
    if plan.header_rewrite_truncated {
        diagnostics.push(mitm_policy_diagnostic(
            DiagnosticSeverity::Warning,
            MITM_POLICY_HTTP_EVENT_HEADER_REWRITES_CAPPED_CODE,
            format!(
                "more than {cap} header rules match; only the first {cap} applied",
                cap = sys::ANIXOPS_PLAN_HEADER_CAP
            ),
        ));
    }
    mutations
}

enum RegexHeaderValue {
    Rewritten(String),
    Unchanged,
    /// The core could not rewrite the value; it stays as it is.
    Skipped,
}

/// Runs the regex rule `rewrite` on one current `value` of its header.
fn regex_header_value(
    engine: &AnixOpsMitmPolicyEngine,
    url: &str,
    phase: MitmPolicyPhase,
    rewrite: &MitmPolicyHeaderRewriteResult,
    value: &str,
) -> RegexHeaderValue {
    let Ok(start_index) = usize::try_from(rewrite.rule_index) else {
        return RegexHeaderValue::Skipped;
    };
    match engine.evaluate_named_header(url, phase, start_index, &rewrite.header_name, value) {
        Ok(result)
            if result.rule_index == rewrite.rule_index
                && result.operation == MitmPolicyHeaderOperation::ReplaceRegex =>
        {
            match result.message.as_str() {
                CORE_HEADER_REWRITTEN => RegexHeaderValue::Rewritten(result.value),
                CORE_HEADER_REGEX_NOT_MATCHED => RegexHeaderValue::Unchanged,
                // "header value truncated": `result.value` is cut short.
                _ => RegexHeaderValue::Skipped,
            }
        }
        _ => RegexHeaderValue::Skipped,
    }
}

/// Applies `mutation` to `headers` the way the data plane does
/// (`engine-native`'s plain HTTP header mutation), so later rules see what
/// earlier ones left.
fn apply_header_mutation(headers: &mut Vec<MetadataEntry>, mutation: &HttpHeaderMutation) {
    let name = mutation.name.as_str();
    match (mutation.operation, mutation.value.as_ref()) {
        (HttpHeaderMutationOperation::Delete, _) => {
            headers.retain(|header| !header.key.eq_ignore_ascii_case(name))
        }
        (_, None) => {}
        (HttpHeaderMutationOperation::Add, Some(value)) => headers.push(MetadataEntry {
            key: mutation.name.clone(),
            value: value.clone(),
        }),
        (HttpHeaderMutationOperation::Replace, Some(value)) => {
            for header in headers
                .iter_mut()
                .filter(|header| header.key.eq_ignore_ascii_case(name))
            {
                header.value = value.clone();
            }
        }
        (HttpHeaderMutationOperation::Set, Some(value)) => {
            headers.retain(|header| !header.key.eq_ignore_ascii_case(name));
            headers.push(MetadataEntry {
                key: mutation.name.clone(),
                value: value.clone(),
            });
        }
    }
}

/// A header rewrite without a regex as a domain mutation. Regex rewrites go
/// through [`header_mutations_from_plan`], which has the header's values.
fn domain_header_mutation_from_policy(
    rewrite: &MitmPolicyHeaderRewriteResult,
) -> HttpHeaderMutation {
    HttpHeaderMutation {
        operation: match rewrite.operation {
            MitmPolicyHeaderOperation::Add => HttpHeaderMutationOperation::Add,
            MitmPolicyHeaderOperation::Replace | MitmPolicyHeaderOperation::ReplaceRegex => {
                HttpHeaderMutationOperation::Replace
            }
            MitmPolicyHeaderOperation::Delete => HttpHeaderMutationOperation::Delete,
            MitmPolicyHeaderOperation::Set => HttpHeaderMutationOperation::Set,
        },
        name: rewrite.header_name.clone(),
        value: if rewrite.operation == MitmPolicyHeaderOperation::Delete {
            None
        } else {
            Some(rewrite.value.clone())
        },
    }
}

fn domain_script_dispatch_from_policy(
    script: &MitmPolicyScriptDispatch,
) -> Option<HttpMitmScriptDispatch> {
    let kind = match script.kind {
        MitmPolicyScriptKind::None => return None,
        MitmPolicyScriptKind::HttpRequest => HttpMitmScriptKind::Request,
        MitmPolicyScriptKind::HttpResponse => HttpMitmScriptKind::Response,
    };

    Some(HttpMitmScriptDispatch {
        kind,
        phase: domain_phase_from_policy(script.phase),
        requires_body: script.requires_body,
        timeout_ms: script.timeout_ms,
        max_size: script.max_size,
        script_path: script.script_path.clone(),
        tag: script.tag.clone(),
        argument: script.argument.clone(),
        binary_body_mode: script.binary_body_mode,
    })
}

fn c_string(value: &str, message: &'static str) -> DomainResult<CString> {
    CString::new(value).map_err(|_| DomainError::new(MITM_POLICY_INPUT_NUL_BYTE_CODE, message))
}

fn rewrite_result_from_sys(result: &sys::AnixOpsRewriteResult) -> MitmPolicyRewriteResult {
    MitmPolicyRewriteResult {
        action: result.action.into(),
        status_code: result.status_code,
        rule_index: result.rule_index,
        matched_pattern: ffi_string(&result.matched_pattern),
        value: ffi_string(&result.value),
        message: ffi_string(&result.message),
        reject_body: MitmPolicyRejectBody::from_sys(result.action),
    }
}

fn body_rewrite_chain_from_sys(chain: &sys::AnixOpsBodyRewriteChain) -> MitmPolicyBodyRewriteChain {
    let count = chain.rewrite_count.min(sys::ANIXOPS_BODY_CHAIN_CAP);
    let rewrites = chain
        .rewrites
        .iter()
        .take(count)
        .map(rewrite_result_from_sys)
        .collect();

    MitmPolicyBodyRewriteChain {
        rewrites,
        rewritten: chain.rewritten != 0,
        truncated: chain.truncated != 0,
    }
}

fn header_rewrite_result_from_sys(
    result: &sys::AnixOpsHeaderRewriteResult,
) -> MitmPolicyHeaderRewriteResult {
    MitmPolicyHeaderRewriteResult {
        action: result.action.into(),
        operation: header_operation_from_sys(result.action),
        phase: result.phase.into(),
        rule_index: result.rule_index,
        matched_pattern: ffi_string(&result.matched_pattern),
        header_name: ffi_string(&result.header_name),
        value: ffi_string(&result.value),
        message: ffi_string(&result.message),
    }
}

fn header_operation_from_sys(action: sys::AnixOpsRewriteAction) -> MitmPolicyHeaderOperation {
    match action {
        sys::AnixOpsRewriteAction::HeaderAdd | sys::AnixOpsRewriteAction::ResponseHeaderAdd => {
            MitmPolicyHeaderOperation::Add
        }
        sys::AnixOpsRewriteAction::HeaderReplace
        | sys::AnixOpsRewriteAction::ResponseHeaderReplace => MitmPolicyHeaderOperation::Replace,
        sys::AnixOpsRewriteAction::HeaderReplaceRegex
        | sys::AnixOpsRewriteAction::ResponseHeaderReplaceRegex => {
            MitmPolicyHeaderOperation::ReplaceRegex
        }
        sys::AnixOpsRewriteAction::HeaderDel | sys::AnixOpsRewriteAction::ResponseHeaderDel => {
            MitmPolicyHeaderOperation::Delete
        }
        _ => MitmPolicyHeaderOperation::Set,
    }
}

fn header_list_to_sys(headers: &[MitmPolicyHeaderField]) -> DomainResult<sys::AnixOpsHeaderList> {
    if headers.len() > sys::ANIXOPS_HEADER_LIST_CAP {
        return Err(DomainError::new(
            MITM_POLICY_HEADER_LIST_CAPACITY_CODE,
            "mitm header list exceeds the C ABI capacity",
        ));
    }

    let mut out = empty_header_list();
    out.count = headers.len();
    for (index, field) in headers.iter().enumerate() {
        if write_str_to_buf(&mut out.fields[index].name, &field.name) {
            out.truncated = 1;
        }
        if write_str_to_buf(&mut out.fields[index].value, &field.value) {
            out.truncated = 1;
        }
    }

    Ok(out)
}

fn header_list_from_sys(headers: &sys::AnixOpsHeaderList) -> MitmPolicyHeaderList {
    let count = headers.count.min(sys::ANIXOPS_HEADER_LIST_CAP);
    let fields = headers
        .fields
        .iter()
        .take(count)
        .map(|field| MitmPolicyHeaderField {
            name: ffi_string(&field.name),
            value: ffi_string(&field.value),
        })
        .collect();

    MitmPolicyHeaderList {
        fields,
        truncated: headers.truncated != 0,
    }
}

fn script_dispatch_from_sys(result: &sys::AnixOpsScriptResult) -> MitmPolicyScriptDispatch {
    MitmPolicyScriptDispatch {
        kind: result.kind.into(),
        phase: result.phase.into(),
        requires_body: result.requires_body != 0,
        timeout_ms: result.timeout_ms,
        max_size: result.max_size,
        rule_index: result.rule_index,
        matched_pattern: ffi_string(&result.matched_pattern),
        script_path: ffi_string(&result.script_path),
        tag: ffi_string(&result.tag),
        argument: loon_syntax::decode_core_argument(&ffi_string(&result.argument)),
        message: ffi_string(&result.message),
        binary_body_mode: result.binary_body_mode != 0,
    }
}

fn rewrite_plan_from_sys(plan: &sys::AnixOpsRewritePlan) -> MitmPolicyRewritePlan {
    let count = plan.header_rewrite_count.min(sys::ANIXOPS_PLAN_HEADER_CAP);
    let header_rewrites = plan
        .header_rewrites
        .iter()
        .take(count)
        .map(header_rewrite_result_from_sys)
        .collect();

    MitmPolicyRewritePlan {
        phase: plan.phase.into(),
        body_available: plan.body_available != 0,
        requires_body: plan.requires_body != 0,
        rewrite: rewrite_result_from_sys(&plan.rewrite),
        header_rewrites,
        header_rewrite_truncated: plan.header_rewrite_truncated != 0,
        script: script_dispatch_from_sys(&plan.script),
    }
}

fn rule_diagnostic_to_domain(diagnostic: &MitmPolicyRuleDiagnostic) -> Diagnostic {
    let (severity, code) = match diagnostic.status {
        MitmPolicyRuleDiagnosticStatus::Accepted => {
            (DiagnosticSeverity::Info, MITM_POLICY_RULE_ACCEPTED_CODE)
        }
        MitmPolicyRuleDiagnosticStatus::Ignored => {
            (DiagnosticSeverity::Warning, MITM_POLICY_RULE_IGNORED_CODE)
        }
        MitmPolicyRuleDiagnosticStatus::Rejected => {
            (DiagnosticSeverity::Error, MITM_POLICY_RULE_REJECTED_CODE)
        }
    };

    mitm_policy_diagnostic(
        severity,
        code,
        format!(
            "mitm_anixops {} rule at line {} in {}: {}",
            match diagnostic.status {
                MitmPolicyRuleDiagnosticStatus::Accepted => "accepted",
                MitmPolicyRuleDiagnosticStatus::Ignored => "ignored",
                MitmPolicyRuleDiagnosticStatus::Rejected => "rejected",
            },
            diagnostic.line,
            diagnostic.section,
            diagnostic.message
        ),
    )
}

fn evaluation_error(status: c_int) -> DomainError {
    DomainError::new(
        MITM_POLICY_EVALUATION_FAILED_CODE,
        format!("mitm_anixops evaluation failed: {}", status_message(status)),
    )
}

fn status_message(status: c_int) -> String {
    let message = unsafe { CStr::from_ptr(sys::anixops_status_message(status)) };
    message.to_string_lossy().into_owned()
}

fn ffi_string(buffer: &[c_char]) -> String {
    let value = unsafe { CStr::from_ptr(buffer.as_ptr()) };
    value.to_string_lossy().into_owned()
}

fn write_str_to_buf(buffer: &mut [c_char], value: &str) -> bool {
    for slot in buffer.iter_mut() {
        *slot = 0;
    }
    if buffer.is_empty() {
        return !value.is_empty();
    }

    let bytes = value.as_bytes();
    let copy_len = bytes.len().min(buffer.len() - 1);
    for (index, byte) in bytes.iter().take(copy_len).enumerate() {
        buffer[index] = *byte as c_char;
    }

    bytes.len() >= buffer.len()
}

fn empty_rewrite_result() -> sys::AnixOpsRewriteResult {
    sys::AnixOpsRewriteResult {
        action: sys::AnixOpsRewriteAction::None,
        status_code: 0,
        rule_index: 0,
        matched_pattern: [0 as c_char; sys::ANIXOPS_PATTERN_CAP],
        value: [0 as c_char; sys::ANIXOPS_VALUE_CAP],
        message: [0 as c_char; sys::ANIXOPS_MESSAGE_CAP],
    }
}

fn empty_body_rewrite_chain() -> sys::AnixOpsBodyRewriteChain {
    sys::AnixOpsBodyRewriteChain {
        rewrite_count: 0,
        rewritten: 0,
        truncated: 0,
        rewrites: [empty_rewrite_result(); sys::ANIXOPS_BODY_CHAIN_CAP],
    }
}

fn empty_header_rewrite_result() -> sys::AnixOpsHeaderRewriteResult {
    sys::AnixOpsHeaderRewriteResult {
        action: sys::AnixOpsRewriteAction::None,
        phase: sys::AnixOpsPhase::Request,
        rule_index: 0,
        matched_pattern: [0 as c_char; sys::ANIXOPS_PATTERN_CAP],
        header_name: [0 as c_char; sys::ANIXOPS_PATTERN_CAP],
        value: [0 as c_char; sys::ANIXOPS_VALUE_CAP],
        message: [0 as c_char; sys::ANIXOPS_MESSAGE_CAP],
    }
}

fn empty_header_field() -> sys::AnixOpsHeaderField {
    sys::AnixOpsHeaderField {
        name: [0 as c_char; sys::ANIXOPS_PATTERN_CAP],
        value: [0 as c_char; sys::ANIXOPS_VALUE_CAP],
    }
}

fn empty_header_list() -> sys::AnixOpsHeaderList {
    sys::AnixOpsHeaderList {
        count: 0,
        truncated: 0,
        fields: [empty_header_field(); sys::ANIXOPS_HEADER_LIST_CAP],
    }
}

fn empty_script_result() -> sys::AnixOpsScriptResult {
    sys::AnixOpsScriptResult {
        kind: sys::AnixOpsScriptKind::None,
        phase: sys::AnixOpsPhase::Request,
        requires_body: 0,
        timeout_ms: 0,
        max_size: 0,
        rule_index: 0,
        matched_pattern: [0 as c_char; sys::ANIXOPS_PATTERN_CAP],
        script_path: [0 as c_char; sys::ANIXOPS_VALUE_CAP],
        tag: [0 as c_char; sys::ANIXOPS_VALUE_CAP],
        argument: [0 as c_char; sys::ANIXOPS_ARGUMENT_CAP],
        message: [0 as c_char; sys::ANIXOPS_MESSAGE_CAP],
        binary_body_mode: 0,
    }
}

fn empty_rewrite_plan() -> sys::AnixOpsRewritePlan {
    sys::AnixOpsRewritePlan {
        phase: sys::AnixOpsPhase::Request,
        body_available: 0,
        requires_body: 0,
        rewrite: empty_rewrite_result(),
        header_rewrite_count: 0,
        header_rewrite_truncated: 0,
        header_rewrites: [empty_header_rewrite_result(); sys::ANIXOPS_PLAN_HEADER_CAP],
        script: empty_script_result(),
    }
}
