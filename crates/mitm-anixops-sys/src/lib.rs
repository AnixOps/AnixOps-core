//! Unsafe Rust bindings for the vendored `mitm_anixops` C ABI.
//!
//! This crate deliberately exposes only the low-level ABI surface. Safe policy
//! abstractions belong in the `mitm-policy` adapter crate.
//!
//! The `#[repr(C)]` enums below are read straight out of structs the C core
//! fills in, so each one must list every enumerator of its C counterpart: a
//! value Rust does not declare is undefined behaviour. The test
//! `rust_enums_mirror_every_c_enumerator` parses the pinned
//! `mitm_anixops.h` and fails when the header and these enums drift apart.

// Keep the PCRE2 static library on the link line: only the C core calls it.
#[cfg(feature = "pcre2")]
use pcre2_sys as _;

use std::ffi::CStr;
use std::os::raw::{c_char, c_int};

pub const ANIXOPS_PATTERN_CAP: usize = 256;
pub const ANIXOPS_VALUE_CAP: usize = 2048;
pub const ANIXOPS_ARGUMENT_CAP: usize = 4096;
pub const ANIXOPS_MESSAGE_CAP: usize = 256;
pub const ANIXOPS_PLAN_HEADER_CAP: usize = 16;
pub const ANIXOPS_HEADER_LIST_CAP: usize = 32;
pub const ANIXOPS_BODY_CHAIN_CAP: usize = 16;
pub const ANIXOPS_JQ_MAX_INPUT_BYTES_DEFAULT: usize = 1_048_576;
pub const POLICY_CAPABILITY_QUERY_ABI_VERSION: u32 = 1;
pub const POLICY_CAPABILITY_MITM_DECISION: u64 = 1 << 0;
pub const POLICY_CAPABILITY_URL_REWRITE: u64 = 1 << 1;
pub const POLICY_CAPABILITY_HEADER_MUTATION: u64 = 1 << 2;
pub const POLICY_CAPABILITY_BODY_MUTATION_BYTES: u64 = 1 << 3;
pub const POLICY_CAPABILITY_SCRIPT_DISPATCH_METADATA: u64 = 1 << 4;
pub const POLICY_CAPABILITY_RULE_DIAGNOSTICS: u64 = 1 << 5;
pub const POLICY_CAPABILITY_TASK_DESCRIPTOR_METADATA: u64 = 1 << 6;
pub const POLICY_CAPABILITY_ALL_V1: u64 = POLICY_CAPABILITY_MITM_DECISION
    | POLICY_CAPABILITY_URL_REWRITE
    | POLICY_CAPABILITY_HEADER_MUTATION
    | POLICY_CAPABILITY_BODY_MUTATION_BYTES
    | POLICY_CAPABILITY_SCRIPT_DISPATCH_METADATA
    | POLICY_CAPABILITY_RULE_DIAGNOSTICS
    | POLICY_CAPABILITY_TASK_DESCRIPTOR_METADATA;

pub const ANIXOPS_OK: c_int = 0;
pub const ANIXOPS_ERR_INVALID_ARGUMENT: c_int = -1;
pub const ANIXOPS_ERR_OUT_OF_MEMORY: c_int = -2;
pub const ANIXOPS_ERR_REGEX: c_int = -3;
pub const ANIXOPS_ERR_CAPACITY: c_int = -4;
pub const ANIXOPS_ERR_PARSE: c_int = -5;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PolicyCapabilitySet(u64);

impl PolicyCapabilitySet {
    pub const fn bits(self) -> u64 {
        self.0
    }

    pub const fn supports(self, required: u64) -> bool {
        required == 0 || (self.0 & required) == required
    }

    pub const fn is_v1_compatible(self) -> bool {
        self.0 & !POLICY_CAPABILITY_ALL_V1 == 0
    }
}

#[repr(C)]
pub struct AnixOpsEngine {
    _private: [u8; 0],
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnixOpsCertState {
    Unknown = 0,
    NotInstalled = 1,
    InstalledUntrusted = 2,
    Trusted = 3,
    Revoked = 4,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnixOpsMitmDecisionType {
    Bypass = 0,
    Intercept = 1,
    RejectQuic = 2,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnixOpsMitmReason {
    None = 0,
    Disabled = 1,
    EmptyHost = 2,
    CertNotTrusted = 3,
    DenyHost = 4,
    NoHostMatch = 5,
    QuicDisabledForMitm = 6,
    Allowed = 7,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnixOpsPhase {
    Request = 0,
    Response = 1,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnixOpsCompatProfile {
    Portable = 0,
    LoonStrict = 1,
    SurgeStrict = 2,
    QuantumultXStrict = 3,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnixOpsRegexBackend {
    PosixLite = 0,
    Pcre2 = 1,
    NsRegularExpression = 2,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnixOpsRuleDiagnosticStatus {
    Accepted = 1,
    Ignored = 2,
    Rejected = 3,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnixOpsRewriteAction {
    None = 0,
    Redirect302 = 1,
    Redirect307 = 2,
    Reject = 3,
    Reject200 = 4,
    RejectImg = 5,
    RejectVideo = 6,
    RejectDict = 7,
    RejectArray = 8,
    MockRequestBody = 9,
    MockResponseBody = 10,
    RequestBodyReplaceRegex = 11,
    ResponseBodyReplaceRegex = 12,
    HeaderReplace = 13,
    HeaderAdd = 14,
    HeaderReplaceRegex = 15,
    ResponseHeaderDel = 16,
    ResponseHeaderReplace = 17,
    ResponseHeaderAdd = 18,
    ResponseHeaderReplaceRegex = 19,
    RequestBodyJsonReplace = 20,
    ResponseBodyJsonReplace = 21,
    Redirect301 = 22,
    Redirect303 = 23,
    Redirect308 = 24,
    HeaderDel = 25,
    RequestBodyJq = 26,
    ResponseBodyJq = 27,
    /// `<pattern> 200 <url>` and its `url 200` / `<url> 200` spellings: the
    /// core rewrites the request URL without answering with a redirect.
    UrlRewrite200 = 28,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnixOpsScriptKind {
    None = 0,
    HttpRequest = 1,
    HttpResponse = 2,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct AnixOpsMitmDecision {
    pub decision: AnixOpsMitmDecisionType,
    pub reason: AnixOpsMitmReason,
    pub matched_pattern: [c_char; ANIXOPS_PATTERN_CAP],
    pub message: [c_char; ANIXOPS_MESSAGE_CAP],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct AnixOpsRewriteResult {
    pub action: AnixOpsRewriteAction,
    pub status_code: c_int,
    pub rule_index: c_int,
    pub matched_pattern: [c_char; ANIXOPS_PATTERN_CAP],
    pub value: [c_char; ANIXOPS_VALUE_CAP],
    pub message: [c_char; ANIXOPS_MESSAGE_CAP],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct AnixOpsBodyRewriteChain {
    pub rewrite_count: usize,
    pub rewritten: c_int,
    pub truncated: c_int,
    pub rewrites: [AnixOpsRewriteResult; ANIXOPS_BODY_CHAIN_CAP],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct AnixOpsHeaderRewriteResult {
    pub action: AnixOpsRewriteAction,
    pub phase: AnixOpsPhase,
    pub rule_index: c_int,
    pub matched_pattern: [c_char; ANIXOPS_PATTERN_CAP],
    pub header_name: [c_char; ANIXOPS_PATTERN_CAP],
    pub value: [c_char; ANIXOPS_VALUE_CAP],
    pub message: [c_char; ANIXOPS_MESSAGE_CAP],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct AnixOpsHeaderField {
    pub name: [c_char; ANIXOPS_PATTERN_CAP],
    pub value: [c_char; ANIXOPS_VALUE_CAP],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct AnixOpsHeaderList {
    pub count: usize,
    pub truncated: c_int,
    pub fields: [AnixOpsHeaderField; ANIXOPS_HEADER_LIST_CAP],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct AnixOpsScriptResult {
    pub kind: AnixOpsScriptKind,
    pub phase: AnixOpsPhase,
    pub requires_body: c_int,
    pub timeout_ms: usize,
    pub max_size: usize,
    pub rule_index: c_int,
    pub matched_pattern: [c_char; ANIXOPS_PATTERN_CAP],
    pub script_path: [c_char; ANIXOPS_VALUE_CAP],
    pub tag: [c_char; ANIXOPS_VALUE_CAP],
    pub argument: [c_char; ANIXOPS_ARGUMENT_CAP],
    pub message: [c_char; ANIXOPS_MESSAGE_CAP],
    pub binary_body_mode: c_int,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct AnixOpsRewritePlan {
    pub phase: AnixOpsPhase,
    pub body_available: c_int,
    pub requires_body: c_int,
    pub rewrite: AnixOpsRewriteResult,
    pub header_rewrite_count: usize,
    pub header_rewrite_truncated: c_int,
    pub header_rewrites: [AnixOpsHeaderRewriteResult; ANIXOPS_PLAN_HEADER_CAP],
    pub script: AnixOpsScriptResult,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct AnixOpsRuleDiagnostic {
    pub status: AnixOpsRuleDiagnosticStatus,
    pub profile: AnixOpsCompatProfile,
    pub line: usize,
    pub section: [c_char; ANIXOPS_PATTERN_CAP],
    pub action: [c_char; ANIXOPS_PATTERN_CAP],
    pub message: [c_char; ANIXOPS_MESSAGE_CAP],
}

unsafe extern "C" {
    pub fn anixops_version() -> *const c_char;
    pub fn anixops_status_message(status: c_int) -> *const c_char;
    pub fn anixops_policy_capability_query_abi_version() -> u32;
    pub fn anixops_policy_capability_flags() -> u64;
    pub fn anixops_engine_new() -> *mut AnixOpsEngine;
    pub fn anixops_engine_free(engine: *mut AnixOpsEngine);
    pub fn anixops_engine_clear(engine: *mut AnixOpsEngine);
    pub fn anixops_engine_copy_last_error(
        engine: *const AnixOpsEngine,
        out_status: *mut c_int,
        out_line: *mut usize,
        out_message: *mut c_char,
        out_message_cap: usize,
    ) -> c_int;
    pub fn anixops_engine_set_compat_profile(
        engine: *mut AnixOpsEngine,
        profile: AnixOpsCompatProfile,
    ) -> c_int;
    pub fn anixops_engine_compat_profile(engine: *const AnixOpsEngine) -> AnixOpsCompatProfile;
    pub fn anixops_regex_backend_available(backend: AnixOpsRegexBackend) -> c_int;
    pub fn anixops_engine_set_regex_backend(
        engine: *mut AnixOpsEngine,
        backend: AnixOpsRegexBackend,
    ) -> c_int;
    pub fn anixops_engine_regex_backend(engine: *const AnixOpsEngine) -> AnixOpsRegexBackend;
    pub fn anixops_engine_set_jq_max_input_bytes(
        engine: *mut AnixOpsEngine,
        max_input_bytes: usize,
    ) -> c_int;
    pub fn anixops_engine_jq_max_input_bytes(engine: *const AnixOpsEngine) -> usize;
    pub fn anixops_engine_rule_diagnostic_count(engine: *const AnixOpsEngine) -> usize;
    pub fn anixops_engine_copy_rule_diagnostic(
        engine: *const AnixOpsEngine,
        index: usize,
        out_diagnostic: *mut AnixOpsRuleDiagnostic,
    ) -> c_int;
    pub fn anixops_engine_load_config(
        engine: *mut AnixOpsEngine,
        config_text: *const c_char,
    ) -> c_int;
    pub fn anixops_engine_add_rewrite_rule(
        engine: *mut AnixOpsEngine,
        line: *const c_char,
    ) -> c_int;
    pub fn anixops_engine_add_script_rule(engine: *mut AnixOpsEngine, line: *const c_char)
        -> c_int;
    pub fn anixops_engine_add_argument(engine: *mut AnixOpsEngine, line: *const c_char) -> c_int;
    pub fn anixops_engine_set_argument_value(
        engine: *mut AnixOpsEngine,
        name: *const c_char,
        value: *const c_char,
    ) -> c_int;
    pub fn anixops_engine_add_mitm_hostname(
        engine: *mut AnixOpsEngine,
        pattern: *const c_char,
    ) -> c_int;
    pub fn anixops_engine_set_mitm_enabled(engine: *mut AnixOpsEngine, enabled: c_int);
    pub fn anixops_engine_set_h2_mitm_enabled(engine: *mut AnixOpsEngine, enabled: c_int);
    pub fn anixops_engine_set_disable_quic_for_mitm(engine: *mut AnixOpsEngine, enabled: c_int);
    pub fn anixops_engine_set_cert_state(engine: *mut AnixOpsEngine, state: AnixOpsCertState);
    pub fn anixops_mitm_evaluate(
        engine: *const AnixOpsEngine,
        hostname: *const c_char,
        is_quic: c_int,
        out_decision: *mut AnixOpsMitmDecision,
    ) -> c_int;
    pub fn anixops_rewrite_evaluate_url(
        engine: *const AnixOpsEngine,
        url: *const c_char,
        phase: AnixOpsPhase,
        out_result: *mut AnixOpsRewriteResult,
    ) -> c_int;
    pub fn anixops_rewrite_apply_body(
        engine: *const AnixOpsEngine,
        url: *const c_char,
        phase: AnixOpsPhase,
        body: *const c_char,
        out_body: *mut c_char,
        out_body_cap: usize,
        out_result: *mut AnixOpsRewriteResult,
    ) -> c_int;
    pub fn anixops_rewrite_apply_body_chain(
        engine: *const AnixOpsEngine,
        url: *const c_char,
        phase: AnixOpsPhase,
        body: *const c_char,
        out_body: *mut c_char,
        out_body_cap: usize,
        out_chain: *mut AnixOpsBodyRewriteChain,
    ) -> c_int;
    pub fn anixops_rewrite_evaluate_header(
        engine: *const AnixOpsEngine,
        url: *const c_char,
        phase: AnixOpsPhase,
        start_index: usize,
        current_header_value: *const c_char,
        out_result: *mut AnixOpsHeaderRewriteResult,
    ) -> c_int;
    pub fn anixops_rewrite_evaluate_named_header(
        engine: *const AnixOpsEngine,
        url: *const c_char,
        phase: AnixOpsPhase,
        start_index: usize,
        header_name: *const c_char,
        current_header_value: *const c_char,
        out_result: *mut AnixOpsHeaderRewriteResult,
    ) -> c_int;
    pub fn anixops_rewrite_apply_headers(
        engine: *const AnixOpsEngine,
        url: *const c_char,
        phase: AnixOpsPhase,
        headers: *const AnixOpsHeaderList,
        out_headers: *mut AnixOpsHeaderList,
        out_plan: *mut AnixOpsRewritePlan,
    ) -> c_int;
    pub fn anixops_script_evaluate_url(
        engine: *const AnixOpsEngine,
        url: *const c_char,
        phase: AnixOpsPhase,
        out_result: *mut AnixOpsScriptResult,
    ) -> c_int;
    pub fn anixops_rewrite_build_plan(
        engine: *const AnixOpsEngine,
        url: *const c_char,
        phase: AnixOpsPhase,
        body: *const c_char,
        out_body: *mut c_char,
        out_body_cap: usize,
        current_header_value: *const c_char,
        out_plan: *mut AnixOpsRewritePlan,
    ) -> c_int;
    pub fn anixops_engine_mitm_pattern_count(engine: *const AnixOpsEngine) -> usize;
    pub fn anixops_engine_rewrite_rule_count(engine: *const AnixOpsEngine) -> usize;
    pub fn anixops_engine_script_rule_count(engine: *const AnixOpsEngine) -> usize;
    pub fn anixops_engine_argument_count(engine: *const AnixOpsEngine) -> usize;
    pub fn anixops_engine_h2_mitm_enabled(engine: *const AnixOpsEngine) -> c_int;
    pub fn anixops_engine_skip_server_cert_verify(engine: *const AnixOpsEngine) -> c_int;
}

/// Returns the version reported by the linked `mitm_anixops` C core.
pub fn version() -> &'static str {
    // SAFETY: `anixops_version` returns a non-null pointer to a static
    // NUL-terminated string owned by the C library.
    let version = unsafe { CStr::from_ptr(anixops_version()) };
    version
        .to_str()
        .expect("mitm_anixops version must be valid UTF-8")
}

/// Returns the ABI version for the released, process-global policy capability query.
pub fn policy_capability_query_abi_version() -> u32 {
    unsafe { anixops_policy_capability_query_abi_version() }
}

/// Returns the released policy capability mask reported by the linked C core.
pub fn policy_capabilities() -> PolicyCapabilitySet {
    PolicyCapabilitySet(unsafe { anixops_policy_capability_flags() })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn linked_c_core_reports_pinned_version() {
        assert_eq!(version(), "0.45.10");
    }

    #[test]
    fn linked_c_core_reports_v1_policy_capabilities() {
        assert_eq!(
            policy_capability_query_abi_version(),
            POLICY_CAPABILITY_QUERY_ABI_VERSION
        );

        let capabilities = policy_capabilities();
        assert_eq!(capabilities.bits(), POLICY_CAPABILITY_ALL_V1);
        assert!(capabilities.supports(POLICY_CAPABILITY_MITM_DECISION));
        assert!(capabilities.supports(POLICY_CAPABILITY_ALL_V1));
        assert!(!capabilities.supports(1_u64 << 63));
        assert!(capabilities.is_v1_compatible());
        assert!(!PolicyCapabilitySet(POLICY_CAPABILITY_ALL_V1 | (1_u64 << 63)).is_v1_compatible());
    }

    /// The C header the build compiles against.
    const HEADER: &str =
        include_str!("../../../third_party/mitm_anixops/mitm_anixops/include/mitm_anixops.h");

    /// `NAME = value` enumerators of `typedef enum <name> { ... }` in the header.
    fn c_enumerators(name: &str) -> Vec<(String, i64)> {
        let opening = format!("typedef enum {name} {{");
        let start = HEADER
            .find(&opening)
            .unwrap_or_else(|| panic!("mitm_anixops.h declares no enum {name}"))
            + opening.len();
        let end = start
            + HEADER[start..]
                .find('}')
                .unwrap_or_else(|| panic!("enum {name} is not closed"));
        HEADER[start..end]
            .split(',')
            .map(str::trim)
            .filter(|item| !item.is_empty())
            .map(|item| {
                let (enumerator, value) = item
                    .split_once('=')
                    .unwrap_or_else(|| panic!("enumerator without a value in {name}: {item}"));
                let value = value
                    .trim()
                    .parse::<i64>()
                    .unwrap_or_else(|_| panic!("enumerator value is not a number: {item}"));
                (enumerator.trim().to_string(), value)
            })
            .collect()
    }

    /// `#define NAME value` of the header.
    fn c_define(name: &str) -> u64 {
        HEADER
            .lines()
            .find_map(|line| {
                let rest = line.trim().strip_prefix("#define ")?;
                let (defined, value) = rest.split_once(char::is_whitespace)?;
                (defined == name).then(|| value.trim().trim_end_matches('u'))
            })
            .unwrap_or_else(|| panic!("mitm_anixops.h does not define {name}"))
            .parse()
            .unwrap_or_else(|_| panic!("{name} is not a plain number"))
    }

    fn assert_mirrors(c_enum: &str, rust: &[(i64, &str)]) {
        let c = c_enumerators(c_enum);
        for (value, name) in rust {
            let declared = c
                .iter()
                .find(|(enumerator, _)| enumerator == name)
                .unwrap_or_else(|| panic!("{c_enum} has no enumerator {name}"));
            assert_eq!(declared.1, *value, "{c_enum}::{name}");
        }
        for (enumerator, value) in &c {
            assert!(
                rust.iter().any(|(_, name)| name == enumerator),
                "{c_enum}::{enumerator} = {value} has no Rust variant: reading it is undefined behaviour"
            );
        }
        assert_eq!(c.len(), rust.len(), "{c_enum} enumerator count");
    }

    /// Lists every variant of `$rust` with its C enumerator. The `match` has
    /// no wildcard, so a Rust variant without a C name does not compile;
    /// `assert_mirrors` catches a C enumerator without a Rust variant.
    macro_rules! assert_enum_mirrors {
        ($rust:ident, $c_enum:literal, [$($variant:ident => $c_name:literal),+ $(,)?]) => {{
            fn c_name(value: $rust) -> &'static str {
                match value {
                    $($rust::$variant => $c_name),+
                }
            }
            let rust = [$(($rust::$variant as i64, c_name($rust::$variant))),+];
            assert_mirrors($c_enum, &rust);
        }};
    }

    #[test]
    fn rust_enums_mirror_every_c_enumerator() {
        assert_enum_mirrors!(AnixOpsCertState, "anixops_cert_state", [
            Unknown => "ANIXOPS_CERT_UNKNOWN",
            NotInstalled => "ANIXOPS_CERT_NOT_INSTALLED",
            InstalledUntrusted => "ANIXOPS_CERT_INSTALLED_UNTRUSTED",
            Trusted => "ANIXOPS_CERT_TRUSTED",
            Revoked => "ANIXOPS_CERT_REVOKED",
        ]);
        assert_enum_mirrors!(AnixOpsMitmDecisionType, "anixops_mitm_decision_type", [
            Bypass => "ANIXOPS_MITM_BYPASS",
            Intercept => "ANIXOPS_MITM_INTERCEPT",
            RejectQuic => "ANIXOPS_MITM_REJECT_QUIC",
        ]);
        assert_enum_mirrors!(AnixOpsMitmReason, "anixops_mitm_reason", [
            None => "ANIXOPS_MITM_REASON_NONE",
            Disabled => "ANIXOPS_MITM_REASON_DISABLED",
            EmptyHost => "ANIXOPS_MITM_REASON_EMPTY_HOST",
            CertNotTrusted => "ANIXOPS_MITM_REASON_CERT_NOT_TRUSTED",
            DenyHost => "ANIXOPS_MITM_REASON_DENY_HOST",
            NoHostMatch => "ANIXOPS_MITM_REASON_NO_HOST_MATCH",
            QuicDisabledForMitm => "ANIXOPS_MITM_REASON_QUIC_DISABLED_FOR_MITM",
            Allowed => "ANIXOPS_MITM_REASON_ALLOWED",
        ]);
        assert_enum_mirrors!(AnixOpsPhase, "anixops_phase", [
            Request => "ANIXOPS_PHASE_REQUEST",
            Response => "ANIXOPS_PHASE_RESPONSE",
        ]);
        assert_enum_mirrors!(AnixOpsCompatProfile, "anixops_compat_profile", [
            Portable => "ANIXOPS_COMPAT_PORTABLE",
            LoonStrict => "ANIXOPS_COMPAT_LOON_STRICT",
            SurgeStrict => "ANIXOPS_COMPAT_SURGE_STRICT",
            QuantumultXStrict => "ANIXOPS_COMPAT_QUANTUMULTX_STRICT",
        ]);
        assert_enum_mirrors!(AnixOpsRegexBackend, "anixops_regex_backend", [
            PosixLite => "ANIXOPS_REGEX_BACKEND_POSIX_LITE",
            Pcre2 => "ANIXOPS_REGEX_BACKEND_PCRE2",
            NsRegularExpression => "ANIXOPS_REGEX_BACKEND_NSREGULAR_EXPRESSION",
        ]);
        assert_enum_mirrors!(AnixOpsRuleDiagnosticStatus, "anixops_rule_diagnostic_status", [
            Accepted => "ANIXOPS_RULE_DIAGNOSTIC_ACCEPTED",
            Ignored => "ANIXOPS_RULE_DIAGNOSTIC_IGNORED",
            Rejected => "ANIXOPS_RULE_DIAGNOSTIC_REJECTED",
        ]);
        assert_enum_mirrors!(AnixOpsRewriteAction, "anixops_rewrite_action", [
            None => "ANIXOPS_REWRITE_NONE",
            Redirect302 => "ANIXOPS_REWRITE_REDIRECT_302",
            Redirect307 => "ANIXOPS_REWRITE_REDIRECT_307",
            Reject => "ANIXOPS_REWRITE_REJECT",
            Reject200 => "ANIXOPS_REWRITE_REJECT_200",
            RejectImg => "ANIXOPS_REWRITE_REJECT_IMG",
            RejectVideo => "ANIXOPS_REWRITE_REJECT_VIDEO",
            RejectDict => "ANIXOPS_REWRITE_REJECT_DICT",
            RejectArray => "ANIXOPS_REWRITE_REJECT_ARRAY",
            MockRequestBody => "ANIXOPS_REWRITE_MOCK_REQUEST_BODY",
            MockResponseBody => "ANIXOPS_REWRITE_MOCK_RESPONSE_BODY",
            RequestBodyReplaceRegex => "ANIXOPS_REWRITE_REQUEST_BODY_REPLACE_REGEX",
            ResponseBodyReplaceRegex => "ANIXOPS_REWRITE_RESPONSE_BODY_REPLACE_REGEX",
            HeaderReplace => "ANIXOPS_REWRITE_HEADER_REPLACE",
            HeaderAdd => "ANIXOPS_REWRITE_HEADER_ADD",
            HeaderReplaceRegex => "ANIXOPS_REWRITE_HEADER_REPLACE_REGEX",
            ResponseHeaderDel => "ANIXOPS_REWRITE_RESPONSE_HEADER_DEL",
            ResponseHeaderReplace => "ANIXOPS_REWRITE_RESPONSE_HEADER_REPLACE",
            ResponseHeaderAdd => "ANIXOPS_REWRITE_RESPONSE_HEADER_ADD",
            ResponseHeaderReplaceRegex => "ANIXOPS_REWRITE_RESPONSE_HEADER_REPLACE_REGEX",
            RequestBodyJsonReplace => "ANIXOPS_REWRITE_REQUEST_BODY_JSON_REPLACE",
            ResponseBodyJsonReplace => "ANIXOPS_REWRITE_RESPONSE_BODY_JSON_REPLACE",
            Redirect301 => "ANIXOPS_REWRITE_REDIRECT_301",
            Redirect303 => "ANIXOPS_REWRITE_REDIRECT_303",
            Redirect308 => "ANIXOPS_REWRITE_REDIRECT_308",
            HeaderDel => "ANIXOPS_REWRITE_HEADER_DEL",
            RequestBodyJq => "ANIXOPS_REWRITE_REQUEST_BODY_JQ",
            ResponseBodyJq => "ANIXOPS_REWRITE_RESPONSE_BODY_JQ",
            UrlRewrite200 => "ANIXOPS_REWRITE_URL_REWRITE_200",
        ]);
        assert_enum_mirrors!(AnixOpsScriptKind, "anixops_script_kind", [
            None => "ANIXOPS_SCRIPT_NONE",
            HttpRequest => "ANIXOPS_SCRIPT_HTTP_REQUEST",
            HttpResponse => "ANIXOPS_SCRIPT_HTTP_RESPONSE",
        ]);

        let statuses = c_enumerators("anixops_status");
        for (name, value) in [
            ("ANIXOPS_OK", ANIXOPS_OK),
            ("ANIXOPS_ERR_INVALID_ARGUMENT", ANIXOPS_ERR_INVALID_ARGUMENT),
            ("ANIXOPS_ERR_OUT_OF_MEMORY", ANIXOPS_ERR_OUT_OF_MEMORY),
            ("ANIXOPS_ERR_REGEX", ANIXOPS_ERR_REGEX),
            ("ANIXOPS_ERR_CAPACITY", ANIXOPS_ERR_CAPACITY),
            ("ANIXOPS_ERR_PARSE", ANIXOPS_ERR_PARSE),
        ] {
            assert!(
                statuses.contains(&(name.to_string(), i64::from(value))),
                "{name} = {value} does not match the header"
            );
        }
        assert_eq!(statuses.len(), 6, "anixops_status gained a code");
    }

    #[test]
    fn buffer_capacities_match_the_c_header() {
        for (name, value) in [
            ("ANIXOPS_PATTERN_CAP", ANIXOPS_PATTERN_CAP),
            ("ANIXOPS_VALUE_CAP", ANIXOPS_VALUE_CAP),
            ("ANIXOPS_ARGUMENT_CAP", ANIXOPS_ARGUMENT_CAP),
            ("ANIXOPS_MESSAGE_CAP", ANIXOPS_MESSAGE_CAP),
            ("ANIXOPS_PLAN_HEADER_CAP", ANIXOPS_PLAN_HEADER_CAP),
            ("ANIXOPS_HEADER_LIST_CAP", ANIXOPS_HEADER_LIST_CAP),
            ("ANIXOPS_BODY_CHAIN_CAP", ANIXOPS_BODY_CHAIN_CAP),
            (
                "ANIXOPS_JQ_MAX_INPUT_BYTES_DEFAULT",
                ANIXOPS_JQ_MAX_INPUT_BYTES_DEFAULT,
            ),
        ] {
            assert_eq!(c_define(name), value as u64, "{name}");
        }
    }

    #[test]
    fn url_rewrite_200_rules_report_their_own_action() {
        let config = std::ffi::CString::new(concat!(
            "[Rewrite]\n",
            "^https://old\\.example\\.test/(.*) https://new.example.test/$1 200\n",
        ))
        .expect("fixture must not contain nul bytes");
        let url = std::ffi::CString::new("https://old.example.test/page")
            .expect("fixture must not contain nul bytes");

        // SAFETY: as above; the result struct is fully written by the C core
        // before it is read, and every value it writes is a declared variant.
        unsafe {
            let engine = anixops_engine_new();
            assert!(!engine.is_null());
            assert_eq!(
                anixops_engine_load_config(engine, config.as_ptr()),
                ANIXOPS_OK
            );
            let mut result = std::mem::MaybeUninit::<AnixOpsRewriteResult>::uninit();
            assert_eq!(
                anixops_rewrite_evaluate_url(
                    engine,
                    url.as_ptr(),
                    AnixOpsPhase::Request,
                    result.as_mut_ptr()
                ),
                ANIXOPS_OK
            );
            let action = std::ptr::addr_of!((*result.as_ptr()).action)
                .cast::<std::os::raw::c_int>()
                .read();
            anixops_engine_free(engine);
            assert_eq!(
                action,
                AnixOpsRewriteAction::UrlRewrite200 as std::os::raw::c_int
            );
        }
    }

    #[test]
    fn low_level_engine_loads_minimal_config() {
        let config = std::ffi::CString::new(concat!(
            "[URL Rewrite]\n",
            "^https://ads\\.example\\.test reject\n",
            "[MITM]\n",
            "hostname = ads.example.test\n",
        ))
        .expect("fixture must not contain nul bytes");

        // SAFETY: the C engine pointer is checked for null, the config is a
        // valid NUL-terminated string, and the engine is freed exactly once.
        unsafe {
            let engine = anixops_engine_new();
            assert!(!engine.is_null());
            assert_eq!(
                anixops_engine_load_config(engine, config.as_ptr()),
                ANIXOPS_OK
            );
            assert_eq!(anixops_engine_rewrite_rule_count(engine), 1);
            assert_eq!(anixops_engine_mitm_pattern_count(engine), 1);
            anixops_engine_free(engine);
        }
    }
}
