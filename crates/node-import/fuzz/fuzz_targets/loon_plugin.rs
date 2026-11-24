//! Fuzzes Loon plugin import (`mitm_policy::loon_plugin::import_loon_plugin`): sections,
//! rules, rewrites, header and body edits, Map Local, scripts and MITM host
//! lists, with the HTTP rewrite lines the MITM core grades.
//!
//! A panic or an allocation above the libFuzzer RSS limit is a finding, a
//! rejected or partly unsupported plugin is not.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(data);
    let _ = mitm_policy::loon_plugin::import_loon_plugin(&text);
});
