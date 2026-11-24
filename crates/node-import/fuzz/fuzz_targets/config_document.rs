//! Fuzzes the NetworkCore TOML config document parser
//! (`config_core::parse_config_document`): profiles, listeners, nodes,
//! routes, rules and policy groups.
//!
//! A panic or an allocation above the libFuzzer RSS limit is a finding, a
//! rejected document is not.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(data);
    let _ = config_core::parse_config_document(&text);
});
