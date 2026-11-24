//! Fuzzes the text formats rules arrive in: each line as a routing rule
//! (including logical `AND`/`OR`/`NOT` rules), a redirect rule and a
//! certificate pin, and the whole input as a downloaded rule set in both
//! bare-domain readings, through both rule set readers.
//!
//! A panic or an allocation above the libFuzzer RSS limit is a finding, a
//! rejected line is not.

#![no_main]

use config_core::rule_set::{BareDomain, RuleSetBuilder, RuleSetEntries};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(data);
    for line in text.lines() {
        let _ = config_core::routing::parse_rule_line(line);
        let _ = config_core::redirect::parse_redirect_line(line);
        let _ = config_core::certificate_pin::parse(line);
    }
    for bare in [BareDomain::Suffix, BareDomain::Exact] {
        let _ = RuleSetEntries::parse_list(&text, bare);
        let _ = RuleSetBuilder::parse_list(&text, bare);
    }
});
