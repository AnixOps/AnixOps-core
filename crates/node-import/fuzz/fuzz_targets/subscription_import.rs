//! Fuzzes subscription and share-link import: share links, base64 link lists,
//! Clash YAML, sing-box JSON and Surge, Loon or Quantumult X proxy lines, with
//! the routing that comes with them (`node_import::import_text`, the path a
//! pasted or downloaded subscription takes), and the routing import on its
//! own with no nodes.
//!
//! Inputs are text from outside the app; a panic or an allocation above the
//! libFuzzer RSS limit is a finding, an import error is not.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(data);
    let _ = node_import::import_text(&text);
    let _ = config_core::routing_import::import_subscription_routing(&text, &[]);
});
