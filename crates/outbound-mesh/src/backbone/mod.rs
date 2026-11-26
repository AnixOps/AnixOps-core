//! The inter-region backbone between border nodes (spec §15.6, §17.3 and
//! `docs/protocols/intranet-mesh-appendix.md` A–C), without I/O.
//!
//! - [`region`]: region IDs, summary prefixes and the longest-prefix table.
//! - [`msg`]: the messages of the links' reliable channel.
//! - [`config`]: the border node's `backbone` section.
//! - [`metrics`]: probes, per-field link metrics, cost and stability.
//! - [`topology`]: received region adverts and link states.
//! - [`select`]: path choice per foreign prefix with region policy and
//!   hysteresis.
//! - [`forward`]: what to do with each IP packet, and the links' receive
//!   policy.
//! - [`engine`]: one border node's backbone tying these together.
//!
//! Backbone links themselves (transport, encryption, forward secrecy) are
//! provided through `engine-outbound::backbone` by private builds; this
//! module only sees their reports and their two channels.

pub mod config;
pub mod engine;
pub mod forward;
pub mod metrics;
pub mod msg;
pub mod region;
pub mod select;
pub mod topology;

/// A member's backbone ID, assigned by the panel; 0 is never used.
pub type BackboneId = u32;

pub use config::{BackboneConfig, BackboneSettings, ConfigError};
pub use engine::{Backbone, Output, Status};
pub use forward::{DropReason, Verdict};
pub use metrics::LinkReport;
pub use region::RegionId;

#[cfg(test)]
pub(crate) mod testutil {
    use super::config::{BackboneConfig, BackboneSettings};
    use super::region::{parse_summary_prefix, RegionId};
    use crate::net::IpNet;

    pub fn net(text: &str) -> IpNet {
        parse_summary_prefix(text).unwrap()
    }

    pub fn rid(text: &str) -> RegionId {
        RegionId::parse(text).unwrap()
    }

    pub fn settings_json(value: serde_json::Value) -> BackboneSettings {
        let config: BackboneConfig = serde_json::from_value(value).unwrap();
        config.validate().unwrap()
    }

    /// This node 11 in eu; 12 eu, 21/22 ap, 31 cn.
    pub fn settings() -> BackboneSettings {
        settings_json(serde_json::json!({
            "id": 11,
            "region": "eu",
            "members": [
                { "id": 11, "region": "eu", "link": { "kind": "k" } },
                { "id": 12, "region": "eu", "link": { "kind": "k" } },
                { "id": 21, "region": "ap", "link": { "kind": "k" } },
                { "id": 22, "region": "ap", "link": { "kind": "k" } },
                { "id": 31, "region": "cn", "link": { "kind": "k" } }
            ]
        }))
    }
}
