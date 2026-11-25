//! External network bridge of the intranet mesh (spec §15.12, requirement
//! R36; kernel 0.4, capability `mesh_external_bridge`).
//!
//! A Linux full node that sits in both an external network (another overlay
//! program's network) and one of our region networks advertises chosen
//! external addresses into the region, and forwards traffic from allowed
//! members to them with its own external address as the source. The import
//! is one way: nothing of ours is announced to the external network, and
//! new connections from it into the mesh are dropped.
//!
//! - [`config`]: the `external_bridge` section and its checks.
//! - [`ruleset`]: the nftables table of one bridge.
//! - [`apply`]: installing, replacing and removing it, the IPv4 forwarding
//!   switch, alerts and drop counters.
//! - [`conntrack`]: deleting the tracked connections a narrowed or
//!   removed bridge no longer allows.
//! - [`status`]: `externalBridge` of the status API and its digests.
//! - [`lock`]: the host-wide lock that keeps a second node program from
//!   cleaning up the first one's tables.
//!
//! The mesh module itself (`outbound-mesh`) is only read from: wiring the
//! section into the network config, the route advertisement (field 5) and
//! the node program's start and stop is a separate step. See
//! `docs/architecture/mesh-bridge.md`.

pub mod apply;
pub mod config;
pub mod conntrack;
pub mod lock;
pub mod ruleset;
pub mod status;

pub use apply::{
    cleanup_all, probe, ApplyError, Bridge, BridgeAlert, Counters, Forwarding, Host, SystemHost,
};
pub use config::{BridgeError, ExternalBridge, ExternalBridgeConfig};
pub use lock::HostLock;
pub use status::BridgeStatus;

/// The capability name a kernel lists once the node program applies
/// `external_bridge` (`docs/architecture/mesh-status.md`). Linux only.
pub const FEATURE: &str = "mesh_external_bridge";
