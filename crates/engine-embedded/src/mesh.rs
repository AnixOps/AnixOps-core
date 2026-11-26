//! The embedded engine's side of the mesh engine (`mesh-status.md`,
//! 隧道生命周期): each runtime builds its `"type": "mesh"` outbounds bound to
//! the process's [`EngineSlot`], commits the networks of its profile once
//! its tunnel runs, and holds the mesh engine until it stops. A new profile
//! takes the engine over within the grace period, so networks whose
//! settings did not change keep their sessions; `mesh_engine_stop` lets go
//! at once when the user closes the VPN.
//!
//! Delay tests and checkups build their outbounds from the default registry,
//! whose mesh factory is detached: their mesh outbounds answer
//! `unsupported` and never start or replace a network.

use std::sync::{Arc, Mutex, MutexGuard};

use engine_outbound::registry::OutboundRegistry;
use outbound_mesh::outbound::engine::{EngineHold, EngineSlot, GRACE};
use outbound_mesh::outbound::MeshFactory;
use outbound_mesh::{MeshSettings, TYPE_NAME};
use serde::Deserialize;
use serde_json::json;

use crate::{RuntimeError, RuntimeErrorCode};

/// The mesh engine of this process.
static SLOT: EngineSlot = EngineSlot::new(GRACE);

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// One runtime's link to the mesh engine.
#[derive(Default)]
pub(crate) struct MeshBinding {
    /// The settings of every mesh outbound the runtime's profile built.
    built: Arc<Mutex<Vec<MeshSettings>>>,
    /// Held from the tunnel's start to its stop.
    hold: Mutex<Option<EngineHold>>,
}

#[derive(Deserialize)]
#[serde(tag = "cmd")]
enum MeshControl {
    #[serde(rename = "mesh_engine_stop")]
    EngineStop,
}

impl MeshBinding {
    /// `registry` with its mesh factory bound to the engine, when it has
    /// one: a registry without mesh support stays without it.
    pub(crate) fn bind(&self, registry: &OutboundRegistry) -> OutboundRegistry {
        let mut bound = registry.clone();
        if bound.contains(TYPE_NAME) {
            bound.register(Arc::new(MeshFactory::bound(&SLOT, self.built.clone())));
        }
        bound
    }

    /// Commits the profile's networks, after the tunnel started: the
    /// profile is adopted only then. A profile without mesh outbounds
    /// stops the networks of the previous one (unless saved with
    /// `mesh_save_network`) without holding the engine.
    pub(crate) fn commit(&self) {
        let networks = lock(&self.built).clone();
        if networks.is_empty() {
            if let Some(engine) = SLOT.current() {
                engine.registry().commit(Vec::new());
            }
            return;
        }
        let mut hold = lock(&self.hold);
        if hold.is_none() {
            // Without a thread for the engine the mesh outbounds report
            // that it is not running; the tunnel runs regardless.
            *hold = SLOT.acquire().ok();
        }
        if let Some(hold) = &*hold {
            hold.engine().registry().commit(networks);
        }
    }

    /// Lets go of the engine when the tunnel stops: it stops after the
    /// grace period unless another profile takes it over.
    pub(crate) fn release(&self) {
        lock(&self.hold).take();
    }

    /// `{"cmd": "mesh_engine_stop"}`: the user closed the VPN; lets go of
    /// the engine and stops it at once unless another runtime holds it.
    pub(crate) fn control(&self, request: &[u8]) -> Option<Result<Vec<u8>, RuntimeError>> {
        if request.len() > 256 {
            return None;
        }
        let MeshControl::EngineStop = serde_json::from_slice(request).ok()?;
        if let Some(hold) = lock(&self.hold).take() {
            hold.close();
        }
        Some(serde_json::to_vec(&json!({"ok": true})).map_err(|_| {
            RuntimeError::new(
                RuntimeErrorCode::InternalError,
                "mesh answer could not be encoded",
            )
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use engine_outbound::TcpDialer;

    fn outbound_settings(address: &str) -> engine_outbound::registry::Settings {
        json!({
            "config_version": 1,
            "network": {"name": "embedded-office", "secret": "s3cr3t", "kind": "legacy"},
            "node": {"address": address, "role": "access"},
            "peers": [{"server": "127.0.0.1", "port": 1}],
        })
        .as_object()
        .unwrap()
        .clone()
    }

    /// One test for the process's engine slot, so that no other test
    /// shares it.
    #[test]
    fn a_profile_commits_its_networks_and_closing_the_vpn_stops_them() {
        // The default registry (delay tests, checkups) builds nothing that
        // reaches a network, and starts nothing.
        let detached = crate::protocols::default_registry();
        let _ = detached
            .build(
                TYPE_NAME,
                &outbound_settings("10.160.0.2/24"),
                Arc::new(TcpDialer),
            )
            .unwrap();
        assert!(SLOT.current().is_none());

        let first = MeshBinding::default();
        let registry = first.bind(&detached);
        registry
            .build(
                TYPE_NAME,
                &outbound_settings("10.160.0.2/24"),
                Arc::new(TcpDialer),
            )
            .unwrap();
        // Built, not adopted.
        assert!(SLOT.current().is_none());
        first.commit();
        let engine = SLOT.current().expect("the engine runs");
        let instance = engine.registry().networks()[0]
            .instance
            .clone()
            .expect("the network runs");

        // The next profile keeps the network as it is, whichever runtime
        // stops first.
        let second = MeshBinding::default();
        second
            .bind(&detached)
            .build(
                TYPE_NAME,
                &outbound_settings("10.160.0.2/24"),
                Arc::new(TcpDialer),
            )
            .unwrap();
        first.release();
        second.commit();
        assert!(!instance.is_retired());
        assert!(Arc::ptr_eq(
            &instance,
            engine.registry().networks()[0].instance.as_ref().unwrap()
        ));

        // A request for another command is not the mesh's.
        assert!(second.control(br#"{"cmd":"traffic"}"#).is_none());
        // The user closes the VPN: the engine stops at once.
        let answer = second.control(br#"{"cmd":"mesh_engine_stop"}"#).unwrap();
        assert_eq!(answer.unwrap(), br#"{"ok":true}"#);
        assert!(engine.is_stopped());
        assert!(instance.is_retired());
        assert!(SLOT.current().is_none());
    }
}
