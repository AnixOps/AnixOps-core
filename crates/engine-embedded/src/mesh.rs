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
//!
//! The `mesh_*` commands of `mesh-status.md` reach the engine through any
//! runtime's control channel ([`outbound_mesh::outbound::control`]).
//! `mesh_save_network` and `mesh_join` start the engine when none runs; the
//! runtime that answered them then holds it until it stops, so that a
//! network saved while only the proxy runs keeps running.

use std::sync::{Arc, Mutex, MutexGuard};

use engine_outbound::registry::OutboundRegistry;
use outbound_mesh::outbound::control;
use outbound_mesh::outbound::engine::{EngineHold, EngineSlot, GRACE};
use outbound_mesh::outbound::MeshFactory;
use outbound_mesh::{MeshSettings, TYPE_NAME};
use serde_json::{json, Value};

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

    /// Answers a `mesh_*` request; `None` for any other request.
    ///
    /// `{"cmd": "mesh_engine_stop"}`: the user closed the VPN; lets go of
    /// the engine and stops it at once unless another runtime holds it
    /// (`stopped` says whether it stopped).
    pub(crate) fn control(&self, request: &[u8]) -> Option<Result<Vec<u8>, RuntimeError>> {
        // Cheap test before parsing: every mesh command names itself.
        if !contains(request, b"mesh_") {
            return None;
        }
        let value: Value = serde_json::from_slice(request).ok()?;
        if value.get("cmd").and_then(Value::as_str) == Some("mesh_engine_stop") {
            if let Some(hold) = lock(&self.hold).take() {
                hold.close();
            }
            let stopped = SLOT.current().is_none();
            return Some(encode(&json!({"ok": true, "stopped": stopped})));
        }
        let request = control::parse(&value)?;
        let engine = match &request {
            control::Request::Command(command) if command.starts_engine() => self.engine(),
            _ => SLOT.current(),
        };
        let answer = control::answer(request, engine.as_deref().map(|engine| engine.registry()));
        Some(encode(&answer))
    }

    /// The running engine, started and held by this runtime when none runs
    /// or this runtime does not hold it yet; `None` when it cannot start.
    fn engine(&self) -> Option<Arc<outbound_mesh::outbound::engine::MeshEngine>> {
        let mut hold = lock(&self.hold);
        if hold.is_none() {
            *hold = SLOT.acquire().ok();
        }
        hold.as_ref().map(|hold| hold.engine().clone())
    }
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

fn encode(answer: &Value) -> Result<Vec<u8>, RuntimeError> {
    serde_json::to_vec(answer).map_err(|_| {
        RuntimeError::new(
            RuntimeErrorCode::InternalError,
            "mesh answer could not be encoded",
        )
    })
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

        // The mesh commands reach the engine through any runtime.
        let ask = |binding: &MeshBinding, request: Value| -> Value {
            let answer = binding
                .control(request.to_string().as_bytes())
                .expect("a mesh command")
                .unwrap();
            serde_json::from_slice(&answer).unwrap()
        };
        let status = ask(&first, json!({"cmd": "mesh_status"}));
        assert_eq!(status["network"]["id"], "embedded-office");
        let left = ask(
            &first,
            json!({"cmd": "mesh_leave", "network": "embedded-office"}),
        );
        assert_eq!(left, json!({"ok": true}));
        assert!(instance.is_retired());
        // A later profile does not join it again.
        second.commit();
        let status = ask(&second, json!({"cmd": "mesh_status"}));
        assert_eq!(status["network"]["state"], "not_joined");
        let joined = ask(
            &second,
            json!({"cmd": "mesh_join", "network": "embedded-office"}),
        );
        assert_eq!(joined, json!({"ok": true}));
        let instance = engine.registry().networks()[0]
            .instance
            .clone()
            .expect("the network runs again");
        let unsupported = ask(&second, json!({"cmd": "mesh_set_paths", "network": "x"}));
        assert_eq!(unsupported["error"]["code"], "unsupported");

        // A profile naming another device ID than the running network is
        // refused when built.
        let mut other = outbound_settings("10.161.0.2/24");
        other.insert(
            "network".into(),
            json!({"name": "lab", "secret": "s3cr3t", "kind": "legacy"}),
        );
        other.insert(
            "node".into(),
            json!({"address": "10.161.0.2/24", "role": "access", "instance_id": "device-2"}),
        );
        let third = MeshBinding::default();
        assert!(third
            .bind(&detached)
            .build(TYPE_NAME, &other, Arc::new(TcpDialer))
            .is_err());
        // The user closes the VPN: the engine stops at once.
        let answer = second.control(br#"{"cmd":"mesh_engine_stop"}"#).unwrap();
        let answer: Value = serde_json::from_slice(&answer.unwrap()).unwrap();
        assert_eq!(answer, json!({"ok": true, "stopped": true}));
        assert!(engine.is_stopped());
        assert!(instance.is_retired());
        assert!(SLOT.current().is_none());

        // Saving a network starts the engine; the runtime that answered
        // holds it until it lets go.
        let status = ask(&third, json!({"cmd": "mesh_status"}));
        assert_eq!(status["networks"], json!([]));
        assert!(SLOT.current().is_none());
        let saved = ask(
            &third,
            json!({"cmd": "mesh_save_network", "config": Value::Object(outbound_settings("10.160.0.2/24"))}),
        );
        assert_eq!(saved, json!({"ok": true}));
        let engine = SLOT.current().expect("saving started the engine");
        let answer = ask(&third, json!({"cmd": "mesh_engine_stop"}));
        assert_eq!(answer, json!({"ok": true, "stopped": true}));
        assert!(engine.is_stopped());
    }
}
