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

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

use engine_outbound::registry::OutboundRegistry;
use outbound_mesh::outbound::control;
use outbound_mesh::outbound::engine::{EngineHold, EngineSlot, MeshEngine, GRACE};
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
    /// Set once the runtime stopped: no command makes it hold the engine
    /// again, so that a host that stopped the tunnel but keeps the runtime
    /// cannot keep the mesh running with the VPN closed.
    stopped: AtomicBool,
}

/// The registry of an engine a runtime looked up for a command.
struct Engine(Arc<MeshEngine>);

impl std::ops::Deref for Engine {
    type Target = outbound_mesh::outbound::registry::Registry;

    fn deref(&self) -> &Self::Target {
        self.0.registry()
    }
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
    ///
    /// Only the runtime of the profile the user runs may call it: a
    /// runtime started for anything else in the same process (a
    /// diagnostic, say) would stop every network that profile did not
    /// list, and saved networks of another device ID than its own. Today only the iOS bridge creates runtimes, one per profile.
    pub(crate) fn commit(&self) {
        // The tunnel runs (again): a runtime started after a stop may hold
        // the engine once more.
        self.stopped.store(false, Ordering::SeqCst);
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
        self.stopped.store(true, Ordering::SeqCst);
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
        let name = control::command_name(request)?;
        if name == "mesh_engine_stop" {
            if let Some(hold) = lock(&self.hold).take() {
                hold.close();
            }
            let stopped = SLOT.current().is_none();
            return Some(encode(&json!({"ok": true, "stopped": stopped})));
        }
        let request = control::parse(request)?;
        // The engine is looked up once the arguments are checked: a
        // malformed `mesh_save_network` starts nothing.
        let answer = control::answer_with(request, |starts| {
            if !starts {
                return SLOT.current().map(Engine);
            }
            // The engine this runtime held stopped meanwhile (the user
            // closed the VPN through another runtime): start a new one,
            // once.
            let engine = match self.engine() {
                Some(engine) if engine.is_stopped() => {
                    lock(&self.hold).take();
                    self.engine()
                }
                engine => engine,
            };
            engine.map(Engine)
        });
        Some(encode(&answer))
    }

    /// The running engine, started and held by this runtime when none runs
    /// or this runtime does not hold it yet; `None` when it cannot start or
    /// the runtime stopped.
    fn engine(&self) -> Option<Arc<MeshEngine>> {
        if self.stopped.load(Ordering::SeqCst) {
            return None;
        }
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
        // A stopped runtime does not hold the engine again.
        let refused: Value = serde_json::from_slice(
            &first
                .control(
                    json!({"cmd": "mesh_join", "network": "embedded-office"})
                        .to_string()
                        .as_bytes(),
                )
                .expect("a mesh command")
                .unwrap(),
        )
        .unwrap();
        assert_eq!(refused["error"]["code"], "engine_unavailable");
        assert!(lock(&first.hold).is_none());
        assert!(first.control(br#"["mesh_engine_stop"]"#).is_none());
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

        // A profile whose networks name different device IDs is refused
        // when built; building does not look at the running networks.
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
        let registry = third.bind(&detached);
        assert!(registry
            .build(TYPE_NAME, &other, Arc::new(TcpDialer))
            .is_ok());
        assert!(registry
            .build(
                TYPE_NAME,
                &outbound_settings("10.160.0.2/24"),
                Arc::new(TcpDialer)
            )
            .is_err());
        lock(&third.built).clear();
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

        // A malformed config is refused before the engine is looked at:
        // it starts nothing, and a stopped runtime refuses it alike.
        let mut bad = outbound_settings("10.160.0.2/24");
        bad.insert(
            "node".into(),
            json!({"address": "not an address", "role": "access"}),
        );
        let save_bad = json!({"cmd": "mesh_save_network", "config": Value::Object(bad)});
        for binding in [&third, &first] {
            let refused = ask(binding, save_bad.clone());
            assert_eq!(refused["error"]["code"], "invalid_argument");
            assert!(SLOT.current().is_none());
        }

        // The new profile starts before the old one stops: the network
        // keeps running.
        let fourth = MeshBinding::default();
        let fifth = MeshBinding::default();
        for binding in [&fourth, &fifth] {
            binding
                .bind(&detached)
                .build(
                    TYPE_NAME,
                    &outbound_settings("10.160.0.2/24"),
                    Arc::new(TcpDialer),
                )
                .unwrap();
        }
        fourth.commit();
        let engine = SLOT.current().expect("the engine runs");
        let instance = engine.registry().networks()[0]
            .instance
            .clone()
            .expect("the network runs");
        fifth.commit();
        fourth.release();
        assert!(!instance.is_retired());
        assert!(Arc::ptr_eq(
            &instance,
            engine.registry().networks()[0].instance.as_ref().unwrap()
        ));

        // A profile without mesh outbounds stops the networks it does not
        // list, without holding the engine.
        let proxy_only = MeshBinding::default();
        proxy_only.commit();
        assert!(instance.is_retired());
        assert!(engine.registry().networks().is_empty());
        assert!(lock(&proxy_only.hold).is_none());
        assert!(!engine.is_stopped());

        // A runtime whose tunnel starts again after a stop holds the
        // engine again, and its commands may start networks.
        fourth.commit();
        assert!(lock(&fourth.hold).is_some());
        let left = ask(
            &fourth,
            json!({"cmd": "mesh_leave", "network": "embedded-office"}),
        );
        assert_eq!(left, json!({"ok": true}));
        let joined = ask(
            &fourth,
            json!({"cmd": "mesh_join", "network": "embedded-office"}),
        );
        assert_eq!(joined, json!({"ok": true}));
        // Another runtime still holds the engine: closing one does not
        // stop it; closing the last does.
        let answer = ask(&fourth, json!({"cmd": "mesh_engine_stop"}));
        assert_eq!(answer, json!({"ok": true, "stopped": false}));
        let answer = ask(&fifth, json!({"cmd": "mesh_engine_stop"}));
        assert_eq!(answer, json!({"ok": true, "stopped": true}));
        assert!(engine.is_stopped());
    }
}
