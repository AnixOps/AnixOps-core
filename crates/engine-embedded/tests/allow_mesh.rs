//! `allow_mesh: false` (docs/architecture/mesh-status.md): a config with a
//! mesh outbound anywhere is refused with one fixed error, and the runtime
//! answers no mesh command.

use engine_embedded::config::{RuntimeConfig, MESH_NOT_ALLOWED};
use engine_embedded::{EmbeddedRuntime, RuntimeError, RuntimeErrorCode};
use serde_json::{json, Value};

fn mesh() -> Value {
    json!({
        "type": "mesh",
        "config_version": 1,
        "network": {"name": "office", "secret": "s3cr3t", "kind": "legacy"},
        "node": {"address": "10.160.0.2/24", "role": "access"},
        "peers": [{"server": "127.0.0.1", "port": 1}],
    })
}

fn routing(outbounds: Value, allow_mesh: Option<bool>) -> Vec<u8> {
    let mut config = json!({
        "schema_version": 1,
        "profile_id": "p",
        "routing": {"outbounds": outbounds, "rules": ["FINAL,a"]},
    });
    if let Some(allow) = allow_mesh {
        config["allow_mesh"] = json!(allow);
    }
    serde_json::to_vec(&config).unwrap()
}

fn refusal(bytes: &[u8]) -> RuntimeError {
    match RuntimeConfig::from_json(bytes) {
        Ok(_) => panic!("the config should be refused"),
        Err(error) => error,
    }
}

fn assert_refused(bytes: &[u8]) {
    let error = refusal(bytes);
    assert_eq!(error.code, RuntimeErrorCode::ConfigRejected);
    assert_eq!(error.message, MESH_NOT_ALLOWED);
    match EmbeddedRuntime::from_json(bytes) {
        Ok(_) => panic!("the runtime should refuse it too"),
        Err(error) => assert_eq!(error.message, MESH_NOT_ALLOWED),
    }
}

#[test]
fn a_mesh_outbound_anywhere_refuses_the_config() {
    // The top-level outbound.
    let single = json!({
        "schema_version": 1,
        "profile_id": "p",
        "outbound": mesh(),
        "allow_mesh": false,
    });
    assert_refused(&serde_json::to_vec(&single).unwrap());
    // A routing outbound, used by the rules or not.
    assert_refused(&routing(json!({"a": mesh()}), Some(false)));
    assert_refused(&routing(
        json!({"a": {"type": "direct"}, "b": mesh()}),
        Some(false),
    ));
    // An inline `via`, however deep in the chain.
    assert_refused(&routing(
        json!({"a": {"type": "direct", "via": mesh()}}),
        Some(false),
    ));
    assert_refused(&routing(
        json!({"a": {"type": "direct", "via": {"type": "direct", "via": mesh()}}}),
        Some(false),
    ));
    // A mesh outbound with a `via` of its own.
    let mut chained = mesh();
    chained["via"] = json!({"type": "direct"});
    assert_refused(&routing(json!({"a": chained}), Some(false)));
}

#[test]
fn other_configs_are_unchanged() {
    // Without mesh outbounds the field changes nothing.
    for allow in [None, Some(false), Some(true)] {
        let bytes = routing(json!({"a": {"type": "direct"}}), allow);
        assert!(RuntimeConfig::from_json(&bytes).is_ok(), "{allow:?}");
    }
    // A mesh outbound is not refused for this field when it is on, or
    // left out (it defaults to on).
    for allow in [None, Some(true)] {
        let bytes = routing(json!({"a": mesh()}), allow);
        if let Err(error) = RuntimeConfig::from_json(&bytes) {
            assert_ne!(error.message, MESH_NOT_ALLOWED, "{allow:?}");
        }
    }
    // A node that is only named `mesh` is not a mesh outbound.
    let named = routing(
        json!({"a": {"type": "direct", "via": "mesh"}, "mesh": {"type": "direct"}}),
        Some(false),
    );
    assert!(RuntimeConfig::from_json(&named).is_ok());
}

fn ask(runtime: &EmbeddedRuntime, request: Value) -> Value {
    let request = serde_json::to_vec(&request).unwrap();
    serde_json::from_slice(&runtime.control_json(&request).unwrap()).unwrap()
}

#[test]
fn a_runtime_without_mesh_answers_no_mesh_command() {
    let runtime =
        match EmbeddedRuntime::from_json(&routing(json!({"a": {"type": "direct"}}), Some(false))) {
            Ok(runtime) => runtime,
            Err(error) => panic!("{error}"),
        };
    assert_eq!(
        ask(&runtime, json!({"cmd": "capabilities"})),
        json!({"capabilities": {"mesh": false}})
    );
    let mut network = mesh();
    network.as_object_mut().unwrap().remove("type");
    for request in [
        json!({"cmd": "mesh_status"}),
        json!({"cmd": "mesh_save_network", "network": network}),
        json!({"cmd": "mesh_join", "network": "office"}),
        json!({"cmd": "mesh_engine_stop"}),
    ] {
        let answer = ask(&runtime, request.clone());
        assert_eq!(answer["ok"], false, "{request}");
        assert_eq!(answer["error"]["code"], "unsupported", "{request}");
    }
}

#[cfg(feature = "mesh")]
#[test]
fn a_runtime_with_mesh_says_so() {
    let runtime = match EmbeddedRuntime::from_json(&routing(json!({"a": {"type": "direct"}}), None))
    {
        Ok(runtime) => runtime,
        Err(error) => panic!("{error}"),
    };
    assert_eq!(
        ask(&runtime, json!({"cmd": "capabilities"})),
        json!({"capabilities": {"mesh": true}})
    );
}
