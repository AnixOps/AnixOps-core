//! `allow_mesh` (docs/architecture/mesh-status.md): off unless the config
//! turns it on; while off, a config with a mesh outbound anywhere is refused
//! with one fixed error, and the runtime answers no mesh command.

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

fn with_allow(mut config: Value, allow_mesh: Option<bool>) -> Vec<u8> {
    if let Some(allow) = allow_mesh {
        config["allow_mesh"] = json!(allow);
    }
    serde_json::to_vec(&config).unwrap()
}

fn single(outbound: Value, allow_mesh: Option<bool>) -> Vec<u8> {
    with_allow(
        json!({"schema_version": 1, "profile_id": "p", "outbound": outbound}),
        allow_mesh,
    )
}

fn routing(outbounds: Value, allow_mesh: Option<bool>) -> Vec<u8> {
    with_allow(
        json!({
            "schema_version": 1,
            "profile_id": "p",
            "routing": {"outbounds": outbounds, "rules": ["FINAL,a"]},
        }),
        allow_mesh,
    )
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
fn a_mesh_outbound_anywhere_refuses_the_config_unless_allowed() {
    // Left out and `false` alike: the gate is closed by default.
    for allow in [None, Some(false)] {
        // The top-level outbound, and an inline `via` of it.
        assert_refused(&single(mesh(), allow));
        assert_refused(&single(json!({"type": "direct", "via": mesh()}), allow));
        // A routing outbound, used by the rules or not.
        assert_refused(&routing(json!({"a": mesh()}), allow));
        assert_refused(&routing(
            json!({"a": {"type": "direct"}, "b": mesh()}),
            allow,
        ));
        // An inline `via`, however deep in the chain.
        assert_refused(&routing(
            json!({"a": {"type": "direct", "via": mesh()}}),
            allow,
        ));
        assert_refused(&routing(
            json!({"a": {"type": "direct", "via": {"type": "direct", "via": mesh()}}}),
            allow,
        ));
        // A mesh outbound with a `via` of its own.
        let mut chained = mesh();
        chained["via"] = json!({"type": "direct"});
        assert_refused(&routing(json!({"a": chained}), allow));
    }
    // Allowed, a mesh outbound is not refused for the field.
    for bytes in [
        single(mesh(), Some(true)),
        routing(json!({"a": mesh()}), Some(true)),
    ] {
        if let Err(error) = RuntimeConfig::from_json(&bytes) {
            assert_ne!(error.message, MESH_NOT_ALLOWED);
        }
    }
}

#[test]
fn configs_without_mesh_outbounds_are_unchanged() {
    for allow in [None, Some(false), Some(true)] {
        let bytes = routing(json!({"a": {"type": "direct"}}), allow);
        assert!(RuntimeConfig::from_json(&bytes).is_ok(), "{allow:?}");
    }
    // A node that is only named `mesh` is not a mesh outbound.
    let named = routing(
        json!({"a": {"type": "direct", "via": "mesh"}, "mesh": {"type": "direct"}}),
        None,
    );
    assert!(RuntimeConfig::from_json(&named).is_ok());
}

#[test]
fn only_a_json_true_allows_mesh_outbounds() {
    let envelope = |allow: &str| {
        format!(
            r#"{{"schema_version":1,"profile_id":"p","outbound":{},"allow_mesh":{allow}}}"#,
            mesh()
        )
    };
    for allow in [r#""true""#, "null", "1"] {
        let error = refusal(envelope(allow).as_bytes());
        assert_eq!(error.code, RuntimeErrorCode::ConfigRejected, "{allow}");
    }
    // A repeated key is refused, whichever comes last.
    for repeated in [r#"true,"allow_mesh":false"#, r#"false,"allow_mesh":true"#] {
        let error = refusal(envelope(repeated).as_bytes());
        assert_eq!(error.code, RuntimeErrorCode::ConfigRejected, "{repeated}");
    }
}

fn ask(runtime: &EmbeddedRuntime, request: Value) -> Value {
    let request = serde_json::to_vec(&request).unwrap();
    serde_json::from_slice(&runtime.control_json(&request).unwrap()).unwrap()
}

fn runtime(bytes: &[u8]) -> EmbeddedRuntime {
    match EmbeddedRuntime::from_json(bytes) {
        Ok(runtime) => runtime,
        Err(error) => panic!("{error}"),
    }
}

#[test]
fn a_runtime_without_mesh_answers_no_mesh_command() {
    for allow in [None, Some(false)] {
        let runtime = runtime(&routing(json!({"a": {"type": "direct"}}), allow));
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
}

#[test]
fn a_runtime_allowed_mesh_says_whether_it_runs_them() {
    let runtime = runtime(&routing(json!({"a": {"type": "direct"}}), Some(true)));
    assert_eq!(
        ask(&runtime, json!({"cmd": "capabilities"})),
        json!({"capabilities": {"mesh": cfg!(feature = "mesh")}})
    );
}
