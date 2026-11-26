//! The `mesh_*` control commands of the embedded engine
//! (`docs/architecture/mesh-status.md`, 命令), answered from the engine's
//! [`Registry`]. The caller owns the engine's lifetime: it hands a registry
//! to [`execute`] for the commands that need the engine, and `None` when no
//! engine runs.
//!
//! Every answer is JSON: `{"ok": true}`, the snapshot for `mesh_status`, or
//! `{"ok": false, "error": {"code", "detail"}}`.

use serde::de::IgnoredAny;
use serde::Deserialize;
use serde_json::{json, Value};

use super::registry::{NetworkState, Registry, RegistryError};
use super::snapshot::{self, Joined, NetworkView, Tunnel};
use crate::driver::Snapshot;
use crate::{IpNet, MeshConfig};

/// The commands of kernel 0.3 this module answers. Every other `mesh_*`
/// command answers `unsupported`.
pub enum Command {
    Status {
        network: Option<String>,
    },
    Join {
        network: String,
    },
    Leave {
        network: String,
    },
    Remove {
        network: String,
    },
    /// Read straight from the request into the config, whose secret and
    /// private key are wiped when dropped: no copy of them stays in an
    /// intermediate JSON value.
    Save {
        config: Box<MeshConfig>,
    },
    SetSubnetRoute {
        network: String,
        cidr: String,
        route: Route,
    },
}

/// The command name of a request; every other field is skipped unread.
#[derive(Deserialize)]
struct Head {
    #[serde(default)]
    cmd: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StatusArgs {
    #[allow(dead_code)]
    cmd: IgnoredAny,
    #[serde(default)]
    network: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NetworkArgs {
    #[allow(dead_code)]
    cmd: IgnoredAny,
    network: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SaveArgs {
    #[allow(dead_code)]
    cmd: IgnoredAny,
    config: Box<MeshConfig>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SubnetRouteArgs {
    #[allow(dead_code)]
    cmd: IgnoredAny,
    network: String,
    cidr: String,
    route: Route,
}

#[derive(Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Route {
    Local,
    Mesh,
}

/// What a `mesh_*` request asks for.
pub enum Request {
    /// One of [`Command`].
    Command(Command),
    /// A command of this table this engine does not run (a later kernel
    /// version, or `mesh_set_dns` before intranet names reach the embedded
    /// engine).
    Unsupported(String),
    /// A known command with missing or malformed arguments.
    Invalid(String),
}

/// The commands [`parse`] knows but leaves to [`Request::Unsupported`].
const UNSUPPORTED: &[&str] = &[
    "mesh_set_dns",
    "mesh_set_relay",
    "mesh_set_host_mode",
    "mesh_advertise",
    "mesh_withdraw",
    "mesh_request_region",
    "mesh_withdraw_region_request",
    "mesh_set_policy",
    "mesh_set_paths",
    "mesh_join_credential",
];

/// Reads `request` when its `cmd` is a `mesh_*` command other than
/// `mesh_engine_stop` (which the caller answers); `None` otherwise,
/// including for a request that is not a JSON object.
pub fn parse(request: &[u8]) -> Option<Request> {
    // An object only: the derived readers would also take an array.
    if request.iter().find(|byte| !byte.is_ascii_whitespace()) != Some(&b'{') {
        return None;
    }
    let name = serde_json::from_slice::<Head>(request).ok()?.cmd?;
    if !name.starts_with("mesh_") || name == "mesh_engine_stop" {
        return None;
    }
    if UNSUPPORTED.contains(&name.as_str()) {
        return Some(Request::Unsupported(name));
    }
    let command = match name.as_str() {
        "mesh_status" => {
            serde_json::from_slice::<StatusArgs>(request).map(|args| Command::Status {
                network: args.network,
            })
        }
        "mesh_join" => serde_json::from_slice::<NetworkArgs>(request).map(|args| Command::Join {
            network: args.network,
        }),
        "mesh_leave" => serde_json::from_slice::<NetworkArgs>(request).map(|args| Command::Leave {
            network: args.network,
        }),
        "mesh_remove_network" => {
            serde_json::from_slice::<NetworkArgs>(request).map(|args| Command::Remove {
                network: args.network,
            })
        }
        "mesh_save_network" => {
            serde_json::from_slice::<SaveArgs>(request).map(|args| Command::Save {
                config: args.config,
            })
        }
        "mesh_set_subnet_route" => {
            serde_json::from_slice::<SubnetRouteArgs>(request).map(|args| Command::SetSubnetRoute {
                network: args.network,
                cidr: args.cidr,
                route: args.route,
            })
        }
        _ => return Some(Request::Unsupported(name)),
    };
    Some(match command {
        Ok(command) => Request::Command(command),
        // The parser's message may quote the request: only the command is
        // named.
        Err(_) => Request::Invalid(format!(
            "{name}: arguments missing, unknown or of the wrong type"
        )),
    })
}

impl Command {
    /// Whether the command adds a network or starts one, so that the caller
    /// starts the engine for it; the others need a running engine.
    pub fn starts_engine(&self) -> bool {
        matches!(self, Self::Save { .. } | Self::Join { .. })
    }
}

/// The answer to `request`; `registry` is `None` when no engine runs.
pub fn answer(request: Request, registry: Option<&Registry>) -> Value {
    match request {
        Request::Unsupported(name) => error("unsupported", &format!("{name} is not supported")),
        Request::Invalid(detail) => error("invalid_argument", &detail),
        Request::Command(command) => execute(command, registry),
    }
}

fn execute(command: Command, registry: Option<&Registry>) -> Value {
    if let Command::Status { network } = &command {
        return match registry {
            Some(registry) => status(registry, network.as_deref()),
            None if network.is_some() => refused(RegistryError::NotFound),
            None => empty_status(),
        };
    }
    let Some(registry) = registry else {
        return match command {
            // The caller could not start the engine.
            Command::Save { .. } | Command::Join { .. } => refused(RegistryError::Closed),
            _ => refused(RegistryError::NotFound),
        };
    };
    let starts = command.starts_engine();
    let result = match command {
        Command::Status { .. } => unreachable!("answered above"),
        Command::Join { network } => registry.join(&network),
        Command::Leave { network } => registry.leave(&network),
        Command::Remove { network } => registry.remove(&network),
        Command::Save { config } => match (*config).validate() {
            Ok(settings) => registry.save(settings),
            Err(detail) => return error("invalid_argument", detail),
        },
        Command::SetSubnetRoute {
            network,
            cidr,
            route,
        } => {
            // `IpNet` equality compares networks only: the address is
            // compared apart, as the config checks do.
            let Some(cidr) =
                IpNet::parse(&cidr).filter(|net| net.trunc().address() == net.address())
            else {
                return error(
                    "invalid_argument",
                    "cidr is not a network with its host bits zero",
                );
            };
            registry.set_route_override(&network, cidr, route == Route::Mesh)
        }
    };
    match result {
        Ok(()) => json!({"ok": true}),
        // The engine stopped meanwhile: it holds no network any more.
        Err(RegistryError::Closed) if !starts => refused(RegistryError::NotFound),
        Err(refusal) => refused(refusal),
    }
}

fn error(code: &str, detail: &str) -> Value {
    json!({"ok": false, "error": {"code": code, "detail": detail}})
}

fn refused(refusal: RegistryError) -> Value {
    let (code, detail) = refusal.answer();
    error(code, detail)
}

/// The snapshot when the engine holds no network.
fn empty_status() -> Value {
    json!({
        "statusVersion": snapshot::STATUS_VERSION,
        "networks": [],
        "network": Value::Null,
        "self": Value::Null,
        "members": [],
        "subnets": [],
        "refusedAdvertisements": 0,
        "tunnel": {"routes": [], "routesVersion": 0, "dns": Value::Null},
    })
}

/// One network as the snapshot sees it, collected from the registry before
/// anything is serialized: the registry's lock is released by then, and
/// each driver snapshot is a copy.
struct Collected {
    state: NetworkState,
    /// `None` when the network is not joined.
    joined: Option<(bool, Option<crate::outbound::Failure>, Snapshot)>,
    static_key: Option<[u8; 32]>,
}

fn collect(state: NetworkState) -> Collected {
    // A retired instance is the one being replaced: it runs no more.
    let instance = state
        .instance
        .clone()
        .filter(|instance| !instance.is_retired());
    let joined = state.joined.then(|| match &instance {
        Some(instance) => {
            let (running, failure) = instance.state();
            let current = instance.snapshot().borrow().clone();
            (running, failure.or(state.failure), current)
        }
        None => (false, state.failure, Snapshot::default()),
    });
    let static_key = instance
        .filter(|_| state.settings.security == crate::config::SecurityMode::ForwardSecrecy)
        .map(|instance| instance.static_public_key());
    Collected {
        state,
        joined,
        static_key,
    }
}

/// `mesh_status`: the snapshot of `network`, or of the first joined
/// network, or else of the first saved one.
fn status(registry: &Registry, network: Option<&str>) -> Value {
    let collected: Vec<Collected> = registry.networks().into_iter().map(collect).collect();
    if collected.is_empty() {
        return match network {
            Some(_) => refused(RegistryError::NotFound),
            None => empty_status(),
        };
    }
    let views: Vec<NetworkView<'_>> = collected
        .iter()
        .map(|network| NetworkView {
            settings: &network.state.settings,
            joined: network
                .joined
                .as_ref()
                .map(|(running, failure, snapshot)| Joined {
                    running: *running,
                    failure: *failure,
                    snapshot,
                }),
            static_key: network.static_key,
        })
        .collect();
    let chosen = match network {
        Some(name) => views
            .iter()
            .position(|view| view.settings.network_name == name),
        None => views
            .iter()
            .position(|view| view.joined.is_some())
            .or(Some(0)),
    };
    let Some(chosen) = chosen else {
        return refused(RegistryError::NotFound);
    };
    let routes = snapshot::tunnel_routes(views.iter().filter_map(|view| {
        view.joined
            .as_ref()
            .filter(|joined| joined.running)
            .map(|joined| (view.settings, joined.snapshot))
    }));
    let routes_version = registry.routes_version(&routes);
    snapshot::snapshot(
        &views[chosen],
        &views,
        &Tunnel {
            routes: &routes,
            routes_version,
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::encode_key;

    fn config(name: &str, address: &str, kind: &str) -> Value {
        json!({
            "config_version": 1,
            "network": {"name": name, "secret": "s3cr3t", "kind": kind},
            "node": {"address": address, "role": "access", "instance_id": "device-1"},
            "peers": [{"server": "127.0.0.1", "port": 1}],
        })
    }

    /// A runtime that is never driven: drivers spawned on it never run, so
    /// the tests open no socket.
    fn registry() -> (tokio::runtime::Runtime, Registry) {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let registry = Registry::new(runtime.handle().clone());
        (runtime, registry)
    }

    fn run(registry: Option<&Registry>, request: Value) -> Value {
        answer(
            parse(request.to_string().as_bytes()).expect("a mesh command"),
            registry,
        )
    }

    fn code(answer: &Value) -> &str {
        answer["error"]["code"].as_str().unwrap_or("")
    }

    #[test]
    fn only_mesh_commands_other_than_the_engine_stop_are_parsed_here() {
        let parsed = |request: Value| parse(request.to_string().as_bytes());
        assert!(parsed(json!({"cmd": "traffic"})).is_none());
        assert!(parsed(json!({"cmd": "mesh_engine_stop"})).is_none());
        assert!(parsed(json!({"no": "cmd"})).is_none());
        // `mesh_` elsewhere than in the command does not make it a mesh
        // request.
        assert!(parsed(json!({"cmd": "traffic", "note": "mesh_status"})).is_none());
        assert!(parsed(json!({"cmd": 7, "mesh_status": true})).is_none());
        assert!(parse(b"mesh_status").is_none());
        assert!(parse(b"[\"mesh_status\"]").is_none());
        // Nesting deeper than the parser takes is refused, not followed.
        let deep = format!(
            "{{\"cmd\":\"mesh_status\",\"x\":{}{}}}",
            "[".repeat(10_000),
            "]".repeat(10_000)
        );
        assert!(parse(deep.as_bytes()).is_none());
        // A large request of another command is left alone.
        let large = format!(
            "{{\"cmd\":\"traffic\",\"pad\":\"{}\"}}",
            "mesh_".repeat(100_000)
        );
        assert!(parse(large.as_bytes()).is_none());
        for name in ["mesh_set_dns", "mesh_set_paths", "mesh_something_later"] {
            let answer = run(None, json!({"cmd": name}));
            assert_eq!(code(&answer), "unsupported", "{name}");
        }
        for request in [
            json!({"cmd": "mesh_join"}),
            json!({"cmd": "mesh_join", "network": 1}),
            json!({"cmd": "mesh_leave", "network": "a", "extra": true}),
            json!({"cmd": "mesh_set_subnet_route", "network": "a", "cidr": "10.0.0.0/8", "route": "elsewhere"}),
        ] {
            assert_eq!(
                code(&run(None, request.clone())),
                "invalid_argument",
                "{request}"
            );
        }
    }

    #[test]
    fn without_an_engine_the_status_is_empty_and_commands_find_nothing() {
        let status = run(None, json!({"cmd": "mesh_status"}));
        assert_eq!(status["statusVersion"], 1);
        assert_eq!(status["networks"], json!([]));
        assert_eq!(status["network"], Value::Null);
        let named = run(None, json!({"cmd": "mesh_status", "network": "office"}));
        assert_eq!(code(&named), "not_found");
        let left = run(None, json!({"cmd": "mesh_leave", "network": "office"}));
        assert_eq!(code(&left), "not_found");
    }

    #[test]
    fn a_saved_network_is_joined_left_and_removed_by_command() {
        let (_runtime, registry) = registry();
        let registry = Some(&registry);
        let saved = run(
            registry,
            json!({"cmd": "mesh_save_network", "config": config("office", "10.144.0.2/24", "legacy")}),
        );
        assert_eq!(saved, json!({"ok": true}));
        let status = run(registry, json!({"cmd": "mesh_status"}));
        assert_eq!(status["network"]["id"], "office");
        assert_eq!(status["self"]["id"], "device-1");
        assert_eq!(status["networks"].as_array().unwrap().len(), 1);
        assert_eq!(status["tunnel"]["routesVersion"], 1);
        // The answer never carries the secret.
        assert!(!status.to_string().contains("s3cr3t"));

        let left = run(registry, json!({"cmd": "mesh_leave", "network": "office"}));
        assert_eq!(left, json!({"ok": true}));
        let status = run(registry, json!({"cmd": "mesh_status", "network": "office"}));
        assert_eq!(status["network"]["state"], "not_joined");
        let joined = run(registry, json!({"cmd": "mesh_join", "network": "office"}));
        assert_eq!(joined, json!({"ok": true}));
        let status = run(registry, json!({"cmd": "mesh_status", "network": "office"}));
        assert_ne!(status["network"]["state"], "not_joined");

        let removed = run(
            registry,
            json!({"cmd": "mesh_remove_network", "network": "office"}),
        );
        assert_eq!(removed, json!({"ok": true}));
        let again = run(
            registry,
            json!({"cmd": "mesh_remove_network", "network": "office"}),
        );
        assert_eq!(code(&again), "not_found");
        let status = run(registry, json!({"cmd": "mesh_status"}));
        assert_eq!(status["networks"], json!([]));
    }

    #[test]
    fn a_bad_or_conflicting_config_is_refused_and_not_stored() {
        let (_runtime, registry) = registry();
        let registry = Some(&registry);
        let mut bad = config("office", "10.144.0.2/24", "legacy");
        bad["node"]["address"] = json!("not an address");
        let answer = run(registry, json!({"cmd": "mesh_save_network", "config": bad}));
        assert_eq!(code(&answer), "invalid_argument");
        let unknown = run(
            registry,
            json!({"cmd": "mesh_save_network", "config": {"config_version": 1, "surprise": 1}}),
        );
        assert_eq!(code(&unknown), "invalid_argument");

        // A managed network needs its key.
        let managed = run(
            registry,
            json!({"cmd": "mesh_save_network", "config": config("office", "10.144.0.2/24", "managed")}),
        );
        assert_eq!(code(&managed), "invalid_argument");
        assert!(managed["error"]["detail"]
            .as_str()
            .unwrap()
            .starts_with("private_key_required"));
        let mut keyed = config("office", "10.144.0.2/24", "managed");
        keyed["node"]["private_key"] = json!(encode_key(&[9; 32]));
        let answer = run(
            registry,
            json!({"cmd": "mesh_save_network", "config": keyed}),
        );
        assert_eq!(answer, json!({"ok": true}));

        // Another device ID than the saved network's.
        let mut other = config("lab", "10.145.0.2/24", "legacy");
        other["node"]["instance_id"] = json!("device-2");
        let answer = run(
            registry,
            json!({"cmd": "mesh_save_network", "config": other}),
        );
        assert_eq!(code(&answer), "invalid_argument");
        let status = run(registry, json!({"cmd": "mesh_status"}));
        assert_eq!(status["networks"].as_array().unwrap().len(), 1);
        // The private key is never given out.
        assert!(!status.to_string().contains(&encode_key(&[9; 32])));
    }

    #[test]
    fn a_subnet_route_override_is_kept_per_network() {
        let (_runtime, registry) = registry();
        let saved = run(
            Some(&registry),
            json!({"cmd": "mesh_save_network", "config": config("office", "10.144.0.2/24", "legacy")}),
        );
        assert_eq!(saved, json!({"ok": true}));
        let overrides = |registry: &Registry| registry.networks()[0].route_overrides.clone();
        let set = |route: &str, cidr: &str| {
            run(
                Some(&registry),
                json!({"cmd": "mesh_set_subnet_route", "network": "office", "cidr": cidr, "route": route}),
            )
        };
        assert_eq!(set("mesh", "192.168.10.0/24"), json!({"ok": true}));
        assert_eq!(set("mesh", "192.168.10.0/24"), json!({"ok": true}));
        assert_eq!(
            overrides(&registry),
            [IpNet::parse("192.168.10.0/24").unwrap()]
        );
        assert_eq!(code(&set("mesh", "192.168.10.1/24")), "invalid_argument");
        assert_eq!(code(&set("mesh", "fd00:10::1/64")), "invalid_argument");
        assert_eq!(set("mesh", "fd00:10::/64"), json!({"ok": true}));
        assert_eq!(set("local", "fd00:10::/64"), json!({"ok": true}));
        assert_eq!(set("local", "192.168.10.0/24"), json!({"ok": true}));
        assert!(overrides(&registry).is_empty());
        let unknown = run(
            Some(&registry),
            json!({"cmd": "mesh_set_subnet_route", "network": "lab", "cidr": "10.0.0.0/8", "route": "mesh"}),
        );
        assert_eq!(code(&unknown), "not_found");
        // At most 256 overrides per network; removing one makes room.
        for index in 0..256 {
            let cidr = format!("10.{}.{}.0/24", 200 + index / 256, index % 256);
            assert_eq!(set("mesh", &cidr), json!({"ok": true}), "{cidr}");
        }
        assert_eq!(code(&set("mesh", "10.201.0.0/24")), "invalid_argument");
        // Already listed: no new entry.
        assert_eq!(set("mesh", "10.200.0.0/24"), json!({"ok": true}));
        assert_eq!(set("local", "10.200.0.0/24"), json!({"ok": true}));
        assert_eq!(set("mesh", "10.201.0.0/24"), json!({"ok": true}));
        assert_eq!(overrides(&registry).len(), 256);
    }
}
