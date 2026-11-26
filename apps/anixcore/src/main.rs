//! `anixcore`: the node kernel.
//!
//! ```text
//! anixcore run -c config.json     start the inbounds and the management API
//! anixcore run -c -               the same, reading the config from stdin
//! anixcore check -c config.json   parse the config and build every inbound
//! anixcore version
//! ```
//!
//! See `node_runtime::config` for the config format and `node_runtime::api`
//! for the management API.

use std::process::ExitCode;
use std::sync::Arc;

use node_runtime::{api, default_registry, Node, NodeConfig};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = match args.first().map(String::as_str) {
        Some("version") | Some("--version") => {
            println!("anixcore {}", env!("CARGO_PKG_VERSION"));
            println!("inbounds: {}", default_registry().type_names().join(", "));
            println!("features: config-stdin");
            Ok(())
        }
        Some(command @ ("run" | "check")) => match config_path(&args[1..]) {
            Some(path) => load(path).and_then(|config| start(config, command == "check")),
            None => Err("usage: anixcore run -c <config.json>".to_owned()),
        },
        _ => Err("usage: anixcore run|check -c <config.json> | anixcore version".to_owned()),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("anixcore: {message}");
            ExitCode::FAILURE
        }
    }
}

fn config_path(args: &[String]) -> Option<&str> {
    match args {
        [flag, path] if flag == "-c" || flag == "--config" => Some(path.as_str()),
        _ => None,
    }
}

fn load(path: &str) -> Result<NodeConfig, String> {
    // "-" is stdin: the agent pipes the config so that no file holds it.
    let bytes = if path == "-" {
        let mut bytes = Vec::new();
        std::io::Read::read_to_end(&mut std::io::stdin(), &mut bytes)
            .map_err(|error| format!("cannot read the config from stdin: {error}"))?;
        bytes
    } else {
        std::fs::read(path).map_err(|error| format!("cannot read {path}: {error}"))?
    };
    // Only the position: serde messages can quote values such as passwords.
    serde_json::from_slice(&bytes).map_err(|error| {
        format!(
            "invalid config {path} at line {} column {} ({:?})",
            error.line(),
            error.column(),
            error.classify()
        )
    })
}

fn start(config: NodeConfig, check_only: bool) -> Result<(), String> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|error| format!("cannot start runtime: {error}"))?;
    // Before anything binds, and in `check` too: a management listen that
    // is not loopback is refused unless `insecure_public` accepts it.
    if let Some(management) = &config.management {
        management.check().map_err(|error| error.to_string())?;
    }
    runtime.block_on(async move {
        let node = Node::new(default_registry(), config.allow_private_targets)
            .with_default_outbound(config.default_outbound);
        let node = Arc::new(if check_only {
            node
        } else {
            with_mesh(
                node,
                config.mesh_state_dir.as_deref(),
                config.mesh_external_bridge,
                config.mesh_backbone,
                config.mesh_paths,
                config.mesh_regions,
                config.mesh_host_groups,
            )
        });
        if let Some(bundle) = &config.tls_fingerprints {
            let status = node_runtime::apply_tls_fingerprints(bundle)
                .map_err(|error| format!("tls_fingerprints: {error}"))?;
            println!(
                "tls fingerprints: revision {:?}, replaced {:?}",
                status.revision, status.replaced
            );
        }
        if let Some(network) = &config.network {
            let status = node
                .apply_network(network)
                .await
                .map_err(|error| format!("network: {error}"))?;
            println!(
                "network: generation {}, {} egresses, {} ingresses",
                status.generation,
                status.egresses.len(),
                status.ingresses.len()
            );
        }
        for inbound in config.inbounds {
            let tag = inbound.tag.clone();
            let listen = node
                .add_inbound(inbound)
                .await
                .map_err(|error| format!("inbound {tag}: {error}"))?;
            println!("inbound {tag} listening on {listen}");
        }
        if let Some(egress) = &config.egress {
            let status = node
                .apply_egress(egress)
                .await
                .map_err(|error| format!("egress: {error}"))?;
            println!(
                "egress: {} routes, {} relays",
                status.routes.len(),
                status.relays.len()
            );
        }
        if check_only {
            println!("config ok");
            return Ok(());
        }
        if let Some(management) = config.management {
            let listener = management.bind("anixcore").await?;
            println!("management api listening on {}", management.listen);
            let node = node.clone();
            tokio::spawn(async move {
                if let Err(error) = api::serve(listener, node, management.token).await {
                    eprintln!("anixcore: management api stopped: {error}");
                }
            });
        }
        shutdown_signal().await;
        println!("shutting down");
        // Mesh networks withdraw their advertisements and close a few
        // seconds later (spec §15.7 rule 6).
        node.stop_mesh().await;
        Ok(())
    })
}

/// Where the managed mesh keeps its state when the config names no place.
#[cfg(target_os = "linux")]
const MESH_STATE_DIR: &str = "/var/lib/anixcore/mesh";

/// Installs the managed mesh networks of `PUT /v1/mesh` (Linux). Without
/// its state directory the node runs without them: `GET /v1/status` does
/// not list `mesh` and `/v1/mesh` answers 404. The inter-region backbone
/// stays off unless the config sets `mesh_backbone`, custom paths unless
/// it sets `mesh_paths`, regions unless it sets `mesh_regions`, host groups
/// unless it sets `mesh_host_groups`.
#[cfg(target_os = "linux")]
fn with_mesh(
    node: Node,
    dir: Option<&std::path::Path>,
    external_bridge: bool,
    backbone: bool,
    paths: bool,
    regions: bool,
    host_groups: bool,
) -> Node {
    let dir = dir.unwrap_or(std::path::Path::new(MESH_STATE_DIR));
    match mesh_node::managed::ManagedMesh::open_with_options(dir, external_bridge) {
        Ok(mesh) => {
            let mesh = mesh
                .with_backbone(backbone)
                .with_paths(paths)
                .with_regions(regions)
                .with_host_groups(host_groups);
            println!("mesh: instance {}", mesh.instance_id());
            node.with_mesh(Arc::new(mesh))
        }
        Err(error) => {
            eprintln!(
                "anixcore: mesh networks unavailable: {}: {error}",
                dir.display()
            );
            node
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn with_mesh(
    node: Node,
    _dir: Option<&std::path::Path>,
    _external_bridge: bool,
    _backbone: bool,
    _paths: bool,
    _regions: bool,
    _host_groups: bool,
) -> Node {
    node
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        if let Ok(mut terminate) = signal(SignalKind::terminate()) {
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {}
                _ = terminate.recv() => {}
            }
            return;
        }
    }
    let _ = tokio::signal::ctrl_c().await;
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    /// The mesh features of kernel 0.3, written out. A node whose config
    /// leaves every mesh switch at its default lists exactly these beside
    /// [`node_runtime::FEATURES`] in `GET /v1/status`; a feature of a
    /// later version appears only behind its switch, and adding one here
    /// is a change reviewers see.
    const MESH_FEATURES_0_3: &[&str] = &[
        "mesh",
        "mesh_dns",
        "mesh_resolver_address",
        "mesh_native_keys",
    ];

    #[test]
    fn a_node_with_the_default_switches_lists_the_0_3_features_only() {
        let config: NodeConfig = serde_json::from_value(serde_json::json!({})).unwrap();
        let dir = std::env::temp_dir().join(format!("anixcore-features-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let node = with_mesh(
            Node::new(default_registry(), false),
            Some(&dir),
            config.mesh_external_bridge,
            config.mesh_backbone,
            config.mesh_paths,
            config.mesh_regions,
            config.mesh_host_groups,
        );
        let mut expected = node_runtime::FEATURES.to_vec();
        expected.extend_from_slice(MESH_FEATURES_0_3);
        assert_eq!(node.features(), expected);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
