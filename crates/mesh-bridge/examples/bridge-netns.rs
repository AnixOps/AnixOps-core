//! Drives the real nftables and `/proc/sys` for
//! `.github/scripts/mesh-bridge-netns.sh`, which runs it inside a network
//! namespace on a CI runner. Not shipped.
//!
//! ```text
//! bridge-netns apply  MESH_IF CONFIG_JSON VIRTUAL_SUBNET LOCAL_ADDRESS
//! bridge-netns remove MESH_IF
//! bridge-netns counters MESH_IF
//! bridge-netns cleanup
//! ```
//!
//! `apply` keeps the rules and forwarding after it exits (the script
//! removes them with `remove`), and prints the status and alerts as JSON.

use std::process::ExitCode;
use std::sync::Arc;

use mesh_bridge::apply::Host;
use mesh_bridge::{Bridge, ExternalBridgeConfig, Forwarding, SystemHost};
use outbound_mesh::IpNet;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let host: Arc<dyn Host> = Arc::new(SystemHost);
    let forwarding = Forwarding::new(host.clone());
    match args
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>()
        .as_slice()
    {
        ["apply", mesh_if, config, subnet, local] => {
            let config: ExternalBridgeConfig = match serde_json::from_str(config) {
                Ok(config) => config,
                Err(error) => return fail(&format!("config: {error}")),
            };
            let checked = match config.validate() {
                Ok(checked) => checked,
                Err(error) => return fail(&format!("{}: {error}", error.reason())),
            };
            let subnet = IpNet::parse(subnet).expect("virtual subnet");
            let local = local.parse().expect("local address");
            let mut bridge =
                Bridge::new(host, forwarding.clone(), mesh_if).expect("mesh interface");
            if let Err(error) = bridge.apply(&checked, &[subnet], &[local]) {
                return fail(&error.to_string());
            }
            let alerts: Vec<&str> = bridge.alerts().iter().map(|alert| alert.code).collect();
            println!(
                "{}",
                serde_json::json!({ "status": bridge.status(), "alerts": alerts })
            );
            // Keep the rules and the forwarding switch for the script.
            std::mem::forget(bridge);
            std::mem::forget(forwarding);
            ExitCode::SUCCESS
        }
        ["remove", mesh_if] => {
            let script = mesh_bridge::ruleset::render_removal(mesh_if);
            match host.nft(&["-f", "-"], Some(&script)) {
                Ok(_) => ExitCode::SUCCESS,
                Err(error) => fail(&error.to_string()),
            }
        }
        ["counters", mesh_if] => {
            let table = mesh_bridge::ruleset::table_name(mesh_if);
            let json = match host.nft(&["-j", "list", "counters", "table", "inet", &table], None) {
                Ok(json) => json,
                Err(error) => return fail(&error.to_string()),
            };
            match mesh_bridge::apply::parse_counters(&json) {
                Ok(counters) => {
                    println!("{} {}", counters.source_denied, counters.inbound_denied);
                    ExitCode::SUCCESS
                }
                Err(error) => fail(&error.to_string()),
            }
        }
        ["cleanup"] => match mesh_bridge::cleanup_all(host.as_ref()) {
            Ok(removed) => {
                println!("{removed}");
                ExitCode::SUCCESS
            }
            Err(error) => fail(&error.to_string()),
        },
        _ => fail("usage: bridge-netns apply|remove|counters|cleanup ..."),
    }
}

fn fail(detail: &str) -> ExitCode {
    eprintln!("{detail}");
    ExitCode::FAILURE
}
