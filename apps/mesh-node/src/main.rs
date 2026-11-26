//! Command-line entry of `anixops-mesh`.
//!
//! Output is JSON on standard output; errors are one JSON line on standard
//! error. Exit codes are listed in `docs/deploy/mesh-node.md`.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use mesh_node::convert::ImportOptions;
use mesh_node::detect::{detect, Found, Origin};
use mesh_node::host::{Host, RealHost};
use mesh_node::import::import;
use mesh_node::profile::Profile;
use mesh_node::source::Invocation;
use mesh_node::takeover::{rollback_forgetting, takeover};

const USAGE: &str = "usage:
  anixops-mesh detect   --profile FILE
  anixops-mesh import   --profile FILE [--out-dir DIR] [--report FILE]
                        [--allow-unencrypted] [--address CIDR] [-- ARGS...]
  anixops-mesh takeover --profile FILE --state-dir DIR [--dry-run] [--report FILE]
  anixops-mesh rollback --state-dir DIR [--forget-process PID... --confirm] [--report FILE]
  anixops-mesh run      --config FILE [--interface NAME]
  anixops-mesh restore-host
  anixops-mesh capabilities
  anixops-mesh version";

/// Exit code for usage, profile and state errors.
const EXIT_USAGE: u8 = 2;

struct Options {
    profile: Option<PathBuf>,
    /// `run`: the mesh configuration.
    config: Option<PathBuf>,
    /// `run`: the virtual interface name.
    interface: Option<String>,
    out_dir: Option<PathBuf>,
    report: Option<PathBuf>,
    state_dir: Option<PathBuf>,
    address: Option<String>,
    allow_unencrypted: bool,
    dry_run: bool,
    /// `rollback`: recorded processes the operator started again by hand.
    forget: Vec<u32>,
    confirm: bool,
    /// Arguments after `--`: import this command line instead of detecting.
    manual: Option<Vec<String>>,
}

fn fail(kind: &str, detail: &str) -> ExitCode {
    eprintln!("{}", serde_json::json!({ "error": kind, "detail": detail }));
    ExitCode::from(EXIT_USAGE)
}

fn take(args: &[String], index: &mut usize, name: &str) -> Result<String, String> {
    let value = args
        .get(*index)
        .cloned()
        .ok_or_else(|| format!("{name} needs a value"))?;
    *index += 1;
    Ok(value)
}

fn parse(args: &[String]) -> Result<Options, String> {
    let mut options = Options {
        profile: None,
        config: None,
        interface: None,
        out_dir: None,
        report: None,
        state_dir: None,
        address: None,
        allow_unencrypted: false,
        dry_run: false,
        forget: Vec::new(),
        confirm: false,
        manual: None,
    };
    let mut index = 0;
    while index < args.len() {
        let arg = args[index].as_str();
        index += 1;
        match arg {
            "--profile" => options.profile = Some(PathBuf::from(take(args, &mut index, arg)?)),
            "--config" => options.config = Some(PathBuf::from(take(args, &mut index, arg)?)),
            "--interface" => options.interface = Some(take(args, &mut index, arg)?),
            "--out-dir" => options.out_dir = Some(PathBuf::from(take(args, &mut index, arg)?)),
            "--report" => options.report = Some(PathBuf::from(take(args, &mut index, arg)?)),
            "--state-dir" => {
                options.state_dir = Some(PathBuf::from(take(args, &mut index, arg)?));
            }
            "--address" => options.address = Some(take(args, &mut index, arg)?),
            "--allow-unencrypted" => options.allow_unencrypted = true,
            "--dry-run" => options.dry_run = true,
            "--forget-process" => {
                let value = take(args, &mut index, arg)?;
                options.forget.push(
                    value
                        .parse()
                        .map_err(|_| format!("{arg} needs a process id, not {value}"))?,
                );
            }
            "--confirm" => options.confirm = true,
            "--" => {
                options.manual = Some(args[index..].to_vec());
                break;
            }
            other => return Err(format!("unknown option {other}")),
        }
    }
    Ok(options)
}

fn load_profile(host: &dyn Host, options: &Options) -> Result<Profile, ExitCode> {
    let Some(path) = &options.profile else {
        return Err(fail("usage", "--profile is required"));
    };
    let text = host
        .read_to_string(path)
        .map_err(|error| fail("profile", &format!("{}: {error}", path.display())))?;
    Profile::from_json(&text).map_err(|error| fail("profile", &error.to_string()))
}

fn emit(
    host: &dyn Host,
    report: &impl serde::Serialize,
    path: Option<&Path>,
) -> Result<(), ExitCode> {
    let text =
        serde_json::to_string_pretty(report).map_err(|error| fail("report", &error.to_string()))?;
    println!("{text}");
    if let Some(path) = path {
        host.write(path, text.as_bytes(), 0o600, None)
            .map_err(|error| fail("report", &format!("{}: {error}", path.display())))?;
    }
    Ok(())
}

/// Systems detection, takeover and rollback know: Linux, macOS, Windows.
fn platform_supported() -> bool {
    cfg!(any(target_os = "linux", target_os = "macos", windows))
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn run_node(options: &Options) -> Result<ExitCode, ExitCode> {
    let Some(config) = &options.config else {
        return Err(fail("usage", "--config is required"));
    };
    match mesh_node::serve::run(config, options.interface.as_deref()) {
        Ok(()) => Ok(ExitCode::SUCCESS),
        Err(failure) => {
            eprintln!(
                "{}",
                serde_json::json!({ "error": failure.kind(), "detail": failure.detail() })
            );
            Err(ExitCode::from(failure.exit_code()))
        }
    }
}

/// Runs the node and returns its exit code, after writing why it stopped.
#[cfg(windows)]
fn node_exit_code(config: &Path, interface: Option<&str>) -> u8 {
    match mesh_node::serve::run(config, interface) {
        Ok(()) => 0,
        Err(failure) => {
            eprintln!(
                "{}",
                serde_json::json!({ "error": failure.kind(), "detail": failure.detail() })
            );
            failure.exit_code()
        }
    }
}

/// On Windows the node runs as a service when the service manager started
/// it, and in the console otherwise.
#[cfg(windows)]
fn run_node(options: &Options) -> Result<ExitCode, ExitCode> {
    let Some(config) = options.config.clone() else {
        return Err(fail("usage", "--config is required"));
    };
    let interface = options.interface.clone();
    let service_config = config.clone();
    let service_interface = interface.clone();
    let code = mesh_node::service_windows::dispatch(move || {
        node_exit_code(&service_config, service_interface.as_deref())
    })
    .unwrap_or_else(|| node_exit_code(&config, interface.as_deref()));
    if code == 0 {
        Ok(ExitCode::SUCCESS)
    } else {
        Err(ExitCode::from(code))
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
fn run_node(options: &Options) -> Result<ExitCode, ExitCode> {
    let _ = (&options.config, &options.interface);
    Err(fail(
        "platform",
        "the node runs on Linux, macOS and Windows only",
    ))
}

/// Puts back the forwarding, rules and translation a node that died left
/// on the host. The uninstallers run it after stopping the service.
#[cfg(any(target_os = "linux", target_os = "macos", windows))]
fn restore_host() -> Result<ExitCode, ExitCode> {
    let warnings =
        mesh_node::serve::restore_host().map_err(|error| fail("restore", &error.to_string()))?;
    println!(
        "{}",
        serde_json::json!({ "restored": true, "warnings": warnings })
    );
    Ok(ExitCode::SUCCESS)
}

#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
fn restore_host() -> Result<ExitCode, ExitCode> {
    Err(fail(
        "platform",
        "the node runs on Linux, macOS and Windows only",
    ))
}

fn run(command: &str, options: &Options) -> Result<ExitCode, ExitCode> {
    let host = RealHost::default();
    match command {
        "version" => {
            println!("{}", mesh_node::VERSION);
            Ok(ExitCode::SUCCESS)
        }
        "capabilities" => {
            println!(
                "{}",
                serde_json::json!({
                    "version": mesh_node::VERSION,
                    "commands": mesh_node::COMMANDS,
                    "detect_platforms": ["linux"],
                })
            );
            Ok(ExitCode::SUCCESS)
        }
        "run" => run_node(options),
        "restore-host" => restore_host(),
        "detect" => {
            if !platform_supported() {
                return Err(fail(
                    "platform",
                    "detection is implemented for Linux, macOS and Windows only",
                ));
            }
            let profile = load_profile(&host, options)?;
            let found = detect(&host, &profile);
            let summary: Vec<_> = found.iter().map(Found::summary).collect();
            emit(&host, &summary, options.report.as_deref())?;
            Ok(ExitCode::SUCCESS)
        }
        "import" => {
            let profile = load_profile(&host, options)?;
            let found = match &options.manual {
                Some(args) => {
                    // A command line given by hand, with this process's own
                    // environment and working directory.
                    let env: BTreeMap<String, String> = std::env::vars()
                        .filter(|(name, _)| profile.wants_env(name))
                        .collect();
                    vec![Found {
                        origin: Origin::Process {
                            pid: std::process::id(),
                        },
                        program: None,
                        invocation: Some(Invocation {
                            args: args.clone(),
                            env,
                            cwd: std::env::current_dir()
                                .ok()
                                .map(|dir| dir.display().to_string()),
                        }),
                        processes: Vec::new(),
                        notes: Vec::new(),
                    }]
                }
                None => {
                    if !platform_supported() {
                        return Err(fail(
                            "platform",
                            "detection is implemented for Linux, macOS and Windows only; pass the command line after --",
                        ));
                    }
                    detect(&host, &profile)
                }
            };
            let import_options = ImportOptions {
                allow_unencrypted: options.allow_unencrypted,
                address: options.address.clone(),
            };
            let report = import(
                &host,
                &profile,
                &import_options,
                &found,
                options.out_dir.as_deref(),
            );
            emit(&host, &report, options.report.as_deref())?;
            Ok(ExitCode::from(
                u8::try_from(report.exit_code()).unwrap_or(1),
            ))
        }
        "takeover" => {
            if !platform_supported() {
                return Err(fail(
                    "platform",
                    "takeover is implemented for Linux, macOS and Windows only",
                ));
            }
            let profile = load_profile(&host, options)?;
            let Some(state) = &options.state_dir else {
                return Err(fail("usage", "--state-dir is required"));
            };
            let report = takeover(&host, &profile, state, options.dry_run)
                .map_err(|error| fail("takeover", &error.to_string()))?;
            emit(&host, &report, options.report.as_deref())?;
            Ok(ExitCode::from(
                u8::try_from(report.exit_code()).unwrap_or(1),
            ))
        }
        "rollback" => {
            if !platform_supported() {
                return Err(fail(
                    "platform",
                    "rollback is implemented for Linux, macOS and Windows only",
                ));
            }
            let Some(state) = &options.state_dir else {
                return Err(fail("usage", "--state-dir is required"));
            };
            if !options.forget.is_empty() && !options.confirm {
                return Err(fail(
                    "usage",
                    "--forget-process drops a recorded process without starting it; start it again by hand first, then add --confirm",
                ));
            }
            let report = rollback_forgetting(&host, state, &options.forget)
                .map_err(|error| fail("rollback", &error.to_string()))?;
            emit(&host, &report, options.report.as_deref())?;
            Ok(if report.ok {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(7)
            })
        }
        other => Err(fail("usage", &format!("unknown command {other}\n{USAGE}"))),
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let Some((command, rest)) = args.split_first() else {
        eprintln!("{USAGE}");
        return ExitCode::from(EXIT_USAGE);
    };
    if matches!(command.as_str(), "-h" | "--help" | "help") {
        println!("{USAGE}");
        return ExitCode::SUCCESS;
    }
    let options = match parse(rest) {
        Ok(options) => options,
        Err(error) => return fail("usage", &format!("{error}\n{USAGE}")),
    };
    match run(command, &options) {
        Ok(code) | Err(code) => code,
    }
}
