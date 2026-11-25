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
use mesh_node::takeover::{rollback, takeover};

const USAGE: &str = "usage:
  anixops-mesh detect   --profile FILE
  anixops-mesh import   --profile FILE [--out-dir DIR] [--report FILE]
                        [--allow-unencrypted] [--address CIDR] [-- ARGS...]
  anixops-mesh takeover --profile FILE --state-dir DIR [--dry-run] [--report FILE]
  anixops-mesh rollback --state-dir DIR [--report FILE]
  anixops-mesh capabilities
  anixops-mesh version";

/// Exit code for usage, profile and state errors.
const EXIT_USAGE: u8 = 2;

struct Options {
    profile: Option<PathBuf>,
    out_dir: Option<PathBuf>,
    report: Option<PathBuf>,
    state_dir: Option<PathBuf>,
    address: Option<String>,
    allow_unencrypted: bool,
    dry_run: bool,
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
        out_dir: None,
        report: None,
        state_dir: None,
        address: None,
        allow_unencrypted: false,
        dry_run: false,
        manual: None,
    };
    let mut index = 0;
    while index < args.len() {
        let arg = args[index].as_str();
        index += 1;
        match arg {
            "--profile" => options.profile = Some(PathBuf::from(take(args, &mut index, arg)?)),
            "--out-dir" => options.out_dir = Some(PathBuf::from(take(args, &mut index, arg)?)),
            "--report" => options.report = Some(PathBuf::from(take(args, &mut index, arg)?)),
            "--state-dir" => {
                options.state_dir = Some(PathBuf::from(take(args, &mut index, arg)?));
            }
            "--address" => options.address = Some(take(args, &mut index, arg)?),
            "--allow-unencrypted" => options.allow_unencrypted = true,
            "--dry-run" => options.dry_run = true,
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

fn platform_supported() -> bool {
    cfg!(target_os = "linux")
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
        "detect" => {
            if !platform_supported() {
                return Err(fail("platform", "detection is implemented for Linux only"));
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
                            "detection is implemented for Linux only; pass the command line after --",
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
                return Err(fail("platform", "takeover is implemented for Linux only"));
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
                return Err(fail("platform", "rollback is implemented for Linux only"));
            }
            let Some(state) = &options.state_dir else {
                return Err(fail("usage", "--state-dir is required"));
            };
            let report =
                rollback(&host, state).map_err(|error| fail("rollback", &error.to_string()))?;
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
