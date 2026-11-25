//! Taking over existing installations (requirement R12) and rolling back.
//!
//! Order: back up every file that will change, turn off every way the
//! program starts on boot, stop the services, then end any process that is
//! still running (TERM, then KILL). Program files and configurations are
//! never deleted. Each step is written to the manifest in the state
//! directory as soon as it is done, so a failure part-way, or a later
//! `rollback`, undoes exactly what was done, in reverse order.
//!
//! Containers are never touched; they are listed for manual handling.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::detect::{
    classify_units, detect, in_container, real_id, scan_processes, uses_process_table, Found,
    Origin,
};
use crate::host::{Hold, Host, Signal, Spawn};
use crate::profile::Profile;

pub const MANIFEST_VERSION: u32 = 1;
/// Prefix of a line this program turned into a comment.
pub const COMMENT_MARKER: &str = "#[anixops-mesh takeover] ";
const MANIFEST: &str = "takeover.json";
const LOCK: &str = "takeover.lock";
/// How long a process gets to exit after TERM.
const TERM_WAIT_MS: u64 = 10_000;
const KILL_WAIT_MS: u64 = 2_000;
const POLL_MS: u64 = 100;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum Action {
    /// A copy of a file before anything changed it.
    Backup {
        path: String,
        copy: String,
        sha256: String,
        mode: u32,
        uid: u32,
        gid: u32,
    },
    SystemdDisable {
        unit: String,
        /// `UnitFileState` before.
        previous: String,
    },
    SystemdMask {
        unit: String,
    },
    SystemdStop {
        unit: String,
    },
    OpenrcDelete {
        name: String,
        runlevel: String,
    },
    /// `update-rc.d`, `chkconfig` or a procd script's own `disable`.
    ScriptDisable {
        name: String,
        script: String,
        tool: String,
    },
    ScriptStop {
        name: String,
        script: String,
        openrc: bool,
    },
    /// A line of `rc.local` or a crontab turned into a comment.
    CommentLine {
        file: String,
        line: usize,
        original: String,
        /// Digest of the file right after the change; rollback restores the
        /// backup only if nothing else changed the file since.
        sha256_after: String,
    },
    /// `launchctl disable` (macOS).
    LaunchdDisable {
        domain: String,
        label: String,
        /// `enabled` when `launchctl enable` was set before, `none` when the
        /// job file decided.
        previous: String,
    },
    /// `launchctl bootout`: the job stopped and unloaded (macOS).
    LaunchdBootout {
        domain: String,
        label: String,
        plist: String,
    },
    /// `sc.exe stop`, waited for (Windows).
    WinServiceStop {
        name: String,
    },
    /// `sc.exe config start= disabled` (Windows).
    WinServiceDisable {
        name: String,
        /// The start type before: `auto`, `delayed-auto` or `demand`.
        previous: String,
    },
    /// A process ended with TERM or KILL.
    Terminate {
        pid: u32,
        exe: String,
        /// Restarted on rollback; holds what the process was started with.
        argv: Vec<String>,
        env: Vec<(String, String)>,
        /// `env` is the process's whole environment (older manifests kept
        /// only the profile's variables and add them to ours).
        #[serde(default)]
        full_env: bool,
        cwd: Option<String>,
        /// The user and group it ran as.
        #[serde(default)]
        uid: Option<u32>,
        #[serde(default)]
        gid: Option<u32>,
        /// Its supplementary groups.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        groups: Option<Vec<u32>>,
        /// `false` for processes a service manager restarts on rollback.
        restart: bool,
        killed: bool,
        /// The network namespace it ran in, as `/proc/<pid>/ns/net` names
        /// it; a rollback looks for a copy already running there.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        net_ns: Option<String>,
    },
}

impl Action {
    /// One line for reports; never includes arguments or environment.
    pub fn describe(&self) -> String {
        match self {
            Action::Backup { path, copy, .. } => format!("backup {path} -> {copy}"),
            Action::SystemdDisable { unit, previous } => {
                format!("systemctl disable {unit} (was {previous})")
            }
            Action::SystemdMask { unit } => format!("systemctl mask {unit}"),
            Action::SystemdStop { unit } => format!("systemctl stop {unit}"),
            Action::OpenrcDelete { name, runlevel } => format!("rc-update del {name} {runlevel}"),
            Action::ScriptDisable { name, tool, .. } => format!("{tool} disable {name}"),
            Action::ScriptStop { script, .. } => format!("{script} stop"),
            Action::CommentLine { file, line, .. } => format!("comment out {file}:{line}"),
            Action::LaunchdDisable { domain, label, .. } => {
                format!("launchctl disable {domain}/{label}")
            }
            Action::LaunchdBootout { domain, label, .. } => {
                format!("launchctl bootout {domain}/{label}")
            }
            Action::WinServiceStop { name } => format!("sc.exe stop {name}"),
            Action::WinServiceDisable { name, previous } => {
                format!("sc.exe config {name} start= disabled (was {previous})")
            }
            Action::Terminate {
                pid, exe, killed, ..
            } => format!(
                "end process {pid} ({exe}) with {}",
                if *killed { "KILL" } else { "TERM" }
            ),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Step {
    pub action: Action,
    pub at: u64,
    /// The takeover run this step belongs to.
    pub run: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Manifest {
    pub manifest_version: u32,
    pub steps: Vec<Step>,
    #[serde(default)]
    pub runs: u32,
    /// Processes the operator started again by hand and told `rollback`
    /// to forget (`--forget-process`); kept as an audit trail.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub forgotten: Vec<Forgotten>,
}

/// A recorded process removed from the manifest by the operator.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Forgotten {
    pub pid: u32,
    pub exe: String,
    pub argv: Vec<String>,
    #[serde(default)]
    pub uid: Option<u32>,
    /// When it was forgotten, seconds since the Unix epoch.
    pub at: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct StepReport {
    pub step: String,
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    /// Nothing was running or starting on boot.
    NothingFound,
    /// Planned only (`--dry-run`).
    Planned,
    Done,
    /// A step failed and everything done in this run was undone.
    RolledBack,
    /// A step failed and undoing it failed too: manual work needed.
    RollbackFailed,
}

#[derive(Debug, Clone, Serialize)]
pub struct TakeoverReport {
    pub report_version: u32,
    pub outcome: Outcome,
    pub steps: Vec<StepReport>,
    /// Installations left alone (containers).
    pub manual: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub rollback: Vec<StepReport>,
}

impl TakeoverReport {
    pub fn exit_code(&self) -> i32 {
        match self.outcome {
            Outcome::NothingFound | Outcome::Planned | Outcome::Done => 0,
            Outcome::RolledBack => 1,
            Outcome::RollbackFailed => 7,
        }
    }
}

#[derive(Debug)]
pub enum TakeoverError {
    Locked(PathBuf),
    Io(String),
    Manifest(String),
}

impl std::fmt::Display for TakeoverError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TakeoverError::Locked(path) => write!(
                f,
                "another takeover or rollback is running (it holds {})",
                path.display()
            ),
            TakeoverError::Io(error) => write!(f, "{error}"),
            TakeoverError::Manifest(error) => write!(f, "takeover manifest: {error}"),
        }
    }
}

impl std::error::Error for TakeoverError {}

fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// Holds the state directory's lock; released on drop.
struct Lock<'a> {
    host: &'a dyn Host,
    path: PathBuf,
}

impl<'a> Lock<'a> {
    fn take(host: &'a dyn Host, state: &Path) -> Result<Self, TakeoverError> {
        host.create_dir_all(state, 0o700)
            .map_err(|error| TakeoverError::Io(format!("{}: {error}", state.display())))?;
        let path = state.join(LOCK);
        // An advisory lock on a fixed file: the kernel releases it when the
        // holder exits, so there is no stale lock to judge or remove, and two
        // runs can never both hold it.
        match host.try_lock(&path, &host.own_pid().to_string()) {
            Ok(true) => Ok(Lock { host, path }),
            Ok(false) => Err(TakeoverError::Locked(path)),
            Err(error) => Err(TakeoverError::Io(format!("{}: {error}", path.display()))),
        }
    }
}

impl Drop for Lock<'_> {
    fn drop(&mut self) {
        self.host.unlock(&self.path);
    }
}

pub fn load_manifest(host: &dyn Host, state: &Path) -> Result<Option<Manifest>, TakeoverError> {
    let path = state.join(MANIFEST);
    if !host.exists(&path) {
        return Ok(None);
    }
    // Read through the checked state directory: a rollback starts programs
    // as the users this record names, so it must be the one we wrote.
    let bytes = host
        .read_state(&path)
        .map_err(|error| TakeoverError::Manifest(error.to_string()))?;
    let text =
        String::from_utf8(bytes).map_err(|error| TakeoverError::Manifest(error.to_string()))?;
    let manifest: Manifest =
        serde_json::from_str(&text).map_err(|error| TakeoverError::Manifest(error.to_string()))?;
    if manifest.manifest_version != MANIFEST_VERSION {
        return Err(TakeoverError::Manifest(format!(
            "manifest_version {} is not supported",
            manifest.manifest_version
        )));
    }
    Ok(Some(manifest))
}

fn save_manifest(host: &dyn Host, state: &Path, manifest: &Manifest) -> Result<(), String> {
    let text = serde_json::to_string_pretty(manifest).map_err(|error| error.to_string())?;
    // Never save what `load_manifest` could not read back.
    if text.len() as u64 > crate::host::MAX_TEXT_FILE {
        return Err(format!(
            "the record would exceed {} bytes",
            crate::host::MAX_TEXT_FILE
        ));
    }
    // It holds the command lines of ended processes, which may include
    // secrets: owner only.
    host.write_state(&state.join(MANIFEST), text.as_bytes())
        .map_err(|error| error.to_string())
}

/// What will be done for one installation, before any process is ended.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Planned {
    Backup(String),
    SystemdDisable {
        unit: String,
        previous: String,
    },
    SystemdMask(String),
    SystemdStop(String),
    OpenrcDelete {
        name: String,
        runlevel: String,
    },
    ScriptDisable {
        name: String,
        script: String,
    },
    ScriptStop {
        name: String,
        script: String,
        openrc: bool,
    },
    CommentLine {
        file: String,
        line: usize,
    },
    LaunchdDisable {
        domain: String,
        label: String,
        previous: String,
    },
    LaunchdBootout {
        domain: String,
        label: String,
        plist: String,
    },
    WinServiceStop(String),
    WinServiceDisable {
        name: String,
        previous: String,
    },
}

fn plan(host: &dyn Host, found: &[Found]) -> (Vec<Planned>, Vec<String>) {
    let mut backups: Vec<Planned> = Vec::new();
    let mut disables: Vec<Planned> = Vec::new();
    let mut stops: Vec<Planned> = Vec::new();
    let mut manual: Vec<String> = Vec::new();
    let backup = |path: &str, backups: &mut Vec<Planned>| {
        let planned = Planned::Backup(path.to_string());
        if host.is_file(Path::new(path)) && !backups.contains(&planned) {
            backups.push(planned);
        }
    };
    for entry in found {
        match &entry.origin {
            Origin::Systemd {
                unit,
                fragment,
                drop_ins,
                unit_file_state,
                active,
            } => {
                for path in fragment.iter().chain(drop_ins) {
                    backup(path, &mut backups);
                }
                match unit_file_state.as_str() {
                    "disabled" | "masked" | "masked-runtime" => {}
                    "static" | "indirect" | "generated" | "transient" => {
                        disables.push(Planned::SystemdMask(unit.clone()));
                    }
                    previous => disables.push(Planned::SystemdDisable {
                        unit: unit.clone(),
                        previous: previous.to_string(),
                    }),
                }
                if *active {
                    stops.push(Planned::SystemdStop(unit.clone()));
                }
            }
            Origin::Openrc {
                name,
                script,
                runlevels,
            } => {
                backup(script, &mut backups);
                for runlevel in runlevels {
                    disables.push(Planned::OpenrcDelete {
                        name: name.clone(),
                        runlevel: runlevel.clone(),
                    });
                }
                // Stopped (and started again on rollback) only if it runs.
                if !entry.processes.is_empty() {
                    stops.push(Planned::ScriptStop {
                        name: name.clone(),
                        script: script.clone(),
                        openrc: true,
                    });
                }
            }
            Origin::Sysv { name, script } => {
                backup(script, &mut backups);
                disables.push(Planned::ScriptDisable {
                    name: name.clone(),
                    script: script.clone(),
                });
                if !entry.processes.is_empty() {
                    stops.push(Planned::ScriptStop {
                        name: name.clone(),
                        script: script.clone(),
                        openrc: false,
                    });
                }
            }
            Origin::Autostart { file, line } => {
                backup(file, &mut backups);
                disables.push(Planned::CommentLine {
                    file: file.clone(),
                    line: *line,
                });
            }
            Origin::Launchd {
                label,
                plist,
                domain,
                override_off,
                disabled_key,
                loaded,
            } => {
                let Some(domain) = domain else {
                    manual.push(format!("login item {label} ({plist})"));
                    continue;
                };
                backup(plist, &mut backups);
                // Unloaded first, then turned off: a rollback turns it on
                // again before loading it, as launchd loads no job that is
                // turned off.
                if *loaded {
                    disables.push(Planned::LaunchdBootout {
                        domain: domain.clone(),
                        label: label.clone(),
                        plist: plist.clone(),
                    });
                }
                let off_at_boot = match override_off {
                    Some(off) => *off,
                    None => *disabled_key,
                };
                if !off_at_boot {
                    disables.push(Planned::LaunchdDisable {
                        domain: domain.clone(),
                        label: label.clone(),
                        previous: if override_off.is_some() {
                            "enabled".into()
                        } else {
                            "none".into()
                        },
                    });
                }
            }
            Origin::WinService {
                name,
                start,
                running,
            } => {
                // Stopped first, then turned off: a rollback turns it on
                // again before starting it, as Windows starts no service
                // that is turned off.
                if *running {
                    disables.push(Planned::WinServiceStop(name.clone()));
                }
                match start.as_str() {
                    "auto" | "delayed-auto" | "demand" => {
                        disables.push(Planned::WinServiceDisable {
                            name: name.clone(),
                            previous: start.clone(),
                        })
                    }
                    "disabled" => {}
                    _ => manual.push(format!("service {name} (starts as {start})")),
                }
            }
            Origin::Process { .. } => {}
            Origin::Container { id, image } => {
                manual.push(format!("container {id} {image}").trim_end().to_string());
            }
        }
    }
    let mut planned = backups;
    planned.extend(disables);
    planned.extend(stops);
    (planned, manual)
}

fn describe_planned(planned: &Planned) -> String {
    match planned {
        Planned::Backup(path) => format!("backup {path}"),
        Planned::SystemdDisable { unit, previous } => {
            format!("systemctl disable {unit} (now {previous})")
        }
        Planned::SystemdMask(unit) => format!("systemctl mask {unit}"),
        Planned::SystemdStop(unit) => format!("systemctl stop {unit}"),
        Planned::OpenrcDelete { name, runlevel } => format!("rc-update del {name} {runlevel}"),
        Planned::ScriptDisable { name, .. } => format!("disable init script {name}"),
        Planned::ScriptStop { script, .. } => format!("{script} stop"),
        Planned::CommentLine { file, line } => format!("comment out {file}:{line}"),
        Planned::LaunchdDisable { domain, label, .. } => {
            format!("launchctl disable {domain}/{label}")
        }
        Planned::LaunchdBootout { domain, label, .. } => {
            format!("launchctl bootout {domain}/{label}")
        }
        Planned::WinServiceStop(name) => format!("sc.exe stop {name}"),
        Planned::WinServiceDisable { name, previous } => {
            format!("sc.exe config {name} start= disabled (now {previous})")
        }
    }
}

fn run_ok(host: &dyn Host, program: &str, args: &[&str]) -> Result<(), String> {
    let output = host
        .run(program, args)
        .map_err(|error| format!("{program}: {error}"))?;
    if output.success() {
        Ok(())
    } else {
        Err(format!(
            "{program} {} failed ({}): {}",
            args.join(" "),
            output
                .code
                .map_or_else(|| "signal".to_string(), |code| code.to_string()),
            output.stderr.trim()
        ))
    }
}

fn unit_file_state(host: &dyn Host, unit: &str) -> String {
    host.run(
        "systemctl",
        &["show", unit, "-p", "UnitFileState", "--value"],
    )
    .map(|output| output.stdout.trim().to_string())
    .unwrap_or_default()
}

fn script_tool(host: &dyn Host, script: &str) -> Option<&'static str> {
    let first = host
        .read_to_string(Path::new(script))
        .ok()
        .and_then(|text| text.lines().next().map(str::to_string))
        .unwrap_or_default();
    if first.contains("/etc/rc.common") {
        Some("procd")
    } else if host.has_program("update-rc.d") {
        Some("update-rc.d")
    } else if host.has_program("chkconfig") {
        Some("chkconfig")
    } else {
        None
    }
}

/// Carries out one planned step; returns the actions to record.
fn execute(
    host: &dyn Host,
    state: &Path,
    planned: &Planned,
    index: usize,
) -> Result<Vec<Action>, String> {
    match planned {
        Planned::Backup(path) => {
            let source = Path::new(path);
            let bytes = host
                .read(source)
                .map_err(|error| format!("{path}: {error}"))?;
            let stat = host
                .stat(source)
                .map_err(|error| format!("{path}: {error}"))?;
            let name = source
                .file_name()
                .map(|name| name.to_string_lossy().into_owned())
                .unwrap_or_else(|| "file".into());
            let dir = state.join("backup");
            host.create_dir_all(&dir, 0o700)
                .map_err(|error| format!("{}: {error}", dir.display()))?;
            let copy = dir.join(format!("{}-{index}-{name}", host.now_unix()));
            host.write_state(&copy, &bytes)
                .map_err(|error| format!("{}: {error}", copy.display()))?;
            Ok(vec![Action::Backup {
                path: path.clone(),
                copy: copy.display().to_string(),
                sha256: sha256_hex(&bytes),
                mode: stat.mode,
                uid: stat.uid,
                gid: stat.gid,
            }])
        }
        Planned::SystemdDisable { unit, previous } => {
            run_ok(host, "systemctl", &["disable", unit])?;
            let mut actions = vec![Action::SystemdDisable {
                unit: unit.clone(),
                previous: previous.clone(),
            }];
            // A unit pulled in some other way stays startable: mask it.
            let now = unit_file_state(host, unit);
            if !matches!(now.as_str(), "disabled" | "masked" | "masked-runtime") {
                run_ok(host, "systemctl", &["mask", unit])?;
                actions.push(Action::SystemdMask { unit: unit.clone() });
            }
            Ok(actions)
        }
        Planned::SystemdMask(unit) => {
            run_ok(host, "systemctl", &["mask", unit])?;
            Ok(vec![Action::SystemdMask { unit: unit.clone() }])
        }
        Planned::SystemdStop(unit) => {
            run_ok(host, "systemctl", &["stop", unit])?;
            Ok(vec![Action::SystemdStop { unit: unit.clone() }])
        }
        Planned::OpenrcDelete { name, runlevel } => {
            run_ok(host, "rc-update", &["del", name, runlevel])?;
            Ok(vec![Action::OpenrcDelete {
                name: name.clone(),
                runlevel: runlevel.clone(),
            }])
        }
        Planned::ScriptDisable { name, script } => {
            let tool = script_tool(host, script)
                .ok_or_else(|| format!("no tool to turn off the init script {name}"))?;
            match tool {
                "procd" => run_ok(host, script, &["disable"])?,
                "update-rc.d" => run_ok(host, "update-rc.d", &[name, "disable"])?,
                _ => run_ok(host, "chkconfig", &[name, "off"])?,
            }
            Ok(vec![Action::ScriptDisable {
                name: name.clone(),
                script: script.clone(),
                tool: tool.to_string(),
            }])
        }
        Planned::ScriptStop {
            name,
            script,
            openrc,
        } => {
            if *openrc && host.has_program("rc-service") {
                run_ok(host, "rc-service", &[name, "stop"])?;
            } else {
                run_ok(host, script, &["stop"])?;
            }
            Ok(vec![Action::ScriptStop {
                name: name.clone(),
                script: script.clone(),
                openrc: *openrc,
            }])
        }
        Planned::CommentLine { file, line } => {
            let path = Path::new(file);
            let text = host
                .read_to_string(path)
                .map_err(|error| format!("{file}: {error}"))?;
            let stat = host
                .stat(path)
                .map_err(|error| format!("{file}: {error}"))?;
            let mut lines: Vec<String> = text.lines().map(str::to_string).collect();
            let index = line
                .checked_sub(1)
                .filter(|index| *index < lines.len())
                .ok_or_else(|| format!("{file}:{line} no longer exists"))?;
            let original = lines[index].clone();
            if original.trim_start().starts_with('#') {
                return Err(format!("{file}:{line} changed since detection"));
            }
            lines[index] = format!("{COMMENT_MARKER}{original}");
            let mut updated = lines.join("\n");
            if text.ends_with('\n') {
                updated.push('\n');
            }
            host.write(
                path,
                updated.as_bytes(),
                stat.mode,
                Some((stat.uid, stat.gid)),
            )
            .map_err(|error| format!("{file}: {error}"))?;
            Ok(vec![Action::CommentLine {
                file: file.clone(),
                line: *line,
                original,
                sha256_after: sha256_hex(updated.as_bytes()),
            }])
        }
        Planned::LaunchdDisable {
            domain,
            label,
            previous,
        } => {
            run_ok(
                host,
                "launchctl",
                &["disable", &format!("{domain}/{label}")],
            )?;
            Ok(vec![Action::LaunchdDisable {
                domain: domain.clone(),
                label: label.clone(),
                previous: previous.clone(),
            }])
        }
        Planned::LaunchdBootout {
            domain,
            label,
            plist,
        } => {
            let target = format!("{domain}/{label}");
            let result = run_ok(host, "launchctl", &["bootout", &target]);
            // Some versions report an error for a job they did unload: what
            // counts is that it is no longer loaded.
            if let Err(error) = result {
                if crate::launchd::loaded(host, domain, label).0 {
                    return Err(error);
                }
            }
            Ok(vec![Action::LaunchdBootout {
                domain: domain.clone(),
                label: label.clone(),
                plist: plist.clone(),
            }])
        }
        Planned::WinServiceStop(name) => {
            crate::winsvc::stop(host, name)?;
            Ok(vec![Action::WinServiceStop { name: name.clone() }])
        }
        Planned::WinServiceDisable { name, previous } => {
            crate::winsvc::set_start(host, name, "disabled")?;
            Ok(vec![Action::WinServiceDisable {
                name: name.clone(),
                previous: previous.clone(),
            }])
        }
    }
}

fn alive(host: &dyn Host, pid: u32, exe: &str) -> bool {
    if uses_process_table(host) {
        return match host.process_info(pid) {
            // A reused pid running something else counts as gone.
            Ok(info) => info.exe.as_deref().is_none_or(|path| path == exe),
            Err(error) => error.kind() != std::io::ErrorKind::NotFound,
        };
    }
    let base = PathBuf::from(format!("/proc/{pid}"));
    if !host.exists(&base) {
        return false;
    }
    // A reused pid running something else counts as gone.
    match host.read_link(&base.join("exe")) {
        Ok(path) => path.display().to_string().trim_end_matches(" (deleted)") == exe,
        Err(_) => true,
    }
}

/// Whether the program already runs again where a rollback would start it.
#[derive(Debug, Clone, PartialEq, Eq)]
enum CopyCheck {
    Running(u32),
    None,
    /// A process with the same command line whose program, user, cgroup or
    /// network we could not read (a security module may hide them): it may
    /// be a copy, so nothing is started on a guess.
    Unknown(u32),
}

/// A running process of the same program and command line, run by the
/// same user, outside containers and in the network the ended process was
/// in (recorded at takeover; older records compare with PID 1's): a copy
/// that serves the same network as the one we would start.
///
/// Mount namespaces are not compared: a unit with PrivateTmp= or
/// ProtectSystem= starts the program in a mount namespace of its own, and
/// so may the service that runs the rollback, yet that copy still holds the
/// same ports, interface and node identity.
fn running_copy(
    host: &dyn Host,
    exe: &str,
    argv: &[String],
    uid: Option<u32>,
    net_ns: Option<&str>,
) -> CopyCheck {
    if uses_process_table(host) {
        return running_copy_in_table(host, exe, argv, uid);
    }
    let Ok(entries) = host.list_dir(Path::new("/proc")) else {
        return CopyCheck::None;
    };
    let own = host.own_pid();
    let network = net_ns
        .map(str::to_string)
        .or_else(|| net_namespace(host, 1));
    let mut unknown = None;
    for entry in entries {
        let Some(pid) = entry
            .file_name()
            .and_then(|name| name.to_str())
            .and_then(|name| name.parse::<u32>().ok())
        else {
            continue;
        };
        if pid == own {
            continue;
        }
        // The command line is readable for every process we could have
        // ended; one we cannot read is not ours.
        let Ok(cmdline) = host.read(&entry.join("cmdline")) else {
            continue;
        };
        if crate::cmdline::split_nul(&cmdline) != argv {
            continue;
        }
        match copy_matches(host, &entry, exe, uid, network.as_deref()) {
            Some(true) => return CopyCheck::Running(pid),
            Some(false) => {}
            None => unknown = unknown.or(Some(pid)),
        }
    }
    unknown.map_or(CopyCheck::None, CopyCheck::Unknown)
}

/// [`running_copy`] where processes are read from the process table
/// (macOS): there are no containers or network namespaces to compare.
fn running_copy_in_table(
    host: &dyn Host,
    exe: &str,
    argv: &[String],
    uid: Option<u32>,
) -> CopyCheck {
    let Ok(pids) = host.list_pids() else {
        return CopyCheck::None;
    };
    let own = host.own_pid();
    let mut unknown = None;
    for pid in pids.into_iter().filter(|pid| *pid != own) {
        // As with `/proc`: a process whose arguments we cannot read is not
        // one we could have ended.
        let Ok(info) = host.process_info(pid) else {
            continue;
        };
        if info.argv != argv {
            continue;
        }
        let same_program = info.exe.as_deref().map(|path| path == exe);
        let same_user = match (uid, info.uid) {
            (Some(uid), Some(theirs)) => Some(uid == theirs),
            (Some(_), None) => None,
            (None, _) => Some(true),
        };
        match (same_program, same_user) {
            (Some(true), Some(true)) => return CopyCheck::Running(pid),
            (Some(false), _) | (_, Some(false)) => {}
            _ => unknown = unknown.or(Some(pid)),
        }
    }
    unknown.map_or(CopyCheck::None, CopyCheck::Unknown)
}

/// `Some(true)` for a copy, `Some(false)` for something else, `None` when
/// what tells them apart cannot be read.
fn copy_matches(
    host: &dyn Host,
    entry: &Path,
    exe: &str,
    uid: Option<u32>,
    network: Option<&str>,
) -> Option<bool> {
    let actual = host.read_link(&entry.join("exe")).ok()?;
    if actual.display().to_string().trim_end_matches(" (deleted)") != exe {
        return Some(false);
    }
    if let Some(uid) = uid {
        let status = host.read_to_string(&entry.join("status")).ok()?;
        if real_id(&status, "Uid:")? != uid {
            return Some(false);
        }
    }
    let cgroup = host.read_to_string(&entry.join("cgroup")).ok()?;
    if in_container(&cgroup) {
        return Some(false);
    }
    // Where no network to compare with is known, there is nothing to compare.
    if let Some(network) = network {
        let theirs = host.read_link(&entry.join("ns/net")).ok()?;
        if theirs.display().to_string() != network {
            return Some(false);
        }
    }
    Some(true)
}

/// One message for each process of the program running in another network
/// namespace than the host's.
fn foreign_network_processes(host: &dyn Host, profile: &Profile) -> Vec<String> {
    let Some(host_network) = net_namespace(host, 1) else {
        return Vec::new();
    };
    scan_processes(host, profile)
        .into_iter()
        .filter(|process| !process.contained)
        .filter_map(|process| {
            let theirs = net_namespace(host, process.pid)?;
            (theirs != host_network).then(|| foreign_network_message(process.pid, &theirs))
        })
        .collect()
}

/// One message for each process of the program, other than a taken-over
/// service's, that runs as another account than this program (Windows,
/// where a process cannot be started again as another account without its
/// password), or whose account cannot be read.
fn foreign_account_processes(
    host: &dyn Host,
    profile: &Profile,
    service_pids: &BTreeSet<u32>,
) -> Vec<String> {
    if !uses_process_table(host) {
        return Vec::new();
    }
    let Some(own) = host
        .process_info(host.own_pid())
        .ok()
        .and_then(|info| info.sid)
    else {
        return Vec::new();
    };
    scan_processes(host, profile)
        .into_iter()
        .filter(|process| !service_pids.contains(&process.pid))
        .filter_map(|process| match &process.sid {
            Some(sid) if *sid == own => None,
            Some(sid) => Some(format!(
                "process {} runs as another account ({sid}); stop it by hand, and start it again by hand to undo",
                process.pid
            )),
            None => Some(format!(
                "cannot tell which account runs process {}; stop it by hand, and start it again by hand to undo",
                process.pid
            )),
        })
        .collect()
}

fn foreign_network_message(pid: u32, namespace: &str) -> String {
    format!(
        "process {pid} runs in another network namespace ({namespace}); stop it by hand, and start it there again by hand to undo"
    )
}

/// The network namespace a process is in, as `/proc/<pid>/ns/net` names it.
fn net_namespace(host: &dyn Host, pid: u32) -> Option<String> {
    host.read_link(&PathBuf::from(format!("/proc/{pid}/ns/net")))
        .ok()
        .map(|link| link.display().to_string())
}

fn wait_gone(host: &dyn Host, pid: u32, exe: &str, ms: u64) -> bool {
    let mut waited = 0;
    while alive(host, pid, exe) {
        if waited >= ms {
            return false;
        }
        host.sleep_ms(POLL_MS);
        waited += POLL_MS;
    }
    true
}

fn end_processes(
    host: &dyn Host,
    profile: &Profile,
    owned_units: &BTreeSet<String>,
    service_pids: &BTreeSet<u32>,
) -> Vec<Result<Action, String>> {
    let mut out = Vec::new();
    let mut processes = scan_processes(host, profile);
    classify_units(&mut processes, owned_units);
    let host_network = net_namespace(host, 1);
    for process in processes {
        if process.contained {
            continue;
        }
        // Read while it runs: a rollback looks for a copy in this network.
        let net_ns = net_namespace(host, process.pid);
        // Started in another network namespace (say with `ip netns exec`):
        // a rollback could not start it there again, so it is not ended.
        if let (Some(theirs), Some(host_network)) = (&net_ns, &host_network) {
            if theirs != host_network {
                out.push(Err(foreign_network_message(process.pid, theirs)));
                continue;
            }
        }
        let killed = match host.signal(process.pid, Signal::Terminate) {
            // Already gone on its own: nothing to record.
            Ok(false) => continue,
            Ok(true) if wait_gone(host, process.pid, &process.exe, TERM_WAIT_MS) => false,
            Ok(true) => {
                let _ = host.signal(process.pid, Signal::Kill);
                if !wait_gone(host, process.pid, &process.exe, KILL_WAIT_MS) {
                    out.push(Err(format!("process {} did not exit", process.pid)));
                    continue;
                }
                true
            }
            Err(error) => {
                out.push(Err(format!("process {}: {error}", process.pid)));
                continue;
            }
        };
        out.push(Ok(Action::Terminate {
            pid: process.pid,
            exe: process.exe.clone(),
            argv: process.argv.clone(),
            full_env: !process.environ.is_empty(),
            env: if process.environ.is_empty() {
                process.env.clone().into_iter().collect()
            } else {
                process.environ.clone()
            },
            cwd: process.cwd.clone(),
            uid: process.uid,
            gid: process.gid,
            groups: process.groups.clone(),
            // Only our own services start it again on rollback; a process
            // started by hand, rc.local or cron is restarted as it was.
            restart: process.unit.is_none() && !service_pids.contains(&process.pid),
            killed,
            net_ns,
        }));
    }
    out
}

/// Turns off and stops every installation the profile describes.
pub fn takeover(
    host: &dyn Host,
    profile: &Profile,
    state: &Path,
    dry_run: bool,
) -> Result<TakeoverReport, TakeoverError> {
    let found = detect(host, profile);
    let owned_units: BTreeSet<String> = found
        .iter()
        .filter_map(|entry| match &entry.origin {
            Origin::Systemd { unit, .. } => Some(unit.clone()),
            _ => None,
        })
        .collect();
    // Processes of launchd jobs and Windows services taken over: loading
    // the job or starting the service again on rollback starts them, so
    // they are never started a second time.
    let service_pids: BTreeSet<u32> = found
        .iter()
        .filter(|entry| {
            matches!(
                entry.origin,
                Origin::Launchd { .. } | Origin::WinService { .. }
            )
        })
        .flat_map(|entry| entry.processes.iter().map(|process| process.pid))
        .collect();
    let (planned, manual) = plan(host, &found);
    let has_processes = scan_processes(host, profile)
        .iter()
        .any(|process| !process.contained);
    let mut report = TakeoverReport {
        report_version: crate::report::REPORT_VERSION,
        outcome: Outcome::Done,
        steps: Vec::new(),
        manual,
        rollback: Vec::new(),
    };
    if planned.is_empty() && !has_processes {
        report.outcome = Outcome::NothingFound;
        return Ok(report);
    }
    if dry_run {
        report.outcome = Outcome::Planned;
        report.steps = planned
            .iter()
            .map(|planned| StepReport {
                step: describe_planned(planned),
                ok: true,
                detail: None,
            })
            .collect();
        if has_processes {
            report.steps.push(StepReport {
                step: "end remaining processes".into(),
                ok: true,
                detail: None,
            });
        }
        return Ok(report);
    }

    let _lock = Lock::take(host, state)?;
    let mut manifest = load_manifest(host, state)?.unwrap_or(Manifest {
        manifest_version: MANIFEST_VERSION,
        steps: Vec::new(),
        runs: 0,
        forgotten: Vec::new(),
    });
    manifest.runs += 1;
    let run = manifest.runs;
    let first_new = manifest.steps.len();
    let mut failure: Option<String> = None;

    let record = |manifest: &mut Manifest, action: Action, report: &mut TakeoverReport| {
        report.steps.push(StepReport {
            step: action.describe(),
            ok: true,
            detail: None,
        });
        manifest.steps.push(Step {
            action,
            at: host.now_unix(),
            run,
        });
        save_manifest(host, state, manifest)
    };

    // Checked before anything is changed: a process in another network
    // namespace is never ended (a rollback could not put it back there), so
    // finding one later would only interrupt the network for nothing.
    for error in foreign_network_processes(host, profile)
        .into_iter()
        .chain(foreign_account_processes(host, profile, &service_pids))
    {
        report.steps.push(StepReport {
            step: "check networks".into(),
            ok: false,
            detail: Some(error.clone()),
        });
        failure.get_or_insert(error);
    }
    for (index, step) in planned.iter().enumerate() {
        if failure.is_some() {
            break;
        }
        match execute(host, state, step, index) {
            Ok(actions) => {
                for action in actions {
                    if let Err(error) = record(&mut manifest, action, &mut report) {
                        failure = Some(format!("saving the manifest: {error}"));
                        break;
                    }
                }
            }
            Err(error) => {
                report.steps.push(StepReport {
                    step: describe_planned(step),
                    ok: false,
                    detail: Some(error.clone()),
                });
                failure = Some(error);
            }
        }
        if failure.is_some() {
            break;
        }
    }
    // Units that are not the program's own but run it (cron, rc-local, a
    // wrapper the profile does not name). Only their process is ended; if
    // one restarts it, that shows only after its restart delay.
    let host_units: BTreeSet<String> = {
        let mut processes = scan_processes(host, profile);
        classify_units(&mut processes, &owned_units);
        processes
            .into_iter()
            .filter(|process| !process.contained)
            .filter_map(|process| process.host_unit)
            .collect()
    };
    // Decided before any process is ended: a unit whose restart delay is
    // unknown or too long fails the takeover while nothing has been
    // stopped that it could start a second time.
    let mut restart_wait = 0;
    if failure.is_none() {
        match restart_wait_ms(host, &host_units) {
            Ok(wait) => restart_wait = wait,
            Err(error) => {
                report.steps.push(StepReport {
                    step: "check host units".into(),
                    ok: false,
                    detail: Some(error.clone()),
                });
                failure = Some(error);
            }
        }
    }
    let mut waited = false;
    if failure.is_none() {
        // Every process that was ended is recorded before any failure is
        // handled: one that could not be ended must not hide those ended
        // after it, or the undo would never start them again.
        let (ended, failed): (Vec<_>, Vec<_>) =
            end_processes(host, profile, &owned_units, &service_pids)
                .into_iter()
                .partition(Result::is_ok);
        // On macOS a launchd job the profile does not name may keep the
        // program alive; it starts it again only after its throttle
        // interval, so wait that out before the final check.
        if !ended.is_empty() && uses_process_table(host) {
            restart_wait = restart_wait.max(LAUNCHD_RESTART_WAIT_MS);
        }
        for action in ended.into_iter().flatten() {
            // `record` keeps the step in memory even when saving fails, so
            // the undo below still starts it again.
            if let Err(error) = record(&mut manifest, action, &mut report) {
                failure.get_or_insert(format!("saving the manifest: {error}"));
            }
        }
        for error in failed.into_iter().filter_map(Result::err) {
            report.steps.push(StepReport {
                step: "end process".into(),
                ok: false,
                detail: Some(error.clone()),
            });
            failure.get_or_insert(error);
        }
    }
    if failure.is_none() && restart_wait > 0 {
        host.sleep_ms(restart_wait);
        waited = true;
    }
    if failure.is_none() {
        let left: Vec<u32> = scan_processes(host, profile)
            .iter()
            .filter(|process| !process.contained)
            .map(|process| process.pid)
            .collect();
        if !left.is_empty() {
            let error = if host_units.is_empty() {
                format!("processes still running after takeover: {left:?}")
            } else {
                format!(
                    "processes still running after takeover: {left:?}; if {} starts the program again, name it in the profile's detect.services",
                    host_units.iter().cloned().collect::<Vec<_>>().join(", ")
                )
            };
            report.steps.push(StepReport {
                step: "verify".into(),
                ok: false,
                detail: Some(error.clone()),
            });
            failure = Some(error);
        }
    }
    if failure.is_some() {
        let steps: Vec<Step> = manifest.steps.split_off(first_new);
        // A host unit restarts what we ended only after its delay; wait for
        // it before restarting anything, so the undo sees its copy and does
        // not start a second one.
        let ended = steps
            .iter()
            .any(|step| matches!(step.action, Action::Terminate { .. }));
        if ended && restart_wait > 0 && !waited {
            host.sleep_ms(restart_wait);
        }
        let (results, remaining) = undo(host, &steps);
        report.rollback = results;
        if remaining.is_empty() {
            report.outcome = Outcome::RolledBack;
            manifest.runs -= 1;
        } else {
            report.outcome = Outcome::RollbackFailed;
            // Keep only what could not be undone for a later `rollback`;
            // steps already undone are never repeated.
            manifest.steps.extend(remaining);
        }
        let _ = save_manifest(host, state, &manifest);
    }
    Ok(report)
}

fn undo_one(host: &dyn Host, action: &Action, backups: &[&Action]) -> Result<String, String> {
    match action {
        Action::Backup { .. } => Ok("kept".into()),
        Action::SystemdDisable { unit, previous } => {
            match previous.as_str() {
                "enabled-runtime" | "linked-runtime" => {
                    run_ok(host, "systemctl", &["enable", "--runtime", unit])?
                }
                _ => run_ok(host, "systemctl", &["enable", unit])?,
            }
            Ok(format!("systemctl enable {unit}"))
        }
        Action::SystemdMask { unit } => {
            run_ok(host, "systemctl", &["unmask", unit])?;
            Ok(format!("systemctl unmask {unit}"))
        }
        Action::SystemdStop { unit } => {
            run_ok(host, "systemctl", &["start", unit])?;
            Ok(format!("systemctl start {unit}"))
        }
        Action::OpenrcDelete { name, runlevel } => {
            run_ok(host, "rc-update", &["add", name, runlevel])?;
            Ok(format!("rc-update add {name} {runlevel}"))
        }
        Action::ScriptDisable { name, script, tool } => {
            match tool.as_str() {
                "procd" => run_ok(host, script, &["enable"])?,
                "update-rc.d" => run_ok(host, "update-rc.d", &[name, "enable"])?,
                _ => run_ok(host, "chkconfig", &[name, "on"])?,
            }
            Ok(format!("{tool} enable {name}"))
        }
        Action::ScriptStop {
            name,
            script,
            openrc,
        } => {
            if *openrc && host.has_program("rc-service") {
                run_ok(host, "rc-service", &[name, "start"])?;
            } else {
                run_ok(host, script, &["start"])?;
            }
            Ok(format!("{script} start"))
        }
        Action::CommentLine {
            file,
            line,
            original,
            sha256_after,
        } => {
            let path = Path::new(file);
            let current = host
                .read(path)
                .map_err(|error| format!("{file}: {error}"))?;
            let backup = backups.iter().rev().find_map(|backup| match backup {
                Action::Backup {
                    path: backed,
                    copy,
                    mode,
                    uid,
                    gid,
                    ..
                } if backed == file => Some((copy.clone(), *mode, *uid, *gid)),
                _ => None,
            });
            if sha256_hex(&current) == *sha256_after {
                // Nothing changed the file since: put the copy back. Without
                // a readable copy, fall through and uncomment just our line.
                if let Some((copy, mode, uid, gid)) = backup {
                    if let Ok(bytes) = host.read_state(Path::new(&copy)) {
                        host.write(path, &bytes, mode, Some((uid, gid)))
                            .map_err(|error| format!("{file}: {error}"))?;
                        return Ok(format!("restored {file} from {copy}"));
                    }
                }
            }
            // The file changed since: put back just our line.
            let text = String::from_utf8_lossy(&current).into_owned();
            let marked = format!("{COMMENT_MARKER}{original}");
            let mut lines: Vec<String> = text.lines().map(str::to_string).collect();
            let found = line
                .checked_sub(1)
                .filter(|index| lines.get(*index) == Some(&marked))
                .or_else(|| lines.iter().position(|candidate| *candidate == marked));
            let Some(index) = found else {
                // Already put back by an earlier attempt.
                if lines.iter().any(|candidate| candidate == original) {
                    return Ok(format!("{file}: the line is already restored"));
                }
                return Err(format!("{file}: the commented line is gone"));
            };
            lines[index] = original.clone();
            let mut updated = lines.join("\n");
            if text.ends_with('\n') {
                updated.push('\n');
            }
            let stat = host
                .stat(path)
                .map_err(|error| format!("{file}: {error}"))?;
            host.write(
                path,
                updated.as_bytes(),
                stat.mode,
                Some((stat.uid, stat.gid)),
            )
            .map_err(|error| format!("{file}: {error}"))?;
            Ok(format!("uncommented {file}:{}", index + 1))
        }
        Action::LaunchdDisable { domain, label, .. } => {
            // Turned on whether or not an override was set before: the job
            // was only turned off here when its file did not turn it off,
            // so an explicit "on" starts it at boot exactly as before.
            run_ok(host, "launchctl", &["enable", &format!("{domain}/{label}")])?;
            Ok(format!("launchctl enable {domain}/{label}"))
        }
        Action::LaunchdBootout {
            domain,
            label,
            plist,
        } => {
            if crate::launchd::loaded(host, domain, label).0 {
                return Ok(format!("{domain}/{label} is already loaded"));
            }
            run_ok(host, "launchctl", &["bootstrap", domain, plist])?;
            Ok(format!("launchctl bootstrap {domain} {plist}"))
        }
        Action::WinServiceStop { name } => {
            crate::winsvc::start(host, name)?;
            Ok(format!("sc.exe start {name}"))
        }
        Action::WinServiceDisable { name, previous } => {
            crate::winsvc::set_start(host, name, previous)?;
            Ok(format!("sc.exe config {name} start= {previous}"))
        }
        Action::Terminate {
            argv,
            env,
            full_env,
            cwd,
            uid,
            gid,
            groups,
            restart,
            pid,
            exe,
            net_ns,
            ..
        } => {
            if !*restart {
                return Ok(format!("process {pid} is started by its service"));
            }
            // A unit that restarts what it runs may already have started it
            // again; a second copy would fight it for ports, the virtual
            // interface and the node identity.
            // We start processes in the host's network only; one recorded in
            // another (never ended by this version) is left to the operator.
            if let (Some(theirs), Some(host_network)) = (net_ns, net_namespace(host, 1)) {
                if *theirs != host_network {
                    return Err(format!(
                        "process {pid} ran in another network namespace ({theirs}); start it there by hand, then rollback --forget-process {pid} --confirm"
                    ));
                }
            }
            match running_copy(host, exe, argv, *uid, net_ns.as_deref()) {
                CopyCheck::Running(other) => {
                    return Ok(format!(
                        "process {pid} already runs again as {other}; not started twice"
                    ));
                }
                // Kept for a later `rollback`, once it can be told apart.
                CopyCheck::Unknown(other) => {
                    return Err(format!(
                        "process {pid}: cannot tell whether process {other} is a copy of it; not started"
                    ));
                }
                CopyCheck::None => {}
            }
            let spawn = Spawn {
                argv: argv.clone(),
                env: env.clone(),
                clear_env: *full_env,
                cwd: cwd.clone(),
                uid: *uid,
                gid: *gid,
                groups: groups.clone(),
            };
            // On systemd hosts the new process moves into a scope of its own
            // before it runs anything, so neither it nor a child it forks
            // stays in the cgroup of whoever ran the rollback.
            let systemd = host.exists(Path::new("/run/systemd/system"));
            let scope = |new_pid: u32| own_scope(host, new_pid);
            let spawned = host
                .spawn_detached(&spawn, systemd.then_some(&scope as Hold<'_>))
                .map_err(|error| format!("restarting process {pid}: {error}"))?;
            let new_pid = spawned.pid;
            Ok(match spawned.held {
                Some(Ok(scope)) => format!("restarted process {pid} as {new_pid} in {scope}"),
                None => format!("restarted process {pid} as {new_pid}"),
                // Running, only still in our cgroup: worth knowing, not a failure.
                Some(Err(error)) => format!(
                    "restarted process {pid} as {new_pid}; it stays in this program's cgroup ({error})"
                ),
            })
        }
    }
}

/// The longest restart delay a host unit may have; a takeover does not wait
/// longer to see whether the program comes back. systemd's default is
/// 100 ms and wrapper units commonly use 1–30 s; the old network is already
/// down while we wait, so one minute bounds that outage. A longer delay is
/// not guessed: the takeover fails and the unit belongs in the profile.
const MAX_RESTART_WAIT_MS: u64 = 60_000;
/// Margin after a unit's restart delay before the final check.
const RESTART_MARGIN_MS: u64 = 2_000;
/// launchd's default throttle interval (10 s) plus the margin: how long
/// a job that keeps the program alive takes to start it again.
const LAUNCHD_RESTART_WAIT_MS: u64 = 10_000 + RESTART_MARGIN_MS;

/// How long to wait before the final check so that a host unit that
/// restarts the program has done so. A unit whose delay is unknown or too
/// long fails the takeover rather than report it done on a guess.
fn restart_wait_ms(host: &dyn Host, units: &BTreeSet<String>) -> Result<u64, String> {
    let mut wait = 0;
    for unit in units {
        let output = host
            .run(
                "systemctl",
                &[
                    "show",
                    unit.as_str(),
                    "-p",
                    "Restart",
                    "-p",
                    "RestartUSec",
                    "-p",
                    "RestartUSecNext",
                    "-p",
                    "RestartSteps",
                    "-p",
                    "RestartMaxDelayUSec",
                ],
            )
            .map_err(|error| format!("systemctl show {unit}: {error}"))?;
        if !output.success() {
            return Err(format!("systemctl show {unit} failed"));
        }
        let value = |key: &str| {
            output
                .stdout
                .lines()
                .find_map(|line| line.strip_prefix(key)?.strip_prefix('='))
                .map(str::trim)
        };
        match value("Restart") {
            Some("no") => continue,
            Some(_) => {}
            None => return Err(format!("{unit}: restart setting unknown")),
        }
        let unknown = || {
            format!("{unit} restarts what it runs after an unknown or long delay; name it in the profile's detect.services")
        };
        // With RestartSteps= (systemd 254+) each restart waits longer, up to
        // RestartMaxDelayUSec=; RestartUSecNext= is the next one. Older
        // systemd prints none of these and restarts after RestartUSec=.
        let steps = match value("RestartSteps").filter(|steps| !steps.is_empty()) {
            None => 0,
            Some(steps) => steps.parse::<u32>().map_err(|_| unknown())?,
        };
        let mut spans = vec![value("RestartUSec").ok_or_else(unknown)?];
        spans.extend(value("RestartUSecNext").filter(|next| !next.is_empty()));
        if steps > 0 {
            spans.push(value("RestartMaxDelayUSec").ok_or_else(unknown)?);
        }
        for span in spans {
            let delay = timespan_ms(span)
                .filter(|delay| *delay <= MAX_RESTART_WAIT_MS)
                .ok_or_else(unknown)?;
            wait = wait.max(delay + RESTART_MARGIN_MS);
        }
    }
    Ok(wait)
}

/// Parses a systemd time span as `systemctl show` prints it: `100ms`,
/// `5s`, `1min 30s`, `0`.
fn timespan_ms(text: &str) -> Option<u64> {
    let mut total_us: u64 = 0;
    for part in text.split_whitespace() {
        let digits = part
            .find(|c: char| !c.is_ascii_digit() && c != '.')
            .unwrap_or(part.len());
        let (number, unit) = part.split_at(digits);
        // systemd prints fractions such as `1.500000s`.
        let (whole, fraction) = number.split_once('.').unwrap_or((number, ""));
        if whole.is_empty() && fraction.is_empty() {
            return None;
        }
        let whole: u64 = if whole.is_empty() {
            0
        } else {
            whole.parse().ok()?
        };
        if !fraction.chars().all(|c| c.is_ascii_digit()) || fraction.len() > 9 {
            return None;
        }
        let scale: u64 = match unit {
            "" | "s" | "sec" => 1_000_000,
            "us" | "usec" => 1,
            "ms" | "msec" => 1_000,
            "min" | "m" => 60_000_000,
            "h" | "hr" => 3_600_000_000,
            _ => return None,
        };
        let mut part_us = whole.checked_mul(scale)?;
        if !fraction.is_empty() {
            let denominator = 10u64.pow(fraction.len() as u32);
            let numerator: u64 = fraction.parse().ok()?;
            // Rounded up: waiting a little longer is the safe side.
            part_us = part_us.checked_add(
                (u128::from(numerator) * u128::from(scale)).div_ceil(u128::from(denominator))
                    as u64,
            )?;
        }
        total_us = total_us.checked_add(part_us)?;
    }
    Some(total_us.div_ceil(1_000))
}

/// On systemd hosts, moves a restarted process into a transient scope of
/// its own, so it does not live in the cgroup of whoever ran the rollback
/// (an SSH session, the Agent's service) and end with it.
fn own_scope(host: &dyn Host, pid: u32) -> Result<String, String> {
    let scope = format!("anixops-mesh-restored-{pid}.scope");
    let pid_text = pid.to_string();
    let output = host
        .run(
            "busctl",
            &[
                "call",
                "org.freedesktop.systemd1",
                "/org/freedesktop/systemd1",
                "org.freedesktop.systemd1.Manager",
                "StartTransientUnit",
                "ssa(sv)a(sa(sv))",
                &scope,
                "fail",
                "2",
                "PIDs",
                "au",
                "1",
                &pid_text,
                "CollectMode",
                "s",
                "inactive-or-failed",
                "0",
            ],
        )
        .map_err(|error| format!("busctl: {error}"))?;
    if !output.success() {
        return Err(format!("busctl exited with {:?}", output.code));
    }
    // The call only queues a job: wait until the process is really there.
    let cgroup = PathBuf::from(format!("/proc/{pid}/cgroup"));
    for _ in 0..SCOPE_WAIT_POLLS {
        if host
            .read_to_string(&cgroup)
            .is_ok_and(|text| text.contains(&format!("/{scope}")))
        {
            return Ok(scope);
        }
        host.sleep_ms(POLL_MS);
    }
    Err(format!("{scope} did not take the process in time"))
}

/// How many polls of [`POLL_MS`] to wait for a scope to take a process.
const SCOPE_WAIT_POLLS: u32 = 30;

/// Undoes steps in reverse order; keeps going past failures. Returns the
/// steps still to undo, in their original order: the ones that failed, and
/// the backups while any of those remain (a later attempt may need them).
fn undo(host: &dyn Host, steps: &[Step]) -> (Vec<StepReport>, Vec<Step>) {
    let backups: Vec<&Action> = steps
        .iter()
        .map(|step| &step.action)
        .filter(|action| matches!(action, Action::Backup { .. }))
        .collect();
    let mut results = Vec::new();
    let mut failed = vec![false; steps.len()];
    for (index, step) in steps.iter().enumerate().rev() {
        match undo_one(host, &step.action, &backups) {
            Ok(detail) => results.push(StepReport {
                step: step.action.describe(),
                ok: true,
                detail: Some(detail),
            }),
            Err(error) => {
                failed[index] = true;
                results.push(StepReport {
                    step: step.action.describe(),
                    ok: false,
                    detail: Some(error),
                });
            }
        }
    }
    let any_failed = failed.iter().any(|failed| *failed);
    let remaining = steps
        .iter()
        .zip(&failed)
        .filter(|(step, failed)| {
            **failed || (any_failed && matches!(step.action, Action::Backup { .. }))
        })
        .map(|(step, _)| step.clone())
        .collect();
    (results, remaining)
}

#[derive(Debug, Clone, Serialize)]
pub struct RollbackReport {
    pub report_version: u32,
    pub ok: bool,
    pub steps: Vec<StepReport>,
}

/// Undoes every recorded takeover. The caller stops our own node first.
pub fn rollback(host: &dyn Host, state: &Path) -> Result<RollbackReport, TakeoverError> {
    rollback_forgetting(host, state, &[])
}

/// Like [`rollback`], but first drops the recorded processes in `forget`:
/// the operator has confirmed starting them again by hand (a process this
/// program cannot tell apart from a copy, or one that ran in another network
/// namespace), so they are neither started nor kept for later.
pub fn rollback_forgetting(
    host: &dyn Host,
    state: &Path,
    forget: &[u32],
) -> Result<RollbackReport, TakeoverError> {
    let _lock = Lock::take(host, state)?;
    let Some(mut manifest) = load_manifest(host, state)? else {
        if let Some(pid) = forget.first() {
            return Err(TakeoverError::Manifest(format!(
                "no recorded process {pid}"
            )));
        }
        return Ok(RollbackReport {
            report_version: crate::report::REPORT_VERSION,
            ok: true,
            steps: Vec::new(),
        });
    };
    let mut forgotten = Vec::new();
    for pid in forget {
        let before = manifest.steps.len();
        let mut dropped = Vec::new();
        manifest.steps.retain(|step| match &step.action {
            Action::Terminate {
                pid: recorded,
                exe,
                argv,
                uid,
                ..
            } if recorded == pid => {
                dropped.push(Forgotten {
                    pid: *pid,
                    exe: exe.clone(),
                    argv: argv.clone(),
                    uid: *uid,
                    at: host.now_unix(),
                });
                false
            }
            _ => true,
        });
        if manifest.steps.len() == before {
            return Err(TakeoverError::Manifest(format!(
                "no recorded process {pid}"
            )));
        }
        // Kept in the record (owner only, like the steps) so what the
        // operator dropped stays visible after the steps are gone.
        manifest.forgotten.append(&mut dropped);
        forgotten.push(StepReport {
            step: format!("forget process {pid}"),
            ok: true,
            detail: Some("started again by hand, as the operator confirmed".into()),
        });
    }
    let (mut steps, remaining) = undo(host, &manifest.steps);
    forgotten.append(&mut steps);
    let steps = forgotten;
    let ok = remaining.is_empty();
    // A later rollback retries only what is left.
    manifest.steps = remaining;
    if ok {
        manifest.runs = 0;
    }
    save_manifest(host, state, &manifest).map_err(TakeoverError::Io)?;
    Ok(RollbackReport {
        report_version: crate::report::REPORT_VERSION,
        ok,
        steps,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host::fake::FakeHost;
    use crate::profile::tests::demo;

    const STATE: &str = "/var/lib/anixops-mesh/takeover";

    fn machine() -> FakeHost {
        let host = FakeHost::default();
        host.file("/run/systemd/system/.keep", "");
        host.file(
            "/etc/systemd/system/demo-meshd.service",
            "[Service]\nExecStart=/usr/bin/demo-meshd -c /etc/demo/a.toml\n",
        );
        host.answer(
            "systemctl show demo-meshd.service -p LoadState -p FragmentPath -p DropInPaths -p UnitFileState -p ActiveState",
            0,
            "LoadState=loaded\nFragmentPath=/etc/systemd/system/demo-meshd.service\nDropInPaths=\nUnitFileState=enabled\nActiveState=active\n",
        );
        host.answer(
            "systemctl show demo-meshd.service -p UnitFileState --value",
            0,
            "disabled\n",
        );
        host.process(
            100,
            "/usr/bin/demo-meshd",
            &["/usr/bin/demo-meshd", "-c", "/etc/demo/a.toml"],
            &[],
            "0::/system.slice/demo-meshd.service\n",
        );
        host.file(
            "/etc/rc.local",
            "#!/bin/sh\n/opt/demo-meshd --net-name lab &\nexit 0\n",
        );
        host.process(
            200,
            "/opt/demo-meshd",
            &["/opt/demo-meshd", "--net-name", "lab"],
            &["DEMO_NET_SECRET=x"],
            "0::/user.slice\n",
        );
        host
    }

    #[test]
    fn dry_run_changes_nothing() {
        let host = machine();
        let report = takeover(&host, &demo(), Path::new(STATE), true).unwrap();
        assert_eq!(report.outcome, Outcome::Planned);
        let steps: Vec<&str> = report.steps.iter().map(|step| step.step.as_str()).collect();
        assert_eq!(
            steps,
            vec![
                "backup /etc/systemd/system/demo-meshd.service",
                "backup /etc/rc.local",
                "systemctl disable demo-meshd.service (now enabled)",
                "comment out /etc/rc.local:2",
                "systemctl stop demo-meshd.service",
                "end remaining processes",
            ]
        );
        assert!(host
            .ran
            .borrow()
            .iter()
            .all(|command| command.starts_with("systemctl show")));
        assert!(host.signals.borrow().is_empty());
    }

    #[test]
    fn takes_over_and_rolls_back() {
        let host = machine();
        // `systemctl stop` ends the service's process.
        host.stubborn.borrow_mut().insert(200);
        let profile = demo();
        // Stopping the unit is simulated by removing its process up front:
        // the fake runs no service manager.
        host.signal(100, Signal::Kill).unwrap();
        host.signals.borrow_mut().clear();

        let report = takeover(&host, &profile, Path::new(STATE), false).unwrap();
        assert_eq!(report.outcome, Outcome::Done, "{report:?}");
        let ran = host.ran.borrow().clone();
        assert!(ran.contains(&"systemctl disable demo-meshd.service".to_string()));
        assert!(ran.contains(&"systemctl stop demo-meshd.service".to_string()));
        assert!(!ran.iter().any(|command| command.contains("mask")));
        // TERM was ignored, so KILL followed.
        assert_eq!(
            *host.signals.borrow(),
            vec![(200, Signal::Terminate), (200, Signal::Kill)]
        );
        let rc_local = host.text("/etc/rc.local").unwrap();
        assert_eq!(
            rc_local,
            format!("#!/bin/sh\n{COMMENT_MARKER}/opt/demo-meshd --net-name lab &\nexit 0\n")
        );
        let manifest = load_manifest(&host, Path::new(STATE)).unwrap().unwrap();
        assert_eq!(manifest.runs, 1);
        assert!(manifest.steps.iter().any(|step| matches!(
            &step.action,
            Action::Terminate {
                pid: 200,
                restart: true,
                killed: true,
                ..
            }
        )));
        // The lock is released (its file stays).
        assert!(host.locks.borrow().is_empty());

        host.ran.borrow_mut().clear();
        let rollback = rollback(&host, Path::new(STATE)).unwrap();
        assert!(rollback.ok, "{rollback:?}");
        // The restarted process is reported in its own scope.
        assert!(
            rollback
                .steps
                .iter()
                .any(|step| step.detail.as_deref().is_some_and(
                    |detail| detail.ends_with("as 4242 in anixops-mesh-restored-4242.scope")
                )),
            "{rollback:?}"
        );
        let mut ran = host.ran.borrow().clone();
        // The restarted process gets a scope of its own first.
        let scope = ran.remove(0);
        assert!(
            scope.starts_with("busctl call org.freedesktop.systemd1")
                && scope.contains("StartTransientUnit")
                && scope.contains("PIDs au 1 "),
            "{scope}"
        );
        assert_eq!(
            ran,
            vec![
                "systemctl start demo-meshd.service".to_string(),
                "systemctl enable demo-meshd.service".to_string(),
            ]
        );
        assert_eq!(
            host.text("/etc/rc.local").unwrap(),
            "#!/bin/sh\n/opt/demo-meshd --net-name lab &\nexit 0\n"
        );
        let spawned = host.spawned.borrow();
        assert_eq!(spawned.len(), 1);
        assert_eq!(
            spawned[0].argv,
            vec!["/opt/demo-meshd", "--net-name", "lab"]
        );
        assert_eq!(
            spawned[0].env,
            vec![("DEMO_NET_SECRET".to_string(), "x".to_string())]
        );
        // The whole environment it had, not ours.
        assert!(spawned[0].clear_env);
        let manifest = load_manifest(&host, Path::new(STATE)).unwrap().unwrap();
        assert!(manifest.steps.is_empty());
    }

    #[test]
    fn failure_rolls_back_the_run() {
        let host = machine();
        host.answer("systemctl stop demo-meshd.service", 1, "");
        let report = takeover(&host, &demo(), Path::new(STATE), false).unwrap();
        assert_eq!(report.outcome, Outcome::RolledBack, "{report:?}");
        assert_eq!(report.exit_code(), 1);
        let ran = host.ran.borrow().clone();
        assert!(ran.contains(&"systemctl enable demo-meshd.service".to_string()));
        assert_eq!(
            host.text("/etc/rc.local").unwrap(),
            "#!/bin/sh\n/opt/demo-meshd --net-name lab &\nexit 0\n"
        );
        assert!(host.signals.borrow().is_empty());
        let manifest = load_manifest(&host, Path::new(STATE)).unwrap().unwrap();
        assert!(manifest.steps.is_empty());
        assert_eq!(manifest.runs, 0);
    }

    #[test]
    fn rollback_keeps_later_edits() {
        let host = machine();
        host.signal(100, Signal::Kill).unwrap();
        let report = takeover(&host, &demo(), Path::new(STATE), false).unwrap();
        assert_eq!(report.outcome, Outcome::Done);
        // Somebody edits rc.local after the takeover.
        let edited = host
            .text("/etc/rc.local")
            .unwrap()
            .replace("exit 0", "echo hi\nexit 0");
        host.file("/etc/rc.local", &edited);
        let rollback = rollback(&host, Path::new(STATE)).unwrap();
        assert!(rollback.ok);
        assert_eq!(
            host.text("/etc/rc.local").unwrap(),
            "#!/bin/sh\n/opt/demo-meshd --net-name lab &\necho hi\nexit 0\n"
        );
    }

    #[test]
    fn a_second_run_is_refused_while_locked() {
        let host = machine();
        host.held_by_others
            .borrow_mut()
            .insert(Path::new(STATE).join(LOCK));
        assert!(matches!(
            takeover(&host, &demo(), Path::new(STATE), false),
            Err(TakeoverError::Locked(_))
        ));
        assert!(matches!(
            rollback(&host, Path::new(STATE)),
            Err(TakeoverError::Locked(_))
        ));
    }

    #[test]
    fn a_lock_file_left_behind_does_not_block() {
        let host = machine();
        host.signal(100, Signal::Kill).unwrap();
        // Left by a run that was killed: the file stays, its lock went with
        // the process.
        host.file(&format!("{STATE}/{LOCK}"), "4242");
        let report = takeover(&host, &demo(), Path::new(STATE), false).unwrap();
        assert_eq!(report.outcome, Outcome::Done, "{report:?}");
        // Released after the run, and the next run takes it again.
        assert!(host.locks.borrow().is_empty());
        assert!(rollback(&host, Path::new(STATE)).unwrap().ok);
        assert!(host.locks.borrow().is_empty());
    }

    #[test]
    fn host_services_are_never_turned_off() {
        let host = machine();
        // On systemd hosts rc.local runs inside rc-local.service.
        host.process(
            200,
            "/opt/demo-meshd",
            &["/opt/demo-meshd", "--net-name", "lab"],
            &["DEMO_NET_SECRET=x", "PATH=/usr/bin"],
            "0::/system.slice/rc-local.service\n",
        );
        host.file(
            "/proc/200/status",
            "Name:\tdemo-meshd\nUid:\t1000\t1000\t1000\t1000\nGid:\t100\t100\t100\t100\nGroups:\t27 100 998 \n",
        );
        host.file(
            "/lib/systemd/system/rc-local.service",
            "[Service]\nType=forking\nExecStart=/etc/rc.local start\n",
        );
        host.answer(
            "systemctl show rc-local.service -p LoadState -p FragmentPath -p DropInPaths -p UnitFileState -p ActiveState",
            0,
            "LoadState=loaded\nFragmentPath=/lib/systemd/system/rc-local.service\nDropInPaths=\nUnitFileState=static\nActiveState=active\n",
        );
        host.answer(
            "systemctl show rc-local.service -p Restart -p RestartUSec -p RestartUSecNext -p RestartSteps -p RestartMaxDelayUSec",
            0,
            "Restart=no\nRestartUSec=100ms\n",
        );
        host.signal(100, Signal::Kill).unwrap();
        host.signals.borrow_mut().clear();

        let report = takeover(&host, &demo(), Path::new(STATE), false).unwrap();
        assert_eq!(report.outcome, Outcome::Done, "{report:?}");
        let ran = host.ran.borrow().clone();
        assert!(
            !ran.iter()
                .any(|command| command.contains("rc-local")
                    && !command.starts_with("systemctl show")),
            "{ran:?}"
        );
        assert_eq!(*host.signals.borrow(), vec![(200, Signal::Terminate)]);

        rollback(&host, Path::new(STATE)).unwrap();
        // Restarted as it ran: same user, group and environment.
        let spawned = host.spawned.borrow();
        assert_eq!(spawned.len(), 1);
        assert_eq!(spawned[0].uid, Some(1000));
        assert_eq!(spawned[0].gid, Some(100));
        assert_eq!(spawned[0].groups, Some(vec![27, 100, 998]));
        assert!(spawned[0].clear_env);
        assert!(spawned[0]
            .env
            .contains(&("PATH".to_string(), "/usr/bin".to_string())));
    }

    #[test]
    fn parses_restart_delays() {
        assert_eq!(timespan_ms("100ms"), Some(100));
        assert_eq!(timespan_ms("5s"), Some(5_000));
        assert_eq!(timespan_ms("1min 30s"), Some(90_000));
        assert_eq!(timespan_ms("0"), Some(0));
        assert_eq!(timespan_ms("1.500000s"), Some(1_500));
        assert_eq!(timespan_ms("2min 0.25s"), Some(120_250));
        assert_eq!(timespan_ms("0.0001ms"), Some(1));
        assert_eq!(timespan_ms("1w"), None);
        assert_eq!(timespan_ms("."), None);
        assert_eq!(timespan_ms("1.2.3s"), None);
    }

    #[test]
    fn a_host_unit_that_restarts_the_program_fails_the_takeover() {
        let host = machine();
        host.signal(100, Signal::Kill).unwrap();
        // A wrapper unit the profile does not name runs the program.
        let office = ["/opt/demo-meshd", "--net-name", "office"];
        host.process(
            300,
            "/opt/demo-meshd",
            &office,
            &[],
            "0::/system.slice/office-vpn.service\n",
        );
        host.answer(
            "systemctl show office-vpn.service -p Restart -p RestartUSec -p RestartUSecNext -p RestartSteps -p RestartMaxDelayUSec",
            0,
            "Restart=always\nRestartUSec=5s\n",
        );
        // It comes back after the delay.
        host.respawn_after_sleep.borrow_mut().push((
            301,
            office.iter().map(|arg| arg.to_string()).collect(),
            "0::/system.slice/office-vpn.service\n".into(),
        ));
        let report = takeover(&host, &demo(), Path::new(STATE), false).unwrap();
        assert_eq!(report.outcome, Outcome::RolledBack, "{report:?}");
        assert!(host.slept.borrow().iter().any(|ms| *ms >= 7_000));
        let verify = report
            .steps
            .iter()
            .find(|step| step.step == "verify")
            .unwrap();
        assert!(verify
            .detail
            .as_deref()
            .unwrap()
            .contains("office-vpn.service"));
        // The unit's own copy runs; the rollback does not start a second.
        assert!(host.alive.borrow().contains(&301));
        let spawned = host.spawned.borrow();
        assert!(
            !spawned.iter().any(|spawn| spawn.argv == office),
            "{spawned:?}"
        );
        // The process outside any unit is restarted as before.
        assert_eq!(spawned.len(), 1);
        assert_eq!(spawned[0].argv, ["/opt/demo-meshd", "--net-name", "lab"]);
        assert!(report.rollback.iter().any(|step| step
            .detail
            .as_deref()
            .is_some_and(|detail| detail.contains("already runs again as 301"))));
    }

    #[test]
    fn a_host_unit_with_a_long_restart_delay_is_not_guessed() {
        let host = machine();
        host.signal(100, Signal::Kill).unwrap();
        host.process(
            300,
            "/opt/demo-meshd",
            &["/opt/demo-meshd", "--net-name", "lab"],
            &[],
            "0::/system.slice/office-vpn.service\n",
        );
        host.answer(
            "systemctl show office-vpn.service -p Restart -p RestartUSec -p RestartUSecNext -p RestartSteps -p RestartMaxDelayUSec",
            0,
            "Restart=on-failure\nRestartUSec=5min\n",
        );
        let report = takeover(&host, &demo(), Path::new(STATE), false).unwrap();
        assert_eq!(report.outcome, Outcome::RolledBack, "{report:?}");
        // Decided before ending anything: no process was stopped, so there
        // is nothing the unit could start a second time.
        assert!(report
            .steps
            .iter()
            .any(|step| step.step == "check host units" && !step.ok));
        assert!(
            !host
                .signals
                .borrow()
                .iter()
                .any(|(pid, _)| *pid == 300 || *pid == 200),
            "{:?}",
            host.signals.borrow()
        );
        assert!(host.spawned.borrow().is_empty());
        assert!(host.alive.borrow().contains(&300));
    }

    #[test]
    fn a_failure_while_ending_processes_waits_for_host_units() {
        let host = machine();
        host.signal(100, Signal::Kill).unwrap();
        let office = ["/opt/demo-meshd", "--net-name", "office"];
        host.process(
            300,
            "/opt/demo-meshd",
            &office,
            &[],
            "0::/system.slice/office-vpn.service\n",
        );
        host.answer(
            "systemctl show office-vpn.service -p Restart -p RestartUSec -p RestartUSecNext -p RestartSteps -p RestartMaxDelayUSec",
            0,
            "Restart=always\nRestartUSec=1.5s\n",
        );
        // Ended after the others, and it will not exit.
        host.process(
            400,
            "/opt/demo-meshd",
            &["/opt/demo-meshd", "--net-name", "lab2"],
            &[],
            "0::/user.slice\n",
        );
        host.unkillable.borrow_mut().insert(400);
        host.respawn_after_sleep.borrow_mut().push((
            301,
            office.iter().map(|arg| arg.to_string()).collect(),
            "0::/system.slice/office-vpn.service\n".into(),
        ));
        let report = takeover(&host, &demo(), Path::new(STATE), false).unwrap();
        assert_eq!(report.outcome, Outcome::RolledBack, "{report:?}");
        // Waited out the unit's delay before undoing anything.
        assert!(
            host.slept.borrow().contains(&3_500),
            "{:?}",
            host.slept.borrow()
        );
        let spawned = host.spawned.borrow();
        assert!(
            !spawned.iter().any(|spawn| spawn.argv == office),
            "{spawned:?}"
        );
        assert!(spawned
            .iter()
            .any(|spawn| spawn.argv == ["/opt/demo-meshd", "--net-name", "lab"]));
    }

    #[test]
    fn a_copy_run_by_another_user_or_in_a_container_is_not_ours() {
        let host = FakeHost::default();
        let argv: Vec<String> = ["/opt/demo-meshd", "--net-name", "lab"]
            .iter()
            .map(|arg| arg.to_string())
            .collect();
        let args: Vec<&str> = argv.iter().map(String::as_str).collect();
        let copy = |uid, net: Option<&str>| running_copy(&host, "/opt/demo-meshd", &argv, uid, net);
        host.process(500, "/opt/demo-meshd", &args, &[], "0::/user.slice\n");
        host.file("/proc/500/status", "Uid:\t1000\t1000\t1000\t1000\n");
        assert_eq!(copy(Some(1000), None), CopyCheck::Running(500));
        assert_eq!(copy(Some(0), None), CopyCheck::None);
        host.file("/proc/500/cgroup", "0::/system.slice/docker-abc.scope\n");
        assert_eq!(copy(Some(1000), None), CopyCheck::None);
        host.file("/proc/500/cgroup", "0::/user.slice\n");
        // Another network than the one the ended process was in.
        host.link("/proc/500/ns/net", "net:[2]");
        assert_eq!(copy(Some(1000), Some("net:[1]")), CopyCheck::None);
        assert_eq!(copy(Some(1000), Some("net:[2]")), CopyCheck::Running(500));
        // Older records compare with PID 1's network.
        host.link("/proc/1/ns/net", "net:[1]");
        assert_eq!(copy(Some(1000), None), CopyCheck::None);
        host.link("/proc/500/ns/net", "net:[1]");
        assert_eq!(copy(Some(1000), None), CopyCheck::Running(500));
        // A unit's private mounts (PrivateTmp=, ProtectSystem=) do not make
        // it another copy: mount namespaces are not compared.
        host.link(&format!("/proc/{}/ns/mnt", host.own_pid()), "mnt:[1]");
        host.link("/proc/500/ns/mnt", "mnt:[9]");
        assert_eq!(copy(Some(1000), None), CopyCheck::Running(500));
        // Same command line but nothing else readable: it may be a copy, so
        // it is neither counted nor ignored.
        host.links.borrow_mut().remove(Path::new("/proc/500/exe"));
        assert_eq!(copy(Some(1000), None), CopyCheck::Unknown(500));
        host.link("/proc/500/exe", "/opt/demo-meshd");
        host.files
            .borrow_mut()
            .remove(Path::new("/proc/500/status"));
        assert_eq!(copy(Some(1000), None), CopyCheck::Unknown(500));
        assert_eq!(copy(None, None), CopyCheck::Running(500));
        // Another program with the same command line is not a candidate.
        host.link("/proc/500/exe", "/usr/bin/other");
        assert_eq!(copy(Some(1000), None), CopyCheck::None);
    }

    #[test]
    fn restart_delays_that_grow_are_waited_out_in_full() {
        let host = FakeHost::default();
        let units: BTreeSet<String> = ["office-vpn.service".to_string()].into();
        let key = "systemctl show office-vpn.service -p Restart -p RestartUSec -p RestartUSecNext -p RestartSteps -p RestartMaxDelayUSec";
        // Older systemd: only RestartUSec.
        host.answer(key, 0, "Restart=always\nRestartUSec=1s\n");
        assert_eq!(restart_wait_ms(&host, &units), Ok(3_000));
        // The next restart already waits longer.
        host.answer(
            key,
            0,
            "Restart=always\nRestartUSec=1s\nRestartUSecNext=4s\nRestartSteps=0\nRestartMaxDelayUSec=infinity\n",
        );
        assert_eq!(restart_wait_ms(&host, &units), Ok(6_000));
        // Growing delays: the longest one counts.
        host.answer(
            key,
            0,
            "Restart=always\nRestartUSec=1s\nRestartUSecNext=1s\nRestartSteps=3\nRestartMaxDelayUSec=10s\n",
        );
        assert_eq!(restart_wait_ms(&host, &units), Ok(12_000));
        // Growing without a bound is not guessed.
        host.answer(
            key,
            0,
            "Restart=always\nRestartUSec=1s\nRestartUSecNext=1s\nRestartSteps=3\nRestartMaxDelayUSec=infinity\n",
        );
        assert!(restart_wait_ms(&host, &units).is_err());
    }

    #[test]
    fn a_rollback_does_not_guess_about_a_process_it_cannot_read() {
        let host = machine();
        let report = takeover(&host, &demo(), Path::new(STATE), false).unwrap();
        assert_eq!(report.outcome, Outcome::Done, "{report:?}");
        // Same command line, program unreadable (a security module hides it).
        host.process(
            600,
            "/opt/demo-meshd",
            &["/opt/demo-meshd", "--net-name", "lab"],
            &[],
            "0::/user.slice\n",
        );
        host.links.borrow_mut().remove(Path::new("/proc/600/exe"));
        host.spawned.borrow_mut().clear();
        let first = rollback(&host, Path::new(STATE)).unwrap();
        assert!(!first.ok, "{first:?}");
        assert!(host.spawned.borrow().is_empty());
        // Once it is gone, a later rollback starts the program.
        host.signal(600, Signal::Kill).unwrap();
        let second = rollback(&host, Path::new(STATE)).unwrap();
        assert!(second.ok, "{second:?}");
        assert!(host
            .spawned
            .borrow()
            .iter()
            .any(|spawn| spawn.argv == ["/opt/demo-meshd", "--net-name", "lab"]));
    }

    #[test]
    fn a_process_in_another_network_namespace_is_left_to_the_operator() {
        let host = machine();
        host.link("/proc/1/ns/net", "net:[1]");
        host.link("/proc/100/ns/net", "net:[1]");
        // Started with `ip netns exec`: a rollback could not put it back.
        host.link("/proc/200/ns/net", "net:[7]");
        let report = takeover(&host, &demo(), Path::new(STATE), false).unwrap();
        assert_eq!(report.outcome, Outcome::RolledBack, "{report:?}");
        assert!(report.steps.iter().any(|step| !step.ok
            && step.detail.as_deref().is_some_and(
                |detail| detail.starts_with("process 200 runs in another network namespace")
            )));
        assert!(host.spawned.borrow().is_empty());
        // Found before anything changed: no service stopped or turned off,
        // no line commented, no process signalled.
        assert!(
            host.signals.borrow().is_empty(),
            "{:?}",
            host.signals.borrow()
        );
        assert!(!host.ran.borrow().iter().any(|command| {
            command.starts_with("systemctl stop") || command.starts_with("systemctl disable")
        }));
        assert!(!host.text("/etc/rc.local").unwrap().contains(COMMENT_MARKER));
    }

    #[test]
    fn the_operator_can_forget_a_process_started_by_hand() {
        let host = machine();
        let report = takeover(&host, &demo(), Path::new(STATE), false).unwrap();
        assert_eq!(report.outcome, Outcome::Done, "{report:?}");
        // A security module keeps hiding a process with the same command line.
        host.process(
            600,
            "/opt/demo-meshd",
            &["/opt/demo-meshd", "--net-name", "lab"],
            &[],
            "0::/user.slice\n",
        );
        host.links.borrow_mut().remove(Path::new("/proc/600/exe"));
        assert!(!rollback(&host, Path::new(STATE)).unwrap().ok);
        // Only a process that was recorded can be forgotten.
        assert!(rollback_forgetting(&host, Path::new(STATE), &[999]).is_err());
        let done = rollback_forgetting(&host, Path::new(STATE), &[200]).unwrap();
        assert!(done.ok, "{done:?}");
        assert_eq!(done.steps[0].step, "forget process 200");
        assert!(host.spawned.borrow().is_empty());
        let manifest = load_manifest(&host, Path::new(STATE)).unwrap().unwrap();
        assert!(manifest.steps.is_empty());
        // What the operator dropped stays on record.
        assert_eq!(manifest.forgotten.len(), 1);
        assert_eq!(manifest.forgotten[0].pid, 200);
        assert_eq!(
            manifest.forgotten[0].argv,
            ["/opt/demo-meshd", "--net-name", "lab"]
        );
    }

    #[test]
    fn a_record_too_large_to_read_back_is_never_saved() {
        let host = FakeHost::default();
        let huge = Manifest {
            manifest_version: MANIFEST_VERSION,
            steps: vec![Step {
                action: Action::CommentLine {
                    file: "/etc/rc.local".into(),
                    line: 1,
                    original: "x".repeat(crate::host::MAX_TEXT_FILE as usize),
                    sha256_after: String::new(),
                },
                at: 0,
                run: 1,
            }],
            runs: 1,
            forgotten: Vec::new(),
        };
        assert!(save_manifest(&host, Path::new(STATE), &huge).is_err());
        assert!(!host.exists(&Path::new(STATE).join(MANIFEST)));
    }

    #[test]
    fn a_process_that_will_not_exit_does_not_hide_those_ended_after_it() {
        let host = machine();
        // Listed before the others in /proc (`/proc/10` sorts before
        // `/proc/100` and `/proc/200`), and it will not exit.
        host.process(
            10,
            "/opt/demo-meshd",
            &["/opt/demo-meshd", "--net-name", "lab2"],
            &[],
            "0::/user.slice\n",
        );
        host.unkillable.borrow_mut().insert(10);
        let report = takeover(&host, &demo(), Path::new(STATE), false).unwrap();
        assert_eq!(report.outcome, Outcome::RolledBack, "{report:?}");
        assert!(report
            .steps
            .iter()
            .any(|step| !step.ok && step.detail.as_deref() == Some("process 10 did not exit")));
        // Process 200, ended after the failure, is recorded and started again.
        assert!(report
            .steps
            .iter()
            .any(|step| step.ok && step.step.starts_with("end process 200 ")));
        assert!(host
            .spawned
            .borrow()
            .iter()
            .any(|spawn| spawn.argv == ["/opt/demo-meshd", "--net-name", "lab"]));
    }

    #[test]
    fn a_failed_rollback_retries_only_what_is_left() {
        let host = machine();
        host.signal(100, Signal::Kill).unwrap();
        let report = takeover(&host, &demo(), Path::new(STATE), false).unwrap();
        assert_eq!(report.outcome, Outcome::Done, "{report:?}");

        // The service cannot be started the first time.
        host.answer("systemctl start demo-meshd.service", 1, "");
        let first = rollback(&host, Path::new(STATE)).unwrap();
        assert!(!first.ok);
        assert_eq!(host.spawned.borrow().len(), 1);
        let manifest = load_manifest(&host, Path::new(STATE)).unwrap().unwrap();
        assert!(manifest.steps.iter().all(|step| matches!(
            step.action,
            Action::SystemdStop { .. } | Action::Backup { .. }
        )));

        host.answer("systemctl start demo-meshd.service", 0, "");
        host.ran.borrow_mut().clear();
        let second = rollback(&host, Path::new(STATE)).unwrap();
        assert!(second.ok, "{second:?}");
        // The manual process is not started twice and rc.local is fine.
        assert_eq!(host.spawned.borrow().len(), 1);
        assert_eq!(
            *host.ran.borrow(),
            vec!["systemctl start demo-meshd.service".to_string()]
        );
        assert_eq!(
            host.text("/etc/rc.local").unwrap(),
            "#!/bin/sh\n/opt/demo-meshd --net-name lab &\nexit 0\n"
        );
        assert!(load_manifest(&host, Path::new(STATE))
            .unwrap()
            .unwrap()
            .steps
            .is_empty());
    }

    #[test]
    fn openrc_services_are_stopped_only_when_running() {
        let host = FakeHost::default();
        host.file(
            "/etc/init.d/demo-meshd",
            "#!/sbin/openrc-run\ncommand=\"/usr/bin/demo-meshd\"\ncommand_args=\"-c /etc/demo.toml\"\n",
        );
        host.answer("rc-update show -v", 0, "         demo-meshd | default\n");
        let report = takeover(&host, &demo(), Path::new(STATE), false).unwrap();
        assert_eq!(report.outcome, Outcome::Done, "{report:?}");
        let ran = host.ran.borrow().clone();
        assert!(ran.contains(&"rc-update del demo-meshd default".to_string()));
        assert!(
            !ran.iter().any(|command| command.contains("stop")),
            "{ran:?}"
        );

        host.ran.borrow_mut().clear();
        assert!(rollback(&host, Path::new(STATE)).unwrap().ok);
        let ran = host.ran.borrow().clone();
        assert_eq!(ran, vec!["rc-update add demo-meshd default".to_string()]);
    }

    #[test]
    fn nothing_found() {
        let host = FakeHost::default();
        let report = takeover(&host, &demo(), Path::new(STATE), false).unwrap();
        assert_eq!(report.outcome, Outcome::NothingFound);
    }

    const DAEMON: &str = "/Library/LaunchDaemons/com.example.demo.plist";

    /// A Mac: a system daemon running the program, and a copy a user
    /// started by hand.
    fn mac() -> FakeHost {
        let mut host = FakeHost::default();
        host.programs.insert("launchctl".into());
        host.programs.insert("plutil".into());
        host.file(DAEMON, "<plist/>");
        host.answer(
            &format!("plutil -convert json -o - -- {DAEMON}"),
            0,
            r#"{"Label":"com.example.demo","ProgramArguments":["/usr/local/bin/demo-meshd","-c","/etc/demo/a.toml"],"KeepAlive":true}"#,
        );
        host.answer(
            "launchctl print-disabled system",
            0,
            "disabled services = {\n}\n",
        );
        host.launchd.borrow_mut().insert(
            "system/com.example.demo".into(),
            (DAEMON.into(), Some(300), true),
        );
        host.table_process(
            300,
            "/usr/local/bin/demo-meshd",
            &["/usr/local/bin/demo-meshd", "-c", "/etc/demo/a.toml"],
            &[],
            0,
        );
        host.table_process(
            400,
            "/Users/alice/bin/demo-meshd",
            &["/Users/alice/bin/demo-meshd", "--net-name", "lab"],
            &["DEMO_NET_SECRET=x", "HOME=/Users/alice"],
            501,
        );
        host
    }

    #[test]
    fn a_launchd_job_is_unloaded_then_turned_off_and_restored_in_reverse() {
        let host = mac();
        let report = takeover(&host, &demo(), Path::new(STATE), false).unwrap();
        assert_eq!(report.outcome, Outcome::Done, "{report:?}");
        let steps: Vec<&str> = report.steps.iter().map(|step| step.step.as_str()).collect();
        assert_eq!(
            steps[1..],
            [
                "launchctl bootout system/com.example.demo",
                "launchctl disable system/com.example.demo",
                "end process 400 (/Users/alice/bin/demo-meshd) with TERM",
            ]
        );
        assert!(steps[0].starts_with(&format!("backup {DAEMON} -> ")));
        // Only the copy started by hand was signalled; launchd ended its own.
        assert_eq!(*host.signals.borrow(), vec![(400, Signal::Terminate)]);
        // A job launchd keeps alive comes back only after its throttle
        // interval: waited out before the final check.
        assert!(host.slept.borrow().contains(&LAUNCHD_RESTART_WAIT_MS));
        let manifest = load_manifest(&host, Path::new(STATE)).unwrap().unwrap();
        let restart = manifest.steps.iter().find_map(|step| match &step.action {
            Action::Terminate { pid, restart, .. } => Some((*pid, *restart)),
            _ => None,
        });
        assert_eq!(restart, Some((400, true)));

        let rollback = rollback(&host, Path::new(STATE)).unwrap();
        assert!(rollback.ok, "{rollback:?}");
        let ran = host.ran.borrow();
        let enable = ran
            .iter()
            .position(|line| line == "launchctl enable system/com.example.demo")
            .expect("turned on again");
        let bootstrap = ran
            .iter()
            .position(|line| *line == format!("launchctl bootstrap system {DAEMON}"))
            .expect("loaded again");
        // launchd loads no job that is turned off.
        assert!(enable < bootstrap);
        let spawned = host.spawned.borrow();
        assert_eq!(spawned.len(), 1);
        assert_eq!(spawned[0].argv[0], "/Users/alice/bin/demo-meshd");
        assert_eq!(spawned[0].uid, Some(501));
        assert!(spawned[0].clear_env);
    }

    #[test]
    fn a_launchd_job_already_off_at_boot_is_only_unloaded() {
        let host = mac();
        host.answer(
            "launchctl print-disabled system",
            0,
            "disabled services = {\n\t\"com.example.demo\" => disabled\n}\n",
        );
        let report = takeover(&host, &demo(), Path::new(STATE), true).unwrap();
        let steps: Vec<&str> = report.steps.iter().map(|step| step.step.as_str()).collect();
        let backup = format!("backup {DAEMON}");
        assert_eq!(
            steps,
            vec![
                backup.as_str(),
                "launchctl bootout system/com.example.demo",
                "end remaining processes",
            ]
        );
    }

    #[test]
    fn a_users_agent_is_taken_over_in_that_users_session() {
        let host = mac();
        let agent = "/Users/alice/Library/LaunchAgents/local.demo.plist";
        host.file(agent, "<plist/>");
        host.stats.borrow_mut().insert(
            PathBuf::from(agent),
            crate::host::FileStat {
                mode: 0o644,
                uid: 501,
                gid: 20,
            },
        );
        host.answer(
            &format!("plutil -convert json -o - -- {agent}"),
            0,
            r#"{"Label":"local.demo","ProgramArguments":["/bin/sh","-c","exec /Users/alice/bin/demo-meshd --net-name lab"]}"#,
        );
        host.answer("launchctl print-disabled gui/501", 0, "");
        host.launchd
            .borrow_mut()
            .insert("gui/501/local.demo".into(), (agent.into(), None, true));
        let report = takeover(&host, &demo(), Path::new(STATE), false).unwrap();
        assert_eq!(report.outcome, Outcome::Done, "{report:?}");
        let steps: Vec<&str> = report.steps.iter().map(|step| step.step.as_str()).collect();
        assert!(steps.contains(&"launchctl bootout gui/501/local.demo"));
        assert!(steps.contains(&"launchctl disable gui/501/local.demo"));
        // The agent's shell runs the copy: loading the agent again starts
        // it, so the rollback does not start it a second time.
        let manifest = load_manifest(&host, Path::new(STATE)).unwrap().unwrap();
        assert!(manifest.steps.iter().all(|step| !matches!(
            step.action,
            Action::Terminate {
                pid: 400,
                restart: true,
                ..
            }
        )));
    }

    #[test]
    fn an_agent_every_user_loads_is_left_to_the_operator() {
        let host = mac();
        let shared = "/Library/LaunchAgents/com.example.demo-ui.plist";
        host.file(shared, "<plist/>");
        host.answer(
            &format!("plutil -convert json -o - -- {shared}"),
            0,
            r#"{"Label":"com.example.demo-ui","Program":"/usr/local/bin/demo-meshd"}"#,
        );
        let report = takeover(&host, &demo(), Path::new(STATE), true).unwrap();
        assert_eq!(
            report.manual,
            vec![format!("login item com.example.demo-ui ({shared})")]
        );
        assert!(report
            .steps
            .iter()
            .all(|step| !step.step.contains("com.example.demo-ui")));
    }

    #[test]
    fn a_failed_unload_is_put_back() {
        let host = mac();
        // Turning the job off fails after it was unloaded.
        host.answer("launchctl disable system/com.example.demo", 1, "");
        let report = takeover(&host, &demo(), Path::new(STATE), false).unwrap();
        assert_eq!(report.outcome, Outcome::RolledBack, "{report:?}");
        assert!(host
            .ran
            .borrow()
            .contains(&format!("launchctl bootstrap system {DAEMON}")));
        assert!(host.signals.borrow().is_empty());
    }

    #[test]
    fn a_copy_in_the_process_table_is_not_started_twice() {
        let host = mac();
        let argv: Vec<String> = ["/Users/alice/bin/demo-meshd", "--net-name", "lab"]
            .map(String::from)
            .to_vec();
        assert_eq!(
            running_copy(&host, "/Users/alice/bin/demo-meshd", &argv, Some(501), None),
            CopyCheck::Running(400)
        );
        // Another user's copy is not ours.
        assert_eq!(
            running_copy(&host, "/Users/alice/bin/demo-meshd", &argv, Some(502), None),
            CopyCheck::None
        );
        // A copy whose program cannot be read may be ours.
        host.table
            .borrow_mut()
            .as_mut()
            .unwrap()
            .get_mut(&400)
            .unwrap()
            .exe = None;
        assert_eq!(
            running_copy(&host, "/Users/alice/bin/demo-meshd", &argv, Some(501), None),
            CopyCheck::Unknown(400)
        );
    }

    const ADMIN: &str = "S-1-5-21-9-500";
    const SYSTEM: &str = "S-1-5-18";

    /// A Windows machine: a service running the program, a copy the
    /// administrator started by hand, and this program run by the
    /// administrator.
    fn windows(services_json: &str) -> FakeHost {
        let mut host = FakeHost::default();
        host.programs.insert("powershell.exe".into());
        host.answer(
            &format!(
                "powershell.exe -NoProfile -NonInteractive -Command {}",
                crate::winsvc::SERVICES_QUERY
            ),
            0,
            services_json,
        );
        host.answer(
            "sc.exe query DemoMesh",
            0,
            "SERVICE_NAME: DemoMesh\r\n        STATE              : 1  STOPPED\r\n",
        );
        host.windows_process(
            1,
            r"C:\anixops\anixops-mesh.exe",
            &["anixops-mesh"],
            ADMIN,
            9,
        );
        host.windows_process(
            500,
            r"C:\Program Files\Demo\demo-meshd.exe",
            &[
                r"C:\Program Files\Demo\demo-meshd.exe",
                "-c",
                r"C:\demo\a.toml",
            ],
            SYSTEM,
            600,
        );
        host.windows_process(
            700,
            r"C:\Users\admin\demo-meshd.exe",
            &[r"C:\Users\admin\demo-meshd.exe", "--net-name", "lab"],
            ADMIN,
            800,
        );
        host.exits_on
            .borrow_mut()
            .insert("sc.exe stop DemoMesh".into(), vec![500]);
        host
    }

    const DEMO_SERVICE: &str = r#"[{"Name":"DemoMesh","PathName":"\"C:\\Program Files\\Demo\\demo-meshd.exe\" -c C:\\demo\\a.toml","StartMode":"Auto","State":"Running","ProcessId":500,"DelayedAutoStart":true},{"Name":"Spooler","PathName":"C:\\Windows\\System32\\spoolsv.exe","StartMode":"Auto","State":"Running","ProcessId":40,"DelayedAutoStart":false}]"#;

    #[test]
    fn a_windows_service_is_stopped_then_turned_off_and_restored_in_reverse() {
        let host = windows(DEMO_SERVICE);
        let report = takeover(&host, &demo(), Path::new(STATE), false).unwrap();
        assert_eq!(report.outcome, Outcome::Done, "{report:?}");
        let steps: Vec<&str> = report.steps.iter().map(|step| step.step.as_str()).collect();
        assert_eq!(
            steps,
            vec![
                "sc.exe stop DemoMesh",
                "sc.exe config DemoMesh start= disabled (was delayed-auto)",
                r"end process 700 (C:\Users\admin\demo-meshd.exe) with TERM",
            ]
        );
        // The service's own process was ended by the service manager.
        assert_eq!(*host.signals.borrow(), vec![(700, Signal::Terminate)]);
        assert!(!host
            .ran
            .borrow()
            .iter()
            .any(|line| line.contains("Spooler")));

        let rollback = rollback(&host, Path::new(STATE)).unwrap();
        assert!(rollback.ok, "{rollback:?}");
        let ran = host.ran.borrow();
        let config = ran
            .iter()
            .position(|line| line == "sc.exe config DemoMesh start= delayed-auto")
            .expect("start type restored");
        let start = ran
            .iter()
            .position(|line| line == "sc.exe start DemoMesh")
            .expect("started again");
        // Windows starts no service that is turned off.
        assert!(config < start);
        let spawned = host.spawned.borrow();
        assert_eq!(spawned.len(), 1);
        assert_eq!(spawned[0].argv[0], r"C:\Users\admin\demo-meshd.exe");
        assert_eq!(spawned[0].cwd.as_deref(), Some(r"C:\"));
        assert!(spawned[0].clear_env);
    }

    #[test]
    fn a_process_of_another_windows_account_is_left_to_the_operator() {
        let host = windows(DEMO_SERVICE);
        host.windows_process(
            701,
            r"C:\Users\bob\demo-meshd.exe",
            &[r"C:\Users\bob\demo-meshd.exe"],
            "S-1-5-21-9-1001",
            800,
        );
        let report = takeover(&host, &demo(), Path::new(STATE), false).unwrap();
        assert_eq!(report.outcome, Outcome::RolledBack, "{report:?}");
        assert!(report
            .steps
            .iter()
            .any(|step| step
                .detail
                .as_deref()
                .is_some_and(|detail| detail
                    .contains("process 701 runs as another account (S-1-5-21-9-1001)"))));
        // Nothing was changed.
        assert!(!host
            .ran
            .borrow()
            .iter()
            .any(|line| line.starts_with("sc.exe")));
        assert!(host.signals.borrow().is_empty());
    }

    #[test]
    fn a_wrapper_service_named_in_the_profile_is_taken_over_with_its_child() {
        let host = windows(
            r#"[{"Name":"demo-meshd","PathName":"C:\\tools\\wrapper.exe","StartMode":"Manual","State":"Running","ProcessId":900,"DelayedAutoStart":false}]"#,
        );
        // Only the wrapper service runs the program here.
        host.table.borrow_mut().as_mut().unwrap().remove(&500);
        host.windows_process(
            900,
            r"C:\tools\wrapper.exe",
            &[r"C:\tools\wrapper.exe"],
            SYSTEM,
            600,
        );
        host.windows_process(
            901,
            r"C:\opt\Demo-Meshd.EXE",
            &[r"C:\opt\Demo-Meshd.EXE", "--net-name", "lab"],
            SYSTEM,
            900,
        );
        host.answer(
            "sc.exe query demo-meshd",
            0,
            "        STATE              : 1  STOPPED\r\n",
        );
        host.exits_on
            .borrow_mut()
            .insert("sc.exe stop demo-meshd".into(), vec![900, 901]);
        let found = detect(&host, &demo());
        let service = found
            .iter()
            .find(|entry| matches!(entry.origin, Origin::WinService { .. }))
            .unwrap();
        assert_eq!(service.processes.len(), 1);
        assert_eq!(service.processes[0].pid, 901);
        assert_eq!(
            service.invocation.as_ref().unwrap().args,
            vec!["--net-name".to_string(), "lab".to_string()]
        );
        let report = takeover(&host, &demo(), Path::new(STATE), false).unwrap();
        assert_eq!(report.outcome, Outcome::Done, "{report:?}");
        let steps: Vec<&str> = report.steps.iter().map(|step| step.step.as_str()).collect();
        assert!(steps.contains(&"sc.exe config demo-meshd start= disabled (was demand)"));
        // The service's child runs as another account but is the
        // service's: no account check, and not restarted on its own.
        let manifest = load_manifest(&host, Path::new(STATE)).unwrap().unwrap();
        assert!(manifest
            .steps
            .iter()
            .all(|step| !matches!(step.action, Action::Terminate { pid: 901, .. })));
    }
}
