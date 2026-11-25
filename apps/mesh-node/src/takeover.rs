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

use crate::detect::{classify_units, detect, scan_processes, Found, Origin};
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
    let text = host
        .read_to_string(&path)
        .map_err(|error| TakeoverError::Manifest(error.to_string()))?;
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
    // It holds the command lines of ended processes, which may include
    // secrets: owner only.
    host.write(&state.join(MANIFEST), text.as_bytes(), 0o600, None)
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
            host.write(&copy, &bytes, 0o600, None)
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
    }
}

fn alive(host: &dyn Host, pid: u32, exe: &str) -> bool {
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

/// A running process of the same program and command line.
fn running_copy(host: &dyn Host, exe: &str, argv: &[String]) -> Option<u32> {
    let entries = host.list_dir(Path::new("/proc")).ok()?;
    entries.into_iter().find_map(|entry| {
        let pid: u32 = entry.file_name()?.to_str()?.parse().ok()?;
        if !alive(host, pid, exe) {
            return None;
        }
        let cmdline = host.read(&entry.join("cmdline")).ok()?;
        (crate::cmdline::split_nul(&cmdline) == argv).then_some(pid)
    })
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
) -> Vec<Result<Action, String>> {
    let mut out = Vec::new();
    let mut processes = scan_processes(host, profile);
    classify_units(&mut processes, owned_units);
    for process in processes {
        if process.contained {
            continue;
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
            restart: process.unit.is_none(),
            killed,
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

    for (index, step) in planned.iter().enumerate() {
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
    if failure.is_none() {
        for result in end_processes(host, profile, &owned_units) {
            match result {
                Ok(action) => {
                    if let Err(error) = record(&mut manifest, action, &mut report) {
                        failure = Some(format!("saving the manifest: {error}"));
                        break;
                    }
                }
                Err(error) => {
                    report.steps.push(StepReport {
                        step: "end process".into(),
                        ok: false,
                        detail: Some(error.clone()),
                    });
                    failure = Some(error);
                    break;
                }
            }
        }
    }
    if failure.is_none() {
        match restart_wait_ms(host, &host_units) {
            Ok(wait) if wait > 0 => host.sleep_ms(wait),
            Ok(_) => {}
            Err(error) => {
                report.steps.push(StepReport {
                    step: "verify".into(),
                    ok: false,
                    detail: Some(error.clone()),
                });
                failure = Some(error);
            }
        }
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
                    if let Ok(bytes) = host.read(Path::new(&copy)) {
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
            ..
        } => {
            if !*restart {
                return Ok(format!("process {pid} is started by its service"));
            }
            // A unit that restarts what it runs may already have started it
            // again; a second copy would fight it for ports, the virtual
            // interface and the node identity.
            if let Some(other) = running_copy(host, exe, argv) {
                return Ok(format!(
                    "process {pid} already runs again as {other}; not started twice"
                ));
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

/// How long to wait before the final check so that a host unit that
/// restarts the program has done so. A unit whose delay is unknown or too
/// long fails the takeover rather than report it done on a guess.
fn restart_wait_ms(host: &dyn Host, units: &BTreeSet<String>) -> Result<u64, String> {
    let mut wait = 0;
    for unit in units {
        let output = host
            .run(
                "systemctl",
                &["show", unit.as_str(), "-p", "Restart", "-p", "RestartUSec"],
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
        let delay = value("RestartUSec")
            .and_then(timespan_ms)
            .filter(|delay| *delay <= MAX_RESTART_WAIT_MS)
            .ok_or_else(|| {
                format!("{unit} restarts what it runs after an unknown or long delay; name it in the profile's detect.services")
            })?;
        wait = wait.max(delay + RESTART_MARGIN_MS);
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
    let _lock = Lock::take(host, state)?;
    let Some(mut manifest) = load_manifest(host, state)? else {
        return Ok(RollbackReport {
            report_version: crate::report::REPORT_VERSION,
            ok: true,
            steps: Vec::new(),
        });
    };
    let (steps, remaining) = undo(host, &manifest.steps);
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
            "systemctl show rc-local.service -p Restart -p RestartUSec",
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
            "systemctl show office-vpn.service -p Restart -p RestartUSec",
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
            "systemctl show office-vpn.service -p Restart -p RestartUSec",
            0,
            "Restart=on-failure\nRestartUSec=5min\n",
        );
        let report = takeover(&host, &demo(), Path::new(STATE), false).unwrap();
        assert_eq!(report.outcome, Outcome::RolledBack, "{report:?}");
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
}
