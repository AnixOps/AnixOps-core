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

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::detect::{detect, scan_processes, Found, Origin};
use crate::host::{Host, Signal, Spawn};
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
        cwd: Option<String>,
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
                "another takeover or rollback is running ({} exists)",
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
        let pid = host.own_pid().to_string();
        match host.create_new(&path, pid.as_bytes()) {
            Ok(true) => Ok(Lock { host, path }),
            Ok(false) => Err(TakeoverError::Locked(path)),
            Err(error) => Err(TakeoverError::Io(format!("{}: {error}", path.display()))),
        }
    }
}

impl Drop for Lock<'_> {
    fn drop(&mut self) {
        let _ = self.host.remove_file(&self.path);
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
                stops.push(Planned::ScriptStop {
                    name: name.clone(),
                    script: script.clone(),
                    openrc: true,
                });
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

fn end_processes(host: &dyn Host, profile: &Profile) -> Vec<Result<Action, String>> {
    let mut out = Vec::new();
    for process in scan_processes(host, profile) {
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
            env: process.env.clone().into_iter().collect(),
            cwd: process.cwd.clone(),
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
    if failure.is_none() {
        for result in end_processes(host, profile) {
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
        let left: Vec<u32> = scan_processes(host, profile)
            .iter()
            .filter(|process| !process.contained)
            .map(|process| process.pid)
            .collect();
        if !left.is_empty() {
            let error = format!("processes still running after takeover: {left:?}");
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
        let (results, ok) = undo(host, &steps);
        report.rollback = results;
        if ok {
            report.outcome = Outcome::RolledBack;
            manifest.runs -= 1;
        } else {
            report.outcome = Outcome::RollbackFailed;
            // Keep what could not be undone for a later `rollback`.
            manifest.steps.extend(steps);
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
                if let Some((copy, mode, uid, gid)) = backup {
                    let bytes = host
                        .read(Path::new(&copy))
                        .map_err(|error| format!("{copy}: {error}"))?;
                    host.write(path, &bytes, mode, Some((uid, gid)))
                        .map_err(|error| format!("{file}: {error}"))?;
                    return Ok(format!("restored {file} from {copy}"));
                }
            }
            // The file changed since: put back just our line.
            let text = String::from_utf8_lossy(&current).into_owned();
            let marked = format!("{COMMENT_MARKER}{original}");
            let mut lines: Vec<String> = text.lines().map(str::to_string).collect();
            let index = line
                .checked_sub(1)
                .filter(|index| lines.get(*index) == Some(&marked))
                .or_else(|| lines.iter().position(|candidate| *candidate == marked))
                .ok_or_else(|| format!("{file}: the commented line is gone"))?;
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
            cwd,
            restart,
            pid,
            ..
        } => {
            if !*restart {
                return Ok(format!("process {pid} is started by its service"));
            }
            let new_pid = host
                .spawn_detached(&Spawn {
                    argv: argv.clone(),
                    env: env.clone(),
                    cwd: cwd.clone(),
                })
                .map_err(|error| format!("restarting process {pid}: {error}"))?;
            Ok(format!("restarted process {pid} as {new_pid}"))
        }
    }
}

/// Undoes steps in reverse order; keeps going past failures.
fn undo(host: &dyn Host, steps: &[Step]) -> (Vec<StepReport>, bool) {
    let backups: Vec<&Action> = steps
        .iter()
        .map(|step| &step.action)
        .filter(|action| matches!(action, Action::Backup { .. }))
        .collect();
    let mut results = Vec::new();
    let mut ok = true;
    for step in steps.iter().rev() {
        match undo_one(host, &step.action, &backups) {
            Ok(detail) => results.push(StepReport {
                step: step.action.describe(),
                ok: true,
                detail: Some(detail),
            }),
            Err(error) => {
                ok = false;
                results.push(StepReport {
                    step: step.action.describe(),
                    ok: false,
                    detail: Some(error),
                });
            }
        }
    }
    (results, ok)
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
    let (steps, ok) = undo(host, &manifest.steps);
    if ok {
        manifest.steps.clear();
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
        // The lock is released.
        assert!(!host.exists(&Path::new(STATE).join(LOCK)));

        host.ran.borrow_mut().clear();
        let rollback = rollback(&host, Path::new(STATE)).unwrap();
        assert!(rollback.ok, "{rollback:?}");
        let ran = host.ran.borrow().clone();
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
        host.file(&format!("{STATE}/{LOCK}"), "99");
        assert!(matches!(
            takeover(&host, &demo(), Path::new(STATE), false),
            Err(TakeoverError::Locked(_))
        ));
    }

    #[test]
    fn nothing_found() {
        let host = FakeHost::default();
        let report = takeover(&host, &demo(), Path::new(STATE), false).unwrap();
        assert_eq!(report.outcome, Outcome::NothingFound);
    }
}
