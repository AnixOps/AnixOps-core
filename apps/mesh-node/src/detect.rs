//! Finding existing installations (requirement R12). On Linux: systemd
//! services, OpenRC, OpenWrt procd and other init scripts, autostart lines
//! in `rc.local` and crontabs, and processes started by hand; containers are
//! found and reported but never touched. On macOS: launchd jobs (see
//! [`crate::launchd`]) and processes started by hand. On Windows: services
//! (see [`crate::winsvc`]), scheduled tasks and logon entries (see
//! [`crate::winstart`]) and processes started by hand.
//!
//! Each finding carries the command line the program runs with, taken from
//! the running process where there is one (the most exact source) and from
//! the service definition otherwise.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::cmdline::{
    command_in_line, exec_argv, leading_assignments, parse_assignments, parse_unit, split_nul,
    split_words, UnitService,
};
use crate::host::{Host, Os};
use crate::profile::Profile;
use crate::source::Invocation;

/// How an installation is started.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Origin {
    Systemd {
        unit: String,
        #[serde(default)]
        fragment: Option<String>,
        #[serde(default)]
        drop_ins: Vec<String>,
        /// `UnitFileState`: enabled, disabled, static, masked, ...
        unit_file_state: String,
        active: bool,
    },
    /// An OpenRC service.
    Openrc {
        name: String,
        script: String,
        runlevels: Vec<String>,
    },
    /// A System V style init script.
    Sysv { name: String, script: String },
    /// An OpenWrt procd init script, possibly installed by a package.
    Procd {
        name: String,
        script: String,
        /// Linked in `/etc/rc.d`, so it starts on boot.
        enabled: bool,
        /// procd has a running instance of the service.
        running: bool,
        /// The package that owns the script, when opkg or apk lists it.
        #[serde(default)]
        package: Option<String>,
    },
    /// A line in `rc.local` or a crontab.
    Autostart { file: String, line: usize },
    /// A process with no service or script behind it.
    Process { pid: u32 },
    /// Runs in a container; reported only.
    Container { id: String, image: String },
    /// A launchd job (macOS).
    Launchd {
        label: String,
        plist: String,
        /// `system`, or `gui/<uid>` for a user's agent; `None` for an agent
        /// every user loads, which is left to the operator.
        domain: Option<String>,
        /// `launchctl disable` (`true`) or `enable` (`false`) set for the
        /// job; `None` when its file's `Disabled` key decides.
        override_off: Option<bool>,
        disabled_key: bool,
        loaded: bool,
    },
    /// A Windows service.
    WinService {
        name: String,
        /// How it starts, as `sc.exe config start=` takes it: `auto`,
        /// `delayed-auto`, `demand`, `disabled` (or a driver's `boot`,
        /// `system`).
        start: String,
        running: bool,
    },
    /// A scheduled task (Windows), by its full name (`\folder\name`).
    WinTask {
        name: String,
        /// Not turned off.
        enabled: bool,
        running: bool,
    },
    /// A logon entry (Windows): a value of a `Run` key or an item of a
    /// Startup folder.
    WinLogon {
        /// The `Run` key or the Startup folder.
        place: String,
        /// The value or file name.
        name: String,
        /// The `StartupApproved` key that turns it off; `None` for a user
        /// whose settings are not loaded, which is left to the operator.
        approved: Option<String>,
        /// The value there before, in hexadecimal.
        previous: Option<String>,
        /// Already turned off there.
        disabled: bool,
    },
}

impl Origin {
    pub fn id(&self) -> String {
        match self {
            Origin::Systemd { unit, .. } => format!("systemd:{unit}"),
            Origin::Openrc { name, .. } => format!("openrc:{name}"),
            Origin::Sysv { name, .. } => format!("sysv:{name}"),
            Origin::Procd { name, .. } => format!("procd:{name}"),
            Origin::Autostart { file, line } => format!("autostart:{file}:{line}"),
            Origin::Process { pid } => format!("process:{pid}"),
            Origin::Container { id, .. } => format!("container:{id}"),
            Origin::Launchd { label, domain, .. } => {
                format!("launchd:{}/{label}", domain.as_deref().unwrap_or("*"))
            }
            Origin::WinService { name, .. } => format!("service:{name}"),
            Origin::WinTask { name, .. } => format!("task:{name}"),
            Origin::WinLogon { place, name, .. } => format!("logon:{place}\\{name}"),
        }
    }
}

/// A running process of the program.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Process {
    pub pid: u32,
    pub exe: String,
    /// Full argv including the program. Holds secrets; never printed.
    #[serde(skip_serializing, default)]
    pub argv: Vec<String>,
    #[serde(skip_serializing, default)]
    pub env: BTreeMap<String, String>,
    #[serde(default)]
    pub cwd: Option<String>,
    /// The program's own systemd service, from the cgroup. A process in the
    /// cgroup of any other unit (rc-local, cron, a user session, a process
    /// supervisor) has `None` here and that unit in `host_unit`: such a unit
    /// is never turned off or stopped.
    #[serde(default)]
    pub unit: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host_unit: Option<String>,
    /// Inside a container.
    #[serde(default)]
    pub contained: bool,
    /// Real user and group (from `/proc/PID/status`); a restart on rollback
    /// runs as them.
    #[serde(default)]
    pub uid: Option<u32>,
    #[serde(default)]
    pub gid: Option<u32>,
    /// Supplementary groups (`Groups:` in `/proc/PID/status`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub groups: Option<Vec<u32>>,
    /// The whole environment, for a restart on rollback. Holds secrets.
    #[serde(skip_serializing, default)]
    pub environ: Vec<(String, String)>,
    /// The parent process (Windows), which a service wrapper may be.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ppid: Option<u32>,
    /// The account it runs as (Windows), as a SID string.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sid: Option<String>,
}

/// Whether a process with this `/proc/PID/cgroup` runs in a container.
pub fn in_container(cgroup: &str) -> bool {
    [
        "docker",
        "containerd",
        "kubepods",
        "libpod",
        "/lxc",
        "machine.slice",
    ]
    .iter()
    .any(|marker| cgroup.contains(marker))
}

/// The real id from a `Uid:` or `Gid:` line of `/proc/PID/status`.
pub fn real_id(status: &str, key: &str) -> Option<u32> {
    status.lines().find_map(|line| {
        line.strip_prefix(key)?
            .split_whitespace()
            .next()?
            .parse::<u32>()
            .ok()
    })
}

/// One installation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Found {
    pub origin: Origin,
    /// The program path, when known.
    pub program: Option<String>,
    /// How it runs; `None` when that cannot be read with certainty.
    pub invocation: Option<Invocation>,
    /// Its running processes.
    pub processes: Vec<Process>,
    /// Why the command line is uncertain, or other facts for the report.
    pub notes: Vec<String>,
}

/// Printable summary: flag names only, never values.
#[derive(Debug, Clone, Serialize)]
pub struct FoundSummary {
    pub id: String,
    pub origin: Origin,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub program: Option<String>,
    pub flags: Vec<String>,
    pub env: Vec<String>,
    pub pids: Vec<u32>,
    pub notes: Vec<String>,
}

impl Found {
    pub fn summary(&self) -> FoundSummary {
        let flags = self
            .invocation
            .as_ref()
            .map(|invocation| {
                invocation
                    .args
                    .iter()
                    .filter(|arg| arg.len() > 1 && arg.starts_with('-'))
                    .map(|arg| {
                        let name = arg.split('=').next().unwrap_or(arg);
                        if name.starts_with("--") {
                            name.to_string()
                        } else {
                            name.chars().take(2).collect()
                        }
                    })
                    .collect()
            })
            .unwrap_or_default();
        let env = self
            .invocation
            .as_ref()
            .map(|invocation| invocation.env.keys().cloned().collect())
            .unwrap_or_default();
        FoundSummary {
            id: self.origin.id(),
            origin: self.origin.clone(),
            program: self.program.clone(),
            flags,
            env,
            pids: self.processes.iter().map(|process| process.pid).collect(),
            notes: self.notes.clone(),
        }
    }
}

const UNIT_DIRS: [&str; 5] = [
    "/etc/systemd/system",
    "/run/systemd/system",
    "/usr/local/lib/systemd/system",
    "/usr/lib/systemd/system",
    "/lib/systemd/system",
];

/// The file name of a path; a Windows path (`C:\\…`, `\\\\server\\…`)
/// is split at backslashes too.
pub fn base_name(path: &str) -> &str {
    if windows_path(path) {
        path.rsplit(['/', '\\']).next().unwrap_or(path)
    } else {
        path.rsplit('/').next().unwrap_or(path)
    }
}

fn windows_path(path: &str) -> bool {
    let bytes = path.as_bytes();
    (bytes.len() >= 3 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' && bytes[2] == b'\\')
        || path.starts_with("\\\\")
}

/// Whether a program file is one of `names`. Windows file names compare
/// without case, and `name.exe` is `name`.
pub fn program_named(names: &[String], path: &str) -> bool {
    let base = base_name(path.trim_end_matches(" (deleted)"));
    if !windows_path(path) {
        return names.iter().any(|name| name == base);
    }
    let cut = base.len().saturating_sub(4);
    let stem = match base.get(cut..) {
        Some(ext) if cut > 0 && ext.eq_ignore_ascii_case(".exe") => &base[..cut],
        _ => base,
    };
    names
        .iter()
        .any(|name| name.eq_ignore_ascii_case(base) || name.eq_ignore_ascii_case(stem))
}

fn is_program(profile: &Profile, path: &str) -> bool {
    program_named(&profile.detect.executables, path)
}

fn wanted_env(
    profile: &Profile,
    env: impl IntoIterator<Item = (String, String)>,
) -> BTreeMap<String, String> {
    env.into_iter()
        .filter(|(name, _)| profile.wants_env(name))
        .collect()
}

/// Running processes of the program.
pub fn scan_processes(host: &dyn Host, profile: &Profile) -> Vec<Process> {
    let mut out = Vec::new();
    if uses_process_table(host) {
        return scan_table(host, profile);
    }
    let own = host.own_pid();
    let Ok(entries) = host.list_dir(Path::new("/proc")) else {
        return out;
    };
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
        let argv = host
            .read(&entry.join("cmdline"))
            .map(|bytes| split_nul(&bytes))
            .unwrap_or_default();
        let exe = host
            .read_link(&entry.join("exe"))
            .ok()
            .map(|path| path.display().to_string())
            .map(|path| path.trim_end_matches(" (deleted)").to_string())
            .or_else(|| argv.first().cloned());
        let Some(exe) = exe else {
            continue;
        };
        if !is_program(profile, &exe) {
            continue;
        }
        let environ = host
            .read(&entry.join("environ"))
            .map(|bytes| {
                split_nul(&bytes)
                    .into_iter()
                    .filter_map(|pair| {
                        pair.split_once('=')
                            .map(|(name, value)| (name.to_string(), value.to_string()))
                    })
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        let status = host
            .read_to_string(&entry.join("status"))
            .unwrap_or_default();
        // "Uid:\treal\teffective\tsaved\tfs": the real id.
        let (uid, gid) = (real_id(&status, "Uid:"), real_id(&status, "Gid:"));
        let groups = status.lines().find_map(|line| {
            line.strip_prefix("Groups:").map(|list| {
                list.split_whitespace()
                    .filter_map(|group| group.parse::<u32>().ok())
                    .collect::<Vec<_>>()
            })
        });
        let cwd = host
            .read_link(&entry.join("cwd"))
            .ok()
            .map(|path| path.display().to_string());
        let cgroup = host
            .read_to_string(&entry.join("cgroup"))
            .unwrap_or_default();
        let contained = in_container(&cgroup);
        let unit = cgroup.lines().find_map(|line| {
            let path = line.rsplit(':').next()?;
            path.split('/')
                .rev()
                .find(|segment| segment.ends_with(".service"))
                .map(str::to_string)
        });
        out.push(Process {
            pid,
            exe,
            argv,
            env: wanted_env(profile, environ.clone()),
            cwd,
            unit,
            host_unit: None,
            contained,
            uid,
            gid,
            groups,
            environ,
            ppid: None,
            sid: None,
        });
    }
    out
}

/// Whether processes are read from the process table (macOS, Windows)
/// rather than from `/proc` (Linux). Decided by the system, never by
/// whether `/proc` exists: on Windows any user may create `C:\proc`.
pub fn uses_process_table(host: &dyn Host) -> bool {
    host.os() != Os::Linux
}

/// Running processes of the program, from the process table (macOS).
/// There are no containers or cgroups to read there.
fn scan_table(host: &dyn Host, profile: &Profile) -> Vec<Process> {
    let own = host.own_pid();
    let Ok(pids) = host.list_pids() else {
        return Vec::new();
    };
    pids.into_iter()
        .filter(|pid| *pid != own)
        .filter_map(|pid| {
            let info = host.process_info(pid).ok()?;
            let exe = info.exe.clone().or_else(|| info.argv.first().cloned())?;
            if !is_program(profile, &exe) {
                return None;
            }
            Some(Process {
                pid,
                exe,
                env: wanted_env(profile, info.environ.clone()),
                argv: info.argv,
                cwd: info.cwd,
                unit: None,
                host_unit: None,
                contained: false,
                uid: info.uid,
                gid: info.gid,
                groups: info.groups,
                environ: info.environ,
                ppid: info.ppid,
                sid: info.sid,
            })
        })
        .collect()
}

/// How many parents up [`descends_from`] looks.
const MAX_ANCESTRY: usize = 16;

/// Whether `ancestor` started the process, directly or through its
/// children (a wrapper that runs `cmd` that runs the program), as the
/// process table records parents.
pub fn descends_from(host: &dyn Host, process: &Process, ancestor: u32) -> bool {
    let mut parent = process.ppid;
    for _ in 0..MAX_ANCESTRY {
        match parent {
            Some(pid) if pid == ancestor => return true,
            // Pid 0 and the system process (4 on Windows, 1 elsewhere)
            // end the chain.
            Some(pid) if pid > 4 && pid != process.pid => {
                parent = host.process_info(pid).ok().and_then(|info| info.ppid);
            }
            _ => return false,
        }
    }
    false
}

fn show_unit(host: &dyn Host, unit: &str) -> BTreeMap<String, String> {
    let Ok(output) = host.run(
        "systemctl",
        &[
            "show",
            unit,
            "-p",
            "LoadState",
            "-p",
            "FragmentPath",
            "-p",
            "DropInPaths",
            "-p",
            "UnitFileState",
            "-p",
            "ActiveState",
        ],
    ) else {
        return BTreeMap::new();
    };
    output
        .stdout
        .lines()
        .filter_map(|line| line.split_once('='))
        .map(|(key, value)| (key.to_string(), value.to_string()))
        .collect()
}

/// Unit names to look at: named by the profile, running the program, or
/// whose processes run it.
fn candidate_units(host: &dyn Host, profile: &Profile, processes: &[Process]) -> BTreeSet<String> {
    let mut units: BTreeSet<String> = processes
        .iter()
        .filter(|process| !process.contained)
        .filter_map(|process| process.unit.clone())
        .collect();
    let mut templates: BTreeSet<String> = BTreeSet::new();
    for dir in UNIT_DIRS {
        let Ok(entries) = host.list_dir(Path::new(dir)) else {
            continue;
        };
        for entry in entries {
            let Some(name) = entry.file_name().and_then(|name| name.to_str()) else {
                continue;
            };
            let Some(stem) = name.strip_suffix(".service") else {
                continue;
            };
            let (stem, template) = match stem.split_once('@') {
                Some((stem, "")) => (stem, true),
                Some((stem, _)) => (stem, false),
                None => (stem, false),
            };
            let named = profile
                .detect
                .services
                .iter()
                .any(|service| service == stem);
            let runs = || {
                let mut service = UnitService::default();
                if let Ok(text) = host.read_to_string(&entry) {
                    parse_unit(&text, &mut service);
                }
                service
                    .exec_start
                    .as_deref()
                    .and_then(|line| {
                        split_words(line.trim_start_matches(['-', '@', ':', '+', '!'])).ok()
                    })
                    .and_then(|words| words.first().cloned())
                    .is_some_and(|program| is_program(profile, &program))
            };
            if named || runs() {
                if template {
                    templates.insert(stem.to_string());
                } else {
                    units.insert(name.to_string());
                }
            }
        }
    }
    // Enabled instances of template units.
    if !templates.is_empty() {
        for dir in ["/etc/systemd/system", "/run/systemd/system"] {
            let Ok(entries) = host.list_dir(Path::new(dir)) else {
                continue;
            };
            for wants in entries {
                let is_wants = wants
                    .file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| name.ends_with(".wants"));
                if !is_wants {
                    continue;
                }
                for link in host.list_dir(&wants).unwrap_or_default() {
                    let Some(name) = link.file_name().and_then(|name| name.to_str()) else {
                        continue;
                    };
                    let instance_of = name
                        .strip_suffix(".service")
                        .and_then(|stem| stem.split_once('@'))
                        .filter(|(_, instance)| !instance.is_empty())
                        .map(|(stem, _)| stem);
                    if instance_of.is_some_and(|stem| templates.contains(stem)) {
                        units.insert(name.to_string());
                    }
                }
            }
        }
    }
    units
}

fn read_unit_environment(
    host: &dyn Host,
    service: &UnitService,
    notes: &mut Vec<String>,
) -> BTreeMap<String, String> {
    let mut env: BTreeMap<String, String> = BTreeMap::new();
    // systemd applies EnvironmentFile= after Environment=.
    env.extend(service.environment.iter().cloned());
    for (path, optional) in &service.environment_files {
        match host.read_to_string(Path::new(path)) {
            Ok(text) => env.extend(parse_assignments(&text)),
            Err(_) if *optional => {}
            Err(error) => notes.push(format!("environment file {path} unreadable: {error}")),
        }
    }
    env
}

fn systemd_found(
    host: &dyn Host,
    profile: &Profile,
    unit: &str,
    processes: &[Process],
) -> Option<Found> {
    let shown = show_unit(host, unit);
    if shown.get("LoadState").map(String::as_str) == Some("not-found") {
        return None;
    }
    let fragment = shown
        .get("FragmentPath")
        .filter(|path| !path.is_empty())
        .cloned();
    let drop_ins: Vec<String> = shown
        .get("DropInPaths")
        .map(|paths| paths.split_whitespace().map(str::to_string).collect())
        .unwrap_or_default();
    let unit_file_state = shown.get("UnitFileState").cloned().unwrap_or_default();
    let active = matches!(
        shown.get("ActiveState").map(String::as_str),
        Some("active" | "activating" | "reloading")
    );
    let mut notes = Vec::new();
    let mut service = UnitService::default();
    for path in fragment.iter().chain(drop_ins.iter()) {
        match host.read_to_string(Path::new(path)) {
            Ok(text) => parse_unit(&text, &mut service),
            Err(error) => notes.push(format!("unit file {path} unreadable: {error}")),
        }
    }
    // Only the program's own service is taken over: one the profile names,
    // or one whose ExecStart runs the program. A unit that merely holds a
    // process of it in its cgroup (rc-local, cron, a user session, a process
    // supervisor) belongs to the host and is left alone.
    let stem = unit.trim_end_matches(".service");
    let stem = stem.split('@').next().unwrap_or(stem);
    let named = profile
        .detect
        .services
        .iter()
        .any(|service| service == stem);
    let runs_program = service
        .exec_start
        .as_deref()
        .and_then(|line| split_words(line.trim_start_matches(['-', '@', ':', '+', '!'])).ok())
        .and_then(|words| words.first().cloned())
        .is_some_and(|program| is_program(profile, &program));
    if !(named || runs_program) {
        return None;
    }
    let unit_env = read_unit_environment(host, &service, &mut notes);
    let own: Vec<Process> = processes
        .iter()
        .filter(|process| process.unit.as_deref() == Some(unit))
        .cloned()
        .collect();
    let instance = unit
        .strip_suffix(".service")
        .and_then(|stem| stem.split_once('@'))
        .map(|(_, instance)| instance);

    let (program, invocation) = if let Some(process) = own.first() {
        (
            Some(process.exe.clone()),
            Some(Invocation {
                args: process.argv.iter().skip(1).cloned().collect(),
                env: process.env.clone(),
                cwd: process.cwd.clone(),
            }),
        )
    } else {
        match service
            .exec_start
            .as_deref()
            .map(|line| exec_argv(line, instance, &unit_env))
        {
            Some(Ok(argv)) if is_program(profile, &argv[0]) => (
                Some(argv[0].clone()),
                Some(Invocation {
                    args: argv[1..].to_vec(),
                    env: wanted_env(profile, unit_env.clone()),
                    cwd: service.working_directory.clone(),
                }),
            ),
            Some(Ok(argv)) => {
                notes.push(format!(
                    "the service starts {} rather than the program; its arguments cannot be read",
                    argv[0]
                ));
                (Some(argv[0].clone()), None)
            }
            Some(Err(error)) => {
                notes.push(format!(
                    "the service command line cannot be read exactly: {}",
                    error.describe()
                ));
                (None, None)
            }
            None => {
                notes.push("the service has no ExecStart".into());
                (None, None)
            }
        }
    };
    Some(Found {
        origin: Origin::Systemd {
            unit: unit.to_string(),
            fragment,
            drop_ins,
            unit_file_state,
            active,
        },
        program,
        invocation,
        processes: own,
        notes,
    })
}

fn openrc_runlevels(host: &dyn Host) -> BTreeMap<String, Vec<String>> {
    let mut out = BTreeMap::new();
    let Ok(output) = host.run("rc-update", &["show", "-v"]) else {
        return out;
    };
    for line in output.stdout.lines() {
        let Some((name, levels)) = line.split_once('|') else {
            continue;
        };
        let levels: Vec<String> = levels.split_whitespace().map(str::to_string).collect();
        out.insert(name.trim().to_string(), levels);
    }
    out
}

fn init_scripts(
    host: &dyn Host,
    profile: &Profile,
    skip: &BTreeSet<String>,
    processes: &[Process],
) -> Vec<Found> {
    let mut out = Vec::new();
    let Ok(entries) = host.list_dir(Path::new("/etc/init.d")) else {
        return out;
    };
    let mut runlevels: Option<BTreeMap<String, Vec<String>>> = None;
    for entry in entries {
        let Some(name) = entry
            .file_name()
            .and_then(|name| name.to_str())
            .map(str::to_string)
        else {
            continue;
        };
        if skip.contains(&name) || !host.is_file(&entry) {
            continue;
        }
        let Ok(text) = host.read_to_string(&entry) else {
            continue;
        };
        let named = profile.detect.services.contains(&name);
        let mentions = profile.detect.executables.iter().any(|program| {
            text.split(|c: char| !(c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.'))
                .any(|word| word == program)
        });
        if !(named || mentions) {
            continue;
        }
        let script = entry.display().to_string();
        let procd = text
            .lines()
            .next()
            .is_some_and(|line| line.contains("/etc/rc.common"))
            && text
                .lines()
                .any(|line| line.trim().starts_with("USE_PROCD=1"));
        if procd {
            out.push(procd_script(host, profile, processes, name, script));
            continue;
        }
        let openrc = text
            .lines()
            .next()
            .is_some_and(|line| line.contains("openrc-run"));
        let mut vars: BTreeMap<String, String> = parse_assignments(&text).into_iter().collect();
        if let Ok(conf) = host.read_to_string(&Path::new("/etc/conf.d").join(&name)) {
            vars.extend(parse_assignments(&conf));
        }
        let mut notes = Vec::new();
        let command = vars.get("command").cloned();
        let invocation = match &command {
            Some(command) if is_program(profile, command) => {
                let args = vars.get("command_args").cloned().unwrap_or_default();
                if args.contains('$') || command.contains('$') {
                    notes.push("the script's arguments use shell variables".into());
                    None
                } else {
                    match split_words(&args) {
                        Ok(args) => Some(Invocation {
                            args,
                            env: wanted_env(profile, vars.clone()),
                            cwd: vars.get("directory").cloned(),
                        }),
                        Err(error) => {
                            notes
                                .push(format!("the script's arguments cannot be split: {error:?}"));
                            None
                        }
                    }
                }
            }
            _ => {
                notes.push("the script's command line cannot be read; it is taken from the running process if there is one".into());
                None
            }
        };
        let origin = if openrc {
            let levels = runlevels.get_or_insert_with(|| openrc_runlevels(host));
            Origin::Openrc {
                name: name.clone(),
                script,
                runlevels: levels.get(&name).cloned().unwrap_or_default(),
            }
        } else {
            Origin::Sysv {
                name: name.clone(),
                script,
            }
        };
        // Processes started by the script: same program path, or the same
        // arguments.
        let own: Vec<Process> = processes
            .iter()
            .filter(|process| !process.contained && process.unit.is_none())
            .filter(|process| {
                let same_program = command.as_deref() == Some(process.exe.as_str());
                let same_args = invocation.as_ref().is_some_and(|invocation| {
                    process.argv.get(1..) == Some(invocation.args.as_slice())
                });
                same_program || same_args
            })
            .cloned()
            .collect();
        let invocation = invocation.or_else(|| {
            own.first().map(|process| Invocation {
                args: process.argv.iter().skip(1).cloned().collect(),
                env: process.env.clone(),
                cwd: process.cwd.clone(),
            })
        });
        out.push(Found {
            origin,
            program: command.or_else(|| own.first().map(|process| process.exe.clone())),
            invocation,
            processes: own,
            notes,
        });
    }
    out
}

/// An OpenWrt procd init script: whether it starts on boot, what procd runs
/// for it, and which package installed it.
fn procd_script(
    host: &dyn Host,
    profile: &Profile,
    processes: &[Process],
    name: String,
    script: String,
) -> Found {
    let mut notes = Vec::new();
    let enabled = host
        .list_dir(Path::new("/etc/rc.d"))
        .map(|entries| {
            entries.iter().any(|entry| {
                entry
                    .file_name()
                    .and_then(|file| file.to_str())
                    .and_then(|file| file.strip_prefix('S'))
                    .and_then(|rest| rest.strip_suffix(name.as_str()))
                    .is_some_and(|digits| {
                        !digits.is_empty() && digits.bytes().all(|byte| byte.is_ascii_digit())
                    })
            })
        })
        .unwrap_or(false);
    let query = serde_json::json!({ "name": name }).to_string();
    let state = host
        .run("ubus", &["call", "service", "list", &query])
        .ok()
        .and_then(|output| serde_json::from_str::<serde_json::Value>(&output.stdout).ok());
    let mut running = false;
    let mut pids: BTreeSet<u32> = BTreeSet::new();
    let mut first_running: Option<&serde_json::Value> = None;
    match &state {
        Some(state) => {
            let instances = state
                .get(&name)
                .and_then(|service| service.get("instances"))
                .and_then(|instances| instances.as_object());
            for instance in instances.into_iter().flat_map(|map| map.values()) {
                if instance.get("running").and_then(|value| value.as_bool()) == Some(true) {
                    running = true;
                    if first_running.is_none() {
                        first_running = Some(instance);
                    }
                }
                if let Some(pid) = instance
                    .get("pid")
                    .and_then(|value| value.as_u64())
                    .and_then(|pid| u32::try_from(pid).ok())
                {
                    pids.insert(pid);
                }
            }
        }
        None => notes.push("procd state cannot be read".into()),
    }
    let command: Option<Vec<String>> = first_running
        .and_then(|instance| instance.get("command"))
        .and_then(|command| command.as_array())
        .and_then(|command| {
            command
                .iter()
                .map(|word| word.as_str().map(str::to_string))
                .collect::<Option<Vec<String>>>()
        })
        .filter(|command: &Vec<String>| {
            command
                .first()
                .is_some_and(|program| is_program(profile, program))
        });
    let own: Vec<Process> = processes
        .iter()
        .filter(|process| !process.contained && pids.contains(&process.pid))
        .cloned()
        .collect();
    let mut invocation = None;
    let mut program = None;
    if let Some(command) = &command {
        let env = first_running
            .and_then(|instance| instance.get("env"))
            .and_then(|env| env.as_object())
            .map(|env| {
                env.iter()
                    .filter_map(|(key, value)| Some((key.clone(), value.as_str()?.to_string())))
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        invocation = Some(Invocation {
            args: command[1..].to_vec(),
            env: wanted_env(profile, env),
            cwd: None,
        });
        program = Some(command[0].clone());
    }
    if invocation.is_none() {
        invocation = own.first().map(|process| Invocation {
            args: process.argv.iter().skip(1).cloned().collect(),
            env: process.env.clone(),
            cwd: process.cwd.clone(),
        });
        program = own.first().map(|process| process.exe.clone());
    }
    let package = owning_package(host, &script);
    if let Some(package) = &package {
        notes.push(format!(
            "installed by the package {package}; upgrading that package starts the service again"
        ));
    }
    Found {
        origin: Origin::Procd {
            name,
            script,
            enabled,
            running,
            package,
        },
        program,
        invocation,
        processes: own,
        notes,
    }
}

/// The package whose file list (opkg, or apk on OpenWrt 25.x) names the
/// script.
fn owning_package(host: &dyn Host, script: &str) -> Option<String> {
    for dir in ["/usr/lib/opkg/info", "/lib/apk/packages"] {
        let Ok(entries) = host.list_dir(Path::new(dir)) else {
            continue;
        };
        for entry in entries {
            let Some(stem) = entry
                .file_name()
                .and_then(|file| file.to_str())
                .and_then(|file| file.strip_suffix(".list"))
            else {
                continue;
            };
            if host
                .read_to_string(&entry)
                .is_ok_and(|text| text.lines().any(|line| line == script))
            {
                return Some(stem.to_string());
            }
        }
    }
    None
}

/// The command part of a crontab line: skips the schedule and, for system
/// crontabs, the user.
fn cron_command(line: &str, has_user: bool) -> Option<&str> {
    let mut rest = line.trim_start();
    let fields = if rest.starts_with('@') { 1 } else { 5 } + usize::from(has_user);
    for _ in 0..fields {
        let end = rest.find(char::is_whitespace)?;
        rest = rest[end..].trim_start();
    }
    (!rest.is_empty()).then_some(rest)
}

fn autostart_files(host: &dyn Host) -> Vec<(PathBuf, Option<bool>)> {
    // (file, None) = shell script, (file, Some(has_user)) = crontab.
    let mut files: Vec<(PathBuf, Option<bool>)> = vec![
        (PathBuf::from("/etc/rc.local"), None),
        (PathBuf::from("/etc/crontab"), Some(true)),
    ];
    for (dir, has_user) in [
        ("/etc/cron.d", true),
        ("/var/spool/cron/crontabs", false),
        ("/var/spool/cron", false),
    ] {
        for entry in host.list_dir(Path::new(dir)).unwrap_or_default() {
            if host.is_file(&entry) {
                files.push((entry, Some(has_user)));
            }
        }
    }
    files
}

fn autostart_lines(host: &dyn Host, profile: &Profile, processes: &[Process]) -> Vec<Found> {
    let mut out = Vec::new();
    for (path, cron) in autostart_files(host) {
        let Ok(text) = host.read_to_string(&path) else {
            continue;
        };
        for (index, line) in text.lines().enumerate() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            // Crontab lines that are too short, such as `NAME=value`
            // environment lines, run nothing.
            let command = match cron {
                Some(has_user) => match cron_command(trimmed, has_user) {
                    Some(command) => command,
                    None => continue,
                },
                None => trimmed,
            };
            let Some(argv) = command_in_line(command, &profile.detect.executables) else {
                continue;
            };
            let env = wanted_env(profile, leading_assignments(command));
            let args: Vec<String> = argv[1..].to_vec();
            let own: Vec<Process> = processes
                .iter()
                .filter(|process| !process.contained && process.unit.is_none())
                .filter(|process| process.argv.get(1..) == Some(args.as_slice()))
                .cloned()
                .collect();
            let mut notes = Vec::new();
            if args.iter().any(|arg| arg.contains('$')) {
                notes.push("the line's arguments use shell variables".into());
            }
            let invocation = if notes.is_empty() {
                Some(Invocation {
                    args,
                    env,
                    cwd: None,
                })
            } else {
                own.first().map(|process| Invocation {
                    args: process.argv.iter().skip(1).cloned().collect(),
                    env: process.env.clone(),
                    cwd: process.cwd.clone(),
                })
            };
            out.push(Found {
                origin: Origin::Autostart {
                    file: path.display().to_string(),
                    line: index + 1,
                },
                program: Some(argv[0].clone()),
                invocation,
                processes: own,
                notes,
            });
        }
    }
    out
}

fn containers(host: &dyn Host, profile: &Profile, processes: &[Process]) -> Vec<Found> {
    let mut out = Vec::new();
    let contained: Vec<Process> = processes
        .iter()
        .filter(|process| process.contained)
        .cloned()
        .collect();
    if host.has_program("docker") && !profile.detect.images.is_empty() {
        if let Ok(output) = host.run(
            "docker",
            &["ps", "-a", "--no-trunc", "--format", "{{.ID}}\t{{.Image}}"],
        ) {
            for line in output.stdout.lines() {
                let Some((id, image)) = line.split_once('\t') else {
                    continue;
                };
                if profile
                    .detect
                    .images
                    .iter()
                    .any(|pattern| image.contains(pattern.as_str()))
                {
                    out.push(Found {
                        origin: Origin::Container {
                            id: id.chars().take(12).collect(),
                            image: image.to_string(),
                        },
                        program: None,
                        invocation: None,
                        processes: Vec::new(),
                        notes: vec!["runs in a container; take it over by hand".into()],
                    });
                }
            }
        }
    }
    if out.is_empty() && !contained.is_empty() {
        out.push(Found {
            origin: Origin::Container {
                id: "unknown".into(),
                image: String::new(),
            },
            program: contained.first().map(|process| process.exe.clone()),
            invocation: None,
            processes: contained,
            notes: vec!["runs in a container; take it over by hand".into()],
        });
    }
    out
}

/// Keeps `unit` only for the program's own services; any other unit a
/// process runs under moves to `host_unit`.
pub fn classify_units(processes: &mut [Process], owned_units: &BTreeSet<String>) {
    for process in processes {
        if process
            .unit
            .as_ref()
            .is_some_and(|unit| !owned_units.contains(unit))
        {
            process.host_unit = process.unit.take();
        }
    }
}

/// Every installation on this machine.
pub fn detect(host: &dyn Host, profile: &Profile) -> Vec<Found> {
    let mut processes = scan_processes(host, profile);
    let mut found: Vec<Found> = Vec::new();

    let mut systemd_stems: BTreeSet<String> = BTreeSet::new();
    let mut owned_units: BTreeSet<String> = BTreeSet::new();
    let os = host.os();
    // Only the sources of the system it runs on. On Windows the Unix paths
    // below are directories at the root of the drive that any user may
    // create, so reading them there would let that user plant processes,
    // autostart lines and configurations.
    if os == Os::Linux && host.exists(Path::new("/run/systemd/system")) {
        for unit in candidate_units(host, profile, &processes) {
            if let Some(entry) = systemd_found(host, profile, &unit, &processes) {
                let stem = unit.trim_end_matches(".service");
                systemd_stems.insert(stem.split('@').next().unwrap_or(stem).to_string());
                owned_units.insert(unit);
                found.push(entry);
            }
        }
    }
    classify_units(&mut processes, &owned_units);
    if os != Os::Windows {
        found.extend(init_scripts(host, profile, &systemd_stems, &processes));
        found.extend(autostart_lines(host, profile, &processes));
        found.extend(containers(host, profile, &processes));
    }
    if os == Os::Macos {
        found.extend(crate::launchd::jobs(host, profile, &processes));
    }
    if os == Os::Windows {
        found.extend(crate::winsvc::services(host, profile, &processes));
        found.extend(crate::winstart::tasks(host, profile, &processes));
        found.extend(crate::winstart::logon_entries(host, profile, &processes));
    }

    let claimed: BTreeSet<u32> = found
        .iter()
        .flat_map(|entry| entry.processes.iter().map(|process| process.pid))
        .collect();
    for process in &processes {
        if claimed.contains(&process.pid) || process.contained {
            continue;
        }
        let mut notes = Vec::new();
        if let Some(unit) = &process.host_unit {
            notes.push(format!(
                "runs in the cgroup of {unit}, which is not taken over; if that unit starts the program again, turn it off by hand"
            ));
        }
        found.push(Found {
            origin: Origin::Process { pid: process.pid },
            program: Some(process.exe.clone()),
            invocation: Some(Invocation {
                args: process.argv.iter().skip(1).cloned().collect(),
                env: process.env.clone(),
                cwd: process.cwd.clone(),
            }),
            processes: vec![process.clone()],
            notes,
        });
    }
    found
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn windows_program_names_ignore_case_and_the_exe_suffix() {
        let names = vec!["demo-meshd".to_string()];
        assert!(program_named(
            &names,
            r"C:\Program Files\Demo\Demo-Meshd.EXE"
        ));
        assert!(program_named(&names, r"\\server\share\demo-meshd"));
        assert!(!program_named(&names, r"C:\demo-meshd\other.exe"));
        // Unix names stay exact.
        assert!(program_named(&names, "/usr/bin/demo-meshd"));
        assert!(!program_named(&names, "/usr/bin/Demo-Meshd"));
        assert!(!program_named(&names, "/usr/bin/demo-meshd.exe"));
        assert_eq!(base_name(r"C:\a\b.exe"), "b.exe");
        assert_eq!(base_name("/a/b\\c"), "b\\c");
    }
    use crate::host::fake::FakeHost;
    use crate::profile::tests::demo;

    fn machine() -> FakeHost {
        let host = FakeHost::default();
        host.file("/run/systemd/system/.keep", "");
        // A service, running.
        host.file(
            "/etc/systemd/system/demo-meshd.service",
            "[Service]\nEnvironmentFile=-/etc/default/demo\nExecStart=/usr/bin/demo-meshd -c /etc/demo/a.toml $EXTRA\n",
        );
        host.file(
            "/etc/default/demo",
            "EXTRA=--latency-first\nDEMO_NET_SECRET=x\n",
        );
        host.answer(
            "systemctl show demo-meshd.service -p LoadState -p FragmentPath -p DropInPaths -p UnitFileState -p ActiveState",
            0,
            "LoadState=loaded\nFragmentPath=/etc/systemd/system/demo-meshd.service\nDropInPaths=\nUnitFileState=enabled\nActiveState=active\n",
        );
        host.process(
            100,
            "/usr/bin/demo-meshd",
            &[
                "/usr/bin/demo-meshd",
                "-c",
                "/etc/demo/a.toml",
                "--latency-first",
            ],
            &["DEMO_NET_SECRET=x", "PATH=/bin"],
            "0::/system.slice/demo-meshd.service\n",
        );
        // A template instance, enabled but stopped, whose ExecStart is read.
        host.file(
            "/usr/lib/systemd/system/demo-meshd@.service",
            "[Service]\nExecStart=/usr/bin/demo-meshd -c /etc/demo/%i.toml\n",
        );
        host.link(
            "/etc/systemd/system/multi-user.target.wants/demo-meshd@lab.service",
            "/usr/lib/systemd/system/demo-meshd@.service",
        );
        host.answer(
            "systemctl show demo-meshd@lab.service -p LoadState -p FragmentPath -p DropInPaths -p UnitFileState -p ActiveState",
            0,
            "LoadState=loaded\nFragmentPath=/usr/lib/systemd/system/demo-meshd@.service\nDropInPaths=\nUnitFileState=enabled\nActiveState=inactive\n",
        );
        // An unrelated unit.
        host.file(
            "/etc/systemd/system/other.service",
            "[Service]\nExecStart=/usr/bin/other\n",
        );
        // A crontab line and its process.
        host.file(
            "/etc/crontab",
            "SHELL=/bin/sh\n@reboot root /opt/demo-meshd --net-name lab2 >/dev/null 2>&1\n",
        );
        host.process(
            200,
            "/opt/demo-meshd",
            &["/opt/demo-meshd", "--net-name", "lab2"],
            &[],
            "0::/user.slice\n",
        );
        // A process started by hand.
        host.process(
            300,
            "/root/demo-meshd (deleted)",
            &["./demo-meshd", "--net-name", "manual"],
            &["DEMO_IPV4=10.0.0.3/24"],
            "0::/user.slice/user-0.slice/session-1.scope\n",
        );
        // A container process: reported, never claimed as a manual process.
        host.process(
            400,
            "/usr/bin/demo-meshd",
            &["demo-meshd"],
            &[],
            "0::/system.slice/docker-abc.scope\n",
        );
        // Something else.
        host.process(
            500,
            "/usr/bin/sshd",
            &["sshd"],
            &[],
            "0::/system.slice/ssh.service\n",
        );
        host
    }

    #[test]
    fn finds_every_kind() {
        let host = machine();
        let profile = demo();
        let found = detect(&host, &profile);
        let ids: Vec<String> = found.iter().map(|entry| entry.origin.id()).collect();
        assert_eq!(
            ids,
            vec![
                "systemd:demo-meshd.service",
                "systemd:demo-meshd@lab.service",
                "autostart:/etc/crontab:2",
                "container:unknown",
                "process:300",
            ]
        );

        let service = &found[0];
        assert_eq!(service.processes.len(), 1);
        let invocation = service.invocation.as_ref().unwrap();
        assert_eq!(
            invocation.args,
            vec!["-c", "/etc/demo/a.toml", "--latency-first"]
        );
        assert_eq!(
            invocation.env.get("DEMO_NET_SECRET").map(String::as_str),
            Some("x")
        );
        assert!(!invocation.env.contains_key("PATH"));

        let template = &found[1];
        assert!(template.processes.is_empty());
        assert_eq!(
            template.invocation.as_ref().unwrap().args,
            vec!["-c", "/etc/demo/lab.toml"]
        );
        assert!(matches!(
            &template.origin,
            Origin::Systemd { active: false, unit_file_state, .. } if unit_file_state == "enabled"
        ));

        let cron = &found[2];
        assert_eq!(cron.processes[0].pid, 200);
        assert_eq!(
            cron.invocation.as_ref().unwrap().args,
            vec!["--net-name", "lab2"]
        );

        assert_eq!(found[3].processes[0].pid, 400);
        let manual = &found[4];
        assert_eq!(manual.program.as_deref(), Some("/root/demo-meshd"));

        // The printable summary carries flag names only.
        let summary = serde_json::to_string(&manual.summary()).unwrap();
        assert!(summary.contains("--net-name"));
        assert!(!summary.contains("manual"), "{summary}");
        assert!(!summary.contains("10.0.0.3"));
    }

    #[test]
    fn host_units_are_not_the_programs_services() {
        let host = machine();
        // On systemd hosts a program started from cron runs inside the cron
        // service's cgroup; that service is the host's, not ours.
        host.process(
            200,
            "/opt/demo-meshd",
            &["/opt/demo-meshd", "--net-name", "lab2"],
            &[],
            "0::/system.slice/cron.service\n",
        );
        host.file(
            "/lib/systemd/system/cron.service",
            "[Service]\nExecStart=/usr/sbin/cron -f\n",
        );
        host.answer(
            "systemctl show cron.service -p LoadState -p FragmentPath -p DropInPaths -p UnitFileState -p ActiveState",
            0,
            "LoadState=loaded\nFragmentPath=/lib/systemd/system/cron.service\nDropInPaths=\nUnitFileState=enabled\nActiveState=active\n",
        );
        let found = detect(&host, &demo());
        let ids: Vec<String> = found.iter().map(|entry| entry.origin.id()).collect();
        assert!(!ids.iter().any(|id| id.contains("cron.service")), "{ids:?}");
        let cron = found
            .iter()
            .find(|entry| entry.origin.id() == "autostart:/etc/crontab:2")
            .unwrap();
        assert_eq!(cron.processes[0].pid, 200);
        assert_eq!(cron.processes[0].unit, None);
        assert_eq!(cron.processes[0].host_unit.as_deref(), Some("cron.service"));
    }

    #[test]
    fn unreadable_arguments_are_not_printed() {
        let host = FakeHost::default();
        host.file("/run/systemd/system/.keep", "");
        host.file(
            "/etc/systemd/system/demo-meshd.service",
            "[Service]\nExecStart=/usr/bin/demo-meshd --net-secret=pa$$w0rd\n",
        );
        host.answer(
            "systemctl show demo-meshd.service -p LoadState -p FragmentPath -p DropInPaths -p UnitFileState -p ActiveState",
            0,
            "LoadState=loaded\nFragmentPath=/etc/systemd/system/demo-meshd.service\nDropInPaths=\nUnitFileState=enabled\nActiveState=inactive\n",
        );
        let found = detect(&host, &demo());
        assert_eq!(found.len(), 1);
        assert!(found[0].invocation.is_none());
        let summary = serde_json::to_string(&found[0].summary()).unwrap();
        assert!(!summary.contains("w0rd"), "{summary}");
        assert!(summary.contains("argument 1"), "{summary}");
    }

    #[test]
    fn init_scripts_and_openrc() {
        let host = FakeHost::default();
        host.file(
            "/etc/init.d/demo-meshd",
            "#!/sbin/openrc-run\ncommand=\"/usr/local/bin/demo-meshd\"\ncommand_args=\"-c /etc/demo.toml\"\n",
        );
        host.file(
            "/etc/conf.d/demo-meshd",
            "command_args=\"-c /etc/demo2.toml\"\n",
        );
        host.answer(
            "rc-update show -v",
            0,
            "         demo-meshd | default\n               sshd | default boot\n",
        );
        host.file(
            "/etc/init.d/legacy",
            "#!/bin/sh\n# starts demo-meshd\n/usr/sbin/demo-meshd &\n",
        );
        host.file("/etc/init.d/unrelated", "#!/bin/sh\necho hi\n");
        let profile = demo();
        let found = detect(&host, &profile);
        assert_eq!(found.len(), 2);
        assert_eq!(
            found[0].origin,
            Origin::Openrc {
                name: "demo-meshd".into(),
                script: "/etc/init.d/demo-meshd".into(),
                runlevels: vec!["default".into()],
            }
        );
        assert_eq!(
            found[0].invocation.as_ref().unwrap().args,
            vec!["-c", "/etc/demo2.toml"]
        );
        assert!(matches!(found[1].origin, Origin::Sysv { .. }));
        assert!(found[1].invocation.is_none());
        assert!(!found[1].notes.is_empty());
    }

    fn procd_host(listed: bool) -> FakeHost {
        let host = FakeHost::default();
        host.file(
            "/etc/init.d/demo",
            "#!/bin/sh /etc/rc.common\nUSE_PROCD=1\nSTART=99\nPROG=/usr/bin/demo-meshd\nstart_service() {\n\tprocd_open_instance\n\tprocd_set_param command \"$PROG\" -c /etc/demo.conf\n}\n",
        );
        if listed {
            host.link("/etc/rc.d/S99demo", "../init.d/demo");
        }
        host
    }

    #[test]
    fn procd_service_enabled_and_running() {
        let host = procd_host(true);
        host.file(
            "/usr/lib/opkg/info/demo.list",
            "/usr/bin/demo-meshd\n/etc/init.d/demo\n",
        );
        host.process(
            321,
            "/usr/bin/demo-meshd",
            &["/usr/bin/demo-meshd", "-c", "/etc/demo.conf"],
            &[],
            "0::/\n",
        );
        host.answer(
            "ubus call service list {\"name\":\"demo\"}",
            0,
            r#"{"demo":{"instances":{"instance1":{"running":true,"pid":321,"command":["/usr/bin/demo-meshd","-c","/etc/demo.conf"],"term_timeout":5}}}}"#,
        );
        let found = detect(&host, &demo());
        let entry = found
            .iter()
            .find(|entry| entry.origin.id() == "procd:demo")
            .unwrap();
        assert_eq!(
            entry.origin,
            Origin::Procd {
                name: "demo".into(),
                script: "/etc/init.d/demo".into(),
                enabled: true,
                running: true,
                package: Some("demo".into()),
            }
        );
        assert_eq!(entry.processes.len(), 1);
        assert_eq!(entry.processes[0].pid, 321);
        assert_eq!(entry.program.as_deref(), Some("/usr/bin/demo-meshd"));
        assert_eq!(
            entry.invocation.as_ref().unwrap().args,
            vec!["-c", "/etc/demo.conf"]
        );
        assert!(entry.notes.iter().any(|note| note.contains(
            "installed by the package demo; upgrading that package starts the service again"
        )));
    }

    #[test]
    fn procd_service_not_enabled_and_stopped() {
        let host = procd_host(false);
        host.file("/lib/apk/packages/demo.list", "/etc/init.d/demo\n");
        host.answer("ubus call service list {\"name\":\"demo\"}", 0, "{}");
        let found = detect(&host, &demo());
        let entry = found
            .iter()
            .find(|entry| entry.origin.id() == "procd:demo")
            .unwrap();
        assert_eq!(
            entry.origin,
            Origin::Procd {
                name: "demo".into(),
                script: "/etc/init.d/demo".into(),
                enabled: false,
                running: false,
                package: Some("demo".into()),
            }
        );
        assert!(entry.processes.is_empty());

        // No package list, and procd cannot be asked.
        let host = procd_host(false);
        let found = detect(&host, &demo());
        let entry = found
            .iter()
            .find(|entry| entry.origin.id() == "procd:demo")
            .unwrap();
        assert!(matches!(
            entry.origin,
            Origin::Procd {
                running: false,
                package: None,
                ..
            }
        ));
        assert!(entry
            .notes
            .iter()
            .any(|note| note == "procd state cannot be read"));
    }

    #[test]
    fn cron_fields() {
        assert_eq!(cron_command("* * * * * /x a", false), Some("/x a"));
        assert_eq!(cron_command("*/5 1 * * 0 root /x", true), Some("/x"));
        assert_eq!(cron_command("@reboot /x", false), Some("/x"));
        assert_eq!(cron_command("@reboot", false), None);
    }
}
