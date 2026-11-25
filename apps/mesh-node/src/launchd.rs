//! Finding installations started by launchd on macOS (requirement R12):
//! system daemons in `/Library/LaunchDaemons`, each user's agents in
//! `~/Library/LaunchAgents` (where a per-user package manager puts its
//! services), and agents in `/Library/LaunchAgents`, which load for every
//! user and are left to the operator.
//!
//! Job files are read with `plutil`, which reads both the XML and the
//! binary form; whether a job is loaded, and its process, come from
//! `launchctl print`, and whether it is turned off from
//! `launchctl print-disabled`.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde_json::Value;

use crate::cmdline::command_in_line;
use crate::detect::{descends_from, Found, Origin, Process};
use crate::host::Host;
use crate::profile::Profile;
use crate::source::Invocation;

/// System daemons: the `system` domain.
pub const DAEMONS: &str = "/Library/LaunchDaemons";
/// Agents every user loads: the operator handles them.
pub const SHARED_AGENTS: &str = "/Library/LaunchAgents";
/// Home directories; each user's agents are in `Library/LaunchAgents`.
pub const HOMES: &str = "/Users";

/// A job file, as far as finding the program needs it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Job {
    pub label: String,
    /// Program and arguments launchd runs.
    pub argv: Vec<String>,
    pub env: BTreeMap<String, String>,
    pub cwd: Option<String>,
    /// The file's own `Disabled` key.
    pub disabled_key: bool,
}

/// Reads a job file through `plutil`. `None` when it cannot be read or has
/// no label or program.
pub fn read_job(host: &dyn Host, path: &Path) -> Option<Job> {
    let file = path.to_str()?;
    let output = host
        .run("plutil", &["-convert", "json", "-o", "-", "--", file])
        .ok()?;
    if !output.success() {
        return None;
    }
    let value: Value = serde_json::from_str(&output.stdout).ok()?;
    let label = value.get("Label")?.as_str()?.to_string();
    let mut argv: Vec<String> = value
        .get("ProgramArguments")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(|item| item.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default();
    // `Program` names the file to run; `ProgramArguments` is then its argv
    // with argv[0] free to say anything.
    if let Some(program) = value.get("Program").and_then(Value::as_str) {
        if argv.is_empty() {
            argv.push(program.to_string());
        } else {
            argv[0] = program.to_string();
        }
    }
    if argv.is_empty() {
        return None;
    }
    let env = value
        .get("EnvironmentVariables")
        .and_then(Value::as_object)
        .map(|vars| {
            vars.iter()
                .filter_map(|(name, value)| Some((name.clone(), value.as_str()?.to_string())))
                .collect()
        })
        .unwrap_or_default();
    Some(Job {
        label,
        argv,
        env,
        cwd: value
            .get("WorkingDirectory")
            .and_then(Value::as_str)
            .map(str::to_string),
        disabled_key: value
            .get("Disabled")
            .and_then(Value::as_bool)
            .unwrap_or(false),
    })
}

/// The program a job runs, with its argv: the job's own program, or the
/// command a shell started with `-c` runs.
fn program_argv(job: &Job, profile: &Profile) -> Option<Vec<String>> {
    let base = |path: &str| path.rsplit('/').next().unwrap_or(path).to_string();
    if profile
        .detect
        .executables
        .iter()
        .any(|name| *name == base(&job.argv[0]))
    {
        return Some(job.argv.clone());
    }
    let shell = matches!(base(&job.argv[0]).as_str(), "sh" | "bash" | "zsh" | "dash");
    if shell && job.argv.get(1).map(String::as_str) == Some("-c") {
        return command_in_line(job.argv.get(2)?, &profile.detect.executables);
    }
    None
}

/// Whether the job is loaded in `domain`, and its process.
pub fn loaded(host: &dyn Host, domain: &str, label: &str) -> (bool, Option<u32>) {
    let Ok(output) = host.run("launchctl", &["print", &format!("{domain}/{label}")]) else {
        return (false, None);
    };
    if !output.success() {
        return (false, None);
    }
    let pid = output.stdout.lines().find_map(|line| {
        line.trim()
            .strip_prefix("pid = ")
            .and_then(|pid| pid.trim().parse::<u32>().ok())
    });
    (true, pid)
}

/// The turned-off overrides of a domain: `Some(true)` for a job turned off
/// with `launchctl disable`, `Some(false)` for one turned on with
/// `launchctl enable`; absent jobs follow their file's `Disabled` key.
pub fn overrides(host: &dyn Host, domain: &str) -> BTreeMap<String, bool> {
    let Ok(output) = host.run("launchctl", &["print-disabled", domain]) else {
        return BTreeMap::new();
    };
    output
        .stdout
        .lines()
        .filter_map(|line| {
            let (label, state) = line.trim().split_once("=>")?;
            let label = label.trim().trim_matches('"').to_string();
            // Older systems print true/false, newer disabled/enabled.
            let disabled = match state.trim() {
                "disabled" | "true" => true,
                "enabled" | "false" => false,
                _ => return None,
            };
            Some((label, disabled))
        })
        .collect()
}

/// Job files of one directory.
fn job_files(host: &dyn Host, dir: &Path) -> Vec<PathBuf> {
    host.list_dir(dir)
        .unwrap_or_default()
        .into_iter()
        .filter(|path| path.extension().is_some_and(|ext| ext == "plist"))
        .filter(|path| host.is_file(path))
        .collect()
}

/// Directories of job files with their domain; `None` for agents every
/// user loads.
fn job_dirs(host: &dyn Host) -> Vec<(PathBuf, Option<String>)> {
    let mut dirs = vec![
        (PathBuf::from(DAEMONS), Some("system".to_string())),
        (PathBuf::from(SHARED_AGENTS), None),
    ];
    for home in host.list_dir(Path::new(HOMES)).unwrap_or_default() {
        let dir = home.join("Library/LaunchAgents");
        // The agents of the user who owns the home directory's job files.
        for file in job_files(host, &dir) {
            if let Ok(stat) = host.stat(&file) {
                if stat.uid != 0 {
                    dirs.push((file, Some(format!("gui/{}", stat.uid))));
                }
            }
        }
    }
    dirs
}

/// Every launchd job that runs the program.
pub fn jobs(host: &dyn Host, profile: &Profile, processes: &[Process]) -> Vec<Found> {
    let mut out = Vec::new();
    let mut domain_overrides: BTreeMap<String, BTreeMap<String, bool>> = BTreeMap::new();
    for (place, domain) in job_dirs(host) {
        // A user's job file is listed one by one with its own domain.
        let files = if host.is_file(&place) {
            vec![place.clone()]
        } else {
            job_files(host, &place)
        };
        for file in files {
            let Some(job) = read_job(host, &file) else {
                continue;
            };
            let named = profile.detect.services.contains(&job.label);
            let Some(argv) =
                program_argv(&job, profile).or_else(|| named.then(|| job.argv.clone()))
            else {
                continue;
            };
            let plist = file.display().to_string();
            let args: Vec<String> = argv[1..].to_vec();
            let (is_loaded, pid) = match &domain {
                Some(domain) => loaded(host, domain, &job.label),
                None => (false, None),
            };
            // Its process: the one launchd names, or one that process
            // started (a shell's child). A copy started by hand with the
            // same command line is not the job's.
            let own: Vec<Process> = processes
                .iter()
                .filter(|process| {
                    pid.is_some_and(|pid| process.pid == pid || descends_from(host, process, pid))
                })
                .cloned()
                .collect();
            let override_off = domain.as_ref().and_then(|domain| {
                domain_overrides
                    .entry(domain.clone())
                    .or_insert_with(|| overrides(host, domain))
                    .get(&job.label)
                    .copied()
            });
            // The running process is the exact source; the job file
            // otherwise.
            let invocation = match own.first() {
                Some(process) => Invocation {
                    args: process.argv.iter().skip(1).cloned().collect(),
                    env: process.env.clone(),
                    cwd: process.cwd.clone(),
                },
                None => Invocation {
                    args,
                    env: job
                        .env
                        .iter()
                        .filter(|(name, _)| profile.wants_env(name))
                        .map(|(name, value)| (name.clone(), value.clone()))
                        .collect(),
                    cwd: job.cwd.clone(),
                },
            };
            let mut notes = Vec::new();
            if domain.is_none() {
                notes.push(format!(
                    "{plist} loads for every user who logs in; turn it off by hand"
                ));
            }
            out.push(Found {
                origin: Origin::Launchd {
                    label: job.label.clone(),
                    plist,
                    domain: domain.clone(),
                    override_off,
                    disabled_key: job.disabled_key,
                    loaded: is_loaded,
                },
                program: Some(argv[0].clone()),
                invocation: Some(invocation),
                processes: own,
                notes,
            });
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn overrides_read_both_spellings() {
        let host = crate::host::fake::FakeHost::default();
        host.answer(
            "launchctl print-disabled system",
            0,
            "disabled services = {\n\t\"com.example.a\" => disabled\n\t\"com.example.b\" => enabled\n\t\"com.example.c\" => true\n}\n",
        );
        let found = overrides(&host, "system");
        assert_eq!(found.get("com.example.a"), Some(&true));
        assert_eq!(found.get("com.example.b"), Some(&false));
        assert_eq!(found.get("com.example.c"), Some(&true));
        assert_eq!(found.get("com.example.d"), None);
    }

    #[test]
    fn loaded_reads_the_process() {
        let host = crate::host::fake::FakeHost::default();
        host.answer(
            "launchctl print system/com.example.a",
            0,
            "system/com.example.a = {\n\tstate = running\n\tpid = 321\n}\n",
        );
        host.answer("launchctl print system/com.example.b", 113, "");
        assert_eq!(loaded(&host, "system", "com.example.a"), (true, Some(321)));
        assert_eq!(loaded(&host, "system", "com.example.b"), (false, None));
    }
}
