//! Finding installations run as Windows services (requirement R12).
//!
//! The service list comes from one PowerShell query of `Win32_Service`
//! (name, command line, start mode, state and process); services are
//! stopped, started and reconfigured with `sc.exe`. A service runs the
//! program when its command line does, or, for a wrapper that starts the
//! program as a child, when the profile names the service.

use serde::Deserialize;

use crate::cmdline::split_windows_command_line;
use crate::detect::{descends_from, program_named, Found, Origin, Process};
use crate::host::Host;
use crate::profile::Profile;
use crate::source::Invocation;

/// The service list as JSON, in UTF-8 whatever the console code page.
pub const SERVICES_QUERY: &str = "[Console]::OutputEncoding=[Text.Encoding]::UTF8; ConvertTo-Json -Compress -InputObject @(Get-CimInstance -ClassName Win32_Service | Select-Object Name,PathName,StartMode,State,ProcessId,DelayedAutoStart)";

/// How long a service gets to stop.
const STOP_WAIT_MS: u64 = 30_000;
const STOP_POLL_MS: u64 = 500;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Service {
    name: String,
    #[serde(default)]
    path_name: Option<String>,
    #[serde(default)]
    start_mode: Option<String>,
    #[serde(default)]
    state: Option<String>,
    #[serde(default)]
    process_id: Option<u32>,
    #[serde(default)]
    delayed_auto_start: Option<bool>,
}

/// Runs PowerShell with one command.
pub fn powershell(host: &dyn Host, command: &str) -> Option<String> {
    let output = host
        .run(
            "powershell.exe",
            &["-NoProfile", "-NonInteractive", "-Command", command],
        )
        .ok()?;
    output.success().then_some(output.stdout)
}

/// The start type `sc.exe config start=` takes back: `auto`,
/// `delayed-auto`, `demand` or `disabled`; drivers' `boot` and `system`.
fn start_type(service: &Service) -> String {
    match service.start_mode.as_deref().unwrap_or("") {
        "Auto" if service.delayed_auto_start == Some(true) => "delayed-auto".into(),
        "Auto" => "auto".into(),
        "Manual" => "demand".into(),
        other => other.to_ascii_lowercase(),
    }
}

/// Every service that runs the program.
pub fn services(host: &dyn Host, profile: &Profile, processes: &[Process]) -> Vec<Found> {
    let Some(json) = powershell(host, SERVICES_QUERY) else {
        return Vec::new();
    };
    let Ok(list) = serde_json::from_str::<Vec<Service>>(json.trim()) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for service in list {
        let argv = service
            .path_name
            .as_deref()
            .map(split_windows_command_line)
            .unwrap_or_default();
        let runs_program = argv
            .first()
            .is_some_and(|program| program_named(&profile.detect.executables, program));
        let named = profile
            .detect
            .services
            .iter()
            .any(|name| name.eq_ignore_ascii_case(&service.name));
        if !runs_program && !named {
            continue;
        }
        let running = service.state.as_deref() == Some("Running");
        let service_pid = service.process_id.filter(|pid| *pid != 0 && running);
        // Its process, or the program a wrapper service started, however
        // far down (a wrapper may start it through `cmd`).
        let own: Vec<Process> = processes
            .iter()
            .filter(|process| {
                service_pid
                    .is_some_and(|pid| process.pid == pid || descends_from(host, process, pid))
            })
            .cloned()
            .collect();
        let mut notes = Vec::new();
        let invocation = match own.first() {
            Some(process) => Some(Invocation {
                args: process.argv.iter().skip(1).cloned().collect(),
                env: process.env.clone(),
                cwd: process.cwd.clone(),
            }),
            None if runs_program => Some(Invocation {
                args: argv[1..].to_vec(),
                env: Default::default(),
                cwd: None,
            }),
            None => {
                notes.push(
                    "the service runs a wrapper and is not running; its command line for the program is unknown"
                        .into(),
                );
                None
            }
        };
        let mut start = start_type(&service);
        // Older systems leave the delayed start out of the query; the
        // service's own setting says it.
        if start == "auto"
            && service.delayed_auto_start.is_none()
            && delayed_in_registry(host, &service.name)
        {
            start = "delayed-auto".into();
        }
        if matches!(start.as_str(), "boot" | "system") {
            notes.push(format!("{} is a driver; turn it off by hand", service.name));
        }
        out.push(Found {
            origin: Origin::WinService {
                name: service.name.clone(),
                start,
                running,
            },
            program: own
                .first()
                .map(|process| process.exe.clone())
                .or_else(|| argv.first().cloned()),
            invocation,
            processes: own,
            notes,
        });
    }
    out
}

/// Whether a service's registry key sets `DelayedAutostart`.
fn delayed_in_registry(host: &dyn Host, name: &str) -> bool {
    let key = format!("HKLM\\SYSTEM\\CurrentControlSet\\Services\\{name}");
    let Ok(output) = host.run("reg.exe", &["query", &key, "/v", "DelayedAutostart"]) else {
        return false;
    };
    output.success()
        && output.stdout.lines().any(|line| {
            line.split_once("REG_DWORD")
                .and_then(|(_, value)| {
                    let value = value.trim();
                    let digits = value.strip_prefix("0x").unwrap_or(value);
                    u32::from_str_radix(digits, 16).ok()
                })
                .is_some_and(|value| value != 0)
        })
}

/// The state code of a service from `sc.exe query` (1 stopped, 4
/// running); `None` when it cannot be read.
pub fn state_code(output: &str) -> Option<u32> {
    output.lines().find_map(|line| {
        let (key, value) = line.split_once(':')?;
        if key.trim() != "STATE" {
            return None;
        }
        value.split_whitespace().next()?.parse().ok()
    })
}

const STOPPED: u32 = 1;

/// Stops a service and waits until it has.
pub fn stop(host: &dyn Host, name: &str) -> Result<(), String> {
    let output = host
        .run("sc.exe", &["stop", name])
        .map_err(|error| format!("sc.exe: {error}"))?;
    // 1062: the service has not been started.
    if !output.success() && !output.stdout.contains("1062") {
        return Err(format!(
            "sc.exe stop {name} failed: {}",
            output.stdout.trim()
        ));
    }
    let mut waited = 0;
    loop {
        let query = host
            .run("sc.exe", &["query", name])
            .map_err(|error| format!("sc.exe: {error}"))?;
        if state_code(&query.stdout) == Some(STOPPED) {
            return Ok(());
        }
        if waited >= STOP_WAIT_MS {
            return Err(format!("service {name} did not stop"));
        }
        host.sleep_ms(STOP_POLL_MS);
        waited += STOP_POLL_MS;
    }
}

/// Starts a service; one already running counts.
pub fn start(host: &dyn Host, name: &str) -> Result<(), String> {
    let output = host
        .run("sc.exe", &["start", name])
        .map_err(|error| format!("sc.exe: {error}"))?;
    // 1056: an instance of the service is already running.
    if output.success() || output.stdout.contains("1056") {
        Ok(())
    } else {
        Err(format!(
            "sc.exe start {name} failed: {}",
            output.stdout.trim()
        ))
    }
}

/// Sets how a service starts.
pub fn set_start(host: &dyn Host, name: &str, start: &str) -> Result<(), String> {
    let output = host
        .run("sc.exe", &["config", name, "start=", start])
        .map_err(|error| format!("sc.exe: {error}"))?;
    if output.success() {
        Ok(())
    } else {
        Err(format!(
            "sc.exe config {name} start= {start} failed: {}",
            output.stdout.trim()
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_delayed_start_missing_from_the_query_is_read_from_the_registry() {
        let host = crate::host::fake::FakeHost::default();
        host.answer(
            "reg.exe query HKLM\\SYSTEM\\CurrentControlSet\\Services\\demo /v DelayedAutostart",
            0,
            "\r\nHKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\demo\r\n    DelayedAutostart    REG_DWORD    0x1\r\n",
        );
        host.answer(
            "reg.exe query HKLM\\SYSTEM\\CurrentControlSet\\Services\\other /v DelayedAutostart",
            1,
            "",
        );
        assert!(delayed_in_registry(&host, "demo"));
        assert!(!delayed_in_registry(&host, "other"));
    }

    #[test]
    fn reads_the_state_code() {
        let output = "\r\nSERVICE_NAME: demo\r\n        TYPE               : 10  WIN32_OWN_PROCESS\r\n        STATE              : 1  STOPPED\r\n";
        assert_eq!(state_code(output), Some(1));
        assert_eq!(state_code("nothing"), None);
    }

    #[test]
    fn start_types_round_trip_through_sc() {
        let service = |mode: &str, delayed: Option<bool>| Service {
            name: "x".into(),
            path_name: None,
            start_mode: Some(mode.into()),
            state: None,
            process_id: None,
            delayed_auto_start: delayed,
        };
        assert_eq!(start_type(&service("Auto", Some(true))), "delayed-auto");
        assert_eq!(start_type(&service("Auto", Some(false))), "auto");
        assert_eq!(start_type(&service("Manual", None)), "demand");
        assert_eq!(start_type(&service("Disabled", None)), "disabled");
    }
}
