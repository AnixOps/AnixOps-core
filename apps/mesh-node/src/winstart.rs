//! Finding installations Windows starts without a service (requirement
//! R12): scheduled tasks, and logon entries, the values of the `Run` keys
//! and the items of the Startup folders.
//!
//! Both lists come from one PowerShell query each. A scheduled task is
//! ended with `schtasks.exe /End` and turned off with `/Change /DISABLE`;
//! rollback turns it on and runs it again. A logon entry is turned off the
//! way Windows' own startup settings do it, with a value under
//! `Explorer\StartupApproved` that `reg.exe` writes; rollback puts back the
//! value that was there before.

use serde::Deserialize;

use crate::cmdline::split_windows_command_line;
use crate::detect::{program_named, Found, Origin, Process};
use crate::host::Host;
use crate::profile::Profile;
use crate::source::Invocation;
use crate::winsvc::powershell;

/// Every scheduled task with its program actions, and the process of the
/// Task Scheduler service, which starts them. No double quotes: the
/// command reaches PowerShell as one argument.
pub const TASKS_QUERY: &str = "[Console]::OutputEncoding=[Text.Encoding]::UTF8; $s=(Get-CimInstance -ClassName Win32_Service | Where-Object { $_.Name -eq 'Schedule' }).ProcessId; ConvertTo-Json -Compress -Depth 4 -InputObject ([pscustomobject]@{Schedule=$s; Tasks=@(Get-ScheduledTask | ForEach-Object { [pscustomobject]@{Path=$_.TaskPath; Name=$_.TaskName; State=[string]$_.State; Actions=@($_.Actions | Where-Object { $_.CimClass.CimClassName -eq 'MSFT_TaskExecAction' } | ForEach-Object { [pscustomobject]@{Execute=$_.Execute; Arguments=$_.Arguments; WorkingDirectory=$_.WorkingDirectory} })} })})";

/// Every logon entry: the machine's `Run` keys (64- and 32-bit), the `Run`
/// key of each user whose settings are loaded, the common Startup folder
/// and each user profile's Startup folder; with the `StartupApproved` key
/// that turns each off (`null` when the user's settings are not loaded)
/// and its current value in hexadecimal. Keys are given as `reg.exe`
/// takes them.
pub const LOGON_QUERY: &str = concat!(
    "[Console]::OutputEncoding=[Text.Encoding]::UTF8; ",
    "$e='\\Microsoft\\Windows\\CurrentVersion\\Explorer\\StartupApproved\\'; ",
    "$out=New-Object Collections.ArrayList; ",
    "function Full($k){ 'Registry::' + ($k -replace '^HKLM\\\\','HKEY_LOCAL_MACHINE\\' -replace '^HKU\\\\','HKEY_USERS\\') }; ",
    "function Hex($k,$n){ $v=$null; try { $v=(Get-Item -LiteralPath (Full $k) -ErrorAction Stop).GetValue($n) } catch {}; if ($v -is [byte[]]) { ($v | ForEach-Object { $_.ToString('x2') }) -join '' } else { $null } }; ",
    "function Put($kind,$place,$name,$line,$target,$a,$cwd,$approved){ $p=$null; if ($approved) { $p=Hex $approved $name }; [void]$out.Add([pscustomobject]@{Kind=$kind; Place=$place; Name=$name; Line=$line; Target=$target; Arguments=$a; WorkingDirectory=$cwd; Approved=$approved; Previous=$p}) }; ",
    "$runs=@(@('HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run',('HKLM\\SOFTWARE'+$e+'Run')),@('HKLM\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run',('HKLM\\SOFTWARE'+$e+'Run32'))); ",
    "foreach ($u in Get-ChildItem -LiteralPath 'Registry::HKEY_USERS' | Where-Object { $_.PSChildName -match '^S-1-5-21-[0-9-]+$' }) { $h='HKU\\'+$u.PSChildName+'\\Software'; $runs+=,@(($h+'\\Microsoft\\Windows\\CurrentVersion\\Run'),($h+$e+'Run')) }; ",
    "foreach ($r in $runs) { $k=Get-Item -LiteralPath (Full $r[0]) -ErrorAction SilentlyContinue; if ($k) { foreach ($n in $k.GetValueNames()) { Put 'run' $r[0] $n ([string]$k.GetValue($n,$null,'DoNotExpandEnvironmentNames')) $null $null $null $r[1] } } }; ",
    "$sh=New-Object -ComObject WScript.Shell; ",
    "$dirs=@(,@(($env:ProgramData+'\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp'),('HKLM\\SOFTWARE'+$e+'StartupFolder'))); ",
    "foreach ($p in Get-CimInstance -ClassName Win32_UserProfile | Where-Object { $_.SID -match '^S-1-5-21-[0-9-]+$' }) { $a=$null; if (Test-Path -LiteralPath ('Registry::HKEY_USERS\\'+$p.SID)) { $a='HKU\\'+$p.SID+'\\Software'+$e+'StartupFolder' }; $dirs+=,@(($p.LocalPath+'\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup'),$a) }; ",
    "foreach ($d in $dirs) { foreach ($f in Get-ChildItem -LiteralPath $d[0] -File -Force -ErrorAction SilentlyContinue) { if ($f.Extension -eq '.lnk') { $l=$sh.CreateShortcut($f.FullName); Put 'shortcut' $d[0] $f.Name $null $l.TargetPath $l.Arguments $l.WorkingDirectory $d[1] } else { Put 'file' $d[0] $f.Name $null $f.FullName $null $null $d[1] } } }; ",
    "ConvertTo-Json -Compress -InputObject @($out)"
);

/// What a logon entry is turned off with: the first byte odd turns it
/// off, the rest is a time Windows fills in and may stay zero.
pub const APPROVED_OFF: &str = "030000000000000000000000";

/// How long a task's program gets to end.
const END_WAIT_MS: u64 = 30_000;
const END_POLL_MS: u64 = 500;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct TaskList {
    #[serde(default)]
    schedule: Option<u32>,
    #[serde(default)]
    tasks: Vec<Task>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Task {
    #[serde(default)]
    path: Option<String>,
    name: String,
    #[serde(default)]
    state: Option<String>,
    #[serde(default)]
    actions: Vec<ExecAction>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct ExecAction {
    #[serde(default)]
    execute: Option<String>,
    #[serde(default)]
    arguments: Option<String>,
    #[serde(default)]
    working_directory: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct LogonEntry {
    kind: String,
    place: String,
    name: String,
    #[serde(default)]
    line: Option<String>,
    #[serde(default)]
    target: Option<String>,
    #[serde(default)]
    arguments: Option<String>,
    #[serde(default)]
    working_directory: Option<String>,
    #[serde(default)]
    approved: Option<String>,
    #[serde(default)]
    previous: Option<String>,
}

/// A task's full name as `schtasks.exe /TN` takes it: its folder and name.
fn full_name(task: &Task) -> String {
    let path = task.path.as_deref().unwrap_or("\\");
    if path.ends_with('\\') {
        format!("{path}{}", task.name)
    } else {
        format!("{path}\\{}", task.name)
    }
}

fn unquote(text: &str) -> &str {
    let text = text.trim();
    text.strip_prefix('"')
        .and_then(|rest| rest.strip_suffix('"'))
        .unwrap_or(text)
}

/// Whether a `StartupApproved` value turns its entry off.
pub fn approved_off(value: Option<&str>) -> bool {
    value
        .and_then(|hex| hex.get(..2))
        .and_then(|byte| u8::from_str_radix(byte, 16).ok())
        .is_some_and(|byte| byte & 1 == 1)
}

/// Every scheduled task that runs the program.
pub fn tasks(host: &dyn Host, profile: &Profile, processes: &[Process]) -> Vec<Found> {
    let Some(json) = powershell(host, TASKS_QUERY) else {
        return Vec::new();
    };
    let Ok(list) = serde_json::from_str::<TaskList>(json.trim()) else {
        return Vec::new();
    };
    let schedule = list.schedule.filter(|pid| *pid != 0);
    let mut out = Vec::new();
    for task in &list.tasks {
        let name = full_name(task);
        let action = task.actions.iter().find(|action| {
            action
                .execute
                .as_deref()
                .is_some_and(|execute| program_named(&profile.detect.executables, unquote(execute)))
        });
        let named = profile
            .detect
            .services
            .iter()
            .any(|service| service.eq_ignore_ascii_case(&task.name));
        if action.is_none() && !named {
            continue;
        }
        let state = task.state.as_deref().unwrap_or("");
        let running = state == "Running";
        // A running task's program is a child of the Task Scheduler; a
        // wrapper the profile names starts it one level further down.
        let own: Vec<Process> = processes
            .iter()
            .filter(|process| {
                running
                    && schedule.is_some_and(|schedule| {
                        process.ppid == Some(schedule)
                            || (named
                                && process.ppid.is_some_and(|parent| {
                                    host.process_info(parent).ok().and_then(|info| info.ppid)
                                        == Some(schedule)
                                }))
                    })
            })
            .cloned()
            .collect();
        let mut notes = Vec::new();
        let invocation = match (own.first(), action) {
            (Some(process), _) => Some(Invocation {
                args: process.argv.iter().skip(1).cloned().collect(),
                env: process.env.clone(),
                cwd: process.cwd.clone(),
            }),
            (None, Some(action)) => Some(Invocation {
                args: action
                    .arguments
                    .as_deref()
                    .map(|line| split_windows_command_line(&format!("x {line}")))
                    .map(|argv| argv[1..].to_vec())
                    .unwrap_or_default(),
                env: Default::default(),
                cwd: action
                    .working_directory
                    .clone()
                    .filter(|cwd| !cwd.is_empty()),
            }),
            (None, None) => {
                notes.push(
                    "the task runs a wrapper and is not running; its command line for the program is unknown"
                        .into(),
                );
                None
            }
        };
        if running && own.is_empty() {
            notes.push(format!(
                "task {name} is running but its process of the program was not found"
            ));
        }
        out.push(Found {
            origin: Origin::WinTask {
                name: name.clone(),
                enabled: state != "Disabled",
                running,
            },
            program: own.first().map(|process| process.exe.clone()).or_else(|| {
                action.and_then(|action| action.execute.as_deref().map(|e| unquote(e).to_string()))
            }),
            invocation,
            processes: own,
            notes,
        });
    }
    out
}

/// Every logon entry that runs the program.
pub fn logon_entries(host: &dyn Host, profile: &Profile, processes: &[Process]) -> Vec<Found> {
    let Some(json) = powershell(host, LOGON_QUERY) else {
        return Vec::new();
    };
    let Ok(list) = serde_json::from_str::<Vec<LogonEntry>>(json.trim()) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for entry in list {
        let argv: Vec<String> = match entry.kind.as_str() {
            "run" => split_windows_command_line(entry.line.as_deref().unwrap_or("")),
            "shortcut" => {
                let Some(target) = entry.target.as_deref().filter(|target| !target.is_empty())
                else {
                    continue;
                };
                let mut argv = vec![target.to_string()];
                if let Some(arguments) = entry.arguments.as_deref() {
                    argv.extend(
                        split_windows_command_line(&format!("x {arguments}"))
                            .into_iter()
                            .skip(1),
                    );
                }
                argv
            }
            "file" => entry.target.iter().cloned().collect(),
            _ => continue,
        };
        let Some(program) = argv.first() else {
            continue;
        };
        if !program_named(&profile.detect.executables, program) {
            continue;
        }
        // Its processes: the same command line, as far as it can be told.
        let own: Vec<Process> = processes
            .iter()
            .filter(|process| {
                process.argv.get(1..) == argv.get(1..)
                    && program_named(&profile.detect.executables, &process.exe)
            })
            .cloned()
            .collect();
        let mut notes = Vec::new();
        if entry.approved.is_none() {
            notes.push(format!(
                "{} in {} belongs to a user who is not logged on; turn it off by hand",
                entry.name, entry.place
            ));
        }
        let invocation = match own.first() {
            Some(process) => Invocation {
                args: process.argv.iter().skip(1).cloned().collect(),
                env: process.env.clone(),
                cwd: process.cwd.clone(),
            },
            None => Invocation {
                args: argv[1..].to_vec(),
                env: Default::default(),
                cwd: entry
                    .working_directory
                    .clone()
                    .filter(|cwd| !cwd.is_empty()),
            },
        };
        out.push(Found {
            origin: Origin::WinLogon {
                place: entry.place.clone(),
                name: entry.name.clone(),
                disabled: approved_off(entry.previous.as_deref()),
                approved: entry.approved.clone(),
                previous: entry.previous.clone(),
            },
            program: Some(program.clone()),
            invocation: Some(invocation),
            processes: own,
            notes,
        });
    }
    out
}

fn base64(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let n = (u32::from(chunk[0]) << 16)
            | (u32::from(*chunk.get(1).unwrap_or(&0)) << 8)
            | u32::from(*chunk.get(2).unwrap_or(&0));
        for (index, shift) in [18u32, 12, 6, 0].into_iter().enumerate() {
            if index <= chunk.len() {
                out.push(ALPHABET[((n >> shift) & 63) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// The query [`task_state`] runs.
pub fn task_state_query(name: &str) -> String {
    format!(
        "[Console]::OutputEncoding=[Text.Encoding]::UTF8; $n=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('{}')); [string](Get-ScheduledTask | Where-Object {{ ($_.TaskPath + $_.TaskName) -eq $n }} | Select-Object -First 1).State",
        base64(name.as_bytes())
    )
}

/// The state of a task (`Ready`, `Running`, `Disabled`, ...); `None` when
/// it cannot be read. The name reaches PowerShell encoded, so no character
/// in it is read as code.
pub fn task_state(host: &dyn Host, name: &str) -> Option<String> {
    let state = powershell(host, &task_state_query(name))?
        .trim()
        .to_string();
    (!state.is_empty()).then_some(state)
}

fn schtasks(host: &dyn Host, args: &[&str]) -> Result<(), String> {
    let output = host
        .run("schtasks.exe", args)
        .map_err(|error| format!("schtasks.exe: {error}"))?;
    if output.success() {
        Ok(())
    } else {
        let detail = format!("{} {}", output.stdout.trim(), output.stderr.trim());
        Err(format!(
            "schtasks.exe {} failed: {}",
            args.join(" "),
            detail.trim()
        ))
    }
}

/// Ends a running task and waits until it no longer runs.
pub fn end(host: &dyn Host, name: &str) -> Result<(), String> {
    let result = schtasks(host, &["/End", "/TN", name]);
    let mut waited = 0;
    loop {
        match task_state(host, name).as_deref() {
            Some("Running") => {}
            Some(_) => return Ok(()),
            None => return result.and(Err(format!("cannot read the state of task {name}"))),
        }
        if waited >= END_WAIT_MS {
            return Err(result
                .err()
                .unwrap_or_else(|| format!("task {name} did not end")));
        }
        host.sleep_ms(END_POLL_MS);
        waited += END_POLL_MS;
    }
}

/// Runs a task now; one already running counts.
pub fn run(host: &dyn Host, name: &str) -> Result<(), String> {
    if task_state(host, name).as_deref() == Some("Running") {
        return Ok(());
    }
    schtasks(host, &["/Run", "/TN", name])
}

/// Turns a task on or off.
pub fn set_enabled(host: &dyn Host, name: &str, enabled: bool) -> Result<(), String> {
    schtasks(
        host,
        &[
            "/Change",
            "/TN",
            name,
            if enabled { "/ENABLE" } else { "/DISABLE" },
        ],
    )
}

/// `reg.exe` arguments naming one value; an empty name is the key's
/// default value.
fn value_args<'a>(key: &'a str, name: &'a str) -> Vec<&'a str> {
    if name.is_empty() {
        vec![key, "/ve"]
    } else {
        vec![key, "/v", name]
    }
}

/// The binary value `reg.exe query` prints, in lower-case hexadecimal;
/// `None` when there is none.
pub fn read_approved(host: &dyn Host, key: &str, name: &str) -> Result<Option<String>, String> {
    let mut args = vec!["query"];
    args.extend(value_args(key, name));
    let output = host
        .run("reg.exe", &args)
        .map_err(|error| format!("reg.exe: {error}"))?;
    if !output.success() {
        // A missing value or key: nothing turns the entry off.
        return Ok(None);
    }
    Ok(output.stdout.lines().find_map(|line| {
        let (_, value) = line.split_once("REG_BINARY")?;
        Some(value.trim().to_ascii_lowercase())
    }))
}

/// Writes a `StartupApproved` value.
pub fn write_approved(host: &dyn Host, key: &str, name: &str, hex: &str) -> Result<(), String> {
    let mut args = vec!["add"];
    args.extend(value_args(key, name));
    args.extend(["/t", "REG_BINARY", "/d", hex, "/f"]);
    reg(host, &args)
}

/// Removes a `StartupApproved` value.
pub fn delete_approved(host: &dyn Host, key: &str, name: &str) -> Result<(), String> {
    let mut args = vec!["delete"];
    args.extend(value_args(key, name));
    args.push("/f");
    reg(host, &args)
}

fn reg(host: &dyn Host, args: &[&str]) -> Result<(), String> {
    let output = host
        .run("reg.exe", args)
        .map_err(|error| format!("reg.exe: {error}"))?;
    if output.success() {
        Ok(())
    } else {
        let detail = format!("{} {}", output.stdout.trim(), output.stderr.trim());
        Err(format!(
            "reg.exe {} failed: {}",
            args.first().copied().unwrap_or(""),
            detail.trim()
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_matches_the_standard_alphabet() {
        assert_eq!(base64(b""), "");
        assert_eq!(base64(b"f"), "Zg==");
        assert_eq!(base64(b"fo"), "Zm8=");
        assert_eq!(base64(b"foo"), "Zm9v");
        assert_eq!(base64("\\Demo\\网".as_bytes()), "XERlbW9c572R");
    }

    #[test]
    fn approved_values_turn_off_on_an_odd_first_byte() {
        assert!(!approved_off(None));
        assert!(!approved_off(Some("020000000000000000000000")));
        assert!(!approved_off(Some("06000000")));
        assert!(approved_off(Some(APPROVED_OFF)));
        assert!(approved_off(Some("07000000")));
        assert!(!approved_off(Some("")));
    }

    #[test]
    fn task_names_join_folder_and_name() {
        let task = |path: Option<&str>| Task {
            path: path.map(str::to_string),
            name: "demo".into(),
            state: None,
            actions: Vec::new(),
        };
        assert_eq!(full_name(&task(Some("\\"))), "\\demo");
        assert_eq!(full_name(&task(Some("\\Vendor\\"))), "\\Vendor\\demo");
        assert_eq!(full_name(&task(None)), "\\demo");
    }

    #[test]
    fn reads_the_approved_value_reg_prints() {
        let host = crate::host::fake::FakeHost::default();
        host.answer(
            "reg.exe query HKLM\\SOFTWARE\\X\\Run /v demo mesh",
            0,
            "\r\nHKEY_LOCAL_MACHINE\\SOFTWARE\\X\\Run\r\n    demo mesh    REG_BINARY    0300000000000000AB000000\r\n\r\n",
        );
        host.answer("reg.exe query HKLM\\SOFTWARE\\X\\Run /v other", 1, "");
        assert_eq!(
            read_approved(&host, "HKLM\\SOFTWARE\\X\\Run", "demo mesh").unwrap(),
            Some("0300000000000000ab000000".into())
        );
        assert_eq!(
            read_approved(&host, "HKLM\\SOFTWARE\\X\\Run", "other").unwrap(),
            None
        );
    }
}
