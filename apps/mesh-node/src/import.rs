//! The import pipeline: findings → collected settings → our configuration
//! files and one report.

use std::collections::BTreeMap;
use std::path::Path;

use crate::convert::{convert, ImportOptions};
use crate::detect::{Found, Origin};
use crate::host::Host;
use crate::profile::Profile;
use crate::report::{
    item, ImportReport, InstanceReport, InstanceStatus, Item, ItemStatus, REPORT_VERSION,
};
use crate::source::collect;

fn file_name_for(id: &str) -> String {
    let safe: String = id
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_') {
                c
            } else {
                '_'
            }
        })
        .collect();
    format!("{}.json", safe.trim_matches('_'))
}

fn status_of(report: &InstanceReport) -> InstanceStatus {
    match report.worst() {
        ItemStatus::Blocked => InstanceStatus::Blocked,
        ItemStatus::NeedsConfirmation => InstanceStatus::NeedsConfirmation,
        ItemStatus::Imported | ItemStatus::Dropped => InstanceStatus::Ready,
    }
}

/// Converts every finding. With `out_dir`, writes each usable
/// configuration there (owner-only: it holds the secret).
pub fn import(
    host: &dyn Host,
    profile: &Profile,
    options: &ImportOptions,
    found: &[Found],
    out_dir: Option<&Path>,
) -> ImportReport {
    let mut report = ImportReport {
        report_version: REPORT_VERSION,
        tool_version: crate::VERSION,
        profile_label: profile.label.clone(),
        source_version: profile.source_version.clone(),
        instances: Vec::new(),
        notes: Vec::new(),
    };
    // (network name, address) → id of the first instance with them.
    let mut seen: BTreeMap<(String, String), String> = BTreeMap::new();

    for entry in found {
        let origin = serde_json::to_value(&entry.origin).unwrap_or_default();
        let notes: Vec<Item> = entry
            .notes
            .iter()
            .map(|note| {
                item(
                    "detection",
                    ItemStatus::NeedsConfirmation,
                    "detection_note",
                    note,
                )
            })
            .collect();
        if let Origin::Container { .. } = entry.origin {
            let mut items = vec![item(
                "origin",
                ItemStatus::Blocked,
                "container",
                "该程序运行在容器中，不自动接管，需人工迁移。",
            )];
            items.extend(notes);
            report.instances.push(InstanceReport {
                id: entry.origin.id(),
                status: InstanceStatus::Blocked,
                origin,
                config_file: None,
                output: None,
                network: None,
                duplicate_of: None,
                items,
            });
            continue;
        }
        let Some(invocation) = &entry.invocation else {
            let mut items = vec![item(
                "origin",
                ItemStatus::Blocked,
                "command_unknown",
                "无法确定该程序的启动参数，需人工迁移。",
            )];
            items.extend(notes);
            report.instances.push(InstanceReport {
                id: entry.origin.id(),
                status: InstanceStatus::Blocked,
                origin,
                config_file: None,
                output: None,
                network: None,
                duplicate_of: None,
                items,
            });
            continue;
        };
        let collected = collect(host, profile, invocation);
        let several = collected.len() > 1;
        for (index, instance) in collected.iter().enumerate() {
            let id = if several {
                format!("{}#{}", entry.origin.id(), index + 1)
            } else {
                entry.origin.id()
            };
            let converted = convert(profile, instance, options);
            let mut items = converted.items;
            items.extend(notes.iter().cloned());
            let mut instance_report = InstanceReport {
                id: id.clone(),
                status: InstanceStatus::Ready,
                origin: origin.clone(),
                config_file: instance.config_file.clone(),
                output: None,
                network: converted.network.clone(),
                duplicate_of: None,
                items,
            };
            instance_report.status = status_of(&instance_report);

            // The same network and address found twice (a service and its
            // process, a script and its cron line): one node.
            let address = instance_report
                .items
                .iter()
                .find(|entry| entry.field == "node.address" && entry.status == ItemStatus::Imported)
                .and_then(|entry| entry.value.clone());
            if let (Some(network), Some(address)) = (&converted.network, address) {
                let key = (network.name.clone(), address);
                if let Some(first) = seen.get(&key) {
                    instance_report.duplicate_of = Some(first.clone());
                    instance_report.status = InstanceStatus::Ready;
                    instance_report.items.clear();
                    report.instances.push(instance_report);
                    continue;
                }
                seen.insert(key, id.clone());
            }

            if let (
                Some(config),
                Some(dir),
                InstanceStatus::Ready | InstanceStatus::NeedsConfirmation,
            ) = (&converted.config, out_dir, instance_report.status)
            {
                let path = dir.join(file_name_for(&id));
                let text = serde_json::to_string_pretty(config).unwrap_or_default();
                let written = host
                    .create_dir_all(dir, 0o700)
                    .and_then(|()| host.write(&path, text.as_bytes(), 0o600, None));
                match written {
                    Ok(()) => instance_report.output = Some(path.display().to_string()),
                    Err(error) => {
                        instance_report.items.push(item(
                            "output",
                            ItemStatus::Blocked,
                            "write_failed",
                            &format!("配置写入失败：{error}。"),
                        ));
                        instance_report.status = InstanceStatus::Blocked;
                    }
                }
            }
            report.instances.push(instance_report);
        }
    }

    // Instances of one network found on this machine must agree.
    let mut modes: BTreeMap<&str, (bool, bool, &str)> = BTreeMap::new();
    let mut conflicts: Vec<String> = Vec::new();
    for instance in &report.instances {
        if let Some(network) = &instance.network {
            let mode = (
                network.secure_mode,
                network.encrypted,
                network.cipher.as_str(),
            );
            match modes.get(network.name.as_str()) {
                Some(existing) if *existing != mode => conflicts.push(network.name.clone()),
                Some(_) => {}
                None => {
                    modes.insert(network.name.as_str(), mode);
                }
            }
        }
    }
    conflicts.sort();
    conflicts.dedup();
    for name in conflicts {
        report.notes.push(
            item(
                "network",
                ItemStatus::Blocked,
                "network_mode_mismatch",
                "同一网络的节点加密模式或算法不一致，停止导入。",
            )
            .with_value(name.clone()),
        );
        for instance in &mut report.instances {
            if instance
                .network
                .as_ref()
                .is_some_and(|network| network.name == name)
            {
                instance.status = InstanceStatus::Blocked;
            }
        }
    }
    report
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host::fake::FakeHost;
    use crate::profile::tests::demo;
    use crate::source::Invocation;

    fn found(origin: Origin, args: &[&str]) -> Found {
        Found {
            origin,
            program: Some("/usr/bin/demo-meshd".into()),
            invocation: Some(Invocation {
                args: args.iter().map(|arg| arg.to_string()).collect(),
                ..Invocation::default()
            }),
            processes: Vec::new(),
            notes: Vec::new(),
        }
    }

    const ARGS: &[&str] = &[
        "--net-name",
        "office",
        "--net-secret",
        "s3cret",
        "-i",
        "10.126.0.5/24",
        "-p",
        "tcp://peer:1",
    ];

    #[test]
    fn writes_configs_and_reports() {
        let host = FakeHost::default();
        let profile = demo();
        let entries = vec![
            found(
                Origin::Systemd {
                    unit: "demo-meshd.service".into(),
                    fragment: None,
                    drop_ins: Vec::new(),
                    unit_file_state: "enabled".into(),
                    active: true,
                },
                ARGS,
            ),
            found(Origin::Process { pid: 7 }, ARGS),
            Found {
                origin: Origin::Container {
                    id: "abc".into(),
                    image: "demo/meshd".into(),
                },
                program: None,
                invocation: None,
                processes: Vec::new(),
                notes: Vec::new(),
            },
        ];
        let report = import(
            &host,
            &profile,
            &ImportOptions::default(),
            &entries,
            Some(Path::new("/etc/anixops-mesh/imported")),
        );
        assert_eq!(report.instances.len(), 3);
        let first = &report.instances[0];
        assert_eq!(first.status, InstanceStatus::Ready);
        // Joined with the platform's separator.
        let expected = Path::new("/etc/anixops-mesh/imported")
            .join("systemd_demo-meshd.service.json")
            .to_string_lossy()
            .into_owned();
        assert_eq!(first.output.as_deref(), Some(expected.as_str()));
        let written = host
            .text("/etc/anixops-mesh/imported/systemd_demo-meshd.service.json")
            .unwrap();
        let config: serde_json::Value = serde_json::from_str(&written).unwrap();
        assert_eq!(config["network"]["secret"], "s3cret");
        assert_eq!(
            host.stats
                .borrow()
                .get(Path::new(
                    "/etc/anixops-mesh/imported/systemd_demo-meshd.service.json"
                ))
                .unwrap()
                .mode,
            0o600
        );

        assert_eq!(
            report.instances[1].duplicate_of.as_deref(),
            Some("systemd:demo-meshd.service")
        );
        assert!(report.instances[1].output.is_none());
        assert_eq!(report.instances[2].status, InstanceStatus::Blocked);
        assert_eq!(report.exit_code(), 6);

        let printed = serde_json::to_string(&report).unwrap();
        assert!(!printed.contains("s3cret"));
    }

    #[test]
    fn mismatched_modes_block_the_network() {
        let host = FakeHost::default();
        let profile = demo();
        let mut other = ARGS.to_vec();
        other[5] = "10.126.0.6/24";
        other.push("--secure");
        let entries = vec![
            found(Origin::Process { pid: 1 }, ARGS),
            found(Origin::Process { pid: 2 }, &other),
        ];
        let report = import(&host, &profile, &ImportOptions::default(), &entries, None);
        assert!(report
            .instances
            .iter()
            .all(|instance| instance.status == InstanceStatus::Blocked));
        assert_eq!(report.notes[0].code, "network_mode_mismatch");
    }

    #[test]
    fn nothing_found_is_its_own_exit_code() {
        let host = FakeHost::default();
        let report = import(&host, &demo(), &ImportOptions::default(), &[], None);
        assert_eq!(report.exit_code(), 3);
    }
}
