//! One-way conversion of collected settings into our mesh configuration
//! (config v1 of the `"type": "mesh"` outbound, requirement R13).
//!
//! Only what interworking needs is taken: network name, secret, handshake
//! mode and cipher, virtual addresses, listeners, peers, advertised subnets
//! and the route policy. Everything else is listed in the report.

use std::collections::HashSet;
use std::net::IpAddr;

use serde_json::{json, Value};

use crate::net::{is_intranet, Cidr, Endpoint};
use crate::profile::{Field, Profile, Severity};
use crate::report::{item, Item, ItemStatus, NetworkSummary};
use crate::source::{Collected, Problem};

/// `config_version` of the configuration written.
pub const CONFIG_VERSION: u32 = 1;
/// Port used when nothing else names one.
pub const DEFAULT_PORT: u16 = 11010;
/// MTU our node uses when the configuration names none.
pub const DEFAULT_MTU: i64 = 1380;
const MAX_PEERS: usize = 64;
const MAX_SUBNETS: usize = 256;
const MAX_NETWORK_NAME_BYTES: usize = 255;

/// Choices made by whoever runs the import.
#[derive(Debug, Clone, Default)]
pub struct ImportOptions {
    /// Accept a network without encryption (requirement R14).
    pub allow_unencrypted: bool,
    /// Fixed address to use, for nodes that had theirs assigned
    /// automatically.
    pub address: Option<String>,
}

pub struct Converted {
    /// Our configuration; `None` when the instance is blocked. Holds the
    /// secret.
    pub config: Option<Value>,
    pub network: Option<NetworkSummary>,
    pub items: Vec<Item>,
}

fn status_for(severity: Severity) -> ItemStatus {
    match severity {
        Severity::Note => ItemStatus::Dropped,
        Severity::Confirm => ItemStatus::NeedsConfirmation,
        Severity::Block => ItemStatus::Blocked,
    }
}

fn reason_code(reason: crate::profile::DropReason) -> String {
    serde_json::to_value(reason)
        .ok()
        .and_then(|value| value.as_str().map(str::to_string))
        .unwrap_or_default()
}

/// Normalises a cipher name to the names config v1 uses.
pub fn normalize_cipher(name: &str) -> Result<&'static str, &'static str> {
    match name.trim().to_ascii_lowercase().as_str() {
        "aes-gcm" | "aes-128-gcm" | "openssl-aes-gcm" | "openssl-aes-128-gcm" => Ok("aes-gcm"),
        "aes-256-gcm" | "openssl-aes-256-gcm" => Ok("aes-256-gcm"),
        "chacha20" | "chacha20-poly1305" | "openssl-chacha20" | "openssl-chacha20-poly1305" => {
            Ok("chacha20")
        }
        "xor" => Err("weak_cipher"),
        _ => Err("unknown_cipher"),
    }
}

/// Checks an interface address: inside the intranet scope, a sensible
/// prefix, and neither the network nor the broadcast address.
fn check_interface(cidr: &Cidr, min: u8, max: u8) -> Result<(), &'static str> {
    if cidr.prefix < min || cidr.prefix > max {
        return Err("prefix_out_of_range");
    }
    if !is_intranet(&Cidr {
        address: cidr.network(),
        prefix: cidr.prefix,
    }) {
        return Err("address_not_intranet");
    }
    if cidr.address == cidr.network() {
        return Err("address_is_network");
    }
    if let IpAddr::V4(address) = cidr.address {
        // The prefix is at most `max` (below 32), so the shift is in range.
        let host_mask = u32::MAX >> u32::from(cidr.prefix);
        if u32::from(address) & host_mask == host_mask {
            return Err("address_is_broadcast");
        }
    }
    Ok(())
}

#[derive(Clone, PartialEq, Eq, Hash)]
struct Listen {
    transport: &'static str,
    port: u16,
    address: Option<IpAddr>,
}

fn transport_name(scheme: &str) -> Option<&'static str> {
    match scheme {
        "tcp" => Some("tcp"),
        "udp" => Some("udp"),
        _ => None,
    }
}

/// Listeners as (transport, port, address).
type Expanded = Vec<(String, u16, Option<IpAddr>)>;

/// Expands one listener value into (transport, port, address) triples.
fn expand_listener(profile: &Profile, text: &str) -> Result<Expanded, ()> {
    let text = text.trim();
    if let Some(endpoint) = Endpoint::parse(text) {
        let address = if endpoint.is_wildcard() {
            None
        } else {
            Some(endpoint.host.parse::<IpAddr>().map_err(|_| ())?)
        };
        let port = match endpoint.port {
            Some(port) => port,
            None => shorthand_port(profile, &endpoint.scheme).ok_or(())?,
        };
        return Ok(vec![(endpoint.scheme, port, address)]);
    }
    let shorthand = profile.listener_shorthand.as_ref().ok_or(())?;
    let all = |port: u16, address: Option<IpAddr>| -> Result<Expanded, ()> {
        shorthand
            .transports
            .iter()
            .map(|transport| {
                port.checked_add(transport.offset)
                    .map(|port| (transport.name.clone(), port, address))
                    .ok_or(())
            })
            .collect()
    };
    // A bare port.
    if let Ok(port) = text.parse::<u16>() {
        return all(port, None);
    }
    // A bare address.
    let unbracketed = text
        .strip_prefix('[')
        .and_then(|rest| rest.strip_suffix(']'))
        .unwrap_or(text);
    if let Ok(address) = unbracketed.parse::<IpAddr>() {
        let address = (!address.is_unspecified()).then_some(address);
        return all(shorthand.default_port, address);
    }
    // address:port
    if let Ok(socket) = text.parse::<std::net::SocketAddr>() {
        let address = (!socket.ip().is_unspecified()).then_some(socket.ip());
        return all(socket.port(), address);
    }
    // transport or transport:port
    let (name, port) = match text.split_once(':') {
        Some((name, port)) => (name, Some(port.parse::<u16>().map_err(|_| ())?)),
        None => (text, None),
    };
    let transport = shorthand
        .transports
        .iter()
        .find(|transport| transport.name.eq_ignore_ascii_case(name))
        .ok_or(())?;
    let port = match port {
        Some(port) => port,
        None => shorthand
            .default_port
            .checked_add(transport.offset)
            .ok_or(())?,
    };
    Ok(vec![(transport.name.clone(), port, None)])
}

fn shorthand_port(profile: &Profile, scheme: &str) -> Option<u16> {
    let shorthand = profile.listener_shorthand.as_ref()?;
    let transport = shorthand
        .transports
        .iter()
        .find(|transport| transport.name == scheme)?;
    shorthand.default_port.checked_add(transport.offset)
}

pub fn convert(profile: &Profile, collected: &Collected, options: &ImportOptions) -> Converted {
    let mut items: Vec<Item> = Vec::new();

    for problem in &collected.problems {
        items.push(match problem {
            Problem::Unknown(what) => item(
                what,
                ItemStatus::NeedsConfirmation,
                "unrecognized",
                "未识别的设置，未导入；请确认它不影响互通。",
            ),
            Problem::BadValue { origin, why } => item(
                origin,
                ItemStatus::NeedsConfirmation,
                "bad_value",
                &format!("取值无法解析，未导入：{why}。"),
            ),
            Problem::Unreadable { path, why } => item(
                "config_file",
                ItemStatus::Blocked,
                "unreadable",
                &format!("配置文件无法读取：{why}。"),
            )
            .with_value(path.clone()),
            Problem::Stdin => item(
                "config_file",
                ItemStatus::Blocked,
                "config_from_stdin",
                "配置从标准输入读取，本机没有可导入的配置文件。",
            ),
        });
    }
    for dropped in &collected.dropped {
        items.push(item(
            &dropped.origin,
            status_for(dropped.reason.severity()),
            &reason_code(dropped.reason),
            dropped.reason.message(),
        ));
    }

    // Network.
    let name = collected.text(Field::NetworkName).unwrap_or("").to_string();
    let name_origin = collected.origin(Field::NetworkName);
    if name.trim().is_empty() {
        items.push(item(
            Field::NetworkName.name(),
            ItemStatus::Blocked,
            "missing_network_name",
            "没有网络名。",
        ));
    } else if name.len() > MAX_NETWORK_NAME_BYTES || name.chars().any(char::is_control) {
        items.push(item(
            Field::NetworkName.name(),
            ItemStatus::Blocked,
            "invalid_network_name",
            "网络名过长或含控制字符。",
        ));
    } else {
        items.push(
            item(
                Field::NetworkName.name(),
                ItemStatus::Imported,
                "imported",
                "已导入。",
            )
            .at(name_origin)
            .with_value(name.clone()),
        );
    }

    let secret = collected
        .text(Field::NetworkSecret)
        .unwrap_or("")
        .to_string();
    if secret.is_empty() {
        items.push(item(
            Field::NetworkSecret.name(),
            ItemStatus::Blocked,
            "missing_secret",
            "没有网络密钥；空密钥的网络不导入。",
        ));
    } else {
        items.push(
            item(
                Field::NetworkSecret.name(),
                ItemStatus::Imported,
                "imported",
                "已导入（不在报告中显示）。",
            )
            .at(collected.origin(Field::NetworkSecret)),
        );
    }

    let secure_mode = collected.bool(Field::SecureMode).unwrap_or(false);
    items.push(
        item(
            Field::SecureMode.name(),
            ItemStatus::Imported,
            "imported",
            if secure_mode {
                "安全模式（前向保密）。"
            } else {
                "默认模式，未启用前向保密。"
            },
        )
        .at(collected.origin(Field::SecureMode))
        .with_value(secure_mode.to_string()),
    );
    if collected.text(Field::SecurePrivateKey).is_some() {
        items.push(
            item(
                Field::SecurePrivateKey.name(),
                ItemStatus::NeedsConfirmation,
                "static_key_not_imported",
                "安全模式静态私钥未导入（配置格式暂无此项），节点身份会改变；若对端固定了本节点公钥，需要同步更新。",
            )
            .at(collected.origin(Field::SecurePrivateKey)),
        );
    }

    let encryption = collected.bool(Field::Encryption).unwrap_or(true);
    let mut cipher: &'static str = "aes-gcm";
    let mut encrypted = true;
    if let Some(text) = collected.text(Field::Cipher) {
        match normalize_cipher(text) {
            Ok(normalized) => {
                cipher = normalized;
                items.push(
                    item(
                        Field::Cipher.name(),
                        ItemStatus::Imported,
                        "imported",
                        "已导入。",
                    )
                    .at(collected.origin(Field::Cipher))
                    .with_value(normalized),
                );
            }
            Err(code) => {
                let message = if code == "weak_cipher" {
                    "该加密算法没有完整性保护，拒绝导入。"
                } else {
                    "无法识别的加密算法，拒绝导入。"
                };
                items.push(
                    item(Field::Cipher.name(), ItemStatus::Blocked, code, message)
                        .at(collected.origin(Field::Cipher))
                        .with_value(text.to_string()),
                );
            }
        }
    }
    if !encryption {
        let origin = collected.origin(Field::Encryption);
        if secure_mode {
            items.push(
                item(
                    Field::Encryption.name(),
                    ItemStatus::NeedsConfirmation,
                    "encryption_switch_ignored",
                    "安全模式始终加密，关闭加密的设置不生效。",
                )
                .at(origin),
            );
        } else if options.allow_unencrypted {
            cipher = "none";
            encrypted = false;
            items.push(
                item(
                    Field::Encryption.name(),
                    ItemStatus::NeedsConfirmation,
                    "unencrypted",
                    "该网络未加密，已按显式选择以「未加密」状态导入。",
                )
                .at(origin),
            );
        } else {
            items.push(
                item(
                    Field::Encryption.name(),
                    ItemStatus::Blocked,
                    "unencrypted_refused",
                    "该网络关闭了加密，默认拒绝导入；确需加入时须显式选择「未加密」。",
                )
                .at(origin),
            );
        }
    }

    // This node's addresses.
    let mut address: Option<Cidr> = None;
    let given = options.address.as_deref();
    let auto = collected.bool(Field::AutoAddress).unwrap_or(false);
    let (address_text, address_origin) = match given {
        Some(text) => (Some(text.to_string()), Some("command line")),
        None => (
            collected.text(Field::Ipv4).map(str::to_string),
            collected.origin(Field::Ipv4),
        ),
    };
    if auto && given.is_none() {
        items.push(
            item(
                Field::Ipv4.name(),
                ItemStatus::Blocked,
                "auto_address",
                "原节点自动分配地址；受管网络须使用固定地址，请指定该节点当前的实际地址。",
            )
            .at(collected.origin(Field::AutoAddress)),
        );
    } else if let Some(text) = address_text {
        let parsed = if text.contains('/') {
            Cidr::parse(&text)
        } else {
            text.trim().parse::<IpAddr>().ok().map(|address| {
                items.push(
                    item(
                        Field::Ipv4.name(),
                        ItemStatus::NeedsConfirmation,
                        "prefix_assumed",
                        "地址未写前缀长度，按 /24 导入，请确认。",
                    )
                    .at(address_origin),
                );
                Cidr {
                    address,
                    prefix: 24,
                }
            })
        };
        match parsed {
            Some(cidr) if cidr.address.is_ipv4() => match check_interface(&cidr, 8, 30) {
                Ok(()) => {
                    items.push(
                        item(
                            Field::Ipv4.name(),
                            ItemStatus::Imported,
                            "imported",
                            "已导入。",
                        )
                        .at(address_origin)
                        .with_value(cidr.to_string()),
                    );
                    address = Some(cidr);
                }
                Err(code) => items.push(
                    item(
                        Field::Ipv4.name(),
                        ItemStatus::Blocked,
                        code,
                        "虚拟地址不在内网范围或不是可用的主机地址。",
                    )
                    .at(address_origin)
                    .with_value(cidr.to_string()),
                ),
            },
            _ => items.push(
                item(
                    Field::Ipv4.name(),
                    ItemStatus::Blocked,
                    "invalid_address",
                    "虚拟 IPv4 地址无法解析。",
                )
                .at(address_origin)
                .with_value(text),
            ),
        }
    } else {
        items.push(item(
            Field::Ipv4.name(),
            ItemStatus::Blocked,
            "missing_address",
            "没有虚拟 IPv4 地址。",
        ));
    }

    let mut address_v6: Option<Cidr> = None;
    if let Some(text) = collected.text(Field::Ipv6) {
        let origin = collected.origin(Field::Ipv6);
        if collected.bool(Field::EnableIpv6) == Some(false) {
            items.push(
                item(
                    Field::Ipv6.name(),
                    ItemStatus::Dropped,
                    "ipv6_disabled",
                    "原配置关闭了 IPv6，虚拟 IPv6 地址不导入。",
                )
                .at(origin),
            );
        } else {
            match Cidr::parse(text).filter(|cidr| !cidr.address.is_ipv4()) {
                Some(cidr) => match check_interface(&cidr, 8, 126) {
                    Ok(()) => {
                        items.push(
                            item(
                                Field::Ipv6.name(),
                                ItemStatus::Imported,
                                "imported",
                                "已导入。",
                            )
                            .at(origin)
                            .with_value(cidr.to_string()),
                        );
                        address_v6 = Some(cidr);
                    }
                    Err(code) => items.push(
                        item(
                            Field::Ipv6.name(),
                            ItemStatus::NeedsConfirmation,
                            code,
                            "虚拟 IPv6 地址不在内网范围或不可用，未导入。",
                        )
                        .at(origin)
                        .with_value(cidr.to_string()),
                    ),
                },
                None => items.push(
                    item(
                        Field::Ipv6.name(),
                        ItemStatus::NeedsConfirmation,
                        "invalid_address",
                        "虚拟 IPv6 地址无法解析，未导入。",
                    )
                    .at(origin)
                    .with_value(text.to_string()),
                ),
            }
        }
    }

    // Listeners.
    let listener_values: Vec<String> = match collected.list(Field::Listeners) {
        Some(list) => list.iter().map(|entry| entry.value.clone()).collect(),
        None => profile.default_listeners.clone(),
    };
    let listener_origin = collected
        .origin(Field::Listeners)
        .unwrap_or("default listeners");
    let mut listens: Vec<Listen> = Vec::new();
    let mut seen_listens = HashSet::new();
    let mut other_listeners = false;
    for value in &listener_values {
        match expand_listener(profile, value) {
            Ok(expanded) => {
                for (scheme, port, address) in expanded {
                    match transport_name(&scheme.to_ascii_lowercase()) {
                        Some(transport) if port != 0 => {
                            let listen = Listen {
                                transport,
                                port,
                                address,
                            };
                            if seen_listens.insert(listen.clone()) {
                                listens.push(listen);
                            }
                        }
                        Some(_) => items.push(
                            item(
                                Field::Listeners.name(),
                                ItemStatus::NeedsConfirmation,
                                "invalid_port",
                                "监听端口为 0，未导入。",
                            )
                            .at(Some(listener_origin))
                            .with_value(value.clone()),
                        ),
                        None => {
                            other_listeners = true;
                            items.push(
                                item(
                                    Field::Listeners.name(),
                                    ItemStatus::Dropped,
                                    "transport_unsupported",
                                    "第一版只支持 TCP 和 UDP，该监听不迁移。",
                                )
                                .at(Some(listener_origin))
                                .with_value(format!("{scheme}:{port}")),
                            );
                        }
                    }
                }
            }
            Err(()) => items.push(
                item(
                    Field::Listeners.name(),
                    ItemStatus::NeedsConfirmation,
                    "invalid_listener",
                    "监听地址无法解析，未导入。",
                )
                .at(Some(listener_origin))
                .with_value(value.clone()),
            ),
        }
    }
    if listens.is_empty() && other_listeners {
        items.push(
            item(
                Field::Listeners.name(),
                ItemStatus::NeedsConfirmation,
                "no_supported_listener",
                "原节点只在其他传输上监听，迁移后其他节点无法主动连入本节点，请确认。",
            )
            .at(Some(listener_origin)),
        );
    }
    let listen_json: Vec<Value> = listens
        .iter()
        .map(|listen| {
            let mut entry = json!({ "transport": listen.transport, "port": listen.port });
            if let Some(address) = listen.address {
                entry["address"] = json!(address.to_string());
            }
            entry
        })
        .collect();
    if !listens.is_empty() {
        items.push(
            item(
                Field::Listeners.name(),
                ItemStatus::Imported,
                "imported",
                "已导入。",
            )
            .at(Some(listener_origin))
            .with_value(
                listens
                    .iter()
                    .map(|listen| match listen.address {
                        Some(address) => {
                            format!("{}://{}:{}", listen.transport, address, listen.port)
                        }
                        None => format!("{}:{}", listen.transport, listen.port),
                    })
                    .collect::<Vec<_>>()
                    .join(", "),
            ),
        );
    } else if collected
        .list(Field::Listeners)
        .is_some_and(<[_]>::is_empty)
    {
        items.push(
            item(
                Field::Listeners.name(),
                ItemStatus::Imported,
                "no_listener",
                "原节点不监听，只主动连接。",
            )
            .at(Some(listener_origin)),
        );
    }

    // Peers.
    let peer_origin = collected.origin(Field::Peers);
    let mut peers: Vec<(String, u16, &'static str)> = Vec::new();
    let mut seen_peers = HashSet::new();
    let mut other_transport_hosts: Vec<(String, String)> = Vec::new();
    for entry in collected.list(Field::Peers).unwrap_or(&[]) {
        for key in &entry.confirm {
            items.push(
                item(
                    Field::Peers.name(),
                    ItemStatus::NeedsConfirmation,
                    "peer_option",
                    &format!("对端附加设置 {key} 未导入，请确认。"),
                )
                .at(peer_origin)
                .with_value(entry.value.clone()),
            );
        }
        let Some(endpoint) = Endpoint::parse(&entry.value) else {
            items.push(
                item(
                    Field::Peers.name(),
                    ItemStatus::NeedsConfirmation,
                    "invalid_peer",
                    "对端地址无法解析，未导入。",
                )
                .at(peer_origin)
                .with_value(entry.value.clone()),
            );
            continue;
        };
        match transport_name(&endpoint.scheme) {
            Some(transport) => {
                let port = endpoint
                    .port
                    .or_else(|| profile.default_peer_ports.get(&endpoint.scheme).copied())
                    .unwrap_or(DEFAULT_PORT);
                if seen_peers.insert((endpoint.host.clone(), port, transport)) {
                    peers.push((endpoint.host.clone(), port, transport));
                }
            }
            None => other_transport_hosts.push((endpoint.host.clone(), entry.value.clone())),
        }
    }
    for (host, value) in other_transport_hosts {
        let has_supported = peers.iter().any(|(server, _, _)| *server == host);
        items.push(
            item(
                Field::Peers.name(),
                if has_supported {
                    ItemStatus::Dropped
                } else {
                    ItemStatus::NeedsConfirmation
                },
                "peer_transport_unsupported",
                if has_supported {
                    "该对端的其他传输地址不迁移，已使用其 TCP/UDP 地址。"
                } else {
                    "该对端只有其他传输地址，第一版无法连接，请为它提供 TCP 或 UDP 地址。"
                },
            )
            .at(peer_origin)
            .with_value(value),
        );
    }
    if peers.len() > MAX_PEERS {
        items.push(
            item(
                Field::Peers.name(),
                ItemStatus::NeedsConfirmation,
                "too_many_peers",
                &format!("对端超过 {MAX_PEERS} 个，只导入前 {MAX_PEERS} 个。"),
            )
            .at(peer_origin),
        );
        peers.truncate(MAX_PEERS);
    }
    if peers.is_empty() {
        items.push(
            item(
                Field::Peers.name(),
                ItemStatus::Blocked,
                "no_peer",
                "没有可用的 TCP 或 UDP 对端；配置至少需要一个对端地址。",
            )
            .at(peer_origin),
        );
    } else {
        items.push(
            item(
                Field::Peers.name(),
                ItemStatus::Imported,
                "imported",
                "已导入。",
            )
            .at(peer_origin)
            .with_value(
                peers
                    .iter()
                    .map(|(server, port, transport)| {
                        if server.contains(':') {
                            format!("{transport}://[{server}]:{port}")
                        } else {
                            format!("{transport}://{server}:{port}")
                        }
                    })
                    .collect::<Vec<_>>()
                    .join(", "),
            ),
        );
    }

    // Advertised subnets.
    let subnet_origin = collected.origin(Field::Subnets);
    let mut advertise: Vec<String> = Vec::new();
    for entry in collected.list(Field::Subnets).unwrap_or(&[]) {
        if let Some(mapped) = &entry.mapped {
            items.push(
                item(
                    Field::Subnets.name(),
                    ItemStatus::Blocked,
                    "subnet_mapping",
                    "该节点把真实网段映射为另一网段通告，第一版无法自动迁移，需人工处理。",
                )
                .at(subnet_origin)
                .with_value(format!("{} -> {mapped}", entry.value)),
            );
            continue;
        }
        for key in &entry.confirm {
            items.push(
                item(
                    Field::Subnets.name(),
                    ItemStatus::NeedsConfirmation,
                    "subnet_option",
                    &format!("子网附加设置 {key} 未导入，请确认。"),
                )
                .at(subnet_origin)
                .with_value(entry.value.clone()),
            );
        }
        let overlaps_own = |cidr: &Cidr| {
            address
                .iter()
                .chain(address_v6.iter())
                .any(|own| own.overlaps(cidr))
        };
        match Cidr::parse(&entry.value) {
            Some(cidr) if is_intranet(&cidr) && overlaps_own(&cidr) => items.push(
                item(
                    Field::Subnets.name(),
                    ItemStatus::NeedsConfirmation,
                    "subnet_overlaps_virtual",
                    "该网段与本节点的虚拟网段重叠，不通告。",
                )
                .at(subnet_origin)
                .with_value(cidr.network_text()),
            ),
            Some(cidr) if is_intranet(&cidr) => {
                let network = cidr.network_text();
                if !advertise.contains(&network) {
                    advertise.push(network);
                }
            }
            Some(cidr) => items.push(
                item(
                    Field::Subnets.name(),
                    ItemStatus::NeedsConfirmation,
                    "public_subnet",
                    "非私有网段不通告。",
                )
                .at(subnet_origin)
                .with_value(cidr.network_text()),
            ),
            None => items.push(
                item(
                    Field::Subnets.name(),
                    ItemStatus::NeedsConfirmation,
                    "invalid_subnet",
                    "网段无法解析，未导入。",
                )
                .at(subnet_origin)
                .with_value(entry.value.clone()),
            ),
        }
    }
    if advertise.len() > MAX_SUBNETS {
        items.push(
            item(
                Field::Subnets.name(),
                ItemStatus::NeedsConfirmation,
                "too_many_subnets",
                &format!("通告网段超过 {MAX_SUBNETS} 个，只导入前 {MAX_SUBNETS} 个。"),
            )
            .at(subnet_origin),
        );
        advertise.truncate(MAX_SUBNETS);
    }
    if !advertise.is_empty() {
        items.push(
            item(
                Field::Subnets.name(),
                ItemStatus::Imported,
                "imported",
                "已导入。",
            )
            .at(subnet_origin)
            .with_value(advertise.join(", ")),
        );
    }

    // Routing and the settings config v1 does not hold yet.
    let latency = collected.bool(Field::LatencyFirst).unwrap_or(false);
    let policy = if latency { "latency" } else { "hops" };
    items.push(
        item(
            Field::LatencyFirst.name(),
            ItemStatus::Imported,
            "imported",
            "已导入。",
        )
        .at(collected.origin(Field::LatencyFirst))
        .with_value(policy),
    );
    if collected.bool(Field::RelayDisabled) == Some(true) {
        items.push(
            item(
                Field::RelayDisabled.name(),
                ItemStatus::NeedsConfirmation,
                "not_yet_supported",
                "原节点不替其他节点中转；当前配置格式暂无此项，导入后本节点会参与中转，请确认。",
            )
            .at(collected.origin(Field::RelayDisabled)),
        );
    }
    if let Some(routes) = collected.list(Field::SystemRoutes) {
        items.push(
            item(
                Field::SystemRoutes.name(),
                ItemStatus::NeedsConfirmation,
                "not_yet_supported",
                "原节点只把指定网段写入系统路由；当前配置格式暂无此项，导入后会安装全部已接受的路由，请确认。",
            )
            .at(collected.origin(Field::SystemRoutes))
            .with_value(
                routes
                    .iter()
                    .map(|route| route.value.clone())
                    .collect::<Vec<_>>()
                    .join(", "),
            ),
        );
    }
    if let Some(mtu) = collected.integer(Field::Mtu) {
        items.push(
            item(
                Field::Mtu.name(),
                if mtu == DEFAULT_MTU {
                    ItemStatus::Dropped
                } else {
                    ItemStatus::NeedsConfirmation
                },
                "not_yet_supported",
                "当前配置格式暂无 MTU 项，使用默认值 1380。",
            )
            .at(collected.origin(Field::Mtu))
            .with_value(mtu.to_string()),
        );
    }
    if let Some(hostname) = collected.text(Field::Hostname) {
        items.push(
            item(
                Field::Hostname.name(),
                ItemStatus::Dropped,
                "not_yet_supported",
                "当前配置格式暂无主机名项，使用系统主机名。",
            )
            .at(collected.origin(Field::Hostname))
            .with_value(hostname.to_string()),
        );
    }

    let blocked = items
        .iter()
        .any(|entry| entry.status == ItemStatus::Blocked);
    let network = (!name.trim().is_empty()).then(|| NetworkSummary {
        name: name.clone(),
        secure_mode,
        encrypted: encrypted || secure_mode,
        cipher: cipher.to_string(),
    });
    let config = match (blocked, address) {
        (false, Some(address)) => {
            let mut node = json!({
                "address": address.to_string(),
                "role": "full",
                "listen": listen_json,
            });
            if let Some(v6) = address_v6 {
                node["address_v6"] = json!(v6.to_string());
            }
            let mut config = json!({
                "config_version": CONFIG_VERSION,
                "network": {
                    "name": name,
                    "secret": secret,
                    "secure_mode": secure_mode,
                    "cipher": cipher,
                },
                "node": node,
                "peers": peers
                    .iter()
                    .map(|(server, port, transport)| {
                        json!({ "server": server, "port": port, "transport": transport })
                    })
                    .collect::<Vec<_>>(),
                "routing": { "policy": policy },
            });
            if !advertise.is_empty() {
                config["subnets"] = json!({ "advertise": advertise });
            }
            Some(config)
        }
        _ => None,
    };
    Converted {
        config,
        network,
        items,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host::fake::FakeHost;
    use crate::profile::tests::demo;
    use crate::source::{collect, Invocation};

    fn run(args: &[&str], options: &ImportOptions) -> Converted {
        let host = FakeHost::default();
        let profile = demo();
        let invocation = Invocation {
            args: args.iter().map(|arg| arg.to_string()).collect(),
            ..Invocation::default()
        };
        let collected = collect(&host, &profile, &invocation);
        assert_eq!(collected.len(), 1);
        convert(&profile, &collected[0], options)
    }

    /// The configuration passes the mesh module's own validation.
    fn assert_valid(config: &Value) {
        let parsed: outbound_mesh::MeshConfig =
            serde_json::from_value(config.clone()).expect("config v1 shape");
        let result = parsed.validate();
        assert!(result.is_ok(), "{:?}: {config}", result.err());
    }

    fn codes(converted: &Converted, status: ItemStatus) -> Vec<String> {
        converted
            .items
            .iter()
            .filter(|entry| entry.status == status)
            .map(|entry| entry.code.clone())
            .collect()
    }

    const BASE: &[&str] = &[
        "--net-name",
        "office",
        "--net-secret",
        "s3cret",
        "-i",
        "10.126.0.5/24",
        "-p",
        "tcp://peer.example:20010",
    ];

    #[test]
    fn converts_a_plain_node() {
        let mut args = BASE.to_vec();
        args.extend([
            "-l",
            "20010",
            "udp://10.0.0.1:9000",
            "-p",
            "udp://[fd00::2]:7",
            "ws://peer.example:80",
            "ws://only-ws.example",
            "-n",
            "192.168.10.7/24",
            "8.8.8.0/24",
            "--latency-first",
            "--ipv6",
            "fd00::5/64",
            "--cipher",
            "openssl-aes-256-gcm",
        ]);
        let converted = run(&args, &ImportOptions::default());
        assert!(codes(&converted, ItemStatus::Blocked).is_empty());
        let config = converted.config.clone().expect("config");
        assert_valid(&config);
        assert_eq!(
            config,
            json!({
                "config_version": 1,
                "network": {
                    "name": "office",
                    "secret": "s3cret",
                    "secure_mode": false,
                    "cipher": "aes-256-gcm",
                },
                "node": {
                    "address": "10.126.0.5/24",
                    "address_v6": "fd00::5/64",
                    "role": "full",
                    "listen": [
                        { "transport": "tcp", "port": 20010 },
                        { "transport": "udp", "port": 20010 },
                        { "transport": "udp", "port": 9000, "address": "10.0.0.1" },
                    ],
                },
                "peers": [
                    { "server": "peer.example", "port": 20010, "transport": "tcp" },
                    { "server": "fd00::2", "port": 7, "transport": "udp" },
                ],
                "subnets": { "advertise": ["192.168.10.0/24"] },
                "routing": { "policy": "latency" },
            })
        );
        let confirm = codes(&converted, ItemStatus::NeedsConfirmation);
        assert_eq!(confirm, vec!["peer_transport_unsupported", "public_subnet"]);
        let dropped = codes(&converted, ItemStatus::Dropped);
        assert_eq!(
            dropped,
            vec!["transport_unsupported", "peer_transport_unsupported"]
        );
        assert_eq!(
            converted.network,
            Some(NetworkSummary {
                name: "office".into(),
                secure_mode: false,
                encrypted: true,
                cipher: "aes-256-gcm".into(),
            })
        );
        // The secret never appears in the report.
        let report = serde_json::to_string(&converted.items).unwrap();
        assert!(!report.contains("s3cret"));
    }

    #[test]
    fn default_listeners_come_from_the_profile() {
        let converted = run(BASE, &ImportOptions::default());
        let config = converted.config.unwrap();
        assert_valid(&config);
        assert_eq!(
            config["node"]["listen"],
            json!([
                { "transport": "tcp", "port": 20010 },
                { "transport": "udp", "port": 20010 },
            ])
        );
        let mut args = BASE.to_vec();
        args.push("--no-listen");
        let converted = run(&args, &ImportOptions::default());
        assert_eq!(converted.config.unwrap()["node"]["listen"], json!([]));
        assert!(converted
            .items
            .iter()
            .any(|entry| entry.code == "no_listener"));
    }

    #[test]
    fn unencrypted_needs_an_explicit_choice() {
        let mut args = BASE.to_vec();
        args.push("--no-crypto");
        let refused = run(&args, &ImportOptions::default());
        assert!(refused.config.is_none());
        assert_eq!(
            codes(&refused, ItemStatus::Blocked),
            vec!["unencrypted_refused"]
        );

        let accepted = run(
            &args,
            &ImportOptions {
                allow_unencrypted: true,
                ..ImportOptions::default()
            },
        );
        let config = accepted.config.unwrap();
        assert_valid(&config);
        assert_eq!(config["network"]["cipher"], json!("none"));
        assert!(!accepted.network.unwrap().encrypted);

        let mut secure = args.clone();
        secure.push("--secure");
        let secure = run(&secure, &ImportOptions::default());
        assert_eq!(
            secure.config.unwrap()["network"]["secure_mode"],
            json!(true)
        );
        assert!(secure
            .items
            .iter()
            .any(|entry| entry.code == "encryption_switch_ignored"));
    }

    #[test]
    fn blocking_cases() {
        let cases: Vec<(Vec<&str>, &str)> = vec![
            (
                vec!["--net-secret", "s", "-i", "10.0.0.2/24", "-p", "tcp://a:1"],
                "missing_network_name",
            ),
            (
                vec!["--net-name", "n", "-i", "10.0.0.2/24", "-p", "tcp://a:1"],
                "missing_secret",
            ),
            (
                vec!["--net-name", "n", "--net-secret", "s", "-p", "tcp://a:1"],
                "missing_address",
            ),
            (
                vec![
                    "--net-name",
                    "n",
                    "--net-secret",
                    "s",
                    "-d",
                    "-p",
                    "tcp://a:1",
                ],
                "auto_address",
            ),
            (
                vec![
                    "--net-name",
                    "n",
                    "--net-secret",
                    "s",
                    "-i",
                    "8.8.8.8/24",
                    "-p",
                    "tcp://a:1",
                ],
                "address_not_intranet",
            ),
            (
                vec![
                    "--net-name",
                    "n",
                    "--net-secret",
                    "s",
                    "-i",
                    "10.0.0.0/24",
                    "-p",
                    "tcp://a:1",
                ],
                "address_is_network",
            ),
            (
                vec![
                    "--net-name",
                    "n",
                    "--net-secret",
                    "s",
                    "-i",
                    "10.0.0.255/24",
                    "-p",
                    "tcp://a:1",
                ],
                "address_is_broadcast",
            ),
            (
                vec!["--net-name", "n", "--net-secret", "s", "-i", "10.0.0.2/24"],
                "no_peer",
            ),
            (
                vec![
                    "--net-name",
                    "n",
                    "--net-secret",
                    "s",
                    "-i",
                    "10.0.0.2/24",
                    "-p",
                    "tcp://a:1",
                    "--cipher",
                    "xor",
                ],
                "weak_cipher",
            ),
            (
                vec![
                    "--net-name",
                    "n",
                    "--net-secret",
                    "s",
                    "-i",
                    "10.0.0.2/24",
                    "-p",
                    "tcp://a:1",
                    "-n",
                    "192.168.1.0/24->10.9.0.0/24",
                ],
                "subnet_mapping",
            ),
            (
                vec![
                    "--net-name",
                    "n",
                    "--net-secret",
                    "s",
                    "-i",
                    "10.0.0.2/24",
                    "-p",
                    "tcp://a:1",
                    "-w",
                    "user",
                ],
                "remote_config",
            ),
        ];
        for (args, code) in cases {
            let converted = run(&args, &ImportOptions::default());
            assert!(converted.config.is_none(), "{code}");
            assert_eq!(
                codes(&converted, ItemStatus::Blocked),
                vec![code.to_string()],
                "{args:?}"
            );
        }
    }

    #[test]
    fn auto_address_with_a_given_address() {
        let args = [
            "--net-name",
            "n",
            "--net-secret",
            "s",
            "-d",
            "-p",
            "tcp://a:1",
        ];
        let converted = run(
            &args,
            &ImportOptions {
                address: Some("10.126.0.9/24".into()),
                ..ImportOptions::default()
            },
        );
        assert_eq!(
            converted.config.unwrap()["node"]["address"],
            json!("10.126.0.9/24")
        );
    }

    #[test]
    fn prefix_is_assumed_and_pending_fields_are_reported() {
        let args = [
            "--net-name",
            "n",
            "--net-secret",
            "s",
            "-i",
            "10.0.0.2",
            "-p",
            "tcp://a:1",
            "--mtu",
            "1400",
            "--no-relay",
            "--routes",
            "10.5.0.0/16",
            "--hostname",
            "box",
            "--private-key",
            "k",
        ];
        let converted = run(&args, &ImportOptions::default());
        assert_eq!(
            converted.config.as_ref().unwrap()["node"]["address"],
            json!("10.0.0.2/24")
        );
        let confirm = codes(&converted, ItemStatus::NeedsConfirmation);
        for code in [
            "prefix_assumed",
            "static_key_not_imported",
            "not_yet_supported",
        ] {
            assert!(confirm.iter().any(|c| c == code), "{code}: {confirm:?}");
        }
        assert_eq!(
            confirm.iter().filter(|c| *c == "not_yet_supported").count(),
            3
        );
        assert!(codes(&converted, ItemStatus::Dropped).contains(&"not_yet_supported".to_string()));
    }

    #[test]
    fn subnets_overlapping_the_virtual_subnet_are_not_advertised() {
        let mut args = BASE.to_vec();
        args.extend(["-n", "10.126.0.0/16", "192.168.3.0/24"]);
        let converted = run(&args, &ImportOptions::default());
        assert_eq!(
            codes(&converted, ItemStatus::NeedsConfirmation),
            vec!["subnet_overlaps_virtual"]
        );
        let config = converted.config.unwrap();
        assert_valid(&config);
        assert_eq!(config["subnets"]["advertise"], json!(["192.168.3.0/24"]));
    }

    #[test]
    fn cipher_names() {
        assert_eq!(normalize_cipher("AES-GCM"), Ok("aes-gcm"));
        assert_eq!(normalize_cipher("openssl-chacha20"), Ok("chacha20"));
        assert_eq!(normalize_cipher("xor"), Err("weak_cipher"));
        assert_eq!(normalize_cipher("rot13"), Err("unknown_cipher"));
    }

    #[test]
    fn listener_shorthands() {
        let profile = demo();
        let expand = |text: &str| expand_listener(&profile, text);
        assert_eq!(
            expand("30000").unwrap(),
            vec![
                ("tcp".to_string(), 30000, None),
                ("udp".to_string(), 30000, None),
                ("ws".to_string(), 30001, None),
            ]
        );
        assert_eq!(
            expand("10.0.0.1").unwrap()[0],
            ("tcp".to_string(), 20010, Some("10.0.0.1".parse().unwrap()))
        );
        assert_eq!(expand("[::]:5").unwrap()[2], ("ws".to_string(), 6, None));
        assert_eq!(
            expand("udp:4000").unwrap(),
            vec![("udp".to_string(), 4000, None)]
        );
        assert_eq!(expand("ws").unwrap(), vec![("ws".to_string(), 20011, None)]);
        assert_eq!(
            expand("tcp://0.0.0.0").unwrap(),
            vec![("tcp".to_string(), 20010, None)]
        );
        assert!(expand("quic").is_err());
        assert!(expand("tcp://host.example:1").is_err());
    }
}
