//! Quantumult X proxy-line subscriptions.

use super::*;

pub(crate) fn parse_quantumult_x_proxy_line_subscription(
    source_id: &str,
    content: &str,
) -> DomainResult<Option<SubscriptionDocument>> {
    let content = content.trim();
    if content.is_empty() {
        return Ok(None);
    }

    let mut saw_server_local_section = false;
    let mut in_server_local_section = false;
    let mut proxy_lines = Vec::new();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty()
            || line.starts_with('#')
            || line.starts_with("//")
            || line.starts_with(';')
        {
            continue;
        }

        if let Some(section) = parse_surge_section_header(line) {
            in_server_local_section = normalized_token(section).as_str() == "server_local";
            saw_server_local_section |= in_server_local_section;
            continue;
        }

        if in_server_local_section {
            proxy_lines.push(line.to_string());
        }
    }

    if !saw_server_local_section {
        return Ok(None);
    }
    if proxy_lines.is_empty() {
        return Err(domain_error(
            SUBSCRIPTION_QUANTUMULT_X_PROXY_LINE_INVALID_CODE,
            "quantumult x server_local section cannot be empty",
        ));
    }

    let mut nodes = Vec::new();
    let mut skipped = SkippedEntries::new("quantumult x server_local line");
    for (index, line) in proxy_lines.iter().enumerate() {
        let kind = line.split_once('=').map(|(kind, _)| kind.trim());
        if kind.and_then(builtin_policy).is_some() {
            continue;
        }
        match parse_quantumult_x_proxy_line(line, source_id) {
            Ok(node) => nodes.push(node),
            Err(error) => {
                let tag = quantumult_x_proxy_line_tag(line);
                skipped.skip(index, tag.as_deref(), kind, error);
            }
        }
    }

    node_id::assign_subscription_node_ids(&mut nodes);
    skipped
        .finish(nodes, || {
            domain_error(
                SUBSCRIPTION_QUANTUMULT_X_PROXY_LINE_UNSUPPORTED_CODE,
                "quantumult x server_local section must contain at least one supported proxy",
            )
        })
        .map(Some)
}

/// The `tag=` of a Quantumult X server line, for naming it in a warning.
pub(crate) fn quantumult_x_proxy_line_tag(line: &str) -> Option<String> {
    let (_, definition) = line.split_once('=')?;
    definition.split(',').find_map(|part| {
        let (key, value) = part.split_once('=')?;
        (normalized_token(key) == "tag").then(|| strip_quantumult_x_quotes(value.to_string()))
    })
}

pub(crate) fn parse_quantumult_x_proxy_line(
    line: &str,
    source_id: &str,
) -> DomainResult<NodeDescriptor> {
    let (protocol, definition) = line.split_once('=').ok_or_else(|| {
        domain_error(
            SUBSCRIPTION_QUANTUMULT_X_PROXY_LINE_INVALID_CODE,
            "quantumult x proxy line must contain protocol and definition",
        )
    })?;
    let protocol_token = normalized_token(protocol);
    let parts = definition
        .split(',')
        .map(|part| part.trim().to_string())
        .collect::<Vec<_>>();
    let endpoint = parts.first().cloned().unwrap_or_default();
    let endpoint = required_trimmed(
        endpoint,
        SUBSCRIPTION_QUANTUMULT_X_PROXY_LINE_INVALID_CODE,
        "quantumult x proxy endpoint cannot be empty",
    )?;
    let (host, port) = parse_host_port_for(
        &endpoint,
        SUBSCRIPTION_QUANTUMULT_X_PROXY_LINE_INVALID_CODE,
        "quantumult x proxy",
    )?;
    let options = collect_quantumult_x_proxy_options(&parts[1..])?;

    let (protocol, protocol_tag, mut metadata) = match protocol_token.as_str() {
        "http" | "https" | "socks5" | "socks" => {
            let (protocol, tag, tls) = plain_proxy_kind(&protocol_token).ok_or_else(|| {
                domain_error(
                    SUBSCRIPTION_QUANTUMULT_X_PROXY_LINE_UNSUPPORTED_CODE,
                    "quantumult x proxy type is not http or socks5",
                )
            })?;
            (
                protocol,
                tag,
                quantumult_x_plain_proxy_metadata(&options, tls, &host)?,
            )
        }
        "ss" | "shadowsocks" => {
            let method = required_quantumult_x_proxy_option(
                &options,
                &["method"],
                "quantumult x shadowsocks method cannot be empty",
            )?;
            let password = required_quantumult_x_proxy_option(
                &options,
                &["password"],
                "quantumult x shadowsocks password cannot be empty",
            )?;
            let mut metadata = vec![
                MetadataEntry {
                    key: NODE_METADATA_SHADOWSOCKS_METHOD.to_string(),
                    value: method,
                },
                MetadataEntry {
                    key: NODE_METADATA_SHADOWSOCKS_PASSWORD.to_string(),
                    value: password,
                },
            ];
            metadata.extend(shadowsocks_plugin_entry(
                options
                    .get("obfs")
                    .map(String::as_str)
                    .map(obfs_plugin_name),
            ));
            (Protocol::Shadowsocks, "ss", metadata)
        }
        "trojan" => {
            let password = required_quantumult_x_proxy_option(
                &options,
                &["password"],
                "quantumult x trojan password cannot be empty",
            )?;
            (
                Protocol::Trojan,
                "trojan",
                vec![MetadataEntry {
                    key: NODE_METADATA_TROJAN_PASSWORD.to_string(),
                    value: password,
                }],
            )
        }
        "vless" => {
            let uuid = required_quantumult_x_proxy_option(
                &options,
                &["password", "uuid"],
                "quantumult x vless uuid cannot be empty",
            )?;
            let mut metadata = vec![MetadataEntry {
                key: NODE_METADATA_VLESS_UUID.to_string(),
                value: uuid,
            }];
            if let Some(flow) = optional_quantumult_x_proxy_option(&options, &["vless_flow"]) {
                metadata.push(MetadataEntry {
                    key: NODE_METADATA_VLESS_FLOW.to_string(),
                    value: flow,
                });
            }
            (Protocol::Vless, "vless", metadata)
        }
        "vmess" => {
            let uuid = required_quantumult_x_proxy_option(
                &options,
                &["password", "uuid", "username"],
                "quantumult x vmess uuid cannot be empty",
            )?;
            let mut metadata = vec![MetadataEntry {
                key: NODE_METADATA_VMESS_UUID.to_string(),
                value: uuid,
            }];
            metadata.extend(proxy_vmess_security(optional_quantumult_x_proxy_option(
                &options,
                &["method"],
            )));
            (Protocol::Vmess, "vmess", metadata)
        }
        _ => {
            return Err(domain_error(
                SUBSCRIPTION_QUANTUMULT_X_PROXY_LINE_UNSUPPORTED_CODE,
                "quantumult x proxy type must be shadowsocks, trojan, vless, vmess, http, or socks5 for catalog import",
            ));
        }
    };
    if matches!(
        protocol,
        Protocol::Trojan | Protocol::Vless | Protocol::Vmess
    ) {
        metadata.extend(proxy_line_pin_metadata(
            optional_quantumult_x_proxy_option(&options, &["tls_cert_sha256"]),
            optional_quantumult_x_proxy_option(&options, &["tls_pubkey_sha256"]),
        ));
        quantumult_x_stream_options(&options)?.append_to(
            &mut metadata,
            &host,
            protocol == Protocol::Trojan,
            SUBSCRIPTION_QUANTUMULT_X_PROXY_LINE_INVALID_CODE,
            "quantumult x proxy",
        )?;
    }

    let name = optional_quantumult_x_proxy_option(&options, &["tag"]).unwrap_or_else(|| {
        let host_id = sanitize_identifier(&host);
        let host_id = if host_id.is_empty() {
            "host".to_string()
        } else {
            host_id
        };
        format!("quantumult-x-{protocol_tag}-{host_id}-{port}")
    });
    let name_id = sanitize_identifier(&name);
    let name_id = if name_id.is_empty() {
        "node".to_string()
    } else {
        name_id
    };
    let id = format!("quantumult-x-{protocol_tag}-{name_id}");
    metadata.push(MetadataEntry {
        key: NODE_METADATA_SOURCE_FORMAT.to_string(),
        value: "quantumult-x-proxy-line".to_string(),
    });
    metadata.push(MetadataEntry {
        key: "subscription.source_id".to_string(),
        value: source_id.to_string(),
    });

    Ok(NodeDescriptor {
        id,
        name,
        protocol,
        endpoint: Endpoint { host, port },
        tags: vec![
            "subscription".to_string(),
            "quantumult-x-proxy-line".to_string(),
            protocol_tag.to_string(),
        ],
        metadata,
    })
}

/// The metadata of a Quantumult X `http=` or `socks5=` line from its
/// options: `username`, `password`, `over-tls`, `tls-host`,
/// `tls-verification`, `tls-cert-sha256` and `tls-pubkey-sha256`.
pub(crate) fn quantumult_x_plain_proxy_metadata(
    options: &BTreeMap<String, String>,
    tls: bool,
    host: &str,
) -> DomainResult<Metadata> {
    let code = SUBSCRIPTION_QUANTUMULT_X_PROXY_LINE_INVALID_CODE;
    let tls =
        proxy_line_boolean(options.get("over_tls"), code, "quantumult x over-tls")?.unwrap_or(tls);
    let verify = proxy_line_boolean(
        options.get("tls_verification"),
        code,
        "quantumult x tls-verification",
    )?;
    let option = |key: &str| optional_quantumult_x_proxy_option(options, &[key]);
    Ok(plain_proxy_metadata(
        PlainProxyFields {
            username: option("username"),
            password: option("password"),
            tls,
            server_name: option("tls_host"),
            insecure: verify == Some(false),
            certificate_sha256: option("tls_cert_sha256"),
            public_key_sha256: option("tls_pubkey_sha256"),
            unsupported: None,
        },
        host,
    ))
}

/// The share-link settings of a Quantumult X vmess, vless or trojan line:
/// `obfs=over-tls|wss|ws` with `obfs-host` and `obfs-uri`, `over-tls`,
/// `tls-host`, `tls-verification`, `reality-base64-pubkey` and
/// `reality-hex-shortid`. `obfs=http` (HTTP/1.1 header obfuscation) and
/// other `obfs` values make the node unsupported.
pub(crate) fn quantumult_x_stream_options(
    options: &BTreeMap<String, String>,
) -> DomainResult<ProxyStreamOptions> {
    let code = SUBSCRIPTION_QUANTUMULT_X_PROXY_LINE_INVALID_CODE;
    let mut stream = ProxyStreamOptions::default();
    let mut tls = proxy_line_boolean(options.get("over_tls"), code, "quantumult x over-tls")?;
    match options
        .get("obfs")
        .map(String::as_str)
        .map(normalized_token)
        .as_deref()
    {
        None | Some("" | "none") => {}
        Some("over_tls") => tls = Some(true),
        Some("wss") => {
            tls = Some(true);
            stream.set_transport("ws");
        }
        Some(other) => stream.set_transport(other),
    }
    let obfs_host = options.get("obfs_host").cloned();
    if stream.query.get("type").map(String::as_str) == Some("ws") {
        stream.set("path", options.get("obfs_uri").cloned());
        stream.set("host", obfs_host.clone());
    }
    let reality = options.get("reality_base64_pubkey").cloned();
    if reality.is_some() {
        stream.set("security", Some("reality".to_string()));
        stream.set("pbk", reality);
        stream.set("sid", options.get("reality_hex_shortid").cloned());
    } else if let Some(tls) = tls {
        let security = if tls { "tls" } else { "none" };
        stream.set("security", Some(security.to_string()));
    }
    // `tls-host` names the server; without it the `obfs-host` of a TLS
    // `obfs` does.
    stream.set("sni", options.get("tls_host").cloned());
    if matches!(
        stream.query.get("security").map(String::as_str),
        Some("tls" | "reality")
    ) {
        stream.set_default("sni", obfs_host);
    }
    if let Some(verify) = proxy_line_boolean(
        options.get("tls_verification"),
        code,
        "quantumult x tls-verification",
    )? {
        stream.set("insecure", Some((!verify).to_string()));
    }
    Ok(stream)
}

/// The SIP003 plugin a Shadowsocks `obfs=` option stands for: simple-obfs
/// for `http` and `tls`, v2ray-plugin for `ws` and `wss`. `none` is no
/// plugin.
pub(crate) fn obfs_plugin_name(obfs: &str) -> String {
    match normalized_token(obfs).as_str() {
        "" | "none" => String::new(),
        "http" | "tls" => "obfs-local".to_string(),
        "ws" | "wss" | "websocket" => "v2ray-plugin".to_string(),
        other => other.to_string(),
    }
}

pub(crate) fn collect_quantumult_x_proxy_options(
    parts: &[String],
) -> DomainResult<BTreeMap<String, String>> {
    let mut options = BTreeMap::new();
    for part in parts {
        if part.is_empty() {
            continue;
        }
        let Some((key, value)) = part.split_once('=') else {
            return Err(domain_error(
                SUBSCRIPTION_QUANTUMULT_X_PROXY_LINE_INVALID_CODE,
                "quantumult x proxy option must use key=value",
            ));
        };
        let key = normalized_token(key);
        let value = strip_quantumult_x_quotes(value.to_string());
        let value = required_trimmed(
            value,
            SUBSCRIPTION_QUANTUMULT_X_PROXY_LINE_INVALID_CODE,
            "quantumult x proxy option value cannot be empty",
        )?;
        if !key.is_empty() {
            options.insert(key, value);
        }
    }
    Ok(options)
}

pub(crate) fn optional_quantumult_x_proxy_option(
    options: &BTreeMap<String, String>,
    keys: &[&str],
) -> Option<String> {
    for key in keys {
        if let Some(value) = options.get(*key) {
            return Some(value.clone());
        }
    }
    None
}

pub(crate) fn required_quantumult_x_proxy_option(
    options: &BTreeMap<String, String>,
    keys: &[&str],
    message: &'static str,
) -> DomainResult<String> {
    optional_quantumult_x_proxy_option(options, keys)
        .ok_or_else(|| domain_error(SUBSCRIPTION_QUANTUMULT_X_PROXY_LINE_INVALID_CODE, message))
}

pub(crate) fn strip_quantumult_x_quotes(value: String) -> String {
    let value = value.trim();
    if value.len() >= 2 && value.starts_with('"') && value.ends_with('"') {
        value[1..value.len() - 1].to_string()
    } else {
        value.to_string()
    }
}
