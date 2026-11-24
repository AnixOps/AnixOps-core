//! Surge proxy-line subscriptions.

use super::*;

pub(crate) fn parse_surge_proxy_line_subscription(
    source_id: &str,
    content: &str,
) -> DomainResult<Option<SubscriptionDocument>> {
    let content = content.trim();
    if content.is_empty() {
        return Ok(None);
    }

    let mut saw_proxy_section = false;
    let mut in_proxy_section = false;
    let mut proxy_lines = Vec::new();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with("//") {
            continue;
        }

        if let Some(section) = parse_surge_section_header(line) {
            in_proxy_section = normalized_token(section).as_str() == "proxy";
            saw_proxy_section |= in_proxy_section;
            continue;
        }

        if in_proxy_section {
            proxy_lines.push(line.to_string());
        }
    }

    if !saw_proxy_section {
        return Ok(None);
    }
    if proxy_lines.is_empty() {
        return Err(domain_error(
            SUBSCRIPTION_SURGE_PROXY_LINE_INVALID_CODE,
            "surge proxy section cannot be empty",
        ));
    }

    let mut nodes = Vec::new();
    let mut skipped = SkippedEntries::new("surge proxy line");
    for (index, line) in proxy_lines.iter().enumerate() {
        if proxy_line_builtin_policy(line).is_some() {
            continue;
        }
        match parse_surge_proxy_line(line, source_id) {
            Ok(node) => nodes.push(node),
            Err(error) => {
                let (name, kind) = proxy_line_name_and_kind(line);
                skipped.skip(index, name, kind, error);
            }
        }
    }

    node_id::assign_subscription_node_ids(&mut nodes);
    skipped
        .finish(nodes, || {
            domain_error(
                SUBSCRIPTION_SURGE_PROXY_LINE_UNSUPPORTED_CODE,
                "surge proxy section must contain at least one supported proxy",
            )
        })
        .map(Some)
}

pub(crate) fn parse_surge_proxy_line(line: &str, source_id: &str) -> DomainResult<NodeDescriptor> {
    let (name, definition) = line.split_once('=').ok_or_else(|| {
        domain_error(
            SUBSCRIPTION_SURGE_PROXY_LINE_INVALID_CODE,
            "surge proxy line must contain name and definition",
        )
    })?;
    let name = required_trimmed(
        name.to_string(),
        SUBSCRIPTION_SURGE_PROXY_LINE_INVALID_CODE,
        "surge proxy name cannot be empty",
    )?;
    let parts = definition
        .split(',')
        .map(|part| part.trim().to_string())
        .collect::<Vec<_>>();
    if parts.len() < 3 || parts.iter().take(3).any(String::is_empty) {
        return Err(domain_error(
            SUBSCRIPTION_SURGE_PROXY_LINE_INVALID_CODE,
            "surge proxy line must contain type, server, and port",
        ));
    }

    let protocol_token = normalized_token(&parts[0]);
    let host = required_trimmed(
        parts[1].clone(),
        SUBSCRIPTION_SURGE_PROXY_LINE_INVALID_CODE,
        "surge proxy server cannot be empty",
    )?;
    let port = parts[2].parse::<i64>().map_err(|_| {
        domain_error(
            SUBSCRIPTION_SURGE_PROXY_LINE_INVALID_CODE,
            "surge proxy port must be a number",
        )
    })?;
    let port = parse_port(
        port,
        SUBSCRIPTION_SURGE_PROXY_LINE_INVALID_CODE,
        "surge proxy port must be between 1 and 65535",
    )?;
    // HTTP and SOCKS5 lines may give the user and password positionally.
    let options = if plain_proxy_kind(&protocol_token).is_some() {
        BTreeMap::new()
    } else {
        collect_surge_proxy_options(&parts[3..])?
    };

    let (protocol, protocol_tag, mut metadata) = match protocol_token.as_str() {
        "http" | "https" | "socks5" | "socks" | "socks5_tls" => proxy_line_plain_proxy(
            &protocol_token,
            &parts[3..],
            &host,
            SUBSCRIPTION_SURGE_PROXY_LINE_INVALID_CODE,
        )?,
        "ss" | "shadowsocks" => {
            let method = required_surge_proxy_option(
                &options,
                &["encrypt_method", "method"],
                "surge shadowsocks encrypt-method cannot be empty",
            )?;
            let password = required_surge_proxy_option(
                &options,
                &["password"],
                "surge shadowsocks password cannot be empty",
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
            // simple-obfs (`obfs=http|tls`) or ShadowTLS
            // (`shadow-tls-password=`).
            let plugin = match options
                .get("obfs")
                .map(String::as_str)
                .map(obfs_plugin_name)
            {
                Some(name) if !name.is_empty() => Some(name),
                _ => options
                    .contains_key("shadow_tls_password")
                    .then(|| "shadow-tls".to_string()),
            };
            metadata.extend(shadowsocks_plugin_entry(plugin));
            (Protocol::Shadowsocks, "ss", metadata)
        }
        "trojan" => {
            let password = required_surge_proxy_option(
                &options,
                &["password"],
                "surge trojan password cannot be empty",
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
        "vmess" => {
            let uuid = required_surge_proxy_option(
                &options,
                &["username", "uuid"],
                "surge vmess username cannot be empty",
            )?;
            let mut metadata = vec![MetadataEntry {
                key: NODE_METADATA_VMESS_UUID.to_string(),
                value: uuid,
            }];
            metadata.extend(proxy_vmess_security(options.get("encrypt_method").cloned()));
            (Protocol::Vmess, "vmess", metadata)
        }
        "snell" => {
            let psk =
                required_surge_proxy_option(&options, &["psk"], "surge snell psk cannot be empty")?;
            let option = |key: &str| options.get(key).cloned();
            (
                Protocol::Snell,
                "snell",
                snell_metadata(SnellFields {
                    psk,
                    version: option("version"),
                    mode: option("mode"),
                    obfs: option("obfs"),
                    obfs_host: option("obfs_host"),
                    obfs_uri: option("obfs_uri"),
                    reuse: option("reuse"),
                    user_key: option("userkey"),
                }),
            )
        }
        _ => {
            return Err(domain_error(
                SUBSCRIPTION_SURGE_PROXY_LINE_UNSUPPORTED_CODE,
                "surge proxy type must be ss, trojan, vmess, snell, http, https, socks5, or socks5-tls for catalog import",
            ));
        }
    };
    if matches!(protocol, Protocol::Trojan | Protocol::Vmess) {
        metadata.extend(proxy_line_pin_metadata(
            options.get("server_cert_fingerprint_sha256").cloned(),
            None,
        ));
        surge_stream_options(&options)?.append_to(
            &mut metadata,
            &host,
            protocol == Protocol::Trojan,
            SUBSCRIPTION_SURGE_PROXY_LINE_INVALID_CODE,
            "surge proxy",
        )?;
    }

    let name_id = sanitize_identifier(&name);
    let name_id = if name_id.is_empty() {
        "node".to_string()
    } else {
        name_id
    };
    let id = format!("surge-{protocol_tag}-{name_id}");
    metadata.push(MetadataEntry {
        key: NODE_METADATA_SOURCE_FORMAT.to_string(),
        value: "surge-proxy-line".to_string(),
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
            "surge-proxy-line".to_string(),
            protocol_tag.to_string(),
        ],
        metadata,
    })
}

/// The share-link settings of a Surge vmess or trojan line: `tls`, `sni`,
/// `skip-cert-verify`, and `ws` with `ws-path` and the `Host` of
/// `ws-headers`. `sni=off` (no SNI) is not carried; the node then sends the
/// server name.
pub(crate) fn surge_stream_options(
    options: &BTreeMap<String, String>,
) -> DomainResult<ProxyStreamOptions> {
    let code = SUBSCRIPTION_SURGE_PROXY_LINE_INVALID_CODE;
    let mut stream = ProxyStreamOptions::default();
    if let Some(tls) = proxy_line_boolean(options.get("tls"), code, "surge tls")? {
        let security = if tls { "tls" } else { "none" };
        stream.set("security", Some(security.to_string()));
    }
    stream.set(
        "sni",
        options
            .get("sni")
            .filter(|sni| !sni.trim().eq_ignore_ascii_case("off"))
            .cloned(),
    );
    if let Some(insecure) = proxy_line_boolean(
        options.get("skip_cert_verify"),
        code,
        "surge skip-cert-verify",
    )? {
        stream.set("insecure", Some(insecure.to_string()));
    }
    if proxy_line_boolean(options.get("ws"), code, "surge ws")? == Some(true) {
        stream.set_transport("ws");
        stream.set("path", options.get("ws_path").cloned());
        stream.set(
            "host",
            options
                .get("ws_headers")
                .map(String::as_str)
                .and_then(surge_ws_host_header),
        );
    }
    Ok(stream)
}

/// Snell node options shared by the Surge and Clash parsers.
pub(crate) struct SnellFields {
    pub(crate) psk: String,
    pub(crate) version: Option<String>,
    pub(crate) mode: Option<String>,
    pub(crate) obfs: Option<String>,
    pub(crate) obfs_host: Option<String>,
    pub(crate) obfs_uri: Option<String>,
    pub(crate) reuse: Option<String>,
    pub(crate) user_key: Option<String>,
}

pub(crate) fn snell_metadata(fields: SnellFields) -> Metadata {
    let mut metadata = vec![MetadataEntry {
        key: NODE_METADATA_SNELL_PSK.to_string(),
        value: fields.psk,
    }];
    for (key, value) in [
        (NODE_METADATA_SNELL_VERSION, fields.version),
        (
            NODE_METADATA_SNELL_MODE,
            fields.mode.map(|v| v.to_ascii_lowercase()),
        ),
        (
            NODE_METADATA_SNELL_OBFS,
            fields.obfs.map(|v| v.to_ascii_lowercase()),
        ),
        (NODE_METADATA_SNELL_OBFS_HOST, fields.obfs_host),
        (NODE_METADATA_SNELL_OBFS_URI, fields.obfs_uri),
        (
            NODE_METADATA_SNELL_REUSE,
            fields.reuse.map(|v| v.to_ascii_lowercase()),
        ),
        (NODE_METADATA_SNELL_USER_KEY, fields.user_key),
    ] {
        if let Some(value) = value {
            metadata.push(MetadataEntry {
                key: key.to_string(),
                value,
            });
        }
    }
    metadata
}

pub(crate) fn parse_surge_section_header(line: &str) -> Option<&str> {
    line.strip_prefix('[')?.strip_suffix(']')
}

pub(crate) fn collect_surge_proxy_options(
    parts: &[String],
) -> DomainResult<BTreeMap<String, String>> {
    let mut options = BTreeMap::new();
    for part in parts {
        if part.is_empty() {
            continue;
        }
        let Some((key, value)) = part.split_once('=') else {
            return Err(domain_error(
                SUBSCRIPTION_SURGE_PROXY_LINE_INVALID_CODE,
                "surge proxy option must use key=value",
            ));
        };
        let key = normalized_token(key);
        let value = required_trimmed(
            value.to_string(),
            SUBSCRIPTION_SURGE_PROXY_LINE_INVALID_CODE,
            "surge proxy option value cannot be empty",
        )?;
        if !key.is_empty() {
            options.insert(key, value);
        }
    }
    Ok(options)
}

pub(crate) fn required_surge_proxy_option(
    options: &BTreeMap<String, String>,
    keys: &[&str],
    message: &'static str,
) -> DomainResult<String> {
    for key in keys {
        if let Some(value) = options.get(*key) {
            return required_trimmed(
                value.clone(),
                SUBSCRIPTION_SURGE_PROXY_LINE_INVALID_CODE,
                message,
            );
        }
    }

    Err(domain_error(
        SUBSCRIPTION_SURGE_PROXY_LINE_INVALID_CODE,
        message,
    ))
}
