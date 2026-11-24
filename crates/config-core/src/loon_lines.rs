//! Loon proxy-line subscriptions.

use super::*;

pub(crate) fn parse_loon_proxy_line_subscription(
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
            SUBSCRIPTION_LOON_PROXY_LINE_INVALID_CODE,
            "loon proxy section cannot be empty",
        ));
    }

    let mut nodes = Vec::new();
    let mut skipped = SkippedEntries::new("loon proxy line");
    // Lines in another style (Surge's `key=value` options) or of a type the
    // Loon reader does not know: when no line reads as a Loon node, the
    // section is not Loon's and the Surge reader gets it.
    let mut other_style = Vec::new();
    for (index, line) in proxy_lines.iter().enumerate() {
        if proxy_line_builtin_policy(line).is_some() {
            continue;
        }
        match parse_loon_proxy_line(line, source_id) {
            Ok(Some(node)) => nodes.push(node),
            Ok(None) => other_style.push(index),
            Err(error) => {
                let (name, kind) = proxy_line_name_and_kind(line);
                skipped.skip(index, name, kind, error);
            }
        }
    }

    // HTTP and SOCKS5 lines read the same in Surge (`http, host, port, user,
    // pass`); they alone do not make the section Loon's, so a Surge section
    // with such lines still goes to the Surge reader, which reads them too.
    if !nodes.is_empty()
        && nodes
            .iter()
            .all(|node| matches!(node.protocol, Protocol::Http | Protocol::Socks))
    {
        return Ok(None);
    }
    if nodes.is_empty() {
        // Every line was in Loon's positional style yet none could be
        // imported: report the first one's error rather than letting the
        // Surge reader misread the section.
        if other_style.is_empty() {
            if let Some(error) = skipped.first_error {
                return Err(error);
            }
        }
        return Ok(None);
    }
    for index in other_style {
        let (name, kind) = proxy_line_name_and_kind(&proxy_lines[index]);
        skipped.skip(
            index,
            name,
            kind,
            domain_error(
                SUBSCRIPTION_LOON_PROXY_LINE_UNSUPPORTED_CODE,
                "loon proxy line type or option style is not supported for catalog import",
            ),
        );
    }

    node_id::assign_subscription_node_ids(&mut nodes);
    skipped
        .finish(nodes, || {
            domain_error(
                SUBSCRIPTION_LOON_PROXY_LINE_UNSUPPORTED_CODE,
                "loon proxy section must contain at least one supported proxy",
            )
        })
        .map(Some)
}

/// The name and type of a Surge or Loon `Name = type, server, port, ...`
/// line, for naming it in a warning.
pub(crate) fn proxy_line_name_and_kind(line: &str) -> (Option<&str>, Option<&str>) {
    match line.split_once('=') {
        Some((name, definition)) => (
            Some(name.trim()),
            definition.split(',').next().map(str::trim),
        ),
        None => (None, None),
    }
}

pub(crate) fn parse_loon_proxy_line(
    line: &str,
    source_id: &str,
) -> DomainResult<Option<NodeDescriptor>> {
    let Some((name, definition)) = line.split_once('=') else {
        return Ok(None);
    };
    let name = required_trimmed(
        name.to_string(),
        SUBSCRIPTION_LOON_PROXY_LINE_INVALID_CODE,
        "loon proxy name cannot be empty",
    )?;
    let parts = definition
        .split(',')
        .map(|part| part.trim().to_string())
        .collect::<Vec<_>>();
    if parts.len() < 3 || parts.iter().take(3).any(String::is_empty) {
        return Err(domain_error(
            SUBSCRIPTION_LOON_PROXY_LINE_INVALID_CODE,
            "loon proxy line must contain type, server, and port",
        ));
    }

    let protocol_token = normalized_token(&parts[0]);
    let host = required_trimmed(
        parts[1].clone(),
        SUBSCRIPTION_LOON_PROXY_LINE_INVALID_CODE,
        "loon proxy server cannot be empty",
    )?;
    let port = parts[2].parse::<i64>().map_err(|_| {
        domain_error(
            SUBSCRIPTION_LOON_PROXY_LINE_INVALID_CODE,
            "loon proxy port must be a number",
        )
    })?;
    let port = parse_port(
        port,
        SUBSCRIPTION_LOON_PROXY_LINE_INVALID_CODE,
        "loon proxy port must be between 1 and 65535",
    )?;

    let (protocol, protocol_tag, mut metadata) = match protocol_token.as_str() {
        "ss" | "shadowsocks" => {
            if is_surge_style_proxy_definition(&parts) {
                return Ok(None);
            }
            let method =
                required_loon_proxy_part(&parts, 3, "loon shadowsocks method cannot be empty")?;
            let password =
                required_loon_proxy_part(&parts, 4, "loon shadowsocks password cannot be empty")?;
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
            metadata.extend(shadowsocks_plugin_entry(loon_shadowsocks_plugin(
                parts.get(5..).unwrap_or_default(),
            )));
            (Protocol::Shadowsocks, "ss", metadata)
        }
        "trojan" => {
            if is_surge_style_proxy_definition(&parts) {
                return Ok(None);
            }
            let password =
                required_loon_proxy_part(&parts, 3, "loon trojan password cannot be empty")?;
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
            if is_surge_style_proxy_definition(&parts) {
                return Ok(None);
            }
            let uuid = required_loon_proxy_part(&parts, 3, "loon vless uuid cannot be empty")?;
            let mut metadata = vec![MetadataEntry {
                key: NODE_METADATA_VLESS_UUID.to_string(),
                value: uuid,
            }];
            if let Some(flow) = loon_proxy_option(parts.get(4..).unwrap_or_default(), "flow") {
                metadata.push(MetadataEntry {
                    key: NODE_METADATA_VLESS_FLOW.to_string(),
                    value: flow,
                });
            }
            (Protocol::Vless, "vless", metadata)
        }
        "vmess" => {
            if is_surge_style_proxy_definition(&parts) {
                return Ok(None);
            }
            let uuid = required_loon_proxy_part(&parts, 4, "loon vmess uuid cannot be empty")?;
            let mut metadata = vec![MetadataEntry {
                key: NODE_METADATA_VMESS_UUID.to_string(),
                value: uuid,
            }];
            // The cipher comes before the uuid.
            metadata.extend(proxy_vmess_security(
                parts.get(3).cloned().map(strip_loon_quotes),
            ));
            if let Some(alter_id) = loon_proxy_option(parts.get(5..).unwrap_or_default(), "alterid")
            {
                metadata.push(MetadataEntry {
                    key: NODE_METADATA_VMESS_ALTER_ID.to_string(),
                    value: alter_id,
                });
            }
            (Protocol::Vmess, "vmess", metadata)
        }
        "http" | "https" | "socks5" | "socks" | "socks5_tls" => proxy_line_plain_proxy(
            &protocol_token,
            parts.get(3..).unwrap_or_default(),
            &host,
            SUBSCRIPTION_LOON_PROXY_LINE_INVALID_CODE,
        )?,
        "direct" | "reject" | "ssr" | "shadowsocksr" | "hysteria" | "hysteria2" | "tuic"
        | "wireguard" => {
            return Err(domain_error(
                SUBSCRIPTION_LOON_PROXY_LINE_UNSUPPORTED_CODE,
                "loon proxy type must be shadowsocks, trojan, vless, vmess, http, https, or socks5 for catalog import",
            ));
        }
        _ => return Ok(None),
    };
    // Options follow the credentials: the password or uuid, and for vmess
    // the cipher before the uuid.
    let first_option = match protocol {
        Protocol::Trojan | Protocol::Vless => Some(4),
        Protocol::Vmess => Some(5),
        _ => None,
    };
    if let Some(options) = first_option.and_then(|index| parts.get(index..)) {
        metadata.extend(proxy_line_pin_metadata(
            loon_proxy_option(options, "tls_cert_sha256"),
            loon_proxy_option(options, "tls_pubkey_sha256"),
        ));
        loon_stream_options(options)?.append_to(
            &mut metadata,
            &host,
            protocol == Protocol::Trojan,
            SUBSCRIPTION_LOON_PROXY_LINE_INVALID_CODE,
            "loon proxy",
        )?;
    }

    let name_id = sanitize_identifier(&name);
    let name_id = if name_id.is_empty() {
        "node".to_string()
    } else {
        name_id
    };
    let id = format!("loon-{protocol_tag}-{name_id}");
    metadata.push(MetadataEntry {
        key: NODE_METADATA_SOURCE_FORMAT.to_string(),
        value: "loon-proxy-line".to_string(),
    });
    metadata.push(MetadataEntry {
        key: "subscription.source_id".to_string(),
        value: source_id.to_string(),
    });

    Ok(Some(NodeDescriptor {
        id,
        name,
        protocol,
        endpoint: Endpoint { host, port },
        tags: vec![
            "subscription".to_string(),
            "loon-proxy-line".to_string(),
            protocol_tag.to_string(),
        ],
        metadata,
    }))
}

/// The value of the `key=value` option named `key` (normalized, as
/// [`normalized_token`] spells it) among a Loon proxy line's options.
pub(crate) fn loon_proxy_option(options: &[String], key: &str) -> Option<String> {
    options.iter().find_map(|option| {
        let (name, value) = option.split_once('=')?;
        (normalized_token(name) == key)
            .then(|| strip_loon_quotes(value.to_string()))
            .filter(|value| !value.is_empty())
    })
}

/// The share-link settings of a Loon vmess, vless or trojan line from its
/// options: `over-tls`, `tls-name`/`sni`, `skip-cert-verify`, `alpn`,
/// `transport` with `path` and `host` (ws) or `grpc-service-name` (grpc),
/// and REALITY's `public-key` and `short-id`. `transport=http` (HTTP/1.1
/// header obfuscation) and unknown transports make the node unsupported.
pub(crate) fn loon_stream_options(options: &[String]) -> DomainResult<ProxyStreamOptions> {
    let code = SUBSCRIPTION_LOON_PROXY_LINE_INVALID_CODE;
    let option = |key: &str| loon_proxy_option(options, key);
    let mut stream = ProxyStreamOptions::default();
    let public_key = option("public_key");
    if public_key.is_some() {
        stream.set("security", Some("reality".to_string()));
        stream.set("pbk", public_key);
        stream.set("sid", option("short_id"));
    } else if let Some(tls) =
        proxy_line_boolean(option("over_tls").as_ref(), code, "loon over-tls")?
    {
        let security = if tls { "tls" } else { "none" };
        stream.set("security", Some(security.to_string()));
    }
    stream.set("sni", option("sni").or_else(|| option("tls_name")));
    if let Some(insecure) = proxy_line_boolean(
        option("skip_cert_verify").as_ref(),
        code,
        "loon skip-cert-verify",
    )? {
        stream.set("insecure", Some(insecure.to_string()));
    }
    stream.set("alpn", option("alpn"));
    if let Some(transport) = option("transport") {
        stream.set_transport(&transport);
        match stream.query.get("type").map(String::as_str) {
            Some("ws") => {
                stream.set("path", option("path"));
                stream.set("host", option("host"));
            }
            Some("grpc") => stream.set(
                "servicename",
                option("grpc_service_name").or_else(|| option("service_name")),
            ),
            _ => {}
        }
    }
    Ok(stream)
}

/// The SIP003 plugin of a Loon Shadowsocks line from the fields after its
/// password: `obfs-name=http|tls` (or `obfs=`), a positional `http`/`tls`
/// as older lines write it, or ShadowTLS (`shadow-tls-password=`).
pub(crate) fn loon_shadowsocks_plugin(options: &[String]) -> Option<String> {
    if let Some(obfs) =
        loon_proxy_option(options, "obfs_name").or_else(|| loon_proxy_option(options, "obfs"))
    {
        return Some(obfs_plugin_name(&obfs));
    }
    if loon_proxy_option(options, "shadow_tls_password").is_some() {
        return Some("shadow-tls".to_string());
    }
    options
        .iter()
        .map(|field| field.trim())
        .find(|field| !field.is_empty() && !is_proxy_line_option(field))
        .filter(|field| matches!(normalized_token(field).as_str(), "http" | "tls"))
        .map(obfs_plugin_name)
}

/// Whether a `type, server, port, ...` definition is in Surge's style, where
/// the fields after the port are `key=value` options, rather than Loon's,
/// where the credentials follow the port as positional fields (the cipher
/// and password of shadowsocks, the password of trojan, the UUID of vless,
/// the cipher and UUID of vmess).
///
/// Only the first field after the port decides. A positional password or
/// SS-2022 key may itself contain `=` (base64 padding), so containing `=`
/// alone does not make a field an option; see [`is_proxy_line_option`].
pub(crate) fn is_surge_style_proxy_definition(parts: &[String]) -> bool {
    parts
        .get(3..)
        .unwrap_or_default()
        .iter()
        .find(|field| !field.is_empty())
        .is_some_and(|field| is_proxy_line_option(field))
}

/// Whether a proxy line field is a `key=value` option: not quoted, a key
/// that is a word (a letter, then letters, digits, `-` or `_`), and a value
/// that is more than `=` padding. A base64 value such as `aGVsbG8=` or
/// `AAAAAAAAAAAAAAAAAAAAAA==` splits into a word and padding only, so it
/// stays a positional value.
pub(crate) fn is_proxy_line_option(field: &str) -> bool {
    if field.starts_with('"') {
        return false;
    }
    let Some((key, value)) = field.split_once('=') else {
        return false;
    };
    let mut key = key.trim().chars();
    key.next().is_some_and(|first| first.is_ascii_alphabetic())
        && key.all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        && !value.trim().trim_matches('=').is_empty()
}

pub(crate) fn required_loon_proxy_part(
    parts: &[String],
    index: usize,
    message: &'static str,
) -> DomainResult<String> {
    let value = parts.get(index).cloned().unwrap_or_default();
    let value = strip_loon_quotes(value);
    required_trimmed(value, SUBSCRIPTION_LOON_PROXY_LINE_INVALID_CODE, message)
}

pub(crate) fn strip_loon_quotes(value: String) -> String {
    let value = value.trim();
    if value.len() >= 2 && value.starts_with('"') && value.ends_with('"') {
        value[1..value.len() - 1].to_string()
    } else {
        value.to_string()
    }
}
