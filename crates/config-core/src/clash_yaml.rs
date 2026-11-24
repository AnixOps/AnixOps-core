//! Clash YAML subscriptions.

use super::*;

pub(crate) fn parse_clash_yaml_subscription(
    source_id: &str,
    content: &str,
) -> DomainResult<Option<SubscriptionDocument>> {
    let content = content.trim();
    if content.is_empty() {
        return Ok(None);
    }

    let raw = match serde_saphyr::from_str::<RawClashDocument>(content) {
        Ok(raw) => raw,
        Err(_) => return Ok(None),
    };
    let Some(proxies) = raw.proxies else {
        return Ok(None);
    };
    if proxies.is_empty() {
        return Err(domain_error(
            SUBSCRIPTION_CLASH_YAML_INVALID_CODE,
            "clash yaml proxies cannot be empty",
        ));
    }

    let mut nodes = Vec::new();
    let mut skipped = SkippedEntries::new("clash proxy");
    // Whether any entry reads as a Clash proxy; when none does, the text is
    // not a Clash document and the next format gets it.
    let mut readable = false;
    for (index, value) in proxies.into_iter().enumerate() {
        let name = value
            .get("name")
            .and_then(serde_json::Value::as_str)
            .map(str::to_string);
        let kind = value
            .get("type")
            .and_then(serde_json::Value::as_str)
            .map(str::to_string);
        if kind.as_deref().is_some_and(is_clash_builtin_proxy_type) {
            readable = true;
            continue;
        }
        let raw = match serde_json::from_value::<RawClashProxy>(value) {
            Ok(raw) => raw,
            Err(_) => {
                skipped.skip(
                    index,
                    name.as_deref(),
                    kind.as_deref(),
                    domain_error(
                        SUBSCRIPTION_CLASH_YAML_INVALID_CODE,
                        "clash proxy fields have unexpected types",
                    ),
                );
                continue;
            }
        };
        readable = true;
        match parse_clash_proxy(raw, source_id) {
            Ok(node) => nodes.push(node),
            Err(error) => skipped.skip(index, name.as_deref(), kind.as_deref(), error),
        }
    }
    if !readable {
        return Ok(None);
    }

    node_id::assign_subscription_node_ids(&mut nodes);
    skipped
        .finish(nodes, || {
            domain_error(
                SUBSCRIPTION_CLASH_YAML_UNSUPPORTED_CODE,
                "clash yaml proxies must contain at least one supported proxy",
            )
        })
        .map(Some)
}

/// Clash proxy types that are policies rather than nodes (mihomo's
/// `direct`, `reject`, `reject-drop`, `dns`).
pub(crate) fn is_clash_builtin_proxy_type(kind: &str) -> bool {
    builtin_policy(kind).is_some() || kind.trim().eq_ignore_ascii_case("dns")
}

pub(crate) fn parse_clash_proxy(
    mut raw: RawClashProxy,
    source_id: &str,
) -> DomainResult<NodeDescriptor> {
    let text = |value: Option<RawClashScalar>| {
        value
            .map(RawClashScalar::into_text)
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
    };
    let name = required_clash_scalar_field(raw.name, "clash proxy name cannot be empty")?;
    let protocol = required_clash_scalar_field(raw.protocol, "clash proxy type cannot be empty")?;
    let host = required_clash_scalar_field(raw.server, "clash proxy server cannot be empty")?;
    // Mieru entries may give only `port-range`; its first port is the endpoint.
    let port_range = text(raw.port_range.take());
    let port = match (
        raw.port,
        port_range
            .as_deref()
            .and_then(|range| range.split_once('-')),
    ) {
        (None, Some((low, _))) => low.trim().to_string(),
        (port, _) => required_clash_scalar_field(port, "clash proxy port cannot be empty")?,
    };
    let port = port.parse::<i64>().map_err(|_| {
        domain_error(
            SUBSCRIPTION_CLASH_YAML_INVALID_CODE,
            "clash proxy port must be a number",
        )
    })?;
    let port = parse_port(
        port,
        SUBSCRIPTION_CLASH_YAML_INVALID_CODE,
        "clash proxy port must be between 1 and 65535",
    )?;

    let protocol_token = normalized_token(&protocol);
    let (protocol, protocol_tag, mut metadata) = match protocol_token.as_str() {
        "ss" | "shadowsocks" => {
            let method = required_clash_scalar_field(
                raw.cipher,
                "clash shadowsocks cipher cannot be empty",
            )?;
            let password = required_clash_scalar_field(
                raw.password,
                "clash shadowsocks password cannot be empty",
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
            metadata.extend(shadowsocks_plugin_entry(clash_option_text(
                raw.plugin.as_ref(),
            )));
            (Protocol::Shadowsocks, "ss", metadata)
        }
        "trojan" => {
            let password =
                required_clash_scalar_field(raw.password, "clash trojan password cannot be empty")?;
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
            let uuid = required_clash_scalar_field(raw.uuid, "clash vless uuid cannot be empty")?;
            let mut metadata = vec![MetadataEntry {
                key: NODE_METADATA_VLESS_UUID.to_string(),
                value: uuid,
            }];
            if let Some(encryption) = raw
                .encryption
                .map(|raw| raw.into_text().trim().to_string())
                .filter(|value| !value.is_empty() && value != "none")
            {
                metadata.push(MetadataEntry {
                    key: NODE_METADATA_VLESS_ENCRYPTION.to_string(),
                    value: encryption,
                });
            }
            if let Some(flow) = clash_option_text(raw.flow.as_ref()) {
                metadata.push(MetadataEntry {
                    key: NODE_METADATA_VLESS_FLOW.to_string(),
                    value: flow,
                });
            }
            (Protocol::Vless, "vless", metadata)
        }
        "vmess" => {
            let uuid = required_clash_scalar_field(raw.uuid, "clash vmess uuid cannot be empty")?;
            let mut metadata = vec![MetadataEntry {
                key: NODE_METADATA_VMESS_UUID.to_string(),
                value: uuid,
            }];
            metadata.extend(proxy_vmess_security(text(raw.cipher)));
            if let Some(alter_id) = clash_option_text(raw.alter_id.as_ref()) {
                metadata.push(MetadataEntry {
                    key: NODE_METADATA_VMESS_ALTER_ID.to_string(),
                    value: alter_id,
                });
            }
            (Protocol::Vmess, "vmess", metadata)
        }
        "snell" => {
            let psk = required_clash_scalar_field(raw.psk, "clash snell psk cannot be empty")?;
            let obfs = raw.obfs_opts.unwrap_or(RawClashSnellObfs {
                mode: None,
                host: None,
            });
            (
                Protocol::Snell,
                "snell",
                snell_metadata(SnellFields {
                    psk,
                    version: text(raw.version),
                    mode: None,
                    obfs: text(obfs.mode),
                    obfs_host: text(obfs.host),
                    obfs_uri: None,
                    reuse: None,
                    user_key: None,
                }),
            )
        }
        "mieru" => {
            let username =
                required_clash_scalar_field(raw.username, "clash mieru username cannot be empty")?;
            let password =
                required_clash_scalar_field(raw.password, "clash mieru password cannot be empty")?;
            let mut metadata = vec![
                MetadataEntry {
                    key: NODE_METADATA_MIERU_USERNAME.to_string(),
                    value: username,
                },
                MetadataEntry {
                    key: NODE_METADATA_MIERU_PASSWORD.to_string(),
                    value: password,
                },
                MetadataEntry {
                    key: NODE_METADATA_MIERU_TRANSPORT.to_string(),
                    value: text(raw.transport)
                        .unwrap_or_else(|| "TCP".to_string())
                        .to_ascii_uppercase(),
                },
            ];
            if let Some(range) = port_range {
                metadata.push(MetadataEntry {
                    key: NODE_METADATA_MIERU_PORT_RANGE.to_string(),
                    value: range,
                });
            }
            if let Some(level) = text(raw.multiplexing) {
                if let Ok(enabled) = parse_mieru_multiplexing(&level) {
                    metadata.push(MetadataEntry {
                        key: NODE_METADATA_MIERU_MULTIPLEXING.to_string(),
                        value: enabled.to_string(),
                    });
                }
            }
            (Protocol::Mieru, "mieru", metadata)
        }
        "http" | "socks5" => {
            let (protocol, tag) = if protocol_token == "http" {
                (Protocol::Http, "http")
            } else {
                (Protocol::Socks, "socks")
            };
            let tls = clash_option_bool(
                raw.stream.tls.as_ref(),
                "clash proxy tls must be true or false",
            )?
            .unwrap_or(false);
            let insecure = clash_option_bool(
                raw.stream.skip_cert_verify.as_ref(),
                "clash proxy skip-cert-verify must be true or false",
            )?
            .unwrap_or(false);
            let headers = raw
                .headers
                .as_ref()
                .and_then(serde_json::Value::as_object)
                .is_some_and(|headers| !headers.is_empty());
            let fields = PlainProxyFields {
                username: text(raw.username.take()),
                password: text(raw.password.take()),
                tls,
                server_name: clash_option_text(raw.stream.sni.as_ref())
                    .or_else(|| clash_option_text(raw.stream.servername.as_ref())),
                insecure,
                certificate_sha256: text(raw.fingerprint.take()),
                public_key_sha256: None,
                unsupported: (headers && protocol == Protocol::Http)
                    .then_some(NODE_UNSUPPORTED_OPTION_HTTP_PROXY_HEADERS),
            };
            (protocol, tag, plain_proxy_metadata(fields, &host))
        }
        _ => {
            return Err(domain_error(
                SUBSCRIPTION_CLASH_YAML_UNSUPPORTED_CODE,
                "clash proxy type must be ss, trojan, vless, vmess, snell, mieru, http, or socks5",
            ));
        }
    };

    if matches!(
        protocol,
        Protocol::Trojan | Protocol::Vless | Protocol::Vmess
    ) {
        metadata.extend(proxy_line_pin_metadata(text(raw.fingerprint.take()), None));
        clash_stream_options(&raw.stream)?.append_to(
            &mut metadata,
            &host,
            protocol == Protocol::Trojan,
            SUBSCRIPTION_CLASH_YAML_INVALID_CODE,
            "clash proxy",
        )?;
    }
    metadata.extend(multiplex_metadata(raw.smux.as_ref()));
    let name_id = sanitize_identifier(&name);
    let name_id = if name_id.is_empty() {
        "node".to_string()
    } else {
        name_id
    };
    let id = format!("clash-{protocol_tag}-{name_id}");
    metadata.push(MetadataEntry {
        key: NODE_METADATA_SOURCE_FORMAT.to_string(),
        value: "clash-yaml".to_string(),
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
            "clash-yaml".to_string(),
            protocol_tag.to_string(),
        ],
        metadata,
    })
}

/// The engine's `multiplex` object for a Clash `smux` or sing-box
/// `multiplex` that is turned on: the protocol and pool sizes, in either
/// spelling (`max-connections`, `max_connections`). `None` when it is off
/// or not an object. Values that make no sense are dropped, not rejected,
/// so a node still imports.
pub(crate) fn multiplex_metadata(raw: Option<&serde_json::Value>) -> Option<MetadataEntry> {
    use serde_json::Value;
    let object = raw?.as_object()?;
    let enabled = match object.get("enabled") {
        Some(Value::Bool(enabled)) => *enabled,
        Some(Value::String(text)) => matches!(text.trim(), "true" | "1"),
        Some(Value::Number(number)) => number.as_u64() == Some(1),
        _ => false,
    };
    if !enabled {
        return None;
    }
    let count = |names: [&str; 2]| {
        names.iter().find_map(|name| match object.get(*name)? {
            Value::Number(number) => number.as_u64(),
            Value::String(text) => text.trim().parse::<u64>().ok(),
            _ => None,
        })
    };
    let mut settings = serde_json::Map::new();
    if let Some(protocol) = object.get("protocol").and_then(Value::as_str) {
        if matches!(protocol, "smux" | "yamux" | "h2mux") {
            settings.insert("protocol".into(), protocol.into());
        }
    }
    match count(["max_streams", "max-streams"]).filter(|n| *n > 0) {
        Some(streams) => {
            settings.insert("max_streams".into(), streams.into());
        }
        None => {
            if let Some(n) = count(["max_connections", "max-connections"]).filter(|n| *n > 0) {
                settings.insert("max_connections".into(), n.into());
            }
            if let Some(n) = count(["min_streams", "min-streams"]).filter(|n| *n > 0) {
                settings.insert("min_streams".into(), n.into());
            }
        }
    }
    if object.get("padding").and_then(Value::as_bool) == Some(true) {
        settings.insert("padding".into(), true.into());
    }
    Some(MetadataEntry {
        key: NODE_METADATA_MULTIPLEX.to_string(),
        value: Value::Object(settings).to_string(),
    })
}

pub(crate) fn required_clash_scalar_field(
    raw: Option<RawClashScalar>,
    message: &'static str,
) -> DomainResult<String> {
    let Some(raw) = raw else {
        return Err(domain_error(SUBSCRIPTION_CLASH_YAML_INVALID_CODE, message));
    };

    required_trimmed(
        raw.into_text(),
        SUBSCRIPTION_CLASH_YAML_INVALID_CODE,
        message,
    )
}

/// A Clash scalar option as text: a string trimmed, a number or boolean as
/// YAML read it; `None` when empty, absent or not a scalar.
pub(crate) fn clash_option_text(value: Option<&serde_json::Value>) -> Option<String> {
    let text = match value? {
        serde_json::Value::String(text) => text.trim().to_string(),
        serde_json::Value::Number(number) => number.to_string(),
        serde_json::Value::Bool(flag) => flag.to_string(),
        _ => return None,
    };
    (!text.is_empty()).then_some(text)
}

/// A Clash boolean option: a YAML boolean, or `true`/`false`/`1`/`0`.
pub(crate) fn clash_option_bool(
    value: Option<&serde_json::Value>,
    message: &'static str,
) -> DomainResult<Option<bool>> {
    match value {
        None | Some(serde_json::Value::Null) => Ok(None),
        Some(serde_json::Value::Bool(flag)) => Ok(Some(*flag)),
        Some(serde_json::Value::Number(number)) => match number.as_u64() {
            Some(0) => Ok(Some(false)),
            Some(1) => Ok(Some(true)),
            _ => Err(domain_error(SUBSCRIPTION_CLASH_YAML_INVALID_CODE, message)),
        },
        Some(serde_json::Value::String(text)) => match text.trim().to_ascii_lowercase().as_str() {
            "" => Ok(None),
            "true" | "1" => Ok(Some(true)),
            "false" | "0" => Ok(Some(false)),
            _ => Err(domain_error(SUBSCRIPTION_CLASH_YAML_INVALID_CODE, message)),
        },
        Some(_) => Err(domain_error(SUBSCRIPTION_CLASH_YAML_INVALID_CODE, message)),
    }
}

/// A Clash list option (`alpn: [h2, http/1.1]`, `host: [a, b]`) as a
/// comma-separated list; a single string counts as a list of one.
pub(crate) fn clash_option_list(value: Option<&serde_json::Value>) -> Option<String> {
    let values: Vec<String> = match value? {
        serde_json::Value::Array(values) => values
            .iter()
            .filter_map(|value| clash_option_text(Some(value)))
            .collect(),
        other => clash_option_text(Some(other))
            .map(|text| {
                text.split(',')
                    .map(|value| value.trim().to_string())
                    .filter(|value| !value.is_empty())
                    .collect()
            })
            .unwrap_or_default(),
    };
    (!values.is_empty()).then(|| values.join(","))
}

/// The value of map `object`'s key `name`, ignoring ASCII case (HTTP header
/// names such as `Host`).
pub(crate) fn clash_map_entry<'a>(
    object: Option<&'a serde_json::Value>,
    name: &str,
) -> Option<&'a serde_json::Value> {
    object?
        .as_object()?
        .iter()
        .find(|(key, _)| key.eq_ignore_ascii_case(name))
        .map(|(_, value)| value)
}

/// The share-link settings of a Clash vmess, vless or trojan proxy:
/// `tls`, `servername`/`sni`, `skip-cert-verify`, `alpn`,
/// `client-fingerprint`, `reality-opts`, `network` with `ws-opts`,
/// `grpc-opts`, `h2-opts` or `xhttp-opts`, and `ech-opts`.
pub(crate) fn clash_stream_options(
    raw: &RawClashStreamOptions,
) -> DomainResult<ProxyStreamOptions> {
    let mut options = ProxyStreamOptions::default();
    let tls = clash_option_bool(raw.tls.as_ref(), "clash proxy tls must be true or false")?;
    match raw.reality_opts.as_ref().filter(|value| !value.is_null()) {
        // REALITY is TLS; mihomo also wants `tls: true` beside it.
        Some(reality) => {
            options.set("security", Some("reality".to_string()));
            options.set("pbk", clash_option_text(reality.get("public-key")));
            options.set("sid", clash_option_text(reality.get("short-id")));
        }
        None => {
            if let Some(tls) = tls {
                let security = if tls { "tls" } else { "none" };
                options.set("security", Some(security.to_string()));
            }
        }
    }
    options.set(
        "sni",
        clash_option_text(raw.servername.as_ref()).or_else(|| clash_option_text(raw.sni.as_ref())),
    );
    if let Some(insecure) = clash_option_bool(
        raw.skip_cert_verify.as_ref(),
        "clash proxy skip-cert-verify must be true or false",
    )? {
        options.set("insecure", Some(insecure.to_string()));
    }
    options.set("alpn", clash_option_list(raw.alpn.as_ref()));
    options.set("fp", clash_option_text(raw.client_fingerprint.as_ref()));
    if let Some(ech) = raw.ech_opts.as_ref().filter(|value| !value.is_null()) {
        let enabled = clash_option_bool(
            ech.get("enable"),
            "clash proxy ech-opts enable must be true or false",
        )?;
        if enabled.unwrap_or(false) {
            options.unsupported(NODE_UNSUPPORTED_OPTION_ECH);
        }
    }

    let network = clash_option_text(raw.network.as_ref()).unwrap_or_default();
    match normalized_token(&network).as_str() {
        "ws" | "websocket" => {
            let ws = raw.ws_opts.as_ref();
            let upgrade = clash_option_bool(
                ws.and_then(|ws| ws.get("v2ray-http-upgrade")),
                "clash proxy ws-opts v2ray-http-upgrade must be true or false",
            )?;
            options.set_transport(if upgrade.unwrap_or(false) {
                "httpupgrade"
            } else {
                "ws"
            });
            options.set("path", clash_option_text(ws.and_then(|ws| ws.get("path"))));
            options.set(
                "host",
                clash_option_text(clash_map_entry(ws.and_then(|ws| ws.get("headers")), "host")),
            );
        }
        "grpc" => {
            options.set_transport("grpc");
            options.set(
                "servicename",
                clash_option_text(
                    raw.grpc_opts
                        .as_ref()
                        .and_then(|grpc| grpc.get("grpc-service-name")),
                ),
            );
        }
        "h2" => {
            let h2 = raw.h2_opts.as_ref();
            options.set_transport("h2");
            options.set("host", clash_option_list(h2.and_then(|h2| h2.get("host"))));
            options.set("path", clash_option_text(h2.and_then(|h2| h2.get("path"))));
        }
        "xhttp" => {
            options.set_transport("xhttp");
            if let Some(xhttp) = raw.xhttp_opts.as_ref().and_then(|value| value.as_object()) {
                for (key, value) in xhttp {
                    match key.as_str() {
                        "path" => options.set("path", clash_option_text(Some(value))),
                        "host" => options.set("host", clash_option_text(Some(value))),
                        "mode" => options.set("mode", clash_option_text(Some(value))),
                        "headers" if value.is_object() => options.set(
                            "extra",
                            Some(serde_json::json!({ "headers": value }).to_string()),
                        ),
                        "headers" if value.is_null() => {}
                        _ => options.unsupported(NODE_UNSUPPORTED_OPTION_XHTTP),
                    }
                }
            }
        }
        // `http` is HTTP/1.1 header obfuscation in Clash, not h2.
        other => options.set_transport(other),
    }
    Ok(options)
}
